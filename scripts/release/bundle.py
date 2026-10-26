"""Prepare and validate release evidence. Signature verification is done by Cosign.

No archive is extracted and no command from an artifact is executed.
"""
import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import tarfile


POLICY = pathlib.Path('/opt/licd-release/policy.json')
PAYLOAD_SUFFIXES = ('.tar.gz', '.zip', '.deb', '.rpm', '.apk')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def verify_oci(path, commit, tag, platforms):
    with tarfile.open(path) as archive:
        members = {m.name: m for m in archive.getmembers()}
        require(len(members) == len(archive.getmembers()), 'Duplicate OCI archive member')
        require(all(m.isdir() or m.isfile() for m in members.values()), 'Unexpected OCI link or device')

        def document(name):
            member = members[name]
            require(member.isfile() and member.size < 128 * 1024 * 1024, 'Invalid OCI JSON member')
            with archive.extractfile(member) as stream:
                return json.load(stream)

        checked = set()

        def blob(descriptor):
            algorithm, value = descriptor['digest'].split(':', 1)
            require(algorithm == 'sha256' and re.fullmatch('[0-9a-f]{64}', value), 'Invalid OCI digest')
            name = 'blobs/sha256/' + value
            member = members[name]
            require(member.isfile() and member.size == descriptor['size'], 'OCI blob size mismatch')
            if value not in checked:
                with archive.extractfile(member) as stream:
                    require(hashlib.file_digest(stream, 'sha256').hexdigest() == value, 'OCI blob checksum mismatch')
                checked.add(value)
            return name

        manifests = {}
        attestations = {}

        def visit(descriptor):
            name = blob(descriptor)
            obj = document(name)
            if 'manifests' in obj:
                for child in obj['manifests']:
                    visit(child)
            else:
                reference = descriptor.get('annotations', {}).get('vnd.docker.reference.digest')
                config = document(blob(obj['config']))
                if reference:
                    linked_subject = obj.get('subject')
                    if linked_subject:
                        require(linked_subject['digest'] == reference, 'OCI attestation subject mismatch')
                        blob(linked_subject)
                    evidence = attestations.setdefault(reference, set())
                    for layer in obj['layers']:
                        statement = document(blob(layer))
                        subjects = statement.get('subject', [])
                        require((not subjects and linked_subject) or
                                any(s.get('digest', {}).get('sha256') == reference.removeprefix('sha256:')
                                    for s in subjects), 'OCI attestation subject mismatch')
                        predicate_type = statement['predicateType']
                        if predicate_type == 'https://spdx.dev/Document':
                            require(statement['predicate'].get('packages'), 'Empty container SBOM')
                            evidence.add('sbom')
                        elif predicate_type.startswith('https://slsa.dev/provenance/'):
                            predicate = statement['predicate']
                            if predicate_type == 'https://slsa.dev/provenance/v1':
                                args = predicate.get('buildDefinition', {}).get('externalParameters', {}).get('request', {}).get('args', {})
                            else:
                                args = predicate.get('invocation', {}).get('parameters', {}).get('args', {})
                            require(args.get('build-arg:COMMIT') == commit, 'Container provenance source mismatch')
                            evidence.add('provenance')
                else:
                    platform = descriptor.get('platform', {})
                    identity = platform.get('os', '') + '/' + platform.get('architecture', '')
                    labels = config.get('config', {}).get('Labels', {})
                    require(labels.get('org.opencontainers.image.revision') == commit, 'Container revision mismatch')
                    require(labels.get('org.opencontainers.image.version') == tag, 'Container version mismatch')
                    manifests[descriptor['digest']] = identity
                    for layer in obj['layers']:
                        blob(layer)

        require(document('oci-layout')['imageLayoutVersion'] == '1.0.0', 'Unexpected OCI layout')
        for desc in document('index.json')['manifests']:
            visit(desc)
        require(set(manifests.values()) == set(platforms), 'Container platforms mismatch')
        require(all(attestations.get(key) == {'sbom', 'provenance'} for key in manifests),
                'Missing per-platform container SBOM or provenance')
        return manifests


def validate_payloads(directory, filenames, tag, commit, policy):
    payloads = [n for n in filenames if n.endswith(PAYLOAD_SUFFIXES)]
    require(all(any(n.endswith(s) for n in payloads) for s in PAYLOAD_SUFFIXES), 'Missing release package format')
    for name in payloads:
        sbom = name + '.sbom.json'
        require(sbom in filenames, 'Missing SBOM: ' + sbom)
        data = read_json(directory / sbom)
        require(data.get('spdxVersion', '').startswith('SPDX-') and data.get('packages'), 'Invalid/empty SBOM: ' + sbom)
    image = f'licenceserver_{tag}_container.oci.tar'
    require(image in filenames, 'Missing container archive')
    return verify_oci(directory / image, commit, tag, policy['platforms'])


def manifest(directory):
    result = {}
    for line in (directory / 'checksums.txt').read_text(encoding='ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9_.-]*)', line)
        require(match is not None, 'Invalid checksum entry')
        checksum, name = match.groups()
        require(name not in result, 'Duplicate checksum entry')
        require((directory / name).is_file() and not (directory / name).is_symlink(), 'Missing/non-regular artifact: ' + name)
        require(digest(directory / name) == checksum, 'Checksum mismatch: ' + name)
        result[name] = checksum
    require(result, 'Empty checksum manifest')
    return result


def verify(directory, tag, commit):
    policy = read_json(POLICY)
    files = manifest(directory)
    require('provenance.json' in files and 'source-tag.txt' in files and 'tests.log' in files, 'Missing release evidence')
    provenance = read_json(directory / 'provenance.json')
    require(provenance['_type'] == 'https://in-toto.io/Statement/v1', 'Wrong provenance format')
    require(provenance['predicateType'] == 'https://slsa.dev/provenance/v1', 'Wrong provenance type')
    predicate = provenance['predicate']
    require(predicate['runDetails']['builder']['id'] == policy['builder'], 'Untrusted builder')
    params = predicate['buildDefinition']['externalParameters']
    require(params == {'repository': policy['repository'], 'tag': tag, 'commit': commit}, 'Provenance source mismatch')
    subjects = {s['name']: s['digest']['sha256'] for s in provenance['subject']}
    require(len(subjects) == len(provenance['subject']), 'Duplicate provenance subjects')
    require(subjects == {n: h for n, h in files.items() if n != 'provenance.json'}, 'Provenance artifact mismatch')
    validate_payloads(directory, files, tag, commit, policy)
    log = (directory / 'tests.log').read_text(encoding='utf-8')
    for name in ('TestRepositoryContract', 'TestRealLitestreamConfiguration'):
        require(re.search(r'^--- PASS: ' + name + ' ', log, re.M), 'Missing integration-test evidence: ' + name)
    print('Verified checksums, provenance source/builder/subjects, package SBOMs, OCI blobs and per-platform attestations.')


def prepare(directory, tag, commit):
    policy = read_json(POLICY)
    files = sorted(p.name for p in directory.iterdir() if p.is_file() and (
        p.name.endswith(PAYLOAD_SUFFIXES + ('.sbom.json', '.oci.tar')) or
        p.name in ('tests.log', 'source-tag.txt', 'tag-verification.txt', 'container-build.json')))
    validate_payloads(directory, files, tag, commit, policy)
    statement = {
        '_type': 'https://in-toto.io/Statement/v1',
        'subject': [{'name': n, 'digest': {'sha256': digest(directory / n)}} for n in files],
        'predicateType': 'https://slsa.dev/provenance/v1',
        'predicate': {
            'buildDefinition': {
                'buildType': policy['builder'],
                'externalParameters': {'repository': policy['repository'], 'tag': tag, 'commit': commit},
                'internalParameters': {'workflow': '.woodpecker.yaml', 'script': 'scripts/release/build.sh'},
                'resolvedDependencies': [{'uri': policy['repository'], 'digest': {'gitCommit': commit}}],
            },
            'runDetails': {
                'builder': {'id': policy['builder'], 'version': {
                    'go': subprocess.check_output(['go', 'version'], text=True).strip(),
                    'goreleaser': subprocess.check_output(['goreleaser', '--version'], text=True).strip(),
                    'syft': subprocess.check_output(['syft', 'version'], text=True).strip(),
                }},
            },
        },
    }
    write_json(directory / 'provenance.json', statement)
    files.append('provenance.json')
    (directory / 'checksums.txt').write_text(''.join(f'{digest(directory / n)}  {n}\n' for n in sorted(files)), encoding='ascii')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'verify', 'copy'])
    parser.add_argument('directory', type=pathlib.Path)
    parser.add_argument('destination', nargs='?', type=pathlib.Path)
    parser.add_argument('--tag')
    parser.add_argument('--commit')
    args = parser.parse_args()
    if args.action == 'copy':
        require(args.destination is not None, 'Destination required')
        for name in list(manifest(args.directory)) + ['checksums.txt']:
            shutil.copyfile(args.directory / name, args.destination / name)
    else:
        require(args.tag and args.commit, 'Tag and commit required')
        (prepare if args.action == 'prepare' else verify)(args.directory, args.tag, args.commit)
