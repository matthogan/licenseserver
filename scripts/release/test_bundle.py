import hashlib
import io
import json
import pathlib
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import bundle


class ReleaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = pathlib.Path(self.temporary.name)
        self.tag = 'v1.2.3'
        self.commit = 'a' * 40
        self.policy = {'repository': 'https://example.invalid/source',
                       'builder': 'https://example.invalid/builder',
                       'platforms': ['linux/amd64', 'linux/arm64']}
        self.policy_path = self.directory / 'policy.json'
        bundle.write_json(self.policy_path, self.policy)
        self.policy_patch = patch.object(bundle, 'POLICY', self.policy_path)
        self.policy_patch.start()
        self.addCleanup(self.policy_patch.stop)
        self.addCleanup(self.temporary.cleanup)
        self.write_oci()
        for suffix in bundle.PAYLOAD_SUFFIXES:
            name = 'example' + suffix
            (self.directory / name).write_bytes(b'package bytes')
            bundle.write_json(self.directory / (name + '.sbom.json'),
                              {'spdxVersion': 'SPDX-2.3', 'packages': [{'name': 'licd'}]})
        (self.directory / 'tests.log').write_text(
            '--- PASS: TestRepositoryContract (1s)\n--- PASS: TestRealLitestreamConfiguration (1s)\n')
        (self.directory / 'source-tag.txt').write_text('tag object verified separately by Git')
        self.prepare()

    def write_oci(self, missing_provenance=False, bad_subject=False, modern=False):
        files = {'oci-layout': b'{"imageLayoutVersion":"1.0.0"}'}

        def blob(obj):
            data = json.dumps(obj).encode()
            value = hashlib.sha256(data).hexdigest()
            files['blobs/sha256/' + value] = data
            return {'digest': 'sha256:' + value, 'size': len(data)}

        manifests = []
        for arch in ('amd64', 'arm64'):
            config = blob({'architecture': arch, 'config': {'Labels': {
                'org.opencontainers.image.revision': self.commit,
                'org.opencontainers.image.version': self.tag}}})
            image = blob({'config': config, 'layers': [blob({'layer': arch})]})
            image['platform'] = {'os': 'linux', 'architecture': arch}
            manifests.append(image)
            subject = [{'digest': {'sha256': 'b' * 64 if bad_subject else image['digest'][7:]}}]
            if modern:
                subject = []
            layers = [blob({'subject': subject, 'predicateType': 'https://spdx.dev/Document',
                            'predicate': {'packages': [{'name': 'alpine'}]}})]
            if not missing_provenance:
                args = {'args': {'build-arg:COMMIT': self.commit}}
                predicate = ({'buildDefinition': {'externalParameters': {'request': args}}} if modern else
                             {'invocation': {'parameters': args}})
                layers.append(blob({'subject': subject, 'predicateType': 'https://slsa.dev/provenance/' + ('v1' if modern else 'v0.2'),
                                    'predicate': predicate}))
            obj = {'config': blob({}), 'layers': layers}
            if modern:
                obj['subject'] = dict(image)
                if bad_subject:
                    obj['subject']['digest'] = 'sha256:' + 'b' * 64
            attestation = blob(obj)
            attestation['annotations'] = {'vnd.docker.reference.digest': image['digest']}
            manifests.append(attestation)
        files['index.json'] = json.dumps({'manifests': manifests}).encode()
        with tarfile.open(self.directory / f'licenceserver_{self.tag}_container.oci.tar', 'w') as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))

    def prepare(self):
        with patch('bundle.subprocess.check_output', return_value='test-tool'):
            bundle.prepare(self.directory, self.tag, self.commit)

    def test_complete_evidence(self):
        bundle.verify(self.directory, self.tag, self.commit)

    def test_modern_oci_subject_and_provenance(self):
        self.write_oci(modern=True)
        self.prepare()
        bundle.verify(self.directory, self.tag, self.commit)

    def test_modern_oci_wrong_subject(self):
        self.write_oci(modern=True, bad_subject=True)
        with self.assertRaisesRegex(ValueError, 'subject mismatch'):
            self.prepare()

    def test_tampered_package(self):
        (self.directory / 'example.zip').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'Checksum mismatch'):
            bundle.verify(self.directory, self.tag, self.commit)

    def test_missing_file(self):
        (self.directory / 'example.zip').unlink()
        with self.assertRaisesRegex(ValueError, 'Missing/non-regular artifact'):
            bundle.verify(self.directory, self.tag, self.commit)

    def test_wrong_source(self):
        with self.assertRaisesRegex(ValueError, 'source mismatch'):
            bundle.verify(self.directory, self.tag, 'c' * 40)

    def test_unapproved_builder(self):
        self.policy['builder'] = 'another-builder'
        bundle.write_json(self.policy_path, self.policy)
        with self.assertRaisesRegex(ValueError, 'Untrusted builder'):
            bundle.verify(self.directory, self.tag, self.commit)

    def test_missing_package_sbom(self):
        (self.directory / 'example.zip.sbom.json').unlink()
        with self.assertRaisesRegex(ValueError, 'Missing SBOM'):
            self.prepare()

    def test_missing_container_provenance(self):
        self.write_oci(missing_provenance=True)
        with self.assertRaisesRegex(ValueError, 'Missing per-platform'):
            self.prepare()

    def test_container_attestation_wrong_subject(self):
        self.write_oci(bad_subject=True)
        with self.assertRaisesRegex(ValueError, 'subject mismatch'):
            self.prepare()


if __name__ == '__main__':
    unittest.main()
