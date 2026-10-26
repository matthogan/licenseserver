# Release signing and verification

Local Woodpecker builds release candidates from approved SSH-signed Git tags.
You export, check and sign the candidate on Windows using Cosign. Private keys
and passwords remain on your PC. This replaces the removed GitHub Actions release
workflow. Ordinary push/PR pipelines still only test and build.

## One-time setup

Build the existing test image first (see `docs/local-ci.md`), then:

```powershell
docker build -f ci/release.Dockerfile -t local/licd-release:tools-v1 .
```

The release image contains checksum-pinned GoReleaser/Syft, Docker Buildx, Python,
and public trust policy. It runs on Linux/amd64 and builds Windows amd64/arm64,
Linux amd64/arm64/armv7 packages and a Linux amd64/arm64 container archive.

In Woodpecker, open the repository's **Settings** and enable **Trusted volumes**
(possibly under the trusted repository settings). The release step uses the Docker
socket for Buildx and a named volume for durable output. Docker socket access gives
build code control of this Docker daemon: enable it only for pipeline authors you
trust. The ordinary test step mounts neither. No signing secrets or privileged
execution setting are required.

Keep the pipeline configuration path `.woodpecker.yaml`. Commit and push all
changes before tagging. `release/git-allowed-signers` and
`release/cosign-release.pub` contain public keys only. The Git signer and builder
policy are baked into the release image: changing them in a tag does not change
the verifier's trust. Review and rebuild the image explicitly for trust/tool changes.

## Create a candidate

After ordinary CI passes, choose a release version and sign the tag. For example:

```powershell
git status --short
git tag -s v0.1.0 -m "Release v0.1.0"
git verify-tag v0.1.0
git push origin v0.1.0
```

The setup does not create this example tag. The tag pipeline runs the race suite
and real PostgreSQL/Litestream configuration tests, verifies the signed tag and
exact checkout, then builds archives, deb/rpm/apk packages and SPDX SBOMs.
Buildx exports an OCI container archive with per-platform SBOM/provenance
attestations. A release provenance statement binds files to the tag, commit and
configured builder. Test logs and the signed tag object are retained as evidence.

The final checksum manifest covers every exported artifact, SBOM, provenance
file and test record. Output is saved atomically to Docker volume
`licd-release-candidates` at `/TAG`. Existing candidates are never overwritten.
Use a new tag for changed source; do not move released tags. Failed builds do not
save a completed candidate. Nothing is uploaded to GitHub or a registry.

## Export, sign and verify

After the tag pipeline passes, run:

```powershell
./scripts/release/release.ps1 -Action Export -Tag v0.1.0
./scripts/release/release.ps1 -Action Sign -Tag v0.1.0
./scripts/release/release.ps1 -Action Verify -Tag v0.1.0
```

Export copies and checks the candidate at `.release-output/v0.1.0/`. Sign validates
it before prompting for the Cosign password. It signs `checksums.txt`, saves
`checksums.txt.sigstore.json`, and verifies the result against your public key.
Cosign's default transparency service receives signing metadata/digests, not the
release files. Normal signing/verification needs Internet access. Your private
key is used by Cosign on Windows and never mounted into the Docker verifier.

Keys default to `$env:USERPROFILE\.release-signing\licenceserver`, containing
`allowed_signers`, `cosign-release.key`, and `cosign-release.pub`. Override with
`-SigningDirectory`, or use `-Directory` for downloaded release files. Verify
needs only public trust material; Sign also needs the private key/password.
Both `cosign-windows-amd64.exe` and `cosign` executable names are supported.

Verification checks the selected Git tag, matches the exported signed tag object,
verifies the Cosign manifest signature, then checks all listed files. It validates
provenance source/builder/subjects, package SBOM structure, OCI blob hashes,
revision/version labels, platforms and subject-bound SBOM/provenance attestations.
It writes `verification.json` with the tag, commit, manifest hash, trusted public
key file hash, date and checks. That file is an unsigned local verification record,
not another attestation.

Standalone signature verification is also possible:

```powershell
cosign verify-blob --key path/to/trusted-cosign-release.pub `
  --bundle checksums.txt.sigstore.json checksums.txt
```

Trust public keys/fingerprints from an independently approved record, not simply
because they accompanied a download. Back up encrypted private keys separately.

## Production acceptance and boundaries

Review the SBOM contents and retain the signed manifest, signature bundle,
`verification.json`, tag/commit and reviewer approval in the deployment record.
Publish only verified manifest-listed files plus the manifest/signature bundle;
deploy those exact artifacts. The signed manifest authenticates the provenance
and SBOM files it covers. This is operator-signed local-builder evidence, not a
claim of independent hosted provenance or any particular SLSA assurance level.

The container is an offline OCI image-layout archive. Its full bytes and embedded
attestations are authenticated by the signed manifest. Registry publication is
separate: preserve the OCI index/attestations, sign and verify the resulting
immutable registry digest, and record that digest before deploying from a registry.
This workflow does not automate registry publication or registry-signature checks.

BuildKit provenance is checked against the source commit build argument; release
provenance binds the complete archive to the verified Git source. SBOM structure
and integrity checks are not vulnerability assessments. The current Woodpecker
test workflow does not run the older GitHub Actions vulnerability scans.

References: [Cosign verification](https://docs.sigstore.dev/cosign/verifying/verify/),
[Docker attestations](https://docs.docker.com/build/metadata/attestations/), and
[Woodpecker volumes](https://woodpecker-ci.org/docs/usage/volumes).
