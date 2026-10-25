# Release supply-chain verification

Every change runs tests, vet, reachable Go vulnerability analysis, and a high/critical container-package scan before publishing. GoReleaser produces SPDX JSON SBOMs for each archive and Linux package, calculates SHA-256 checksums, and uses GitHub OIDC with Cosign to create a keyless certificate and detached signature for `checksums.txt`. GitHub artifact attestations record build provenance for release files.

The release workflow also publishes amd64/arm64 images to GHCR with BuildKit provenance and SBOM attestations, signs the immutable image digest with Cosign, and records GitHub provenance for that digest.

Verify downloaded release files by first verifying the signed checksum manifest, then its listed digest:

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github.com/.+/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
sha256sum --ignore-missing --check checksums.txt
```

Verify the container using the immutable digest shown by the release:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/.+/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/OWNER/licenceserver@sha256:DIGEST
```

Local snapshot builds intentionally skip OIDC signing and SBOM generation when those external tools are unavailable:

```bash
goreleaser release --snapshot --clean --skip=sign,sbom
```

Production tags never use those skip flags.
