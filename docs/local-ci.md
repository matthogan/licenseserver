# Local testing and Woodpecker

The test environment is separate from `compose.yaml`, which deploys the actual
licensing service. It needs Docker Desktop in Linux-container mode. You do not
need Go, PostgreSQL, a C compiler, Litestream, or AWS credentials on Windows.

## Run on your computer

From the repository directory in PowerShell:

```powershell
./scripts/test-local.ps1
```

The first run downloads images and dependencies and builds a tooling image.
Subsequent runs reuse the tooling image and Go caches. Docker starts a disposable
PostgreSQL database and a test runner. The script waits for an authenticated
database query, runs vet and the full race suite (including the two normally
optional integrations), then builds the Linux `licd` and `licctl` binaries.

The PowerShell script removes test containers and their network even on test
failure. The database is temporary and has no published host port. Go caches are
retained. Do not run two copies of this local Compose project simultaneously.
Logs and binaries are written to `.ci-results/`, which is ignored by Git.

The equivalent commands on Linux are:

```sh
docker compose -f compose.test.yaml up --build --abort-on-container-exit --exit-code-from test
# Preserve the first command's exit code if using this in a script.
docker compose -f compose.test.yaml down
```

## Use the existing local Woodpecker agent

1. Run the local test command above. It also builds the image needed by Woodpecker.
   To build only the tools, use `docker compose -f compose.test.yaml build`.
2. The Woodpecker Docker agent must use the same Docker daemon as this command.
   The pipeline deliberately uses a local image with `pull: false`; no container
   registry, registry account, or Docker socket inside the test step is needed.
3. Commit and push `.woodpecker.yaml`, `ci/`, `scripts/ci/`, the local wrapper,
   `compose.test.yaml`, and supporting documentation/ignore/line-ending changes.
4. In Woodpecker, keep the configuration path at its default (or explicitly
   `.woodpecker.yaml`) and start a manual pipeline on the pushed branch.
5. Look for `PASS` for `TestRepositoryContract` and
   `TestRealLitestreamConfiguration`. The runner fails if either test skips.

Woodpecker clones the selected GitHub commit. It never reads uncommitted files
from your Windows checkout. The workflow creates its own PostgreSQL service and
calls the same `scripts/ci/run-tests.sh` used locally. Its logs remain in the UI;
files under `.ci-results/` in the CI workspace are temporary, not automatically
downloadable artifacts.

If a job remains queued, check that the agent is connected. If it cannot find
`local/licd-test:go1.26.6-litestream0.5.12-v1`, build the image on the agent's Docker
daemon. Rebuild it after changing `ci/Dockerfile` or `ci/install-litestream.sh`;
bump the image tag in Compose and Woodpecker when changing tool versions.

## What the tests establish

- Go vet, race detection, repository tests, and Linux binary builds.
- Real PostgreSQL migrations and the existing repository contract.
- Real Litestream v0.5.12 acceptance of the generated SSE-KMS and SSE-C configuration.

The database password is disposable test data. This initial PostgreSQL contract
uses plaintext on the private test network; it does not certify production TLS
configuration. Litestream configuration validation does not contact S3 or prove
replication, restore, KMS authorization, or Object Lock. Those need separate
integration/acceptance tests. Windows runtime tests also require a Windows agent.

No production database, licence-server keys, or AWS secrets are required. The
local runner mounts this checkout as its workspace; keep production secrets
outside the repository. This workflow tests and builds; it does not deploy or publish.

Disable existing GitHub Actions workflows separately if all builds should be
local. Woodpecker does not disable them automatically.

Signed `v*` tags additionally run the local release-candidate step described in
`docs/supply-chain-security.md`. It requires the release image and trusted volumes.
It does not run for ordinary pushes or pull requests.
