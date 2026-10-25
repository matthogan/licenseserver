#!/usr/bin/env bash
set -euo pipefail

# These defaults refer only to the disposable PostgreSQL service in the workflow.
export LICD_TEST_POSTGRES_DSN="${LICD_TEST_POSTGRES_DSN:-postgres://licd_test:disposable-test-password@postgres:5432/licenceserver_test?sslmode=disable}"
export LICD_TEST_LITESTREAM_BINARY="${LICD_TEST_LITESTREAM_BINARY:-/usr/local/bin/litestream}"
export CGO_ENABLED=1
results="${LICD_TEST_RESULTS_DIR:-.ci-results}"
mkdir -p "$results"

command -v gcc >/dev/null
command -v psql >/dev/null
test -x "$LICD_TEST_LITESTREAM_BINARY"
go version
"$LICD_TEST_LITESTREAM_BINARY" version

# Authenticate and execute a query, rather than merely checking the TCP port.
ready=false
for attempt in $(seq 1 60); do
    if PGCONNECT_TIMEOUT=2 psql "$LICD_TEST_POSTGRES_DSN" -X -v ON_ERROR_STOP=1 -Atc 'SELECT 1' >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 1
done
if [ "$ready" != true ]; then
    echo 'The disposable PostgreSQL test database did not become ready.' >&2
    exit 1
fi

echo 'Downloading Go modules (cached after the first local run)...'
go mod download
echo 'Running go vet...'
go vet ./... 2>&1 | tee "$results/vet.log"
echo 'Running the race suite and required integrations...'
go test -race -count=1 -timeout=15m -v ./... 2>&1 | tee "$results/tests.log"

# Fail even if an integration test is accidentally removed or starts skipping.
for required_test in TestRepositoryContract TestRealLitestreamConfiguration; do
    if ! grep -q -- "^--- PASS: $required_test " "$results/tests.log"; then
        echo "Required integration test did not pass: $required_test" >&2
        exit 1
    fi
done

echo 'Building Linux binaries...'
go build -trimpath -o "$results/licd" ./cmd/licd
go build -trimpath -o "$results/licctl" ./cmd/licctl
echo 'Local CI passed: vet, race tests, PostgreSQL, Litestream configuration, and both Linux binaries.'
