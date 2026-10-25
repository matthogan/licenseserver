#!/bin/sh
set -eu

repo_root=${1:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
licd=${LICD_BINARY:-$repo_root/dist/licd_linux_amd64_v1/licd}
licctl=${LICCTL_BINARY:-$repo_root/dist/licctl_linux_amd64_v1/licctl}
test_root=$(mktemp -d /tmp/licd-security.XXXXXX)
pid=

cleanup() {
    if [ -n "$pid" ]; then kill "$pid" >/dev/null 2>&1 || true; fi
    rm -rf -- "$test_root"
}
trap cleanup EXIT INT TERM

mkdir -p "$test_root/secrets" "$test_root/data"
"$licctl" issuer generate-root --private-key "$test_root/secrets/root.key" --public-key "$test_root/secrets/root.pub" >/dev/null
"$licctl" issuer generate --root-private-key "$test_root/secrets/root.key" --key-id issuer-unix-test --private-key "$test_root/secrets/issuer.key" --certificate "$test_root/secrets/issuer.cert" --valid-for 8760h >/dev/null
cp "$repo_root/configs/config.linux.yaml" "$test_root/config.yaml"
sed -i \
    -e "s|127.0.0.1:9443|127.0.0.1:21443|g" \
    -e "s|/run/licd/admin.sock|$test_root/admin.sock|g" \
    -e "s|/var/lib/licd/licensing.db|$test_root/data/licensing.db|g" \
    -e "s|/etc/licd/issuer.key|$test_root/secrets/issuer.key|g" \
    -e "s|/etc/licd/issuer.cert|$test_root/secrets/issuer.cert|g" \
    -e "s|/var/lib/licd/archive|$test_root/data/archive|g" \
    "$test_root/config.yaml"

"$licd" --config "$test_root/config.yaml" config check
LICD_TRIAL_PEPPER=unix-security-test-pepper-value "$licd" serve --config "$test_root/config.yaml" >"$test_root/server.log" 2>&1 &
pid=$!

ready=false
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if "$licctl" --config "$test_root/config.yaml" health >"$test_root/health.json" 2>/dev/null; then ready=true; break; fi
    sleep 0.2
done
if [ "$ready" != true ]; then
    sed -n '1,100p' "$test_root/server.log" >&2
    exit 1
fi

test -S "$test_root/admin.sock"
mode=$(stat -c %a "$test_root/admin.sock")
test "$mode" = 660
sed -n '1,100p' "$test_root/health.json"

kill -TERM "$pid"
wait "$pid"
pid=
printf '%s\n' "unix socket mode=$mode and graceful shutdown passed"
