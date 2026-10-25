#!/bin/sh
set -eu

# Checksums from the v0.5.12 upstream release checksums.txt, pinned in source.
version=0.5.12
case "$(dpkg --print-architecture)" in
    amd64) arch=x86_64; checksum=e10049d206079ef12dc623d859780b2f7a06d32418dc1939004381abbafd01f1 ;;
    arm64) arch=arm64; checksum=14f496b640767279e7e9eca71218150d9251bf2d488e9fae6f012543f50a20ec ;;
    *) echo 'The test image supports amd64 and arm64 only.' >&2; exit 1 ;;
esac

archive="litestream-$version-linux-$arch.tar.gz"
curl --fail --location --retry 3 \
    "https://github.com/benbjohnson/litestream/releases/download/v$version/$archive" \
    --output "/tmp/$archive"
printf '%s  %s\n' "$checksum" "/tmp/$archive" | sha256sum --check --strict
tar -xzf "/tmp/$archive" -C /usr/local/bin litestream
rm "/tmp/$archive"
litestream version
