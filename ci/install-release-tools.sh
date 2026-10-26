#!/bin/sh
set -eu
test "$(dpkg --print-architecture)" = amd64 || { echo 'Release tooling currently requires amd64.' >&2; exit 1; }
install_tool() {
    url=$1
    checksum=$2
    binary=$3
    archive=$(mktemp)
    curl --fail --location --retry 3 "$url" --output "$archive"
    printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check --strict
    tar -xzf "$archive" -C /usr/local/bin "$binary"
    rm "$archive"
}
install_tool https://github.com/goreleaser/goreleaser/releases/download/v2.19.0/goreleaser_Linux_x86_64.tar.gz \
    ebc3194ad1d1b1787614405285a0039665cd4c5bd3305215a1b201600f90630b goreleaser
install_tool https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_linux_amd64.tar.gz \
    bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d syft
goreleaser --version
syft version
