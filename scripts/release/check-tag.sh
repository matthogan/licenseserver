#!/usr/bin/env bash
set -euo pipefail
tag=${1:?Pass the release tag}
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo 'Expected a vMAJOR.MINOR.PATCH release tag.' >&2; exit 1; }
test "$(git cat-file -t "refs/tags/$tag")" = tag
test "$(git rev-parse HEAD)" = "$(git rev-parse "refs/tags/$tag^{commit}")"
test -z "$(git status --porcelain --untracked-files=normal)"
git -c gpg.format=ssh -c gpg.ssh.program=ssh-keygen \
    -c gpg.ssh.allowedSignersFile=/opt/licd-release/git-allowed-signers verify-tag "$tag"
