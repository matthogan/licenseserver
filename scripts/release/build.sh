#!/usr/bin/env bash
set -euo pipefail
tag=${CI_COMMIT_TAG:?Release candidates require a tag pipeline}
bash scripts/release/check-tag.sh "$tag"
python3 -m unittest discover -s scripts/release -p 'test_*.py'
commit=$(git rev-parse HEAD)
test -z "${CI_COMMIT_SHA:-}" || test "$CI_COMMIT_SHA" = "$commit"
for required_test in TestRepositoryContract TestRealLitestreamConfiguration; do
    grep -q -- "^--- PASS: $required_test " .ci-results/tests.log
done

destination="/releases/$tag"
test ! -e "$destination" || { echo "Release candidate already exists: $tag (never overwritten)." >&2; exit 1; }
builder="licd-release-${CI_PIPELINE_NUMBER:-local}-$$"
staging=
cleanup() {
    docker buildx rm "$builder" >/dev/null 2>&1 || true
    if [ -n "$staging" ]; then rm -rf -- "$staging"; fi
}
trap cleanup EXIT

# All tests already passed in the preceding pipeline step. No publishing/signing credentials.
goreleaser check
goreleaser release --clean --skip=publish,sign,before
test -z "$(git status --porcelain --untracked-files=normal)"
date=$(git show -s --format=%cI HEAD)
platforms=$(python3 -c 'import json; print(",".join(json.load(open("/opt/licd-release/policy.json"))["platforms"]))')
docker buildx create --name "$builder" --driver docker-container
docker buildx build --builder "$builder" --platform "$platforms" \
    --build-arg "VERSION=${tag#v}" --build-arg "COMMIT=$commit" --build-arg "BUILD_DATE=$date" \
    --label "org.opencontainers.image.revision=$commit" \
    --label "org.opencontainers.image.version=$tag" \
    --provenance=mode=max --sbom=true \
    --metadata-file dist/container-build.json \
    --output "type=oci,dest=dist/licenceserver_${tag}_container.oci.tar" .

cp .ci-results/tests.log dist/tests.log
bash scripts/release/check-tag.sh "$tag" >dist/tag-verification.txt 2>&1
git cat-file tag "refs/tags/$tag" >dist/source-tag.txt
python3 scripts/release/bundle.py prepare dist --tag "$tag" --commit "$commit"
python3 scripts/release/bundle.py verify dist --tag "$tag" --commit "$commit"

# Publish only to a local Docker volume, atomically and without replacing a tag.
staging=$(mktemp -d "/releases/.${tag}.XXXXXX")
python3 scripts/release/bundle.py copy dist "$staging"
test ! -e "$destination"
mv -Tn "$staging" "$destination"
test ! -d "$staging" || { echo 'Another candidate already exists; refusing to overwrite it.' >&2; exit 1; }
staging=
echo "Release candidate saved in Docker volume licd-release-candidates: $tag"
echo 'Next: export and sign it on the release owner PC. Nothing was uploaded.'
