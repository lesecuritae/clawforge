#!/usr/bin/env bash
set -Eeuo pipefail

version="${1:-$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')}"
tag="v${version#v}"
expected="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')"
test "$version" = "$expected" || { echo "requested version $version does not match Cargo version $expected" >&2; exit 1; }
test -z "$(git status --porcelain)" || { echo "working tree must be clean before tagging" >&2; exit 1; }
git rev-parse "$tag" >/dev/null 2>&1 && { echo "tag already exists: $tag" >&2; exit 1; }
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
git tag -a "$tag" -m "Clawforge $version"
echo "created $tag; push it with: git push origin $tag"
