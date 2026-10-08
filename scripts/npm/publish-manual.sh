#!/usr/bin/env bash
# Manual npm publish of one opv release, from the maintainer's machine (npm login + 2FA).
# Used while trusted publishing is off (the release workflow's npm job needs NPM_PUBLISH=true).
#
#   scripts/npm/publish-manual.sh v0.3.0
#
# Downloads the release binaries and SHA256SUMS with `gh`, verifies every checksum, builds
# the packages with scripts/npm/build.mjs, then publishes the six platform packages before
# @matthew-cochran/opv so its optionalDependencies exist. Safe to re-run: a package already
# published at this version is skipped.
set -euo pipefail

tag="${1:?usage: scripts/npm/publish-manual.sh vX.Y.Z}"
case "$tag" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "tag must look like v1.2.3: $tag" >&2; exit 2 ;; esac
version="${tag#v}"
repo="matt-cochran/1password-vault"
root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for tool in gh node npm sha256sum; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 3; }
done

echo "Downloading $tag release assets..."
gh release download "$tag" --repo "$repo" --dir "$work/dist" --pattern 'opv-*' --pattern SHA256SUMS
(cd "$work/dist" && sha256sum -c SHA256SUMS --ignore-missing --quiet)
echo "Checksums verified."

node "$root/scripts/npm/build.mjs" --version "$version" --assets "$work/dist" --out "$work/npm-dist"

if ! npm whoami >/dev/null 2>&1; then
  echo "Signing in to npm (enter your password and 2FA only at npm's prompts)..."
  npm login
fi
echo "npm user: $(npm whoami)"

for dir in "$work"/npm-dist/@matthew-cochran/opv-* "$work/npm-dist/opv"; do
  name="$(node -p "require('$dir/package.json').name")"
  # `npm view` prints nothing for a missing version, so compare its output.
  if [ "$(npm view "$name@$version" version 2>/dev/null)" = "$version" ]; then
    echo "skip     $name@$version (already published)"
    continue
  fi
  echo "publish  $name@$version"
  npm publish "$dir" --access public
done

echo
echo "Done. Check: npm view @matthew-cochran/opv version   and   npx @matthew-cochran/opv@$version --version"
