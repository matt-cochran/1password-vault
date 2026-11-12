#!/usr/bin/env bash
# Manual npm publish of one opv release, from the maintainer's machine (npm login + 2FA).
# A fallback: releases publish to npm from the release workflow through trusted publishing
# (NPM_PUBLISH=true). Use this when that job is off or fails.
#
#   git checkout v0.20.1 && scripts/npm/publish-manual.sh v0.20.1
#
# Refuses unless the tag's qualified release candidate verifies (#295). It publishes the
# retained, qualified npm tarballs exactly as the release workflow does, never a rebuild:
#   1. the retained staging artifact `opv-release-<tree>-<attempt>` of this tag's tree
#      (`release-assets.ts check`), or, once that has expired (90 days), the same files
#      from the GitHub release, whose manifest.json must carry the release workflow's
#      build-provenance attestation;
#   2. `release-assets.ts verify`: the successful staging run, the tree, the six platform
#      qualifications and every file's digest; a missing or extra file fails;
#   3. `release-assets.ts publish`: identical published bytes are skipped, different bytes
#      refused, and the main package is published only after npm lists every platform
#      package. Locally npm is not asked for provenance (that needs the CI OIDC token).
# Safe to re-run.
set -euo pipefail

tag="${1:?usage: scripts/npm/publish-manual.sh vX.Y.Z}"
case "$tag" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "tag must look like v1.2.3: $tag" >&2; exit 2 ;; esac
repo="matt-cochran/1password-vault"
root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for tool in gh git node npm; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 3; }
done

# The verification binds the candidate to this checkout's tree and runs this checkout's
# scripts, so the checkout must be the tag, unmodified.
if [ "$(git -C "$root" describe --tags --exact-match 2>/dev/null)" != "$tag" ]; then
  echo "check out $tag first (git checkout $tag): the candidate is verified against this checkout" >&2
  exit 4
fi
if ! git -C "$root" diff --quiet HEAD --; then
  echo "the checkout has local changes: verify from a clean $tag checkout" >&2
  exit 4
fi

assets() { (cd "$root" && GITHUB_REPOSITORY="$repo" GITHUB_OUTPUT="$work/outputs" node scripts/release-assets.ts "$@"); }
candidate="$work/candidate"

echo "Looking for the retained qualified candidate of $tag..."
: >"$work/outputs"
assets check "$candidate"
if grep -qx 'found=true' "$work/outputs"; then
  echo "Using the retained staging artifact."
else
  echo "No retained artifact (expired after 90 days?); reading the evidence from the $tag GitHub release..."
  rm -rf "$candidate"
  gh release download "$tag" --repo "$repo" --dir "$work/release"
  assets assemble "$candidate" "$work/release"
  [ -f "$candidate/manifest.json" ] || { echo "the $tag release carries no manifest.json: nothing qualified to publish" >&2; exit 5; }
  gh attestation verify "$candidate/manifest.json" --repo "$repo" \
    --signer-workflow "$repo/.github/workflows/release.yml" --source-ref "refs/tags/$tag" >/dev/null \
    || { echo "the $tag manifest.json has no valid release-workflow attestation: refusing" >&2; exit 5; }
fi

assets verify "$candidate" || { echo "the $tag candidate did not verify: refusing to publish" >&2; exit 5; }
echo "Verified: staging run, tree, six platform qualifications and every file digest."

if ! npm whoami >/dev/null 2>&1; then
  echo "Signing in to npm (enter your password and 2FA only at npm's prompts)..."
  npm login
fi
echo "npm user: $(npm whoami)"

# The retained bytes are published as they are: no npm lifecycle scripts run here.
(cd "$root" && NPM_CONFIG_IGNORE_SCRIPTS=true node scripts/release-assets.ts publish "$candidate")

echo
echo "Done. Check: npm view @matthew-cochran/opv version   and   npx @matthew-cochran/opv@${tag#v} --version"
