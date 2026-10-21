# Preflight P10 (local only: no network, no 1Password, Fly or cluster call).
source "$(dirname "$0")/lib.sh"
say "P10: session layout and tools"
echo "scratch fs: $(stat -f -c %T "$S")  canary fs: $(stat -f -c %T "$CANARY")"
[ "$(stat -f -c %T "$CANARY")" = tmpfs ] || { echo "refused: CANARY is not on tmpfs"; exit 3; }
git -C "$S" rev-parse 2>/dev/null && { echo "refused: S is inside a git work tree"; exit 3; }
# kubectl: `version --client`, since plain `kubectl version` fails with no cluster, and under
# pipefail that printed MISSING after the version line (run 256debcd, P11).
tool_version() { case $1 in kubectl) kubectl version --client;; *) $1 --version 2>/dev/null || $1 version 2>/dev/null;; esac; }
for t in op flyctl kubectl kind docker jq gh script python3 cargo; do
  printf '%-8s %s\n' "$t" "$(if command -v "$t" >/dev/null; then tool_version "$t" | head -1; else echo MISSING; fi)"
done
say "P10: generator self-test, run id"
run python3 -I "$KIT/canary/gen-canary.py" --self-test
echo "run id: $(cat "$CANARY/run")  patterns: $(wc -l < "$PATTERNS")"
say "P10: the kit manifest loads with the release binary (no op on PATH, so nothing is read)"
run env -i PATH="$S/rel:/usr/bin:/bin" HOME="$S/cihome" OPV_NO_SKILL=1 "$OPV" target list --config "$PROJECT/secrets.toml"
