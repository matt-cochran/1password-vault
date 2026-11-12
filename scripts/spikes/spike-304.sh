#!/usr/bin/env bash
# Spike #304: record what 1Password shows about a service account's grants.
# See docs/design/spike-304-findings.md for the questions this answers.
#
# Usage (signed in to 1Password as yourself first: eval "$(op signin)"):
#   scripts/spikes/spike-304.sh <account ID or sign-in address>
#
# It creates two throwaway vaults and a service account that can read only the first and
# expires in one day, records six op replies, deletes both vaults on exit, scrubs every
# identifier and copies the scrubbed replies into tests/fixtures/op/success/. The service
# account token lives only in a shell variable of this process: it is never printed, passed as
# an argument or written to a file. opv cannot delete a service account, so the script ends by
# telling you to revoke it in 1Password.
set -euo pipefail
set +x
umask 077

A=${1:?usage: $0 <account ID or sign-in address>}
root=$(cd "$(dirname "$0")/../.." && pwd)
dest="$root/tests/fixtures/op/success"
for tool in op python3; do command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 3; }; done
op whoami --account "$A" --format json </dev/null >/dev/null 2>&1 || {
  echo "not signed in to $A: run  eval \"\$(op signin --account $A)\"  first" >&2; exit 4; }

out=$(mktemp -d); cd "$out"
suffix=$(date +%Y%m%d%H%M%S)
VA=""; VB=""; T=""
cleanup() {
  T=""; unset T OP_SERVICE_ACCOUNT_TOKEN
  for v in "$VA" "$VB"; do
    [ -n "$v" ] && { op vault delete "$v" --account "$A" </dev/null >/dev/null 2>&1 && echo "deleted vault $v" || echo "could not delete vault $v: delete it in 1Password" >&2; }
  done
  echo
  echo "Revoke the service account opv-spike-304-$suffix in 1Password (Developer > Service accounts)."
  echo "Raw replies (unscrubbed, private to you): $out  (rm -rf it when done)"
}
trap cleanup EXIT

# rec NAME cmd...: stdout, stderr and the exit code of one call, stdin closed, never aborting.
rec() { local n=$1; shift; if "$@" </dev/null >"$n.stdout" 2>"$n.stderr"; then echo 0 >"$n.exit"; else echo $? >"$n.exit"; fi; echo "$n exit $(cat "$n.exit")"; }
id_of() { python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])'; }

echo "== set up (owner session)"
VA=$(op vault create "opv-spike-304-a-$suffix" --account "$A" --format json </dev/null | id_of)
VB=$(op vault create "opv-spike-304-b-$suffix" --account "$A" --format json </dev/null | id_of)
echo "created two throwaway vaults"
T=$(op service-account create "opv-spike-304-$suffix" --account "$A" --vault "$VA:read_items" --expires-in 1d --raw </dev/null)
[ -n "$T" ] || { echo "service account creation printed no token" >&2; exit 5; }
echo "created service account opv-spike-304-$suffix (read_items on vault a only)"

echo "== record"
# Under the token: its own view. OP_SERVICE_ACCOUNT_TOKEN reaches op through its environment only.
OP_SERVICE_ACCOUNT_TOKEN="$T" rec s30-whoami-service-account op whoami --format json
OP_SERVICE_ACCOUNT_TOKEN="$T" rec s31-vault-list-service-account op vault list --format json
SA_USER=$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("user_uuid") or d.get("id") or "")' s30-whoami-service-account.stdout 2>/dev/null || true)
# In the owner session: the owner's view of the same grants.
rec s32-vault-user-list-granted op vault user list "$VA" --account "$A" --format json
rec s33-vault-user-list-other op vault user list "$VB" --account "$A" --format json
# F17: can a grant be added after creation?
if [ -n "$SA_USER" ]; then
  rec s34-grant-after-create op vault user grant --vault "$VB" --user "$SA_USER" --permissions read_items --account "$A" --format json
else
  echo "whoami named no user id; recording that instead of a grant" >s34-grant-after-create.stderr; : >s34-grant-after-create.stdout; echo 99 >s34-grant-after-create.exit
fi
OP_SERVICE_ACCOUNT_TOKEN="$T" rec s35-vault-list-after-grant op vault list --format json
T=""; unset T

echo "== scrub"
# A token must never appear anywhere, raw or scrubbed.
if grep -l -E 'ops_[A-Za-z0-9_-]{20,}' ./* >/dev/null 2>&1; then echo "a token-shaped string was recorded: not copying anything" >&2; exit 6; fi
cat >scrub.py <<'EOF'
import json, sys, pathlib
KEYS = {"id": "ID", "account_uuid": "ACCOUNT", "user_uuid": "USER", "email": "EMAIL",
        "url": "ADDRESS", "shorthand": "SHORTHAND", "name": "NAME", "title": "TITLE",
        "tags": "TAG", "additional_information": "INFO", "description": "DESCRIPTION",
        "created_at": "TIME", "updated_at": "TIME", "last_edited_by": "USER"}
seen = {v: f"<{k}>" for k, v in (a.split("=", 1) for a in sys.argv[1:])}
count = {}
def mark(kind, v):
    if v not in seen:
        count[kind] = count.get(kind, 0) + 1
        seen[v] = f"<{kind}_{count[kind]}>"
def walk(x, key=None):
    if isinstance(x, dict):
        for k, v in x.items(): walk(v, k)
    elif isinstance(x, list):
        for v in x: walk(v, key)
    elif isinstance(x, str) and key in KEYS and x:
        mark(KEYS[key], x)
for f in sorted(pathlib.Path(".").glob("s3*.stdout")):
    t = f.read_text()
    if t.strip():
        try: walk(json.loads(t))
        except json.JSONDecodeError: pass
for f in sorted(pathlib.Path(".").glob("s3*.std*")):
    if f.suffix == ".scrubbed": continue
    t = f.read_text()
    for v in sorted(seen, key=len, reverse=True):
        t = t.replace(json.dumps(v, ensure_ascii=False)[1:-1], seen[v])
    f.with_suffix(f.suffix + ".scrubbed").write_text(t)
print(len(seen), "values replaced")
EOF
python3 -I scrub.py "ACCOUNT_2=$A" "VAULT_A=$VA" "VAULT_B=$VB" ${SA_USER:+"SERVICE_ACCOUNT_USER=$SA_USER"}
left=$(grep -l -i -E "@|1password\.(com|eu|ca)|[A-Z0-9]{26}|ops_|$VA|$VB" ./*.scrubbed || true)
if [ -n "$left" ]; then echo "identifiers left in: $left (not copied; inspect $out)" >&2; exit 7; fi
echo "no identifiers left"

for f in ./*.scrubbed; do b=$(basename "$f" .scrubbed); cp "$f" "$dest/$b"; done
cp ./s3*.exit "$dest/"
n=0; for _ in ./*.scrubbed; do n=$((n+1)); done; echo "copied $n scrubbed replies and their exit codes to tests/fixtures/op/success/"

echo "== scrubbed replies (for the findings table)"
for n in s30-whoami-service-account s31-vault-list-service-account s32-vault-user-list-granted s33-vault-user-list-other s34-grant-after-create s35-vault-list-after-grant; do
  echo "--- $n (exit $(cat "$dest/$n.exit"))"; head -c 1500 "$dest/$n.stdout"; head -c 600 "$dest/$n.stderr"; echo
done
