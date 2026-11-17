#!/usr/bin/env bash
# Spike S1 for #338 (agent identity): the owner-only part.
#
# Run in your own terminal, signed in to 1Password:
#   bash docs/design/spike-338-owner.sh                 # create, probe, store, read back
#   bash docs/design/spike-338-owner.sh --after-reboot  # after `wsl --shutdown`: present/absent, then delete
#
# What it does (first run):
#   1. Creates ONE disposable read-only service account, opv-spike-338-<date>,
#      read_items on one vault you name, expiring in 1 hour.
#   2. Under that token, records names-only facts: whoami type and account, vault names and
#      count, whether `op item create` is refused, and `op service-account ratelimit`.
#   3. Stores the token in the candidate WSL store (Windows Credential Manager, reached through
#      WSL interop with powershell.exe; the value goes over stdin, never argv) and reads it back.
#      It prints only "match" or "no match".
#   4. Stores a fixed dummy (not the token) in the kernel user keyring @u, as the control.
#
# It never prints, logs or writes the token or any value. The token lives only in a shell
# variable, reaches `op` only as OP_SERVICE_ACCOUNT_TOKEN on single commands, and is unset on
# exit, including on error. Results (names only) go to docs/design/spike-338-owner-results.txt.
# It never deletes the service account: see the last lines it prints.

# PowerShell snippets are single-quoted on purpose: $pv and $c are PowerShell variables.
# shellcheck disable=SC2016

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS="$SCRIPT_DIR/spike-338-owner-results.txt"
WIN_RESOURCE="opv-spike-338"
WIN_USER="spike"
KEY_DESC="opv-spike-338:control"
DUMMY="spike-dummy-not-a-secret"

token=""
cleanup() {
  token=""
  unset token OP_SERVICE_ACCOUNT_TOKEN 2>/dev/null || true
}
trap cleanup EXIT
trap 'echo "spike-338: stopped by an error on line $LINENO (no value was printed)" >&2' ERR

# Mask the token and any token-shaped string in text before it is shown or recorded.
scrub() {
  local s="$1"
  if [ -n "${token:-}" ]; then s="${s//"$token"/[REDACTED]}"; fi
  printf '%s' "$s" | sed -E 's/ops_[A-Za-z0-9_+\/=-]{8,}/[REDACTED]/g; s/eyJ[A-Za-z0-9_-]{16,}/[REDACTED]/g'
}

rec() {
  local line
  line="$(scrub "$*")"
  printf '%s\n' "$line"
  printf '%s\n' "$line" >> "$RESULTS"
}

# Run one op command under the token only: no person session, no desktop-app integration.
# The token is set as an environment prefix of this one command (never argv).
op_sa() {
  (
    for v in $(compgen -e | grep -E '^(OP_SESSION|OP_CONNECT_|OP_ACCOUNT$)' || true); do unset "$v"; done
    OP_SERVICE_ACCOUNT_TOKEN="$token" OP_BIOMETRIC_UNLOCK_ENABLED=false OP_CACHE=false op "$@"
  )
}

ps_run() {
  # powershell.exe from /mnt/c avoids the UNC-path warning; the script text is fixed, no values in it.
  (cd /mnt/c && timeout 30 powershell.exe -NoProfile -NonInteractive -Command "$1") | tr -d '\r'
}

PS_LOAD='[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $pv=New-Object Windows.Security.Credentials.PasswordVault;'

win_present() {
  ps_run "$PS_LOAD"' try { [void]$pv.Retrieve("'"$WIN_RESOURCE"'","'"$WIN_USER"'"); "present" } catch { "absent" }' 2>/dev/null || echo "error"
}
win_delete() {
  ps_run "$PS_LOAD"' try { $pv.Remove($pv.Retrieve("'"$WIN_RESOURCE"'","'"$WIN_USER"'")); "deleted" } catch { "nothing to delete" }' 2>/dev/null || echo "error"
}

# ---------------------------------------------------------------- --after-reboot
if [ "${1:-}" = "--after-reboot" ]; then
  rec ""
  rec "== after reboot, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  rec "uptime_since: $(uptime -s)"
  rec "windows_credential_manager_entry: $(win_present)"
  if command -v keyctl >/dev/null 2>&1; then
    if keyctl search @u user "$KEY_DESC" >/dev/null 2>&1; then rec "kernel_user_keyring_control: present"; else rec "kernel_user_keyring_control: absent"; fi
    id="$(keyctl search @u user "$KEY_DESC" 2>/dev/null || true)"
    if [ -n "$id" ]; then keyctl invalidate "$id" >/dev/null 2>&1 || true; fi
  else
    rec "kernel_user_keyring_control: skipped (keyctl not installed)"
  fi
  rec "windows_credential_manager_cleanup: $(win_delete)"
  echo
  echo "Done. Results appended to $RESULTS"
  echo "If you have not yet removed the disposable service account: 1Password web app >"
  echo "Developer > Service accounts > opv-spike-338-... > Delete (op cannot delete service accounts)."
  exit 0
fi

# ---------------------------------------------------------------- first run
command -v op >/dev/null || { echo "op is not on PATH" >&2; exit 1; }
command -v powershell.exe >/dev/null || { echo "powershell.exe not reachable: WSL interop is off" >&2; exit 1; }
if ! op whoami >/dev/null 2>&1; then
  echo "Sign in to 1Password first (op signin, or unlock the desktop app), then run this again." >&2
  exit 1
fi

read -r -p "Account to use (shorthand or sign-in address; Enter for the default): " account
read -r -p "Vault to grant read_items on (name or id; not Private): " vault
[ -n "$vault" ] || { echo "a vault is required" >&2; exit 1; }
acct_args=()
if [ -n "$account" ]; then acct_args=(--account "$account"); fi

name="opv-spike-338-$(date +%Y%m%d-%H%M)"
: > "$RESULTS"
rec "# spike-338 owner results (names only; no token, no value)"
rec "== first run, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
rec "op_version: $(op --version)"
rec "wsl_kernel: $(uname -r)"
rec "uptime_since: $(uptime -s)"
rec "service_account_name: $name"
rec "granted_vault: $vault (read_items)"

# Person session facts: how the Private vault is addressed (names and types only).
rec "person_vault_types: $(op vault list "${acct_args[@]}" --format json 2>/dev/null | jq -r '[.[] | (.type // "unknown")] | group_by(.) | map("\(.[0])=\(length)") | join(", ")' 2>/dev/null || echo unknown)"
rec "person_private_vault_names: $(op vault list "${acct_args[@]}" --format json 2>/dev/null | jq -r '[.[] | select((.type // "") | test("PERSONAL|PRIVATE";"i")) | .name] | join(", ")' 2>/dev/null || echo unknown)"

# Create. --raw prints only the token; it goes straight into the variable.
set +e
token="$(op service-account create "$name" "${acct_args[@]}" --vault "$vault:read_items" --expires-in 1h --raw 2>/dev/null)"
rc=$?
set -e
if [ $rc -ne 0 ] || [ -z "$token" ]; then
  token=""
  rec "create: FAILED (exit $rc). Nothing was stored. Check in the web app whether $name exists."
  exit 1
fi
rec "create: ok (expires in 1h)"

# Facts under the token only.
set +e
w="$(op_sa whoami --format json 2>&1)"; rc=$?
set -e
if [ $rc -eq 0 ]; then
  rec "sa_whoami_user_type: $(printf '%s' "$w" | jq -r '.user_type // .type // "unknown"')"
  rec "sa_whoami_account_uuid: $(printf '%s' "$w" | jq -r '.account_uuid // "unknown"')"
  rec "sa_whoami_url: $(printf '%s' "$w" | jq -r '.url // "unknown"')"
else
  rec "sa_whoami: FAILED (exit $rc): $(printf '%s' "$w" | head -n 2)"
fi

set +e
vl="$(op_sa vault list --format json 2>&1)"; rc=$?
set -e
if [ $rc -eq 0 ]; then
  rec "sa_vault_count: $(printf '%s' "$vl" | jq 'length')"
  rec "sa_vault_names: $(printf '%s' "$vl" | jq -r '[.[].name] | join(", ")')"
else
  rec "sa_vault_list: FAILED (exit $rc): $(printf '%s' "$vl" | head -n 2)"
fi

# Read-only proof: an empty secure note, no value in argv.
set +e
ic="$(op_sa item create --vault "$vault" --category "Secure Note" --title "opv-spike-338-readonly-probe" 2>&1)"; rc=$?
set -e
if [ $rc -ne 0 ]; then
  rec "sa_item_create: refused (exit $rc): $(printf '%s' "$ic" | grep -v '^$' | head -n 2 | tr '\n' ' ')"
else
  rec "sa_item_create: NOT REFUSED. An empty note opv-spike-338-readonly-probe was created in $vault; delete it."
fi

set +e
rl="$(op_sa service-account ratelimit 2>&1)"; rc=$?
set -e
rec "sa_ratelimit_no_argument: exit $rc"
while IFS= read -r line; do rec "  ratelimit| $line"; done <<< "$rl"
set +e
rlj="$(op_sa service-account ratelimit --format json 2>&1)"; rc=$?
set -e
rec "sa_ratelimit_json: exit $rc, keys: $(printf '%s' "$rlj" | jq -r '[.[0] | keys[]] | join(",")' 2>/dev/null || echo n/a)"

# Candidate store: Windows Credential Manager through interop. Value over stdin only.
set +e
st="$(printf '%s' "$token" | ps_run "\$v=[Console]::In.ReadToEnd(); $PS_LOAD"' $pv.Add((New-Object Windows.Security.Credentials.PasswordCredential("'"$WIN_RESOURCE"'","'"$WIN_USER"'",$v))); Remove-Variable v; "stored"' 2>&1)"
set -e
rec "windows_credential_manager_store: $(printf '%s' "$st" | tail -n 1)"
t0=$(date +%s%N)
set +e
back="$(ps_run "$PS_LOAD"' $c=$pv.Retrieve("'"$WIN_RESOURCE"'","'"$WIN_USER"'"); $c.RetrievePassword(); [Console]::Out.Write($c.Password)' 2>/dev/null)"
set -e
ms=$(( ($(date +%s%N) - t0) / 1000000 ))
if [ -n "$back" ] && [ "$back" = "$token" ]; then rec "windows_credential_manager_readback: match (${ms} ms)"; else rec "windows_credential_manager_readback: no match (${ms} ms)"; fi
back=""; unset back

# Control: kernel user keyring @u, with a fixed dummy (volatility does not depend on the value).
if command -v keyctl >/dev/null 2>&1; then
  printf '%s' "$DUMMY" | keyctl padd user "$KEY_DESC" @u >/dev/null
  if [ "$(keyctl pipe "$(keyctl search @u user "$KEY_DESC")" 2>/dev/null)" = "$DUMMY" ]; then
    rec "kernel_user_keyring_control: stored and read back (dummy)"
  else
    rec "kernel_user_keyring_control: store failed"
  fi
else
  rec "kernel_user_keyring_control: skipped (keyctl not installed; 'sudo apt install keyutils' adds it)"
fi

token=""; unset token

echo
echo "Results (names only) are in $RESULTS"
echo
echo "Next, the reboot check:"
echo "  1. In Windows (PowerShell or cmd), run:   wsl --shutdown"
echo "  2. Open a new WSL terminal and run:       bash $SCRIPT_DIR/spike-338-owner.sh --after-reboot"
echo "     It prints only 'present' or 'absent' per store, then deletes the entries."
echo
echo "Then delete the disposable service account (op cannot delete service accounts):"
echo "  1Password web app > Developer > Service accounts > $name > Delete."
echo "  It also expires on its own one hour after creation."
