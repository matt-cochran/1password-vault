# T2 (person, the owner's own flyctl login): revoke the session token, then destroy the
# throwaway app. LIVE WRITE: deletes the app, its machines and its secrets.
source "$(dirname "$0")/lib.sh"; person_only; guard_app
say "T2 revoke the token opv-136-live"
flyctl tokens list -a "$FLY_APP"
read -rp "id of the token named opv-136-live: " tid
run flyctl tokens revoke "$tid"
say "T2 destroy $FLY_APP"
read -rp "type the app name to destroy it: " typed
[ "$typed" = "$FLY_APP" ] || { echo "refused: the typed name differs"; exit 3; }
run flyctl apps destroy "$FLY_APP" --yes
say "T2 the app is gone"
flyctl apps list --json | jq -r '.[]|(.Name // .name)' | grep -qx "$FLY_APP"; gone=$?
check T2 app_gone $([ $gone = 1 ] && echo 1 || echo 0)
