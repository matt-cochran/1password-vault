# A5-F0 (CI-like; the token is scoped to the throwaway app): the empty app, then the canary
# file secret. LIVE WRITE on the throwaway app only: secret OPVCANARY_A5_FILE (base64 of a
# canary, on stdin). Rollback: T2 (the app is destroyed).
source "$(dirname "$0")/lib.sh"; guard_app
say "A5-F0 the app is empty: no machines, no IPs"
flyq machine list | jq 'length' | sed 's/^/machines: /'
flyq ips list | jq 'length' | sed 's/^/ips: /'
say "A5-F0 stage the canary file secret (deployed by the A5-F1 deploy)"
flysafe secrets import --stage < "$CANARY/a5/import-v1"
flyq secrets list | jq '[.[]|select(.name=="OPVCANARY_A5_FILE")]' | tee "$E/a5-f0-secret.json"
check A5-F0 staged $(jq -e 'length==1' "$E/a5-f0-secret.json" >/dev/null && echo 1 || echo 0)
