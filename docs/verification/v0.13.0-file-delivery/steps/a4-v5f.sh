# A4-V5f (CI-like): sync the canaries to the throwaway app as CI does, staged (no --deploy:
# the app has no machine yet; A5-F1's deploy and A5-F4's secrets deploy later carry them).
# LIVE WRITE on the throwaway app only: 7 staged secrets. Rollback: T2 (app destroyed).
source "$(dirname "$0")/lib.sh"; ci_only; guard_app
say "A4-V5f"
sampled v5f "$OPV" sync verify-fly --expect-plan "$(cat "$E/plan-verify-fly.id")" --receipt "$E/receipt-verify-fly.json"
rc=$?; check A4-V5f sync_staged $([ $rc = 0 ] && echo 1 || echo 0) "exit $rc; expect pending-deploy lines"
flyq secrets list | jq '[.[]|select(.name|startswith("OPVCANARY__"))]' > "$E/v5f-fly-secrets.json"
jq -r '.[]|"\(.name) \(.status)"' "$E/v5f-fly-secrets.json"
check A4-V5f all_staged $(jq -e 'all(.[]; .status=="Staged")' "$E/v5f-fly-secrets.json" >/dev/null && echo 1 || echo 0)
n=$(declared_keys verify-fly serve | wc -l)  # was a fixed 7 (`seven_names`); the manifest declares 8
check A4-V5f declared_names $([ "$(jq length "$E/v5f-fly-secrets.json")" = "$n" ] && echo 1 || echo 0) "$n names: the manifest's serve keys for verify-fly, LOG_LEVEL included"
run "$OPV" status verify-fly | tee "$E/v5f-status.txt"
