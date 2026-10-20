# A4-V5f (CI-like): sync the canaries to the LIVE staging fleet app, WITHOUT --deploy.
# LIVE WRITE: staged Fly secrets OPVCANARY__JOURNEEZE__* (values on stdin; no deploy, no
# restart). Rollback: T2 (flyctl secrets unset --stage of those names).
source "$(dirname "$0")/lib.sh"; ci_only; guard_app
say "A4-V5f"
sampled v5f "$OPV" sync verify-fly --expect-plan "$(cat "$E/plan-verify-fly.id")" --receipt "$E/receipt-verify-fly.json"
rc=$?; check A4-V5f sync_staged $([ $rc = 0 ] && echo 1 || echo 0) "exit $rc; expect pending-deploy lines, no deploy"
flyq secrets list | jq '[.[]|select(.name|startswith("OPVCANARY"))]' > "$E/v5f-fly-secrets.json"
echo "staged canary names: $(jq length "$E/v5f-fly-secrets.json")"; jq -r '.[]|.name' "$E/v5f-fly-secrets.json"
check A4-V5f all_staged $(jq -e 'all(.[]; .status=="Staged")' "$E/v5f-fly-secrets.json" >/dev/null && echo 1 || echo 0) "status Staged, never Deployed"
check A4-V5f seven_names $([ "$(jq length "$E/v5f-fly-secrets.json")" = 7 ] && echo 1 || echo 0) "6 secrets + LOG_LEVEL"
flyq releases | jq 'max_by(.Version)|{Version,Status,CreatedAt}' > "$E/v5f-release.json"
check A4-V5f no_new_release $(cmp -s "$E/v5f-release.json" "$S/a5/baseline-release.json" && echo 1 || echo 0)
run "$OPV" status verify-fly | tee "$E/v5f-status.txt"
