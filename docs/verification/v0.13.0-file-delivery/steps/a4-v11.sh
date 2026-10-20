# A4-V11 (CI-like; the tamper uses the admin context): drift is detected, then restored.
# Writes: the LOCAL kind cluster only.
source "$(dirname "$0")/lib.sh"; ci_only
say "A4-V11"
run env KUBECONFIG="$ADMIN_KUBECONFIG" kubectl -n jzverify set env deployment/jzverify -c journeeze LOG_LEVEL=tampered
run "$OPV" status verify --fail-on-drift; rc=$?
check A4-V11 status_drift $([ $rc = 8 ] && echo 1 || echo 0) "exit $rc, expect target_drift"
run "$OPV" delivery verify verify --json > "$E/v11-delivery.json"; rc=$?; cat "$E/v11-delivery.json"
check A4-V11 delivery_unverified $([ $rc = 8 ] && echo 1 || echo 0) "exit $rc"
sampled v11 "$OPV" sync verify --deploy; rc=$?
run "$OPV" status verify --fail-on-drift; rc2=$?
check A4-V11 restored $([ $rc = 0 ] && [ $rc2 = 0 ] && echo 1 || echo 0) "sync $rc, status $rc2"
