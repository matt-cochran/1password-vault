# A4-V5 (CI-like): sync the reviewed plan to the kind cluster and deploy. Writes: the LOCAL
# kind cluster only (Secrets, ConfigMap, Deployment). Rollback: A4-V17.
source "$(dirname "$0")/lib.sh"; ci_only
say "A4-V5"
sampled v5 "$OPV" sync verify --deploy --expect-plan "$(cat "$E/plan-verify.id")" --receipt "$E/receipt-verify.json"
rc=$?; check A4-V5 sync $([ $rc = 0 ] && echo 1 || echo 0) "exit $rc"
