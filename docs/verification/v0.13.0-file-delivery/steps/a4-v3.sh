# A4-V3 (CI-like): before any sync, `changed` has no record. Reads 1Password and the cluster.
source "$(dirname "$0")/lib.sh"; ci_only
say "A4-V3"
run "$OPV" changed verify --json > "$E/v3-changed-verify.json"; rc=$?
cat "$E/v3-changed-verify.json"
check A4-V3 exit10 $([ $rc = 10 ] && echo 1 || echo 0) "exit $rc"
check A4-V3 no_record $(grep -q no_record "$E/v3-changed-verify.json" && echo 1 || echo 0)
