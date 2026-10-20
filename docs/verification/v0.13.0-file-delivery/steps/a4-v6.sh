# A4-V6 (CI-like): after the sync nothing has changed (verify; verify-fly once A4-V5f ran).
source "$(dirname "$0")/lib.sh"; ci_only
for env in verify ${1:-}; do
  say "A4-V6 $env"
  run "$OPV" changed "$env"; rc=$?
  check A4-V6 "unchanged-$env" $([ $rc = 0 ] && echo 1 || echo 0) "exit $rc"
done
