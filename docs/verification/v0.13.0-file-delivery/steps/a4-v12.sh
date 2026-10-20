# A4-V12 (CI-like): no fsGroup, so the sync is refused before any write.
source "$(dirname "$0")/lib.sh"; ci_only
say "A4-V12"
run "$OPV" sync verify-nofsgroup --deploy; rc=$?
n=$(kubectl -n jzverify get secret,configmap -l opv-managed=verify-nofsgroup -o name | wc -l)
check A4-V12 refused $([ $rc = 6 ] && echo 1 || echo 0) "exit $rc, expect mount_unreadable"
check A4-V12 nothing_written $([ "$n" = 0 ] && echo 1 || echo 0) "$n objects"
