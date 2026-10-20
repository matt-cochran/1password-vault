# A4-V11f (CI-like): drift on the Fly leg. LIVE WRITE on the throwaway app only: re-stages one
# canary name with the literal "tampered", then opv restores the canary. Rollback: T2.
source "$(dirname "$0")/lib.sh"; ci_only; guard_app
say "A4-V11f"
printf 'OPVCANARY__JOURNEEZE__LOG_LEVEL=tampered\n' | flysafe secrets import --stage
run "$OPV" status verify-fly --fail-on-drift; rc=$?
check A4-V11f drift_detected $([ $rc = 8 ] && echo 1 || echo 0) "exit $rc [UNSURE: Fly shows a staged digest; opv may report pending instead of drift]"
sampled v11f "$OPV" sync verify-fly; rc=$?
run "$OPV" status verify-fly --fail-on-drift; rc2=$?
check A4-V11f restored $([ $rc = 0 ] && [ $rc2 = 0 ] && echo 1 || echo 0) "sync $rc, status $rc2"
