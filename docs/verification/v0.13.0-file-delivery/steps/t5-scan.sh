# T5: the final scan over everything captured, before the canary directory goes.
source "$(dirname "$0")/lib.sh"
say "T5"
run bash "$KIT/canary/scan-canary.sh" "$PATTERNS" transcript="$E/transcript.txt" evidence="$E" scan="$S/scan"
rc=$?; check T5 zero_hits $([ $rc = 0 ] && echo 1 || echo 0) "scan exit $rc"
echo "after recording: rm -rf \"\$CANARY\" \"$S/project\" \"$S/kubeconfig-opv-ci\" \"$S/scan\" (tmpfs), and exit the CI-like shell"
