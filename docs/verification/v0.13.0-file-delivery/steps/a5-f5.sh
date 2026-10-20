# A5-F5: canary scan of every A5 channel. The app holds canaries only, so its whole log is
# captured. LIVE READ only.
source "$(dirname "$0")/lib.sh"; guard_app
say "A5-F5 collect"
flysafe logs --no-tail > "$E/a5/logs-app.txt" 2>&1 || true
flyq secrets list > "$E/a5/f5-secrets-list.json"
flyq machine list > "$E/a5/f5-machine-list.json"
flyq releases > "$E/a5/f5-releases.json"
say "A5-F5 scan"
run bash "$KIT/canary/scan-canary.sh" "$PATTERNS" transcript="$E/transcript.txt" a5-captures="$E/a5" \
  fly-secrets-list="$E/a5/f5-secrets-list.json" fly-machine-list="$E/a5/f5-machine-list.json"
rc=$?; check A5-F5 zero_hits $([ $rc = 0 ] && echo 1 || echo 0) "scan exit $rc"
