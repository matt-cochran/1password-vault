# A5-F5: canary scan of every A5 channel (fly logs of the kit machines only, machine
# configs, secrets list, probes, transcript). LIVE READ only.
source "$(dirname "$0")/lib.sh"; guard_app
say "A5-F5 collect"
while read -r id; do
  flysafe logs --machine "$id" --no-tail > "$E/a5/logs-$id.txt" 2>&1 || true
done < "$S/a5/machines"
flyq secrets list > "$E/a5/f5-secrets-list.json"
flyq machine list > "$S/scan/a5-machine-list.json"   # all machines' configs: scanned, not recorded
say "A5-F5 scan"
run bash "$KIT/canary/scan-canary.sh" "$PATTERNS" transcript="$E/transcript.txt" a5-captures="$E/a5" \
  fly-secrets-list="$E/a5/f5-secrets-list.json" fly-machine-list="$S/scan/a5-machine-list.json"
rc=$?; check A5-F5 zero_hits $([ $rc = 0 ] && echo 1 || echo 0) "scan exit $rc"
