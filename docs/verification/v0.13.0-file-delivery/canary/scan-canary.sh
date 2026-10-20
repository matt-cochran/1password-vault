#!/usr/bin/env bash
# Canary scan: counts canary hits in every captured output channel and artifact.
#
#   scan-canary.sh <patterns.txt> <label>=<file-or-dir> [<label>=<file-or-dir> ...]
#
# For each channel it prints `<label>: files=N lines=N hits=N`, and for a hit only
# `<file>:<line number>` (never the line, which would copy the canary into the record).
# The patterns are read from a file (grep -f), so no needle appears in any argv.
#
# Exit: 0 = every channel scanned, zero hits; 1 = at least one hit; 2 = the scan did not run
# properly (no patterns, the positive control failed, a channel missing or empty). A scan
# that did not run is never reported as a pass: v0.11.0's V16 first attempt failed silently.
set -u -o pipefail
P=${1:?usage: scan-canary.sh <patterns.txt> <label>=<path> ...}
shift
[ -s "$P" ] || { echo "scan: pattern file missing or empty" >&2; exit 2; }
n=$(grep -c . "$P")
# Positive control: the first pattern must hit itself, in memory only.
if [ "$(head -n 1 "$P" | grep -c -F -f "$P")" != 1 ]; then
  echo "scan: positive control failed (grep -F -f does not match)" >&2; exit 2
fi
echo "scan: $n patterns, positive control ok"
[ $# -gt 0 ] || { echo "scan: no channel given" >&2; exit 2; }
status=0
for arg in "$@"; do
  label=${arg%%=*}; path=${arg#*=}
  if [ ! -e "$path" ]; then echo "$label: MISSING ($path)"; status=2; continue; fi
  files=$(find "$path" -type f | wc -l)
  lines=$(find "$path" -type f -exec cat {} + 2>/dev/null | wc -l)
  if [ "$files" -eq 0 ]; then echo "$label: EMPTY (no file)"; status=2; continue; fi
  # -a: binary files (machine images, mixed logs) are scanned as text. -H always prints the
  # file name, so each hit is `file:line:text`; only `file:line` is kept.
  locs=$(grep -r -a -H -n -F -f "$P" "$path" 2>/dev/null | awk -F: '{print $1 ":" $2}')
  count=$(printf '%s' "$locs" | grep -c . || true)
  echo "$label: files=$files lines=$lines hits=$count"
  if [ "$count" -gt 0 ]; then
    printf '%s\n' "$locs" | sed 's/^/  hit at /'
    [ $status -eq 2 ] || status=1
  fi
done
case $status in
  0) echo "scan: PASS (zero hits)";;
  1) echo "scan: FAIL (hits above)";;
  2) echo "scan: DID NOT RUN COMPLETELY (see MISSING/EMPTY above)";;
esac
exit $status
