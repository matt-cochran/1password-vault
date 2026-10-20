#!/usr/bin/env bash
# Runs one step script under `script`, appending to the session transcript.
#   bash steps/rec.sh <step-script> [args]      e.g.  bash steps/rec.sh a4-v5.sh
set -u
: "${S:?}" "${REPO:?}"
KIT=$REPO/docs/verification/v0.13.0-file-delivery
mkdir -p "$S/evidence"
step=$1; shift
printf '\n##### %s %s\n' "$(date -u +%FT%TZ)" "$step" >> "$S/evidence/transcript.txt"
script -q -a -e -c "bash $KIT/steps/$step $*" "$S/evidence/transcript.txt"
rc=$?
printf '##### end %s exit=%s\n' "$step" "$rc" >> "$S/evidence/transcript.txt"
exit $rc
