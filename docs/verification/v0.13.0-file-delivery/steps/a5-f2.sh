# A5-F2: where does the file land (RAM or disk), with what mode and owner? Reads the probes
# A5-F1 took on both machines. Writes nothing.
source "$(dirname "$0")/lib.sh"; guard_app
say "A5-F2"
for m in a b; do echo "--- machine $m"; grep -E '^/|^mount|^env|^PROBE FAILED' "$E/a5/f1-probe-$m.txt"; done | tee "$E/a5/f2.txt"
ram=$(grep -E '^/dev/shm/opvcanary/a5-file: fs=tmpfs' "$E/a5/f2.txt" | wc -l)
echo "machines with the /dev/shm file on tmpfs: $ram of 2"
echo "RECORD A5-F2: per machine and path: present/absent, fs, mountpoint, mode, owner, dir mode; the env line. Read with the table in the runbook."
