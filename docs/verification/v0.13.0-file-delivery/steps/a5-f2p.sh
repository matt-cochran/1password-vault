# A5-F2p: does --rootfs-persist keep the file on disk across a restart?
# Machine A gets --rootfs-persist always and a sentinel in /opt; the secret goes back to v1;
# then a restart. Sentinel present = the rootfs persisted. The file then reads v1 (rewritten
# at boot) or v2 (kept from disk, or not refreshed; compare with A5-F4 (b)).
# LIVE WRITE: updates/restarts machine A only; re-stages OPVCANARY_A5_FILE. Rollback: T1, T2.
source "$(dirname "$0")/lib.sh"; guard_app
id=$(head -1 "$S/a5/machines")
say "A5-F2p"
flysafe machine update "$id" --rootfs-persist always --skip-health-checks -y
sleep 10
flysafe machine exec "$id" "sh -c 'touch /opt/opvcanary-sentinel'"
flysafe secrets import --stage < "$CANARY/a5/import-v1"
flysafe machine restart "$id"
sleep 10; probe "$id" f2p-after-restart; a5_versions "$E/a5/f2p-after-restart.txt" | tee "$E/a5/f2p.txt"
grep sentinel "$E/a5/f2p-after-restart.txt"
echo "RECORD A5-F2p: sentinel present/absent; each path v1/v2/absent; interpret with the table in the runbook."
