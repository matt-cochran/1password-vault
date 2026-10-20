# A5-F2p: does --rootfs-persist keep the file on disk across a restart? Machine B gets
# --rootfs-persist always and a sentinel in /opt; then a restart. Same inode and mtime after
# the restart = the file was kept on disk; new ones = rewritten at boot.
# LIVE WRITE on the throwaway app only: updates and restarts machine B. Rollback: T2.
source "$(dirname "$0")/lib.sh"; guard_app
id=$(cat "$S/a5/machine-b")
say "A5-F2p"
flysafe machine update "$id" --rootfs-persist always --skip-health-checks -y
sleep 10
flysafe machine exec "$id" "sh -c 'touch /opt/opvcanary-sentinel'"
probe "$id" f2p-before >/dev/null
flysafe machine restart "$id"
sleep 10; probe "$id" f2p-after >/dev/null
for p in "${A5_PATHS[@]}"; do
  b=$(grep -F "$p: present" "$E/a5/f2p-before.txt" | grep -o 'inode=[0-9]* mtime=[0-9]*')
  a=$(grep -F "$p: present" "$E/a5/f2p-after.txt" | grep -o 'inode=[0-9]* mtime=[0-9]*')
  echo "$p: before[${b:-absent}] after[${a:-absent}] $([ -n "$b" ] && [ "$b" = "$a" ] && echo kept || echo rewritten-or-absent)"
done | tee "$E/a5/f2p.txt"
grep -h sentinel "$E/a5/f2p-after.txt" | tee -a "$E/a5/f2p.txt"
echo "RECORD A5-F2p: sentinel present/absent; per path kept / rewritten-or-absent."
