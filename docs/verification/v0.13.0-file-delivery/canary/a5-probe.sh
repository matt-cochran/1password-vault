# Runs INSIDE the one-off machine (sent base64-encoded through `flyctl machine exec`).
# Prints metadata and digests only: never the file's content, never the environment.
for p in /dev/shm/opvcanary/a5-file /run/opvcanary/a5-file /opt/opvcanary/a5-file; do
  if [ -e "$p" ]; then
    echo "$p: present $(stat -c 'mode=%a owner=%U:%G size=%s' "$p") sha256=$(sha256sum "$p" | cut -d' ' -f1)"
    echo "$p: fs=$(df -T "$p" | awk 'NR==2{print $2}') mountpoint=$(df -T "$p" | awk 'NR==2{print $7}') dir=$(stat -c 'mode=%a owner=%U:%G' "$(dirname "$p")")"
  else
    echo "$p: absent"
  fi
done
awk '{for(i=7;i<=NF;i++) if($i=="-"){print "mount", $5, "fstype=" $(i+1); break}}' /proc/self/mountinfo | grep -E ' (/|/dev/shm|/run|/opt|/tmp) '
if printenv OPVCANARY_A5_FILE >/dev/null; then echo "env OPVCANARY_A5_FILE: present"; else echo "env OPVCANARY_A5_FILE: absent"; fi
if [ -e /opt/opvcanary-sentinel ]; then echo "sentinel: present"; else echo "sentinel: absent"; fi
echo "uptime_s=$(cut -d. -f1 /proc/uptime) boot_id=$(cat /proc/sys/kernel/random/boot_id)"
