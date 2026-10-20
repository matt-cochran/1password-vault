# A5-F2: one-off machine A with the canary file at three paths; where does it land?
# LIVE WRITE: creates machine opvcanary-a5-a in the staging fleet app (no services, no DNS,
# restart=no, stops itself after 90 min). It also receives EVERY app secret as env (Fly
# design), so nothing in the kit ever prints its environment. Rollback: T1 (destroy).
source "$(dirname "$0")/lib.sh"; guard_app
say "A5-F2 machine A"
mapfile -t fs < <(a5_file_secret_flags)
flysafe machine run "$IMAGE_A5" sleep 5400 --name opvcanary-a5-a --region iad --restart no \
  --skip-dns-registration --vm-size shared-cpu-1x --metadata opv_live_check=a5 "${fs[@]}"
id=$(machine_id opvcanary-a5-a); echo "machine A: $id"
[ -n "$id" ] && echo "$id" >> "$S/a5/machines"
flyq machine list | jq '[.[]|{id,name,state,updated_at}]' > "$E/a5/f2-machines.json"
probe "$id" f2-probe
a5_versions "$E/a5/f2-probe.txt" | tee "$E/a5/f2-versions.txt"
echo "RECORD A5-F2: per path present/absent, fs type, mountpoint, mode, owner (see f2-probe.txt). [UNSURE: Fly may write the file before mounting a tmpfs at /dev/shm or /run, so a path can read absent though the write succeeded]"
