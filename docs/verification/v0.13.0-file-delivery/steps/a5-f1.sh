# A5-F1: what --file-secret writes into the machine config, and whether the same field set
# through --machine-config (the shape a launcher or [[files]] produces) behaves the same.
# LIVE WRITE: creates machine opvcanary-a5-b (--rm, 10 min), destroyed at the end of this
# step. Rollback: T1.
source "$(dirname "$0")/lib.sh"; guard_app
say "A5-F1 machine A's config"
idA=$(head -1 "$S/a5/machines")
flysafe machine status "$idA" -d > "$E/a5/f1-status-a.txt"
grep -n -A3 '"files"' "$E/a5/f1-status-a.txt" || echo "no files field printed"
say "A5-F1b machine B from a machine config"
cat > "$S/a5/b-config.json" <<JSON
{"files":[{"guest_path":"/run/opvcanary/a5-file","secret_name":"OPVCANARY_A5_FILE"}],
 "metadata":{"opv_live_check":"a5"},"restart":{"policy":"no"}}
JSON
flysafe machine run "$IMAGE_A5" sleep 600 --name opvcanary-a5-b --region iad --rm \
  --skip-dns-registration --vm-size shared-cpu-1x --machine-config "$S/a5/b-config.json"
idB=$(machine_id opvcanary-a5-b); echo "machine B: $idB"
[ -n "$idB" ] && echo "$idB" >> "$S/a5/machines"
probe "$idB" f1b-probe
flysafe machine status "$idB" -d > "$E/a5/f1-status-b.txt"
a5_versions "$E/a5/f1b-probe.txt" | tee "$E/a5/f1b-versions.txt"
check A5-F1 machine_config_same $(grep -q '/run/opvcanary/a5-file=v1' "$E/a5/f1b-versions.txt" && echo 1 || echo 0) "[UNSURE: whether --machine-config merges with the CLI flags; fly.toml [[files]] itself needs a fly deploy, which the decision rules out]"
flysafe machine destroy "$idB" --force
