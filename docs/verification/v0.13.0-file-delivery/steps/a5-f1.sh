# A5-F1: does fly.toml [[files]] secret_name behave like --file-secret? Answered literally:
#   machine A = `fly deploy` of kit/fly/fly.toml ([[files]] at three paths)
#   machine B = `fly machine run --file-secret` at the same three paths
# then both machine configs and both probes are compared.
# LIVE WRITE on the throwaway app only: a deploy (machine A) and machine B. Rollback: T2.
source "$(dirname "$0")/lib.sh"; guard_app
mkdir -p "$E/a5"
sed "s/__APP__/$FLY_APP/" "$KIT/kit/fly/fly.toml" > "$S/a5/fly.toml"
say "A5-F1 machine A: fly deploy with [[files]]"
flysafe deploy --config "$S/a5/fly.toml" --image "$IMAGE_A5" --ha=false --no-public-ips --yes
idA=$(flyq machine list | jq -r '[.[]|select(.name!="opvcanary-a5-b")][0].id')
echo "machine A: $idA"; echo "$idA" > "$S/a5/machine-a"
say "A5-F1 machine B: fly machine run --file-secret"
mapfile -t fs < <(a5_file_secret_flags)
flysafe machine run "$IMAGE_A5" sleep 86400 --name opvcanary-a5-b --region iad --restart no \
  --skip-dns-registration --vm-size shared-cpu-1x --metadata opv_live_check=a5 "${fs[@]}"
idB=$(machine_id opvcanary-a5-b); echo "machine B: $idB"; echo "$idB" > "$S/a5/machine-b"
say "A5-F1 the two machine configs (files entries)"
for m in a b; do
  id=$(cat "$S/a5/machine-$m")
  flysafe machine status "$id" -d > "$E/a5/f1-status-$m.txt"
  # The config JSON follows the status header; keep only its files entries.
  sed -n '/^{/,$p' "$E/a5/f1-status-$m.txt" | jq -c '[.files[]?|{guest_path, secret_name}]|sort' > "$E/a5/f1-files-$m.json" \
    || echo "could not parse the config of machine $m: read $E/a5/f1-status-$m.txt"
  echo "machine $m files: $(cat "$E/a5/f1-files-$m.json")"
done
probe "$idA" f1-probe-a; a5_versions "$E/a5/f1-probe-a.txt" | tee "$E/a5/f1-versions-a.txt"
probe "$idB" f1-probe-b; a5_versions "$E/a5/f1-probe-b.txt" | tee "$E/a5/f1-versions-b.txt"
check A5-F1 same_config $(cmp -s "$E/a5/f1-files-a.json" "$E/a5/f1-files-b.json" && [ -s "$E/a5/f1-files-a.json" ] && echo 1 || echo 0) "[[files]] and --file-secret give the same files entries"
check A5-F1 same_result $(cmp -s "$E/a5/f1-versions-a.txt" "$E/a5/f1-versions-b.txt" && echo 1 || echo 0) "same paths present, same bytes"
echo "RECORD A5-F1: both files entries; both version lists; any difference is the answer."
