# A5-F4: does `fly secrets deploy` rewrite the file? Answered literally: stage v2, run
# `fly secrets deploy`, probe both machines. The boot id shows whether each machine restarted.
# LIVE WRITE on the throwaway app only: re-stages the canary and deploys it. Rollback: T2.
source "$(dirname "$0")/lib.sh"; guard_app
idA=$(cat "$S/a5/machine-a"); idB=$(cat "$S/a5/machine-b")
say "A5-F4 stage v2, then secrets deploy"
flysafe secrets import --stage < "$CANARY/a5/import-v2"
probe "$idA" f4-before-a >/dev/null; probe "$idB" f4-before-b >/dev/null
flysafe secrets deploy
sleep 15
for m in a b; do
  id=$(cat "$S/a5/machine-$m")
  probe "$id" "f4-after-$m" >/dev/null
  echo "machine $m: $(a5_versions "$E/a5/f4-after-$m.txt" | paste -sd' ') boot_id_changed=$(if ! probed "$E/a5/f4-before-$m.txt" || ! probed "$E/a5/f4-after-$m.txt"; then echo unknown; elif [ "$(grep -o 'boot_id=.*' "$E/a5/f4-before-$m.txt")" = "$(grep -o 'boot_id=.*' "$E/a5/f4-after-$m.txt")" ]; then echo no; else echo yes; fi)"
done | tee "$E/a5/f4.txt"
check A5-F4 deploy_machine_rewritten $(grep '^machine a:' "$E/a5/f4.txt" | grep -q '=v2' && echo 1 || echo 0) "the [[files]] machine shows v2 after secrets deploy"
echo "RECORD A5-F4: per machine, the version at each path and whether it rebooted. Machine B (machine run) shows whether secrets deploy also reaches machines it didn't create."
