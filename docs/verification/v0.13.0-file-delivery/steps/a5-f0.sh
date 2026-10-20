# A5-F0 (CI-like shell: it holds the app-scoped Fly token): baseline, then stage the canary
# file secret. LIVE WRITE: one staged secret OPVCANARY_A5_FILE (base64 of a canary; stdin,
# never argv). No deploy, no restart. Rollback: T2.
source "$(dirname "$0")/lib.sh"; guard_app
say "A5-F0 baseline (skipped if A4-V4f already took it)"
[ -s "$S/a5/baseline-machines.json" ] || flyq machine list | jq '[.[]|{id,name,state,region,updated_at,image:(.config.image // .image_ref)}]' > "$S/a5/baseline-machines.json"
[ -s "$S/a5/baseline-release.json" ] || flyq releases | jq 'max_by(.Version)|{Version,Status,CreatedAt}' > "$S/a5/baseline-release.json"
cat "$S/a5/baseline-release.json"; jq -r '.[]|"\(.id) \(.name) \(.state)"' "$S/a5/baseline-machines.json"
say "A5-F0 stage"
flysafe secrets import --stage < "$CANARY/a5/import-v1"
flyq secrets list | jq '[.[]|select(.name=="OPVCANARY_A5_FILE")]' | tee "$E/a5-f0-secret.json"
check A5-F0 staged $(jq -e 'length==1 and .[0].status=="Staged"' "$E/a5-f0-secret.json" >/dev/null && echo 1 || echo 0)
