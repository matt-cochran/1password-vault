# Teardown T1-T4 and T6 (T5 is the person's 1Password and token clean-up; see the runbook).
# LIVE WRITES: destroys the kit's machines; unsets the staged canary names (--stage).
source "$(dirname "$0")/lib.sh"; guard_app
say "T1 destroy the one-off machines"
while read -r id; do flysafe machine destroy "$id" --force || true; done < "$S/a5/machines"
left=$(flyq machine list | jq '[.[]|select(.name|startswith("opvcanary"))]|length')
check T1 machines_gone $([ "$left" = 0 ] && echo 1 || echo 0) "$left left"
say "T2 unset the staged canary names"
mapfile -t names < <(flyq secrets list | jq -r '.[].name|select(startswith("OPVCANARY"))')
[ ${#names[@]} -gt 0 ] && flysafe secrets unset --stage "${names[@]}"
n=$(flyq secrets list | jq '[.[]|select(.name|startswith("OPVCANARY"))]|length')
check T2 canary_names_gone $([ "$n" = 0 ] && echo 1 || echo 0) "$n left"
say "T3 the running service is as it was"
flyq machine list | jq '[.[]|{id,name,state,region,updated_at,image:(.config.image // .image_ref)}]' > "$E/t3-machines.json"
flyq releases | jq 'max_by(.Version)|{Version,Status,CreatedAt}' > "$E/t3-release.json"
diff <(jq -S . "$S/a5/baseline-machines.json") <(jq -S . "$E/t3-machines.json"); m=$?
diff <(jq -S . "$S/a5/baseline-release.json") <(jq -S . "$E/t3-release.json"); r=$?
check T3 machines_unchanged $([ $m = 0 ] && echo 1 || echo 0)
check T3 no_new_release $([ $r = 0 ] && echo 1 || echo 0)
say "T4 the local cluster"
kind get clusters 2>/dev/null | grep -qx opv-verify-136 && run kind delete cluster --name opv-verify-136 --kubeconfig "$ADMIN_KUBECONFIG"
say "T6 final scan, then the canary directory goes"
flyq secrets list > "$E/t6-secrets-list.json"
run bash "$KIT/canary/scan-canary.sh" "$PATTERNS" transcript="$E/transcript.txt" evidence="$E" scan="$S/scan"
echo "after recording the scan result: rm -rf \"\$CANARY\" \"$S/project\" \"$S/kubeconfig-opv-ci\" (tmpfs)"
