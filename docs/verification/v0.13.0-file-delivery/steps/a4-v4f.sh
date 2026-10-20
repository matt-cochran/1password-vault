# A4-V4f (CI-like): the Fly leg's doctor and plan, and the live app's baseline.
# LIVE READ of the staging fleet app (names, digests, machines, releases; no value).
source "$(dirname "$0")/lib.sh"; ci_only
say "A4-V4f baseline of the running service (compared again in T3)"
[ -s "$S/a5/baseline-machines.json" ] || flyq machine list | jq '[.[]|{id,name,state,region,updated_at,image:(.config.image // .image_ref)}]' > "$S/a5/baseline-machines.json"
[ -s "$S/a5/baseline-release.json" ] || flyq releases | jq 'max_by(.Version)|{Version,Status,CreatedAt}' > "$S/a5/baseline-release.json"
cat "$S/a5/baseline-machines.json" "$S/a5/baseline-release.json"
flyq secrets list | jq -r '.[].name' | sed -E 's/^(FLEET__[A-Z0-9]+)__.*/\1__*/' | sort | uniq -c > "$E/v4f-names-before.txt"
cat "$E/v4f-names-before.txt"
check A4-V4f no_canary_names_yet $(grep -q OPVCANARY "$E/v4f-names-before.txt" && echo 0 || echo 1)
say "A4-V4f doctor and plan"
run "$OPV" doctor --env verify-fly
run "$OPV" plan verify-fly > "$E/v4f-plan.txt"; cat "$E/v4f-plan.txt"
run "$OPV" plan verify-fly --json > "$E/v4f-plan.json"
jq -r '.plan_id // .data.plan_id // empty' "$E/v4f-plan.json" > "$E/plan-verify-fly.id"
check A4-V4f plan_id $([ -s "$E/plan-verify-fly.id" ] && echo 1 || echo 0)
check A4-V4f unmanaged_counted $(grep -q 'unmanaged' "$E/v4f-plan.txt" && echo 1 || echo 0) "the FLEET__* names are counted as unmanaged, never touched"
