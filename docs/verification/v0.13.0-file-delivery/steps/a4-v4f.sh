# A4-V4f (CI-like): the Fly leg's doctor and plan, against the throwaway canary app.
# LIVE READ of the throwaway app only.
source "$(dirname "$0")/lib.sh"; ci_only; guard_app
say "A4-V4f the app before any sync"
flyq secrets list | jq -r '.[].name' > "$E/v4f-names-before.txt"; cat "$E/v4f-names-before.txt"
check A4-V4f no_opv_names_yet $(grep -q '^OPVCANARY__' "$E/v4f-names-before.txt" && echo 0 || echo 1)
say "A4-V4f doctor and plan"
run "$OPV" doctor --env verify-fly
run "$OPV" plan verify-fly > "$E/v4f-plan.txt"; cat "$E/v4f-plan.txt"
run "$OPV" plan verify-fly --json > "$E/v4f-plan.json"
jq -r '.plan_id // .data.plan_id // empty' "$E/v4f-plan.json" > "$E/plan-verify-fly.id"
check A4-V4f plan_id $([ -s "$E/plan-verify-fly.id" ] && echo 1 || echo 0)
n=$(declared_keys verify-fly serve | wc -l)
check A4-V4f declared_to_stage $(grep -q "· $n to stage ·" "$E/v4f-plan.txt" && echo 1 || echo 0) "$n to stage: the manifest's serve keys for verify-fly, LOG_LEVEL included; file keys shown as file via the app"
