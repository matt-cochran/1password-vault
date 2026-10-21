# A4-V4 (CI-like): doctor and plan; also captures the CLI and MCP previews for A4-V16.
source "$(dirname "$0")/lib.sh"; ci_only
say "A4-V4"
run "$OPV" doctor; check A4-V4 doctor $([ $? = 0 ] && echo 1 || echo 0)
run "$OPV" plan verify > "$E/v4-plan-verify.txt"; cat "$E/v4-plan-verify.txt"
run "$OPV" plan verify --json > "$E/v4-plan-verify.json"
jq -r '.plan_id // .data.plan_id // empty' "$E/v4-plan-verify.json" > "$E/plan-verify.id"
echo "plan id: $(cat "$E/plan-verify.id")"
check A4-V4 plan_id $([ -s "$E/plan-verify.id" ] && echo 1 || echo 0)
check A4-V4 nine_serve_files $([ "$(grep -c 'file' "$E/v4-plan-verify.txt")" -ge 9 ] && echo 1 || echo 0) "read the plan text: 9 serve rows as file, LOG_LEVEL channel config (ConfigMap)"
# The migrate-only keys may appear as rows (`skipped · n/a`); they must not be written. So the check
# reads the would-write lines only (run 256debcd: grepping the whole plan failed on the rows).
migrate_only=$(comm -23 <(declared_keys verify migrate | sort) <(declared_keys verify serve | sort) | sed 's#.*/##' | paste -sd'|')
would_write=$(grep -E ': would write: ' "$E/v4-plan-verify.txt")
check A4-V4 migrate_not_desired $([ -n "$migrate_only" ] && [ -n "$would_write" ] && ! grep -Eq "/($migrate_only) \\(" <<<"$would_write" && echo 1 || echo 0) "no would-write line names a migrate-only key ($migrate_only)"
say "A4-V4 previews (captured for the A4-V16 scan)"
run "$OPV" run verify --product journeeze --role serve --preview --json > "$E/v4-preview-verify.json"
run python3 -I "$KIT/canary/mcp-preview.py" "$OPV" "$PROJECT" verify journeeze "$E/v4-mcp-preview-verify.json"
