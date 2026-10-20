# A4-V15 (person): local delivery through the Compose recipe; then the recipe outside opv.
# Writes nothing outside a tmpfs dir opv removes on exit.
source "$(dirname "$0")/lib.sh"; person_only
[ -n "${XDG_RUNTIME_DIR:-}" ] || { echo "refused: XDG_RUNTIME_DIR unset (file delivery needs it)"; exit 3; }
mkdir -p "$S/v15" && cp "$KIT/kit/compose.yml" "$S/v15/" && cp "$CANARY/expect/expect.txt" "$S/v15/expect.txt"
cd "$S/v15"
say "A4-V15 under opv"
sampled v15 "$OPV" run dev --product journeeze --role serve --config "$PROJECT/secrets.toml" -- docker compose run --rm serve | tee "$E/v15-consumer.txt"
check A4-V15 under_opv $(grep -q '^result: ok' "$E/v15-consumer.txt" && echo 1 || echo 0)
say "A4-V15 outside opv (must refuse, exit 15)"
run env -u OPV_UID -u OPV_GID -u OPV_SECRETS_DIR docker compose config; rc=$?
check A4-V15 outside_refused $([ $rc = 15 ] && echo 1 || echo 0) "exit $rc"
