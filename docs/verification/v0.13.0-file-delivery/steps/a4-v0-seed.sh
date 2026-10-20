# A4-V0 (person, own 1Password session): put the canaries into the canary vault items.
# Writes 1Password (canary items only). Rollback: T5 deletes the canary vaults.
source "$(dirname "$0")/lib.sh"; person_only
cd "$PROJECT"
for env in verify verify-nofsgroup verify-fly dev; do
  f=$CANARY/values/$([ "$env" = verify-nofsgroup ] && echo verify || echo "$env").env
  say "A4-V0 import $env (single-line keys)"
  run "$OPV" import "$env" --from "$f"
done
say "A4-V0 multi-line keys: paste each file's bytes into its field (opv open shows where)"
for env in verify verify-nofsgroup dev; do
  for k in DATABASE_URL GITHUB_APP_PRIVATE_KEY DATABASE_URL_UNPOOLED; do
    run "$OPV" open "journeeze/$k" --env "$env" --print
  done
done
cat <<'MSG'
For each field printed above, copy the canary file's exact bytes, trailing newline included:
  WSL:   clip.exe < "$CANARY/values/multiline/<KEY>"      Linux: xclip -sel clip < ...
and paste into the field in the 1Password app (a multi-line field). Then run
  python3 -I "$KIT/canary/seed-check.py" "$OPV" "$PROJECT" "$CANARY" verify verify-nofsgroup verify-fly dev
MSG
