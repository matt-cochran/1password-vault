# A4-V10, person half: rotate the webhook canary in the verify item. Writes 1Password (canary).
source "$(dirname "$0")/lib.sh"; person_only
say "A4-V10a"
cd "$PROJECT"
run "$OPV" import verify --from "$CANARY/values/rotate/rotate.env" --replace journeeze/GITHUB_WEBHOOK_SECRET
