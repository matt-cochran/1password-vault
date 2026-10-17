set -u
K=${REPO:?set REPO to this checkout}/docs/verification/v0.11.0-file-delivery/kit
echo '=== V15 (second half only): docker compose config outside opv'
echo '$ env -u OPV_UID -u OPV_GID -u OPV_SECRETS_DIR docker compose -f kit/compose.yml config'
env -u OPV_UID -u OPV_GID -u OPV_SECRETS_DIR docker compose -f $K/compose.yml config 2>&1; echo "exit=$?"
