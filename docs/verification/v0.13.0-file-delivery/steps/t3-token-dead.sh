# T3 (CI-like, which still holds the revoked token): the token no longer works.
source "$(dirname "$0")/lib.sh"; ci_only
say "T3"
flyctl auth whoami >/dev/null 2>&1; w=$?
flyctl status --app "$FLY_APP" >/dev/null 2>&1; st=$?
echo "auth whoami exit=$w; status --app exit=$st"
check T3 token_dead $([ $w != 0 ] && [ $st != 0 ] && echo 1 || echo 0) "both must fail [UNSURE: whether whoami fails for a revoked deploy token; status must fail either way, since the app is gone]"
