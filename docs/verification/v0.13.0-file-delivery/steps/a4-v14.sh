# A4-V14 (CI-like, AFTER the person revoked the canary service account): no 1Password at
# runtime. Writes: the LOCAL kind cluster (a restart).
source "$(dirname "$0")/lib.sh"; ci_only
say "A4-V14"
run "$OPV" changed verify; rc=$?
check A4-V14 token_revoked $([ $rc != 0 ] && [ $rc != 10 ] && echo 1 || echo 0) "exit $rc: must fail to sign in"
run env KUBECONFIG="$ADMIN_KUBECONFIG" kubectl -n jzverify rollout restart deployment/jzverify
kadmin -n jzverify rollout status deployment/jzverify --timeout=180s
sleep 40
kadmin -n jzverify logs deploy/jzverify -c journeeze --tail=16 | tee "$E/v14-consumer.txt"
check A4-V14 all_match $(grep -q '^result: ok' "$E/v14-consumer.txt" && echo 1 || echo 0)
