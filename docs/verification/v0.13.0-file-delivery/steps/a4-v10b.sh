# A4-V10, CI half: detect, sync, deploy; the old Secret version stays for the old ReplicaSet.
source "$(dirname "$0")/lib.sh"; ci_only
say "A4-V10b"
before=$(kubectl -n jzverify get secret -l opv-managed=verify -o name | wc -l)
run "$OPV" changed verify; rc=$?
check A4-V10 changed_exit10 $([ $rc = 10 ] && echo 1 || echo 0) "exit $rc; the line must name the journeeze item"
KUBECONFIG=$ADMIN_KUBECONFIG kubectl -n jzverify create configmap jzverify-expect \
  --from-file=expect="$CANARY/expect/expect-rotated.txt" --dry-run=client -o yaml | KUBECONFIG=$ADMIN_KUBECONFIG kubectl apply -f -
sampled v10 "$OPV" sync verify --deploy; rc=$?
check A4-V10 sync $([ $rc = 0 ] && echo 1 || echo 0) "exit $rc"
after=$(kubectl -n jzverify get secret -l opv-managed=verify -o name | wc -l)
echo "opv-managed Secrets: before=$before after=$after"
check A4-V10 old_version_kept $([ "$after" -gt "$before" ] && echo 1 || echo 0)
sleep 90   # the ConfigMap volume refresh plus one consumer cycle
kadmin -n jzverify logs deploy/jzverify -c journeeze --tail=16 | tee "$E/v10-consumer.txt"
check A4-V10 webhook_match $(grep -q '^github/webhook-secret: match' "$E/v10-consumer.txt" && echo 1 || echo 0)
run "$OPV" changed verify; rc=$?
check A4-V10 changed_then_0 $([ $rc = 0 ] && echo 1 || echo 0) "exit $rc"
