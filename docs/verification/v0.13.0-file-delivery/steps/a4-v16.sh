# A4-V16: the canary scan over every channel A4 produced. Reads the cluster (admin) and,
# for the Fly leg, the app's secret names and digests. Writes nothing live.
source "$(dirname "$0")/lib.sh"
mkdir -p "$S/scan"
say "A4-V16 collect"
kadmin get deployments,replicasets,statefulsets,daemonsets,pods -A -o yaml > "$S/scan/objects.yaml"
kadmin get configmaps -A -l '!opv-managed' -o yaml > "$S/scan/configmaps-not-opv.yaml"
kadmin get secrets -A -l '!opv-managed' -o yaml > "$S/scan/secrets-not-opv.yaml"
kadmin get events -A -o yaml > "$S/scan/events.yaml"
: > "$S/scan/logs.txt"
for p in $(kadmin get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}'); do
  kadmin logs -n "${p%/*}" "${p#*/}" --all-containers --prefix >> "$S/scan/logs.txt" 2>&1
  kadmin logs -n "${p%/*}" "${p#*/}" --all-containers --prefix --previous >> "$S/scan/logs.txt" 2>/dev/null
done
N=opv-verify-136-control-plane
echo "node /var/log/pods files: $(docker exec $N sh -c 'find /var/log/pods -type f | wc -l')"
docker exec -i $N grep -r -l -a -F -f /dev/stdin /var/log/pods < "$PATTERNS" > "$S/scan/node-hits.txt"; rc=$?
echo "node grep exit=$rc (1 = no hit, 0 = hit, 2 = error)"; cat "$S/scan/node-hits.txt"
check A4-V16 node_logs $([ $rc = 1 ] && echo 1 || echo 0)
flyq secrets list > "$S/scan/fly-secrets-list.json" 2>&1 || true
say "A4-V16 scan"
run bash "$KIT/canary/scan-canary.sh" "$PATTERNS" \
  transcript="$E/transcript.txt" \
  captures="$E" \
  k8s-objects="$S/scan/objects.yaml" k8s-configmaps-not-opv="$S/scan/configmaps-not-opv.yaml" \
  k8s-secrets-not-opv="$S/scan/secrets-not-opv.yaml" k8s-events="$S/scan/events.yaml" \
  k8s-logs="$S/scan/logs.txt" fly-secrets-list="$S/scan/fly-secrets-list.json"
rc=$?
check A4-V16 zero_hits $([ $rc = 0 ] && echo 1 || echo 0) "scan exit $rc; proc-v15 env_names=LOG_LEVEL is expected, by design"
echo "opv-managed objects (the stores' own data, not scanned): $(kadmin get secret,configmap -A -l opv-managed -o name | wc -l)"
