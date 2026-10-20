# A4-V7 (CI-like, opv-ci identity): the Deployment's shape. Reads the cluster only.
source "$(dirname "$0")/lib.sh"; ci_only
say "A4-V7"
kubectl -n jzverify get deployment jzverify -o json > "$E/v7-deployment.json"
jq '.spec.template.spec | {volumes: [.volumes[]?|{name, projected: (.projected.sources|length?)}], containers: [.containers[]|{name, env: [.env[]?|.name], envFrom: [.envFrom[]?|(.configMapRef.name // .secretRef.name)], mounts: [.volumeMounts[]?|{name, mountPath}]}]}' "$E/v7-deployment.json"
run kubectl -n jzverify get secret,configmap -l opv-managed=verify -o name | tee "$E/v7-objects.txt"
filekeys='DATABASE_URL|GITHUB_APP_PRIVATE_KEY|GITHUB_WEBHOOK_SECRET|TYPESAFE_JEV_API_KEY|BLOB_ACCESS_KEY_ID|BLOB_SECRET_ACCESS_KEY|GUIDE_ASSET_SIGNING_KEY|OTEL_EXPORTER_OTLP_ENDPOINT|OTEL_EXPORTER_OTLP_HEADERS'
envnames=$(jq -r '.spec.template.spec.containers[].env[]?.name' "$E/v7-deployment.json")
check A4-V7 no_file_key_env $(echo "$envnames" | grep -Eqx "$filekeys" && echo 0 || echo 1)
check A4-V7 sidecar_no_mount $(jq -e '.spec.template.spec.containers[]|select(.name=="sidecar")|[.volumeMounts[]?|select(.name|startswith("opv-files-"))]|length==0' "$E/v7-deployment.json" >/dev/null && echo 1 || echo 0)
check A4-V7 no_migrate_object $(grep -Eiq 'unpooled|app-password|owner-url' "$E/v7-objects.txt" && echo 0 || echo 1)
