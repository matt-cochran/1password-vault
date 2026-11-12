#!/usr/bin/env bash
# Spike #297: record a real Azure federated identity and a real GitHub Actions OIDC sign-in.
# Steps: tests/fixtures/azure/oidc/README.md (sections 1-3; section 4 is optional and not run).
#
# Usage (signed in to Azure as yourself first: az login):
#   scripts/spikes/spike-297.sh <subscription id> <resource group> <owner/repo>
#
# <owner/repo> is a GitHub repository you control and may push one throwaway workflow file to
# (a scratch repository is best). The script:
#   1. creates the app registration opv-oidc-spike-<time>, its service principal, a Reader grant
#      on the resource group and one federated credential for repo:<owner/repo>:environment:spike;
#   2. creates the `spike` environment and three repository variables (ids, not secrets), commits
#      .github/workflows/opv-oidc-spike.yml to the default branch, runs it once and downloads
#      its artifact, then deletes the workflow file and the variables;
#   3. records an `az account show` with no sign-in;
#   4. replaces every id with the README's fakes, refuses to copy anything if a token-shaped
#      string or a real id survives, and copies the scrubbed files into tests/fixtures/azure/oidc/;
#   5. deletes the app registration on exit (which removes its service principal, grant and
#      federated credential).
# No token is ever printed, passed as an argument or written: the workflow records only
# `expiresOn`, and a federated identity has no secret.
set -euo pipefail
set +x
umask 077

SUB=${1:?usage: $0 <subscription id> <resource group> <owner/repo>}
RG=${2:?usage: $0 <subscription id> <resource group> <owner/repo>}
REPO=${3:?usage: $0 <subscription id> <resource group> <owner/repo>}
root=$(cd "$(dirname "$0")/../.." && pwd)
dest="$root/tests/fixtures/azure/oidc"
for tool in az gh python3; do command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 3; }; done
az account show -o none 2>/dev/null || { echo "not signed in to Azure: run  az login  first" >&2; exit 4; }
gh repo view "$REPO" --json name >/dev/null || { echo "cannot see $REPO with gh: run  gh auth login  first" >&2; exit 4; }
az group show --name "$RG" --subscription "$SUB" -o none || { echo "resource group $RG not found in $SUB" >&2; exit 4; }

out=$(mktemp -d); cd "$out"
suffix=$(date +%Y%m%d%H%M%S)
name="opv-oidc-spike-$suffix"
APP=""; wf_sha=""
WF=.github/workflows/opv-oidc-spike.yml
cleanup() {
  if [ -n "$wf_sha" ]; then
    gh api -X DELETE "repos/$REPO/contents/$WF" -f message="remove opv OIDC spike workflow" -f sha="$wf_sha" >/dev/null 2>&1 \
      && echo "removed $WF from $REPO" || echo "could not remove $WF from $REPO: delete it by hand" >&2
  fi
  for v in AZURE_TENANT_ID AZURE_CLIENT_ID AZURE_SUBSCRIPTION_ID AZURE_RESOURCE_GROUP; do gh variable delete "$v" -R "$REPO" >/dev/null 2>&1 || true; done
  if [ -n "$APP" ]; then
    az ad app delete --id "$APP" >/dev/null 2>&1 && echo "deleted app registration $name" \
      || echo "could not delete app registration $name: delete it in Entra ID" >&2
  fi
  echo "Raw replies (unscrubbed, private to you): $out  (rm -rf it when done)"
}
trap cleanup EXIT

TENANT=$(az account show --subscription "$SUB" --query tenantId -o tsv)
cred() { printf '{"name":"github-spike","issuer":"https://token.actions.githubusercontent.com","subject":"repo:%s:environment:spike","audiences":["api://AzureADTokenExchange"]}' "$REPO"; }

echo "== 1. create the identity"
az ad app create --display-name "$name" -o json > app-create.json
APP=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["appId"])' app-create.json)
az ad sp create --id "$APP" -o json > sp-create.json
# A new service principal can take a few seconds to replicate before a role assignment sees it.
for i in 1 2 3 4 5 6; do
  az role assignment create --assignee "$APP" --role Reader --scope "/subscriptions/$SUB/resourceGroups/$RG" -o json \
    > role-assignment-create.json 2> role-assignment-create.stderr && break
  [ "$i" = 6 ] && { echo "role assignment failed: see $out/role-assignment-create.stderr" >&2; exit 5; }
  sleep 10
done
az ad app federated-credential create --id "$APP" -o json --parameters "$(cred)" > federated-credential-create.json
az ad app federated-credential list --id "$APP" -o json > federated-credential-list.json
if az ad app federated-credential create --id "$APP" -o json --parameters "$(cred)" \
    > federated-credential-create-again.json 2> federated-credential-create-again.stderr; then
  echo 0 > federated-credential-create-again.exit
else
  echo $? > federated-credential-create-again.exit
fi
echo "created $name (Reader on $RG, federated credential for repo:$REPO:environment:spike)"

echo "== 2. OIDC sign-in in GitHub Actions"
gh api -X PUT "repos/$REPO/environments/spike" >/dev/null
gh variable set AZURE_TENANT_ID -R "$REPO" --body "$TENANT"
gh variable set AZURE_CLIENT_ID -R "$REPO" --body "$APP"
gh variable set AZURE_SUBSCRIPTION_ID -R "$REPO" --body "$SUB"
gh variable set AZURE_RESOURCE_GROUP -R "$REPO" --body "$RG"
cat > workflow.yml <<'EOF'
name: opv-oidc-spike
on: workflow_dispatch
permissions:
  id-token: write
  contents: read
jobs:
  spike:
    runs-on: ubuntu-latest
    environment: spike
    steps:
      - uses: azure/login@v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
      - name: Record the ambient identity
        run: |
          az account show -o json > account-show.json
          # Only the expiry, never the token itself:
          az account get-access-token --query expiresOn -o tsv > access-token-expires-on.txt
          date -u +%Y-%m-%dT%H:%M:%SZ > signed-in-at.txt
          az group show --name "${{ vars.AZURE_RESOURCE_GROUP }}" --query name -o tsv > group-show.txt
      - name: Sign out
        if: always()
        run: |
          az logout
          az account show -o json > account-show-after-logout.json 2> account-show-after-logout.stderr || true
      - uses: actions/upload-artifact@v4
        with:
          name: opv-oidc-spike
          path: |
            *.json
            *.txt
            *.stderr
EOF
wf_sha=$(gh api -X PUT "repos/$REPO/contents/$WF" -f message="opv OIDC spike workflow (temporary)" \
  -f content="$(base64 -w0 workflow.yml)" --jq .content.sha)
before=$(date -u +%Y-%m-%dT%H:%M:%SZ)
sleep 5
gh workflow run opv-oidc-spike.yml -R "$REPO"
run=""
for _ in $(seq 1 30); do
  run=$(gh run list -R "$REPO" --workflow opv-oidc-spike.yml --event workflow_dispatch --json databaseId,createdAt \
    --jq "[.[]|select(.createdAt >= \"$before\")][0].databaseId // empty")
  [ -n "$run" ] && break; sleep 5
done
[ -n "$run" ] || { echo "the spike workflow never started in $REPO" >&2; exit 6; }
echo "waiting for run $run (an environment with required reviewers needs your approval in the Actions tab)"
gh run watch "$run" -R "$REPO" --interval 15 >/dev/null || true
gh run view "$run" -R "$REPO" --json conclusion --jq .conclusion > workflow-conclusion.txt
mkdir -p artifact && gh run download "$run" -R "$REPO" -n opv-oidc-spike -D artifact
mv artifact/* . && rmdir artifact
echo "workflow concluded: $(cat workflow-conclusion.txt)"

echo "== 3. a sign-in that is not there"
if AZURE_CONFIG_DIR=$(mktemp -d) az account show -o json > account-show-not-signed-in.json 2> account-show-not-signed-in.stderr; then
  echo "exit 0" > account-show-not-signed-in.exit
else
  echo "exit $?" > account-show-not-signed-in.exit
fi

echo "== 4. scrub"
if grep -l -E 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' ./* >/dev/null 2>&1; then
  echo "a token-shaped string was recorded: not copying anything (inspect $out)" >&2; exit 7
fi
rm -f workflow.yml
cat > scrub.py <<'EOF'
import pathlib, re, sys
tenant, client, sub, repo, rg, name = sys.argv[1:7]
fixed = {tenant.lower(): "11111111-1111-1111-1111-111111111111", client.lower(): "22222222-2222-2222-2222-222222222222",
         sub.lower(): "33333333-3333-3333-3333-333333333333"}
guid = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
files = sorted(p for p in pathlib.Path(".").iterdir()
               if p.is_file() and p.suffix in (".json", ".txt", ".stderr", ".exit") and p.name != "workflow-conclusion.txt")
others = {}
for p in files:
    for g in guid.findall(p.read_text()):
        if g.lower() not in fixed and g.lower() not in others:
            others[g.lower()] = f"44444444-4444-4444-4444-44444444444{len(others) + 1}"
owner = repo.split("/")[0]
for p in files:
    t = p.read_text()
    t = guid.sub(lambda m: fixed.get(m.group(0).lower()) or others[m.group(0).lower()], t)
    for real, fake in ((repo, "example-org/example-repo"), (name, "opv-oidc-spike"), (rg, "example-rg"), (owner, "example-org")):
        t = t.replace(real, fake)
    t = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "user@example.com", t)
    pathlib.Path(p.name + ".scrubbed").write_text(t)
print(len(others), "other ids replaced")
EOF
python3 -I scrub.py "$TENANT" "$APP" "$SUB" "$REPO" "$RG" "$name"
left=$(grep -l -i -F -e "$TENANT" -e "$APP" -e "$SUB" -e "$REPO" -e "$RG" ./*.scrubbed || true)
left="$left$(grep -l -E 'eyJ[A-Za-z0-9_-]{10,}' ./*.scrubbed || true)"
if [ -n "$left" ]; then echo "real ids left in: $left (not copied; inspect $out)" >&2; exit 8; fi
echo "no real ids left"
n=0; for f in ./*.scrubbed; do cp "$f" "$dest/$(basename "$f" .scrubbed)"; n=$((n+1)); done
echo "copied $n scrubbed files to tests/fixtures/azure/oidc/"

echo "== summary"
echo "workflow: $(cat workflow-conclusion.txt)"
for f in account-show.json access-token-expires-on.txt group-show.txt account-show-after-logout.stderr account-show-not-signed-in.exit federated-credential-create-again.exit; do
  [ -f "$dest/$f" ] && { echo "--- $f"; head -c 600 "$dest/$f"; echo; }
done
