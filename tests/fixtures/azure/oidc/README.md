# Azure OIDC live spike (#297)

Recorded outputs from a real Azure tenant and a real GitHub Actions OIDC sign-in, replayed by
the federated-mode tests. Design: [`docs/design/azure-oidc.md`](../../../../docs/design/azure-oidc.md).

No output here holds a secret: a federated identity has none, and the steps below never print
a token. Tenant, client and subscription IDs are identifiers, not secrets, but they are still
replaced with the fixed fakes below before commit.

| Real value | Replaced with |
|---|---|
| tenant ID | `11111111-1111-1111-1111-111111111111` |
| client (app) ID | `22222222-2222-2222-2222-222222222222` |
| subscription ID | `33333333-3333-3333-3333-333333333333` |
| object IDs | `44444444-4444-4444-4444-44444444444N` (N = 1, 2, …) |
| repository | `example-org/example-repo` |

**Run it as one script:** `az login`, then
`scripts/spikes/spike-297.sh <subscription id> <resource group> <owner/repo>`. It does sections 1–3
below (4 is optional and not run), scrubs every id to the fakes above, refuses to copy a
token-shaped string, copies the files here and deletes the app registration and the workflow on
exit.

## You need

- `az` signed in as a person who can create app registrations in Entra ID and assign roles
  on one resource group (for example Application Administrator plus Owner or User Access
  Administrator on that group).
- A GitHub repository you control, with an environment named `spike`.
- About 30 minutes, plus an optional unattended 70-minute job (step 4).

Set these once in your shell:

```sh
SUB=<subscription id>; RG=<resource group>; REPO=<owner>/<repo>
```

## 1. Create the identity (records the mint fixtures)

```sh
az ad app create --display-name opv-oidc-spike -o json > app-create.json
APP=$(jq -r .appId app-create.json)
az ad sp create --id "$APP" -o json > sp-create.json
az role assignment create --assignee "$APP" --role Reader \
  --scope "/subscriptions/$SUB/resourceGroups/$RG" -o json > role-assignment-create.json
az ad app federated-credential create --id "$APP" -o json --parameters "{
  \"name\": \"github-spike\",
  \"issuer\": \"https://token.actions.githubusercontent.com\",
  \"subject\": \"repo:$REPO:environment:spike\",
  \"audiences\": [\"api://AzureADTokenExchange\"]
}" > federated-credential-create.json
az ad app federated-credential list --id "$APP" -o json > federated-credential-list.json
# A second create of the same credential, to record the "already exists" error (convergence):
az ad app federated-credential create --id "$APP" -o json --parameters "{
  \"name\": \"github-spike\", \"issuer\": \"https://token.actions.githubusercontent.com\",
  \"subject\": \"repo:$REPO:environment:spike\", \"audiences\": [\"api://AzureADTokenExchange\"]
}" > federated-credential-create-again.json 2> federated-credential-create-again.stderr
echo "tenant: $(az account show --query tenantId -o tsv)  client: $APP  subscription: $SUB"
```

## 2. Run the OIDC sign-in in GitHub Actions (records the login fixtures)

Add `.github/workflows/opv-oidc-spike.yml` to `$REPO` (repository variables `AZURE_TENANT_ID`,
`AZURE_CLIENT_ID`, `AZURE_SUBSCRIPTION_ID`; none of them are secrets), then run it once from
the Actions tab:

```yaml
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
          path: '*.json
            *.txt
            *.stderr'
```

## 3. A sign-in that is not there (records the refusal fixture)

On your own machine, in a fresh config dir so your sign-in is untouched:

```sh
AZURE_CONFIG_DIR=$(mktemp -d) az account show -o json > account-show-not-signed-in.json \
  2> account-show-not-signed-in.stderr; echo "exit $?" > account-show-not-signed-in.exit
```

## 4. Optional: does a long run outlive the access token?

The decision document leaves one question open: can a `sync --deploy` outlive the Azure access
token? Add a second job that signs in the same way, then runs
`sleep 4200 && az group show --name … --query name -o tsv` (70 minutes) and records the exit
code and stderr. If it fails, opv must warn before a long deploy starts.

## 5. Hand back

Put every file from steps 1–4 (and the downloaded workflow artifact) in this directory. Then
tell the assistant they are here: it will replace the IDs with the fakes above, check that no
token is present, and accept the spike. Clean up afterwards with
`az ad app delete --id "$APP"`.

## Recorded (2026-11-12)

`scripts/spikes/spike-297.sh` ran against a scratch repository and a resource group in a real
tenant. The job signed in through OIDC as the service principal (`account-show.json`,
`user.type = servicePrincipal`), read the resource group (`group-show.txt`) and saw a token
expiry (`access-token-expires-on.txt`); `az logout` left no account (`account-show-after-logout.*`).
What the run found:

- GitHub issued the immutable subject `repo:<owner>@<id>/<repo>@<id>:environment:<env>`
  (`oidc-sub-customization.json`, the repository default); a credential trusting the classic
  form failed with AADSTS700213 (fixed in 0.20.1, #323).
- A job run seconds after the Reader grant failed in `azure/login` with `No subscriptions
  found`; the grant took effect within one refresh after a 180 s wait (`rbac-wait.txt`).
- Creating the same federated credential twice fails with `already exists` (exit 1,
  `federated-credential-create-again.*`).

Tests read `account-show.json`, `federated-credential-list.json` and
`oidc-sub-customization.json` (`src/adapters/azure/login_tests.rs`, `diagnose_tests.rs`,
`src/adapters/github/gh_tests.rs`).
