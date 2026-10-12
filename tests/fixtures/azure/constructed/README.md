# Constructed Azure fixtures

These files are **constructed**, not recorded: the P1 sandbox had no access-policy vault
and no user-assigned identity, so these cases could not be captured live (R10 exception,
approved for unrecorded cases only). Each one follows the full JSON object `az` prints with
`-o json` (no `--query` projection), as documented by Azure, with fixture ids only.

| File | Command it stands for | Built from |
|---|---|---|
| `keyvault-show-access-policy.json` | `az keyvault show -n <vault> -o json` on an access-policy vault | The recorded `../keyvault-show.json` with `enableRbacAuthorization: false` and two `accessPolicies` entries in the [Vaults - Get](https://learn.microsoft.com/rest/api/keyvault/keyvault/vaults/get) `AccessPolicyEntry` shape; principal `2222…` (the app identity) has secret `Get`/`List` |
| `identity-show.json` | `az identity show --ids <id> -o json` | The [User Assigned Identities - Get](https://learn.microsoft.com/rest/api/managedidentity/user-assigned-identities/get) response as `az` flattens it (`principalId`, `clientId`, `tenantId` at top level) |

Replace a file with a recorded output (values scrubbed) when one becomes available.
