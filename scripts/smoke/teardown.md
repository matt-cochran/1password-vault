# Teardown

Run after the receipt is saved. Each command acts on the disposable sandbox only; check names before pressing Enter.

```sh
# 1. Azure sandbox: the resource group holds the Key Vault, Container App and environment
az group delete --name opv-spike-rg --yes --no-wait
# The vault is soft-deleted; purge it if the name must be reused
az keyvault purge --name "$OPV_SMOKE_AZ_KEY_VAULT" --location eastus

# 2. Temporary service principal used by ESO
az ad sp delete --id <appId of opv-spike-eso>
# also delete its app registration if one was created
az ad app delete --id <appId of opv-spike-eso>

# 3. ClusterSecretStore and its credential Secret
kubectl --context kind-opv delete clustersecretstore prod-vault
kubectl --context kind-opv --namespace external-secrets delete secret <credential secret name>
#    (use the namespace and name the store's spec.provider.azurekv.authSecretRef points at)

# 4. kind cluster (removes the namespace opv-spike and the Deployment api with it)
kind delete cluster --name opv

# 5. Disposable 1Password item (by ID; confirm the title first)
op item get "$OPV_SMOKE_OP_ITEM_ID" --vault "$OPV_SMOKE_OP_VAULT_ID" --fields label=title
op item delete "$OPV_SMOKE_OP_ITEM_ID" --vault "$OPV_SMOKE_OP_VAULT_ID"
```

Finally remove the rendered scratch directory printed as `receipt: ...` once the receipt is archived (`rm -rf <tmpdir>`), and confirm with `az group exists --name opv-spike-rg` (false) and `kind get clusters`.
