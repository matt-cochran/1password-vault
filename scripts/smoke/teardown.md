# Teardown

run.sh removes its own 1Password test data. Run this only when the sandbox itself is no longer needed. Each command acts on the disposable sandbox only; check names before pressing Enter.

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

```

Remove each run's scratch directory (printed as `receipt: ...`) once its receipt is archived, and confirm with `az group exists --name opv-spike-rg` (false) and `kind get clusters`.
