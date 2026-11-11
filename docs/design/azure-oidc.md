# Azure deploys through GitHub OIDC (#297)

Decision (owner, 2026-11-10): **option A — the workflow signs in, opv verifies the identity.**
Rejected: opv fetching the GitHub OIDC token and passing it to `az login --federated-token`
(an SR-3 exception for convenience), and deferring federation (the client secret stays).

## What changes

A target may declare a federated deploy identity instead of `deploy_credentials`:
tenant ID, client ID and subscription ID, all non-secret. No Azure secret exists anywhere.
Config refuses a target that declares both.

- **Trust subject:** the GitHub environment, `repo:<owner>/<repo>:environment:<env>`. The
  environment's protection rules (a `main`-only branch rule, required reviewers) are the
  security boundary for who can deploy, so `opv ci workflow` and `doctor` recommend them.
- **Sign-in:** the workflow's `azure/login` step (OIDC, `permissions: id-token: write`)
  signs in before opv runs. opv never receives, reads or forwards the GitHub token (SR-3
  holds), and it writes no Azure secret anywhere (federated mode does not use the SR-4
  private `AZURE_CONFIG_DIR` exception).
- **Verification before any call (NR-6, NR-7):** opv reads the ambient identity
  (`az account show`) and continues only when the tenant, client ID and subscription equal
  the configured ones and opv runs inside GitHub Actions. A missing sign-in, any other
  identity (a person's own `az login` included) or a run outside CI is refused with
  exactly one `Next:`.
- **Local commands are refused:** `status`, `plan`, `sync` and `doctor --env` against a
  federated target outside GitHub Actions stop with a `Next:` that names the CI workflow.
  No secret-mode fallback credential is kept for people.
- **Sign-out step:** the generated workflow ends with `az logout` under `if: always()`, so a
  self-hosted runner does not keep the session on disk; `doctor` warns when the workflow
  that deploys a federated target runs on a self-hosted runner.
- **Setup:** `opv target credentials <env> --target <t> --create --federated --github
  <owner/repo> --github-env <env>` (a person's own session) creates or reuses the app
  registration and service principal, assigns exactly the target's least-privilege roles,
  and adds the federated credential for the environment subject. The person needs Entra ID
  rights to create applications and to assign roles at the target's scope; a missing right
  is refused before anything is created.

## To confirm in the live spike

- The Azure access token's lifetime after an OIDC sign-in, and whether it can be renewed
  after the GitHub token has expired. If a run can outlive it, `sync --deploy` must say so
  before starting, not fail halfway.
- The exact `az account show` fields that identify a federated service principal.
- The `az ad app federated-credential` output shapes, recorded as fixtures under
  `tests/fixtures/azure/oidc/`.

Requirements to update with the code: FR-40 (deploy credentials), SR-4 (the exception does not
apply in federated mode), SR-5 (the federated identity is the CI deploy identity).
