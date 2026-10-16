# GitHub CLI (`gh`) failure recordings

Real `gh` output for the GitHub diagnosis strategy
(`docs/design/error-catalog.md` §5) and for
[CONTRIBUTING "Adding a provider"](../../../../CONTRIBUTING.md): recordings, never
invented output. Each `NN-<case>.stderr` is the verbatim stderr and
`NN-<case>.exit` is the process exit code. `06-version.stdout` is `gh --version`
output (its stderr is empty, recorded as the empty `06-version.stderr`).

Recorded with **gh 2.102.0 (2026-09-30)** on 2026-10-15.

## How these were recorded

- Every run used an isolated, empty config dir: `GH_CONFIG_DIR=$(mktemp -d)`. The
  person's own `gh` login was never read or used.
- No real credential was read, printed or stored. Only an obviously fake shell
  token (`GH_TOKEN=<TOKEN>` below) was used, and no token text is recorded.
- Pinned environment on every run:
  `GH_PROMPT_DISABLED=1 GH_NO_UPDATE_NOTIFIER=1 NO_COLOR=1 GH_PAGER=cat`.
- Every command ran with stdin closed (`</dev/null`); nothing was interactive.
  `gh auth login --with-token` was fed the token on stdin explicitly.
- The captured output contains no temp path, username, email or token, so no
  value needed substitution. In the commands below `<TMP>` marks the isolated
  empty `GH_CONFIG_DIR` and `<TOKEN>` marks the fake shell token.

## Recorded cases

| Case | Exact command (`<TMP>` = empty `GH_CONFIG_DIR`, `<TOKEN>` = fake token) | gh | Exit | Design §4 cause it should map to |
|---|---|---|---|---|
| `01-not-signed-in` | `env -u GH_TOKEN -u GITHUB_TOKEN GH_CONFIG_DIR=<TMP> gh api user` | 2.102.0 | 4 | `NotSignedIn{system: GitHub, state: SignedOut}` |
| `02-invalid-token` | `GH_CONFIG_DIR=<TMP> GH_TOKEN=<TOKEN> gh api user` | 2.102.0 | 1 | `CredentialRejected{credential: ShellToken{GH_TOKEN}, problem: Rejected}` |
| `03-login-with-token-refused` | `printf '%s\n' <TOKEN> \| GH_CONFIG_DIR=<TMP> GH_TOKEN=<TOKEN> gh auth login --with-token` | 2.102.0 | 1 | `Guard` naming `GH_TOKEN` and how to unset it (§5: `GH_TOKEN`/`GITHUB_TOKEN` make `gh auth login` refuse) |
| `04-repo-not-found` | `GH_CONFIG_DIR=<TMP> GH_TOKEN=<TOKEN> gh api repos/opv-recording-nonexistent-org/none` | 2.102.0 | 1 | `CredentialRejected{credential: ShellToken{GH_TOKEN}, problem: Rejected}` — see note |
| `05-secret-list-not-signed-in` | `env -u GH_TOKEN -u GITHUB_TOKEN GH_CONFIG_DIR=<TMP> gh secret list --repo opv-recording-nonexistent-org/none` | 2.102.0 | 4 | `NotSignedIn{system: GitHub, state: SignedOut}` |
| `06-version` | `GH_CONFIG_DIR=<TMP> gh --version` | 2.102.0 | 0 | Tool version (`Tool::version_args`; §5 probes) |

Note on `04-repo-not-found`: `gh` checks the credential before it looks up the
repository, so with an invalid token (or none) it never reaches the 404 and the
recorded reply is the credential failure. A genuine repository-not-found 404
needs a valid token and is an owner-to-record case below. The recorded pair still
documents what this command really does under the allowed (credential-free) setup.

## Owner to record (need a real fine-grained token)

These reach the response only with a valid credential, so they are not recorded
here. Run each with the same isolated config and pinned environment, then add the
`NN-<case>.stderr` + `NN-<case>.exit` pair and the gh version.

| Case | Exact command (`<TMP>` = empty `GH_CONFIG_DIR`, `<REAL>` = real token) | Design §4 cause it should map to |
|---|---|---|
| repository not found (404) | `GH_CONFIG_DIR=<TMP> GH_TOKEN=<REAL> gh api repos/opv-recording-nonexistent-org/none` | `NotFound{system: GitHub, resource: Repository, state: Missing}` |
| missing Environments permission | `GH_CONFIG_DIR=<TMP> GH_TOKEN=<REAL> gh secret list --repo <repo> -e <environment>` | `CredentialRejected{credential: ShellToken{GH_TOKEN}, problem: Incomplete{missing_fields}}` |
| rate limited | `GH_CONFIG_DIR=<TMP> GH_TOKEN=<REAL> gh api -i repos/<repo>` (repeat until HTTP 403/429) | `Unavailable{system: GitHub, why: RateLimited{retry_after}}` |
