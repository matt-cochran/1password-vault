# Spike: GitHub Actions secrets and variables (live recon)

Status: done; the findings are built into the `github` target and the recorded outputs are test
fixtures.

Date: 2026-10-13. A throwaway private repository owned by the maintainer, one GitHub environment
`staging`. Marker values only (`MARKER_*`, `marker-*`). Tools: `gh` 2.102.0, signed in with a
`repo`/`workflow` OAuth token. Recorded outputs, with the repository renamed to
`example-org/example-repo`, are in `tests/fixtures/github/`.

| # | Question | Finding | Consequence |
|---|---|---|---|
| Q1 | `gh secret set NAME -R <repo>` with the value on stdin | Exit 0, nothing on stdout or stderr when stdin is not a TTY. | Values on stdin only (SR-3); one call per name. |
| Q2 | `gh secret list --json name,updatedAt,visibility` | `[{"name","updatedAt","visibility":""}]`; no value and no digest. | Secret target state is `unknown` when listed: every ready secret is written (design §3). |
| Q3 | `gh variable set` / `list --json name,value,updatedAt,createdAt` | Variables come back **with their values**. `set` on an existing name updates it (exit 0). A trailing newline is kept byte-for-byte. | Config compared exactly; `set` is create-or-update. |
| Q4 | `-e <environment>` when the GitHub environment does not exist | `set`: exit 1, `failed to fetch public key: HTTP 404`; `list`: exit 1, `failed to get secrets: HTTP 404`. | Preflight lists the repository's environments first and names the create command. |
| Q5 | Missing repository | exit 1, `HTTP 404: Not Found`. | Same 404 text as Q4: preflight tells them apart by checking the repository first (`gh api repos/<repo>`). |
| Q6 | Invalid name (`BAD-NAME`), `GITHUB_` prefix | exit 1, HTTP 422 with the rule. | Refused at load (names are known then); never sent. |
| Q7 | Empty value | Secret: accepted. Variable: exit 1, HTTP 422 `missing required key: value`. | An empty config value is a refusal on this target (`plan` shows it). |
| Q8 | Size limits | Secret: 47 952 bytes accepted, 47 953 refused (`Value is too large`, the limit applies to the encrypted form). Variable: 48 000 accepted, 48 001 refused. | Refusals before any write, by the store's `refusal` (FR-22). |
| Q9 | Invalid token (`GH_TOKEN=...`) | exit 1, `HTTP 401: Bad credentials` plus `Try authenticating with: gh auth login`. `gh auth status` exits 1 naming `GH_TOKEN`. | `signed_out` phrase `HTTP 401`; doctor uses `gh auth status`. |
| Q10 | `gh secret delete` / `gh variable delete` of a missing name | exit 1, `HTTP 404`. | Prune deletes only listed names; a 404 on delete counts as already gone. |
| Q11 | Environments of a repository | `gh api repos/<repo>/environments` → `{"environments":[{"name":...}]}`. | Preflight read. |
| Q12 | Output echoing values | No `gh` command used echoes a secret value; `variable list` returns config values only. | Variable values are config (FR-14), never secrets: a concealed config key is refused on this target rather than published as a variable. |

Pinned environment for every `gh` call: `GH_PROMPT_DISABLED=1`, `GH_NO_UPDATE_NOTIFIER=1`,
`NO_COLOR=1`, `GH_PAGER=cat`.
