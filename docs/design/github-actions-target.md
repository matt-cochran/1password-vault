# GitHub Actions target and shared records

Status: designed 2026-10-13 for issue #75 (and the shared-record convention behind #77/#78).
Requirements FR-46 to FR-48 in `docs/design/requirements.md` are normative; this document is
their argument. Spike: `docs/design/spike-github-findings.md`.

## 1. Intent

CI secrets are the last place the portfolio still sets by hand (`gh secret set`), so they drift
from 1Password and rotate by hand. A `github` target lets `opv sync ci` own them with the same
guarantees as every other target: values only on stdin, names-only output, prune only managed
names, a plan before any write.

One value usually feeds many repositories (one Fly org token, one Cloudflare token). The
existing `from` (FR-45) shares a value inside one item, but its source must be some product's
own, delivered key. A *source-only product* gives a shared value one neutral, canonical home.

## 2. Configuration

```toml
[environments.ci]
vault_id = "vci1234example"
item_id  = "ici1234example"

[environments.ci.github]
repo = "my-org/journeeze-saas"        # or repos = ["my-org/a", "my-org/b"]
environment = "staging"               # optional: GitHub environment secrets/variables
products = ["journeeze"]              # optional (fleet): the products this target receives
secret_name = "{KEY}"                 # optional; default "{KEY}"
```

- `repo` / `repos`: exactly one of them; `owner/name` each, validated at load (they go to argv).
- `environment`: optional; must already exist in every listed repository (preflight checks, and
  the `Next:` line is the `gh api -X PUT .../environments/<name>` command). opv never creates a
  GitHub environment: its protection rules are the owner's decision.
- `products`: fleet profile only. Keys of other products render no name for this target (FR-48).
  Default: every product.
- `secret_name`: name template. `{KEY}` required, `{PRODUCT}` optional. Default `{KEY}` because CI
  workflows read fixed names (`secrets.FLY_API_TOKEN`). Names follow GitHub's rule
  `^[A-Za-z_][A-Za-z0-9_]*$`, never `GITHUB_*` (refused at load).

## 3. Flow

GitHub is a staged target with two capabilities the staged flow did not have:

| | Fly | GitHub |
|---|---|---|
| secret read-back | digest only | name and `updatedAt` only |
| change detection | stage, list, compare digests | none: every ready secret is written |
| config | not delivered | GitHub **variables**, read back and compared exactly |
| deploy | `secrets deploy` restarts machines | none: a write is live at once |

- `StagedRuntime::live()` (default `false`): writes are live. `sync` never prints the pending
  line, and `--deploy` prints `nothing to deploy: <target> applies writes at once`.
- `StagedStore::variables()` (default `None`): an optional readable config channel with `list`
  (name → value), `set` (values on stdin, one call per name) and `remove`. `plan`/`status` compare
  config exactly (`present` / `would_change` / `absent`); `sync` sets the ones that differ;
  `--prune` removes managed variable names that are no longer desired.
- Secrets: a listed secret has no digest, so its target state is `unknown` and `sync` writes it
  every run (idempotent; GitHub keeps no history). An `immutable` secret already present by name
  is held, exactly as on Fly. `status` shows `updatedAt` older than the item's last edit as a
  drift hint, never as a verdict.
- `repos = [...]`: one write fans out to every repository; a name counts as present only when
  every repository has it. A failure after some repositories names what was written (NR-10).

## 4. Authentication

`gh` uses the person's session or `GH_TOKEN`/`GITHUB_TOKEN` (credential variables, by name only).
`deploy_credentials` holds one concealed field `GH_TOKEN`: a fine-grained token with *Secrets:
write* and *Variables: write* (plus *Environments: read* for `environment`) on the listed
repositories, never an owner PAT. It reaches `gh` only in the child's environment.

## 5. Shared records: source-only products (FR-47)

```toml
[products.shared]
source_only = true                    # canonical values: never delivered anywhere

[products.shared.keys.FLY_API_TOKEN]
kind = "secret"
environments = ["ci"]

[products.journeeze.keys.FLY_API_TOKEN]
kind = "secret"
from = "shared/FLY_API_TOKEN"
environments = ["ci"]
```

- A source-only product's keys have fields (tidy, skeleton, missing-value lines, rules,
  `immutable`, `--rotate`) but render no target name: never written, never in the managed set,
  never pruned, exempt from the name collision check. `run --product` refuses it.
- `check`/`plan` warn once for a source-only key that no `from` references.
- Opt-in by flag, not by name: an existing product called `shared` keeps its behaviour. The docs
  and `init` recommend the name `shared`.
- The same-item boundary of FR-45 stays: a staging sync never reads a prod value.

## 6. Rejected

- A third "direct" port flow: two optional capabilities on the staged ports cover it with less
  core code and keep `status`/`plan` unchanged for every other target.
- Keyed digests stored as GitHub variables for exact secret change detection: they would publish
  an equality oracle for secret values in a place readable by every workflow.
- Per-product repository templates (`repo = "org/{product}"`): one environment per repository with
  `products = [...]` covers the portfolio with no new naming rules; revisit if it proves verbose.
- Creating GitHub environments: protection rules and reviewers are the owner's call.
