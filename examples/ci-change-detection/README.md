# CI change detection: sync Fly secrets when 1Password changes

This example keeps a Fly app in step with its 1Password source item. A scheduled job runs
`opv changed` to notice when someone edits a value in 1Password, then syncs. Staging syncs
directly; production syncs only after a reviewer approves the exact plan. A nightly job
checks for drift.

| File | What it is |
|---|---|
| [secrets.toml](secrets.toml) | the configuration: three `fly` environments, `dev`, `staging` and `prod`, one product |
| [.github/workflows/opv-sync-on-change.yml](.github/workflows/opv-sync-on-change.yml) | detect a change, sync staging, plan-then-sync prod |
| [.github/workflows/opv-drift.yml](.github/workflows/opv-drift.yml) | nightly `status --fail-on-drift` and `delivery verify` |
| [.github/workflows/opv-promotion.yml](.github/workflows/opv-promotion.yml) | promote dev, then staging, then prod, each tier gated on `opv ready <env> --gate` |
| [.github/workflows/opv-pr.yml](.github/workflows/opv-pr.yml) | pull request: `needs --gate`, `contract --check`, `ready --gate`, and the `opv/relaxations` status |
| [.github/actions/install-opv/action.yml](.github/actions/install-opv/action.yml) | install the 1Password CLI and opv, checksum-verified |

All three generated workflow files are exactly what `opv ci workflow --on-change`, `opv ci
workflow --drift` and `opv ci workflow prod --target app` print for this configuration, so
regenerate them instead of editing by hand:

```sh
opv ci workflow --on-change              > .github/workflows/opv-sync-on-change.yml
opv ci workflow --drift                  > .github/workflows/opv-drift.yml
opv ci workflow prod --target app        > .github/workflows/opv-pr.yml
```

## What the workflows do

**`opv-promotion.yml`** promotes one change through the tiers: a `dev` job runs
`opv ready dev --gate` and, only if the gate passes, `opv sync dev --deploy`. A `staging`
job `needs: dev`, gates on `opv ready staging --gate` and promotes; a `prod` job
`needs: staging`, gates on `opv ready prod --gate` and promotes. A tier never runs after
an earlier tier failed, and a failing gate stops the chain. The recipe is hand-written (not
printed by `opv ci workflow`), reads 1Password with the deployer token, never runs
`opv apply` and never writes a value to 1Password.

**`opv-sync-on-change.yml`** runs every 15 minutes, on a push that edits `secrets.toml`, or
by hand. Its `detect` job runs `opv changed <env> --json` for each environment:

- `staging` (`confirm_env = false`) is synced directly with `opv sync staging --deploy`.
- `prod` (`confirm_env = true`) is planned first. The plan (names only) goes to the job
  summary for a reviewer, and the sync uses `--expect-plan <id>`, so it refuses if anything
  changed after the review.

**`opv-drift.yml`** runs nightly. For each environment it runs `opv status <env>
--fail-on-drift` (exit 8, `target_drift`, when the target no longer matches 1Password) and
`opv delivery verify <env> --json` (exit 8, `delivery_unverified`).

**`opv-pr.yml`** runs on every pull request, on its own repository token and the reader
service account, and holds the sync back to a manual `workflow_dispatch`:

- A `checks-<env>-<target>` job runs `opv needs --gate` (a name the code reads but the
contract does not declare fails), `opv contract --check contract.json` (a stale committed
contract fails) and `opv ready prod --gate` (the promotion gate fails).
- A separate `opv/relaxations` job runs `opv contract --relaxations --json` against
`origin/<default branch>`. It succeeds when the contract lists no relaxation; while it
lists one, it fails unless the pull request's head SHA has an approving review. Make
`opv/relaxations` a required status check so an unapproved relaxation cannot merge. It reads
`${{ github.token }}` and no 1Password secret, and prints names and reasons only.

## Two service accounts

CI needs two 1Password service accounts, so no job holds more access than it needs:

- A **reader**, created with `opv access <env> --create --github <owner/repo>`, is read-only
  on the environment's vaults and the state vault. It runs `opv changed`, `opv plan` and the
  drift check, and its token is the repository secret `OPV_READER_TOKEN`.
- A **deployer** runs `opv sync`. Store its token as a secret on the `prod`/`staging`
  **GitHub environment** and require reviewers there, so GitHub releases the token only after
  the plan has been approved. It is the environment secret `OPV_DEPLOY_TOKEN`.

The workflows reference the tokens as `${{ secrets.… }}` and pass them through a step's
`env:` only, never as an argument and never written to a file. GitHub masks registered
secrets in logs; opv also registers `OP_SERVICE_ACCOUNT_TOKEN` and scrubs it from its own
output. The workflows print names, ids and states only.

## The exit-10 branch, and why "any non-zero exit is a failure" is wrong

`opv changed` uses exit **10** for a result, not a failure: it means the source item changed
and the next step is the sync. Exit **0** means unchanged. Any other exit code is a real
failure, such as `opv` or `op` being unreadable. A wrapper must tell them apart:

```sh
set +e
opv changed staging --json > changed.json
rc=$?
set -e
case $rc in
  0)  echo "staging=no"  >> "$GITHUB_OUTPUT" ;;   # unchanged
  10) echo "staging=yes" >> "$GITHUB_OUTPUT" ;;   # changed: run the sync
  *)  exit "$rc" ;;                               # unreadable: fail the job
esac
```

A wrapper that treats **any** non-zero exit as a failure fails on every legitimate change, so
the sync never runs. A wrapper that ignores **every** non-zero exit hides `unreadable`: the
job reports success while opv never saw the item, and a broken rotation goes unnoticed. Exit
10 is the one non-zero code that means "changed"; keep every other code as a failure.

Reference: [delivery transports §2.5](../../docs/design/delivery-transports.md), [opv and
CI](../../docs/usage.md#when-sync-runs-opv-changed-the-drift-check-and-ci).
