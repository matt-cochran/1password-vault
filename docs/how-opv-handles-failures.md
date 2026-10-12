# How opv handles failures

opv talks to 1Password and to a deployment target through their own CLIs (`op`, `flyctl`, `az`, `kubectl`), over networks that drop, time out and lag. This page says what opv does when something goes wrong and what you see. The exit codes and error codes themselves are listed in [usage](usage.md#exit-codes).

## What a failure looks like

Every failure ends the same way on stderr: opv's error line, then (when an external call failed) what that program said, then at most one `Do:` line and exactly one `Next:` line, always last.

```text
opv: source error: op item edit failed (exit 1): signed in to 1Password as SERVICE_ACCOUNT, but item iprd in vault vprd is not available to this identity
  op said: <the last lines op wrote on stderr, secrets masked as __SECRET__>
Do: grant this identity write access to the vault (vault vprd), or check vault_id and item_id in the configuration
Next: opv item skeleton prod
```

- **`Next:`** is one command that runs as typed: no prose, no placeholders. When the fix is not a command, it is the command you ran, to run again once the `Do:` step is done. A usage error points at that command's `--help`; a misspelt environment, product or key gets the same command with the closest declared name.
- **`Do:`** is a step only a person can take: sign in, fill a value in 1Password, approve a guarded environment, type in their own terminal. A configuration error names `file:line: field`, shows the line, and its `Do:` is the edit to make when opv can work it out.
- **`<program> said:`** is the last stderr lines of the call that failed (at most 5), scrubbed (below). Configuration, policy and findings errors never carry one.
- `run` is the exception: it exits with your command's own code and prints nothing of its own unless opv itself failed (`opv: ...`).

Scripts and assistants can match `^Do: ` and `^Next: `. With `--json` the same lines are the `do` and `next` fields of the [failure document](usage.md#json-contract), and `error.retry` says whether running the same command again can help.

## Reads are retried, writes never are

- A read (`op item get`, a secret list, an app status) is tried up to 3 times, about 1 s and then 2 s apart, with a line on stderr: `retrying op item get (2/3) in 1.0 s`.
- A definite answer is never retried: not signed in, no access, or something that does not exist (`op` saying an item or vault is missing, `kubectl` `NotFound`, `az` `SecretNotFound`/`ResourceNotFound`). Failure text opv does not recognise keeps its retries.
- A failed 1Password item read is diagnosed before it is retried (`op whoami`, then `op vault get <vault_id>`), so a missing sign-in, removed vault access or a moved, archived or deleted item is reported at once, by ID, with the command that fixes it. These checks are free under 1Password's rate limits.
- A write is never repeated. When a write fails or its outcome is unclear, opv reads the target back to find out what happened before it reports anything.

## Time limits and progress

- `--timeout <secs>` (default 1800) is one budget for the whole run, waits included. A read that fails is retried only while time remains.
- Each call has its own limit as well: 15 s for a diagnosis, 60 s for a read, 120 s for a write, and 15 minutes for a write that waits for a rollout (`flyctl secrets deploy`, `az containerapp update`, `kubectl apply`/`replace`).
- Anything that waits prints a progress line on stderr at least every 15 s: `waiting for revision ca-myapp--0000002: Provisioning, 45 s`.
- `--verbose` prints one line per external call (program, arguments, duration, outcome), followed by that call's scrubbed stderr (`    stderr: ...`) and the size and shape of its result (`    stdout: 510 bytes, JSON object with keys: ...`). A result's content is never shown.

```text
op item get iprd --vault vprd --format json (0.02 s): exit 0
    stdout: 510 bytes, JSON object with keys: category, fields, id, sections, title, vault, version
flyctl secrets list --app myapp-prod --json (0.02 s): exit 0
    stdout: 91 bytes, JSON array of 1
```

## Exit 9: re-run the same command

Exit 9 means nothing is known to be broken, but opv cannot say more. It has two causes, with their own error codes:

- **`provider_unavailable`**: 1Password, Fly, Azure or the cluster did not answer after its retries, before anything was written. This applies to `status` and `plan` too. The message names the provider, the step and its status page:

  ```text
  opv: outcome unknown: Fly did not respond after 3 attempts (fly secrets list); nothing was changed. Check https://status.flyio.net, then re-run
  Next: opv plan prod
  ```

- **`outcome_unknown`**: a write timed out, was killed or lost its connection, and reading back could not settle whether it was applied. After a run has started writing, an unanswered read is exit 9 too, never "nothing was changed".

Re-running the same command is safe, and CI may retry a job that exits 9; codes 2 to 8 need a fix first. A re-run with `--expect-plan <id>` still matches: what the interrupted run already wrote counts as that plan's own progress.

An update the target refused with nothing applied (Azure: no new revision, provisioning `Failed`) is not exit 9 but exit 5, `update_refused`, with `Next: opv doctor --env <env>`, so CI does not retry it.

## Checks before the first write

`sync` checks everything it can, read-only, before it writes anything; any failure stops it with nothing written.

- **Keys.** A key missing or failing a rule refuses the sync (exit 6) and names every blocking key at once, with the `opv explain` command for them. On a `confirm_env` environment the missing `--confirm` is named in the same refusal.
- **Plan.** With `--expect-plan <id>`, a plan that changed since it was reviewed refuses (exit 6) with the new id.
- **Fly.** A deleted (`dead`) app stops the run. A Fly deploy already running is waited for (releases re-read every 5 s, within `--timeout` and at most 10 minutes). An app with no machines or only stopped machines is a `warn` line; secrets still stage, and `--deploy` is skipped with `deploy skipped: <app> has no machines; staged secrets apply when machines start` (exit 0).
- **Azure.** The subscription (a sign-in or visibility problem names `az login` or the subscription), the vault (a soft-deleted vault gets the recover command), data-plane access (a firewall or a missing role), and the Container App, which must be in single revision mode. An update already in progress is waited for by `sync`; `status` and `plan` never wait, they print one `warn` line and show the current state. An app whose last update failed is a `warn` line; opv applies a fresh revision.
- **Kubernetes.** Every right a sync needs. `doctor` fails a missing one with the exact grant; `sync` refuses before its first write when a right only a deploy uses is missing (delete Secrets or ExternalSecrets, list ReplicaSets and Pods).
- **Key Vault → Kubernetes.** The cluster serves `external-secrets.io/v1`, the `ClusterSecretStore` exists and is `Ready`, and you may create ExternalSecrets in the namespace.

After a deploy, opv waits until the new revision or rollout is healthy. If it is not, the previous one keeps serving, nothing is pruned, and opv exits 5 (`target_unhealthy`). Store entries are deleted only after a healthy deploy.

## Interruptions

Ctrl-C, a CI cancel or SIGTERM is passed to the running `op`, `flyctl`, `az` or `kubectl` call, which gets 5 s to stop before it is killed. opv then removes its private directories (the Azure sign-in directory of `deploy_credentials`), prints `interrupted during <step>; safe to re-run` and `Next:` with the same command, and exits 130 (SIGINT) or 143 (SIGTERM). With `--json` it also prints the failure document with code `interrupted`.

Every flow is built so that stopping it after any call leaves the app working, and running the same command again finishes the rest. One known exception on Fly is described under [Pruning on Fly](usage.md#pruning-on-fly).

## What a CLI said, without the secrets

The stderr of every `op`, `flyctl`, `az` and `kubectl` call is held in memory (never on disk) and shown only after scrubbing:

- every value opv read or wrote in the run is replaced with `__SECRET__`, in its raw form and its common encodings (JSON-escaped, quoted, base64, base64url, percent-encoded);
- patterns catch secrets opv never handled: JWTs, `Bearer` tokens, `OP_SESSION_*`, 1Password service-account tokens, Azure SAS signatures, account keys and client secrets, PEM private keys, well-known API key prefixes, and `password=`, `token=`, `secret=`, `apikey=` assignments;
- control characters are removed and lines are cut at 240 characters.

Names and IDs stay readable. A CLI's stdout and what opv sends on stdin are never shown. Masking can only catch values it knows or recognises: a value opv has not read yet (a failure during the item read itself) is masked by the patterns alone.

## Sign-in and access problems

- Not signed in to 1Password on a person's machine is exit 7 with `opv login <env>` (the same in every shell). Under CI (`CI` or `GITHUB_ACTIONS` set and not `false`) it says to set `OP_SERVICE_ACCOUNT_TOKEN` instead. A machine with no 1Password account gets the `op account add` command first.
- With a service-account or Connect token set, a failing `op whoami` cannot tell a rejected token from a lost network, so it is a 1Password error (exit 4) that names the variable to check.
- Signed in, but the read still failed: exit 4, naming the vault and item IDs and the identity type (never the identity), and telling removed vault access from a moved, archived or deleted item.
- Fly: with `FLY_API_TOKEN` or `FLY_ACCESS_TOKEN` set, a failed call is a target error (exit 5) asking you to check that the token can access the app. Without a token, `flyctl auth whoami` decides between "not logged in to Fly" (exit 7, `flyctl auth login`) and a target error.
- A rejected or incomplete `deploy_credentials` item is exit 7, `deploy_credentials_failed`, with nothing changed; `doctor --env` shows it as one `FAIL deploy credentials` line and still runs its other checks.
- A missing CLI is exit 3, and `doctor` prints its install command for your OS. Only the CLIs the environment needs are required.

Design and tests: [resilience](design/resilience.md) (NR-1 to NR-31).
