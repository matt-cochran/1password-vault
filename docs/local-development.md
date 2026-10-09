# Local development

## Local-only setup

Use one development vault, an item with one section per product, concealed secret fields
and text configuration fields. Keep operator credentials in a separate profile.

Requirements: the 1Password CLI `op` 2.40.0 or newer, signed in (`opv login dev`, or the desktop app
integration). On WSL, `op` must be the Linux CLI installed inside WSL (see [WSL](#wsl)).

**New configuration.** If there is no `secrets.toml` yet, let `init` write one from the item.
Omitting `--fly-app` creates a run-only environment; no placeholder app is needed:

```sh
opv init dev --vault fleet-dev --item fleet
opv doctor --env dev --product zonetico
opv check dev --product zonetico
opv run dev --product zonetico -- cargo run
```

init writes IDs and declarations, never values; review keys, rules and modes.

**Existing configuration.** `init` refuses when `secrets.toml` already exists (exit 2) and never
merges. To add a local environment next to deployed ones, add its block by hand. It needs only
the vault and item IDs (from `op vault list --format json` and `op item list --vault <vault>
--format json`, which list IDs and titles, not values), and then each key that should load
locally lists `dev` in its `environments`:

```toml
[environments.dev]
vault_id = "vdev1234example"
item_id  = "idev1234example"

[products.zonetico.keys.DATABASE_URL]
kind = "secret"
environments = ["dev", "staging", "prod"]
```

`doctor --env dev` then checks only what local work needs (configuration, `op`, its sign-in and
whether `op` can start a local command) and skips the deployment CLIs. Unscoped `doctor` also
reports that last check, as a warning, because deployment commands still work through
`op.exe`.

`check` reads the selected environment's item once and validates only the selected product;
fields in other products' sections are skipped, so they cannot fail it. It exits 8 when a key
is missing or failing a rule.
It makes no deployment target call. check --json reports names/states/rules/findings and
target_checked=false. It can read values internally to validate them, but prints none.
run remains reference-only: it does not pre-read or transform values. Use check separately.

## Launch from each repository or worktree

Use an explicit config path to avoid selecting an unintended ancestor configuration.

```sh
opv --config /path/to/fleet/secrets.toml run dev --product zonetico -- cargo test
opv --config /path/to/fleet/secrets.toml run dev --product journeeze -- npm run dev
opv --config /path/to/fleet/secrets.toml run dev --product allumata -- docker compose up
```

Do not infer product identity from a worktree directory name or reuse staging credentials
automatically. Compose should consume process environment entries, not a plaintext env_file.

## Switching products: v0.4 migration

run removes every key name declared in the loaded configuration from the inherited
environment, then adds only the selected applicable references. This clears other products'
managed keys and mode-skipped keys. Selected keys are resolved from 1Password.

PATH, shell/tool context, 1Password authentication and undeclared variables remain inherited.
This is managed-key isolation, not a sandbox. Keep operator commands in a separate terminal.
If an app relied on an inherited managed key, declare its proper development field instead.

Library users: `InitArgs::fly_app` is an `Option<String>`; a custom `CommandRunner` must
implement `run_inherited_clean` for managed local runs (the default fails closed with exit 3
when there are names to remove), and may override `local_run_supported`.

## WSL

Windows op.exe may use Windows desktop authentication for metadata reads, but cannot execute
a Linux child for opv run. An `op` on PATH that is a Windows binary is rejected by `run` (exit 3);
`doctor` reports it on its `op local run` line, as a failure under `--env` for a local-only
environment and as a warning otherwise. Shell aliases are not consulted by subprocess lookup.
Do not use a wrapper that silently substitutes op.exe.

Use Linux op with its own owner-authenticated session:

```sh
opv login dev        # adds the account at op's prompts if none is set up, then signs in
opv doctor --env dev --product zonetico
```

Follow CLI prompts yourself; never give credentials or session tokens to an agent.
Do not save them in shell profiles. See [manual sign-in](https://www.1password.dev/cli/sign-in-manually).
Windows-native commands may use Windows opv/op directly in PowerShell.
Automatic Windows desktop-to-Linux execution is not provided.

## Remote development

Local injection does not automatically forward credentials over SSH. A remote wrapper must
define allowed keys, authenticated transport, masking, cancellation and process lifetime.
Do not rsync secret files or use wildcard forwarding.

Track [Zonetico #565](https://github.com/matt-cochran-products/zonetico-saas/issues/565)
and [infra #524](https://github.com/matt-cochran-products/infra/issues/524) for ecosystem integration.
Hetzner remains local development only, outside CI/CD.

## Dogfooding receipt

Automated checks use synthetic credentials and fake vendor CLIs; they do not prove live
account provisioning. The owner configures a disposable development item, runs doctor,
check and a real product smoke test, then records product/tool versions, success/failure
and missing names only. Verify local execution before remote propagation.

Supported: `op` 2.40.0 or newer; WSL 2 with the Linux `op`; native Linux, macOS and Windows
(PowerShell). Automated tests use fake CLIs; live receipts are recorded on issues #52–#54.
