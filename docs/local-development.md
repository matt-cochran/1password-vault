# Local development

## Local-only setup

Use one development vault, an item with one section per product, concealed secret fields
and text configuration fields. Keep operator credentials in a separate profile.

    opv init dev --vault fleet-dev --item fleet
    opv doctor --env dev --product zonetico
    opv check dev --product zonetico
    opv run dev --product zonetico -- cargo run

Omitting --fly-app creates a run-only environment. No placeholder app is needed.
init writes IDs and declarations, never values; review keys, rules and modes.
It never merges an existing configuration. Do not use --force to replace shared settings.

check reads the selected environment's item once and validates only the selected product.
It makes no deployment target call. check --json reports names/states/rules/findings and
target_checked=false. It can read values internally to validate them, but prints none.
run remains reference-only: it does not pre-read or transform values. Use check separately.

## Launch from each repository or worktree

Use an explicit config path to avoid selecting an unintended ancestor configuration.

    opv --config /path/to/fleet/secrets.toml run dev --product zonetico -- cargo test
    opv --config /path/to/fleet/secrets.toml run dev --product journeeze -- npm run dev
    opv --config /path/to/fleet/secrets.toml run dev --product allumata -- docker compose up

Do not infer product identity from a worktree directory name or reuse staging credentials
automatically. Compose should consume process environment entries, not a plaintext env_file.

## Switching products: v0.4 migration

run removes every key name declared in the loaded configuration from the inherited
environment, then adds only the selected applicable references. This clears other products'
managed keys and mode-skipped keys. Selected keys are resolved from 1Password.

PATH, shell/tool context, 1Password authentication and undeclared variables remain inherited.
This is managed-key isolation, not a sandbox. Keep operator commands in a separate terminal.
If an app relied on an inherited managed key, declare its proper development field instead.

Library users: InitArgs.fly_app is optional; a custom CommandRunner must implement
run_inherited_clean for managed local runs. Its default fails closed if removal is needed.

## WSL

Windows op.exe may use Windows desktop authentication for metadata reads, but cannot execute
a Linux child for opv run. An op symlink pointing to a Windows binary is rejected for local
run and development-scoped doctor. Shell aliases are not consulted by subprocess lookup.
Do not use a wrapper that silently substitutes op.exe.

Use Linux op with its own owner-authenticated session:

    op account add
    eval "$(op signin)"
    opv doctor --env dev --product zonetico

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
