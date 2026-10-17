# End-to-end test application (design §13.2)

This directory is a complete, self-contained `opv` project used by the end-to-end tests.
It holds **IDs, names and rules only — never a value**: every field in `world.json` carries
a marker (`test-marker-e2e-…`, `e2e-marker-…`), and no real credential, email address or
account ID appears anywhere here.

It is modelled on `tests/sim/scenarios/check/`, but is a full application rather than a
single item: two environments, multiple products, role-scoped keys, file keys, a personal
key, a remote execution profile, and one target per provider.

## Files

- `secrets.toml` — the project configuration, loaded through the file route
  (`opv --config tests/e2e/app/secrets.toml …`).
- `world.json` — the `opv-sim` world matching that configuration. It is the simulator's
  view of 1Password, Fly, Kubernetes, GitHub and the builder host. Loaded with
  `OPV_SIM_WORLD=tests/e2e/app`.
- `manifest/` — the same project carried as a 1Password manifest item, for the
  configuration-in-1Password route (see `manifest/README.md`).

## The configuration

Two environments:

- `dev` — no targets, so the personal key is allowed. Its team values live in the `shared`
  and `web` boundary items. `personal_vault`/`personal_item` name the developer's own item.
- `prod` — `confirm_env = true`, one target per provider, and the reviewed `builder`
  remote profile. Fly app `e2e-app-prod`, Kubernetes context `e2e-cluster` / namespace
  `e2e-prod` (Deployment `e2e-app`, container `e2e-app` beside a `sidecar`, config as
  ConfigMaps, file keys mounted under `/run/secrets/{product}`), GitHub repo
  `e2e-org/e2e-app` environment `production`. Each target has a `state_vault_id` for its
  state items.

Two products:

- `shared` — `source_only`, holding `DATABASE_URL` (secret) and `FEATURE_FLAGS` (config).
- `web` — `API_KEY` (secret), `LOG_LEVEL` (config), `DATABASE_URL` shared from
  `shared/DATABASE_URL`, `SESSION_SECRET` (`roles = ["serve"]`), `MIGRATION_TOKEN`
  (`roles = ["migrate"]`), file keys `TLS_CERTIFICATE`/`TLS_PRIVATE_KEY` (dev and prod;
  written under `WEB_SECRETS_DIR` locally, mounted on Kubernetes), the config file key
  `OTEL_RESOURCE` (prod), and the personal `PERSONAL_LLM_KEY` (dev).

Every key is declared for exactly the environments that use it. The `web` boundary item
holds the `web` section, the `shared` boundary item the `shared` section; a `from` key
reads the source product's field.

## Running the e2e tests

The Rust test `tests/e2e_app_loads.rs` loads the configuration and opens the world through
the simulator:

- `opv --config tests/e2e/app/secrets.toml config describe --json` must exit 0.
- `OPV_SIM_WORLD=tests/e2e/app opv-sim … op whoami` must exit 0, proving `world.json`
  parses and answers.

For the manifest route, force the project and name one of the two accounts (the world
signs in two accounts on `https://e2e.1password.com`):

```
OPV_PROJECT=e2e-app OP_ACCOUNT=AE2EDEVACCOUNT000000000001 opv config describe --json
```

with the `op` name provided by `opv-sim` (`opv-sim install <bin>` and `PATH=<bin>:$PATH`).

## Simulator artifacts

Running the simulator against this directory creates `.lock`, `calls.log` and
`sim-state.json`. They are bookkeeping, not part of the fixture, and are ignored by
`.gitignore`.
