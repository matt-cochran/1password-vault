# Delivery transports: containers, Fly and the shared-host shim

Status: design for review (#136 item 5). **Nothing here is implemented.** The local transport (`opv run`, [local delivery](local-delivery.md)) is the only mounted-file transport opv ships. The existing app-side shim stays in service until a replacement has been verified, as described below.

## The one contract, several transports

Every transport delivers the same declared contract, which local delivery already uses:

| Part | Where it is declared | Example |
|---|---|---|
| Source | the key's own field, or `from = "<product>/<KEY>"` | `journeeze/GITHUB_APP_PRIVATE_KEY` |
| Destination | `file = "<lowercase/dash segments>"` | `github-app/private-key` |
| Directory variable | `[products.<p>.local] secrets_dir_env` | `JZ_VAULT_DIR` |
| Role | `roles = [...]` on the key (0.9.0); none means every role | `["migrate"]` for `DATABASE_URL_UNPOOLED` |
| Environment mode | `[products.<p>.local] environment` | `declared_only` |

The rules don't change between transports:
- Bytes are delivered exactly: no interpolation or newline changes.
- Files are 0400 inside a 0700 directory that lives in RAM.
- Names follow the consumer's contract.
- A key outside the run's role is never resolved.
- An unsupported transport fails closed, with a metadata-only reason. It never falls back to disk or to plain environment variables.

`opv run --preview` and `opv_delivery_preview` report what a transport would deliver without reading a value. Each transport adds a `transport` field to that preview.

## Platform matrix

| Transport | Status | Where values live | Role separation | Notes |
|---|---|---|---|---|
| Local process, Linux/WSL | implemented | `op run` env, then a tmpfs directory | the selection never resolves another role's keys | [local delivery](local-delivery.md) |
| Local process, macOS / Windows | refused for file keys | n/a | n/a | `declared_only` without file keys works |
| Local container (Docker, Podman) | **proposed** (phase A) | host tmpfs directory, bind-mounted read-only | same as local process | needs a known container UID |
| Fly machine, entrypoint step | **proposed** (phase B) | Fly secrets (env at boot), then a tmpfs directory in the guest | filtered in the guest; see the limit below | replaces the app shim |
| Fly `[[files]]` from a secret | **rejected as default** | written by Fly into the guest root filesystem | none | not RAM-only; verify in a spike before any use |
| Kubernetes, Azure | out of scope here | provider secret stores | n/a | existing sync targets; #40–#42 are deferred |

## Phase A: local containers

```text
opv run dev --product journeeze --role serve --container -- docker run … image
  └─ op run -- opv local-delivery … -- docker run --mount type=bind,src=<ramdir>,dst=/run/secrets/journeeze,readonly \
                                                --user <uid>:<gid> -e JZ_VAULT_DIR=/run/secrets/journeeze … image
```

- opv creates the same private RAM directory as for a local process, then supervises `docker run` (or `podman run`) in the foreground. Cleanup on exit, on signals and in the sweep is the same as today.
- The container reads the files as the host user. opv adds `--user <uid>:<gid>` (Docker) or `--userns=keep-id` (rootless Podman). A runtime whose UID mapping opv can't determine, such as rootless Docker with a remapped user, is refused. It is never answered with world-readable files.
- The container's environment holds only the directory variable and declared configuration. opv never passes `-e` with a secret, an `--env-file`, or a value in an argument.
- **Limits:** the container daemon, and root on the host, can read the directory. A container that runs as root, or with `CAP_DAC_OVERRIDE`, can read any file in the mount. This adds no protection against the same host user. It only keeps values off disk and out of the environment.

## Phase B: Fly, and retiring the app shim

**Today:** Fly delivers app secrets to every machine of the app as environment variables at boot. opv syncs them as `FLEET__<PRODUCT>__<KEY>` (or the target's `secret_name`). Journeeze's shared-host shim (`jz_host::fleet_secrets`, switched on with `JZ_VAULT_FROM_ENV=fleet`) runs at startup. It converts the delivered variables into 0400 files on tmpfs, then re-executes itself without the secret variables. That is an ADR exception owned by the app.

**Proposal:** opv owns that step. The image's entrypoint becomes:

```text
opv local-delivery --from-env FLEET__JOURNEEZE__ --role serve \
  --file GITHUB_APP_PRIVATE_KEY=github-app/private-key … --dir-env JZ_VAULT_DIR -- jz-serve
```

1. **It is the same step as the local transport.** `local-delivery` already turns delivered values into the private RAM directory and filters the environment. `--from-env <prefix>` maps the target's secret names back to keys, using the same name template `opv sync` used. The mapping is computed from the configuration and passed as key names only.
2. **Role filtering happens in the guest.** Variables of keys outside `--role` are removed from the environment before the app starts, and they are never written as files. The serving process therefore never gets `database/owner-url`.
3. **The `release_command` uses `--role migrate`.** The migration process gets only its own material.
4. **Each key is checked against its rules before the app starts.** A missing or failing key stops the start with a names-only message. It doesn't start the app with a partial directory.

**Limit, stated plainly:** on one Fly app, every machine's init process receives every secret of the app as an environment variable at boot. That includes migration-owner material. Role filtering keeps that material out of the serving process and its directory, but not out of the guest's init process memory. **Strict separation** means the migration credentials live on a separate Fly app (a separate opv target that only `migrate` keys are delivered to). The release step then runs there. Both are supported by placements today: `targets.<name>.products` and per-target delivery.

**Fly `[[files]]` with `secret_name`** writes a secret's (base64) value to a path in the guest when the machine starts. It looks like a native mount. But the file lands in the guest's root filesystem, which is disk-backed on the host, not in RAM. It is not used by default. A spike has to confirm where the file is stored and how long it lives before any opt-in.

### Migration plan for the shim (human-authorized at every live step)

| Step | Who | Change | Exit criterion |
|---|---|---|---|
| 0 | opv | ship `local-delivery --from-env` and `--role` in a tagged release, with fixture tests: exact bytes including PEM and a trailing newline, migration keys absent from the serve directory and environment, canary values absent from logs | tests in CI; preview output reviewed |
| 1 | Journeeze maintainers | add opv to the image and add a **second**, unused entrypoint; the shim stays the default | image builds; `opv run --preview` for both roles matches the mapping table in #136 |
| 2 | a person, staging | switch staging to the opv entrypoint (`JZ_VAULT_FROM_ENV` unset); keep the shim in the image | `MountedSecretStore` reads every expected name; the webhook secret's mapping is confirmed or explicitly declared absent; delivery evidence verified |
| 3 | a person, production | canary one machine, then all | same checks; rollback is reverting the entrypoint |
| 4 | Journeeze maintainers | remove the shim and close its ADR exception | only after step 3 has run cleanly for an agreed period |

Each step can be reverted without touching values. No step moves or re-creates a secret: the Fly secrets opv syncs today keep their names.

## What stays out of scope

- Remote development delivery (#139) has its own design: [remote delivery](remote-delivery.md).
- Kubernetes and Azure mounted delivery (#40–#42) are deferred.
- Windows and macOS file delivery stays refused, since neither has a user-owned RAM filesystem opv can verify.

## Open points for review

1. `--container` as an `opv run` flag, compared with a `transport = "container"` setting per product.
2. Whether step 0 also ships a check that the image's entrypoint matches its declared role (a names-only `opv delivery verify` for Fly), or whether that waits for step 2.
3. A separate migration app per environment as the documented default for products with owner credentials. The cost is one more Fly app per environment.
