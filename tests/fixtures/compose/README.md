# Docker Compose recordings (the local recipe)

Recorded on 2026-10-17 with **Docker Compose v2.32.4** (`01-compose-version.stdout`) on WSL 2. Every case ran under `env -i PATH HOME NO_COLOR=1` with stdin closed. `config` only renders the model: nothing was started, pulled or created. `<TIME>` replaces compose's log timestamps.

The paths are markers: `/run/user/1000/opv-run.4242-abcdef` stands for opv's private directory, and `journeeze:local` is never pulled.

| Case | Command | Exit | Shows |
|---|---|---|---|
| 01-compose-version | `docker compose version` | 0 | the version |
| 02-recipe-config-under-opv | `OPV_SECRETS_DIR=… OPV_UID=1000 OPV_GID=1000 docker compose -p opv-recipe -f recipe.yml config` | 0 | `user: 1000:1000`, a read-only bind with no `create_host_path`, `logging: none` |
| 03-recipe-config-outside-opv | the same, without the three variables | 15 | `required variable OPV_UID is missing a value: run this under opv run` |
| 04-naive-config-uid-not-exported | `bash -c 'docker compose … -f naive.yml config'` | 15 | `UID`/`GID` not set; the short volume form with an empty source is invalid |
| 05-bash-uid-not-in-environment | `bash -c 'echo "shell UID=$UID"; env \| grep -c "^UID="; env \| grep -c "^GID="'` | 1 | bash has `UID` as a shell variable, not in the environment; no `GID` |
| 06-naive-config-dir-set-uid-unset | `OPV_SECRETS_DIR=… bash -c 'docker compose … -f naive.yml config'` | 0 | `user: ':'`; the short `:ro` form sets `create_host_path: true` |

`recipe.yml` is the recipe in `docs/design/delivery-transports.md` §5. `naive.yml` is the `${UID}:${GID}` form the design rejects.
