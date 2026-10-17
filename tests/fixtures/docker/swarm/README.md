# docker Swarm recordings (read-only; no swarm)

Recorded on 2026-10-17 with **Docker CLI 27.5.1, Engine 29.8.1, API 1.56** (`04-version-client-server.stdout`) on WSL 2 with Docker Desktop. This node is **not** in a swarm. Every command ran with `env -i PATH HOME NO_COLOR=1` and stdin closed. Nothing was created or changed: no `docker swarm init` was run, because that needs the owner's approval (`docs/design/delivery-transports.md` §8.9, O13).

| Case | Command | Exit | Used for |
|---|---|---|---|
| 01-info-swarm-inactive | `docker info --format '{{json .Swarm}}'` | 0 | the shape of `.Swarm`: `LocalNodeState`, `ControlAvailable` (doctor) |
| 02-secret-ls-not-a-manager | `docker secret ls --format '{{json .}}'` | 1 | `This node is not a swarm manager …` (`OwnerSetupRequired{SwarmManager}`) |
| 03-service-inspect-not-a-manager | `docker service inspect opv-recording-svc --format '{{json .Spec.TaskTemplate.ContainerSpec.Secrets}}'` | 1 | the same refusal, with a `Status: …, Code: 1` wrapper and a blank stdout line |
| 04-version-client-server | `docker version --format '{{.Client.Version}} {{.Server.Version}} {{.Server.APIVersion}}'` | 0 | versions |
| help/* | `docker <secret create\|secret ls\|secret inspect\|secret rm\|config create\|config ls\|config rm\|service create\|service update\|service inspect\|service ps\|context inspect> --help` | 0 | flag names the adapter uses (stdin `-`, `--label`, `--secret-add/rm`, `--config-add/rm`, `--env-add/rm`, `--detach`, `--update-*`, `--rollback*`) |

Still to record, on a throwaway single-node swarm, once the owner approves: S-R1 to S-R9 in the design (§8.9).
