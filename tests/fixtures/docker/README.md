# docker recordings

Real `docker` output. Nothing here is invented.

## Kept from the container-transport recordings (`3b8e180`)

Recorded on 2026-10-16 with **Docker CLI 27.5.1** (API 1.47) against **Docker Desktop 4.93.0, Engine 29.8.1**, through the WSL 2 integration. Each case has `.stdout` and/or `.stderr` (only when non-empty) and `.exit`. Every command ran with stdin closed and `NO_COLOR=1`.

The container transport was dropped (`docs/design/delivery-transports.md` §0). Only the cases the Docker Swarm target reuses are kept (§8.8 and §8.9 of that design). The other cases stay readable at commit `3b8e180` under this directory, and the design cites them there.

| # | Case | Command | Exit | Used for |
|---|---|---|---|---|
| success/01 | client and server version | `docker version --format '{{json .}}'` | 0 | the version shape |
| success/14 | context endpoint | `docker context inspect --format '{{json .Endpoints.docker.Host}}' default` | 0 | `"unix:///var/run/docker.sock"` |
| failures/05 | daemon unreachable, info | `DOCKER_HOST=unix:///nonexistent/docker.sock docker info --format '{{json .SecurityOptions}}'` | **0** | stdout `null`, stderr `Cannot connect to the Docker daemon …`: exit 0 is not success |
| failures/06 | daemon unreachable, run | the same `DOCKER_HOST`, `docker run …` | 125 | `Cannot connect to the Docker daemon` |

## Swarm (`swarm/`)

See `swarm/README.md`.
