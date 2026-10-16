# docker recordings (#136 container transport)

Real `docker` output for the container transport design (`docs/design/delivery-transports.md`, "Container transport"). Recorded 2026-10-16 with **Docker CLI 27.5.1** (API 1.47) against **Docker Desktop 4.93.0, Engine 29.8.1** through the WSL 2 integration (kernel `6.18.33.2-microsoft-standard-WSL2`), image `ubuntu:24.04` already present locally (`--pull never`, `--network none`: nothing was pulled or reached). Host user uid 1000, gid 1000; `$XDG_RUNTIME_DIR=/run/user/1000` on tmpfs.

Each case has `NN-<case>.stdout` / `.stderr` (only when non-empty) and `.exit`. Every command ran with stdin closed and `NO_COLOR=1`.

Markers:

- `<RAMDIR>` / `<RAMDIR-NAME>`: a fresh `mktemp -d "$XDG_RUNTIME_DIR/opv-probe.XXXXXX"`, mode 0700, holding `github/marker` (mode 0400, directory `github` 0700). The marker file holds the test text `-----BEGIN TEST MARKER-----\nopv-136-marker-line\n-----END TEST MARKER-----\n` (multi-line, trailing newline). It is not a credential.
- `<PID>`: the recording shell's pid, in container names.

No recorded file contains a credential, hostname, account or registry name.

| # | Case | Command (abridged) | Exit | Used for |
|---|---|---|---|---|
| success/01 | client and server version | `docker version --format '{{json .}}'` | 0 | runtime identification; `Server.Platform.Name` "Docker Desktop …", `KernelVersion` "…-microsoft-standard-WSL2" |
| success/02 | security options | `docker info --format '{{json .SecurityOptions}}'` | 0 | UID mapping: no `name=rootless`, no `name=userns` |
| success/03 | operating system | `docker info --format '{{.OperatingSystem}}'` | 0 | "Docker Desktop" |
| success/04 | security options and root dir | `docker info --format '{{json .SecurityOptions}} {{.DockerRootDir}}'` | 0 | same, one call |
| success/05 | host user reads the mount | `docker run --rm --pull never --network none --read-only --user 1000:1000 --mount type=bind,src=<RAMDIR>,dst=/run/secrets/probe,readonly ubuntu:24.04 sh -c 'id -u; id -g; stat -f -c %T …; stat -c "%u:%g %a" …; sha256sum < …/github/marker'` | 0 | in the container: uid 1000, the mount is **tmpfs**, dir 1000:1000 700, file 1000:1000 400, digest equal to the host's (06) |
| success/06 | host digest | `sha256sum < <RAMDIR>/github/marker` | 0 | byte equality with 05 and 07 |
| success/07 | container root reads | same mount, no `--user` | 0 | container uid 0 reads a 0400 file owned by uid 1000 (the root limit) |
| success/08 | mountinfo in the container | same as 05, `grep … /proc/self/mountinfo` | 0 | the bind is `ro` and the source is `tmpfs`, uid=1000, mode=700 |
| success/09 | SIGTERM to the client | `docker run --rm … --init --name opv-recording-sig-<PID> … sleep 60`, then `kill -TERM <client pid>` | 143 | the client forwards the signal (sig-proxy, no TTY) |
| success/10 | container gone after SIGTERM | `docker ps -a --filter name=opv-recording-sig-<PID> --format '{{.Names}}'` | 0 | empty: `--rm` removed it |
| success/11 | client SIGKILL | `docker run --rm … --name opv-recording-kill-<PID> … sleep 60`, then `kill -KILL <client pid>`; `docker ps --filter name=… --format '{{.Names}} {{.Status}}'` | 0 | **the container keeps running** after its client is killed |
| success/12 | force removal by name | `docker rm -f opv-recording-kill-<PID>` | 0 | prints the name |
| success/13 | host directory removed while the container runs | `docker run -d … sleep 30`; `rm -rf <RAMDIR>`; `docker exec … sh -c 'ls -la /run/secrets/probe; cat …/github/marker'` | 0 (exec 1) | the container sees an empty directory; the file is gone |
| success/14 | context endpoint | `docker context inspect --format '{{json .Endpoints.docker.Host}}' default` | 0 | `"unix:///var/run/docker.sock"` (a local daemon) |
| success/15 | attached output without a log driver | `docker run --rm … --log-driver none … echo opv-recording-attached-output` | 0 | the attached client still prints the app's output |
| success/16 | default logging driver | `docker info --format '{{.LoggingDriver}}'` | 0 | `json-file`: by default the daemon writes the app's output to disk |
| success/17 | containers by label | `docker run -d … --label io.opv.run=4242 --label io.opv.uid=1000 … sleep 30`; `docker ps -a --filter label=io.opv.uid=1000 --format '{{.Names}} {{.Label "io.opv.run"}}'` | 0 | one line per labelled container: name and owning pid (the sweep's input) |
| success/18 | no labelled container | the same `docker ps` after `docker rm -f` | 0 | empty stdout |
| failures/01 | another uid is refused | `--user 10001:10001`, `cat …/github/marker` | 1 | `Permission denied`: a container user that is not the host user cannot read the files |
| failures/02 | read-only mount | `sh -c 'echo x > /run/secrets/probe/new'` | 2 | `Read-only file system` |
| failures/03 | missing bind source | `--mount type=bind,src=$XDG_RUNTIME_DIR/opv-probe.does-not-exist,…` | **0** | Docker Desktop **creates** the missing source (`.host-ls`: a `drwxr-xr-x root root` directory in the user's runtime directory) instead of failing |
| failures/04 | image absent | `docker run --rm --pull never … opv-recording-absent-image:0 true` | 125 | `No such image` |
| failures/05 | daemon unreachable, info | `DOCKER_HOST=unix:///nonexistent/docker.sock docker info --format '{{json .SecurityOptions}}'` | **0** | stdout `null`, stderr `Cannot connect to the Docker daemon …`: exit 0 is not success |
| failures/06 | daemon unreachable, run | same `DOCKER_HOST`, `docker run …` | 125 | `Cannot connect to the Docker daemon` |
| failures/07 | app exit code | `docker run … sh -c 'exit 3'` | 3 | passed through |
| failures/08 | command not in the image | `docker run … opv-recording-no-such-command` | 127 | OCI runtime `executable file not found in $PATH` |
| failures/09 | force removal of an absent container | `docker rm -f opv-recording-kill-<PID>` (again) | 0 | `No such container` on stderr, exit 0: idempotent |

## Still to record (owner, on hosts that have them)

These are needed before the matching code path may leave "refused" (the design never simulates a reply nobody recorded):

1. **Docker Engine, rootful, native Linux:** `docker version --format '{{json .}}'`, `docker info --format '{{json .SecurityOptions}}'`, `docker info --format '{{.OperatingSystem}}'`, and the 05/07/08 probes.
2. **Rootless Docker:** the same `info` calls (expect `name=rootless` in `SecurityOptions`), and the 05 probe with `--user <host uid>` (expected to fail like failures/01).
3. **Docker with `userns-remap`:** the same `info` calls (expect `name=userns`) and the 05 probe.
4. **Docker Desktop on native Linux and on macOS:** `docker version` and the 08 probe (what file system the mount shows).
5. **A remote endpoint:** `DOCKER_HOST=tcp://127.0.0.1:9 docker context inspect …` and `docker info …` (refusal input).
6. **Podman, rootless:** `podman version --format json`, `podman info --format json` (`host.security.rootless`, `host.idMappings`, `host.serviceIsRemote`, `host.security.selinuxEnabled`), the 05/07/08 probes with `--userns=keep-id` and with `--userns=keep-id:uid=10001,gid=10001`, `--mount type=bind,…,ro=true` and, on an SELinux host, with `relabel=private`; failures 03, 04, 05/06 (`CONTAINER_HOST` unreachable), 08; 09–12 (signals and `podman rm -f`); `--log-driver none` attached output; and `podman ps -a --filter label=io.opv.uid=<uid>` with a `--format` template that prints the name and the `io.opv.run` label (record which template Podman accepts; Docker's `{{.Label "…"}}` is not assumed to work).
7. **Podman, rootful** (`sudo podman info --format json`) and `podman --remote info`: refusal input.
