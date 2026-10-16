# Remote development delivery over pinned SSH

Status: implemented for review (#139). The owner reviews this design before the change merges.

## Problem

A product's development build runs on a remote builder reached over SSH. The consumer wrapper in use bridged secrets to it with a temporary environment file. That puts plaintext values on disk on both hosts, and it hands the remote side whatever the wrapper exported. The owner would rather turn secret forwarding off than keep that, or add another ad-hoc exporter.

What is required:
- Only the selected application's declared secrets reach its trusted remote runtime, over a protected channel.
- No plaintext file on either host. No value in argv, a shell command, a log, an artifact or an MCP response.
- No forwarded 1Password session, service-account credential, cloud administrator token or unrelated app key.
- The host and the command are reviewed and pinned. MCP gains no shell, executable or path argument, and an agent cannot approve itself.
- The run fails closed on every missing or unknown precondition.

## Design

A product declares reviewed remote profiles next to its keys:

```toml
[products.journeeze.remotes.builder]
host = "builder.example.internal"
port = 22                                   # default 22
user = "dev"
host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…"   # the host's public key, pinned
environments = ["dev"]                      # whose values may go there
roles = ["serve"]                           # optional; default every role the keys declare
opv = "/usr/local/bin/opv"                  # opv on the remote host
workdir = "/home/dev/src/journeeze"
command = ["cargo", "run", "-p", "jz-serve"]
identity_file = "~/.ssh/builder_ed25519"    # optional; default the SSH agent
```

A person runs it in their own terminal:

```text
opv run dev --product journeeze --role serve --remote builder
  └─ op run -- opv remote-send --plan <names, paths, the pinned profile>
       └─ ssh -F none -T -o StrictHostKeyChecking=yes -o UserKnownHostsFile=<pinned key> … builder <opv> remote-receive
            └─ (remote) opv remote-receive   payload on stdin → RAM directory and environment
                 └─ cargo run -p jz-serve     in the pinned workdir, its own process group
```

1. **Selection is the local run's.** The same `select` decides which keys are delivered, so it applies the same environments, rules and process roles. A key withheld by role is never resolved, sent or written. Before any 1Password read, opv checks that the profile exists, that it allows this environment, and that it allows this role.
2. **`op run` stays the only resolver.** The `remote-send` step receives values the same way the local delivery step does: in its environment, from `op run`. Its argv is a JSON plan of names, relative paths, the pinned profile and the public host key.
3. **SSH is pinned, not configured.**
   - `-F none` reads no user or system configuration, so no `ProxyCommand`, `LocalCommand`, `SendEnv`, forwarding or multiplexing can come from there.
   - The profile's host key is the only known host, under a per-profile alias, with `StrictHostKeyChecking=yes`, `UpdateHostKeys=no` and `CheckHostIP=no`.
   - `BatchMode=yes`: SSH never prompts for anything.
   - `ForwardAgent=no`, `ForwardX11=no` and `ClearAllForwardings=yes`.
   - `ControlMaster=no` and `ControlPath=none`: no connection is shared.
   - Connection keep-alives are set.
   - SSH's environment is only `PATH`, `HOME`, `USER`, `LOGNAME`, `LANG` and `SSH_AUTH_SOCK`.
4. **The remote command is fixed:** `<opv> remote-receive`. `opv` is an absolute path made only of characters that need no quoting, so the remote shell never sees a value or anything from the run's arguments.
5. **One framed payload on stdin.** The payload is laid out as follows:
   - the line `OPV-REMOTE 1`;
   - the header length and the JSON header: key names, file paths, the directory variable, the working directory and the command, plus `outer`, the person's own `opv run` (environment, product, profile, subcommand and flags; never the arguments after `--`, which are only marked as present). The receiver names that run in its messages, so a `Next:` step is the run to fix and re-run, never the hidden `opv remote-receive`;
   - each value, length-prefixed with its exact bytes;
   - the line `END`.

   The receiver writes `OPV-REMOTE READY 1` (its protocol version) on stderr before it reads the payload, and `OPV-REMOTE DELIVERED` once the payload is checked and delivered, just before the app starts. The sender removes both lines from what it shows and uses them to place a failure: a receiver of another protocol version is `remote_version_mismatch` (exit 3); an SSH exit 255 before the handshake (or 127, no remote opv) is SSH's own failure, diagnosed from SSH's reply (for example `remote_unreachable` or `credential_rejected`, or `remote_disconnected` once the payload was sent); after `DELIVERED`, an exit code is the remote app's own unless SSH's reply explains it.

   The receiver reads the whole payload and re-checks the header on its own before it writes or starts anything. Key names must be valid and not `OP_*`. File paths must follow the `file` rules with no collisions. The directory variable is required for file keys. The working directory must be an absolute path. The command must contain no control characters other than newline and tab. A short, malformed, oversized (header over 64 KiB, value over 1 MiB, more than 256 keys) or unterminated payload is refused, and nothing is delivered.
6. **Delivery on the remote host is local delivery.**
   - File keys go into a fresh 0700 `opv-remote.<pid>-<random>` directory under the remote user's RAM-backed `$XDG_RUNTIME_DIR`. Files are 0400, created exclusively and never through a link. Without such a directory the run is refused; there is no disk fallback.
   - The app's environment is always declared-only: the variable keys, the directory variable, and the fixed non-secret basics from the remote session. Nothing else of the remote session is passed, and never an `OP_*` variable.
   - A value with a NUL byte cannot be an environment variable and is refused; deliver it as a file.
7. **Liveness and cleanup.** After the payload, the sender writes a heartbeat byte every 10 seconds. The receiver stops the app in any of these cases:
   - stdin ends: Ctrl-C, or the local opv, SSH or the connection ended;
   - stdin is silent for 45 seconds;
   - the receiver gets SIGHUP, SIGTERM or SIGINT.

   Stopping means SIGTERM to the app's whole process group, then SIGKILL after 5 seconds. Then the receiver removes the directory and says why on stderr. A normal exit removes the directory too. The run's exit code is the remote app's, or 255 when SSH itself failed, which opv names on stderr.

## Who can do what

| Actor | Can | Cannot |
|---|---|---|
| Person (terminal) | sign in, review and commit a profile, run `opv run --remote` (needs an interactive terminal; refused under CI or with a service-account or Connect credential) | — |
| Agent (MCP) | preview a profile and its delivery: `opv_delivery_preview` with `remote` (identifiers only); edit `secrets.toml` like any file it can edit | run a remote delivery (no MCP tool does), pass a host, command or path to opv through MCP, approve anything |
| Remote host | receive exactly the selected keys of one product, environment and role | receive a 1Password session or credential, another product's keys, or another role's keys |

## What opv enforces, and what it cannot

opv enforces:
- No value in argv, a shell command, opv's output, logs or files outside the remote RAM directory, on either host.
- No `OP_*` credential in SSH's environment, the payload or the remote app's environment.
- Only the profile's pinned host key is accepted.
- The profile's environment and role scope, checked before any read.
- All-or-nothing delivery.
- Stopping and cleanup on disconnect, silence or signal.
- Refusal, never a fallback, where any of these cannot hold.

opv cannot enforce:
- **Trust in the remote host or its source tree.** The pinned command runs whatever code is in `workdir`. If that tree is untrusted, its code receives the delivered values. Pinning the command and host key limits where values go, not what that code does with them. Metadata scoping is not host or process isolation.
- **Isolation from root or the same remote user.** Root or another process of the remote user can read the RAM directory and the app's environment while it runs (through `/proc` or ptrace).
- **The local agent.** An unrestricted local shell running as the person can do anything the person can, including running `opv run --remote` in a pseudo-terminal. The terminal requirement is a gate against unattended use, not a security boundary. That is the same limit [local delivery](local-delivery.md) states.
- **Profile edits.** A profile is configuration. Review it the way you review `secrets.toml`, and keep the configuration where only reviewed changes land (a reviewed repository, or a 1Password manifest edited through `opv config edit`).
- **A killed receiver.** SIGKILL of the remote receiver leaves the directory in RAM until the next `remote-receive` sweeps it, or until the remote session's runtime directory is removed at logout or reboot.
- **A connection that drops without the remote side seeing it.** The app is stopped after at most 45 seconds of silence.

## Platform matrix

| Side | Supported | Notes |
|---|---|---|
| Local (sender) | Linux, WSL with native `op`, macOS | needs `op` and the OpenSSH client; `op.exe` from WSL cannot start a Linux child (#54) |
| Remote (receiver) | Linux | file keys need a user-owned `$XDG_RUNTIME_DIR` on tmpfs (systemd-logind sets it for SSH sessions); variable-only products need none |
| Remote macOS / Windows | refused | no verified RAM-backed directory; the receiver fails closed |

## Failure modes

| Case | Result |
|---|---|
| unknown profile, environment or role not allowed | refused before any read (`usage`, `policy_refused`) |
| `confirm_env` environment | needs `--confirm <env>`, as `opv run` does |
| no terminal, CI, service-account or Connect credential | refused (`terminal_required`) |
| `ssh` missing | `dependency_missing`, nothing sent |
| host key mismatch, unreachable host, authentication failure | SSH exits 255; nothing delivered; opv names the profile and points at the preview |
| remote opv missing, or of another protocol version | the remote shell fails, or the receiver refuses the payload; nothing delivered |
| short or corrupt payload, early disconnect during the transfer | refused; nothing written or started |
| no RAM-backed directory on the remote host | `ram_dir_unavailable`; nothing written |
| disconnect, Ctrl-C or silence while the app runs | the app's process group is stopped; the directory is removed |
| stale configuration | there is no stored plan: each run selects from the configuration it loaded |

## Tests

- **Unit tests** (`src/app/remote_delivery_tests.rs`):
  - the payload round-trips exact PEM bytes;
  - cut, unterminated and wrong-protocol payloads are refused, and refusals never quote a value;
  - the receiver re-checks the header (`OP_*` names, path traversal, relative workdir);
  - the pinned SSH options;
  - no value in SSH's argv or environment;
  - the remote environment is declared-only;
  - profile rules at load;
  - `run --remote` passes references only, never sends another role's key, and refuses before any read.
- **End-to-end tests** (`tests/remote_delivery.rs`, the real binary with marker values):
  - the receiver delivers the exact variable and PEM bytes, with no `OP_*`;
  - a cut payload starts nothing and writes no directory;
  - a dropped connection stops the app within seconds and removes the directory;
  - the sender, through a stand-in `ssh`, delivers exact bytes with no value or `OP_*` in SSH's argv or environment.
