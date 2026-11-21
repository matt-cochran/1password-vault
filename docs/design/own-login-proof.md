# Production writes from a person's own `opv login` (#353)

Status: as built for the next release, 2026-11-21. Amends owner-value-ingestion D6. Related:
#351 (`$XDG_RUNTIME_DIR` on WSL), #54 (WSL and the Windows app), session-reuse §6.

## 1. Problem

D6 refuses a production-tier or `confirm_env` provision when any `OP_SESSION*`,
`OP_SERVICE_ACCOUNT_TOKEN` or `OP_CONNECT_*` variable is set. The write must use the
1Password app's authorization or a sign-in opv prompts for, never a session that was already
in the environment.

On WSL with the Linux `op`, and on Linux without the 1Password app, there is no app
authorization. Every session is an `OP_SESSION_<id>` variable, both from
`opv login [-- <command>]` and from `eval "$(opv login --shell)"`. So a person could provision
production only from a fresh shell with no session variable, where `opv provision` signs them
in itself. That rules out a script run with `opv login -- bash script.sh`, because the script
cannot provision production. The same flow works for staging.

D6 exists to keep a production write with the person at their own terminal. The write must
not come from an inherited, handed-in or agent-held session token. A variable's name says
nothing about where its token came from.

## 2. Decision

`opv login [-- <command>]` proves to its own child that it created the session. A
production write accepts a session variable only when that proof holds.

### 2.1 Issuing (`opv login`)

A proof is issued only when all of these hold:

- the command is `opv login` with a child: a command, or the signed-in terminal it opens;
- `opv login` already needs a terminal, no CI and no service-account or Connect token;
- this login's own sign-in produced the session at 1Password's prompt (a session the login
  reused has no proof);
- no assistant marker is set;
- the process has a controlling terminal;
- `$XDG_RUNTIME_DIR` passes local delivery's check: absolute, a directory owned by the user,
  not writable by others without the sticky bit, on tmpfs or ramfs.

The proof has two parts:

| Where | What |
|---|---|
| `$XDG_RUNTIME_DIR/opv-login-<pid>-<random>/` (0700, created new) holding `proof` (0600, `O_CREAT\|O_EXCL\|O_NOFOLLOW`) | format version, the login's PID, its start time (`/proc/<pid>/stat` field 22), its executable (`/proc/<pid>/exe`), its controlling terminal (`tty_nr`), the SHA-256 of a 32-byte random nonce, and the names of the session variables |
| `OPV_LOGIN_PROOF=<pid>-<random>.<nonce>.<tag>` in the child's environment only | the record's ID, the nonce, and a tag: SHA-256 over a domain separator, the nonce, and each session variable's name and value in name order |

Nothing in the file is derived from a session value. ADR-0001 R1 forbids a digest of a
secret in any file opv writes. The tag lives only in the environment that already holds the
session, so it shows nothing the session variable does not already show. The directory is
removed when the child exits and on a signal. The next login sweeps the directory of a
login that was killed.

When the runtime directory is unusable, the login prints one note and continues without a
proof: `note: production writes from this terminal will be refused: $XDG_RUNTIME_DIR is not a
private, RAM-backed directory you own, ...`. #351 has the fix.

### 2.2 Verifying (`opv provision`, production tier or `confirm_env`)

A service-account or Connect variable always refuses, as before. Otherwise, with session
variables set, the checks run in this order. The first one that fails is the reason, a
`SessionProof` value:

| # | Check | Refused as |
|---|---|---|
| 1 | no assistant marker (`HostEnv::agent_mode`) | `agent` |
| 2 | stdin and stdout are a terminal | `no_terminal` |
| 3 | `OPV_LOGIN_PROOF` is set | `no_proof` |
| 4 | it parses: digits, `-`, lowercase hex ID (never a path), 64-hex nonce and tag | `malformed` |
| 5 | `$XDG_RUNTIME_DIR` passes the check above | `runtime_dir` |
| 6 | the record's directory and file exist | `missing` |
| 7 | the directory is private (0700, the user's) and the file is a private regular file of the user, not a link, at most 16 KiB | `unsafe_record` |
| 8 | the format version and the nonce's SHA-256 (constant-time) match the record | `forged` |
| 9 | the login's PID still runs, with the recorded start time and executable (` (deleted)` ignored, for an upgrade during the login) | `stale` |
| 10 | that process (PID and start time) is an ancestor of this one | `not_ancestor` |
| 11 | this process's controlling terminal is the login's, and not none | `other_terminal` |
| 12 | the set `OP_SESSION*` names equal the record's, and the tag over their values matches (constant-time) | `wrong_session` |

Steps 1 and 2 repeat provision's own earlier refusals (`person_only`, `terminal_required`).
The proof is never the only guard for them.

A refusal keeps the code `own_session_required` (exit 7). The new principal
`shell_session {var, why}` gives the reason:

```text
opv: opv provision grant --env prod must be used in your own session, not with the session in OP_SESSION_ABC: this command does not run under the opv login that signed it in
Do: run it under opv login in your own terminal (opv login -- opv provision grant --env prod), or in a new shell without OP_SESSION_ABC, where opv signs you in at 1Password's prompt
```

### 2.3 `eval "$(opv login --shell)"` does not qualify

`--shell` writes no proof. Its session outlives the login process, so ancestry cannot hold.
The session stays in the shell and is inherited by everything the shell starts later:
editors, build tools and assistants (session-reuse H4). That is the exported session D6
refuses. A person who signed in with `--shell` runs the production write as
`opv login -- opv provision …`, or from a new shell.

### 2.4 `opv doctor`

`opv doctor` reports a `production writes` row whenever an `OP_SESSION*` is set, outside
CI and without a service-account or Connect credential. The row reads `ok`, state
`own_login`, when the proof holds. Otherwise it reads `warn`, state `refused`, with `reason`
set to one of the codes above. It never fails the run. With no session variable there is
no row: the write then signs in at 1Password's prompt.

## 3. Threats

| Case | Outcome |
|---|---|
| a session exported in the shell (`eval $(op signin)`, `--shell`) | `no_proof` |
| a session inherited from another terminal or a parent with a proof from a login that ended | `stale` or `missing` |
| a token handed in alongside a copied `OPV_LOGIN_PROOF` in another terminal or tree | `not_ancestor` or `other_terminal` |
| a guessed or forged nonce | `forged` |
| the login's session swapped for another token inside the login's tree | `wrong_session` |
| another `OP_SESSION_*` set beside the login's own | `wrong_session` |
| an assistant started from the login's terminal (markers) | `person_only` before the proof, and `agent` |
| an assistant's non-TTY tool shell | `terminal_required` before the proof, and `no_terminal` |
| a child that allocates its own pseudo-terminal | `other_terminal` |
| a reused PID | `stale` (start time) |
| a record replaced by a link or opened up | `unsafe_record` |
| a missing or disk-backed `$XDG_RUNTIME_DIR` (#351) | `runtime_dir`; the login says so up front |

Out of scope: code running as the same user. It can read `/proc/<pid>/environ` and the
record, and write a record of its own, as session-reuse §6 and agent-identity's same-user
residual already document. Agent mode is never a security control (R1, review M2). The
proof does not change that. What it changes is narrower: a variable alone is no longer
taken as the person's sign-in, and a session counts only while the person's own `opv login`
that prompted for it still runs, as an ancestor of the write, on the same terminal.

## 4. Platforms

The proof needs Linux and WSL (`/proc` and a RAM-backed `$XDG_RUNTIME_DIR`). Everywhere
else verification is `unsupported`, so D6 behaves as before. macOS and Windows have the
1Password app, and native Windows refuses producers anyway (D12).

## 5. Tests

- `src/app/login_proof_tests.rs`: accepted, and every refusal: no proof, agent marker,
  non-TTY, forged nonce, missing record, malformed (path) proof, wrong session value, an
  extra inherited session, a changed tag, not an ancestor, a login that exited, a reused
  PID, another program at the PID, an upgraded binary (accepted), another controlling
  terminal, an open record, a record replaced by a link, a removed record, an invalid
  runtime directory, cleanup on drop, no session value, digest or nonce in the record, no
  proof without a fresh session or a controlling terminal, and `/proc/<pid>/stat` parsing.
- `src/app/provision_tests.rs`: a proven own login writes production; a failed proof names
  why; a proof never excuses a service-account token or an assistant.
- `src/app/doctor_session_tests.rs`: the row's states and reasons.
