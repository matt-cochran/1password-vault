# Agent sign-in and readiness: one document, typed recovery, no guessing

Status: draft for 0.18.0 (branch `v0180/design`, cut from dev at opv 0.17.2), 2026-11-04. Issues
#265, #266, #257 and #267. It builds on `accounts-and-readiness.md` (FR-49 to FR-51),
`session-reuse.md` (#203) and `error-catalog.md` (the typed cause, its Do and Next). New
requirements FR-64 to FR-66 are proposed in §9; owner decisions are in §5.

Nothing here adds an opv permission layer. 1Password vault access stays the only permission
system: opv reports what the current process's session can do and names the person who can act,
and every step it renders is one the person, or the assistant with the person's session, could
already run.

## 1. Problems found (2026-11-04, opv 0.17.2, op 2.40.0, WSL)

"Verified" means reproduced here or read in the code at the cited line. "Inferred" means not
reproduced, and it says why.

### 1.1 #265: a `--json` command exits 0 with an empty stdout

**Reproduction attempts.** These ran in a Claude Code agent shell with no TTY (`tty`: "not a
tty"), stdin `/dev/null`, stdout redirected to a regular file, and the installed 0.17.2 binary:

| Command (cwd) | Exit | stdout bytes | Result |
|---|---|---|---|
| `opv version --json` (opv checkout) | 0 | 1133 | one document |
| `opv ready --json` (opv checkout, 2 accounts, none selected) | 2 | 1057 | `account_required` document |
| `opv version --json` (zonetico-saas) | 0 | 1182 | one document |
| `opv ready --json` (zonetico-saas, signed out) | 7 | 546 | `op_not_signed_in` document |
| the npm shim (`~/.nvm/.../bin/opv version --json`) | 0 | 1182 | one document |

The report did not reproduce as filed. **The mechanism that produces exactly the reported
symptom (exit 0, 0 bytes) is verified:**

| Command | Exit | stdout |
|---|---|---|
| `opv version --json > /dev/full` (ENOSPC) | 0 | nothing written |
| `opv version --json >&-` (EBADF) | 0 | nothing written |
| `(opv version --json; echo $? >&2) \| true` (EPIPE) | 0 | reader gone |

**Root cause (verified in code).** Under `--json` the command's document is buffered and framed
after the command returns. main.rs:2033 promises "so stdout carries exactly one document
whatever happens". The delivery then discards every write error:

- main.rs:2091: `let _ = opv::output::OutputGuard::new(&mut stdout).write_all(&framed);`
- main.rs:2093: `let _ = stdout.flush();`
- main.rs:2094-2106: the exit code comes only from the command's result `res`, never from the
  write.
- main.rs:1866-1898, `PipeSafe`: swallows `BrokenPipe` and drops every later write. That is
  right for `status | head` in text mode, and wrong for a JSON document an agent depends on.
- `OutputGuard::write` (output.rs:75-79) calls `write_all`. `write_all` retries only on
  `Interrupted`, so `WouldBlock` (an `O_NONBLOCK` stdout) is an error too, and it is dropped.

A second path, verified by reading only: json.rs:153-156. A successful command whose body is
empty, or is not a JSON object, is passed through byte for byte. Today `version`
(version.rs:192-200) and `ready` (ready.rs:1342-1343) always write a body, so this path is not
the reporter's trigger. It is a latent way to break the same invariant: any `--json` command that
returns `Ok` without writing prints nothing and exits 0. MCP already guards against it
(mcp.rs:233-242 refuses an unreadable report). The CLI does not.

**Trigger in the reporter's shell (inferred, not reproduced).** The reporter's `ready` printed
the `using …` line on stderr and exited 0, so the command succeeded and only the delivery was
lost. The likely triggers are a stdout the harness opened non-blocking (`EAGAIN`), a pipe whose
reader closed early (`EPIPE`), or a sandbox that refuses the write (`EPERM`/`EACCES` at write
time). None of them can be told apart today, because opv says nothing. The design (§2.1) makes
every one of them loud and names the error kind, so the next report identifies it.

Related, verified (zonetico-saas, signed out): `ready --json`'s `op_not_signed_in` has
`subject.account: null` and `next.command: "opv login -- opv ready"`, though `.opv` names the
account. The recovery does not name the account. That gap is §2.2's.

### 1.2 #266: `opv run` shows op's raw sign-in error and exits 1

**Reproduced** (zonetico-saas, signed out, no TTY): `opv run dev -- true` printed `[ERROR] …
error initializing client: You are not currently signed in. Please run 'op signin --help' for
instructions` and exited 1. It printed no `Do:` and no `Next:`.

**Root cause (verified in code).**

- run.rs:285-288: the one tolerant item read before `op run` is
  `tidy::read(fleet, env_name, runner).ok()`. Its comment says "If the read fails, `op run`
  reports the problem itself". A typed `op_not_signed_in` from that read is thrown away.
- run.rs:385-388: `op run` is started with inherited stdio (`run_inherited_clean`), so op's own
  stderr, vendor advice included, goes to the terminal. FR-50 forbids that in normal output.
- run passes its child's exit code through (FR-4; NR-19 exempts `run`), so op's exit 1 becomes
  `Ok(1)`.
- main.rs:2070: the in-command sign-in (FR-40, "an ended session is renewed in place") runs only
  when `res` is `Err` with code `op_not_signed_in`. `run` never returns that, so a person at a
  terminal is never offered the sign-in either.

### 1.3 #257: account selection is blocked but `next.kind` is `none`

**Reproduced** (this machine: two accounts on `my.1password.com`, both signed out, none
selected):

- `opv account list --json` gives `selected: null`, both `signed_in: false`, one
  `shared_sign_in_address` finding with `next: null`, and a top-level
  `next: {"kind":"none","actor":"person","command":null}`.
- `opv ready --json` gives exit 2 `account_required` with `human_required: true`, yet
  `next: {"kind":"run","actor":"assistant","command":"opv account list"}`.

So ready sends the assistant to `account list`, and `account list` answers "none". It is a loop
with no exit, and the document contradicts itself (a person is required, but the actor is the
assistant).

**Root cause (verified in code).**

- account.rs:540-561, `report_with`: with several listed accounts and no selection, no finding is
  pushed (only the one-account case selects, at line 555). The only finding is
  `shared_sign_in_address`, which has `next: None` (account.rs:402-444).
- account.rs:574: `next` is the first finding's `next`, so it is `None`, and json.rs:96 renders
  that as kind `none`.
- render.rs:3452-3458: `AccountRequired` plans `Next::Check(opv account list)`. `Check` renders
  as `run`/`assistant`, while `PickBetween` makes `human_required` true (error-catalog §6.3).
  The two are derived from different parts of the plan, so they disagree.
- `next` is a single command string (json.rs:109-111). It cannot carry several choices or argv
  arrays.

### 1.4 #267: the config one folder down is not found; sign-in needs the eval incantation

**Reproduced** (scratch repo: `.opv` with `account = "6AINMAIK…"` at the root, config at
`fly/shared-host/fleet/secrets.toml`, cwd `fly/shared-host`): `opv ready --json` exits 2
`config_not_found`, with `Next: opv propose setup --help`, and its Do starts "start one with opv
propose setup".

**Root cause (verified in code).**

- config.rs:297-307, `discover`: walks up only.
- config_store.rs:696-705: `.opv` holds `project` and `account` only, with
  `deny_unknown_fields`, so it cannot name the configuration.
- config_store.rs:911-952, `locate`: with no walk-up match it falls to `.opv` and then to the git
  remote. Here that fails, and render.rs:2934-2949 renders the first-run router (`opv propose
  setup`). That advice is harmful when a configuration exists (an S1 in error-catalog terms: it
  leads to a second configuration).

**Sign-in (partly inferred).** With the Linux `op` on WSL there is no app integration
(session-reuse §3.2 step 3). Each process signs in itself (the per-command path) unless the
shell holds `OP_SESSION_<id>`. `login_shell::refresh_command` already omits `--account` when
`.opv` or `OP_ACCOUNT` names the account (login_shell.rs:439-448, verified). Why the reporter was
shown a line with `--account` is not reproduced. The likely cause is that the hint came from an
environment's `account` rather than from `.opv` (inferred). A child process cannot change its
parent shell's environment, so "no eval and still signed in for the next command" is possible
only through the subshell (`opv login`), the app integration, or a prompt in every command.

## 2. Proposed behaviour

### 2.1 #265: one document, or a loud failure (FR-64)

**Invariant.** Under `--json`, either stdout carries exactly one parseable JSON document and the
exit code is the command's, or the exit code is non-zero and stderr says why. There is no third
outcome.

1. **No empty success.** In `json::finish_with`, when the result is `Ok` and the call is not raw,
   a body that is not a JSON object becomes `Cause::Bug { site: "a --json command wrote no
   document" }` (exit 70), framed as the failure document. `config export` and
   `run --preview --json` (raw) keep their byte-for-byte output, but an empty raw body is a Bug
   too.
2. **Checked delivery.** A new `src/stdout_sink.rs` makes one call,
   `deliver(doc: &[u8], budget) -> Result<(), OutputLost>`. It writes through `OutputGuard`
   without `PipeSafe`:
   - `Interrupted`: retry.
   - `WouldBlock`: `poll(POLLOUT)` within the run's remaining `--timeout` budget, then retry.
     This is the non-blocking stdout an agent harness may hand opv. opv never clears
     `O_NONBLOCK` itself: that flag belongs to the shared open file description, so clearing it
     would change the parent too.
   - Any other error, `BrokenPipe` included (§5 D1): give up.
3. **The failure.** A new cause, `OutputLost { channel: Stdout, io: IoKind, bytes_written }`,
   with code `output_lost`, **exit 74** (`EX_IOERR`, §5 D1), retry `safe` and Next `Rerun`.
   stderr gets the normal rendered text, for example: `opv: the JSON document could not be
   written to standard output (no space left on device); nothing about the command's own result
   is lost: it was <ok | exit N>`. The command's own outcome is included because a write that
   already happened (a sync) must not look undone.
4. **`--verbose`** adds one stderr line on success: `stdout: one JSON document, <n> bytes,
   delivered`. It gives size and shape only (NR-22). This is how a future report names its
   environment.
5. **Text mode** is unchanged for `BrokenPipe` (`status | head` stays exit 0). Any other stdout
   error becomes `output_lost` (exit 74) as well.
6. **The same rule already exists** for the one other unguarded write, `login --shell`
   (login_shell.rs:450-459: a failed write is `terminal_lost`). This makes the rule general.

MCP parity: MCP answers through `Server::document` (mcp.rs:233), which calls the same
`finish_with`. The empty-body Bug therefore reaches MCP as the same document. Transport loss in
MCP belongs to the MCP library (error-catalog §4.10).

### 2.2 #266: `opv run` stops before `op run` with a typed, account-aware cause (FR-40 amended)

1. **Preflight that cannot be skipped.** In `launch`, the tolerant read keeps tolerating tidy and
   format problems. A *session or account* cause from the read stops the run before `op run`:
   `NotSignedIn`, `AccountNotOnMachine`, `AccountRequired`, `AccountAmbiguous`,
   `NeedsOwnSession` and `CredentialRejected`. The rule is "a read that failed for who-you-are
   reasons is the run's error". Every other read failure keeps today's pass-through, because
   `op run` reports it.
2. **At a terminal** (person, no `--json`, not CI, no service account): main's existing loop
   (main.rs:2044-2081) now sees `Err(op_not_signed_in)`. It signs in at op's own prompt for the
   run's account (`sign_in_here`) and runs `launch` once more **in the same process**. Every
   original argument, the child's words included, is kept in memory and never rendered (SR-3,
   error-catalog §6.1). This is the replay the issue asks for, without printing the child's
   command.
3. **Without a terminal** (agent shell, CI without a token, headless): the error stands,
   rendered by the catalog:

   ```text
   opv: you are not signed in to 1Password account 6AINMAIK… (selected by ./.opv)
   Do: sign in to 6AINMAIK… in your own terminal; the command runs there
   Next: opv login --account 6AINMAIK… -- opv run dev -- <command>
   ```

   The code is `op_not_signed_in` (exit 7, `human_required: true`, `next.kind: authorize`,
   `actor: person`). Under a service-account or Connect credential the read fails as
   `own_session_required` (`NeedsOwnSession`, exit 7) instead, as today. op's vendor line
   (`op signin --help`) never appears, because `op run` is never started.
4. **The account is always named when it is known.** `NotSignedIn.account` is filled from the
   selection (`--account`, `OP_ACCOUNT`, `.opv`, the environment's `account`) whenever the failing
   call carried none. This is done once in the cause's construction
   (`onepassword::session_cause`), not per call site. It fixes ready's `account: null` (§1.1) as
   well.
5. **`--account` is omitted from the Next** when the account came from `.opv` or `OP_ACCOUNT`
   and the shorter `opv login -- …` therefore selects the same account (the
   `refresh_account` rule, login_shell.rs:439). With `.opv` present, the line above becomes
   `opv login -- opv run dev -- <command>`. It is written with `--account` only when the account
   came from somewhere `opv login` would not look by itself.

Code-to-issue mapping: the issue's `selected_signed_out` is `account list`'s finding code for the
same state (FR-49). The run error keeps the catalog's `op_not_signed_in`, so one cause has one
code. `own_session_required` is unchanged.

### 2.3 #257: typed choices, never a guess (FR-65)

**A new `next` shape** (schema 4, §5 D2), produced by `json::typed_next` for every document:

```json
"next": {"kind": "choose", "actor": "person", "command": null, "argv": null,
         "choices": [
  {"account": {"account_id": "TTDZ56BH…", "shorthand": "my", "email": "a@example.com",
               "address": "my.1password.com", "signed_in": false},
   "steps": [
     {"kind": "run", "actor": "assistant", "effect": "writes_config",
      "command": "opv account use TTDZ56BH…", "argv": ["opv","account","use","TTDZ56BH…"]},
     {"kind": "authorize", "actor": "person", "effect": "signs_in",
      "command": "opv login -- opv ready --json", "argv": ["opv","login","--","opv","ready","--json"]},
     {"kind": "run", "actor": "assistant", "effect": "none",
      "command": "opv ready --json", "argv": ["opv","ready","--json"]}]},
  {"account": {"account_id": "6AINMAIK…", …}, "steps": […]}]}
```

- **`argv`** is present on every `next` and every step, built from `Cmd::to_argv` (which already
  round-trips through clap, error-catalog §6.1). It is `null` whenever the step holds a
  placeholder (`-- <command>`), so an agent can never exec a placeholder. `command` stays as the
  display form.
- **`kind: choose`** is new in the closed set. It means "a person picks one of `choices`; then
  run that choice's steps in order". `actor` is always `person`, `command` and `argv` are
  `null`, and `human_required` is true. A `choose` is rendered only when there are two or more
  candidates (the poka-yoke of error-catalog §6.2: there is no "first candidate").
- **Steps are per choice and per state.** A signed-in candidate has no sign-in step.
  `opv account use <account_id>` comes first. The account is named by ID for opv and by
  shorthand only in display text, never `op signin` (FR-50 keeps vendor directions out). The
  assistant may run `account use` only after the person has named the choice; the step's actor
  is `assistant` because it is a deterministic local write (`writes_config`) with no prompt.
- **The sign-in step depends on how far this process can reach a session** (§5 D3). It uses
  `signin::reuse_path` and `doctor_session::classify_static` for the *current* process:

  | Reach (current process) | Sign-in step | Verify step |
  |---|---|---|
  | `app`: desktop integration active or available | `authorize`, person: "unlock the 1Password app and approve its prompt", command `null` | assistant `opv ready --json` (its prompt appears to the person) |
  | `shell`: an `OP_SESSION_<id>` for this account is in this process | the refresh line (`eval "$(opv login --shell)"`), person | assistant `opv ready --json` |
  | `none`: WSL with the Linux `op`, headless, per-command | `authorize`, person: `opv login -- opv ready --json` (the command runs in the person's terminal; the assistant's process stays signed out) | none from the assistant: the person's run is the verification |

  The `reach` value is in the document (`next.reach`), so an assistant can explain why it cannot
  verify by itself.
- **Where it appears.** `AccountRequired` (render.rs) plans `Next::Choose(candidates)` instead of
  `Check(account list)`. `account list` gains a blocking finding `account_required`, with the
  cause's code, when several accounts exist and none is selected; its `next` is the same
  `choose`. `ready --json` gets the same document through the error. One builder,
  `cause::step::account_choices(candidates, reach, rerun)`, serves both, so CLI, `--json` and MCP
  cannot drift apart (error-catalog §2.4).
- **The selected account, signed out:** a single `next` (no `choices`) with the sign-in step for
  that account and the verify step. **Selected and signed in:** no account finding, and `next`
  is whatever the rest of readiness says.
- **`signed_in` per candidate** comes from the existing probe, `op whoami --account <id>` (exit
  status only, FR-49). `pick_account_at` runs it only when it is about to fail with
  `AccountRequired`, so a selected project pays nothing.
- **Safe to log.** The document holds account IDs, emails, shorthands, sign-in addresses and
  booleans, the same fields `account list` prints today. It holds no session, token, value,
  length or digest (§6.2).

MCP parity: `opv_state` gains section `accounts`, which is the `account list --json` document.
`ready` is already a section. Both carry the same `next`.

### 2.4 #267: the configuration named by `.opv`, and a found-config hint (FR-66, FR-25 amended)

1. **`.opv` may name the configuration:** `config = "fly/shared-host/fleet/secrets.toml"`. The
   path is relative to the directory holding the `.opv`. Rules, all checked at parse
   (`parse_dot_opv`), each a `config_invalid` with its field rule:
   - relative, with no `..` component, not absolute, and no NUL (`Pattern{RelativeInRepo}`);
   - the resolved file is inside the repository root after `canonicalize`, so a symlink cannot
     leave the clone (a clone is untrusted, as `record_account` already assumes);
   - not together with `project` (`ConflictsWith{project}`): one `.opv` names one source.
2. **Discovery order** (FR-25, amended): `--config`/`OPV_CONFIG`, then `OPV_PROJECT`, then the
   walk-up `secrets.toml`, then the nearest `.opv`'s `config`, then its `project`, then the git
   remote. A walk-up match still wins, so a file nearer the cwd is never shadowed. The `using …`
   line says `(named by ./.opv)`.
3. **Found-config hint.** When discovery fails, `ConfigNotFound` gains
   `found: Vec<PathBuf>`: the `secrets.toml` files under the repository root, at most 4 levels
   deep and at most 20 of them. `.git`, `node_modules`, `target` and hidden directories are
   skipped. Nothing is read, only names. The render:
   - one found: Do "a configuration exists at <path>; name it in .opv (config = \"<path>\") so
     every command here finds it", Next `Rerun` with `--config <path>` added (`invocation.with`);
   - several found: Do lists them, and Next is `none` with `PickBetween` (no first-match guess);
   - none found: today's first-run router, unchanged.
   opv never uses a found file without being told. It is a hint, not discovery (§5 D5).
4. **The sign-in hint is short when the project records the account** (§2.2 item 5). The one
   rule (`refresh_account`) moves from `login_shell.rs` to `signin.rs` and is used by every
   sign-in Next. It also counts an account that every environment's `account` agrees on, as
   well as `.opv`/`OP_ACCOUNT`. With `.opv` naming the account, the hint is `opv login` (a
   signed-in subshell: no eval, nothing to paste), and `eval "$(opv login --shell)"` is the
   alternative given in the Do (§5 D6).
5. **Interactive commands already sign in by themselves** at a terminal (FR-40 renew-in-place,
   main.rs:2044) for the selected account, `.opv` included. After §2.2 this covers `run` too.
   Nothing new is added: no daemon and no file (session-reuse §1).

MCP parity: MCP resolves the project through the same `config_store::locate`, so `.opv config`
applies to every MCP tool. MCP's errors are the CLI's documents, so they carry the same hint.
Writing `config =` is a person's edit, or a generator's output (the reporter's config is
generated). No command writes it in 0.18 (§3 A6).

## 3. Alternatives considered

| # | Alternative | Why rejected |
|---|---|---|
| A1 | Keep `PipeSafe` for `--json` and only log lost writes | The agent still gets exit 0 and no document; the invariant stays false |
| A2 | Clear `O_NONBLOCK` on fd 1 before writing | The flag belongs to the open file description shared with the parent harness; flipping it changes the harness's own I/O |
| A3 | Give `opv run` a `--json` for failures before the child starts | stdout belongs to the child app; a JSON document would interleave with the app's output. Agents check `ready --json` first (the skill already requires it) |
| A4 | Classify `op run`'s own failure afterwards (probe the session when `op run` exits non-zero) | The app's exit code and op's cannot be told apart: misattribution risk. `op` is a Go binary and passes no extra fd to its child, so a "child started" marker would need a file (SR-4). The preflight covers the reported case |
| A5 | Render the child's words in the login handoff (`-- npm run dev`) | SR-3, error-catalog §6.1: the child's argv may hold a credential. The replay happens in-process at a terminal instead (§2.2 item 2) |
| A6 | `opv config use <path>` to write `config =` | It is a new writer of `.opv` with no reporter need: the generator writes `.opv`. Revisit with a second request |
| A7 | Search one level down automatically and use the match | It infers a configuration that was not declared, and it is ambiguous with several `secrets.toml` files (monorepos). It is kept as a hint only |
| A8 | `next.kind: human_required` (the issue's wording) | `human_required` is already a derived boolean (error-catalog §6.3). A kind with the same name would be a second source of truth. `choose` says what the person does |
| A9 | Auto-select the only *signed-in* account among several | It infers an ambiguous account from session state. FR-40: never op's default by accident |
| A10 | A session broker or daemon so an assistant's process can reuse a person's sign-in on WSL | Rejected by session-reuse §1 (no daemon, no agent process, no file) |
| A11 | Emit `op signin --account <shorthand>` as a step (the issue's example) | FR-50 removes vendor directions. `opv login` names the account by ID and records nothing unless asked |

## 4. Contract changes (summary)

| Change | Where | Kind |
|---|---|---|
| `schema_version` 4: `next` gains `argv`, `choices`, `reach`; new kind `choose` | json.rs, schema.rs, every `--json` document, MCP | breaking (no shim, FR-60) |
| `output_lost` (exit 74, retry safe) | cause catalog §4.10, exit-code help (main.rs:66-76), usage.md | new code, new exit |
| empty `--json` success becomes `internal_error` (exit 70) | json.rs | behaviour |
| `account_required` plans `Next::Choose`; `account list` gains blocking finding `account_required` | render.rs, account.rs | behaviour |
| `NotSignedIn.account` filled from the selection | onepassword.rs `session_cause` | behaviour |
| `run`: a session or account cause from the preflight read stops the run before `op run` (exit 7); a terminal signs in and replays | run.rs, main.rs loop (unchanged code, new reach) | behaviour; NR-19 applies to run's pre-child failures |
| `.opv` key `config` | config_store.rs, FR-25 | new field |
| `ConfigNotFound.found` and its render | cause/mod.rs, render.rs | new subject field |
| `opv_state` section `accounts` | mcp.rs, surface.json | new MCP surface |

## 5. Owner decisions

**D1. What happens when a `--json` document cannot be written to stdout.**
*Situation:* today opv drops the write error and exits with the command's own code, so an agent
can get exit 0 and an empty stdout (#265). Possible write errors are a full disk, a closed
stdout, a sandbox refusal, or a reader that has gone (`EPIPE`).
*Options:* (a) exit 74, a new code following the Unix `EX_IOERR` convention, with one stderr
line naming the error kind and the command's own outcome. `EPIPE` counts too under `--json`; text
mode keeps `| head` at exit 0. (b) The same as (a), but reuse exit 3 ("dependency") and add no
new code. (c) Keep the command's exit code and only add the stderr line.
*In practice:* with (a) a wrapper can tell "the command failed" from "its report was lost". (b)
blurs that with "op is missing". (c) still lets an agent read exit 0 and act on a document it
never got.
*Recommendation:* **(a).** It is the only option where the exit code alone tells the truth. It
needs one new row in the exit-code help, and the help test catches a missing row.

**D2. Bump `schema_version` to 4 for the new `next` fields.**
*Situation:* every `--json` document's `next` gains `argv` and `reach`, and may carry `choices`
with the new kind `choose`. Clients branch on `next.kind`, which is documented as a closed set.
*Options:* (a) bump to 4 and update the TUI, MCP clients and the skill in the same release. (b)
Stay at 3, because the fields are additive.
*In practice:* under (b), a client that switches exhaustively on `kind` meets `choose` with no
signal that the contract moved.
*Recommendation:* **(a).** The closed set changes meaning, which is json.rs's own rule for a
bump, and there are few users and no shims.

**D3. How an assistant gets a usable session when its process cannot share the person's.**
*Situation:* on WSL with the Linux `op`, or on a headless host, a sign-in lives only in the
shell that made it. When the person signs in in their terminal, the assistant's own shell stays
signed out. So after a `choose`, the assistant cannot verify with `opv ready --json` by itself.
*Options:* (a) the sign-in step is `opv login -- <the command>`. The person runs the read in
their terminal and the assistant cannot self-verify (it says so through `reach: none`). (b)
Additionally offer "start the assistant from a signed-in shell"
(`eval "$(opv login --shell)"`, then launch the assistant). The assistant's shell then holds the
person's 1Password session and can do whatever that session can (including `op read`), which is
1Password's permission system applied as the person chose. (c) Offer (b) only, as the default.
*In practice:* (a) is safest, but the person relays results. (b) lets the assistant run every
read itself, at the cost the session-reuse FMECA calls H4 (an exported session reaches every
child process).
*Recommendation:* **(b), with (a)'s step listed first** and the second choice's step marked
`effect: shares_session`. The person decides, and opv adds no permission layer of its own. If
you have already settled H4 as "the `opv` shell function" (session-reuse §5.2), (b) uses that
form, and only opv, not `op`, gets the session.

**D4. Replaying `opv run` after a sign-in.**
*Situation:* the issue asks that the recovery keep "all original `opv run` arguments". The
child's words (`-- npm run dev --token …`) may hold a credential, so opv never prints them
(SR-3).
*Options:* (a) at a terminal, sign in at op's prompt and continue the same run in-process, with
the arguments kept in memory. Without a terminal, the handoff shows `-- <command>` and `argv` is
`null`. (b) Print the exact child command in the handoff.
*In practice:* (a) gives a person at a terminal a seamless replay, and an assistant fills in its
own command (it wrote it). (b) could put a token on screen and in an agent transcript.
*Recommendation:* **(a).**

**D5. How opv finds a configuration that is not on the walk-up path.**
*Situation:* the reporter's config is in `fleet/` below the working directory. opv walks only
upward, and then advises creating a new configuration.
*Options:* (a) `.opv` gains `config = "<path>"`, and a failed discovery lists the
`secrets.toml` files it can see, suggesting `--config` when exactly one exists. (b) Discovery
also looks one or more levels down and uses the match. (c) Only the hint, with no `.opv` key.
*In practice:* (a) is declared once and works from anywhere in the repo, MCP included. (b)
silently picks a configuration nobody named, and a monorepo has several. (c) means typing
`--config` forever.
*Recommendation:* **(a).**

**D6. The sign-in step opv prints when the project records its account.**
*Situation:* on WSL, staying signed in across commands needs either the signed-in subshell
`opv login` or `eval "$(opv login --shell)"` in the current shell. A program cannot change its
parent shell otherwise.
*Options:* (a) `Next: opv login` (a subshell; nothing to paste or evaluate; `exit` leaves it),
with the eval form named in the Do for people who want to keep their shell. (b)
`Next: eval "$(opv login --shell)"` first.
*In practice:* (a) is short, cannot be mistyped and wraps in any terminal. (b) keeps the
person's current shell, its history and its working directory.
*Recommendation:* **(a).** It is what the reporter asked for ("a short, project-aware form").

## 6. Self-vet

### 6.1 Poka-yoke

| Mistake | How it is made impossible or caught |
|---|---|
| A `--json` command prints nothing and exits 0 | `finish_with` makes an empty `Ok` a Bug, and `deliver` makes a lost write exit 74. The test `every_json_command_emits_one_document_without_a_tty` runs every command `surface.json` marks `json` |
| `next` contradicts `human_required` (§1.3) | `kind` and `actor` are derived from the same plan as `human_required`: a `Next::Check` whose plan has a person-only Action is rendered `authorize`/`person`. The unit test `human_required_implies_person_actor` runs over every catalog variant (`codes.rs` already varies every variant) |
| opv guesses an account | `choose` exists only with two or more candidates. `Next::Choose` has no "first" accessor. No code path selects from `signed_in` |
| An agent execs a placeholder | `argv` is `null` whenever a step holds `-- <command>`. The schema test asserts it |
| ready and account list disagree | one builder (`account_choices`), with a golden test comparing the two documents' `next` for the same world |
| `.opv config` leaves the clone | canonicalize-then-prefix check; symlink and `..` tests |
| A found config is used silently | `found` exists only on `ConfigNotFound`; the render produces a `Rerun` with `--config`, never a discovery result |
| A recovery loop (`ready` sends to `account list`, which says `none`) | the e2e case "follow `next` until it is `none` or `choose`" from both commands, with at most 3 hops |

### 6.2 Security

- **Values never in argv, env, files or logs.** None of these paths reads a value. The preflight
  in `run` is the existing item read, whose values are already registered with the scrubber
  (SR-1), and the in-process replay passes nothing new to any child. `account_choices` carries
  IDs, emails, shorthands, addresses and booleans only. `found` carries paths only and reads no
  file content. `OutputLost` names an I/O kind and a byte count, never document text.
- **Session tokens.** No step contains a token. The `shell` reach row prints the *command* that
  emits one, which only ever writes to a pipe (session-reuse §5.5). D3(b) is the person's own
  choice and is labelled `shares_session`.
- **Never infer an ambiguous account.** See §6.1. `signed_in` is shown, never used to choose.
- **No new permission layer.** No step is gated by opv on who is asking. `choose` is
  `human_required` because only the person knows which account holds the project, which is a
  fact and not a policy. The assistant may run `account use` once the person names the choice,
  and what it can then read is decided by 1Password.
- **Untrusted clone.** `.opv config` is validated as in §2.4. A cloned `.opv` can at worst point
  at another file inside the same clone, which the person could already pass as `--config`.
- **Canary scan.** Every new e2e case runs under the matrix's `Rule::NoCanaryValue`, including
  `SESSION_CANARY`.

### 6.3 Architecture guards

- **FR-12 `use_cases_name_no_target_adapter` and FR-37 `core_modules_name_no_provider`.** These
  scan `src/app`, `src/domain`, `config*.rs` and their tests. New tests and fixtures must not use
  the word `fly` in paths: #267's example path becomes `infra/shared-host/fleet/secrets.toml` in
  every test under `src/app` and in `config_store_tests.rs`. `op` and 1Password are the source,
  not a target, so `run.rs` may keep naming them.
- **J7 `observed_seal`.** `OutputLost` is a local I/O cause and never builds an `Observed`. The
  preflight reuses the read's existing diagnosis, adding no `lost_call` caller and no sealed
  constructor.
- **Global registration.** `surface.json` changes in two places: the `opv_state` section enum
  gains `accounts`, and the CLI gains no flag. The exit-code help gains `74` (and the missing
  `10`, source changed, found while reading main.rs:66-76). The all-providers channel contract
  is untouched, because no provider changes. `opv schema` regenerates.

## 7. Test plan

Each test has one behavioural assertion. "No TTY" means the e2e harness runs the binary with
stdin `/dev/null`, `setsid` (no controlling terminal), stdout a pipe or file, and
`OPV_NO_SKILL=1`. The opv-sim world supplies `op`.

### 7.1 Unit

| Test | Assertion |
|---|---|
| `json::empty_success_is_an_internal_error` | `finish_with(b"", Ok, raw=false)` parses with `error.code == "internal_error"` |
| `json::non_object_success_is_an_internal_error` | body `"text\n"` gives `internal_error` |
| `json::raw_success_keeps_its_body` | `config export` raw body is unchanged |
| `stdout_sink::retries_would_block` | a writer returning `WouldBlock` twice, then `Ok`, delivers every byte |
| `stdout_sink::broken_pipe_is_output_lost` | gives `OutputLost{io: BrokenPipe}` |
| `stdout_sink::no_space_is_output_lost` | gives `OutputLost{io: NoSpace}` |
| `stdout_sink::would_block_past_budget_is_output_lost` | a zero budget gives `OutputLost{io: WouldBlock}` |
| `cause::output_lost_exits_74` | `exit_code() == 74` |
| `render::human_required_implies_person_actor` | for every variant, `human_required` implies `next.actor == person` |
| `render::account_required_plans_choose` | two candidates give `kind == choose` |
| `render::choose_needs_two_candidates` | one candidate gives a single `next`, not `choose` |
| `render::placeholder_step_has_null_argv` | `login -- opv run dev -- <command>` gives `argv == null` |
| `render::argv_round_trips_clap` | every renderable `Cmd` argv parses with the real clap |
| `render::signin_next_omits_account_known_to_pointer` | `.opv` account gives `opv login -- …` |
| `render::signin_next_names_account_from_environment_only` | an account from an environment's `account` only gives `--account <id>` |
| `account::several_unselected_is_blocking_account_required` | the finding code is `account_required` and `blocking` |
| `account::several_unselected_next_is_choose` | `next.kind == choose` with two choices |
| `account::signed_in_choice_has_no_signin_step` | that choice's steps contain no `signs_in` effect |
| `account::selected_signed_out_next_names_the_account` | `next.command` names the selected ID |
| `account::selected_signed_in_has_no_account_finding` | no finding code starts with `account_` or `selected_` |
| `account::choices_hold_no_session_var_value` | with `OP_SESSION_x=CANARY`, the document has no `CANARY` |
| `run::signed_out_read_stops_before_op_run` | the sim log has no `op run` call |
| `run::signed_out_read_is_op_not_signed_in` | the error code is `op_not_signed_in` |
| `run::own_session_required_under_service_account` | the code is `own_session_required` |
| `run::tidy_problem_still_runs` | a read with a format problem still calls `op run` |
| `config_store::dot_opv_config_is_honoured` | cwd `infra/shared-host` with `config =` locates that file |
| `config_store::walk_up_beats_dot_opv_config` | a nearer `secrets.toml` wins |
| `config_store::dot_opv_config_with_dotdot_is_invalid` | `config_invalid`, rule `RelativeInRepo` |
| `config_store::dot_opv_config_absolute_is_invalid` | `config_invalid` |
| `config_store::dot_opv_config_symlink_outside_repo_is_invalid` | `config_invalid` |
| `config_store::dot_opv_config_and_project_conflict` | `ConflictsWith{project}` |
| `config::found_lists_below_root_bounded` | 25 files give 20 listed |
| `config::found_skips_node_modules_and_target` | the skipped directories are not listed |
| `render::one_found_config_reruns_with_config_flag` | Next is the invocation plus `--config <path>` |
| `render::several_found_configs_have_no_runnable_next` | `next.kind == choose` or `none`, never `run` |

### 7.2 End-to-end (opv-sim, `tests/e2e/scenarios/agent_signin.rs`, all no TTY unless marked)

| Case | Assertion |
|---|---|
| E1 every `--json` command in `surface.json`, sim world signed in | stdout parses as exactly one JSON object |
| E2 the same, world signed out | stdout parses as exactly one JSON object |
| E3 `opv version --json > /dev/full` | exit 74 |
| E4 `opv version --json >&-` | exit 74 |
| E5 `opv status --all \| head -1` (text) | exit 0 |
| E6 `opv ready --json`, two accounts on one address, none selected | `next.kind == choose` |
| E7 E6 | `len(next.choices) == 2` |
| E8 E6, following `next` hops from `ready` and from `account list` | ends at `choose` within 3 hops |
| E9 selected, signed out | `next.kind == authorize` and names the ID |
| E10 selected, signed in | no `account_*` finding |
| E11 `opv run dev -- true`, signed out | exit 7 |
| E12 E11 | stderr has no `op signin --help` |
| E13 E11 | stderr's last line is `Next: opv login -- opv run dev -- <command>` |
| E14 E11 (`script(1)` PTY, sim sign-in succeeds) | exactly one `op run` call in the sim log |
| E15 E14 with child `sh -c 'exit 3'` | exit 3 (the child's code survives the replay) |
| E16 #267 layout: `.opv config =`, cwd `infra/shared-host`, `opv ready --json` | `ok` or a non-`config_not_found` code |
| E17 #267 layout without `config =` | `config_not_found` with `next.command` containing `--config fleet/secrets.toml` |
| E18 MCP `opv_state section=accounts` vs E6's `account list --json` | equal `next` |
| E19 canary scan over E1-E18 | no canary in any channel |

### 7.3 Release gate

Run E1-E19 with `CI=true` as well (memory: the 0.12.0 #180 CI-only failure), and run the cargo
test suite. The global registration goldens (`surface.json`, exit-code help, `opv schema`) are
regenerated in lane L0 and must not change again in later lanes.

## 8. Delivery steps

Merge order: L0 first (contract and stubs). L1-L4 run in parallel on disjoint files. Then L5
and L6, then L7. Owners: **Claude** means a Claude agent (broad reading needed); **worker** means
a commodity worker (file-scoped, with the tests above as the spec).

| Id | Lane | Owns (files) | Prereqs | Est. h | Owner | Est. lines |
|---|---|---|---|---|---|---|
| L0 | `contract` | `src/cause/{mod,codes,render,step}.rs` (`OutputLost`, `Next::Choose`, `ConfigNotFound.found`, `NotSignedIn` account fill-in and the short-Next rule, `account_choices` stub), `src/json.rs` (schema 4, `choose`, `argv`, `reach`, empty-success Bug), `src/schema.rs`, the main.rs exit-code help block (lines 66-76 only), `tests/e2e/expected/surface.json`, `docs/design/error-catalog.md`, `docs/design/requirements.md` | D1, D2 decided | 5 | Claude | ~380 |
| L1 | `json-delivery` (#265) | `src/stdout_sink.rs` (new), `src/lib.rs` (one `pub mod`), the main.rs final-write block (lines 2085-2106 only) | L0 | 3 | Claude (fd semantics) | ~200 |
| L2 | `run-preflight` (#266) | `src/app/run.rs` (launch read, tests module) | L0 | 2.5 | worker | ~150 |
| L3 | `account-choices` (#257) | `src/app/account.rs`, `src/app/account_tests.rs`, `choose_error` in `src/adapters/onepassword_manifest.rs`, `src/app/signin.rs` (`reach`, moved `refresh_account`), `src/app/login_shell.rs` (caller only) | L0, D3 | 5 | Claude | ~350 |
| L4 | `config-pointer` (#267) | `src/config_store.rs`, `src/config_store_tests.rs`, `src/config.rs` (`found_below`) | L0, D5 | 4 | Claude (untrusted-clone validation) | ~300 |
| L5 | `mcp-accounts` | `src/mcp.rs` (section `accounts`), `src/mcp_state_tests.rs` | L3 | 1.5 | worker | ~90 |
| L6 | `docs-skill` | `docs/usage.md`, `docs/local-development.md`, `docs/agent-skill.md`, `llms.txt`, `docs/mcp.md`, `CHANGELOG.md` | L0-L4 | 2 | worker | ~200 |
| L7 | `e2e-headless` | `tests/e2e/scenarios/agent_signin.rs` (new), `tests/e2e/main.rs` (one `mod`), `tests/e2e/matrix.rs` (rule `OneDocumentNoTty`), sim world fixtures | L1-L5 | 4 | Claude | ~380 |

Critical path: L0 (5) to L3 (5) to L5 (1.5) to L7 (4), 15.5 h. With 3 agents and 2 workers the
other lanes run in parallel and do not lengthen it. L0 shares `main.rs` with L1 by line range
only: L0 merges first and L1 rebases. No other file is owned by two lanes.

## 9. Requirements to adopt

- **FR-64 — One `--json` document or a loud failure** (§2.1): the invariant, exit 74
  `output_lost`, and the empty-success Bug. It amends main.rs's A1 comment into a requirement.
- **FR-65 — Typed account remediation** (§2.3): `choose`, `argv`, `reach`, never guessing, and
  one builder for `ready`, `account list` and MCP. It amends FR-49 (findings) and FR-51 (`next`).
- **FR-66 — `.opv` names the configuration** (§2.4): `config =`, its validation, and the
  found-config hint. It amends FR-25's order.
- **FR-40 amended:** the renew-in-place covers `opv run`'s pre-child failures, and a sign-in
  Next omits `--account` when the project records it.
- **NR-19 amended:** `run` is exempt only for its child's own exit code. Failures before the
  child starts end with `Next:` like every other command.
