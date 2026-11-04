# Agent sign-in and readiness: one document, typed recovery, no guessing

Status: **Revised after DESIGN-FMECA vet** (`agent-signin-readiness-fmeca.md`, verdict "ready with
changes"; every required change applied, §10). Draft for 0.18.0 (branch `v0180/design`, cut from
dev at opv 0.17.2), 2026-11-04. Issues #265, #266, #257 and #267. It builds on
`accounts-and-readiness.md` (FR-49 to FR-51), `session-reuse.md` (#203) and `error-catalog.md` (the
typed cause, its Do and Next). New requirements FR-64 to FR-66 are proposed in §9; owner decisions
are in §5.

Nothing here adds an opv permission layer. 1Password vault access stays the only permission
system: opv reports what the current process's session can do and names the person who can act,
and every step it renders is one the person, or the assistant with the person's session, could
already run.

## 1. Problems found (2026-11-04, opv 0.17.2, op 2.40.0, WSL)

"Verified" means reproduced here or read in the code at the cited line. "Inferred" means not
reproduced, and it says why.

### 1.1 #265: a `--json` command exits 0 with an empty stdout

**Root cause: not established.** The report did not reproduce in three shells, and the fix below
is the diagnostic as well as the remedy. #265 stays open until the reporter re-runs
`opv ready --json --verbose > f; echo $?` on a build with §2.1 (lane L1a, shippable as 0.17.3).

**Non-reproductions.** In each case stdin was not a TTY, stdout was redirected to a regular file,
and the installed 0.17.2 binary was used:

| Shell | Command | Exit | stdout bytes |
|---|---|---|---|
| Claude Code agent shell | `opv version --json` (opv checkout / zonetico-saas) | 0 | 1133 / 1182 |
| Claude Code agent shell | `opv ready --json` (two accounts, none selected) | 2 | 1057 (`account_required`) |
| Claude Code agent shell | `opv ready --json` (zonetico-saas, signed out) | 7 | 546 (`op_not_signed_in`) |
| Claude Code agent shell | the npm shim, `version --json` | 0 | 1182 |
| Codex `workspace-write` sandbox (vet) | `version --json` / `ready --json` / `schema` | 0 / 7 / 0 | 1190 / 546 / 103565 |
| Codex read-only sandbox (vet) | the redirect itself fails (`Read-only file system`) | 2 | not the reported symptom |

**One mechanism is verified.** A write error opv drops gives exactly the reported symptom:

| Command | Exit | stdout |
|---|---|---|
| `opv version --json > /dev/full` (`ENOSPC`, `StorageFull`) | 0 | nothing written |
| `(opv version --json; echo $? >&2) \| true` (`EPIPE`) | 0 | reader gone |

`>&-` is **not** such a case. The Rust runtime reopens a closed fd 0-2 on `/dev/null` before
`main`, so the write succeeds. opv can neither detect that nor tell it from a deliberate
`> /dev/null`. (The first draft listed it as `EBADF`, which was wrong.)

**Code paths that can produce exit 0 with no document (verified in code):**

- main.rs:2033 promises "so stdout carries exactly one document whatever happens". The delivery
  then discards every write error:
  - main.rs:2091: `let _ = opv::output::OutputGuard::new(&mut stdout).write_all(&framed);`
  - main.rs:2093: `let _ = stdout.flush();`
  - main.rs:2094-2106: the exit code comes only from the command's result `res`.
- main.rs:1866-1898, `PipeSafe`: swallows `BrokenPipe` and drops every later write.
- json.rs:153-156: a successful command whose body is empty or not a JSON object is passed
  through byte for byte. `version` (version.rs:191-199) and `ready` (ready.rs:1342-1343) always
  write a body. This path is still a candidate for the reporter's run, because nothing proves
  their run took those branches. MCP already refuses an unreadable report (mcp.rs:233-242); the
  CLI does not.

**Triggers possible for the reporter's command (inferred).** The reporter redirected to a regular
file. A regular file never returns `EAGAIN` and has no reader to lose (`EPIPE`). Only these remain:

- `ENOSPC`, `EDQUOT` or `EIO` on `write(2)`;
- a seccomp or LSM `EPERM` on `write(2)` (a sandbox that blocked the file would normally fail at
  `open`, in the shell, with a non-zero exit);
- the empty-body `Ok` above.

Today none of them can be told apart, because opv says nothing. §2.1 makes each one loud, or names
it with a `--verbose` line.

Related, verified (zonetico-saas, signed out): `ready --json`'s `op_not_signed_in` has
`subject.account: null` and `next.command: "opv login -- opv ready"`, though `.opv` names the
account. That gap is §2.2's.

### 1.2 #266: `opv run` shows op's raw sign-in error and exits 1

**Reproduced** (zonetico-saas, signed out, no TTY; re-run by the vet): `opv run dev -- true`
printed `[ERROR] … error initializing client: You are not currently signed in. Please run 'op
signin --help' for instructions` and exited 1. There was no `Do:` and no `Next:`.

**Root cause (verified in code):**

- run.rs:285-288: the tolerant item read before `op run` is
  `tidy::read(fleet, env_name, runner).ok()` ("If the read fails, `op run` reports the problem
  itself"). A typed `op_not_signed_in` from that read is thrown away.
- run.rs:385-388: `op run` is started with inherited stdio (`run_inherited_clean`), so op's stderr,
  vendor advice included, goes to the terminal. FR-50 forbids that in normal output.
- run passes its child's exit code through (FR-4; NR-19 exempts `run`), so op's 1 becomes `Ok(1)`.
- main.rs:2070: the FR-40 in-command sign-in runs only when `res` is `Err(op_not_signed_in)`. `run`
  never returns that, so a person at a terminal is not offered the sign-in either.

### 1.3 #257: account selection is blocked but `next.kind` is `none`

**Reproduced** (this machine: two accounts on `my.1password.com`, both signed out, none selected):

- `opv account list --json` gives `selected: null`, both `signed_in: false`, one
  `shared_sign_in_address` finding with `next: null`, and a top-level
  `next: {"kind":"none","actor":"person","command":null}`.
- `opv ready --json` gives exit 2 `account_required` with `human_required: true`, yet
  `next: {"kind":"run","actor":"assistant","command":"opv account list"}`.

`ready` sends the assistant to `account list`, which answers "none": a loop with no exit. The
document also contradicts itself, saying a person is required while naming the assistant as actor.

**Root cause (verified in code):**

- account.rs:540-561, `report_with`: with several listed accounts and no selection, no finding is
  pushed (only the one-account case selects, at line 555). The only finding is
  `shared_sign_in_address`, whose `next` is `None` (account.rs:402-444).
- account.rs:574: `next` is the first finding's `next`, so it is `None`; json.rs:96 renders that
  as `none`.
- render.rs:3452-3458: `AccountRequired` plans `Next::Check(opv account list)` with `PickBetween`.
  `Check` renders as `run`/`assistant`, while `PickBetween` makes `human_required` true
  (error-catalog §6.3).
- `typed_next` (json.rs:76-111) rebuilds `next` as `{kind, actor, command}` and drops every other
  field. Most producers (18 `"next"` sites in `src/app/*.rs`) emit a display string, not a `Cmd`.

### 1.4 #267: the config one folder down is not found; sign-in needs the eval incantation

**Reproduced** (scratch repo: `.opv` with `account = "6AINMAIK…"` at the root, config at
`fly/shared-host/fleet/secrets.toml`, cwd `fly/shared-host`). `opv ready --json` exits 2 with
`config_not_found`; its Do begins "start one with opv propose setup" and its Next is
`opv propose setup --help`.

**Root cause (verified in code):**

- config.rs:297-307, `discover`: walks up only, all the way to `/`, not bounded by the repository.
- config_store.rs:696-705: `.opv` holds only `project` and `account` (`deny_unknown_fields`).
- config_store.rs:911-952, `locate`: when the walk-up finds nothing it falls to `.opv` and then to
  the git remote. render.rs:2934-2949 then renders the first-run router. That advice is harmful
  when a configuration exists: it leads the person to create a second one.

**Sign-in (partly inferred).** With the Linux `op` on WSL there is no app integration
(session-reuse §3.2 step 3). Each process signs in itself unless the shell holds
`OP_SESSION_<id>`. `login_shell::refresh_command` already leaves out `--account` when `.opv` or
`OP_ACCOUNT` names the account (login_shell.rs:439-448). Why the reporter saw `--account` is not
reproduced; the likely source is an environment's `account` (inferred). A child process cannot
change its parent shell, so "no eval and still signed in" is possible only through the subshell
(`opv login`), the app integration, or a prompt in every command.

## 2. Proposed behaviour

### 2.1 #265: one document, or a loud failure (FR-64). Lane L1a, shippable as 0.17.3

**Invariant.** Under `--json`, one of two things is true. Either stdout carries exactly one
parseable JSON document and the exit code is the command's, or the exit code is non-zero and
stderr says why.

1. **No empty success.** In `json::finish_with`, an `Ok` result whose body is not a JSON object
   becomes `Cause::Bug { site: "a --json command wrote no document" }` (exit 70). That covers raw
   mode too when its body is empty. `config export` and `run --preview --json` keep a non-empty
   raw body byte for byte.
2. **Checked delivery.** `deliver(doc, budget) -> Result<(), Error>` (in `src/stdout_sink.rs`, a
   small module that exists only for the retry loop) writes through `OutputGuard`, without
   `PipeSafe`. It checks both `write_all` and `flush`, because `LineWriter` reports an error at the
   newline or only on flush. Error handling:
   - `Interrupted`: retry.
   - `WouldBlock`, on Unix (`cfg(unix)`): `poll(POLLOUT)` within the run's remaining `--timeout`
     budget, then retry. opv never clears `O_NONBLOCK`, because the flag belongs to the open file
     description it shares with the parent.
   - `WouldBlock` on Windows, and any other error, `BrokenPipe` included (§5 D1): the delivery is
     lost.
3. **The failure extends the existing cause; there is no new one.**
   - `Cause::LocalIo { op: LocalOp::Stdout, io, … }` (cause/mod.rs:963-967, code
     `local_io_failed`, cause/mod.rs:2051) already reports stdout writes through `write_err`
     (app/mod.rs:535-542).
   - It gains `bytes_written: u64` and `outcome: CommandOutcome` (`ok` or `exit N`).
   - `exit_code()` returns **74** (`EX_IOERR`) for `op: Stdout`, and stays 6 for the other ops, the
     way `Guard::Declined` already varies its exit by field.
   - Retry is `safe` and Next is `Rerun`.
4. **The stderr line leads with the command's own outcome,** so a write that happened (a sync)
   never looks undone. Example: `opv: sync staging finished (ok); its JSON report could not be
   written to standard output (no space left on device, 0 of 2 214 bytes written)`.
5. **The diagnostic.** `--verbose` adds one stderr line on success:
   `stdout: one JSON document, <n> bytes, delivered`. It reports size and shape only (NR-22). This
   is the line the reporter's re-run needs to tell the cases apart:
   - `delivered` with an empty file rules opv out;
   - `local_io_failed` names the errno;
   - `internal_error` names the empty-body path.
6. **Text mode** keeps `BrokenPipe` at exit 0 (`status | head`). A text-mode stdout error was
   already `local_io_failed` through `write_err`; only its exit number changes, to 74.
7. **An exit-code completeness test** (`exit_codes_help_lists_every_code`) reads every number in
   `Cause::exit_code`'s body, the way `codes_in_source` does (codes.rs:1044-1060). It asserts that
   each number appears in the `--help` exit-code block (main.rs:66-76) and in `docs/usage.md`
   "Exit codes". That fixes the missing exit 10 (source changed) and keeps 74 from going missing.

MCP parity: MCP answers through `Server::document` (mcp.rs:233), which calls the same
`finish_with`, so the empty-body Bug reaches MCP as the same document. Transport loss is the MCP
library's (error-catalog §4.10).

### 2.2 #266: `opv run` stops before `op run` with a typed, account-aware cause (FR-40 amended)

1. **A preflight that cannot be skipped.** The tolerant read in `launch` keeps tolerating tidy and
   format problems. A *session or account* cause stops the run before `op run`: `NotSignedIn`,
   `AccountNotOnMachine`, `AccountRequired`, `AccountAmbiguous`, `NeedsOwnSession` or
   `CredentialRejected`. Any other read failure keeps today's pass-through.
   - **Breaking (CHANGELOG):** with several accounts and none selected, a run that `op run` used to
     send to op's default account now stops with `account_required`, and its `choose` (§2.3) gives
     the fix. This is FR-40's "never op's default by accident".
2. **At a terminal** (a person, no `--json`, not CI, no service account), main's existing loop
   (main.rs:2044-2081) now sees `Err(op_not_signed_in)`. It signs in at op's own prompt
   (`sign_in_here`) and runs `launch` once more in the same process. Every original argument,
   the child's words included, is kept in memory from the retained `matches` (main.rs:2050) and is
   never rendered (SR-3, error-catalog §6.1).
3. **Guard: a replay never follows a started child.** `launch` sets a process-wide
   `CHILD_STARTED` flag (in `app::run`) immediately before `run_inherited_clean`. The main loop
   never replays while it is set, whatever error comes back. Today `launch` cannot return
   `Err(op_not_signed_in)` after `op run` starts, but a later change (a post-run read, a remote
   step) could, and a double run of a deploy or migration script is High severity.
4. **Where the fresh session goes.** `sign_in_here` → `use_op_session` (main.rs:5325), and
   `add_op_session` puts the session on **every `op` call** (runner.rs:1773-1779), `op run`
   included. `op run` passes its environment to its child. That child is always opv's
   `local-delivery` step (FMECA H1), which removes every `OP_*` before the app starts
   (`local_delivery::child_env`). So the app should not receive it. That is inferred: it has not
   been verified for the replay path. E14b tests it with a session canary. If it fails, the
   exposure is the same one the session-reuse FMECA accepted as M6 for `opv login -- opv run`, and
   it goes to the owner rather than being silently accepted.
5. **Without a terminal** (an agent shell, CI without a token, headless), the error stands,
   rendered by the catalog:

   ```text
   opv: you are not signed in to 1Password account 6AINMAIK… (selected by ./.opv)
   Do: sign in in your own terminal; the command runs there
   Next: opv login -- opv run dev -- <command>
   ```

   Code `op_not_signed_in`, exit 7, `human_required: true`, `next.kind: authorize`,
   `actor: person`, `argv: null` (the step holds a placeholder). Under a service-account or
   Connect credential the code is `own_session_required`, as today. op's vendor line never
   appears, because `op run` never starts.
6. **The account is named whenever it is known.** `NotSignedIn.account` is filled from the
   selection (`--account`, `OP_ACCOUNT`, `.opv`, the environment's `account`) when the failing call
   carried none. This happens once, in `onepassword::session_cause`, and also fixes ready's
   `account: null`. The Next uses `--account <id>` only when the account came from somewhere
   `opv login` would not look by itself. That is the `refresh_account` rule, moved to `signin.rs`
   (§2.4 item 6).

The issue's `selected_signed_out` is `account list`'s finding code for the same state (FR-49). The
run error keeps the catalog's `op_not_signed_in`, so one cause has one code.

### 2.3 #257: typed choices, never a guess (FR-65)

**`next` in schema 4** (§5 D2). `typed_next` now carries `argv`, `choices` and `reach`; it no longer
drops them.

```json
"next": {"kind": "choose", "actor": "person", "command": null, "argv": null, "reach": "none",
         "choices": [
  {"account": {"account_id": "TTDZ56BH…", "shorthand": "my", "email": "a@example.com",
               "address": "my.1password.com", "signed_in": false},
   "steps": [
     {"kind": "run", "actor": "assistant", "effect": "writes_config",
      "command": "opv account use TTDZ56BH…", "argv": ["opv","account","use","TTDZ56BH…"]},
     {"kind": "authorize", "actor": "person", "effect": "signs_in",
      "command": "opv login -- opv ready --json", "argv": ["opv","login","--","opv","ready","--json"]}]},
  {"account": {"account_id": "6AINMAIK…", …}, "steps": […]}]}
```

- **`argv` is non-null only when it is built from a `Cmd` or `Invocation`** (`Cmd::to_argv`,
  step.rs:74-79, which round-trips through clap). It is **never parsed from `command`'s display
  text**, and it is `null` for a step that holds a placeholder (`-- <command>`). L0 migrates the
  producers this design needs to a typed `next`: `ready`, `account list` and the sign-in causes.
  Every other producer emits `argv: null`, and `schema.rs` documents that. Test: when `argv` is
  present, it parses with the real clap.
- **`kind: choose`** is new in the closed set. It means "a person picks one of `choices`, then the
  steps of that choice run in order". `actor` is `person`, `command` and `argv` are `null`, and
  `human_required` is true. It is rendered only with **two or more** candidates; there is no
  "first candidate" (error-catalog §6.2).
- **Steps depend on the choice and its state.** A signed-in candidate has no sign-in step.
  `opv account use <account_id>` comes first; it names the account by ID and never uses
  `op signin` (FR-50). The assistant runs it only after the person has named the choice. It is a
  deterministic local write (`writes_config`) and asks nothing.
- **The sign-in step depends on how far this process can reach a session** (§5 D3; computed from
  `signin::reuse_path` and `doctor_session::classify_static`, reported as `next.reach`):

  | `reach` (current process) | Sign-in step | Verify step |
  |---|---|---|
  | `app`: desktop integration active or available | `authorize`, person: "unlock the 1Password app and approve its prompt", `command: null` | assistant: `opv ready --json` |
  | `shell`: an `OP_SESSION_<id>` for this account is already in this process | the refresh line, person | assistant: `opv ready --json` |
  | `none`: WSL with the Linux `op`, headless, per-command | `authorize`, person: `opv login -- opv ready --json` (it runs in the person's terminal) | none; the person's run is the check |

  There is no typed step that puts a session into the assistant's shell (§5 D3).
- **Where it appears.**
  - `AccountRequired` plans `Next::Choose(candidates)` instead of `Check(account list)`.
  - `account list` gains a blocking finding `account_required` when several accounts exist and
    none is selected. Its `next` is the same `choose`.
  - `ready --json` gets the same document through the error.
  - One builder, `cause::step::account_choices(candidates, reach, rerun)`, serves all of them.
- **Selected account, signed out:** a single `next` with the sign-in and verify steps.
  **Selected and signed in:** no account finding.
- **`signed_in` per candidate** comes from the existing `op whoami --account <id>` probe (exit
  status only, FR-49). It runs only on the path that is about to fail with `AccountRequired`.
- **The `human_required ⇒ actor person` invariant is scoped, not blanket.** The test runs over
  every catalog variant. Render.rs has 91 `Next::Check` sites, so L0 runs the test first and lists
  every variant it flips in the PR. Each one gets a decision: either `authorize`/`person`, or keep
  the assistant's read and make the person-only Action not imply `human_required` for that
  variant. `AccountRequired` itself is settled by `choose`. The list is part of L0's deliverable
  (§8).
- **Safe to log.** The document holds IDs, emails, shorthands, sign-in addresses and booleans,
  which `account list` already prints. It holds no session, token, value, length or digest.

MCP parity: `opv_state` gains section `accounts` (the `account list --json` document). The tool's
description string (mcp.rs:332) and `SECTION_FORMAT` name it as well. `ready` is already a section.

### 2.4 #267: the configuration named by `.opv`, and a found-config hint (FR-66, FR-25 amended)

1. **`.opv` may name the configuration:** `config = "infra/shared-host/fleet/secrets.toml"`. The
   path is relative to the directory that holds the `.opv`.
2. **At parse, syntax only** (`parse_dot_opv`; each failure is `config_invalid` with its field
   rule): relative, no `..` component, not absolute, no NUL (`Pattern{RelativeInRepo}`), and not
   together with `project` (`ConflictsWith{project}`). No filesystem check runs at parse:
   `pointer_account`, `selected_account` and `record_account` read the same file, so a clone whose
   generated config does not exist yet must still let `opv login` and `opv account use` work.
   Readers of `account` ignore `config`.
3. **At use, existence and containment** (`locate`):
   - Both the repository root and the file are canonicalized. `repo_root` is computed from the
     canonical start (today config_store.rs:856 uses the non-canonical one, so a cwd reached
     through a symlink, or WSL `/mnt/c`, could refuse wrongly or pass wrongly).
   - Outside a repository, the root is the `.opv`'s directory.
   - A missing file, or one outside the root, is `ConfigUnreadable { given_by: DotOpv { path } }`,
     using a new `GivenBy` variant.
   - The check runs again at open. The remaining TOCTOU window needs a local write, so it is
     accepted.
4. **Discovery order** (FR-25, amended): `--config`/`OPV_CONFIG`, then `OPV_PROJECT`, then:
   - a walk-up `secrets.toml` **at or below the nearest `.opv`'s directory** (both sides
     canonicalized);
   - else that `.opv`'s `config`;
   - else its `project`;
   - else a walk-up `secrets.toml` above the `.opv` (only when the `.opv` names neither `config`
     nor `project`);
   - else the git remote.

   A stray `~/secrets.toml` can no longer beat a declared configuration. The `using …` line says
   `(named by ./.opv)` when `.opv` decided.
5. **Found-config hint.** When discovery fails, `ConfigNotFound` gains `found: Vec<PathBuf>`: the
   `secrets.toml` files under the repository root. The scan is capped at 4 levels deep, 20 files
   and 2 000 directories visited ("search stopped" in the Do). It skips `.git`, `node_modules`,
   `target` and hidden directories, and reads names only. The render uses **two bases**:
   - one found: Do "a configuration exists; name it in `<.opv>` as `config = "<path relative to
     the .opv>"`", and Next `Rerun` plus `--config <path relative to cwd>`;
   - several found: Do lists them, and Next is `none` with `PickBetween` (no guess);
   - none found: today's first-run router.

   A found file is never used without being named (§5 D5).
6. **A short sign-in hint when the project records the account.** `refresh_account` moves from
   `login_shell.rs` to `signin.rs`, and every sign-in Next uses it. It also counts an account that
   every environment's `account` agrees on. With `.opv` naming the account, the Next is
   `opv login` (a signed-in subshell, with nothing to evaluate), and the Do mentions
   `eval "$(opv login --shell)"` as the way to keep the current shell (§5 D6).
7. **Interactive commands already sign in by themselves** at a terminal (FR-40, main.rs:2044).
   After §2.2 that covers `run` too. No daemon and no file (session-reuse §1).
8. **Compatibility (CHANGELOG):** opv 0.17 refuses a `.opv` that has `config`
   (`deny_unknown_fields`). The file is committed and shared, so a team upgrades together.
9. **Architecture:** production strings and doc comments in `config.rs`/`config_store.rs` use
   `infra/` paths, never a provider word (FR-37).

MCP parity: MCP resolves the project through the same `locate`. Its errors are the CLI's
documents.

## 3. Alternatives considered

| # | Alternative | Why rejected |
|---|---|---|
| A1 | Keep `PipeSafe` for `--json` and only log lost writes | The agent still gets exit 0 and no document |
| A2 | Clear `O_NONBLOCK` on fd 1 | The flag belongs to the open file description shared with the harness |
| A3 | A new cause `OutputLost` / `output_lost` (the first draft) | It would duplicate `LocalIo{Stdout}` (`local_io_failed`): two codes for one failure (vet R3) |
| A4 | `opv run --json` for pre-child failures | stdout belongs to the app; agents check `ready --json` first |
| A5 | Classify `op run`'s own failure afterwards | The app's exit code and op's cannot be told apart. op (Go) passes no extra fd, so a marker would need a file (SR-4) |
| A6 | Render the child's words in the handoff | SR-3, error-catalog §6.1. The replay is in-process instead |
| A7 | `opv config use <path>` writes `config =` | No reporter need; the generator writes `.opv` |
| A8 | Search downward and use the match | It infers an undeclared configuration and is ambiguous in a monorepo. It is kept as a hint only |
| A9 | `next.kind: human_required` (the issue's wording) | `human_required` is already a derived boolean, so this would be a second source of truth |
| A10 | Auto-select the only *signed-in* account | It infers an ambiguous account (FR-40) |
| A11 | A session broker or daemon for assistants on WSL | Rejected by session-reuse §1 |
| A12 | Emit `op signin --account <shorthand>` | FR-50 removes vendor directions |
| A13 | A typed `shares_session` step that starts the assistant from a signed-in shell (first draft D3(b)) | It steers the assistant's shell into a session that can `op read`, which conflicts with "assistants see value-state only" (vet R19) |
| A14 | Shell-split `command` to fill `argv` for every producer | It could produce a wrong argv. `argv` comes from a `Cmd` or is `null` (vet R9) |
| A15 | Flip every `Check`+person-Action variant to `authorize` | 91 sites; assistants would stop running harmless reads (vet R10) |

## 4. Contract changes (summary)

| Change | Where | Kind |
|---|---|---|
| `schema_version` 4: `next` carries `argv`, `choices`, `reach`; new kind `choose`. Landed alone as a mechanical commit (771 lines in 716 test files, `git diff --word-diff` shows only `3`→`4`); `llms.txt:13` (stale: says 2, `next_kind`) fixed | json.rs, schema.rs, every `--json` document, MCP | breaking (FR-60, no shim) |
| `LocalIo{op: Stdout}` exits 74 and gains `bytes_written`, `outcome` (code stays `local_io_failed`) | cause/mod.rs, render.rs, exit-code help, usage.md | new exit |
| Empty `--json` success becomes `internal_error` (exit 70) | json.rs | behaviour |
| Exit-code help and usage.md list every code, including 10 | main.rs:66-76, usage.md, new test | fix |
| `account_required` plans `Next::Choose`; `account list` gains blocking finding `account_required` | render.rs, account.rs | behaviour |
| Enumerated variants change `actor`/`human_required` (L0's list) | render.rs | behaviour, listed per code |
| `NotSignedIn.account` filled from the selection | onepassword.rs `session_cause` | behaviour |
| `run`'s preflight stops on session/account causes (exit 7 or 2); a terminal signs in and replays, never after a started child | run.rs, main.rs loop | behaviour, breaking for op-default runs |
| `.opv` key `config`; `GivenBy::DotOpv`; FR-25 order | config_store.rs, cause/subject.rs | new field (0.17 refuses it) |
| `ConfigNotFound.found` | cause/mod.rs, render.rs | new subject field |
| `opv_state` section `accounts` | mcp.rs, surface.json | new MCP surface |

## 5. Owner decisions

**D1. What happens when a `--json` document cannot be written to stdout.**
*Situation:* today opv drops the write error and exits with the command's own code, so a full disk
or a closed pipe gives an agent exit 0 and no document. That is one candidate for #265.
*Options:*
- (a) exit 74 (Unix `EX_IOERR`) as the existing `local_io_failed` cause, with a stderr line that
  leads with the command's own outcome. `EPIPE` counts under `--json`; text mode keeps `| head` at
  exit 0.
- (b) reuse exit 6, today's `local_io_failed` exit.
- (c) keep the command's exit code and only add the stderr line.

*In practice:* with (a) a wrapper can tell "the command failed" from "its report was lost". (b)
blurs that with a policy refusal. (c) still lets an agent read exit 0 and act on nothing. Only
`head -c` or an early-exiting reader on a document over 64 KiB triggers `EPIPE`, because documents
are one line.
*Recommendation:* **(a).** The new completeness test (§2.1 item 7) keeps the help and usage.md
honest.

**D2. Bump `schema_version` to 4.**
*Situation:* `next` gains `argv`, `reach` and `choices`, plus the kind `choose`. Clients branch on a
`kind` documented as a closed set.
*Options:*
- (a) bump to 4, as its own mechanical commit before the behaviour changes.
- (b) stay at 3, since the fields are additive.

*In practice:* under (b), a client that switches exhaustively on `kind` meets `choose` with no
signal that anything changed.
*Recommendation:* **(a).** json.rs's own rule bumps the version when the closed set changes
meaning, and there are few users.

**D3. How an assistant gets a session when its process cannot share the person's.**
*Situation:* on WSL with the Linux `op`, or on a headless host, a sign-in lives only in the shell
that made it. When the person signs in in their terminal, the assistant's own shell stays signed
out.
*Options:*
- (a) the typed step is `opv login -- <command>`, and the person runs it in their own terminal.
  `reach: none` tells the assistant it cannot verify by itself.
- (b-docs) as (a). In addition, docs and the skill (not a typed step) describe starting the
  assistant from a shell prepared with the session-reuse §5.2 `opv` shell function. Only `opv`
  receives the session there, never `op`, so the assistant still sees value-state only.

*In practice:* (b-docs) lets a person who wants self-verifying assistants set it up deliberately.
No opv output ever steers the assistant into a session.
*Recommendation:* **(b-docs).** It needs session-reuse H4 settled as "the shell function"; until
then the docs paragraph waits.

**D4. Replaying `opv run` after a sign-in.**
*Situation:* the issue asks to keep "all original arguments". The child's words may hold a
credential (SR-3).
*Options:*
- (a) at a terminal, sign in and continue in-process, with the `CHILD_STARTED` guard. Without a
  terminal, the handoff shows `-- <command>` with `argv: null`.
- (b) print the exact child command.

*Recommendation:* **(a).** It keeps every argument with nothing put on screen.

**D5. A configuration that is not on the walk-up path.**
*Options:*
- (a) `.opv config =`, with syntax checked at parse and existence and containment checked at use,
  the bounded walk-up order, and a two-base found-config hint.
- (b) discovery uses a downward match.
- (c) the hint only.

*In practice:* (a) is declared once and works everywhere, MCP included. (b) picks a file nobody
named. (c) means `--config` forever.
*Recommendation:* **(a).** Note that 0.17 refuses such a `.opv`.

**D6. The sign-in step when the project records its account.**
*Options:*
- (a) `Next: opv login` (a subshell), with the eval form named in the Do.
- (b) `eval "$(opv login --shell)"` first.

*In practice:* (a) is short and cannot be mistyped. (b) keeps the current shell.
*Recommendation:* **(a).**

## 6. Self-vet (after the FMECA vet)

### 6.1 Poka-yoke

| Mistake | How it is made impossible or caught |
|---|---|
| A `--json` command prints nothing and exits 0 | The empty-success Bug and checked delivery, tested by E1/E2 (every `json` command, no TTY) and E3/E3b |
| A replay runs the child twice | The `CHILD_STARTED` flag blocks the loop. A unit test with a fake runner that fails after the child gives one call. E14 counts `op run` calls |
| `next` contradicts `human_required` | Scoped invariant test plus L0's per-variant list |
| opv guesses an account | `choose` needs at least two candidates; no "first" accessor; `signed_in` is never used to select |
| An agent execs a placeholder or a misparsed command | `argv` only from a `Cmd`, `null` with a placeholder, round-trip test |
| ready and account list disagree | One builder, plus a golden comparison |
| A missing generated config blocks sign-in | Syntax-only parse, tested by `dot_opv_config_missing_file_keeps_login_working` |
| A stray file above the repository wins | The bounded walk-up order, tested by `dot_opv_config_beats_walk_up_above_repo` |
| An exit code goes undocumented | `exit_codes_help_lists_every_code` |
| Snapshot churn hides a regression | The bump lands alone; its word-diff shows only `3`→`4` |
| A recovery loop | E8: following `next` from either command ends at `choose` within 3 hops |

### 6.2 Security

- **Values never in argv, env, files or logs.** No path here reads a new value. The preflight is
  the existing item read; its values are registered with the scrubber (SR-1). `account_choices`
  carries IDs, emails, shorthands, addresses and booleans. `found` carries paths. The lost-write
  cause carries an I/O kind, a byte count and an outcome, never document text.
- **The replay's session** reaches `op run` (runner.rs:1773-1779) and, through `op run`'s env
  pass-through, the `local-delivery` step, which strips every `OP_*` before the app (§2.2 item 4).
  That the app is free of it is inferred, and E14b tests it with `SESSION_CANARY`. If the test
  fails, the owner decides between stripping it (`env -u` on Unix) and accepting session-reuse
  M6's exposure. It is never accepted silently.
- **Session tokens in output.** No step contains one. The `shell` reach row names a command whose
  token only ever goes to a pipe (session-reuse §5.5). No typed step puts a session into an
  assistant's shell (D3).
- **Never infer an ambiguous account.** See §6.1.
- **No new permission layer.** `choose` is `human_required` because only the person knows which
  account holds the project: a fact, not a policy. What any session can then read is decided by
  1Password.
- **Untrusted clone.** `.opv config` is checked syntactically at parse and for containment at use,
  with both roots canonicalized. The worst case is another file inside the same clone, which
  `--config` could name anyway.
- **Canary scan.** Every new e2e case runs under `Rule::NoCanaryValue`, the replayed child's env
  included.

### 6.3 Architecture guards

- **FR-12 / FR-37** scan production code only (`production_code` strips `#[cfg(test)]`; FR-37
  skips `*_tests.rs`). The risk is a provider word in a production string in
  `config.rs`/`config_store.rs`, so those use `infra/`. Test paths are exempt. `op` is the source,
  not a target, so `run.rs` may name it.
- **J7 `observed_seal`.** The lost-write cause is local I/O and builds no `Observed`. The preflight
  reuses the read's diagnosis: no `lost_call` caller and no sealed constructor.
- **Global registration.**
  - `surface.json`: the `opv_state` enum and its description gain `accounts`; the CLI gains no
    flag.
  - The exit-code help gains 74 and the missing 10, now checked by a test.
  - The all-providers channel contract is untouched.
  - `opv schema` is regenerated.

## 7. Test plan

Each test makes one behavioural assertion. "No TTY" means stdin `/dev/null`, `setsid` (no
controlling terminal), stdout a pipe or a file, and `OPV_NO_SKILL=1`. The opv-sim world supplies
`op`.

### 7.1 Unit

| Test | Assertion |
|---|---|
| `json::empty_success_is_an_internal_error` | `finish_with(b"", Ok, raw=false)` → `error.code == "internal_error"` |
| `json::non_object_success_is_an_internal_error` | body `"text\n"` → `internal_error` |
| `json::empty_raw_success_is_an_internal_error` | raw, empty body → `internal_error` |
| `json::raw_success_keeps_its_body` | `config export`'s raw body is unchanged |
| `stdout_sink::retries_would_block` (unix) | `WouldBlock` twice, then `Ok` → every byte delivered |
| `stdout_sink::would_block_past_budget_is_lost` (unix) | a zero budget gives `LocalIo{Stdout, WouldBlock}` |
| `stdout_sink::broken_pipe_is_lost` | `LocalIo{Stdout, BrokenPipe}` |
| `stdout_sink::no_space_is_lost` | `LocalIo{Stdout, NoSpace}` |
| `stdout_sink::flush_error_is_lost` | `write_all` succeeds but `flush` fails → `LocalIo{Stdout}` |
| `cause::stdout_local_io_exits_74` | `LocalIo{op: Stdout}.exit_code() == 74` |
| `cause::file_local_io_still_exits_6` | `LocalIo{op: Write}.exit_code() == 6` |
| `render::lost_report_leads_with_outcome` | the first clause of the stderr text is the command's outcome |
| `exit_codes_help_lists_every_code` | every `exit_code()` number appears in the `--help` block and in usage.md |
| `render::human_required_implies_person_actor` | over every variant outside L0's accepted list, `human_required` implies `actor == person` |
| `render::account_required_plans_choose` | two candidates → `kind == choose` |
| `render::choose_needs_two_candidates` | one candidate → a single `next` |
| `render::placeholder_step_has_null_argv` | `login -- opv run dev -- <command>` → `argv == null` |
| `render::argv_round_trips_clap` | every non-null `argv` parses with the real clap |
| `json::typed_next_keeps_argv_choices_reach` | the framed `next` keeps all three |
| `render::signin_next_omits_account_known_to_pointer` | `.opv` account → `opv login -- …` |
| `render::signin_next_names_account_from_environment_only` | environment-only account → `--account <id>` |
| `account::several_unselected_is_blocking_account_required` | finding `account_required`, `blocking` |
| `account::several_unselected_next_is_choose` | `next.kind == choose`, two choices |
| `account::signed_in_choice_has_no_signin_step` | no `signs_in` step in that choice |
| `account::selected_signed_out_next_names_the_account` | `next.command` names the selected ID |
| `account::selected_signed_in_has_no_account_finding` | no `account_*`/`selected_*` finding |
| `account::choices_hold_no_session_var_value` | with `OP_SESSION_x=CANARY`, the document has no `CANARY` |
| `run::signed_out_read_stops_before_op_run` | the sim log has no `op run` |
| `run::signed_out_read_is_op_not_signed_in` | code `op_not_signed_in` |
| `run::own_session_required_under_service_account` | code `own_session_required` |
| `run::tidy_problem_still_runs` | a format problem still calls `op run` |
| `run::op_default_account_is_refused` | several accounts, none selected → `account_required` |
| `main::no_replay_after_child_started` | a fake runner that fails `op_not_signed_in` after the child → exactly one `op run` call |
| `config_store::dot_opv_config_is_honoured` | cwd `infra/shared-host` with `config =` → that file |
| `config_store::walk_up_below_dot_opv_beats_config` | a `secrets.toml` at or below the `.opv` directory wins |
| `config_store::dot_opv_config_beats_walk_up_above_repo` | a `secrets.toml` above the `.opv` loses |
| `config_store::dot_opv_config_missing_file_keeps_login_working` | `pointer_account` still returns the account |
| `config_store::dot_opv_config_missing_file_is_config_unreadable_at_use` | `locate` → `ConfigUnreadable{given_by: DotOpv}` |
| `config_store::dot_opv_config_with_dotdot_is_invalid` | `config_invalid`, `RelativeInRepo` |
| `config_store::dot_opv_config_absolute_is_invalid` | `config_invalid` |
| `config_store::dot_opv_config_symlink_outside_repo_is_refused` | `ConfigUnreadable` at use |
| `config_store::cwd_through_symlink_is_accepted` | a cwd reached by symlink locates the file |
| `config_store::dot_opv_config_and_project_conflict` | `ConflictsWith{project}` |
| `config::found_lists_below_root_bounded` | 25 files → 20 listed |
| `config::found_stops_after_directory_cap` | 2 001 directories → "search stopped" |
| `config::found_skips_node_modules_and_target` | skipped directories are not listed |
| `render::one_found_config_uses_two_bases` | Next `--config` is relative to cwd and Do `config =` is relative to `.opv` (cwd ≠ the `.opv` directory) |
| `render::several_found_configs_have_no_runnable_next` | `next.kind` is not `run` |

### 7.2 End-to-end (opv-sim, `tests/e2e/scenarios/agent_signin.rs`, no TTY unless marked)

| Case | Assertion |
|---|---|
| E1 every `--json` command in `surface.json`, world signed in | stdout is exactly one JSON object |
| E2 the same, world signed out | stdout is exactly one JSON object |
| E3 `opv version --json > /dev/full` | exit 74 |
| E3b `opv version --json \| true` | `PIPESTATUS[0] == 74` |
| E5 `opv status --all \| head -1` (text) | exit 0 |
| E5b `set -o pipefail; opv status --all --json \| head -c1` | stderr begins with the command's outcome |
| E1v `opv version --json --verbose` | stderr has `stdout: one JSON document, <n> bytes, delivered` |
| E6 `ready --json`, two accounts on one address, none selected | `next.kind == choose` |
| E7 E6 | `len(next.choices) == 2` |
| E8 following `next` from `ready` and from `account list` | ends at `choose` within 3 hops |
| E9 selected, signed out | `next.kind == authorize` |
| E10 selected, signed in | no `account_*` finding |
| E11 `opv run dev -- true`, signed out | exit 7 |
| E12 E11 | stderr has no `op signin --help` |
| E13 E11 | last stderr line is `Next: opv login -- opv run dev -- <command>` |
| E14 E11 under a `script(1)` PTY, sim sign-in succeeds | exactly one `op run` call |
| E14b E14 with child `env` | the child's output contains no `SESSION_CANARY` |
| E15 E14 with child `sh -c 'exit 3'` | exit 3 |
| E-R12 `opv run` with two accounts, none selected | exit 2 `account_required` |
| E16 #267 layout with `config =`, cwd `infra/shared-host` | `error.code != config_not_found` |
| E17 #267 layout without `config =` | `next.command` contains `--config fleet/secrets.toml` |
| E18 MCP `opv_state section=accounts` vs `account list --json` | equal `next` |
| E19 canary scan over every case | no canary in any channel |

### 7.3 Release gate

Run all of §7.2 with `CI=true` too, and the cargo tests. L1a's E1/E2/E3/E3b/E1v run in its own
release (0.17.3) as well.

## 8. Delivery steps

**Order:** L1a ships first, alone, as 0.17.3; it gives the #265 reporter a build to re-run. Then
on 0.18: L0a (bump alone), then L0 (contract), then L2/L3/L4 in parallel, then L5, then L6 and L7.
Total effort is **33.5 h**, the vet's revised figure.

| Id | Lane | Owns (files) | Prereqs | Est. h | Owner | Est. lines |
|---|---|---|---|---|---|---|
| L1a | `json-delivery` (#265, 0.17.3) | `src/json.rs` (empty success), `src/stdout_sink.rs` (new), `src/lib.rs` (one `pub mod`), main.rs final-write block (2085-2106) and exit-code help (66-76), `LocalIo` exit and fields in `src/cause/mod.rs` and its arm in `src/cause/render.rs`, `docs/usage.md` exit-code table, `tests/exit_codes.rs` (new) | D1 | 4 | Claude agent (fd semantics) | ~300 |
| L0a | `schema-bump` | `json::SCHEMA_VERSION`, regenerated snapshots and test expectations, `llms.txt` | L1a merged (shares `json.rs`), D2 | 1.5 | commodity worker | ~10 hand-written + ~770 regenerated (mechanical, word-diff only `3`→`4`) |
| L0 | `contract` | `src/cause/{mod,codes,render,step,subject}.rs` (`Next::Choose`, `ConfigNotFound.found`, `GivenBy::DotOpv`, the `NotSignedIn` account fill-in and short Next, `account_choices`, the invariant test plus the **variant list with a decision each**), `src/json.rs` (`typed_next` carries `argv`/`choices`/`reach`), `src/schema.rs`, `tests/e2e/expected/surface.json`, `docs/design/error-catalog.md`, `docs/design/requirements.md` | L0a | 6 | Claude agent | ~400 (split the variant flips into a follow-up commit if over) |
| L2 | `run-preflight` (#266) | `src/app/run.rs` (preflight, `CHILD_STARTED`, tests), main.rs loop (2044-2081: the guard check only) | L0 | 3.5 | commodity worker | ~200 |
| L3 | `account-choices` (#257) | `src/app/account.rs`, `src/app/account_tests.rs`, `choose_error` in `src/adapters/onepassword_manifest.rs`, `src/app/signin.rs` (`reach`, moved `refresh_account`), `src/app/login_shell.rs` (caller only), `src/app/ready.rs` (typed `next`) | L0, D3 | 5 | Claude agent | ~380 |
| L4 | `config-pointer` (#267) | `src/config_store.rs`, `src/config_store_tests.rs`, `src/config.rs` (`found_below`) | L0, D5 | 5 | Claude agent (untrusted-clone checks) | ~380 |
| L5 | `mcp-accounts` | `src/mcp.rs` (section, description, `SECTION_FORMAT`), `src/mcp_state_tests.rs` | L3 | 1.5 | commodity worker | ~90 |
| L6 | `docs-skill` | `docs/usage.md` (non-exit sections), `docs/local-development.md`, `docs/agent-skill.md`, `docs/mcp.md`, `CHANGELOG.md` (breaking preflight; `.opv config` refused by 0.17; schema 4) | L0-L4 | 2.5 | commodity worker | ~220 |
| L7 | `e2e-headless` | `tests/e2e/scenarios/agent_signin.rs` (new), `tests/e2e/main.rs` (one `mod`), `tests/e2e/matrix.rs` (`OneDocumentNoTty`), sim world fixtures | L1a, L2-L5 | 4.5 | Claude agent | ~380 |

**Critical path:**
- With L1a shipped separately as 0.17.3: L0a (1.5) → L0 (6) → L3 (5) → L5 (1.5) → L7 (4.5) =
  **18.5 h**.
- If L1a must merge first in the same line: **22.5 h**.

**File ownership:** `main.rs` is shared by line range only (L1a: 66-76 and 2085-2106; L2:
2044-2081). `json.rs` is owned in sequence (L1a → L0a → L0). No other file has two owners.

## 9. Requirements to adopt

- **FR-64 — One `--json` document or a loud failure** (§2.1): the invariant, `LocalIo{Stdout}` at
  exit 74, the empty-success Bug, the `--verbose` delivered line, and exit-code completeness.
- **FR-65 — Typed account remediation** (§2.3): `choose`, `argv` built only from a `Cmd`, `reach`,
  never guessing, and one builder for `ready`, `account list` and MCP. It amends FR-49 and FR-51.
- **FR-66 — `.opv` names the configuration** (§2.4): syntax checked at parse, containment checked
  at use, the bounded walk-up order, and the two-base hint. It amends FR-25.
- **FR-40 amended:** renew-in-place covers `run`'s pre-child failures and never follows a started
  child. The sign-in Next omits `--account` when the project records it, and an op-default run is
  refused.
- **NR-19 amended:** `run` is exempt only for its child's own exit code.

## 10. Changes from the FMECA vet

| Vet item | Applied in |
|---|---|
| 1 #265 root cause not established; three non-reproductions; regular-file errno set; `>&-` struck | §1.1 |
| 2 No `OutputLost`; `LocalIo{Stdout}` at exit 74 with `bytes_written`/`outcome`; write and flush checked; `cfg(unix)` poll; outcome-first stderr | §2.1, §4, D1, A3 |
| 3 Diagnostic ships first (L1a, 0.17.3); #265 stays open until the reporter re-runs | §1.1, §2.1, §8 |
| 4 `CHILD_STARTED` guard; the session's reach stated and tested (E14b); breaking op-default refusal | §2.2, §6.2, §7 |
| 5 `argv` only from a `Cmd`; `typed_next` carries fields; producers migrated or `null`; D3(b) not a typed step | §2.3, D3, A13, A14 |
| 6 `.opv config` syntax at parse, existence and containment at use; walk-up bounded by the `.opv` directory; both sides canonicalized; two bases; scan cap | §2.4 |
| 7 Invariant scoped with L0's variant list | §2.3, §8 L0 |
| 8 FR-12/FR-37 scan production code only | §6.3 |
| 9 E4 dropped; E3b, E5b, E14b, E-R12 and the listed unit tests added | §7 |
| 10 Bump blast radius and its own commit; `llms.txt` fixed; MCP description; CHANGELOG items | §4, §8 L0a, L5, L6 |
