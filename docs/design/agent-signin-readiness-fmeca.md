# DESIGN-FMECA vet: agent sign-in and readiness (#265, #266, #257, #267), `docs/design/agent-signin-readiness.md`

Reviewer: independent; did not write the design. Date: 2026-11-04. Method: the owner's
DESIGN-FMECA procedure (persona, objective, constraints, code-change-proposal requirements, three
phases, output format, verification checklist), applied as written.

Owner question: **can this be built as written, and does it fix what the reporters hit?**

**Short answer: ready with changes.** The four problems are real and three of the four root
causes hold in the code (#266, #257 and #267 were confirmed here, #266 by re-running it). The
architecture is mostly justified and fits opv's existing seams. Five things must change before
lanes start:

1. **#265's root cause is not established.** The reporter's own command redirects to a regular
   file. On a regular file, `EPIPE` and `EAGAIN` cannot happen, yet the design names them as the
   likely triggers. The fix makes *any* write error loud, and its empty-success rule covers the
   other plausible path, so it is still the right fix. But it must ship with the diagnostic first,
   and #265 must stay open until the reporter re-runs it.
2. **One of the design's "verified" mechanisms is wrong.** With `>&-` (stdout closed), the Rust
   runtime reopens fd 1 on `/dev/null` before `main` runs (verified below). There is no `EBADF`,
   nothing can detect it, and test E4 can never pass.
3. **`OutputLost` duplicates an existing cause.** `Cause::LocalIo { op: LocalOp::Stdout }`
   (`local_io_failed`, exit 6) already reports stdout write failures. The design should extend
   that cause instead of adding a parallel one.
4. **The replay's security claim does not hold.** The design says the replay "passes nothing new
   to any child". In fact the fresh in-memory session goes to `op run`, as it does to every `op`
   call (`runner.rs:1773-1779`), and from there it very likely reaches the app. That is the same
   exposure as the `opv login -- opv run` handoff, but it must be stated and tested. The replay
   also needs a structural guard so that it can never follow a child that has already started.
5. **`.opv config =` is checked in the wrong place and in the wrong order.**
   - It is validated at parse time. The file `.opv` sits in is read by `opv login`, by account
     selection and by every command, so a clone whose generated config does not exist yet would
     break all of them.
   - The walk-up search for `secrets.toml` is not bounded by the repository. A stray
     `~/secrets.toml` would therefore beat the configuration that `.opv` declares.

After these changes no High or Medium risk remains. The design's owner decisions hold, except
D3(b) as written: it conflicts with "assistants see value-state only".

Evidence levels used throughout:
- **Proven**: an industry standard, or opened and shown in code or by experiment here.
- **Adapted**: reasonable, but not proven in this setting.
- **Speculative**: assumed, not validated.

Code paths are relative to `/home/mc/.cache/lanes/opv-0180-design` (rev `9b4f7b9b`). Experiments
used the installed `opv 0.17.2` (`~/.local/bin/opv`) and never printed a document body, a value or
a session. Only exit codes, byte counts and fixed error markers were shown.

---

## 0. Claims checked against the code and by experiment

| Design claim (§) | Verdict | Evidence |
|---|---|---|
| main.rs discards the final write and flush errors (§1.1) | **Holds** | `src/main.rs:2091` `let _ = …write_all(&framed)`, `:2093` `let _ = stdout.flush()`; exit from `res` only `:2094-2106` |
| `PipeSafe` swallows `BrokenPipe` (§1.1) | **Holds** | `src/main.rs:1866-1898` |
| An empty `Ok` body passes through byte for byte (§1.1) | **Holds** | `src/json.rs:153-156`; `version` and `ready` always write a body (`src/app/version.rs:191-199`, `src/app/ready.rs:1342-1343`) |
| MCP refuses an unreadable report (§1.1) | **Holds** | `src/mcp.rs:233-242` |
| `> /dev/full` gives exit 0 and nothing written (§1.1) | **Holds** (mechanism) | Rust test program (§0.1): `write_all` returns `StorageFull` and opv drops it |
| `>&-` is `EBADF` and gives exit 0 with nothing written (§1.1) | **Wrong** | std reopens a closed fd 0-2 on `/dev/null` before `main`. Test program: `fd1=/dev/null write=Ok(())`. opv cannot detect this or tell it from a deliberate `> /dev/null`, so **E4 cannot pass** |
| The likely triggers in the reporter's shell are `EAGAIN`, `EPIPE` or `EPERM` (§1.1) | **Not supported** | The reporter's command is `> /tmp/opv-ready.json`, a regular file. A regular file never returns `EAGAIN` and has no reader to lose (`EPIPE`). What remains for a regular file is `ENOSPC`/`EDQUOT`/`EIO`, or a seccomp/LSM `EPERM` on `write(2)`. A sandbox that blocked the file would normally fail at `open`, in the shell, which gives exit ≠ 0 |
| #265 reproduces in a no-TTY agent shell (§1.1) | **Does not reproduce** (agrees with the design) | Claude Code shell (stdin a socket, no TTY): `version --json` 0/1182 B, `ready --json` 7/546 B. **Codex `workspace-write` sandbox** (`codex sandbox -c sandbox_mode="workspace-write"`, Codex 0.166.0): `version --json` 0/1190 B, `ready --json` 7/546 B, `schema` 0/103565 B. In Codex's default read-only sandbox the redirect itself fails (`Read-only file system`, exit 2), which is not the reporter's symptom |
| #266: the tolerant read discards a typed sign-in cause, and `op run` prints op's vendor line (§1.2) | **Holds**, re-run here | `src/app/run.rs:286-288` `.ok()`; `:387` `run_inherited_clean(OP, …)`. Re-run in zonetico-saas, signed out: exit 1, stderr has "not currently signed in" and "op signin --help", no `Do:`/`Next:` |
| The FR-40 loop retries only on `Err(op_not_signed_in)` (§1.2) | **Holds** | `src/main.rs:2069-2081`, `may_sign_in` `:2044` |
| The replay keeps every original argument (§2.2) | **Holds** | the loop re-parses the retained `matches` (`src/main.rs:2050`), child words included, in memory only |
| "The in-process replay passes nothing new to any child" (§6.2) | **Does not hold** | `sign_in_here` → `use_op_session` (`src/main.rs:5325`); `add_op_session` puts the session on **every `op` call** (`src/runner.rs:1773-1779`), `op run` included. `strip_op_session` strips only non-`op` children. Whether `op run` passes `OP_SESSION_*` on to the app is **inferred, not verified** (it passes its environment through); the module comment "passed … to nothing else" (`src/runner.rs:1762-1764`) is optimistic |
| #257: no finding is pushed for several unselected accounts, `next` is the first finding's (§1.3) | **Holds** | `src/app/account.rs:540-574`; `AccountRequired` plans `Next::Check(account list)` with `PickBetween` (`src/cause/render.rs:3452-3458`) |
| `next` is rebuilt as `{kind, actor, command}` (§1.3) | **Holds, and matters for L0** | `typed_next` (`src/json.rs:76-111`) **drops every other field**, so `argv`/`choices`/`reach` need it changed. 18 `"next"` producers in `src/app/*.rs` emit a string, not a `Cmd` |
| `Cmd::to_argv` exists (§2.3) | **Holds** | `src/cause/step.rs:74-79`; child words are never stored (`:1-6`, `from_cli` `:20-32`) |
| `discover` walks up only, and `.opv` is `deny_unknown_fields` (§1.4) | **Holds** | `src/config.rs:297-307`; `src/config_store.rs:696-705` |
| `find_dot_opv` is bounded by the repository (§6.2 "untrusted clone") | **Holds** | `src/config_store.rs:864-879` (outside a repository, only `start`) |
| `discover` is bounded by the repository | **No**: it walks to `/` | `src/config.rs:297-307`. The design's "walk-up still wins" order lets a file *above* the repository beat `.opv config` |
| "The help test catches a missing row" (§5 D1) | **Wrong**: no test checks exit-code help for completeness | only `tests/cli_ux.rs:92` (target CLI names). Exit 10 is missing today (`src/cause/mod.rs:2160` vs `src/main.rs:66-76`), which is why it went unnoticed |
| The same rule already exists for `login --shell`'s write (§2.1 item 6) | **Holds in spirit** | `src/app/login_shell.rs:450-459` maps any failure to `NeedsTerminal{NoTty}`, not to a `terminal_lost` code |
| Stdout write errors are new (§2.1, §4) | **No**: `Cause::LocalIo { op: LocalOp::Stdout }` exists | `src/app/mod.rs:535-542` (`write_err`), `src/cause/mod.rs:963-967`, code `local_io_failed` `:2051`, exit 6 `:2146` |
| FR-12/FR-37 scan "their tests" (§6.3) | **Partly wrong** | Both scan production code only. `production_code` strips `#[cfg(test)]` items (`src/app/mod.rs:2153-2174`) and FR-37 skips `*_tests.rs` (`:2324`). Renaming `fly/` in test paths is harmless but unnecessary. The real risk is a provider word in a *production* string in `config.rs`/`config_store.rs` |
| J7 `observed_seal` is unaffected (§6.3) | **Holds** | `tests/observed_seal.rs:30-70` checks `from_failed_call(`/`from_unusable_reply(`/`lost_call(`; none is needed |
| Schema bump blast radius (§4) | **Larger than stated, but mechanical** | 771 `"schema_version":3` lines in 716 test files (105 e2e snapshots). One constant `json::SCHEMA_VERSION` is used in 20 source files. No runtime consumer compares versions (remote protocol, TUI and MCP do not). `llms.txt:13` is already stale ("`schema_version` is 2", `next_kind`) |
| `surface.json`: `opv_state` section enum (§6.3) | **Holds** | `tests/e2e/expected/surface.json:1047-1059`; the tool description string in `src/mcp.rs:332` must also name `accounts` |

### 0.1 Experiments (no secret printed)

- **Rust stdout semantics** (a 10-line program built with `rustc`, run in the scratchpad):
  - `>&-` → `fd1=/dev/null write=Ok(()) flush=Ok(())`;
  - `> /dev/full` → `write=Err(StorageFull)`;
  - `| true` → `write=Err(BrokenPipe)`.

  `write_all` through `LineWriter` reports the error at the newline. A body without a trailing
  newline would report it only on `flush`.
- **Reporter's command, three shells**: the Claude Code agent shell, the Codex workspace-write
  sandbox, and Codex read-only (described above). None reproduced exit 0 with 0 bytes.
- **#266**: `opv run dev -- true </dev/null` in zonetico-saas, signed out. Output was matched
  against fixed markers only: exit 1, op's vendor line present.

**What would discriminate #265.** The reporter re-runs `opv ready --json --verbose > f; echo $?`
on a build carrying §2.1, or runs `strace -f -e trace=write,writev` on 0.17.2 (`strace` is not
installed on this machine). An `ok` line with the byte count, plus a non-empty `f`, rules opv out.
A loud `local_io_failed` names the errno. An `internal_error` names the empty-body path.

---

## Phase 1: Architecture Assessment

| Component | Purpose | Classification | Justification | Simpler Alternative | Risk if Removed |
|---|---|---|---|---|---|
| C1 Empty `Ok` body under `--json` is a Bug (exit 70) | No silent empty success | **Essential** (Proven: MCP already refuses it) | Covers the one in-opv path to the reporter's symptom that is not a write error | none | an empty success stays possible |
| C2 Checked delivery (`stdout_sink::deliver`) | A lost document is never exit 0 | **Essential** (Proven), **simplified** | Write and flush results are discarded today (`main.rs:2091-2093`) | Check `write_all` + `flush` inline in main and map to the existing `LocalIo{Stdout}`. A new module only pays for itself with the `WouldBlock` loop | #265's write-error path stays silent |
| C2a `WouldBlock` → `poll(POLLOUT)` within budget | non-blocking stdout from a harness | **Useful** (Adapted) | Not seen here (fd 1 flags had no `O_NONBLOCK` in either harness), but correct and small; Unix only | treat `WouldBlock` as lost | a harness with a non-blocking pipe gets exit 74 instead of a document |
| C3 New cause `OutputLost`, code `output_lost` | Name the failure | **Unjustified as a new variant** | `LocalIo { op: Stdout, io }` already exists (`local_io_failed`) | Extend `LocalIo`: `op: Stdout` exits 74 (as `Guard::Declined` already varies the exit by field), and gains `bytes_written` and the command's `outcome` | none: the extension keeps the value |
| C4 Exit 74 (`EX_IOERR`) | Exit code alone says "report lost" | **Useful** (Proven convention) | D1(a) | reuse 6 | a wrapper cannot tell "failed" from "report lost" |
| C5 `--verbose` "delivered, n bytes" line | Diagnose the next report | **Essential now** (because the root cause is unconfirmed) | It is the discriminating experiment for #265 | none | the next report is as blind as this one |
| C6 Text mode: non-EPIPE errors → 74 | Consistency | **Simplified** | Already an error today (`write_err` → `LocalIo`, exit 6). Only the exit number changes, through C3's extension | — | — |
| C7 `run` preflight stops on who-you-are causes | #266 | **Essential** (Proven: the read already returns the typed cause) | — | — | op's raw error, exit 1 |
| C8 In-process replay at a TTY | #266 "replay all arguments" | **Useful** (Proven loop, new reach) | Free given C7 and the FR-40 loop | none | a person retypes the command |
| C9 `NotSignedIn.account` filled from the selection | Account-aware Next | **Essential** | Fixes ready's `account: null` too | — | the recovery names no account |
| C10 `refresh_account` moved to `signin.rs`, short Next | #267 part 2 | **Useful** | One rule, every sign-in Next | — | long incantations |
| C11 `next.kind: choose` + `choices` | #257 | **Essential** | The only typed way to say "a person picks" without guessing | — | the loop in §1.3 |
| C12 `argv` on `next` and steps | #257 | **Essential, scope-limited** | Non-null only where the producer holds a `Cmd`. Never shell-split a display string | — | agents re-parse display text |
| C13 `next.reach` | Explains why an assistant cannot verify | **Useful** (Adapted) | Cheap; computed from existing `reuse_path`/`classify_static` | Put it in the Do text only | the assistant loops on `ready` after a person's sign-in |
| C14 D3(b) step `shares_session` (start the assistant from a signed-in shell) | Assistant self-verification on WSL | **Speculative; demote** | An exported `OP_SESSION_*` lets the assistant's shell run `op read`, which conflicts with "assistants see value-state only". Acceptable only in the session-reuse §5.2 shell-function form (only `opv` gets the session) | Docs and skill text, not a typed step | none for 0.18 |
| C15 `account list` blocking `account_required` + one builder | #257 parity | **Essential** | — | — | ready and account list disagree |
| C16 `opv_state` section `accounts` | MCP parity | **Useful** | Parity principle | — | MCP clients cannot see choices without `ready` |
| C17 `.opv config = "<path>"` | #267 part 1 | **Essential** | Declared once, works from anywhere, MCP included | `--config` hint only (D5c) | `--config` forever |
| C18 Found-config hint | Stop the harmful `propose setup` advice | **Useful** | The S1 harm is real: it leads to a second configuration | — | misleading Next |
| C19 `schema_version` 4 | Closed `kind` set changes | **Essential** (D2) | json.rs's own rule | — | silent client breakage |
| C20 `human_required ⇒ actor person` invariant over every variant | Consistent documents | **Useful, scope-limited** | 91 `Next::Check` sites (`src/cause/render.rs`). The blast radius is unmeasured, and a blanket flip stops assistants from running harmless reads | Fix `AccountRequired` (now `choose`), then enumerate the variants the test flags and decide each one in L0 | contradictory documents |
| C21 E1/E2 "every `--json` command emits one document, no TTY" | Regression test for #265 | **Essential** | — | — | — |

### Revised Architecture

- **Components retained:** C1, C2 (inline or small module), C2a, C4, C5, C7, C8, C9, C10, C11,
  C12 (scope-limited), C13, C15, C16, C17, C18, C19, C21.
- **Components simplified:**
  - C3 becomes an extension of `LocalIo { op: Stdout }`: exit 74, plus fields `bytes_written`
    and `outcome`. There is no new variant or code, and `local_io_failed` stays the code.
  - C6 needs no new code path.
  - C20 is scoped to an enumerated list of variants.
  - C17 is validated syntactically at parse; existence and containment are checked at use.
- **Components removed:** the `OutputLost` variant and the `output_lost` code; test E4.
- **Components demoted:** C14 (D3(b)) goes to docs and the skill, in the opv-only
  shell-function form, and is not a typed step.

---

## Phase 2: FMECA + poka-yoke + TRIZ

### Iteration 1 Risk Table

| # | Domain | Failure Mode | Cause | Effect | Severity | Probability | Mitigation (Poka-Yoke) | Observability | TRIZ Resolution | Residual Severity | Residual Probability |
|---|---|---|---|---|---|---|---|---|---|---|---|
| R1 | Delivery | #265 closed with a fix that does not touch the reporter's real trigger | The root cause is inferred. The listed triggers (`EAGAIN`/`EPIPE`) are impossible for the reporter's regular-file redirect | Reporter hits it again; trust in `--json` erodes | High | Medium | Ship C1+C2+C5 first (0.17.3 or the first 0.18 lane). Keep #265 open until the reporter's `--verbose` re-run shows `delivered` with a non-empty file, or names the errno. Rewrite §1.1's trigger paragraph to the regular-file errno set | the C5 line; the issue's re-run result | Prior action (#10): ship the diagnostic before the full contract change | Medium | Low |
| R2 | Delivery | Test E4 can never pass | Rust reopens closed fd 0-2 on `/dev/null` (§0.1) | L7 blocks or is "fixed" by weakening the assertion | Medium | High | Drop E4; correct §1.1's table. Keep E3 (`/dev/full`) and add `| true` with `PIPESTATUS[0] == 74` | CI | — | Low | Low |
| R3 | Technical | Parallel cause for stdout loss | `OutputLost` beside `LocalIo{Stdout}` | Two codes for one failure; the catalog drifts; violates "no parallel abstractions" | Medium | High | Extend `LocalIo`: `exit_code()` gives 74 for `op: Stdout`, and the fields `bytes_written`, `outcome` are added. `error-catalog.md` §4.10 names `local_io_failed` with `subject.op = stdout` | `codes_in_source` test (`src/cause/codes.rs:1044`) stays one code | Merging (#5) | Low | Low |
| R4 | Runtime / security | The replay hands the new session to the app | The session is set on every `op` call (`runner.rs:1773`); `op run` passes its env to its child | The app process holds `OP_SESSION_<id>` (it can read every vault the person can) | Medium | Medium (inferred) | State it in §6.2. Add e2e E14b: the child's env names no `OP_SESSION_*`. If op passes it on, accept it explicitly as the same exposure as `opv login -- opv run` (FMECA M6 already accepts that path), or run the child under `op run -- env -u OP_SESSION_<id> …` on Unix | e2e canary scan with `SESSION_CANARY` in the child's env dump (names and canary comparison only) | Separation in space: `op` gets the session, its child does not | Low | Low |
| R5 | Runtime | The replay runs the child twice | A future change makes `launch` return `Err(op_not_signed_in)` after `op run` started (a post-run read, a remote step) | A deploy script or migration runs twice | High | Low | Structural guard: `launch` records `child_started` (a process-wide flag set immediately before `run_inherited_clean`). The main loop never replays when it is set. Unit test: a fake runner that fails `op_not_signed_in` after the child gives one call. E14 stays | sim log: count of `op run` calls | Prior counteraction (#9) | High | Very low (now Low) |
| R6 | UX | A fresh clone, or a config not generated yet, makes every opv command fail | `.opv config` existence/canonicalize checked in `parse_dot_opv`, which `pointer_account`, `selected_account` and login's `record_account` also run | `opv login` and `opv account use` fail with `config_invalid`; the person cannot even sign in | Medium | Medium (the reporter's config is generated) | Parse checks syntax only: relative, no `..`, no NUL, not with `project`. `locate` checks existence and containment, and a missing file is `ConfigUnreadable { given_by: DotOpv }`. Readers of `account` ignore `config` | unit test `dot_opv_config_missing_file_keeps_login_working` | Segmentation (#1): parse vs use | Low | Low |
| R7 | Technical / security | A file above the repository beats the declared configuration | `discover` walks to `/` (`config.rs:297`); §2.4 puts walk-up before `.opv config` | `~/secrets.toml` from an experiment silently becomes the project's config | Medium | Low-Medium | Order rule: a walk-up match wins over `.opv config` only when it is at or below the `.opv`'s directory. Otherwise `.opv config` wins. The `using … (named by ./.opv)` line shows which | `using` line; unit test `dot_opv_config_beats_walk_up_above_repo` | Local quality (#3) | Low | Low |
| R8 | Technical | Path escape through `.opv config` | Cloned `.opv` with `..`, an absolute path or a symlink | opv reads a file outside the clone | Medium | Low | The design's canonicalize-then-prefix check, **with both sides canonicalized**: `repo_root` uses the non-canonical `start` (`config_store.rs:856`), so a cwd reached through a symlink, or WSL `/mnt/c`, gives false refusals or false passes. Outside a repository the root is the `.opv`'s directory. Re-check at open (TOCTOU is local-write only, so accepted) | the design's symlink and `..` tests, plus `cwd_through_symlink_is_accepted` | — | Low | Low |
| R9 | Contract | `argv` promised "on every `next`" cannot be met | `typed_next` drops fields. 18 body producers emit strings; only causes hold a `Cmd` | `argv` is null for most documents, or someone shell-splits display text (and could produce a wrong argv) | Medium | High | Rule: `argv` is non-null **only** when built from a `Cmd`/`Invocation`, never parsed from `command`. L0 migrates the producers this design needs (`ready`, `account list`, sign-in causes) to emit a typed `next`, and lists the rest as `argv: null` in `schema.rs`. Test: `argv` present ⇒ it round-trips through clap | schema test; e2e E1 asserts `argv` is null or parses | — | Low | Low |
| R10 | Contract | The invariant test flips many unrelated variants | `human_required ⇒ actor person` over all variants; 91 `Next::Check` sites | Assistants stop running harmless reads; snapshot churn hides real regressions | Medium | Medium | L0 runs the test first, lists the failing variants in the PR, and decides each one: either `authorize/person`, or keep the read and drop `PickBetween` from `human_required` (`render.rs:2767`) | the PR's list; snapshot diff limited to listed codes | Preliminary action (#10) | Low | Low |
| R11 | UX | `--json` piped to a reader that stops early gives exit 74 plus a stderr line | D1(a) counts `EPIPE` | Pipelines under `pipefail` fail; an agent may think a sync failed | Low-Medium | Low | Documents are one line, so `head -n` reads to EOF; only `head -c`, or `jq` exiting early on a document over 64 KiB, triggers it. The stderr line leads with the command's own outcome ("sync done; the reader closed stdout before the report was complete"). usage.md documents it | e2e E5b `status --json \| head -c1` → `PIPESTATUS[0]==74`, stderr starts with the outcome | Separation by condition: text keeps `\| head` at 0 | Low | Low |
| R12 | Runtime | A run that works today stops | The preflight now stops on `AccountRequired`/`AccountAmbiguous` where `op run` used op's default account | A person's `opv run` exits 2 after upgrading | Low | Medium | Intended (FR-40: never op's default by accident). The CHANGELOG names it as breaking. The `choose` gives the fix | CHANGELOG; E-case | — | Low | Low |
| R13 | Delivery | The exit-code help or usage.md misses 74 (or 10, as today) | No completeness test (`tests/cli_ux.rs:92` checks target names only) | A wrapper meets an undocumented code | Low | High (already happened with 10) | New test: every number in `Cause::exit_code`'s body (read like `codes_in_source`, `src/cause/codes.rs:1044-1060`) appears in the help and in `docs/usage.md` "Exit codes" | test failure | — | Low | Low |
| R14 | Delivery | The schema bump hides behaviour regressions in snapshot churn | 771 lines across 716 files change version | A real change in a snapshot is approved with the bump | Medium | Medium | L0 lands the bump **alone** as a mechanical commit (constant plus regenerated snapshots, verified by `git diff --word-diff` showing only `3`→`4`). Behaviour lanes follow. Fix `llms.txt:13` (already says 2) in L6 | review: a diff with nothing but `3`→`4` | Segmentation (#1) | Low | Low |
| R15 | UX | The found-config hint gives the wrong base path | `--config` is cwd-relative, `.opv config` is `.opv`-relative; §2.4 item 3 renders one `<path>` | The person pastes a path that resolves wrongly | Low | Medium | Render the two bases separately; test with cwd ≠ the `.opv` directory (E17 uses `fleet/secrets.toml` from `infra/shared-host`, so `.opv` needs `infra/shared-host/fleet/secrets.toml`) | unit test | — | Low | Low |
| R16 | Runtime | The found-config scan is slow on large trees or `/mnt/c` | Depth 4 caps depth, not the number of entries | A config-not-found error takes seconds on WSL | Low | Low | Cap visited directories (for example 2,000) and say "search stopped" in the Do | `--verbose` line with the count | — | Low | Low |
| R17 | Architecture | FR-37 trips on a production string | An example path or skip-list in `config.rs`/`config_store.rs` names `fly` | Guard test fails late | Low | Low | Use `infra/` in production strings and doc comments. Test-only paths are exempt (verified) | `core_modules_name_no_provider` | — | Low | Low |
| R18 | Runtime | `deliver` misses a flush error or fails to build on Windows | `LineWriter` reports at the newline or on flush; `poll`/`O_NONBLOCK` are Unix | A silent loss on a body without `\n`; a Windows build break | Low | Low | `deliver` returns `write_all` then `flush`. Gate `WouldBlock`-poll behind `cfg(unix)`; Windows treats `WouldBlock` as lost | unit tests listed in §7.1, plus `flush_error_is_lost` | — | Low | Low |
| R19 | Owner principle | An assistant is steered into a session that can read values | D3(b) as a typed step: an exported session in the assistant's shell allows `op read` | Conflicts with "assistants see value-state only" | Medium | Medium | Demote (C14). Keep D3(a). Offer (b) in docs and skill only in the session-reuse §5.2 form (the `opv` shell function: only `opv` receives the session, and opv never prints a value) | skill text review; canary scan | Intermediary (#24) | Low | Low |

### Remaining Risks After Iteration 1

- **High:** none. R5 keeps High severity, but the structural guard makes its probability very low.
- **Medium:** R1 remains at Medium severity until the reporter re-runs, which is outside the
  design's control. Its probability is Low once C5 ships first.
- **Low:** everything else.

### Iteration Summary

- **Key mitigations applied:**
  - ship the diagnostic first and keep #265 open (R1);
  - drop E4 (R2);
  - extend `LocalIo` instead of adding a cause (R3);
  - state and test the session's reach in the replay (R4), and add a `child_started` guard (R5);
  - split `.opv config` validation into parse and use (R6), with a bounded walk-up order (R7)
    and canonicalized roots (R8);
  - build `argv` only from a `Cmd` (R9);
  - enumerate the variants the invariant flips (R10);
  - add an exit-code completeness test (R13);
  - land the bump as its own commit (R14).
- **Simplifications applied:** no new cause variant or code; no text-mode code path; D3(b) out of
  the schema.
- **Trade-offs introduced:** `argv` is null on documents whose producer was not migrated (honest,
  and documented). `EPIPE` under `--json` is exit 74 (D1(a), accepted).
- **Reason for stopping:** no High or Medium remains except R1's severity, which only the
  reporter's re-run can clear. Further mitigation inside the design would mean guessing the
  trigger.

---

## Phase 3: Systemic Risk Review

- **Calibration risk.** No scores or confidences are involved. The one calibration question is
  the root cause of #265, and it is uncalibrated: there is no reproduction in three shells, and
  the regular-file redirect rules out the named triggers. It is validated by the C5 line in the
  reporter's environment, with E1/E2 as the standing regression test.
- **Observability risk.**
  - *Bad decisions* (a guessed account): `choose` exists only with two or more candidates, and
    E6-E8 test it.
  - *Premature completion* (exit 0, no document): C1 and C2, plus E1/E2.
  - *A replay that ran twice*: the `op run` count in the sim log (E14) and the `child_started`
    guard.
  - *Policy regressions*: the canary scan (E19) should add the child's env for the replay (R4).
  - *A lost report*: today it is invisible. After the change it is `local_io_failed` with
    `subject.op: stdout`, the errno kind and the command's outcome.
- **Complexity vs utility.** The design is proportionate. The simplest viable version is: C1, C2
  inline with `LocalIo`, C5, C7-C9, C11-C12 for `AccountRequired` only, C17 without the hint,
  and the bump. The hint (C18), `reach` (C13) and the MCP section (C16) are cheap and justified.
  D3(b) as a typed step is the one piece whose complexity (a new `effect` value, and a session
  path to explain) exceeds its demonstrated value.
- **Oversimplification risk.** Removing C2a (`WouldBlock`) would be tempting, because neither
  harness showed `O_NONBLOCK`. Keep it: it is a dozen lines, and a harness that sets it would
  otherwise turn every document into exit 74. Do not drop C13 either: without `reach`, an
  assistant on WSL loops on `ready` after the person signs in elsewhere.
- **Incremental delivery.** The work phases cleanly:
  - **(A) #265 diagnostic and fix:** C1, C2, C5 and the `LocalIo` exit 74. No schema change.
    It can ship as 0.17.3 and gives the reporter a build to re-run.
  - **(B)** the schema bump alone, as a mechanical commit.
  - **(C)** the behaviour lanes.

  Rollback: A is contained in `main.rs`, `json.rs` and `cause/mod.rs`. B is one constant.
  `.opv config` is additive, but an older opv (0.17) refuses a `.opv` that has it
  (`deny_unknown_fields`). The CHANGELOG must say so, because the file is committed and shared by
  a team.

### Final Outcome

All High and Medium risks are mitigated to Low by the changes below, except R1's severity. R1's
probability is Low once the diagnostic ships first, and its remaining severity can be cleared only
by the reporter's re-run, which the design cannot control.

---

## Conflicts with owner decisions

| Decision | Recommendation in design | This vet |
|---|---|---|
| D1 exit 74, `EPIPE` counts under `--json` | (a) | **Agree.** Implement it as `LocalIo { op: Stdout }` exiting 74, not as a new `output_lost` code (R3). Add the completeness test, because "the help test catches a missing row" is not true today (R13) |
| D2 `schema_version` 4 | (a) | **Agree.** Land it as its own mechanical commit (R14) |
| D3 assistant session reach | (b), with (a) first | **Conflict.** Typed step (b) (`shares_session`) steers the assistant's shell into a session that can `op read`, against "assistants see value-state only". Take (a). Mention (b) only in docs and the skill, and only in the opv-only shell-function form (session-reuse §5.2) |
| D4 replay in-process | (a) | **Agree**, with the `child_started` guard (R5) and the session-reach test (R4) |
| D5 `.opv config` + hint | (a) | **Agree**, with parse-vs-use validation (R6), the bounded walk-up order (R7), canonicalized roots (R8) and two path bases in the hint (R15) |
| D6 `Next: opv login` | (a) | **Agree** |

---

## Required design changes

1. **§1.1:**
   - Replace the "likely triggers" paragraph: on a regular-file redirect only
     `ENOSPC`/`EDQUOT`/`EIO` or a seccomp/LSM `EPERM` on `write(2)` are possible, and an
     empty-body `Ok` remains a candidate.
   - Record the three non-reproductions (Claude shell, Codex workspace-write, Codex read-only).
   - Strike the `>&-` row: it is `/dev/null` after std's fd sanitization, not `EBADF`.
2. **§2.1 / §4 / §5 D1:**
   - No `OutputLost` variant and no `output_lost` code. Extend `Cause::LocalIo` so that
     `op: Stdout` exits 74 and carries `bytes_written` and the command's `outcome`.
   - `deliver` checks both `write_all` and `flush`, and gates `WouldBlock`-poll behind
     `cfg(unix)`.
   - The stderr line leads with the command's own outcome.
3. **§2.1 delivery order:** ship C1, C2 and C5 first (0.17.3, or lane L1 merged before the bump),
   and keep #265 open until the reporter's `--verbose` re-run.
4. **§2.2:**
   - Add the `child_started` guard: the main loop never replays once `op run` has started.
   - In §6.2, state that the replay's session reaches `op run` (`runner.rs:1773`) and, inferred,
     the app. Test it (E14b) and either strip it with `env -u` on Unix or accept it as M6's
     existing `opv login --` exposure.
   - Note that the preflight now refuses an op-default account (CHANGELOG, breaking).
5. **§2.3:**
   - `argv` is non-null only when built from a `Cmd`/`Invocation`, and is never parsed from
     `command`.
   - `typed_next` must carry `argv`/`choices`/`reach`.
   - L0 migrates `ready`, `account list` and the sign-in causes to a typed `next`. Every other
     producer is `argv: null`, as documented in `schema.rs`.
   - D3(b) is not a typed step.
6. **§2.4:**
   - `parse_dot_opv` checks syntax only. Existence and containment are checked in `locate`, as
     `ConfigUnreadable { given_by: DotOpv }`.
   - A walk-up match wins only at or below the `.opv`'s directory.
   - Canonicalize both the root and the file; outside a repository the root is the `.opv`'s
     directory.
   - The hint renders a cwd-relative `--config` and a `.opv`-relative `config =`.
   - Cap the scan at a number of directories visited.
7. **§6.1 `human_required_implies_person_actor`:** L0 lists every variant the test flips and
   decides each one. It must not be a blanket change.
8. **§6.3:** FR-12/FR-37 scan production code only. Keep provider words out of production strings
   in `config.rs`/`config_store.rs`. Renaming test paths is optional.
9. **§7:**
   - Drop E4. Add E3b (`| true`, `PIPESTATUS[0]==74`), E5b (`--json | head -c1` under
     `pipefail`), E14b (the replayed child's env holds no session canary) and E-R12 (op-default
     account refused).
   - Add unit tests `dot_opv_config_missing_file_keeps_login_working`,
     `dot_opv_config_beats_walk_up_above_repo`, `cwd_through_symlink_is_accepted`,
     `stdout_sink::flush_error_is_lost`, and `exit_codes_help_lists_every_code` (covering the
     help and usage.md).
10. **§4 / L6:**
    - Count the bump's blast radius (771 lines in 716 test files) and fix `llms.txt:13`, which
      is already stale.
    - Update the `opv_state` description string (`src/mcp.rs:332`) for `accounts`.
    - The CHANGELOG notes that 0.17 refuses a `.opv` with `config`.

## Revised delivery steps

| Id | Change from the design | Est. h (design → revised) |
|---|---|---|
| L1a (new first merge) | C1 (empty-success Bug in `json.rs`), C2 `deliver` in main's final block, `LocalIo{Stdout}` exit 74, C5 verbose line, completeness test for exit codes. Can ship as 0.17.3 | — → 4 (moved out of L0/L1) |
| L0a | Schema bump alone: constant, regenerated snapshots, `llms.txt` | — → 1.5 |
| L0 | Contract minus the bump: `Next::Choose`, `typed_next` carrying `argv`/`choices`/`reach`, typed `next` for ready, account list and the sign-in causes, `ConfigNotFound.found`, `NotSignedIn` account fill-in, the variant list for the invariant | 5 → 6 |
| L1 | Absorbed into L1a | 3 → 0 |
| L2 | Plus the `child_started` guard and the E14b env test | 2.5 → 3.5 |
| L3 | Plus migrating account and ready producers to typed `argv`; D3(b) removed from the steps | 5 → 5 |
| L4 | Plus the parse/use split, bounded walk-up order, canonicalized roots, two-base hint, scan cap | 4 → 5 |
| L5 | Unchanged | 1.5 |
| L6 | Plus the CHANGELOG items (breaking preflight, `.opv` and 0.17) | 2 → 2.5 |
| L7 | E4 dropped; E3b, E5b, E14b and E-R12 added | 4 → 4.5 |

**Totals.** Effort: 27 h → 33.5 h. The critical path is L1a (4) → L0a (1.5) → L0 (6) → L3 (5)
→ L5 (1.5) → L7 (4.5) = **22.5 h** if L1a must merge before L0. If L1a ships on its own (0.17.3)
in parallel with L0a and L0, the 0.18 critical path is L0a → L0 → L3 → L5 → L7 = **18.5 h**
(design: 15.5 h).
