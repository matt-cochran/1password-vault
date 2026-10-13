# Accounts, sign-in and the readiness receipt

Status: designed 2026-10-13 for issues #80 (machine account discovery), #79 (login UX) and #81
(readiness and handoff receipt). FR-49 to FR-51 in `docs/design/requirements.md` are normative;
this document is their argument. The receipt model of §4 is also the data model of `opv ui`
(#82).

## 1. Problems found in the code (2026-10-13)

- `onepassword_manifest::accounts` returns an empty list when `op account list` fails or
  prints unexpected JSON, so "no accounts" and "discovery failed" look the same.
- One registered account is chosen silently (`pick_account`, `login::choose_account`): a
  person who meant another account (the #79 report) never sees a choice.
- `status --all` and `projects` search **every** account when several exist, while
  `pick_account` refuses to; the two disagree about what "the selected account" is.
- `Runtime::sign_in` and `add_account` inherit `op`'s stderr, so op's own text (`Please run
  'op signin --help'`) reaches the terminal, followed by opv's generic message. Captured
  excerpts (`op said: …`) can repeat it.
- `session_assignment` itself says "Run op signin --help for this CLI version".
- Sign-in failure text says "rerun opv setup" even when the caller was `login`.
- Nothing tells desktop-app accounts from CLI-registered ones; on WSL the Linux `op` cannot
  see the Windows app's accounts, and only one hint says so.

## 2. `opv account list` (FR-49, #80)

A read-only command. It never prompts, signs in, registers an account, creates a manifest or
tidies an item.

```text
$ opv account list
SELECTED  ACCOUNT                         ADDRESS                 SOURCE  SIGNED IN
*         owner@example.com (ABCD…WXYZ)   my-team.1password.com   cli     yes
          other@example.com (EFGH…STUV)   example.1password.com   cli     no
selected by: .opv (./.opv)
Next: opv login            # sign in to the selected account
```

`--json` document (`opv schema` lists it):

```json
{"schema_version":1,
 "discovery":"ok",                    // ok | unavailable | op_missing
 "platform":"wsl",                    // linux | wsl | macos | windows | other
 "cli_accounts_only":true,            // true where op keeps its own accounts (Linux, WSL)
 "selected":{"account_id":"ABCD…","by":"pointer","source":"./.opv"},  // or null
 "accounts":[{"account_id":"ABCD…","user_id":"…","email":"owner@example.com",
              "address":"my-team.1password.com","shorthand":"my-team",
              "source":"cli","signed_in":true,"selected":true}],
 "findings":[{"code":"selected_account_absent", ...}],
 "next":"opv login"}
```

- `selected.by`: `flag` (`--account`), `env` (`OP_ACCOUNT`), `pointer` (`.opv`),
  `manifest` (the project's recorded account), `only` (exactly one account, **reported, not
  chosen**), or `null`.
- `signed_in` comes from `op whoami --account <id>` per account (a probe; never prompts,
  never wakes the desktop app). Unknown when the probe cannot run: `null`.
- `source` is `cli` for every listed account. Desktop-app accounts the CLI cannot see are
  never claimed: on WSL and Linux the document says `cli_accounts_only: true` and the text
  output ends with one line explaining that accounts in the Windows or desktop app are not
  listed until added to this CLI (`opv login --add`).
- States, each a stable `findings` code with `human_required`: `no_accounts`,
  `selected_account_absent` (a recorded or given account this CLI does not have),
  `selected_signed_out`, `discovery_unavailable` (op failed or printed something
  unexpected; the scrubbed excerpt is never in JSON), `op_missing`.
- `opv account use <id|email|address>` (FR-49) records the account in `.opv`
  deterministically: no prompt, no sign-in. An email or address matching several accounts
  fails with code `account_ambiguous`, listing the candidates' IDs and addresses (never
  anything else), and `Next: opv account use <ID>`.

## 3. Login UX (FR-50, #79)

- With no explicit selection (`--account`, `OP_ACCOUNT`, `.opv`, an environment's
  `account`), `opv login` at a terminal shows a menu **even with one account**:

  ```text
  Which 1Password account holds this project's secrets?
    1. owner@example.com — my-team.1password.com  (signed in)
    2. Add another 1Password account
  On WSL, accounts in the Windows 1Password app are not visible here until you add them.
  ```

  The choice is recorded in `.opv`. Explicit selections and automation never see a menu.
- `op signin` and `op account add` run with **op's prompts on the terminal** (stdin and the
  TTY stay inherited for the password and Secret Key), but op's stderr after the prompts is
  captured, scrubbed and classified instead of printed raw. The classification maps to opv
  states, each with one recovery step naming the selected account:

  | State | Code | Recovery |
  |---|---|---|
  | account not registered with this CLI | `account_not_registered` | `opv login --add --account <email>` |
  | signed out / session expired | `op_not_signed_in` | `opv login --account <id>` |
  | desktop app locked or integration off | `desktop_app_unavailable` | unlock the app, or turn on CLI integration |
  | credential rejected | `credential_rejected` | re-enter at op's prompt: `opv login --account <id>` |
  | MFA failed or prompt cancelled | `sign_in_cancelled` | `opv login --account <id>` |
  | 1Password unreachable | `provider_unavailable` | retry later (exit 9) |
  | unexpected CLI response | `op_unexpected` | `opv doctor` |

  An unclassified failure is never called a bad password. A known account is always named in
  the next step; a bare `opv login` is suggested only when no account is known.
- Vendor directions (`op signin --help`, `op account add …`, `eval $(op signin)`) are removed
  from normal output by the scrubber's vendor-hint filter; `--verbose` still shows the
  scrubbed excerpt for diagnosis. No session, token, password or Secret Key in any error,
  debug output or artifact (SR-1).
- The sign-in failure text names the command that was running (`login`, `setup`, or the
  command that re-signed in), never a hard-coded `opv setup`.

## 4. Readiness receipt (FR-51, #81)

`opv ready [<env>] [--json]` (alias `doctor --receipt`) reports, read-only and
deterministically, everything an owner or agent needs to decide the next action, built from
the existing sources (doctor checks, `status --all`, project discovery, `account list`): no
parallel source of truth.

```json
{"schema_version":1, "receipt_id":"rcpt-<hash of the inputs>", "opv_version":"0.6.0",
 "config":{"source":"manifest opv · myapp in vault myapp-dev", "project":"myapp"},
 "account":{"account_id":"ABCD…","by":"pointer"},
 "matrix":[{"environment":"staging","product":"api","keys":7,"saved":6,"findings":1,
            "target":"fly","deployed":true}],
 "findings":[
   {"code":"op_not_signed_in","scope":{"account":"ABCD…"},"blocking":true,"actor":"owner",
    "effect":"signs_in","prerequisite":"opv login --account ABCD…",
    "verify":"opv ready --json"},
   {"code":"key_missing","scope":{"environment":"staging","product":"api","key":"STRIPE_KEY"},
    "blocking":true,"actor":"owner","effect":"writes_1password",
    "prerequisite":"opv open staging api/STRIPE_KEY","verify":"opv status staging --product api"}],
 "next":{"actor":"owner","command":"opv login --account ABCD…"}}
```

- Each finding: a stable `code` (from `Code` where one exists), `scope` (account,
  environment, product, key), `blocking`, `actor` (`owner` | `agent` | `ci`), `effect`
  (`none` | `signs_in` | `writes_1password` | `writes_target` | `writes_config`), one
  `prerequisite` command and one `verify` command. Machines never parse prose `Do:` lines.
- Layers are distinguished, never conflated: CLI registration, sign-in, vault access, field
  completeness, target access, provider validation. "Stored" never claims the credential
  works.
- `receipt_id` binds the receipt to its inputs (configuration version, item versions,
  account), so an owner handoff can be resumed and a stale receipt detected; it holds no
  value. `--save <file>` writes the receipt (names and IDs only) for an agent to resume
  after a session expires.
- Read-only: `opv ready` never tidies; a pending tidy is a finding with `effect:
  writes_1password` and its own command.

## 5. Order

#80 first (the account model), then #79 and #81 in parallel (both consume it), then #77 and
#78 build their setup and adoption flows on the receipt, and #76 packages the whole journey.
