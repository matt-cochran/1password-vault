# Owner value ingestion: matched sets and in-memory producers (#262, #253)

Status: **Revised after DESIGN-FMECA vet** ([owner-value-ingestion-fmeca.md](owner-value-ingestion-fmeca.md),
verdict "not ready as written, ready with changes for a smaller first slice"). Every required change
of the vet is applied here, its scope cut is taken, and its new decisions are D10-D13 (§8). Draft
for 0.18.0, 2026-11-04, cut from `dev` at opv 0.17.2 (`7cc0b6dd`). No code is changed by this
document.

Evidence convention: `file:line` points at the 0.17.2 tree; infra paths are in
`/home/mc/working/infra-wt-jz` (Journeeze, rev `6b783b8b`) and `/home/mc/working/infra-wt-wave2`
(Workspace Admin, rev `434101cd`). Claims marked **(inferred)** are about behaviour opv does not own
(the `op` CLI, the 1Password service, the kernel); §11 lists them.

## 1. Summary

One new person-only command, `opv provision <SET> --env <ENV>`, fills a **set**: declared keys
whose values must be made together, agree with each other, and land in 1Password in one write. A
set is declared in the committed contract, value-free, and may only span **one 1Password item**
(one access boundary), because 1Password has no cross-item transaction (§4.6). A key is
provisioned because it is a set member; there is no new `source` value.

Each member's value comes from:
- `generate`: opv's CSPRNG with the existing `opv generate` recipes (`hex_bytes`/`base64_bytes`);
- `producer`: a program the contract names (and pins by `sha256`), spawned by opv as a streaming,
  single-attempt runner effect speaking `opv.produce/1` (request on stdin, notices and one result
  on stdout; stderr never shown); this is #253's OAuth consent helper and #262's Journeeze site
  get-or-create;
- `template` (Slice B): a JSON document built from members and from producer outputs that are
  never stored (#262's bundle with its `siteId`s).

Values are made in memory, checked against every destination rule, and written in one `op item
edit` through the one shared, now version-checked writer `import::write_item` (D10).

**One mechanism covers both issues.** #253 is a producer set; #262 is generators plus a producer
plus a template over one item. They share refusals, plan, write and receipt. Delivery is sliced
(D11): **S0** (the `opv set` identity fix, standalone), **Slice A** (#253 and the shared core,
0.18.0), **Slice B** (#262's templates and `--fill-missing`, 0.18.x).

## 2. The problems

### 2.1 #262: a matched set cannot be provisioned atomically

Zonetico's staging release (infra run 40770821491) needs nine fleet fields that must be made once
and agree (`fly/shared-host/fleet/secrets.toml`; owner script
`fly/shared-host/zonetico_journeeze_staging.py:1-40`, `:91-107`):

| Field | Product | How it is made today |
|---|---|---|
| `JOURNEEZE_{PLATFORM,AGENCY,OWNER}_IDENTITY_SECRET` | `zonetico` | generated in memory, 32 bytes lowercase hex (`regex = "[0-9a-f]{64}"`) |
| `JOURNEEZE_SITES_GATEWAY_KEY` | `zonetico` | generated, 32 bytes hex |
| `JOURNEEZE_USER_HASH_KEY` | `zonetico` | generated, 32 bytes hex, `immutable = true` |
| `JOURNEEZE_{PLATFORM,AGENCY,OWNER}_SITE_KEY` | `zonetico` | **issued by Journeeze** (site get-or-create in the staging container), `pk_[A-Za-z0-9_]{1,61}`, `kind = "secret"` |
| `JOURNEEZE_SITE_SECRETS` | `journeeze` | `{"version":1,"sites":[{"siteId","identitySecret","gatewaySecret"}…]}` built from the three site records (`:378-384`); `siteId` is issued by Journeeze and stored only inside the bundle |

`journeeze` and `zonetico` already share `boundary = "fleet"` (`secrets.toml:246-247`), so all nine
fields are in one item and no restructuring is needed. The script works but bypasses opv: it
re-implements owner refusals, the whole-item edit (`fleet_migrate.write_item`), the read-back and
the receipt. The gap was found only by release-time `opv sync`.

### 2.2 #253: a person-owned producer cannot hand a value to opv

The Workspace Admin connector (`workspace/admin/connect.py`) obtains a refresh token in memory after
PKCE consent through a loopback `HTTPServer` and `webbrowser.open` (`:103-110`). The contract
(`workspace/admin/secrets.toml`) puts `WORKSPACE_ADMIN_CLIENT_ID`, `_CLIENT_SECRET` and
`_REFRESH_TOKEN` in product `workspace-admin` (boundary `workspace-admin`), all `kind = "secret"`,
environment `prod-workspace` with `tier = "production"`, `confirm_env = true`. The connector
refuses before consent unless `opv schema` lists exactly one known ingestion capability
(`connect.py:118-134`); none exists (`INGEST_ADAPTERS = {}`, `:37`; `src/schema.rs:520` lists only
`supplied_values/1`). Every current channel needs a terminal, a file, or a never-stored pipe.

### 2.3 What exists today

| Capability | Where | Relevance |
|---|---|---|
| `opv set` | `src/app/set.rs:41-94`: agent refusal `:57`, TTY `:58-63`, rules `:75-84`, write `:85-91` | one typed value; **no identity check** (no `require_person*` in the file; compare `generate.rs:135`): a terminal with `OP_SERVICE_ACCOUNT_TOKEN` exported writes as the service account (D9, fixed in S0) |
| `opv set --from-file` | `set.rs:105-166` | needs a value file |
| `opv generate` (`apply --generate`) | `generate.rs:60-85` recipe, `:98-109` CSPRNG, `:124-178` run; refuses a filled field `:137-145` | the generator reused for `generate` members |
| `opv import` | `import.rs:330-379`; production `--confirm` `:238-241` | files or readable targets |
| `opv_import_local` (MCP) | `mcp.rs:385-402`, `import_local.rs:1-7` | precedent: assistant writes only to `local` tier |
| `sync --supply-stdin` / `opv.supply/1` | `docs/design/deliver-only.md` §3; `deliver_only.rs:205-262` reads to EOF then parses | never stores; only its admission helpers (duplicate-name visitor, value rules, zeroizing buffers) carry over, not its reader |
| The item writer | `import.rs:384-416` `write_values`, `:447-528` `write_item`: one fresh read `:456`, whole-item template, old value kept in `opv · kept` `:461-475`, one `op item edit` `:503`, read-back | **no version check** (vet §0, Proven); D10 adds it |
| `op item edit` | `onepassword_tidy.rs:373-411`: whole item JSON on stdin, argv holds ids only | the only write path |
| Tidy's check | `tidy.rs:635-690`: stamp before, echoed version (`:658-662`) must be `+1` | the check D10 moves into the writer |
| Identity | `host.rs:139-175` (agent markers, presentation only `:85-95`); `tidy.rs:117-132`, `:157-185` | reused |
| Session/token variable refusal | `mcp.rs:530` `credential_in_environment` (FR-61) | reused for production (D6); moved to `host.rs` |
| Child env | `runner.rs:966-975` `isolate`, `:1799-1806` `strip_session_vars` | both **exempt `program == "op"`** (vet F6); the produce spawn clears unconditionally |
| Runner attempts | `runner.rs:1580-1712` `wait_attempt` returns stdout after exit **and** EOF; `:2239-2246` kills the direct child only; `read` retries | cannot carry a live consent flow; Slice A adds a dedicated streaming attempt (§5.2) |
| `Observed` seal | `tests/observed_seal.rs:79-96` asserts the only caller is exactly `src/runner.rs` | the produce effect lives in `runner.rs` |
| Hardening | `hardening.rs:75` `PR_SET_DUMPABLE 0` (reset by `execve` for children); no `pre_exec` anywhere | producer gets a hard `RLIMIT_CORE = 0` |
| URL opener | `src/app/open.rs:30` `opener(env)`: WSL `rundll32.exe`, desktop `xdg-open`, none over SSH/CI/headless | opv opens the consent URL |
| Console prompts | `setup_runtime.rs:659` `confirm_on`, `:676` `choose_on` | the typed-back confirmation reuses this line reader; `masked.rs:84` has no visible mode |
| Run budget | `runner.rs:328` `DEFAULT_RUN_TIMEOUT = 1800 s` | producer timeout capped at 15 min and checked before consent |
| Boundaries | `model.rs:734-777`; FR-57 | the one-item rule |

Architecture guards: FR-37 `core_modules_name_no_provider` (`src/app/mod.rs:2313`; scans
`src/app`, `src/domain`, `src/config/` and `config.rs`, `config_store.rs`, `config_edit.rs`;
`_tests.rs` exempt) and FR-12 `use_cases_name_no_target_adapter` (`:2128`; scans `src/app` and
`src/domain` **including** test files, only `init.rs` and `characterization_tests.rs` exempt); the
`Observed` seal (exactly `src/runner.rs`); the error catalog's registration tests
(`error-catalog.md` §11, §13.4).

## 3. The contract (committed, value-free)

### 3.1 Declarations

Sets and producers live in the contract (D2), so `ready` knows them. Members are `product/KEY`
names of existing declared keys; no key attribute changes.

**#253, Slice A** (keys as already declared in `workspace/admin/secrets.toml`):

```toml
[producers.workspace-consent]
command = ["python3", "workspace/admin/connect.py", "--opv-produce"]  # argv; no shell; no values
sha256  = "9c1d…64 hex…"          # of workspace/admin/connect.py, the project file in command
outputs = ["refresh_token"]
inputs  = { client_id = "workspace-admin/WORKSPACE_ADMIN_CLIENT_ID",
            client_secret = "workspace-admin/WORKSPACE_ADMIN_CLIENT_SECRET" }   # D5-B
open_url_hosts = ["accounts.google.com"]
timeout = "10m"                    # at most 15m

[sets.workspace-admin-grant]
environments = ["prod-workspace"]
members = { "workspace-admin/WORKSPACE_ADMIN_REFRESH_TOKEN" = { producer = "workspace-consent", output = "refresh_token" } }
```

**#262, Slice B** (keys as already declared in `fly/shared-host/fleet/secrets.toml`):

```toml
[producers.journeeze-sites]        # site get-or-create in the staging Journeeze container
command = ["python3", "fly/shared-host/journeeze_sites_produce.py"]
sha256  = "…"
outputs = ["platform_site_id", "platform_site_key", "agency_site_id", "agency_site_key",
           "owner_site_id", "owner_site_key"]
timeout = "5m"

[sets.journeeze-sites]
environments = ["staging"]

[sets.journeeze-sites.members]
"zonetico/JOURNEEZE_PLATFORM_IDENTITY_SECRET" = { generate = { hex_bytes = 32 } }
"zonetico/JOURNEEZE_AGENCY_IDENTITY_SECRET"   = { generate = { hex_bytes = 32 } }
"zonetico/JOURNEEZE_OWNER_IDENTITY_SECRET"    = { generate = { hex_bytes = 32 } }
"zonetico/JOURNEEZE_SITES_GATEWAY_KEY"        = { generate = { hex_bytes = 32 } }
"zonetico/JOURNEEZE_USER_HASH_KEY"            = { generate = { hex_bytes = 32 } }
"zonetico/JOURNEEZE_PLATFORM_SITE_KEY" = { producer = "journeeze-sites", output = "platform_site_key" }
"zonetico/JOURNEEZE_AGENCY_SITE_KEY"   = { producer = "journeeze-sites", output = "agency_site_key" }
"zonetico/JOURNEEZE_OWNER_SITE_KEY"    = { producer = "journeeze-sites", output = "owner_site_key" }

[sets.journeeze-sites.members."journeeze/JOURNEEZE_SITE_SECRETS".template]
version = 1
sites = [
  { siteId = "${journeeze-sites.platform_site_id}", identitySecret = "${zonetico/JOURNEEZE_PLATFORM_IDENTITY_SECRET}", gatewaySecret = "${zonetico/JOURNEEZE_SITES_GATEWAY_KEY}" },
  { siteId = "${journeeze-sites.agency_site_id}",   identitySecret = "${zonetico/JOURNEEZE_AGENCY_IDENTITY_SECRET}",   gatewaySecret = "${zonetico/JOURNEEZE_SITES_GATEWAY_KEY}" },
  { siteId = "${journeeze-sites.owner_site_id}",    identitySecret = "${zonetico/JOURNEEZE_OWNER_IDENTITY_SECRET}",    gatewaySecret = "${zonetico/JOURNEEZE_SITES_GATEWAY_KEY}" },
]
```

The `*_site_id` outputs are **intermediates**: held as `SecretValue` for the run, used only in the
template, never stored as keys. The site specification the producer sends to Journeeze is its own
non-secret code (as the owner script does today over `flyctl`'s stdin); it receives no inputs.
Allumata's append to the same bundle (infra#1430) is out of scope (D13).

Vendor and provider words appear only in contracts and docs, never in `src/app`, `src/domain` or
`src/config` code (FR-37, FR-12).

### 3.2 Load rules (`config_invalid`)

| Rule | Why |
|---|---|
| every member names a declared key wanted in each of the set's `environments` (not `except`ed) | no half-wanted set |
| all members of a set resolve to **one boundary** in each listed environment | §4.6, D1 |
| a key is a member of at most one set | one owner per field; a key in two sets (infra#1430) needs its own design (D13) |
| a member is not `personal`, not `from`, not `source = "infrastructure"` | provisioned values are team values stored in 1Password |
| `generate = "rules"` only on a key whose rules give a recipe (`generate::recipe`); `generate = { hex_bytes = N }` or `{ base64_bytes = N }`, `N` in 16..=1024; the made value is checked against the key's rules at run time (§5.4) | closed, CSPRNG-only generators; no token generator |
| `producer` names a declared `[producers.X]`; `output` is in its `outputs`; each output is used by a member, a template, or both (no "exactly once" rule) | intermediates are allowed |
| `template` (Slice B): a TOML table/array/scalar tree; a string leaf is a literal without `${`, or exactly `"${product/KEY}"` (a member of the same set) or `"${producer.output}"` (an output of a producer of the same set); no partial interpolation; no cycles; the template member is `kind = "secret"` | escaping is the JSON writer's job, never string splicing (§5.3) |
| `[producers.X].command`: non-empty array of strings; `command[0]`'s basename not in {`op`, `op.exe`, `opv`, `opv.exe`}; no element matches the scrubber's secret patterns | SR-7; the producer never gets `op`'s environment exemption (vet F6); a token pasted into argv is caught |
| `sha256` is required when any `command` element is a path to a file inside the project; it must equal the file's current SHA-256, else `producer_changed` | an edited producer cannot silently receive production inputs (vet F17) |
| `inputs` name keys in the set's own boundary and the same environment | no cross-environment or cross-boundary reads |
| `open_url_hosts` are host names; `timeout` at most 15 min | vet F10 |

The contract's new tables are unknown to opv 0.17, which refuses them at load (FR-60); every pin
moves to 0.18 before a contract adds them (deliver-only S13). Because no enum value is added, the
rollback is deleting the tables.

## 4. Command surface and semantics

### 4.1 CLI

```
opv provision <SET> --env <ENV> [--dry-run] [--json] [--replace]      # Slice A
                                                    [--fill-missing]  # Slice B
```

- `--dry-run`: the plan (§4.3) and the set's state; reads 1Password, runs no producer, makes no
  value, writes nothing; allowed for an assistant and in CI (it is a read). An assistant uses
  `opv provision … --dry-run --json`; there is no MCP tool (deferred).
- `--replace`: re-make the whole set (explicit rotation and re-consent, D8); old values are kept in
  `opv · kept` by the writer (`import.rs:461-475`); refused when a member is `immutable`.
- `--fill-missing` (Slice B, D7): recover a partial set (§4.7).
- No `--yes`, `--confirm` or `--expect-plan` (deferred): the confirmation is typed at the prompt.

`opv schema` adds the capability **`owner_produce/1`** (with `opv.produce/1` and `opv.provision/1`
in its schema map), which `connect.py`'s gate (`:118-134`) can list.

### 4.2 Order of operations

Nothing is written before step 11; nothing reaches a producer before step 8.

1. **Load** the contract (§3.2), including every producer's `sha256`.
2. **Resolve** `<SET>`, `--env` in the set's environments.
3. **Who is running** (§6), skipped by `--dry-run`: agent marker ⇒ `PersonOnly`; CI ⇒
   `NeedsTerminal{Ci}`; not a TTY ⇒ `NeedsTerminal{NoTty}`; a producer member on **native Windows**
   ⇒ `Unsupported{producer on Windows}`, Next: run it from WSL (D12).
4. **Identity** (`require_person_on`): service account, Connect, deploy credentials ⇒
   `NeedsOwnSession`. Production tier or `confirm_env`: also refuse when
   `credential_in_environment` finds `OP_SESSION_*`, `OP_SERVICE_ACCOUNT_TOKEN` or `OP_CONNECT_*`
   (D6).
5. **Read** the set's item fresh: stamp `S0`. An item `unprovable()` refuses (a whole-item edit
   could drop a field).
6. **Classify** (§4.5). `complete` without `--replace` ⇒ `unchanged`, exit 0, no producer, no
   generation. `partial` (Slice A: always; Slice B: without `--fill-missing`) or `inconsistent`
   without `--replace` ⇒ refuse.
7. **Plan, budget, confirm** (§4.3, §4.4). The plan shows each producer's command and `sha256`.
   **Budget check before consent:** the sum of the producers' `timeout`s plus the commit reserve
   (the runner's own read 60 s + write 120 s + read 60 s constants, NR-4) must fit the remaining
   run budget, else refuse naming `--timeout` (vet F10). Then the typed confirmation.
8. **Produce** (§5.2), once per producer, in declared order.
9. **Generate** (§5.1); Slice B: **render templates** (§5.3).
10. **Validate** (§5.4, §5.5): all members against their rules; template round-trip; distinctness
    of producer-made members across environments. Any failure drops every value.
11. **Commit** through `import::write_item` with its version check (§4.6).
12. **Receipt** (§7).

### 4.3 The plan (also `--dry-run`)

Names, makers, destinations, hashes and edges only:

```
opv provision workspace-admin-grant --env prod-workspace
  item    workspace-admin · prod-workspace values   (vault …, version 7)
  state   absent (0 of 1 members set)
  make    workspace-admin/WORKSPACE_ADMIN_REFRESH_TOKEN   producer workspace-consent → refresh_token
  producer workspace-consent: python3 workspace/admin/connect.py --opv-produce
           sha256 9c1d…(64 hex)   timeout 10m   inputs WORKSPACE_ADMIN_CLIENT_ID, WORKSPACE_ADMIN_CLIENT_SECRET
           consent opens in: rundll32.exe (WSL)
  budget  10m producer + 4m commit of 30m left
  compare no other environment declared
  write   one edit of one item; nothing else in the item changes
```

### 4.4 Confirmation

After the plan: `Type the environment name to provision <SET> in it:`. Read with the setup
console's line reader (a new `type_back_on` next to `confirm_on`, `setup_runtime.rs:659`). The
answer must equal `--env`; otherwise `ConfirmMismatch`, nothing run. Empty or Ctrl-C ⇒ `Declined`
(exit 0). Confirmation is before any producer runs, so a person agrees to the write before consent.

### 4.5 Set states (also `ready`)

| State | Condition |
|---|---|
| `absent` | no member field holds a value |
| `complete` | every member holds a value passing its rules; Slice B: every template member parses as JSON of the template's shape, its member leaves **equal** the stored members, its intermediate leaves (`siteId`) are non-empty strings of at most 256 bytes (shape, not equality), its literals equal the template's |
| `partial` | some but not all members hold a value |
| `inconsistent` | all members hold a value, but one fails its rules or a template does not match |

Equality is the documented SR-1 exception (#92), never a value, length or digest.

### 4.6 What 1Password guarantees, and the one checked writer

**Can (inferred, relied on since FR-43):** one `op item edit` with the whole item JSON on stdin is
one item revision: the item is at its previous version or the next one with every template field
(`onepassword_tidy.rs:408-409`). Item history keeps prior versions, restorable by a person in the
app.

**Cannot:**
- **no compare-and-swap** (Proven for flags: `op` 2.40.0 `item edit --help` lists no version flag;
  whether the service enforces the template's `version` field is unknown, §11): a concurrent edit
  between opv's last read and its write is overwritten, kept only in history;
- **no cross-item transaction** (inferred);
- **no restore-version command** in `op` (inferred).

**Hence: a set fills exactly one item** (§3.2, D1). The real sets already do (§2.1, §2.2).

**The writer (D10).** `import::write_item` gains the tidy's check, so `set`, `import`, `generate`
and `provision` share one writer:

1. Its fresh read gives `S1`. The caller may pass an expected stamp `S0`. If `S1 ≠ S0`: when every
   member field (presence, and for `--fill-missing` the present values) is unchanged, re-plan on
   `S1` and continue, so a person who just completed a consent does not repeat it; otherwise
   `ChangedBeforeWrite`, nothing written. (`set`/`import`/`generate` pass no `S0`, so only steps 3-5
   change for them.)
2. One `op item edit` with the whole-item template (existing `onepassword_tidy::apply`/`write`).
3. The **echoed** version (as `tidy.rs:658-662`) must be `S1.version + 1`. If not, the result is
   still `written` (members are verified next) with a note: "an edit made just before opv's may
   have been replaced; restore it from the item's history" (`concurrent_edit` in the receipt). It
   is not an error exit inviting a re-run (vet F11).
4. A **final fresh read**: `lost()` and every written field equals its in-memory value, else
   `ReadBackMissing`. The receipt says `verified at version N`.
5. **Unknown outcome** (timeout, kill, lost reply): the final fresh read decides. Version `S1` and
   members unchanged ⇒ not written, safe to re-run. Members equal the in-memory values ⇒ success.
   Otherwise exit 9 `WriteOutcomeUnknown` naming the found set state (`absent`, `complete` or the
   prior one; an atomic edit makes no new partial).

**Producer outputs after a failed commit.** A fixed, neutral Do (vet F19): "the producer's outputs
were not stored; what it created at its issuer still exists". The producer's own documentation
says what to do (revoke a grant; nothing for an idempotent get-or-create).

**Residual (accepted, Low):** a later whole-item write built from a pre-provision read (any writer
on the shared fleet item) can erase the set after its receipt. opv cannot prevent it without CAS;
`ready` detects it and item history recovers it.

### 4.7 `--fill-missing` (Slice B, D7)

Keeps every present member and never rotates it. For each missing member, in this order:
1. a member that a present template holds (by its template path) is filled **from that leaf**, so
   it stays consistent with the bundle;
2. a producer member: the producer runs (only if one of its outputs is missing); its intermediates
   must equal the stored template's leaves (`siteId`s), else `inconsistent`;
3. a generated member not held by any present template is generated.

Then templates are rendered from stored plus new values and checked to round-trip. A missing
template is rendered; a present template that would change is refused (`--replace` is the way).

## 5. Making the values

### 5.1 Generators

Only `generate::recipe`/`generate::make` (`generate.rs:60-109`): `getrandom`, `hex_bytes` or
`base64_bytes`, 16..=1024. Each value is a `SecretValue`, registered with the scrubber as made.

### 5.2 Producers: the `opv.produce/1` effect

A producer is spawned by a new write-class runner effect **inside `src/runner.rs`**
(`CommandRunner::produce(&ProduceCall, on_notice: &mut dyn FnMut(Notice)) -> Result<Produced,
Error>`), so `Observed` is built only there (seal unchanged), and the budget, the current-child
signal forwarding (NR-12) and the verbose line apply. `FakeRunner`/`FakeOp` implement it from a
scripted reply.

**Spawn (Unix).**
- **One attempt**, never retried (a retry could ask for consent twice).
- argv: exactly `command` (SR-7). cwd: the project directory.
- environment: **cleared unconditionally**, then only `host::ENV_BASICS` (`PATH`, `HOME`, `USER`,
  `LOGNAME`, `SHELL`, `TERM`, …). No `BROWSER`, `DISPLAY` or interop variables (opv opens URLs), no
  `OP_SESSION_*`, tokens or provider credentials. No `op` exemption: `command[0]` may not be `op`
  (§3.2).
- stdin, stdout, stderr: pipes owned by opv; the producer never gets the terminal.
- `pre_exec` (async-signal-safe only): `setrlimit(RLIMIT_CORE, {0, 0})` (hard and soft), and
  `process_group(0)`, so the producer and anything it spawns are one group.
- Native Windows: refused before spawn (D12).

**Request** (stdin, one line, then closed; the buffer is `Zeroizing`):

```json
{"schema":"opv.produce/1","kind":"request","env":"prod-workspace","set":"workspace-admin-grant",
 "outputs":["refresh_token"],"nonce":"n-…26 base32…","inputs":{"client_id":"…","client_secret":"…"}}
```

**Response** (stdout): a **line-streaming** reader (bounded: 1 MiB total, 64 KiB per line,
`Zeroizing` buffers) hands each complete line to the parser as it arrives:
- `{"schema":"opv.produce/1","kind":"notice","open_url":"https://…"}`: `https`, host in
  `open_url_hosts`, at most 2048 bytes, no userinfo, else refused. opv **opens it with
  `open::opener`** (`src/app/open.rs:30`; WSL `rundll32.exe`, desktop `xdg-open`) and prints the
  fixed line "opening the consent page in your browser: <url>" (shown so a headless person can copy
  it; OAuth authorization URLs carry only public parameters). With no opener (SSH, headless) it is
  printed only.
- `{"schema":"opv.produce/1","kind":"notice","waiting":true}`: fixed line "waiting for the producer".
- exactly one terminal line, last: a **result**
  `{"schema":"opv.produce/1","kind":"result","env":"…","nonce":"…","outputs":{"refresh_token":"…"}}`
  or an **error** `{"schema":"opv.produce/1","kind":"error","code":"<[a-z_]{1,40}>"}`, rendered
  only as `producer reported <code>` (a closed vocabulary; no free text).

**Ending.** The effect ends at the terminal line **plus the child's exit**, never waiting for
stdout EOF (a browser launcher or loopback server holding the pipe cannot turn a success into a
timeout, vet F2). After the terminal line opv waits up to 5 s for the child's exit status, then
`killpg(SIGTERM)`, 5 s, `killpg(SIGKILL)`. The same group kill runs on the producer's `timeout`, on
the run budget, and on opv's own SIGINT/SIGTERM/SIGHUP (forwarded to the group). A result counts
only if the child then exits 0; a non-zero exit after a result discards it (`ProducerFailed`).

**Admission:**

| Check | Refusal |
|---|---|
| exit 0 after the result, within `timeout` | `ProducerFailed{producer, exit}` / `ProducerFailed{…, timeout}` |
| each line one JSON object, `deny_unknown_fields`, `schema = opv.produce/1` | `InputInvalid{kind: Produce, rule}` by line number, never serde's text |
| exactly one terminal line, last | `NoResult` / `ResultNotLast` |
| `env` = `--env`, `nonce` = this run's | `WrongEnvironment` / `NonceMismatch` |
| `outputs` keys = the declared outputs the set uses, each once (the supply parser's duplicate-name visitor) | `Undeclared` (by position) / `Missing{names}` / `Duplicate` |
| values non-empty JSON strings, no NUL, at most 64 KiB | `Empty` / `NotAString` / `TooLarge` |

Each value is registered with the scrubber as it is parsed. Only the admission helpers of
`deliver_only.rs` are reused (made `pub(crate)`); its read-to-EOF reader is not.

**stderr is never shown.** It is drained into a bounded zeroizing buffer (so the producer never
blocks on a full pipe) and wiped unread, on success and on failure. `--verbose` shows only its byte
count and stdout's line count. A producer explains failure only with its closed `error` code
(#253: "producer diagnostics cannot leak response bodies or credentials").

### 5.3 Templates (Slice B)

A small JSON writer renders the template into a `Zeroizing<Vec<u8>>`: declared order, literals as
given, each `${…}` leaf written as a JSON string escaped straight from its `SecretValue` (member or
intermediate); no `serde_json::Value` holds a secret. Output is compact, matching the owner
script's `separators=(',',':')` (`:384`). The result is parsed back and each reference leaf
compared to its source (round-trip), then checked against the template key's rules.

### 5.4 Validation (step 10)

Collected, so one refusal names every failing member (NR-17): `rules::check` (or `check_verbatim`
for a `file` key) with every rule counted; placeholders refused; secret members at least
`SECRET_MIN` (8) bytes; template round-trip (Slice B). Failing members are named with the rule only.

### 5.5 Production and staging stay distinct

- The environment is one flag, echoed by the producer with the run's nonce, and typed back.
- `inputs` and template references resolve only within this run and this environment's item.
- **Producer-made members only** (vet C21): opv reads the same fields in every other environment of
  the set that the person can read and refuses `SameAcrossEnvironments{member, env}` on equality
  (one OAuth client misused for two environments). Generated members are independent by
  construction and are not compared. An unreadable environment is listed as "not compared".

### 5.6 Other writers and set members

`opv set`, `set --from-file`, `opv import` and `opv apply --generate` refuse a set member with
`Guard::SetMember{set}`, Next `opv provision <set> --env <env> --replace`.

## 6. Refusal rules

| Situation | Where | Cause | Real control or friction |
|---|---|---|---|
| MCP | no write tool; no plan tool in 0.18 | — | structural |
| CI | step 3 | `NeedsTerminal{Ci}` | friction (CI has only a service account, below) |
| agent marker | step 3 | `PersonOnly` with the exact command | friction: markers are the caller's (`host.rs:85-95`; catalog §9.1) |
| not a TTY | step 3 | `NeedsTerminal{NoTty}` | friction |
| producer on native Windows | step 3 | `Unsupported` | platform (D12) |
| service account, Connect, deploy credentials | step 4 | `NeedsOwnSession` | **real**: CI never writes (SR-5) |
| production tier / `confirm_env` with session or token variables | step 4 | `NeedsOwnSession` | narrows: the write uses the app's authorization or a sign-in opv prompts for (D6) |
| producer file changed | step 1 | `ProducerChanged` | review gate at contract change |
| budget too small | step 7 | `ProvisionRefused{BudgetTooSmall}` naming `--timeout` | before consent |
| wrong typed environment | step 7 | `ConfirmMismatch` | friction |
| vault access | 1Password | `MissingRight` | **real**: the only permission system |

The terminal, marker and confirmation rules prevent unattended and accidental writes; against a
same-user process they are not a boundary (catalog §9.1), and the docs say so.

## 7. Receipt (value-free)

```json
{"schema":"opv.provision/1","set":"workspace-admin-grant","env":"prod-workspace",
 "mode":"absent","result":"written","concurrent_edit":false,
 "item":{"vault_id":"…","item_id":"…","version_before":7,"version_after":8,"verified_at":8},
 "members":[{"key":"workspace-admin/WORKSPACE_ADMIN_REFRESH_TOKEN","made_by":"producer","state":"set"}],
 "producers":[{"name":"workspace-consent","sha256":"9c1d…","exit":0}],
 "compared_environments":[],"not_compared":[],"next":"opv ready prod-workspace"}
```

`result`: `written`, `unchanged`, `declined`, or a refusal code. No value, length, digest or prefix.
`version_after` is the revision plan-bound delivery builds on (#253). No marker field is written
into the item (deferred): `ready` computes each set's state (§4.5) from values and reports
`partial`/`inconsistent`/`absent` as a `keys_blocking` finding naming `opv provision <set> --env
<env>` (with `--fill-missing` in Slice B), so #262's detection moves from `sync` to `ready`.

## 8. Owner decisions

**D1. Can a set span items?** 1Password writes one item atomically, never several together.
A: one item per set, refused at load; other products read with `from`. B: several items with
compensating writes, which can leave a partial set opv can only report. **Recommend A**; both real
sets already fit one item (`fleet`, `workspace-admin`).

**D2. Where is a set declared?** A: in the contract (`ready` sees it). B: a separate file (only
`sync` would notice a gap). **Recommend A**.

**D3. Command shape.** A: `opv provision` with `--dry-run`; `--expect-plan` and an MCP plan tool
deferred (an assistant uses `--dry-run --json`). B: `propose` + `apply <plan_id>`, a second command
with no added check. **Recommend A** (as cut by the vet).

**D4. Producer protocol.** A: new `opv.produce/1`: nonce, streaming notices, one result or a closed
error code; opv opens URLs; capability `owner_produce/1`. B: reuse `opv.supply/1` (means "never
stored", no nonce, no notices). **Recommend A**.

**D5. Producer inputs from 1Password.** The real client id and secret are `kind = "secret"`. A:
config keys only (the connector cannot run). B: declared keys of the same item and environment,
secrets included, over stdin, with the producer pinned by `sha256`. C: none. **Recommend B** (the
evidence requires it).

**D6. Production writes.** A: typed environment plus FR-61's refusal of session/token variables for
production tier or `confirm_env`; in practice a WSL person who exported a session opens a fresh
shell. B: typed environment only. **Recommend A**.

**D7. Partial sets.** A: `--fill-missing` (§4.7) in Slice B; Slice A refuses `partial`. B: only
`--replace`, refused for the `immutable` user-hash key, so a Journeeze partial set would be
unrecoverable. **Recommend A, in Slice B**.

**D8. `--replace` in 0.18.0.** A: yes, whole set, old values in `opv · kept`, refused for
`immutable` members; needed to re-consent after a revoked grant. B: defer. **Recommend A**.

**D9. `opv set` identity check.** A: add `require_person` to `set` and `set --from-file`, shipped
alone as 0.17.3 (S0). B: leave the service-account write path. **Recommend A, standalone**.

**D10. One checked writer.** Situation: `import::write_item` serves `set`, `import` and `generate`
with no version check; the first draft added a second writer for provisioning. A: add the
expected-stamp check, the echoed-version check and a final fresh read to `import::write_item`; all
four commands then detect concurrent edits (`set`/`import`/`generate` gain a `concurrent_edit` note
and, when they pass a stamp, a `ChangedBeforeWrite` refusal). B: a separate `provision_commit`
(two writers that will diverge). **Recommend A**.

**D11. Slicing.** A: S0 in 0.17.3; Slice A (#253 + core) in 0.18.0; Slice B (#262 templates +
`--fill-missing`) in 0.18.x. B: one release with both. **Recommend A**: #253 is unblocked first with
no speculative surface, and #262 keeps working through the owner script meanwhile.

**D12. Producers on native Windows.** opv has no `pre_exec`, group kill or core limit there. A:
refuse producer members on native Windows in 0.18 (Next: WSL); generators work everywhere; Job
Objects later. B: support now with weaker guarantees. **Recommend A**.

**D13. Allumata's append to the shared bundle (infra#1430).** It would make
`JOURNEEZE_SITE_SECRETS` a member of two sets. A: out of 0.18; the owner script keeps that path.
B: design multi-set templates now. **Recommend A**.

## 9. Self-vet

### 9.1 Poka-yoke

| Mistake | Prevented by |
|---|---|
| a set spans two items | load rule |
| a member written alone (`set`) and mismatching its bundle | `SetMember` refusal; `ready` reports `inconsistent` |
| hand-built JSON with bad escaping | whole-leaf references; the writer escapes; round-trip |
| silent rotation | `complete` ⇒ `unchanged`; rotation only with `--replace`; `immutable` refused |
| staging values into prod | typed environment; env echo + nonce; same-environment inputs; producer distinctness |
| replayed producer output | nonce; no file or opv-stdin route |
| edited producer receives prod secrets | `sha256` pin at load, shown in the plan |
| producer is `op` and inherits sessions | `command[0]` rule; unconditional env clear |
| consent, then refusal for time | budget check and 15-min cap before consent |
| consent, then refusal for an unrelated edit | re-plan when member fields are unchanged |
| consent succeeded but the pipe is held open | ends at result + exit; group kill |
| partial write | one atomic item edit; final read; unknown outcome reconciled |

### 9.2 Security

| Channel | Status |
|---|---|
| argv | no value anywhere: `op` gets the item on stdin; the producer's argv is committed text checked against secret patterns |
| environment | producer env cleared to basics; inputs only over stdin |
| files | opv writes none; no file route for sets |
| terminal | no value printed; the producer has no terminal; only fixed sentences and an allow-listed `https` URL |
| producer text | **never shown**: stderr wiped unread; failures only as a closed code |
| logs / `--verbose` | byte and line counts only for the producer; existing scrubbed `op` lines |
| core dumps | opv is non-dumpable (`hardening.rs:75`); the producer gets hard `RLIMIT_CORE = 0` (its `PR_SET_DUMPABLE` is reset by `execve`). Limit: a pipe `core_pattern` handler is not bound by `RLIMIT_CORE` at kernel level (systemd-coredump honours it; apport inferred). The producer held the value before opv did, so opv adds no exposure |
| memory | `SecretValue`/`Zeroizing` for request, lines, outputs, intermediates and the rendered template |
| replay | nonce; rerun of a complete set is `unchanged` |
| partial writes | one item, atomic edit (inferred), final read |
| concurrent edits | detected and noted, not prevented (no CAS) |
| same-user agent | not a boundary (§6); D6 narrows the exported-session route |
| Windows | producers refused |

### 9.3 Architecture guards

- New code in `src/app/provision.rs`, `src/app/produce_doc.rs`, `src/config/sets.rs`,
  `src/domain/provision.rs` (and Slice B `src/domain/provision_template.rs`) names no provider word
  and no target adapter: FR-12 covers `src/app`/`src/domain` test files too, FR-37 covers
  `src/config/` production code. Vendor words live only in contracts, docs and `tests/` outside
  `src/`.
- The produce attempt and every `Observed` it needs are in `src/runner.rs`;
  `tests/observed_seal.rs` is unchanged (it pins exactly `src/runner.rs`).
- `credential_in_environment` moves from `mcp.rs:530` to `host.rs` (one copy, used by MCP and
  provision).
- New causes: `Guard::ProvisionRefused{set, env, reason}` (`Partial{missing}`,
  `Inconsistent{members}`, `ImmutableMember`, `SameAcrossEnvironments`, `BudgetTooSmall`; Slice B
  `TemplateWouldChange`), `Guard::SetMember{set}`, `ProducerFailed{producer, exit | timeout |
  code}`, `ProducerChanged{producer}`, `InputInvalid{kind: Produce, rule}` with
  `FieldRule::Produce`, `Unsupported{producer on Windows}`. Reused: `ChangedBeforeWrite`,
  `ReadBackMissing`, `WriteOutcomeUnknown`, `NeedsTerminal`, `PersonOnly`, `NeedsOwnSession`,
  `ConfirmMismatch`, `Declined`. Each new variant needs a fixture (`every_variant_renders`), a
  catalog row, the generated usage table, a parsing `Next`, and an e2e cell **or** an `UNREACHABLE`
  entry with its reason (§10.7).
- Registrations: `schema.rs` (`owner_produce/1`, `opv.produce/1`, `opv.provision/1`, `[sets]`,
  `[producers]`), CLI surface tests (`tests/surface_contract.rs`, `tests/one_way.rs`,
  `tests/docs_commands.rs`), agent guidance (`tests/agent_guidance.rs`).

## 10. Test plan

One behavioural assertion per test. Unit tests use `FakeOp` (`racing_edit`, `edit_elsewhere`) and a
scripted `produce` in `FakeRunner`. Runner tests spawn small real producer fixtures under
`#[cfg(test)]`. The success path end to end uses the PTY pattern of `tests/console.rs` →
`console_walkthrough.py` (Unix), because the e2e harness never gives opv a terminal
(`tests/e2e/coverage.rs:84-92`).

### 10.1 Load (Slice A unless marked)
1. members in two boundaries ⇒ `config_invalid`.
2. a key in two sets ⇒ `config_invalid`.
3. `command[0] = "op"` ⇒ `config_invalid`.
4. a producer argv element matching a token pattern ⇒ `config_invalid`.
5. a `sha256` mismatch ⇒ `producer_changed`.
6. a producer `timeout` of 16 min ⇒ `config_invalid`.
7. an input naming another boundary's key ⇒ `config_invalid`.
8. `generate = "rules"` on a key without a byte rule ⇒ `config_invalid`.
9. (B) a template leaf `"x${A}"` ⇒ `config_invalid`.
10. (B) a template reference cycle ⇒ `config_invalid`.
11. (B) the real Journeeze set (§3.1) loads.

### 10.2 Writer (D10, `import_tests.rs`)
12. `racing_edit` on the write ⇒ `concurrent_edit = true` and members verified.
13. a member field changed between `S0` and `S1` ⇒ `ChangedBeforeWrite`, no edit.
14. an unrelated field changed between `S0` and `S1` ⇒ one edit, re-planned.
15. unknown outcome with the edit applied ⇒ success after the final read.
16. unknown outcome with nothing applied ⇒ "not written; safe to re-run".
17. `opv set` still makes exactly one edit on a quiet item.

### 10.3 Use case (`provision_tests.rs`)
18. absent producer set ⇒ the member holds the producer's value after the write.
19. complete set ⇒ no `item edit` call (#262 AT3).
20. complete set ⇒ the producer is not started.
21. partial set (Slice A) ⇒ refused with no `item edit` call (#262 AT2).
22. an `item edit` failure leaves the item at its prior version (#262 AT5).
23. `--replace` keeps the old value in `opv · kept`.
24. `--replace` with an immutable member ⇒ refused before the producer runs.
25. producer value equal to another environment's ⇒ `SameAcrossEnvironments` (#262 AT7).
26. generated members cause no other-environment read.
27. malformed member ⇒ refused, no edit, every failing member named.
28. budget smaller than timeout + reserve ⇒ refused before the producer starts.
29. `opv set` on a set member ⇒ `SetMember`.
30. (S0) `opv set` with a service-account token ⇒ `NeedsOwnSession`.

### 10.4 Refusals
31. agent marker ⇒ `PersonOnly`, no `op` call.
32. `CI=true` ⇒ `NeedsTerminal{Ci}`, no `op` call.
33. non-TTY ⇒ `NeedsTerminal{NoTty}`, prompt not called.
34. service-account identity ⇒ `NeedsOwnSession`.
35. production tier with `OP_SESSION_x` set ⇒ `NeedsOwnSession`.
36. wrong typed environment ⇒ `ConfirmMismatch`, producer not started.
37. `--dry-run` under an agent marker succeeds with no write.
38. native Windows with a producer member ⇒ `Unsupported` (Windows CI).

### 10.5 Produce effect (`runner.rs` tests) and parser (`produce_doc.rs` tests)
39. argv equals the contract's `command`.
40. the environment holds no `OP_SESSION_*`.
41. the environment holds no `OP_SERVICE_ACCOUNT_TOKEN`.
42. the environment holds no `DISPLAY`.
43. the request carries this run's nonce.
44. a notice reaches `on_notice` before the child exits.
45. a producer that forks a sleeper holding stdout ends at result + exit, not at the timeout.
46. after the result the sleeper's process group is gone.
47. a timeout kills the whole process group.
48. SIGINT to opv reaches the producer's group and nothing is written.
49. the producer is spawned once even when it fails.
50. the producer's `RLIMIT_CORE` hard limit is 0 (`/proc/<pid>/limits`).
51. a result with another nonce ⇒ `NonceMismatch`.
52. a result for another environment ⇒ `WrongEnvironment`.
53. an undeclared output name is reported by position.
54. a duplicate output ⇒ `Duplicate`.
55. exit 1 after a valid result ⇒ `ProducerFailed`, nothing written.
56. an `error` line ⇒ `producer reported <code>`.
57. an `error` code outside `[a-z_]{1,40}` ⇒ `InputInvalid`.
58. `open_url` to a host outside the list ⇒ refused and not opened.
59. an allowed `open_url` is passed to the opener (fake `HostEnv`).
60. serde's error text never appears in a refusal.

### 10.6 Custody canaries (`tests/security.rs`)
61. a canary printed to producer stderr in an unknown format, then exit 1, appears in no output.
62. the canary never appears in any process's argv (#262 AT6).
63. the canary never appears on opv's stdout or stderr on success.
64. the canary never appears in the `--json` receipt.
65. no file under the scratch `HOME` or project holds the canary after the run.
66. no snapshot holds the canary.

### 10.7 End to end
67. PTY: a consent-shaped fake producer set in a production-tier environment writes and prints the
    revision.
68. PTY: a refusal (wrong typed environment) snapshot.
69. opv-sim (non-TTY): `--dry-run --json` plan snapshot, and the `NeedsTerminal` refusal.
70. opv-sim: `ready` finding for a partial set.
71. (B) PTY: the Journeeze-shaped nine-field set is `complete` per `ready`.
72. (B) the rendered bundle is byte-identical to the owner script's `build_aggregate` for the same
    inputs.

Variants no e2e cell reaches (e.g. `ProducerFailed{timeout}` outside the PTY run, `Unsupported` on
Linux runners) get `UNREACHABLE` entries in `tests/e2e/coverage.rs`, each with its reason and the
unit test that covers it.

## 11. Inferred behaviour (for re-vet)

1. A whole-item `op item edit` is one revision (relied on since FR-43; never contradicted).
2. Whether the service enforces the piped template's `version` is unknown. Optional owner
   experiment, a write, on a scratch item only: pipe a template with a stale `version`; if refused,
   §4.6's detection becomes prevention.
3. No cross-item atomicity via `op`; no restore-version command.
4. The 1Password app's authorization of writes per terminal session (catalog §9.1).
5. apport's handling of `RLIMIT_CORE` under a pipe `core_pattern`.

## 12. Delivery

Each lane changes at most about 400 lines. Owner type: **Claude agent** (broad reading, global
registrations) or **commodity worker** (file-scoped, this document as the spec). Lanes assume the
recommendations of D1-D13.

### S0 (0.17.3, standalone)

| Id | Lane | Files owned | Prereqs | h | Owner |
|---|---|---|---|---|---|
| S0 | `require_person` in `set` and `set --from-file` (D9); test 30 | `src/app/set.rs`, `src/app/set_tests.rs` | — | 1.5 | commodity worker |

### Slice A (0.18.0: #253 and the shared core)

| Id | Lane | Files owned | Prereqs | h | Owner |
|---|---|---|---|---|---|
| A1 | Contract `[sets]`/`[producers]` (one boundary, `sha256`, timeout cap, `command[0]` rule, inputs) and the set-state classifier; tests 1-8 | `src/config/sets.rs` (new) + tests, hook lines in `src/config.rs`, `src/domain/provision.rs` (new) + tests, `Fleet` fields in `src/domain/model.rs` | — | 3.5 | Claude agent |
| A2 | Causes and catalog rows | `src/cause/mod.rs`, `render.rs`, `codes.rs`, cause fixtures, `docs/design/error-catalog.md` | — | 2.5 | Claude agent |
| A3 | Streaming produce effect in the runner: one attempt, line reader, process group, `pre_exec` core limit, kill/forward, `Observed`; `FakeRunner`/`FakeOp` script; tests 39-50 | `src/runner.rs`, `src/adapters/fake_op.rs` | A2 | 5 | Claude agent |
| A4 | `opv.produce/1` admission parser (notices, result, error code, nonce/env, outputs); tests 51-58, 60 | `src/app/produce_doc.rs` (new) + tests; visibility-only edits in `src/app/deliver_only.rs` | A2 | 3 | commodity worker |
| A5 | Version check in `import::write_item` (D10) and the `SetMember` guard in `import`; tests 12-17 | `src/app/import.rs`, `src/app/import_tests.rs` | A1, A2 | 2.5 | Claude agent |
| A6a | Use case part 1: refusals (Windows, D6 via the moved `credential_in_environment`), read, classify, plan/`--dry-run`, budget check, typed-back confirm; tests 28, 31-38 | `src/app/provision.rs` (new), `src/app/provision_tests.rs` (new), `src/host.rs`, `src/mcp.rs` (move only), `src/app/setup_runtime.rs` (`type_back_on`), `src/app/mod.rs` (module line) | A1, A2 | 3.5 | Claude agent |
| A6b | Use case part 2: produce with the opener, generate, validate, producer distinctness, commit via A5, receipt, `--replace`; tests 18-27 | `src/app/provision.rs`, `src/app/provision_tests.rs` | A3, A4, A5, A6a | 3.5 | Claude agent |
| A7 | Other writers refuse set members (`set`, `generate`); test 29 | `src/app/set.rs`, `src/app/set_tests.rs`, `src/app/generate.rs`, `src/app/generate_tests.rs` | A1, A2, S0 | 1 | commodity worker |
| A8 | CLI `provision`, schema (`owner_produce/1`, `opv.produce/1`, `opv.provision/1`, contract tables), surface/golden tests | `src/main.rs`, `src/schema.rs`, `tests/surface_contract.rs`, `tests/one_way.rs`, `tests/docs_commands.rs`, `tests/agent_guidance.rs` | A6b | 2 | Claude agent |
| A9 | `ready` set state and blocking finding | `src/app/ready.rs`, `src/app/ready_tests.rs` | A1 | 1.5 | commodity worker |
| A10 | PTY e2e (67-68), opv-sim cells (69-70), canaries (61-66), `UNREACHABLE` entries | `tests/console.rs`, `tests/console_walkthrough.py`, `tests/sim/producer.rs` (new), `tests/sim/opv_sim.rs` (dispatch line), `tests/security.rs`, `tests/e2e/coverage.rs`, `tests/e2e/scenarios/provision.rs` (new), snapshots | A8, A9 | 4 | Claude agent |
| A11 | Docs: `docs/provision.md` (producer contract, OAuth consent-output flow, `connect.py --opv-produce` shape), usage, requirements FR-64 and SR-3/SR-5 notes, CHANGELOG, skill text | `docs/provision.md` (new), `docs/usage.md`, `docs/design/requirements.md`, `CHANGELOG.md`, skill files | A8 | 2.5 | Claude agent |

Slice A ≈ 34.5 h. Critical path A2 → A3 → A6b → A8 → A10 ≈ 17 h (A6a runs beside A3). A1, A2 and
S0 start at once; A4, A5, A6a and A9 run in parallel after A1/A2.

### Slice B (0.18.x: #262)

| Id | Lane | Files owned | Prereqs | h | Owner |
|---|---|---|---|---|---|
| B1 | Templates with `${member}` and `${producer.output}` intermediates: load rules, JSON writer, round-trip, shape classification; tests 9-11, 72 | `src/domain/provision_template.rs` (new) + tests, `src/config/sets.rs` (template rules) | Slice A | 4 | commodity worker |
| B2 | Wire templates and `--fill-missing` (§4.7, recovery from bundle leaves) into the use case and `ready` | `src/app/provision.rs`, `src/app/provision_tests.rs`, `src/app/ready.rs`, `src/app/ready_tests.rs`, `src/main.rs` (flag) | B1 | 3 | Claude agent |
| B3 | Journeeze-shaped PTY e2e (71) with a fake site producer; docs section on matched sets | `tests/e2e/scenarios/provision_sets.rs` (new), `tests/sim/producer.rs`, `docs/provision.md` | B2 | 3 | Claude agent |

Slice B ≈ 10 h. Total with S0 ≈ 46 h.

Release gate (project practice): `cargo test`, the e2e suite with `CI=true`, the PTY tests and the
canary scan. Rollback: delete the `[sets]`/`[producers]` tables; written values stay in 1Password.
