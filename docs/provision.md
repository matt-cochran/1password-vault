# Provisioning values together: `opv provision`

Some values cannot be typed one at a time. An OAuth refresh token exists only after a person
consents in a browser, and only the helper that ran the consent ever holds it. A set of signing
keys and a JSON bundle built from them must be made once and agree with each other, or the app
that reads them breaks. From opv 0.18.0 the contract declares such values as a **set**, and a
person runs:

```sh
opv provision <SET> --env <env>
```

opv makes every member in memory (its own generator, a program the contract names, or a
template over both), checks each against its rules, and writes the whole set into its one
1Password item in **one checked edit**. No value is printed, written to a file or passed in
argv; the receipt names versions and members only.

## Who runs it

The owner, in their own terminal. `provision` writes 1Password, so it needs a person signed in
with their own session, an interactive terminal and a typed confirmation. CI never runs it and
an assistant never runs it: an assistant runs only `opv provision <SET> --env <env> --dry-run
--json` (a read) and hands the command to the person. There is no MCP tool for it.

| The value | Use |
|---|---|
| A person copies it from a dashboard | a normal key: `opv set` or the 1Password app |
| opv can generate it alone | `source = "generated"` and `opv propose generate` |
| Only a program the owner runs can obtain it (an OAuth consent), or several values must be made together and agree | a set, filled with `opv provision` |
| Infrastructure creates it and only the deploy job sees it | `source = "infrastructure"` ([supplied at sync](infra-generated-values.md)) |

## What 1Password can and cannot guarantee

**Can.** One `op item edit` with the whole item on stdin is one item revision: the item is at
its previous version, or at the next one with every field of the edit. Item history keeps the
prior versions, and a person can restore one in the 1Password app.

**Cannot.**

- No version precondition: `op item edit` has no compare-and-swap. An edit made by someone else
  between opv's last read and its write is overwritten (kept only in the item's history). opv
  **detects** it and says so; it cannot **prevent** it.
- No transaction across items. So a set fills exactly **one item**: all members must be in one
  [boundary](configuration.md), checked at load.
- No restore-version command in `op`; restoring is a person's step in the app.

The one writer that `set`, `import`, `generate` and `provision` share therefore checks around
the edit:

1. A fresh read just before the edit. If a set member's field changed since the plan was read,
   nothing is written (`item_changed`). If only an unrelated field changed, the write is
   re-planned on the fresh item, so a person who has just consented does not consent again.
2. One `op item edit`, the item on stdin only.
3. The version the edit returns must be one past the fresh read. If not, the write stands
   (its members are verified next) and the receipt says `concurrent_edit: true`: "an edit made
   just before opv's may have been replaced; restore it from the item's history".
4. A final fresh read: every written member holds its value and nothing the item held is
   lost, else the run fails. The receipt says `verified_at`.
5. An edit whose outcome is unknown (a timeout, a kill, a lost reply) is decided by that read:
   written, "not written; safe to re-run", or exit 9 `outcome_unknown` naming the set's state.
   One atomic edit never leaves a new partial set.

A later whole-item write built from a read taken before the provision (any writer on a shared
item) can still erase the set. `opv ready` reports it, and item history recovers it.

## The contract

Both tables are committed and value-free. Members are existing declared keys, named
`"<product>/<KEY>"`; no key attribute changes. opv 0.17 and earlier refuse a contract with
these tables, so pin 0.18 everywhere before adding them; removing the tables is the rollback
(written values stay in 1Password).

### `[sets.<name>]`

| Field | Value |
|---|---|
| `environments` | the environments the set is made in; each member must be wanted in every one |
| `members` | `"<product>/<KEY>" = <how it is made>`, one of the forms below |

| Member form | Made by |
|---|---|
| `{ producer = "<name>", output = "<output>" }` | one output of a `[producers.<name>]` |
| `{ generate = "rules" }` | the key's own rules (a key whose rules give a byte recipe) |
| `{ generate = { hex_bytes = N } }`, `{ generate = { base64_bytes = N } }` | opv's CSPRNG, `N` from 16 to 1024 bytes |
| a `template` table | a JSON document built from members and producer outputs ([templates](#templates)) |

Load rules (each failure is `config_invalid`, naming the field):

- every member is a declared key wanted in each of the set's `environments`;
- every member is a team value stored in 1Password: not `personal`, not `from`, not
  `source = "infrastructure"`;
- all members are in **one boundary** (one item per environment);
- a key is a member of at most one set;
- a set's and a producer's name: a lowercase letter, then lowercase letters, digits, `_` or `-`.

### `[producers.<name>]`

| Field | Value |
|---|---|
| `command` | argv, no shell: `["python3", "path/to/helper.py", "--opv-produce"]`. Not empty; `command[0]` is not `op`, `op.exe`, `opv` or `opv.exe`; no element may look like a secret |
| `sha256` | 64 hex digits of the project file `command` names. Required when an element names a file inside the project (at most one); when it differs from the file now, the contract does not load (`producer_changed`) |
| `outputs` | the names the producer returns; each is used by a member, a template, or both |
| `inputs` | `{ <name> = "<product>/<KEY>" }`: values sent to the producer on stdin, only keys of the set's own boundary and environment (optional) |
| `open_url_hosts` | host names an `open_url` notice may name (optional) |
| `timeout` | `"<n>s"` or `"<n>m"`, at most `"15m"` |

The producer runs in the project directory (the contract's folder). The pin means an edited
producer never receives production inputs silently: whoever changes the file re-pins it in the
same reviewed change, and the plan shows the pin before anything runs.

### Example: an OAuth consent producer (#253)

A connector obtains a refresh token by PKCE consent through a loopback server. Its client id
and secret are already in the same item:

```toml
[producers.workspace-consent]
command = ["python3", "workspace/admin/connect.py", "--opv-produce"]
sha256  = "9c1d0000000000000000000000000000000000000000000000000000000000ab"
outputs = ["refresh_token"]
inputs  = { client_id = "workspace-admin/WORKSPACE_ADMIN_CLIENT_ID", client_secret = "workspace-admin/WORKSPACE_ADMIN_CLIENT_SECRET" }
open_url_hosts = ["accounts.google.com"]
timeout = "10m"

[sets.workspace-admin-grant]
environments = ["prod-workspace"]
members = { "workspace-admin/WORKSPACE_ADMIN_REFRESH_TOKEN" = { producer = "workspace-consent", output = "refresh_token" } }
```

### Example: a matched set with a template (#262)

Eight `zonetico` keys and one `journeeze` bundle share the `fleet` boundary. Five keys are
generated, three site keys are issued by Journeeze (a site get-or-create), and the bundle is
built from them and from the site ids, which are never stored as keys:

```toml
[producers.journeeze-sites]
command = ["python3", "fly/shared-host/journeeze_sites_produce.py"]
sha256  = "4e7a0000000000000000000000000000000000000000000000000000000000cd"
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

The rendered bundle, with fake values, is one compact line:

```json
{"version":1,"sites":[{"siteId":"site_fake1","identitySecret":"<64 hex>","gatewaySecret":"<64 hex>"},…]}
```

### Templates

A template is a TOML tree of tables, arrays, strings, integers and booleans (no floats or
dates). A string leaf is a literal without `${`, or **exactly** one reference:
`"${<product>/<KEY>}"` (a member of the same set) or `"${<producer>.<output>}"` (an output of a
producer of the same set). There is no partial interpolation (`"x${…}"` is refused) and no
cycle. The template member must be `kind = "secret"`.

opv writes the JSON itself, in declared order and compact, escaping each referenced value as a
JSON string straight from memory; it never splices strings. It then parses the result back,
checks every reference leaf equals its source, and checks the bundle against the template key's
rules. A producer output used only in a template (the `siteId`s above) is an intermediate: held
for the run, never stored as a key.

## The producer protocol: `opv.produce/1`

A producer is a program the owner already trusts with the value (it obtains it). opv spawns it
once and talks to it in JSON lines. `opv schema` lists the capability `owner_produce/1`, with
`opv.produce/1` and `opv.provision/1` in its schema map, so a helper can check that the opv it
runs under speaks the protocol before it asks anyone to consent.

**Request.** One line on stdin, then stdin is closed:

```json
{"schema":"opv.produce/1","kind":"request","env":"prod-workspace","set":"workspace-admin-grant","outputs":["refresh_token"],"nonce":"n-abcdefghijklmnopqrstuvwxyz","inputs":{"client_id":"fake-client-id","client_secret":"fake-client-secret"}}
```

`outputs` are the declared outputs the set uses; `inputs` holds the declared inputs' values,
read from the set's item in this environment. `nonce` is `n-` and 26 base32 characters, new
each run.

**Notices.** Any number of lines on stdout while it works:

```json
{"schema":"opv.produce/1","kind":"notice","open_url":"https://accounts.google.com/o/oauth2/v2/auth?client_id=…"}
{"schema":"opv.produce/1","kind":"notice","waiting":true}
```

An `open_url` must be `https`, on a host in `open_url_hosts`, at most 2048 bytes, with no
userinfo; otherwise it is refused and not opened. opv opens it itself (WSL: `rundll32.exe`;
a desktop: `xdg-open`) and prints `opening the consent page in your browser: <url>`; with no
opener (SSH, headless) it prints `open the consent page in your browser: <url>` for the person to
copy. The producer gets no `BROWSER` or `DISPLAY`, so it never opens one itself. `waiting`
prints `waiting for the producer`.

**One terminal line, last.** Either a result:

```json
{"schema":"opv.produce/1","kind":"result","env":"prod-workspace","nonce":"n-abcdefghijklmnopqrstuvwxyz","outputs":{"refresh_token":"fake-refresh-token"}}
```

or an error, from a closed vocabulary of `[a-z_]{1,40}`, shown only as
`producer reported <code>`:

```json
{"schema":"opv.produce/1","kind":"error","code":"consent_denied"}
```

**Checks.** Each line is one JSON object with `schema` `opv.produce/1` and no unknown field.
A result counts only when its `env` equals `--env`, its `nonce` equals this run's (a replayed
or misdirected result is refused), its `outputs` are exactly the requested names, each once,
each a non-empty string without NUL of at most 64 KiB, and the producer then **exits 0**. A
non-zero exit after a result discards it. Refusals name a line number or an output position,
never the producer's text. Limits: 1 MiB of stdout in all, 64 KiB per line.

**The run.**

- One attempt, never retried: a retry could ask for consent twice.
- argv exactly `command`; the environment cleared to basics (`PATH`, `HOME`, `USER`, `SHELL`,
  `TERM`, locale, temporary directories, proxy and CA variables): no `OP_SESSION_*`,
  service-account or Connect token, provider credential, `BROWSER` or `DISPLAY`. Inputs
  arrive on stdin only.
- stdin, stdout and stderr are pipes; the producer never gets the terminal.
- **stderr is never shown**: it is drained, counted and wiped unread, on success and on
  failure. `--verbose` shows only its byte count and stdout's line count. A producer explains a
  failure with its `error` code.
- Its own process group and a hard core-dump limit of 0.
- The run ends at the terminal line plus the producer's exit, not at stdout's end, so a browser
  or loopback server still holding the pipe cannot turn a success into a timeout. Then, or at
  `timeout`, or at the run budget, or when opv gets Ctrl-C/SIGTERM/SIGHUP, the whole group is
  stopped (SIGTERM, 5 s, SIGKILL).
- `timeout` is capped at 15 minutes, and the plan checks before consent that the producers'
  timeouts plus the write fit the run budget (`--timeout`, default 1800 s).

**Why `op` cannot be a producer.** opv's runner gives `op` the 1Password session variables it
needs; a producer always gets a cleared environment. A `command` that starts with `op` (or
`opv`) would either inherit a session a producer must never see or recurse into opv, so the
contract refuses it. A producer that needs a 1Password value declares it in `inputs`.

**Native Windows.** opv runs no producer there (no process group, group kill or core limit),
and refuses before reading the item with `platform_unsupported`: run it from WSL. Sets made only
by generators work everywhere.

**A consent helper's shape** (`connect.py --opv-produce`): check that `opv schema` lists
`owner_produce/1`, read the request, start the loopback server, announce the URL, wait, answer
once:

```python
req = json.loads(sys.stdin.readline())               # schema, env, nonce, inputs
emit({"kind": "notice", "open_url": auth_url(req["inputs"]["client_id"])})
emit({"kind": "notice", "waiting": True})
code = loopback.wait_for_code()                       # None if the person declined
if code is None:
    emit({"kind": "error", "code": "consent_denied"})
    sys.exit(1)
token = exchange(code, req["inputs"])                 # in memory only
emit({"kind": "result", "env": req["env"], "nonce": req["nonce"],
      "outputs": {"refresh_token": token}})
```

where `emit` writes one line `{"schema": "opv.produce/1", …}` and flushes. Never print the
token or a response body anywhere else, and never write it to a file.

When a producer fails, nothing is written: "the producer's outputs were not stored; what it
created at its issuer still exists". The producer's own documentation says what to do (revoke
a grant; nothing for an idempotent get-or-create).

## Running it

```sh
opv provision workspace-admin-grant --env prod-workspace --dry-run
opv provision workspace-admin-grant --env prod-workspace
```

In order: load the contract (with every pin), resolve the set and `--env` (one of the set's
`environments`), check who is running ([refusals](#refusals)), read the item fresh, classify
the set, show the plan, check the budget, ask for the environment name, run each producer once,
generate, render templates, validate every member, compare producer-made members with the set's
other environments, write once, read back, print the receipt. Nothing reaches a producer before
the confirmation and nothing is written before the last step.

The plan, on stderr (`--dry-run` prints it on stdout):

```text
opv provision workspace-admin-grant --env prod-workspace
  item    workspace-admin · prod-workspace   (vault v7k…, item i3q…, version 7)
  state   absent (0 of 1 members set)
  make    workspace-admin/WORKSPACE_ADMIN_REFRESH_TOKEN   producer workspace-consent → refresh_token
  producer workspace-consent: python3 workspace/admin/connect.py --opv-produce
           sha256 9c1d…ab   timeout 10m   inputs workspace-admin/WORKSPACE_ADMIN_CLIENT_ID, workspace-admin/WORKSPACE_ADMIN_CLIENT_SECRET
  budget  10m producer + 4m commit of 30m left
  compare no other environment declared
  write   one edit of one item; nothing else in the item changes
Type the environment name to provision workspace-admin-grant in it:
```

The answer must equal `--env` (else `confirm_mismatch`, nothing run). An empty answer or Ctrl-C
declines (exit 0). There is no `--yes` or `--confirm`.

Before consent opv also checks that every producer input holds a value in the item
(`keys_blocking` naming the missing ones).

**Every value is validated** against all its key's rules, placeholders are refused and a secret
must be at least 8 bytes; one refusal names every failing member, by rule only. **Production
and staging stay apart**: the environment is typed back and echoed by the producer with the
nonce, inputs come only from this environment's item, and a producer-made member equal to the
same field in another environment of the set is refused (one OAuth client used for two
environments). Generated members are not compared; an environment opv cannot read is listed as
`not_compared`.

### Set states

| State | Meaning | Without a flag |
|---|---|---|
| `absent` | no member holds a value | made and written |
| `complete` | every member holds a value that passes its rules; a template member parses as the template's shape, its member leaves equal the stored members, its intermediates are non-empty strings of at most 256 bytes and its literals equal the template's | `unchanged`, exit 0: no producer runs, nothing is made |
| `partial` | some members hold a value, not all | refused (`policy_refused`); `--fill-missing` recovers it |
| `inconsistent` | every member holds a value, but one fails its rules or a template does not match | refused (`policy_refused`); `--replace` re-makes it |

A complete set re-run is a no-op, so running the command twice never rotates anything.

### `--dry-run`

The plan and the set's state only: reads 1Password, runs no producer, makes no value, writes
nothing. It is a read, so it skips the terminal, assistant and identity checks: an assistant and
CI may run it. With `--json` it prints one document:

```json
{"schema":"opv.provision/1","result":"dry_run","plan":{"set":"workspace-admin-grant","env":"prod-workspace","item":{"boundary":"workspace-admin","vault_id":"v7k…","item_id":"i3q…","version":7},"state":"absent","replace":false,"members":[{"key":"workspace-admin/WORKSPACE_ADMIN_REFRESH_TOKEN","made_by":{"maker":"producer","producer":"workspace-consent","output":"refresh_token"},"state":"absent"}],"producers":[{"name":"workspace-consent","command":["python3","workspace/admin/connect.py","--opv-produce"],"sha256":"9c1d…ab","timeout_seconds":600,"inputs":["workspace-admin/WORKSPACE_ADMIN_CLIENT_ID","workspace-admin/WORKSPACE_ADMIN_CLIENT_SECRET"],"open_url_hosts":["accounts.google.com"]}],"budget":{"producers_seconds":600,"commit_seconds":240,"left_seconds":1800},"compare":[]},"next":{"actor":"person","command":"opv provision workspace-admin-grant --env prod-workspace"}}
```

A member's `state` is `absent`, `set` or `malformed` (with the failing `rule` by name).

### `--replace`

Re-makes the whole set: rotation, or a new consent after a revoked grant. Every producer runs
again and every generated member is made again; the old values are kept in the item's
`opv · kept` section by the writer. Refused before any producer runs when a member is
`immutable` (it is made once). It is the only way to change a set member: `opv set`,
`opv set --from-file`, `opv import` and a generate plan's `opv apply` refuse a member
(`policy_refused`, Next: `opv provision <set> --env <env> --replace`).

### `--fill-missing`

Recovers a `partial` set without rotating anything. Every present member is kept. Each missing
member is filled, in this order:

1. from a present template that holds it (by its template path), so it stays consistent with
   the bundle;
2. by its producer, which runs only when one of its outputs is missing; its intermediates must
   equal the stored template's leaves (the `siteId`s), else the set is `inconsistent`;
3. by generation, when no present template holds it.

Then templates are rendered from the stored and new values and checked to round-trip. A missing
template is rendered; a present template that would change is refused (`--replace` is the way).
The Journeeze user-hash key is `immutable`, so `--fill-missing`, never `--replace`, is how a
partial Journeeze set is recovered.

## Refusals

| Situation | Code (exit) | When |
|---|---|---|
| an assistant (agent mode) | `person_only` (6), with the exact command for the person | before any `op` call |
| CI | `terminal_required` (6) | before any `op` call |
| no interactive terminal | `terminal_required` (6) | before any `op` call |
| a producer member on native Windows | `platform_unsupported` (6) | before any `op` call |
| a service account, Connect or a target's deploy credentials | `own_session_required` (7) | before the item is read |
| production tier or `confirm_env`, with `OP_SESSION_*`, `OP_SERVICE_ACCOUNT_TOKEN` or `OP_CONNECT_*` in the environment | `own_session_required` (7) | before any `op` call |
| the producer's file no longer has its pin | `producer_changed` (2) | at load |
| partial, inconsistent, an immutable member under `--replace`, a value equal to another environment's, a budget too small, an item opv cannot rewrite whole | `policy_refused` (6) | before consent, except the comparison (after the producer) |
| the typed environment differs | `confirm_mismatch` (6) | before any producer |
| empty answer or Ctrl-C | `declined` (0) | before any producer |
| a producer that fails, times out or reports an error code | `producer_failed` (3) | nothing written |
| a producer line that breaks the protocol | `input_invalid` (2) | nothing written |
| a member field changed before the write | `item_changed` (4) | nothing written; re-run |
| the write's outcome stays unknown | `outcome_unknown` (9) | names the set's state |
| no access to the vault | 1Password's own refusal | the only permission system |

In production the write uses the 1Password app's authorization or a sign-in opv prompts for,
never a session or token already exported: open a fresh shell if one is. The terminal, agent
and confirmation rules prevent unattended and accidental writes; against another process of the
same user they are friction, not a boundary. Vault access is the real control, and CI, which has
only a service account, can never write.

## The receipt

`--json` prints `opv.provision/1`; the text form prints
`provisioned set <SET> in environment <env>: item at version <n>, verified` and `Next: opv ready
<env>`.

```json
{"schema":"opv.provision/1","set":"workspace-admin-grant","env":"prod-workspace","mode":"absent","result":"written","concurrent_edit":false,"item":{"vault_id":"v7k…","item_id":"i3q…","version_before":7,"version_after":8,"verified_at":8},"members":[{"key":"workspace-admin/WORKSPACE_ADMIN_REFRESH_TOKEN","made_by":"producer","state":"set"}],"producers":[{"name":"workspace-consent","sha256":"9c1d…ab","exit":0}],"compared_environments":[],"not_compared":[],"next":"opv ready prod-workspace"}
```

| Field | Meaning |
|---|---|
| `mode` | the state the set was read in (`absent`, `complete`, `inconsistent`, …) or `replace` |
| `result` | `written`, `unchanged` or `declined`; a refusal is the error document instead |
| `concurrent_edit` | the edit's version was not one past opv's own read: restore the other edit from the item's history |
| `item` | IDs, `version_before` (the plan's read), `version_after` (the revision delivery builds on), `verified_at` |
| `members` | each member, `made_by` `producer`, `generate` or `template`, and its state |
| `producers` | each producer that ran, its pin and its exit |
| `compared_environments`, `not_compared` | where producer-made members were compared, and where they could not be |

No value, length, digest or prefix appears anywhere, and nothing is written into the item
besides the members.

## `opv ready` and sets

`opv ready` computes each set's state in each of its environments from the values it already
reads (no marker is stored) and lists them in the receipt's `sets`
(`[{set, environment, state}]`, omitted when the contract declares none). A `partial` or
`inconsistent` set is a blocking `keys_blocking` finding with `scope.set`, actor `owner` and
prerequisite `opv provision <set> --env <env>`; a partial set is recovered with
`--fill-missing`, an inconsistent one with `--replace`. An `absent` set is reported and
does not block; a `complete` one has no finding. So a set broken by a later edit is found by
`ready`, not first by a release-time `sync`.

An assistant reads that finding, may run the `--dry-run --json` plan to show the person what
will run, and hands the command to the person verbatim.

## Matched sets: a worked example

A matched set is a set whose members must agree with each other: values one system issues,
values opv generates, and a bundle that repeats some of them for another consumer. This walk
through uses the shape of the Journeeze set above (§ "Example: a matched set with a template")
with neutral names, as the end-to-end test `tests/e2e/scenarios/provision_sets.rs` runs it.

**The members.** Nine fields of one item (one boundary, so one checked write):

| Member | Made by | Read by |
|---|---|---|
| `web/PLATFORM_IDENTITY_SECRET`, `web/AGENCY_IDENTITY_SECRET`, `web/OWNER_IDENTITY_SECRET` | `generate = { hex_bytes = 32 }` | the consumer, one per site, and the bundle |
| `web/SITES_GATEWAY_KEY` | `generate = { hex_bytes = 32 }` | the consumer and every site of the bundle |
| `web/USER_HASH_KEY` | `generate = { hex_bytes = 32 }` | the consumer only |
| `web/PLATFORM_SITE_KEY`, `web/AGENCY_SITE_KEY`, `web/OWNER_SITE_KEY` | the producer `site-issuer` (`<site>_site_key`) | the consumer |
| `web/SITE_SECRETS` | a template | the bundle's own reader |

**The producer issues the site keys.** `site-issuer` is a get-or-create: it asks the issuing
system for the platform, agency and owner sites, creates any that do not exist, and returns six
outputs, each site's id and key. A second call returns the same sites, so running it again
never makes new ones. The three `*_site_id` outputs are intermediates: they go into the bundle
and are never stored as keys.

```toml
[producers.site-issuer]
command = ["python3", "deploy/sites_produce.py"]
sha256  = "…64 hex of deploy/sites_produce.py…"
outputs = ["platform_site_id", "platform_site_key", "agency_site_id", "agency_site_key",
           "owner_site_id", "owner_site_key"]
timeout = "5m"
```

**The bundle template.** Its shape is the bundle's reader's, and each leaf is one reference:

```toml
[sets.sites.members."web/SITE_SECRETS".template]
version = 1
sites = [
  { siteId = "${site-issuer.platform_site_id}", identitySecret = "${web/PLATFORM_IDENTITY_SECRET}", gatewaySecret = "${web/SITES_GATEWAY_KEY}" },
  { siteId = "${site-issuer.agency_site_id}",   identitySecret = "${web/AGENCY_IDENTITY_SECRET}",   gatewaySecret = "${web/SITES_GATEWAY_KEY}" },
  { siteId = "${site-issuer.owner_site_id}",    identitySecret = "${web/OWNER_IDENTITY_SECRET}",    gatewaySecret = "${web/SITES_GATEWAY_KEY}" },
]
```

rendered compact as
`{"version":1,"sites":[{"siteId":…,"identitySecret":…,"gatewaySecret":…},…]}`.

**The consumer fields match the bundle.** The consumer reads
`PLATFORM_IDENTITY_SECRET`, `AGENCY_IDENTITY_SECRET`, `OWNER_IDENTITY_SECRET` and
`SITES_GATEWAY_KEY` as its own fields, and the bundle's reader reads the same values out of
`SITE_SECRETS`. Because both come from one run and one write, each `identitySecret` leaf equals
its site's identity secret and every `gatewaySecret` leaf equals the gateway key. opv checks
this on every run and in `ready`; a bundle that no longer matches is `inconsistent`.

**First run.** At a person's terminal:

```
$ opv provision sites --env prod
  …
  state   absent (0 of 9 members set)
  make    web/AGENCY_IDENTITY_SECRET   generate hex_bytes 32
  …
  make    web/PLATFORM_SITE_KEY   producer site-issuer → platform_site_key
  make    web/SITE_SECRETS   template of ${site-issuer.platform_site_id}, ${web/PLATFORM_IDENTITY_SECRET}, …
  …
Type the environment name to provision sites in it: prod
provisioned set sites in environment prod: item at version 2, verified
Next: opv ready prod
```

All nine fields arrive in one item edit; the receipt's `item.version_after` is one past
`version_before` and `verified_at` equals it. `opv ready prod` then reports the set as
`complete` (`"sets":[{"set":"sites","environment":"prod","state":"complete"}]`).

**A second run** asks nothing, runs no producer and writes nothing:

```
set sites in environment prod is already complete; nothing made or written
```

**A partial set.** Suppose `PLATFORM_SITE_KEY` and `USER_HASH_KEY` are lost from the item (a
hand edit, an older whole-item write). `opv ready prod` reports the set `partial` with the
blocking finding `keys_blocking prod → opv provision sites --env prod`, and that command
refuses, naming the recovery:

```
opv: opv does not provision set sites in environment prod: the set is partial (web/PLATFORM_SITE_KEY, web/USER_HASH_KEY without a value), so it is completed only with --fill-missing
Do: make only the missing members, keeping every present one: opv provision sites --env prod --fill-missing
```

`--fill-missing --dry-run` shows what it will keep and make:

```
opv provision sites --env prod --fill-missing
  state   partial (7 of 9 members set)
  keep    web/AGENCY_IDENTITY_SECRET
  keep    web/AGENCY_SITE_KEY
  keep    web/OWNER_IDENTITY_SECRET
  keep    web/OWNER_SITE_KEY
  keep    web/PLATFORM_IDENTITY_SECRET
  make    web/PLATFORM_SITE_KEY   producer site-issuer → platform_site_key
  keep    web/SITES_GATEWAY_KEY
  keep    web/SITE_SECRETS
  make    web/USER_HASH_KEY   generate hex_bytes 32
```

Run without `--dry-run`, the issuer is asked again and returns the platform site it already
made, so the lost site key comes back as it was and its site id equals the bundle's `siteId`
(had it differed, the set would be `inconsistent` and nothing written). `USER_HASH_KEY`, which
no bundle holds, is generated. Every other member, and the bundle, keeps its value; the write is
again one item edit, and `ready` reads the set `complete`.

**An inconsistent set.** Every member holds a value but the bundle no longer matches them, for
instance `SITES_GATEWAY_KEY` was changed by hand. `ready` reports `keys_blocking` for the set
(`state: "inconsistent"`), and `opv provision sites --env prod` refuses:

```
opv: opv does not provision set sites in environment prod: every member holds a value, but web/SITE_SECRETS fail their rules
Do: re-make the whole set: opv provision sites --env prod --replace (the replaced values are kept in the item's opv · kept section)
```

`--fill-missing` cannot help here (nothing is missing). `--replace` re-makes the set, unless a
member is `immutable`: then a person decides which value is right, restores it from the item's
history, and `ready` reads the set `complete` again.

No value appears in any of this output, in the receipts or in `ready`: the end-to-end test runs
every step above with marked values and fails if a marker, or any value the vault holds,
reaches a stream, a receipt, a file other than the vault, or its snapshot.
