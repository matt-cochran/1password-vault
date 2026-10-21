# HTTP target: deliver to an application's own secret store through its API (#231)

Status: revised after the DESIGN-FMECA vet (`http-target-fmeca.md`), 2026-10-21; awaiting the
owner's approval. Issue #231; consumer zonetico-saas #844. Nothing here is built.

Evidence (under `.delivery/v0160/`, not committed: the Zonetico recon names people and accounts):
`recon-opv-targets.md`, `recon-zonetico-api.md`, `spike-http-client.md`, `spike-grpc-web.md`.
The vet (`http-target-fmeca.md`) verified this design's claims against the code and supplied the
risk ids cited below (T*, U*, P*, R*, Z*).

## 1. Intent

Some applications keep their own secrets in their own encrypted store, written through an admin
API, and read them at runtime from there. Zonetico's system keys (OpenRouter, Tavily, Stripe and
so on) live in its platform vault by owner decision (D55); Zonetico checks each key with its
provider when it is saved.

1Password stays the source of truth. The application's store is one more delivery target, like
Fly secrets or a Kubernetes Secret: opv reads each value from 1Password, writes it to the store,
records a value-free receipt and reports drift when the store changes outside opv. It replaces the
owner's interim script, which signs in as a person (password and TOTP).

Owner decisions (2026-10-21):

1. **Built in, not an adapter binary.** opv makes the HTTPS calls itself, *as an effect of its
   command runner* (§5), and per-application configuration describes them.
2. **Declarative and deterministic**, validated at load, and generated from the application's API
   schema (§7, kept in this release by owner decision over the vet's demotion, C10).
3. **gRPC-Web from a descriptor set**, client only: no server, no HTTP/2, no code generation.
   The JSON wire format is deferred until an application needs it (vet Phase 1, C4/C5, which the
   owner delegated to the vet).
4. **Zonetico keeps its RPCs** and meets requirements Z1–Z9 (§10), including Z7: a key its
   provider rejects never displaces a usable key.

## 2. What the target does, per command

| Command | Calls | Result |
|---|---|---|
| `plan`, `status` | `list` | each managed name present or absent with its version; drift against the last receipt; `Store::refusal` shows Zonetico's value rules before any write (§3.3) |
| `sync` | `list`, one `put` per changed name, `list` again (`confirm`) | versions recorded from the confirming list; then the written names' statuses are checked (§6) |
| `delivery verify` | `list` | `verified` when each listed version equals the recorded one |
| `changed` | none (1Password only) | unchanged |
| `history` | `list` | the recorded and current versions |
| retire (pruning a managed name) | none | refused for this target, before any write; removing a key is a person's action in the application |

The store applies a write at once, so this is a staged target whose runtime is already live, the
shape of the GitHub target (`StagedRuntime::live() == true`). No new port.

## 3. Configuration

### 3.1 The target section

```toml
[environments.prod.targets.platform]
products = ["zonetico"]
deploy_credentials = "op://Zonetico Platform/opv-platform-prod"   # the item of §4

http.host = "central.zonetico.com"          # must equal the item's base_url host (§4.2)
http.descriptor = "deploy/opv/platform_console.binpb"
http.descriptor_sha256 = "ec5b6933b89fc49c1ebeaaa31afc666e9090036c53301648cc657cd18f8a7445"

[environments.prod.targets.platform.http.names]   # delivered env name = remote name
OPENROUTER_API_KEY = "openrouter"
TAVILY_API_KEY     = "tavily"
STRIPE_SECRET_KEY  = "stripe"

[environments.prod.targets.platform.http.list]
call    = "portal.v1.PlatformConsoleService/ListPlatformConnections"
request = { operator_id = "<tenant uuid>" }
items   = "connections"                  # descriptor field path to the repeated entry message
name    = "provider"                     # field paths within one entry
version = "version"
status  = "status"                       # must be an enum field
absent   = ["CONNECTION_STATUS_NOT_CONFIGURED", "CONNECTION_STATUS_REVOKED"]
rejected = ["CONNECTION_STATUS_REJECTED"]

[environments.prod.targets.platform.http.put]
call     = "portal.v1.PlatformConsoleService/SavePlatformConnection"
request  = { operator_id = "<tenant uuid>", provider = "{name}", expected_version = "{version}" }
value    = { field = "secret_value", number = 3, type = "bytes" }
reply    = "connection"                  # field path to the written entry (list's roles apply)
conflict = ["ALREADY_EXISTS"]            # gRPC codes that mean "changed since opv listed"
```

### 3.2 Load rules (fail fast; messages name file, field and rule, never a value)

1. **Descriptor pinned.** The file's sha256 equals `descriptor_sha256`; every named method exists.
2. **One place for the value.** `put.value` names one singular `string` or `bytes` field of the
   request message, and its `number` and `type` must match the descriptor (P6: a renumbered field
   can never receive the value silently).
3. **No templating of the value.** A request template is a literal object decoded against the
   request message with unknown fields refused. A string leaf may be a literal or exactly one of
   two whole-leaf placeholders, `{name}` or `{version}`. Partial substitution, any other
   placeholder and any reference to a credential are load errors. The template may not set the
   value field.
4. **Roles are typed field paths.** `items` is a repeated message field; `name` a string;
   `version` an integer; `status` an enum, and every name in `absent`/`rejected` is one of its
   values. Nothing else in a reply is ever read (Zonetico's `masked_key`, four trailing characters
   of the value, is never decoded into opv memory as a field it keeps).
5. **Every delivered name is mapped**, and no two env names map to one remote name.
6. **`http.host`** is a lowercase ASCII hostname: not a URL, not an IP literal, no port, no
   trailing dot.
7. **`conflict`** lists gRPC status names; empty means no code is treated as a conflict.

### 3.3 Value rules the store enforces, shown before any write

`Store::refusal` implements the application's fixed rules so `plan` shows them and `sync` refuses
before writing (U3, FR-22): for Zonetico, the trimmed value is 16 to 65536 characters with no
control characters. Stripe-shaped keys should carry contract rules (`sk_`/`rk_` mode, `whsec_`)
so a test key is never written to a production slot (U2).

## 4. Destination and credentials come from 1Password

### 4.1 The item

`deploy_credentials` names one item. Its fields are fixed for this target:

| Field | Kind | Use |
|---|---|---|
| `base_url` | text | `https://<host>[/<prefix>]`; the only place the destination is |
| `token` | concealed | sent as `Authorization: Bearer <token>`; opv adds the scheme |
| `cf_access_client_id` | concealed | sent as `CF-Access-Client-Id` |
| `cf_access_client_secret` | concealed | sent as `CF-Access-Client-Secret` |

All four are required (T21). A credential containing a control character is refused. Every
credential is a `SecretValue` registered with the scrubber. Configuration cannot add headers.
opv cannot mint this credential, so `opv target credentials --create` refuses for this target;
a person creates the item, and vault access decides who may.

### 4.2 Two keys agree on the destination

`base_url` is parsed once (T11): scheme `https`; no userinfo, port, query or fragment; host
lowercase ASCII, not an IP literal, no trailing dot; path prefix of `/`-separated
`[A-Za-z0-9._-]` segments. Its host must equal `http.host`, and the request URI is built from the
same parsed value, so the host checked is the host connected to. Changing where values go takes
both a vault write and a reviewed configuration change; a staging item used for production fails
on the first call. `target_locator` is the host plus the list request's literal fields, so a
changed host is a new placement and no receipt carries over. One actor holding both repository
write and write to a vault the CI reads is outside opv's scope (T12, owner decision 4).

### 4.3 Transport rules

- HTTPS only; no redirects (`max_redirects(0)`): a 3xx is a refusal naming the status code.
- Deadlines from the runner: `READ_TIMEOUT` for `list`, `WRITE_TIMEOUT` for `put`, under the run
  budget (`--timeout`).
- TLS roots from the operating system's store (`rustls-platform-verifier`), so the target works
  behind a TLS-inspecting proxy and no bundled-roots licence enters the tree. An empty OS store is
  a fixed, non-retried refusal. `HTTPS_PROXY`/`NO_PROXY` are honoured; `--verbose` says "via
  proxy" when one is used. (To confirm in implementation: `cargo deny`, `cargo tree -i
  webpki-roots` empty, six release targets in CI; T13.)

## 5. HTTPS is a runner effect

opv's runner owns how every external call is made and observed: read retries, the run budget,
write tracking (`wrote()`, so an interrupt after a write says so), the verbose line, the output
cap, and the only constructor of `Observed`, which every failure cause carries (guard-tested).
A client beside the runner could not build the causes in §8 and would make the tested path differ
from the shipped one (T1). So:

- `CommandRunner` gains an HTTPS call, `https_read` and `https_write`, sharing `read_on`/`write_on`,
  observation (program `https`), the budget, `wrote()`, the verbose line and a reply cap.
- **Credentials:** the target's `DeployLogin::env("https")` returns the header pairs from the item;
  `EnvRunner::extra` already merges deploy-login values into calls (`signin.rs:377-390`), and the
  HTTPS call turns them into headers. Never logged; `as_principal` applies (T2).
- **The real attempt** uses `ureq` 3 on `rustls` with the platform verifier.
- **The fake attempt**, compiled only with the `fake` feature and selected only when
  `OPV_SIM_WORLD` is set, runs `opv-sim https` with the request on stdin (header values masked)
  and the reply on stdout. The fault matrix discovers and faults HTTPS calls like any CLI call.
  A release build has no fake attempt. `FakeRunner` serves unit tests.

### 5.1 The gRPC-Web codec

- **Request:** decode the template (without the value) into a `DynamicMessage`, encode it into a
  `Zeroizing<Vec<u8>>`, then append the value field directly: its tag, length and bytes from the
  `SecretValue`. The value never passes through JSON, a `String` or an unzeroized buffer (T9).
  Frame it (`0x00`, 4-byte big-endian length) and POST it with
  `Content-Type: application/grpc-web+proto`, `x-grpc-web: 1`.
- **Reply:** require `application/grpc-web` or `application/grpc-web+proto`; refuse
  `grpc-web-text` and compressed frames (flag `0x01`). Read `grpc-status`/`grpc-message` from the
  response headers (trailers-only replies, the usual error shape) *and* from a body trailer frame
  (`0x80`) (T8). Decode message frames with the descriptor and read only the role fields by field
  path from the decoded message; no JSON conversion (T10, enforced by a source guard).
- Fixtures for unit and e2e tests come from **recorded** Zonetico replies (a local Zonetico run
  now, staging after #844) before the sim is built (P2).

## 6. Versions, receipts, drift and status

Zonetico has a per-name write counter, `version`, bumped by every value change (save, revoke) and
only by those (Z9), and no fingerprint of the stored value.

- `list` reports a name present only when its status is not in `absent`; an absent entry's
  version is kept inside the adapter, and unmapped remote names are dropped (T4, T16).
- `put` sends the version from that cached list as `expected_version` (0 for a slot never saved,
  which Zonetico lists with version 0).
- `write` returns `Ok` for any write the store accepted, whatever its status, so the version is
  recorded (T5). After `confirm` re-lists and `record_delivery` writes the receipt and evidence
  (`v1|version|fingerprint|item_id|field`), a new defaulted hook,
  `StagedStore::check_written(&self, names) -> Result<(), Error>` (default `Ok(())`), runs; the
  HTTP store returns `TargetRefused { why: Unhealthy }` (`target_unhealthy`, exit 5) for names
  whose status is in `rejected`, and a note for other non-healthy statuses (`UNVERIFIED`,
  `UNAVAILABLE`; Q5).
- Drift: a listed version different from the recorded one is "changed outside opv since its last
  sync" (`TargetDrift`, exit 8 under `--fail-on-drift`).
- A conflict on `put` (`conflict` codes) is `ChangedBeforeWrite { object: Resource }`
  (`target_changed`, exit 5), reachable in e2e through a new opv-sim fault "version bumped before
  put"; `ChangedBeforeWrite` leaves `UNREACHABLE` in the same change (P3).
- What this cannot prove: that the stored value equals the 1Password value when nobody changed it
  through the API. The version counter is accepted for v1 (Q4); a server-side keyed digest can be
  added later.
- `versions_reveal_values()` stays `false`.
- Status appears only in `sync`'s check above, not in `plan`, `status`, `history` or
  `delivery verify` (P4).

## 7. Generating the configuration from the application's schema

`opv propose target http <env> --descriptor <file.binpb> --service <full.name>` (kept in this
release by owner decision) reads a descriptor set and writes a proposal through the existing
value-free `propose`/`apply` flow, also reachable through MCP `opv_propose`:

- every RPC of the service with its request and reply field paths, numbers and types, sorted, in
  canonical form: the same descriptor always produces byte-identical output;
- `descriptor_sha256` filled in;
- suggestions, marked as such, for the decisions a person confirms: which RPC is `list` and `put`;
  which field receives the value (only singular `string`/`bytes` fields are offered, with number
  and type filled in); which fields are `items`, `name`, `version`, `status` (status only from
  enum fields) and which enum values are `absent` and `rejected`;
- no network call; the result passes the same load rules as hand-written configuration.

The descriptor file is a build artifact of the application (`buf build -o` or
`protoc --include_imports --descriptor_set_out`), committed beside the configuration and pinned by
hash. Server reflection is not used.

## 8. Errors (catalog)

New `System::Https` (labelled with `http.host`); existing causes only:

| Condition | Cause (exit) |
|---|---|
| item host ≠ `http.host`, malformed `base_url`, missing item field, descriptor hash or field mismatch | `ConfigInvalid` (2), before any call |
| `UNAUTHENTICATED`, `PERMISSION_DENIED`, HTTP 401/403 | `CredentialRejected { DeployCredentials }` (7) |
| 3xx | `TargetRefused` naming the status (5) |
| `list`: 5xx, `UNAVAILABLE`, connect, TLS or timeout | `Unavailable` (9), retried as a read |
| `put`: a declared `conflict` code | `ChangedBeforeWrite { Resource }`, `target_changed` (5) |
| `put`: `INVALID_ARGUMENT` | `TargetRefused` (5), status name and scrubbed message |
| `put`: anything else once the request was sent (5xx, `UNAVAILABLE`, `INTERNAL`, timeout, lost connection, unparseable reply) | `WriteOutcomeUnknown` (9); the next `list` shows what happened (T6, T7) |
| reply missing a role field, wrong type, unknown status value | `TargetRefused` naming the field path (5), never the reply |
| written name's status in `rejected` | `TargetRefused { Unhealthy }`, `target_unhealthy` (5), after recording |

Server text (`grpc-message`, an error body) is percent-decoded, scrubbed of every registered
value, stripped of control characters and truncated to 200 characters, in that order, with a test
for a value straddling the cut (T20). `--verbose` prints one line per call: RPC name, host, status,
duration; never a header or a body.

## 9. Testing

- Unit: `FakeRunner` with recorded replies; load rules; codec (template + appended value
  round-trips; trailers in headers and in body; refusals of text/compressed frames); URL parsing
  per malformed form; server-text scrubbing.
- e2e through `opv-sim https` and a descriptor-driven fake store in `world.json`: first sync writes
  every mapped name; a second sync writes nothing; a rotated value is written with the listed
  `expected_version`; an entry changed outside opv is drift under `--fail-on-drift`; a version
  bumped before `put` is `target_changed`; a rejected key fails after the receipt is recorded; an
  item host ≠ `http.host` refuses before any call; no snapshot contains a value, a credential or
  the `masked_key` tail.
- Coverage: every new cause path is a fault-matrix cell or an `UNREACHABLE` entry with its reason.
- The local release gate runs native checks; CI (native macOS/Windows clippy and builds, zigbuild
  for musl) is the gate for non-native targets, since `ring` compiles C (Q3).

## 10. What Zonetico provides (#844): requirements Z1–Z9

Requirements, not a Zonetico design; Zonetico's identity design gets its own review.

- **Z1. Scoped TOTP exemption:** the non-interactive identity is accepted without aal2/TOTP only
  in the platform-operator gate for the connection RPCs, never in the shared `owner_gate` that also
  gates agency and business owners.
- **Z2. Least privilege by method:** `ListPlatformConnections` and `SavePlatformConnection` only.
- **Z3. Credential properties:** revocable server-side; bounded lifetime with a rotation runbook;
  stored only in 1Password; environment-scoped (a staging token is rejected by production, which
  makes a cross-environment mix-up fail closed); accepted from `Authorization: Bearer` alone.
- **Z4. Audited as itself**, distinct from any person.
- **Z5. No portal sign-in**, central host only.
- **Z6. A Cloudflare Access service token** per environment, scoped to the API host.
- **Z7. A rejected key never displaces a usable one:** verify with the provider before committing,
  or keep the previous key when the new one is rejected (owner decision 2026-10-21).
- **Z8. Stable wire contract:** documented conflict code (today `ALREADY_EXISTS`); error text never
  contains key material; field numbers never reused; the descriptor set published with every API
  change.
- **Z9. `version` semantics unchanged:** bumped by every value change and only by those.

The live canary on Zonetico staging (canary keys only) is the gate before any production section
is configured. opv's release does not depend on #844: the target is complete against recordings
and the sim.

## 11. Delivery plan (incremental, reversible)

1. Runner HTTPS effect: `https_read`/`https_write`, `Observed` program `https`, budget, `wrote()`,
   verbose line, reply cap, credential headers from `DeployLogin::env("https")`; real attempt
   (ureq, rustls, platform verifier, no redirects, proxy) and fake attempt (`opv-sim https`).
2. gRPC-Web codec: descriptor loading and pinning, template encode plus appended value field,
   framing, headers and body trailers, role-field reads by path; from recorded replies.
3. The `http` provider: config and load rules (§3.2), `Store::refusal` rules (§3.3), `Store` +
   `StagedStore` + live `StagedRuntime`, `check_written`, URL parsing and host check, catalog
   mappings and `System::Https`.
4. `opv propose target http --descriptor` generator (off the critical path).
5. `opv-sim https` with a descriptor-driven fake store; scenarios and fault-matrix cells.
6. Docs; then the live canary against Zonetico staging once #844 lands.

Rollback: the target is opt-in per environment; removing the section stops all HTTPS calls, and
the owner's existing importer keeps working until it is retired.

## 12. Open questions, closed by the vet

- Q1. JSON wire format: deferred (no consumer).
- Q2. No `environment` field on the item: Z3 environment-scoped tokens plus the host check fail
  closed.
- Q3. Local gate native only; CI gates non-native targets.
- Q4. The version counter is accepted for v1.
- Q5. Fail only on `rejected`; other non-healthy statuses are notes.
