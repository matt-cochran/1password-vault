# DESIGN-FMECA vet: HTTP target (#231), `docs/design/http-target.md`

Reviewer: independent; did not write the design. Date: 2026-10-21. Method: the owner's
DESIGN-FMECA procedure (persona, objective, constraints, code-change-proposal requirements, three
phases, output format, verification checklist), applied as written.

Owner question: **is this design secure and actually feasible?**

**Short answer.** The goal is sound and feasible: Zonetico's API gives opv what it needs to keep
1Password as the source of truth, using a version counter for drift and optimistic concurrency.
**As written, though, the design cannot be built on opv's current code.** Its central seam, an
in-process `HttpTransport` beside the `CommandRunner`, cannot raise the catalog causes the
design's own error table needs, because only the runner may build an `Observed`. It would also skip
the runner's write tracking, run budget and retry policy, and the shape the tests exercise would
differ from the shape that ships. Several statements about Zonetico are wrong or unchecked:
- the conflict status is `ALREADY_EXISTS`, not `ABORTED`;
- unconfigured slots are listed with version 0;
- a save can fail after it has committed;
- error replies are probably trailers-only.

Several statements about opv are also wrong:
- no `StoreEntry` status field exists;
- there is no receipt "basis" field;
- optional credential fields are not supported;
- a failed write skips recording.

The value-safety design is mostly right but leaks in two places that the spike carried over: the
reply is reduced through JSON (so `masked_key` lands in a `String`), and the value is copied into a
`DynamicMessage`.

All of these can be fixed with small changes that reuse existing structures (listed at the end).
After those changes and the scope cuts below, no High risks remain. One Medium remains: a key that
Zonetico rejects replaces a working key. It stays Medium unless Zonetico adopts requirement Z7.

Evidence levels used throughout: **Proven** (industry standard, or opened and shown in code here),
**Adapted** (reasonable, not proven in this setting), **Speculative** (assumed, not validated).
Every code claim cites `path:line`. opv paths are relative to `/home/mc/.cache/lanes/opv-0160-design`
(rev `b56f21a`); Zonetico paths are relative to `/home/mc/working/zonetico-saas` (rev `d54f92eb`).

---

## 0. Claims checked against the code (summary)

| Design claim (§) | Verdict | Evidence |
|---|---|---|
| A staged target with `live() == true`, as GitHub (§2) | **Holds** | `src/ports.rs:93-102`; GitHub `src/adapters/github/mod.rs:142` |
| "No new port" (§2) | **Does not hold**: status per name, recording a rejected write, and handing credentials to an in-process client all need extensions | `src/domain/plan.rs:44-50` (no status); `src/app/sync.rs:1128` (`store.write(&batch)?` returns before `record_delivery` at `:1134-1153`); `src/provider.rs:183-198` (credentials only as child env) |
| Errors map to existing causes (§8) | **Infeasible outside the runner**: `CredentialRejected`, `TargetRefused`, `WriteOutcomeUnknown`, `Unavailable` all carry `seen: Observed`, which only the runner may build (guard-tested) | `src/cause/mod.rs:36-58`, `:691-695`, `:721-728`, `:752-762`; builders only in `src/runner.rs:799,996,1005,1015` |
| The causes' codes and exits (§8) | **Hold** | `target_changed` exit 5 `src/cause/mod.rs:1942-1946,2037-2039`; `CredentialRejected` exit 7 `:2075-2080`; `TargetDrift` exit 8 `:2081-2084`; `WriteOutcomeUnknown`/`Unavailable` exit 9 `:2086-2090` |
| Zonetico conflict = `ABORTED`/409 (§6, §8) | **Wrong**: `CONFLICT` maps to `ALREADY_EXISTS` (6) | `services/api/src/rpc/mod.rs:69`; message at `services/api/src/platform_admin.rs:43` |
| A `FAILED_PRECONDITION` on put means a conflict (§8) | **Wrong for Zonetico**: it means "No key is stored" (verify) | `services/api/src/platform_admin.rs:640`; `rpc/mod.rs:71-73` |
| An unconfigured slot is omitted or listed with v0, "to be confirmed" (§6) | **Resolved: always listed**, version 0, status `NOT_CONFIGURED`. A revoked slot is listed with version > 0 and status `REVOKED` | `services/api/src/platform_admin.rs:343-364`; `services/api/src/rpc/console/platform_console.rs:526-535` |
| Version semantics: save bumps, revoke bumps, verify does not | **Holds** | put `services/platform/migrations/0095_system_portal.sql:191-192`; revoke `:219-221`; verify updates only `outcome` `:208` |
| Save is atomic from the client's view | **No**: it commits, then probes the provider (up to 12 s), records the outcome and refreshes; any later failure returns `UNAVAILABLE`/`INTERNAL` for a write that has already happened | `services/api/src/platform_admin.rs:608-621`, `:26-28`, `:458` |
| Ledger drift through `Store::list` versions (§6) | **Holds** | `src/domain/ledger.rs:132-164`; `src/app/mod.rs:381-415` |
| "The receipt states the basis, `version`" (§6) | **Does not hold**: `Receipt` has no such field | `src/domain/delivery.rs:38-58` |
| `deploy_credentials` item with optional `cf_access_*` fields (§4.1) | **Does not hold**: the reader refuses a missing declared field (`Incomplete`) | `src/adapters/onepassword.rs:1077-1086` |
| Scrubber registration (§5) | **Holds**, with an ordering caveat (scrub, then truncate) | `src/scrub.rs:92-98` |
| Sim transport keeps the fault matrix working (§9) | **Only partly**: the sim path would go through the runner while the real path would not; replies would be invented, not recorded; `ChangedBeforeWrite` is in `UNREACHABLE` | `docs/design/error-catalog.md:625-633`; `tests/e2e/coverage.rs:76-81` |
| gRPC-Web trailer in the body (§11 step 2) | **Speculative**: the spike parses only an in-body `0x80` frame; tonic error replies are usually trailers-only (`grpc-status` in the HTTP headers, empty body). Zonetico uses tonic-web 0.14.6 | `/home/mc/.cache/lanes/opv-0160-spike-grpc/src/grpc_web_spike.rs:144-191`; `Cargo.lock:3048-3049`, `services/api/src/rpc/mod.rs:321-324` |
| The value never enters JSON or a `String` (§5) | **Request: holds. Reply: does not hold as spiked**. `reduce()` works on the whole reply serialized to `serde_json::Value` | `grpc_web_spike.rs:211-236`, tests `:353-370`; copy into `bytes::Bytes` at `:119` |
| Platform verifier removes the CDLA licence (§4.3) | **Speculative**: the spike built only `webpki-roots` | `spike-http-client.md` "Root-certificate choice", "cargo deny" |
| Q3: ring needs a C compiler for cross clippy | **Holds**; CI runs clippy natively on macOS and Windows | `.github/workflows/ci-checks.yml:16-30` |

---

## Phase 1: Architecture Assessment

| Component | Purpose | Classification | Justification | Simpler Alternative | Risk if Removed |
|---|---|---|---|---|---|
| C1. `http` provider (`Store` + `StagedStore` + `StagedRuntime{live}`) | Make the app store a target of the existing flows | **Essential** (Proven shape: GitHub) | The only way to get receipts, drift and `plan` for this store; fits ports without a new flow (`src/ports.rs:12-14`) | None | No feature |
| C2. `HttpTransport` trait with a real and a sim implementation beside the runner | HTTPS calls; a seam for tests | **Essential need, wrong placement** (Speculative as designed) | Outside the runner it cannot build `Observed` (`src/cause/mod.rs:36-58`), does not set `writes_started` (`src/runner.rs:203,404-411`), ignores the run budget, and the sim and real paths differ | **An HTTPS effect of the `CommandRunner`**: the runner's read/write policy, observation, verbose line and budget shared; only the final attempt differs (socket vs `opv-sim http` under `fake`), like the existing fake-only knobs `src/runner.rs:1740-1775` | No tests or no catalog causes |
| C3. gRPC-Web codec (descriptor-driven, pinned) | Speak Zonetico's API without codegen | **Essential** (Adapted: spike 9/9 unit tests, no live server) | The only consumer is gRPC-Web | None | No consumer served |
| C4. JSON codec | A REST store | **Speculative**: no consumer | Adds a second request builder, value placement, status lists and URL templating, all untested against any real API | Add when a consumer exists | None today |
| C5. `Codec` trait over two codecs | Abstraction | **Unjustified for v1** | One implementation; FR-60 "one way only" (`docs/design/requirements.md:151`); the code-change rules forbid parallel abstractions without a consumer | A concrete gRPC-Web module; introduce the trait with the second codec | None |
| C6. Declarative call mapping (`list`/`put` calls, templates, field roles) | Configure per-app calls | **Essential** (owner decision 1; Adapted) | The built-in target needs configuration | Keep, but resolve field roles as **descriptor field paths at load**, not JSON pointers into a serialized reply | — |
| C7. Descriptor pinning (`descriptor_sha256`) | Integrity of the schema opv encodes with | **Essential** (Proven pattern) | Cheap; fails fast | — | A wrong encoding could put the value in another field |
| C8. `names` map (env name → remote name) | Store spelling (FR-8) | **Essential** (Proven: Key Vault maps inside its adapter, `src/ports.rs:22-26`) | — | — | Cannot map env names |
| C9. Host two-key check (item `base_url` host == config `http.host`) | Destination integrity | **Essential** (Adapted) | Cheap; stops a staging/production mix-up and a vault-only redirect | — | One vault edit redirects production values |
| C10. `opv propose target http --descriptor` generator | Generate config from the schema | **Useful / Speculative value for v1** | One consumer with ~25 lines of TOML. Load-time validation (§3.2) already gives fail-fast diagnostics. The generator brings determinism tests, MCP surface and docs | Hand-written config plus load-time validation; generate later | Slightly more typing once |
| C11. `opv propose target http --names-from map.json` | Import Zonetico's name map | **Unjustified** | The map is branch-only in Zonetico (`recon-zonetico-api.md` §1, §6), holds a personal identifier, covers 10 of 15 slots (§6 "Mapping observation"), and is a one-time 10-line translation | Write the `names` table by hand | None |
| C12. `remove` operation (retire through `RevokePlatformConnection`) | Retire a name | **Speculative / risky** | Revoke disables a production key at once (`0095_system_portal.sql:219`). Retire is rare. A person can revoke in the Zonetico console | Refuse retire for this target (the design's own fallback) | A person revokes by hand |
| C13. Store status per name in `plan`/`status`/`history`/`verify` | Show provider verification | **Useful, not buildable as stated** | `StoreEntry` has no status (`src/domain/plan.rs:44-50`); adding one is a core and domain change across four commands | Check status only at `sync`, after recording: `REJECTED` fails, the rest is a note | Health shown in the Zonetico console only |
| C14. `expected_version` concurrency | Required by the API | **Essential** (Proven: the API requires it, `0095_system_portal.sql:191`) | — | — | Every save refused |
| C15. Error-mapping table | Catalog causes | **Essential** | — | Needs per-target conflict codes and an "outcome unknown" default for put | Wrong codes |
| C16. Zeroizing value placement | SR-2, SR-8 | **Essential** | — | **Append-encode** the value field into the `Zeroizing` buffer instead of `DynamicMessage::set_field` | A non-zeroized copy |
| C17. Server error text (≤ 200 chars, scrubbed) | Usable refusals ("Paste the full key…") | **Useful** | Zonetico's messages are fixed strings (`platform_admin.rs:31-55`) | Keep: scrub, then truncate, then strip control characters | Less helpful messages |
| C18. TLS from the OS trust store (`rustls-platform-verifier`) | Corporate proxies; licence | **Useful** (Speculative until spiked) | Same trust as the CLIs opv already drives (`gh`, `flyctl` use OS roots) | `webpki-roots` + allow CDLA | Breaks behind TLS inspection |
| C19. Receipt "basis" | Say equality was not proven | **Unjustified** (no field exists) | The GitHub `updatedAt` precedent has the same semantics with no field (`src/adapters/github/mod.rs:18-19`) | Document it in docs/usage | None |

### Revised Architecture

- **Components retained:** C1 provider; C3 gRPC-Web codec (concrete module, no trait); C6 declarative
  `list`/`put` mapping with field roles as descriptor field paths; C7 descriptor pinning; C8 names
  map; C9 host two-key check (strict URL parsing); C14 `expected_version`; C15 error mapping;
  C16 zeroizing placement; C17 scrubbed server text; C18 platform verifier (after a re-spike).
- **Components simplified:**
  - C2: the transport becomes an **HTTPS effect of the `CommandRunner`**, with one policy path for
    real and sim.
  - C13: store status is checked once at `sync`, after evidence is recorded, through one defaulted
    `StagedStore` hook. `REJECTED` fails; `UNAVAILABLE`/`UNVERIFIED` is a note.
  - C15: on `put`, anything but a definitive pre-write refusal is `WriteOutcomeUnknown`; the
    conflict code is declared per target.
  - Credential item: `cf_access_*` required; `token` holds the bare token.
- **Components removed:** C4 JSON codec; C5 `Codec` trait; C11 `--names-from`; C12 `remove`/revoke;
  C19 receipt basis; status in `status`/`plan`/`history`/`delivery verify`.
- **Components demoted:** C10 descriptor generator (later release, once a second consumer or a
  schema change shows the need); a server-side value digest (later, optional).

---

## Phase 2: FMECA + poka-yoke + TRIZ

Risk level is the combination of Severity × Probability: H×H, H×M and M×H are **High**; H×L, L×H
and M×M are **Medium**; M×L and L×L are **Low**. Ids: T = technical architecture, R = runtime,
U = UX / user interaction, P = project / delivery.

### Iteration 1 Risk Table

| Id | Domain | Failure Mode | Cause | Effect | Severity | Probability | Mitigation (Poka-Yoke) | Observability | TRIZ Resolution | Residual Severity | Residual Probability |
|---|---|---|---|---|---|---|---|---|---|---|---|
| T1 | Technical | HTTP calls bypass the runner | `HttpTransport` beside `CommandRunner` (design §9). `Observed` can be built only by the runner (`src/cause/mod.rs:36-58`, guard-tested). `writes_started` is a runner fact (`src/runner.rs:203,404-411,1867`), as are the run budget (`:177-215`) and read retries (`READ_ATTEMPTS`, `:302`) | The design's §8 causes cannot be constructed (compile or guard failure, or a forged observation). An interrupt after a put says "nothing changed". `--timeout` is ignored. The tested sim path (through the runner) differs from the shipped path | High | High | **Prevention:** HTTPS becomes a runner effect: `Call` gets an HTTPS variant, or `CommandRunner` gets `https_read`/`https_write`, sharing `read_on`/`write_on`, observation, verbose line, budget, `wrote()`. `EnvRunner` adds credential headers. `FakeRunner` serves unit tests. Under `cfg(feature = "fake")` with `OPV_SIM_WORLD` set, only the *attempt* goes to `opv-sim http` (precedent: `src/runner.rs:1740-1775`) | Each cause carries `Observed` with program `https`; `--verbose` lines come from the runner; the e2e matrix faults HTTPS calls like CLI calls | Contradiction: "in-process client" vs "fakes at the boundary". Principle **#24 Intermediary**: the runner is the boundary, and the process/socket split sits below it | Low | Low |
| T2 | Technical | Credentials cannot reach the client | `DeployLogin` exposes values only as `env(program)` for child processes (`src/provider.rs:183-198`; merged in `src/app/signin.rs:377-390`) | Real transport has no headers, or a new ad-hoc credential channel appears | Medium | High | Under T1: the http login's `env("https")` returns `(header, value)` pairs that `EnvRunner::extra` already merges (`signin.rs:377-390`). The HTTPS engine turns them into headers, never logs them, and `as_principal` applies (`signin.rs:367-375`) | 401/403 raise `deploy_credentials_failed` naming the item | #6 Universality: reuse the env-merge channel | Low | Low |
| T3 | Technical | Optional `cf_access_*` fields | Reader refuses a missing declared field (`src/adapters/onepassword.rs:1077-1086`) | Every target without Access fails at sign-in, or the reader is quietly changed | Low | High | Make `cf_access_client_id`/`_secret` **required** for v1 (Zonetico is behind Access); add `optional` to `CredentialField` only when a consumer without Access appears | `deploy_credentials_failed` `Incomplete` names the field | Simplification instead of a new reader mode | Low | Low |
| T4 | Technical | Store status cannot be shown | `StoreEntry{name,version,pending,stamp}` (`src/domain/plan.rs:44-50`); design §2 promises status in `plan`/`status`/`history`/`verify` | Core and domain changes across four commands, or the promises are silently dropped | Medium | High | Remove status from those commands for v1 (C13); keep the version. Status is checked at `sync` only (T5) | Zonetico console shows health; `sync` fails on `REJECTED` | Segmentation: health at write time only | Low | Low |
| T5 | Technical | A rejected write is not recorded | `run_staged` calls `store.write(&batch)?` (`src/app/sync.rs:1128`) before `record_delivery` (`:1134-1153`); design §6 says "the sync records the write and fails" | The store moved to a new version opv did not record, so the next `status` reports opv's own write as drift | Medium | High | `write` returns `Ok` for a write the store accepted (any reply status). Add one defaulted method, `StagedStore::check_written(&self, names) -> Result<(), Error> { Ok(()) }`, called after `record_delivery` and before `finish_supplied`; the http store returns `TargetRefused{why: Unhealthy}` (`target_unhealthy`, `src/cause/mod.rs:1925-1929`) for names whose reply status is declared `rejected` | Exit 5 `target_unhealthy` naming the key; the receipt records the version | #10 Preliminary action: record first, judge after | Low | Low |
| T6 | Technical | A concurrent change is reported as `update_refused` | Zonetico maps conflict to `ALREADY_EXISTS` (`services/api/src/rpc/mod.rs:69`); design maps `ABORTED`/`FAILED_PRECONDITION` | Wrong code and next step (same exit 5) | Low | High | `put.conflict = ["ALREADY_EXISTS"]`, required and validated against the gRPC code names at load; anything else stays `TargetRefused` | `target_changed` with the key named | Declarative per target (no guessing) | Low | Low |
| T7 | Runtime | A committed save reported as a refusal | Save commits (`platform_admin.rs:608-612`) then probes up to 12 s (`:458`), records and refreshes (`:616-621`); any failure becomes `UNAVAILABLE` (`:26-28`) or `INTERNAL`. Design §8 does not classify 5xx/`UNAVAILABLE` on `put` | "Nothing changed" while the value changed; the rerun's `expected_version` is stale and hits a conflict | High | Medium | On `put`, only `UNAUTHENTICATED`, `PERMISSION_DENIED`, `INVALID_ARGUMENT`, a declared conflict code, or an HTTP 4xx before the gRPC layer are refusals. **Everything else after the request was sent** (5xx, `UNAVAILABLE`, `INTERNAL`, `UNKNOWN`, `DEADLINE_EXCEEDED`, a lost connection, a malformed reply) is `WriteOutcomeUnknown` (exit 9, `RetryClass::Safe`, `src/cause/mod.rs:2100-2104`) | Exit 9 naming the key; the next `status` shows the version | — | Low | Low |
| T8 | Technical | gRPC-Web error replies misread | Spike requires an in-body `0x80` trailer (`grpc_web_spike.rs:144-191`, "missing grpc-status trailer"). tonic error replies are typically trailers-only (`grpc-status` in headers, empty body) (Adapted; tonic-web 0.14.6 per `Cargo.lock:3048-3049`) | Every refusal (401, 403, conflict) is reported as a malformed reply | Medium | High | Read `grpc-status`/`grpc-message` from the response headers first, then from a body trailer frame. Require response `content-type` `application/grpc-web[+proto]`. Refuse a compressed frame (flag `0x01`) and `grpc-web-text`. Test both shapes with **recorded** replies (P2) | Unit tests per shape; e2e cells per status | — | Low | Low |
| T9 | Technical | `masked_key` in a non-zeroized `String`; one bug away from output | Spike `reduce()` takes the full reply as `serde_json::Value` (`grpc_web_spike.rs:211-236`; tests `:353-370`); design §3.1 uses JSON pointers | Four trailing characters of a value in freed heap; any `Debug` or log of the JSON shows them | Medium | High | Field roles are **descriptor field paths** resolved at load (type-checked: name string, version int64, status enum). Read with `get_field_by_name` on the decoded message; never serialize a reply. A unit test asserts `masked_key` never appears in the reduced value. A source guard bans `serde_json` in the codec module | Guard test fails on a JSON call; snapshot canary (`MARK`, `tests/e2e/coverage.rs:38`) for `masked_key`'s fixture tail | — | Low | Low |
| T10 | Technical | Value copy not zeroized | `set_field_by_name(.., Value::Bytes(secret.to_vec().into()))` (`grpc_web_spike.rs:119`) | A full value copy in freed heap (SR-8) | Low | High | Encode the template message **without** the value field (rule 3.2.1 guarantees it is absent), then append `tag(field, LEN)`, varint length and the value bytes straight into the `Zeroizing<Vec<u8>>` (protobuf merge semantics). The value field must be top-level and singular (load rule) | Unit test: decoded request round-trips; no `DynamicMessage` holds the value | #2 Taking out | Low | Low |
| T11 | Technical | Values sent to an unintended host through URL parsing | `base_url` from the item; userinfo (`https://a@b`), port, IDNA, trailing dot, case, path tricks; a check-vs-connect parser differential | Production keys exposed to a third party | High | Low | Parse once (`http::Uri`/`url`). Require scheme `https`, no userinfo/port/query/fragment, ASCII-lowercase host, no trailing dot, not an IP literal; the host must equal `http.host`. **Build the request URI from the same parsed struct.** Path prefix: `/`-segments of `[A-Za-z0-9._-]` only | Value-free refusal `ConfigInvalid` naming the item field and the rule; unit tests per malformed form | — | Low (any mismatch is a refusal) | Low |
| T12 | Technical | One actor changes both keys | Someone with repo write **and** write to any vault the CI identity can read repoints `deploy_credentials` and `http.host` | Values to an attacker host | High | Low | **Out of opv's scope (owner decision 4):** who may write vaults the CI reads is 1Password's access control. In opv: `target_locator` includes the host, so a changed host is a new placement (no receipt reuse, `src/provider.rs:398-399`), and Z3 makes credentials environment-scoped | Plan output names the host; receipts' locator changes | — | Recorded as out of scope | — |
| T13 | Technical | Platform verifier unverified | Spike built only `webpki-roots` | `cargo deny` or a release target fails late; on CA-less containers TLS fails | Low | Medium | Re-spike with ureq `platform-verifier`: `cargo deny check`, `cargo tree -i webpki-roots` (expect empty), six targets in CI. A CA-less trust store is a fixed, non-retried refusal ("no trusted root certificates on this system") | CI matrix; refusal text | — | Low | Low |
| T14 | Runtime | Proxy behaviour unstated | ureq 3.5's default config reads `ALL_PROXY`/`HTTPS_PROXY`/`HTTP_PROXY` (incl. SOCKS) (`ureq-3.5.0/src/config.rs:1073`, `src/proxy.rs:232-249`) | Surprise routing. TLS is end to end through `CONNECT`, so values are not exposed | Low | Medium | State it: honour `HTTPS_PROXY`/`NO_PROXY`; the `--verbose` line says "via proxy <host>" (no credentials) | Verbose line | — | Low | Low |
| T15 | Technical | Unconfigured or revoked slots treated as present | Zonetico lists **every** slot (`platform_admin.rs:343-364`): never-configured at version 0 / `NOT_CONFIGURED`, revoked at version > 0 / `REVOKED` (`platform_console.rs:526-535`) | `status` calls an empty slot present; `plan` may skip it or misreport it | Medium | High | Declared `absent = ["CONNECTION_STATUS_NOT_CONFIGURED", "CONNECTION_STATUS_REVOKED"]`; such entries are **absent** in `Store::list`, but their version is kept inside the adapter for `expected_version`. Remote names not in `names` are dropped from `list` | `plan` shows "missing → will write" | — | Low | Low |
| T16 | Technical | `expected_version` from the wrong listing | `StagedStore::write` receives no versions (`src/ports.rs:41`) | A re-list inside `write` narrows the protected window | Low | Medium | The adapter keeps the versions from its own `list()` (the plan's list A; the same `Ports` instance runs prepare and write, `src/app/sync.rs:448`) in a `RefCell`; `write` refuses a name it has not listed (opv bug) | Conflict surfaces as `target_changed` | — | Low | Low |
| T17 | Runtime | Partial batch leaves writes unrecorded | `store.write(&batch)?` (`sync.rs:1128`); same as GitHub today (`src/adapters/github/gh.rs:157-163`) | False drift for opv's own earlier writes in the batch until the next sync | Medium | Medium | Accept the existing behaviour for v1 (same as GitHub); the `Partial` cause names the written keys (`write_failure(.., &written)`); the next sync re-lists and re-records | `Partial` names done keys; drift line | — | Medium | Medium (see Iteration 2) |
| T18 | Technical | Receipt "basis" promise | No field in `Receipt` (`src/domain/delivery.rs:38-58`) | A schema change or an unkept promise | Low | High | Drop the claim; document "version = change counter, equality not proven" in usage, as for GitHub `updatedAt` | Docs | Simplify | Low | Low |
| T19 | Technical | Version counter misses a change | A DB edit keeping the version; Zonetico has no value digest (`recon-zonetico-api.md` §3.4) | Drift undetected | Medium | Low | Accept for v1 (Q4): every API write path bumps (`0095_system_portal.sql:191-192,219`), verify does not (`:208`); a server-side keyed digest is a later optional requirement | — | — | Low | Low |
| T20 | Technical | Server text leaks part of a value or injects terminal control | Truncating before scrubbing leaves an unmatched prefix; ANSI or control bytes in `grpc-message` | Partial value or a spoofed terminal | High | Low | Order: percent-decode `grpc-message` → scrub all registered values (`src/scrub.rs`) → strip control characters → truncate to 200 chars. Unit test with a value straddling position 200 | Test; `--verbose` never shows bodies | — | Low | Low |
| T21 | Technical | Token echoed without its `Bearer ` prefix is not scrubbed; header injection | Item field holds `Bearer <token>`; scrubber matches whole needles | Token in an excerpt; CR/LF splits a header | Medium | Low | Item field `token` (concealed) holds the bare token; opv prepends `Bearer `; register the token. Refuse any credential with control characters at sign-in (value-free) | `deploy_credentials_failed` `WrongType`-style problem | — | Low | Low |
| T22 | Runtime | Unbounded reply / slow server | No cap stated | Memory or time blow-up | Low | Medium | Cap the reply body like `OUTPUT_CAP` (`src/runner.rs:300`); deadlines inside the run budget (T1) | `UnexpectedOutput`/over-cap | — | Low | Low |
| U1 | UX | `sync` fails on a transient provider status | Design §6: non-healthy after put fails. `UNAVAILABLE` covers a provider outage, and an order dependency: `stripe-connect-client` needs the Connect key first (`platform_admin.rs:556-568`) | Spurious failed syncs; people learn to ignore failures | Medium | Medium | Only declared `rejected` statuses (`CONNECTION_STATUS_REJECTED`) fail (T5). `UNAVAILABLE`/`UNVERIFIED` is a note naming the key (answers **Q5**) | Note line; `--json` carries it | #35 Parameter change: severity per status | Low | Low |
| U2 | UX | A key that Zonetico rejects replaces a working key | Save commits before verifying (`platform_admin.rs:608-617`); a rejected key is never used (`:667-678`) | That provider (payments, LLM) stops in production until fixed | High | Medium | **opv:** `Store::refusal` implements Zonetico's fixed rules (trimmed length 16..65536, no control chars, `platform_admin.rs:595-598`); contract shape rules for Stripe keys (`sk_`/`rk_` mode, `whsec_`) refuse before any write (FR-22 path, `src/ports.rs:31-33`); `sync` fails loudly on `REJECTED` (T5). **Zonetico (Z7):** a save must not displace a usable key with one its provider rejects (verify, then commit), or offer a validate-only call | `target_unhealthy` exit 5; Zonetico console | Contradiction: "verify needs the provider" vs "opv must not hold provider logic". **#10 Preliminary action** placed in Zonetico | High | Low (opv-side only) |
| U3 | UX | Short or whitespace values refused mid-batch | Zonetico trims and refuses < 16 chars (`platform_admin.rs:595-598`) | Partial batch (T17) | Low | Medium | Same `Store::refusal` rules as U2 → shown by `status`/`plan` before any write; `no_surrounding_space` rule per §10 | Refusal row in `plan` | — | Low | Low |
| U4 | UX | Machine token expires | Bearer JWT with `exp` (`services/api/src/lib.rs:150-164,174-191`) | All syncs fail | Low | Medium | Z3: bounded lifetime with a rotation runbook; 401 → `deploy_credentials_failed` naming the item | Exit 7 | — | Low | Low |
| R1 | Runtime | Interrupt during a put | Ctrl-C after send | Wrong "nothing changed" | Medium | Medium | Under T1 the runner records the write start (`WRITES_STARTED`, `src/runner.rs:2014`) | `interrupted` with `writes_started: true` | — | Low | Low |
| R2 | Runtime | Retire revokes a production key | `remove` → `RevokePlatformConnection` (`0095_system_portal.sql:219`) | Provider outage | High | Low | **Removed** (C12): retire refused for this target before any write (design's own fallback) | Refusal naming the target | Simplify | Low | Low |
| P1 | Project | No non-interactive identity exists; a naive bypass widens access | Every RPC is gated by `owner_gate` (aal2 + TOTP, `services/api/src/connections.rs:128-137`), which is **shared** with agency and business connection owners (`:124-127`). Save needs a TOTP from the last 5 minutes (`platform_console.rs:997-1003`). `operator()` is the same gate for **all** console RPCs (agency notes, tiers: `platform_console.rs:837-840,982-987`) | Feature unusable; or a TOTP exemption in the shared gate opens agency/business endpoints and every console RPC to the token | High | Medium | Requirements Z1–Z9 (below) in §10; opv ships the target documented "requires application support" and the live canary is a release gate (P2) | #844 checklist; live canary result | — | High | Low (Medium: see Iteration 2) |
| P2 | Project | Sim replies invented | "Replies are recorded, not invented" (`docs/design/error-catalog.md:629-633`); plan builds the sim (step 5) before any live call (step 6) | The fake disagrees with tonic-web (T8) and the matrix proves the wrong thing | Medium | High | Reorder: record success, trailers-only errors (unauthenticated, permission denied, conflict, invalid argument) and list replies from a **local Zonetico API run** (same tonic-web stack) into `tests/fixtures/https/` before the sim. Re-record on staging after #844 | Fixture provenance file; a manual contract re-run | — | Low | Low |
| P3 | Project | Coverage gate | `ChangedBeforeWrite` is `UNREACHABLE` because the sim world never changes between reads (`tests/e2e/coverage.rs:76-81`); design scenario "concurrent change refused" | Gate inconsistency | Low | High | New `opv-sim` fault "version bumped before put" for HTTPS writes; remove the `UNREACHABLE` entry in the same change | Coverage gate | — | Low | Low |
| P4 | Project | Over-scope | JSON codec, `Codec` trait, two generators, `remove`, status everywhere | Schedule slip; dead paths against FR-60 (`docs/design/requirements.md:151`) | Medium | High | Phase 1 cuts (C4, C5, C10, C11, C12, C13) | Plan size; review | Simplify | Low | Low |
| P5 | Project | Local release gate (Q3) | `ring` compiles C; local cross clippy has no target C compilers (`spike-http-client.md` per-target table) | Local gate always red | Low | High | CI is the gate for non-native targets (clippy runs natively on macOS/Windows, `.github/workflows/ci-checks.yml:16-30`; musl via zigbuild in release). Local gate: native clippy + `cargo zigbuild` for musl if wanted. Answers **Q3: acceptable** | CI matrix | — | Low | Low |
| P6 | Project | Pinned descriptor diverges from the server | Zonetico renumbers or reuses a field | Wrong encoding (the value could land in another field) | High | Low | Z8: never reuse field numbers (`reserved`), republish per change; opv refuses replies missing role fields; the value field must keep the pinned number and type | `TargetRefused` naming the field path | — | High | Low (Medium: see Iteration 2) |

### Remaining Risks After Iteration 1

- **High:** none.
- **Medium:**
  - U2: Severity High / Probability Low with opv-side controls only.
  - P1: Zonetico dependency.
  - P6: High / Low.
  - T17: Medium / Medium as residual.
- **Low:**
  - T1–T11, T13–T16, T18–T22, U1, U3, U4, R1, R2, P2–P5.
  - T12 is recorded as out of opv's scope (owner decision 4).

### Iteration Summary (1)

- **Key mitigations applied:**
  - HTTPS as a runner effect (T1, T2, R1, T22).
  - Put classification: refusal vs outcome unknown (T7), with a declared conflict code (T6).
  - Trailers-only parsing (T8).
  - Descriptor-path reduction and append-encoding (T9, T10).
  - Strict URL parsing (T11).
  - Absent statuses (T15).
  - A post-record health hook (T5).
  - `Store::refusal` with Zonetico's rules (U2, U3).
  - Recordings before the sim (P2).
- **Simplifications applied:** removed C4, C5, C11, C12, C19 and status in read commands; demoted C10.
- **Trade-offs introduced:**
  - The runner gains a non-process effect. TRIZ #24 Intermediary: one policy path, two attempt kinds.
  - Credentials become required fields (T3). Less general, simpler.
- **Reason for continuing:** four Medium residuals.

### Iteration 2 Risk Table

| Id | Domain | Failure Mode | Cause | Effect | Severity | Probability | Mitigation (Poka-Yoke) | Observability | TRIZ Resolution | Residual Severity | Residual Probability |
|---|---|---|---|---|---|---|---|---|---|---|---|
| U2 | UX | A key Zonetico rejects replaces a working key | As Iteration 1 | Provider outage in production | High | Low | **Z7 adopted:** Zonetico verifies before it commits (or keeps the previous usable key on `rejected`), so a save never makes the slot unusable. Further opv-side options were considered and rejected: verifying keys against providers inside opv (a divergent copy of Zonetico's `check`, `platform_admin.rs:457-577`, against the code-change rules), and auto-rollback by re-putting the previous 1Password version (opv does not know that the stored value was that version; adds a write path) | Sync `target_unhealthy`; Zonetico audit `platform.connection.rejected` | **#10 Preliminary action** in the system that owns verification | Medium (with Z7: Low) | Low |
| P1 | Project | Identity not delivered or too broad | As Iteration 1 | No consumer, or over-privileged token | High | Medium | Requirements Z1–Z6 stated as acceptance criteria of #844. opv's own release does not depend on #844: the target is complete against recordings and the sim. The **live canary on staging** (canary keys, design §11 step 6) is the gate before any production section is added | Canary run report; #844 review | Separation in time: build opv now, enable per environment later | Low (for opv) | Medium (for the end-to-end goal: Zonetico schedule) → overall Low |
| P6 | Project | Descriptor divergence | As Iteration 1 | Value encoded into a wrong field | High | Low | Add a load rule: the value field's **number and type** are pinned in config (`put.value = { field = "secret_value", number = 3, type = "bytes" }`) and must match the descriptor. Z8: field numbers never reused. On reply, every role field must decode with its declared type or the call is `TargetRefused` | Load error naming the field; reply refusal | #11 Beforehand cushioning | Low | Low |
| T17 | Runtime | Partial batch unrecorded | As Iteration 1 | False drift until the next sync | Medium | Medium | Order writes so that a refusal is likely before the first write (U3's `Store::refusal` runs in `plan`/`validate`, `src/ports.rs:39`). The residual cases are a conflict or an outage mid-batch. The next sync re-records. Making core record partial evidence is a cross-target change (Fly/GitHub too), out of this design's scope; filed as a follow-up | Drift line names keys; `Partial` lists done keys | — | Low | Medium → Low (bounded: self-heals on the next sync, no value risk) |

### Remaining Risks After Iteration 2

- **High:** none.
- **Medium:** U2, **only if Zonetico does not adopt Z7** (with Z7: Low).
- **Low:** all others; T12 is recorded as out of scope (decision 4).

### Iteration Summary (2)

- **Key mitigations applied:**
  - Z7 placed in Zonetico (U2).
  - Value-field number and type pinned (P6).
  - Canary gate and #844 acceptance criteria (P1).
  - Partial-batch bounded and filed (T17).
- **Simplifications applied:** none new. The cross-target "record partial evidence" change was deliberately *not* added (scope).
- **Trade-offs introduced:** U2's final mitigation moves work to Zonetico (see Conflicts, decision 3).
- **Reason for stopping:** no High remains. The only possible Medium (U2 without Z7) cannot be lowered inside opv without duplicating provider verification (a divergent implementation) or adding an unsafe rollback write path. Both violate the constraints.

---

## Requirements Zonetico's machine identity must meet for opv's guarantees to hold

These are requirements, not a Zonetico design.

- **Z1. Scoped TOTP exemption.** The non-interactive identity kind is accepted without aal2 or TOTP
  only in `operator()` for the platform-connection RPCs. It must **not** be accepted in the
  shared `owner_gate`, which also gates agency and business connection owners
  (`services/api/src/connections.rs:124-137`).
- **Z2. Least privilege by method.** The identity may call `ListPlatformConnections` and
  `SavePlatformConnection` (Verify optional) and nothing else on `PlatformConsoleService`: no
  revoke, no agency, tier or config RPCs. Today one `operator()` check gates them all
  (`platform_console.rs:837-840`).
- **Z3. Credential properties.**
  - Revocable server-side (a registry like `platform_sessions`, `lib.rs:183-184`).
  - A bounded lifetime with a rotation runbook. The token is stored only in 1Password.
  - **Environment-scoped:** a staging token is rejected by production. This makes a cross-environment mix-up fail closed with 401, which answers **Q2**: no extra `environment` field is needed.
  - Accepted from `Authorization: Bearer` alone. No cookie, CSRF, `Origin` or binding headers, because opv cannot add headers by design.
- **Z4. Audited as itself.** Audit rows name the identity, distinct from any person
  (`0095_system_portal.sql:187` `platform_operator_identity`).
- **Z5. No portal sign-in, central host only.** The identity cannot sign in to any portal and is
  accepted only on the central host. Host-kind checks happen today only at sign-in
  (`recon-zonetico-api.md` §4.5).
- **Z6. Access token.** A Cloudflare Access service token per environment, in a policy scoped to
  the API host.
- **Z7. A rejected key never displaces a usable one.** A save never leaves a slot unusable because
  of a key its provider rejects (verify before commit, or keep the previous key), or Zonetico
  offers a validate-only call.
- **Z8. Stable wire contract.**
  - Stable error codes: conflict stays a documented code (today `ALREADY_EXISTS`).
  - Error text never contains key material (true today: `platform_admin.rs:31-55`).
  - Field numbers are never reused.
  - The descriptor set is published with every API change.
- **Z9. Unchanged semantics.** `version` is bumped by every value change (save, revoke) and only
  by those (true today: `0095_system_portal.sql:191-192,208,219`).

---

## Phase 3: Systemic Risk Review

- **Calibration Risk.** No scores or confidences are used. The calibrated element is the mapping
  from gRPC code and status enum to cause. It is calibrated against **recorded** replies
  (P2: a local Zonetico run now, staging after #844), not against assumptions. Two assumptions in
  the draft (`ABORTED` for conflict, an in-body trailer) were wrong or unproven on inspection. That
  is why recordings come before the sim. Re-validate on every Zonetico API change (Z8): the
  descriptor hash changes, so opv's config change is reviewed.
- **Observability Risk.**
  - Bad decisions (a wrong cause): e2e cells per status code over recordings.
  - Incorrect extraction (wrong field): role fields are type-checked at load and on every reply.
  - Premature completion (a write reported done that did not land): `confirm()` re-lists after
    writes (`src/app/sync.rs:2377-2410`), and the version is recorded from that listing.
  - Unknown outcomes: exit 9 with the key named.
  - Policy regressions:
    - the `Observed` sealing guard (`src/cause/mod.rs:40`);
    - the coverage gate (`tests/e2e/coverage.rs`);
    - the snapshot canary for values and the `masked_key` fixture tail;
    - a source guard against JSON in the codec.
  - In production: `status --fail-on-drift` (exit 8) in the nightly workflow
    (`src/app/ci_workflow.rs:256`), and Zonetico's audit log of the identity (Z4).
- **Complexity vs Utility Risk.** Before the cuts, the draft carried two codecs, a trait, two
  generators, a remove path, and status plumbing through four commands, all for one consumer.
  After the cuts, the simplest viable version is: one provider, one concrete gRPC-Web module, one
  runner effect, one defaulted store hook, and three config sections (`http`, `names`, `list`/`put`).
- **Oversimplification Risk.** Checked whether any cut loses a critical capability:
  - Retire stays possible by hand, and revoking is destructive anyway (SR-6, `docs/design/requirements.md:1106-1110`).
  - JSON has no consumer.
  - Health stays visible in Zonetico's console and at sync.
  - Equality-proof (digest) remains optional later.
  - The generator is a convenience.

  No critical capability is lost. The **host two-key check and descriptor pinning were kept**
  even though they are "extra", because each is a one-line fail-fast check against
  High-severity effects.
- **Incremental Delivery Risk.** The work can be phased, and each phase is reversible:
  1. Runner HTTPS effect (real and fake attempt) plus recordings.
  2. gRPC-Web module (descriptor load and pin, append-encode, trailers-only and in-body parsing,
     field-path reduction).
  3. Provider plus the `check_written` hook, catalog mapping, strict URL parsing, required
     credential fields.
  4. opv-sim `https` from recordings, the new fault, and the coverage-gate update.
  5. Docs.
  6. Staging canary after #844.

  Rollback: remove the target section, and the owner's importer keeps working. The runner effect
  is inert without a configured target.

### Final Outcome

- **High risks:** 34 failure modes in Iteration 1; **12 High** at the start, **0** at the end.
- **Medium risks:** **14** at the start; **0** at the end if Zonetico adopts Z7. Otherwise **1**
  (U2), which cannot be lowered further inside opv without a divergent copy of Zonetico's provider
  verification or an unsafe rollback write path, both of which break the method's constraints.
- **Low risks:** 8 at the start; all remaining failure modes at the end (T12 recorded as out of
  opv's scope per owner decision 4).
- **Verdict:**
  - **Secure:** yes, with the required changes. The value path is SR-1/SR-3/SR-8 compliant once T9, T10, T20 and T21 are applied. The destination is integrity-checked (T11, C9). Credentials are header-only through the existing login channel.
  - **Feasible:** yes, but **not as drafted**. T1 (runner placement) is a hard prerequisite: without it the design's own error table cannot compile under opv's sealing rule.

Verification checklist (method): architecture judged before mitigation ✔; components classified ✔;
simplification used as mitigation (C4, C5, C11, C12, C13, C19) ✔; all four domains ✔; full FMECA
fields per row ✔; observability per mitigation ✔; iterated to stop condition ✔; no unnecessary
complexity added (one runner effect, one defaulted hook) ✔; no fabricated numbers (none used) ✔;
no critical capability lost ✔.

---

## Conflicts with owner decisions

1. **Decision 2 (two wire formats).** Not a conflict in substance; Phase 1 decides as allowed.
   Recommend **deferring the JSON codec and the `Codec` trait** until a JSON consumer exists:
   - no consumer;
   - FR-60 "one way only" (`docs/design/requirements.md:151`);
   - the code-change rules forbid parallel abstractions without a consumer.

   The owner decides.
2. **Decision 3 (Zonetico keeps its existing RPCs).** Requirement **Z7** changes the behaviour of
   the existing `SavePlatformConnection`: verify before commit, or keep the previous usable key.
   Without it, risk U2 stays Medium: one wrong value in 1Password takes a production provider down
   until fixed (`platform_admin.rs:608-617,667-678`). Alternatives for the owner:
   - (a) adopt Z7 inside the existing RPC (signature unchanged, behaviour changed);
   - (b) add a separate validate-only RPC that opv calls before saving (a new RPC, contrary to the decision);
   - (c) accept U2 as a Medium residual risk.

   Z2 (method allowlist for the identity) and Z1 (exemption scoped to `operator()`) are additions
   inside Zonetico's auth, not RPC changes, so they do not conflict.
3. **Decision 1 (built-in, not an adapter binary).** No conflict. Note that "built-in" must still
   mean **through the `CommandRunner`** (T1). An in-process client beside the runner is
   infeasible under opv's `Observed` sealing rule (`src/cause/mod.rs:36-40`).
4. **Decision 4 (access control is 1Password's job).** No conflict. T12 (one actor holding both
   repo write and a CI-readable vault) is recorded as out of opv's scope, as instructed.
5. **The design's own "generated from the schema" principle (its §1 item 2; not among the four
   decisions given to this review).** Recommend demoting the descriptor generator and removing
   `--names-from` for v1 (C10, C11). If the owner considers generation a decision, keep only the
   descriptor generator.

---

## Required design changes

Each change is tied to a risk id. Apply in this order.

1. **(T1, T2, R1, T22) Put HTTPS inside the runner.** Replace the standalone `HttpTransport`
   with an HTTPS effect of `CommandRunner` that shares `read_on`/`write_on`, observation
   (`Observed` with program `https`), the run budget, `wrote()`, the verbose line, and a reply cap.
   - Real attempt: ureq + rustls.
   - Fake attempt (`cfg(feature = "fake")` + `OPV_SIM_WORLD`): `opv-sim https`, with the request on stdin.
   - Credential headers come from the http `DeployLogin::env("https")` through `EnvRunner::extra`.

   Rewrite §9 and §11 step 1 accordingly.
2. **(T7, T6) Rewrite the put column of §8.**
   - Refusals only for `UNAUTHENTICATED`/`PERMISSION_DENIED` (exit 7), `INVALID_ARGUMENT` (exit 5)
     and the declared `put.conflict` codes (`target_changed`, exit 5; Zonetico: `ALREADY_EXISTS`).
   - Every other outcome after the request is sent is `WriteOutcomeUnknown` (exit 9).
   - Remove `ABORTED`/`FAILED_PRECONDITION` as built-in conflict codes.
3. **(T8, P2) gRPC-Web parsing.**
   - Read `grpc-status` from the response headers (trailers-only) and from a body trailer frame.
   - Require the `application/grpc-web[+proto]` response type.
   - Refuse compressed frames and `grpc-web-text`.
   - Build unit and e2e fixtures from **recorded** Zonetico replies (a local run now, staging later) before the sim.
4. **(T9, T10, P6) Value and reply handling.**
   - Field roles become descriptor field paths, type-checked at load. Read them from the decoded message, never through JSON (with a source guard).
   - Encode the template without the value, then append the value field (tag, length, bytes) into the `Zeroizing` buffer.
   - Pin the value field's number and type in config.
5. **(T4, T5, T15, T16, U1) Store semantics.**
   - `absent` statuses (`NOT_CONFIGURED`, `REVOKED`) are absent from `list`, with their version kept internally.
   - Unmapped remote names are dropped.
   - `expected_version` comes from the adapter's cached list A.
   - `write` returns `Ok` for any accepted write.
   - Add the defaulted `StagedStore::check_written` hook after `record_delivery` (`src/app/sync.rs:1134-1153`). It fails only on declared `rejected` statuses; others are a note.
   - Remove status from `plan`/`status`/`history`/`delivery verify` (§2 table, §6 last bullet).
6. **(P4, R2, T18) Cut scope.**
   - Remove the JSON codec, the `Codec` trait, `--names-from`, the `remove` operation (retire is refused for this target), and the receipt "basis" sentence.
   - Defer `opv propose target http --descriptor`.
7. **(T11) Strict destination parsing.**
   - Parse `base_url` once: `https` only, no userinfo/port/query/fragment/IP, lowercase ASCII host with no trailing dot, safe path segments.
   - Compare the host with `http.host`, then build the request URI from the same parsed value.
   - `target_locator` = host + the literal scope fields of the list request (operator id).
8. **(T3, T21) Credential item.**
   - Fields: `base_url` (text), `token` (concealed, bare token; opv adds `Bearer `), `cf_access_client_id` and `cf_access_client_secret` (concealed, **required**).
   - Register the token with the scrubber.
   - Refuse control characters in any credential.
9. **(U2, U3) `Store::refusal` implements Zonetico's fixed value rules** (trimmed length 16..65536,
   no control characters) so `plan` shows them before any write. Recommend Stripe shape rules
   (`sk_`/`rk_` mode, `whsec_`) in the contract for these keys.
10. **(T20) Server text.** Percent-decode, then scrub, then strip control characters, then
    truncate to 200. Add a test with a value straddling the cut.
11. **(P3) Coverage.** Add an `opv-sim` fault "version bumped before put" and remove
    `ChangedBeforeWrite` from `UNREACHABLE` (`tests/e2e/coverage.rs:76-81`) in the same change.
12. **(T13, T14) TLS and proxy.**
    - Re-spike with ureq `platform-verifier`: `cargo deny`, `cargo tree -i webpki-roots`, six CI targets.
    - Give a fixed refusal when the OS store is empty.
    - State that `HTTPS_PROXY`/`NO_PROXY` are honoured, and show "via proxy" in `--verbose`.
13. **(P1, U2, P6) Replace §10 items 1–3 with requirements Z1–Z9.** Make the staging canary run
    (canary keys) the gate before any production section is configured.
14. **(P5) Answer Q3 in the doc.** CI (native macOS/Windows clippy; zigbuild musl) is the gate for
    non-native targets; the local gate runs native checks only.
15. **(Q2, Q4, Q5) Close the open questions.**
    - Q2: no `environment` field; Z3 environment-scoped tokens plus the host check suffice.
    - Q4: the version counter is accepted for v1; a server-side digest is optional later.
    - Q5: fail only on `REJECTED`; `UNAVAILABLE`/`UNVERIFIED` warn.

## Owner decisions on this review (2026-10-21)

- **U2 / Z7:** adopted. Zonetico's #844 must meet Z7 (a rejected key never displaces a usable
  one), so U2's residual risk is Low.
- **C10, the descriptor generator:** kept in 0.16.0 by owner decision, over this review's
  demotion. It is built off the critical path and must pass the same load rules as hand-written
  configuration.
- **C4/C5, the JSON codec and the codec trait:** deferred, as recommended. The owner had delegated
  this Phase 1 call to the review.
- All other required design changes are applied in `http-target.md`.
