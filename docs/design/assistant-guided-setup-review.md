# Review: assistant-guided configuration (North Star and gap analysis)

Reviewed: `docs/design/assistant-guided-setup.md` at `9430f9c` (branch `v0120/design-assistant`, code identical to v0.11.0).
Procedure: the owner's DESIGN-FMECA (Phase 1 architecture validity, Phase 2 FMECA + poka-yoke + TRIZ until no High or Medium remains, Phase 3 calibration and delivery).
Reviewer: independent agent, 2026-10-18. The design doc is unchanged, and nothing is committed.

The document is judged as a North Star plus a gap analysis, not as an implementation spec. Claims about current opv were checked against the code and docs. Evidence is `file:line` in this worktree.

**Assumptions** (stated because the doc or repository doesn't settle them):
- **A1.** `opv_ready` over MCP reads item values to evaluate rules. The MCP read-only runner refuses writes, not `op item get` reads, and the ready receipt carries `key_failed_rule` per key. This comes from reading the code; an e2e test against opv-sim should confirm it (finding H1).
- **A2.** The 1Password CLI's desktop-app integration authorizes a session, not each read. Once authorized, it lasts until an inactivity timeout. This is 1Password's documented behaviour, not something this repository records. The repository only records the 60-second approval wait (`docs/mcp.md:190`).
- **A3.** The assistant runs as the same OS user as the person, with the same `op`, `flyctl`, `kubectl`, `az` and `gh` credentials on its PATH. This is the doc's own threat model (§1, "the honest limit").

## Summary

| Severity | Count |
|---|---|
| High | 4 |
| Medium | 14 |
| Low | 11 |

All of them reach Low residual risk through the design changes below, except **H3**. H3 is a documented, accepted Medium: an assistant that can edit and run the application with real values can't be stopped without OS isolation, which is outside opv's constraints.

The North Star's shape is sound: value states in place of values, content-addressed plans, deterministic `next`, contract with the code. The serious problems are these:
1. **Oracles.** Several proposed states and existing outputs are comparisons the assistant can steer. The worst is assistant-written validation rules: today's `opv_declare_key` plus `opv_ready` already give an assistant an arbitrary-predicate oracle over every stored value.
2. **`opv run` redaction (P-5/G27)** rests on a wrong premise and a misread of the 0.10.0 lesson.
3. **The honest limit** names only `op read`, but the larger channels are the application itself and the platform CLIs.
4. **The gap analysis** has about a dozen rows whose 0.11.0 column or status is wrong. Most of them understate what exists.

---

## Phase 1: architecture assessment

| Component | Purpose | Classification | Justification | Simpler alternative | Risk if removed | Evidence level |
|---|---|---|---|---|---|---|
| Invariant V and value-free surfaces | No value or partial value reaches an assistant | **Essential** | The objective itself | — | Objective fails | Proven (SecretValue, canary scan, layered scrub) |
| Value states (§3.3) | Tell "is it filled and plausible" without the value | **Essential**, trimmed | Replaces inference from silence (#174) | Drop `.env.example` equality, and make `suspect` advisory (H2, M7) | The assistant can't guide | Adapted |
| `suspect` sub-signals (entropy, same as lower tier, live/test, localhost) | Catch plausible-but-wrong values | **Useful** (advisory only) | Existing health findings prove the value of these (`health.rs`) | Keep today's settings-health warnings as reasons | Fewer catches | Proven (existing), Speculative (entropy) |
| Contract in the repository (§2.2, C9) | Contract reviewed with the code | **Useful**, split | Code/contract drift is real | Contract (keys, attributes) in the repository; **bindings and policy relaxations** approved and recorded by the owner (M4) | Drift between code and contract | Adapted |
| Key attributes: kind, scope (personal) | Channel, per-person values | **Essential** (exist) | — | — | — | Proven |
| Key attribute: source | Say "needs a person" | **Useful** | Lets `next` name the actor | Derive it from existing `from`/`generate` rules, plus a `person` default | `next` less precise | Adapted |
| Presence `all` / `except` | Consistency across environments | **Essential** (#179 owner decision) | — | — | Gaps by accident | Adapted |
| Shape catalog (G9, G19) | Kind, shape and guidance for known providers | **Useful**, advisory | Removes guesswork | Catalog shapes produce `suspect`, never `malformed`, unless the person approves them (M8) | More manual rules | Speculative (drift) |
| Lifecycle / retire | Removal as a state | **Useful** | Today's three manual steps (#179) | #179's `opv retire` plan | Orphans | Adapted (prune order exists) |
| Rotation period / expiry | Expiry warnings, rotation plans | **Speculative**: demote to phase G | No demonstrated need in the issues | `expires_at` metadata only, later | — | Speculative |
| Ordered lanes and tiers | Gate order, tier policy | Tier **Useful**; lane ordering **Speculative** | `confirm_env` already marks guarded environments | Tier = `local`/`shared`/`production` on the environment; no global ordering until rotation needs it | — | Adapted |
| Ephemeral environments | Preview and per-engineer environments | **Speculative**: keep in H | Personal keys cover per-engineer values | — | — | Speculative |
| Tier policy | What must differ in production | **Useful**, non-blocking unless declared (M7) | — | Today's warnings, plus one declared rule | — | Proven (warnings) |
| Inventory matrix (#174) | Keys × environments with state | **Essential** | Core of "full visibility" | Extend the existing `opv ui` key table and the `ready` grid to JSON/MCP | Objective fails | Proven (TUI exists) |
| `opv needs` scanner (#175) | Code ↔ contract comparison | **Useful** (near-essential) | Lets the assistant tie app to contract | Assistant-supplied `--names` first; scanner second | The assistant must grep | Adapted |
| `opv detect` (G18) | Components, environments, targets from the repository | **Speculative**: demote | The assistant reads a repository well; the deterministic value is in **validating** a proposal, not in producing it | `opv_declare_*` validation plus `opv_configuration` | Small | Speculative |
| Five verbs (§4.1) | One shape for every capability | **Useful** as a *documentation and envelope* rule; **Unjustified** as a second command surface | Without a migration and removal plan it is a parallel abstraction (M14) | Keep the existing commands and add the typed envelope to them | — | Adapted |
| Typed envelope and `next` | No prose parsing | **Essential** | Mostly exists (`actor`, `next_kind`, `human_required`) | Extend what exists (M6) | — | Proven |
| `opv next` | One action | **Useful** | `ready` already computes it (`ready.rs:162-202`) | Alias of `ready`'s `next` | — | Proven |
| One setup plan (G23) | One approval for setup | **Useful** | Today it is 5–6 commands | Compose the existing structure plan, declarations and target plans under one `plan_id` | — | Adapted |
| Person-only steps inside `approve` (G24, C3) | Run imports and masked entry at approval | **Speculative**: demote (M3) | It has an ordering contradiction and widens `approve` | `approve` stays approve-only; `next` lists `opv set` / `opv adopt --apply` | — | Speculative |
| `opv set` (masked) | Value entry outside the 1Password app | **Useful** | `masked.rs` exists | — | The person uses the 1Password app | Proven (setup prompt) |
| Agent mode | No prompts, refusals that name the person | **Useful** as UX; **Unjustified** as a security control (M2) | Spoofable by `env -u` | TTY checks (exist) plus marker hints | — | Adapted |
| `opv run` encoding redaction (P-5) | Mask injected values in child output | **Useful**, re-scoped (H4) | `op run` already masks exact values | Secret-kind ≥ 8 bytes only, in the local delivery step, unconditional | — | Speculative as specified |
| Harness guard rules (P-4) | Deter `op read` in the assistant's shell | **Useful** (deterrent) | Cheap | — | — | Adapted |
| Free-text screening (P-2) | Stop values pasted into guidance or rules | **Useful**, pattern-only (M13) | — | Grammar-first; patterns for the rest | — | Adapted |
| Sealed `ValueFree` trait (P-1) | Compile-time value-free output | **Speculative** as specified (M1) | Sealing does nothing inside one crate | Capability-gated `expose()` plus the canary scan | — | Speculative |
| Exposure / people reports | Leak response, offboarding | **Useful**, later | — | — | — | Adapted |
| Provisioners | Mint credentials | **Speculative**, later | — | — | — | Adapted (`access --create`) |

### Revised architecture

- **Retained:** Invariant V; the trimmed value states; key kind, scope and presence; the inventory matrix; the typed envelope with `next`; `opv set`; the one setup plan; the harness guard rules; lifecycle/retire; tier policy as warnings.
- **Simplified:**
  - Value states lose `.env.example` equality.
  - `suspect` never blocks.
  - Assistant-supplied rules become closed shape names.
  - The contract is split from bindings and policy relaxations.
  - `opv next` is `ready`'s `next`.
  - `opv run` redaction moves into the existing local delivery step, secret-kind only and unconditional.
  - Agent mode becomes UX only.
- **Removed:** the five-verb *second surface* (keep the envelope rule); the sealed-trait renderer as a phase-A prerequisite.
- **Demoted:**
  - person-only steps inside `approve` (back to separate person commands);
  - `opv detect` (later, as validation);
  - lane ordering, ephemeral environments, rotation period and expiry (phase G/H).

---

## Phase 2: FMECA, iteration 1

Scores are qualitative (Low/Medium/High). "Residual" assumes the change in the last column but one is adopted.

### Iteration 1 risk table

| ID | Domain | Failure mode | Cause | Effect | Sev | Prob | Mitigation (poka-yoke) | Observability | TRIZ resolution | Res. sev | Res. prob |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **H1** | Runtime / security | Assistant extracts a value through validation rules | Rules are predicates the assistant writes (`regex`, `prefix`, `enum`, `not_prefix`, `prefix_by_mode`), and their pass/fail is reported per key | Full value recovery, one predicate per call | High | High | **Prevent:** value states use only a person-approved rule set (below) | Plan diff shows rule changes; refusal code `rules_pending_approval` | Separation in time (#22 preliminary action) | Low | Low |
| **H2** | Runtime / security | Assistant confirms a guess by equality | `.env.example` equality (proposed `placeholder`), `opv adopt` / `init --from` "same / differs" against an assistant-written file, and any free-text check against stored values | Low-entropy values (passwords, hosts, settings) confirmed by guessing | High | Medium | **Prevent:** remove assistant-steerable comparisons from every assistant-readable surface | Canary test of a guess file; a test that output is identical for equal and unequal guesses | Separation by condition (who is asking) | Low | Low |
| **H3** | Security / UX | Honest-limit statement understates exposure | It names only `op read`; the application, platform CLIs and session-scoped authorization aren't named, and §9.4 doesn't exist | The owner over-trusts the guarantees | High | High | **Rewrite the honest limit; limit the blast radius by vault membership per tier** | `opv doctor` reports when the person's own session can read production-tier vaults | Segmentation (#1) of who can read what | Medium (accepted) | Low |
| **H4** | Runtime / technical | P-5 redaction fails or corrupts output | Wrong premise (`op run` already masks), opv holds no values on the run path, short/setting values, offset encodings, an adversarial command, and agent-mode gating | Corrupted JSON logs, or false assurance | High | Medium | **Re-scope** (below) | Unit and property tests per encoding; a run note "N values masked" (count only, per stream) | Intermediary (#24), already present as the local delivery step | Low | Low |
| M1 | Technical | P-1 "prevents" is not true | Sealing doesn't bind inside one crate; `expose()` → `String` → `Name` passes | False assurance; a large refactor (375 `json!` sites in 48 files) blocks phase A | Medium | High | **Capability-gated `expose()`** | trybuild compile-fail test; the canary scan stays | Copying (#26): the `Observed` token pattern | Low | Low |
| M2 | Security / UX | Agent mode spoofed or missed | Env markers are under the caller's control; harnesses that allocate a pty; marker in a person's shell | A security property is bypassed, or a person is refused in their own terminal | Medium | High | **Agent mode is UX only**; security defaults unconditional | Refusal names the marker that triggered it | Separation on condition, with the condition moved to TTY plus 1Password auth | Low | Low |
| M3 | UX / runtime | `approve` with person-only steps fails part-way or runs out of order | §6.1 imports at step 4, but structure is created at step 5; 15-minute TTL; the 1Password 60 s wait | Import into nonexistent fields; a half-claimed approval | Medium | High | **Keep `approve` approve-only**; person steps are separate commands that `next` lists | `next` shows the remaining person steps; inventory shows `absent` | Separation in time | Low | Low |
| M4 | Security / delivery | Contract edits weaken policy or redirect delivery | Repository is the writable source; the assistant writes it; CI syncs on change | Gate passed by `except prod`/`allow_same_value`; values bound to another vault or target | Medium | Medium | **Split contract and bindings; flag policy relaxations** | Plan section "relaxations"; `config check` compares bindings with the approved record | Asymmetry (#4) | Low | Low |
| M5 | Technical | Concurrent writes race | P-22 claims a lock "as for sync today"; none exists | Duplicate or interleaved writes (assistant `apply`, CI sync, person) | Medium | Medium | A real lock, or drop the claim and rely on idempotent convergence plus plan expectation | Lock-held refusal naming the holder; `stale_plan` | Preliminary action | Low | Low |
| M6 | Delivery | Gap analysis misstates 0.11.0 | About a dozen rows (table below) | Work planned for capabilities that exist; risky ones marked "Have" | Medium | High | Correct the rows | Each row carries file:line evidence | — | Low | Low |
| M7 | UX / delivery | `suspect` blocks production falsely | P-11 and §6.4 make `suspect` fail the gate; heuristic signals; conflicts with #177 | Release blocked; pressure to set `allow_same_value` | Medium | Medium | `suspect` is advisory; only declared, approved rules block | Gate output lists advisory reasons separately | Local quality (#3) | Low | Low |
| M8 | Runtime | Catalog drifts from provider reality | Providers change prefixes and console paths | Valid keys reported `malformed`; wrong guidance | Medium | High | Catalog shapes advisory unless approved; entries dated with source | `opv doctor` reports catalog age; `suspect: unrecognized_format` count in the inventory | Cushion in advance (#11) | Low | Medium→Low |
| M9 | UX | Scanner false positives create junk keys | Runtime vars (`PATH`, `NODE_ENV`, `CI`), vendored/test code, dynamic names | Junk keys, and with presence `all` they're required everywhere; the CI gate fails every PR | Medium | High | Built-in ignore list; excluded paths reported in coverage; `ignore` with reason; the gate fails on *new* names only | Coverage section; `undeclared` count per PR | Segmentation | Low | Low |
| M10 | Delivery | Presence `all` delivers local-only keys to production | Default `all` (#179) | The production gate demands a value, so the person fills it with junk or a dev copy, which is delivered | Medium | Medium | The plan for a new key shows each production-tier environment as "value or `except` (reason)"; local-only names suggested from the catalog | Inventory `not_wanted` vs `absent` per tier | Asymmetry | Low | Low |
| M11 | Runtime | Rotation in lane order causes an outage, or "safe to revoke" is wrong | Single-active provider credentials; signing secrets; unknown consumers | Production down, or the old credential revoked while still in use | Medium | Medium | Rotation types (overlap / cutover / independent); report "every *known* delivery holds the new version" | Plan lists unknown consumers (personal items, `from` sharers, other projects) | Segmentation | Low | Low |
| M12 | Delivery | Phases aren't independently shippable as claimed | F depends on A's agent mode; A front-loads the heaviest refactor; B and C overlap on presence; split conflicts with #174–#177 (0.12.0) | Slips; 0.12.0 ships no assistant-visible value | Medium | Medium | Reorder (Phase 3 below) | Each phase's walkthrough metric | — | Low | Low |
| M13 | Security / UX | Free-text screening leaks or misfires | Screening by comparing against stored values is an oracle; entropy detectors flag URLs and IDs; rule parameters are a free-text channel too | Oracle, or legitimate guidance refused | Medium | Medium | Pattern-only screening, never value-matching; rule parameters screened; P-3's schema test names its known exceptions (`rules`, `guidance`) | Refusal `value_in_text_field` with the detector name | Prior counteraction (#9) | Low | Low |
| M14 | Technical | Five verbs create a parallel surface | `setup plan`/`change plan`/`apply` beside `structure plan/apply`, `plan`/`sync`, `add`, `env add` with no migration or removal plan | Two ways to do everything; MCP/CLI parity doubles | Medium | Medium | Envelope rule now; any new verb ships with a deprecation of the command it replaces | `opv schema` lists one command per capability | Universality (#6) | Low | Low |
| L1–L11 | various | see the Low list | | | Low | — | | | | Low | Low |

### Required design changes for the High findings

**H1: the rule-predicate oracle (exists today).**
- **Evidence:**
  - `opv_declare_key` accepts free rules (`src/mcp.rs:86-88`, passed through at `src/mcp.rs:1446-1447`) and writes them to the local file with no approval (`docs/mcp.md:16`, "Changes: local `secrets.toml`").
  - The rule evaluator tests:
    - `prefix` (`src/domain/rules.rs:331-336`);
    - `not_prefix` (`:336-340`);
    - `regex` (anchored, assistant-chosen pattern; `:360-377`);
    - `enum` (`:378-387`).
  - `opv_ready` reports `key_failed_rule` per key, with the key in its scope (`src/app/ready.rs:476`; projection `docs/mcp.md:27-30`).
- **The attack:** a `regex` of `sk_live_a.*`, then `sk_live_b.*`, recovers the value one character per few calls. `.{40}` gives the length. The design makes this worse in three ways:
  - §3.3 `malformed` is the same oracle;
  - C9 makes the assistant-writable file the source;
  - catalog shapes "or explicit rules" (§2.1).
- **Change (add to §3.3, P-3 and C9):**
  1. A value state is evaluated only against rules in the **approved contract**: the rule set's text is part of a `plan_id` the person approved. An unapproved rule change reports the key as `rules_pending_approval` and evaluates nothing.
  2. Assistant-supplied rules are a **closed set of parameterless shape names** (`stripe_secret`, `https_url`, `base64_bytes(32)`, …). Free `regex`, `prefix`, `not_prefix`, `enum` and `prefix_by_mode` come only from a person (CLI in a terminal, or an approved plan).
  3. Add this to Invariant V's text: "a predicate chosen by the assistant counts as a comparison with a guess."
  4. Add a gate test that declares a regex through MCP and calls `opv_ready`. The state must not differ between a matching and a non-matching pattern until approval.
  5. Treat it as a 0.11.x fix, not a North Star item.

**H2: comparison oracles.**
- **Proposed:** `placeholder` includes "equal to the value in `.env.example`" (§3.3; also owner issue #177, `example_value`). `.env.example` is a repository file the assistant edits, so this is an equality oracle with any guess.
- **Existing:**
  - `opv adopt <env> --from <file>` prints `differs` or `same value after the key's rules` for a file the caller supplies (`docs/usage.md:565-567`).
  - `init --from` reports a differing value (`docs/configuration.md:655`).
  - Both contradict G1's "Have" under the doc's own definition of Invariant V, which lists "a comparison with a guess".
- **Change:**
  1. Drop `.env.example` equality. The fixed placeholder list (`src/domain/health.rs:291-317`) plus #177's config-key placeholders cover the intent.
  2. If the owner keeps it: compare only at a person's own `opv adopt` / import, never in the inventory.
  3. Classify `adopt` and `init --from` dry runs as value-bearing person commands: never MCP, listed in the honest limit.
  4. In P-2, require pattern-only screening.
  5. G1 becomes **Part**.
- **Note:** "same value as a lower tier" compares two stored values. The assistant can choose neither side without a store write, which would already let it read, so it stays Low. `docs/usage.md:1027` already discloses it.

**H3: the honest limit.**
- **Replace §1's paragraph with a statement that names every channel:**
  1. An assistant with a shell as the same user can run `op read` while the person's 1Password authorization is active. That authorization covers a session, not each read (assumption A2).
  2. It can read delivered copies with the person's platform credentials: `kubectl get secret -o yaml`, `az keyvault secret show`, `fly ssh console -C env`.
  3. It can edit and run the application under `opv run`, so the application can print any value in any encoding. Redaction catches accidents, not intent.
  4. It can drive `opv approve` through a pseudo-terminal (already stated, `docs/mcp.md:113-118`).
- **Then the one control that holds:** a person whose own session can't read production-tier vaults can't leak production values through any of these channels. Recommend per-tier vault membership. `opv doctor` warns when the person's session can read a `production`-tier vault from a developer machine.
- **Also:**
  - Fix the dangling §9.3, §9.4 and §15 references; the guard-rule design they point to doesn't exist.
  - Relabel P-4 from "detects" to "deters".
- **Residual:** Medium, accepted. Removing it needs OS isolation, which violates the constraint not to oversimplify below domain complexity; opv is not a sandbox. The owner should accept it explicitly.

**H4: `opv run` redaction (P-5, G27, C4, decision 4).**
- **Wrong premise.** The child of `opv run` is not unscrubbed. `opv run` runs `op run`, and `op run` masks the values it resolved in the child's output (`src/app/run.rs:1-12`, `:299`, `:357`; `src/app/local_delivery.rs:21-22`). C4's "opv holds the values, so it can match them exactly" is false on this path: "No value passes through opv" (`run.rs:11`). The real gap is encodings.
- **Misread lesson.** The 0.10.0 lesson was not "bytes vs whole match". It was that matching **short and setting values** corrupts JSON (`true` → `********`) and masks opv's own names (`docs/design/error-catalog.md:364-369`). Masking every injected value, including `PORT=8080`, `NODE_ENV=production` and `LOG_LEVEL=info`, repeats it in the application's own output.
- **Change:**
  1. Do the extra masking in the existing local delivery step, which is `op run`'s child and does hold the values. Make it the step for every local run, not only for products with `[products.<p>.local]`.
  2. Mask secret-kind values of at least `SECRET_MIN` (8) bytes only, with the encodings `scrub.rs` already builds (`src/scrub.rs:213-232`). Hex is not among them today; add it.
  3. Also add the three alignment-offset cores of base64 for values embedded in larger blobs (Basic auth, Kubernetes manifests).
  4. Stream with an Aho–Corasick automaton that holds back only bytes that are a live partial match, so prompts and progress bars aren't delayed.
  5. Apply it **unconditionally** (as `op run` does), not only in agent mode.
  6. State in the honest limit that a command the assistant chooses can defeat any encoding list (H3).
  7. Decision 4 becomes: "redaction is always on, for secrets only."

### Gap-analysis corrections (M6)

| Row | Doc says | Actually in 0.11.0 | Evidence | Corrected status |
|---|---|---|---|---|
| G1 | Have | The canary and scrub layers hold for literal values. Comparisons with a caller-chosen guess are emitted by `adopt`/`init --from` and by assistant-written rules (H1, H2) | `docs/usage.md:565-567`; `src/domain/rules.rs:360-377`; `src/mcp.rs:86-88` | **Part** |
| G2 | "`opv run` passes child output unredacted" | `op run` masks resolved values in the child's output | `src/app/run.rs:1-12`, `src/app/local_delivery.rs:21-22` | Part, with the reason corrected: no guard rules, and no encoding masking |
| G12 | "production is inferred from the name" | True for the live-key warning (`src/domain/health.rs:280-282`). `confirm_env` is a declared per-environment guard used by `sync` and `run` | `src/app/run.rs:28-53`; `docs/usage.md:351-360` | Gap, but name `confirm_env` as the seed of tiers |
| G15 | "findings, not a state per key" | A per-key row state exists: `saved`, `missing`, `failing_rule`, `skipped`, `source_blocked` (`KeyState`). The gaps are `empty`, `placeholder`, `suspect` and `unreadable` per key, and exposure through MCP | `src/domain/plan.rs:53-68`; `src/schema.rs:492`; `docs/usage.md:113-130` | Part (narrower gap) |
| G16 | Inventory matrix: none | `opv ui` shows a keys × environments table; `ready` has a product × environment grid with counts. Missing: a key × environment JSON/MCP document | `src/ui/render.rs:256-319`; `src/app/ready.rs:88-103`; `docs/usage.md:541-551` | **Part** |
| G21 | "`do` is prose; there is no actor" | Ready findings carry `actor` (`owner`, `agent`, `ci`) and `effect`; errors carry `human_required` and `next_kind` (`rerun`, `run`, `check`, `handoff`, `vendor`, `none`) | `src/app/ready.rs:142-170`; `docs/usage.md:726`; `docs/mcp.md:44-52` | Part (the gap is *uniformity* across documents, not the absence of an actor) |
| G22 | `opv next`: Gap, "no single action" | `ready`'s receipt has one `next {actor, command}`: the first blocking finding, else the first | `src/app/ready.rs:162-170`, `:195-202` | **Part** |
| G27 | "the child writes straight to the terminal, unscrubbed" | Masked by `op run` (exact values) | as G2 | Part, with the reason corrected: no encodings |
| G29 | "no per-environment completeness gate" | `sync` refuses (exit 6) while any key is missing or failing; `status <env>` exits 8 on findings | `docs/usage.md:111`, `:913-915`; `docs/how-opv-handles-failures.md:122` | Part. The gap is placeholder/tier policy and a CI recipe, not completeness |
| G35 | "CLI `init --from` (imports values too)" | Also `opv adopt` (dotenv, Key Vault, Kubernetes, GitHub variables), which the doc omits | `docs/usage.md:557-578` | Part; add `adopt` |
| P-22 | "One lock per project and environment for writes, as for sync today" | opv has no lock; serialization is the CI concurrency group | `docs/design/delivery-transports.md:717`; `examples/ci-change-detection/.github/workflows/opv-sync-on-change.yml:8` | Claim false (M5) |
| Summary | Have 4 / Part 21 / Gap 13 | With G1→Part, G16→Part and G22→Part: **Have 3 / Part 24 / Gap 11** | — | — |

Rows verified as stated: G3 to G11 (the `add.rs:37` default, `generate`, `personal`); G13; G14 (`health.rs`; `allow_same_value` already exists, so P-11 should say "existing"); G17; G18; G19 (`kind_guess.rs`); G20; G23 to G26 (`setup_runtime.rs:594`, `masked.rs`; the CLI already refuses prompts without a TTY, `src/main.rs:2863`, `src/app/setup_runtime.rs:507`); G28; G30 to G34; G36 (`opv skill install` ships instructions, not guard rules); G37; G38. The Evidence table's anchors (`health.rs:291`, `add.rs:37`, `setup_runtime.rs:594`, "Prune order") resolve correctly.

### Changes for the Medium findings

- **M1, P-1.** `#[non_exhaustive]` taught that in-crate restrictions need a private constructor (`docs/design/error-catalog.md:233-238`). A sealed trait only stops *other crates* from implementing it, and opv is one crate. Worse, a value leaves the type system at `expose()` (`src/domain/secret.rs:17`, 93 non-test call sites): `Name::new(v.expose())` is `ValueFree`.
  - **Change:** make `expose()` require a capability token (as `Observed` does), constructible only in the sink modules: stdin writers, the rule evaluator, the health comparator and the scrub registry. Prove it with a trybuild compile-fail test.
  - Keep the canary scan as the proof for documents.
  - Apply `ValueFree` builders to new documents only. Don't migrate the 375 `json!` sites as a phase-A prerequisite.
  - Relabel P-1 as "prevents (where values become strings), detects (documents)".
- **M2, agent mode.** `CLAUDECODE`, `OPV_AGENT` and similar markers are in the caller's own environment, so `env -u` removes them. Some harnesses run commands in a pty, so TTY checks miss them. A person's shell can inherit a marker from an IDE.
  - **Change:** agent mode only selects UX (no prompt; return `next.actor = person`).
  - Every security property is unconditional (redaction) or rests on a TTY plus 1Password's own authorization, which `require_terminal` already enforces (`src/main.rs:2863`, `:3712`).
  - A refusal names the marker it saw, so a person can see why.
- **M3, C3/§6.1.** §6.1 step 4 imports `.env` values during `approve`, before step 5 (`apply`) creates the vaults, items and fields they go into. The approval TTL is 15 minutes (`src/approval.rs:19`), and typing several values at masked prompts plus the 1Password app's 60 s waits can exceed it after the approval is claimed.
  - **Change:** `approve` approves. `next` then lists the person's value steps (`opv set`, `opv adopt --apply`) after `apply`.
  - The one-approval property holds for every write; value entry was always separate.
- **M4, C9.**
  - **Change:** the repository holds the *contract* (keys, kind, scope, presence, shape names, guidance).
  - *Bindings* (vault and item IDs, target locators, deploy-identity references) and *policy relaxations* (`except` on a production tier, `allow_same_value`, a removed rule, a tier downgrade) take effect only through an owner-approved plan, recorded in the 1Password manifest.
  - `config check` fails CI when the repository's bindings differ from the approved record. Add CODEOWNERS on the contract file.
  - Least-privilege deploy identities (existing) limit where CI can deliver.
- **M5.** Either add a lock (an item in the state vault, or a per-project file lock) or remove the claim from P-22. Rely on `--expect-plan` and idempotent re-plans, which already exist.
- **M7.** §6.4 and P-11 make `suspect` block production; #177 says new signals warn unless they are a declared rule. Adopt #177's rule: block on `absent`, `empty`, fixed-list `placeholder`, `malformed` (approved rules) and `unreadable`.
- **M8.**
  - Each catalog entry carries the provider, a source URL and a "checked" date.
  - A catalog shape mismatch is `suspect: unrecognized_format` unless the person approved the shape as a rule.
  - Guidance is a link plus one line, with no screenshots of console paths.
- **M9.**
  - The scanner ignores a built-in list of runtime names (`PATH`, `HOME`, `CI`, `NODE_ENV`, …) and excludes `node_modules`, `vendor`, `target`, `dist` and test directories, reporting each exclusion in coverage.
  - The contract can declare `ignore = [{name, reason}]`.
  - The `needs` gate fails on names new in the PR's diff, not on the whole backlog.
  - `undeclared` never auto-declares.
- **M10.** Keep #179's default. A plan that adds a key lists each production-tier environment as "needs a value, or `except` with a reason". The catalog suggests `except` for known local-only names (tunnelling and debugging tokens).
- **M11.** Rotation plans have a type:
  - `overlap`: the provider allows two active credentials. Create, deliver everywhere, verify, then revoke.
  - `cutover`: single active. Deliver and revoke as one step per environment, with the outage window stated.
  - `independent`: tier policy already gives each environment its own value, so there is no lane coupling.
  
  The final report says "every known delivery holds the new version" and lists consumers opv can't see: personal items, other projects that share the value, and copies imported elsewhere. Never "safe to revoke".
- **M12.** See Phase 3.
- **M13.**
  - Screening is grammar-first. Patterns are used only for known token formats and private-key markers; drop raw entropy, which flags URLs.
  - Never compare against stored or registered values.
  - Screen rule parameters (`prefix`, `enum`, `regex`) as well, since a pasted key in `prefix=` is a value in the contract.
  - P-3's "no field carries a value" test must allow `rules` and `guidance` today (`src/mcp.rs:76-92`), or H1's closed shape names must land first.
  - Align the guidance limit: 200 in P-2, 300 today (`src/mcp.rs:1445`).
- **M14.** Keep the existing command names. Add the envelope (`next` kind and actor) to every document. A new verb such as `opv setup plan` is a composition that emits the existing plans under one `plan_id`, and the doc names the commands it supersedes and when they are removed (code-change requirement: no parallel abstractions).

### Low findings

- **L1.** Dangling references: §9.3 and §9.4 (lines 35, 179, 181, 204, 361) and §15 (line 333). Sections 8–10 and 14 don't exist.
- **L2.** P-4's level "detects" should be "deters". Prefix deny rules are bypassed by `sh -c`, by `python -c` and by a wrapper script, and nothing logs a bypass.
- **L3.** Names differ from #179: the doc's `except` vs #179's `exclude`; `ready --gate` vs `--fail-on-missing`; the doc keeps a `retired` declaration, while #179 deletes it after pruning. Pick one name for each.
- **L4.** A low-entropy `suspect` tells the assistant that a value is weak, which helps a guesser. Keep the threshold fixed in code, not configurable, and report it only for `secret` keys whose shape is unknown.
- **L5.** The live/test and localhost signals reveal a class (a public prefix family, a local address). This is accepted and already disclosed (`docs/usage.md:1027`); reference that text from §3.3.
- **L6.** "Same value as a lower tier" compares two stored values (see H2). Accepted.
- **L7.** #174's inventory would return vault and item IDs and rule parameters, which `opv_configuration` withholds today (`src/mcp.rs:381`). This is not a value leak, but it is a policy change, and rule parameters can carry pasted values (M13).
- **L8.** Ephemeral environments break a linear lane order. Lanes need a DAG with template instances, and rotate/retire must enumerate the live instances. Defer with H.
- **L9.** The `.env` file isn't bound to the plan, so a file edited between review and approval imports other values under the same names. Show the file's modification time at approval and refuse if it changes during the run.
- **L10.** `expires_at` findings make `next` depend on the clock, so P-24's golden tests need an injected clock (the runner already has a fake clock, `src/runner.rs:390`).
- **L11.** The P-2 key-name grammar `^[A-Z][A-Z0-9_]*$` matches today's field rule (`docs/configuration.md:610`). Product and environment names use `identifier()` (`src/app/agent_view.rs:13-18`). The doc should say which applies where.

### Remaining risks after iteration 1

- **High:** none.
- **Medium:** H3's residual, accepted under the constraints. An assistant that edits and runs the application with real local or dev values can exfiltrate them. Mitigated by per-tier vault membership and documentation. Removing it needs OS isolation.
- **Medium→Low:** M8 (catalog drift), on the condition that catalog shapes never block.
- **Low:** everything else.

### Iteration summary

- **Key mitigations:**
  - approved-rule evaluation and closed shape names (H1);
  - removal of steerable comparisons (H2);
  - an honest-limit rewrite plus vault separation by tier (H3);
  - re-scoped, unconditional, secret-only redaction in the local delivery step (H4);
  - capability-gated `expose()` (M1).
- **Simplifications:**
  - agent mode becomes UX;
  - `approve` stays approve-only;
  - `opv next` reuses `ready`'s `next`;
  - no second verb surface;
  - `opv detect`, lanes, ephemerals and expiry are deferred.
- **Trade-offs introduced:**
  - Rule changes need a person's approval before they affect states. Resolved by separation in time: the assistant still proposes, and the state says `rules_pending_approval`.
  - Redaction holds back partial matches. Resolved with a streaming automaton that holds back only live matches.
- **Stopping:** a second iteration over the revised design found no new High or Medium beyond H3's accepted residual.

---

## Phase 3: systemic risk review

**Calibration risk.**
- The heuristic signals have no ground truth: entropy, catalog shapes, scanner matches. Each must be advisory until validated:
  - per catalog entry, a recorded real-format fixture;
  - per scanner pattern, a fixture per language (#175 already asks for this);
  - a tracked false-positive record from walkthroughs. opv has no telemetry, so the walkthrough logs are the only data.
- "Records the number of person actions" (Part V) is the right metric. Define the baseline from today's flow before phase B, or the improvement can't be shown.

**Observability risk.**
- *Bad decisions:* every plan states its relaxations (M4), and `ready` names advisory versus blocking reasons (M7).
- *Incorrect extraction:* scanner coverage and exclusions are in the document (M9).
- *Premature completion:* the gate must not pass on a relaxation the assistant made. M4's approved-relaxation record makes that visible.
- *Policy regressions:* a gate scenario must show that an MCP-declared rule, an `.env.example` edit or an adopt guess file changes no assistant-visible byte (H1, H2). Add these to the canary suite; the canary alone can't see comparisons.

**Over-engineering risk.**
- The North Star is large: 38 rows. The simplest viable version that meets #173's "done when" is:
  - H1/H2 fixes;
  - `opv inventory` (extending the TUI table and ready rows to JSON/MCP);
  - `opv_declare_from_env` (#176);
  - `opv needs --names` (assistant-supplied names), with the scanner after;
  - presence `all` (#179 item 1);
  - the walkthrough.
- The five verbs, `opv detect`, provisioners, lanes and ephemeral environments are not needed for it.

**Oversimplification risk.**
- Don't drop value states down to findings only: #174's "silence is not set" is a real defect.
- Don't drop `unreadable`: P-7 is correct and cheap.

**Incremental delivery (replaces Part V's order and decision 5).**

| Release | Contents | Ships alone because |
|---|---|---|
| 0.11.x | H1: rules from the approved contract, closed shape names over MCP; H2: adopt and `init --from` comparisons marked person-only; the honest-limit text | Fixes existing behaviour; no new surface |
| 0.12.0 (with the planned targets) | #174 inventory with the trimmed states; #176; `needs --names`; the typed envelope on existing documents; `next` = ready's; capability-gated `expose()` | Each item is read-only or name-only, with CLI/MCP parity and canary coverage |
| 0.12.x | Redaction in the local delivery step (H4), unconditional; harness guard rules (deterrent) | Independent of agent mode once redaction is unconditional |
| 0.13.0 | #179 (presence, gap finding, retire, gate), the tier attribute from `confirm_env`, catalog (advisory), scanner | Builds on the inventory |
| 0.14.0+ | One setup plan, `opv set`, rotation types, exposure, people, detect, ephemerals, provisioners | Each is additive |

- **Rollback:** every step is additive. Presence `all` keeps explicit lists (#179), and the approved-rule change reports `rules_pending_approval` instead of failing.
- **The one migration:** contract/binding split (M4). It needs a `config check` mode that reports the split before it enforces it.
- **The walkthrough:** "once each under Claude Code, Cursor and Codex" per phase is costly and not reproducible. Run a scripted MCP client against opv-sim in CI per phase, and the three harnesses manually at release.

---

## Conflicts with owner decisions (flagged separately)

1. **#177 `example_value`** (`.env.example` equality). This review recommends removing it (H2): it is an equality oracle the assistant steers. If the owner keeps it, compute it only inside a person's own import.
2. **#177's "every new signal is a warning … unless it is a declared rule"** conflicts with **the design doc** (P-11, §6.4: `suspect` fails the production gate). This review sides with #177 (M7).
3. **#179 item 3** (retire deletes the declaration after pruning) differs from the doc's lifecycle state `retired` (the declaration stays). Not a safety issue; the owner should pick one (L3). The same applies to `exclude` vs `except` and `--fail-on-missing` vs `--gate`.
4. **#173–#177 are labelled "Part of the 0.12.0 assistant visibility work"**, but the doc's decision 5 moves #175, #176 and #177 (phases C/D) to 0.13.0. This review proposes a third split, with #176 and `needs --names` in 0.12.0 and the scanner and catalog in 0.13.0. The owner decides.
5. **#174 includes rule parameters and vault/item IDs** in the MCP inventory, which today's `opv_configuration` withholds by design. This review doesn't oppose it, but it is a policy change that should be stated (L7), and it depends on H1 (rules no longer assistant-writable as free predicates).
6. **#173 and #174 imply MCP declarations of rules stay assistant-owned** ("The assistant owns declarations", `docs/mcp.md:69-75`). H1 takes free rule parameters away from the assistant. This is the largest change to an existing owner-approved behaviour in this review.
7. **Doc recommendations (not yet owner decisions) this review changes:**
   - decision 1: the repository holds the contract but not the bindings (M4);
   - decision 4: redaction is unconditional and secret-only, not tied to agent mode (H4, M2);
   - decision 5: the release split above.
