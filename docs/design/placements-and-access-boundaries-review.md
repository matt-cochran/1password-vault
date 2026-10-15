# Review: Placements and access boundaries

Reviewed: `docs/design/placements-and-access-boundaries.md` (draft, 2026-10-14), which answers
issue #114. Reviewed on 2026-10-14 using the owner's vetting procedure (Phase 1 architecture
validity, Phase 2 FMECA + poka-yoke + TRIZ, Phase 3 calibration).

Method: every claim about current behavior was checked against the code and docs, not taken
from the design. Sources read: `src/domain/model.rs`, `src/domain/delivery.rs`,
`src/app/delivery.rs`, `src/app/sync.rs` (record paths, `record_ledger`), `src/app/mod.rs`
(`target`, `open_target`, `managed_names`), `src/app/tidy.rs`, `src/app/repair.rs`,
`src/app/access.rs`, `src/domain/access.rs`, `src/domain/convention.rs`,
`src/domain/ledger.rs`, `src/provider.rs`, `src/adapters/fly/{config,mod}.rs`,
`src/adapters/github/config.rs`, `src/adapters/onepassword{,_init,_tidy}.rs`,
`docs/configuration.md`, `docs/usage.md`, `docs/design/requirements.md` (FR-13, FR-40 to
FR-55), `docs/design/delivery-receipts.md`, `docs/design/spike-d0-findings.md`, and
`gh issue view 114`. No 1Password, Fly or other network call was made.

Evidence levels used throughout: **Proven** (in the code and tested, or industry standard),
**Adapted** (a reasonable reuse of a proven mechanism, not yet proven here), **Speculative**
(depends on an unverified 1Password capability, or contradicts the code).

Owner's stance, applied as the scoring rule: security is a hard requirement, ergonomics is the
aspiration, a bigger change is acceptable if the tool ends up better, and per-boundary vaults
are the owner's own direction (they lean on 1Password's vault-level permission model).

---

## 0. Fact check: the design against current code

The design's diagnosis of #114 is accurate. Several statements about mechanisms it builds on
are not.

| # | Design says | Code / docs say | Verdict |
|---|---|---|---|
| F1 | §1: state item `opv · delivery · <product>`, looked up by product alone | `delivery::item_title(product)`; `read_state` looks it up by title in `state_vault_id` | Correct |
| F2 | §1: a receipt file is matched on the first entry with that product | `verify`: `from_file.iter().find(\|k\| k.scope.product == product)` | Correct |
| F3 | §1: an environment has one deployment target; values are one item with one section per product | `Environment { vault_id, item_id, target: Option<Box<dyn TargetConfig>> }`; convention "section `<product>` → field" | Correct |
| F4 | §5.3: receipt schema `opv.delivery/2`: "`target` gains `name`" | `domain::delivery::Receipt` has **no `target` object**. It has a flat `scope {account_id, environment, product, provider, locator}`. `docs/usage.md` documents the flat form. The nested `target` object exists only in the example in `delivery-receipts.md` §4, which is already stale. | **Wrong** (the design copied a stale doc) |
| F5 | §4.5 step 5: rebinding the evidence's source references keeps unchanged products `verified` | The **public receipt's** `bindings` also carry `source.item_id`. `domain::delivery::verify` compares the recorded binding set with the expected one and returns `not_delivered` ("the binding set changed") when an item id differs. Rebinding only the evidence does not keep anything `verified`. Rebinding the receipt as well would change the content of an already-minted revision. | **Wrong** |
| F6 | §5.3: a changed locator becomes `not_delivered (locator_changed)`, as if new | Already the behavior: `first_scope_difference` returns `not_delivered`, "recorded for another locator" | Already exists. Reuse it; do not add a new code path |
| F7 | §6.3: a deploy identity that can write the per-environment state vault "cannot forge `verified` for values it cannot read", so the only risk is deletion or replacement | The state item holds the **evidence key** (`KEY_FIELD`) next to the HMAC fingerprints, plus each name's store version. For Fly that version is the **Fly digest of the value** (`fly/mod.rs`: `version: e.digest`; `versions_reveal_values() == true`). `delivery-receipts.md` §5, `docs/configuration.md` and `model.rs` all state the invariant "only identities that can read the values should read the state vault". Under per-boundary vaults with a per-environment state vault, the `p-overflow` identity could read `api`'s key, fingerprints and Fly digests, and so could confirm guesses offline. | **Wrong and unsafe**: the design breaks a documented invariant and leaves the confidentiality loss unstated |
| F8 | §7: "Rate limits are per service account and per account per hour"; "about 10 reads per full sync, well below any plan's limit" | FR-13: 1,000 reads/hour per token, and per account 1,000 (Families) or 5,000 (Teams) requests **per 24 hours**. The D0 spike measured that one cold whole-item read costs **2** requests. Delivery state adds an `op item list` (title lookup in `read_state`) plus an item read per product, and a write. | **Wrong window, and the arithmetic is unsupported** |
| F9 | §7: "the existing one-read-per-item rule holds" | FR-13 also says title lookup must be unreachable from `sync`, yet `read_state` already does a title lookup (`find_item` → `op item list`) for every product during `sync`. Per-placement items multiply this. | Incomplete: an existing deviation that the cost table hides |
| F10 | §4.2: `from = "org/OPENAI_API_KEY"` across items, "builds on FR-45" | FR-45: the value is read "from the source's field in the **same environment's item**, within the one item read. References to another item or environment are refused at load." | Needs an explicit FR-45 amendment. The design does not mention one. |
| F11 | §5.1: "Any provider works as a target … with today's options", plus a target-level `products = ["p"]` | `products` (FR-48) is implemented only on `github` (`GithubTarget::serves`). Fly, Azure and Kubernetes use the default `serves() == true`. | A new generic option. It must replace GitHub's own option, not sit next to it. |
| F12 | §5.1: "Two targets naming one Fly app is a configuration error" | `FlyTarget::same_target` compares app **and** `secret_name` template, so today two environments may share one app with different templates (`configuration.md` §Targets says otherwise). The receipt locator is `app <name>` with no template. | A behavior change, stricter than the code. State it as one. |
| F13 | §4.1: keys sit in the item's **default section** | FR-43 / `convention.rs`: unsectioned fields are the simple profile's home. The fleet tidy "reads a key-shaped field at the top level but never moves, relabels, conceals … it", and notes it. Under today's tidy, a per-boundary item would look like a mixed simple/fleet item. | Needs a second convention, which the design does not acknowledge |
| F14 | §4.4: "opv reads, checks and tidies **only declared fields** in an account item" | Today's tidy (FR-43) runs **implicitly on every signed-in person's read**, claims unsectioned fields and fields in non-product-shaped sections, creates missing empty fields, conceals text secrets, relabels, and moves duplicates to `opv · kept`. Labels match ignoring case, `-` and `_`. | Not true of the code. This needs a tidy change that the design does not describe. |
| F15 | §6.1–6.2 present `opv access` and its audit as new, and §8.3 spikes `op vault user list` | `opv access [<env>]` already exists (#96, FR-52, `app/access.rs`). It already calls `op vault user list` and reports `access_not_visible`, `no_ci_reader` and `ci_reader_can_write`. The `SERVICE_ACCOUNT` type string is marked unconfirmed in `domain/access.rs`. | Extend the existing command. The spike should confirm the type string and group listing only. |
| F16 | Header: "builds on … the version ledger (FR-54)" | The ledger (`opv · state` section **in the values item**, keyed **by target name only**) is never discussed in the body. Under per-boundary vaults it has no defined home, and with two targets in one environment two placements that render the same name share one entry. | Omission |
| F17 | §4.5 / §5.x: "a 1Password service account's vault access is fixed at creation" (stated as fact; §8.2 then spikes it) | Not verified anywhere in the repo | **Speculative** |
| F18 | §6.2: under a service account, `op vault list` shows exactly the granted vaults; `op vault group list` works and is available by plan | Not verified. Today the code uses `op vault list` only as an exit-status probe and for title lookup. | **Speculative** |
| F19 | §5.2: `--target` on `delivery verify` is "required only when the product is placed on more than one target. Without it, a product with several placements returns every placement" | The two sentences contradict each other | Internal error |

---

## Phase 1 — Architecture assessment

| Component | Purpose | Classification | Justification | Simpler alternative | Risk if removed |
|---|---|---|---|---|---|
| C1 Named targets per environment (`targets.<name>`) | Several placements per environment (#114) | **Essential** | The issue's core ask. Evidence: Adapted (`TargetConfig` is reused unchanged; `Environment.target` becomes a map). | none simpler | #114 stays unsolved |
| C2 Env-level target as an implicit `default` | Existing configurations keep working (E4) | **Useful → simplified** | Acceptable only as load-time *desugaring* into `targets.default` (one runtime model, the way the simple profile desugars). Not acceptable as a second runtime path. | Desugar at load; `opv target add` rewrites the shorthand into `targets.default` once a second target is added | Every existing config breaks |
| C3 Per-placement state item `opv · delivery · <product> · <target>` | Independent evidence (S5) | **Essential** | Proven pattern (one item per product today). The scope check already rejects another locator (F6). | none | #114 acceptance 1–2 fail |
| C4 Receipt schema `opv.delivery/2` adding the target name | Disambiguate receipt entries | **Unjustified → removed** | The existing scope `(account, environment, product, provider, locator)` is already unique once a locator belongs to one placement (§5.1 rule). The name is a configuration label that can be renamed; the locator is the identity the issue asks for. The bump only creates v1/v2 coexistence (C5). | Keep `opv.delivery/1`; fix only the selection: full-scope match, order-independent, `duplicate_scope` refusal | none |
| C5 v1 receipt reading mapped to `default`, else `receipt_needs_migration` | Old receipt files | **Unjustified → removed** | It exists only because of C4. Without the schema bump, v1 receipts are matched on full scope, with no mapping and no legacy reader. | none needed | none |
| C6 Full-scope receipt selection + `duplicate_scope` | #114 acceptance 3 | **Essential** | Small change to `verify` | — | acceptance 3 fails |
| C7 `opv delivery migrate` (copy, verify, archive) | Keep old evidence (issue acceptance 4, S8) | **Essential → simplified** | Copy, then verify, then archive leaves two items with the same evidence key during the window, and needs an archive step. A **rename** in place (one `op item edit` of title and tag) keeps item id, key and evidence atomically. Evidence: Adapted (whether `op item edit` can change title and tags must be confirmed in the spike; if not, fall back to the design's copy). | rename; `delivery verify` reports `needs_migration` with the exact command until it runs | acceptance 4 fails |
| C8 Per-target `deploy_credentials`, "falling back to the environment's" | S3 least privilege | **Essential → simplified** | The fallback is a hidden inheritance. Put `deploy_credentials` on the target. The env-level shorthand puts it on `default` by desugaring. Mixing the two is a configuration error. | — | S3 unmet |
| C9 `opv target add/list`, TARGET columns, `--target` filters | E2, E5 | **Useful** | Reuses `config_edit` (comments kept, concurrency refused) | hand-edit TOML | ergonomics only |
| C10 Boundaries: product → `(vault_id, item_id)` | S1/S2 per-vault least privilege | **Essential** | The owner's direction. It is the only lever 1Password offers (vault-level grants), which is Proven. | — | S2 cannot hold |
| C11 `layout = "single" \| "per-boundary"` kept indefinitely | Coexistence (E4) | **Unjustified → removed** | Two layouts forever is a parallel abstraction with no removal plan: read paths, tidy, bootstrap, ledger and evidence sources all fork. With C12 kept as sections, today's layout is just *every product assigned to one boundary*, the degenerate case of the same model. D5 (`boundary = "core"`) already admits this. | One model: each product names its boundary. Today's env-level `vault_id/item_id` desugars to "every product in boundary `<env>`". No `layout` key, no `single_boundary` doctor mode. | none |
| C12 Keys in the item's default section ("the item is the product") | Cosmetics | **Unjustified → removed** | Needs convention 2, conflicts with FR-43's simple/fleet rule (F13), changes evidence `source.field`, and makes account items collide across projects (F14). | Keep section `<product>` inside each boundary item. Convention, tidy, `read_fields`, `field_label`, `item skeleton` and the evidence field labels stay unchanged; only `item_id` differs. | none |
| C13 Account-scope boundary `shared-<env>` (`scope = "account"`, `account_env`) | One value across projects | **Speculative → demoted** (after phase 3) | Safe only after the implicit tidy is turned off for account items (F14), and with a fixed section name every project agrees on. Account write permissions are cross-project, and environment-name mapping across projects is unvalidated. | Project-shared boundary first; account scope as a later, opt-in phase | Some duplicated values across projects for a while (E3 partly) |
| C14 One source per key, precedence rejected | S4 | **Essential** | Matches FR-55's no-fallback rule (Proven in the code). The "field in two boundaries" finding is FR-45's existing *extra field under a referencing key*, computed only on items the command already reads. | reuse the extra-field finding | silent shadowing |
| C15 `opv split` (copy, compare, rewrite config, **rebind evidence**, keep old) | Migration to boundaries | **Essential → simplified** | Rebinding is wrong (F5) and mutates minted revisions. Splitting a whole environment at once is a big-bang change. | Per product: `opv split <env> --product <p>` moves one product's section into its boundary item. Evidence is **re-minted by the next confirmed sync** (names are `identical`, so nothing is written; `record` mints because the bindings changed). Two steps: copy+verify, then `--switch` (config) only after access checks pass. `--finish` retires the old vault. | no path from today's layout |
| C16 `opv access` computing who needs what + owner commands | S3, E5 | **Useful** | Extend the existing `opv access` (F15); do not add a second one | — | grants done by hand |
| C17 `overbroad_access` / `cross_environment_access` via `op vault list` under a service account | S6 | **Speculative → demoted** (gated by spike) | Depends on F18. Can classify only vault IDs found in this configuration, and does not see permission level. | Phase 4, after the spike | S6 partly unmet; S1 not *measured* |
| C18 `opv access --audit` (vault users and groups against `audience`) | S6 for people | **Useful / Speculative** for groups | User listing already works (`vault_users`). Group listing and plan availability are unverified. | users now; groups after the spike | weaker people audit |
| C19 State vault per environment (D4 recommendation) | Simplicity | **Unjustified once boundaries exist** | Breaks the invariant (F7) | Phase 1: per environment is still valid (one values item, so every reader can read every value). From phase 3: **`state_vault_id` on the target**, refused at load when a state vault would be readable by an identity that cannot read every product whose evidence it holds. | — (replaced) |
| C20 Spike (§8) | Remove Speculative items | **Essential** | Must run *before* phase 3 commitments, and before C7's rename choice | — | building on guesses |
| C21 FR-54 ledger placement (missing from the design) | Exact change detection | **Essential to address** | The ledger is keyed by name in the env item (F16) | Phase 1: key entries per placement (`<target>/<name>`). Phase 3: the ledger lives in each boundary item, per placement. Longer term, consider folding the ledger into per-placement delivery evidence. | false `drift`, ledger thrash |

### Revised architecture

- **Components retained:** C1 named targets; C3 per-placement state; C6 full-scope receipt selection; C9 target commands and columns; C10 boundaries; C14 one source per key; C16 `opv access` (extended); C20 spike.
- **Components simplified:**
  - C2 env-level target becomes load-time sugar for `targets.default` only.
  - C7 `delivery migrate` renames in place instead of copy, verify and archive.
  - C8 `deploy_credentials` lives on the target, with no fallback.
  - C12 boundary items keep `<product>` sections, so the convention is unchanged.
  - C11 + C12 together: one boundary model, with no `layout` key. Today's layout is "all products in one boundary".
  - C15 `split` works per product in two steps (copy+verify, then `--switch`), re-mints instead of rebinding, and `--finish` retires the old vault.
  - C14 the "two boundaries" finding reuses FR-45's extra-field finding.
  - C19 state vault per target from phase 3, with a load-time check.
  - C21 ledger keyed per placement.
- **Components removed:** C4 `opv.delivery/2`; C5 v1 receipt mapping and `receipt_needs_migration`; C11 the `layout` enum and the indefinite `single` mode; C12 the default-section layout; the rebind step of `split`; the new `locator_changed` code (reuse the existing scope reason).
- **Components demoted:** C13 account-scope boundaries (after phase 3, opt-in, behind the tidy change); C17 service-account vault-list audit (phase 4, spike-gated); C18 group audit (spike-gated).

Revised phasing:

| Phase | Ships |
|---|---|
| 1 (0.7.0, closes #114) | C1, C2 (sugar), C3, C6, C7 (rename, or copy if the spike says so), C8, C9, C21 (ledger per placement), and per-target `state_vault_id` as optional. Spike items 2 (rename) and 5 (read cost) run first; they are read-only or test-account only. |
| 2 | Rest of the spike (vault list, users and groups, service-account immutability, template on stdin) |
| 3 (0.8.0) | C10 boundaries (sections kept, no `layout`), FR-45 amendment, per-product `split`, per-target state vault enforced, `opv access` per boundary |
| 4 | C17/C18 measurement; C13 account scope behind the tidy change |

---

## Phase 2 — FMECA, iteration 1

Severity and probability are qualitative. No numbers are estimated.

| Domain | Failure mode | Cause | Effect | Severity | Probability | Mitigation (poka-yoke) | Observability | TRIZ resolution | Residual Severity | Residual Probability |
|---|---|---|---|---|---|---|---|---|---|---|
| Technical | R1 Per-env state vault leaks other products' evidence | D4 keeps one state vault per env while values split per product (F7) | p-overflow identity reads api's evidence key, fingerprints and **Fly digests**, so it can confirm guessed secrets offline. Breaks S2/S3 and the documented invariant. | High | High (every deploy identity needs write, hence read) | **Prevention:** `state_vault_id` on the target. A load-time check refuses `state_vault_shared_across_boundaries` when one state vault holds evidence for products whose boundaries differ in who can read them (computed from configuration). `opv access` prints per-target state-vault grants. | `opv doctor` / `ready` finding `state_vault_wider_than_values` with `error.code`; `opv access --json` lists each state vault's readers | Segmentation (#1): split state per placement group, matching the identities | Low | Low |
| Technical | R2 `split` "rebind" silently claims `verified` | F5: the receipt's bindings include `item_id`; rebinding mutates a minted revision, or leaves a stale binding set | Either `not_delivered` everywhere (if only evidence is rebound) or receipts that no longer mean what was attested | High | High (deterministic) | **Remove the step.** After `--switch`, `delivery verify` returns `not_delivered` ("the binding set changed"), which is honest. `split` ends with `Next: opv sync <env> --expect-plan …`; that sync writes nothing (names are `identical`) and mints new revisions. | `delivery verify --json` state per placement; sync report `minted` / `not_minted` | Preliminary action (#10): re-mint rather than rewrite history | Low | Low |
| Runtime | R3 Deploys break between config switch and grants | §4.5 rewrites config (step 4) **then** prints the grants. Per F17, new service accounts may be needed. | CI sync fails on vault access in production until the owner creates identities and rotates CI tokens | High | High | **Fail fast before the switch:** `split --switch` refuses (`grants_missing`) until, for each target and CI reader named in the configuration, `opv access` shows a reader on every new boundary vault (where `op vault user list` is visible), or the owner passes `--grants-done`, which is recorded. The `Next:` line is the exact `op service-account create … --vault <id>:read_items`. | `split --json` `grants: [{principal, vault, state}]`; `ready` finding `grant_missing` | Separation in time (#15/#10): grant before switching | Medium (owner override still possible) | Low |
| Technical | R4 Implicit tidy edits shared/account items across projects | F14: tidy claims unsectioned and loosely matched fields, creates empty fields, conceals, and moves to `opv · kept` on any person's read | Project A rewrites project B's fields in `shared-<env>`; flapping edits; cross-project write blast radius | High | Medium (whenever two projects declare overlapping or differently-kinded keys) | **Prevention:** keep `<product>` sections (C12). The account boundary has a fixed section name. **Implicit tidy never writes an item that holds another configuration's sections or that is account-scoped**; only `opv tidy <env>` with a declared-fields-only plan. Demote account scope (C13). | `tidied 1Password` stderr line names the item; `doctor` note `tidy_skipped_shared_item` | Segmentation (#1) + local quality (#3) | Medium (tidy logic change) | Low |
| Technical | R5 Two layouts forever | `layout = "single"` kept indefinitely (C11) | Every reader, tidy, bootstrap, ledger and evidence path forks; bugs fixed twice; violates "no parallel abstraction" | Medium | High | **Remove:** one boundary model. Today's item is one boundary that every product maps to. | n/a (structural) | Universality (#6) | Low | Low |
| Technical | R6 Receipt v1/v2 coexistence | C4/C5 | Legacy reader, mapping rules, `receipt_needs_migration` | Medium | High | **Remove:** keep `opv.delivery/1`; full-scope match; `duplicate_scope` | `delivery verify` error code `duplicate_scope` | Trimming | Low | Low |
| Runtime | R7 Ledger collisions across placements | F16: ledger keyed by name in one item | False `drift` on B after syncing A with the same rendered names; ledger thrash; wrong `same`/`would_change` judgement | Medium | Medium | **Prevention:** ledger entry key `<target>/<name>` (phase 1); in phase 3 the ledger lives in each boundary item. Old entries without a target are read for `default` only by `delivery migrate`, then dropped (no legacy reader). | `plan --json` `drift` per placement; tests: P on A and P on B with the same template | Segmentation | Low | Low |
| Runtime | R8 Read and rate-limit cost underestimated | F8/F9: wrong limit window; reads ≠ requests (cold read = 2); per-placement title lookups and state reads/writes not counted | CI hits account limits (per 24 h on Families/Teams) in busy fleets; syncs fail with rate-limit errors | Medium | Medium (Unknown without measurement) | **Detection + prevention:** the spike measures one full sync with `OP_CACHE=false` via `op service-account ratelimit` before and after (FR-13 method). Record state item IDs at first creation, so `read_state` stops doing a title lookup in `sync` (FR-13 compliance). `ready` reports the per-sync request count from the spike. | `op service-account ratelimit` deltas in the CI summary; `rate_limited` error code | Prior counteraction (#9) | Low | Low |
| UX | R9 Old single item still readable after split, giving false assurance | Archive keeps the item in the same vault; everyone with the old vault still reads every product (archive semantics are **Speculative**) | S2 believed achieved while every old reader still sees all values | High | High | **Prevention:** `split --finish` **retires the old vault** (deletes the item after confirmation, then prints the owner's command to remove remaining grants or delete the vault) and refuses while the old vault holds anything opv still reads (manifest, deploy credentials). `opv access` reports `superseded_vault_readers` for every reader of a vault whose item is tagged `opv-superseded`. | `ready` / `access --json` finding with `actor: owner` | Separation in time | Medium | Low |
| UX | R10 People keep editing the old item after split | Muscle memory, saved item links | Edits are silently ignored; production keeps the copied value | Medium | High | **Detection:** record the old item's version at copy. Every command that reads the configuration's IDs does nothing with the old item, but `doctor`/`ready` compare the version (metadata, one cheap read) and report `superseded_item_edited`. `--finish` refuses if it changed. | finding code; `split --json` `old_version` | Feedback (#23) | Low | Low |
| Technical | R11 Split equality check false positive or negative | Comparing through `op`'s cache, after normalization, or ignoring field type | A changed or truncated value is accepted as copied; concealed becomes text | High | Low | **Prevention:** compare raw bytes on `--cache=false` reads of both items (as FR-43 safe writes do), compare field **type** too, and require both items' versions to be unchanged since the copy; any mismatch is `split_unverified` with names only | `split --json` `verified: [names]`, `mismatch: [names]` (no values) | — | Medium | Low |
| UX | R12 Vault and identity sprawl | Products × environments + shared + state vaults; an identity per target; CI readers per boundary set | Owner burden; misgrants; possible plan limits on vaults or service accounts (**Speculative**, no numbers known) | Medium | Medium | **Simplification:** D5 opt-in shared boundary (`boundary = "core"`) as the small-team default; `opv access` prints only missing grants; the spike checks plan limits | `opv access` counts per environment | Trimming / partial action (#16) | Low | Medium (inherent to the security model) |
| Technical | R13 Cross-item `from` without the FR-45 change | F10: load refuses cross-item references today | Feature unusable, or a second resolver added beside FR-45 | Medium | High | **Prevention:** amend FR-45 and extend the existing `KeySpec::source` resolution to `(boundary item, section, key)`; an unreadable source is `source_not_accessible` naming the boundary and its `audience` (reuse FR-55's wording) | row state `source_blocked`; `error.code` | Universality | Low | Low |
| Technical | R14 Stricter one-app rule breaks configs | F12: today two environments may share an app with different templates | Upgrade breaks a valid config (E4) | Medium | Low | **Fail fast with migration text:** a load error naming both environments and the fix; documented as a breaking change in 0.7.0 | config error with line/column | — | Low | Low |
| Technical | R15 `{KEY}`-only template rule duplicated | D8 adds a special "one product" rule | A second collision mechanism beside FR-30 | Low | Medium | **Reuse** the FR-30 collision check (GitHub already allows `{KEY}`); drop the special rule for Fly | load error `name collision` | — | Low | Low |
| Runtime | R16 Overflow target never gets its grants | `target add` prints needs, owner skips them | `sync --target p-overflow` fails at deploy credentials or vault read | Medium | Medium | **Fail fast:** `target add` ends with `Next: opv access <env> --target <t>`; `ready` shows the target as `grants_missing` until its credentials read works (the existing `doctor --env` deploy-credentials check per target) | `ready` matrix TARGET column | — | Low | Low |
| Project | R17 Phase 3 committed before the spike | Speculative 1Password capabilities (F17, F18, archive semantics, template on stdin) | Rework or a weaker security story after shipping | High | Medium | **Gate:** phase 3 starts only after spike items are recorded as fixtures. Any capability not confirmed is designed around (for example, assume service-account access is immutable and always plan new identities). | spike findings doc; requirements FR-56 to FR-59 marked normative only after it | Preliminary action | Low | Low |
| Project | R18 `delivery migrate` misattributes evidence with several targets | Owner picks the wrong `--target` | Old evidence lands on the wrong placement | Medium | Low | **Prevention:** the recorded scope locator must equal the chosen target's locator (the design already says this); the rename refuses otherwise. Under C7-rename, no second copy exists. | `migrate --json` per product: `moved`, `refused: locator_mismatch` | — | Low | Low |
| UX | R19 `delivery verify --target` contract ambiguous | F19 | Agents and scripts disagree on behavior | Low | Medium | Pick one: **without `--target`, return every placement**, each with `target`; never required | schema entry | — | Low | Low |

### Remaining risks after iteration 1

- **High:** none.
- **Medium:**
  - R3: the owner can still override with `--grants-done`.
  - R4: the change to tidy logic is itself new code.
  - R9: depends on the owner removing old grants; opv can only detect this.
  - R11: the comparison is new code.
  - R12: probability stays Medium, because sprawl is inherent to per-boundary vaults.
- **Low:** R1, R2, R5, R6, R7, R8, R10, R13 to R19.

### Iteration 1 summary

- **Key mitigations:**
  - per-target state vault, with a load-time check;
  - re-mint instead of rebind;
  - grants checked before `--switch`;
  - the old vault is retired, not archived;
  - implicit tidy is off for shared items;
  - full-scope receipt selection;
  - the ledger is keyed per placement.
- **Simplifications:** removed `opv.delivery/2`, the v1 mapping, the `layout` enum, the default-section layout and the rebind step. `delivery migrate` became a rename and `deploy_credentials` lost its fallback.
- **Trade-offs:**
  - After a split, products read `not_delivered` until the next no-op sync, instead of staying `verified`. This is honest, at the cost of one command.
  - Per-target state vaults mean more vaults.
  - Keeping sections means boundary items look "redundant" (one section in a one-product item). That cosmetic cost buys an unchanged convention.
- **Continuing:** five Medium risks remain.

---

## Phase 2 — FMECA, iteration 2 (the remaining Medium risks)

| Domain | Failure mode | Cause | Effect | Severity | Probability | Mitigation (poka-yoke) | Observability | TRIZ resolution | Residual Severity | Residual Probability |
|---|---|---|---|---|---|---|---|---|---|---|
| Runtime | R3' Owner overrides the grants check | `--grants-done` while the identities are not ready | CI fails after the switch | Medium | Low | **Rollback in place:** until `--finish`, `opv split <env> --product p --revert` restores the config entry (the old item is still intact; the refusal names any value edited in the new item since, by version). Fail fast in CI with `vault_no_access` naming the new boundary vault. | `split --json` `revertible: true`; CI error code | Reversibility (#13, "the other way round") | Low | Low |
| Technical | R4' Tidy change regresses FR-43 for normal items | Excluding shared items mis-classifies a project item | A project item is never tidied | Low | Low | Classify by configuration only (the boundary is project-scoped and every section in it is declared by this configuration). Characterization tests on today's fixtures (`characterization_tests.rs` pattern). | existing `tidy_tests.rs` + new fixtures | — | Low | Low |
| UX | R9' Old readers remain after `--finish` | Owner does not run the printed grant removal | Residual exposure of every product's **old** values; these are current values unless rotated | Medium | Low (the item is deleted on `--finish`, so the old vault holds nothing opv put there) | **Prevention:** deleting the item at `--finish` removes the values themselves, so any remaining grants are harmless for opv's data. `opv access` reports the empty vault for removal. | `access` finding `empty_superseded_vault` | Trimming | Low | Low |
| Technical | R11' Comparison code defect | New code | A wrong copy is accepted | Medium | Low | Reuse the FR-43 verify-after-edit path (`onepassword_tidy::lost`-style check: every intended field present with identical bytes and type) instead of new comparison code; synthetic marker-value tests | test suite; `split_unverified` | Universality | Low | Low |
| UX | R12' Sprawl | per-boundary model | Owner workload | Medium | Medium | D5 shared boundary as the documented small-team default; `opv access` prints the minimal grant set; `bootstrap` creates vaults idempotently | `opv access` summary counts | Partial action | Low | Medium |

### Remaining risks after iteration 2

- **High:** none.
- **Medium:** R12' probability only. Owner burden from vault and identity count is inherent to "one vault per access boundary". Lowering it further would mean fewer boundaries, which violates the S2 security requirement. D5 lets an owner choose that trade-off explicitly.
- **Low:** everything else.

### Iteration 2 summary

- **Key mitigations:** a `--revert` path before `--finish`; deletion (not archive) at `--finish`; reuse of the FR-43 verification for split.
- **Simplifications:** split verification reuses existing tidy verification code.
- **Trade-offs:** `--finish` deletes the old item, which is irreversible. It asks first and refuses while anything still reads the item (S8 is kept: nothing is implicit).
- **Stopping:** the only remaining Medium is constrained by the security requirement.

---

## Phase 3 — Systemic risk review

**Calibration risk (opv's own signals).**

- **`verified` / `changed` / `unverifiable`.**
  - Trustworthy only if the binding set and evidence are never rewritten after minting. The design's rebind (F5) would break that, so it is removed.
  - Per-placement items keep `verified` local to one locator. The existing scope comparison already guards against locator reuse.
  - **Validation:** #114 acceptance tests 1–3, plus a new test that a split product reads `not_delivered` until a no-op sync re-mints, and then `verified`.
  - `unverifiable` stays honest for stores without versions.
- **Readiness findings.**
  - New codes (`needs_migration`, `grants_missing`, `state_vault_wider_than_values`, `superseded_item_edited`) must each carry `actor`, `effect`, `prerequisite` and `verify` (FR-51).
  - **Validation:** `guidance_tests` / `json_tests` patterns.
- **`overbroad_access` / `cross_environment_access`.**
  - Poorly calibrated until the spike: the result depends on what `op vault list` returns under a service account (F18). It sees vaults, not permission levels, and can classify only vault IDs this configuration knows.
  - Rule: never report "clean". Report `checked: n, unclassified: m`.
  - **Validation:** spike fixtures; a fixture service account that sees another environment's vault (design acceptance 9).
- **`opv split` equality checks.**
  - Calibrated only with fresh reads (`--cache=false`), raw-byte and type comparison, and version pins on both items (R11/R11').
  - **Validation:** marker-value tests, including whitespace and multi-line values and a concealed-versus-text mismatch.

**Observability risk.**

- *Bad decisions:*
  - `split --switch` refusals and `grants_missing` are visible in `ready`.
  - Wrong placement attribution shows as `locator_mismatch`.
- *Incorrect extraction:* `split_unverified` names the keys.
- *Premature completion:*
  - `--finish` refuses while the old item changed or is still read.
  - `needs_migration` blocks a false `verified`.
- *Policy regressions:*
  - `state_vault_wider_than_values` is a load or `doctor` check, not advisory.
  - The redaction tests (acceptance 10) extend to `split` and `delivery migrate` stdin, argv and JSON.
- *Gap:* access drift caused outside opv (someone grants a vault later) is caught only when `ready`/`access` runs. Recommend running `opv access --json` in CI on a schedule; this is a documentation item, not a new mechanism.

**Complexity vs utility.**

- The original design carried:
  - two layouts;
  - two receipt schemas;
  - two forms of `deploy_credentials`;
  - a rebind mechanism;
  - copy/verify/archive migration of evidence;
  - account scope in the same release.
- The revised version has one boundary model, one receipt schema and one place per setting. Migrations become a rename and a per-product split.
- **Simplest viable version for #114:** phase 1 only, which is named targets, per-placement state, full-scope selection, rename migration and the per-placement ledger. It does not depend on boundaries.

**Oversimplification risk.**

- Not removed, because each is required by security or by the issue:
  - per-placement evidence;
  - migration of existing evidence (issue acceptance 4);
  - the FR-45 amendment for cross-boundary `from`;
  - access computation;
  - the spike gate.
- Account-scope boundaries are only *demoted*, not removed, so the owner's cross-project use case keeps a path.
- Keeping sections in boundary items loses nothing functionally.

**Incremental delivery.**

- Phase 1 ships alone and closes #114.
- **Rollback:**
  - Phase 1: an older opv cannot find renamed state items and reports `not_delivered`, which is safe, with no corruption.
  - Phase 3: per-product split is revertible until `--finish`.
  - Each phase's config change is one desugared model, so there is no dual-read code to remove later.

---

## Final outcome

All High risks are mitigated to Low. One Medium remains: the *probability* of owner burden from
vault and identity sprawl (R12'). Mitigating it further would mean fewer access boundaries,
which violates the security requirement S2. D5 makes it an explicit, opt-in owner choice.

### Recommended changes to the design doc, in priority order

1. **D4: state vault.** Replace "per environment, audited" with "per environment in phase 1; `state_vault_id` on the target from phase 3, with a load-time refusal when a state vault would be readable by an identity that cannot read every product it holds evidence for". State the reason: the state item holds the evidence key, fingerprints and Fly digests (F7).
2. **§4.5 `split`:**
   - Delete step 5 (rebind) and say evidence is re-minted by the next confirmed (no-op) sync (F5).
   - Make split per product, in two steps (copy+verify, then `--switch`).
   - Check grants **before** the config switch.
   - Add `--revert` before `--finish`.
   - `--finish` deletes the old item and retires the vault rather than archiving it.
   - Verification uses fresh raw-byte and type comparison with version pins.
3. **§4.1 / §4.5: drop `layout` and the default-section layout.** Keep `<product>` sections inside boundary items. Model today's layout as every product in one boundary (desugared from env-level `vault_id/item_id`). Remove the `single_boundary` mode.
4. **§5.3: drop `opv.delivery/2` and the v1 mapping.** Keep `opv.delivery/1`; select on the full existing scope, order-independent, with `duplicate_scope`. Correct the schema description: there is no `target` object (F4).
5. **§4.4: the tidy rule.** State that implicit tidy never writes an item that is account-scoped or holds another configuration's sections (F14). Demote `scope = "account"` to a later phase.
6. **Add a section on the FR-54 ledger:** key entries per placement in phase 1, and place them in boundary items in phase 3 (F16).
7. **Amend FR-45 explicitly** for cross-item `from` (F10); add `source_not_accessible`.
8. **§5.4: `delivery migrate` renames in place** (title and tag); copy is the fallback only if the spike shows `op item edit` cannot rename.
9. **§5.1:**
   - Move `products` to the target level, replacing GitHub's provider-specific option (F11).
   - Put `deploy_credentials` on the target with no fallback.
   - Make the env-level target load-time sugar for `targets.default`, which `target add` rewrites.
   - State the one-app rule as a breaking change (F12).
   - Replace D8 with the FR-30 collision check.
10. **§6: extend the existing `opv access`** (F15). Mark `op vault list` scope, group listing, plan availability and service-account immutability as **Speculative** until the spike (F17, F18). Make §4.5's "fixed at creation" conditional.
11. **§7: correct the rate-limit window** (per 24 hours for the account, FR-13). Count requests, not items (a cold read costs 2). Include state item lookups and writes. Record state item IDs to remove the title lookup in `sync`. Replace "well below any plan's limit" with the spike measurement (F8, F9).
12. **§5.2: resolve the `--target` contradiction** (F19).
13. **§8 / §10: gate phase 3 on the spike.** Add spike items: whether `op item edit` can rename an item, what archiving does to readability, and vault and service-account limits by plan.

### Verification checklist

| Check | Done |
|---|---|
| Architecture validity evaluated before risk mitigation | Yes (Phase 1 before Phase 2) |
| Components classified Essential / Useful / Speculative / Unjustified | Yes (C1 to C21) |
| Simplification and removal considered as mitigation | Yes (R2, R5, R6 removed by deletion; C4, C5, C11, C12 removed) |
| All four domains analyzed | Yes: UX (R9, R10, R12, R19), Runtime (R3, R7, R8, R16), Technical (R1, R2, R4, R5, R6, R11, R13 to R15), Project (R17, R18) |
| Every failure mode has full FMECA fields | Yes |
| Observability defined for each mitigation | Yes (finding or error codes, `--json` fields, tests) |
| Iterated until risks reduced appropriately | Yes (two iterations; one constrained Medium) |
| No unnecessary complexity introduced | Yes (net removal: two schemas → one, two layouts → one, rebind removed) |
| No fabricated precision | Yes (only the FR-13 and D0 figures quoted from the repo; plan limits left unknown) |
| No critical capability lost | Yes (account scope demoted, not removed; issue acceptance 1–5 preserved) |
