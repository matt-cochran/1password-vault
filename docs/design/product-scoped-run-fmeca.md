# DESIGN-FMECA vet: product-scoped `opv run` (#264, #263), `docs/design/product-scoped-run.md`

Reviewer: independent; did not write the design. Date: 2026-11-04. Method: the owner's
DESIGN-FMECA procedure (persona, objective, constraints, code-change-proposal requirements, three
phases, output format, verification checklist), applied as written.

**Short answer.** The code reading in §1.2 is accurate, and the core change is sound and small:
derive one `wanted` set, read only the boundary items it needs, name only `wanted` keys, and never
name an infrastructure key. **The root-cause story in §1.3-§1.4 is wrong, though, and it matters.**
The Zonetico producer did start (verified), but it failed at `stage=input` because **`opv run`
removed four inputs that the workflow passed in its environment**. They are declared
infrastructure keys of a sibling product, so the FR-4 clear list strips them
(`src/app/run.rs:376-385`). The producer checks those four names first, before it looks at the
three selected keys. The selected keys may also be empty, but the producer never got that far. So
the design, as written, fixes #263's text and FR-57's over-read, **but the reporter's pipeline
will still fail at the same stage**, and #264 would be closed while still broken. A real
producer/consumer cycle does exist. It is caused by the clear list (design rule 5, "unchanged"),
not by a gate.

Verdict: **ready with changes.** The changes are one new owner decision (D4, the clear list for
infrastructure names), a corrected §1.3, one simplification of the tidy-note filter, test
hardening, and a live names-only check before #264 is closed. After them, no High or Medium risk
remains.

Evidence levels: **Proven** (shown in code or in the names-only CI log here), **Adapted**
(reasonable, not proven here), **Speculative** (assumed). opv paths are relative to
`/home/mc/.cache/lanes/opv-0180-design` (rev `7cc0b6dd`). Zonetico evidence:
`matt-cochran-products/zonetico-saas` at `b8f820a4` (the run's head commit),
`scripts/release/provision-private-production-acceptance.ts`. The opv configuration is
`matt-cochran-products/infra` at `50b370a1`, `fly/shared-host/acceptance-authority/zonetico/secrets.toml`.
Only names and code were read. No value was read or printed.

---

## 0. Claims checked against the code and evidence

| Design claim (§) | Verdict | Evidence |
|---|---|---|
| Selection is product-scoped; only selected keys become references (§1.2.1) | **Holds** | `src/app/run.rs:237-250`, `:298-345`; `src/app/delivery_preview.rs:59-102` |
| The read is fleet-wide (§1.2.2) | **Holds** | `run.rs:287-289` → `tidy.rs:321`, `:383-390`, `:393-421`; `src/domain/model.rs:746-763` |
| The note is boundary-wide (§1.2.3) | **Holds** | `tidy.rs:368-378`, `:403`, `:721-744`, `:790`; tidy path `:520-530` |
| Infrastructure keys are named as needing a value (§1.2.4) | **Holds, and it is most of the Zonetico noise.** All 13 sibling names in the run's note are `source = "infrastructure"` keys | filter `tidy.rs:733`; never created `convention.rs:645-649`; infra config lines 15-136 |
| No gate on empty values; read errors dropped (§1.2.5) | **Holds** for empty fields | `run.rs:288` (`.ok()`), `:293-297`; `tidy_tests.rs:1264-1277` |
| "An empty **or missing** field reaches the child as `""`" (§2.3 table, row 2) | **Unverified for "missing"; likely wrong.** A missing field gets the conventional `op://…/<product>/<KEY>` reference (`run.rs:337-340`). `op run` resolves every reference before it starts the child, and is expected to fail on one it cannot resolve. **Adapted**, not proven here | `run.rs:337-340`; the "Found live" comment at `:291-292` covers empty fields only |
| One note, 16 keys, split 3/7/6 (§1.3) | **Holds** | CI log line 187 (names only) |
| "opv started the child" (§1.3) | **Holds.** The message comes from the producer's `ProvisioningStageError` | producer `:109-124`, `:174-178`, `:1290` |
| "The real blocker was the selected product's own three keys" (§1.3, §1.4) | **Wrong.** The log line has **no** `missing=` suffix. An empty platform key would throw `ProvisioningStageError('input', [names])` with the suffix (producer `:286-297`, `:111`). No suffix means a plain `Error` from `inputFromEnvironment`, wrapped by `atStage` (`:121-122`). That function first requires `PRIVATE_PRODUCTION_ACCEPTANCE_TENANT_ID/_EMAIL/_PASSWORD/_TOTP_SECRET` (`:233-261`). The workflow sets all four (log lines 178-181), and **all four are declared keys** of `zonetico-private-acceptance` (infra config lines 18-42), so `run` removes them (`run.rs:376-385`) | producer and infra config cited; CI log lines 178-181 and 188 |
| "The workflow also sets `PRIVATE_PRODUCTION_ACCEPTANCE_*`… intended and stays" (§1.3, marked inferred) | **Now verified, and it is the failure.** Keeping it unchanged leaves #264's pipeline broken | as above |
| Two-product exact-label match is claimed by neither, with no note (§1.3) | **Holds** for a sectioned, non-product-shaped section. An unsectioned field does get a note (`ambiguous_note`, `tidy.rs:564-582`). It misses a second mechanism: **infrastructure keys take part in `resolve`** (`convention.rs:185-188` filters only `from` and personal keys). `zonetico-private-acceptance` declares `PRIVATE_PRODUCTION_PLATFORM_ACCEPTANCE_*` as infrastructure (infra config lines 46-63). A filled field in that product's section is claimed by the infrastructure key, and the platform key stays empty | `convention.rs:175-258` |
| `sync --product`: "blocking is scoped" (§1.5) | **Partly wrong.** Row blocking is scoped (`sync.rs:1035`, `mod.rs:1743-1760`). But `refuse_stored` runs **before** scoping and checks every product's fields (`sync.rs:1015`, `:1602`; `deliver_only.rs:907-927`), so another product's stored infrastructure field refuses a `--product` sync | as cited |
| `status --product`, `doctor`, `changed` rows (§1.5) | **Hold** (spot-checked) | `status.rs:304-306`; `doctor.rs:146-151` |
| Preview lists infrastructure keys as delivered (§1.5, D2) | **Holds** | `delivery_preview.rs:200-218` against `run.rs:240-250` |
| D2 keeps snapshots byte-identical | **Holds** for JSON (no snapshot has an infrastructure key). The design **omits the text renderer** `write_text` (`delivery_preview.rs:317-336`), which would silently stop listing the key | 8 `run_preview__*.snap` files; no schema registry names preview fields |
| FR-37 / FR-12 apply to test fixtures in `src/app` (§5.1) | **Half right.** FR-37 skips `*_tests.rs` (`mod.rs:2326`). FR-12 scans them with `cfg(test)` items removed (`mod.rs:2125-2145`). It is harmless: the fixture names no target | `mod.rs:2125-2145`, `:2310-2334` |
| J7 `observed_seal`, error catalog, `surface.json` untouched under D1-A | **Holds.** `tests/observed_seal.rs` excludes `*_tests.rs`; no new `Cause`; no new flag | |
| Fake `op` "resolves the references and execs the child" follows the `tests/local_delivery.rs:420-460` pattern | **Does not match the pattern.** That fake only execs (`local_delivery.rs:408`) and resolves nothing. Resolving `op://` in `sh` is new work and not needed for B1-B4 | |
| Unit tests exercise the read | **Only if each test holds `tidy::activate()`.** Without it `active()` is false in unit tests (`tidy.rs:44-56`), the read is skipped, and every "names no X" assertion passes vacuously | |

---

## Phase 1: Architecture Assessment

| Component | Purpose | Classification | Justification | Simpler Alternative | Risk if Removed |
|---|---|---|---|---|---|
| C1 `wanted` set (§2.1) | One source of truth for read scope, references and note | **Essential** (Proven pattern: derive, don't duplicate) | Removes the read/reference/note divergence that is #263 | none simpler | Note and references drift again |
| C2 `ReadScope` + `read_for` (§5.1) | Read only `wanted`'s boundary items; tidy still sees every product in an item | **Essential**, simplified | FR-57 acceptance line. Keeps `in_boundary(whole fleet)` so a shared item is never tidied with missing sections | Build the scope from `wanted`'s **KeyIds**; boundaries come from their products (and `from` sources). Not a product-name set (see C4) | CI identity with one-boundary access loses the whole read (`.ok()`) |
| C3 Note = `wanted ∩ needing_values` (rule 2) | Name only keys this run uses | **Essential** | #263 acceptance | none | #263 stays |
| C4 Tidy-path note filtered inside `read_item_as` (rule 3) | Same filter when a person's run tidied | **Essential goal, simplify mechanism** | A product-name `ReadScope` cannot express role-withheld keys or a single `from` key of a source product, so T15/T16 break on the tidy path | **One print site:** a scoped read never prints the needs-value note inside `read_item_as`; `run` always prints `needing ∩ wanted` after the read, whether or not it tidied. The "tidied 1Password" summary stays inside, item-wide | A second filter that disagrees with C3 |
| C5 Infrastructure filter in `needing_values` (rule 4) | Never name a never-stored key | **Essential** | Alone it removes all 13 sibling names in the Zonetico log. Same predicate as `run.rs:243` | none | The noise remains for every command |
| C6 Preview `supplied_at_sync` (D2-A) | Preview matches run | **Useful** | Small. Fixes a real parity lie | must include the text renderer | Preview over-reports |
| C7 Binary regression with a fake `op` (L4) | Real argv, real hand-off | **Useful**, simplified | Exercises the #264 path | Exec-only fake `op`, as `tests/local_delivery.rs` does. No reference resolution | Only unit-level proof |
| C8 opv-sim `op run` (D3-B) | e2e scenario | **Speculative for this release** | New fault-matrix surface; not on the bug's path | Defer (agree with D3-A) | none now |
| C9 Clear list unchanged (rule 5) | Declared names never reach the child from the parent | **Must be decided (missing D4)** | It is the verified Zonetico failure. Infrastructure values are never in 1Password (deliver-only §4.4), so a run cannot inject them **and** removes the only carrier the workflow has | see D4 | — |
| C10 Docs (L5) | Usage, deliver-only §6.4, FR-43 | **Essential** | Behaviour visible to users | none | Docs lie |
| C11 Follow-ups 1-3 | Scope the rest | **Useful**, rewrite #2 | #2 must name infrastructure keys claiming fields, and the fleet-wide `refuse_stored` | — | Next Zonetico blocker unexplained |

### Revised Architecture

- **Retained:** C1, C3, C5, C10; C2 keyed by `wanted` KeyIds.
- **Simplified:** C4 → one print site in `run`; C7 → exec-only fake `op`; C6 → plus the
  `write_text` line `supplied at sync (not injected): <names>`.
- **Removed:** reference resolution in the fake `op`.
- **Demoted:** C8 (D3-A, as recommended).
- **Added:** D4 (clear list for infrastructure names), owner-decided. A live names-only check of the
  Zonetico workflow gates closing #264.

---

## Phase 2: FMECA + poka-yoke + TRIZ

### Iteration 1 Risk Table

| Id | Domain | Failure Mode | Cause | Effect | Severity | Probability | Mitigation (Poka-Yoke) | Observability | TRIZ Resolution | Residual Severity | Residual Probability |
|---|---|---|---|---|---|---|---|---|---|---|---|
| R1 | Delivery / UX | #264 closed, Zonetico still fails at `stage=input` | Wrong root cause (§1.3). Rule 5 keeps stripping the four declared sibling infrastructure names the producer needs | Owner believes the deadlock is fixed; the pipeline still fails, now with a *clean* opv note, which is more confusing | High | High | Correct §1.3/§1.4 with the evidence in §0. Add **D4**. Add binary test **B5**: parent environment carries a declared sibling infrastructure name, and the child's view of it matches D4. **Gate:** #264 closes only after a names-only re-run of the Zonetico workflow gets past `stage=input` | The producer's own `stage=`/`missing=` line; opv's D4 note (below) | Contradiction: "never let a declared name leak in from the parent" vs "a value opv never holds must still reach the child". Principle **#3 Local quality**: treat infrastructure names differently from stored names | Low | Low |
| R2 | Technical | Tidy-path note leaks non-wanted keys | `ReadScope` holds product names. On a person's tidy the note is printed in `read_item_as` with a product filter, so a source product's other keys and role-withheld keys are named | T15/T16 fail on the tidy path, or pass only on the non-tidy path | Medium | High | C4: one print site. A scoped read returns `needing_values` and never prints them. `run` prints `needing ∩ wanted` once, after any "tidied" summary. Other commands (`ReadScope::Whole`) keep the in-tidy print unchanged | T5, T15, T16 run twice: with `FakeOp::person` on a messy item (tidy path) and on a tidy item | **#2 Taking out**: move the print out of the shared reader | Low | Low |
| R3 | Test | Negative tests pass vacuously | `tidy::active()` is false in unit tests without `activate()`. A fixture with no empty sibling field also passes before the fix | Regression tests that guard nothing | Medium | Medium | Every run test holds `let _on = activate();`. Every "names no X" test also asserts a positive in the same run (T9 asserts `input/A` *is* named when A is empty, or that `item get` ran). Write T9/T12/B2 first and see them **fail on 7cc0b6dd** (record in the PR) | PR evidence: red then green | — | Low | Low |
| R4 | UX / accuracy | Design states a missing field reaches the child as `""` | Not verified. `op run` is expected to refuse an unresolvable reference, so the child never starts | D1's "nothing blocks" is wrong for a missing field under a read-only identity. Users get `op`'s error, not the note | Medium | Medium | Change row 2 to: "empty: child gets `""`; **missing**: `op run` is expected to refuse the reference before the child starts (op's error, NR-31 excerpt); the note already names the key first". Mark it **inferred** until a live names-only check | `op said:` excerpt on the run's error | — | Low | Low |
| R5 | Technical | Scoped read misses a `from` source or the personal item | `wanted` maps `from` keys to sources; personal is separate | Field-id refs (`refs`) or normalization warnings lost for the source | Medium | Low | Scope built from `wanted` KeyIds, so sources are included by construction. T3 + T15. Personal untouched (`run.rs:251-283`) | T3/T17 count `item get` per item id | — | Low | Low |
| R6 | UX | D2 text preview drops infrastructure keys silently | `write_text` iterates only `keys` (`delivery_preview.rs:317-336`) | `--preview` text shows fewer keys and no reason | Medium | High (certain if not done) | L3 adds the line `supplied at sync (not injected): Z` when the array is present; test T21 | Unit test on the text form | — | Low | Low |
| R7 | Delivery | Fake `op` that resolves references overruns L4 | Not the existing pattern; `sh` parsing of `op://` and item JSON | L4 slips; brittle test | Low | Medium | Exec-only fake `op` (`local_delivery.rs:408`); item JSON served for `item get` | — | Simplification | Low | Low |
| R8 | Runtime | Next blocker after D4: selected keys read empty, or `sync --product` refused | Infrastructure keys claim fields in `resolve` (`convention.rs:185-188`). `refuse_stored` is fleet-wide and runs before scoping (`sync.rs:1015`) | Zonetico gets past `stage=input`, then fails on platform keys or on `supply_refused` | Medium | Medium | Not in this release's code. Rewrite follow-up #2 to name both mechanisms (infrastructure keys must not claim fields, matching `convention.rs:645-649` and deliver-only §4.4; `refuse_stored` scoped like `scope_plan`). Give the owner the names-only check now: `opv explain zonetico-platform-acceptance/PRIVATE_PRODUCTION_PLATFORM_ACCEPTANCE_EMAIL --env zonetico-prod-acceptance` | After this release the run note names *only* the 3 selected keys, and the producer prints `missing=…`. Either signal is unambiguous | **#10 Preliminary action**: diagnose before the next live run | Low | Medium (detected, not prevented) |
| R9 | Security | D4 lets a stale or wrong parent value reach the child | Infrastructure names inherited instead of cleared | Child runs with a stale tenant id or credential | Medium | Low | D4-B limits inheritance to declared **infrastructure** names (opv never holds them, so it has nothing better to offer). It prints one names-only note per run, "taken from the environment as given: <names>", only when present. Stored keys stay cleared (`clears_another_products_managed_keys` stays green) | The note; B5 | **#1 Segmentation** by value source | Low | Low |
| R10 | Technical | Clear list and D4 live in `run.rs`, owned by L2 | File contention if D4 is its own lane | Merge conflicts | Low | Medium | D4 implementation folds into L2 (+0.5 h, ~20 + 60 lines; L2 stays under 400) | — | — | Low | Low |
| R11 | Technical | Guards and snapshots | New fixture names a target; tests mounted wrongly | FR-12 hit (`fly::` in a `_tests.rs` file); surface diff | Low | Low | Fixture has no target (design). `run_scope_tests.rs` mounted with `#[path]` from `run.rs` (existing pattern, e.g. `delivery_preview.rs:423`). D4-B adds no flag; D4-C changes `surface.json`, completions and `opv schema` | L6 gate | — | Low | Low |
| R12 | Runtime | `--remote` run regresses | Same `launch`; tests are local only | Remote note unscoped | Low | Low | One unit test: `run --remote` on the T7 fixture names no `output/` key | Unit test | — | Low | Low |
| R13 | Observability | A fully filled run prints nothing; a dropped read (`.ok()`) is invisible | Existing behaviour | Cannot tell "no empty keys" from "read failed" | Low | Medium | Keep as is (existing); `--verbose` shows the `item get` calls. Optional later: one `--verbose` line when the read fails | `--verbose` | — | Low | Medium (accepted: unchanged behaviour, not introduced here) |

### Remaining Risks After Iteration 1

- High: none.
- Medium: none. (R8 and R13 keep a Medium *probability* at Low severity. R8 is out of this
  release's code and is detected by name; R13 is unchanged existing behaviour.)
- Low: all others.

### Iteration Summary (1)

- **Mitigations:** D4 + B5 + live gate (R1); one print site (R2); `activate()` + paired positive
  assertions + red-first evidence (R3); corrected row (R4); text renderer (R6).
- **Simplifications:** exec-only fake `op`; no product-name scope type; no reference parsing.
- **Trade-offs:** D4 relaxes the FR-4 v0.4 clear rule for one value source (TRIZ #3/#1 above).
- **Stop:** a second iteration over the revised design found no new High or Medium.

---

## Phase 3: Systemic Risk Review

- **Calibration risk.** No scoring signal. The only "calibration" is the root-cause claim, and it
  was wrong because the producer's own output contract (`missing=` suffix) was not read. Rule for
  future vets: read the child's diagnostic code before attributing a child failure to opv.
- **Observability risk.**
  - Bad decisions: the scoped note is the signal.
  - Premature completion: #264 must not close on unit tests. The live gate in R1 covers it.
  - Policy regressions: `clears_another_products_managed_keys` and B5 pin both sides of D4.
- **Complexity vs utility.** The design is already lean. The vet removes a type distinction
  (product-name scope), a second print site and fake-`op` parsing. It adds one owner decision.
  Simplest viable version: C1 + C3 + C5 + scoped read + D4.
- **Oversimplification risk.** The design's §3 "filter only the printed note" alternative would be
  too simple (FR-57 stays breached). Rejecting it is correct. Dropping D4 would leave the
  reporter's real cycle in place.
- **Incremental delivery.** L1 (reader) → L2 (run + D4) → L4 is a clean chain. L3 is independent.
  Each lane can be reverted alone. `ReadScope::Whole` keeps every other caller byte-identical (T6).

### Final Outcome

All High and Medium risks are mitigated to Low by the changes below. The design's goal and core
mechanism stand.

---

## Conflicts with the design's recommended owner decisions

1. **Rule 5 ("the clear list is unchanged") conflicts with fixing #264.** It is presented as a
   non-decision, but it is the verified failure. A new **D4** is required:
   - **A. Keep clearing.** #264 stays open with the documented workaround (run the producer
     outside `opv run`). Honest, no code.
   - **B. Recommended: a run does not clear a declared `source = "infrastructure"` name.** opv
     never holds that value, so the parent environment is its only carrier. Stored and `from`
     names stay cleared. One names-only note lists inherited names that are present. No flag.
   - **C. Opt-in `--inherit <NAME>`**, limited to declared infrastructure names. Explicit, but a
     surface change: `surface.json`, completions, `opv schema`, docs, about +1.5 h.
2. **D1-A (note only): agree**, with the R4 correction: a *missing* field is expected to stop
   `op run` itself, so "nothing blocks" holds for opv but not for the hand-off.
3. **D2-A: agree**, plus the text renderer.
4. **D3-A: agree.**

---

## Required design changes

1. **(R1)** Rewrite §1.3-§1.4. Use the evidence: no `missing=` suffix; `inputFromEnvironment`
   requires four names; they are declared infrastructure keys of `zonetico-private-acceptance`;
   `run.rs:376-385` strips them. Remove the claim "the real blocker was the selected product's own
   three keys". Add D4 (above). Add B5. Add the live names-only re-run as the gate for closing #264.
2. **(R2)** Replace the rule 3 mechanism. A scoped read never prints the needs-value note; `run`
   prints `needing ∩ wanted` once after the read, whether or not it tidied. `ReadScope` is built
   from `wanted` KeyIds (`ReadScope::Whole` unchanged for every other caller).
3. **(R3)** Test plan: every `run` unit test holds `activate()`. Every negative assertion has a
   positive partner in the same run. T5, T15, T16 run on both the tidy and the non-tidy path.
   T9, T12 and B2 are shown red on `7cc0b6dd` in the PR.
4. **(R4)** §2.3 row 2: split empty from missing; mark "missing → `op run` refuses" as inferred.
5. **(R6)** L3 also changes `write_text`; add T21 `preview_text_names_supplied_at_sync_keys`.
6. **(R7)** L4's fake `op` execs only (`tests/local_delivery.rs:408` pattern).
7. **(R8)** Rewrite follow-up #2: infrastructure keys must not claim fields in `resolve`
   (`convention.rs:185-188`), and `refuse_stored` must be scoped by `--product`
   (`sync.rs:1015`, `:1602`). Correct the §1.5 `sync --product` row ("blocking is scoped",
   except `refuse_stored`).
8. **(R12)** Add one `--remote` note-scope unit test to L2.
9. Minor: §5.1 says FR-37 covers test fixtures. It exempts `*_tests.rs`; FR-12 does scan them.

## Delivery steps after this vet

| id | change | est. h (was) |
|---|---|---|
| L1 | Scope from `wanted` KeyIds; scoped read never prints the needs-value note; T1-T6 | 3.0 (3.0) |
| L2 | + D4-B clear-list rule and note, + remote test, tests on both tidy paths | 3.0 (2.5) |
| L3 | + `write_text` line and T21 | 1.25 (1.0) |
| L4 | exec-only fake `op` (saves time); + B5 | 2.0 (2.0) |
| L5 | + D4 in `docs/usage.md`, FR-4 decision line in `requirements.md`, deliver-only §6.4 `opv run` row | 1.25 (1.0) |
| L6 | unchanged, plus red-first evidence check | 1.0 (1.0) |
| L8 (new, owner) | names-only re-run of the Zonetico workflow; gates closing #264 | 0.25 |

Critical path L1 → L2 → L4 → L6: **9.0 h** (was 8.5 h). With D4-C instead of D4-B, add about
1.5 h to L2/L5 and the `surface.json` diff. Every lane stays under about 400 changed lines. File
ownership is unchanged: D4 lives in `run.rs`, inside L2.
