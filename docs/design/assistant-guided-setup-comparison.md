# FMECA comparison: assistant-guided setup, before and after the Part VI reframe

Subject: [assistant-guided-setup.md](assistant-guided-setup.md).
- **Before:** Parts I–V as written, recorded in [assistant-guided-setup-fmeca.md](assistant-guided-setup-fmeca.md).
- **After:** the reframed design, where Part VI (R1–R7, §20–§23) wins over Parts I–V on any conflict.

Reviewer: FMECA reviewer agent, 2026-10-18. The design doc was not edited, and nothing is committed.

**Inputs.**
- Before: six DeepSeek worker analyses (78 raw failure modes) and the independent [review](assistant-guided-setup-review.md).
- After: six new worker analyses of the reframed design (76 raw failure modes) and the `evaluate` architecture review (`opv-fm2-evaluate/.delivery/evaluate/evaluation.md`).
- Both passes: the code at v0.11.0.

**Record.** Both passes are in the same store, `.delivery/fmeca/fmeca-state/`:
- Before: `assistant-guided-setup-technical-plan` and `asg-<k>-technical-plan`.
- After: `assistant-guided-setup-reframed-technical-plan` and `asgr-<k>-technical-plan`.

Exports are in `.delivery/fmeca/export/`. `fmeca-mcp check` prints `ok` for all 14 logs.

**Same calibration in both passes.**
- `security_breach` only when a usable value reaches an unintended reader, or access control is lost.
- `service_outage` only when the running application fails.
- `happens_in_normal_use` only when the ordinary journey, as written, triggers the failure.
- `requires_misuse` for deliberate oracle attacks.
- A residual stays medium wherever a value-exposure or outage path survives. The 3×3 matrix never scores high severity as low.

**How the after pass was built.**
- Every failure mode from the before pass was carried over unless the reframe eliminates it. Carried modes kept their ids, so the two passes join on id.
- The new worker findings were checked against the reframed design and the code. Each one was merged into a carried mode, kept as new, or dropped.

## 1. Before → after, per perspective

H/M/L = raw criticality. "Res ≥ M" = failure modes whose residual stays medium or above after the proposed changes. Response classes come from the tool: minor_fix / restructure / re_architecture. Readiness is `ready` counting planned mitigations; `verified.ready` is false in all 14 sessions because no change is built.

| Perspective | FMs before → after | Raw H/M/L before | Raw H/M/L after | Res ≥ M before → after | Response classes before (minor / restr. / re-arch) | after | `ready` before → after |
|---|---|---|---|---|---|---|---|
| Cross-cutting (parent) | 5 → 6 | 3 / 2 / 0 | 4 / 2 / 0 | 2 → 2 | 0 / 3 / 2 | 0 / 3 / **3** | false → false |
| Runtime | 6 → 5 | 3 / 3 / 0 | 2 / 1 / 2 | 2 → 2 | 0 / 6 / 0 | 2 / 3 / 0 | false → false |
| Ergonomics | 9 → 8 | 1 / 8 / 0 | 1 / 6 / 1 | 0 → 0 | 0 / 9 / 0 | 1 / 7 / 0 | true → true |
| Confidentiality | 11 → 12 | 2 / 8 / 1 | 3 / 8 / 1 | 2 → 2 | 1 / 10 / 0 | 1 / 11 / 0 | false → false |
| Consistency | 9 → 9 | 3 / 6 / 0 | 2 / 7 / 0 | 1 → 1 | 0 / 9 / 0 | 0 / 9 / 0 | false → false |
| Recovery | 8 → 9 | 0 / 6 / 2 | 0 / 7 / 2 | 0 → 0 | 2 / 6 / 0 | 2 / 7 / 0 | true → true |
| Adoption | 6 → 7 | 0 / 6 / 0 | 1 / 5 / 1 | 0 → 0 | 0 / 6 / 0 | 1 / 6 / 0 | true → true |
| **Total** | **54 → 56** | **12 / 39 / 3** | **13 / 36 / 7** | **7 → 7** | **3 / 49 / 2** | **7 / 46 / 3** | 3 of 7 ready → 3 of 7 |

**Critical items** (single point and raw high):
- Before: `fm-asg-honest-limit-understated` and `fm-asg-r4-platform-channels`.
- After: the same two, plus `fm-asgr-deployed-actuator-undefined`.

**How the after set was built.**
- **Carried, 50 of 54.** Their reframe marks:
  - unchanged: 26;
  - reduced: 17;
  - widened: 7.
- **Eliminated, 3**, not carried because they can't be expressed under the reframe:
  - `fm-ergonomics-approve-runs-person-steps` (review M3), by R1;
  - `fm-ergonomics-approval-state-invisible`, by R1;
  - `fm-consistency-policy-relaxation` (review M4 relaxations), by R6, provided the CI gate checks the `opv apply` record.
- **Merged, 1:** `fm-runtime-gate-ignores-delivery` went into the receipt-staleness mode.
- **New, 6:**
  - `fm-asgr-deployed-actuator-undefined` (R1 × R4);
  - `fm-ergonomics-actor-model-not-restated`;
  - `fm-confidentiality-tier-equality-leak` (R3 × R4);
  - `fm-consistency-r5-generated-annotations` (R5 × #178);
  - `fm-recovery-r4-no-break-glass` (R4);
  - `fm-adoption-r2-parameterized-rules` (R2: the intended cost of closing H1).
- **The after workers' 76 raw findings:**
  - 6 became the new modes above;
  - 66 merged into carried modes;
  - 4 were dropped:
    - core dumps: already handled in `src/hardening.rs`;
    - a reference smuggling a value through a filename: the assistant already holds any value it could smuggle;
    - two ephemeral-environment findings: phase H, review L8.

**What moved, beyond the totals.**
- **Down:**
  - `run-redaction-mutates-output` (H4): high → low, because §22.1 adopts always-on, secret-only redaction of values of 8 bytes or more.
  - `presence-all-prod` (M10): medium → low. R6 asks a categorical question for each production environment.
  - `agent-mode-misdetected` (M2): medium → low. Agent mode is presentation only.
  - `scanner-junk-keys` (M9): high → medium. R5's `ignore` is an annotation.
  - `screening-false-positive`: medium → low. Only guidance is screened.
  - The approve/apply race (M3) and quiet relaxations (M4) are gone.
- **Up:**
  - `document-contract-change`: medium → high. As written, 13 MCP tools are replaced by 5 with no deprecation phase.
  - `tier-defaulted`: severity rises to `security_breach`. The tier now decides where the assistant may import and what R4 protects.
- **New highs:**
  - the deployed-tier actuator gap;
  - the actor-model contradictions between Part VI and §4.1/§5/§6.1/phase E;
  - the tier-equality leak.
- **Unchanged: the residual tail.** The seven medium residuals are the same seven failure modes in both passes:
  - H3 (honest limit);
  - R4's platform channels;
  - H4 encodings;
  - kind downgrade;
  - rotation (M11);
  - retire;
  - scanner coverage.

  None of them is addressed by any reframe.

## 2. Where `re_architecture` items cluster

| Pass | `re_architecture` failure modes | Component |
|---|---|---|
| Before | `fm-asg-honest-limit-understated` (H3), `fm-asg-r4-platform-channels` | **The value boundary against a same-user shell** (`boundary.*`) |
| After | the same two | the same component |
| After | `fm-asgr-deployed-actuator-undefined` | **Deployed-tier actuation** (`actuators.deployed_tier`): who writes staging and production when R1 removes the assistant and R4 removes the laptop |

**One cluster in both passes: the value boundary against a same-user shell.**
- No reframe moves it.
- R4 narrows only the 1Password channel. Platform CLIs, deployed logs, pty-driven person commands and CI-workflow PRs remain.
- Closing it needs separation at the level of credentials or the OS. That is outside opv, and the review already proposes that the owner accept it.

**The reframe adds one structural question: deployed-tier actuation.**
- It is a decision, not code: merge-time CI application with a scoped identity, or an owner account, decided by the A-1 spike.
- Its residual reaches low once it is decided.
- It is the only structural item the reframe creates.

## 3. Verdict

**Adopt Part VI as the 0.12.0 direction, with the corrections in section 4.** The numbers support this, but not because the totals fall: they don't (54 → 56 failure modes, 12 → 13 raw high, 7 → 7 residual medium).

What the numbers show:
- **The reframe removes the risks it was built for, at their root.**
  - The review's oracles are closed on the assistant surface: H1 over MCP and H2's `adopt`/`init` comparisons.
  - The approve/apply race (M3) and quiet relaxations (M4) can no longer be expressed.
  - Four failure modes drop to low raw.
  - Minor fixes rise from 3 to 7.
- **Most of what it adds is integration debt, not structural risk.**
  - Of the six new failure modes and the one upgraded to high, four are document or contract fixes, each with a low residual:
    - the actor model not restated;
    - tool replacement with no deprecation;
    - generated contracts losing annotations;
    - parameterised rules (an intended cost of closing H1).
  - Two are design rules the reframe missed, each closable by one sentence:
    - the tier-equality leak;
    - the missing break-glass account.
  - One is structural: deployed-tier actuation.
- **The residual tail is untouched,** so the reframe is not a reason to relax anything else. The seven residual mediums are the boundary limit (to be accepted by the owner) and six operational risks:
  - rotation;
  - retire;
  - scanner coverage;
  - encodings;
  - kind downgrade;
  - R4's platform credentials.

  Rotation and retire belong to phases C and G, not 0.12.0.

**Components that need more redesign before they are built:**
1. **Deployed-tier actuation and R4** (structural). Run the A-1 spike first. Define who writes deployed structure and values, how CI is approved, and the break-glass account. Extend R4 to platform credentials.
2. **Fixed comparisons in R3** (`same value as a lower tier`, `CompareFixedPair`, the committed `.env.example`). Under R4 they become oracles against the tier R4 protects. Report cross-tier results only to the person and CI.
3. **R3's assistant-triggered local import.** It contradicts R1 ("never writes to 1Password"), #173 and #176. Restrict it to an explicit `local` tier with provenance, or make it a step in the person's `opv apply`.
4. **R5 and R6 file ownership:**
   - names leave the contract only by retire;
   - annotations live outside generated contracts;
   - the bindings file is committed and checked against the record `opv apply` writes.
5. **The client surface.** Restate §4.1, §5, §6.1 and phase E; make `opv_propose` pure; plan the deprecation of 13 tools down to 5.

**The `evaluate` review against the FMECA.**

| `evaluate` classification or proposal | FMECA | Agree? |
|---|---|---|
| Value boundary, R1 split, R2 intent, R3 diode, R6 contract-in-repository: **Essential** | They close H1 (MCP), H2 (`adopt`/`init`), M3 and M4; their own new risks have low residuals except R4's | **Agree** |
| R4: **Useful**, strong form **Speculative** pending A-1 | R4 also creates the only new structural item (actuation), the break-glass gap and the tier-equality leak, and it does not cover platform credentials. The FMECA is stricter: R4 needs the A-1 spike and the actuation decision before it ships | **Agree, and the FMECA goes further** |
| Value states: ship the core four (absent, empty, set, unreadable) first | `placeholder` and `suspect` carry `suspect-blocks`, `suspect-reveals-class`, the `.env.example` oracle and the new tier-equality leak (a raw high). Shipping the core four first removes four failure modes from 0.12.0 | **Strong agreement** |
| R7 purpose tokens: **Useful**, defer to the contract-hardening track, with the canary scan as the 0.12.0 layer | R7 closes M1 (raw medium). H1's closure rests on approved-rule evaluation (D1), not on R7. Deferring is acceptable if D1 lands in 0.12.0, which the owner has decided | **Agree, on condition** |
| Cut ephemeral environments (C5) and provisioners (C15) from 0.12.0 | The ephemeral findings were dropped as phase H in both passes. The provisioner modes (mint orphan, low; credential expiry, medium) only apply once provisioners exist | **Agree** |
| Demote harness guard rules to defence in depth | The guard-install mode is medium with a low residual; the guards are not the control for H3 | **Agree** |
| Demote `opv run` redaction to a fast-follow behind R4 | `run-encoding-miss` is one of the seven residual mediums. R4 shrinks it to local values, which are still `security_breach`. `op run` already masks exact values, so deferring the encoding extension is acceptable, but redaction must not be gated on agent mode in the meantime | **Partly agree** |
| 13 tools, not 11; a deprecation plan is required (F11) | `document-contract-change` is now high raw because of this | **Agree** |
| Treat §22.1's "eliminated" labels as proposed controls | The FMECA keeps M1, M9, H1 and H2 as **reduced**, not eliminated; only M3, M4 relaxations and approval-state are eliminated | **Agree** |
| Write-only import blind spot (F9) needs an explicit acceptance | `r3-import-skips-updated` (medium, low residual) is closed by the person's `opv import --replace` | **Agree**; the FMECA proposes the mitigation |
| Scope (F14): probability **High** | `phasing` is kept at occasional, so medium, to stay comparable with the before pass | **Differs in probability only** |
| Not raised by `evaluate` | Deployed-tier actuation, the tier-equality leak, R4's platform channels, R5's observed set shrinking, the kind downgrade | The FMECA adds these |

## 4. Corrections to Part VI that both passes show are needed

1. **H1 is closed only if "approved" means the `opv apply` digest.** The assistant can write a `regex` into `secrets.toml` through its shell, so R2 closes the oracle over MCP only. R3's "rules a person approved" must mean "rule text in the digest recorded by the person's last `opv apply`". Add a gate test that covers both an MCP-declared rule and a hand-edited one.
2. **The committed `.env.example` check is still an oracle.** A local `git commit` puts the assistant's guess in the "committed" file. Drop it, or compute it only in CI against the default branch, as a warning for the person.
3. **The tool count is 13, not 11** (`src/mcp.rs` registers 13). Add a deprecation phase to Part V: old tools become aliases that return a typed `next` naming their replacement for one minor release.
4. **`op run` already masks exact values** (`src/app/run.rs:6-7`). G2, G27 and §22.1's H4 row should say the gap is encodings only. Part VII decision 4 still says "redact in agent mode" while §22.1 says "always on"; make it "always on, secret values of 8 bytes or more".
5. **§22.1's "eliminated" should say "reduced" for M1, M9, H1 and H2.**
   - M1: purpose tokens hold only with module-private constructors and no `unsafe`.
   - M9: an assistant can annotate a false positive as a real key.
   - H1 and H2: see items 1 and 2.
   - M4 is eliminated only if the CI gate checks the apply record.
6. **R4 does not reduce H3 "to the local tier".** The laptop's platform credentials (kubectl, az, fly, gh), deployed logs and CI-workflow PRs still reach production. Extend the tier policy to platform credentials, and say so in the honest limit.
7. **Cross-tier comparisons must not reach the assistant under R4.** "Same value as a lower tier" tells an assistant that can read dev the production value. Report it only to the person and CI.
8. **R3's local import contradicts R1, #173 and #176.**
   - Limit it to an explicit `local` tier (no target, no `confirm_env`).
   - Tag what it writes `assistant_imported` and keep those values out of comparisons and promotion.
   - Or move it into the person's `opv apply`.
9. **Resolve §23 before R4 ships.**
   - Who writes deployed-tier structure and values: CI on merge, with a scoped identity and the merged plan as its approval, or an owner account.
   - The break-glass account.
   - The A-1 spike decides between the two forms.
10. **R2/R6: `secret`→`config` is a relaxation.** Make `opv_propose` pure: it returns the diff and the plan and writes nothing.
11. **R5 file ownership.**
    - Names leave the contract only by retire (`declared_unobserved`).
    - `ignore` must be re-checked when an evidence span changes.
    - Annotations get a home outside generated contracts (#178).
12. **R6 bindings file lifecycle.**
    - It is committed and union-mergeable.
    - It is checked against the record that `opv apply` writes; "opv-written" alone is not a control.
13. **Receipts carry their age and the item versions they saw.** `next` shows the age, and the promotion gate recomputes in CI and never trusts a receipt.
14. **Restate the superseded parts under Part VI:** §4.1, §5, §6.1, Part V phase E and Part VII decisions 4 and 5.

---

# Third pass: the second reframe (§24, R8–R11)

**Subject:** §24 at the branch tip (`7534fb8`), read together with the owner's decisions of 2026-10-18. These decisions bind the calibration:
1. Access control is 1Password's vault permissions.
2. CI runs opv, and opv carries values only in memory and over stdin or a pipe.
3. Defects inside third-party tools are out of opv's scope.
4. "The assistant" is always an external model.

**Inputs:** six worker analyses of §24 at `0cfc96c`, with 87 raw failure modes.

**Record:** `assistant-guided-setup-reframe2-technical-plan` with six children `asgr2-<k>-technical-plan`, in the same store as the earlier passes. Exports are in `.delivery/fmeca/export/`. `fmeca-mcp check` prints `ok` for all 21 logs. The calibration rules are the same as before.

## 5. Three-way comparison: as written → reframe 1 → reframe 2

Columns are as in section 1. Each cell reads written → R1–R7 → R8–R11.

| Perspective | FMs | Raw H/M/L | Res ≥ M | Response classes (minor / restr. / re-arch) | `ready` |
|---|---|---|---|---|---|
| Cross-cutting (parent) | 5 → 6 → 5 | 3/2/0 → 4/2/0 → 2/3/0 | 2 → 2 → **1** | 0/3/2 → 0/3/3 → 0/5/**0** | false → false → false |
| Runtime | 6 → 5 → 7 | 3/3/0 → 2/1/2 → 1/4/2 | 2 → 2 → 2 | 0/6/0 → 2/3/0 → 2/5/0 | false → false → false |
| Ergonomics | 9 → 8 → 9 | 1/8/0 → 1/6/1 → 1/7/1 | 0 → 0 → 0 | 0/9/0 → 1/7/0 → 1/8/0 | true → true → true |
| Confidentiality | 11 → 12 → 15 | 2/8/1 → 3/8/1 → 1/13/1 | 2 → 2 → **0** | 1/10/0 → 1/11/0 → 1/14/0 | false → false → **true** |
| Consistency | 9 → 9 → 12 | 3/6/0 → 2/7/0 → 3/9/0 | 1 → 1 → 1 | 0/9/0 → 0/9/0 → 0/12/0 | false → false → false |
| Recovery | 8 → 9 → 9 | 0/6/2 → 0/7/2 → 0/7/2 | 0 → 0 → 0 | 2/6/0 → 2/7/0 → 2/7/0 | true → true → true |
| Adoption | 6 → 7 → 8 | 0/6/0 → 1/5/1 → 1/6/1 | 0 → 0 → 0 | 0/6/0 → 1/6/0 → 1/7/0 | true → true → true |
| **Total** | **54 → 56 → 65** | **12/39/3 → 13/36/7 → 9/49/7** | **7 → 7 → 4** | **3/49/2 → 7/46/3 → 7/58/0** | **3 → 3 → 4 of 7** |

**Critical items:** 2 → 3 → **1**. The one left is `fm-asg-honest-limit-understated`.

**Mitigations:** all of them are planned and none is verified. `verified.ready` is false in all 21 sessions.

**How the reframe-2 set was built:**
- **54 of the 56 after-pass failure modes were carried.** `fm-asgr-deployed-actuator-undefined` is eliminated by R8: whoever 1Password lets write a vault writes it, and CI only delivers. `fm-asg-r4-platform-channels` was merged into `fm-asg-honest-limit-understated`, because both now have one root: access that 1Password or a platform grants.
- **`fm-consistency-policy-relaxation` (review M4) is back.** R8 moves relaxation approval to PR review and the check, replacing R6's person `opv apply`.
- **10 failure modes are new.** Nine come from the workers and one from my own review (the CI courier).
- **Of the 87 worker findings:** 9 became new failure modes, 72 merged into carried ones, and 6 were dropped:
  - core dumps: already handled in `src/hardening.rs`;
  - channel and kind mismatch: belongs to delivery-transports' own FMECA;
  - a DevOps person writing directly to a platform: already detected by `opv status` and `opv history` as "changed outside opv";
  - offboarding a developer: decision 1, it is 1Password administration;
  - a value pasted while filling by hand: covered by P-6;
  - ephemeral lanes: phase H.
- **Decision 3:** no worker recorded a third-party-tool defect as its own failure mode. The CI courier failure mode covers only how opv hands a value to a tool. What the tool does with it afterwards is excluded under decision 3.

### The seven residual mediums from the earlier passes

| # | Residual | Status under R8–R11 | Why |
|---|---|---|---|
| 1 | `fm-asg-honest-limit-understated` (H3) | **Still medium**, narrowed | R9 keeps production off developer machines by vault permission, and local values are sandbox-grade. Three paths remain: DevOps machines (by design), migrated projects whose groups still let developers read production vaults, and production platform logins left on a laptop. opv can only report them. This becomes an owner acceptance under decision 1, with the separate admin account as the stronger option. Reclassified from structural to cross_cutting: closing it is 1Password and platform configuration, not an opv architecture change |
| 2 | `fm-asg-r4-platform-channels` | **Merged into #1** | The same root, access granted outside opv. `doctor` reports production platform logins |
| 3 | `fm-confidentiality-run-encoding-miss` (H4) | **Now low** | On a developer machine `opv run` injects sandbox-grade values, so a missed encoding is a test key to rotate. The DevOps-machine case is #1 |
| 4 | `fm-confidentiality-r2-kind-downgrade` | **Now low** | §24 makes secret→config a flagged PR change whose check fails until accepted. A credential-shaped check in CI runs before any sync |
| 5 | `fm-runtime-rotation-revokes-in-use` (M11) | **Still medium** (raw high → medium) | R11's overlap and observed rollout leave two paths: a process that read the old value at boot and is invisible to rollout status, and an undeclared outside consumer. Phase G, not 0.12.0 |
| 6 | `fm-runtime-retire-prunes-read-key` | **Still medium** (raw high → medium) | Low in generated languages, because the build fails while the key is still read. Still medium where the scanner is the fallback: `needs` at the deployed revision misses dynamic or lazy reads |
| 7 | `fm-consistency-scanner-missed-names` | **Still medium** | Impossible in generated languages (R10). Unchanged for the scanner fallback |

**Out of scope under decision 3:** none of the seven. None of them is a defect inside a third-party tool.

### New risks R8–R11 introduce

All are recorded with a planned mitigation and a low residual:

| Failure mode | From | Raw | The risk |
|---|---|---|---|
| `fm-runtime-set-not-delivered` | R8 | **high** | A value filled in the 1Password app is `set`, and the gate passes, while CI hasn't delivered it. Fix: the gate requires delivery evidence whose version equals the item version, and CI runs `opv changed` then `opv sync` on a schedule |
| `fm-consistency-generated-module-stale` | R10 | **high** | A generated module not regenerated after a contract change voids R10's retire and boot guarantees. Fix: CI regenerates and diffs, and the module embeds the contract digest |
| `fm-asgr2-capability-misread` | R8 | medium | 1Password doesn't always expose effective permissions, so `next` names the wrong actor. Fix: an `unknown` capability state |
| `fm-runtime-module-required-ignores-presence` | R10 | medium | The boot check demands a key that is excepted in that environment, so the deploy rolls back |
| `fm-confidentiality-module-prints-value` | R10 | medium | The generated check prints a value in a startup error, outside opv's scrubber |
| `fm-confidentiality-ci-courier-argv-env` | R8, decision 2 | medium | A transport puts a value in argv, the environment or a file on the CI runner. Fix: one stdin/pipe-only courier and a transport test with S7MARKER |
| `fm-consistency-app-fill-wrong-binding` | R8 | medium | A value is filled in the app under another label or item, so opv keeps asking for it |
| `fm-ergonomics-team-dev-env-gaps` | R8 | medium | Grant lag, missing personal items, or later keys missing from a team-managed environment |
| `fm-adoption-codegen-language-gap` | R10 | medium | Four languages first, and adoption needs refactoring, so guarantees differ across a portfolio |
| `fm-consistency-policy-relaxation` | R8 replaces R6 | medium | Relaxations are approved by ordinary PR review again |

**Surfaced, not introduced:** `fm-confidentiality-assistant-reads-env-for-names`. §3.2 asks the assistant to find names the scanner can't, so it opens `.env` files. Under R9 those values are sandbox-grade. The fix is names-only tools (#176) plus a guard against reading `.env*`.

## 6. Where `re_architecture` items cluster now

| Pass | `re_architecture` | Component |
|---|---|---|
| As written | 2 | The value boundary against a same-user shell |
| Reframe 1 | 3 | The same, plus deployed-tier actuation (R1 × R4) |
| Reframe 2 | **0** | — |

Two moves account for the drop to zero:
- **Deployed-tier actuation is eliminated by R8.** People with vault write access fill values, and CI only delivers.
- **The value-boundary cluster is no longer structural for opv.** R8 and R9 put the tier boundary in 1Password's vault permissions (decision 1), so what remains is configuration plus an owner acceptance.

This is a reclassification, not a disappearance. The residual is still medium and still the one critical item. It now lives in 1Password group membership and platform logins, which opv reports but cannot change.

## 7. Verdict

**The numbers support adopting R8–R11, together with R1–R7 and the corrections in section 8, as the 0.12.0 direction.**

| | As written | R1–R7 | R8–R11 |
|---|---|---|---|
| Structural (`re_architecture`) items | 2 | 3 | 0 |
| Critical items | 2 | 3 | 1 |
| Residual medium | 7 | 7 | 4 |
| Raw high | 12 | 13 | 9 |
| Sessions ready on planned changes | 3 | 3 | 4 |

The failure-mode count rises to 65 because R8 (capability, app-side filling, the CI courier) and R10 (generated modules) add surface. All ten new failure modes reach a low residual with a design-text or test change.

**Which reframes do the most work:**
- **R10** moves the most. Retire, scanner coverage, the shrinking contract and generated encodings all improve. Its cost is four new failure modes (stale module, required set, printed value, language gap), all cheap to close. Its guarantees stop at the four generated languages, which is why two of the four remaining mediums survive.
- **R8 and R9** remove the structural cluster by delegating access to 1Password. That is right only if the owner accepts the DevOps-machine residual and teams actually tighten vault groups; opv can report loose groups but not fix them.

**The four remaining mediums:**
- **H3 (owner acceptance).** Accept it explicitly under decision 1 and recommend the separate admin account.
- **Rotation and retire (phases G and C).** They don't block 0.12.0.
- **Scanner coverage for non-generated languages.** It is mitigated by stated coverage and doesn't block 0.12.0.

**The `evaluate` review against reframe 2.** Its "core four value states first" advice still removes the tier-equality and `.env.example` oracles, and now two R10-adjacent states (`suspect`, `placeholder`) as well. Its demotion of the guard rules is confirmed: under R9 they are defence in depth on sandbox-grade machines.

## 8. Remaining corrections to the design text after §24

Still open from section 4:
1. H1: "approved" must mean the digest recorded by the person's last `opv apply`, or, under R8, the merged contract checked by CI. Pick one and test the hand-edited `secrets.toml` case.
2. Drop the `.env.example` equality check, or compute it only in CI against the default branch.
3. The MCP tool count is 13, not 11; add the deprecation phase.
4. Make the redaction rule consistent. P-5 says "every injected value", §22.1 says secrets of 8 bytes or more, §4.4 ties it to agent mode, G27 says the child is unscrubbed, and decision 4 says agent mode. Make it "always on, secrets of 8 bytes or more", and note that `op run` already masks exact values.
5. Change §22.1's "eliminated" to "reduced" for M1, M9, H1 and H2. §24's claim table should say "a developer machine reaches only local/dev **where vault groups are tight**; opv reports loose groups".
6. Keep "same value as a lower tier" off assistant surfaces. R9 makes dev readable by design, so the bit discloses an equal production value.
7. R3's assistant-triggered local import contradicts R1, R8 ("people set up values"), #173 and #176. Restrict it to an explicit local tier with provenance, or drop it.
8. R5 and R6 file ownership: names leave only by retire; `ignore` is re-checked; annotations live outside generated contracts; the bindings file is committed and checked against the recorded apply.
9. Receipts carry their age and the item versions they saw; the gate recomputes in CI.
10. Restate §4.1, §5, §6.1, Part V phase E and Part VII decisions 4 and 5 under Parts VI and §24. The third-pass workers still read "approve runs the person's steps" as current.

New from §24:

11. **Relaxations: R6 or R8?** R6 says a relaxation needs the person's `opv apply`; R8 says relaxations "show in the PR diff and the check". State one rule. If it's the PR, make relaxations a separate required check status.
12. **§23 is answered by R8.** Mark merge-time application as declined. CI does not write to 1Password beyond delivery evidence (decision 2). Remove the open question.
13. **Set is not delivered.** The promotion gate must require delivery evidence equal to the item version, not just `set`. The CI recipe runs `opv changed` and `opv sync` on a schedule, so values filled in the app are delivered.
14. **Capability needs an `unknown` state** with its source. A 1Password refusal is a typed finding.
15. **R10 module rules:**
    - the required set is per environment (contract × presence);
    - errors name only the key and the rule;
    - CI checks freshness against an embedded contract digest;
    - each component states whether it uses the module.
16. **The courier rule from decision 2 belongs in R8 as a testable invariant:** stdin or a private pipe only, with a transport test. Verify that the Key Vault path ("named pipe or stdin") has an `az` input that is neither an argument nor a file.
17. **Emergencies:** "no special path" should name 1Password's account recovery and a second writer per deployed-tier vault, which `opv people` reports.
18. **A-1 is still open.** R9(a)'s separate admin account is the stronger form, and the DevOps-machine residual needs the owner's explicit acceptance.
