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
