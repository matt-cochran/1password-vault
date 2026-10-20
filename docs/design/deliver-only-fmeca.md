# DESIGN-FMECA review: deliver-only (#206)

Review of `deliver-only.md` (b088610, opv 0.12.3) by a separate agent, per the owner's DESIGN-FMECA procedure.
**Verdict: approve after the fixes listed below.** No owner principle is violated.

## Phase 1: Architecture validity

| Component | Purpose | Class | Evidence | Simpler alternative / note |
|---|---|---|---|---|
| `source = "infrastructure"` | per-key opt-in | Essential | Proven | none |
| stdin intake, multi-document | the value path without argv, env or files | Essential | Adapted | `--supply-fd`: drop (§13 Q5) |
| Admission, shape rule, `Stored` refusal | fail closed; one source of truth | Essential | Adapted/Proven | none |
| Serial / staleness | stops an old run overwriting a newer value | Useful | Speculative (producer serials untested) | keep, with an override and better serials (S6, S7) |
| `s1` tag + carried set | value-free memory; keeps revisions valid | Essential | Adapted from `a1` | none |
| Plan-id exclusion; evidence failure as error | no value bit; honest outcome | Essential | Adapted | error must cover more than `Err` (S1) |
| Re-read merge in `record` | concurrent writers | Useful | Speculative (no 1Password CAS) | rebuild from the fresh read, then refuse on a second change |
| Limits: 1 MiB / 64 KiB / 256 | memory bound | Useful (total cap); Unjustified (per-value cap) | Proven | store guard already caps values (`ValueTooLarge`) |
| `kind = "config"` allowed | non-secret infra settings | Speculative | contradicts code (S3) | refuse at load |
| Fly + GitHub only | bounded scope | Essential | Proven | none |
| `ci workflow --supply` | the paved path | Useful | Adapted | needs value-safe producer idioms (S4) |

**Revised architecture.** Retained: everything except the items below. Simplified: per-value
limit removed, keeping the total cap and store limits. Merge becomes "re-read, recompute, write,
or `item_changed`". Removed: `--supply-fd` and supplied `kind = "config"`. Demoted: serial stays
required, but `--rotate p/K` overrides `Stale`.

## Phase 2: Iteration 1 risk table

S/P = severity/probability. Res = residual.

| # | Domain | Failure mode: cause → effect (evidence) | S/P | Poka-yoke + observability | Res |
|---|---|---|---|---|---|
| S1 | Runtime | A supplied write is confirmed, but `record` returns **Ok** with the name unrecorded: the target lists no version yet (`delivery.rs:449`), an unrecordable version (`:518`), or no item (`:455`). §5.4 makes only `Err` fatal (`sync.rs:1216`), so the run exits 0 with no `s1` line and no serial. It then shows `Unrecorded`, and immutable keys are stuck | High/Med | Any supplied name left without an `s1` line → `DeliveryUnverified{NotRecorded}`, exit 8. `record` returns per-name outcomes. Obs: T12 adds unlisted/unencodable cases | Low/Low |
| S2 | Runtime/UX | Empty stdin, or a supply omitting an in-scope key, holds it and exits 0 (§6.4). Terraform rotated the password, the producer printed nothing: green job, `verify` says `verified` | High/Med | Refuse `NoDocuments`. A supplying run must supply every infrastructure key in its selected scope, or `SupplyRefused{NotSupplied}`. Disjoint producers narrow with `--product`/`--target` or share a pipe (TRIZ: separation in space, no new flag). Obs: refusal names the keys | Low/Low |
| S3 | Tech | A supplied `kind = "config"` key on a GitHub target that publishes config is refused on every run as `concealed-config` (`variables.rs:79-80`), yet §2.2 allows it. Short config values (<8 B) also escape the output guard (`scrub.rs:127`) | Med/Med | Load refuses `kind = "config"` with `source = "infrastructure"`. Every supplied value is a secret, so `TooShort` covers all. Obs: T17 row | Low/Low |
| S4 | Runtime | Leak through producers that opv's paved path writes: `${{ steps.x.outputs.v }}` in the producer block is expanded into the step's logged script, and jq errors can quote input. §12.2 puts producer stderr out of scope, but §8.1/§8.4 are opv's own template | High/Med | Template emits `jq -e '.x.value \| strings // error("x missing")'` (constant message) and a comment forbidding `${{ }}`. A check refuses non-`github.*` `${{ }}` in a step piping to `--supply-stdin`. Obs: golden T19 | Med/Low |
| S5 | UX | `--rotate p/K`, added to the YAML for adoption, is left in. Every later run then overrides immutability silently (§4.3) | Med/Med | `ci workflow` never emits `--rotate`. Docs run a rotation as `workflow_dispatch` with a boolean input. The sync line prints `rotated (immutable) p/K at serial N` and `status` shows the last rotation. Obs: the run log | Low/Med |
| S6 | Runtime | Stripe serial `github.run_number`: a re-run attempt keeps the number. If the helper makes a new secret, the result is `SerialReused` and the run is stuck while Stripe already signs with the new secret. §5.1 also says a re-run "reads as stale", but it reads as *equal* | High/Med | Derive the serial from the producer's own object (the Stripe endpoint's secret creation time), not from CI counters. Fix the §5.1 text. `--rotate p/K` overrides `Stale`/`SerialReused`, for producer resets such as a Terraform state migration. Obs: the refusal shows the recorded and supplied serials | Med/Low |
| S7 | Tech | **Older-opv analogue of the `a1` hazard.** `decode_evidence` drops unknown tags (`domain/delivery.rs:142-148`), and `record` drops lines outside the binding set (`delivery.rs:472`). An old opv with an old manifest (a rollback run) or a key leaving the set erases `s1`, so the serial high-water is lost and a later old-serial supply is accepted. The delivery claim fails safe (`Unrecorded`); **staleness fails open**. Old opv also re-serializes `Receipt` and drops `supplied` | High/Low | Extend §4.3's "no evidence → `Unproven` unless `--rotate`" to **all** infrastructure keys the target lists. One rule, not two. Obs: `Unrecorded` in plan/ready | Low/Low |
| S8 | Delivery | GitHub cancels the *pending* job in a concurrency group when another queues, whatever `cancel-in-progress` says. A scheduled `--on-change` sync in `opv-sync-<env>` can cancel a pending supply job after Terraform rotated → outage. The rename from today's `opv-sync` (`ci_workflow.rs:140`) also splits old and new generated jobs | High/Low-Med | Supply in the same job as `terraform apply`. Scheduled non-supplying jobs use another group and rely on the re-read. Migrate old group names explicitly. Obs: `ready --gate` → `supplied_not_delivered` | Med/Low |
| S9 | Runtime | Two supplying runs race. Both pass the staleness check, and the older serial writes last. The §5.3 merge keeps "this run's" line | High/Low | At the re-read in `record`, a fresh line for a supplied name with a higher serial → `Partial` + `Stale` after write, exit ≠ 0. 1Password has no CAS: the residual window is accepted. Obs: red run naming both serials | Med/Low |
| S10 | Runtime | §5.1 table: equal serial + same fingerprint = idempotent, even when the target `Drifted` → drift not repaired | Med/Low | Idempotent only when the target state is `AsSupplied`. Otherwise follow §4.3 or write | Low/Low |
| S11 | Tech | `Undeclared` echoes the unknown name (§4.1). A base64 value with one `/` can pass the key-reference grammar | Med/Low | Echo only names that are declared keys. Report others by position, still offering the closest key | Low/Low |
| S12 | Runtime | A producer that never closes stdin blocks the read until the job timeout | Low/Low | Bound the read by the run budget → `InputInvalid{Timeout}` | Low/Low |
| S13 | Delivery | Adding the attribute breaks every other workflow or teammate pinned to opv < 0.13. This is fail-loud by design | Med/Med | Migration step 0: bump all pins first. CHANGELOG names it | Low/Low |

**Checked, sound:** the deploy SA only reads boundaries (`access_create.rs:267-268`), so CI cannot write
1Password values (§7, T14). The plan id has no value bit (`provenance.rs:54-94`). Fingerprints
stay in the state vault. Serde text is never shown.

**Remaining after iteration 1.** High: none. Medium: S4 (people hand-edit YAML; `--check` only
detects) and S5 (a person can still pass `--rotate`, but the result is visible). Both are bounded by
the "people apply" principle: removing them would need opv to own the producer or forbid rotation.
Low: the rest. Stopping: more mitigation adds surface, not safety.

## Phase 3: Systemic review

- **Calibration.** The serial is the only trust signal, and it is unvalidated. S6/S7 make it fail
  closed. Validate on staging Terraform/Stripe runs first.
- **Observability.** Premature completion (S1, S2) becomes a non-zero exit. Document that
  `verified` for a supplied name means "unchanged since supplied", not "current".
- **Over-engineering.** Drop `--supply-fd`, the per-value limit and supplied config. The rest
  is justified.
- **Incremental delivery.** Step 0 and two lanes is clean. Rollback is to revert the attribute and
  restore the field (`s1` lines then drop safely once S7 is fixed). infra keeps direct delivery
  until verified.

## Recommendations on §13

1. **Serial required:** yes. Add a `--rotate` override and producer-derived serials (S6).
2. **Stored field:** refuse, as designed.
3. **Unproven on adoption:** one `--rotate` run, applied to all infrastructure keys (S7). An attest
   step would need a person to hold the value, which conflicts with "never stored".
4. **8th value state `supplied`:** adopt. Rows outside the closed set would break inventory
   consumers.
5. **`--supply-fd`:** no. stdin only.
6. **Pinned targets:** file a 0.14 issue only when a user needs it. Keep the load refusal.
7. **`opv run`:** a note. Refusing would block local runs for every other key.
