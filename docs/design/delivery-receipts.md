# Delivery receipts: verifiable, value-free proof of what a product was delivered (#106)

Status: built for 0.6.0, 2026-10-13. Owner decisions: option B, with multiple products considered
(§5), shipped in 0.6.0.

## 1. The need

An infrastructure consumer promotes one product at a time on a shared host (Fly) and reuses
records it has already accepted for products that did not change. It needs a
machine-readable answer to: *"Is product P in environment E (account A, target T) still
running exactly the binding set opv delivered, and which revision is that?"*. The answer
must never contain a value or a value-derived digest. And it must not present a random
marker or an environment label as proof of equality.

opv already produces three kinds of evidence. This adds the fourth:

| Evidence | What it proves | Where |
|---|---|---|
| Readiness (`opv ready`, `receipt_id`) | what is declared, saved and missing, now | FR-51 |
| Reviewed plan (`plan_id`) | the exact intent a person reviewed | FR-41 |
| **Delivery (new)** | that a confirmed write put this binding set on the target, and whether the target still holds it | this document |
| Deployed generation | whether the running release uses the delivered values (staged vs deployed) | per provider |

## 2. Terms

- **Binding set**: for one `(account, environment, product, target)`, the sorted set of
  `(target name, source field)` pairs opv manages. The source field is the 1Password
  `(item id, section, label)` the value comes from, so a shared key (`from`, FR-45) names
  its source.
- **Delivery revision**: `drv-<26 chars>`, 128 random bits, minted once per confirmed
  delivery of a whole binding set. It is opaque and carries nothing about values.
- **Private evidence**, per name: the store's version as listed after the confirmed write
  (a Fly digest, a Key Vault version id, a GitHub `updatedAt`) and a keyed fingerprint of
  the 1Password value written (HMAC-SHA256 under the ledger key, FR-54). It is visible only
  to someone who can already read the values. Never in output, logs or argv.
- **Recorded source versions** (C2): the delivery item also holds a non-secret
  `source versions` field, one `v1|<item_id>|<version>` line per source item the sync read,
  sorted by item id and holding ids and integers only. It is written only after a sync whose
  writes the target confirmed; an unconfirmed sync keeps whatever the item already held.
  `opv changed` reads that one field back and compares each version with `op item list`.
- **Public receipt**: the JSON a person or agent keeps, with names, ids and times only (§4).

## 3. Semantics (acceptance 2–4)

- **Minting.** `sync` mints a revision only after the provider confirmed every write of the
  product's binding set (the existing `confirm` step, NR-11), and records the private
  evidence of each name at the same time. A partial, failed or interrupted write mints
  nothing. Its names stay `unverified`, and the next `sync` (or `sync --product P`) retries
  idempotently: unchanged names are not rewritten, and the revision covers the whole set
  once it is all confirmed.
- **Reuse.** `opv delivery verify` recomputes, read-only, for the set: is each target
  version equal to the recorded one, and each 1Password fingerprint equal to the recorded
  one? Comparison happens in memory. If every name holds, the answer is `verified` and the
  **same** revision is returned: reusable identity for an unchanged binding.
- **What cannot reuse a revision.** The revision is stored per
  `(account id, environment, product, target locator, binding set)`. Another account,
  environment, product or target, or a different name set (a key added or removed), finds
  no revision: `not_delivered`.
- **Changes are named.**
  - `source_changed`: the 1Password value differs from what was delivered (rotation), or a
    shared source changed. That one change invalidates every consumer that reads it.
  - `drifted_on_target`: the target's version differs (an edit outside opv).
  - `missing_on_target`.
  - An unrelated product's edit, even in the same item, changes neither fingerprint nor
    target version, so it leaves this product verified.
- **Unverifiable stays unverifiable.** A store that lists no version for a name, or a
  verifier who cannot read the evidence, gets `unverifiable` with the reason. Never
  `verified`.
- **Deployed generation**, reported separately and never folded into `verified`:
  - Fly: `staged` (pending secrets) or `deployed`, plus the release version;
  - pinned targets: whether the runtime binding references the delivered version (FR-29);
  - GitHub: `n/a` (values are read at job time).

## 4. CLI and JSON (acceptance 1, 6)

```sh
opv sync prod --product api --receipt api-prod.receipt.json   # mint on confirmed delivery
opv delivery verify prod --product api --json                 # read-only; reuse or explain
opv delivery verify prod --product api --receipt api-prod.receipt.json --json
```

The receipt (schema `opv.delivery/1`):

```json
{"schema": "opv.delivery/1", "revision": "drv-…", "account_id": "…", "environment": "prod",
 "product": "api", "target": {"provider": "fly", "locator": "myapp"},
 "bindings": [{"name": "FLEET__API__TOKEN", "source": {"item_id": "…", "field": "api/TOKEN"}}],
 "delivered_at": "2026-10-13T12:00:00Z", "plan_id": "7f3c9a1e", "opv_version": "0.7.0",
 "deployed": {"state": "deployed", "generation": "v42"}}
```

`verify` returns `{revision, state: verified|changed|unverifiable|not_delivered,
names: [{name, state, reason}], deployed}`. The two other documents agents use advertise
the capability:
- `opv schema`: `capabilities: ["delivery_receipts/1"]`, the installed-version check;
- `opv guide agent`.

## 5. The owner's decision: where the private evidence lives

Production syncs run in CI under a **read-only** service account (FR-52), which today
records nothing (the ledger is written only by a person's own session). The evidence must
be written by whoever delivers, and read by whoever verifies.

| Option | How | Pros | Cons |
|---|---|---|---|
| **A. The values item** (today's ledger) | CI's deploy identity may edit the env's item | no new artifact; verify needs nothing but access | CI gets **write access to the values**, breaking least privilege (FR-52) |
| **B. A state item** | a separate `opv · state · <env>` item (or vault) the deploy identity may edit, holding only evidence; the fingerprint key stays in the values item | values stay read-only to CI; verify needs only read access to both | one more item and permission to set up (`bootstrap` can create it); evidence is centralized |
| **C. Sealed evidence in the receipt** | the receipt carries the private evidence encrypted (AES-256-GCM) under a key derived from the ledger key in the values item; whoever keeps the receipt keeps the evidence | no new write access at all; fits a consumer that already keeps accepted records | verify needs the receipt file; a lost receipt means re-deliver; ciphertext travels in CI artifacts (opaque, but still sensitive-adjacent) |

**Decided: B** (owner, 2026-10-13), with multiple products considered:

- 1Password grants access per vault, not per item. So the state lives in a **separate state vault per environment** (`state_vault_id`, created by `opv bootstrap --state <env>`); an item in the values vault would have given CI write access to the values.
- There is **one item per product** (`opv · delivery · <product>`), so products promoted independently on a shared host never write the same item, and each has its own revision and evidence.
- The evidence key lives in the state item. That is why only identities that can read the values should read the state vault.

The original recommendation, kept for the record:
- It keeps CI read-only on values.
- It gives "verify" one place to look: no artifact to carry, and reuse works across
  pipelines.
- It makes interrupted runs visible, because the state item shows minted and unminted sets.
- C is the fallback if adding a writable item is not acceptable.
- A is listed for completeness only.

## 6. Tests (acceptance 5), on synthetic fixtures

- Unchanged reuse returns the same revision.
- A shared-source change invalidates exactly its consumers.
- Rotation gives `source_changed`; a re-sync mints a new revision.
- An unrelated product's edit in the same item stays verified.
- Wrong account, environment, product or target gives `not_delivered`.
- An interrupted sync (one name confirmed, the run killed) mints nothing, and the retry
  mints one revision.
- A target edit outside opv gives `drifted_on_target`.
- A store without versions gives `unverifiable`.
- Redaction: no value, digest or fingerprint appears in any output, receipt, error or argv
  (marker values, as everywhere).

## 7. Boundaries kept

- `versions_reveal_values`: Fly digests are compared in memory and never emitted.
- No password, session or token in a receipt.
- opv implements no release policy: the receipt is evidence for the consumer's own policy.
