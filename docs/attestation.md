# Attesting a held immutable key

An attestation is a person's statement that a target already holds 1Password's value of a
key. opv records it as the key's delivery evidence, and the receipt says the name is
**attested, not proven**. Use it only for the case below.

## When you need it

opv proves a key delivered by comparing what the target holds with 1Password. Some targets
make that comparison impossible:

- **Fly** shows a digest of each secret that opv cannot recompute, and never shows the value.
- On such a staged target, a key is proven identical only by its **delivery evidence**: an
  evidence line opv wrote when it last delivered the key, recorded at the target's version,
  with a keyed fingerprint of the 1Password value.

An **immutable** key is written only when it is absent from the target, or when you rotate
it. So an immutable key that reached the target *before* opv recorded evidence for it (set
by hand, or by an older opv) gets stuck:

- every `opv sync` holds it (it is on the target, and it is immutable);
- nothing ever writes it, so it never gets an evidence line;
- its product never gets a delivery revision, and `opv delivery verify` reports `not_delivered`.

`opv sync` names the stuck keys in its `delivery: <product> not recorded: not confirmed by
this sync: …` line.

You have two ways out:

1. **Rotate the key** (`opv sync <env> --rotate <product/KEY>`; see [rotating a key](rotation.md)).
   opv writes the value and records real evidence. This is the proven route, but it changes
   the value, which an immutable key (a JWT signing secret, an encryption key) often must not do.
2. **Attest the key.** You state that the target holds 1Password's value. opv records the
   evidence line at the target's current version **without writing the target**, and marks
   the name as attested.

## The risk

opv cannot check an attestation. If the target holds another value than 1Password, the
attestation is wrong. From then on the ledger "proves" the wrong value unchanged, sync keeps
holding it, and receipts and `opv delivery verify` count it.

**An attestation that is wrong is only caught when the app fails**, for example when tokens
signed with the target's secret no longer verify against 1Password's.

Attest a key only when you know where the target's value came from: it was copied from this
1Password field, or 1Password's value was imported from the target. If you are not sure,
rotate instead.

## How to attest

An attestation is a proposal, then your own `opv apply`, the same two steps as every other
change opv makes for you.

The assistant (or you) proposes it. Over MCP, `opv_propose` takes the intent document;
on the command line, `opv propose --intent` takes the same document from a file:

```json
{"kind": "attest", "env": "staging", "target": "web", "keys": ["api/JWT_SECRET"]}
```

```sh
opv propose --intent attest.json
```

The proposal prints exactly what would be recorded, and a plan id:

- each key, its name on the target, and the target's current version.
- On Fly the version is itself a digest of the value, so opv prints a version tag instead:
  a keyed hash that changes when the version does and reveals nothing of the value.
- Never a value.

Every name is checked first. opv refuses (`policy_refused`, guard `attest_refused`, with a
reason) a key that:

- the target does not deliver (`not_delivered`);
- is not immutable (`not_immutable`): sync writes it and records its evidence itself;
- the target does not list with a version (`not_on_target`): sync writes it once;
- is on a target whose values opv reads and compares exactly (`compared_directly`);
- sync does not hold back, because its 1Password value is not ready (`not_held`);
- the ledger already proves (`proven`);
- is already attested at the target's current version (`already_attested`);
- the ledger shows differs from 1Password (`differs`), or that changed on the target outside
  opv since opv recorded it (`drifted`). Rotate these: never attest a value known to differ;
- is on a placement that no sync has recorded yet, with no delivery item or evidence key
  (`not_recorded`). Run `opv sync` once first.

Then **you** run the plan in your own terminal:

```sh
opv apply ap-0123456789abcdef --attest staging:web:api/JWT_SECRET
```

`opv apply` works the same way here as for a structure plan:

- it recomputes the proposal;
- it refuses the plan id if anything changed since (`stale_plan`): the target's version of a
  name, or its 1Password value;
- it shows the names, asks once, and records each name's evidence line in its placement's
  delivery item in the state vault, tagged as an attestation (below);
- it reads each delivery item again just before writing it, and refuses the plan as stale
  (`stale_plan`) if the item changed since the proposal (another evidence key, or a line
  recorded for the name meanwhile);
- without a plan id it shows the attestation it would record and asks before recording it.

Nothing is written to the target. `--attest` takes `<env>:<target>:<product/KEY>`, can be
repeated, and names one environment and target per run.

Each product's delivery item is one write. If a write fails part way (for example, the
second of two products), `opv apply` prints the names it recorded before the failure, and
running the same `opv apply <plan_id> --attest …` again succeeds: names already attested
as the plan says are skipped. A plan whose names are all attested already is refused
(`already_attested`).

Who can record one:

- Only a person, in their own terminal.
- `opv apply` refuses agent mode (`person_only`), CI (`terminal_required`) and a run without a
  terminal, before it reads anything.
- No MCP tool records an attestation; `opv_propose` only proposes it.
- 1Password's own item history shows who edited the delivery item, and when.

Then sync:

```sh
opv sync staging --target web
```

The ledger now proves the attested names identical at the target's version, so the
product's revision is minted.

## How it is recorded

An attested name's evidence line is the ledger line sync writes, under its own tag:

- opv's own evidence: `v1|<version>|<fingerprint>|<item>|<field>`;
- a person's attestation: `a1|<version>|<fingerprint>|<item>|<field>|<attested at>`.

opv 0.12.3 and later read both: the ledger judges an `a1` line exactly like a `v1` line (the
target still holds that version of 1Password's value), and reports the name as attested
everywhere. An opv before 0.12.3 does not read an `a1` line. When it rewrites the delivery
item it drops the line, so the key goes back to held and the product gets no new revision:
an older opv never counts an attested name as proven.

## How it appears

Everywhere an attested name is shown, it says so:

- the receipt (schema `opv.delivery/1`, unchanged) has an optional field `attested`: the names
  of `bindings` that the revision counts on an attestation, not on a write or a proof;

  ```json
  {"schema": "opv.delivery/1", "revision": "drv-…", "bindings": [ … ],
   "attested": ["FLEET__API__JWT_SECRET"], "…": "…"}
  ```

  The field is left out when no name is attested. A receipt consumer that ignores fields it
  does not know (as JSON readers usually do) reads an attested name as proven: check
  `attested` wherever the difference matters;
- `opv sync` prints `delivery: api revision drv-… (attested, not proven: FLEET__API__JWT_SECRET)`,
  and its `--json` gives each minted revision an `attested` list;
- `opv plan` and `opv status` show `attested` in the ON TARGET column instead of `held` or
  `same`, and their `--json` rows add `"attested": true` beside `"target_state": "present"`;
- `opv delivery verify --json` gives each name an `"attested": true` and each placement the
  receipt's `attested` list; its text report adds `attested by a person, not proven` under the
  placement.

`opv ready --gate` passes on an attested key. The owner accepted attestation as delivery, and
the gate judges value states and delivery freshness, not how a name was proven. The gate's
findings do not list attested names: run `opv delivery verify <env>` to see them.

## When it ends

An attestation lasts while its `a1` line keeps the version and value it was recorded at.

- **A sync writes the name** (`--rotate`): the write records an ordinary `v1` line and the
  next revision no longer lists the name as attested.
- **The target's version changes outside opv**: the name shows as drifted, and the attestation
  no longer vouches for anything.
- **1Password's value changes**: the ledger shows the target holds another value; rotate it.
- **An opv before 0.12.3 rewrites the delivery item**: it drops the `a1` line (above), and the
  key is held again.

Who attested is not recorded in the line; 1Password's own item history shows who edited the
delivery item, and when.
