# Assistant-guided configuration: the North Star, and the gap from opv 0.11.0

Status: **direction locked by the owner (2026-10-18): R1–R11 (Part VI, including §24)**, with the 18 corrections of [the FMECA comparison §8](assistant-guided-setup-comparison.md) applied. Tracks #173 and its parts #174 to #179. This document first describes the North Star: the ideal system from first principles, without reference to what opv does today (Part I). Most of opv's existing decisions turn out to sit on the path to it, so the gap is mostly an added layer, not a redesign. It then measures opv 0.11.0 against it (Part II), resolves the design's contradictions with TRIZ (Part III), makes confusion and failure structurally impossible where it can (Part IV, poka-yoke), sets out the phases of delivery (Part V), reframes the problem so whole classes of risk cannot be expressed (Part VI), and records the owner's decisions (Part VII).

**Precedence.** Part VI and §24 win over Parts I–IV wherever they conflict. The superseded passages (§4.1, §4.4, §5, §6.1) are restated in place below, marked "restated under Part VI".

## 0. The objective (owner, 2026-10-18)

> An assistant (Claude Code, Cursor, Codex) can guide a person **100%** of the way, from local development to production, with full visibility of the structure and **no access to any value**. It knows every key and its attributes, and whether each one has a value, but never the value. It compares what the application needs with what is stored, and guides the person to fill the gaps under the project's 1Password conventions. Anything that needs generative AI is exposed through the CLI and MCP. Anything that can be deterministic is in opv's Rust code, so the assistant and the person can both see exactly what is going on and what to do next. A person may type a value into a masked prompt, but no value ever touches a language model.

Two questions frame every decision here:

1. **Can this be a function of the inputs?** If the answer follows from the repository's files, the configuration, store metadata and platform metadata, it belongs in code. It is then deterministic, tested, and identical for every assistant and every person.
2. **Does this need a value?** If it does, it happens only inside opv's process, in the store, on a platform channel, in the running application, or at a person's masked prompt. Never anywhere an assistant can read.

---

# Part I: the North Star

## 1. Actors and the value boundary

| Actor | Can see structure | Can see values | Can approve writes | Can enter values |
|---|---|---|---|---|
| **Person** (owner, engineer) | yes | in 1Password only, by choice | yes, in their own terminal or the 1Password app | yes: the 1Password app, or opv's masked prompt |
| **Assistant** (an LLM in a harness, through MCP or a shell) | yes, all of it | **never** | never | never |
| **opv** (deterministic engine) | yes | in process memory only, zeroized | no: it carries out what a person approved | no |
| **Store** (1Password) | n/a | holds them | n/a | n/a |
| **CI** (a service account) | the parts it needs | in opv's process memory only, to carry them to a platform over stdin or a pipe (R8) | no: it runs syncs on change and on a schedule | no; its only 1Password write is value-free delivery evidence |
| **Platforms** (Fly, Kubernetes, Azure, GitHub, …) | n/a | hold the delivered copies | n/a | n/a |

**Invariant V (the value boundary).** A value, or anything from which part of a value can be recovered, never appears on a surface an assistant can read. That covers stdout, stderr, a JSON document, an MCP response, a log, an error, a file opv writes outside a platform channel or the application's runtime directory, and a command line. "Anything from which part of a value can be recovered" includes its length, a prefix or suffix, a digest, an encoding, an entropy figure and a comparison with a guess.

What may cross the boundary is a **value state**: a closed set of words computed inside opv, where each word describes a value without carrying any of it (§3.3).

**The honest limit.** opv can make its own surfaces incapable of emitting a value. It cannot stop an assistant that also has an unrestricted shell, as the same OS user, from reaching whatever that user's sessions can reach:
- `op read` and `op item get` through the person's 1Password session;
- platform CLIs already logged in on the machine (`kubectl`, `az`, `flyctl`, `gh`);
- the running application and its logs, and deployed logs the person can read;
- a pull request that changes a CI workflow.

The system therefore has three layers, none of which is a sandbox, and the documentation says so:
- opv's surfaces are value-free by construction (Part IV);
- **1Password vault permissions are the tier boundary** (R9): a developer's session reaches only local and dev vaults **where the team's vault groups are tight**, and opv reports when they are not (`opv doctor`, `opv access`), together with production platform logins on the machine;
- 1Password's own authorization prompt is defence in depth, and the docs describe harness guard rules a team may add (a docs section only; opv installs none, D-G).

**Accepted residual (owner, D-A).** A DevOps machine that can read production by design can be reached by an assistant running in its shell. The hardened option, described in the docs, is a separate 1Password admin account used only for production work. opv reports when the current session can read a production-tier vault or holds a production platform login.

## 2. The model: an application moving through environments

```
Application (one contract, versioned with the code)
 ├─ Components            web, api, worker …   (a role; a unit of deployment)
 │   └─ Keys              the contract: what the component needs
 ├─ Environments          local → dev → staging → prod   (ordered lanes)
 │   ├─ ephemeral         preview-<branch>, <engineer>-dev   (instances of a template)
 │   └─ tier              local | shared | production   (policy follows the tier)
 └─ Bindings              per environment: where values live (store boundaries) and where they go (targets)
```

### 2.1 A key is a contract, not a field

A key declares what the application needs, independently of any environment:

| Attribute | Values | Why it matters |
|---|---|---|
| name, component | `api/STRIPE_SECRET_KEY` | identity |
| kind | `secret` / `setting` / `file` | the channel it travels in |
| **source** | `person` (someone fetches it), `generated` (opv makes it), `derived` (another key's value, or composed from keys), `provisioned` (opv mints it through a provider's API) | who or what produces the value; only `person` needs a human |
| **scope** | `shared` / `personal` | one value per environment, or one per engineer |
| **presence** | `all` environments, minus explicit `except` (each with a reason), or `only` some | consistency by default |
| shape | a catalog shape (`stripe_secret`, `openai_key`, `pem_private_key`, `url`, `base64_bytes(32)`, …) or explicit rules | deterministic validation and placeholder detection |
| lifecycle | `active` / `retiring` / `retired` | removal is a state, not a deletion |
| rotation | none, or a period, plus `expires_at` metadata the person records | expiry warnings, rotation plans |
| guidance | one line on where to get it; a link | coaching without the assistant guessing |
| tier policy | for example, production requires a value distinct from lower tiers, and a live key | a policy, not a habit |

### 2.2 The contract lives with the code

The application's key contract is a file in the repository, reviewed in the same pull request as the code that needs the key. A dependency that adds `STRIPE_WEBHOOK_SECRET` adds its declaration in the same diff. This is consistency by construction: code and contract cannot drift apart unnoticed, because a deterministic check compares them (§3.2).

Bindings (vault and item IDs, target locators) are not secret and live in the same file or a sibling. IDs are recorded by opv, never typed by hand.

### 2.3 State, desired and actual

opv reconciles, as Terraform and Kubernetes do:

- **Desired state** = contract × environments × tier policy.
- **Actual state** = store metadata (vaults, items, fields), **value states** (computed in memory), platform metadata (what is delivered, with which version), and the code's references (what the application reads).
- **The plan** is a deterministic function: desired minus actual, ordered, and content-addressed.

Every question a person or an assistant can ask ("what is missing?", "is prod ready?", "what changed?", "what reads this key?") is a query over these two states. None of them is a judgment.

## 3. The division of labour

### 3.1 The rule

**Deterministic (opv's code)**:
- everything that is a function of files, configuration, metadata and value states;
- every write, every check and every ordering;
- every "what next";
- every rendering of state.

**Generative (the assistant)**:
- understanding what the person wants;
- choosing among options opv has enumerated, when the choice is a judgment;
- supplying names or text that opv's grammar then validates;
- explaining and coaching in natural language, from opv's documents.

**Person**:
- approving each plan;
- entering the values only a person can obtain;
- authorizing 1Password.

The assistant never produces anything that opv consumes without checking it. Every assistant-supplied input is either a choice from an enumerated set or a string that a grammar validates, and free text is screened for values (§11, P-2).

### 3.2 Every task, assigned

| Task | Deterministic in opv | Generative (assistant) | Person |
|---|---|---|---|
| Find the names the code reads | Scanner per language and framework: env reads, settings files, mounted files, `.env.example`, Compose, Kubernetes, `fly.toml`. It reports **coverage** (files and languages scanned, patterns skipped) | Supplies names in code the scanner cannot read (dynamic names, an unsupported language). Each one is validated against the name grammar and tagged `assistant_supplied` | — |
| Compare code with the contract | `undeclared`, `declared_unused`, `ambiguous`, `declared`, each with its value state per environment | Resolves an `ambiguous` owner by choosing from opv's candidates | — |
| Propose components | From repository layout: build files, Dockerfiles, app manifests, monorepo paths. Each proposal carries its evidence (file:line) | Accepts, merges or renames | Reviews in the plan |
| Propose environments and targets | Detectors over `fly.toml`, workflow `environment:` keys, Kubernetes manifests, Azure and Compose files. Candidates with evidence | Chooses | Reviews in the plan |
| Kind, scope, source, shape | A catalog of known names and providers (`STRIPE_SECRET_KEY` → secret, shape `stripe_secret`, source `person`, guidance "Stripe › Developers › API keys"; `JWT_SECRET` → `generated` `base64_bytes(32)`; `OPENAI_API_KEY` in a local tier → suggested `personal`). Unknown names default to secret, source person, no shape | Overrides with a reason, choosing from the enumerated attribute values | Reviews |
| Guidance text | From the catalog for known providers | Writes it for unknown keys (one line, screened, §11 P-2) | — |
| Create structure (vaults, items, fields) | The plan, then apply | — | Approves |
| Values a person must fetch | Lists them with links, the shape and the guidance | Coaches: where to get it, what it looks like | Enters it: 1Password, or opv's masked prompt |
| Generated values | Generates in memory and writes to the store | — | Approves (inside the plan) |
| Provisioned values | Mints through the provider's API and writes to the store | — | Approves; authorizes the provider |
| Importing an existing `.env` | Parses, classifies by name, imports values directly to the store | — | Runs the person-side step (§6.1) |
| Consistency across environments | Presence rules, the gap check, tier policy | — | — |
| Readiness, promotion gates | The matrix and the gates | Explains | — |
| Delivery to platforms | Plan, approval, sync, verification | — | Approves (or CI on a schedule) |
| Rotation, retirement, leak response, offboarding | Plans in a fixed order, resumable | Explains | Approves; enters values |
| "What do I do now?" | **One** next action, chosen by a fixed priority, plus the full queue | Turns it into conversation | Acts when the actor is the person |

### 3.3 Value states (the only thing an assistant learns about a value)

A closed enumeration, computed in memory from the value and the key's contract:

| State | Meaning |
|---|---|
| `absent` | no field |
| `empty` | the field exists and is empty |
| `placeholder` | a known placeholder from a fixed list (`changeme`, `<your key>`, `xxx`, `your…here`, `todo`, …). There is **no** comparison with `.env.example`: that check is dropped, because a file the assistant can write and commit would turn it into an equality oracle (correction 2) |
| `malformed` | fails its declared shape or rules (the rule's name is reported, never the part that failed). Only rules from the contract as committed on the default branch count (R3, H1); any other rule shows `rules_pending_review` instead of a result |
| `suspect` | passes its shape but trips a warning: low entropy, a test key in production, a live key outside production, `localhost` in a deployed tier. **The same value as a lower tier is never reported on an assistant surface** (MCP, agent mode); it is reported only to a person at a terminal and to CI, because under R9 dev is readable by design and the bit would disclose an equal production value (correction 6) |
| `set` | present and passes everything |
| `unreadable` | opv could not read it. The cause is reported, and it is **never** reported as absent or empty |
| `not_wanted` | the key's presence excludes this environment |

There is deliberately no numeric field. A score would leak information about the value.

**0.12.0 ships seven states (D-G):** `absent`, `empty`, `placeholder`, `malformed`, `set`, `unreadable` and `not_wanted`. `suspect` is not a state: its signals (low entropy, a test key in production, a live key outside production, `localhost` in a deployed tier, the same value as a lower tier) stay **advisory health warnings** in `opv ready`, which never block a gate (review M7), and the cross-tier one is shown only to a person at a terminal and to CI. `not_wanted` is computed from the contract, never from a value. `malformed` is reported only for rules committed on the default branch (default 2).

**Capability is not a value state.** Next to each cell the inventory shows what the current session can do with the vault that holds it: `write`, `read`, `none` or `unknown`. `unknown` carries its source (for example "1Password did not report effective permissions"), and a 1Password refusal is a typed finding, never a guess (correction 14).

## 4. The contract between opv and every client

One contract serves the person at a terminal, the assistant over MCP and the assistant in a shell. The same document is rendered as text, as JSON or as an MCP result.

### 4.1 Five verbs (restated under Part VI)

Every capability is one of five verbs, and each verb has one shape. Under R1 the assistant plans and never actuates; the only actuators are a person's terminal and CI.

| Verb | Writes? | Who calls it | Returns |
|---|---|---|---|
| **inspect** | no | anyone | state documents (inventory, needs, readiness, access, delivery, history) |
| **propose** | **nothing** (correction 10: `opv_propose` is pure) | assistant or person | the contract diff and a **plan**: every step by name, its actor, and a content-addressed `plan_id` |
| **apply** | the plan's steps, in one process: structure, generation, value entry, imports | **a person, in a terminal** (shows the plan, confirms, runs) | what ran, what remains |
| **deliver** | platforms, plus value-free delivery evidence in 1Password | **CI** (`opv changed`, `opv sync`), or a person | what was delivered, with evidence |
| **next** | no | anyone | exactly one recommended action, plus the queue |

There is no separate `approve`: R1 removes the approval file, its window and the approve/apply race. The one exception to "the assistant writes nothing" is R3's write-only import into an environment of tier `local` (§21 R3, decision default 5).

Fewer verbs make a smaller surface for an assistant to learn, and the same shape every time lets one prompt pattern work across Claude Code, Cursor and Codex.

### 4.2 The document envelope

Every document has:
- `schema_version` and `ok`;
- the payload;
- a typed `next`: one action with a kind (`run`, `approve`, `enter_value`, `authorize`, `wait_ci`, `none`), an actor (`assistant`, `person`, `ci`), and either the exact command or a link;
- for a failure, a typed `error`: a closed cause, a subject, evidence, retry, `human_required`.

No field ever holds free text that a client must parse to decide what to do.

### 4.3 Determinism of output

The same inputs give the same bytes: stable sort orders, no timestamps in plans, stable IDs. Plans are content-addressed over the project, the account, the contract text and every step, so any change makes an approval stale rather than silently different.

### 4.4 Agent mode (restated under Part VI: presentation only)

opv knows when its caller is probably an assistant: always over MCP, and in a shell when a harness marker or `OPV_AGENT=1` is present. Markers are under the caller's control, so **agent mode is presentation, never a security control** (R1, review M2). In agent mode:
- **No prompt ever opens.** A person-only step returns `next.actor = person` with the exact command, instead of hanging on a prompt the assistant cannot answer and must not see.
- **Value-entry commands refuse** with that typed `next`.
- **Cross-tier comparison results are left out** (correction 6).

**Redaction does not depend on agent mode.** The rule is one sentence, used everywhere in this document: *redaction is always on in local delivery, and it is `op run`'s masking of exact values* (`src/app/run.rs:5-7`; correction 4, default 4). opv adds no encoding redaction in 0.12.0 (D-G): developer machines hold sandbox-grade values (R9), so a value that leaks through an encoding is a test key to rotate.

## 5. The surface (restated under Part VI)

The 0.12.0 surface, CLI and MCP, is the one interface of §25. It replaces the ideal table that stood here: the assistant gets five MCP tools (`opv_state`, `opv_next`, `opv_propose`, `opv_import_local`, `opv_explain`), a person gets `opv apply`, `opv set` and `opv import`, and CI gets `opv changed`, `opv sync`, `opv ready --gate`, `opv needs --gate` and receipts.

## 6. The journeys

Each journey step is marked **D** (deterministic, opv), **G** (generative, assistant) or **P** (person).

### 6.1 First setup: "put this app's configuration into 1Password" (restated under Part VI)

1. **D** `opv_state` (section `needs`) reads the repository: every name the code reads, with the scanner's coverage, compared with the contract.
2. **D** If the project has an environment of tier `local`, the assistant may call `opv_import_local` with the path of the local `.env`. It is write-only: values go straight from the file to the local vault, the reply is presence per key, and what it writes is tagged `assistant_imported` (default 5). For any other tier the import is the person's `opv import`.
3. **G** The assistant resolves ambiguities from opv's candidates, annotates the observed names categorically, and writes guidance for unknown keys (screened, stored as `assistant_written`).
4. **D** `opv_propose` returns the contract diff and one plan, and writes nothing:
   - the contract file (the assistant may write the diff into the repository; it is reviewed in the pull request);
   - boundaries (vaults and items) per environment under the project's conventions;
   - fields for every key in every environment where it is present, with "a value, or `except`?" asked for each production-tier environment;
   - generated values for `generated` keys;
   - targets and identities.
5. **P** `opv apply <plan_id>` in the person's terminal shows the whole plan once and runs it in one process: structure, generation, bindings, and masked entry for any value the person chooses to type now. 1Password asks for authorization once.
6. **D** `opv_next` → "3 values only you can provide", each with its vault, its link, its shape and its guidance, listed only to sessions with write access to that vault (R8).
7. **P** The person enters them, in the 1Password app or with `opv set`. **D** The value states turn `set`. **G** The assistant confirms in conversation.

The person's whole effort is one `opv apply`, one authorization, and the values only they can fetch.

### 6.2 A new engineer joins

1. **D** `opv next` on a fresh clone sees the shared environment is complete and lists the engineer's own `personal` keys as `absent`, with links to create their item.
2. **P** They enter their own keys.
3. **D** `opv run -- <app>` works.

Access comes from vault membership, which an owner grants in 1Password. `opv access` shows who can read and write each vault.

### 6.3 The application changes

- **Adding a key.**
  1. **D** In CI, `opv needs --gate` fails a pull request that reads an undeclared name, and gives the declaration command.
  2. **G** The assistant runs `opv_change_plan` with the new key; its presence defaults to `all`.
  3. **D** The plan adds the field everywhere and generates it if it is `generated`.
  4. **D** The PR check shows the key's row across the matrix (dev `set`, staging `absent`, prod `absent`).
  5. **D** The promotion gate blocks staging and prod until they are filled.
- **Removing a key.**
  1. **G** "We dropped Mixpanel" becomes `opv_change_plan --retire`.
  2. **D** The plan marks the key `retiring`, prunes it from every target in lane order, then marks it `retired` and archives the 1Password fields. It is resumable, and the matrix shows a half-finished retirement.
- **Adding an environment.** **D** The new environment receives every `all` key automatically, and its fields arrive with the next structure plan.

### 6.4 Promotion: local → dev → staging → prod

**D** The gate `opv ready <env> --gate` passes only when every present key is `set`, the tier policy holds and the targets are reachable. **D** CI syncs only on change, with the target's own identity. **D** Production never needs 1Password or opv at runtime: its values live in the platform's channels.

### 6.5 Life after setup

- **Rotation:**
  1. **G** "Rotate the database password."
  2. **D** The rotation plan orders every step: generate or ask, write a new version, sync each environment in lane order, verify, then report that the old credential is safe to revoke.
  3. **P** The person approves and revokes.
- **Expiry:** **D** keys with `expires_at` produce a finding ahead of time, with the rotation plan as `next`.
- **Leak response:** **D** `opv explain KEY` lists every environment, target and delivery holding it (0.12.0: no separate `exposure` command, D-G), then the rotation procedure.
- **Offboarding:** 1Password administration (D-G). opv adds no report; `opv access` shows who can read each vault.
- **Portfolio:** **D** One inventory spans every application in the account, and shared values are defined once.

## 7. Provisioners (the ideal's far edge)

For providers with an API (Fly deploy tokens, GitHub fine-grained tokens, database users, cloud service principals, 1Password service accounts), opv mints the credential itself and pipes it straight into the store. The key's source becomes `provisioned`, and no person or assistant ever handles it. Every provisioner follows the same plan → approve → apply shape. opv already does this for 1Password service accounts (`opv access --create`); the ideal generalizes it.

---

# Part II: gap analysis against opv 0.11.0

Legend:
- **Have:** exists in 0.11.0.
- **Part:** exists in a narrower form.
- **Gap:** missing.

| # | Ideal capability (Part I) | opv 0.11.0 | Status | Issue |
|---|---|---|---|---|
| G1 | Value boundary on every surface | `SecretValue` (`Debug` and `Display` print `<REDACTED>`; no `Serialize`), the S7MARKER canary scan over CLI, `--json` and MCP, layered scrubbing, value-free MCP tools | **Have** (enforced by tests, not by types; see P-1) | — |
| G2 | Agent cannot reach values through a shell | 1Password's authorization prompt on writes; `opv_structure_apply` refuses an inherited session | **Part:** no harness guard rules; `op run` masks exact values in the child's output (`src/app/run.rs:6-7`), so the gap is encodings only | new |
| G3 | One application contract, versioned with the code | `secrets.toml` in the repository **or** a manifest in 1Password, with the same schema | **Part:** both are allowed; nothing ties the contract to the code that needs it | #175 |
| G4 | Components | `products` (name, role, keys) | **Have** (name differs: "product") | — |
| G5 | Key: kind | `secret` / `config`; `file` destinations | **Have** | — |
| G6 | Key: source (`person` / `generated` / `derived` / `provisioned`) | `from` (derived), `generate` for rule-backed keys, service-account creation | **Part:** source is not an attribute, so opv cannot say "this needs a person" | new |
| G7 | Key: scope `personal` | `personal = true` | **Have** | — |
| G8 | Key: presence `all` minus `except`, inherited by new environments | explicit `environments` lists; `opv add` defaults to every environment that exists at the time | **Gap** | #179 |
| G9 | Key: shape from a catalog | rules (`prefix`, `base64_bytes`, …) | **Part:** no provider catalog | #177 |
| G10 | Key: lifecycle (`retiring` / `retired`) | three manual steps; fields remain | **Gap** | #179 |
| G11 | Key: rotation period and expiry | `--rotate` exists for sync; no expiry metadata | **Gap** | new |
| G12 | Environments: ordered lanes and tiers | environments are unordered; production is inferred from the name | **Gap** | #179 |
| G13 | Ephemeral environments from a template | none (personal keys cover per-engineer values) | **Gap** (low priority) | new |
| G14 | Tier policy | settings-health warnings (test or live key, same value, localhost) | **Part:** warnings, not policy | #177, #179 |
| G15 | Value states (closed set, §3.3) | `opv ready` findings: missing, failing rule, placeholder, same value, … | **Part:** findings, not a state per key; `unreadable` is not a state | #174 |
| G16 | Inventory matrix | none | **Gap** | #174 |
| G17 | Code ↔ contract comparison with coverage | none | **Gap** | #175 |
| G18 | Detection of components, environments and targets from the repository | none | **Gap** | new |
| G19 | Name catalog (kind, shape, source, guidance for known providers) | name-based kind guess in `init --from` | **Part** | new |
| G20 | Five verbs with one shape | many commands; plan → approve → apply for structure and sync only | **Part** | new |
| G21 | Typed `next` (kind, actor) | `next` (a command) and `do` (prose for a person) | **Part:** `do` is prose; there is no actor | new |
| G22 | `opv next`: one action from a fixed priority | `opv ready` orders findings; no single action | **Gap** | new |
| G23 | One setup plan, approved once | `init`, `add`, `structure plan`/`approve`/`apply`, `init --from --apply`, `target add`, `access` are separate | **Gap** | new |
| G24 | Person-only steps run inside `approve` | `approve` only approves | **Gap** | new |
| G25 | Masked value entry in the terminal | `opv setup` has a masked prompt for its own credentials | **Part:** no `opv set` for keys | new |
| G26 | Agent mode (no prompts; refusals naming the person's step) | MCP never prompts; the CLI does not detect an agent | **Part** | new |
| G27 | `opv run` redaction of injected values | every value opv reads is registered with a scrubber that masks it in tool output opv shows (NR-31, `SecretValue::new`) | **Part:** `op run` masks exact values in the child's output (`src/app/run.rs:6-7`); encodings (base64, hex, URL) and chunk boundaries are not masked | new |
| G28 | Change plan (add, alter, retire, extend) | `opv add`, `env add`, `target add`, `init --add-env` | **Part:** no retirement, no bulk extend | #176, #179 |
| G29 | Promotion gate | `opv ready` exit codes; `status --fail-on-drift` | **Part:** no per-environment completeness gate | #179 |
| G30 | Rotation plan across environments | `sync --rotate` per environment | **Part** | new |
| G31 | Exposure report (leak response) | `opv explain KEY` (one key's chain) | **Part** | new |
| G32 | Access and offboarding report | `opv access` (identities per vault) | **Part:** no person-centred view | new |
| G33 | Provisioners | 1Password service accounts (`access --create`) | **Part** | new (later) |
| G34 | Generated configurations | refused by declare tools; `generator_ids` returned by structure apply | **Part** | #178 |
| G35 | Declare from a `.env` by name only, through MCP | CLI `init --from` (imports values too) | **Part** | #176 |
| G36 | Guard rules for assistant harnesses | none | **Gap** | new |
| G37 | Free-text inputs screened for values | none | **Gap** | new |
| G38 | Portfolio inventory | `opv projects`, `status --all` | **Part** | #174 |

Summary of the 38 rows:
- **Have (4):** G1, G4, G5, G7.
- **Part (21):** G2, G3, G6, G9, G14, G15, G19, G20, G21, G25, G26, G27, G28, G29, G30, G31, G32, G33, G34, G35, G38.
- **Gap (13):** G8, G10, G11, G12, G13, G16, G17, G18, G22, G23, G24, G36, G37.

The foundation (value-free surfaces, plans bound to content, reconciliation of delivery, personal keys, shared values) is sound. The missing layer is the **application model** and the **assistant contract** on top of it.

---

# Part III: contradictions (TRIZ)

TRIZ is worth using here because the objective contains real contradictions: two requirements that pull against each other, where a compromise would weaken both. The principles below come from the offline catalog (`triz catalog`, triz-software-2).

**Cross-check with `triz analyze` (Jev through OpenRouter, run 2026-10-18 with the owner's authorization).** Each contradiction was sent as design prose only, with no value, ID or name. Requests and results are in [assistant-guided-setup-triz/](assistant-guided-setup-triz/). The reported cost was about $0.0004 in total, a Pi-reported estimate rather than a bill.

| # | This design says | Jev classified | Confidence | Agrees? |
|---|---|---|---|---|
| C1 | physical | `uncertain` when framed with both technical and physical fields; `physical` when reframed as physical only (`c1b`) | 0.35 → 0.63 | yes (after reframing) |
| C2 | technical | technical | 0.93 | yes |
| C3 | physical | physical | 0.63 | yes |
| C4 | technical | technical | 0.91 | yes |
| C5 | technical | technical | 0.88 | yes |
| C6 | technical | technical | 0.99 | yes |
| C7 | technical | technical | 0.99 | yes |
| C8 | technical | technical | 0.97 | yes |
| C9 | technical | technical | 0.85 | yes |
| C10 | physical | technical | 0.60 (at the threshold) | partly: the resolution holds either way (agent mode is principle 3, local quality, as much as separation on condition) |

Two limits of the tool's output:
- For every technical result, `principles` is the whole catalog of 40, unranked, so Jev's call confirms the *classification* but does not choose principles.
- For physical results it returns all six separation routes.

The principle choices in the table below are therefore this design's, made from the catalog, and the classifier only corroborates the type of each contradiction.

| # | Contradiction | Type | Resolution | Principle |
|---|---|---|---|---|
| C1 | The assistant must know about every value, to guide the person, and must know nothing of any value | physical: information about the value must be both present and absent | **Separate by abstraction level.** Expose a closed value state (§3.3), computed in opv's process; the value itself never leaves. No numeric field, because a number is a partial leak | 2 extraction; 26 copying (a simplified copy stands in for the original) |
| C2 | Setup should take one approval, for ergonomics, but every write must be approved, for safety | technical | **Consolidate the approval and keep it exact.** One content-addressed plan lists every step by name. Approving it approves exactly those steps; any change makes it stale and needs a new approval | 5 consolidation; 10 preliminary action |
| C3 | Value-bearing steps (imports, typed values) need a person present, but the assistant should drive the whole setup | physical: the step must be both in the assistant's flow and outside it | **Separate in space.** The plan holds both kinds of step. The assistant's `apply` runs the steps that need no person; the person's `approve`, in their own terminal, runs the person-only steps. The plan is shared; where each step runs is not | separation in space; 1 segmentation |
| C4 | The assistant should be able to run the application to debug it, but the application's output can contain the values opv injected | technical | **opv as intermediary.** `opv run` masks every injected secret-kind value of 8 bytes or more, and its common encodings, in the child's output, always (not only in agent mode). `op run` already masks exact values; opv adds the encodings | 24 intermediary; 9 prior counteraction |
| C5 | Keys must be consistent across environments, but environments legitimately differ | technical | **Consistent by default, different by declaration.** Presence `all` plus an explicit `except` with a reason, and tier policy for what must differ (production distinct from lower tiers) | 3 local quality; 4 asymmetry |
| C6 | Scanning must find every name the code reads, but no deterministic scanner covers every language and dynamic name | technical | **Deterministic core with a validated generative supplement.** The scanner reports its coverage; the assistant supplies what it can see that the scanner can't, through a grammar-checked list tagged `assistant_supplied`. The comparison is still deterministic | 1 segmentation; 23 feedback |
| C7 | Free-text inputs (guidance, reasons) are needed, but a value could be pasted into one | technical | **Screen before accepting.** Every free-text field passes through the same detectors as the value states (secret shapes, high entropy, known prefixes). A hit is refused with `value_in_text_field`, before anything is written | 9 prior counteraction; 11 cushion in advance |
| C8 | The surface must be complete, but small enough that any assistant uses it consistently | technical | **One shape, few verbs.** Five verbs (§4.1) with one envelope; capability grows by adding nouns, not shapes | 6 universality; 7 nesting |
| C9 | The contract should live with the code (reviewed in PRs), but some teams keep it in 1Password so non-repository tools can read it | technical | **One source, two views.** The repository file is the source; a manifest in 1Password is a read-only mirror stamped with the commit, for tools that cannot read the repository. Only one is writable | 4 asymmetry; 26 copying |
| C10 | opv should prompt a person when that helps, but an assistant's shell must never hang on a prompt or see one | physical: the same command must prompt and not prompt | **Separate by condition.** Agent mode (MCP, harness markers, `OPV_AGENT`) never prompts and returns the person's command; a TTY without agent markers prompts | separation on condition |

---

# Part IV: poka-yoke (making confusion and failure structurally impossible)

Each row names a failure or a confusion, and the structure that prevents it. **Prevents** means the failure cannot be expressed. **Detects** means it is caught before harm. **Warns** means the person is told.

## 11. The value boundary

| # | Failure | Structural prevention | Level |
|---|---|---|---|
| P-1 | A value reaches an output | Output documents are built only from value-free types: `Name`, `Id`, `ValueState`, `Path`, closed enums. `SecretValue` implements no `Serialize`, and an output type cannot hold it. A compile-time check (a sealed `ValueFree` trait required by the renderer, implemented only for those types) makes a value-bearing field fail to build. The canary scan stays as the second layer | prevents |
| P-2 | A value is pasted into a free-text input (guidance, reason, name) | Every string input has a grammar (names: `^[A-Z][A-Z0-9_]*$`; guidance: one line, at most 200 characters). Free text passes the secret detectors, and a hit is refused (`value_in_text_field`) before any write | prevents (names), detects (free text) |
| P-3 | A tool input accepts a value | No MCP schema has a field that carries a value. A schema test fails if any input property is not a closed enum, a grammar-checked string or an id | prevents |
| P-4 | An assistant's shell reads a value through `op` | (0.12.0: a docs section only, D-G.) Harness guard rules (§9.4) deny `op read`, `op item get --reveal`, `op inject` and `opv run -- <shell>` for the assistant, and 1Password's authorization prompt protects the rest. This is not a sandbox, and the docs say so | detects |
| P-5 | Child process output leaks an injected value | Always on in local delivery: `op run` masks exact values. **Encoding redaction (base64, hex, URL) is cut from 0.12.0 (D-G)**, because developer machines hold sandbox-grade values; the design below is kept for reference. The mask replaces the whole match with a fixed marker, never by bytes, which keeps JSON well-formed (the 0.10.0 lesson) | detects |
| P-6 | A person pastes a value into the chat | Outside opv's control. The skill and the MCP instructions tell the assistant to stop, never repeat it, point to `opv set`, and treat the value as exposed, which makes the rotation plan the `next` action | warns |

## 12. Model and state

| # | Failure | Structural prevention | Level |
|---|---|---|---|
| P-7 | A failed read is reported as a missing value | `unreadable` is its own value state with its cause. The type that computes states has no path from an error to `absent` | prevents |
| P-8 | A key is missing from an environment by accident | Presence `all` by default. An explicit list that leaves out an environment needs an `except` with a reason, otherwise load warns with `environment_gap` | prevents (new keys), warns (old ones) |
| P-9 | A new environment lacks existing keys | Presence `all` is inherited on creation; the structure plan adds its fields | prevents |
| P-10 | A removed key leaves orphans | Lifecycle states: `retire` moves through `retiring` → `retired` in a fixed order, and archives fields instead of deleting | prevents |
| P-11 | A dev value is copied into production | Tier policy: a production value equal to a lower tier's is an **advisory** health warning (D-G folds `suspect` into the warnings; review M7) unless the key says `allow_same_value`. The comparison is computed only for a person at a terminal and for CI, never on an assistant surface (correction 6). An import into a production-tier environment is the person's `opv import` with `--confirm <env>` | detects |
| P-12 | The code reads a key the contract doesn't declare | The `needs` gate in CI | detects |
| P-13 | A personal key is stored as shared | The catalog marks known per-developer keys (`OPENAI_API_KEY` in a local tier) as suggested `personal`, and the plan shows the suggestion | warns |
| P-14 | A generated contract is edited by hand | Declarations to a generated contract return fragments for the generator (#178), and an edit is refused | prevents |
| P-15 | The contract and the 1Password mirror diverge | Only one is writable (C9). The mirror carries the commit, and `config check` compares | prevents |

## 13. Contract and flow

| # | Failure | Structural prevention | Level |
|---|---|---|---|
| P-16 | The assistant doesn't know what to do next | Every document ends with a typed `next` (kind, actor, command or link). `opv next` returns one action from a fixed priority | prevents |
| P-17 | Different assistants do things in different orders | The order is opv's (`next`, plan step order), not the assistant's. The same state gives the same `next` | prevents |
| P-18 | A plan changes between review and apply | Content-addressed `plan_id`; a stale plan refuses | prevents |
| P-19 | An approval is replayed or used for another project | Single use, bound to the project, account and contract text, and claimed by an atomic rename (as today) | prevents |
| P-20 | The assistant runs a person-only command and hangs on a prompt | Agent mode: the command refuses at once with `next.actor = person` and the exact command | prevents |
| P-21 | A half-finished plan leaves an unknown state | Every plan is resumable. The inventory and `next` show the partial state, and a re-run converges without duplicates | prevents |
| P-22 | Two runs race | One lock per project and environment for writes, as for sync today | prevents |
| P-23 | A promotion goes out with missing values | `ready --gate` per environment in the CI recipe | detects |
| P-24 | Output differs run to run, so plans never match | Stable ordering, no clock in plans, golden tests on documents | prevents |

---

# Part V: delivery (0.12.0)

The deliverables of the 0.12.0 scope (D-G), in the style of `delivery-transports.md` §11.1. They are one plan, `v0120` in `.cpm-planner/plans/v0120/`, whose rows equal this table. Anchors are file:line in opv 0.11.0 (`c381749`).

**Rules every row follows.**
- **Executors.** `junior` (DeepSeek through the Junior CPM tool) takes single-module or file-seam rows of at most about 400 changed lines, with recorded fixtures or focused tests and exact pointers, so a contract can be built from the row. `agent` (a Claude subagent) takes only what Junior is known to stall on: `src/mcp.rs`, the CLI removal sweep across `src/main.rs`, e2e simulator scenarios, integration and the gate. `owner` is manual work on the owner's 1Password; `manager` is acceptance review and the release.
- **Tests** follow `CONTRIBUTING.md:73-75`: atomic scenarios, declarative names, exactly one behavioural assertion per test, observable outcomes, recordings and never invented replies.
- **Surfaces.** A row that exposes something to the CLI or MCP adds the S7MARKER canary scan of its document; CLI/MCP parity is proven where the MCP tool lands (`mcp-state`, `mcp-propose`) and swept in `canary-surface` and `e2e-coverage`.
- **Shared files** are claimed `[append]` (additive edits to separate items: new enum variants, new struct fields, module lines) and reconciled in `integrate`.
- **Checks** a Junior contract runs: `cargo fmt --all -- --check`; `cargo-safe.sh clippy --all-targets --features fake,mcp -- -D warnings`; `cargo-safe.sh nextest run --features fake,mcp` scoped to the module.

**Groups and milestones.** `surface-contract` fixes the §25 surface first (a contract), so the e2e and surface-doc rows build against it. `model` and `state` (value boundary, tiers, presence, value states, capability, H1, inventory, `next`, gate, doctor) end at the internal milestone `core-accepted`; `needs` (scanner, contract as data, catalog, relaxations) and `flows` (intent, propose, apply, import, set, retire) end at `flows-accepted`; `surface` (the one interface on MCP and the CLI, canary, e2e) and `docs` follow; `release` ends at `release-0120`, then `verify-0120`.

| ID | Deliverable | Owned files (anchors) | Prereq. (consumes) | h | Acceptance criteria | Executor |
|---|---|---|---|---|---|---|
| a1-spike | A-1 spike: can a 1Password person write a vault they can't read | `docs/design/spike-a1-findings.md` (new) | — | 2 | Records, from the owner's account, whether a member with write-but-not-read permission can create an item and fill a field, and what `op` returns to them. States which form of R4/R9(a) holds. No value is recorded. | owner |
| rec-owner | Recorded op and kubectl replies for vault permissions and platform logins | `tests/fixtures/op/success/` (new `s2x-*` cases beside `s04-vault-user-list`); `tests/fixtures/kubernetes/success/` (`config current-context`, `config view --minify -o json`) | — | 3 | Replies recorded with the existing recorder (`.delivery/v0100/record-op-failures.sh` pattern) for `op whoami`, `op vault user list` and `op vault get` as a writer, a read-only member and a non-member, plus the two kubectl replies; README rows name each case. Names only; the canary scan of the fixtures is clean. | owner |
| tier | Environment tier attribute (local | shared | production) | `src/domain/model.rs` (`Environment` :285) [append]; `src/config.rs` (`validate` :1140) [append]; `src/domain/health.rs` (`is_production` :348) [append]; `src/domain/tier_tests.rs` (new) | — | 4 | `tier` parses; an absent tier loads as `production` where `is_production` holds today, else `shared`; `local` with a target or `confirm_env` is refused `config_invalid` naming the environment; `is_production` reads the tier. One test per rule; existing tests pass. | junior |
| key-attrs | Key attributes source, expires and lifecycle | `src/domain/model.rs` (`KeySpec` :85) [append]; `src/config.rs` (`validate_key` :1854) [append]; `src/domain/key_attrs_tests.rs` (new) | — | 4 | `source = person|generated|derived` (derived iff `from`; generated iff a `generate.rs:60` recipe), `expires = <date>`, `lifecycle = active|retiring|retired` parse; each inconsistency is refused with the key named. One test per refusal. | junior |
| presence | Presence all plus except, and the not_wanted resolution | `src/domain/presence.rs` (new: `present_in(key, env)`); `src/domain/model.rs` (`KeySpec` :85) [append]; `src/config.rs` (`validate_key` :1854) [append]; `src/domain/plan.rs` (row selection in `build_with` :267-321) [append] | — | 6 | A key without `environments` is present in every environment; `except = {env = "reason"}` makes it `not_wanted` there with the reason; an explicit list leaving an environment out without `except` loads with warning `environment_gap`; an empty reason is refused. Plans skip `not_wanted` rows. One test per rule. | junior |
| bindings-load | Bindings file: ids out of the contract, plus the apply-record format *(contract)* | `src/config/bindings.rs` (new); `src/config.rs` (`parse` :182, `load` :42) [append]; `src/config/bindings_tests.rs` (new) | — | 5/6/9 | `secrets.bindings.toml` (one sorted line per id, union-mergeable) supplies boundary, item, state-vault and personal ids; inline ids still load with finding `ids_inline` whose `next` is `opv propose structure`; the apply record (`.opv/applied.json`: plan id, contract digest, bindings digest) has a typed reader and writer. Tests: merge, inline finding, record round-trip. | junior |
| bindings-check | config check compares the bindings file with the apply record | `src/app/config_cmd.rs` (`check`); `src/cause/mod.rs` (`ConfigCheck`) [append] | bindings-load (apply-record reader) | 4 | `opv config check` fails `bindings_unapplied` when the committed bindings digest differs from the apply record, naming the environment; passes when equal. Two tests, one assertion each. | junior |
| agent-mode | Agent mode as presentation and the person-only refusal | `src/host.rs` (`agent_mode()` beside `interactive()` :87); `src/cause/mod.rs` (`Refusal` :1117) [append]; `src/cause/render.rs` (`document` :4305-4330) [append] | — | 3 | MCP, `OPV_AGENT=1` and the documented harness markers set agent mode; a person-only command in agent mode refuses at once with `next.actor = person` and the exact command; the refusal names the marker. One test per marker; no prompt opens (FakeRunner shows no read of stdin). | junior |
| next-envelope | Typed next (kind, actor) in the JSON envelope, schema 3 *(contract)* | `src/json.rs` (`SCHEMA_VERSION` :19, `frame` :61-84); `src/cause/render.rs` (`document` :4305-4330) [append]; `src/app/ready.rs` (`Next` :165) [append] | — | 5 | Every `--json` document's `next` carries `kind` (`run`, `apply`, `enter_value`, `authorize`, `wait_ci`, `none`) and `actor` (`assistant`, `person`, `ci`); `schema_version` is 3; no free-text field decides an action. Golden tests of three documents; the e2e snapshots are regenerated in `e2e-coverage`. | junior |
| rule-source | Default-branch rule source (H1) *(contract)* | `src/app/rule_source.rs` (new); `src/app/rule_source_tests.rs` (new) | — | 6 | The default branch comes from `git symbolic-ref refs/remotes/origin/HEAD` (else `main`); the contract there is read with `git show` and parsed by `config::parse` (src/config.rs:182); each key's rules are `committed` or `pending_review`; a manifest-only project is `manifest`. Temp-repo tests: committed counts; working-tree-only, branch-only and hand-edited rules are pending. | junior |
| rule-gate | Only committed rules are evaluated for assistants | `src/domain/plan.rs` (`RuleFailed` mapping :345, `KeyState` :53) [append]; `src/app/ready.rs` (`row_findings` :450-476) [append]; `src/cause/mod.rs` (`rules_pending_review`) [append] | rule-source (rule status per key); agent-mode (agent-mode flag) | 5 | For MCP and agent-mode callers a rule that is not committed yields `rules_pending_review`, never pass/fail; a person at a TTY and CI see the result. The gate test covers a rule declared through the propose route and one hand-edited into `secrets.toml`. | junior |
| value-state | The seven value states, computed in memory *(contract)* | `src/domain/value_state.rs` (new); `src/domain/value_state_tests.rs` (new) | presence (not_wanted resolution); rule-source (rule status) | 5 | `absent`, `empty`, `placeholder` (`health::is_placeholder` :291), `malformed{rule}` (`rules::check` :259, committed rules only), `set`, `unreadable{cause}`, `not_wanted{reason}`; the read error type has no conversion to `absent` (a compile-fail test); no state carries a number or a part of the value. One test per state. | junior |
| health-filter | Cross-tier warnings off assistant surfaces; health advisory only | `src/app/ready.rs` (`build_findings` :625-655) [append]; `src/domain/health.rs` (`same_across` :134, `same_under_two` :175) [append] | agent-mode (agent-mode flag) | 3 | `same_across` and `same_under_two` never appear for MCP or agent-mode callers and appear for a TTY person and CI; no health finding is blocking. Two tests per surface. | junior |
| capability | Capability per vault: write, read, none, unknown *(contract)* | `src/domain/capability.rs` (new); `src/app/access.rs` (`observe` :346, `diagnose_vault` :394) [append]; `src/adapters/onepassword_init.rs` (`vault_users` :99) [append] | rec-owner (recorded permission replies) | 5/6/9 | From the recorded replies: a writer is `write`, a read-only member `read`, a non-member `none`; a reply without permissions is `unknown{source}`; a refusal is a typed finding. One test per recording. | junior |
| receipts | Receipts carry age, item versions and revision; staleness | `src/app/ready.rs` (`Receipt` :172, `--save` :1004) [append]; `src/app/receipt_age.rs` (new) | — | 5 | A saved receipt holds `generated_at`, the item versions it saw and the git revision; `stale` holds when a newer item version exists (the `op item list` versions of `changed.rs` :106); no value or digest. Tests: fresh, stale, missing revision. | junior |
| gate | ready --gate: set and delivered; expiry advisory | `src/app/ready.rs` (end of `run` :1010-1020) [append]; `src/cause/mod.rs` (`GateFailed`) [append]; `src/cause/codes.rs` (`table` :24) [append] | value-state (states); receipts (item versions); key-attrs (expires) | 6 | `--gate` exits non-zero `gate_failed` when a present key is not `set`, or its delivery evidence (`delivery.rs` source versions :49, :317) is older than the item version; an `expires` within 30 days is an advisory finding; without `--gate` the exit is unchanged. One test per condition; canary scan of `ready --gate --json`. | junior |
| inventory-doc | Inventory document (pure builder) *(contract)* | `src/domain/inventory.rs` (new); `src/domain/inventory_tests.rs` (new) | value-state (states); capability (capability); tier (tier); key-attrs (attributes); receipts (receipt age) | 5 | Keys × environments, each cell a state plus the capability on its vault, with ids, source, presence and tier; cells of a `none` vault come from the newest receipt with its age; sort order stable (golden test). | junior |
| inventory-cmd | opv inventory (gather, render text and JSON) | `src/app/inventory.rs` (new); `src/app/inventory_tests.rs` (new) | inventory-doc (document); next-envelope (typed next); bindings-load (ids) | 5/6/9 | Reads fields once per item, delivery state from `delivery.rs` `read_state` :284; renders text and `--json`; the S7MARKER scan over both is clean (test in this row); FakeRunner shows one `op item get` per item. | junior |
| next-cmd | opv next: one action and the queue | `src/app/next.rs` (new); `src/app/next_tests.rs` (new) | inventory-doc (cells); next-envelope (typed next) | 5 | A fixed priority picks one action this session can take; then the queue; then what waits on others, by vault; a deployed-tier vault with one writer is a finding. Same state gives the same bytes. One test per priority rank. | junior |
| explain-leak | explain KEY lists every place the key is delivered | `src/app/explain.rs` (`explain_in` :237); `src/app/explain_tests.rs` [append] | — | 4 | `opv explain KEY` adds every environment, target and delivery holding the key (delivery items via `delivery.rs` `read_state` :284), names only; `explain <plan_id>` explains the steps of the recomputed plan. Canary clean. | junior |
| doctor-r9 | doctor reports production-tier vault reads and production platform logins | `src/app/doctor.rs` (`run_on_with` :378, `target_checks` :754) | capability (capability); tier (tier) | 6 | Warn rows (never fail): the session can read a production-tier vault; a production target's platform session is live: kube current-context equals the target's context (`kubernetes/mod.rs` :105, recorded reply), `flyctl auth whoami` (`fly/mod.rs` :558), `az account show` (`az.rs` :64), `gh auth status` (`github/config.rs` :413). Each names the fix and the hardened option. One test per check. | junior |
| access-writers | access shows writers, tier membership and second writers | `src/app/access.rs` (`build` :476) [append]; `src/domain/access.rs` (`findings` :119) | capability (capability) | 4 | `opv access` lists who can write each vault where 1Password reports it, marks production-tier vaults, and raises `single_writer` for a deployed-tier vault with one writer. One test per finding. | junior |
| scan-core | Scanner core: walker, name grammar, ignore list, coverage *(contract)* | `src/scan/mod.rs` (new); `src/lib.rs` (module list :7-36) [append]; `src/scan/mod_tests.rs` (new) | — | 5 | Walks the repository respecting `.gitignore`, skips vendored and build directories, validates `^[A-Z][A-Z0-9_]*$`, drops the built-in runtime names (PATH, HOME, NODE_ENV, CI, …), and reports coverage (files, languages, skipped patterns). Defines the `Pattern` trait the languages implement. | junior |
| scan-lang | Scanner patterns: Rust, TypeScript/JavaScript, Python, Go | `src/scan/lang.rs` (new); `tests/fixtures/scan/` (new per-language sources) | scan-core (Pattern trait) | 5/6/8 | Each language's static env reads give `observed` with file:line; a computed name gives `ambiguous`. One fixture file and one test per pattern. | junior |
| scan-manifests | Scanner patterns: .env.example names, Compose, Kubernetes, fly.toml, workflows | `src/scan/manifests.rs` (new); `tests/fixtures/scan/manifests/` (new) | scan-core (Pattern trait) | 5 | Names only (a value in `.env.example` is never read into memory beyond the line split); one test per manifest kind. | junior |
| annotations | ignore annotations with their evidence span | `src/domain/model.rs` (`Product` :132) [append]; `src/config.rs` (`validate` :1140) [append] | — | 3 | `[products.<p>.ignore] NAME = {reason, span}` parses; an empty reason is refused; the span is a stable hash of the evidence line. One test per rule. | junior |
| needs | opv needs and the needs gate | `src/app/needs.rs` (new); `src/app/needs_tests.rs` (new) | scan-lang (observations); scan-manifests (observations); annotations (ignore); rule-source (default-branch reader) | 5/6/9 | `undeclared`, `declared_unobserved`, `ambiguous`, `declared`, with coverage; an `ignore` whose span changed shows again as unannotated; `--gate` fails on an undeclared name that the default-branch contract lacks. Canary clean. One test per state. | junior |
| relaxations | Relaxation classifier against the default branch *(contract)* | `src/domain/relaxation.rs` (new); `src/domain/relaxation_tests.rs` (new) | rule-source (default-branch contract); tier (tier); presence (except) | 5 | Lists, with reasons: `except` of a production-tier environment, `allow_same_value` added, a rule or shape removed, presence narrowed, `secret` → `config`. One test per relaxation kind; an unchanged contract lists none. | junior |
| catalog | Shape and provider catalog *(contract)* | `src/domain/catalog.rs` (new); `src/domain/catalog_tests.rs` (new) | — | 4 | Shape names (`stripe_secret`, `openai_key`, `pem_private_key`, `https_url`, `url`, `base64_bytes_32`, `hex_bytes_32`, `email_list`, …) map to `Rules` (src/domain/model.rs:26); known names suggest kind, source, scope and one-line guidance, each entry dated with its source. One test per shape. | junior |
| contract-data | opv contract: the contract as data, JSON Schema, check, relaxations, docs | `src/app/contract.rs` (new); `src/app/contract_tests.rs` (new); `docs/contract-validation.md` (new) | key-attrs (attributes); catalog (shape names); relaxations (relaxation list and presence) | 6/7/9 | Per component and environment: name, kind, shape name, required (contract × presence) and the contract digest; `--schema` emits a JSON Schema that the emitted document validates against; `--check <file>` fails on a stale copy; `--relaxations` lists them. No id, rule parameter or value (canary). The doc shows startup validation with zod, pydantic, serde and Go, each erroring with key and shape only. | junior |
| intent | The intent document: types, grammar, guidance screening *(contract)* | `src/domain/intent.rs` (new); `src/domain/intent_tests.rs` (new) | catalog (shape names) | 5 | Kinds `key`, `env`, `target`, `retire`, `setup`, `structure`, `generate`, `tidy`; names grammar-checked; attributes closed enums; shapes catalog names only (no rule parameters); guidance one line ≤ 200 characters, screened by pattern detectors (known prefixes, PEM headers, high entropy), refused `value_in_text_field` naming the detector, stored `assistant_written`. JSON Schema emitted for MCP. One test per refusal. | junior |
| propose-key | opv propose key, env, retire (contract diff, relaxations first) | `src/app/propose/key.rs` (new); `src/config_edit.rs` (`add_key` :155, `add_key_env` :219, `add_environment` :246) [append]; `src/app/add.rs` (`rule` :353, `environments` :331 move out) | intent (intent types); relaxations (classifier (with presence and tier)); key-attrs (attributes) | 5/6/9 | Returns the contract diff and a content-addressed plan id; relaxations listed first; each production-tier environment asks "a value, or except?"; `--write` writes the diff only to the contract file. Pure without `--write` (FakeRunner shows no `op` write). One test per kind. | junior |
| propose-target | opv propose target | `src/app/propose/target.rs` (new); `src/app/declare.rs` (`target` :205 move out) | intent (intent types) | 4 | Folds `target add` and `opv_declare_target`: provider options validated as today (`src/app/target_cmd.rs`), the diff and plan returned, `--write` as above. One test per provider. | junior |
| propose-setup | opv propose setup (from an item, or a .env's names) | `src/app/propose/setup.rs` (new); `src/app/init.rs` (`read_from` :111, `plan_from` :174) [append] | propose-key (key diff builder) | 5/7/10 | `--from-item` builds the contract from an item as `init` does; `--names-from <.env>` reads names only (`setup_import.rs` `parse_at` :37 names, kinds by `kind_guess`), never values into the plan; the plan includes boundaries, items and fields. One test per source. | junior |
| propose-structure | opv propose structure, generate, tidy, rebind | `src/app/propose/structure.rs` (new); `src/app/propose/mod.rs` (new) | bindings-load (bindings and record); intent (intent types) | 5/6/10 | One structure plan over contract, bindings and actual state: missing vaults, items, state vaults and empty fields (from `structure_cmd.rs` `plan` :93, `bootstrap.rs`, item skeleton), generation (`generate.rs` `plan` :161), tidy (`tidy.rs`), `--rebind`; inline ids are moved to the bindings file. Plan id stable (golden). | junior |
| apply-core | opv apply: recompute, refuse stale, confirm, run in one process | `src/app/apply.rs` (new); `src/app/apply_tests.rs` (new) | propose-structure (structure plan); agent-mode (refusal) | 5/6/10 | Recomputes the plan from the contract on disk; a different id refuses `stale_plan`; shows it, confirms in a TTY, runs every step with the existing executors (`structure_cmd.rs` `apply_authorized` :167, `generate.rs` `make` :93) and writes bindings plus the apply record; non-TTY and agent mode refuse with `next.actor = person`; a re-run converges with no duplicate. One test per outcome. | junior |
| approval-removal | Remove the approval file and approve paths | `src/approval.rs` (delete (TTL :19)); `src/app/approve.rs` (delete); `src/app/structure_cmd.rs` (`apply` :141-167); `src/approval_tests.rs` (delete) | apply-core (replacement path) | 3 | No code path reads or writes an approval record; `structure_cmd` keeps only what `apply` calls; `cargo test` passes with the approval tests removed. | junior |
| import-domain | Write-only import actions | `src/domain/adopt.rs` (`Action` :18, compare :203-246 → src/domain/import.rs) | — | 4 | Actions are `imported`, `skipped_already_set`, `skipped_empty`, `replaced`, `held_immutable`; there is no `match`, `differs` or `format_only`; the output for equal and unequal file values is identical (H2 test). | junior |
| import-cmd | opv import (person): file or target source | `src/app/import.rs` (from `src/app/adopt.rs` (`run` :187, `write_item` :326, `print` :443)); `src/app/adopt.rs` (delete); `src/app/init.rs` (`import_values` :407) [append] | import-domain (actions) | 4/5/8 | `--from <file.env|target:NAME>`, `--replace`, `--rotate`, `--skip`, `--dry-run`; reports presence words only; values go file → 1Password via stdin (FakeRunner argv clean). One test per flag. | junior |
| import-local | opv_import_local guard: tier local, assistant_imported | `src/app/import_local.rs` (new); `src/domain/health.rs` (skip tagged values in `same_across` :134) [append] | import-cmd (importer); tier (tier) | 4 | Refuses any environment whose tier isn't `local` (`import_tier_refused`); tags written keys `assistant_imported` (an item tag, value-free); tagged values are left out of comparisons and never count toward a gate. One test per rule. | junior |
| set-cmd | opv set: masked entry of one value | `src/app/set.rs` (new); `src/app/set_tests.rs` (new) | agent-mode (refusal); import-cmd (field writer) | 4 | Prompts with `masked.rs` `prompt` :84; refuses non-TTY (`no_terminal` :99) and agent mode with the typed `next`; writes through the importer's stdin path; prints the new state only. One test per outcome. | junior |
| retire | Retirement: needs at the deployed revision, prune by tier, archive | `src/app/retire.rs` (new); `src/domain/plan.rs` (prune of `retiring` keys) [append] | needs (scanner over a revision); receipts (deployed revision); apply-core (step runner); key-attrs (lifecycle) | 5/7/10 | A key still read at the deployed revision refuses `retire_still_read` naming the file; otherwise prune shared tiers before production, then mark `retired` and archive the fields; resumable, and the inventory shows `retiring`. One test per step. | junior |
| ui-remap | opv ui actions call the new commands | `src/ui/run.rs` (:138); `src/ui/adopt_review.rs` (:98-104); `src/ui/forms.rs`; `src/ui/adopt_review_tests.rs` (:175-253) | import-cmd (import flags); propose-key (propose flags) | 4 | The review screen fetches `import --dry-run --json`, the form runs `propose key --write` then `apply`; the argv tests are updated. | junior |
| courier-test | Courier invariant test over every transport | `tests/courier.rs` (new) | — | 4 | With an S7MARKER value, Fly (`fly/mod.rs` `stage` :168-182), Kubernetes (`store.rs` `write_one` :548-586), Key Vault (`keyvault.rs` `write_secret` :269-297, `/dev/stdin`), GitHub (`gh.rs` `set_secrets` :137-153, `set_variables` :261) and local delivery send the marker on stdin only: never argv, the child environment, a file or output. One test per transport. | junior |
| ci-workflow | ci workflow: needs, contract check, ready gate, relaxations check | `src/app/ci_workflow.rs` (`run` :25, `Job` :265, `workflow` :319); `examples/ci-change-detection/` | needs (needs --gate); contract-data (contract --check/--relaxations); gate (ready --gate) | 5 | The PR workflow runs `opv needs --gate`, `opv contract --check` and `opv ready --gate`, and a separate job `opv/relaxations` that fails while `opv contract --relaxations` lists any and the PR has no approving review at its head; golden tests; `actionlint` passes; the example equals the output. | junior |
| rotation-doc | The documented rotation procedure and expiry | `docs/rotation.md` (new) | key-attrs (expires) | 3 | The four steps of R11 on `sync --rotate` and `delivery verify`, outside consumers, and `expires`; every command shown exists in `opv schema` (a doc test in `tests/agent_guidance.rs` style). | junior |
| doc-config | docs/configuration.md for tiers, presence, attributes, bindings, rules | `docs/configuration.md` (`:89`, `:544`, `:580`, `:661-685`) | propose-key (flags and attributes); bindings-load (bindings file) | 4 | Sections for `tier`, `except`, `source`, `expires`, `lifecycle`, the bindings file and the apply record, the default-branch rule rule, advisory health; `init --add-env` and `opv add` sections become `opv propose`. Links resolve. | junior |
| doc-security | README and security docs: honest limit, admin account, guard rules | `README.md` (`:107-141`); `docs/security.md` (new) | a1-spike (A-1 result); courier-test (courier invariant) | 4 | The honest limit of §1; D-A's accepted residual and the separate admin account as the hardened option; A-1's result; the courier invariant; a harness guard-rules section (docs only). | junior |
| surface-contract | The §25 surface as a golden the CLI and MCP must equal *(contract)* | `tests/e2e/expected/surface.json` (new) | intent (intent JSON Schema for opv_propose) | 3 | §25.1's commands and flags and §25.2's five tool names and input schemas, as one JSON golden; `cli-sweep` and `mcp-propose` add a test that `opv schema` and `tools/list` equal it, and e2e and the surface docs are written against it before the surface lands. | junior |
| core-accepted | Core accepted: state, inventory, next, gates reviewed together **(milestone)** | `.delivery/v0120/core-acceptance.md` (new) | inventory-cmd (inventory); next-cmd (next); gate (gate); rule-gate (H1 fix); health-filter (filter); doctor-r9 (doctor); access-writers (access); explain-leak (explain) | 1 | Each row's receipt and checks reviewed; the core documents render in one sim run. | manager |
| flows-accepted | Flows accepted: propose, apply, import, set, retire reviewed together **(milestone)** | `.delivery/v0120/flows-acceptance.md` (new) | approval-removal (apply path); set-cmd (set); import-local (local import); retire (retire); propose-setup (setup); propose-target (target); ui-remap (ui) | 1 | Each row's receipt and checks reviewed; one sim run from no configuration to a set local tier. | manager |
| mcp-state | MCP opv_state replaces the six read tools | `src/mcp.rs` (router :367-450, `inspect` :1032, workers :1111-1598) | core-accepted (core documents); needs (needs); contract-data (contract) | 6/8/12 | One tool, `section` enum, each section byte-equal to the CLI `--json` (parity tests); the six old tools are gone. | agent |
| mcp-propose | MCP opv_propose, opv_import_local, opv_next, opv_explain; write tools removed | `src/mcp.rs` (tools :453-581, schemas :43-615, workers :833, :1429-1520, :1744-1850, parity :2638); `src/schema.rs` (`MCP_TOOLS` :12-16) [append]; `tests/mcp_protocol.py` (:45-62) | mcp-state (src/mcp.rs router); flows-accepted (flows) | 6/8/12 | `tools/list` is exactly the five; only `opv_import_local` writes; none is destructive; `opv_propose` is pure (FakeRunner shows no `op` write); each tool's document equals the CLI's. | agent |
| cli-sweep | The one CLI: new commands wired, duplicates removed | `src/main.rs` (`Cmd` :578-1164, sub-enums :1324-1670, dispatch); `src/schema.rs` (`EFFECTS` :50) [append]; `src/completions.rs`; `src/app/declare.rs` (delete); `src/app/mod.rs` (module list :12-67) [append] | core-accepted (core commands); flows-accepted (flow commands); contract-data (contract) | 8/10/14 | `opv schema` equals §25.1; every removed command in §25.3 is absent (one test that each fails as an unknown subcommand); no alias exists. | agent |
| canary-surface | Canary scan and MCP input-schema test over the one interface | `tests/security.rs` (`COMMANDS` :553, MCP tests near :2790) | mcp-propose (tools); cli-sweep (commands) | 5 | Every new CLI document and each of the five tools is in the S7MARKER scan; P-3: every MCP input property is a closed enum, a grammar-checked name, an id or a path, `guidance` the named exception. | junior |
| e2e-coverage | e2e coverage cases and snapshots for the new documents | `tests/e2e/coverage.rs` (`cases` :503, `scenarios!` :1638); `tests/e2e/snapshots/`; `tests/e2e/app/world.json` (vault permissions, tiers); `tests/sim/op.rs` (permission replies) | surface-contract (the §25 surface, interface); core-accepted (core behaviour); flows-accepted (flow behaviour) | 6/7/10 | Written against the surface golden, reconciled with the real surface in `integrate`: a json, text and mcp case per new command and tool; snapshots reviewed in `REVIEWED.md`; schema 3 snapshots regenerated. | agent |
| e2e-walkthrough | The assistant walkthrough on opv-sim | `tests/e2e/scenarios/assistant.rs` (new); `tests/e2e/main.rs` (`mod scenarios` :7-13); `tests/e2e/snapshots/scenarios/` | e2e-coverage (world and sim replies) | 6/8/12 | From a repository with no configuration to `ready --gate` passing in every environment using only the five tools plus `opv apply`, `opv set`, `opv import` and CI's `sync`; records the person-action count; canary clean. | agent |
| doc-usage | docs/usage.md: the one interface | `docs/usage.md` (commands :7-59, JSON :696, exit codes :904-919) | surface-contract (the §25 surface, interface) | 5 | The commands table equals §25.1; exit codes include `gate_failed`; the JSON contract shows schema 3 and typed `next`; a migration section carries §25.3. | junior |
| doc-mcp-skill | docs/mcp.md, the agent skill and agent setup | `docs/mcp.md` (tools :8-22, who does what :69-95, authorization :97); `docs/agent-skill.md`; `docs/agent-setup.md`; `tests/agent_guidance.rs` | surface-contract (the §25 surface, interface) | 5 | Five tools, the actor model (assistant proposes; person applies; CI delivers), P-6 (a pasted value is exposed, `opv set` next); the guidance test passes. | junior |
| integrate | v0120/integrate: every lane merged, conflicts resolved | `.delivery/v0120/integration.md` (new) | canary-surface (scan); e2e-walkthrough (walkthrough); doc-usage (usage); doc-mcp-skill (mcp docs); doc-config (configuration docs); doc-security (security docs); rotation-doc (rotation doc); ci-workflow (workflows); bindings-check (config check) | 4/6/10 | All lanes on one branch; `cargo test --features fake,mcp` green; the main checkout untouched. | agent |
| changelog-version | CHANGELOG and version 0.12.0 | `CHANGELOG.md` (:8); `Cargo.toml` (:4); `Cargo.lock`; `docs/install.md` (:26); `examples/ci-change-detection/.github/actions/install-opv/action.yml` (:7, :9) | integrate (integrated branch) | 2 | `[0.12.0]` with the §25.5 migration notes, the cut list of D-G and every R row; version strings 0.12.0 everywhere `0.11.0` was a release pin (`docs/usage.md:978` included). | junior |
| full-gate | Full gate report | `.delivery/v0120/gate-report.md` (new) | changelog-version (versioned branch) | 4 | `cargo fmt --check`; clippy `--all-targets --features fake,mcp -D warnings`; nextest `--features fake,mcp`; `tests/mcp_protocol.py`; cargo-deny; `actionlint` on the examples; snapshot review clean. | agent |
| release-0120 | opv 0.12.0 tagged and published **(milestone)** | `.delivery/v0120/release.md` (new) | full-gate (green gate) | 3 | `.delivery/release.sh 0.12.0 v0120/integrate`: PRs to dev, staging and main green; tag `v0.12.0`; the release workflow and npm publish succeed. | manager |
| verify-live | Owner's live check on the tagged release | `.delivery/v0120/owner-live-check.md` (new) | release-0120 (the tag) | 2 | On the owner's account: capability states, `opv set`, `opv apply` in one process, `opv import` write-only, the doctor R9 rows. Names only. | owner |
| verify-0120 | Post-tag verification of opv 0.12.0 **(milestone)** | `docs/verification/v0.12.0-one-interface.md` (new) | verify-live (owner's notes) | 5 | The installed release: `opv schema` equals §25.1; `tools/list` is the five; the walkthrough passes against the release binary in the sim; canary clean; the owner's notes attached. | agent |


**Totals:** 65 deliverables, 312 h (likely values; 18 rows carry a three-point estimate, sampled by Monte Carlo). By executor: junior 244 h (78 %), agent 56 h (18 %), owner 7 h, manager 5 h. By group: model 24, state 74, needs 41, flows 65, ci 12, docs 18, surface 51, release 22, owner 5.

**Schedule (plan `v0120`, selected variant `surface-contract`, baseline 1 from 2026-10-18, 8 h/day Mon–Fri).** Capacities junior 6, agent 3, owner 1, manager 1.
- CPM 66 h, levelled 73 h, P50 69.2 h, P80 70.9 h, P95 72.5 h; project buffer 18.25 h.
- Critical path: `catalog` → `intent` → `propose-structure` → `apply-core` → `retire` → `flows-accepted` → `cli-sweep` → `canary-surface` → `integrate` → `changelog-version` → `full-gate` → `release-0120` → `verify-live` → `verify-0120`.
- Milestones: `core-accepted` at 23 h, `flows-accepted` at 29 h, `release-0120` at 59 h, `verify-0120` at 66 h (CPM).
- Utilisation: junior 0.56, agent 0.26, owner 0.10, manager 0.07. The schedule is bound by dependencies, not capacity.
- The selected variant is the contract-first one: `surface-contract` fixes the §25 surface as a golden early, so e2e coverage and the surface docs are written in parallel with the surface instead of after it. Against the first plan it saves 9 h of CPM, 10 h levelled and 9.3 h at P80, for 4 h more effort.

Out of this plan (D-G): Docker Swarm S1–S6 and X2, GCP Secret Manager and the VM step (`delivery-transports.md` §11.2), R7 purpose tokens, and everything D-G cut.

---

# Part VI: reframings (2026-10-18)

The review and the FMECAs found risks that Parts I–IV answer one by one: an extra check here, a guard rule there. The owner asked a better question. Can the problem be reframed, by giving each part of the work to the right kind of tool, so that whole classes of risk cannot be expressed **and** the experience gets simpler at the same time? This part tries seven reframings, keeps the ones that pay off, and drops the ones that don't. The owner also decided (2026-10-18) that the rule-predicate oracle (review H1) is fixed in the 0.12.0 design, not as a 0.11.x patch.

## 20. The three kinds of work

Every input or decision in the system is one of three kinds:

| Kind | Examples | Who produces it | How opv treats it |
|---|---|---|---|
| **Deterministic** | the names the code reads, the plan, value states, ordering, imports, generation, delivery | opv's code | computed; never accepted from a client |
| **Categorical** | a key's kind, source, scope, presence, catalog shape, tier, an `except`, an ambiguity resolution, approve or decline | the assistant or the person | **chosen from a closed set opv enumerates**; nothing else parses |
| **Generative** | understanding intent, choosing among categories, prose guidance for an unknown provider, conversation | the assistant | kept outside opv, or stored only as screened, labelled, inert text |

**The governing rule:** a client can hand opv a **choice** (categorical), a **name** that opv's grammar validates, or a **reference** (a path or an id). It never hands opv **content** that opv evaluates against a value. Every risk in the review's High list breaks this rule:
- **H1:** a regular expression is content evaluated against a value.
- **H2:** a caller's `.env` is content compared with a value.
- **H4:** a command's output is content derived from a value.

## 21. Seven attempts

### R1. The assistant plans; it never actuates

- **Today, and in Parts I–IV:** the assistant applies approved plans (`opv_structure_apply`, `opv_sync`). Approval is a separate act in the person's terminal, recorded in an approval file with a 15-minute window.
- **The reframe:** only two actuators exist.
  - **The person's terminal:** `opv apply` shows the plan, the person confirms, and it runs in one process. Value entry and imports happen there too.
  - **CI:** scheduled, approved syncs with the target's own identity.
- **The assistant's role:** it reads state and proposes. It never writes to a target, and never to 1Password except R3's write-only import into an environment of tier `local` (default 5).

What it removes:
- the approval file, its window and the race between `approve` and `apply` (review M3);
- plan replay;
- the assistant running a person-only step (P-20);
- the need for agent mode to be a security control (review M2): it becomes presentation only.

What it simplifies: the person runs one command instead of two, `approve` then the assistant's `apply`. The assistant's tool surface loses every write tool.

What it costs: nothing changes in 1Password or on a platform unless a person or CI acts. Today that's already true in effect, because every write needs the person's approval, and 1Password asks the person to authorize it.

**Verdict: keep.** It shrinks the surface and removes a class of races.

### R2. A categorical intent language instead of commands

- **The reframe:** the assistant's only write is to the **contract**, through one tool, `opv_propose`, that takes an *intent document*. Its fields are:
  - names, checked by grammar;
  - enumerated attributes: kind, source, scope, presence, tier;
  - **catalog shape names with no parameters**: `stripe_secret`, `base64_bytes_32`, `https_url`;
  - references: paths and ids;
  - optional guidance.
- **What can't be expressed:** a regex, a prefix string, an `enum=` list or any other parameterized rule. Those come only from the catalog or from a person editing the contract in review.
- **What opv returns:** the contract diff and the plan it implies. Nothing is written until a person runs `opv apply`, or merges the contract change in a pull request (R6).

What it removes:
- **H1 entirely:** the assistant cannot choose a predicate, so there is no adaptive oracle;
- free-text value paste into most fields (P-2): only guidance stays free text, it is screened, and it is stored labelled `assistant_written`;
- the schema test conflict the review found (M13);
- most of the per-command shapes the assistant has to learn (C8, M14).

What it simplifies: the assistant fills one form, the same way across Claude Code, Cursor and Codex. opv explains every refusal against the form.

**Verdict: keep.** This is the core of the reframe.

### R3. A data diode for values

- **The reframe:** values flow one way only:
  - **in:** a person, a file reference, a generator or a provisioner, into the store;
  - **onward:** the store, into the platforms, into the application.
- **What may flow back to the control plane,** where the assistant lives, is fixed in advance:
  - **presence:** absent, empty or set;
  - **results of predicates fixed before the question is asked:** catalog shapes, and rules **as committed on the repository's default branch** (default 2). A rule that exists only in the working tree or on a branch, including one hand-edited into `secrets.toml` through a shell, shows `rules_pending_review` and is not evaluated for MCP or agent-mode callers. This closes H1 on both routes, MCP and the shell; a gate test covers an MCP-declared rule and a hand-edited one (correction 1);
  - **comparisons between stored values that the contract fixes,** such as the same value across tiers, reported **only to a person at a terminal and to CI**, never to an assistant surface (correction 6).

  Nothing the caller supplies at question time ever meets a value. A non-adaptive predicate set bounds what can leak to a few fixed bits per key, and the caller cannot choose which bits.
- **Imports become write-only.** `import <file>` reports per key `imported`, `skipped: already set` or `skipped: empty`. It never reports "differs". Overwriting a set value is the person's `opv import --replace` in their terminal.

What it reduces: H2 (caller-steered equality), and it removes the `.env.example` comparison in #177 (conflict 1 in the review): the check is **dropped**, not moved, because a local commit would put the assistant's guess in the "committed" file (default 3, correction 2). It also gives one invariant to test, in place of a list of special cases.

What it simplifies: for an environment of **tier `local`**, importing a `.env` can run straight from the assistant's request (`opv_import_local`), because it is write-only and reports presence only. This is the one exception to R1 and R8 ("people set up values"), so it is bounded (default 5, correction 7):
- only into an environment whose tier is explicitly `local` (no targets, no `confirm_env`); deployed tiers are person-only;
- it acts through the person's own 1Password session, so 1Password's authorization prompt applies;
- what it writes is tagged `assistant_imported`, and those values are kept out of cross-tier comparisons and out of promotion until a person re-enters or confirms them.

"Import my `.env`" then needs no separate person step for local development, which is the commonest first experience.

**Verdict: keep.** It replaces several point fixes with one rule.

### R4. Tiered sight: deployed tiers are seen through receipts, not reads

- **The problem behind review H3:** an assistant with a shell on the person's laptop can reach whatever the person's sessions can reach: `op read`, `kubectl get secret`, `az keyvault secret show`. No opv design closes that. 1Password's JSON for an item includes concealed values (opv reads items with `op item get --format json`), so there is no read that returns metadata alone.
- **The reframe:** the laptop never *needs* to read a deployed tier.
  - Production and staging are read by **CI identities only**.
  - CI publishes a **value-free state receipt** (opv already has `opv ready --save` and delivery receipts), signed by the run. A receipt carries **its age and the item versions it saw**; `next` shows the age, a receipt older than the newest relevant item version is `stale`, and the promotion gate **recomputes in CI and never trusts a receipt** (correction 9).
  - The assistant and the person see deployed tiers' state through those receipts.
  - The laptop's session needs access to local and dev only. A person enters a production value through a 1Password link, so the CLI never reads it.

What it reduces: the 1Password half of H3. On a laptop whose vault groups follow the tier policy, an assistant with a shell reaches local and dev values through 1Password. It does **not** reduce H3 "to the local tier": production platform logins on the laptop (`kubectl`, `az`, `flyctl`, `gh`), deployed logs and pull requests that change CI workflows still reach production. The tier policy therefore extends to platform credentials, which `opv doctor` reports (R9), and the honest limit (§1) names them. The guard rules (P-4) are defence in depth, not the main control.

What it costs:
- deployed-tier state is as fresh as the last CI run. A `refresh` action can trigger one.
- **Assumption A-1, to check in a spike:** whether 1Password lets a person create and fill fields in a vault without being able to read its items. If it doesn't, the strongest form needs a separate owner account for entering deployed-tier values, and opv can only *detect and warn* when the laptop's session can read a deployed tier (an `access` finding), not prevent it.

**Verdict: keep, as tier policy plus receipts.** The strongest form waits on A-1.

### R5. The contract is observed, then annotated

- **The reframe:** people and assistants don't author key lists. The scanner observes what the code reads. The contract becomes **the observed names plus categorical annotations**: kind, source, scope, presence, shape, and `ignore` with a reason.
- **What the assistant contributes:** annotations, and names in code the scanner cannot read, tagged `assistant_supplied` and shown as such.

What it removes:
- most drift between code and contract: a new name appears as unannotated, never silently missing;
- junk keys from false positives (review M9): `ignore` is an annotation, so a junk name never becomes a required key.

What it simplifies: adding a dependency's key needs no declaration step. The pull request shows "1 new name: annotate it", with the catalog's suggestion pre-filled.

**File ownership (correction 8):**
- A name leaves the contract **only by retire**. A name the scanner no longer sees is `declared_unobserved`, never dropped silently.
- `ignore` records the evidence span it was made against, and is re-checked (shown again as unannotated) when that span changes. An assistant can still annotate a false positive as a real key, so M9 is reduced, not eliminated.
- Annotations live in the repository contract, never inside a generated contract (#178), so regenerating cannot lose them.

**Verdict: keep for the code-facing half.** Keys no code reads, such as CI-only or platform-only keys, are still declared, categorically.

### R6. The contract changes only through review; relaxations are categorical and loud

- **The reframe:**
  - The contract lives in the repository (decision 1).
  - **Bindings** (vault and item ids, targets) live in a separate, opv-written file. It is **committed and union-mergeable**, and it is checked against the record that `opv apply` writes: "opv-written" alone is not a control, so `opv config check` and the CI gate compare the file with the apply record and fail on a difference (correction 8).
  - **Policy relaxations** are categorical attributes that opv marks as relaxations: `except <production-tier env>`, `allow_same_value`, removing a shape, presence narrowing, and `secret` → `config` (correction 10).
  - **One rule for approving them (default 1, correction 11; R8 wins over this section's earlier "person's `opv apply`"):** a relaxation is approved by **pull-request review of the contract**. CI posts it as a **separate required check status** (`opv/relaxations`) that lists each relaxation with its reason and fails until the relaxation is accepted in review. The plan shows relaxations first.

What it reduces: review M4, a pull request or assistant quietly weakening policy (now visible and separately gated, though approved by ordinary review: `fm-consistency-policy-relaxation` stays a medium with a low residual), and it removes review M10, the `all` default pushing junk into production. A new key's plan asks "a value, or `except`?" for each production-tier environment, as a categorical choice.

**Verdict: keep.**

### R7. Value access in code is bound to a purpose

- **The reframe, in the Rust:** `SecretValue::expose()` takes a **purpose token** from a closed set: `DeliverToStore`, `DeliverToPlatform`, `DeliverToChild`, `EvaluateFixedPredicate(PredicateId)` and `CompareFixedPair(KeyRef, KeyRef)`.
  - Each token can only be minted by the module that owns that purpose, the pattern `Observed` already uses.
  - The predicate and comparison tokens can only return the closed `ValueState`.
- This is the code form of R3. It makes "a new feature compares a value with caller input" fail review structurally, because no token for it exists. The canary scan stays as the second layer.

What it removes: the review's M1 (a sealed trait seals nothing inside one crate) by changing the mechanism, not by adding a lint.

**Verdict: keep, deferred (D-G).** R7 is not in 0.12.0. The canary scan stays the layer that catches a value on an output, and H1's fix rests on the default-branch rule source (default 2), not on R7. M1 therefore stays a medium until R7 lands.

### Attempts that did not pan out

| Attempt | Why it was dropped |
|---|---|
| **opv as the assistant's only shell** (a sandbox) | It depends on each harness, breaks the assistant's normal work (editing code, running tests), and is not opv's job. R4 gets most of the benefit by policy. |
| **Store digests so comparisons don't need values** | A digest of a low-entropy value is an oracle in itself, and digests are already kept out of outputs for that reason. |
| **Redact in the assistant, not in opv** | It moves trust to the component we trust least. |
| **A per-session copy of the vault with dummy values for the assistant** | It duplicates the store, invites drift, and the assistant still can't see real values, so there's no gain. |
| **Remove the assistant from setup entirely** (a wizard instead) | It loses the generative parts that matter: reading arbitrary code, writing guidance, conversation. R2 keeps those and removes the rest. |

## 22. The synthesis: planner, compiler, actuators, diode

```
 Assistant (planner) ──categorical intent, names, references──▶ opv (compiler / reconciler)
       ▲                                                            │ plan
       │ value-free state: inventory, needs, next, receipts         ▼
       │                                                  Actuators: the person's terminal (opv apply)
       │                                                             CI (scheduled, approved syncs)
       │                                                            │
       └────────────── presence + fixed predicates only ◀── Store ──▶ Platforms ──▶ Application
                          (the diode)                     (values flow this way only)
```

**The assistant's whole surface:**
- `opv_state`: the inventory matrix, needs, value states and receipts for deployed tiers;
- `opv_next`: one action and the queue;
- `opv_propose`: an intent document in, a contract diff and plan out;
- `opv_import_local`: a file reference in; write-only, local tier only;
- `opv_explain`: why a key or plan is the way it is.

That is 5 tools, down from the **13** registered today (`src/mcp.rs`; correction 3). None of them writes anything except `opv_import_local`, and that only into an environment of tier `local`. The old tools become aliases for one minor release, each returning a typed `next` that names its replacement, and are then removed.

**The person's whole surface:** `opv apply`, `opv set` (masked entry), `opv import`, the 1Password app and the links opv gives, and reading the plan.

**CI's surface:** `opv changed`, `opv sync`, `opv ready --gate`, `opv needs --gate`, the relaxations check, receipts. CI's only 1Password write is value-free delivery evidence (D-C).

### 22.1 What the reframe does to the risks

| Risk | Parts I–IV answer | After the reframe |
|---|---|---|
| H1: rule-predicate oracle | approve rules before they count | **reduced** (R2, R3, R7): no client-supplied predicate is evaluated for an assistant; rules count only as committed on the default branch, otherwise `rules_pending_review` (default 2), which also covers a rule hand-edited through a shell |
| H2: equality the caller steers | drop the `.env.example` check; make imports person-only | **reduced** (R3): write-only imports; the `.env.example` check is dropped; cross-tier comparisons reach only a person and CI |
| H3: an assistant shell reaches values | guard rules; an honest limit | **reduced** for 1Password by vault permissions where groups are tight (R4, R9); platform logins, deployed logs and CI-workflow PRs remain, reported by `doctor`; the DevOps machine is an accepted residual (D-A); the strongest form waits on A-1 |
| H4: `opv run` output | redaction tied to agent mode | **reduced:** under R4 the local tier holds only local values. Redaction is always on, for secret-kind values of 8 bytes or more, in local delivery; `op run` already masks exact values, so the added work is encodings |
| M1: a trait seals nothing | a sealed trait | **reduced** by a different mechanism (R7): purpose tokens hold only with module-private constructors and no `unsafe` |
| M2: agent mode can be spoofed | detection | **no longer a security control** (R1) |
| M3: approve/apply race, window expiry | keep approve approve-only | **eliminated** (R1: one process) |
| M4: a PR weakens policy | split bindings | **reduced** (R6, R8): relaxations are a separate required check, approved in PR review; bindings are checked against the apply record |
| M9: scanner junk keys | an ignore list | **reduced** (R5: `ignore` is an annotation, re-checked when its evidence changes; an assistant can still mis-annotate a false positive) |
| M10: the `all` default and production | ask per production environment | **eliminated** (R6: a categorical question in the plan) |
| M13: free-text screening, rule parameters | screening | **reduced to guidance only** (R2) |
| M14: a parallel command surface | a migration plan | **reduced:** 5 assistant tools replace 13; the old ones are aliases with a typed `next` for one minor release |
| P-20: assistant hangs on a prompt | agent mode | **eliminated** (R1: the assistant runs nothing that prompts) |

### 22.2 What it does to the experience

| Journey | Parts I–IV | After the reframe |
|---|---|---|
| First local setup from a `.env` | plan, then the person approves, then the assistant applies, then the person imports | the assistant imports the local `.env` (write-only), proposes the contract, and the person runs **one** `opv apply` |
| Adding a dependency's key | declare, plan, approve, apply | the PR shows "1 new name" with the catalog's suggestion; the assistant annotates it; the merge plus one `opv apply` creates the fields everywhere |
| Seeing production's state | a laptop read of the production vault | the latest CI receipt; no production access on the laptop |
| Person actions for a typical change | 2 to 3 commands, plus a time window | 1 command, no window |

## 23. Open questions the reframe raised, and their answers

- **A-1 (spike, still open; correction 18):** can a 1Password person write into a vault without reading it? It decides only between R4's strong and weak forms. Until it is answered, R9(a)'s separate admin account is the stronger form, and the DevOps-machine residual is accepted by the owner (D-A).
- **Receipt freshness (answered, correction 9):** a receipt carries its age and the item versions it saw. One older than the newest relevant item version is `stale` (opv already compares item versions in `opv changed`), `next` shows the age, and the promotion gate recomputes in CI and never trusts a receipt.
- **Merge-time application (declined, correction 12):** R8 answers it. CI does not write to 1Password beyond value-free delivery evidence (D-C), so merging a contract change does not make CI create deployed-tier structure or values. People with write access to each vault do that, in the 1Password app or with `opv apply`.

---

## 24. Second reframe: capability from 1Password, CI only delivers, and know what the code reads (R8–R11)

The before/after comparison (`assistant-guided-setup-comparison.md`) showed the first reframe removed the oracles but left the same seven medium residuals. Those residuals have two roots:
- capability over deployed tiers on a developer's machine;
- opv **inferring** what the application consumes instead of knowing it.

The owner's direction (2026-10-18): access control is **1Password's job and already built**, and opv should lean into it, not rebuild it. Only DevOps can read staging and production vaults. Developers have the local and dev vaults. CI uses service accounts scoped per vault. opv's model of one vault per boundary per environment exists so that 1Password's vault permissions **are** the tier boundary.

**Definition.** "The assistant" in this document is always an external generative model (Claude Code, Cursor, Codex, any MCP client) using opv's MCP tools or CLI through its harness. opv has no built-in model and calls none. opv is the deterministic bridge between 1Password, the repository, CI and the platforms.

### R8. Capability comes from 1Password; opv helps whoever has it; CI only delivers

**Owner direction (2026-10-18):**
- CI does not write to 1Password. CI takes the values in 1Password and applies them to the environments they go to.
- People set up values at every tier. Who may set up which environment is decided by **access to the vaults that hold its values**, which 1Password manages.
- opv defines no roles and requires no particular path. It helps the people who have the capability to do what they need to do.
- A team may set up a developer's environment entirely for them: grant the developer the vault, and everything works.

**Capability is discovered, not configured:**
- opv reads what the current 1Password session can do with each vault the contract names: `write`, `read`, `none`, or **`unknown`** with its source when 1Password does not expose effective permissions to this session. A 1Password refusal is a typed finding. opv never guesses a capability, so `next` never names the wrong actor (correction 14). This uses 1Password's own vault permissions.
- **Write access to a vault** means this person can set up that environment's structure and values. They can do it in the 1Password app directly, or with opv's help, using the links, empty fields, generation and masked entry opv offers. 1Password authorizes every write. opv reads the result the same way whichever route was used.
- **Read access only** means this person can run with those values (`opv run`) and see their states, but not change them.
- **No access** means opv shows the environment's structure from the contract and the latest value-free CI receipt, and names the vault. "Someone with write access to vault X can fill this", with the people and groups `opv access` reports for that vault when 1Password lets the session see them.

**What each person sees:** `opv next` and the inventory list, first, the actions **this session can take**, then what is waiting on others, by vault. Nobody is told to run a command they lack the access for.

**CI runs opv; opv carries values; nobody in CI sees them.**
- A CI job runs `opv sync` (or `opv changed`, then `opv sync`) for the configured destinations.
- Inside that run, opv itself is the courier (D-C). Using a service account that can only read the values vault, it reads each value from 1Password into its own process memory and writes it straight to the platform's channel: Fly secrets on stdin, Kubernetes Secrets and ConfigMaps by `kubectl apply` on stdin, Key Vault through the named pipe or stdin, GitHub secrets by `gh secret set` on stdin.
- **A value never appears in the CI job's logs, files, environment variables or command arguments**, so no person or tool reading CI sees it. The scrubber (NR-31) masks any value a platform tool echoes.
- **The courier invariant (correction 16), testable:** every transport hands a value to a platform tool over **stdin or a private pipe only**. A transport test runs each transport with an `S7MARKER` value and fails if the marker appears in any recorded argv, child environment, file opv wrote, or output. The Key Vault path already meets it: `az keyvault secret set --file /dev/stdin` reads the bytes from stdin on Linux, WSL and macOS, and from a user-only named pipe on Windows (`src/adapters/azure/keyvault.rs:269-297`, `src/adapters/azure/handoff.rs:103`); the argument is a path to the stream, never the value. The transport test pins this.
- Something has to carry the bytes from 1Password to the platform. The only alternative is the platform reading 1Password itself at runtime, which the owner ruled out: production never needs 1Password. So the value's only stop on the CI runner is opv's memory, for the length of the run.
- **Scope boundary (owner, 2026-10-18).**
  - **opv is responsible** for running every step that touches a value: getting it from 1Password, then executing the platform tool (`flyctl`, `kubectl`, `az`, `gh`) in a way that exposes nothing. That means stdin or a private pipe, never arguments or inherited environment, never files, and output scrubbed before it is shown.
  - **opv is not responsible** for what another tool does with a value once it has it. A defect in `az` or `flyctl` that logs or leaks a value is outside opv's purview. opv's scrubber still masks a value such a tool echoes back to opv, as best-effort defence, not as a guarantee.
  - **FMECA treatment:** failure modes inside third-party tools are recorded as out of scope, not as opv risks.
- CI also posts the value-free plan and key × environment matrix as a check on pull requests that change the contract.
- Its only 1Password write is delivery evidence, holding no values, in the target's state vault, as since 0.7.0.

**The contract** changes through pull requests. Reviewers approve the change to *what is needed*; filling values is done by whoever has write access to each vault.

**A new key, end to end:**
1. A PR adds the key.
2. The check shows its row: dev, staging and prod are each `absent`, with the vault each one lives in.
3. After merge, each person with write access to one of those vaults sees it in their `opv next` and fills it, in the 1Password app or through opv.
4. CI delivers on change.
5. The promotion gate holds a tier until its value is `set` **and** delivery evidence records the current item version on every target of that tier (correction 13). A value filled in the 1Password app is delivered by CI's scheduled `opv changed` then `opv sync`, so `set` alone never passes the gate.

**Team-managed developer environments:**
1. Someone with write access to the dev vault sets the environment up once.
2. 1Password access to that vault is granted to the developer or their group, in 1Password. opv can print the link or the `op` command, but never grants access itself.
3. The developer runs `opv run -- <app>`. If something is missing, `opv doctor` names the vault and who can fill it, instead of asking the developer to set anything up.

Personal keys exist only where the team gives developers their own items.

**Emergencies** need no special path: anyone with write access to the vault fixes the value, and CI delivers. What makes that hold (correction 17):
- every deployed-tier vault has **a second writer**, which `opv access` reports, and `next` raises a finding when a deployed-tier vault has only one;
- losing the only writer's access is 1Password's **account recovery**, which the docs name as the break-glass path; opv adds no account of its own.

**What it answers:**
- who writes each tier: whoever 1Password lets write its vault;
- loosened policy: relaxations show in the PR diff and fail the separate `opv/relaxations` check until accepted in review (default 1);
- visibility of tiers a person can't read: the contract plus CI's value-free receipts.

### R9. Tier separation is 1Password's vault permissions; opv verifies it and never re-implements it

- **The boundary:** 1Password grants per vault, and opv puts each environment's values in its own vault(s). So "developers can't read production" is a vault permission the owner sets, through 1Password groups.
- **opv adds no access layer.** It **checks and reports**:
  - `opv access` already reports per-vault readers for CI identities. It extends to tier membership: "this environment is production-tier, and these people and groups can read it".
  - `opv doctor` on a developer machine reports when the current 1Password session can read a deployed-tier vault, or when the shell holds a production platform login (kubeconfig context, `fly`/`az`/`gh` auth). Each is reported as a finding with a fix, never blocked.
- **Local tier policy:** local and dev should hold sandbox-grade values (test-mode keys, local databases). Catalog shapes flag a live key in a local tier.

**What 1Password does not cover**, so it stays in scope:
- **(a) A DevOps person's own machine.** Their account can read production by design, so an assistant running in their shell can too. 1Password's desktop authorization prompt is the control there. The documentation states it honestly, and recommends a separate admin account for production work where the team wants the stronger form (A-1 asks whether write-without-read exists).
- **(b) Platform credentials outside 1Password.** opv detects them, as above.
- **(c) Everything that is not access:** rotation, retirement, scanner coverage and runtime misconfiguration (R10, R11).

### R10. The contract as data (simplified by the owner, D-G)

The first form of R10 generated a typed configuration module per language. The owner replaced it with **the contract as data**: no generated code.

- **What opv emits:** `opv contract [--env <env>] [--component <c>] [--json | --schema]` prints the machine-readable contract per component and environment: each key's name, kind, shape name and whether it is required there (contract × presence), plus a **JSON Schema** of the same. It holds names and categories only, never a value, an id or a rule parameter. The same document is the `contract` section of `opv_state`.
- **How an application uses it:** the docs show startup validation with each ecosystem's own library: zod (TypeScript), pydantic (Python), serde (Rust) and Go's standard library. A missing or ill-shaped required key fails at boot, so a broken deploy fails its health check and rolls back.
- **Module rules (correction 15), restated for data:**
  - the required set is **per environment** (contract × presence), so a key `except`ed in an environment is never demanded at boot there;
  - the docs' validation examples report only the key and the shape name, never the value;
  - the emitted document carries the contract digest, and `opv contract --check <file>` fails in CI when a committed copy is stale;
  - each component may say whether it validates at startup, and the inventory shows it.
- **Retirement** checks `needs` at the deployed revision before anything is pruned.
- **What it isn't:** a runtime dependency on opv or 1Password. The application reads only the platform's own channels (env, files).

What this gives up against generated code: "unknown names don't compile". Undeclared reads are caught by the scanner and the `needs` gate, so `fm-consistency-scanner-missed-names` keeps its medium residual for dynamic names, and `fm-consistency-generated-module-stale` and `fm-adoption-codegen-language-gap` no longer apply.

### R11. Rotation: a documented safe procedure (simplified by the owner, D-G)

There is no rotation planner. The docs give one safe procedure built on what exists:
1. add the new credential alongside the old at the provider, and put it in 1Password (the app or `opv set`);
2. deliver it with `opv sync <env> --rotate <product/KEY>`, environment by environment;
3. confirm with `opv delivery verify` and the platform's rollout status that every running revision holds it;
4. only then revoke the old one at the provider, which is the person's step.

Consumers outside opv's view (another host, a partner's webhook) are listed in the key's guidance, and the procedure says to check them before step 4. `fm-runtime-rotation-revokes-in-use` stays a medium residual.

**Expiry:** a key may carry an optional `expires` date. `opv ready` reports an advisory finding ahead of it, pointing at the procedure above.

### What R8–R11 claim, to be tested by FMECA

| Residual after the first reframe | Claim under R8–R11 |
|---|---|
| An assistant shell reaches values (H3) | A developer machine reaches only local/dev vaults by 1Password permission **where vault groups are tight**; opv reports loose groups (correction 5). A DevOps machine stays residual, accepted by the owner (D-A), with the authorization prompt and a separate admin account as the hardened option |
| Platform tools reach production | No production platform logins on developer machines; `doctor` detects them |
| `opv run` encoding leak | Local values are sandbox-grade: recoverable, not a breach |
| Secret downgraded to config | A relaxation: the separate `opv/relaxations` check fails until it is accepted in PR review (default 1) |
| Rotation revokes while in use | A documented overlap procedure on `sync --rotate` plus `delivery verify`; outside consumers named in guidance (D-G) |
| Retire while still read | `needs` at the deployed revision before pruning (D-G: no generated code) |
| Scanner misses a name | The scanner's stated coverage and the `needs` gate; startup validation against the contract as data catches a missing value, not an undeclared read |
| Nobody writes deployed tiers | Whoever 1Password lets write that tier's vault, in the 1Password app or with opv's help; CI only runs opv, which carries values from 1Password to the platforms without exposing them (R8). A deployed-tier vault with a single writer is a finding (correction 17) |
| Set but not delivered | The gate requires delivery evidence at the current item version (correction 13) |

## 25. The one interface (0.12.0)

**Owner (D-G): one way only.** 0.12.0 is a breaking release. The simplified interactions below are the **only** interface, for both the CLI and MCP. The 0.11.0 MCP tools are removed and replaced; CLI commands and flags that duplicate the new flows are removed or folded in. There are no aliases and no deprecation period. Every removal below was checked against `src/main.rs` (`Cmd` `:578`, sub-commands `:1324-1670`), `src/mcp.rs` (the router `:367-581`) and `docs/usage.md` (`:7-59`). No capability is dropped without a replacement, except the narrowings listed in §25.4, which are the reframe's intent.

### 25.1 The CLI after 0.12.0

Every command that prints takes `--json` and returns the envelope of §4.2, with a typed `next`.

| Group | Command | Who | What it does |
|---|---|---|---|
| inspect | `opv inventory [--env <e>] [--product <p>]` | anyone | the matrix: keys × environments, each cell a value state (§3.3) and the session's capability on its vault (`write`/`read`/`none`/`unknown`), with ids, source, presence, tier and delivery state per target; deployed tiers the session can't read come from CI receipts with their age |
| inspect | `opv needs [--gate]` | anyone, CI | code ↔ contract: `undeclared`, `declared_unobserved`, `ambiguous`, `declared`, with the scanner's coverage; `--gate` fails on new undeclared names |
| inspect | `opv contract [--env <e>] [--component <c>] [--schema] [--check <file>] [--relaxations [--base <ref>]]` | anyone, CI | the contract as data and its JSON Schema (R10); `--check` fails on a stale committed copy; `--relaxations` lists the relaxations against the default branch (the `opv/relaxations` check, default 1) |
| inspect | `opv ready [<env>] [--gate] [--save <file>]` | anyone, CI | findings, receipts and gates; `--gate` fails unless every present key is `set` with delivery evidence at its item version, and no relaxation is unaccepted |
| inspect | `opv next` | anyone | one action this session can take, then the queue, then what waits on others, by vault |
| inspect | `opv explain <[product/]KEY \| plan_id> [--env <e>]` | anyone | why a key or plan is as it is; for a key, every environment, target and delivery holding it (leak response) |
| inspect | `opv status [<env>] [--product] [--all] [--target <t>] [--fail-on-drift]` | anyone, CI | 1Password and each target side by side, names only, drift |
| inspect | `opv plan <env> [--product] [--target] [--rotate <p/KEY>]` | anyone | what a sync would do, and its plan id |
| inspect | `opv history <env> [--target <t>]` | anyone | what opv last wrote to the target |
| inspect | `opv access [<env>] [--target <t>] [--project <p>]` | anyone | who can read and write each vault (capability, second writers, tier membership) and the owner's command to create a reader |
| inspect | `opv doctor [--env <e> [--product] [--target]] [--settings]` | anyone | setup problems; R9's findings: this session reads a production-tier vault, a production platform login is present |
| propose | `opv propose key <[p/]KEY> --kind … [--env …] [--except <env>=<reason>] [--source …] [--shape <name>] [--rule <NAME[=VALUE]>] [--personal] [--from <p/KEY>] [--guidance …] [--allow-same-value] [--immutable] [--expires <date>]` | anyone | a new or changed key: the contract diff and plan. A `--rule` counts only once committed on the default branch (default 2) |
| propose | `opv propose env <env> [--tier local\|shared\|production]` | anyone | a new environment, inheriting every `all` key |
| propose | `opv propose target <env> <name> --<provider options> [--products …] [--role …] [--deploy-credentials <op://…>]` | anyone | a new target |
| propose | `opv propose retire <[p/]KEY>` | anyone | retirement in order: `needs` at the deployed revision, prune from targets, archive the fields |
| propose | `opv propose setup [--from-item <env> [--vault <t>] [--item <t>]] [--names-from <.env> [--config-key K]… [--secret-key K]…] [--file \| --project <p>] [--account <a>]` | anyone | first setup: the contract from an existing item or from a `.env`'s names, and every boundary, item, state vault and field |
| propose | `opv propose structure [--rebind <env>]…` | anyone | the structure the contract declares (missing vaults, items, state vaults, empty fields), or new ids for an environment |
| propose | `opv propose generate <env> <p/KEY>…` | anyone | generated values for rule-backed keys |
| propose | `opv propose tidy <env>` | anyone | put an item in opv's layout |
| propose | `opv propose --intent <file.json>` | anyone | the categorical intent document of R2 (the same as `opv_propose`) |
| propose | any `opv propose …` with `--write` | anyone (CLI only) | also writes the contract diff into the repository's contract file, which is reviewed in the pull request. Without `--write`, and always over MCP, a proposal writes nothing |
| apply | `opv apply [<plan_id>]` | **person, in a terminal** | recomputes the plan from the contract on disk and the actual state, refuses if it differs from `<plan_id>` (stale), shows it, confirms, and runs it in one process: bindings and the apply record, structure, generation, retirement steps, masked entry for values typed now; refuses non-TTY and agent mode with a typed `next` |
| person | `opv set <[p/]KEY> --env <e>` | **person, in a terminal** | masked entry of one value |
| person | `opv import <env> --from <file.env \| target:NAME> [--replace <p/KEY>]… [--rotate <p/KEY>]… [--skip <p/KEY>]… [--dry-run]` | **person** | write-only import: per key `imported`, `skipped: already set`, `skipped: empty`; never "differs"; `--replace` overwrites a set value |
| person | `opv open <[p/]KEY> [--env] [--print]` | person | the key's item in 1Password, where a value is typed |
| person | `opv run <env> [--product] [--role] [--preview] [--remote <profile>] [--confirm <env>] -- <cmd>` | person | run with the keys injected; `op run` masks exact values |
| person | `opv setup`, `opv login`, `opv account list\|use`, `opv ui`, `opv config edit` | person | unchanged; `opv ui` actions run the commands above |
| deliver | `opv changed <env> [--product] [--target]` | CI, person | did a source item change since the last sync (exit 10) |
| deliver | `opv sync <env> [--deploy] [--prune] [--rotate …] [--prune-immutable …] [--expect-plan <id>] [--confirm <env>] [--product] [--target] [--receipt <file>]` | CI, person | delivery, opv as the courier (R8) |
| deliver | `opv delivery verify <env> [--product] [--target] [--receipt <file>]` | CI, person | does every placement still hold what opv delivered |
| deliver | `opv ci workflow <env> --target <t> [--github-env] [--deploy]`, `… --on-change [--every <m>]`, `… --drift` | person | ready-to-commit workflows, now including the `needs`, `contract --check`, `ready --gate` and `opv/relaxations` checks |
| admin | `opv access <env> --create --github <owner/repo> [--github-env] [--secret-name]`, `opv target credentials <env> --target <t> [--create]` | person | CI and deploy identities, unchanged |
| admin | `opv config import\|export\|check`, `opv projects`, `opv vault locate` | person | the 1Password manifest mirror and account tools, unchanged |
| tooling | `opv mcp serve\|install`, `opv skill install\|status`, `opv guide agent`, `opv schema`, `opv version`, `opv completions`, `opv help` | anyone | unchanged |

Hidden internal commands (`remote-send`, `remote-receive`, `local-delivery`) are unchanged.

### 25.2 The MCP tools after 0.12.0

| Tool | Writes | Input | Returns |
|---|---|---|---|
| `opv_state` | nothing | `section`: `inventory`, `needs`, `contract`, `ready`, `plan`, `changed`, `access`, `delivery_preview`, `history`, `status`; optional `env`, `product`, `target` | the same document as the CLI command of that name |
| `opv_next` | nothing | optional `env` | one action this session can take, the queue, and what waits on others |
| `opv_propose` | nothing (pure) | the intent document: `kind` (`key`, `env`, `target`, `retire`, `setup`, `structure`, `generate`, `tidy`), names (grammar-checked), enumerated attributes, **catalog shape names only (no rule parameters)**, references, optional guidance (screened, stored `assistant_written`) | the contract diff and the plan with its `plan_id`, which only a person's `opv apply` runs |
| `opv_import_local` | the local vault only | `env` (must be tier `local`), a file path | per key `imported` / `skipped: already set` / `skipped: empty`; values tagged `assistant_imported` |
| `opv_explain` | nothing | a key or a `plan_id` | the explanation, including every place the key is delivered |

`tests/mcp_protocol.py` asserts exactly these five names; only `opv_import_local` is a writer and none is destructive.

### 25.3 Every 0.11.0 command, flag and tool, mapped

**CLI**

| 0.11.0 | 0.12.0 |
|---|---|
| `opv approve <plan_id>` (structure) | `opv apply <plan_id>` |
| `opv approve <plan_id> --sync <env> [--target] [--product] [--deploy] [--prune] [--rotate]` | removed: the assistant no longer prepares syncs; a person runs `opv sync <env> --expect-plan <id>` with the same flags, or CI syncs |
| `opv sync --approved <plan_id>` (hidden) | removed, with the approval file and its 15-minute window (`src/approval.rs`) |
| `opv structure plan` | `opv propose structure` |
| `opv structure apply <plan_id>` | `opv apply <plan_id>` |
| `opv bootstrap [--file] [--project]` | `opv propose structure` (or `propose setup`), then `opv apply` |
| `opv bootstrap --dry-run` | `opv propose structure` (a proposal never writes) |
| `opv bootstrap --rebind <env>` | `opv propose structure --rebind <env>` |
| `opv bootstrap --ci-reader <env>` | `opv access <env>` (prints the owner's reader command) |
| `opv init <env> [--vault] [--item] [--product] [--file\|--project] [--account]` | `opv propose setup --from-item <env> [--vault] [--item] …`, then `opv apply` |
| `opv init <env> --add-env` | `opv propose env <env>` |
| `opv init <env> --from <.env> [--config-key] [--secret-key]` | `opv propose setup --names-from <.env> [--config-key] [--secret-key]` (names only) |
| `opv init … --from … --apply` | `opv apply <plan_id>`, then `opv import <env> --from <.env>` |
| `opv init --force` (hidden) | removed: a proposal shows the contract diff, and `opv apply` overwrites only what it shows |
| `opv add <KEY> [--kind] [--env] [--rule] [--guidance] [--immutable] [--from] [--personal] [--allow-same-value]` | `opv propose key <KEY>` with the same flags, plus `--except`, `--source`, `--shape`, `--expires` |
| `opv env add <env>` | `opv propose env <env>` |
| `opv target add <env> <name> … [--dry-run]` | `opv propose target <env> <name> …` (always a dry run until `opv apply`) |
| `opv item skeleton <env>` | `opv propose structure` (empty fields are part of it), then `opv apply` |
| `opv generate <env> <p/KEY>…` | `opv propose generate <env> <p/KEY>…`, then `opv apply` |
| `opv tidy <env>` | `opv propose tidy <env>`, then `opv apply` |
| `opv adopt <env> --from <file\|target:NAME> [--replace] [--rotate] [--skip] [--apply]` | `opv import <env> --from <file\|target:NAME> [--replace] [--rotate] [--skip]`; without `--apply` → `--dry-run`. Write-only: `match`/`differs` reporting is removed (R3) |
| `opv check <env> [--product]` | `opv inventory --env <env> [--product]` |
| `opv config describe` | `opv inventory` (structure) and `opv contract` (the contract as data) |
| `opv ready [<env>] [--save]` | unchanged, plus `--gate` |
| everything else in `docs/usage.md:7-59` (`setup`, `login`, `account`, `doctor`, `status`, `plan`, `sync`, `run`, `explain`, `open`, `history`, `access`, `delivery verify`, `changed`, `ci workflow`, `target list`, `target credentials`, `vault locate`, `projects`, `config export\|import\|edit\|check`, `mcp`, `skill`, `guide`, `schema`, `version`, `completions`, `help`, `ui`) | unchanged, with `explain` extended (leak response) and `doctor` and `access` extended (R8, R9) |
| (new) | `opv inventory`, `opv needs`, `opv contract`, `opv next`, `opv propose`, `opv apply`, `opv set`, `opv import` |

**MCP**

| 0.11.0 tool (`src/mcp.rs`) | 0.12.0 |
|---|---|
| `opv_ready` `:369` | `opv_state` `section: ready` |
| `opv_configuration` `:379` | `opv_state` `section: inventory` (and `contract`) |
| `opv_deployment_plan` `:389` | `opv_state` `section: plan` |
| `opv_changed` `:402` | `opv_state` `section: changed` |
| `opv_access` `:415` | `opv_state` `section: access` |
| `opv_delivery_preview` `:433` | `opv_state` `section: delivery_preview` |
| `opv_structure_plan` `:453` | `opv_propose` `kind: structure` |
| `opv_declare_key` `:483` | `opv_propose` `kind: key`; catalog shape names only, no rule text |
| `opv_declare_environment` `:500` | `opv_propose` `kind: env` |
| `opv_declare_target` `:520` | `opv_propose` `kind: target` |
| `opv_structure_apply` `:466` | removed: a person's `opv apply` (R1) |
| `opv_generate` `:537` | removed: `opv_propose` `kind: generate`, then a person's `opv apply` (R1) |
| `opv_sync` `:572` | removed: CI or a person's `opv sync` (R1, R8) |
| (new) | `opv_next`, `opv_import_local`, `opv_explain` |

### 25.4 Narrowings that are the reframe's intent (flagged)

These remove something an assistant or a person could do in 0.11.0. Each one is deliberate, and each has a person-side or CI-side route:
- **The assistant can no longer apply structure, generate or sync** over MCP (R1). A person's `opv apply` and `opv sync`, or CI, do it.
- **The assistant can no longer declare rule parameters** (`regex`, `prefix`, `enum`, …) over MCP (R2, H1). It names catalog shapes; rules are written in the contract and reviewed in the pull request.
- **Import no longer reports which values differ** (R3, H2). A person who wants to overwrite uses `--replace`, after checking in the 1Password app.

### 25.5 CHANGELOG migration notes

```markdown
### Breaking: one interface

opv 0.12.0 replaces the plan/approve/apply commands and the MCP tool set with one
interface. There are no aliases: update scripts and assistant settings when you upgrade.

- Changes to the configuration are proposed, then applied by a person:
  `opv propose key|env|target|retire|setup|structure|generate|tidy …`, then `opv apply <plan_id>`.
  This replaces `opv add`, `opv env add`, `opv target add`, `opv init`, `opv bootstrap`,
  `opv structure plan|apply`, `opv item skeleton`, `opv generate`, `opv tidy` and `opv approve`.
- `opv adopt` is now `opv import <env> --from <file|target:NAME>`. It is write-only and
  reports imported / skipped per key; it no longer says whether a value differs.
- `opv check` is `opv inventory --env <env>`; `opv config describe` is `opv inventory`
  and `opv contract`.
- Assistant-approved syncs are gone (`opv approve --sync`, `opv sync --approved`). Run
  `opv sync` yourself, or let CI run it.
- MCP: 13 tools become 5 (`opv_state`, `opv_next`, `opv_propose`, `opv_import_local`,
  `opv_explain`). `opv_structure_apply`, `opv_generate` and `opv_sync` are removed;
  `opv_declare_*` accept catalog shape names, not rule text. Re-run `opv mcp install`
  and `opv skill install` after upgrading.
- Validation rules count for assistants only once committed on the default branch;
  until then they show `rules_pending_review`.
- `opv ready --gate` fails on a value that is set but not yet delivered.
```

---

# Part VII: decisions

## Owner decisions (2026-10-18)

The owner locked the direction: R1–R11 (Part VI, including §24), with the corrections of the FMECA comparison §8 applied in this document.

- **D-A. The DevOps machine is an accepted residual.** A machine whose 1Password account can read production lets an assistant in its shell read production too. The documentation describes a separate 1Password admin account, used only for production work, as the **hardened option**. opv reports when the current session can read a production-tier vault or holds a production platform login (`opv doctor`, `opv access`). Recorded in the FMECA as an accepted risk on `fm-asg-honest-limit-understated`.
- **D-B. Access control is 1Password vault permissions only.** opv defines no roles. It discovers what the current session can do (`write`, `read`, `none`, `unknown`) and helps whoever has access. People fill values at every tier, in the 1Password app or with opv's help.
- **D-C. CI runs opv, and opv is the courier.** Values go from 1Password into opv's memory, then to the platform tool over stdin or a pipe, never through argv, the environment, files or logs. CI's only 1Password write is value-free delivery evidence.
- **D-D. Defects inside third-party tools are out of scope.** What `az`, `flyctl`, `kubectl` or `gh` do with a value after opv hands it over correctly is not opv's responsibility. opv's scrubber still masks a value such a tool echoes back to opv, as best-effort defence. The FMECA records such failure modes as out of scope.
- **D-E. H1, the rule-predicate oracle, is fixed in 0.12.0,** with no 0.11.x patch. The window until 0.12.0 ships is accepted.
- **D-F. "The assistant" is always an external model** using MCP or the CLI through its harness. opv has no built-in model and calls none.
- **D-G. The 0.12.0 scope, and one interface only.** 0.12.0 is a breaking release with the one interface of §25: no aliases, no deprecation period. One release milestone, `release-0120`.
  - **Keep (the core):** the value boundary and value states; H1's fix (only rules committed on the default branch count); the categorical intent form (names, references, choices); write-only local import, tier `local` only; capability discovered from 1Password (`next` shows what this session can do); CI as the courier; value-free CI receipts for tiers a session can't read; the contract as data; the scanner and the `needs` CI gate; the inventory matrix (with ids); presence `all` plus explicit exceptions; retirement; the promotion gate (set and delivered); `opv set`; agent mode as presentation only; the A-1 spike (owner) and the admin-account documentation.
  - **Simplify:**
    - R10 → **the contract as data**: a machine-readable contract plus a JSON Schema, with startup validation shown in the docs for zod, pydantic, serde and Go. No generated code. Retirement checks `needs` at the deployed revision.
    - R11 → **a documented safe procedure** on `sync --rotate` plus delivery verification. No planner.
    - **Expiry:** an optional `expires` date on a key, and an advisory finding in `ready`.
    - **Leak response:** `opv explain KEY` lists every place the key is delivered. No new command.
    - **Value states:** `absent`, `empty`, `placeholder`, `malformed`, `set`, `unreadable`, `not_wanted`. `suspect` folds into the advisory health warnings.
    - **Tiers:** one attribute per environment, `local`, `shared` or `production`. No lane-ordering engine.
  - **Deferred, not cut:** R7 purpose tokens. The canary scan stays; H1's fix does not depend on R7.
  - **Cut, with the reason:**
    - R10 per-language code generation: replaced by the contract as data;
    - provisioners: a person or `opv access --create` provides credentials; minting through provider APIs did not earn its cost;
    - ephemeral environments: personal keys and ordinary environments cover the need (the design's own "low priority");
    - the offboarding report: 1Password administration does it;
    - harness guard rules: a docs section only; they were never the control (R9);
    - `opv run` encoding redaction: `op run` masks exact values, and developer machines hold sandbox-grade values;
    - `opv detect`: the scanner and the person's proposal cover setup without repository heuristics.
  - **Deferred to a later release (out of plan `v0120`):** Docker Swarm (S1–S6, X2), GCP Secret Manager and the VM startup step. Their designs stay in `delivery-transports.md` §8–§9 and §11.2.

## Decided by default (the owner may override)

Each default follows D-B and D-C.

1. **Relaxations are approved by PR review of the contract.** A relaxation (`except <production-tier env>`, `allow_same_value`, removing a shape, narrowing presence, `secret` → `config`) is posted by CI as a separate required check status, `opv/relaxations`, which fails until the relaxation is accepted in review. R8 wins over R6's person `opv apply` (correction 11).
2. **Which rules count.** Rules evaluated on values over MCP, or for an assistant, come only from the contract as committed on the repository's default branch. A rule that is uncommitted or exists only on a branch, including one hand-edited into `secrets.toml`, shows `rules_pending_review` and is not evaluated for those callers. This closes H1 on both routes (correction 1).
3. **The `.env.example` equality check is dropped** (correction 2).
4. **Redaction is always on in local delivery,** and does not depend on agent mode (correction 4). It is `op run`'s masking of exact values; D-G cut the encoding extension. This replaces the earlier recommendation "redact in agent mode".
5. **R3's assistant-triggered import** is allowed only into an environment of tier `local`. It is write-only and reports presence only. What it writes is tagged `assistant_imported` and kept out of comparisons and promotion. It acts through the person's own 1Password session. Deployed tiers are person-only (correction 7).

## Earlier recommendations

1. **Where the contract lives (C9, G3).**
   - **The question:** today a project's configuration can be a `secrets.toml` in the repository or a manifest in 1Password. The ideal wants the key contract reviewed in the same pull request as the code that needs it, which argues for the repository file as the single writable source, with the 1Password manifest as a read-only mirror.
   - **What changes:** projects that keep their configuration only in 1Password would move it into the repository.
   - **Recommendation:** make the repository file the source for applications, with the bindings in a separate committed, opv-written file (R6). Keep the manifest as a mirror for portfolio views. Default 2 relies on this: a project whose contract is only in 1Password has no default branch, so MCP declarations there accept catalog shape names only, never rule parameters (R2).
2. **Presence default (C5, G8).** Covered in #179.
   - **Recommendation:** the new `all` form becomes the default for new keys, and existing explicit lists keep their meaning. Nothing breaks.
3. **Naming: "product" or "component".**
   - **The question:** "product" in opv means a part of the application (web, api). The ideal calls it a component and calls the whole an application.
   - **Recommendation:** keep `products` in the file format, because renaming breaks every configuration. Use "application" and "component" in documentation and in new commands' text.
4. **How far agent mode goes (C4, C10).** Superseded by default 4: agent mode is presentation only, and redaction is always on.
5. **Release split.** Decided by D-G: one release, 0.12.0.
6. **TRIZ analysis.** Done: `triz analyze` cross-checked C1–C10 with the owner's authorization (Part III).

## Still open

- **A-1** (§23): whether a 1Password person can write a vault they cannot read. It needs the owner's 1Password.

---

## Evidence (opv 0.11.0)

| What | Where |
|---|---|
| The value type | `src/domain/secret.rs` (`SecretValue`, `expose`) |
| Masked entry (setup only) | `src/app/masked.rs`, `src/app/setup_runtime.rs:594` |
| Settings-health detectors | `src/domain/health.rs` (`is_placeholder` :291) |
| The MCP surface and its authorization model | `docs/mcp.md` |
| The JSON envelope (`next`, `do`, typed errors) | `docs/usage.md` "Every command that takes `--json`" |
| `opv add` defaulting to every declared environment | `src/app/add.rs:37` |
| `init --from` (name-based kind, value import) | `docs/configuration.md` "Start from an existing `.env`" |
| The retirement steps today | `docs/usage.md` "Prune order" |
| Scrubbing lessons | `docs/design/error-catalog.md` |
