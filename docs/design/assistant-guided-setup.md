# Assistant-guided configuration: the North Star, and the gap from opv 0.11.0

Status: **design for review** (2026-10-18). Tracks #173 and its parts #174 to #179. This document first describes the North Star: the ideal system from first principles, without reference to what opv does today (Part I). Most of opv's existing decisions turn out to sit on the path to it, so the gap is mostly an added layer, not a redesign. It then measures opv 0.11.0 against it (Part II), resolves the design's contradictions with TRIZ (Part III), makes confusion and failure structurally impossible where it can (Part IV, poka-yoke), and proposes an order of delivery (Part V), reframes the problem so whole classes of risk cannot be expressed (Part VI), and lists the decisions that are the owner's (Part VII).

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
| **CI** (a service account) | the parts it needs | in process, to deliver them | no: it runs approved, scheduled syncs | no |
| **Platforms** (Fly, Kubernetes, Azure, GitHub, …) | n/a | hold the delivered copies | n/a | n/a |

**Invariant V (the value boundary).** A value, or anything from which part of a value can be recovered, never appears on a surface an assistant can read. That covers stdout, stderr, a JSON document, an MCP response, a log, an error, a file opv writes outside a platform channel or the application's runtime directory, and a command line. "Anything from which part of a value can be recovered" includes its length, a prefix or suffix, a digest, an encoding, an entropy figure and a comparison with a guess.

What may cross the boundary is a **value state**: a closed set of words computed inside opv, where each word describes a value without carrying any of it (§3.3).

**The honest limit.** opv can make its own surfaces incapable of emitting a value. It cannot stop an assistant that also has an unrestricted shell, as the same OS user, from running `op read` itself. The ideal system therefore has two layers:
- opv's surfaces are value-free by construction (Part IV);
- opv installs deterministic guard rules into each assistant harness, and the store's own authorization prompt protects every read that bypasses opv (§9.4).

Neither layer is a sandbox, and the documentation says so.

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
| `placeholder` | a known placeholder (`changeme`, `<your key>`, `xxx`, `your…here`, `todo`, …), or equal to the value in `.env.example` |
| `malformed` | fails its declared shape or rules (the rule's name is reported, never the part that failed) |
| `suspect` | passes its shape but trips a warning: low entropy, a test key in production, a live key outside production, the same value as a lower tier, `localhost` in a deployed tier |
| `set` | present and passes everything |
| `unreadable` | opv could not read it. The cause is reported, and it is **never** reported as absent or empty |
| `not_wanted` | the key's presence excludes this environment |

There is deliberately no numeric field. A score would leak information about the value.

## 4. The contract between opv and every client

One contract serves the person at a terminal, the assistant over MCP and the assistant in a shell. The same document is rendered as text, as JSON or as an MCP result.

### 4.1 Five verbs

Every capability is one of five verbs, and each verb has one shape:

| Verb | Writes? | Who calls it | Returns |
|---|---|---|---|
| **inspect** | no | anyone | state documents (inventory, needs, readiness, access, delivery, history) |
| **propose** | local files only (the contract), or nothing | assistant or person | a **plan**: every step by name, its actor, and a content-addressed `plan_id` |
| **approve** | marks one plan approved; runs that plan's **person-only steps** in the person's terminal | **person only**, in a terminal | what ran, what remains |
| **apply** | carries out the approved steps that need no person | assistant or CI | what ran, with evidence |
| **next** | no | anyone | exactly one recommended action, plus the queue |

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

### 4.4 Agent mode

opv knows when its caller is an assistant: always over MCP, and in a shell when a harness marker or `OPV_AGENT=1` is present (§9.4 installs the marker). In agent mode:
- **No prompt ever opens.** A person-only step returns `next.actor = person` with the exact command, instead of hanging on a prompt the assistant cannot answer and must not see.
- **`run` redacts.** Output of a child started by `opv run` has every value opv injected masked, including their common encodings (§9.3).
- **Value-entry commands refuse.**

## 5. The surface (ideal)

Each row exists in both the CLI and MCP.

| Verb | CLI | MCP | Purpose |
|---|---|---|---|
| inspect | `opv inventory [--env …] [--json]` | `opv_inventory` | the application matrix: keys × environments, each cell a value state; attributes; delivery state per target |
| inspect | `opv needs [--scan …] [--names …]` | `opv_needs` | code ↔ contract comparison, with scanner coverage |
| inspect | `opv detect` | `opv_detect` | candidate components, environments and targets from the repository, with evidence |
| inspect | `opv ready [--env] [--gate]` | `opv_ready` | findings and gates (promotion, CI) |
| inspect | `opv exposure <KEY>` | `opv_exposure` | everywhere a key's value lives and is delivered (leak response) |
| inspect | `opv people` | `opv_people` | who and what can read each boundary (offboarding); names of people only where 1Password reports them |
| propose | `opv setup plan` | `opv_setup_plan` | first setup: contract, structure, imports, generation, targets, as **one** plan |
| propose | `opv change plan` | `opv_change_plan` | add, alter or retire keys; add environments |
| propose | `opv rotate plan <KEY>…` | `opv_rotation_plan` | rotation across environments, in order |
| propose | `opv deploy plan <env>` | `opv_deployment_plan` | delivery to targets |
| approve | `opv approve <plan_id>` | — (never) | the person reviews, approves, and runs the person-only steps (imports, masked entry) |
| apply | `opv apply <plan_id>` | `opv_apply` | runs the approved non-person steps |
| next | `opv next` | `opv_next` | one action, plus the queue |
| person | `opv set <KEY> --env <env>` | — (never) | masked entry in the person's terminal; refuses agent mode and non-TTY |
| guard | `opv assistant guard install` | — | writes the harness rules (§9.4) |

## 6. The journeys

Each journey step is marked **D** (deterministic, opv), **G** (generative, assistant) or **P** (person).

### 6.1 First setup: "put this app's configuration into 1Password"

1. **D** `opv_detect` and `opv_needs` read the repository: components, environments, targets and every name the code reads, with coverage.
2. **G** The assistant resolves ambiguities from opv's candidates and writes guidance for unknown keys.
3. **D** `opv_setup_plan` returns one plan:
   - the contract file;
   - boundaries (vaults and items) per environment under the project's conventions;
   - fields for every key in every environment where it is present;
   - generated values for `generated` keys;
   - the `.env` import for the local environment;
   - targets and identities.
4. **P** `opv approve <id>` in the person's terminal shows the whole plan once. On approval it runs the person-only steps right there:
   - the `.env` import, with values going straight from the file to 1Password;
   - masked entry for any value the person chooses to type now.
   
   1Password asks for authorization once.
5. **D** `opv_apply` runs everything else: structure, generation, contract file and IDs.
6. **D** `opv_next` → "3 values only you can provide", each with its link, its shape and its guidance.
7. **P** The person enters them. **D** The value states turn `set`. **G** The assistant confirms in conversation.

The person's whole effort is one approval, one authorization, and the values only they can fetch.

### 6.2 A new engineer joins

1. **D** `opv next` on a fresh clone sees the shared environment is complete and lists the engineer's own `personal` keys as `absent`, with links to create their item.
2. **P** They enter their own keys.
3. **D** `opv run -- <app>` works.

Access comes from vault membership, which an owner grants. `opv people` shows it.

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
- **Leak response:** **D** `opv exposure KEY` lists every environment, target and delivery holding it, then the rotation plan.
- **Offboarding:** **D** `opv people` lists the boundaries a person can read, and the identities and personal items to revoke.
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
| G2 | Agent cannot reach values through a shell | 1Password's authorization prompt on writes; `opv_structure_apply` refuses an inherited session | **Part:** no harness guard rules; `opv run` passes child output unredacted | new |
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
| G27 | `opv run` redaction of injected values | every value opv reads is registered with a scrubber that masks it in tool output opv shows (NR-31, `SecretValue::new`) | **Part:** the child of `opv run` writes straight to the terminal, unscrubbed | new |
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
| C4 | The assistant should be able to run the application to debug it, but the application's output can contain the values opv injected | technical | **opv as intermediary.** `opv run` in agent mode masks every injected value, and its common encodings, in the child's output before the assistant sees it. opv holds the values, so it can match them exactly | 24 intermediary; 9 prior counteraction |
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
| P-4 | An assistant's shell reads a value through `op` | Harness guard rules (§9.4) deny `op read`, `op item get --reveal`, `op inject` and `opv run -- <shell>` for the assistant, and 1Password's authorization prompt protects the rest. This is not a sandbox, and the docs say so | detects |
| P-5 | Child process output leaks an injected value | `opv run` in agent mode masks exact values and their base64, hex and URL encodings in the child's output, streaming across chunk boundaries. The mask replaces the whole match with a fixed marker, never by bytes, which keeps JSON well-formed (the 0.10.0 lesson) | detects |
| P-6 | A person pastes a value into the chat | Outside opv's control. The skill and the MCP instructions tell the assistant to stop, never repeat it, point to `opv set`, and treat the value as exposed, which makes the rotation plan the `next` action | warns |

## 12. Model and state

| # | Failure | Structural prevention | Level |
|---|---|---|---|
| P-7 | A failed read is reported as a missing value | `unreadable` is its own value state with its cause. The type that computes states has no path from an error to `absent` | prevents |
| P-8 | A key is missing from an environment by accident | Presence `all` by default. An explicit list that leaves out an environment needs an `except` with a reason, otherwise load warns with `environment_gap` | prevents (new keys), warns (old ones) |
| P-9 | A new environment lacks existing keys | Presence `all` is inherited on creation; the structure plan adds its fields | prevents |
| P-10 | A removed key leaves orphans | Lifecycle states: `retire` moves through `retiring` → `retired` in a fixed order, and archives fields instead of deleting | prevents |
| P-11 | A dev value is copied into production | Tier policy: a production value equal to a lower tier's is `suspect` and fails the production gate unless the key says `allow_same_value`. An import into a production-tier environment needs `--confirm <env>` | detects |
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

# Part V: delivery

The order puts the assistant contract and the application model first, because every later journey depends on them.

| Phase | Contents | Gaps closed | Issues |
|---|---|---|---|
| **A. Contract hardening** | `ValueFree` output types (P-1) and the MCP input schema test (P-3); typed `next` with kind and actor; agent mode (P-20, C10); free-text screening (P-2) | G1 (by types), G21, G26, G37 | new |
| **B. State you can see** | value states (§3.3); `opv inventory` matrix; `opv next`; scope, source and presence attributes | G6, G15, G16, G22, G38 | #174 |
| **C. The application model** | presence `all`/`except`; ordered lanes and tiers; tier policy; the gap finding; lifecycle and `retire`; bulk extend; the promotion gate | G8, G10, G12, G14, G28, G29 | #179, #177 |
| **D. Code ↔ contract** | the scanner with coverage; `opv needs` and its gate; name-only declaration from a `.env`; the name catalog | G3, G17, G19, G35 | #175, #176 |
| **E. One-plan setup** | `opv detect`; `setup plan`; person-only steps inside `approve`; `opv set` (masked) | G18, G23, G24, G25 | new |
| **F. Assistant safety in a shell** | `opv run` redaction (P-5); harness guard rules (P-4) | G2, G27, G36 | new |
| **G. Life after setup** | rotation plan; expiry; exposure; people and offboarding | G11, G30, G31, G32 | new |
| **H. Later** | provisioners; ephemeral environments; generated-contract fragments | G13, G33, G34 | #178 |

Phases A and B are prerequisites for the rest. C and D can run in parallel after B. E needs B, C and D. F is independent and could ship first. G needs C. Swarm, GCP and VMs are already planned for 0.12.0 (delivery-transports §8–9), so Part VI asks the owner how to split this work between 0.12.0 and 0.13.0.

Each phase lands with:
- CLI and MCP parity gate scenarios;
- canary-scan coverage of every new document;
- e2e scenarios against opv-sim;
- for phases B–E, an **assistant walkthrough**: a scripted run from a repository with no opv configuration to `ready --gate` passing in every environment, using only MCP tools plus the person-only steps. It runs once each under Claude Code, Cursor and Codex, and records the number of person actions.

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
- **The assistant's role:** it reads state and proposes. It never writes to 1Password or to a target.

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
  - **results of predicates fixed before the question is asked:** catalog shapes, and rules a person approved;
  - **comparisons between stored values that the contract fixes,** such as the same value across tiers.

  Nothing the caller supplies at question time ever meets a value. A non-adaptive predicate set bounds what can leak to a few fixed bits per key, and the caller cannot choose which bits.
- **Imports become write-only.** `import <file>` reports per key `imported`, `skipped: already set` or `skipped: empty`. It never reports "differs", and it never overwrites a value without a person's `opv apply`.

What it removes: H2 (caller-steered equality), and the `.env.example` comparison in #177 (conflict 1 in the review). "Equal to the example file" becomes a fixed check against the committed example, and it is only a warning. It also gives one invariant to test, in place of a list of special cases.

What it simplifies: for the **local tier**, importing a `.env` can run straight from the assistant's request, because it is write-only and reports presence only. "Import my `.env`" then needs no person step at all for local development, which is the commonest first experience.

**Verdict: keep.** It replaces several point fixes with one rule.

### R4. Tiered sight: deployed tiers are seen through receipts, not reads

- **The problem behind review H3:** an assistant with a shell on the person's laptop can reach whatever the person's sessions can reach: `op read`, `kubectl get secret`, `az keyvault secret show`. No opv design closes that. 1Password's JSON for an item includes concealed values (opv reads items with `op item get --format json`), so there is no read that returns metadata alone.
- **The reframe:** the laptop never *needs* to read a deployed tier.
  - Production and staging are read by **CI identities only**.
  - CI publishes a **value-free state receipt** (opv already has `opv ready --save` and delivery receipts), signed by the run.
  - The assistant and the person see deployed tiers' state through those receipts.
  - The laptop's session needs access to local and dev only. A person enters a production value through a 1Password link, so the CLI never reads it.

What it removes: the worst case of H3. On a laptop that follows the tier policy, an assistant with a shell can at most reach local and dev values. The guard rules (P-4) become defence in depth, not the main control.

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

**Verdict: keep for the code-facing half.** Keys no code reads, such as CI-only or platform-only keys, are still declared, categorically.

### R6. The contract changes only through review; relaxations are categorical and loud

- **The reframe:**
  - The contract lives in the repository (decision 1).
  - **Bindings** (vault and item ids, targets) live in a separate, opv-written file. Neither an assistant nor a pull request edits them; only `opv apply` and `opv target add` do.
  - **Policy relaxations** are categorical attributes that opv marks as relaxations: `except <production-tier env>`, `allow_same_value`, removing a shape, presence narrowing.
  - The plan for a change that contains one shows it first, with its reason. It needs the person's `opv apply` (R1) and fails the `needs`/`ready` gate in CI until then.

What it removes: review M4, a pull request or assistant quietly weakening policy, and review M10, the `all` default pushing junk into production. A new key's plan asks "a value, or `except`?" for each production-tier environment, as a categorical choice.

**Verdict: keep.**

### R7. Value access in code is bound to a purpose

- **The reframe, in the Rust:** `SecretValue::expose()` takes a **purpose token** from a closed set: `DeliverToStore`, `DeliverToPlatform`, `DeliverToChild`, `EvaluateFixedPredicate(PredicateId)` and `CompareFixedPair(KeyRef, KeyRef)`.
  - Each token can only be minted by the module that owns that purpose, the pattern `Observed` already uses.
  - The predicate and comparison tokens can only return the closed `ValueState`.
- This is the code form of R3. It makes "a new feature compares a value with caller input" fail review structurally, because no token for it exists. The canary scan stays as the second layer.

What it removes: the review's M1 (a sealed trait seals nothing inside one crate) by changing the mechanism, not by adding a lint.

**Verdict: keep.** It lands with the 0.12.0 contract hardening.

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

That is 5 tools, down from 11, all of them without side effects outside the local contract and the local tier.

**The person's whole surface:** `opv apply`, `opv set` (masked entry), the 1Password links opv gives, and reading the plan.

**CI's surface:** `opv sync`, `opv changed`, `opv ready --gate`, receipts.

### 22.1 What the reframe does to the risks

| Risk | Parts I–IV answer | After the reframe |
|---|---|---|
| H1: rule-predicate oracle | approve rules before they count | **eliminated** (R2, R3, R7): no client-supplied predicate exists |
| H2: equality the caller steers | drop the `.env.example` check; make imports person-only | **eliminated** (R3): write-only imports; fixed comparisons only |
| H3: an assistant shell reaches values | guard rules; an honest limit | **reduced to the local tier** (R4); the strongest form waits on A-1 |
| H4: `opv run` output | redaction tied to agent mode | **reduced:** under R4 the local tier holds only local values. Redaction stays (secret values of 8+ bytes, always on), as defence in depth |
| M1: a trait seals nothing | a sealed trait | **eliminated** by a different mechanism (R7) |
| M2: agent mode can be spoofed | detection | **no longer a security control** (R1) |
| M3: approve/apply race, window expiry | keep approve approve-only | **eliminated** (R1: one process) |
| M4: a PR weakens policy | split bindings | **eliminated** (R6) |
| M9: scanner junk keys | an ignore list | **eliminated** (R5: `ignore` is an annotation) |
| M10: the `all` default and production | ask per production environment | **eliminated** (R6: a categorical question in the plan) |
| M13: free-text screening, rule parameters | screening | **reduced to guidance only** (R2) |
| M14: a parallel command surface | a migration plan | **reduced:** 5 assistant tools replace 11 (still needs a deprecation plan) |
| P-20: assistant hangs on a prompt | agent mode | **eliminated** (R1: the assistant runs nothing that prompts) |

### 22.2 What it does to the experience

| Journey | Parts I–IV | After the reframe |
|---|---|---|
| First local setup from a `.env` | plan, then the person approves, then the assistant applies, then the person imports | the assistant imports the local `.env` (write-only), proposes the contract, and the person runs **one** `opv apply` |
| Adding a dependency's key | declare, plan, approve, apply | the PR shows "1 new name" with the catalog's suggestion; the assistant annotates it; the merge plus one `opv apply` creates the fields everywhere |
| Seeing production's state | a laptop read of the production vault | the latest CI receipt; no production access on the laptop |
| Person actions for a typical change | 2 to 3 commands, plus a time window | 1 command, no window |

## 23. Open questions the reframe raises

- **A-1 (spike):** can a 1Password person write into a vault without reading it? This decides between R4's strong and weak forms.
- **Receipt freshness:** how stale may deployed-tier state be before `next` asks for a CI refresh? Proposed: a receipt older than the newest relevant item version is `stale` (opv already compares item versions in `opv changed`).
- **Merge-time application:** can merging a contract change trigger CI to apply the parts that need no person (deployed-tier structure, generated values) under the CI identity? That would make a person's `opv apply` necessary only for person-sourced values and relaxations. This is a good fit, but it gives CI write access to deployed-tier structure, which needs its own access review.

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
- opv reads what the current 1Password session can do with each vault the contract names: read, write, or no access. This uses 1Password's own vault permissions.
- **Write access to a vault** means this person can set up that environment's structure and values. They can do it in the 1Password app directly, or with opv's help, using the links, empty fields, generation and masked entry opv offers. 1Password authorizes every write. opv reads the result the same way whichever route was used.
- **Read access only** means this person can run with those values (`opv run`) and see their states, but not change them.
- **No access** means opv shows the environment's structure from the contract and the latest value-free CI receipt, and names the vault. "Someone with write access to vault X can fill this", with the people and groups `opv access` reports for that vault when 1Password lets the session see them.

**What each person sees:** `opv next` and the inventory list, first, the actions **this session can take**, then what is waiting on others, by vault. Nobody is told to run a command they lack the access for.

**CI:**
- reads values with a read-only service account per values vault, and delivers them to the platforms (`opv sync`, `opv changed`);
- posts the value-free plan and key × environment matrix as a check on pull requests that change the contract;
- its only 1Password write is delivery evidence, holding no values, in the target's state vault, as since 0.7.0.

**The contract** changes through pull requests. Reviewers approve the change to *what is needed*; filling values is done by whoever has write access to each vault.

**A new key, end to end:**
1. A PR adds the key.
2. The check shows its row: dev, staging and prod are each `absent`, with the vault each one lives in.
3. After merge, each person with write access to one of those vaults sees it in their `opv next` and fills it, in the 1Password app or through opv.
4. CI delivers on change.
5. The promotion gate holds a tier until its value is `set`.

**Team-managed developer environments:**
1. Someone with write access to the dev vault sets the environment up once.
2. 1Password access to that vault is granted to the developer or their group, in 1Password. opv can print the link or the `op` command, but never grants access itself.
3. The developer runs `opv run -- <app>`. If something is missing, `opv doctor` names the vault and who can fill it, instead of asking the developer to set anything up.

Personal keys exist only where the team gives developers their own items.

**Emergencies** need no special path: anyone with write access to the vault fixes the value, and CI delivers.

**What it answers:**
- who writes each tier: whoever 1Password lets write its vault;
- loosened policy: relaxations show in the PR diff and the check;
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

### R10. The contract generates the application's configuration module

- **What opv generates:** for each supported language (TypeScript, Python, Rust and Go first), a typed accessor from the contract, for example `config.stripeSecretKey`.
- **What that guarantees:**
  - **Unknown names don't compile.** Code can't read a name the contract doesn't declare, so the scanner becomes a fallback for languages without generation.
  - **A key can't be retired while it's still read.** Retiring removes the accessor, so a build that still uses it fails before anything is pruned. For deployed tiers, retirement also checks `needs` at the deployed revision.
  - **Misconfiguration fails at startup.** At boot the module checks every required key's presence and shape, so a broken deploy fails its health check and rolls back instead of failing at first use.
- **What it isn't:** a runtime dependency on opv or 1Password, which the owner decided production must never need. The module reads only the platform's own channels (env, files).

### R11. Rotation overlaps and is observed

A rotation:
1. adds the new credential alongside the old;
2. delivers it;
3. confirms through opv's delivery evidence and the platform's rollout status that every running revision holds it;
4. only then offers to revoke the old one.

Consumers outside opv's view (another host, a partner's webhook) are declared in the contract. When any exist, revoking is a person's step with that list shown.

### What R8–R11 claim, to be tested by FMECA

| Residual after the first reframe | Claim under R8–R11 |
|---|---|
| An assistant shell reaches values (H3) | A developer machine reaches only local/dev vaults by 1Password permission. A DevOps machine stays residual, with the authorization prompt and an optional admin account |
| Platform tools reach production | No production platform logins on developer machines; `doctor` detects them |
| `opv run` encoding leak | Local values are sandbox-grade: recoverable, not a breach |
| Secret downgraded to config | A flagged change in a reviewed PR; the check fails until it is accepted |
| Rotation revokes while in use | Overlap plus observed rollout; declared outside consumers |
| Retire while still read | The build fails while still read; `needs` at the deployed revision |
| Scanner misses a name | Impossible in generated languages; detection elsewhere |
| Nobody writes deployed tiers | Whoever 1Password lets write that tier's vault, in the 1Password app or with opv's help; CI only reads and delivers (R8) |

---

# Part VII: decisions for the owner

Each one is explained, with a recommendation.

1. **Where the contract lives (C9, G3).**
   - **The question:** today a project's configuration can be a `secrets.toml` in the repository or a manifest in 1Password. The ideal wants the key contract reviewed in the same pull request as the code that needs it, which argues for the repository file as the single writable source, with the 1Password manifest as a read-only mirror.
   - **What changes:** projects that keep their configuration only in 1Password would move it into the repository.
   - **Recommendation:** make the repository file the source for applications. Keep the manifest as a mirror for portfolio views.
2. **Presence default (C5, G8).** Covered in #179.
   - **Recommendation:** the new `all` form becomes the default for new keys, and existing explicit lists keep their meaning. Nothing breaks.
3. **Naming: "product" or "component".**
   - **The question:** "product" in opv means a part of the application (web, api). The ideal calls it a component and calls the whole an application.
   - **Recommendation:** keep `products` in the file format, because renaming breaks every configuration. Use "application" and "component" in documentation and in new commands' text.
4. **How far agent mode goes (C4, C10).**
   - **The question:** redacting `opv run` output in agent mode protects values, but changes what an assistant sees while debugging.
   - **Recommendation:** redact by default in agent mode, with no switch to turn it off from agent mode.
5. **Release split.**
   - **The question:** Phases A–F are a large body of work, and 0.12.0 already holds Swarm, GCP Secret Manager and the VM step.
   - **Recommendation:** 0.12.0 = phases A, B and F plus the planned targets. 0.13.0 = C, D and E. 0.14.0 = G.
6. **TRIZ analysis.** The contradictions above were resolved with the offline catalog. The paid `triz analyze` (OpenRouter) could cross-check C1–C10 and needs the owner's authorization.

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
