# opv CLI UX, pass 2: agents, humans, power and safety

Status: done. Review input for 0.5.0; the adopted findings shipped (CHANGELOG 0.5.0). Kept as a record: the output it quotes predates the release.

Read-only review. Nothing in the repo was edited. No real 1Password, Fly, Azure or cluster was contacted.

**Evidence.** I used the debug binaries already built in the three worktrees, copied so a rebuild could not change them mid-review:

| Binary | Branch | HEAD |
|---|---|---|
| `opv-ux1` | feat/p1-ux1 | `eed61bf` |
| `opv-p1` | feat/p1-azure | `0a27b33`; that worktree has an unfinished merge, `UU CHANGELOG.md` and `docs/agent-setup.md` |
| `opv-login` | feat/p1-login | `63ab5b4` |

I ran them against a temporary fleet `secrets.toml`: two products, a run-only `dev`, a Fly `prod` with `confirm_env = true`, and an immutable key. Shell stubs for `op` and `flyctl` sat on PATH. The `flyctl` stub keeps state, so stage, list and deploy behave realistically. Marker values never appeared in any stub's argv log (`grep -c MARKER` returned 0 for both logs).

Two outputs in this report come from stub limits, not opv: `signed in (unknown type)`, and `op said:` lines that disagree with the diagnosis. Both are flagged where they appear. File:line references are to `opv-ux1` unless another worktree is named.

The first pass (P1–P22 approved, X1–X7 rejected) is the baseline. This pass does not repeat it. It checks how the approved items landed, then goes further.

---

## 0. Where the three branches stand (the integration risk is UX debt in itself)

| Area | ux1 | p1 | login |
|---|---|---|---|
| `Next:` as the last line (P1) | yes | no (`Next step (...)`, then `opv: …` after it) | no |
| Run summary and `sync --json` (P2) | yes | no | no |
| `confirm_env` / `--confirm` (P10) | yes | config parse error: `unknown field "confirm_env"` | no |
| `plan` names its actions (P11) | yes | no | no |
| `status`/`plan --product` (P12) | yes | no | no |
| `opv status` with no env (P22) | yes | no | no |
| First-run router (P3) | **no**: says "Run opv setup", then `Next: opv doctor` | yes | yes |
| Enum failures show allowed values (P9) | **no** | yes | yes |
| Scrubbed `op said:` lines | no | yes, **on by default** | yes, on by default |
| `explain` suggestions (P8) | **no** | yes | yes |
| `doctor --json` (P18) | no | yes | yes |
| Sign-in advice | `eval $(op signin)` | `eval $(op signin)` | `opv login prod` |

Each branch fixes something another breaks. The merge must take the union. Section 6 lists regressions to watch, such as `opv: status findings: 1` coming back from p1 and login.

---

## 1. Benchmark: concrete journeys

Legend: **opv+** opv is already better; **them+** a competitor is better today; **=** about the same.

| Journey | What the best tools do | opv today | Verdict |
|---|---|---|---|
| First run | Doppler: `doppler login`, then `doppler setup` (pick project/config, bound to the directory), then `doppler run -- cmd`. gh: `gh auth login` device flow | `opv init dev --vault V --item I` reads field names and types only. `opv login dev` (login branch) needs no `eval`. The first-run router lands only on p1/login | **them+** on speed: Doppler binds the directory once and needs no IDs. **opv+** on safety, and no SaaS state |
| Add a secret | Doppler/Infisical: `secrets set KEY` (prompt or stdin). sops: edit the file and commit | Edit `secrets.toml` by hand (`init` refuses an existing file), then `item skeleton`, then find the field in the 1Password app, then `status` | **them+**. The worst journey: about 4 tools and 2 context switches |
| Rotate | Vault: leases. Doppler: set the value, integrations auto-sync | Edit in 1Password, then `opv sync <env> --deploy`. Immutable keys need `--rotate api/K`, a deliberate and well-guarded step | **opv+** for guarded immutables. **=** otherwise |
| What is out of sync? | terraform `plan -detailed-exitcode`; kubectl `diff`; Doppler sync status in the dashboard | Azure/K8s: an exact `unchanged`/`changed`. **Fly: every present secret is "potentially changed" forever** (no plan is ever clean). No drift exit code | **opv+** on pinned targets; **them+** on Fly and in cron drift checks |
| Deploy safely | flyctl `secrets set` deploys implicitly (worse). terraform: a saved plan, then `apply plan.out` | Explicit `--deploy`, a health-gated prune, `confirm_env`, a refusal before any write, and a run summary | **opv+** clearly. terraform still wins on "apply exactly what was reviewed" (see A7) |
| Recover from a failure | gh/kubectl: a raw error. az: a long JSON blob | A typed exit, a diagnosis (signed in? vault access?), `Next:`, and exit 9 meaning "safe to re-run" | **opv+**, held back by prose `Next:` lines (A3) and useless `Next: opv doctor` defaults (B3) |
| Onboard a teammate | Doppler: `doppler setup` picks up the repo's `doppler.yaml`. direnv auto-loads | `opv login dev`, `opv doctor --env dev`, `opv run dev --product api -- …`. `OPV_PRODUCT` helps | **=**. No single entry point, and a missing key shows up when the *app* crashes, not before |
| Run locally | `doppler run -- cmd`; `sops exec-env`; direnv | `opv run dev -- cmd` uses `op run`, scrubs declared names and masks output | **opv+** on hygiene. **them+** on keystrokes (Doppler needs no env) |
| Wire CI | Doppler/Infisical: official GitHub Actions; terraform: PR-comment plans (Atlantis) | A hand-written workflow; the docs example **pins v0.3.0** (`docs/usage.md` GitHub Actions). No step summary, no Action | **them+** |
| Let an AI agent set it up | gh: `--json` with field selection, `gh help formatting`. kubectl: `explain` (a self-describing schema). No secrets CLI has a never-values contract | llms.txt, agent-setup.md, names-only JSON, typed exits, `Next:` | **opv+** on safety, the best in class. **them+** on machine self-description (no `opv schema`) and on JSON errors (none) |

**Summary.** opv already wins on safety, explicitness, multi-provider parity and recovery. It loses on adding a key, Fly drift visibility, CI wiring and machine self-description. Every one of those can be fixed without breaking §7/§9.

---

## 2. Proposals

Fields: change (before → after) · who / journey · TRIZ · pros · cons/risks · effort · verdict.
Effort: S ≤ 1 day, M ≤ 3 days, L > 3 days.

### A. Agent and machine contract

**A1. A JSON error envelope for every `--json` command**
- **Before** (`opv status prod --json`, not signed in): stdout is empty. stderr carries 7 lines of prose ending in `Next: sign in: eval $(op signin)`, and the exit is 7.
- **After:** stdout gets one document, and stderr keeps the human text:
  ```json
  {"schema_version":1,"ok":false,"exit_code":7,
   "error":{"category":"auth","code":"op_not_signed_in","message":"not signed in to 1Password",
            "next":{"argv":["opv","login","prod"],"display":"opv login prod","kind":"human_terminal"},
            "retry":"after_fix","human_required":true}}
  ```
  Successful documents gain `"ok":true`.
- **Who / journey:** every agent and CI script. Today an agent must parse stderr prose to recover.
- **TRIZ:** none needed.
- **Pros:** one parse path for success and failure. `retry` and `human_required` let an agent decide without heuristics.
- **Cons/risks:** messages are already names-only (SR-1), so this adds no new leak surface. It is a new contract, so pin it with a schema test. Additive: schema stays 1.
- **Effort:** M. **Verdict: Recommend.** It is the single biggest gap for agent use.

**A2. Stable error `code` slugs (an error taxonomy)**
- **Change:** each error site gets a fixed slug in a closed list documented in `opv schema` (A4). Examples: `confirm_required`, `confirm_mismatch`, `keys_blocking`, `op_not_signed_in`, `item_not_found`, `vault_no_access`, `target_unhealthy`, `terminal_required`, `undeclared_key`, `unknown_env`, `stale_plan`.
- **Text output:** unchanged by default. `--verbose` appends ` [code]`.
- **Who / journey:** agents and CI branch on the cause, not just the category. Exit 6 today means four different things: blocking keys, `--confirm` missing, needs a terminal, and config export refused.
- **TRIZ:** #3 Local quality. The code appears only where a machine reads it (JSON, verbose). This removes the pass-1 objection to bracketed codes in human text (`[SETUP-TERMINAL]`).
- **Pros:** the exit-code table stays at 9 entries and the extra precision lives in the code.
- **Cons/risks:** every new slug is a contract, which adds maintenance. Keep the list short and closed.
- **Effort:** S–M. **Verdict: Recommend** (ship with A1).

**A3. Split `Next:` into `Do:` (a human action) and `Next:` (always a runnable command)**
- **Before:**
  - `Next: fix the keys above in 1Password, then run opv status prod`
  - `Next: sign in: eval $(op signin)`
  - `Next: opv explain api/DATABASE_URL --env prod (and likewise for each key above)`
- **After:**
  ```
  Do: fill api/DATABASE_URL, fix api/LOG_LEVEL (expected one of: debug, info), fix web/OPENAI_API_KEY (stored as text, declared secret) in 1Password
  Next: opv status prod
  ```
  ```
  Do: sign in at 1Password's prompt in your own terminal
  Next: opv login prod
  ```
- **Contract:** `^Next: ` is followed by a command that runs as-is (no prose, no parentheses). `^Do: ` is optional and comes right before it.
- **Who / journey:** agents (agent-setup rule 7 says "Run that command"). Today 3 of the 5 most common `Next:` lines cannot be run.
- **TRIZ:** contradiction: the step must guide a human-only action (values never pass through opv) *and* be machine-runnable. Principle **#1 Segmentation**: split the instruction into a human part and a machine part.
- **Pros:** quotable and deterministic. Maps directly onto A1's `next.argv`.
- **Cons/risks:** golden churn in `sync_refused_missing_key`. Doctor tests change.
- **Effort:** S. **Verdict: Recommend.** It closes the gap between what NR-19 promises and what the code prints.

**A4. `opv schema`: a machine-readable self-description**
- **Before:** an agent scrapes `--help`, whose global options repeat 25 lines in every subcommand.
- **After:** `opv schema` prints one JSON document:
  ```json
  {"opv_version":"0.5.0","schema_version":1,
   "commands":[{"name":"sync","args":[{"name":"env","required":true}],
     "flags":[{"name":"--deploy","effect":"deploys"},{"name":"--prune","effect":"deletes"},...],
     "effect":"writes_target","needs_terminal":false,"reads_values":false,"json":true,
     "ask_user_first":true}, ...],
   "exit_codes":{"0":"ok",...,"9":{"meaning":"outcome unknown","retry":"safe"}},
   "error_codes":[...], "states":{"source":[...],"target":[...]},
   "documents":{"status":{"$schema":"https://json-schema.org/draft/2020-12/schema",...}}}
  ```
  Optional: `opv schema status` prints one JSON Schema.
- **Generation:** from clap plus one static effect table. A test checks that every subcommand has an entry.
- **Who / journey:** agent setup. One call replaces reading 4 docs, and the answer matches the *installed* binary, not `main`.
- **TRIZ:** **#25 Self-service.** The binary describes itself.
- **Pros:** same idea as `kubectl explain` and `gh help formatting`. It is the base for A8 (MCP) and doc drift guards.
- **Cons/risks:** another surface to keep in sync. Mitigate by generating it from the code and testing it.
- **Effort:** M. **Verdict: Recommend.**

**A5. Close the `--json` coverage gaps**
- **Gaps:**
  - `opv status --json` with no env is a clap error today: `the following required arguments were not provided: <ENV>`.
  - `explain --json` (reference, kind, target name, rules, guidance, inspect argv).
  - `init --json` (what was written: env, profile, keys and kinds).
  - `item skeleton --json` (fields added).
  - `config export` already prints JSON only and should drop the mandatory `--json` (pass-1 P5g).
- **After:** `opv status --json` prints `{"schema_version":1,"environments":[{"name":"dev","target":null,"findings":1},…]}`.
- **Who / journey:** agents and fleet dashboards.
- **TRIZ:** none.
- **Pros:** every read command becomes scriptable.
- **Cons/risks:** more shapes to keep stable. Use A6's shared row type.
- **Effort:** S–M. **Verdict: Recommend.**

**A6. One JSON row shape and one key order**
- **Before, three incompatible shapes:**
  - `check --json` has alphabetical keys, rows without `kind`, top-level `findings`, and `target_checked`.
  - `status`/`plan` use declared order, `totals.findings`, and both `fly_name` and `target_name`.
  - `sync --json` is alphabetical and its arrays hold **target names only** (`"unchanged":["FLEET__API__DATABASE_URL",…]`). Its text output says `api/DATABASE_URL (FLEET__API__DATABASE_URL)`.
- **After:**
  - One `Row {product,key,kind,state,rule,reason,target_name,target,action}` in every document, keys in declared order (serde `preserve_order`).
  - `sync` arrays hold `{product,key,target_name}` objects. Bare-name arrays stay as `written_names` for compatibility.
  - Every document carries `next`, so check, status and plan gain it.
  - `fly_name` is marked deprecated in `opv schema`.
- **Who / journey:** anyone joining `check`, `plan` and `sync` output.
- **TRIZ:** none.
- **Pros:** an agent learns one shape.
- **Cons/risks:** any reordering is technically visible. JSON consumers should not depend on order, so additive fields keep schema 1.
- **Effort:** M. **Verdict: Recommend** (before 0.5.0 freezes `sync --json`).

**A7. A plan fingerprint: `sync --expect-plan <id>`**
- **Before:** a human approves `opv plan prod`. Minutes later the agent runs `opv sync prod --deploy --confirm prod`. Anything that changed in between, such as a teammate's 1Password edit or another tool staging, is applied without review.
- **After:**
  - `plan` prints `plan 7f3c9a1e (valid while 1Password item v41, the target listing and secrets.toml are unchanged)`, and JSON gets `"plan_id"`.
  - `opv sync prod --deploy --expect-plan 7f3c9a1e` re-derives the id and refuses with exit 6 and `stale_plan` if it differs: `plan changed since 7f3c9a1e: 1Password item v41 → v42; Next: opv plan prod`.
  - The id is a hash of `secrets.toml` bytes, the env name, flags, the item's `version` integer, and the target listing (Fly digests and Key Vault version ids are already visible on the target). **No values and no value digests.**
  - On a `confirm_env` environment, `--expect-plan` satisfies the guard on its own, because the id is bound to that environment.
- **Who / journey:** "deploy safely" with an agent or reviewer in the loop, and CI that plans in a PR and applies on merge.
- **TRIZ:** contradiction: safety (apply exactly what was reviewed) against speed (no extra prompts or round trips) and statelessness (no saved plan file). Principles **#10 Prior action** and **#11 Beforehand cushioning**. The fingerprint is recomputed, not stored, so opv stays stateless (§7/§9).
- **Pros:** terraform-grade guarantees with no plan file. It also gives A8 a natural approval token.
- **Cons/risks:**
  - Fly listing order and lag can make ids flap, so normalise them.
  - The item `version` changes on any field edit, which is conservative (an unrelated edit causes a re-plan).
  - Hash the *metadata* only, never values (the lesson from pass-1 bug 30).
- **Effort:** M. **Verdict: Recommend** for 0.6.0.

**A8. `opv mcp`: an MCP server over stdio**
- **Change:**
  - Read-only tools by default: `doctor`, `status`, `plan`, `check`, `explain`, `schema`.
  - `sync` appears only with `opv mcp --allow-sync`, is annotated `destructiveHint`, *requires* `expect_plan` (A7), and asks for confirmation through MCP elicitation.
  - `run`, `setup`, `login` and `item skeleton` are never exposed. `run` can exfiltrate through the child, and the others need a human.
- **Who / journey:** agents in Claude Code, Cursor and similar. Typed tools, no shell quoting, and discoverable safety annotations.
- **TRIZ:** **#24 Intermediary**. The server is a policy layer between agent and CLI.
- **Pros:** the tool list *is* the policy, and agents cannot invent `op read`.
- **Cons/risks:**
  - A long-lived process holds an op session, so tokens live longer.
  - A second interface to keep stable.
  - Most of the value already comes from A1+A4 over the CLI.
- **Effort:** L. **Verdict: Consider** (0.6.0 at the earliest, after A1/A4/A7, as a thin wrapper over the same JSON).

**A9. "Needs a human" becomes an explicit hand-off**
- **Before** (`opv login prod` without a TTY):
  ```
  opv: policy denied: opv login signs in at 1Password's own prompts, so it needs your own interactive terminal. Automation signs in with OP_SERVICE_ACCOUNT_TOKEN and uses init, doctor, check, item skeleton, run and sync with declared configuration.
  ```
  Exit 6 and no `Next:` (login branch).
- **After:**
  ```
  opv: refused: opv login needs your own terminal (1Password prompts for your password there)
  Do: ask the user to run this in their own terminal
  Next: opv login prod
  ```
  Exit 6, code `terminal_required`, `human_required: true`.
- **Who / journey:** agents. agent-setup rule 5 asks them to relay exactly this, but the message does not say it.
- **TRIZ:** **#23 Feedback.**
- **Pros:** gives the agent a deterministic hand-off.
- **Cons/risks:** none material.
- **Effort:** S. **Verdict: Recommend.**

**A10. A version-matched agent guide, and llms.txt fixes**
- **Change:**
  - `opv guide agent` prints the agent-setup guide embedded in the binary, so agents read the version they are driving instead of `main`.
  - Put a 12-line "contract" block at the top of llms.txt:
    - commands safe without asking;
    - the ask-first list;
    - `Next:` and `Do:` rules;
    - the exit-code table with retry semantics;
    - "`opv schema` describes this binary".
  - Fix stale lines. Exit 6 in agent-setup lists only blocking keys (it misses `--confirm`, terminal-required and config export). Step 4 says `failing rule`, but output says `failed <rule> (…)`. The `<!-- verify: init for azure/kubernetes -->` marker is still there.
- **Who / journey:** agent setup.
- **TRIZ:** **#25 Self-service.**
- **Pros:** cheap. Removes version skew.
- **Cons/risks:** binary size grows by a few KB. The docs drift guard must cover the embedded copy.
- **Effort:** S. **Verdict: Recommend.**

### H. Human journeys

**H1. Deep links to the field in 1Password, plus `opv open`**
- **Before:** `status` says `api/DATABASE_URL failed nonempty (empty)`. The human opens 1Password and hunts for vault `vprd`, item `iprd`, section `api`. `explain` prints `inspect: op item get iprd --vault vprd`, which is a CLI command, not where values get typed.
- **After:**
  - `explain` and `check` print `open: https://start.1password.com/open/i?a=<account uuid>&v=vprd&i=iprd`. This is 1Password's private-link format. The account uuid comes from the `op whoami` opv already runs.
  - `opv open prod [api/DATABASE_URL]` opens it with `xdg-open` / `open` / `start`.
  - `status` prints one `open:` line under the table when it has findings.
- **Who / journey:** humans on add-a-secret, fix-a-finding and onboarding. It removes the worst context switch.
- **TRIZ:** contradiction: opv must never take a value, yet the user must enter one now. Principle **#24 Intermediary**: hand off to the 1Password app, the only surface allowed to take values.
- **Pros:** no value touches opv. Works for agents too, which can show the link.
- **Cons/risks:** the link format belongs to 1Password (confirm it in a spike). On a headless machine or SSH session, only print it.
- **Effort:** S–M. **Verdict: Recommend.**

**H2. `opv add`: declare a key without hand-editing TOML; `opv init --add-env`**
- **Before:** adding `api/STRIPE_KEY` means editing `secrets.toml` by hand (format, rules syntax, environments list). Adding an environment means copying IDs by hand, because `init` says `already exists; init never merges: pass --force`.
- **After:**
  ```
  $ opv add api/STRIPE_KEY --secret --env dev,prod --rule prefix=sk_ --guidance "Stripe › Developers › API keys"
  added api/STRIPE_KEY to secrets.toml (secret; dev, prod; prefix = "sk_")
  Do: add the empty field to the prod item (opv item skeleton prod), then fill it
  Next: opv check dev --product api
  ```
  - Edits use `toml_edit`, so comments and order are kept.
  - `opv init staging --vault … --item … --add-env` appends one `[environments.staging]` and refuses if it already exists.
- **Who / journey:** humans and agents adding a secret, the weakest journey in §1. Agents write TOML badly. This makes it one validated command.
- **TRIZ:** contradiction: `init` must never clobber (safety) but should grow the file (convenience). **#1 Segmentation**: append-only operations, each refusing to overwrite.
- **Pros:** writes only the repo file, never 1Password (FR-11 holds). Rules are validated at write time, not at the next load.
- **Cons/risks:** opv becomes a config editor, which is more code. `toml_edit` preserves formatting but not every style.
- **Effort:** M. **Verdict: Recommend.**

**H3. `init` for every provider**
- **Before:** only `--fly-app` exists. Azure, Kubernetes and `secrets_in` blocks are written by hand (agent-setup has a verify marker for exactly this).
- **After:** one flag shape, `opv init prod --vault V --item I --target fly:myapp`, `--target azure:<rg>/<containerapp> --key-vault kv-x --subscription <guid>`, or `--target k8s:<context>/<namespace>/<deployment>`. Nothing is looked up, the same as `--fly-app` today. `--fly-app` stays as an alias.
- **Who / journey:** first run on the two providers 0.5.0 adds.
- **TRIZ:** none.
- **Pros:** first run works the same on every provider.
- **Cons/risks:** the parser is compact but must be validated. Many Azure fields might call for a TOML template instead of flags.
- **Effort:** M. **Verdict: Recommend.**

**H4. Status and plan put problems first, with the full fix reason**
- **Before:**
  - One flat alphabetical table.
  - `wrong kind` without saying which way.
  - `failed enum (not one of the allowed values)` on ux1 (P9 landed only on p1/login).
  - A 40-key fleet shows 39 clean rows and 1 bad row, with no order.
- **After:**
  ```
  prod: 5 keys · 3 findings · 2 to stage
  FIX  api  DATABASE_URL    secret  failed nonempty (empty)
  FIX  api  LOG_LEVEL       config  failed enum (expected one of: debug, info)
  FIX  web  OPENAI_API_KEY  secret  wrong kind (stored as text; declared secret → concealed field)
  ok   2 more saved and ready (use --all to list)
  ```
  - `--all` restores today's table.
  - JSON is unchanged.
- **Who / journey:** humans scanning fleets: "what's broken?" in one look.
- **TRIZ:** contradiction: complete information against scanability. **#15 Dynamics**: the table shape changes with the state, collapsing clean rows unless asked.
- **Pros:** the fix reasons need no extra calls.
- **Cons/risks:** golden churn in status and plan. The default view hides rows, so the collapsed count must stay explicit. The "stored as text" detail is field *type* metadata, not a value.
- **Effort:** S–M. **Verdict: Recommend** (reasons now; the collapse may be Consider).

**H5. One state vocabulary of ten words or fewer, plus `opv help states`**
- **Before:** the user meets saved, missing, wrong kind, failed <rule>, skipped, absent, absent (new), present, present (not desired), present (immutable, held), potentially changed, unchanged, changed, written, staged, pending, pending deploy, kept, held, unmanaged, current, stale, drift, `-`.
- **After:** two columns, each with a closed set:
  - SOURCE: `saved · missing · wrong kind · failing · skipped`
  - TARGET: `new · same · changed · unknown · pending · held · extra · drift · n/a`

  Specific changes:
  - `potentially changed` becomes `unknown (Fly hides values)`.
  - `present (not desired)` becomes `extra`.
  - The bare `-` for config on Fly becomes `n/a (config: use config export)`.
  - `kept` becomes `not pruned`.
  - `opv help states` prints one line per word.
- **Who / journey:** humans learning the tool; agents mapping states.
- **TRIZ:** none.
- **Pros:** fewer concepts. The same words on every provider (P4's goal).
- **Cons/risks:** the JSON `state` and `target` enums must stay as they are (or gain aliases). Goldens churn.
- **Effort:** S. **Verdict: Recommend** (text only, in the same golden pass as P2).

**H6. Show that Fly is in sync without seeing values**
- **Before:** after a clean `sync --deploy`, `opv plan prod` says `3 to stage`, marks every key `potentially changed`, and suggests `Next: opv sync prod --deploy --confirm prod`. That sync is a no-op. A plan is never clean on Fly, so a cron "is prod in sync?" check is impossible.
- **After:** compare the 1Password item's `version`/`updated_at` with the time of the target's last write:
  - Fly `secrets list` timestamps, if `--json` has them (needs a spike);
  - or the stamp from H7.
  - When 1Password has not changed since the last write, show `same (no 1Password edit since last sync)`. Otherwise show `unknown`.
- **Who / journey:** "what is out of sync", drift alerts, and less fatigue in plan review.
- **TRIZ:** contradiction: opv must know whether a value changed but cannot compute Fly's digest. **#35 Parameter change**: compare versions and times instead of values. **#24 Intermediary**: the item's version counter.
- **Pros:** most plans become clean. Stays stateless.
- **Cons/risks:** an unrelated edit to the item makes every key `unknown` (conservative, never a false "same"). Clock skew needs a margin.
- **Effort:** M (a spike first). **Verdict: Consider** (high value; depends on Fly metadata or H7).

**H7. A provenance stamp on the target: "what changed and when" without a state store**
- **Change:** every write also records metadata (never values):
  - Azure: tags on each Key Vault version.
  - Kubernetes: annotations on each Secret or ExternalSecret.
  - Fly: one managed non-secret name, `OPV_PROVENANCE`.

  Fields: `opv-item-version=41`, `opv-written=2026-10-08T14:02Z`, `opv-config=<sha256(secrets.toml)[:12]>`, `opv-by=<op user uuid | ci:$GITHUB_RUN_ID>`, `opv-version=0.5.0`.

  `opv status prod --history` reads it back:
  ```
  api/OPENAI_API_KEY  written 2026-10-07 14:02 by ci:run 81234 · item v41 · deployed rev ca-app--0007
  ```
- **Who / journey:** audits ("who rotated this, and when?"), incident review, and the H6 comparison.
- **TRIZ:** contradiction: auditability against statelessness (§7/§9: no state store). **#25 Self-service**: the target carries its own audit trail, the same way the existing `opv-managed=<env>` tag already works.
- **Pros:** no server and no file. It survives opv being uninstalled.
- **Cons/risks:**
  - `opv-by` may be personal data, so use the op user uuid, not an email, or make it configurable.
  - On Fly, a provenance name restarts machines like any secret, so stage it in the same batch only when something else changed.
  - The tags are visible to metadata readers. They are non-secret by construction.
- **Effort:** M (Azure/K8s), L (Fly). **Verdict: Recommend** for Azure/K8s in 0.6.0; **Consider** for Fly.

**H8. Built for CI: step summary, an official Action, and a drift exit**
- **Before:**
  - The docs' workflow pins `v0.3.0` and installs only `op`/`flyctl`.
  - CI output is plain logs.
  - `plan` exits 0 whether or not changes are pending.
- **After:**
  - When `$GITHUB_STEP_SUMMARY` is set, `plan` and `sync` append a Markdown table (names and states only) and the summary line.
  - A published `matt-cochran/opv-action@v1` installs a pinned, checksummed opv plus the target CLI.
  - `opv plan prod --detailed-exitcode` exits 10 when changes are pending (opt-in, like terraform). JSON gets `"changes":"none"|"some"|"unknown"`.
- **Who / journey:** wiring CI, PR review of secrets changes, nightly drift checks.
- **TRIZ:** none.
- **Pros:** cheap, high visibility, and names-only.
- **Cons/risks:** exit 10 is a new opt-in code that must go in the exit table and `opv schema`. On Fly it returns `unknown` until H6 lands. An Action is a second release artifact to maintain.
- **Effort:** S (summary), S (JSON field), M (Action). **Verdict: Recommend** (summary and JSON field); **Consider** (exit code, Action).

**H9. Shorter subcommand `--help`**
- **Before:** `opv sync --help` is about 60 lines, and roughly 25 are the same four global options with long prose.
- **After:** subcommand help ends with `Global options: --config --timeout --verbose --color (details: opv --help)`.
- **Who / journey:** everyone reading help, and agents scraping it.
- **TRIZ:** none.
- **Pros:** help halves in length.
- **Cons/risks:** none (help text is not a contract).
- **Effort:** S. **Verdict: Recommend.**

**H10. Specific `Next:` for usage and config errors (no more `opv doctor` fallback)**
- **Before:** each of these ends with `Next: opv doctor`, which cannot fix any of them:
  - `undefined environment "staging" (defined: dev, prod)`
  - `undefined product "nope"; choose one of: api, web`
  - `--rotate "api/OPENAI": not a declared key`
  - `explain expects <product>/<key>` (ux1)
  - `--product is required … Choose one of: api, web`

  Source: `src/error.rs:287`, `_ => "opv doctor"`.
- **After:**
  - `Next: opv status prod` (did you mean prod?).
  - `Next: opv check dev --product api` (the first of api, web).
  - `Next: opv explain api/OPENAI_API_KEY --env prod` (closest match). This is shown, never applied, for `--rotate` and `--prune-immutable`.
- **Who / journey:** recovery from errors for everyone.
- **TRIZ:** **#23 Feedback.**
- **Pros:** reuses the p1 `suggest.rs` edit-distance code.
- **Cons/risks:** a suggestion must never run a destructive flag on its own. It is only printed.
- **Effort:** S. **Verdict: Recommend.**

**H11. The `opv status` overview reads run-only environments and honours `--product`, `OPV_PRODUCT` and `--json`**
- **Before:**
  - `dev: run-only (no target)`, even though dev has a failing `api/LOG_LEVEL`. The morning check hides local breakage (`src/app/status.rs:134-136`).
  - `OPV_PRODUCT=api opv status` silently ignores the product (no `product api (from OPV_PRODUCT)` line).
  - `--json` is refused (`requires = "env"`, `src/main.rs:252-255`).
- **After:** `dev: run-only · 2 keys · 1 finding`; the overview is scoped by `--product`; JSON as in A5.
- **Who / journey:** fleet operators and teammates.
- **TRIZ:** none.
- **Pros:** "green overview" finally means everything is green.
- **Cons/risks:** one more item read per run-only environment (FR-13 still holds: one read per environment).
- **Effort:** S. **Verdict: Recommend.**

**H12. Validate before the `confirm_env` refusal**
- **Before:** two round trips.
  ```
  $ opv sync prod --deploy
  opv: policy denied: environment prod is guarded … Next: opv sync prod --deploy --confirm prod
  $ opv sync prod --deploy --confirm prod
  opv: policy denied: sync refused, nothing staged: api/DATABASE_URL …, api/LOG_LEVEL …, web/OPENAI_API_KEY …
  ```
- **After:** the read-only part (item read, list, validation) runs first. The guard gates only the first *write*: `sync refused, nothing staged: 3 keys blocking (…); prod is also guarded: add --confirm prod when you re-run`.
- **Who / journey:** experts and agents deploying safely. One message holds everything.
- **TRIZ:** contradiction: the guard must stop early (safety) and feedback must be complete (speed). **#10 Prior action**: do every harmless step before the guard, which still sits before the first write.
- **Pros:** fewer round trips, and still zero writes without `--confirm`.
- **Cons/risks:** an unconfirmed run now reads 1Password and the target (costs rate limit, writes nothing).
- **Effort:** S. **Verdict: Recommend.**

**H13. `confirm_env` engages only when the run would change something live**
- **Before:** `opv sync prod` with nothing to do still needs `--confirm prod`.
- **After:**
  - With nothing to write, deploy or prune: `nothing to do (guard not needed)`, exit 0.
  - Staging only, without `--deploy`: still guarded on Fly, because another tool's `fly deploy` would apply it. On Azure/K8s the write is invisible to the app, so make that configurable: `confirm_env = "deploy"` or `true`.
- **Who / journey:** experts and CI on guarded environments (safety against speed).
- **TRIZ:** **#15 Dynamics**: the guard's strength follows the actual effect.
- **Pros:** no friction on no-ops.
- **Cons/risks:** more rules to explain, and Fly staging risk. Default stays `true` (strict).
- **Effort:** S–M. **Verdict: Consider.**

**H14. `run --check`: refuse before the app starts when a key is not ready**
- **Before:** `opv run dev --product api -- npm run dev` with a missing key. Either `op run` fails with op's own message and its exit code (indistinguishable from the child's, since `run` returns the child's code), or the app starts and crashes on an undefined variable.
- **After:** `opv run dev --product api --check -- npm run dev`. It makes one item read (as `check` does) and, if anything blocks, prints check-style findings plus the H1 `open:` link and exits 8 before the app starts. Recommend it in package.json scripts.
- **Who / journey:** local run and onboarding a teammate.
- **TRIZ:** contradiction: fail fast (correctness) against no extra read (speed, rate limits). **#10 Prior action**, made optional (#15 Dynamics).
- **Pros:** shifts failure to the start with a fix-oriented message.
- **Cons/risks:** about 1 s and about 2 requests per run when enabled. Never the default under CI.
- **Effort:** S. **Verdict: Consider.** (Recommend if onboarding feedback shows crash-on-missing-var.)

**H15. Plan shows config diffs (names plus non-secret config values) on request**
- **Before:** plan cannot tell a reviewer that `LOG_LEVEL` goes `debug → info`.
- **After:** `opv plan prod --show-config` prints `config LOG_LEVEL: debug → info` for `kind = "config"` keys only, and only when both the field type check (text field) and the declared kind agree.
- **Who / journey:** reviewers approving a deploy.
- **TRIZ:** contradiction: maximum review context against SR-1. **#3 Local quality**: values appear only for the class that is already non-secret by design (`config export` prints them today), and only when asked.
- **Pros:** real review power.
- **Cons/risks:** a secret wrongly stored as a text field *and* declared config would print. That is the same exposure as `config export`. Opt-in only. Never on Fly, where config is not synced.
- **Effort:** M. **Verdict: Consider.**

**H16. `opv fill <env> <product/KEY>`: hidden-input entry for one key, validated before save**
- **Before:** a missing key means leaving the terminal (H1 helps). `setup` already has hidden input, rule checks and a single confirmed save, but only as a whole guided flow.
- **After:** `opv fill dev api/OPENAI_API_KEY` uses a hidden prompt (TTY only, refused for agents with `terminal_required`). The rule is checked *before* saving (`expected prefix sk-`), then saved through op on stdin, and `Next: opv check dev --product api`.
- **Who / journey:** humans adding or rotating a secret. It beats Doppler's `secrets set`, which cannot validate the shape.
- **TRIZ:** contradiction: read-only against 1Password (FR-11) against filling values in place. **#3 Local quality**: writes only through the TTY-gated owner path that `setup` already owns.
- **Pros:** reuses setup's code, and agents cannot use it.
- **Cons/risks:**
  - Widens the write surface beyond `setup` and `skeleton`, which needs an FR-11/SR-5 amendment.
  - It must never accept argv or piped values: refuse unless stdin is a TTY.
- **Effort:** M. **Verdict: Consider** (the owner decides FR-11 scope; H1 covers most of the need first).

**H17. `OPV_ENV`, a re-examination of rejected X3 (implicit default environment)**
- **Before:** X3 was rejected: "wrong-env footgun and one more rule".
- **After:** `export OPV_ENV=dev` sets a default for `check`, `run`, `explain`, `doctor`, `status` and `plan`, printed as `environment dev (from OPV_ENV)`. It is **never** used for `sync` or `item skeleton`, and refused when the environment sets `confirm_env`.
- **Who / journey:** daily local runs: `opv run -- npm run dev`.
- **TRIZ:** **#3 Local quality**. Implicitness is allowed only where a mistake is harmless (read or local) and is always announced. That removes the footgun half of the X3 reason, but not the "one more rule" half.
- **Pros:** mirrors `OPV_PRODUCT`, which already shipped.
- **Cons/risks:** hidden state, and a second implicit variable.
- **Effort:** S. **Verdict: Consider** (only after `OPV_PRODUCT` adoption is measured; keep X3's reasoning otherwise).

### S. Safety and consistency

**S1. One rule: `op said:` / `<program> said:` excerpts appear only under `--verbose`, and never when they contradict the diagnosis**
- **Before** (p1/login, default): `opv: authentication error: not signed in … op said: [ERROR] … "iprd" isn't an item in the "vprd" vault`. Here the raw excerpt and opv's diagnosis disagree. (The trigger was my stub, but it shows that raw provider text competes with the diagnosis.)
- **After:**
  - Default: the diagnosis and `Next:` only.
  - Under `--verbose`: `  op said (masked): …`.
  - Text-only diagnoses such as "isn't an item" are matched into codes (A2) so they drive the diagnosis instead.
- **Who / journey:** recovery from failure, and the secret-safety stance.
- **TRIZ:** contradiction: diagnostic depth against leak risk and clarity. **#3 Local quality** (verbose only) plus **#23 Feedback** (parse what you can).
- **Pros:** matches pass-1 P21's verdict ("Consider, verbose-only") and NR-22 as written.
- **Cons/risks:** loses some first-glance detail for Azure 403s. Mitigate by mapping common provider errors to codes.
- **Effort:** S. **Verdict: Recommend** (it reverses a default the integrated branch picked without a decision on record).

**S2. Don't retry a non-transient "not found"**
- **Before** (p1/login): `op item get failed; signed in with access to vault vprd, so retrying` / `retrying op item get (2/3)…(3/3)`, then `item iprd not found`. op's stderr literally says "isn't an item".
- **After:** classify op's stable "isn't an item" / "isn't a vault" stderr as Refused (no retry). Retry only when the item and vault are confirmed but the read failed.
- **Who / journey:** first-run typos.
- **TRIZ:** none.
- **Pros:** about 3 s faster, and no false "network" impression.
- **Cons/risks:** matching op's text is brittle. Fall back to retrying when the text is unrecognised.
- **Effort:** S. **Verdict: Recommend.**

**S3. Help examples must be agent-safe**
- **Before:**
  - `opv status prod || opv item skeleton prod` (status help, `src/main.rs:108`) runs a 1Password **write** on *any* non-zero exit, including 7 (auth) and 9 (unknown). That contradicts agent-setup rule 4.
  - `opv plan prod && opv sync prod --deploy` (plan help, `src/main.rs:115`) fails on a guarded prod.
- **After:**
  - `opv status prod; [ $? -eq 8 ] && echo "fill the missing fields (opv item skeleton prod adds them)"`, or drop the example.
  - `opv plan staging && opv sync staging --deploy`.
- **Who / journey:** agents copying examples.
- **TRIZ:** none.
- **Pros/cons:** text only.
- **Effort:** S. **Verdict: Recommend.**

**S4. One summary line, complete and the same on every provider**
- **Before:** `summary: written 0 · deployed yes · pruned 0 · pending 0 · unchanged 3 · skipped 0`. It omits `held` and `kept`, which the JSON has (`src/app/sync.rs:222-236`). It does not say *why* it deployed (here, names left pending by an earlier run). Docs show a comma-separated variant (`docs/usage.md` §Progress).
- **After:** `summary: written 0 · unchanged 3 · held 1 · deployed yes (3 pending from an earlier run) · pruned 0 · kept 0 · skipped 0`. Docs quote the exact line, and JSON gains `deploy_reason` and `deployed_names`.
- **Who / journey:** "did my change go live?"
- **TRIZ:** none.
- **Pros:** text and JSON agree.
- **Cons/risks:** golden churn (in the same pass as P2).
- **Effort:** S. **Verdict: Recommend.**

### Rejected ideas I considered

| ID | Idea | Why rejected |
|---|---|---|
| R1 | `opv secret set KEY=value` via argv or stdin pipe | SR-3 (argv), and it makes opv a value channel for agents. H16 (TTY-only) is the most that is acceptable |
| R2 | A new exit code for "needs a human" (for example 10 for A9) | Exit codes are the oldest contract. Category 6 plus `code: terminal_required` carries it without growing the table (A2) |
| R3 | A local history file of runs (`~/.opv/history.jsonl`) for audit | A state store in all but name (§7/§9) that is never shared across machines. H7 puts provenance on the target instead |
| R4 | Keyed digests of values in plan/status for Fly drift | Any stable digest of a value is a fingerprint (pass-1 bug 30). H6 compares versions and times instead |
| R5 | Auto-applying `Next:` (`opv … --fix`) | It blurs reading and writing, and the next step is often a human 1Password edit. A3's `Do:`/`Next:` split is the right granularity |
| R6 | Interactive TUI for status | Fails "no prompts" and agent parity. H4 delivers the scan gains in plain text |
| R7 | `--output yaml\|table\|tsv` (az style) | One JSON plus one text format is enough. Every format is another contract |
| R8 | Re-proposing X1 (TTY "are you sure?") | Still breaks FR-9. A7's `--expect-plan` and H12 address the risk without a prompt |
| R9 | Re-proposing X5 (short aliases) | Still rejected. Completions (static, shipped) give the speed. Dynamic env/key completion stays Consider (P13) |
| R10 | `opv run` with no env when only one environment exists | Still X3: a config change silently changes behaviour. H17 (explicit `OPV_ENV`, announced) is the only acceptable form |

---

## 3. The six highest-leverage changes for 0.5.0

1. **Merge the union of UX1, UX2, UX3 and login without regressions (section 0 and section 6).** Today each branch has its own `Next:` dialect, sign-in advice, enum text and first-run message. Shipping any single branch's state ships half of the approved work, and some of it backwards.
2. **A3 (`Do:` + runnable `Next:`) and H10 (specific next steps instead of `opv doctor`).** These make the most promised contract (NR-19, agent-setup rule 7) true. They are S effort and they touch every failure an agent sees.
3. **A1 + A2 (a JSON error envelope with stable codes).** Without it every `--json` consumer still parses prose on failure. Freeze it now, together with `sync --json`, so 0.5.0's machine contract is complete.
4. **A6 (one row shape and key order) before `sync --json` ships.** Once `sync --json` with bare target names and alphabetical keys is out, fixing it costs a schema bump.
5. **H12 + S3 + S4 (validate before the guard, safe examples, a complete summary).** These are the deploy-safely journey and the new `confirm_env` feature. All S effort, all user-visible on the first guarded deploy.
6. **H11 + S1 + S2 (an honest overview, verbose-only provider text, no retry on not-found).** These correct three outputs that currently mislead: a green overview hiding a broken `dev`, raw op text contradicting the diagnosis, and fake "retrying" on typos.

Runners-up for 0.5.0 if capacity allows: H9 (shorter help), A9 (hand-off), A10 (llms.txt contract block and fixing the stale exit-6 row).

## 4. The six highest-leverage changes for 0.6.0

1. **A4 `opv schema`.** The base for MCP, doc drift guards and zero-doc agent onboarding.
2. **A7 plan fingerprint and `--expect-plan`.** "Apply exactly what was reviewed" with no state. It upgrades the deploy-safely journey past terraform's for agents.
3. **H1 deep links and `opv open`, plus H2 `opv add` / `init --add-env`.** These fix the weakest journey (adding a secret) end to end without opv touching a value.
4. **H7 provenance stamps (Azure/K8s) and H6 version-based Fly sync detection.** Audit plus a clean plan, both stateless. Makes "what is out of sync" answerable everywhere.
5. **H8 CI: step summary, a `changes` field, an official Action.** Wiring CI is where Doppler and Infisical still win outright.
6. **H3 `init --target` for Azure/K8s, and H4 problems-first status.** First run and scanability for the providers 0.5.0 introduces.

Then 0.7.0 candidates: A8 MCP (on top of A1/A4/A7), H16 `fill` (if FR-11 scope is widened), H15 config diffs.

---

## 5. Answers to the specific questions

- **Is MCP a large win?** Not yet. With A1 (JSON errors), A4 (schema) and A7 (plan ids), a CLI-driving agent gets typed results, a closed error taxonomy and an approval token. That is about 80% of MCP's value with none of its process lifetime. Build MCP later as a thin wrapper. It stays secret-safe because no opv command returns a value, and the server leaves out `run`, `setup`, `login` and `skeleton`, and `sync` unless explicitly enabled.
- **`opv agent` mode?** No separate mode. Agent-friendliness should be the default contract: JSON envelope, `Do:`/`Next:`, `human_required`. A mode would split behaviour, and agents would then be tested on a path humans never use.
- **Idempotency and retry signals.** `sync` is idempotent by design (digest or value compare). Expose it as `retry: safe | after_fix | no` (A1). Exit 9 maps to `safe`, 2/6/8 to `after_fix`, and 5 after a failed health gate to `safe` (the old revision keeps serving).
- **llms.txt quality.** Good safety rules, but it lacks a machine contract and is version-skewed (it points to `main`). Fix with A10 and A4.

---

## 6. Bugs and inconsistencies in current output

Refs are to `opv-ux1` unless marked p1 or login.

**Contract violations (the `Next:` contract and JSON)**
1. Non-runnable `Next:` lines:
   - `fix the keys above in 1Password, then run opv status prod` (`src/app/status.rs:120-122` `fix_then`; `src/error.rs:278` default for Findings/Policy).
   - `sign in: eval $(op signin)` (auth default: the first indented line of the message, `src/error.rs:279-286`).
   - `opv explain api/DATABASE_URL --env prod (and likewise for each key above)` (`src/app/sync.rs:1149`).
2. Config and usage errors fall back to `Next: opv doctor`, which cannot fix them (`src/error.rs:287`). Seen for an unknown env, an unknown product, `--rotate` with an undeclared key, `explain` with a bare key, and `--product` required.
3. No JSON on failure. `--json` commands print nothing on stdout when they fail (every `--json` path).
4. `opv status --json` without an env is refused by clap (`src/main.rs:252-255`, `requires = "env"`), although `opv status` without an env is supported. `OPV_PRODUCT` is silently ignored by the overview, with no `product api (from OPV_PRODUCT)` line.
5. JSON key order differs. `check`, `sync` and `doctor` use alphabetical keys (`serde_json::json!` without `preserve_order`). `status` and `plan` use declared order. Shapes also differ: check rows have no `kind` and `findings` is top-level, against status's `totals.findings`.
6. `sync --json` arrays carry target names only, while the text carries `product/KEY (TARGET)`. There is no `deployed_names` or deploy reason (`src/app/sync.rs:254-274`).
7. p1/login: `Next step (config): …` is followed by `opv: configuration error: the config check failed …`, so `Next` is not the last line. Check and doctor print `opv: status findings: 1`, which names the wrong command (fixed in ux1; do not let the merge undo it).

**Wrong or misleading output**

8. The `opv status` overview prints `dev: run-only (no target)` and never reads run-only environments, so a broken `dev` is hidden and the exit is 0 (`src/app/status.rs:134-136`).
9. On Fly, `plan` after a clean deploy still says `3 to stage` and `potentially changed` and suggests a no-op `sync --deploy` (`src/app/sync.rs:1303-1314`; inherent until H6).
10. `plan` prints `would stage: …` while findings block the sync (exit 8). Make it `would stage once the findings are fixed: …`, or leave the line out.
11. `wrong kind` never says which way: stored as text against declared secret (status, plan, check, sync refusal).
12. ux1 still prints `failed enum (not one of the allowed values)`. P9's `expected one of: debug, info` exists only on p1/login.
13. The summary line omits `held` and `kept`, and does not say why a deploy happened when `written 0` (`src/app/sync.rs:222-236`). The usage.md example (`written 2, deployed yes, …`, commas) does not match the code's ` · ` format and still carries verify marker.
14. `check` prints its count twice: `1 finding(s); no deployment target checked` and then `opv: 1 finding` (`src/app/local.rs:106`). `(s)` plurals remain in `local.rs:106` and in doctor (`field(s)`, `environment(s)`, `key(s)`), while a `plural()` helper exists in `app/mod.rs`.
15. `confirm_env` is checked before validation, so a guarded env costs two round trips to learn about blocking keys (`src/app/sync.rs:150-167`).
16. ux1 with no config: `New project? Run opv setup.` and `Next: opv doctor`. The P3 router exists only on p1/login.
17. p1/login: a not-found item is still retried 3× after the diagnosis has confirmed vault access (`op item get failed; signed in with access to vault vprd, so retrying`). The item is missing, so the failure is not transient.
18. p1/login: `op said:` excerpts are on by default. That contradicts pass-1 P21 ("verbose-only") and NR-22's text, and can contradict opv's own diagnosis. In my run, opv said "not signed in" while op said "isn't an item" (stub-induced, but a real class of confusion).
19. `doctor`: `ok  op auth: signed in (unknown type)` prints when `whoami` has no `user_type` (`src/adapters/onepassword.rs:89`). Real op returns one; minor wording.
20. login: the no-TTY refusal from `opv login` and `opv setup` is exit 6 `policy denied` with no `Next:`, and does not tell an agent to hand the command to the user.
21. login: `init` refuses an existing `secrets.toml` (`init never merges`), so adding a second environment is a hand edit. agent-setup step 3 documents the hand edit as the workflow.

**Help and docs**

22. `opv status prod || opv item skeleton prod` (`src/main.rs:108`) is an unsafe example: it writes to 1Password on auth or unknown failures.
23. `opv plan prod && opv sync prod --deploy` (`src/main.rs:115`) fails on a `confirm_env` prod.
24. Every subcommand's `--help` repeats about 25 lines of global options in long form.
25. `docs/agent-setup.md` (login):
    - The exit 6 row lists only blocking keys; it misses `--confirm`, needs-terminal and config export.
    - Step 4 says `failing rule`, while the output says `failed <rule> (…)`.
    - `<!-- verify: init for azure/kubernetes -->` remains.
    - Step 3 tells agents to hand-edit additional environments.
26. `docs/usage.md` GitHub Actions example still pins `v0.3.0` and installs only `op`/`flyctl` (pass-1 item 6, still open).
27. `docs/usage.md` §Next step still describes doctor's `Next step (op auth):` spelling, which conflicts with the `Next:` contract once ux1 merges.
28. Fly config keys show `-` in the TARGET column with no explanation (`src/app/sync.rs:1305`). Only `explain` says `config: not a Fly secret`.

**Pass-1 items now resolved (verified):** Kubernetes Secret names no longer carry a value fingerprint (random id, `docs/configuration.md:183,209`). `drift_line` no longer says Key Vault (`src/app/sync.rs:743`). `target_name` sits beside `fly_name`. The explain column is aligned (`src/app/explain.rs:206`). `confirm_env` is implemented (ux1). Help has groups, examples, Docs and AI URLs, and completions (p1/login).
