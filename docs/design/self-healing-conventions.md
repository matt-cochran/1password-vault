# Self-healing 1Password conventions (FR-43)

Decided 2026-10-08 for 0.5.0. Requirement: [FR-43](requirements.md#fr-43--self-healing-conventions).

## Problem

opv's convention is vault → item → section `<product>` → field `<KEY>`, concealed = secret,
text = config (the simple profile: unsectioned fields). Before 0.5.0 a field in the wrong
section, a label spelled `openai api key`, a secret saved as text or a duplicate label was an
error. People lay items out by hand in the 1Password app, so these errors were common, and each
one blocked every command until the person fixed the item themselves.

The owner's decision: users never get errors because 1Password is not laid out the way opv
expects. opv fixes the layout itself, never deletes information, and hides the convention.

## The contradiction

opv must change the item (so the next read is clean) and must not change it (CI holds a
read-only service account, FR-11 and SR-5, and a tidy must never lose a value). Three TRIZ
principles resolve it.

### #3 Local quality: tolerant reads

The reader adapts to the item instead of the item to the reader. `domain::convention::resolve`
finds each declared key wherever its field is:

- labels match ignoring case, spaces, `-` and `_` (`openai api-key` is `OPENAI_API_KEY`);
- a field at the top level, in a section spelled differently (`API` for `api`) or in a
  human-named section (`Secrets`, `API keys`) is found;
- a secret stored as text and config stored as concealed are read under the declared kind;
- of several candidates, the choice is deterministic: a filled field in the right section, then
  any filled field, then an empty field in the right section, then any empty field; ties go to
  the field later in the item. 1Password exposes no per-field edit time, and it lists newer
  fields later, so "later" stands in for "most recently edited". An empty field never shadows a
  filled one (a field created empty by a tidy must not hide the value a person put elsewhere).

Two guards keep the reader from taking what is not its own:

- a field in a **product-shaped** section (`^[a-z][a-z0-9_-]*$`) belongs to that product, which
  may be managed by another `secrets.toml` sharing the item, so it is never claimed for a
  different product (the simple profile has no products and searches every section);
- a field two declared keys could both claim (`TOKEN` at the top level, declared by `a` and `b`)
  is left alone.

Values are normalized in memory, by the same rule the tidy uses (below), so a service account
and a person read the same value.

### #1 Segmentation by identity

Who runs opv decides whether 1Password may change:

| Identity | How it is detected | 1Password |
| --- | --- | --- |
| Signed-in person | `op whoami` reports `user_type` `USER` | tidied |
| Service account | `OP_SERVICE_ACCOUNT_TOKEN` set, or `whoami` says `SERVICE_ACCOUNT` | read-only, one note |
| Connect | `OP_CONNECT_HOST` / `OP_CONNECT_TOKEN` set | read-only, one note |
| CI | `CI` set (truthy) | read-only, one note |
| Unknown | `whoami` fails or cannot be parsed | read-only, silent |

A token or CI decides without a call. `whoami` is the existing diagnosis probe (free under rate
limits, D0); only `user_type` is parsed. It runs only when the item actually needs a tidy, so a
conventional item still costs exactly one read.

### #24 Intermediary: the archive section

Every displaced or replaced thing goes to section `opv · kept` instead of being removed:

- a duplicate field is moved there, labelled `<original label> (from <section>, <UTC date>)`,
  concealed if it belonged to a secret;
- a normalized value's original is added there as a concealed field;
- a renamed label leaves an empty breadcrumb `<old label> (renamed to <product/KEY>, <date>)`.

Nothing is ever deleted, and the archive is never read as a key. A person can review and empty
it whenever they like.

## The tidy plan

`domain::convention::plan` is pure (no `op`, no clock: the date is an argument). It returns
`Op`s (relabel a section, place a field, set a value, add a field) and the names-only `Change`s
reported to the user:

- create missing product sections and missing fields (keys declared for this environment,
  mode-skipped ones included, like `item skeleton`), empty and of the right kind;
- conceal a secret stored as text; never the reverse (config kept concealed is accepted);
- rename a label to the key; relabel a product section spelled differently;
- move a field home (into its product section, or to the top level under the simple profile);
- move duplicates to `opv · kept`;
- normalize a value only when the key's rules make the intended form unambiguous: a trailing
  newline/CR/space is removed only when the value fails its rules and the trimmed value passes;
  a missing `ensure_prefix` is added when the result passes. Keys with a `transform` are never
  normalized;
- add `opv/convention = 1` (text) for future migrations, only together with another fix, so an
  already-tidy item is never written just for the marker.

Applying the plan to the item JSON (`adapters::onepassword_tidy::apply`) never removes a field
or a section. Field indices stay valid because nothing is removed.

## Safe writes

1. Read the item once (FR-13) and plan.
2. Read it again just before writing. If its `version`/`updated_at` changed, someone edited it:
   re-plan on the new version, once. If it changed again, write nothing and say so.
3. Write the whole item with one `op item edit <item> --vault <vault> --format json`, the JSON
   on stdin (SR-3), from `Zeroizing` buffers. This is the `item skeleton` invocation proven in
   D0. One edit is atomic: an interrupted write leaves the item untouched or fully tidied, and
   the archive is part of the same edit, so it can never be lost half-way.
4. Re-read and re-plan to verify; a non-empty plan prints a note (the next run finishes it).

A failed tidy (no write access, an unknown outcome, an item edited twice meanwhile) prints one
note and the command goes on with the tolerant read. It never fails the command.

The check read narrows, but cannot close, the window between the check and the edit: `op` has
no conditional write. The window is the duration of one local `op` call.

## Where it hooks in

- `app::tidy::read` replaces the strict item read in `status`, `plan`, `sync`, `check`,
  `config export` and `doctor --env`; `run` calls it first and references a field that is
  still misplaced (a read-only run) by field ID, `op://<vault>/<item>/<field id>`.
- `setup` applies the plan to the item it is about to save (saved only after the owner
  confirms); `init` creates a missing vault or item for a person and tidies the item it
  declared.
- Output: one stderr line per run that tidied
  (`tidied 1Password (dev): created section api; made api/OPENAI_API_KEY concealed; kept old copies in "opv · kept"`),
  one line naming keys that still need a value, and a `tidy` array of `{action, name}` in
  `status --json`, `plan --json` and `check --json` when something was tidied.

## Not done

- No per-field edit time is available from `op`; item order stands in for it.
- `item skeleton` keeps its strict reader: it is the explicit, any-identity write command.
- Field links in the "still needs a value" line wait for the `opv://` link work (U6).
