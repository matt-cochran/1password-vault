# Guided local setup

For a project that ships an `opv.setup.toml` recipe, `opv setup` walks a person through every setting: where it comes from, private input, progress saved in 1Password. Start in your project:
```sh
opv login dev
opv setup
opv check dev --product api
opv run dev --product api -- npm run dev
```

When the project's configuration lives in 1Password (a manifest, see [configuration](configuration.md#configuration-in-1password)), a checkout needs no file: sign in and run. `opv doctor` names the configuration it found on its `config` line.

`opv login dev` signs in to the 1Password account the `dev` environment uses (its `account` setting) at 1Password's own prompts, and opens a terminal with the session available. Type `exit` to leave it. No export commands or token copying are needed, and no token is printed. Desktop integration can provide authentication without a session token. `opv login` without an environment signs in to the one account all environments use, or asks which environment when they use different accounts; before `secrets.toml` exists it uses your default account. `opv login dev -- <command>` runs one command signed in and returns its exit code.

Sessions for environments in different accounts coexist in one terminal, and every command uses the account of the environment it acts on ([usage](usage.md#sign-in-opv-login)).

`setup` finds `opv.setup.toml` in your current directory or its parents. It explains each setting, where to find it, and how to finish later. Several products produce a numbered choice; `--product NAME` selects directly. Filled values are kept. Enter skips a missing value. One final confirmation saves progress in 1Password; rerun the same command to resume. If someone changed the item in 1Password while setup was open, setup does not overwrite it: it reads the item again, keeps what is there, fills only the settings still empty with what you already entered (without asking for it again), tells you, and asks once more before saving.

A project maintainer checks in the recipe once. It contains instructions and names only:
```toml
title = "API development"
environment = "dev"
vault = "Development"
item = "api-local"
output = "secrets.toml"

[[fields]]
product = "api"
key = "API_KEY"
title = "Provider login"
description = "Lets the API call its provider."
source = "Your provider dashboard → API keys."
```

Omit every `product` for a single app. All fields must consistently use sections or be unsectioned. Optional field properties are `kind = "config"` (default secret), `immutable = true`, `multiline = true`, and `rules` using the existing configuration rule format. The resulting configuration declares every recipe product so local execution can clear other products' managed variables.

A missing vault requires creation in the 1Password app, or selecting the account that owns it; setup does not guess where to store credentials. Duplicate vault or item titles require a rename. An existing item must be a Secure Note. You don't need to lay the existing item out by hand: setup tidies it to opv's layout (it conceals secrets saved as text, renames and moves fields, sets duplicates aside in a section named `opv · kept`, and deletes nothing), says what it changed, and saves the tidy with your progress only after you confirm. A conflicting configuration is left intact: review it or choose a separate `--config PATH`.

## Adding a setting later

Declare a new key without editing `secrets.toml` by hand, then add its empty field to the item and fill it:
```sh
opv add api/STRIPE_KEY --kind secret --env dev --rule prefix=sk_
opv item skeleton dev
opv check dev --product api
```

`opv add` edits the configuration where it lives (a `secrets.toml`, or the manifest in 1Password), keeps comments and order, validates the result like a hand-written file and never reads the item. Add the key to the recipe's `[[fields]]` too, so the next person's `opv setup` asks for it. `opv init <env> --vault … --item … --add-env` adds another environment the same way. See [configuration.md](configuration.md#declare-a-key-opv-add).

## Existing local settings

A recipe may declare `legacy_env = "~/.config/platform/r2.env"`. Setup offers to copy only missing declared settings after your confirmation. It accepts literal assignments, including single-quoted multiline values, and never executes the file. On Unix, the original must be private to its owner. Shell expressions, duplicate keys, symlinks and files above 1 MiB are refused; setup continues with private prompts. A recipe importing a file must cover at most one product.

Multiline settings need the exact full value from that private file, or entry in the 1Password app. Setup never replaces encryption configuration or generates new credentials. The original file remains intact.

## Recovery and readiness

Partial setup exits 8 and lists the remaining settings by their human names. Cancellation exits 6 without saving. Successful saving does not prove provider permissions: `check` validates declared kinds and rules; the application or owner provisioning command verifies actual access. Saved progress survives an expired sign-in.

These commands require an owner terminal and refuse CI, service-account and Connect authentication. Existing `init`, `doctor`, `check`, `run`, `status`, `plan`, `sync`, `config export`, `item skeleton` and `explain` remain noninteractive; when you run them signed in as yourself they also tidy the item's layout the same way, with one line saying what changed, and under CI or a service account they only read. Deployment, rotation and pruning retain their explicit flags.

