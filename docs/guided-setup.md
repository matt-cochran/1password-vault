# Guided local setup

Start in your project:
```sh
opv session
opv setup
opv check dev --product api
opv run dev --product api -- npm run dev
```

When the project's configuration lives in 1Password (a manifest, see [configuration](configuration.md#configuration-in-1password)), a checkout needs no file: sign in and run. `opv doctor` names the configuration it found on its `config` line.

`session` signs in at 1Password's own prompts and opens a terminal with the session available. Type `exit` to leave it. No export commands or token copying are needed. Desktop integration can provide authentication without a session token. Use `--account` when you have several accounts, or `opv session -- <command>` for one command.

`setup` finds `opv.setup.toml` in your current directory or its parents. It explains each setting, where to find it, and how to finish later. Several products produce a numbered choice; `--product NAME` selects directly. Filled values are kept. Enter skips a missing value. One final confirmation saves progress in 1Password; rerun the same command to resume.

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

A missing vault requires creation in the 1Password app, or selecting the account that owns it; setup does not guess where to store credentials. Duplicate titles require a rename. An existing item must be a Secure Note. Wrong field types require changing the field to Password/concealed or Text, keeping its value. A conflicting configuration is left intact: review it or choose a separate `--config PATH`.

## Existing local settings

A recipe may declare `legacy_env = "~/.config/platform/r2.env"`. Setup offers to copy only missing declared settings after your confirmation. It accepts literal assignments, including single-quoted multiline values, and never executes the file. On Unix, the original must be private to its owner. Shell expressions, duplicate keys, symlinks and files above 1 MiB are refused; setup continues with private prompts. A recipe importing a file must cover at most one product.

Multiline settings need the exact full value from that private file, or entry in the 1Password app. Setup never replaces encryption configuration or generates new credentials. The original file remains intact.

## Recovery and readiness

Partial setup exits 8 and lists the remaining settings by their human names. Cancellation exits 6 without saving. Successful saving does not prove provider permissions: `check` validates declared kinds and rules; the application or owner provisioning command verifies actual access. Saved progress survives an expired sign-in.

These commands require an owner terminal and refuse CI, service-account and Connect authentication. Existing `init`, `doctor`, `check`, `run`, `status`, `plan`, `sync`, `config export`, `item skeleton` and `explain` remain noninteractive. Deployment, rotation and pruning retain their explicit flags.

