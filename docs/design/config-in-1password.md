# Configuration in 1Password (FR-44)

Status: as built for 0.5.0.

Owner decision 2026-10-08, for 0.5.0: keep the complete configuration in 1Password and make
`secrets.toml` optional. The goal is a checkout that needs no file:

```sh
opv login dev
opv run dev -- npm run dev
```

## TRIZ notes

- **#24 Intermediary: same schema, new home.** The manifest is a Secure Note whose notes hold
  the exact TOML of `secrets.toml`. No new schema, no translation: `config::parse` validates
  both, `config import` then `config export --toml` is byte-identical, and every command loads
  a `Fleet` through one `ConfigStore` abstraction (`FileStore`, `ManifestStore`) that `add`,
  `init` and tidy-ups can also write through.
- **#2 Taking out: no file.** The file is taken out of the checkout, not out of the design. A
  repository finds its manifest by its git remote (`opv-repo:github.com|owner|repo` tag), a
  monorepo directory by a path tag (`opv-path:apps|api`), anything else by `.opv` or
  `OPV_PROJECT`. An existing `secrets.toml` still wins, so nothing changes until a team
  imports and deletes it.

## Discovery

First match wins:

1. `--config <file>` / `OPV_CONFIG`;
2. `OPV_PROJECT=<name>`: the manifest titled `opv · <name>`;
3. `secrets.toml` in the current directory or a parent (the v0.2 walk-up, unchanged);
4. `.opv` in the current directory or a parent: `project = "<name>"`, optionally
   `account = "<account>"`;
5. `git remote get-url origin`, normalized to `host/owner/repo` (https, ssh, scp-like; no
   user, password, port or `.git`), matched against repo tags. In a monorepo the manifest
   whose path is the longest whole-segment prefix of the current directory (relative to
   `git rev-parse --show-toplevel`) wins; a manifest without paths covers the whole repo at
   the lowest priority; a tie (for example at the root) lists the candidates and points to
   `OPV_PROJECT`.

Steps 2, 4 and 5 cost one `op item list --tags opv-manifest --format json` (metadata only).
Loading costs one `op item get` by IDs, before the environment's own item read.

### Tag escaping

1Password reads `/` in a tag as nesting, and `--tags` splits on `,`. Repo and path tags
therefore write `/` as `|`: `opv-repo:github.com|acme|myapp`, `opv-path:apps|api`. Segments
are limited to `[A-Za-z0-9._-]`, so neither `|` nor `,` can occur inside one and the encoding
round-trips. Tags are sent in the item JSON on stdin, never through `--tags`. (Live check
against a signed-in op 2.40 is an owner receipt; the fake `op` in the tests stores tags
verbatim.)

## The review trade-off

A committed file is reviewed in pull requests; a manifest is not. The counters:

- **Item history.** 1Password keeps every version of the item, with who changed it and when.
- **`opv config check --file secrets.toml`** exits 8 with a diff when a committed copy differs,
  so a team that wants PR review keeps a copy in the repo and checks it in CI.
- **`opv config export --toml`** prints the configuration at any time (no secrets), to diff,
  archive or commit.
- **`opv config edit`** shows the diff and asks once before saving, and refuses when someone
  else saved in the meantime (it re-reads the item version just before writing; op has no
  conditional write, so only the moment between that read and the write is uncovered).

## Many projects

- `opv projects [--long] [--json]` lists every visible manifest: one metadata listing per
  account op knows; `--long` reads each manifest once for its environment names.
- `opv status --all [--json]`: the per-environment overview of every project; one manifest
  read per project plus the overview's reads. A project that cannot be read is one line with
  its reason; the rest still run.

## Secrecy

The manifest holds names, IDs and rules, never a value. Its text goes to `op` on stdin; argv
carries fixed words, IDs, the vault and the account. The git remote URL can carry a token: it
is parsed in memory and only `host/owner/repo` is kept or printed. `config edit`'s temporary
copy is created with mode 0600 and removed afterwards.
