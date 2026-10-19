# opv 0.13.0 CLI surface (lane `cli-surface`)

This lane owns `src/main.rs` and `tests/e2e/expected/surface.json`. It adds the 0.13 flags,
their handler wiring and a minimal library behind each, so the feature lanes change library
code only and never edit `main.rs` or the surface golden.

## `opv needs` (#175)

```
opv needs [<ENV>] [--product <p>] [--scan <DIR> | --names <FILE>] [--gate] [--json]
```

| Flag | Meaning |
|---|---|
| `<ENV>` (positional) | Only declared keys desired in this environment. Unknown: `unknown_env`. |
| `--product <p>` | Only this product's declared keys; rows no product owns (undeclared, ambiguous) stay. Unknown: `unknown_product`. |
| `--scan <DIR>` | Walk DIR on disk without git (`scan::DirTree`, `SKIP_DIRS` pruned, symlinks not followed); `file:line` is relative to DIR. Conflicts with `--names` (clap `ArgumentConflict`). |
| `--names <FILE>` | Names an assistant found itself, one per line (`-` = stdin; blank and `#` lines skipped). Each is an observation with no `file:line`. Unreadable: `input_unreadable` (new `InputKind::NamesFile`). |

Library (`src/app/needs.rs`):

```rust
pub enum NeedsInput { Git /* default */, Scan(PathBuf), Names(Vec<String>) }
pub struct NeedsOptions { pub env: Option<String>, pub product: Option<String>, pub input: NeedsInput }

pub fn run(r: &dyn CommandRunner, repo: &Path, fleet: &Fleet, options: &NeedsOptions,
           gate_on: bool, json: bool, out: &mut dyn Write) -> Result<(), Error>;
pub fn needs_with(runner: &dyn CommandRunner, repo: &Path, fleet: &Fleet, base: Option<&Fleet>,
                  options: &NeedsOptions) -> Result<NeedsReport, Error>;
pub fn parse_names(text: &str) -> Vec<String>;
pub fn read_names(path: &Path) -> Result<Vec<String>, Error>;   // `-` = stdin
```

`needs(runner, repo, tree, fleet, base)` is unchanged (used by `retire`). `main.rs` builds the
options in `needs_options(env, product, scan, names)` and calls `run`. MCP `opv_state`
section `needs` passes `NeedsOptions::default()` (git tree, no narrowing).

Minimal behaviour shipped here:

- Classification runs against the whole contract, then `narrow` drops rows: another
  product's (with `--product`), or a declared key not desired in `<ENV>`.
- A `--names` observation has an empty `file`; it adds no location, and an `ignore`
  annotation for it is treated as current (there is no source line to hash).
- A name outside the grammar or on the runtime list is counted in
  `coverage.skipped_patterns`, never echoed.

What the needs-input lane implements (library only):

- `ambiguous` meaning several products could own a name (today: a computed name).
- Ruby `ENV[]`, C `getenv`, files under the secrets directory (new `Pattern`s).
- A `declared` row with its value state; an `undeclared` row with a suggested declaration.
- MCP parity for `env`/`product`/`scan`/`names` on `opv_state` (build a `NeedsOptions` in
  `src/mcp.rs`; the type is the contract).

## `opv config check` (#178)

```
opv [--config <F0>] config check --file <F>
```

`main.rs` decides the project kind in `file_project_for_check(given_config, dir, file)`:

- `--config F0` given: file project F0.
- Else, with no `OPV_PROJECT` and no `.opv` found from here: the `secrets.toml` found from
  here is the file project when it is not F itself (a file regenerated elsewhere).
- Otherwise the manifest check, unchanged (`config_cmd::check`).

Library (`src/app/config_cmd.rs`):

```rust
pub fn check_file_project(project: &Path, file: &Path, r: &dyn CommandRunner,
                          out: &mut dyn Write) -> Result<(), Error>;
```

Minimal behaviour shipped here: F must load (parsed with the project's
`secrets.bindings.toml`, since a generator writes only the contract), then its `Fleet` must
equal the committed one: the project file, or its `git show HEAD:./<name>` copy when F is the
project file (regenerated in place; not committed is `config_unreadable`). Where each was
read from is ignored. Equal: one line, exit 0. Different: a text diff and `copies_differ`
(exit 2).

What the config-check-file lane implements (library only):

- Its own cause for a differing regenerated file: `copies_differ` renders "the 1Password
  manifest", which is wrong wording for a file project.
- `generated_by` reporting, and a validated declaration fragment (TOML and JSON) instead of a
  whole-file diff, including the error the file would raise.
- A test that a merged fragment makes `check` pass.

## Tests added

- `src/main.rs` (CLI parsing and plumbing): `needs_scan_and_names_are_mutually_exclusive`,
  `needs_takes_the_environment_as_a_positional`, `needs_product_reaches_the_library_options`,
  `needs_without_an_input_scans_the_git_tree`, `needs_scan_reaches_the_library_as_a_directory`,
  `needs_names_reaches_the_library_as_the_files_names`,
  `config_check_on_a_given_config_is_a_file_project`,
  `config_check_of_the_discovered_file_itself_stays_a_manifest_check`.
- `src/app/needs_tests.rs`: env and product narrowing, unknown env and product, `--scan`
  outside git, given names (undeclared, no location, grammar), names-file parsing and
  unreadable file.
- `src/scan/mod_tests.rs`: `DirTree` lists files outside git and prunes `SKIP_DIRS`.
- `src/app/config_cmd_tests.rs`: equivalent regenerated file passes, a different one is
  `copies_differ`, one that does not load prints nothing, in place outside git is
  `config_unreadable`.
