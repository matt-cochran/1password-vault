//! `run --product` reads and names only its own keys (#263, FR-57), and keeps a declared
//! infrastructure name the parent environment carries (#264, D4-B). Design:
//! `docs/design/product-scoped-run.md` §2 and §6 (T7-T17, T22-T24).
//!
//! Every test holds `tidy::activate()`: without it a unit test skips the read, and every
//! "names no X" assertion would pass vacuously. Each negative test has its positive partner
//! on the same fixture. The tests for rule 3 (one print site) run on both paths: a person's
//! run that tidies a messy item, and one whose item is already tidy.

use serde_json::Value;

use super::*;
use crate::app::tidy::activate;
use crate::app::tidy::tests::{F, FakeOp, MARKER, item};

/// One boundary `acceptance` (item `idev`) holding two products in `prod`: `input` with A
/// and B, `output` with X and Y.
const CORE: &str = r#"
[environments.prod]
boundaries.acceptance = { vault_id = "vdev", item_id = "idev" }

[products.input]
boundary = "acceptance"

[products.input.keys.A]
kind = "secret"
environments = ["prod"]

[products.input.keys.B]
kind = "secret"
environments = ["prod"]

[products.output]
boundary = "acceptance"

[products.output.keys.X]
kind = "secret"
environments = ["prod"]

[products.output.keys.Y]
kind = "secret"
environments = ["prod"]
"#;

/// `output`'s infrastructure key Z. The load requires a target for it; `run` never reads
/// the target.
const INFRA: &str = r#"
[environments.prod.targets.web]
fly.app = "web-prod"
fly.secret_name = "{KEY}"
products = ["output"]
state_vault_id = "sprod"

[products.output.keys.Z]
kind = "secret"
source = "infrastructure"
environments = ["prod"]
rules = { regex = "z-.+" }
"#;

/// The fixture of the design's test plan (§6): [`CORE`] and [`INFRA`], plus `extra`.
fn fleet_with(extra: &str) -> Fleet {
    crate::config::parse(&format!("{CORE}\n{INFRA}\n{extra}")).unwrap()
}

fn base() -> Fleet {
    fleet_with("")
}

/// The base fleet with `output` in a boundary item of its own (`iout`).
fn split() -> Fleet {
    crate::config::parse(&format!(
        "{}\n{INFRA}",
        CORE.replace(
            "boundaries.acceptance = { vault_id = \"vdev\", item_id = \"idev\" }",
            "boundaries.acceptance = { vault_id = \"vdev\", item_id = \"idev\" }\n\
                 boundaries.out = { vault_id = \"vdev\", item_id = \"iout\" }",
        )
        .replace(
            "[products.output]\nboundary = \"acceptance\"",
            "[products.output]\nboundary = \"out\"",
        )
    ))
    .unwrap()
}

/// `input` also reads `shared/K` with `from` (FR-45).
fn with_source() -> Fleet {
    fleet_with(
        "[products.shared]\nboundary = \"acceptance\"\n\
         [products.shared.keys.K]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\
         [products.input.keys.S]\nkind = \"secret\"\nenvironments = [\"prod\"]\nfrom = \"shared/K\"\n",
    )
}

/// `input` also holds one key for each of two roles (#136).
fn with_roles() -> Fleet {
    fleet_with(
        "[products.input.keys.R_SERVE]\nkind = \"secret\"\nenvironments = [\"prod\"]\nroles = [\"serve\"]\n\
         [products.input.keys.R_MIGRATE]\nkind = \"secret\"\nenvironments = [\"prod\"]\nroles = [\"migrate\"]\n",
    )
}

/// A reviewed remote profile for `input` (#139).
const REMOTE: &str = r#"
[products.input.remotes.builder]
host = "builder.example.internal"
user = "dev"
host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestMarkerHostKeyNotARealKey263"
opv = "/usr/local/bin/opv"
workdir = "/home/dev/src/app"
command = ["cargo", "run"]
environments = ["prod"]
"#;

/// [`CORE`] with [`REMOTE`]. A profile may name only an environment with no target (O9), so
/// this fleet has no infrastructure key.
fn with_remote() -> Fleet {
    crate::config::parse(&format!("{CORE}\n{REMOTE}")).unwrap()
}

/// Which path a person's run takes through the read.
#[derive(Clone, Copy)]
enum Path {
    /// The item is messy (B outside its section): the read tidies it.
    Tidy,
    /// The item is laid out by the convention: nothing to write.
    NonTidy,
}

/// The item: A and B filled (B emptied by `empty`), X and Y empty, plus `more` fields,
/// with every field in its section unless `path` is [`Path::Tidy`].
fn item_for(path: Path, empty: &[&str], more: &[F<'_>]) -> Value {
    let value = |k: &str, v: &'static str| if empty.contains(&k) { "" } else { v };
    let b_section = match path {
        Path::Tidy => "",
        Path::NonTidy => "input",
    };
    let mut fields: Vec<F<'_>> = vec![
        ("input", "A", "CONCEALED", value("A", "a-TIDYMARKER")),
        (b_section, "B", "CONCEALED", value("B", "b-TIDYMARKER")),
        ("output", "X", "CONCEALED", ""),
        ("output", "Y", "CONCEALED", ""),
    ];
    fields.extend_from_slice(more);
    fields.push(("opv", "convention", "STRING", "1"));
    item(&fields)
}

fn cmd() -> Vec<String> {
    vec!["app".to_string()]
}

/// Runs `product` (with `role`) on `fleet` as a person, against `item`.
fn run_as_person(fleet: &Fleet, product: &str, role: Option<&str>, item: Value) -> FakeOp {
    let op = FakeOp::person(item);
    let _on = activate();
    let _ = run_with_role(fleet, "prod", product, role, &cmd(), &op);
    op
}

fn run_input(item: Value) -> FakeOp {
    run_as_person(&base(), "input", None, item)
}

/// The "still needs a value" note, or "" when there is none.
fn needs_note(op: &FakeOp) -> String {
    op.notes
        .borrow()
        .iter()
        .find(|n| n.starts_with("still needs a value"))
        .cloned()
        .unwrap_or_default()
}

/// The `product/KEY` labels the "still needs a value" note names.
fn named(op: &FakeOp) -> Vec<String> {
    let note = needs_note(op);
    let Some((_, rest)) = note.split_once("): ") else {
        return Vec::new();
    };
    let list = rest.split(". Open it with").next().unwrap_or_default();
    list.split(", ").map(str::to_string).collect()
}

/// The D4-B note lines.
fn inherit_notes(op: &FakeOp) -> Vec<String> {
    op.notes
        .borrow()
        .iter()
        .filter(|n| n.starts_with("taken from the environment as given"))
        .cloned()
        .collect()
}

// ---- #264: the producer starts ---------------------------------------------------------

#[test]
fn run_input_starts_the_child_when_only_output_keys_are_empty() {
    let op = FakeOp::person(item_for(Path::NonTidy, &[], &[]));
    let _on = activate();
    let started = run(&base(), "prod", "input", &cmd(), &op).map(|_| op.count(&["run", "--"]));
    assert_eq!(started.ok(), Some(1));
}

#[test]
fn run_input_references_only_input_keys() {
    let op = run_input(item_for(Path::NonTidy, &[], &[]));
    let mut names: Vec<String> = op
        .child_env
        .borrow()
        .iter()
        .map(|(k, _)| k.clone())
        .filter(|k| k != super::OUTER_VAR)
        .collect();
    names.sort();
    assert_eq!(names, ["A", "B"]);
}

// ---- #263: the note names only the run's own keys --------------------------------------

#[test]
fn run_input_names_no_output_key_as_needing_a_value() {
    let op = run_input(item_for(Path::NonTidy, &["A"], &[]));
    assert!(!op.notes().contains("output/"), "{}", op.notes());
}

#[test]
fn run_input_names_its_own_empty_key() {
    let op = run_input(item_for(Path::NonTidy, &["A"], &[]));
    assert!(needs_note(&op).contains("input/A"), "{}", op.notes());
}

#[test]
fn run_input_prints_no_needs_value_line_when_its_keys_are_filled() {
    let op = run_input(item_for(Path::NonTidy, &[], &[]));
    assert!(
        !op.notes().contains("still needs a value"),
        "{}",
        op.notes()
    );
}

#[test]
fn run_never_names_an_infrastructure_key_as_needing_a_value() {
    let op = run_as_person(&base(), "output", None, item_for(Path::NonTidy, &[], &[]));
    assert!(!needs_note(&op).contains("output/Z"), "{}", op.notes());
}

#[test]
fn run_output_names_its_empty_stored_key() {
    let op = run_as_person(&base(), "output", None, item_for(Path::NonTidy, &[], &[]));
    assert!(needs_note(&op).contains("output/X"), "{}", op.notes());
}

#[test]
fn the_needs_value_note_names_only_referenced_keys() {
    let op = run_input(item_for(Path::NonTidy, &["A", "B"], &[]));
    let referenced = ["input/A", "input/B"];
    let names = named(&op);
    assert!(
        !names.is_empty() && names.iter().all(|n| referenced.contains(&n.as_str())),
        "{names:?}"
    );
}

#[test]
fn the_needs_value_note_holds_no_value() {
    let op = run_input(item_for(Path::Tidy, &["A"], &[]));
    assert!(!op.notes().contains(MARKER), "{}", op.notes());
}

#[test]
fn run_input_does_not_read_a_separate_sibling_boundary() {
    let op = run_as_person(&split(), "input", None, item_for(Path::NonTidy, &[], &[]));
    assert_eq!(op.count(&["item", "get", "iout"]), 0);
}

#[test]
fn run_input_reads_its_own_boundary() {
    let op = run_as_person(&split(), "input", None, item_for(Path::NonTidy, &[], &[]));
    assert_eq!(op.count(&["item", "get", "idev"]), 1);
}

#[test]
fn a_remote_run_names_no_output_key() {
    let op = FakeOp::person(item_for(Path::NonTidy, &["A"], &[]));
    let _on = activate();
    let _ = run_remote(&with_remote(), "prod", Some("input"), None, "builder", &op);
    assert!(!op.notes().contains("output/"), "{}", op.notes());
}

/// A sanity check of the tidy-path fixture: the read writes the item once.
#[test]
fn the_tidy_path_fixture_is_tidied() {
    let op = run_input(item_for(Path::Tidy, &[], &[]));
    assert_eq!(op.edits(), 1);
}

/// Rule 3: these run on both paths, so the tidy and the non-tidy path cannot disagree.
macro_rules! on_both_paths {
    ($($path:ident: $p:expr;)*) => {$(
        mod $path {
            use super::*;

            const PATH: Path = $p;

            #[test]
            fn run_names_an_empty_from_source_of_a_selected_key() {
                let item = item_for(PATH, &[], &[("shared", "K", "CONCEALED", "")]);
                let op = run_as_person(&with_source(), "input", None, item);
                assert!(needs_note(&op).contains("shared/K"), "{}", op.notes());
            }

            #[test]
            fn run_skips_a_role_withheld_empty_key() {
                let more = [
                    ("input", "R_SERVE", "CONCEALED", ""),
                    ("input", "R_MIGRATE", "CONCEALED", ""),
                ];
                let op = run_as_person(&with_roles(), "input", Some("serve"), item_for(PATH, &[], &more));
                assert!(!op.notes().contains("input/R_MIGRATE"), "{}", op.notes());
            }

            #[test]
            fn run_names_an_empty_key_of_the_selected_role() {
                let more = [
                    ("input", "R_SERVE", "CONCEALED", ""),
                    ("input", "R_MIGRATE", "CONCEALED", ""),
                ];
                let op = run_as_person(&with_roles(), "input", Some("serve"), item_for(PATH, &[], &more));
                assert!(needs_note(&op).contains("input/R_SERVE"), "{}", op.notes());
            }

            #[test]
            fn run_prints_the_needs_value_note_once() {
                let op = run_input(item_for(PATH, &["A"], &[]));
                let lines = op.notes.borrow().iter().filter(|n| n.starts_with("still needs a value")).count();
                assert_eq!(lines, 1, "{}", op.notes());
            }
        }
    )*};
}

on_both_paths! {
    tidy_path: Path::Tidy;
    non_tidy_path: Path::NonTidy;
}

// ---- D4-B: a declared infrastructure name is the parent environment's to carry ---------

#[test]
fn run_keeps_an_inherited_infrastructure_name() {
    let _parent = parent_env(&["Z"]);
    let op = run_input(item_for(Path::NonTidy, &[], &[]));
    assert!(!op.removed.borrow().contains(&"Z".to_string()));
}

#[test]
fn run_still_clears_an_inherited_stored_name() {
    let _parent = parent_env(&["X"]);
    let op = run_input(item_for(Path::NonTidy, &[], &[]));
    assert!(op.removed.borrow().contains(&"X".to_string()));
}

#[test]
fn run_names_an_inherited_infrastructure_name_once() {
    let _parent = parent_env(&["Z"]);
    let op = run_input(item_for(Path::NonTidy, &[], &[]));
    assert_eq!(
        inherit_notes(&op),
        [
            "taken from the environment as given (supplied at sync, never stored in \
          1Password): output/Z"
        ]
    );
}

#[test]
fn run_prints_no_inherit_note_without_one() {
    let _parent = parent_env(&[]);
    let op = run_input(item_for(Path::NonTidy, &[], &[]));
    assert!(inherit_notes(&op).is_empty(), "{}", op.notes());
}
