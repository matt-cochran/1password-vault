//! Tests for `opv init` (FR-23) in the one configuration form (FR-56, FR-57, FR-60). Every
//! fake item value contains [`MARKER`]; no marker may reach the written file, stdout, an
//! error or argv (SR-1, SR-3, SR-4).

use super::*;

// ---- One item, one boundary (FR-57) ----

// ---- Output ----

// ---- Lookups and refusals ----

// ---- Skipped fields ----

// ---- Status and other commands ----

// ---- Ancestor note ----

#[test]
fn no_ancestor_note_without_an_ancestor_file() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("x");
    fs::create_dir_all(&nested).unwrap();
    // Only meaningful when nothing above the temp dir holds a secrets.toml.
    if config::discover(dir.path()).is_none() {
        assert_eq!(ancestor_note(&nested), None);
    }
}

// ---- Targets: init writes none (FR-56, FR-60) ----

// ---- H2: `init <env> --add-env` adds one environment in the one form ----

// ---- FR-55: an item holding only personal keys is no environment boundary ----

// ---- A5: `init --json` ----

// ---- M6: `--add-env` and shared keys (FR-45) ----

/// Found live: `demo-app` beside `opv · demo-app` gave no hint which note held the values.
#[test]
fn the_default_item_reads_apart_from_the_manifest() {
    assert_eq!(default_item("demo-app", "dev"), "demo-app · dev values");
}

#[test]
fn the_default_vault_is_the_project_and_environment() {
    assert_eq!(default_vault("demo-app", "dev"), "demo-app-dev");
}

// ---- catalog steps (05.01, 05.07) ----

/// R2-4: a field the file does not hold came from opv's proposal.
#[test]
fn an_invalid_field_missing_from_the_file_is_marked_as_from_the_proposal() {
    let e = would_write(Some("[environments.dev]\n"))(
        config::parse("[environments.dev]\nbogus = 1\n").unwrap_err(),
    );
    assert!(matches!(
        e.cause(),
        Some((
            crate::cause::Cause::ConfigProposalInvalid {
                from_proposal: true,
                ..
            },
            _
        ))
    ));
}

/// R2-4: a field the file already holds is the file's own.
#[test]
fn an_invalid_field_already_in_the_file_is_not_from_the_proposal() {
    let file = "[environments.dev]\nbogus = 1\n";
    let e = would_write(Some(file))(config::parse(file).unwrap_err());
    assert!(matches!(
        e.cause(),
        Some((
            crate::cause::Cause::ConfigProposalInvalid {
                from_proposal: false,
                ..
            },
            _
        ))
    ));
}

#[test]
fn an_invalid_proposed_configuration_says_nothing_was_written() {
    // F2: text opv generated that fails validation is `ConfigProposalInvalid`.
    let e = would_write(None)(config::parse("[environments.dev]\nbogus = 1\n").unwrap_err());
    assert!(e.to_string().contains("nothing was written"), "{e}");
}
