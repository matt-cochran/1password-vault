//! Tests for `secrets.bindings.toml`: the union-mergeable ids file, the inline-id refusal
//! and the apply record (D-G).

use super::{
    APPLIED, ApplyRecord, Bindings, digest, original_lines, read_record, split, write_record,
    write_sibling, write_split,
};

/// A minimal valid contract: one environment, one boundary (ids inline), one product whose
/// key lives in that environment.
const INLINE_CONTRACT: &str = r#"[environments.prod]
boundaries.web = { vault_id = "vweb", item_id = "iweb" }

[products.web]
boundary = "web"

[products.web.keys.API_KEY]
kind = "secret"
environments = ["prod"]
"#;

/// [`INLINE_CONTRACT`] with the boundary ids moved out: they come from the sibling bindings
/// file.
const CONTRACT_WITHOUT_IDS: &str = r#"[environments.prod]
boundaries.web = {}

[products.web]
boundary = "web"

[products.web.keys.API_KEY]
kind = "secret"
environments = ["prod"]
"#;

/// The sibling file for [`CONTRACT_WITHOUT_IDS`].
const BINDINGS: &str = "\
environments.prod.boundaries.web.item_id = \"iweb\"
environments.prod.boundaries.web.vault_id = \"vweb\"
";

fn write(text: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    std::fs::write(&path, text).unwrap();
    (dir, path)
}

#[test]
fn union_of_two_files_is_the_sorted_union() {
    let a = Bindings::parse("environments.prod.targets.web.state_vault_id = \"sweb\"\n").unwrap();
    let b = Bindings::parse("environments.prod.boundaries.web.vault_id = \"vweb\"\n").unwrap();
    assert_eq!(
        a.union(b).render(),
        "environments.prod.boundaries.web.vault_id = \"vweb\"\n\
         environments.prod.targets.web.state_vault_id = \"sweb\"\n"
    );
}

#[test]
fn writer_emits_the_sorted_canonical_form() {
    let mut b = Bindings::default();
    b.insert("environments.prod.targets.web.state_vault_id", "sweb");
    b.insert("environments.prod.boundaries.web.vault_id", "vweb");
    assert_eq!(
        b.render(),
        "environments.prod.boundaries.web.vault_id = \"vweb\"\n\
         environments.prod.targets.web.state_vault_id = \"sweb\"\n"
    );
}

#[test]
fn reader_refuses_an_unknown_key_naming_its_line() {
    let e = Bindings::parse("environments.prod.boundaries.web.nope = \"x\"\n").unwrap_err();
    assert!(
        e.to_string()
            .contains("environments.prod.boundaries.web.nope"),
        "{e}"
    );
}

#[test]
fn load_refuses_an_inline_boundary_vault_id_naming_its_field() {
    let (_dir, path) = write(
        "[environments.prod]\n\
         boundaries.web = { vault_id = \"vweb\" }\n",
    );
    let e = crate::config::load(&path).unwrap_err();
    assert!(
        e.to_string()
            .contains("environments.prod.boundaries.web.vault_id"),
        "{e}"
    );
}

#[test]
fn load_refuses_an_inline_state_vault_id_naming_its_field() {
    let (_dir, path) = write(
        "[environments.prod.targets.web]\n\
         fly.app = \"web-prod\"\n\
         state_vault_id = \"sweb\"\n",
    );
    let e = crate::config::load(&path).unwrap_err();
    assert!(
        e.to_string()
            .contains("environments.prod.targets.web.state_vault_id"),
        "{e}"
    );
}

#[test]
fn load_for_move_returns_the_inline_ids() {
    let (_dir, path) = write(INLINE_CONTRACT);
    let (_, ids) = crate::config::load_for_move(&path).unwrap();
    assert_eq!(
        ids.get("environments.prod.boundaries.web.vault_id"),
        Some("vweb")
    );
}

#[test]
fn load_with_a_bindings_file_gives_the_boundary_ids() {
    let (_dir, path) = write(CONTRACT_WITHOUT_IDS);
    std::fs::write(path.with_file_name("secrets.bindings.toml"), BINDINGS).unwrap();
    let fleet = crate::config::load(&path).unwrap();
    assert_eq!(
        fleet.environments["prod"].boundaries["web"].vault_id,
        "vweb"
    );
}

#[test]
fn apply_record_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(APPLIED);
    let record = ApplyRecord {
        plan_id: "01JPLAN".into(),
        contract_digest: digest(b"contract"),
        bindings_digest: digest(b"bindings"),
    };
    write_record(&path, &record).unwrap();
    assert_eq!(read_record(&path).unwrap(), Some(record));
}

#[test]
fn split_moves_the_ids_out_and_keeps_their_tables() {
    assert_eq!(
        split(INLINE_CONTRACT),
        (
            CONTRACT_WITHOUT_IDS.to_string(),
            Bindings::parse(BINDINGS).unwrap()
        )
    );
}

#[test]
fn split_records_no_empty_id() {
    let (_, ids) =
        split("[environments.prod]\nboundaries.web = { vault_id = \"\", item_id = \"\" }\n");
    assert!(ids.is_empty());
}

#[test]
fn merge_of_a_split_contract_writes_the_vault_before_the_item() {
    let (contract, ids) = split(INLINE_CONTRACT);
    assert_eq!(super::merge(&contract, &ids), INLINE_CONTRACT);
}

#[test]
fn no_ids_write_no_bindings_file() {
    let (dir, path) = write(CONTRACT_WITHOUT_IDS);
    write_sibling(&path, &Bindings::default()).unwrap();
    assert!(!dir.path().join(super::FILE).exists());
}

#[test]
fn a_written_configuration_loads_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    write_split(&path, INLINE_CONTRACT).unwrap();
    assert_eq!(
        crate::config::load(&path).unwrap().environments["prod"].boundaries["web"].item_id,
        "iweb"
    );
}

#[test]
fn a_line_merge_inserted_has_no_line_in_the_contract() {
    let contract = "[t]\na = 1\n\n[u]\nb = {}\n";
    let merged = "[t]\na = 1\nid = \"x\"\n\n[u]\nb = { id = \"y\" }\n";
    assert_eq!(
        original_lines(contract, merged),
        vec![Some(0), Some(1), None, Some(2), Some(3), Some(4)]
    );
}

/// An error in the contract names its line in `secrets.toml`, though the state vault id
/// filled in above it shifts the text `parse` sees by one line.
#[test]
fn a_contract_error_names_its_line_in_the_contract() {
    let (_dir, path) = write(
        "[environments.prod]\n\
         boundaries.web = {}\n\
         [environments.prod.targets.app]\n\
         fly.app = \"web-prod\"\n\
         [products.web.keys.API_KEY]\n\
         kind = \"secert\"\n\
         environments = [\"prod\"]\n",
    );
    std::fs::write(
        path.with_file_name("secrets.bindings.toml"),
        format!("{BINDINGS}environments.prod.targets.app.state_vault_id = \"sapp\"\n"),
    )
    .unwrap();
    let e = crate::config::load(&path).unwrap_err();
    assert!(e.to_string().contains(" at line 6, column "), "{e}");
}

/// An error about an id the bindings file holds names that file and the id's line.
#[test]
fn an_error_on_a_bound_id_names_the_bindings_file() {
    let (dir, path) = write(
        "[environments.prod]\n\
         boundaries.web = {}\n\
         [environments.prod.targets.a]\n\
         fly.app = \"a\"\n\
         fly.secret_name = \"{KEY}\"\n\
         [environments.staging]\n\
         boundaries.web = {}\n\
         [environments.staging.targets.a]\n\
         fly.app = \"b\"\n\
         fly.secret_name = \"{KEY}\"\n\
         [products.web.keys.API_KEY]\n\
         kind = \"secret\"\n\
         environments = [\"prod\", \"staging\"]\n",
    );
    std::fs::write(
        path.with_file_name("secrets.bindings.toml"),
        "environments.prod.boundaries.web.item_id = \"iweb\"\n\
         environments.prod.boundaries.web.vault_id = \"vweb\"\n\
         environments.prod.targets.a.state_vault_id = \"sone\"\n\
         environments.staging.boundaries.web.item_id = \"istg\"\n\
         environments.staging.boundaries.web.vault_id = \"vstg\"\n\
         environments.staging.targets.a.state_vault_id = \"sone\"\n",
    )
    .unwrap();
    let e = crate::config::load(&path).unwrap_err();
    let want = format!("{} at line 3,", dir.path().join(super::FILE).display());
    let shown = e
        .cause()
        .and_then(|(c, _)| c.do_text(&crate::cause::Invocation::default()));
    assert!(
        shown.as_ref().is_some_and(|d| d.contains(&want)),
        "{e} {shown:?}"
    );
}

/// A stale id, for a boundary the contract no longer declares, is left out: it does not
/// declare the boundary again.
#[test]
fn merge_skips_an_id_of_an_undeclared_boundary() {
    let ids = Bindings::parse(&format!(
        "{BINDINGS}environments.prod.boundaries.gone.vault_id = \"vgone\"\n"
    ))
    .unwrap();
    assert_eq!(
        super::merge(CONTRACT_WITHOUT_IDS, &ids),
        super::merge(CONTRACT_WITHOUT_IDS, &Bindings::parse(BINDINGS).unwrap())
    );
}
