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
        fleet.environments["prod"].boundaries["web"]
            .as_ref()
            .unwrap()
            .vault_id,
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
        crate::config::load(&path).unwrap().environments["prod"].boundaries["web"]
            .as_ref()
            .unwrap()
            .item_id,
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

#[test]
fn the_apply_record_is_written_beside_a_dot_opv_account_pointer() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".opv"), "account = \"A1\"\n").unwrap();
    let record = ApplyRecord {
        plan_id: "sp-0000000000000000".into(),
        contract_digest: digest(b"c"),
        bindings_digest: digest(b"b"),
    };
    assert!(write_record(&dir.path().join(APPLIED), &record).is_ok());
}

/// #304: a grant receipt table is a record beside the ids, not an unknown key.
#[test]
fn reader_accepts_a_grant_receipt_table() {
    let text = "environments.prod.boundaries.web.vault_id = \"vweb\"\n\
                [environments.prod.ci_reader.receipt]\n\
                schema = \"opv.grant-receipt/1\"\n\
                vaults = [{ id = \"vweb\", permissions = [\"read_items\"] }]\n";
    assert!(Bindings::parse(text).is_ok());
}

/// #304: a target's CI identity receipt is read back as its own table.
#[test]
fn a_target_receipt_is_read_as_its_table() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("secrets.bindings.toml"),
        "[environments.prod.targets.web.ci_identity.receipt]\nschema = \"s\"\n",
    )
    .unwrap();
    let text = super::read_receipt(&dir.path().join("secrets.toml"), "prod", Some("web"));
    assert_eq!(text.unwrap().as_deref(), Some("schema = \"s\"\n"));
}

// --- #304, FR-70: a CI identity's grant receipt beside its expiry -------------------

fn grant_receipt() -> crate::domain::grant_receipt::GrantReceipt {
    use crate::domain::grant_receipt::{GrantReceipt, IssuedBy, ReceiptVault, SCHEMA};
    GrantReceipt {
        schema: SCHEMA.into(),
        account_id: "ACC".into(),
        service_account_user_id: "USR".into(),
        service_account_name: "shop-prod-ci".into(),
        vaults: vec![ReceiptVault {
            id: "vweb".into(),
            permissions: vec!["read_items".into()],
        }],
        issued_at: "2026-11-11T10:24:11Z".into(),
        issued_by: IssuedBy::Create,
        expires_on: "2027-02-09".into(),
        contract_grants: format!("sha256:{}", "0".repeat(64)),
    }
}

const RECEIPT_PATH: &str = "environments.prod.ci_reader.receipt";

/// The bindings with an expiry and a receipt for the same CI reader, rendered.
fn rendered_with_receipt() -> String {
    let mut bindings = Bindings::parse(BINDINGS).unwrap();
    bindings.insert("environments.prod.ci_reader.expires_on", "2027-02-09");
    bindings.insert_receipt(RECEIPT_PATH, &grant_receipt());
    bindings.render()
}

#[test]
fn a_rendered_receipt_reads_back_as_the_same_receipt() {
    let read = Bindings::parse(&rendered_with_receipt()).unwrap();
    assert_eq!(read.receipt(RECEIPT_PATH), Some(Ok(grant_receipt())));
}

#[test]
fn a_rendered_receipt_keeps_the_expiry_beside_it() {
    let read = Bindings::parse(&rendered_with_receipt()).unwrap();
    assert_eq!(
        read.get("environments.prod.ci_reader.expires_on"),
        Some("2027-02-09")
    );
}

#[test]
fn a_malformed_receipt_still_loads_and_reads_as_invalid() {
    let text = "[environments.prod.ci_reader.receipt]\nschema = \"something-else\"\n";
    let read = Bindings::parse(text).unwrap();
    assert_eq!(
        read.receipt(RECEIPT_PATH),
        Some(Err(crate::domain::grant_receipt::Reason::ReceiptInvalid))
    );
}

#[test]
fn a_receipt_that_is_not_a_table_reads_as_invalid() {
    let text = "environments.prod.ci_reader.receipt = \"x\"\n";
    assert_eq!(
        Bindings::parse(text).unwrap().receipt(RECEIPT_PATH),
        Some(Err(crate::domain::grant_receipt::Reason::ReceiptInvalid))
    );
}

#[test]
fn a_receipt_that_is_not_a_table_survives_a_rewrite() {
    let text = "environments.prod.ci_reader.receipt = \"x\"\n";
    assert_eq!(Bindings::parse(text).unwrap().render(), text);
}

#[test]
fn rendering_bindings_without_a_receipt_is_unchanged() {
    assert_eq!(Bindings::parse(BINDINGS).unwrap().render(), BINDINGS);
}

#[test]
fn a_contract_loads_with_a_receipt_in_its_bindings_file() {
    let (_dir, path) = write(CONTRACT_WITHOUT_IDS);
    std::fs::write(
        path.with_file_name("secrets.bindings.toml"),
        rendered_with_receipt(),
    )
    .unwrap();
    assert!(crate::config::load(&path).is_ok());
}
