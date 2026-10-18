//! One behaviour per test for the assistant's local import (design row `import-local`).

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::domain::health::EnvValues;
use crate::domain::{ItemField, KeyState, Kind, Row, SecretValue, TargetState};

const MARK_NEW: &str = "sk-proj-LOCALMARK-new";
const ITEM: &str = "vdev0000000000000000000001";

/// A dev environment declared `local`, with api/OPENAI_API_KEY (secret, empty) and
/// api/LOG_LEVEL (config, empty), on the fake's `myapp-dev` vault.
fn local_world() -> (FakeOp, Fleet, tempfile::TempDir) {
    let op = FakeOp::default();
    let id = op.insert(
        ITEM,
        serde_json::json!({
            "title": "myapp · dev values", "category": "SECURE_NOTE",
            "sections": [{"id": "api", "label": "api"}],
            "fields": [
                {"id": "f1", "section": {"id": "api", "label": "api"}, "type": "CONCEALED", "label": "OPENAI_API_KEY", "value": ""},
                {"id": "f2", "section": {"id": "api", "label": "api"}, "type": "STRING", "label": "LOG_LEVEL", "value": ""}
            ]
        }),
    );
    let fleet = crate::config::parse(&format!(
        "[environments.dev]\ntier = \"local\"\n\
         boundaries.api = {{ vault_id = \"{ITEM}\", item_id = \"{id}\" }}\n\
         [products.api.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n\
         [products.api.keys.LOG_LEVEL]\nkind = \"config\"\nenvironments = [\"dev\"]\n"
    ))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let env_file = dir.path().join("dev.env");
    std::fs::write(
        &env_file,
        format!("OPENAI_API_KEY={MARK_NEW}\nLOG_LEVEL=info\n"),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&env_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (op, fleet, dir)
}

/// A one-environment, one-key fleet at `tier`, for the refusals.
fn fleet_at(tier: &str) -> Fleet {
    crate::config::parse(&format!(
        "[environments.dev]\ntier = \"{tier}\"\n\
         boundaries.api = {{ vault_id = \"v\", item_id = \"i\" }}\n\
         [products.api.keys.KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n"
    ))
    .unwrap()
}

fn field_in(op: &FakeOp, id: &str, label: &str) -> String {
    op.item(id)["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == label)
        .and_then(|f| f["value"].as_str())
        .unwrap_or_default()
        .to_string()
}

/// True when `needle` occurs in any argv (not stdin: that is where values belong).
fn value_in_argv(op: &FakeOp, needle: &str) -> bool {
    op.calls
        .borrow()
        .iter()
        .any(|c| c.args.iter().any(|a| a.contains(needle)))
}

// Refusals ----------------------------------------------------------------------------------

#[test]
fn a_shared_environment_is_refused_by_its_code() {
    let op = FakeOp::default();
    let e = import_local(
        &fleet_at("shared"),
        "dev",
        std::path::Path::new("dev.env"),
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "import_tier_refused");
}

#[test]
fn a_production_environment_is_refused() {
    let op = FakeOp::default();
    let e = import_local(
        &fleet_at("production"),
        "dev",
        std::path::Path::new("dev.env"),
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "import_tier_refused");
}

#[test]
fn a_refused_tier_reads_nothing_at_all() {
    let op = FakeOp::default();
    let _ = import_local(
        &fleet_at("shared"),
        "dev",
        std::path::Path::new("dev.env"),
        &op,
        &mut Vec::new(),
    );
    assert!(op.calls.borrow().is_empty());
}

// The local import --------------------------------------------------------------------------

#[test]
fn a_local_environment_imports_a_missing_key() {
    let (op, fleet, dir) = local_world();
    let file = dir.path().join("dev.env");
    import_local(&fleet, "dev", &file, &op, &mut Vec::new()).unwrap();
    let id = fleet.environments["dev"].boundaries["api"].item_id.clone();
    assert_eq!(field_in(&op, &id, "OPENAI_API_KEY"), MARK_NEW);
    assert_eq!(field_in(&op, &id, "LOG_LEVEL"), "info");
}

#[test]
fn a_written_item_carries_the_assistant_imported_tag() {
    let (op, fleet, dir) = local_world();
    let file = dir.path().join("dev.env");
    import_local(&fleet, "dev", &file, &op, &mut Vec::new()).unwrap();
    let id = fleet.environments["dev"].boundaries["api"].item_id.clone();
    let has = op.item(&id)["tags"]
        .as_array()
        .is_some_and(|t| t.iter().any(|v| v.as_str() == Some(ASSISTANT_IMPORTED)));
    assert!(has, "tags carry {ASSISTANT_IMPORTED}");
}

#[test]
fn no_value_reaches_any_argv() {
    let (op, fleet, dir) = local_world();
    let file = dir.path().join("dev.env");
    import_local(&fleet, "dev", &file, &op, &mut Vec::new()).unwrap();
    assert!(!value_in_argv(&op, MARK_NEW));
}

// Health and the gate -----------------------------------------------------------------------

/// The two-environment fleet the health tests compare across.
fn cross_fleet() -> Fleet {
    crate::config::parse(
        "[environments.dev]\ntier = \"local\"\nboundaries.api = { vault_id = \"v\", item_id = \"i1\" }\n\
         [environments.staging]\ntier = \"local\"\nboundaries.api = { vault_id = \"v\", item_id = \"i2\" }\n\
         [products.api.keys.SECRET]\nkind = \"secret\"\nenvironments = [\"dev\", \"staging\"]\n",
    )
    .unwrap()
}

fn secret(key: &str, value: &str) -> ItemField {
    ItemField {
        section: "api".into(),
        label: key.into(),
        kind: Kind::Secret,
        value: SecretValue::new(value.to_string()),
        concealed: true,
    }
}

fn values<'a>(name: &'a str, fields: &'a [ItemField], imported: bool) -> EnvValues<'a> {
    EnvValues {
        name,
        title: None,
        deployed: false,
        fields,
        tier: Tier::Shared,
        assistant_imported: imported,
    }
}

#[test]
fn health_ignores_a_tagged_value_in_same_across() {
    let fleet = cross_fleet();
    let dev = vec![secret("SECRET", "shared-value")];
    let staging = vec![secret("SECRET", "shared-value")];
    let found = crate::domain::health::check(
        &fleet,
        &[
            values("dev", &dev, true),
            values("staging", &staging, false),
        ],
    );
    assert!(
        !found
            .iter()
            .any(|h| h.code == crate::domain::health::SAME_ACROSS)
    );
}

#[test]
fn health_reports_an_untagged_same_across_value() {
    let fleet = cross_fleet();
    let dev = vec![secret("SECRET", "shared-value")];
    let staging = vec![secret("SECRET", "shared-value")];
    let found = crate::domain::health::check(
        &fleet,
        &[
            values("dev", &dev, false),
            values("staging", &staging, false),
        ],
    );
    assert!(
        found
            .iter()
            .any(|h| h.code == crate::domain::health::SAME_ACROSS)
    );
}

#[test]
fn the_gate_does_not_count_a_tagged_value_as_set() {
    let fleet = crate::config::parse(
        "[environments.dev]\nboundaries.app = { vault_id = \"v\", item_id = \"src1\" }\n\
         [products.app.keys.DATABASE_URL]\nkind = \"secret\"\nenvironments = [\"dev\"]\n",
    )
    .unwrap();
    let rows = vec![Row {
        product: "app".into(),
        key: "DATABASE_URL".into(),
        kind: Kind::Secret,
        state: KeyState::Ready,
        target: TargetState::Present,
        guidance: String::new(),
        source: None,
        shared_by: Vec::new(),
    }];
    let keys = crate::app::ready::gate_keys(
        &fleet,
        "dev",
        &rows,
        &std::collections::BTreeSet::new(),
        &std::collections::BTreeSet::from(["app".to_string()]),
        &std::collections::BTreeMap::from([("src1".to_string(), 3)]),
        &std::collections::BTreeMap::from([("src1".to_string(), 3)]),
        &std::collections::BTreeSet::from(["src1".to_string()]),
    );
    assert_eq!(
        keys,
        vec![(
            "app".to_string(),
            "DATABASE_URL".to_string(),
            "assistant_imported"
        )]
    );
}
