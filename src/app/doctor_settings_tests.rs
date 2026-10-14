//! `opv doctor --settings` (#92): the settings health check across environments. Every
//! value holds [`MARK`]; no row may contain it.

use super::*;
use crate::adapters::fake_op::FakeOp;

const MARK: &str = "DOCTORHEALTHMARK";
const VAULT: &str = "vdev0000000000000000000001";

/// Two run-only environments (dev, ci) whose items hold DATABASE_URL = `dev` / `ci`.
fn world(dev: &str, ci: &str) -> (FakeOp, Fleet) {
    let op = FakeOp::default();
    let item = |value: &str| {
        serde_json::json!({
            "title": "t", "category": "SECURE_NOTE",
            "sections": [{"id": "app", "label": "app"}],
            "fields": [{"id": "f1", "type": "CONCEALED", "section": {"id": "app", "label": "app"},
                        "label": "DATABASE_URL", "value": value}]
        })
    };
    let dev_id = op.insert(VAULT, item(dev));
    let ci_id = op.insert(VAULT, item(ci));
    let fleet = crate::config::parse(&format!(
        "[environments.dev]\nboundaries.app = {{ vault_id = \"{VAULT}\", item_id = \"{dev_id}\" }}\n\
         [environments.ci]\nboundaries.app = {{ vault_id = \"{VAULT}\", item_id = \"{ci_id}\" }}\n\
         [products.app.keys.DATABASE_URL]\nkind = \"secret\"\nenvironments = [\"dev\", \"ci\"]\n"
    ))
    .unwrap();
    (op, fleet)
}

fn settings_row(dev: &str, ci: &str, only: Option<&str>) -> Row {
    let (op, fleet) = world(dev, ci);
    let mut report = Report::default();
    settings_check(&fleet, only, &op, &mut report);
    report.rows.pop().unwrap()
}

fn same() -> String {
    format!("pw-{MARK}")
}

#[test]
fn one_secret_in_two_environments_warns() {
    assert_eq!(settings_row(&same(), &same(), None).state, State::Warn);
}

#[test]
fn the_warning_names_the_code() {
    assert!(
        settings_row(&same(), &same(), None)
            .text
            .contains("same_value_across_environments")
    );
}

#[test]
fn the_warning_never_shows_the_value() {
    assert!(!settings_row(&same(), &same(), None).text.contains(MARK));
}

#[test]
fn the_warning_opens_the_key_where_to_fix_it() {
    assert_eq!(
        settings_row(&same(), &same(), None).fix.as_deref(),
        Some("opv open app/DATABASE_URL --env ci")
    );
}

#[test]
fn different_values_pass() {
    assert_eq!(
        settings_row(&format!("a-{MARK}"), &format!("b-{MARK}"), None).state,
        State::Ok
    );
}

#[test]
fn env_scope_keeps_findings_that_involve_it() {
    assert_eq!(
        settings_row(&same(), &same(), Some("dev")).state,
        State::Warn
    );
}

#[test]
fn a_settings_check_never_fails_doctor() {
    let (op, fleet) = world(&same(), &same());
    let mut report = Report::default();
    settings_check(&fleet, None, &op, &mut report);
    assert!(report.first.is_none());
}
