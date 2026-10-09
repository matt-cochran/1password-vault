//! Local-only validation. One item read, no deployment store, names-only output.
use super::{read_and_plan_products, write_err};
use crate::domain::{Fleet, KeyState};
use crate::error::Error;
use crate::runner::CommandRunner;
use std::io::Write;

/// Select configuration before any subprocess call. Does not read values.
pub fn select(
    fleet: &Fleet,
    env: &str,
    product: Option<&str>,
    required: bool,
) -> Result<Fleet, Error> {
    fleet.environment(env)?;
    if fleet.is_simple() && product.is_some() {
        return Err(Error::Config(
            "--product is not used under the simple profile".into(),
        ));
    }
    if !fleet.is_simple() && required && product.is_none() {
        return Err(Error::Config(format!(
            "--product is required because this configuration contains multiple products. Choose --product <name> (available: {}).",
            fleet
                .products
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ).into()));
    }
    if let Some(p) = product
        && !fleet.products.contains_key(p)
    {
        return Err(Error::Config(
            format!(
                "undefined product {p:?}; choose one of: {}",
                fleet
                    .products
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .into(),
        ));
    }
    let mut selected = fleet.clone();
    selected.environments.retain(|name, _| name == env);
    if let Some(p) = product {
        selected.products.retain(|name, _| name == p);
    }
    Ok(selected)
}

pub fn check(
    fleet: &Fleet,
    env: &str,
    product: Option<&str>,
    runner: &dyn CommandRunner,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    let mut selected = select(fleet, env, product, true)?;
    selected
        .environments
        .get_mut(env)
        .expect("selected env")
        .target = None;
    let mut plan = read_and_plan_products(&selected, env, runner)?;
    plan.extras.clear();
    let findings = plan.blocking();
    // The 1Password link for the rows to fix (H1): one free `op whoami`, only when needed.
    let link = if findings > 0 {
        Some(super::item_url(&selected, env, runner)?)
    } else {
        None
    };
    if json {
        let rows: Vec<_> = plan
            .rows
            .iter()
            .map(|row| {
                let mut v = serde_json::json!({
                    "product": super::json_product(&row.product), "key": row.key,
                    "state": super::json_state(&row.state), "rule": super::json_rule(&row.state),
                    "reason": super::json_reason(&row.state)
                });
                // H1: the item link to fix a blocking row in; IDs only.
                if let Some(url) = link.as_ref().filter(|_| super::is_blocking(row)) {
                    v["open_url"] = serde_json::Value::String(url.clone());
                }
                v
            })
            .collect();
        let doc = serde_json::json!({"schema_version": 1, "environment": env,
            "target_checked": false, "rows": rows, "findings": findings});
        writeln!(out, "{doc}").map_err(write_err)?;
    } else {
        for row in super::problems_first(&plan.rows) {
            let label = crate::domain::key_label(&row.product, &row.key);
            writeln!(out, "{label}: {}", super::row_state_label(row)).map_err(write_err)?;
            if !matches!(row.state, KeyState::Ready | KeyState::Skipped) {
                let guidance = &selected.products[&row.product].keys[&row.key].guidance;
                if !guidance.is_empty() {
                    writeln!(out, "  guidance: {guidance}").map_err(write_err)?;
                }
                if let Some(url) = &link {
                    writeln!(out, "  open: {url} ({})", super::field_locator(row))
                        .map_err(write_err)?;
                }
            }
        }
        writeln!(out, "{findings} finding(s); no deployment target checked").map_err(write_err)?;
    }
    if findings > 0 {
        Err(Error::findings(findings, super::open_next(&plan.rows, env)))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::testutil::*;
    use crate::runner::fake::FakeRunner;

    #[test]
    fn check_reads_one_item_and_never_opens_target() {
        let r = FakeRunner::new([item(&complete_fields())]);
        let mut out = Vec::new();
        check(&fleet(), "prod", Some("allumata"), &r, &mut out, false).unwrap();
        assert_eq!(r.calls.borrow().len(), 1);
    }

    #[test]
    fn targetless_check_reports_missing_without_values() {
        let f = fleet_with(
            "[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n[products.allumata.keys.DEV_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n",
        );
        let r = FakeRunner::new([item(&[])]);
        let mut out = Vec::new();
        let result = check(&f, "dev", Some("allumata"), &r, &mut out, true);
        assert!(matches!(result, Err(Error::Findings(1, _))));
        assert_no_values(&text_of(&out));
    }

    #[test]
    fn invalid_selection_never_reads_item() {
        let r = FakeRunner::new([]);
        let mut out = Vec::new();
        let _ = check(&fleet(), "prod", Some("unknown"), &r, &mut out, false);
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn json_check_has_no_value_or_deployment_action() {
        let r = FakeRunner::new([item(&complete_fields())]);
        let mut out = Vec::new();
        check(&fleet(), "prod", Some("allumata"), &r, &mut out, true).unwrap();
        let text = text_of(&out);
        assert_no_values(&text);
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(
            doc["rows"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["action"].is_null())
        );
    }

    #[test]
    fn check_ignores_unselected_products_missing_fields() {
        let mut f = fleet();
        f.products
            .insert("unselected".into(), f.products["allumata"].clone());
        let r = FakeRunner::new([item(&complete_fields())]);
        let mut out = Vec::new();
        assert!(check(&f, "prod", Some("allumata"), &r, &mut out, false).is_ok());
    }

    #[test]
    fn simple_check_accepts_no_product_selection() {
        let f = crate::config::parse("[profile]\nkind = \"simple\"\n[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n[keys.DEV_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n").unwrap();
        let r = FakeRunner::new([item(&[secret("", "DEV_KEY", "FIXTUREVALUE")])]);
        let mut out = Vec::new();
        assert!(check(&f, "dev", None, &r, &mut out, true).is_ok());
    }

    #[test]
    fn check_kind_failure_reports_names_not_values() {
        let r = FakeRunner::new([item(&[text("allumata", "OPENAI_API_KEY", OPENAI)])]);
        let mut out = Vec::new();
        let _ = check(&fleet(), "prod", Some("allumata"), &r, &mut out, true);
        let text = text_of(&out);
        assert_no_values(&text);
        assert!(text.contains("wrong_kind"));
    }
    #[test]
    fn malformed_field_in_another_products_section_does_not_fail_the_check() {
        let f = fleet_with(
            "[products.other.keys.SITE]\nkind = \"config\"\nenvironments = [\"prod\"]\n",
        );
        let mut doc: serde_json::Value =
            serde_json::from_slice(&item_json(&complete_fields())).unwrap();
        doc["fields"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "id": "other_site", "section": {"id": "other", "label": "other"},
                "type": "URL", "label": "SITE", "value": "https://example.invalid"
            }));
        let r = FakeRunner::new([crate::runner::Output::success(
            serde_json::to_vec(&doc).unwrap(),
        )]);
        let res = check(&f, "prod", Some("allumata"), &r, &mut Vec::new(), false);
        assert!(res.is_ok(), "{res:?}");
    }
}
