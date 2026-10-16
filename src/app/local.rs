//! Local-only validation. One item read, no deployment store, names-only output.
use super::{personal, read_and_plan_products, write_err};
use crate::domain::Fleet;
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
    // D10/FR-34: one product with keys desired in `env` needs no `--product`; the rule
    // lives in `super::pick_product`. `doctor` (required = false) keeps the whole
    // environment when the choice is ambiguous instead of failing.
    let chosen = match product {
        Some(p) => Some(super::pick_product(fleet, env, Some(p))?),
        None => match super::pick_product(fleet, env, None) {
            Ok(p) => Some(p),
            Err(_) if !required => None,
            Err(e) => return Err(e),
        },
    };
    let mut selected = fleet.clone();
    selected.environments.retain(|name, _| name == env);
    if let Some(p) = chosen.as_deref() {
        // The sources of the product's shared keys (FR-45) stay, alone: the read then
        // covers their sections too, and their findings are reported once, on them.
        let sources = fleet.sources_of(p);
        selected
            .products
            .retain(|name, _| name == p || sources.iter().any(|(s, _)| s == name));
        for (name, prod) in selected.products.iter_mut().filter(|(n, _)| *n != p) {
            prod.keys
                .retain(|k, _| sources.contains(&(name.clone(), k.clone())));
        }
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
    let selected = select(fleet, env, product, true)?;
    // FR-55: a targetless environment's personal keys live in the person's own item. Merge
    // its fields (never a team fallback) before planning, so they appear as ordinary rows;
    // environments without personal keys keep the exact read path they had.
    let mut plan = if personal::declared(fleet, env) {
        let project = personal::project_name(runner, &std::env::current_dir().unwrap_or_default());
        let read = super::tidy::read_for(&selected, fleet, env, runner)?;
        let fields = personal::merged_fields(runner, fleet, env, read.fields, &project)?;
        let none = std::collections::BTreeSet::new();
        // Planned without a target: check never reaches one.
        let mut plan = super::plan_item(&selected, env, None, fields, None, &none, &none)?.0;
        plan.tidy = read.changes;
        plan.tidy_error = read.tidy_error;
        plan
    } else {
        read_and_plan_products(&selected, fleet, env, runner)?
    };
    plan.extras.clear();
    let findings = plan.blocking();
    // The 1Password link for the rows to fix (H1): one free `op whoami`, only when needed.
    let link = if findings > 0 {
        super::rows_item_url(&selected, env, &plan.rows, runner)?
    } else {
        None
    };
    if json {
        // The shared row shape (A6); no target is read, so `target`, `target_state` and
        // `action` are null.
        let declared = fleet.environment(env)?;
        let rows: Vec<_> = plan
            .rows
            .iter()
            .map(|row| {
                // The environment's first target by name renders the row's name.
                let name = declared
                    .targets
                    .values()
                    .next()
                    .map(|t| t.config.env_name(&row.product, &row.key));
                super::JsonRow {
                    // H1: the item link to fix a blocking row in; IDs only.
                    open_url: link.as_ref().filter(|_| super::is_blocking(row)).cloned(),
                    ..super::JsonRow::new(row, name, None, None)
                }
            })
            .collect();
        let mut doc = serde_json::json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "environment": env,
            "product": product,
            "target_checked": false,
            "rows": rows,
            "findings": findings,
            "totals": {"rows": plan.rows.len(), "findings": findings},
        });
        // FR-43: what opv tidied in 1Password before reading, names only; omitted when none.
        if !plan.tidy.is_empty() {
            doc["tidy"] = serde_json::json!(super::json_tidy(&plan.tidy));
        }
        if let Some(code) = plan.tidy_error {
            doc["tidy_error"] = code.into();
        }
        writeln!(out, "{doc}").map_err(write_err)?;
    } else {
        for row in super::problems_first(&plan.rows, |r| r) {
            let label = crate::domain::key_label(&row.product, &row.key);
            writeln!(
                out,
                "{label}: {}{}",
                super::row_state_label(row),
                super::shared_note(row)
            )
            .map_err(write_err)?;
            if super::is_blocking(row) {
                let guidance = &selected.products[&row.product].keys[&row.key].guidance;
                if !guidance.is_empty() {
                    writeln!(out, "  guidance: {guidance}").map_err(write_err)?;
                }
                // The item link is left to `Next: opv open …` (found live: the long link
                // read like a secret and repeated what the next step already says).
            }
        }
        // With findings, the error line counts them (`opv: 1 finding`); not twice (M4).
        let line = if findings == 0 {
            "no findings; no deployment target checked"
        } else {
            "no deployment target checked"
        };
        writeln!(out, "{line}").map_err(write_err)?;
    }
    if findings > 0 {
        Err(super::findings_error(&plan.rows, env))
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
            "[environments.dev]\nboundaries.allumata = { vault_id = \"vdev\", item_id = \"idev\" }\n[products.allumata.keys.DEV_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n",
        );
        let r = FakeRunner::new([item(&[])]);
        let mut out = Vec::new();
        let result = check(&f, "dev", Some("allumata"), &r, &mut out, true);
        assert!(
            result
                .as_ref()
                .err()
                .and_then(crate::app::testutil::findings_of)
                == Some(1)
        );
        assert_no_values(&text_of(&out));
    }

    /// Found live: 1Password shows an empty field only in edit mode.
    #[test]
    fn a_missing_key_tells_the_person_to_click_edit() {
        let f = fleet_with(
            "[environments.dev]\nboundaries.allumata = { vault_id = \"vdev\", item_id = \"idev\" }\n[products.allumata.keys.DEV_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n",
        );
        let r = FakeRunner::new([item(&[])]);
        let e = check(&f, "dev", Some("allumata"), &r, &mut Vec::new(), true).unwrap_err();
        assert!(e.do_text().is_some_and(|a| a.contains("click Edit")));
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
    fn a_single_product_check_accepts_no_product_selection() {
        let f = crate::config::parse(
            "[environments.dev]\nboundaries.app = { vault_id = \"vdev\", item_id = \"idev\" }\n\
             [products.app.keys.DEV_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n",
        )
        .unwrap();
        let r = FakeRunner::new([item(&[secret("app", "DEV_KEY", "FIXTUREVALUE")])]);
        let mut out = Vec::new();
        assert!(check(&f, "dev", None, &r, &mut out, true).is_ok());
    }

    #[test]
    fn check_reads_a_secret_stored_as_text_without_values() {
        // FR-43: the other kind is read tolerantly, never a finding.
        let r = FakeRunner::new([item(&[text("allumata", "OPENAI_API_KEY", OPENAI)])]);
        let mut out = Vec::new();
        let _ = check(&fleet(), "prod", Some("allumata"), &r, &mut out, true);
        let text = text_of(&out);
        assert_no_values(&text);
        assert!(!text.contains("wrong_kind"), "{text}");
    }
    #[test]
    fn malformed_field_in_another_products_section_does_not_fail_the_check() {
        let f = fleet_with(
            "[products.other]\nboundary = \"allumata\"\n[products.other.keys.SITE]\nkind = \"config\"\nenvironments = [\"prod\"]\n",
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

    /// `shared` is source-only; `api` is the only product that can be chosen (FR-47).
    #[test]
    fn select_ignores_a_source_only_product_for_the_single_product_shortcut() {
        let f = crate::config::parse(
            r#"
[environments.ci]
boundaries.core = { vault_id = "vci", item_id = "ici" }
[environments.ci.targets.app]
fly.app = "app"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
state_vault_id = "sci"
[products.shared]
source_only = true
boundary = "core"
[products.shared.keys.TOKEN]
kind = "secret"
environments = ["ci"]
[products.api]
boundary = "core"
[products.api.keys.TOKEN]
kind = "secret"
environments = ["ci"]
"#,
        )
        .unwrap();
        let selected = select(&f, "ci", None, true).unwrap();
        assert_eq!(
            selected.products.keys().cloned().collect::<Vec<_>>(),
            vec!["api".to_string()]
        );
    }
}
