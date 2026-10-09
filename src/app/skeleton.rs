//! `item skeleton <env>` use case (FR-19): the explicit 1Password write, for any identity.
//! (A signed-in person's runs also tidy the item, FR-43, [`super::tidy`].)
//!
//! One read of the item, then at most one edit adding every key declared for `env` (all
//! products, mode-skipped keys included) that has no field yet, as an empty field of the
//! declared kind. Existing fields are never touched, whatever their kind or value.

use std::io::Write;

use super::{kind_label, write_err};
use crate::adapters::{onepassword, onepassword_tidy};
use crate::domain::{Fleet, Kind, convention, key_label};
use crate::error::Error;
use crate::runner::CommandRunner;

pub fn run(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    run_as(fleet, env_name, r, out, false)
}

/// [`run`], printing `{schema_version, environment, added: [{product, key, kind}]}` instead
/// of lines when `json` (A5). Names and kinds only.
pub fn run_as(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    let env = fleet.environment(env_name)?;
    // The tolerant reader (FR-43): a field opv would read for a key (another label
    // spelling, a wrong section, another type, a duplicate) counts as present, so no
    // second field is added beside it, and an item the strict reader refuses still works.
    let item = onepassword::read_whole(r, env)?;
    let (layout, _) = onepassword_tidy::parse(item.raw())?;
    let found = convention::resolve(&layout, fleet).chosen;
    let missing: Vec<(String, String, Kind)> = fleet
        .products
        .iter()
        .flat_map(|(product, p)| {
            p.keys
                .iter()
                // A shared key (FR-45) reads its source's field and never gets one of its
                // own. Task X (self-healing): keep this filter wherever fields are created.
                .filter(|(_, spec)| spec.from.is_none())
                .filter(|(_, spec)| spec.environments.iter().any(|e| e == env_name))
                .map(move |(key, spec)| (product.clone(), key.clone(), spec.kind))
        })
        .filter(|(product, key, _)| !found.contains_key(&(product.clone(), key.clone())))
        .collect();
    if !missing.is_empty() {
        onepassword::write_skeleton(r, env, &item, &missing)?;
    }
    if json {
        let added: Vec<serde_json::Value> = missing
            .iter()
            .map(|(product, key, kind)| {
                serde_json::json!({
                    "product": super::json_product(product),
                    "key": key,
                    "kind": kind_label(*kind),
                })
            })
            .collect();
        let doc = serde_json::json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "environment": env_name,
            "added": added,
        });
        return writeln!(out, "{doc}").map_err(write_err);
    }
    if missing.is_empty() {
        writeln!(out, "nothing to add: every declared field exists").map_err(write_err)?;
        return Ok(());
    }
    for (product, key, kind) in &missing {
        writeln!(
            out,
            "added {} ({}, empty)",
            key_label(product, key),
            kind_label(*kind)
        )
        .map_err(write_err)?;
    }
    writeln!(out, "{} field(s) added", missing.len()).map_err(write_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::testutil::*;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;
    use serde_json::Value;

    fn skeleton(item: Output) -> (Result<(), Error>, String, FakeRunner) {
        let r = FakeRunner::new([item, ok()]);
        let mut out = Vec::new();
        let res = run(&fleet(), "prod", &r, &mut out);
        (res, text_of(&out), r)
    }

    fn edit_template(r: &FakeRunner) -> Value {
        let calls = r.calls.borrow();
        let c = calls
            .iter()
            .find(|c| c.program == "op" && c.args.get(1).is_some_and(|a| a == "edit"))
            .expect("no op item edit call");
        serde_json::from_slice(c.stdin.as_ref().unwrap()).unwrap()
    }

    fn field<'a>(t: &'a Value, section: &str, label: &str) -> Option<&'a Value> {
        t["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["section"]["label"] == section && f["label"] == label)
    }

    #[test]
    fn adds_only_missing_declared_fields_with_their_kind() {
        let (res, out, r) = skeleton(item(&[secret("allumata", "OPENAI_API_KEY", OPENAI)]));
        res.unwrap();
        let t = edit_template(&r);
        // Every key declared for prod, including mode-skipped ones (STRIPE in payments=off).
        for (label, ty) in [
            ("INTEGRATION_ENC_KEY", "CONCEALED"),
            ("STRIPE_SECRET_KEY", "CONCEALED"),
            ("SIGNUP_POLICY", "STRING"),
        ] {
            let f = field(&t, "allumata", label).unwrap_or_else(|| panic!("{label} not added"));
            assert_eq!(f["type"], ty, "{label}");
            assert_eq!(f["value"], "", "{label}");
        }
        // The existing field is sent back unchanged (full-item template).
        assert_eq!(
            field(&t, "allumata", "OPENAI_API_KEY").unwrap()["value"],
            OPENAI
        );
        assert!(out.contains("allumata/INTEGRATION_ENC_KEY"), "{out}");
        assert!(out.contains("3 field(s) added"), "{out}");
        assert_no_values(&out);
    }

    #[test]
    fn one_read_and_one_edit() {
        let (res, _, r) = skeleton(item(&[]));
        res.unwrap();
        let a = argvs(&r);
        assert_eq!(
            a,
            vec![
                "op item get iprd --vault vprd --format json",
                "op item edit iprd --vault vprd --format json",
            ]
        );
        assert_no_values_in_argv(&r);
    }

    #[test]
    fn complete_item_makes_no_edit() {
        let mut fs = complete_fields();
        fs.push(secret("allumata", "STRIPE_SECRET_KEY", ""));
        let (res, out, r) = skeleton(item(&fs));
        res.unwrap();
        assert_eq!(op_calls(&r), 1);
        assert!(out.contains("nothing to add"), "{out}");
    }

    /// Existing fields are never touched, even with the wrong kind (status reports that).
    #[test]
    fn wrong_kind_field_is_left_alone() {
        let (res, _, r) = skeleton(item(&[text("allumata", "OPENAI_API_KEY", OPENAI)]));
        res.unwrap();
        let t = edit_template(&r);
        let f = field(&t, "allumata", "OPENAI_API_KEY").unwrap();
        assert_eq!(f["type"], "STRING");
        assert_eq!(f["value"], OPENAI);
        let n = t["fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["label"] == "OPENAI_API_KEY")
            .count();
        assert_eq!(n, 1);
    }

    /// Only keys declared for the requested env: OPENAI_API_KEY is prod-only.
    #[test]
    fn staging_skeleton_omits_prod_only_keys() {
        let r = FakeRunner::new([item(&[]), ok()]);
        run(&fleet(), "staging", &r, &mut Vec::new()).unwrap();
        let t = edit_template(&r);
        assert!(field(&t, "allumata", "OPENAI_API_KEY").is_none());
        assert!(field(&t, "allumata", "INTEGRATION_ENC_KEY").is_some());
    }

    /// I5: item skeleton works for an environment without a `fly` section.
    #[test]
    fn works_without_fly_section() {
        let fl = fleet_with(
            "[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n\
             [products.allumata.keys.DEV_FLAG]\nkind = \"config\"\nenvironments = [\"dev\"]\n",
        );
        let r = FakeRunner::new([item(&[]), ok()]);
        let mut out = Vec::new();
        run(&fl, "dev", &r, &mut out).unwrap();
        assert!(
            text_of(&out).contains("added allumata/DEV_FLAG"),
            "{}",
            text_of(&out)
        );
        assert_eq!(
            argvs(&r),
            vec![
                "op item get idev --vault vdev --format json",
                "op item edit idev --vault vdev --format json",
            ]
        );
    }

    #[test]
    fn unknown_env_is_config_error_before_any_call() {
        let r = FakeRunner::new([]);
        let e = run(&fleet(), "qa", &r, &mut Vec::new()).unwrap_err();
        assert!(matches!(e, Error::Config(_)), "{e}");
        assert!(r.calls.borrow().is_empty());
    }
}
