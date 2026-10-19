//! `config export <env> --json` use case (FR-18, spec §7.2).
//!
//! Prints `plan.config` (config-kind values only) as JSON, `{product: {KEY: value}}`, for every
//! product or the one `--product` names (#188). Refuses with `Cause::ValuesNeeded` (each key
//! and why), printing nothing, when a config key in scope is missing, fails a rule or is
//! stored as a secret, or when a secret key is stored as text: the kind check is S5's `WrongKind`. One `op`
//! call; Fly is not contacted.

use std::collections::BTreeSet;
use std::io::Write;

use super::{is_blocking, read_and_plan, write_err};
use crate::cause::{Cause, EnvName, KeyName, ProductName, ValueRow, ValueState};
use crate::domain::{Fleet, KeyState, Kind, Row};
use crate::error::Error;
use crate::runner::CommandRunner;

pub fn run(
    fleet: &Fleet,
    env_name: &str,
    product: Option<&str>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    // D10/FR-34 (#188): without `--product` the document holds every product's config,
    // `{product: {KEY: value}}`; `--product` limits it to that product, checked exactly as
    // `run` checks it (an unknown or source-only product is refused before any call).
    // FR-47: a source-only product is never run, so it is never a key of the document; the
    // products that read its values carry them. A product with no config value here is
    // left out, as `plan.config` never holds an empty product.
    super::check_product(fleet, product, Some(env_name))?;
    let none = BTreeSet::new();
    let (plan, _) = read_and_plan(fleet, env_name, None, r, None, &none, &none)?;
    // With `--product`, only that product's keys (and the sources they read) block it;
    // without, every key does.
    let sources: BTreeSet<(&str, &str)> = plan
        .rows
        .iter()
        .filter(|r| Some(r.product.as_str()) == product)
        .filter_map(|r| r.source.as_ref())
        .map(|(p, k)| (p.as_str(), k.as_str()))
        .collect();
    let in_scope = |r: &Row| match product {
        None => true,
        Some(p) => r.product == p || sources.contains(&(r.product.as_str(), r.key.as_str())),
    };
    // 03.06: each key that blocks the export, with why (missing, failing its rule, or kept
    // in the wrong kind of field); filling a value is a person's step in 1Password.
    let rows: Vec<ValueRow> = plan
        .rows
        .iter()
        .filter(|r| in_scope(r) && refuses(r))
        .map(|r| ValueRow {
            product: ProductName::new(r.product.clone()),
            key: KeyName::new(r.key.clone()),
            target: None,
            state: match (&r.state, r.kind) {
                (KeyState::RuleFailed(rule, why), _) => ValueState::RuleFailed {
                    rule,
                    reason: Some(why.to_string()),
                },
                (KeyState::WrongKind, Kind::Secret) => ValueState::StoredAsText,
                (KeyState::WrongKind, Kind::Config) => ValueState::ConcealedConfig,
                _ => ValueState::Missing,
            },
        })
        .collect();
    if !rows.is_empty() {
        return Err(Cause::ValuesNeeded {
            env: EnvName::new(env_name),
            rows,
        }
        .into());
    }
    // Config values are not secret (FR-18); `plan.config` never holds a secret-kind value.
    // M4 (owner ruling): config kept concealed in 1Password is accepted, but its value is
    // never printed.
    let mut config = plan.config.clone();
    config.retain(|p, _| {
        product.is_none_or(|only| p == only)
            && fleet.products.get(p).is_some_and(|spec| !spec.source_only)
    });
    for (p, key) in &plan.concealed_config {
        if let Some(v) = config.get_mut(p).and_then(|m| m.get_mut(key)) {
            *v = CONCEALED.to_string();
        }
    }
    let plan_config = &config;
    let json = serde_json::to_string_pretty(plan_config).map_err(|_| -> Error {
        Cause::Bug {
            site: "config export: serialize",
        }
        .into()
    })?;
    writeln!(out, "{json}").map_err(write_err)
}

/// What `config export` shows for a config key kept concealed in 1Password (M4).
pub const CONCEALED: &str = "<concealed in 1Password>";

fn refuses(r: &Row) -> bool {
    match r.kind {
        Kind::Config => is_blocking(r),
        Kind::Secret => r.state == KeyState::WrongKind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::testutil::*;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    fn export(item: Output) -> (Result<(), Error>, Vec<u8>, FakeRunner) {
        let r = FakeRunner::new([item, fly_empty()]);
        let mut out = Vec::new();
        let res = run(&fleet(), "prod", None, &r, &mut out);
        (res, out, r)
    }

    #[test]
    fn config_export_contains_only_config() {
        let (res, out, _) = export(complete_item());
        res.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["allumata"]["SIGNUP_POLICY"], "invite_only");
        assert!(v["allumata"].get("OPENAI_API_KEY").is_none());
        assert!(v["allumata"].get("INTEGRATION_ENC_KEY").is_none());
    }

    #[test]
    fn config_export_never_contains_a_secret_value() {
        let (res, out, _) = export(complete_item());
        res.unwrap();
        assert_no_values(&text_of(&out));
    }

    #[test]
    fn config_export_reads_item_once_and_never_calls_flyctl() {
        let (res, _, r) = export(complete_item());
        res.unwrap();
        assert_eq!(op_calls(&r), 1);
        assert_eq!(r.calls.borrow().len(), 1, "{:?}", argvs(&r));
    }

    /// FR-43: config kept concealed is read tolerantly.
    #[test]
    fn reads_config_stored_as_secret() {
        let (res, _, _) = export(complete_with(secret("allumata", "SIGNUP_POLICY", POLICY)));
        assert!(res.is_ok());
    }

    /// M4: config kept concealed is never printed.
    #[test]
    fn config_stored_as_secret_is_never_printed() {
        let (_, out, _) = export(complete_with(secret("allumata", "SIGNUP_POLICY", POLICY)));
        assert!(!text_of(&out).contains(POLICY), "{}", text_of(&out));
    }

    /// M4: it shows as `<concealed in 1Password>` instead.
    #[test]
    fn config_stored_as_secret_shows_as_concealed() {
        let (_, out, _) = export(complete_with(secret("allumata", "SIGNUP_POLICY", POLICY)));
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["allumata"]["SIGNUP_POLICY"], CONCEALED);
    }

    /// FR-43: a secret stored as text is read tolerantly; its value is never printed.
    #[test]
    fn reads_secret_stored_as_text_without_printing_it() {
        let (_, out, _) = export(complete_with(text("allumata", "OPENAI_API_KEY", OPENAI)));
        assert_no_values(&text_of(&out));
    }

    #[test]
    fn refuses_config_that_is_missing_or_fails_a_rule() {
        for item in [
            item_without("allumata", "SIGNUP_POLICY"),
            complete_with(text("allumata", "SIGNUP_POLICY", "FIXTUREVALUE")),
        ] {
            let (res, out, _) = export(item);
            let e = res.unwrap_err();
            assert!(
                matches!(
                    e.cause(),
                    Some((crate::cause::Cause::ValuesNeeded { .. }, _))
                ),
                "{e}"
            );
            assert!(e.to_string().contains("SIGNUP_POLICY"), "{e}");
            assert_no_values(&e.to_string());
            assert!(out.is_empty());
        }
    }

    /// 03.06: the refusal says why each key blocks it, not only its name.
    #[test]
    fn a_config_value_failing_its_rule_is_named_with_the_rule() {
        let (res, _, _) = export(complete_with(text(
            "allumata",
            "SIGNUP_POLICY",
            "FIXTUREVALUE",
        )));
        let e = res.unwrap_err();
        assert!(
            matches!(
                e.cause(),
                Some((crate::cause::Cause::ValuesNeeded { rows, .. }, _))
                    if matches!(rows[0].state, ValueState::RuleFailed { .. })
            ),
            "{e:?}"
        );
    }

    /// 03.06: filling a value is a person's step (human_required), never an agent's.
    #[test]
    fn a_missing_config_value_is_a_persons_step() {
        let (res, _, _) = export(item_without("allumata", "SIGNUP_POLICY"));
        let e = res.unwrap_err();
        let inv = crate::cause::Invocation::from_cli(&[
            "opv".into(),
            "config".into(),
            "export".into(),
            "prod".into(),
        ]);
        assert!(e.cause().unwrap().0.human_required(&inv), "{e:?}");
    }

    /// A missing secret does not concern config export (secrets are `fly sync`'s job).
    #[test]
    fn missing_secret_does_not_block_export() {
        let (res, out, _) = export(item_without("allumata", "OPENAI_API_KEY"));
        res.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["allumata"]["SIGNUP_POLICY"], "invite_only");
    }

    /// I5: config export works for an environment without a `fly` section.
    #[test]
    fn works_without_fly_section() {
        let fl = fleet_with(
            "[environments.dev]\nboundaries.allumata = { vault_id = \"vdev\", item_id = \"idev\" }\n\
             [products.allumata.keys.DEV_FLAG]\nkind = \"config\"\nenvironments = [\"dev\"]\n",
        );
        let r = FakeRunner::new([item(&[text("allumata", "DEV_FLAG", "on")])]);
        let mut out = Vec::new();
        run(&fl, "dev", None, &r, &mut out).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["allumata"]["DEV_FLAG"], "on");
        assert_eq!(
            argvs(&r),
            vec!["op item get idev --vault vdev --format json"]
        );
    }

    #[test]
    fn unknown_env_is_config_error_before_any_call() {
        let r = FakeRunner::new([]);
        let e = run(&fleet(), "qa", None, &r, &mut Vec::new()).unwrap_err();
        assert_eq!(e.code_str(), "unknown_env", "{e}");
        assert!(r.calls.borrow().is_empty());
    }
}
