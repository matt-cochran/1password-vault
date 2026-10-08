//! `config export <env> --json` use case (FR-18, spec §7.2).
//!
//! Prints `plan.config` (config-kind values only) as JSON. Refuses with `Error::Policy`,
//! printing nothing, when a config key is missing, fails a rule or is stored as a secret,
//! or when a secret key is stored as text: the kind check is S5's `WrongKind`. One `op`
//! call; Fly is not contacted.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use super::{is_blocking, read_and_plan, row_names, write_err};
use crate::domain::{Fleet, KeyState, Kind, Row, SIMPLE_PRODUCT};
use crate::error::Error;
use crate::runner::CommandRunner;

pub fn run(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    fleet.environment(env_name)?;
    let none = BTreeSet::new();
    let (plan, _) = read_and_plan(fleet, env_name, r, None, &none, &none)?;
    let refused = row_names(&plan.rows, refuses);
    if !refused.is_empty() {
        return Err(Error::Policy(format!(
            "config export refused: {}",
            refused.join(", ")
        )));
    }
    // Config values are not secret (FR-18); `plan.config` never holds a secret-kind value.
    // Under the simple profile (FR-20) the export is a flat `KEY -> value` object, with no
    // product level.
    let empty = BTreeMap::new();
    let json = if fleet.is_simple() {
        serde_json::to_string_pretty(plan.config.get(SIMPLE_PRODUCT).unwrap_or(&empty))
    } else {
        serde_json::to_string_pretty(&plan.config)
    }
    .map_err(|_| Error::Config("cannot serialize config export".into()))?;
    writeln!(out, "{json}").map_err(write_err)
}

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
        let res = run(&fleet(), "prod", &r, &mut out);
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

    #[test]
    fn refuses_config_stored_as_secret() {
        let (res, out, _) = export(complete_with(secret("allumata", "SIGNUP_POLICY", POLICY)));
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Policy(_)), "{e}");
        assert!(e.to_string().contains("allumata/SIGNUP_POLICY"), "{e}");
        assert!(out.is_empty());
    }

    #[test]
    fn refuses_secret_stored_as_text() {
        let (res, out, _) = export(complete_with(text("allumata", "OPENAI_API_KEY", OPENAI)));
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Policy(_)), "{e}");
        assert!(e.to_string().contains("allumata/OPENAI_API_KEY"), "{e}");
        assert_no_values(&e.to_string());
        assert!(out.is_empty(), "printed despite refusal");
    }

    #[test]
    fn refuses_config_that_is_missing_or_fails_a_rule() {
        for item in [
            item_without("allumata", "SIGNUP_POLICY"),
            complete_with(text("allumata", "SIGNUP_POLICY", "FIXTUREVALUE")),
        ] {
            let (res, out, _) = export(item);
            let e = res.unwrap_err();
            assert!(matches!(e, Error::Policy(_)), "{e}");
            assert!(e.to_string().contains("SIGNUP_POLICY"), "{e}");
            assert_no_values(&e.to_string());
            assert!(out.is_empty());
        }
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
            "[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n\
             [products.allumata.keys.DEV_FLAG]\nkind = \"config\"\nenvironments = [\"dev\"]\n",
        );
        let r = FakeRunner::new([item(&[text("allumata", "DEV_FLAG", "on")])]);
        let mut out = Vec::new();
        run(&fl, "dev", &r, &mut out).unwrap();
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
        let e = run(&fleet(), "qa", &r, &mut Vec::new()).unwrap_err();
        assert!(matches!(e, Error::Config(_)), "{e}");
        assert!(r.calls.borrow().is_empty());
    }
}
