//! `config export <env> --json` use case (FR-18).

use std::io::Write;

use crate::domain::Fleet;
use crate::error::Error;
use crate::runner::CommandRunner;

pub fn run(
    _fleet: &Fleet,
    _env_name: &str,
    _r: &dyn CommandRunner,
    _out: &mut dyn Write,
) -> Result<(), Error> {
    todo!()
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

    #[test]
    fn unknown_env_is_config_error_before_any_call() {
        let r = FakeRunner::new([]);
        let e = run(&fleet(), "qa", &r, &mut Vec::new()).unwrap_err();
        assert!(matches!(e, Error::Config(_)), "{e}");
        assert!(r.calls.borrow().is_empty());
    }
}
