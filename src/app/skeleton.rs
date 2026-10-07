//! `item skeleton <env>` use case (FR-19).

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

    #[test]
    fn unknown_env_is_config_error_before_any_call() {
        let r = FakeRunner::new([]);
        let e = run(&fleet(), "qa", &r, &mut Vec::new()).unwrap_err();
        assert!(matches!(e, Error::Config(_)), "{e}");
        assert!(r.calls.borrow().is_empty());
    }
}
