//! `status <env>` use case (FR-17).

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

    fn status_of(item: Output, fly_list: Output) -> (Result<(), Error>, String, FakeRunner) {
        let r = FakeRunner::new([item, fly_list]);
        let mut out = Vec::new();
        let res = run(&fleet(), "prod", &r, &mut out);
        (res, text_of(&out), r)
    }

    /// Every value-bearing path: saved rows, rule failures, wrong kind, missing (with
    /// guidance), extras, and the returned error. The marker must never appear.
    #[test]
    fn status_prints_names_never_values() {
        let extra = secret("allumata", "OPENAI_API_KEYS", "sk-proj-FIXTUREVALUE-typo");
        let cases: Vec<(Vec<Field>, &str)> = vec![
            (complete_fields(), "saved"),
            (
                vec![
                    secret("allumata", "OPENAI_API_KEY", "sk-or-FIXTUREVALUE"),
                    secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
                    text("allumata", "SIGNUP_POLICY", "FIXTUREVALUE"),
                ],
                "fails rule",
            ),
            (
                vec![
                    text("allumata", "OPENAI_API_KEY", OPENAI),
                    secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
                    secret("allumata", "SIGNUP_POLICY", POLICY),
                ],
                "wrong kind",
            ),
            (
                vec![
                    secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
                    text("allumata", "SIGNUP_POLICY", POLICY),
                    extra.clone(),
                ],
                "missing",
            ),
            (
                vec![
                    secret("allumata", "OPENAI_API_KEY", " sk-proj-FIXTUREVALUE\n"),
                    secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
                    text("allumata", "SIGNUP_POLICY", POLICY),
                    extra.clone(),
                ],
                "fails rule",
            ),
        ];
        for (fields, expect) in cases {
            let (res, out, _) = status_of(item(&fields), fly(&[(OPENAI_FLY, "d1")]));
            assert!(out.contains("OPENAI_API_KEY"), "{out}");
            assert!(out.contains(expect), "{expect}: {out}");
            assert_no_values(&out);
            if let Err(e) = res {
                assert_no_values(&e.to_string());
                assert_no_values(&format!("{e:?}"));
            }
        }
    }

    #[test]
    fn status_missing_row_prints_guidance_on_next_line() {
        let (res, out, _) = status_of(item_without("allumata", "OPENAI_API_KEY"), fly_empty());
        assert!(matches!(res, Err(Error::Findings(1))), "{res:?}");
        let lines: Vec<&str> = out.lines().collect();
        let i = lines
            .iter()
            .position(|l| l.contains("OPENAI_API_KEY") && l.contains("missing"))
            .unwrap();
        assert!(lines[i + 1].contains("OpenAI platform / API keys"), "{out}");
    }

    /// Review Focus 2: a missing product section reports every desired key missing.
    #[test]
    fn status_missing_section_reports_every_key_missing() {
        let (res, out, _) = status_of(item(&[]), fly_empty());
        assert!(matches!(res, Err(Error::Findings(3))), "{res:?}");
        for k in ["OPENAI_API_KEY", "INTEGRATION_ENC_KEY", "SIGNUP_POLICY"] {
            assert!(
                out.lines().any(|l| l.contains(k) && l.contains("missing")),
                "{k}: {out}"
            );
        }
        // prod has payments = "off": the Stripe key is skipped, not missing.
        assert!(
            out.lines()
                .any(|l| l.contains("STRIPE_SECRET_KEY") && l.contains("skipped")),
            "{out}"
        );
    }

    /// P17: extras are warnings; they alone exit 0.
    #[test]
    fn status_extras_alone_exit_zero() {
        let mut fs = complete_fields();
        fs.push(secret("allumata", "OPENAI_API_KEYS", OPENAI));
        let (res, out, _) = status_of(item(&fs), fly_empty());
        res.unwrap();
        assert!(
            out.contains("warning: extra field allumata/OPENAI_API_KEYS"),
            "{out}"
        );
        assert_no_values(&out);
    }

    #[test]
    fn status_complete_is_ok_and_shows_target_state() {
        let (res, out, _) = status_of(complete_item(), fly(&[(OPENAI_FLY, "d1")]));
        res.unwrap();
        let row = |k: &str| out.lines().find(|l| l.contains(k)).unwrap().to_string();
        assert!(row("OPENAI_API_KEY").ends_with("present"), "{out}");
        assert!(row("INTEGRATION_ENC_KEY").ends_with("absent"), "{out}");
        assert!(row("SIGNUP_POLICY").ends_with('-'), "{out}");
        assert!(out.contains("PRODUCT") && out.contains("TARGET"), "{out}");
    }

    #[test]
    fn status_reads_item_once_and_lists_once() {
        let (_, _, r) = status_of(complete_item(), fly_empty());
        assert_eq!(op_calls(&r), 1);
        assert_eq!(
            argvs(&r),
            vec![
                "op item get iprd --vault vprd --format json",
                "flyctl secrets list --app mcproductlabs-portfolio-production --json",
            ]
        );
    }

    #[test]
    fn status_unknown_env_is_config_error_before_any_call() {
        let r = FakeRunner::new([]);
        let e = run(&fleet(), "qa", &r, &mut Vec::new()).unwrap_err();
        assert!(matches!(e, Error::Config(_)), "{e}");
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn status_source_failure_is_typed_and_value_free() {
        let r = FakeRunner::new([Output::failure(1)]);
        let mut out = Vec::new();
        let e = run(&fleet(), "prod", &r, &mut out).unwrap_err();
        assert!(matches!(e, Error::Source(_) | Error::Auth(_)), "{e}");
        assert_eq!(r.calls.borrow().len(), 1);
    }
}
