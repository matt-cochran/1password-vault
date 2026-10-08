//! `status <env>` use case (FR-17, spec §7.3, ruling P17).
//!
//! One row per product × key with its 1Password state and Fly state, guidance under each
//! missing row, extras as warnings. Names only. Exits `Findings(n)` for the n rows that are
//! missing, of the wrong kind or failing a rule; extras alone exit 0. A clean run ends with
//! a summary line on stdout (FR-26). Read-only: one `op item get` and one `flyctl secrets
//! list` (plus the free `op whoami` diagnosis when the read fails).

use std::collections::BTreeSet;
use std::io::Write;

use super::{is_blocking, print_extras, print_rows, read_and_plan, write_err, write_json};
use crate::adapters;
use crate::domain::{Fleet, KeyState, Kind, Row, TargetState};
use crate::error::Error;
use crate::runner::CommandRunner;

pub fn run(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    run_with(fleet, env_name, r, out, false)
}

/// `status <env> [--json]`. With `json`, stdout carries one FR-21 document and no table or
/// summary line; exit codes are unchanged (`Findings(n)` for blocking rows).
pub fn run_with(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    // Needs a Fly target: `Error::Config` naming the environment otherwise, before any call.
    let (store, _) = adapters::open(fleet.target(env_name)?.1, r);
    let none = BTreeSet::new();
    let (plan, _) = read_and_plan(fleet, env_name, r, Some(store.as_ref()), &none, &none)?;
    if json {
        write_json(out, fleet, env_name, &plan)?;
        let n = plan.rows.iter().filter(|r| is_blocking(r)).count();
        return if n > 0 {
            Err(Error::Findings(n))
        } else {
            Ok(())
        };
    }
    print_rows(out, fleet, &plan.rows, target)?;
    print_extras(out, &plan)?;
    let n = plan.rows.iter().filter(|r| is_blocking(r)).count();
    if n > 0 {
        writeln!(
            out,
            "{n} key(s) missing, of the wrong kind or failing a rule"
        )
        .map_err(write_err)?;
        return Err(Error::Findings(n));
    }
    writeln!(out, "{}", summary(&plan.rows)).map_err(write_err)?;
    Ok(())
}

/// The clean-run summary line (FR-26): `N saved, M not yet on Fly (staged by the next fly
/// sync), 0 findings`. N counts saved rows (secret and config); M counts saved secrets
/// absent from Fly. Skipped rows count in neither. Names and counts only.
fn summary(rows: &[Row]) -> String {
    let saved = rows.iter().filter(|r| r.state == KeyState::Ready);
    let pending = saved
        .clone()
        .filter(|r| r.kind == Kind::Secret && r.target == TargetState::Absent)
        .count();
    format!(
        "{} saved, {pending} not yet on Fly (staged by the next sync), 0 findings",
        saved.count()
    )
}

/// Fly state of a row. Digests cannot be compared locally (P1), so a secret on Fly is
/// "present"; `fly sync` reports whether staging changed it.
fn target(r: &Row) -> String {
    match (r.kind, r.target) {
        (Kind::Config, _) => "-",
        (Kind::Secret, TargetState::Absent) => "absent",
        (Kind::Secret, TargetState::WouldChange) => "would change",
        (Kind::Secret, _) => "present",
    }
    .to_string()
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
                "failed ",
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
                "failed ",
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

    /// FR-26: a value failing its rule shows the reason and, under it, the key's guidance.
    #[test]
    fn status_rule_failure_prints_guidance_on_next_line() {
        let (res, out, _) = status_of(
            complete_with(secret("allumata", "OPENAI_API_KEY", "sk-or-FIXTUREVALUE")),
            fly_empty(),
        );
        assert!(matches!(res, Err(Error::Findings(1))), "{res:?}");
        let lines: Vec<&str> = out.lines().collect();
        let i = lines
            .iter()
            .position(|l| l.contains("OPENAI_API_KEY") && l.contains("failed "))
            .unwrap();
        assert!(lines[i + 1].starts_with("    guidance: "), "{out}");
        assert!(lines[i + 1].contains("OpenAI platform / API keys"), "{out}");
        assert_no_values(&out);
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

    /// I1: a prod-only SMTP_PASS present (non-empty) in the staging item is a blocking
    /// `refuse_in` row in staging status, naming product and key.
    #[test]
    fn status_refuse_in_is_blocking_in_refused_env() {
        let fl = fleet_with(
            "[products.allumata.keys.SMTP_PASS]\nkind = \"secret\"\n\
             environments = [\"prod\"]\nrules = { refuse_in = [\"staging\"] }\n",
        );
        let fields = vec![
            secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
            secret("allumata", "STRIPE_SECRET_KEY", "sk_test_FIXTUREVALUE"),
            text("allumata", "SIGNUP_POLICY", POLICY),
            secret("allumata", "SMTP_PASS", "FIXTUREVALUE-smtp"),
        ];
        let r = FakeRunner::new([item(&fields), fly_empty()]);
        let mut out = Vec::new();
        let res = run(&fl, "staging", &r, &mut out);
        let out = text_of(&out);
        assert!(matches!(res, Err(Error::Findings(1))), "{res:?}");
        assert!(
            out.lines().any(|l| l.starts_with("allumata")
                && l.contains("SMTP_PASS")
                && l.contains("failed refuse_in (")),
            "{out}"
        );
        assert_no_values(&out);
    }

    /// I2: a value that passes the rules but cannot travel on a Fly import line shows as a
    /// failing rule (exit 8), not green.
    #[test]
    fn status_shows_import_refusal_as_failing_rule() {
        let (res, out, _) = status_of(
            complete_with(secret("allumata", "OPENAI_API_KEY", "sk-a\"#FIXTUREVALUE")),
            fly_empty(),
        );
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Findings(1)), "{e}");
        assert_eq!(e.exit_code(), 8);
        assert!(
            out.lines().any(|l| l.contains("OPENAI_API_KEY")
                && l.contains("failed import-hash-after-odd-quotes (")),
            "{out}"
        );
        assert_no_values(&out);
    }

    /// I5: status needs a Fly target; Config naming the environment, before any call.
    #[test]
    fn status_env_without_fly_is_config_error_before_any_call() {
        let fl = fleet_with("[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n");
        let r = FakeRunner::new([]);
        let e = run(&fl, "dev", &r, &mut Vec::new()).unwrap_err();
        assert!(
            matches!(&e, Error::Config(m) if m.contains("\"dev\"") && m.contains("no deployment target")),
            "{e}"
        );
        assert!(r.calls.borrow().is_empty());
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
        let r = FakeRunner::new([
            Output::failure(1),
            Output::success(
                br#"{"email":"x-FIXTUREVALUE@example.com","user_type":"SERVICE_ACCOUNT"}"#.to_vec(),
            ),
        ]);
        let mut out = Vec::new();
        let e = run(&fleet(), "prod", &r, &mut out).unwrap_err();
        assert!(matches!(e, Error::Source(_)), "{e}");
        assert_no_values(&e.to_string());
        // One item read, then the free session check; no Fly call.
        assert_eq!(
            argvs(&r),
            vec![
                "op item get iprd --vault vprd --format json",
                "op whoami --format json"
            ]
        );
    }

    /// FR-26: a clean run ends with the summary line; exit stays 0.
    #[test]
    fn status_clean_run_prints_summary_line() {
        let (res, out, _) = status_of(complete_item(), fly(&[(OPENAI_FLY, "d1")]));
        res.unwrap();
        // prod: OPENAI_API_KEY (on Fly), INTEGRATION_ENC_KEY (absent), SIGNUP_POLICY
        // (config); the Stripe key is skipped and counts in neither number.
        assert_eq!(
            out.lines().last().unwrap(),
            "3 saved, 1 not yet on Fly (staged by the next sync), 0 findings",
            "{out}"
        );
    }

    /// Findings: no summary line (the findings line is last) and exit 8 unchanged.
    #[test]
    fn status_with_findings_prints_no_summary_line() {
        let (res, out, _) = status_of(item_without("allumata", "OPENAI_API_KEY"), fly_empty());
        assert_eq!(res.unwrap_err().exit_code(), 8);
        assert!(!out.contains("0 findings"), "{out}");
    }
}
