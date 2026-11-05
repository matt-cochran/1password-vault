//! The `opv.produce/1` admission parser (#253, tests 51-58 and 60 of
//! `docs/design/owner-value-ingestion.md` §10.5): one atomic scenario per test, one assertion
//! on a public outcome. A refused producer value is a `S7MARKER` canary.

use super::*;
use crate::cause::{Cause, FieldRule, OpenUrlProblem, ProduceRule};

const ENV: &str = "prod-workspace";
const NONCE: &str = "n-abcdefghijklmnopqrstuvwxyz";
const OUT: &str = "refresh_token";
const HOST: &str = "consent.example";
const URL: &str = "https://consent.example/authorize?x=1";
const MARK: &str = "S7MARKER";

fn notice_open(url: &str) -> String {
    format!(r#"{{"schema":"{SCHEMA}","kind":"notice","open_url":"{url}"}}"#)
}

fn notice_waiting() -> String {
    format!(r#"{{"schema":"{SCHEMA}","kind":"notice","waiting":true}}"#)
}

fn result(outputs: &str) -> String {
    format!(
        r#"{{"schema":"{SCHEMA}","kind":"result","env":"{ENV}","nonce":"{NONCE}","outputs":{{{outputs}}}}}"#
    )
}

fn error(code: &str) -> String {
    format!(r#"{{"schema":"{SCHEMA}","kind":"error","code":"{code}"}}"#)
}

fn context<'a>(outputs: &'a [String], hosts: &'a [String]) -> Context<'a> {
    Context {
        env: ENV,
        nonce: NONCE,
        outputs,
        open_url_hosts: hosts,
    }
}

fn names() -> Vec<String> {
    vec![OUT.to_string()]
}

fn allow() -> Vec<String> {
    vec![HOST.to_string()]
}

fn run(text: &str) -> Result<Produced, Error> {
    let outputs = names();
    let hosts = allow();
    parse(text.lines(), context(&outputs, &hosts))
}

fn rule_of(text: &str) -> Option<ProduceRule> {
    let outputs = names();
    let hosts = allow();
    let e = parse(text.lines(), context(&outputs, &hosts)).err()?;
    match e.parts().0 {
        Cause::InputInvalid {
            rule: FieldRule::Produce { produce },
            ..
        } => Some(produce.clone()),
        _ => None,
    }
}

/// Every text opv could show for `e`: the report (message, Do, Next), the `--json` error
/// document and the `Debug` form.
fn shown(e: &Error) -> String {
    let doc = crate::error::document(e, &crate::error::invocation(), true);
    format!("{}\n{doc}\n{e:?}", crate::error::report(e))
}

// --- notices -----------------------------------------------------------------------------

#[test]
fn an_allowed_open_url_is_returned_as_a_notice() {
    let text = format!("{}\n{}", notice_open(URL), result(r#""refresh_token":"v1""#));
    let produced = run(&text).unwrap();
    assert!(matches!(produced.notices(), [Notice::OpenUrl(u)] if u == URL));
}

#[test]
fn a_waiting_notice_is_returned() {
    let text = format!(
        "{}\n{}",
        notice_waiting(),
        result(r#""refresh_token":"v1""#)
    );
    let produced = run(&text).unwrap();
    assert!(matches!(produced.notices(), [Notice::Waiting]));
}

#[test]
fn a_non_https_open_url_is_refused() {
    let text = format!(
        "{}\n{}",
        notice_open("http://consent.example/authorize"),
        result(r#""refresh_token":"v1""#)
    );
    assert_eq!(
        rule_of(&text),
        Some(ProduceRule::OpenUrlRefused {
            line: 1,
            why: OpenUrlProblem::NotHttps,
        })
    );
}

#[test]
fn an_open_url_to_a_host_outside_the_list_is_refused() {
    let text = format!(
        "{}\n{}",
        notice_open("https://evil.example/authorize"),
        result(r#""refresh_token":"v1""#)
    );
    assert_eq!(
        rule_of(&text),
        Some(ProduceRule::OpenUrlRefused {
            line: 1,
            why: OpenUrlProblem::HostNotListed,
        })
    );
}

#[test]
fn an_open_url_longer_than_the_limit_is_refused() {
    let long = format!("https://{HOST}/{}", "a".repeat(URL_LIMIT));
    let text = format!("{}\n{}", notice_open(&long), result(r#""refresh_token":"v1""#));
    assert_eq!(
        rule_of(&text),
        Some(ProduceRule::OpenUrlRefused {
            line: 1,
            why: OpenUrlProblem::TooLong { limit: 2048 },
        })
    );
}

#[test]
fn an_open_url_with_userinfo_is_refused() {
    let text = format!(
        "{}\n{}",
        notice_open("https://user:pass@consent.example/authorize"),
        result(r#""refresh_token":"v1""#)
    );
    assert_eq!(
        rule_of(&text),
        Some(ProduceRule::OpenUrlRefused {
            line: 1,
            why: OpenUrlProblem::Userinfo,
        })
    );
}

// --- the result --------------------------------------------------------------------------

#[test]
fn a_valid_result_admits_its_output() {
    let produced = run(&result(r#""refresh_token":"S7MARKER-refresh-0001""#)).unwrap();
    match produced.terminal() {
        Terminal::Result(outputs) => {
            assert_eq!(outputs[OUT].expose(), "S7MARKER-refresh-0001");
        }
        Terminal::Error(code) => panic!("producer reported {code}"),
    }
}

#[test]
fn a_result_with_another_nonce_is_refused() {
    let text = result(r#""refresh_token":"v1""#).replace(NONCE, "n-other");
    assert_eq!(rule_of(&text), Some(ProduceRule::NonceMismatch { line: 1 }));
}

#[test]
fn a_result_for_another_environment_is_refused() {
    let text = result(r#""refresh_token":"v1""#).replace(ENV, "staging");
    assert_eq!(
        rule_of(&text),
        Some(ProduceRule::WrongEnvironment { line: 1 })
    );
}

#[test]
fn an_undeclared_output_is_reported_by_its_position() {
    let text = result(r#""refresh_token":"v1","extra":"v2""#);
    assert_eq!(rule_of(&text), Some(ProduceRule::Undeclared { position: 2 }));
}

#[test]
fn a_duplicate_output_is_refused_at_its_position() {
    let text = result(r#""refresh_token":"v1","refresh_token":"v2""#);
    assert_eq!(rule_of(&text), Some(ProduceRule::Duplicate { position: 2 }));
}

#[test]
fn a_result_missing_a_declared_output_is_refused() {
    assert_eq!(
        rule_of(&result("")),
        Some(ProduceRule::Missing {
            names: vec![OUT.to_string()],
        })
    );
}

#[test]
fn an_empty_output_is_refused() {
    assert_eq!(
        rule_of(&result(r#""refresh_token":"""#)),
        Some(ProduceRule::Empty {
            output: OUT.to_string(),
        })
    );
}

#[test]
fn a_non_string_output_is_refused() {
    assert_eq!(
        rule_of(&result(r#""refresh_token":123"#)),
        Some(ProduceRule::NotAString {
            output: OUT.to_string(),
        })
    );
}

#[test]
fn an_output_with_a_nul_is_refused() {
    assert_eq!(
        rule_of(&result(r#""refresh_token":"a\u0000b""#)),
        Some(ProduceRule::NotAString {
            output: OUT.to_string(),
        })
    );
}

// --- the error line ----------------------------------------------------------------------

#[test]
fn an_error_line_yields_the_producer_reported_code() {
    let produced = run(&error("access_denied")).unwrap();
    assert!(matches!(produced.terminal(), Terminal::Error(code) if code == "access_denied"));
}

#[test]
fn an_error_code_outside_the_vocabulary_is_refused() {
    assert_eq!(
        rule_of(&error("AccessDenied")),
        Some(ProduceRule::ErrorCode { line: 1 })
    );
}

#[test]
fn an_error_code_longer_than_the_limit_is_refused() {
    assert_eq!(
        rule_of(&error(&"a".repeat(41))),
        Some(ProduceRule::ErrorCode { line: 1 })
    );
}

// --- terminal line and line shape --------------------------------------------------------

#[test]
fn a_second_terminal_line_after_a_result_is_refused() {
    let text = format!(
        "{}\n{}",
        result(r#""refresh_token":"v1""#),
        result(r#""refresh_token":"v2""#)
    );
    assert_eq!(rule_of(&text), Some(ProduceRule::ResultNotLast { line: 2 }));
}

#[test]
fn no_terminal_line_is_refused() {
    assert_eq!(
        rule_of(&notice_waiting()),
        Some(ProduceRule::NoResult)
    );
}

#[test]
fn an_unknown_field_is_refused() {
    let text = format!(
        r#"{{"schema":"{SCHEMA}","kind":"notice","waiting":true,"extra":1}}"#
    );
    assert_eq!(rule_of(&text), Some(ProduceRule::UnknownField { line: 1 }));
}

#[test]
fn a_wrong_schema_is_refused() {
    let text = r#"{"schema":"opv.produce/2","kind":"notice","waiting":true}"#;
    assert_eq!(rule_of(text), Some(ProduceRule::WrongSchema { line: 1 }));
}

#[test]
fn a_line_that_is_not_a_json_object_is_refused() {
    assert_eq!(rule_of("[1, 2]"), Some(ProduceRule::NotJson { line: 1 }));
}

#[test]
fn a_line_longer_than_the_per_line_limit_is_refused() {
    let text = format!("{}{}", notice_waiting(), " ".repeat(LINE_LIMIT));
    assert_eq!(
        rule_of(&text),
        Some(ProduceRule::LineTooLong {
            line: 1,
            limit: 65536,
        })
    );
}

#[test]
fn output_larger_than_the_total_limit_is_refused() {
    let one = format!("{}{}", notice_waiting(), " ".repeat(60_000));
    let text = std::iter::repeat_n(one, 18).collect::<Vec<_>>().join("\n");
    assert_eq!(
        rule_of(&text),
        Some(ProduceRule::TooMuchOutput { limit: 1_048_576 })
    );
}

#[test]
fn a_notice_on_the_second_line_reports_its_line_number() {
    let text = format!(
        "{}\n{}",
        notice_waiting(),
        notice_open("https://evil.example/authorize")
    );
    assert_eq!(
        rule_of(&text),
        Some(ProduceRule::OpenUrlRefused {
            line: 2,
            why: OpenUrlProblem::HostNotListed,
        })
    );
}

// --- secrecy -----------------------------------------------------------------------------

#[test]
fn a_value_is_registered_with_the_output_guard_as_it_is_parsed() {
    let canary = "S7MARKER-registered-at-parse-0001";
    let _ = run(&result(&format!(r#""refresh_token":"{canary}""#)));
    assert!(!crate::scrub::guard_scrub(&format!("x {canary} y")).contains(MARK));
}

#[test]
fn debug_of_a_result_shows_no_output_value() {
    let canary = "S7MARKER-debug-0001";
    let produced = run(&result(&format!(r#""refresh_token":"{canary}""#))).unwrap();
    assert!(!format!("{produced:?}").contains(MARK));
}

#[test]
fn serde_error_text_never_appears_in_a_refusal() {
    let text = format!(r#"{{"schema":"{SCHEMA}","kind":"notice","open_url":{MARK}}}"#);
    let e = run(&text).unwrap_err();
    assert!(!shown(&e).contains("expected value"));
}
