//! Fly.io adapter wrapping `flyctl` (S4; FR-6, FR-7, FR-8, SR-1, SR-3, SR-4, §6.4).
//!
//! STUB: tests first; implementation follows in the next commit.

use zeroize::Zeroizing;

use crate::domain::SecretValue;
use crate::domain::plan::FlySecret;
use crate::error::Error;
use crate::runner::CommandRunner;

/// The Fly CLI binary.
pub const PROGRAM: &str = "flyctl";

/// Longest encoded stdin line (`NAME="""VALUE"""`, excluding the newline) we will send.
pub const MAX_IMPORT_LINE: usize = 60_000;

pub fn list(_r: &dyn CommandRunner, _app: &str) -> Result<Vec<FlySecret>, Error> {
    todo!()
}

pub fn stage(
    _r: &dyn CommandRunner,
    _app: &str,
    _values: &[(String, &SecretValue)],
) -> Result<(), Error> {
    todo!()
}

pub fn unset_staged(_r: &dyn CommandRunner, _app: &str, _names: &[String]) -> Result<(), Error> {
    todo!()
}

pub fn deploy(_r: &dyn CommandRunner, _app: &str) -> Result<(), Error> {
    todo!()
}

pub fn validate_import(_values: &[(String, &SecretValue)]) -> Result<(), Error> {
    todo!()
}

pub fn import_refusal(_value: &[u8]) -> Option<&'static str> {
    todo!()
}

pub fn encode_import(_values: &[(String, &SecretValue)]) -> Result<Zeroizing<Vec<u8>>, Error> {
    todo!()
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    const MARK: &str = "sk-proj-LEAKCANARY";

    fn sv(v: &str) -> SecretValue {
        SecretValue::new(v.to_string())
    }

    fn args(r: &FakeRunner, i: usize) -> Vec<String> {
        r.calls.borrow()[i].args.clone()
    }

    fn stdin(r: &FakeRunner, i: usize) -> Vec<u8> {
        r.calls.borrow()[i].stdin.clone().expect("stdin was sent")
    }

    fn err_text(e: &Error) -> String {
        format!("{e} {e:?} {e:#?}")
    }

    // ---------------------------------------------------------------- stage

    #[test]
    fn stage_sends_values_only_on_stdin() {
        let r = FakeRunner::new([Output::success("")]);
        let v = sv("sk-proj-XYZ");
        stage(&r, "app", &[("FLEET__ALLUMATA__OPENAI_API_KEY".into(), &v)]).unwrap();
        let calls = r.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "flyctl");
        assert_eq!(
            calls[0].args,
            ["secrets", "import", "--app", "app", "--stage"]
        );
        assert!(calls[0].env.is_empty());
        assert_eq!(
            calls[0].stdin.as_deref(),
            Some(&b"FLEET__ALLUMATA__OPENAI_API_KEY=\"\"\"sk-proj-XYZ\"\"\"\n"[..])
        );
        drop(calls);
        assert!(!r.argv_contains("sk-proj"));
    }

    #[test]
    fn stage_batches_every_value_into_one_import_call() {
        let r = FakeRunner::new([Output::success("")]);
        let (a, b, c) = (sv("alpha"), sv(" spaced "), sv("x=y#\"\"z"));
        stage(
            &r,
            "fleet-prod",
            &[("A".into(), &a), ("B_2".into(), &b), ("C".into(), &c)],
        )
        .unwrap();
        assert_eq!(r.calls.borrow().len(), 1);
        assert_eq!(
            args(&r, 0),
            ["secrets", "import", "--app", "fleet-prod", "--stage"]
        );
        assert_eq!(
            stdin(&r, 0),
            b"A=\"\"\"alpha\"\"\"\nB_2=\"\"\" spaced \"\"\"\nC=\"\"\"x=y#\"\"z\"\"\"\n".to_vec()
        );
        for v in ["alpha", "spaced", "x=y"] {
            assert!(!r.argv_contains(v), "{v} reached argv");
        }
    }

    #[test]
    fn empty_stage_makes_no_call() {
        let r = FakeRunner::default();
        stage(&r, "app", &[]).unwrap();
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn stage_refuses_whole_batch_naming_key_and_rule_never_value() {
        let long = format!("{MARK}{}", "x".repeat(MAX_IMPORT_LINE));
        let cases: Vec<(String, &str)> = vec![
            (format!("{MARK}\nsecond"), "import-newline"),
            (format!("{MARK}\r"), "import-newline"),
            (format!("{MARK}\rmid"), "import-newline"),
            (format!("{MARK}\"#frag"), "import-hash-after-odd-quotes"),
            (format!("\"\"\"{MARK}#"), "import-hash-after-odd-quotes"),
            (long, "import-line-too-long"),
        ];
        for (bad, rule) in cases {
            let r = FakeRunner::default(); // no response queued: any call would panic
            let good = sv("fine");
            let bad = sv(&bad);
            let e = stage(
                &r,
                "app",
                &[("GOOD".into(), &good), ("FLEET__P__BAD_KEY".into(), &bad)],
            )
            .unwrap_err();
            assert!(matches!(e, Error::Policy(_)), "{rule}: {e:?}");
            let t = err_text(&e);
            assert!(t.contains("FLEET__P__BAD_KEY"), "{t}");
            assert!(t.contains(rule), "{rule}: {t}");
            assert!(!t.contains(MARK), "value leaked: {t}");
            assert!(!t.contains("GOOD"), "names the wrong key: {t}");
            assert!(r.calls.borrow().is_empty(), "{rule}: staged something");
        }
    }

    #[test]
    fn stage_refuses_invalid_and_duplicate_names_before_any_call() {
        let v = sv(MARK);
        for name in [
            "",
            "lower",
            "1LEADING_DIGIT",
            "_LEAD",
            "HAS-DASH",
            "HAS SPACE",
            "EQ=X",
            "--app",
            "É",
        ] {
            let r = FakeRunner::default();
            let e = stage(&r, "app", &[(name.into(), &v)]).unwrap_err();
            assert!(matches!(e, Error::Policy(_)), "{name}: {e:?}");
            assert!(err_text(&e).contains("fly-name-invalid"), "{name}");
            assert!(!err_text(&e).contains(MARK));
            assert!(r.calls.borrow().is_empty());
        }
        let r = FakeRunner::default();
        let e = stage(&r, "app", &[("DUP".into(), &v), ("DUP".into(), &v)]).unwrap_err();
        let t = err_text(&e);
        assert!(
            t.contains("DUP") && t.contains("import-duplicate-name"),
            "{t}"
        );
        assert!(!t.contains(MARK));
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn line_length_limit_is_on_the_encoded_line() {
        let name = "FLEET__P__K";
        let overhead = name.len() + "=\"\"\"".len() + "\"\"\"".len();
        let at = sv(&"v".repeat(MAX_IMPORT_LINE - overhead));
        assert!(validate_import(&[(name.into(), &at)]).is_ok());
        let over = sv(&"v".repeat(MAX_IMPORT_LINE - overhead + 1));
        let e = validate_import(&[(name.into(), &over)]).unwrap_err();
        assert!(err_text(&e).contains("import-line-too-long"));
        // Multi-byte characters count as bytes, not chars.
        let euro = sv(&"€".repeat((MAX_IMPORT_LINE - overhead) / 3 + 1));
        assert!(validate_import(&[(name.into(), &euro)]).is_err());
    }

    #[test]
    fn import_refusal_byte_rules() {
        assert_eq!(import_refusal(b"plain"), None);
        assert_eq!(import_refusal(b""), None);
        assert_eq!(import_refusal(b"a\nb"), Some("import-newline"));
        assert_eq!(import_refusal(b"a\rb"), Some("import-newline"));
        assert_eq!(
            import_refusal(b"a\"#b"),
            Some("import-hash-after-odd-quotes")
        );
        assert_eq!(import_refusal(b"a\"\"#b"), None);
        assert_eq!(import_refusal(b"#lead"), None);
        assert_eq!(
            import_refusal(b"a#b\"c"),
            None,
            "quotes after the # don't count"
        );
        assert_eq!(import_refusal(b"\xff\xfe"), Some("import-invalid-utf8"));
        assert_eq!(import_refusal(b"ok\xc3"), Some("import-invalid-utf8"));
        assert_eq!(import_refusal("é€😀".as_bytes()), None);
    }

    #[test]
    fn stdin_buffer_is_zeroizing() {
        let v = sv("abc");
        let buf: Zeroizing<Vec<u8>> = encode_import(&[("K".into(), &v)]).unwrap();
        assert_eq!(buf.as_slice(), b"K=\"\"\"abc\"\"\"\n");
    }

    #[test]
    fn stage_failure_is_target_error_without_value_or_stderr() {
        let r = FakeRunner::new([Output::failure(1)]);
        let v = sv(MARK);
        let e = stage(&r, "app", &[("K".into(), &v)]).unwrap_err();
        match &e {
            Error::Target(m) => assert_eq!(m, "fly secrets import failed (exit 1)"),
            other => panic!("{other:?}"),
        }
        assert!(!err_text(&e).contains(MARK));
    }

    // ---------------------------------------------------------------- list

    #[test]
    fn list_parses_names_and_digests() {
        let r = FakeRunner::new([Output::success(
            &include_bytes!("../../tests/fixtures/fly_list.json")[..],
        )]);
        let s = list(&r, "app").unwrap();
        assert_eq!(
            s,
            vec![
                FlySecret {
                    name: "A".into(),
                    digest: Some("<digest-a>".into())
                },
                FlySecret {
                    name: "B".into(),
                    digest: Some("<digest-b>".into())
                },
            ]
        );
        assert_eq!(r.calls.borrow().len(), 1);
        assert_eq!(r.calls.borrow()[0].program, "flyctl");
        assert_eq!(args(&r, 0), ["secrets", "list", "--app", "app", "--json"]);
        assert!(r.calls.borrow()[0].stdin.is_none());
    }

    #[test]
    fn list_real_shape_ignores_status_and_tolerates_missing_digest() {
        let json = br#"[
          {"name":"FLEET__ALLUMATA__OPENAI_API_KEY","digest":"abbf42e97d95a292","status":"Deployed"},
          {"name":"FLEET__ALLUMATA__STRIPE_SECRET_KEY","digest":"abd0c8276c1dd3e9","status":"Staged"},
          {"name":"OTHER_TOOL","digest":"0123456789abcdef","status":"Partial","extra":1},
          {"name":"NULL_DIGEST","digest":null,"status":"Unknown"},
          {"name":"NO_DIGEST"}
        ]"#;
        let r = FakeRunner::new([Output::success(&json[..])]);
        let s = list(&r, "fleet-prod").unwrap();
        let got: Vec<(&str, Option<&str>)> = s
            .iter()
            .map(|f| (f.name.as_str(), f.digest.as_deref()))
            .collect();
        assert_eq!(
            got,
            [
                ("FLEET__ALLUMATA__OPENAI_API_KEY", Some("abbf42e97d95a292")),
                (
                    "FLEET__ALLUMATA__STRIPE_SECRET_KEY",
                    Some("abd0c8276c1dd3e9")
                ),
                ("OTHER_TOOL", Some("0123456789abcdef")),
                ("NULL_DIGEST", None),
                ("NO_DIGEST", None),
            ]
        );
    }

    #[test]
    fn list_of_empty_app_is_empty() {
        let r = FakeRunner::new([Output::success("[]\n")]);
        assert!(list(&r, "app").unwrap().is_empty());
    }

    #[test]
    fn list_malformed_json_is_target_error_without_echoing_output() {
        for body in [
            &b"not json sk-proj-LEAKCANARY"[..],
            b"{\"name\":\"A\"}",
            b"",
        ] {
            let r = FakeRunner::new([Output::success(body)]);
            let e = list(&r, "app").unwrap_err();
            assert!(matches!(e, Error::Target(_)), "{e:?}");
            assert!(!err_text(&e).contains(MARK));
        }
    }

    #[test]
    fn failure_is_target_error() {
        let r = FakeRunner::new([Output::failure(1)]);
        match list(&r, "app") {
            Err(Error::Target(m)) => assert_eq!(m, "fly secrets list failed (exit 1)"),
            other => panic!("{other:?}"),
        }
    }

    // ---------------------------------------------------------------- unset / deploy

    #[test]
    fn unset_staged_passes_names_and_stage_flag() {
        let r = FakeRunner::new([Output::success("")]);
        unset_staged(&r, "app", &["FLEET__A__X".into(), "FLEET__B__Y".into()]).unwrap();
        assert_eq!(
            args(&r, 0),
            [
                "secrets",
                "unset",
                "FLEET__A__X",
                "FLEET__B__Y",
                "--app",
                "app",
                "--stage"
            ]
        );
        assert!(r.calls.borrow()[0].stdin.is_none());
    }

    #[test]
    fn empty_unset_makes_no_call() {
        let r = FakeRunner::default();
        unset_staged(&r, "app", &[]).unwrap();
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn unset_refuses_invalid_names_before_any_call() {
        let r = FakeRunner::default();
        let e = unset_staged(&r, "app", &["OK".into(), "--app".into()]).unwrap_err();
        assert!(err_text(&e).contains("fly-name-invalid"));
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn unset_failure_is_target_error() {
        let r = FakeRunner::new([Output::failure(2)]);
        match unset_staged(&r, "app", &["X".into()]) {
            Err(Error::Target(m)) => assert_eq!(m, "fly secrets unset failed (exit 2)"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn deploy_runs_secrets_deploy() {
        let r = FakeRunner::new([Output::success("")]);
        deploy(&r, "app").unwrap();
        assert_eq!(r.calls.borrow()[0].program, "flyctl");
        assert_eq!(args(&r, 0), ["secrets", "deploy", "--app", "app"]);
    }

    #[test]
    fn deploy_without_machines_is_target_error() {
        // D0: `fly secrets deploy` on an app with no machines exits 1.
        let r = FakeRunner::new([Output::failure(1)]);
        match deploy(&r, "app") {
            Err(Error::Target(m)) => assert_eq!(m, "fly secrets deploy failed (exit 1)"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn non_zero_exit_is_never_classified_as_auth() {
        // flyctl has no distinct auth exit code and stderr is discarded (SR-1), so no exit
        // status may be guessed into Auth.
        for code in [1, 2, 3, 4, 5, 77, 126, 127, 255, -1] {
            let r = FakeRunner::new([Output::failure(code)]);
            assert!(matches!(list(&r, "app"), Err(Error::Target(_))), "{code}");
        }
    }

    #[test]
    fn missing_flyctl_is_dependency_error_other_spawn_errors_are_target() {
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::NotFound);
        assert!(matches!(list(&r, "app"), Err(Error::Dependency(_))));
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::PermissionDenied);
        let v = sv(MARK);
        let e = stage(&r, "app", &[("K".into(), &v)]).unwrap_err();
        assert!(matches!(e, Error::Target(_)), "{e:?}");
        assert!(!err_text(&e).contains(MARK));
        let r = FakeRunner::default();
        r.push_io_error(io::ErrorKind::NotFound);
        assert!(matches!(deploy(&r, "app"), Err(Error::Dependency(_))));
    }

    #[test]
    fn no_value_reaches_argv_across_a_full_sequence() {
        // list A -> stage -> list B -> unset -> deploy: values only ever on stdin (SR-3).
        let r = FakeRunner::new([
            Output::success("[]"),
            Output::success(""),
            Output::success("[]"),
            Output::success(""),
            Output::success(""),
        ]);
        let (a, b) = (sv(MARK), sv(&format!("{MARK}-two \"q\" $x \\n")));
        list(&r, "app").unwrap();
        stage(&r, "app", &[("A".into(), &a), ("B".into(), &b)]).unwrap();
        list(&r, "app").unwrap();
        unset_staged(&r, "app", &["OLD".into()]).unwrap();
        deploy(&r, "app").unwrap();
        assert_eq!(r.calls.borrow().len(), 5);
        assert!(!r.argv_contains(MARK));
        assert!(r.calls.borrow().iter().all(|c| c.env.is_empty()));
        let only_stdin: Vec<bool> = r.calls.borrow().iter().map(|c| c.stdin.is_some()).collect();
        assert_eq!(only_stdin, [false, true, false, false, false]);
    }

    // ------------------------------------------------- flyctl import parser port
    //
    // A Rust port of `parseSecrets` in flyctl v0.4.112 `internal/command/secrets/parser.go`
    // (commit ca63052e), as documented line by line in docs/spike-d0-findings.md
    // ("Follow-up 2a"). Go strings are bytes; every byte the parser inspects (`\n`, `\r`,
    // `#`, `"`, `'`, `=`, ` `) is ASCII, and UTF-8 continuation bytes are never ASCII, so
    // char-level operations on `&str` are equivalent here.

    const TQ: &str = "\"\"\"";

    /// Returns the parsed (key, value) pairs, or `None` where flyctl would misbehave in a
    /// way we can't model faithfully (unterminated multiline at EOF, the `"` panic, a line
    /// with no `=`). Those outcomes are never a faithful round trip either way.
    fn go_parse(input: &str) -> Option<Vec<(String, String)>> {
        let mut out = Vec::new();
        let mut multi: Option<(String, Vec<String>)> = None;
        // L17: bufio.Scanner splits on '\n' and strips one trailing '\r' per line. A final
        // empty token after a trailing '\n' is not emitted; it would be skipped as blank.
        for line in input.split('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.len() >= 64 * 1024 {
                // L17/L77: the scanner stops silently, dropping the rest.
                return Some(out);
            }
            // L62-72: multiline continuation until a line ends with `"""`.
            if let Some((key, parts)) = multi.as_mut() {
                if let Some(last) = line.strip_suffix(TQ) {
                    parts.push(last.to_string());
                    out.push((std::mem::take(key), parts.join("\n")));
                    multi = None;
                } else {
                    parts.push(line.to_string());
                }
                continue;
            }
            // L27: blank / whitespace-only / leading '#' lines are skipped.
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            // L31: split at the first '='.
            let (k, v) = line.split_once('=')?;
            // L35: key TrimSpace; L36: strip leading U+0020 from the value only.
            let key = k.trim().to_string();
            let mut v = v.trim_start_matches(' ');
            // L37-40: cut at the first '#' when an even number of '"' precede it.
            if let Some(i) = v.find('#')
                && v[..i].matches('"').count() % 2 == 0
            {
                v = v[..i].trim_end_matches(' ');
            }
            if v.len() >= 6 && v.starts_with(TQ) && v.ends_with(TQ) {
                // L42-45: triple-quoted, inner text verbatim.
                v = &v[3..v.len() - 3];
            } else if let Some(rest) = v.strip_prefix(TQ) {
                // L46-51: start of a multiline value.
                multi = Some((key, vec![rest.to_string()]));
                continue;
            } else if v == "\"" {
                // L53-59: `value[1:0]` panics in flyctl.
                return None;
            } else if v.len() >= 2
                && ((v.starts_with('"') && v.ends_with('"'))
                    || (v.starts_with('\'') && v.ends_with('\'')))
            {
                v = &v[1..v.len() - 1];
            }
            out.push((key, v.to_string()));
        }
        if multi.is_some() {
            return None;
        }
        Some(out)
    }

    /// What flyctl would store for `value` sent in our encoding, ignoring our refusals.
    fn stored_unchecked(value: &str) -> Option<String> {
        let line = format!("K={TQ}{value}{TQ}\n");
        match go_parse(&line)?.as_slice() {
            [(k, v)] if k == "K" => Some(v.clone()),
            _ => None,
        }
    }

    #[test]
    fn parser_port_matches_documented_examples() {
        // Plain form pitfalls the triple-quoted form avoids (findings 2a).
        let p = |l: &str| go_parse(l).unwrap()[0].1.clone();
        assert_eq!(p("K=pa#ss"), "pa");
        assert_eq!(p("K=  lead"), "lead");
        assert_eq!(p("K=\"wrapped\""), "wrapped");
        assert_eq!(p("K='single'"), "single");
        assert_eq!(p("K=a=b=c"), "a=b=c");
        assert_eq!(p("K= probe-dq\"h#x$y\\z=w"), "probe-dq\"h#x$y\\z=w");
        assert_eq!(p("K=v  # comment"), "v");
        assert_eq!(p(" K =v"), "v");
        assert_eq!(go_parse(" K =v").unwrap()[0].0, "K");
        // Triple-quoted keeps spaces, quotes, `\`, `$`, `=`.
        assert_eq!(
            p("K=\"\"\"  a \"b\" 'c' \\n $X = \"\"\""),
            "  a \"b\" 'c' \\n $X = "
        );
        // A value of exactly `"` panics flyctl.
        assert!(go_parse("K=\"").is_none());
        // Comment and blank lines skipped; CRLF stripped.
        assert_eq!(
            go_parse("# c\n\n   \nA=1\r\nB=2\n").unwrap(),
            vec![("A".into(), "1".into()), ("B".into(), "2".into())]
        );
        // Odd quotes before '#' in our encoding: the cut fires and the value is mangled.
        assert_ne!(stored_unchecked("a\"#b").as_deref(), Some("a\"#b"));
    }

    fn tricky_corpus() -> Vec<String> {
        let mut v: Vec<String> = [
            "",
            " ",
            "  lead",
            "trail  ",
            " both ",
            "\t",
            "\ttab",
            "#",
            "##",
            "#lead",
            "trail#",
            "pa#ss",
            "a #b",
            "postgres://u:p@h/db#frag",
            "\"",
            "\"\"",
            "\"\"\"",
            "\"\"\"\"\"\"",
            "\"wrapped\"",
            "'single'",
            "'",
            "\"\"#even",
            "\"a\"\"b\"#c",
            "\"#odd",
            "a\"#b",
            "\"\"\"#",
            "x\"\"\"y",
            "ends\"\"\"",
            "\"\"\"starts",
            "$HOME",
            "${VAR}",
            "\\",
            "\\n",
            "back\\slash\\",
            "=",
            "==",
            "a=b=c",
            "=lead",
            "é",
            "€uro",
            "😀 emoji 😀",
            "日本語#テスト",
            "mixed \"q\" 'q' $ \\ = # end",
            "sk-proj-abc123_XYZ-789",
            "whsec_0123456789abcdef",
            "base64+/==",
            "\r",
            "a\rb",
            "\n",
            "a\nb",
            "trailing-cr\r",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        // Deterministic pseudo-random values over a tricky alphabet (xorshift64*).
        let alphabet = [
            "\"", "'", "#", "$", "\\", "=", " ", "\t", "a", "Z", "0", "é", "€", "😀", "\"\"\"",
            "\r", "\n", "{", "}", "%", "`", ";", "!", "\u{0}",
        ];
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            s.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        for _ in 0..20_000 {
            let len = (next() % 14) as usize;
            let val: String = (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                .collect();
            v.push(val);
        }
        v
    }

    #[test]
    fn every_accepted_value_round_trips_through_the_parser() {
        let mut accepted = 0;
        for value in tricky_corpus() {
            let v = sv(&value);
            let batch = [("K".to_string(), &v)];
            if validate_import(&batch).is_ok() {
                accepted += 1;
                let buf = encode_import(&batch).unwrap();
                let text = std::str::from_utf8(&buf).unwrap();
                assert_eq!(
                    go_parse(text),
                    Some(vec![("K".to_string(), value.clone())]),
                    "accepted value did not round-trip: {value:?}"
                );
            }
        }
        assert!(accepted > 5_000, "corpus too weak: {accepted} accepted");
    }

    #[test]
    fn refusal_rules_are_exact_for_single_line_values() {
        // For values without newline/CR (which we refuse by policy), the hash rule rejects
        // exactly the values flyctl would mangle: no false refusals, no misses.
        for value in tricky_corpus() {
            if value.contains('\n') || value.contains('\r') {
                continue;
            }
            let refused = import_refusal(value.as_bytes()).is_some();
            let faithful = stored_unchecked(&value).as_deref() == Some(value.as_str());
            assert_eq!(refused, !faithful, "rule mismatch for {value:?}");
        }
    }

    #[test]
    fn multi_value_batch_round_trips_in_order() {
        let corpus = tricky_corpus();
        let accepted: Vec<SecretValue> = corpus
            .iter()
            .filter(|v| import_refusal(v.as_bytes()).is_none())
            .take(500)
            .map(|v| sv(v))
            .collect();
        let batch: Vec<(String, &SecretValue)> = accepted
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("K_{i}"), v))
            .collect();
        let buf = encode_import(&batch).unwrap();
        let parsed = go_parse(std::str::from_utf8(&buf).unwrap()).unwrap();
        let want: Vec<(String, String)> = batch
            .iter()
            .map(|(k, v)| (k.clone(), v.expose().to_string()))
            .collect();
        assert_eq!(parsed, want);
    }
}
