//! Declarative rules engine (FR-14, FR-15). Generic: no product-specific code.
//!
//! `RuleFailure` names the key and the rule, never the value. Values are read with
//! `expose()` only inside `check`; nothing value-bearing is formatted or retained.

use std::fmt;
use std::sync::OnceLock;

use base64::Engine as _;
use regex::Regex;
use zeroize::Zeroizing;

use crate::domain::model::{Environment, KeySpec};
use crate::domain::secret::SecretValue;

/// Maximum accepted value size in bytes. Kept below the Fly import line limit (name + 7 +
/// value ≤ 60 000 bytes) so a value that passes the rules also fits on an import line.
pub const MAX_LEN: usize = 59_000;

/// A failed rule. Holds the key and rule name only (FR-15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleFailure {
    pub key: String,
    pub rule: &'static str,
}

impl fmt::Display for RuleFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: failed {}", self.key, self.rule)
    }
}

impl std::error::Error for RuleFailure {}

/// Whether `refuse_in` lists `env_name`: the key must not exist there at all (FR-15).
pub fn refused_in(spec: &KeySpec, env_name: &str) -> bool {
    spec.rules.refuse_in.iter().any(|e| e == env_name)
}

/// Whether the key is expected for this environment and not skipped by a payments-style
/// mode. A missing mode does not skip (it fails in `check` instead).
pub fn applies(spec: &KeySpec, env_name: &str, env: &Environment, product: &str) -> bool {
    if !spec.environments.iter().any(|e| e == env_name) {
        return false;
    }
    if let Some(p) = &spec.rules.prefix_by_mode
        && let Some(mode) = env.modes.get(product).and_then(|m| m.get(&p.mode))
        && p.skip.iter().any(|s| s == mode)
    {
        return false;
    }
    true
}

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).expect("static regex"))
}

fn email_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, r"^[^@\s,]+@[^@\s,]+\.[^@\s,]+$")
}

const SIGNOZ_BODY: &str = r"[A-Za-z0-9._~+/-]+={0,2}";
const SIGNOZ_PREFIX: &str = "signoz-ingestion-key=";

fn signoz_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    re(&R, &format!("^{SIGNOZ_BODY}$"))
}

/// Transform name: one PEM private key block, staged as a single line.
pub const PEM_PRIVATE_KEY: &str = "pem_private_key";

/// Normalise one PEM private key block to `-----BEGIN L-----<base64>-----END L-----`.
///
/// Accepts the multi-line form (LF or CRLF, surrounding whitespace allowed, as a `.pem` file
/// or a paste) and the already single-line form. `L` must end in `PRIVATE KEY` (PKCS#1
/// `RSA PRIVATE KEY`, PKCS#8 `PRIVATE KEY`, `EC PRIVATE KEY`); the BEGIN and END labels must
/// match; there are no PEM headers (an encrypted `Proc-Type` key is refused); the body is
/// standard base64 of a DER SEQUENCE. Only whitespace is removed, so the output decodes to the
/// same DER: RFC 7468 parsers that skip whitespace inside the body (Rust `pem` 3.x, used by
/// journeeze's GitHub App client) read it unchanged. `None` on any failure; nothing value-
/// bearing is returned or formatted on the error path.
fn pem_private_key(v: &str) -> Option<Zeroizing<String>> {
    let s = v.trim_matches(|c: char| c.is_ascii_whitespace());
    let rest = s.strip_prefix("-----BEGIN ")?;
    let (label, rest) = rest.split_once("-----")?;
    if !label.ends_with("PRIVATE KEY")
        || !label.bytes().all(|b| b.is_ascii_uppercase() || b == b' ')
    {
        return None;
    }
    let end = format!("-----END {label}-----");
    let body = rest.strip_suffix(end.as_str())?;
    if body.contains("-----") {
        return None;
    }
    let mut b64 = Zeroizing::new(String::with_capacity(body.len()));
    b64.extend(body.chars().filter(|c| !c.is_ascii_whitespace()));
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map(Zeroizing::new)
        .ok()?;
    if der.first() != Some(&0x30) {
        return None;
    }
    // Built at its final size: no reallocation leaves an unzeroized copy behind (SR-8).
    let begin = format!("-----BEGIN {label}-----");
    let mut out = Zeroizing::new(String::with_capacity(begin.len() + b64.len() + end.len()));
    out.push_str(&begin);
    out.push_str(&b64);
    out.push_str(&end);
    Some(out)
}

/// Check one value against its key's rules.
///
/// - `Err(refuse_in)`: the environment is listed in `refuse_in` and the value is non-empty.
///   Checked first, before [`applies`], because a refused environment is never one the key
///   is declared for (config validation guarantees it).
/// - `Ok(None)`: the key does not apply (other environment, or skipped by mode), or it is
///   refused here and empty.
/// - `Ok(Some(v))`: the value to stage (after any transform).
/// - `Err`: the first failing rule, naming key and rule only.
pub fn check(
    product: &str,
    key: &str,
    spec: &KeySpec,
    env_name: &str,
    env: &Environment,
    value: &SecretValue,
) -> Result<Option<SecretValue>, RuleFailure> {
    let fail = |rule: &'static str| RuleFailure {
        key: key.to_string(),
        rule,
    };
    let v = value.expose();
    if refused_in(spec, env_name) {
        return if v.is_empty() {
            Ok(None)
        } else {
            Err(fail("refuse_in"))
        };
    }
    if !applies(spec, env_name, env, product) {
        return Ok(None);
    }
    let r = &spec.rules;

    if v.is_empty() {
        return Err(fail("nonempty"));
    }
    // A PEM private key is multi-line in 1Password (a concealed field holds it as pasted or
    // as the downloaded `.pem`). Normalise it to one line *before* the always-on rules so the
    // single-line Fly import format can carry it; every later rule sees the normalised value.
    let pem: Option<Zeroizing<String>> = match r.transform.as_deref() {
        Some(PEM_PRIVATE_KEY) => Some(pem_private_key(v).ok_or_else(|| fail("transform"))?),
        _ => None,
    };
    let v: &str = pem.as_deref().map_or(v, String::as_str);
    if v.contains(['\n', '\r', '\0']) {
        return Err(fail("single_line"));
    }
    if v.trim() != v {
        return Err(fail("no_surrounding_space"));
    }
    if v.len() > MAX_LEN {
        return Err(fail("max_len"));
    }
    if let Some(p) = &r.prefix
        && !v.starts_with(p.as_str())
    {
        return Err(fail("prefix"));
    }
    if let Some(p) = &r.not_prefix
        && p.any_prefix_of(v)
    {
        return Err(fail("not_prefix"));
    }
    if let Some(p) = &r.prefix_by_mode {
        let ok = env
            .modes
            .get(product)
            .and_then(|m| m.get(&p.mode))
            .and_then(|mode| p.values.get(mode))
            .is_some_and(|pre| pre.any_prefix_of(v));
        if !ok {
            return Err(fail("prefix_by_mode"));
        }
    }
    if let Some(pat) = &r.regex {
        // Config validation guarantees the pattern compiles; fail closed otherwise.
        let full = Regex::new(&format!("^(?:{pat})$")).map_err(|_| fail("regex"))?;
        if !full.is_match(v) {
            return Err(fail("regex"));
        }
    }
    if let Some(allowed) = &r.r#enum
        && !allowed.iter().any(|a| a == v)
    {
        return Err(fail("enum"));
    }
    if let Some(n) = r.base64_bytes {
        let ok = base64::engine::general_purpose::STANDARD
            .decode(v)
            .map(Zeroizing::new)
            .is_ok_and(|b| b.len() == n);
        if !ok {
            return Err(fail("base64_bytes"));
        }
    }
    if let Some(n) = r.hex_bytes {
        let ok = hex::decode(v)
            .map(Zeroizing::new)
            .is_ok_and(|b| b.len() == n);
        if !ok {
            return Err(fail("hex_bytes"));
        }
    }
    if r.email_list && !v.split(',').all(|e| email_re().is_match(e)) {
        return Err(fail("email_list"));
    }
    if r.https_url && !(v.starts_with("https://") && !v.contains(char::is_whitespace)) {
        return Err(fail("https_url"));
    }
    if let Some(t) = &r.transform {
        if t == PEM_PRIVATE_KEY {
            return Ok(Some(SecretValue::new(v.to_string())));
        }
        if t != "signoz_ingestion_header" {
            return Err(fail("transform"));
        }
        let body = v.strip_prefix(SIGNOZ_PREFIX).unwrap_or(v);
        if !signoz_re().is_match(body) {
            return Err(fail("transform"));
        }
        // Built at its final size: no reallocation leaves an unzeroized copy behind (SR-8).
        let mut out = String::with_capacity(SIGNOZ_PREFIX.len() + body.len());
        out.push_str(SIGNOZ_PREFIX);
        out.push_str(body);
        return Ok(Some(SecretValue::new(out)));
    }
    Ok(Some(SecretValue::new(v.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;
    use crate::domain::model::{Fleet, Kind, OneOrMany, PrefixByMode, Rules};
    use std::collections::BTreeMap;

    fn f() -> Fleet {
        parse(include_str!("../../tests/fixtures/secrets.toml")).unwrap()
    }
    fn chk(env: &str, key: &str, v: &str) -> Result<Option<String>, RuleFailure> {
        let f = f();
        let spec = &f.products["allumata"].keys[key];
        check(
            "allumata",
            key,
            spec,
            env,
            &f.environments[env],
            &SecretValue::new(v.into()),
        )
        .map(|o| o.map(|s| s.expose().to_string()))
    }

    /// Check `v` against an ad-hoc rule set in env "prod".
    fn with(rules: Rules, v: &str) -> Result<Option<String>, RuleFailure> {
        let f = f();
        let spec = KeySpec {
            kind: Kind::Secret,
            environments: vec!["prod".into(), "staging".into()],
            rules,
            immutable: false,
            guidance: String::new(),
        };
        let env = &f.environments["prod"];
        check(
            "allumata",
            "K",
            &spec,
            "prod",
            env,
            &SecretValue::new(v.into()),
        )
        .map(|o| o.map(|s| s.expose().to_string()))
    }
    fn rule_of(rules: Rules, v: &str) -> &'static str {
        with(rules, v).unwrap_err().rule
    }

    #[test]
    fn openrouter_key_in_openai_field_is_rejected() {
        assert_eq!(
            chk("prod", "OPENAI_API_KEY", "sk-or-v1-abc")
                .unwrap_err()
                .rule,
            "not_prefix"
        );
    }
    #[test]
    fn real_openai_key_passes() {
        assert!(
            chk("prod", "OPENAI_API_KEY", "sk-proj-abc")
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn prefix_rule() {
        assert_eq!(
            chk("prod", "OPENAI_API_KEY", "pk-abc").unwrap_err().rule,
            "prefix"
        );
    }
    #[test]
    fn pasted_trailing_newline_is_rejected_not_trimmed() {
        let e = chk("prod", "OPENAI_API_KEY", "sk-proj-abc\n").unwrap_err();
        assert_eq!((e.key.as_str(), e.rule), ("OPENAI_API_KEY", "single_line"));
        for v in ["sk-proj-abc\r\n", "sk-proj-\0abc", "sk-proj\nabc"] {
            assert_eq!(
                chk("prod", "OPENAI_API_KEY", v).unwrap_err().rule,
                "single_line"
            );
        }
        for v in [" sk-proj-abc", "sk-proj-abc ", "\tsk-proj-abc"] {
            let e = chk("prod", "OPENAI_API_KEY", v).unwrap_err();
            assert_eq!(e.rule, "no_surrounding_space", "{v:?}");
        }
    }
    #[test]
    fn empty_is_rejected() {
        assert_eq!(
            chk("prod", "OPENAI_API_KEY", "").unwrap_err().rule,
            "nonempty"
        );
    }
    #[test]
    fn max_len_boundary() {
        assert!(
            with(Rules::default(), &"a".repeat(MAX_LEN))
                .unwrap()
                .is_some()
        );
        assert_eq!(
            rule_of(Rules::default(), &"a".repeat(MAX_LEN + 1)),
            "max_len"
        );
    }
    #[test]
    fn base64_32_bytes() {
        let ok = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert!(chk("prod", "INTEGRATION_ENC_KEY", &ok).unwrap().is_some());
        assert_eq!(
            chk("prod", "INTEGRATION_ENC_KEY", &"ab".repeat(32))
                .unwrap_err()
                .rule,
            "base64_bytes"
        );
        // not base64 at all
        assert_eq!(
            chk("prod", "INTEGRATION_ENC_KEY", "!!!").unwrap_err().rule,
            "base64_bytes"
        );
    }
    #[test]
    fn stripe_prefix_follows_mode_and_off_skips() {
        assert!(
            chk("staging", "STRIPE_SECRET_KEY", "sk_test_1")
                .unwrap()
                .is_some()
        );
        assert_eq!(
            chk("staging", "STRIPE_SECRET_KEY", "sk_live_1")
                .unwrap_err()
                .rule,
            "prefix_by_mode"
        );
        assert_eq!(chk("prod", "STRIPE_SECRET_KEY", "anything").unwrap(), None);
    }
    #[test]
    fn prefix_by_mode_missing_or_unmapped_mode_fails() {
        let mut f = f();
        let spec = f.products["allumata"].keys["STRIPE_SECRET_KEY"].clone();
        let v = SecretValue::new("sk_test_1".into());
        // mode absent
        f.environments.get_mut("staging").unwrap().modes.clear();
        let env = &f.environments["staging"];
        let e = check("allumata", "STRIPE_SECRET_KEY", &spec, "staging", env, &v).unwrap_err();
        assert_eq!(e.rule, "prefix_by_mode");
        // mode value neither mapped nor skipped
        let mut modes = BTreeMap::new();
        modes.insert(
            "allumata".to_string(),
            BTreeMap::from([("payments".to_string(), "weird".to_string())]),
        );
        f.environments.get_mut("staging").unwrap().modes = modes;
        let env = &f.environments["staging"];
        let e = check("allumata", "STRIPE_SECRET_KEY", &spec, "staging", env, &v).unwrap_err();
        assert_eq!(e.rule, "prefix_by_mode");
    }
    fn stripe_lists(env: &str, v: &str) -> Result<Option<String>, RuleFailure> {
        let t = include_str!("../../tests/fixtures/secrets.toml").replace(
            r#"values = { test = "sk_test_", live = "sk_live_" }"#,
            r#"values = { test = ["sk_test_", "rk_test_"], live = ["sk_live_", "rk_live_"] }"#,
        );
        let mut f = parse(&t).unwrap();
        f.environments
            .get_mut(env)
            .unwrap()
            .modes
            .get_mut("allumata")
            .unwrap()
            .insert("payments".into(), "live".into());
        let spec = &f.products["allumata"].keys["STRIPE_SECRET_KEY"];
        check(
            "allumata",
            "STRIPE_SECRET_KEY",
            spec,
            env,
            &f.environments[env],
            &SecretValue::new(v.into()),
        )
        .map(|o| o.map(|s| s.expose().to_string()))
    }
    #[test]
    fn prefix_by_mode_accepts_any_listed_prefix_for_the_mode() {
        assert!(stripe_lists("staging", "rk_live_1").unwrap().is_some());
        assert!(stripe_lists("staging", "sk_live_1").unwrap().is_some());
        assert_eq!(
            stripe_lists("staging", "rk_test_1").unwrap_err().rule,
            "prefix_by_mode"
        );
        assert_eq!(
            stripe_lists("staging", "sk_test_1").unwrap_err().rule,
            "prefix_by_mode"
        );
    }
    #[test]
    fn not_prefix_list_refuses_each_entry() {
        let r = || Rules {
            not_prefix: Some(OneOrMany::Many(vec!["sk-or-".into(), "sk-ant-".into()])),
            ..Rules::default()
        };
        assert_eq!(rule_of(r(), "sk-or-x"), "not_prefix");
        assert_eq!(rule_of(r(), "sk-ant-x"), "not_prefix");
        assert!(with(r(), "sk-proj-x").unwrap().is_some());
    }
    #[test]
    fn enum_rule() {
        assert_eq!(
            chk("prod", "SIGNUP_POLICY", "closed").unwrap_err().rule,
            "enum"
        );
        assert!(
            chk("prod", "SIGNUP_POLICY", "invite_only")
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn applies_checks_environment_membership() {
        let f = f();
        let spec = &f.products["allumata"].keys["OPENAI_API_KEY"]; // prod only
        assert!(applies(spec, "prod", &f.environments["prod"], "allumata"));
        assert!(!applies(
            spec,
            "staging",
            &f.environments["staging"],
            "allumata"
        ));
        // not applicable: Ok(None) even for an invalid value
        assert_eq!(chk("staging", "OPENAI_API_KEY", "").unwrap(), None);
    }
    #[test]
    fn refuse_in_rejects_listed_environment_only() {
        let r = || Rules {
            refuse_in: vec!["prod".into()],
            ..Rules::default()
        };
        assert_eq!(rule_of(r(), "x"), "refuse_in");
        let r2 = Rules {
            refuse_in: vec!["staging".into()],
            ..Rules::default()
        };
        assert!(with(r2, "x").unwrap().is_some());
    }

    /// I1: refuse_in is evaluated before `applies`. A key declared for prod only and refused
    /// in staging: a non-empty value in staging fails `refuse_in` even though the key does
    /// not apply there; an empty (or absent) one is fine.
    #[test]
    fn refuse_in_fires_where_the_key_does_not_apply() {
        let f = f();
        let spec = KeySpec {
            kind: Kind::Secret,
            environments: vec!["prod".into()],
            rules: Rules {
                refuse_in: vec!["staging".into()],
                ..Rules::default()
            },
            immutable: false,
            guidance: String::new(),
        };
        let env = &f.environments["staging"];
        assert!(!applies(&spec, "staging", env, "allumata"));
        let e = check(
            "allumata",
            "SMTP_PASS",
            &spec,
            "staging",
            env,
            &SecretValue::new("hunter2".into()),
        )
        .unwrap_err();
        assert_eq!((e.key.as_str(), e.rule), ("SMTP_PASS", "refuse_in"));
        let empty = SecretValue::new(String::new());
        assert_eq!(
            check("allumata", "SMTP_PASS", &spec, "staging", env, &empty).map(|o| o.is_none()),
            Ok(true)
        );
        // Whitespace is not empty: still refused.
        let ws = SecretValue::new(" ".into());
        assert_eq!(
            check("allumata", "SMTP_PASS", &spec, "staging", env, &ws)
                .unwrap_err()
                .rule,
            "refuse_in"
        );
    }
    #[test]
    fn hex_bytes_rule() {
        let r = || Rules {
            hex_bytes: Some(4),
            ..Rules::default()
        };
        assert!(with(r(), "deadbeef").unwrap().is_some());
        assert!(with(r(), "DEADBEEF").unwrap().is_some());
        assert_eq!(rule_of(r(), "deadbe"), "hex_bytes");
        assert_eq!(rule_of(r(), "deadbeeg"), "hex_bytes");
        assert_eq!(rule_of(r(), "deadbeef00"), "hex_bytes");
    }
    #[test]
    fn email_list_rule() {
        let r = || Rules {
            email_list: true,
            ..Rules::default()
        };
        assert!(with(r(), "a@b.co").unwrap().is_some());
        assert!(with(r(), "a@b.co,c@d.org").unwrap().is_some());
        for bad in [
            "a@b",
            "a@b.co,",
            "a@b.co, c@d.org",
            "a b@c.de",
            "plain",
            "a@@b.co",
        ] {
            assert_eq!(rule_of(r(), bad), "email_list", "{bad}");
        }
    }
    #[test]
    fn https_url_rule() {
        let r = || Rules {
            https_url: true,
            ..Rules::default()
        };
        assert!(with(r(), "https://example.com/x?y=1").unwrap().is_some());
        for bad in ["http://example.com", "example.com", "https://a b"] {
            assert_eq!(rule_of(r(), bad), "https_url", "{bad}");
        }
    }
    #[test]
    fn regex_rule_is_full_match() {
        let r = || Rules {
            regex: Some("[a-z]{3}[0-9]".into()),
            ..Rules::default()
        };
        assert!(with(r(), "abc1").unwrap().is_some());
        assert_eq!(rule_of(r(), "abc12"), "regex");
        assert_eq!(rule_of(r(), "xabc1"), "regex");
        // alternation must not escape the anchors
        let alt = Rules {
            regex: Some("aa|bb".into()),
            ..Rules::default()
        };
        assert_eq!(rule_of(alt, "aax"), "regex");
    }
    #[test]
    fn signoz_transform_normalises_and_returns_transformed_value() {
        let r = || Rules {
            transform: Some("signoz_ingestion_header".into()),
            ..Rules::default()
        };
        let want = "signoz-ingestion-key=abc.DEF_1~+/-x==";
        assert_eq!(with(r(), "abc.DEF_1~+/-x==").unwrap().unwrap(), want);
        assert_eq!(with(r(), want).unwrap().unwrap(), want);
        for bad in [
            "a b",
            "ab===",
            "a$b",
            "signoz-ingestion-key=",
            "signoz-ingestion-key=a b",
        ] {
            assert_eq!(rule_of(r(), bad), "transform", "{bad}");
        }
    }
    fn pem(label: &str, eol: &str) -> (String, String) {
        let der: Vec<u8> = std::iter::once(0x30u8)
            .chain((0..150u8).map(|i| i.wrapping_mul(7)))
            .collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let lines: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        let multi = format!(
            "-----BEGIN {label}-----{eol}{}{eol}-----END {label}-----{eol}",
            lines.join(eol)
        );
        let single = format!("-----BEGIN {label}-----{b64}-----END {label}-----");
        (multi, single)
    }
    fn pem_rules() -> Rules {
        Rules {
            transform: Some(PEM_PRIVATE_KEY.into()),
            ..Rules::default()
        }
    }
    #[test]
    fn pem_private_key_multiline_is_staged_as_one_line() {
        for label in ["RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY"] {
            for eol in ["\n", "\r\n"] {
                let (multi, single) = pem(label, eol);
                assert_eq!(
                    with(pem_rules(), &multi).unwrap().unwrap(),
                    single,
                    "{label}"
                );
                // Already single-line (a bundle-migrated value) passes unchanged.
                assert_eq!(with(pem_rules(), &single).unwrap().unwrap(), single);
                assert!(!single.contains(['\n', '\r']));
            }
        }
    }
    #[test]
    fn pem_private_key_refusals_name_the_rule_only() {
        let (multi, _) = pem("RSA PRIVATE KEY", "\n");
        let (cert, _) = pem("CERTIFICATE", "\n");
        let mismatched = multi.replace("-----END RSA", "-----END EC");
        let encrypted = multi.replace(
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n",
        );
        let not_der = "-----BEGIN PRIVATE KEY-----QUJD-----END PRIVATE KEY-----";
        let two = format!("{multi}{multi}");
        for bad in [
            cert.as_str(),
            mismatched.as_str(),
            encrypted.as_str(),
            not_der,
            two.as_str(),
            "-----BEGIN PRIVATE KEY-----%%%-----END PRIVATE KEY-----",
            "not a pem",
        ] {
            let e = with(pem_rules(), bad).unwrap_err();
            assert_eq!(e.rule, "transform");
            assert_eq!(e.to_string(), "K: failed transform");
        }
    }
    #[test]
    fn unknown_transform_fails_closed() {
        let r = Rules {
            transform: Some("nope".into()),
            ..Rules::default()
        };
        assert_eq!(rule_of(r, "x"), "transform");
    }
    #[test]
    fn rules_run_in_documented_order() {
        // empty beats everything; prefix beats not_prefix etc.
        let r = Rules {
            prefix: Some("a".into()),
            ..Rules::default()
        };
        assert_eq!(rule_of(r.clone(), ""), "nonempty");
        assert_eq!(rule_of(r, "b\n"), "single_line");
    }

    const MARK: &str = "ZQXMARKERZQX";

    #[test]
    fn failure_never_contains_value() {
        let prefixed = |s: &str| format!("{MARK}{s}");
        let mut cases: Vec<(Rules, String)> = vec![
            (Rules::default(), String::new()), // nonempty: marker-free by nature
            (Rules::default(), prefixed("\nx")),
            (Rules::default(), format!(" {MARK}")),
            (Rules::default(), format!("{MARK}{}", "a".repeat(MAX_LEN))),
            (
                Rules {
                    refuse_in: vec!["prod".into()],
                    ..Rules::default()
                },
                prefixed(""),
            ),
            (
                Rules {
                    prefix: Some("zzz".into()),
                    ..Rules::default()
                },
                prefixed(""),
            ),
            (
                Rules {
                    not_prefix: Some(OneOrMany::Many(vec!["nope".into(), "ZQX".into()])),
                    ..Rules::default()
                },
                prefixed(""),
            ),
            (
                Rules {
                    prefix_by_mode: Some(PrefixByMode {
                        mode: "payments".into(),
                        values: BTreeMap::new(),
                        skip: vec![],
                    }),
                    ..Rules::default()
                },
                prefixed(""),
            ),
            (
                Rules {
                    regex: Some("nomatch".into()),
                    ..Rules::default()
                },
                prefixed(""),
            ),
            (
                Rules {
                    r#enum: Some(vec!["a".into()]),
                    ..Rules::default()
                },
                prefixed(""),
            ),
            (
                Rules {
                    base64_bytes: Some(3),
                    ..Rules::default()
                },
                prefixed(""),
            ),
            (
                Rules {
                    hex_bytes: Some(3),
                    ..Rules::default()
                },
                prefixed(""),
            ),
            (
                Rules {
                    email_list: true,
                    ..Rules::default()
                },
                prefixed(""),
            ),
            (
                Rules {
                    https_url: true,
                    ..Rules::default()
                },
                prefixed(""),
            ),
            (
                Rules {
                    transform: Some("signoz_ingestion_header".into()),
                    ..Rules::default()
                },
                format!("{MARK} $"),
            ),
            (
                Rules {
                    transform: Some("unknown".into()),
                    ..Rules::default()
                },
                prefixed(""),
            ),
        ];
        // regex that itself contains the marker must not leak via the failure either
        cases.push((
            Rules {
                regex: Some(format!("{MARK}Z")),
                ..Rules::default()
            },
            prefixed(""),
        ));
        let mut n = 0;
        for (rules, v) in cases {
            if let Err(e) = with(rules, &v) {
                n += 1;
                let shown = format!("{e} {e:?} {e:#?}");
                let _ = &shown;
                // the regex-pattern case legitimately names no value; check all the same
                assert!(!shown.contains(MARK), "leak in {shown}");
                let err = crate::error::Error::Policy(e.to_string());
                let shown = format!("{err} {err:?}");
                assert!(!shown.contains(MARK), "leak in {shown}");
            }
        }
        assert!(n >= 15, "expected nearly every case to fail, got {n}");
    }
}
