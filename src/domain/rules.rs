//! Declarative rules engine (FR-14, FR-15). Generic: no product-specific code.
//!
//! `RuleFailure` names the key, the rule and a [`Reason`], never the value. Values are read
//! with `expose()` only inside `check`; nothing value-bearing is formatted or retained.
//!
//! FR-22: every reason comes from its rule's closed set below. A reason is a compile-time
//! constant or is built only from configuration (a configured prefix, a mode, a byte count),
//! never from the value: no length, position, character, actual prefix or label read from it.

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

/// A failed rule. Holds the key, the rule name and why, never the value (FR-15, FR-22).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleFailure {
    pub key: String,
    pub rule: &'static str,
    pub reason: Reason,
}

impl fmt::Display for RuleFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: failed {} ({})", self.key, self.rule, self.reason)
    }
}

/// Why a rule failed (FR-22). The rule name stays the stable identifier; a reason may be
/// added or reworded in a minor release.
///
/// Closed by construction: [`Reason::Fixed`] holds only `&'static str` constants (the
/// `REASON_*` and `PEM_*` constants below and the Fly import reasons), and every other
/// variant carries only text or numbers taken from the configuration. Nothing here is ever
/// built from a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// One constant from the rule's fixed set.
    Fixed(&'static str),
    /// `prefix`: the configured prefix the value does not start with.
    ExpectedPrefix(String),
    /// `prefix_by_mode`: the environment's mode value (from config) whose prefixes the
    /// value does not start with.
    WrongPrefixForMode(String),
    /// `prefix_by_mode`: the configured mode name is not set (for the product, under the
    /// fleet profile) in this environment. Worded to read under both profiles (FR-20).
    ModeNotSet(String),
    /// `prefix_by_mode`: the configured mode value has no prefix and is not skipped.
    ModeUnmapped(String),
    /// `base64_bytes` / `hex_bytes`: decodes, but not to the configured byte count.
    NotBytes(usize),
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::Fixed(s) => f.write_str(s),
            Reason::ExpectedPrefix(p) => write!(f, "expected prefix {p}"),
            Reason::WrongPrefixForMode(m) => write!(f, "wrong prefix for mode {m}"),
            Reason::ModeNotSet(m) => write!(f, "mode {m} is not set in this environment"),
            Reason::ModeUnmapped(m) => write!(f, "no prefix is configured for mode {m}"),
            Reason::NotBytes(n) => write!(f, "does not decode to {n} bytes"),
        }
    }
}

/// `refuse_in`.
pub const REASON_REFUSED: &str = "must not be set in this environment";
/// `nonempty`.
pub const REASON_EMPTY: &str = "empty";
/// `single_line`.
pub const REASON_MULTILINE: &str = "contains a line break or NUL";
/// `no_surrounding_space`.
pub const REASON_SURROUNDING_SPACE: &str = "leading or trailing whitespace";
/// `max_len` (the limit is [`MAX_LEN`]; a unit test keeps the two in step).
pub const REASON_TOO_LONG: &str = "longer than the 59000-byte limit";
/// `not_prefix`. Never names which refused prefix matched: that would be the actual prefix.
pub const REASON_REFUSED_PREFIX: &str = "starts with a refused prefix";
/// `prefix_by_mode` and `regex`/`pattern` when the configured pattern does not compile.
pub const REASON_BAD_PATTERN: &str = "configured pattern does not compile";
/// `regex`.
pub const REASON_NO_REGEX_MATCH: &str = "does not match the configured regex";
/// `enum`.
pub const REASON_NOT_ALLOWED: &str = "not one of the allowed values";
/// `base64_bytes`.
pub const REASON_NOT_BASE64: &str = "not standard base64";
/// `hex_bytes`.
pub const REASON_NOT_HEX: &str = "not hex";
/// `email_list`.
pub const REASON_NOT_EMAIL_LIST: &str = "not a comma-separated list of email addresses";
/// `https_url`.
pub const REASON_NOT_HTTPS: &str = "not an https:// URL";
/// `https_url`.
pub const REASON_URL_WHITESPACE: &str = "URL contains whitespace";
/// `ensure_prefix`.
pub const REASON_NOTHING_AFTER_PREFIX: &str = "nothing after the prefix";
/// `pattern`.
pub const REASON_NO_PATTERN_MATCH: &str = "text after the prefix does not match the pattern";
/// `transform` with a name this version does not know.
pub const REASON_UNKNOWN_TRANSFORM: &str = "unknown transform";

/// `pem_private_key` (rule `transform`): no `-----BEGIN ...-----` / `-----END ...-----`.
pub const PEM_NO_MARKERS: &str = "no BEGIN/END markers";
/// `pem_private_key`: the END label is not the BEGIN label.
pub const PEM_LABELS_DIFFER: &str = "BEGIN/END labels differ";
/// `pem_private_key`: the label does not end in `PRIVATE KEY` (or is not upper case).
pub const PEM_NOT_PRIVATE_KEY: &str = "not a private key";
/// `pem_private_key`: `ENCRYPTED PRIVATE KEY`, or a `Proc-Type:` header.
pub const PEM_ENCRYPTED: &str = "encrypted key";
/// `pem_private_key`: another `-----` marker inside the block.
pub const PEM_MORE_THAN_ONE_BLOCK: &str = "more than one PEM block";
/// `pem_private_key`: the body does not decode as standard base64.
pub const PEM_BODY_NOT_BASE64: &str = "body is not base64";
/// `pem_private_key`: the body does not decode to a DER SEQUENCE.
pub const PEM_NOT_KEY_STRUCTURE: &str = "not a key structure";

/// The seven `pem_private_key` reasons (FR-22), in the order `pem_private_key` checks them.
pub const PEM_REASONS: [&str; 7] = [
    PEM_NO_MARKERS,
    PEM_MORE_THAN_ONE_BLOCK,
    PEM_LABELS_DIFFER,
    PEM_NOT_PRIVATE_KEY,
    PEM_ENCRYPTED,
    PEM_BODY_NOT_BASE64,
    PEM_NOT_KEY_STRUCTURE,
];

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

/// The generic `pattern` used to reproduce the removed SigNoz body check in the 0.4.0
/// removal error (FR-24).
pub const SIGNOZ_BODY: &str = r"[A-Za-z0-9._~+/-]+={0,2}";
/// The prefix of the removed SigNoz ingestion header (FR-24).
pub const SIGNOZ_PREFIX: &str = "signoz-ingestion-key=";

/// Transform name: one PEM private key block, staged as a single line.
pub const PEM_PRIVATE_KEY: &str = "pem_private_key";

/// `ensure_prefix`/`pattern` normalisation (FR-24). Accepts the value with or without
/// `prefix`, stages exactly one `prefix`, and (when given) requires the body after the
/// prefix to fully match `pattern`. Returns the staged value or the failing rule name and
/// its reason. Built at its final size: no reallocation leaves an unzeroized copy behind
/// (SR-8).
fn ensure_prefixed(
    v: &str,
    prefix: &str,
    pattern: Option<&str>,
) -> Result<SecretValue, (&'static str, &'static str)> {
    let body = v.strip_prefix(prefix).unwrap_or(v);
    if body.is_empty() {
        return Err(("ensure_prefix", REASON_NOTHING_AFTER_PREFIX));
    }
    if let Some(pat) = pattern {
        // Config validation guarantees the pattern compiles; fail closed otherwise.
        let full =
            Regex::new(&format!("^(?:{pat})$")).map_err(|_| ("pattern", REASON_BAD_PATTERN))?;
        if !full.is_match(body) {
            return Err(("pattern", REASON_NO_PATTERN_MATCH));
        }
    }
    let mut out = String::with_capacity(prefix.len() + body.len());
    out.push_str(prefix);
    out.push_str(body);
    Ok(SecretValue::new(out))
}

/// Normalise one PEM private key block to `-----BEGIN L-----<base64>-----END L-----`.
///
/// Accepts the multi-line form (LF or CRLF, surrounding whitespace allowed, as a `.pem` file
/// or a paste) and the already single-line form. `L` must end in `PRIVATE KEY` (PKCS#1
/// `RSA PRIVATE KEY`, PKCS#8 `PRIVATE KEY`, `EC PRIVATE KEY`); the BEGIN and END labels must
/// match; the key must not be encrypted (`ENCRYPTED PRIVATE KEY`, or a `Proc-Type` header);
/// the body is standard base64 of a DER SEQUENCE. Only whitespace is removed, so the output
/// decodes to the same DER: RFC 7468 parsers that skip whitespace inside the body (Rust
/// `pem` 3.x, used by journeeze's GitHub App client) read it unchanged.
///
/// On failure returns one of [`PEM_REASONS`] (FR-22): a constant, never anything read from
/// the value (no label, length or position).
fn pem_private_key(v: &str) -> Result<Zeroizing<String>, &'static str> {
    let s = v.trim_matches(|c: char| c.is_ascii_whitespace());
    let rest = s.strip_prefix("-----BEGIN ").ok_or(PEM_NO_MARKERS)?;
    let (label, rest) = rest.split_once("-----").ok_or(PEM_NO_MARKERS)?;
    // The last END marker closes the block; anything else that looks like a marker inside
    // it is a second block.
    let end_at = rest.rfind("-----END ").ok_or(PEM_NO_MARKERS)?;
    let (body, end_marker) = rest.split_at(end_at);
    let end_label = end_marker["-----END ".len()..]
        .strip_suffix("-----")
        .ok_or(PEM_NO_MARKERS)?;
    if body.contains("-----") || end_label.contains("-----") {
        return Err(PEM_MORE_THAN_ONE_BLOCK);
    }
    if end_label != label {
        return Err(PEM_LABELS_DIFFER);
    }
    if !label.ends_with("PRIVATE KEY")
        || !label.bytes().all(|b| b.is_ascii_uppercase() || b == b' ')
    {
        return Err(PEM_NOT_PRIVATE_KEY);
    }
    if label.starts_with("ENCRYPTED ") || body.contains("Proc-Type:") {
        return Err(PEM_ENCRYPTED);
    }
    let mut b64 = Zeroizing::new(String::with_capacity(body.len()));
    b64.extend(body.chars().filter(|c| !c.is_ascii_whitespace()));
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| PEM_BODY_NOT_BASE64)?;
    if der.first() != Some(&0x30) {
        return Err(PEM_NOT_KEY_STRUCTURE);
    }
    // Built at its final size: no reallocation leaves an unzeroized copy behind (SR-8).
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Zeroizing::new(String::with_capacity(begin.len() + b64.len() + end.len()));
    out.push_str(&begin);
    out.push_str(&b64);
    out.push_str(&end);
    Ok(out)
}

/// Check one value against its key's rules.
///
/// - `Err(refuse_in)`: the environment is listed in `refuse_in` and the value is non-empty.
///   Checked first, before [`applies`], because a refused environment is never one the key
///   is declared for (config validation guarantees it).
/// - `Ok(None)`: the key does not apply (other environment, or skipped by mode), or it is
///   refused here and empty.
/// - `Ok(Some(v))`: the value to stage (after any transform).
/// - `Err`: the first failing rule, naming key, rule and [`Reason`] only.
pub fn check(
    product: &str,
    key: &str,
    spec: &KeySpec,
    env_name: &str,
    env: &Environment,
    value: &SecretValue,
) -> Result<Option<SecretValue>, RuleFailure> {
    let fail_with = |rule: &'static str, reason: Reason| RuleFailure {
        key: key.to_string(),
        rule,
        reason,
    };
    let fail = |rule: &'static str, reason: &'static str| fail_with(rule, Reason::Fixed(reason));
    let v = value.expose();
    if refused_in(spec, env_name) {
        return if v.is_empty() {
            Ok(None)
        } else {
            Err(fail("refuse_in", REASON_REFUSED))
        };
    }
    if !applies(spec, env_name, env, product) {
        return Ok(None);
    }
    let r = &spec.rules;

    if v.is_empty() {
        return Err(fail("nonempty", REASON_EMPTY));
    }
    // A PEM private key is multi-line in 1Password (a concealed field holds it as pasted or
    // as the downloaded `.pem`). Normalise it to one line *before* the always-on rules so the
    // single-line Fly import format can carry it; every later rule sees the normalised value.
    let pem: Option<Zeroizing<String>> = match r.transform.as_deref() {
        Some(PEM_PRIVATE_KEY) => Some(pem_private_key(v).map_err(|why| fail("transform", why))?),
        _ => None,
    };
    let v: &str = pem.as_deref().map_or(v, String::as_str);
    if v.contains(['\n', '\r', '\0']) {
        return Err(fail("single_line", REASON_MULTILINE));
    }
    if v.trim() != v {
        return Err(fail("no_surrounding_space", REASON_SURROUNDING_SPACE));
    }
    if v.len() > MAX_LEN {
        return Err(fail("max_len", REASON_TOO_LONG));
    }
    if let Some(p) = &r.prefix
        && !v.starts_with(p.as_str())
    {
        return Err(fail_with("prefix", Reason::ExpectedPrefix(p.clone())));
    }
    if let Some(p) = &r.not_prefix
        && p.any_prefix_of(v)
    {
        return Err(fail("not_prefix", REASON_REFUSED_PREFIX));
    }
    if let Some(p) = &r.prefix_by_mode {
        let mode = env.modes.get(product).and_then(|m| m.get(&p.mode));
        let why = match mode {
            None => Some(Reason::ModeNotSet(p.mode.clone())),
            Some(mode) => match p.values.get(mode) {
                None => Some(Reason::ModeUnmapped(mode.clone())),
                Some(pre) if !pre.any_prefix_of(v) => {
                    Some(Reason::WrongPrefixForMode(mode.clone()))
                }
                Some(_) => None,
            },
        };
        if let Some(why) = why {
            return Err(fail_with("prefix_by_mode", why));
        }
    }
    if let Some(pat) = &r.regex {
        // Config validation guarantees the pattern compiles; fail closed otherwise.
        let full =
            Regex::new(&format!("^(?:{pat})$")).map_err(|_| fail("regex", REASON_BAD_PATTERN))?;
        if !full.is_match(v) {
            return Err(fail("regex", REASON_NO_REGEX_MATCH));
        }
    }
    if let Some(allowed) = &r.r#enum
        && !allowed.iter().any(|a| a == v)
    {
        return Err(fail("enum", REASON_NOT_ALLOWED));
    }
    if let Some(n) = r.base64_bytes {
        match base64::engine::general_purpose::STANDARD
            .decode(v)
            .map(Zeroizing::new)
        {
            Err(_) => return Err(fail("base64_bytes", REASON_NOT_BASE64)),
            Ok(b) if b.len() != n => return Err(fail_with("base64_bytes", Reason::NotBytes(n))),
            Ok(_) => {}
        }
    }
    if let Some(n) = r.hex_bytes {
        match hex::decode(v).map(Zeroizing::new) {
            Err(_) => return Err(fail("hex_bytes", REASON_NOT_HEX)),
            Ok(b) if b.len() != n => return Err(fail_with("hex_bytes", Reason::NotBytes(n))),
            Ok(_) => {}
        }
    }
    if r.email_list && !v.split(',').all(|e| email_re().is_match(e)) {
        return Err(fail("email_list", REASON_NOT_EMAIL_LIST));
    }
    if r.https_url {
        if !v.starts_with("https://") {
            return Err(fail("https_url", REASON_NOT_HTTPS));
        }
        if v.contains(char::is_whitespace) {
            return Err(fail("https_url", REASON_URL_WHITESPACE));
        }
    }
    if let Some(prefix) = &r.ensure_prefix {
        return ensure_prefixed(v, prefix, r.pattern.as_deref())
            .map(Some)
            .map_err(|(rule, why)| fail(rule, why));
    }
    if let Some(t) = &r.transform {
        if t == PEM_PRIVATE_KEY {
            return Ok(Some(SecretValue::new(v.to_string())));
        }
        return Err(fail("transform", REASON_UNKNOWN_TRANSFORM));
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
    fn prefixed_rules(prefix: &str, pattern: Option<&str>) -> Rules {
        Rules {
            ensure_prefix: Some(prefix.into()),
            pattern: pattern.map(Into::into),
            ..Rules::default()
        }
    }
    #[test]
    fn ensure_prefix_prepends_a_missing_prefix() {
        assert_eq!(
            with(prefixed_rules("sk-", None), "abc").unwrap().unwrap(),
            "sk-abc"
        );
    }
    #[test]
    fn ensure_prefix_keeps_an_existing_prefix_once() {
        assert_eq!(
            with(prefixed_rules("sk-", None), "sk-abc")
                .unwrap()
                .unwrap(),
            "sk-abc"
        );
    }
    #[test]
    fn ensure_prefix_empty_body_fails_as_ensure_prefix() {
        assert_eq!(rule_of(prefixed_rules("sk-", None), "sk-"), "ensure_prefix");
    }
    #[test]
    fn pattern_rejects_a_body_that_does_not_match() {
        assert_eq!(
            rule_of(prefixed_rules("sk-", Some("[a-z]+")), "sk-ABC"),
            "pattern"
        );
    }
    #[test]
    fn pattern_accepts_a_body_after_the_prefix_is_prepended() {
        assert_eq!(
            with(prefixed_rules("sk-", Some("[a-z]+")), "abc")
                .unwrap()
                .unwrap(),
            "sk-abc"
        );
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
            assert!(e.to_string().starts_with("K: failed transform ("), "{e}");
        }
    }
    fn pem_reason(v: &str) -> (&'static str, Reason) {
        let e = with(pem_rules(), v).unwrap_err();
        (e.rule, e.reason)
    }
    fn pem_fails_with(v: &str, why: &'static str) {
        assert_eq!(pem_reason(v), ("transform", Reason::Fixed(why)));
    }
    #[test]
    fn pem_reason_no_markers() {
        pem_fails_with("not a pem", PEM_NO_MARKERS);
    }
    #[test]
    fn pem_reason_no_end_marker() {
        let (multi, _) = pem("RSA PRIVATE KEY", "\n");
        pem_fails_with(
            &multi.replace("-----END RSA PRIVATE KEY-----", ""),
            PEM_NO_MARKERS,
        );
    }
    #[test]
    fn pem_reason_labels_differ() {
        let (multi, _) = pem("RSA PRIVATE KEY", "\n");
        pem_fails_with(
            &multi.replace("-----END RSA", "-----END EC"),
            PEM_LABELS_DIFFER,
        );
    }
    #[test]
    fn pem_reason_not_a_private_key() {
        let (cert, _) = pem("CERTIFICATE", "\n");
        pem_fails_with(&cert, PEM_NOT_PRIVATE_KEY);
    }
    #[test]
    fn pem_reason_encrypted_proc_type_header() {
        let (multi, _) = pem("RSA PRIVATE KEY", "\n");
        let encrypted = multi.replace(
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n",
        );
        pem_fails_with(&encrypted, PEM_ENCRYPTED);
    }
    #[test]
    fn pem_reason_encrypted_pkcs8_label() {
        let (enc, _) = pem("ENCRYPTED PRIVATE KEY", "\n");
        pem_fails_with(&enc, PEM_ENCRYPTED);
    }
    #[test]
    fn pem_reason_more_than_one_block() {
        let (multi, _) = pem("RSA PRIVATE KEY", "\n");
        pem_fails_with(&format!("{multi}{multi}"), PEM_MORE_THAN_ONE_BLOCK);
    }
    #[test]
    fn pem_reason_body_not_base64() {
        pem_fails_with(
            "-----BEGIN PRIVATE KEY-----%%%-----END PRIVATE KEY-----",
            PEM_BODY_NOT_BASE64,
        );
    }
    #[test]
    fn pem_reason_not_a_key_structure() {
        pem_fails_with(
            "-----BEGIN PRIVATE KEY-----QUJD-----END PRIVATE KEY-----",
            PEM_NOT_KEY_STRUCTURE,
        );
    }
    #[test]
    fn pem_reasons_are_seven_distinct_constants() {
        let set: std::collections::BTreeSet<&str> = PEM_REASONS.into_iter().collect();
        assert_eq!(set.len(), 7);
    }
    #[test]
    fn rule_failure_display_shows_rule_then_reason() {
        let (multi, _) = pem("RSA PRIVATE KEY", "\n");
        let e = with(pem_rules(), &multi.replace("-----END RSA", "-----END EC")).unwrap_err();
        assert_eq!(
            e.to_string(),
            "K: failed transform (BEGIN/END labels differ)"
        );
    }
    fn reason_of(rules: Rules, v: &str) -> String {
        with(rules, v).unwrap_err().reason.to_string()
    }
    #[test]
    fn prefix_reason_names_the_configured_prefix() {
        let r = Rules {
            prefix: Some("sk-".into()),
            ..Rules::default()
        };
        assert_eq!(reason_of(r, "pk-abc"), "expected prefix sk-");
    }
    #[test]
    fn not_prefix_reason_never_names_the_matching_prefix() {
        let r = Rules {
            not_prefix: Some(OneOrMany::One("sk-or-".into())),
            ..Rules::default()
        };
        assert_eq!(reason_of(r, "sk-or-x"), REASON_REFUSED_PREFIX);
    }
    #[test]
    fn prefix_by_mode_reason_names_the_mode() {
        assert_eq!(
            chk("staging", "STRIPE_SECRET_KEY", "sk_live_1")
                .unwrap_err()
                .reason
                .to_string(),
            "wrong prefix for mode test"
        );
    }
    #[test]
    fn prefix_by_mode_reason_when_mode_is_not_set() {
        let mut f = f();
        let spec = f.products["allumata"].keys["STRIPE_SECRET_KEY"].clone();
        f.environments.get_mut("staging").unwrap().modes.clear();
        let v = SecretValue::new("sk_test_1".into());
        let env = &f.environments["staging"];
        let e = check("allumata", "STRIPE_SECRET_KEY", &spec, "staging", env, &v).unwrap_err();
        assert_eq!(e.reason, Reason::ModeNotSet("payments".into()));
    }
    #[test]
    fn prefix_by_mode_reason_when_mode_is_unmapped() {
        let r = Rules {
            prefix_by_mode: Some(PrefixByMode {
                mode: "payments".into(),
                values: BTreeMap::new(),
                skip: vec![],
            }),
            ..Rules::default()
        };
        // prod has allumata.payments = "off", neither mapped nor skipped here.
        assert_eq!(reason_of(r, "x"), "no prefix is configured for mode off");
    }
    #[test]
    fn base64_bytes_reason_not_base64() {
        let r = Rules {
            base64_bytes: Some(32),
            ..Rules::default()
        };
        assert_eq!(reason_of(r, "!!!"), REASON_NOT_BASE64);
    }
    #[test]
    fn base64_bytes_reason_wrong_byte_count_names_configured_count() {
        let r = Rules {
            base64_bytes: Some(32),
            ..Rules::default()
        };
        assert_eq!(reason_of(r, "QUJD"), "does not decode to 32 bytes");
    }
    #[test]
    fn hex_bytes_reason_not_hex() {
        let r = Rules {
            hex_bytes: Some(4),
            ..Rules::default()
        };
        assert_eq!(reason_of(r, "deadbeeg"), REASON_NOT_HEX);
    }
    #[test]
    fn hex_bytes_reason_wrong_byte_count_names_configured_count() {
        let r = Rules {
            hex_bytes: Some(4),
            ..Rules::default()
        };
        assert_eq!(reason_of(r, "dead"), "does not decode to 4 bytes");
    }
    #[test]
    fn https_url_reason_not_https() {
        let r = Rules {
            https_url: true,
            ..Rules::default()
        };
        assert_eq!(reason_of(r, "http://a"), REASON_NOT_HTTPS);
    }
    #[test]
    fn https_url_reason_whitespace() {
        let r = Rules {
            https_url: true,
            ..Rules::default()
        };
        assert_eq!(reason_of(r, "https://a b"), REASON_URL_WHITESPACE);
    }
    #[test]
    fn ensure_prefix_reason_nothing_after_prefix() {
        assert_eq!(
            reason_of(prefixed_rules("sk-", None), "sk-"),
            REASON_NOTHING_AFTER_PREFIX
        );
    }
    #[test]
    fn pattern_reason_body_does_not_match() {
        assert_eq!(
            reason_of(prefixed_rules("sk-", Some("[a-z]+")), "sk-ABC"),
            REASON_NO_PATTERN_MATCH
        );
    }
    #[test]
    fn max_len_reason_states_the_limit() {
        assert!(REASON_TOO_LONG.contains(&MAX_LEN.to_string()));
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
