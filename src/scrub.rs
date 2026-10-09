//! Scrubber for child stderr shown to the user (SR-1, NR-31).
//!
//! Child stderr is held in memory only. Before any of it is shown (the failure excerpt or
//! `--verbose`), every value opv has seen in this run is replaced with [`MASK`], and then
//! pattern scrubbers remove secrets opv never handled (tokens, keys, connection strings).
//!
//! Registered values: every field value of every 1Password item read in this run
//! ([`register_item_values`], hooked into the one `op item get` path) and every
//! [`SecretValue`](crate::domain::SecretValue) created (transformed values such as
//! `ensure_prefix`, staged values, target reads). Each value is matched raw, JSON-escaped
//! (plain and ASCII-only), standard base64, base64url (padded and unpadded) and
//! percent-encoded (upper and lower hex). Values shorter than [`MIN_SUBSTRING`] bytes are
//! replaced only as whole tokens, so a value such as `on` cannot mangle unrelated text.
//!
//! The registry keeps values in zeroizing memory; its `Debug` shows a count only.

#[cfg(not(test))]
use std::sync::Mutex;
use std::sync::OnceLock;

use base64::Engine as _;
use regex::Regex;
use zeroize::{Zeroize, Zeroizing};

/// What every registered value and every pattern match is replaced with.
pub const MASK: &str = "__SECRET__";
/// Values (and encodings) shorter than this are replaced only as whole tokens.
pub const MIN_SUBSTRING: usize = 4;
/// Lines shown after a failed call's error line (NR-31).
pub const FAILURE_LINES: usize = 5;
/// Lines shown per call with `--verbose`.
pub const VERBOSE_LINES: usize = 20;
/// Longest line shown; the rest is cut and marked with `…`.
const LINE_CHARS: usize = 240;

/// The values to scrub. `Debug` prints the count only.
#[derive(Default)]
pub struct Registry {
    /// Needles of at least [`MIN_SUBSTRING`] bytes, replaced wherever they occur, longest
    /// first so a value containing another one is replaced whole.
    long: Vec<Zeroizing<String>>,
    /// Shorter values, replaced only where they form a whole token.
    short: Vec<Zeroizing<String>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("needles", &(self.long.len() + self.short.len()))
            .finish()
    }
}

impl Registry {
    pub const fn new() -> Self {
        Self {
            long: Vec::new(),
            short: Vec::new(),
        }
    }

    /// Number of needles held (a value and its distinct encodings).
    pub fn len(&self) -> usize {
        self.long.len() + self.short.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Add `value` and its encodings. Blank values are ignored.
    pub fn register(&mut self, value: &str) {
        if value.trim().is_empty() {
            return;
        }
        if value.len() < MIN_SUBSTRING {
            // A short value and its encodings (its base64 is what a Kubernetes Secret
            // manifest carries) are masked as whole tokens only.
            for needle in encodings(value) {
                push_unique(&mut self.short, needle);
            }
            return;
        }
        for needle in encodings(value) {
            if needle.len() >= MIN_SUBSTRING {
                push_unique(&mut self.long, needle);
            }
        }
        self.long.sort_by_key(|n| std::cmp::Reverse(n.len()));
    }

    /// `text` with every registered value replaced by [`MASK`] (no pattern scrubbing).
    pub fn scrub_values(&self, text: &str) -> Zeroizing<String> {
        let mut out = Zeroizing::new(text.to_owned());
        for n in &self.long {
            if out.contains(n.as_str()) {
                out = Zeroizing::new(out.replace(n.as_str(), MASK));
            }
        }
        for n in &self.short {
            if out.contains(n.as_str()) {
                out = replace_tokens(&out, n);
            }
        }
        out
    }

    /// `text` with registered values and then known secret patterns replaced.
    pub fn scrub(&self, text: &str) -> String {
        scrub_patterns(&self.scrub_values(text))
    }
}

fn push_unique(v: &mut Vec<Zeroizing<String>>, s: Zeroizing<String>) {
    if !v.iter().any(|x| x.as_str() == s.as_str()) {
        v.push(s);
    }
}

/// Replace `needle` where it is not adjacent to a word character.
fn replace_tokens(text: &str, needle: &str) -> Zeroizing<String> {
    let word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    let mut last = 0;
    for (i, _) in text.match_indices(needle) {
        if i < last {
            continue;
        }
        let end = i + needle.len();
        if word(text[..i].chars().next_back()) || word(text[end..].chars().next()) {
            continue;
        }
        out.push_str(&text[last..i]);
        out.push_str(MASK);
        last = end;
    }
    out.push_str(&text[last..]);
    out
}

/// The forms a value can take in a CLI's stderr.
fn encodings(value: &str) -> Vec<Zeroizing<String>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let b = value.as_bytes();
    let mut out = vec![Zeroizing::new(value.to_owned())];
    if let Ok(json) = serde_json::to_string(value).map(Zeroizing::new) {
        out.push(Zeroizing::new(json[1..json.len() - 1].to_owned()));
    }
    out.push(json_ascii(value));
    out.push(escaped(value, Quoting::GoJson));
    out.push(escaped(value, Quoting::GoQuote));
    out.push(escaped(value, Quoting::PythonRepr));
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        out.push(Zeroizing::new(engine.encode(b)));
    }
    out.push(percent(b, false));
    out.push(percent(b, true));
    out
}

/// JSON string body with every non-ASCII character as `\uXXXX` (Python's default, so `az`).
fn json_ascii(value: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(value.len()));
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || !c.is_ascii() => {
                let mut units = [0u16; 2];
                for u in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// The escaping of a quoted string by the CLIs opv runs, beyond plain JSON.
#[derive(Clone, Copy)]
enum Quoting {
    /// Go `encoding/json` (kubectl, the Kubernetes API, flyctl): JSON, plus `<`, `>`, `&`,
    /// U+2028 and U+2029 as `\uXXXX`.
    GoJson,
    /// Go `%q` / `strconv.Quote` (kubectl and flyctl error text): `\a \b \f \v` and
    /// `\xNN` for other control bytes.
    GoQuote,
    /// Python `repr` in single quotes (az): `\'`, and `\xNN` for control bytes.
    PythonRepr,
}

/// The body of `value` quoted the way `q` writes it (non-ASCII printable text kept as is).
fn escaped(value: &str, q: Quoting) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(value.len() + 8));
    for c in value.chars() {
        match (c, q) {
            ('\\', _) => out.push_str("\\\\"),
            ('\n', _) => out.push_str("\\n"),
            ('\r', _) => out.push_str("\\r"),
            ('\t', _) => out.push_str("\\t"),
            ('"', Quoting::GoJson | Quoting::GoQuote) => out.push_str("\\\""),
            ('\'', Quoting::PythonRepr) => out.push_str("\\'"),
            ('<' | '>' | '&' | '\u{2028}' | '\u{2029}', Quoting::GoJson) => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            (c, Quoting::GoJson) if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            ('\u{07}', Quoting::GoQuote) => out.push_str("\\a"),
            ('\u{08}', Quoting::GoQuote) => out.push_str("\\b"),
            ('\u{0c}', Quoting::GoQuote) => out.push_str("\\f"),
            ('\u{0b}', Quoting::GoQuote) => out.push_str("\\v"),
            (c, Quoting::GoQuote | Quoting::PythonRepr) if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            (c, _) => out.push(c),
        }
    }
    out
}

/// Percent-encoding of every byte outside the URL unreserved set.
fn percent(b: &[u8], lower: bool) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(b.len() * 3));
    for &x in b {
        if x.is_ascii_alphanumeric() || b"-._~".contains(&x) {
            out.push(x as char);
        } else if lower {
            out.push_str(&format!("%{x:02x}"));
        } else {
            out.push_str(&format!("%{x:02X}"));
        }
    }
    out
}

/// Secrets opv never handled, replaced by shape. Each entry: pattern and replacement.
fn patterns() -> &'static [(Regex, &'static str)] {
    static P: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    const KEYS: &str =
        r"[A-Za-z0-9_.-]*(?:password|passwd|token|secret|apikey|api_key|api-key)[A-Za-z0-9_.-]*";
    P.get_or_init(|| {
        let r = |p: &str| Regex::new(p).expect("valid scrub pattern");
        vec![
            // PEM private keys, and the tail of one whose BEGIN line was cut off.
            (
                r(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)"),
                MASK,
            ),
            (r(r"(?s)\A.*?-----END [A-Z0-9 ]*PRIVATE KEY-----"), MASK),
            // JWTs.
            (r(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), MASK),
            // `Bearer <token>`.
            (r(r"(?i)\b(bearer)(\s+)[A-Za-z0-9._~+/=-]+"), "${1}${2}__SECRET__"),
            // 1Password session variables and service-account tokens.
            (
                r(r#"\b(OP_SESSION_\w*)(\s*=\s*)("[^"]*"|'[^']*'|\S+)"#),
                "${1}${2}__SECRET__",
            ),
            (r(r"\bops_[A-Za-z0-9+/=_-]{16,}"), MASK),
            // Azure SAS signatures, storage account keys, client secrets.
            (
                r(r#"(?i)\b(sig|client_secret)=[^&;\s"',]+"#),
                "${1}=__SECRET__",
            ),
            (
                r(r#"(?i)\b(AccountKey|SharedAccessSignature)=[^;\s"',]+"#),
                "${1}=__SECRET__",
            ),
            // Well-known API key prefixes (OpenAI, Stripe, GitHub, Slack, AWS).
            (
                r(r"\b(?:sk|pk|rk)[-_](?:live|test|proj)[-_][A-Za-z0-9_-]{8,}"),
                MASK,
            ),
            (r(r"\bsk-[A-Za-z0-9_-]{20,}"), MASK),
            (r(r"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}"), MASK),
            (r(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), MASK),
            (r(r"\bAKIA[0-9A-Z]{16}\b"), MASK),
            // `password=…`, `token=…`, `secret=…`, `apikey=…` and their JSON form.
            (
                r(&format!(
                    r#"(?i)("{KEYS}"\s*:\s*)"(?:[^"\\]|\\.)*""#
                )),
                "${1}\"__SECRET__\"",
            ),
            (
                r(&format!(
                    r#"(?i)\b({KEYS})(\s*=\s*)("[^"]*"|'[^']*'|[^\s&;,"']+)"#
                )),
                "${1}${2}__SECRET__",
            ),
        ]
    })
}

/// `text` with every known secret pattern replaced.
pub fn scrub_patterns(text: &str) -> String {
    let mut out = Zeroizing::new(text.to_owned());
    for (re, with) in patterns() {
        if re.is_match(&out) {
            out = Zeroizing::new(re.replace_all(&out, *with).into_owned());
        }
    }
    std::mem::take(&mut *out)
}

/// The run's registry. A process-wide lock, so a value registered on any thread is
/// scrubbed on every thread (fail closed).
#[cfg(not(test))]
static REGISTRY: Mutex<Registry> = Mutex::new(Registry::new());

#[cfg(not(test))]
fn with_registry<R>(f: impl FnOnce(&mut Registry) -> R) -> R {
    f(&mut REGISTRY.lock().unwrap_or_else(|p| p.into_inner()))
}

// Unit tests run in parallel threads of one process: each test gets its own registry so
// values registered by one cannot mask text another asserts on. The binary (and every
// integration test) uses the process-wide one above.
#[cfg(test)]
thread_local! {
    static REGISTRY: std::cell::RefCell<Registry> = const { std::cell::RefCell::new(Registry::new()) };
}

#[cfg(test)]
fn with_registry<R>(f: impl FnOnce(&mut Registry) -> R) -> R {
    REGISTRY.with(|r| f(&mut r.borrow_mut()))
}

/// Register one value for scrubbing.
pub fn register(value: &str) {
    with_registry(|r| r.register(value));
}

/// Register every field value of an `op item get --format json` document: each string
/// under a `value` key, anywhere in it. Malformed JSON registers nothing (the caller
/// reports it). The parsed copy is wiped before it is dropped.
pub fn register_item_values(raw: &[u8]) {
    let Ok(mut doc) = serde_json::from_slice::<serde_json::Value>(raw) else {
        return;
    };
    fn walk(v: &serde_json::Value, reg: &mut Registry) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, x) in m {
                    match x {
                        serde_json::Value::String(s) if k == "value" => reg.register(s),
                        _ => walk(x, reg),
                    }
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, reg)),
            _ => {}
        }
    }
    with_registry(|r| walk(&doc, r));
    wipe_json(&mut doc);
}

/// Zeroize every string (and key) in a parsed JSON document.
pub(crate) fn wipe_json(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) => s.zeroize(),
        serde_json::Value::Array(a) => a.iter_mut().for_each(wipe_json),
        serde_json::Value::Object(m) => m.values_mut().for_each(wipe_json),
        _ => {}
    }
}

/// `text` with every registered value and known pattern replaced.
pub fn scrub(text: &str) -> String {
    let values = with_registry(|r| r.scrub_values(text));
    scrub_patterns(&values)
}

/// The last `max` non-empty lines of a child's `stderr`, scrubbed and safe to print:
/// escape sequences and control characters removed, each line cut at 240 characters.
/// When the buffer was `truncated` (only its tail was kept), the first, partial line is
/// dropped so no value cut in half can show.
pub fn tail_lines(stderr: &[u8], truncated: bool, max: usize) -> Vec<String> {
    let mut bytes = stderr;
    if truncated {
        bytes = match bytes.iter().position(|&b| b == b'\n') {
            Some(i) => &bytes[i + 1..],
            None => &[],
        };
    }
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Vec::new();
    }
    let text = Zeroizing::new(String::from_utf8_lossy(bytes).into_owned());
    let plain = strip_escapes(&text);
    let clean = scrub(&plain);
    let lines: Vec<&str> = clean
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.trim().is_empty())
        .collect();
    lines[lines.len().saturating_sub(max)..]
        .iter()
        .map(|l| cut(l))
        .collect()
}

/// Remove ANSI escape sequences and every control character except tab and newline.
fn strip_escapes(text: &str) -> Zeroizing<String> {
    static ANSI: OnceLock<Regex> = OnceLock::new();
    let ansi = ANSI.get_or_init(|| {
        Regex::new(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*\x07|.)").expect("valid")
    });
    let no_ansi = Zeroizing::new(ansi.replace_all(text, "").into_owned());
    Zeroizing::new(
        no_ansi
            .chars()
            .filter(|c| !c.is_control() || *c == '\t' || *c == '\n')
            .collect(),
    )
}

fn cut(line: &str) -> String {
    match line.char_indices().nth(LINE_CHARS) {
        Some((i, _)) => format!("{}…", &line[..i]),
        None => line.to_string(),
    }
}

/// The scrubbed stderr lines of a failed call, shown under opv's error line (NR-31).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Excerpt {
    /// The program that failed (`op`, `flyctl`, `az`, `kubectl`).
    pub program: String,
    /// At most [`FAILURE_LINES`] scrubbed lines, oldest first.
    pub lines: Vec<String>,
}

impl Excerpt {
    /// `None` when the child wrote nothing worth showing.
    pub fn from_stderr(program: &str, stderr: &[u8], truncated: bool) -> Option<Self> {
        let lines = tail_lines(stderr, truncated, FAILURE_LINES);
        (!lines.is_empty()).then(|| Self {
            program: program.to_string(),
            lines,
        })
    }

    /// One `  <program> said: <line>` per line.
    pub fn render(&self) -> String {
        self.lines
            .iter()
            .map(|l| format!("  {} said: {l}\n", self.program))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARK: &str = "Zq9-MARKER/value+1é";

    fn reg() -> Registry {
        let mut r = Registry::new();
        r.register(MARK);
        r
    }

    #[test]
    fn raw_value_is_replaced() {
        assert_eq!(reg().scrub(&format!("x {MARK} y")), "x __SECRET__ y");
    }

    #[test]
    fn json_escaped_value_is_replaced() {
        let mut r = Registry::new();
        r.register("a\"b\\c\nd");
        assert_eq!(r.scrub(r#"{"v":"a\"b\\c\nd"}"#), r#"{"v":"__SECRET__"}"#);
    }

    #[test]
    fn json_ascii_escaped_value_is_replaced() {
        assert!(!reg().scrub(&json_ascii(MARK)).contains("MARKER"));
    }

    #[test]
    fn base64_value_is_replaced() {
        use base64::engine::general_purpose::STANDARD;
        let enc = STANDARD.encode(MARK);
        assert_eq!(reg().scrub(&format!("data={enc};")), "data=__SECRET__;");
    }

    #[test]
    fn base64url_unpadded_value_is_replaced() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let enc = URL_SAFE_NO_PAD.encode(MARK);
        assert_eq!(reg().scrub(&format!("[{enc}]")), "[__SECRET__]");
    }

    #[test]
    fn percent_encoded_value_is_replaced() {
        let enc = percent(MARK.as_bytes(), false);
        assert_eq!(
            reg().scrub(&format!("q={}&", enc.as_str())),
            "q=__SECRET__&"
        );
    }

    #[test]
    fn go_json_escaped_value_is_replaced() {
        let mut r = Registry::new();
        r.register("p<w>&d");
        assert_eq!(
            r.scrub(r#"{"value":"p\u003cw\u003e\u0026d"}"#),
            r#"{"value":"__SECRET__"}"#
        );
    }

    #[test]
    fn go_quoted_control_byte_value_is_replaced() {
        let mut r = Registry::new();
        r.register("bell\u{07}ring");
        assert_eq!(
            r.scrub(r#"Invalid value: "bell\aring""#),
            r#"Invalid value: "__SECRET__""#
        );
    }

    #[test]
    fn python_repr_value_is_replaced() {
        let mut r = Registry::new();
        r.register("it's \"x\"");
        assert_eq!(r.scrub(r#"value 'it\'s "x"'"#), "value '__SECRET__'");
    }

    /// A Kubernetes Secret manifest carries a short value as its base64.
    #[test]
    fn short_value_base64_is_replaced_as_a_token() {
        let mut r = Registry::new();
        r.register("ab");
        assert_eq!(
            r.scrub(r#""data":{"value":"YWI="}"#),
            r#""data":{"value":"__SECRET__"}"#
        );
    }

    /// az errors name Key Vault secret ids; they stay readable while the value is masked.
    #[test]
    fn key_vault_id_is_kept_while_the_value_is_masked() {
        let line = format!(
            "ERROR: (Conflict) https://kv-prod.vault.azure.net/secrets/fleet--api--db-url/0f3c9a2b7d4e4f0a: {MARK}"
        );
        assert_eq!(
            reg().scrub(&line),
            "ERROR: (Conflict) https://kv-prod.vault.azure.net/secrets/fleet--api--db-url/0f3c9a2b7d4e4f0a: __SECRET__"
        );
    }

    #[test]
    fn short_value_is_not_replaced_inside_words() {
        let mut r = Registry::new();
        r.register("on");
        assert_eq!(r.scrub("connection on"), "connection __SECRET__");
    }

    #[test]
    fn longer_value_containing_a_shorter_one_is_replaced_whole() {
        let mut r = Registry::new();
        r.register("abcd");
        r.register("xxabcdyy");
        assert_eq!(r.scrub("1 xxabcdyy 2"), "1 __SECRET__ 2");
    }

    #[test]
    fn registry_debug_shows_a_count_only() {
        assert_eq!(
            format!("{:?}", reg()),
            format!("Registry {{ needles: {} }}", reg().len())
        );
    }

    #[test]
    fn jwt_is_scrubbed() {
        let t = "token was eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl ok";
        assert_eq!(scrub_patterns(t), "token was __SECRET__ ok");
    }

    #[test]
    fn bearer_token_is_scrubbed() {
        assert_eq!(
            scrub_patterns("Authorization: Bearer abc.def-123"),
            "Authorization: Bearer __SECRET__"
        );
    }

    #[test]
    fn op_session_assignment_is_scrubbed() {
        assert_eq!(
            scrub_patterns("export OP_SESSION_my=abcDEF123"),
            "export OP_SESSION_my=__SECRET__"
        );
    }

    #[test]
    fn service_account_token_is_scrubbed() {
        assert_eq!(
            scrub_patterns("bad ops_eyJzaWduSW5BZGRyZXNzIjoi"),
            "bad __SECRET__"
        );
    }

    #[test]
    fn azure_sas_signature_is_scrubbed() {
        assert_eq!(
            scrub_patterns("https://a.blob/c?sv=1&sig=abc%2Bdef&se=2"),
            "https://a.blob/c?sv=1&sig=__SECRET__&se=2"
        );
    }

    #[test]
    fn azure_account_key_is_scrubbed() {
        assert_eq!(
            scrub_patterns("AccountName=a;AccountKey=abc+def==;EndpointSuffix=x"),
            "AccountName=a;AccountKey=__SECRET__;EndpointSuffix=x"
        );
    }

    #[test]
    fn azure_shared_access_signature_is_scrubbed() {
        assert_eq!(
            scrub_patterns("SharedAccessSignature=sv=1&sig=abc;Endpoint=x"),
            "SharedAccessSignature=__SECRET__;Endpoint=x"
        );
    }

    #[test]
    fn azure_client_secret_is_scrubbed() {
        assert_eq!(
            scrub_patterns("grant_type=client_credentials&client_secret=s3cr3t&x=1"),
            "grant_type=client_credentials&client_secret=__SECRET__&x=1"
        );
    }

    #[test]
    fn private_key_block_is_scrubbed() {
        let t = "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\nb";
        assert_eq!(scrub_patterns(t), "a\n__SECRET__\nb");
    }

    #[test]
    fn private_key_tail_without_begin_is_scrubbed() {
        let t = "MIIabc\nMIIdef\n-----END PRIVATE KEY-----\nb";
        assert_eq!(scrub_patterns(t), "__SECRET__\nb");
    }

    #[test]
    fn key_value_assignments_are_scrubbed() {
        assert_eq!(
            scrub_patterns("password=hunter2 token=t1 secret='s 1' apikey=k1 db_password = p"),
            "password=__SECRET__ token=__SECRET__ secret=__SECRET__ apikey=__SECRET__ db_password = __SECRET__"
        );
    }

    #[test]
    fn json_key_value_assignments_are_scrubbed() {
        assert_eq!(
            scrub_patterns(r#"{"clientSecret": "a\"b", "name": "n", "API_KEY":"k"}"#),
            r#"{"clientSecret": "__SECRET__", "name": "n", "API_KEY":"__SECRET__"}"#
        );
    }

    #[test]
    fn vendor_api_key_is_scrubbed() {
        assert_eq!(
            scrub_patterns("got sk-proj-abcdefghij0123456789xyz"),
            "got __SECRET__"
        );
    }

    #[test]
    fn plain_error_text_is_kept() {
        let t =
            "ERROR: (SecretNotFound) A secret with (name/id) x was not found in this key vault.";
        assert_eq!(scrub_patterns(t), t);
    }

    #[test]
    fn tail_keeps_the_last_five_non_empty_lines() {
        let s = b"1\n2\n\n3\n4\n5\n6\n   \n7\n";
        assert_eq!(tail_lines(s, false, 5), ["3", "4", "5", "6", "7"]);
    }

    #[test]
    fn tail_drops_the_partial_first_line_of_a_truncated_buffer() {
        assert_eq!(tail_lines(b"rtial\nwhole", true, 5), ["whole"]);
    }

    #[test]
    fn tail_strips_escape_sequences() {
        assert_eq!(tail_lines(b"\x1b[31mred\x1b[0m\x07", false, 5), ["red"]);
    }

    #[test]
    fn tail_cuts_long_lines() {
        let long = "x".repeat(500);
        assert_eq!(
            tail_lines(long.as_bytes(), false, 5)[0].chars().count(),
            LINE_CHARS + 1
        );
    }

    #[test]
    fn excerpt_labels_each_line_with_the_program() {
        let e = Excerpt::from_stderr("az", b"ERROR: one\nERROR: two\n", false).unwrap();
        assert_eq!(e.render(), "  az said: ERROR: one\n  az said: ERROR: two\n");
    }

    #[test]
    fn empty_stderr_has_no_excerpt() {
        assert_eq!(Excerpt::from_stderr("az", b"\n  \n", false), None);
    }

    #[test]
    fn item_values_are_registered_for_scrubbing() {
        register_item_values(br#"{"fields":[{"label":"K","value":"itemValueQ7x"}]}"#);
        assert_eq!(scrub("e itemValueQ7x"), "e __SECRET__");
    }
}
