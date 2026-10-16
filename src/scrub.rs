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
//! Each value is registered with a [`Kind`]. Every kind is value-matched in untrusted text
//! ([`scrub`], the excerpts). Only [`Kind::Secret`] values of at least [`SECRET_MIN`] bytes
//! are also matched by the output guard's byte backstop ([`guard_scrub`], used by
//! [`crate::output::OutputGuard`]), so a setting such as `true` or `production` never masks
//! opv's own output (design §8).
//!
//! The registry keeps values in zeroizing memory; its `Debug` shows a count only.

#[cfg(not(test))]
use std::sync::Mutex;
use std::sync::OnceLock;

use base64::Engine as _;
use regex::Regex;
use zeroize::{Zeroize, Zeroizing};

/// What every registered value and every pattern match is replaced with.
pub const MASK: &str = "********";
/// Secret-kind values (and encodings) shorter than this are not matched by the output
/// guard's backstop (design §8).
pub const SECRET_MIN: usize = 8;

/// What a registered value is: a secret is masked everywhere, including by the output
/// guard; a setting only in untrusted text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Secret,
    Setting,
}
/// Values (and encodings) shorter than this are replaced only as whole tokens.
pub const MIN_SUBSTRING: usize = 4;

/// The values to scrub. `Debug` prints the count only.
#[derive(Default)]
pub struct Registry {
    /// Needles of at least [`MIN_SUBSTRING`] bytes, replaced wherever they occur, longest
    /// first so a value containing another one is replaced whole.
    long: Vec<Zeroizing<String>>,
    /// Shorter values, replaced only where they form a whole token.
    short: Vec<Zeroizing<String>>,
    /// Secret-kind needles of at least [`SECRET_MIN`] bytes, longest first: the output
    /// guard's backstop.
    secret: Vec<Zeroizing<String>>,
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
            secret: Vec::new(),
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
    ///
    /// Also added (I1): the value with control characters and escape sequences removed
    /// (the form a terminal-safe excerpt shows), and each line of a multi-line value,
    /// trimmed, when it is at least [`MIN_SUBSTRING`] bytes (a CLI that re-indents or
    /// prefixes each line defeats the whole-value needle).
    pub fn register(&mut self, value: &str) {
        self.register_kind(value, Kind::Setting);
    }

    /// Add `value` as [`Kind::Secret`]: also matched by the output guard when it is at
    /// least [`SECRET_MIN`] bytes.
    pub fn register_secret(&mut self, value: &str) {
        self.register_kind(value, Kind::Secret);
    }

    /// Add `value` and its encodings as `kind` (see [`Registry::register`]).
    pub fn register_kind(&mut self, value: &str, kind: Kind) {
        self.register_one(value, kind);
        let stripped = strip_escapes(value);
        if stripped.as_str() != value {
            self.register_one(&stripped, kind);
        }
        if value.contains(['\n', '\r']) {
            for line in value.split(['\n', '\r']) {
                let line = line.trim();
                if line.len() >= MIN_SUBSTRING && line != value {
                    self.register_one(line, kind);
                    let s = strip_escapes(line);
                    if s.len() >= MIN_SUBSTRING && s.as_str() != line {
                        self.register_one(&s, kind);
                    }
                }
            }
        }
    }

    fn register_one(&mut self, value: &str, kind: Kind) {
        if value.trim().is_empty() {
            return;
        }
        if kind == Kind::Secret && value.len() >= SECRET_MIN {
            for needle in encodings(value) {
                if needle.len() >= SECRET_MIN {
                    push_unique(&mut self.secret, needle);
                }
            }
            self.secret.sort_by_key(|n| std::cmp::Reverse(n.len()));
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

    /// `text` with every secret-kind needle of at least [`SECRET_MIN`] bytes replaced by
    /// [`MASK`] (the output guard's backstop; settings and short values are kept).
    pub fn scrub_secrets(&self, text: &str) -> Zeroizing<String> {
        let mut out = Zeroizing::new(text.to_owned());
        for n in &self.secret {
            if out.contains(n.as_str()) {
                out = Zeroizing::new(out.replace(n.as_str(), MASK));
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

/// Secrets opv never handled, recognised by their shape (tokens, keys, signatures, the
/// password in a connection string). Each entry: pattern and replacement. The output guard
/// applies these to every line opv writes.
fn token_patterns() -> &'static [(Regex, String)] {
    static P: OnceLock<Vec<(Regex, String)>> = OnceLock::new();
    P.get_or_init(|| {
        let r = |p: &str| Regex::new(p).expect("valid scrub pattern");
        let keep = |groups: &str| format!("{groups}{MASK}");
        vec![
            // PEM private keys, and the tail of one whose BEGIN line was cut off.
            (
                r(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)"),
                MASK.to_string(),
            ),
            (r(r"(?s)\A.*?-----END [A-Z0-9 ]*PRIVATE KEY-----"), MASK.to_string()),
            // JWTs (also Kubernetes service-account tokens).
            (r(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), MASK.to_string()),
            // Fly.io macaroon tokens: `FlyV1 fm2_…,fm2_…`, and a bare `fm1_`/`fm2_` one.
            (r(r"\bFlyV1\s+[A-Za-z0-9_+/=,.-]+"), MASK.to_string()),
            (r(r"\bfm[12][a-z]?_[A-Za-z0-9_+/=-]{16,}"), MASK.to_string()),
            // `Bearer <token>` (also a kubeconfig's bearer token on the wire).
            (r(r"(?i)\b(bearer)(\s+)[A-Za-z0-9._~+/=-]+"), keep("${1}${2}")),
            // Kubernetes bootstrap tokens (`abcdef.0123456789abcdef`).
            (r(r"\b[a-z0-9]{6}\.[a-z0-9]{16}\b"), MASK.to_string()),
            // 1Password session variables and service-account tokens.
            (
                r(r#"\b(OP_SESSION_\w*)(\s*=\s*)("[^"]*"|'[^']*'|\S+)"#),
                keep("${1}${2}"),
            ),
            (r(r"\bops_[A-Za-z0-9+/=_-]{16,}"), MASK.to_string()),
            // Azure SAS signatures, storage account keys, client secrets.
            (r(r#"(?i)\b(sig|client_secret)=[^&;\s"',]+"#), keep("${1}=")),
            (
                r(r#"(?i)\b(AccountKey|SharedAccessSignature)=[^;\s"',]+"#),
                keep("${1}="),
            ),
            // Connection strings with a password: `scheme://user:password@host` and
            // `…;Password=…;`.
            (
                r(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]*:)[^\s@/]+(@)"),
                format!("${{1}}{MASK}${{2}}"),
            ),
            (r(r#"(?i)\b(password|pwd)=[^;&\s"']+"#), keep("${1}=")),
            // Well-known API key prefixes (OpenAI, Stripe, GitHub, Slack, AWS).
            (
                r(r"\b(?:sk|pk|rk)[-_](?:live|test|proj)[-_][A-Za-z0-9_-]{8,}"),
                MASK.to_string(),
            ),
            (r(r"\bsk-[A-Za-z0-9_-]{20,}"), MASK.to_string()),
            (r(r"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}"), MASK.to_string()),
            (r(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), MASK.to_string()),
            (r(r"\bAKIA[0-9A-Z]{16}\b"), MASK.to_string()),
        ]
    })
}

/// `password=…`, `token=…`, `secret=…`, `apikey=…` and their JSON form: applied to
/// untrusted text only, since opv's own documents name such keys.
fn assignment_patterns() -> &'static [(Regex, String)] {
    static P: OnceLock<Vec<(Regex, String)>> = OnceLock::new();
    const KEYS: &str =
        r"[A-Za-z0-9_.-]*(?:password|passwd|token|secret|apikey|api_key|api-key)[A-Za-z0-9_.-]*";
    P.get_or_init(|| {
        let r = |p: &str| Regex::new(p).expect("valid scrub pattern");
        vec![
            (
                r(&format!(r#"(?i)("{KEYS}"\s*:\s*)"(?:[^"\\]|\\.)*""#)),
                format!("${{1}}\"{MASK}\""),
            ),
            (
                r(&format!(
                    r#"(?i)\b({KEYS})(\s*=\s*)("[^"]*"|'[^']*'|[^\s&;,"']+)"#
                )),
                format!("${{1}}${{2}}{MASK}"),
            ),
        ]
    })
}

fn apply(text: &str, patterns: &[(Regex, String)]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(text.to_owned());
    for (re, with) in patterns {
        if re.is_match(&out) {
            out = Zeroizing::new(re.replace_all(&out, with.as_str()).into_owned());
        }
    }
    out
}

/// `text` with every known token shape replaced (the output guard's patterns).
pub fn scrub_tokens(text: &str) -> String {
    std::mem::take(&mut *apply(text, token_patterns()))
}

/// `text` with every known secret pattern replaced: token shapes, then assignments.
pub fn scrub_patterns(text: &str) -> String {
    let tokens = apply(text, token_patterns());
    std::mem::take(&mut *apply(&tokens, assignment_patterns()))
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

/// Clear only the current unit-test thread's synthetic values between independent
/// corpus cases. Production and integration-test registries are unchanged.
#[cfg(test)]
pub(crate) fn reset_test_registry() {
    with_registry(|registry| *registry = Registry::new());
}

/// End the serialized MCP inspection's redaction lifetime. This must only be used
/// by the MCP server while it holds its operation gate; CLI behavior is unchanged.
#[cfg(feature = "mcp")]
pub(crate) fn clear_mcp_registry() {
    with_registry(|registry| *registry = Registry::new());
    // The server's own credentials stay secrets for its whole life.
    register_credential_env();
}

/// Register one value for scrubbing in untrusted text, as a [`Kind::Setting`].
pub fn register(value: &str) {
    with_registry(|r| r.register(value));
}

/// Register one value as [`Kind::Secret`]: masked in untrusted text and, when at least
/// [`SECRET_MIN`] bytes, by the output guard too.
pub fn register_secret(value: &str) {
    with_registry(|r| r.register_secret(value));
}

/// Register one value as `kind`.
pub fn register_kind(value: &str, kind: Kind) {
    with_registry(|r| r.register_kind(value, kind));
}

/// The credential variables in opv's own environment whose values are secrets for the run
/// (design §8): `OP_SERVICE_ACCOUNT_TOKEN`, every `OP_SESSION_*`, `OP_CONNECT_TOKEN`, Fly's,
/// GitHub's and Azure's tokens and client secrets.
pub const CREDENTIAL_VARS: [&str; 8] = [
    "OP_SERVICE_ACCOUNT_TOKEN",
    "OP_CONNECT_TOKEN",
    "FLY_API_TOKEN",
    "FLY_ACCESS_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "AZURE_CLIENT_SECRET",
    "ARM_CLIENT_SECRET",
];

/// Whether the environment variable `name` holds a credential opv registers at startup.
pub fn is_credential_var(name: &str) -> bool {
    CREDENTIAL_VARS.contains(&name) || name.starts_with("OP_SESSION_")
}

/// Register the value of every credential variable in `vars` as [`Kind::Secret`].
pub fn register_credentials_from<I, K, V>(vars: I)
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    for (k, v) in vars {
        if k.as_ref().to_str().is_some_and(is_credential_var)
            && let Some(v) = v.as_ref().to_str()
        {
            let v = Zeroizing::new(v.to_owned());
            register_secret(&v);
        }
    }
}

/// Register the credential variables of opv's own environment (called first thing in
/// `main`).
pub fn register_credential_env() {
    register_credentials_from(std::env::vars_os());
}

/// One chunk of opv's own output as the output guard writes it: secret-kind values masked
/// on the raw text, escape sequences, control characters (other than tab and newline) and
/// bidi overrides removed, secret-kind values masked again (a value that held an escape),
/// then known token shapes masked. Settings and short values are never matched here.
pub fn guard_scrub(text: &str) -> String {
    let raw = with_registry(|r| r.scrub_secrets(text));
    let plain = strip_escapes(&raw);
    let again = with_registry(|r| r.scrub_secrets(&plain));
    scrub_tokens(&again)
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
                let kind = field_kind(m.get("type").and_then(serde_json::Value::as_str));
                for (k, x) in m {
                    match x {
                        serde_json::Value::String(s) if k == "value" => reg.register_kind(s, kind),
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

/// The kind of a 1Password field by its `type` (FR-14: `CONCEALED` is a secret, `STRING` is
/// configuration). Fails closed: an unknown or missing type is a secret.
fn field_kind(ty: Option<&str>) -> Kind {
    const PLAIN: [&str; 9] = [
        "STRING",
        "URL",
        "EMAIL",
        "PHONE",
        "MENU",
        "DATE",
        "MONTH_YEAR",
        "ADDRESS",
        "REFERENCE",
    ];
    match ty {
        Some(t) if PLAIN.contains(&t) => Kind::Setting,
        _ => Kind::Secret,
    }
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

/// Every non-empty line of a child's `stderr`, scrubbed and safe to print: registered
/// values masked on the raw text, then escape sequences and control characters removed,
/// then values and patterns scrubbed again. No line is cut or left out; what is shown is
/// the display's choice (design §7.3: the error line plus the tail, all of it with
/// `--verbose`).
/// When the buffer was `truncated` (only its last [`crate::runner::STDERR_CAP`] bytes were
/// kept), the first, partial line is dropped so no value cut in half can show; the caller
/// says the reply was truncated.
pub fn reply_lines(stderr: &[u8], truncated: bool) -> Vec<String> {
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
    // Registered values are masked on the raw text first (I1): a value holding CR, BEL or
    // ESC no longer matches once control characters are stripped. The stripped text is
    // masked again (stripped and per-line forms), then pattern-scrubbed.
    let raw = with_registry(|r| r.scrub_values(&text));
    let plain = strip_escapes(&raw);
    let clean = scrub(&plain);
    clean
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// Whether `c` is a bidirectional embedding, override or isolate (U+202A–202E,
/// U+2066–2069), which can make displayed text read differently from its bytes.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Remove escape sequences (ANSI CSI; OSC, including OSC 8 links and OSC 52 clipboard
/// writes; DCS, SOS, PM and APC strings; their 8-bit C1 forms), every other control
/// character except tab and newline, and bidi overrides (design §9.4).
pub fn strip_escapes(text: &str) -> Zeroizing<String> {
    static ANSI: OnceLock<Regex> = OnceLock::new();
    let ansi = ANSI.get_or_init(|| {
        Regex::new(concat!(
            r"\x1b\[[0-?]*[ -/]*[@-~]",
            r"|\x1b[\]PX^_][^\x07\x1b\n\u{9c}]*(?:\x07|\x1b\\|\u{9c})?",
            r"|\u{9b}[0-?]*[ -/]*[@-~]",
            r"|[\u{90}\u{98}\u{9d}\u{9e}\u{9f}][^\x07\x1b\n\u{9c}]*(?:\x07|\x1b\\|\u{9c})?",
            r"|\x1b[^\n]",
        ))
        .expect("valid")
    });
    let no_ansi = Zeroizing::new(ansi.replace_all(text, "").into_owned());
    Zeroizing::new(
        no_ansi
            .chars()
            .filter(|c| (!c.is_control() || *c == '\t' || *c == '\n') && !is_bidi_control(*c))
            .collect(),
    )
}

/// `line` without a CLI's own directions to the person (FR-50): opv's `Do:` and `Next:` say
/// what to do, so `Please run 'op signin --help' for instructions` and the like are cut,
/// keeping the reason before them.
fn without_vendor_directions(line: &str) -> String {
    const DIRECTIONS: [&str; 4] = [
        "Please run `op signin --help`",
        "Please run 'op signin --help'",
        "Try authenticating with:",
        "To sign in, run",
    ];
    // A line without a direction passes through unchanged.
    match DIRECTIONS.iter().filter_map(|d| line.find(d)).min() {
        Some(cut_at) => line[..cut_at].trim_end_matches([' ', '.']).to_string(),
        None => line.to_string(),
    }
}

/// The scrubbed stderr lines of a failed call, shown under opv's error line (NR-31).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Excerpt {
    /// The program that failed (`op`, `flyctl`, `az`, `kubectl`).
    pub program: String,
    /// Every scrubbed line of the reply, oldest first; the display picks what to show.
    pub lines: Vec<String>,
    /// The reply was longer than [`crate::runner::STDERR_CAP`] bytes and only its end was
    /// kept; every display of it says so.
    pub truncated: bool,
}

impl Excerpt {
    /// `None` when the child wrote nothing worth showing.
    pub fn from_stderr(program: &str, stderr: &[u8], truncated: bool) -> Option<Self> {
        let lines: Vec<String> = reply_lines(stderr, truncated)
            .into_iter()
            .map(|l| without_vendor_directions(&l))
            .filter(|l| !l.trim().is_empty())
            .collect();
        (!lines.is_empty()).then(|| Self {
            program: program.to_string(),
            lines,
            truncated,
        })
    }

    /// The lines of `excerpt` and whether it was truncated; none and false without one.
    pub fn parts(excerpt: Option<Self>) -> (Vec<String>, bool) {
        excerpt.map_or_else(Default::default, |x| (x.lines, x.truncated))
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

    #[test]
    fn ops_sign_in_direction_is_cut_from_an_excerpt() {
        let e = Excerpt::from_stderr(
            "op",
            b"[ERROR] 2026/10/13 03:21:25 You are not currently signed in. Please run `op signin --help` for instructions\n",
            false,
        )
        .unwrap();
        assert!(!e.render().contains("--help"), "{}", e.render());
    }

    #[test]
    fn the_reason_before_a_direction_is_kept() {
        assert_eq!(
            without_vendor_directions(
                "You are not currently signed in. Please run `op signin --help` for instructions"
            ),
            "You are not currently signed in"
        );
    }

    #[test]
    fn a_line_without_a_direction_keeps_its_full_stop() {
        assert_eq!(
            without_vendor_directions("Host key verification failed."),
            "Host key verification failed."
        );
    }

    #[test]
    fn a_line_that_is_only_a_direction_is_dropped() {
        assert_eq!(
            Excerpt::from_stderr(
                "gh",
                b"Try authenticating with:  gh auth login -h github.com\n",
                false
            ),
            None
        );
    }

    fn reg() -> Registry {
        let mut r = Registry::new();
        r.register(MARK);
        r
    }

    #[test]
    fn raw_value_is_replaced() {
        assert_eq!(reg().scrub(&format!("x {MARK} y")), "x ******** y");
    }

    #[test]
    fn json_escaped_value_is_replaced() {
        let mut r = Registry::new();
        r.register("a\"b\\c\nd");
        assert_eq!(r.scrub(r#"{"v":"a\"b\\c\nd"}"#), r#"{"v":"********"}"#);
    }

    #[test]
    fn json_ascii_escaped_value_is_replaced() {
        assert!(!reg().scrub(&json_ascii(MARK)).contains("MARKER"));
    }

    #[test]
    fn base64_value_is_replaced() {
        use base64::engine::general_purpose::STANDARD;
        let enc = STANDARD.encode(MARK);
        assert_eq!(reg().scrub(&format!("data={enc};")), "data=********;");
    }

    #[test]
    fn base64url_unpadded_value_is_replaced() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let enc = URL_SAFE_NO_PAD.encode(MARK);
        assert_eq!(reg().scrub(&format!("[{enc}]")), "[********]");
    }

    #[test]
    fn percent_encoded_value_is_replaced() {
        let enc = percent(MARK.as_bytes(), false);
        assert_eq!(reg().scrub(&format!("q={}&", enc.as_str())), "q=********&");
    }

    #[test]
    fn go_json_escaped_value_is_replaced() {
        let mut r = Registry::new();
        r.register("p<w>&d");
        assert_eq!(
            r.scrub(r#"{"value":"p\u003cw\u003e\u0026d"}"#),
            r#"{"value":"********"}"#
        );
    }

    #[test]
    fn go_quoted_control_byte_value_is_replaced() {
        let mut r = Registry::new();
        r.register("bell\u{07}ring");
        assert_eq!(
            r.scrub(r#"Invalid value: "bell\aring""#),
            r#"Invalid value: "********""#
        );
    }

    #[test]
    fn python_repr_value_is_replaced() {
        let mut r = Registry::new();
        r.register("it's \"x\"");
        assert_eq!(r.scrub(r#"value 'it\'s "x"'"#), "value '********'");
    }

    /// A Kubernetes Secret manifest carries a short value as its base64.
    #[test]
    fn short_value_base64_is_replaced_as_a_token() {
        let mut r = Registry::new();
        r.register("ab");
        assert_eq!(
            r.scrub(r#""data":{"value":"YWI="}"#),
            r#""data":{"value":"********"}"#
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
            "ERROR: (Conflict) https://kv-prod.vault.azure.net/secrets/fleet--api--db-url/0f3c9a2b7d4e4f0a: ********"
        );
    }

    #[test]
    fn short_value_is_not_replaced_inside_words() {
        let mut r = Registry::new();
        r.register("on");
        assert_eq!(r.scrub("connection on"), "connection ********");
    }

    #[test]
    fn longer_value_containing_a_shorter_one_is_replaced_whole() {
        let mut r = Registry::new();
        r.register("abcd");
        r.register("xxabcdyy");
        assert_eq!(r.scrub("1 xxabcdyy 2"), "1 ******** 2");
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
        assert_eq!(scrub_patterns(t), "token was ******** ok");
    }

    #[test]
    fn bearer_token_is_scrubbed() {
        assert_eq!(
            scrub_patterns("Authorization: Bearer abc.def-123"),
            "Authorization: Bearer ********"
        );
    }

    #[test]
    fn op_session_assignment_is_scrubbed() {
        assert_eq!(
            scrub_patterns("export OP_SESSION_my=abcDEF123"),
            "export OP_SESSION_my=********"
        );
    }

    #[test]
    fn service_account_token_is_scrubbed() {
        assert_eq!(
            scrub_patterns("bad ops_eyJzaWduSW5BZGRyZXNzIjoi"),
            "bad ********"
        );
    }

    #[test]
    fn azure_sas_signature_is_scrubbed() {
        assert_eq!(
            scrub_patterns("https://a.blob/c?sv=1&sig=abc%2Bdef&se=2"),
            "https://a.blob/c?sv=1&sig=********&se=2"
        );
    }

    #[test]
    fn azure_account_key_is_scrubbed() {
        assert_eq!(
            scrub_patterns("AccountName=a;AccountKey=abc+def==;EndpointSuffix=x"),
            "AccountName=a;AccountKey=********;EndpointSuffix=x"
        );
    }

    #[test]
    fn azure_shared_access_signature_is_scrubbed() {
        assert_eq!(
            scrub_patterns("SharedAccessSignature=sv=1&sig=abc;Endpoint=x"),
            "SharedAccessSignature=********;Endpoint=x"
        );
    }

    #[test]
    fn azure_client_secret_is_scrubbed() {
        assert_eq!(
            scrub_patterns("grant_type=client_credentials&client_secret=s3cr3t&x=1"),
            "grant_type=client_credentials&client_secret=********&x=1"
        );
    }

    #[test]
    fn private_key_block_is_scrubbed() {
        let t = "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\nb";
        assert_eq!(scrub_patterns(t), "a\n********\nb");
    }

    #[test]
    fn private_key_tail_without_begin_is_scrubbed() {
        let t = "MIIabc\nMIIdef\n-----END PRIVATE KEY-----\nb";
        assert_eq!(scrub_patterns(t), "********\nb");
    }

    #[test]
    fn key_value_assignments_are_scrubbed() {
        assert_eq!(
            scrub_patterns("password=hunter2 token=t1 secret='s 1' apikey=k1 db_password = p"),
            "password=******** token=******** secret=******** apikey=******** db_password = ********"
        );
    }

    #[test]
    fn json_key_value_assignments_are_scrubbed() {
        assert_eq!(
            scrub_patterns(r#"{"clientSecret": "a\"b", "name": "n", "API_KEY":"k"}"#),
            r#"{"clientSecret": "********", "name": "n", "API_KEY":"********"}"#
        );
    }

    #[test]
    fn vendor_api_key_is_scrubbed() {
        assert_eq!(
            scrub_patterns("got sk-proj-abcdefghij0123456789xyz"),
            "got ********"
        );
    }

    #[test]
    fn plain_error_text_is_kept() {
        let t =
            "ERROR: (SecretNotFound) A secret with (name/id) x was not found in this key vault.";
        assert_eq!(scrub_patterns(t), t);
    }

    #[test]
    fn reply_keeps_every_non_empty_line() {
        let s = b"1\n2\n\n3\n4\n5\n6\n   \n7\n";
        assert_eq!(reply_lines(s, false), ["1", "2", "3", "4", "5", "6", "7"]);
    }

    #[test]
    fn reply_drops_the_partial_first_line_of_a_truncated_buffer() {
        assert_eq!(reply_lines(b"rtial\nwhole", true), ["whole"]);
    }

    #[test]
    fn reply_strips_escape_sequences() {
        assert_eq!(reply_lines(b"\x1b[31mred\x1b[0m\x07", false), ["red"]);
    }

    #[test]
    fn reply_keeps_long_lines_whole() {
        let long = "x".repeat(500);
        assert_eq!(reply_lines(long.as_bytes(), false)[0].chars().count(), 500);
    }

    #[test]
    fn a_registered_value_never_survives_in_any_line_of_a_long_reply() {
        let mut stderr = String::from("[ERROR] 2026/10/16 10:00:00 request failed\n");
        for i in 0..400 {
            stderr.push_str(&format!("detail {i}: field holds VerboseMark-77x{i}\n"));
        }
        with_registry(|r| r.register("VerboseMark-77x"));
        let lines = reply_lines(stderr.as_bytes(), false);
        assert!(
            !lines.iter().any(|l| l.contains("VerboseMark")),
            "{lines:?}"
        );
    }

    #[test]
    fn a_truncated_excerpt_says_so() {
        let e = Excerpt::from_stderr("op", b"rtial\n[ERROR] whole\n", true).unwrap();
        assert!(e.truncated);
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
        assert_eq!(scrub("e itemValueQ7x"), "e ********");
    }
}
