//! The output guard (design §8, §9.4): every byte opv itself writes to stdout or stderr
//! passes through an [`OutputGuard`].
//!
//! The guard buffers by line. On each line it masks registered secret-kind values of at
//! least [`crate::scrub::SECRET_MIN`] bytes and known token shapes with
//! [`crate::scrub::MASK`], and strips escape sequences (ANSI CSI, OSC 8 links, OSC 52
//! clipboard writes), control characters other than tab and newline, and bidi overrides.
//! Settings and short values are never matched, so `--json` documents stay valid and opv's
//! own names stay readable. Lines inside a PEM private-key block are masked whole.
//!
//! It is a last line of defence: typed fields are clean by construction and untrusted text
//! is scrubbed before it is rendered. `opv run`'s child writes to the inherited terminal
//! directly, never through the guard (its output is the person's app, and `op run` masks
//! it).
//!
//! A partial line is written on [`Write::flush`] (a prompt waiting for an answer), and on
//! drop.

use std::io::{self, Write};

use zeroize::Zeroizing;

use crate::scrub;

/// A [`Write`] that scrubs each line before passing it to `inner`.
pub struct OutputGuard<W: Write> {
    inner: W,
    /// Bytes of the current, unfinished line.
    line: Zeroizing<Vec<u8>>,
    /// Inside a PEM private-key block: every line is masked until its END line.
    in_pem: bool,
}

impl<W: Write> OutputGuard<W> {
    /// Guard `inner`. The MCP serializer and the TUI renderer wrap their writers with this.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            line: Zeroizing::new(Vec::new()),
            in_pem: false,
        }
    }

    /// The guarded writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    /// `text` (one line, or a partial one) as the guard writes it.
    fn clean(&mut self, text: &[u8]) -> String {
        let text = Zeroizing::new(String::from_utf8_lossy(text).into_owned());
        let begins = text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----");
        let ends = text.contains("-----END ") && text.contains("PRIVATE KEY-----");
        if self.in_pem {
            self.in_pem = !ends;
            let newline = if text.ends_with('\n') { "\n" } else { "" };
            return format!("{}{newline}", scrub::MASK);
        }
        self.in_pem = begins && !ends;
        scrub::guard_scrub(&text)
    }

    /// Write every complete line held.
    fn emit_lines(&mut self) -> io::Result<()> {
        while let Some(end) = self.line.iter().position(|&b| b == b'\n') {
            let line: Zeroizing<Vec<u8>> = Zeroizing::new(self.line.drain(..=end).collect());
            let clean = Zeroizing::new(self.clean(&line));
            self.inner.write_all(clean.as_bytes())?;
        }
        Ok(())
    }
}

impl<W: Write> Write for OutputGuard<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.line.extend_from_slice(buf);
        self.emit_lines()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit_lines()?;
        if !self.line.is_empty() {
            let rest: Zeroizing<Vec<u8>> = Zeroizing::new(std::mem::take(&mut *self.line));
            let clean = Zeroizing::new(self.clean(&rest));
            self.inner.write_all(clean.as_bytes())?;
        }
        self.inner.flush()
    }
}

impl<W: Write> Drop for OutputGuard<W> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// opv's stdout, guarded.
pub fn stdout() -> OutputGuard<io::Stdout> {
    OutputGuard::new(io::stdout())
}

/// opv's stderr, guarded.
pub fn stderr() -> OutputGuard<io::Stderr> {
    OutputGuard::new(io::stderr())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `text` looks like after the guard.
    fn guarded(text: &str) -> String {
        let mut out = Vec::new();
        {
            let mut g = OutputGuard::new(&mut out);
            g.write_all(text.as_bytes()).unwrap();
            g.flush().unwrap();
        }
        String::from_utf8(out).unwrap()
    }

    const CANARY: &str = "CanaryS3cret-9Qz";

    /// One fake credential of every token shape the guard knows.
    const FAKE_TOKENS: [&str; 14] = [
        "FlyV1 fm2_lJPECAAAAAAAAMQxkQZx0k4LgsQQAbCdEfGhIjKlMnOpQrStUvWxYz",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123",
        "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123",
        "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.c2lnbmF0dXJlLWNhbmFyeQ",
        "postgres://app:Pw0rdCanary99@db.example.com:5432/app",
        "Server=db;User Id=app;Password=Pw0rdCanary98;",
        "https://acct.blob.core.windows.net/c?sv=2022&sig=SigCanary%2Bxyz%3D&se=2",
        "SharedAccessSignature=SasCanaryKey123",
        "AccountKey=AcctKeyCanary456==",
        "Authorization: Bearer KubeBearerCanary.abc",
        "abcdef.0123456789abcdef",
        "ops_eyJzaWduSW5BZGRyZXNzIjoibXkuMXBhc3N3b3JkLmNvbSJ9canary",
        "OP_SESSION_my=SessCanary0123456789",
    ];

    /// The secret part of each [`FAKE_TOKENS`] entry, which must never pass.
    const FAKE_SECRETS: [&str; 14] = [
        "fm2_lJPECAAAAAAAAMQxkQZx0k4LgsQQAbCdEfGhIjKlMnOpQrStUvWxYz",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123",
        "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123",
        "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz",
        "c2lnbmF0dXJlLWNhbmFyeQ",
        "Pw0rdCanary99",
        "Pw0rdCanary98",
        "SigCanary",
        "SasCanaryKey123",
        "AcctKeyCanary456",
        "KubeBearerCanary",
        "0123456789abcdef",
        "ops_eyJzaWduSW5BZGRyZXNzIjoibXkuMXBhc3N3b3JkLmNvbSJ9canary",
        "SessCanary0123456789",
    ];

    const PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BPemCanaryBody\n-----END PRIVATE KEY-----\n";

    #[test]
    fn canary_never_escapes_as_a_registered_secret() {
        scrub::reset_test_registry();
        scrub::register_secret(CANARY);
        assert!(!guarded(&format!("leak: {CANARY}\n")).contains(CANARY));
    }

    #[test]
    fn canary_never_escapes_inside_an_escape_sequence() {
        scrub::reset_test_registry();
        scrub::register_secret(CANARY);
        assert!(!guarded("leak: CanaryS3\x1b[0mcret-9Qz\n").contains(CANARY));
    }

    #[test]
    fn canary_never_escapes_across_writes() {
        scrub::reset_test_registry();
        scrub::register_secret(CANARY);
        let mut out = Vec::new();
        {
            let mut g = OutputGuard::new(&mut out);
            g.write_all(b"leak: CanaryS3").unwrap();
            g.write_all(b"cret-9Qz\n").unwrap();
        }
        assert!(!String::from_utf8(out).unwrap().contains(CANARY));
    }

    #[test]
    fn canary_never_escapes_as_any_token_shape() {
        scrub::reset_test_registry();
        let text: String = FAKE_TOKENS.iter().map(|t| format!("x {t} y\n")).collect();
        let out = guarded(&text);
        let leaked: Vec<&str> = FAKE_SECRETS
            .iter()
            .copied()
            .filter(|s| out.contains(s))
            .collect();
        assert_eq!(leaked, Vec::<&str>::new(), "{out}");
    }

    #[test]
    fn canary_never_escapes_from_a_pem_block() {
        scrub::reset_test_registry();
        assert!(!guarded(PEM).contains("PemCanaryBody"));
    }

    #[test]
    fn a_line_after_a_pem_block_is_kept() {
        scrub::reset_test_registry();
        assert!(guarded(&format!("{PEM}done\n")).ends_with("done\n"));
    }

    #[test]
    fn the_mask_is_fixed() {
        scrub::reset_test_registry();
        scrub::register_secret(CANARY);
        assert_eq!(guarded(&format!("v={CANARY}\n")), "v=********\n");
    }

    #[test]
    fn a_short_secret_is_not_matched_by_the_guard() {
        scrub::reset_test_registry();
        scrub::register_secret("prod1");
        assert_eq!(guarded("env prod1\n"), "env prod1\n");
    }

    #[test]
    fn a_long_setting_is_not_matched_by_the_guard() {
        scrub::reset_test_registry();
        scrub::register("production");
        assert_eq!(guarded("env production\n"), "env production\n");
    }

    #[test]
    fn json_stays_valid_under_registry() {
        scrub::reset_test_registry();
        for v in ["true", "prod", "DATABASE_URL", "production-settings"] {
            scrub::register(v);
        }
        scrub::register_secret("prod");
        let doc =
            r#"{"ok": true, "env": "prod", "key": "DATABASE_URL", "mode": "production-settings"}"#;
        let out = guarded(&format!("{doc}\n"));
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            parsed,
            serde_json::json!({"ok": true, "env": "prod", "key": "DATABASE_URL", "mode": "production-settings"})
        );
    }

    #[test]
    fn escapes_are_stripped_ansi() {
        assert_eq!(guarded("\x1b[31mred\x1b[0m \x1b[2Kok\n"), "red ok\n");
    }

    #[test]
    fn escapes_are_stripped_osc8_link() {
        assert_eq!(
            guarded("\x1b]8;;https://evil.example\x1b\\click\x1b]8;;\x1b\\\n"),
            "click\n"
        );
    }

    #[test]
    fn escapes_are_stripped_osc52_clipboard() {
        assert_eq!(guarded("a\x1b]52;c;cm0gLXJmIH4=\x07b\n"), "ab\n");
    }

    #[test]
    fn escapes_are_stripped_c1_csi() {
        assert_eq!(guarded("a\u{9b}31mb\n"), "ab\n");
    }

    #[test]
    fn escapes_are_stripped_bidi() {
        assert_eq!(
            guarded(
                "a\u{202a}b\u{202b}c\u{202c}d\u{202d}e\u{202e}f\u{2066}g\u{2067}h\u{2068}i\u{2069}j\n"
            ),
            "abcdefghij\n"
        );
    }

    #[test]
    fn escapes_are_stripped_control_characters_but_tab_and_newline() {
        assert_eq!(guarded("a\tb\r\x07\x08c\u{85}\n"), "a\tbc\n");
    }

    #[test]
    fn a_partial_line_is_written_on_flush() {
        let mut out = Vec::new();
        {
            let mut g = OutputGuard::new(&mut out);
            g.write_all(b"Continue? ").unwrap();
            g.flush().unwrap();
        }
        assert_eq!(out, b"Continue? ");
    }

    #[test]
    fn a_partial_line_is_written_on_drop() {
        let mut out = Vec::new();
        {
            let mut g = OutputGuard::new(&mut out);
            g.write_all(b"tail").unwrap();
        }
        assert_eq!(out, b"tail");
    }

    #[test]
    fn credential_env_values_are_registered_as_secrets() {
        scrub::reset_test_registry();
        scrub::register_credentials_from([("GH_TOKEN", "EnvCanaryToken42")]);
        assert_eq!(guarded("t EnvCanaryToken42\n"), "t ********\n");
    }

    #[test]
    fn op_session_env_values_are_registered_as_secrets() {
        scrub::reset_test_registry();
        scrub::register_credentials_from([("OP_SESSION_abc", "SessEnvCanary77")]);
        assert_eq!(guarded("s SessEnvCanary77\n"), "s ********\n");
    }

    #[test]
    fn other_env_values_are_not_registered() {
        scrub::reset_test_registry();
        scrub::register_credentials_from([("HOME", "/home/someone-long")]);
        assert_eq!(guarded("h /home/someone-long\n"), "h /home/someone-long\n");
    }

    #[test]
    fn every_listed_credential_variable_is_recognised() {
        let missed: Vec<&str> = [
            "OP_SERVICE_ACCOUNT_TOKEN",
            "OP_SESSION_my",
            "OP_CONNECT_TOKEN",
            "FLY_API_TOKEN",
            "FLY_ACCESS_TOKEN",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "AZURE_CLIENT_SECRET",
            "ARM_CLIENT_SECRET",
        ]
        .into_iter()
        .filter(|v| !scrub::is_credential_var(v))
        .collect();
        assert_eq!(missed, Vec::<&str>::new());
    }

    #[test]
    fn a_concealed_item_field_is_a_guarded_secret() {
        scrub::reset_test_registry();
        scrub::register_item_values(
            br#"{"fields":[{"type":"CONCEALED","value":"ItemCanary0987"}]}"#,
        );
        assert_eq!(guarded("i ItemCanary0987\n"), "i ********\n");
    }

    #[test]
    fn a_string_item_field_is_not_matched_by_the_guard() {
        scrub::reset_test_registry();
        scrub::register_item_values(br#"{"fields":[{"type":"STRING","value":"production"}]}"#);
        assert_eq!(guarded("e production\n"), "e production\n");
    }

    #[test]
    fn a_string_item_field_is_still_masked_in_untrusted_text() {
        scrub::reset_test_registry();
        scrub::register_item_values(br#"{"fields":[{"type":"STRING","value":"production"}]}"#);
        assert_eq!(scrub::scrub("e production"), "e ********");
    }
}
