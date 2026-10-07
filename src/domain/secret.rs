//! Redacting wrapper for secret values (SR-1, SR-2, SR-8).

use secrecy::{ExposeSecret, SecretString};

/// A secret value. `Debug` and `Display` print `<REDACTED>`; memory is zeroized on drop
/// (via `secrecy`). Read the value only with [`SecretValue::expose`], at the point of use.
pub struct SecretValue(SecretString);

impl SecretValue {
    pub fn new(v: String) -> Self {
        Self(SecretString::from(v))
    }

    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<REDACTED>")
    }
}

impl std::fmt::Display for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<REDACTED>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_display_are_redacted() {
        let s = SecretValue::new("sk-live-123".into());
        assert_eq!(format!("{s:?}"), "<REDACTED>");
        assert_eq!(format!("{s}"), "<REDACTED>");
        assert_eq!(s.expose(), "sk-live-123");
    }

    #[test]
    fn redacted_inside_containers_and_alternate_debug() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            key: &'static str,
            value: SecretValue,
        }
        let h = Holder {
            key: "OPENAI_API_KEY",
            value: SecretValue::new("sk-live-123".into()),
        };
        let v = vec![SecretValue::new("sk-live-456".into())];
        for out in [
            format!("{h:?}"),
            format!("{h:#?}"),
            format!("{v:?}"),
            format!("{:>20}", v[0]),
        ] {
            assert!(!out.contains("sk-live"), "leaked: {out}");
            assert!(out.contains("<REDACTED>"));
        }
    }

    #[test]
    fn panic_message_from_debug_does_not_leak() {
        let r = std::panic::catch_unwind(|| {
            let s = SecretValue::new("sk-live-789".into());
            panic!("boom {s:?} {s}");
        });
        let payload = r.unwrap_err();
        let msg = payload.downcast_ref::<String>().unwrap();
        assert!(!msg.contains("sk-live"), "leaked: {msg}");
    }
}
