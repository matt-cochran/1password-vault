//! Configuration errors that point at the source (H10, FR-2). Names and positions only,
//! never the offending line (C1, SR-1): a file given by mistake (a `.env`) may hold values,
//! so no error quotes the text it came from.
//!
//! `parse` reports a catalog cause ([`Cause::ConfigInvalid`] and the other §4.1 variants)
//! whose field and rule come from the validator, against a stand-in source (it never sees a
//! path). [`relocate_at`] names the real source: the cause's fields are kept as they are,
//! never re-derived from a message or a line (audit 03.01). Provider sections report the
//! same typed causes (C15, D1), so no free text is rewritten here.

use crate::cause::{Cause, ConfigSource};
use crate::error::Error;

/// `e`, when it is a configuration cause from parsing `text`, naming `source` in place of
/// the stand-in (a manifest has no file, so no line). Any other error is returned unchanged.
pub(super) fn relocate_at(e: Error, _text: &str, source: ConfigSource) -> Error {
    match e.cause() {
        Some((cause, _)) => with_source(cause.clone(), source).into(),
        None => e,
    }
}

/// `cause` naming `source`; a manifest has no lines, so its location is dropped (FR-44).
fn with_source(mut cause: Cause, real: ConfigSource) -> Cause {
    let manifest = matches!(real, ConfigSource::Manifest { .. });
    match &mut cause {
        Cause::ConfigInvalid { source, at, .. } | Cause::StateVaultTooWide { source, at, .. } => {
            *source = real;
            if manifest {
                *at = None;
            }
        }
        Cause::BoundaryMissing { source, .. } | Cause::StateVaultMissing { source, .. } => {
            *source = real;
        }
        _ => {}
    }
    cause
}

#[cfg(test)]
mod tests {
    use crate::cause::{Cause, ConfigSource, Invocation};
    use crate::error::Error;

    /// The fixture with `from` replaced by `to`, loaded from a file beside the fixture's
    /// bindings (whose ids `load` fills in, shifting the filled-in text's lines); the error's
    /// text and the file's path.
    fn load_err(from: &str, to: &str) -> (Error, String) {
        let text = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
        assert!(text.contains(from), "{from}");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.toml");
        std::fs::write(&path, text.replacen(from, to, 1)).unwrap();
        std::fs::copy(
            "tests/fixtures/secrets.bindings.toml",
            dir.path().join("secrets.bindings.toml"),
        )
        .unwrap();
        let e = crate::config::load(&path).unwrap_err();
        (e, path.display().to_string())
    }

    /// The Do of `e`, a catalog cause, as rendered.
    fn do_of(e: &Error) -> Option<String> {
        e.cause()
            .and_then(|(c, _)| c.do_text(&Invocation::default()))
    }

    #[test]
    fn unknown_field_names_file_line_and_field() {
        let (e, file) = load_err(
            "modes.allumata.payments = \"off\"",
            "modes.allumata.payments = \"off\"\nconfrm_env = true",
        );
        let want = format!("{file} at line 13, column 1: environments.prod.confrm_env ");
        assert!(e.to_string().starts_with(&want), "{e}");
    }

    #[test]
    fn unknown_field_fix_names_the_closest_field() {
        let (e, file) = load_err(
            "modes.allumata.payments = \"off\"",
            "modes.allumata.payments = \"off\"\nconfrm_env = true",
        );
        assert_eq!(
            do_of(&e),
            Some(format!(
                "rename environments.prod.confrm_env to confirm_env in {file} at line 13, column 1"
            ))
        );
    }

    #[test]
    fn unknown_variant_fix_names_the_closest_value() {
        let (e, _) = load_err("kind = \"secret\"", "kind = \"secert\"");
        assert!(
            do_of(&e).is_some_and(|d| d.starts_with("set kind = \"secret\" in ")),
            "{:?}",
            do_of(&e)
        );
    }

    #[test]
    fn undefined_environment_is_located_at_the_key() {
        let (e, file) = load_err("environments = [\"prod\"]", "environments = [\"prd\"]");
        let want = format!(
            "{file} at line 21, column 1: products.allumata.keys.OPENAI_API_KEY.environments \
             names environment prd"
        );
        assert!(e.to_string().starts_with(&want), "{e}");
    }

    #[test]
    fn undefined_environment_fix_names_the_closest_environment() {
        let (e, _) = load_err("environments = [\"prod\"]", "environments = [\"prd\"]");
        assert!(
            do_of(&e).is_some_and(|d| d.starts_with(
                "change prd to prod in products.allumata.keys.OPENAI_API_KEY.environments"
            )),
            "{:?}",
            do_of(&e)
        );
    }

    #[test]
    fn missing_field_fix_names_the_field() {
        let (e, _) = load_err("kind = \"secret\"\n", "");
        assert!(
            do_of(&e)
                .is_some_and(|d| d.starts_with("add products.allumata.keys.OPENAI_API_KEY.kind")),
            "{:?}",
            do_of(&e)
        );
    }

    #[test]
    fn bad_key_name_names_its_line() {
        let (e, file) = load_err(
            "[products.allumata.keys.OPENAI_API_KEY]",
            "[products.allumata.keys.openai]",
        );
        assert!(
            e.to_string().starts_with(&format!(
                "{file} at line 19, column 25: products.allumata.keys.openai must be"
            )),
            "{e}"
        );
    }

    #[test]
    fn located_error_never_shows_the_offending_line() {
        let (e, _) = load_err("kind = \"secret\"", "kind = \"secert\"");
        assert!(!e.to_string().contains("secert"), "{e}");
    }

    /// C15, D1: a provider section's refusal is a typed cause naming the real file.
    #[test]
    fn a_provider_section_refusal_names_the_file() {
        let (e, file) = load_err(
            "fly.app = \"mcproductlabs-portfolio-staging\"",
            "fly.app = \"-a\"",
        );
        assert!(matches!(
            e.cause(),
            Some((Cause::ConfigInvalid { source: ConfigSource::File { path, .. }, .. }, _))
                if path.display().to_string() == file
        ));
    }

    /// 03.01: a manifest's refusal names the manifest, and no file line.
    #[test]
    fn a_manifest_refusal_names_the_manifest() {
        let text = crate::config::merged_text("tests/fixtures/secrets.toml").replacen(
            "kind = \"secret\"",
            "kind = \"secert\"",
            1,
        );
        let e = crate::config::parse_at(
            &text,
            crate::config::Source::ManifestIn {
                title: "opv · app",
                vault: "vlt",
            },
        )
        .unwrap_err();
        assert!(matches!(
            e.cause(),
            Some((Cause::ConfigInvalid { source: ConfigSource::Manifest { title, .. }, at: None, .. }, _))
                if title == "opv · app"
        ));
    }

    /// C1 (SR-1): a `.env` given as the configuration, with its value quoted or bare.
    const MARKER: &str = "sk-live-C1MARKERVALUE";

    fn env_file_error(text: &str) -> Error {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, text).unwrap();
        crate::config::load(&path).unwrap_err()
    }

    /// Everything a refusal shows: its message and its Do.
    fn shown(e: &Error) -> String {
        format!("{e} {:?}", do_of(e))
    }

    #[test]
    fn quoted_env_file_error_never_shows_the_value() {
        let e = env_file_error(&format!("OPENAI_API_KEY=\"{MARKER}\"\n"));
        assert!(!shown(&e).contains("C1MARKER"), "{}", shown(&e));
    }

    #[test]
    fn bare_env_file_error_never_shows_the_value() {
        let e = env_file_error(&format!("OPENAI_API_KEY={MARKER}\n"));
        assert!(!shown(&e).contains("C1MARKER"), "{}", shown(&e));
    }

    #[test]
    fn env_file_error_still_names_line_and_column() {
        let e = env_file_error(&format!("# comment\nOPENAI_API_KEY={MARKER}\n"));
        assert!(e.to_string().contains(" at line 2, column "), "{e}");
    }

    #[test]
    fn manifest_error_never_shows_the_value() {
        let text = format!("OPENAI_API_KEY=\"{MARKER}\"\n");
        let e = crate::config::parse_at(&text, crate::config::Source::Manifest("opv · app"))
            .unwrap_err();
        assert!(!shown(&e).contains("C1MARKER"), "{}", shown(&e));
    }

    #[test]
    fn mistyped_string_error_never_shows_the_value() {
        let text = crate::config::merged_text("tests/fixtures/secrets.toml");
        let bad = text.replacen(
            "[environments.staging]",
            &format!("stores = \"{MARKER}\"\n[environments.staging]"),
            1,
        );
        let e = crate::config::parse(&bad).unwrap_err();
        assert!(!shown(&e).contains("C1MARKER"), "{}", shown(&e));
    }

    #[test]
    fn env_file_error_json_envelope_never_shows_the_value() {
        let e = env_file_error(&format!("OPENAI_API_KEY=\"{MARKER}\"\n"));
        let v = crate::error::document(&e, &crate::error::invocation(), true);
        assert!(!v.to_string().contains("C1MARKER"), "{v}");
    }
}
