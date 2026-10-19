//! The names of a dotenv file for `opv propose setup --names-from` (#90): every key and its
//! kind, never a value.
//! Every value in the file holds [`MARK`]; none may reach the output or the configuration.

use std::path::{Path, PathBuf};

use super::*;

const MARK: &str = "INITFROMMARKER";

/// A private `dev.env` in a fresh directory: two secrets (one empty) and one config.
fn env_file(text: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dev.env");
    std::fs::write(&path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (dir, path)
}

fn standard() -> (tempfile::TempDir, PathBuf) {
    env_file(&format!(
        "OPENAI_API_KEY=sk-{MARK}\nSTRIPE_SECRET_KEY=\nSIGNUP_POLICY=open-{MARK}\n"
    ))
}

fn from(path: &Path) -> FromFile {
    FromFile {
        path: path.to_path_buf(),
        config: vec!["SIGNUP_POLICY".into()],
        secret: Vec::new(),
    }
}

// The names ---------------------------------------------------------------------------

#[test]
fn every_key_in_the_file_is_declared() {
    let (_d, path) = standard();
    let imported = read_from(&from(&path)).unwrap();
    assert_eq!(imported.kinds.len(), 3);
}

#[test]
fn a_config_key_override_makes_the_key_config() {
    let (_d, path) = standard();
    let imported = read_from(&from(&path)).unwrap();
    assert_eq!(imported.kinds["SIGNUP_POLICY"], Kind::Config);
}

#[test]
fn a_secret_key_override_makes_the_key_secret() {
    let (_d, path) = env_file("APP_PORT=8080\n");
    let mut f = from(&path);
    f.config.clear();
    f.secret = vec!["APP_PORT".into()];
    assert_eq!(read_from(&f).unwrap().kinds["APP_PORT"], Kind::Secret);
}

#[test]
fn an_empty_value_is_listed_as_empty() {
    let (_d, path) = standard();
    let imported = read_from(&from(&path)).unwrap();
    assert_eq!(imported.empty, ["STRIPE_SECRET_KEY"]);
}

#[test]
fn an_override_for_a_key_not_in_the_file_is_refused() {
    let (_d, path) = standard();
    let mut f = from(&path);
    f.config.push("NOT_THERE".into());
    assert!(read_from(&f).is_err());
}

#[test]
fn the_same_key_as_config_and_secret_is_refused() {
    let (_d, path) = standard();
    let mut f = from(&path);
    f.secret.push("SIGNUP_POLICY".into());
    assert!(read_from(&f).is_err());
}

#[test]
fn a_file_without_keys_is_refused() {
    let (_d, path) = env_file("# nothing here\n");
    let mut f = from(&path);
    f.config.clear();
    assert!(read_from(&f).is_err());
}

#[cfg(unix)]
#[test]
fn a_file_others_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let (_d, path) = standard();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_from(&from(&path)).is_err());
}

// --apply -----------------------------------------------------------------------------
