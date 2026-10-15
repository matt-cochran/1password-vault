//! `opv skill install` / `opv skill status` (FR-52): one behavioural outcome per test.
//! Every test uses a temporary directory; nothing here touches the developer's home.

use std::fs;

use super::skill::{self, Target};

/// The version the tests pretend the binary is.
const V: &str = "1.2.3";

fn roots(
    home: &std::path::Path,
    project: &std::path::Path,
) -> Vec<(&'static str, std::path::PathBuf)> {
    vec![
        ("user", home.to_path_buf()),
        ("project", project.to_path_buf()),
    ]
}

#[test]
fn render_replaces_the_version_placeholder() {
    let text = skill::render(V);
    assert!(!text.contains("{{OPV_VERSION}}"), "{text}");
}

#[test]
fn render_ends_with_a_marker_that_matches_its_content() {
    let text = skill::render(V);
    assert_eq!(
        skill::installed_version(&text),
        Some(V.to_string()),
        "{text}"
    );
}

#[test]
fn install_writes_both_targets() {
    let dir = tempfile::tempdir().unwrap();
    let installed = skill::install(dir.path(), &skill::ALL, V, false).unwrap();
    assert_eq!(installed.written.len(), 2, "{installed:?}");
    assert!(Target::Claude.path(dir.path()).is_file());
    assert!(Target::Codex.path(dir.path()).is_file());
}

#[test]
fn install_updates_an_unedited_older_copy() {
    let dir = tempfile::tempdir().unwrap();
    let path = Target::Claude.path(dir.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, skill::render("0.1.0")).unwrap();

    let installed = skill::install(dir.path(), &[Target::Claude], V, false).unwrap();
    assert!(installed.kept.is_empty(), "{installed:?}");
    assert_eq!(
        skill::installed_version(&fs::read_to_string(&path).unwrap()),
        Some(V.to_string())
    );
}

#[test]
fn install_keeps_an_edited_copy() {
    let dir = tempfile::tempdir().unwrap();
    let path = Target::Claude.path(dir.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, format!("{}hand edit\n", skill::render("0.1.0"))).unwrap();

    let installed = skill::install(dir.path(), &[Target::Claude], V, false).unwrap();
    assert_eq!(installed.kept.len(), 1, "{installed:?}");
    assert!(fs::read_to_string(&path).unwrap().contains("hand edit"));
}

#[test]
fn install_force_replaces_an_edited_copy() {
    let dir = tempfile::tempdir().unwrap();
    let path = Target::Claude.path(dir.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, format!("{}hand edit\n", skill::render("0.1.0"))).unwrap();

    let installed = skill::install(dir.path(), &[Target::Claude], V, true).unwrap();
    assert_eq!(installed.written.len(), 1, "{installed:?}");
    assert!(!fs::read_to_string(&path).unwrap().contains("hand edit"));
}

#[test]
fn refresh_rewrites_an_unedited_older_copy() {
    let dir = tempfile::tempdir().unwrap();
    let path = Target::Claude.path(dir.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, skill::render("0.1.0")).unwrap();

    let updated = skill::refresh_user_copies(dir.path(), V);
    assert_eq!(updated, vec![path]);
}

#[test]
fn refresh_leaves_an_edited_copy_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = Target::Claude.path(dir.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, format!("{}hand edit\n", skill::render("0.1.0"))).unwrap();

    let updated = skill::refresh_user_copies(dir.path(), V);
    assert!(updated.is_empty(), "{updated:?}");
}

#[test]
fn refresh_does_not_create_a_missing_copy() {
    let dir = tempfile::tempdir().unwrap();
    let path = Target::Codex.path(dir.path());

    skill::refresh_user_copies(dir.path(), V);
    assert!(!path.exists(), "{} was created", path.display());
}

#[test]
fn refresh_leaves_a_current_copy_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = Target::Claude.path(dir.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, skill::render(V)).unwrap();

    let updated = skill::refresh_user_copies(dir.path(), V);
    assert!(updated.is_empty(), "{updated:?}");
}

#[test]
fn status_reports_the_version_and_state_of_each_copy() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let current = Target::Claude.path(home.path());
    let older = Target::Codex.path(project.path());
    let edited = Target::Claude.path(project.path());
    for p in [&current, &older, &edited] {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
    }
    fs::write(&current, skill::render(V)).unwrap();
    fs::write(&older, skill::render("0.1.0")).unwrap();
    fs::write(&edited, format!("{}hand edit\n", skill::render(V))).unwrap();

    let copies = skill::status(&roots(home.path(), project.path()), V);
    let find = |target: Target, scope: &str| {
        copies
            .iter()
            .find(|c| c.target == target && c.scope == scope)
            .unwrap()
    };
    assert!(
        find(Target::Claude, "user").current && !find(Target::Claude, "user").edited,
        "{copies:?}"
    );
    assert_eq!(
        find(Target::Codex, "project").version.as_deref(),
        Some("0.1.0")
    );
    assert!(find(Target::Claude, "project").edited, "{copies:?}");
}
