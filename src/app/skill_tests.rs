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

/// A copy as `status` reports it, without touching the disk.
fn copy(scope: &str, root: &str, target: Target, edited: bool, current: bool) -> skill::Copy {
    let root = std::path::PathBuf::from(root);
    skill::Copy {
        scope: scope.into(),
        path: target.path(&root),
        root,
        target,
        version: Some("0.1.0".into()),
        edited,
        current,
    }
}

/// 02.11: an outdated project copy is updated with `--project <root>`, never `--user`.
#[test]
fn update_commands_name_the_project_root_for_an_outdated_project_copy() {
    let copies = [copy("project", "/work/app", Target::Claude, false, false)];
    assert_eq!(
        skill::update_commands(&copies),
        vec!["opv skill install --project /work/app --target claude"]
    );
}

#[test]
fn update_commands_name_user_for_an_outdated_home_copy() {
    let copies = [copy("user", "/home/x", Target::Codex, false, false)];
    assert_eq!(
        skill::update_commands(&copies),
        vec!["opv skill install --user --target codex"]
    );
}

#[test]
fn update_commands_install_every_target_when_both_copies_of_a_root_are_outdated() {
    let copies = [
        copy("user", "/home/x", Target::Claude, false, false),
        copy("user", "/home/x", Target::Codex, false, false),
    ];
    assert_eq!(
        skill::update_commands(&copies),
        vec!["opv skill install --user"]
    );
}

#[test]
fn update_commands_leave_an_edited_copy_alone() {
    let copies = [copy("user", "/home/x", Target::Claude, true, false)];
    assert!(skill::update_commands(&copies).is_empty());
}

#[test]
fn update_commands_are_empty_when_every_copy_is_current() {
    let copies = [copy("user", "/home/x", Target::Claude, false, true)];
    assert!(skill::update_commands(&copies).is_empty());
}

#[test]
fn status_document_names_the_update_as_its_next_step() {
    let copies = [copy("project", "/work/app", Target::Claude, false, false)];
    let doc: serde_json::Value =
        serde_json::from_str(&skill::status_document(&copies).unwrap()).unwrap();
    assert_eq!(
        doc["next"],
        "opv skill install --project /work/app --target claude"
    );
}

#[test]
fn status_document_names_install_when_nothing_is_installed() {
    let doc: serde_json::Value =
        serde_json::from_str(&skill::status_document(&[]).unwrap()).unwrap();
    assert_eq!(doc["next"], "opv skill install");
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
