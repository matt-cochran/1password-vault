use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::adapters::onepassword_manifest::template;

/// A run-only simple configuration: no value, no target.
pub(crate) const TOML: &str = "[profile]\nkind = \"simple\"\n\n[environments.dev]\nvault_id = \"vdev0000000000000000000001\"\nitem_id = \"app\"\n\n[keys.API_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n";

const REPO: &str = "github.com/acme/myapp";

fn put(op: &FakeOp, vault: &str, project: &str, tags: &[String]) -> String {
    op.insert(
        vault,
        template(&manifest_title(project), project, tags, TOML),
    )
}

fn repo_tags(paths: &[&str]) -> Vec<String> {
    let paths: Vec<String> = paths.iter().map(|p| p.to_string()).collect();
    manifest_tags(Some(REPO), &paths)
}

fn req(dir: &Path) -> Request {
    Request {
        start: dir.to_path_buf(),
        ..Request::default()
    }
}

fn title_of(found: Result<Found, Error>) -> String {
    match found {
        Ok(Found::Manifest(m)) => m.title,
        Ok(Found::File { store, .. }) => store.path.display().to_string(),
        Err(e) => format!("error: {e}"),
    }
}

// --- git remote normalization ---

#[test]
fn https_remote_is_normalized() {
    assert_eq!(
        normalize_remote("https://github.com/Acme/MyApp.git").as_deref(),
        Some(REPO)
    );
}

#[test]
fn ssh_url_remote_drops_user_and_port() {
    assert_eq!(
        normalize_remote("ssh://git@github.com:22/acme/myapp.git").as_deref(),
        Some(REPO)
    );
}

#[test]
fn scp_like_remote_is_normalized() {
    assert_eq!(
        normalize_remote("git@github.com:acme/myapp.git\n").as_deref(),
        Some(REPO)
    );
}

#[test]
fn remote_without_git_suffix_is_normalized() {
    assert_eq!(
        normalize_remote("https://github.com/acme/myapp/").as_deref(),
        Some(REPO)
    );
}

#[test]
fn credentials_in_a_remote_never_reach_the_repo() {
    assert_eq!(
        normalize_remote("https://x-access-token:ghp_SECRETMARKER@github.com/acme/myapp.git")
            .as_deref(),
        Some(REPO)
    );
}

#[test]
fn local_path_remote_is_not_a_repo() {
    assert_eq!(normalize_remote("/srv/git/myapp.git"), None);
}

#[test]
fn nested_group_remote_keeps_every_segment() {
    assert_eq!(
        normalize_remote("git@gitlab.com:acme/platform/myapp.git").as_deref(),
        Some("gitlab.com/acme/platform/myapp")
    );
}

// --- tag escaping ---

#[test]
fn repo_tag_has_no_slash_or_comma() {
    let t = repo_tag(REPO);
    assert!(!t.contains('/') && !t.contains(','), "{t}");
}

#[test]
fn repo_tag_round_trips() {
    assert_eq!(parse_repo_tag(&repo_tag(REPO)).as_deref(), Some(REPO));
}

#[test]
fn path_tag_round_trips() {
    assert_eq!(
        parse_path_tag(&path_tag("apps/api")).as_deref(),
        Some("apps/api")
    );
}

#[test]
fn path_with_dot_dot_is_refused() {
    assert_eq!(normalize_path("apps/../secret"), None);
}

#[test]
fn path_score_prefers_the_longest_prefix() {
    let paths = vec!["apps".to_string(), "apps/api".to_string()];
    assert_eq!(
        path_score(&paths, "apps/api/src"),
        Some("apps/api".len() + 1)
    );
}

#[test]
fn path_score_needs_whole_segments() {
    assert_eq!(path_score(&["apps/api".to_string()], "apps/apiary"), None);
}

// --- discovery order ---

#[test]
fn config_flag_wins_over_opv_project() {
    let op = FakeOp::default();
    let dir = tempfile::tempdir().unwrap();
    let mut r = req(dir.path());
    r.config = Some((PathBuf::from("x.toml"), Given::Flag));
    r.project = Some("myapp".into());
    assert_eq!(title_of(locate(&r, &op)), "x.toml");
}

#[test]
fn opv_project_wins_over_a_secrets_toml() {
    let op = FakeOp::default();
    put(&op, "myapp-dev", "myapp", &manifest_tags(None, &[]));
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(FILE_NAME), TOML).unwrap();
    let mut r = req(dir.path());
    r.project = Some("myapp".into());
    assert_eq!(title_of(locate(&r, &op)), "opv · myapp");
}

#[test]
fn existing_secrets_toml_wins_over_the_git_remote() {
    let op = FakeOp::with_remote("git@github.com:acme/myapp.git");
    put(&op, "myapp-dev", "myapp", &repo_tags(&[]));
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(FILE_NAME), TOML).unwrap();
    assert!(matches!(
        locate(&req(dir.path()), &op),
        Ok(Found::File { .. })
    ));
}

#[test]
fn existing_secrets_toml_makes_no_op_or_git_call() {
    let op = FakeOp::with_remote("git@github.com:acme/myapp.git");
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(FILE_NAME), TOML).unwrap();
    let _ = locate(&req(dir.path()), &op);
    assert!(op.calls.borrow().is_empty());
}

#[test]
fn secrets_toml_wins_over_a_dot_opv() {
    let op = FakeOp::default();
    put(&op, "myapp-dev", "myapp", &manifest_tags(None, &[]));
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(FILE_NAME), TOML).unwrap();
    std::fs::write(dir.path().join(DOT_FILE), "project = \"myapp\"\n").unwrap();
    assert!(matches!(
        locate(&req(dir.path()), &op),
        Ok(Found::File { .. })
    ));
}

#[test]
fn dot_opv_selects_the_manifest_by_project() {
    let op = FakeOp::default();
    put(&op, "myapp-dev", "myapp", &manifest_tags(None, &[]));
    put(&op, "shared", "other", &manifest_tags(None, &[]));
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(DOT_FILE), "project = \"myapp\"\n").unwrap();
    assert_eq!(title_of(locate(&req(dir.path()), &op)), "opv · myapp");
}

#[test]
fn dot_opv_account_reaches_the_listing() {
    let op = FakeOp::default();
    put(&op, "myapp-dev", "myapp", &manifest_tags(None, &[]));
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(DOT_FILE),
        "project = \"myapp\"\naccount = \"acme.1password.com\"\n",
    )
    .unwrap();
    let _ = locate(&req(dir.path()), &op);
    assert_eq!(
        op.count(&[
            "op",
            "item",
            "list",
            "--tags",
            MANIFEST_TAG,
            "--format",
            "json",
            "--account",
            "acme.1password.com"
        ]),
        1
    );
}

#[test]
fn dot_opv_with_an_unknown_key_is_a_config_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(DOT_FILE), "projct = \"myapp\"\n").unwrap();
    assert!(matches!(
        locate(&req(dir.path()), &FakeOp::default()),
        Err(Error::Config(_))
    ));
}

#[test]
fn git_remote_matches_the_repo_tag() {
    let op = FakeOp::with_remote("https://github.com/acme/myapp.git");
    put(
        &op,
        "shared",
        "other",
        &manifest_tags(Some("github.com/acme/other"), &[]),
    );
    put(&op, "myapp-dev", "myapp", &repo_tags(&[]));
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(title_of(locate(&req(dir.path()), &op)), "opv · myapp");
}

#[test]
fn git_remote_discovery_is_one_listing() {
    let op = FakeOp::with_remote("https://github.com/acme/myapp.git");
    put(&op, "myapp-dev", "myapp", &repo_tags(&[]));
    let dir = tempfile::tempdir().unwrap();
    let _ = locate(&req(dir.path()), &op);
    assert_eq!(op.count(&["op", "item", "list"]), 1);
}

#[test]
fn several_repo_matches_are_listed_with_opv_project_next() {
    let op = FakeOp::with_remote("https://github.com/acme/myapp.git");
    put(&op, "myapp-dev", "api", &repo_tags(&[]));
    put(&op, "shared", "web", &repo_tags(&[]));
    let dir = tempfile::tempdir().unwrap();
    let e = locate(&req(dir.path()), &op).unwrap_err();
    assert!(
        e.text().contains("opv · api")
            && e.text().contains("opv · web")
            && e.next_step().unwrap().starts_with("OPV_PROJECT="),
        "{e:?}"
    );
}

#[test]
fn opv_project_picks_one_of_several_repo_matches() {
    let op = FakeOp::with_remote("https://github.com/acme/myapp.git");
    put(&op, "myapp-dev", "api", &repo_tags(&[]));
    put(&op, "shared", "web", &repo_tags(&[]));
    let dir = tempfile::tempdir().unwrap();
    let mut r = req(dir.path());
    r.project = Some("web".into());
    assert_eq!(title_of(locate(&r, &op)), "opv · web");
}

#[test]
fn no_match_names_init_as_the_next_step() {
    let op = FakeOp::with_remote("https://github.com/acme/myapp.git");
    let dir = tempfile::tempdir().unwrap();
    let e = locate(&req(dir.path()), &op).unwrap_err();
    assert!(e.next_step().unwrap().starts_with("opv init "), "{e:?}");
}

#[test]
fn no_config_anywhere_keeps_the_not_found_prefix_for_doctor() {
    let dir = tempfile::tempdir().unwrap();
    let e = locate(&req(dir.path()), &FakeOp::default()).unwrap_err();
    assert!(e.text().starts_with(config::NOT_FOUND), "{e:?}");
}

#[test]
fn missing_session_gives_next_opv_login() {
    let op = FakeOp::with_remote("https://github.com/acme/myapp.git");
    op.signed_in.set(false);
    let dir = tempfile::tempdir().unwrap();
    let e = locate(&req(dir.path()), &op).unwrap_err();
    assert_eq!(e.next_step(), Some("opv login"), "{e:?}");
}

#[test]
fn missing_session_says_the_configuration_lives_in_1password() {
    let op = FakeOp::default();
    op.signed_in.set(false);
    let dir = tempfile::tempdir().unwrap();
    let mut r = req(dir.path());
    r.project = Some("myapp".into());
    let e = locate(&r, &op).unwrap_err();
    assert!(
        e.text().contains("configuration lives in 1Password"),
        "{e:?}"
    );
}

// --- monorepo paths ---

fn monorepo(op: &FakeOp) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("apps/api/src")).unwrap();
    std::fs::create_dir_all(dir.path().join("apps/web")).unwrap();
    *op.toplevel.borrow_mut() = Some(dir.path().display().to_string());
    dir
}

#[test]
fn longest_path_prefix_wins() {
    let op = FakeOp::with_remote("git@github.com:acme/myapp.git");
    let dir = monorepo(&op);
    put(&op, "myapp-dev", "apps", &repo_tags(&["apps"]));
    put(&op, "myapp-dev", "api", &repo_tags(&["apps/api"]));
    let start = dir.path().join("apps/api/src");
    assert_eq!(title_of(locate(&req(&start), &op)), "opv · api");
}

#[test]
fn manifest_without_paths_is_the_fallback() {
    let op = FakeOp::with_remote("git@github.com:acme/myapp.git");
    let dir = monorepo(&op);
    put(&op, "myapp-dev", "api", &repo_tags(&["apps/api"]));
    put(&op, "myapp-dev", "whole", &repo_tags(&[]));
    let start = dir.path().join("apps/web");
    assert_eq!(title_of(locate(&req(&start), &op)), "opv · whole");
}

#[test]
fn root_with_path_manifests_lists_candidates() {
    let op = FakeOp::with_remote("git@github.com:acme/myapp.git");
    let dir = monorepo(&op);
    put(&op, "myapp-dev", "api", &repo_tags(&["apps/api"]));
    put(&op, "myapp-dev", "web", &repo_tags(&["apps/web"]));
    let e = locate(&req(dir.path()), &op).unwrap_err();
    assert!(
        e.text().contains("paths apps/api") && e.text().contains("paths apps/web"),
        "{e:?}"
    );
}

// --- stores ---

#[test]
fn manifest_load_parses_the_notes() {
    let op = FakeOp::default();
    put(&op, "myapp-dev", "myapp", &manifest_tags(None, &[]));
    let dir = tempfile::tempdir().unwrap();
    let mut r = req(dir.path());
    r.project = Some("myapp".into());
    let fleet = locate(&r, &op).unwrap().load(&op).unwrap();
    assert!(fleet.environments.contains_key("dev"));
}

#[test]
fn invalid_manifest_names_the_manifest_not_the_file() {
    let op = FakeOp::default();
    op.insert(
        "myapp-dev",
        template("opv · bad", "bad", &manifest_tags(None, &[]), "[profile\n"),
    );
    let dir = tempfile::tempdir().unwrap();
    let mut r = req(dir.path());
    r.project = Some("bad".into());
    let e = locate(&r, &op).unwrap().load(&op).unwrap_err();
    assert!(e.text().contains("manifest \"opv · bad\""), "{e:?}");
}

#[test]
fn manifest_replace_refuses_when_the_version_moved() {
    let op = FakeOp::default();
    let id = put(&op, "myapp-dev", "myapp", &manifest_tags(None, &[]));
    let dir = tempfile::tempdir().unwrap();
    let mut r = req(dir.path());
    r.project = Some("myapp".into());
    let found = locate(&r, &op).unwrap();
    let base = found.store().read(&op).unwrap();
    op.bump(&id);
    let res = found.store().replace(&op, &base, "x").unwrap();
    assert!(matches!(res, Replaced::Changed(_)));
}

#[test]
fn file_replace_refuses_when_the_file_changed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(FILE_NAME);
    std::fs::write(&path, TOML).unwrap();
    let s = FileStore { path: path.clone() };
    let base = s.read(&FakeOp::default()).unwrap();
    std::fs::write(&path, "# changed\n").unwrap();
    let res = s.replace(&FakeOp::default(), &base, TOML).unwrap();
    assert!(matches!(res, Replaced::Changed(_)));
}

#[test]
fn create_refuses_a_second_manifest_for_the_same_repo() {
    let op = FakeOp::default();
    put(&op, "myapp-dev", "myapp", &repo_tags(&[]));
    let e = create_manifest(&op, "shared", "renamed", Some(REPO), &[], TOML, None).unwrap_err();
    assert_eq!(e.next_step(), Some("opv config edit"));
}

#[test]
fn create_allows_another_path_in_the_same_repo() {
    let op = FakeOp::default();
    put(&op, "myapp-dev", "api", &repo_tags(&["apps/api"]));
    let res = create_manifest(
        &op,
        "myapp-dev",
        "web",
        Some(REPO),
        &["apps/web".to_string()],
        TOML,
        None,
    );
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn manifest_text_goes_on_stdin_never_argv() {
    let op = FakeOp::default();
    create_manifest(&op, "myapp-dev", "myapp", Some(REPO), &[], TOML, None).unwrap();
    let in_argv = op
        .calls
        .borrow()
        .iter()
        .any(|c| c.args.iter().any(|a| a.contains("API_KEY")));
    assert!(!in_argv);
}

#[test]
fn new_manifest_has_no_concealed_field() {
    let op = FakeOp::default();
    let m = create_manifest(&op, "myapp-dev", "myapp", Some(REPO), &[], TOML, None).unwrap();
    let item = op.item(&m.item_id);
    let concealed = item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["type"] == "CONCEALED");
    assert!(!concealed);
}

#[test]
fn new_manifest_carries_convention_1() {
    let op = FakeOp::default();
    let m = create_manifest(&op, "myapp-dev", "myapp", None, &[], TOML, None).unwrap();
    let item = op.item(&m.item_id);
    let conv = item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == "convention")
        .map(|f| f["value"].clone());
    assert_eq!(conv, Some(serde_json::json!("1")));
}

#[test]
fn default_project_is_the_repo_name() {
    assert_eq!(
        default_project(None, Some(REPO), Path::new("/x/checkout")).unwrap(),
        "myapp"
    );
}
