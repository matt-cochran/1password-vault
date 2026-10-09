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

// --- final review (FR-44): fresh reads, version checks, identity gate, accounts ---

/// The manifest `opv · myapp` (no tags) and its store, found by `OPV_PROJECT`.
fn myapp(op: &FakeOp) -> (String, Found) {
    let id = put(op, "myapp-dev", "myapp", &manifest_tags(None, &[]));
    let dir = tempfile::tempdir().unwrap();
    let mut r = req(dir.path());
    r.project = Some("myapp".into());
    (id, locate(&r, op).unwrap())
}

/// TOML with one more key: an edit someone made in the 1Password app.
fn edited() -> String {
    format!("{TOML}\n[keys.ROTATED]\nkind = \"secret\"\nenvironments = [\"dev\"]\n")
}

fn under<T>(env: crate::host::FakeEnv, f: impl FnOnce() -> T) -> T {
    crate::host::with_test_host(Host::from_env(&env.shell("/bin/bash")), f)
}

#[test]
fn the_read_an_edit_starts_from_sees_past_ops_cache() {
    let op = FakeOp::default();
    let (id, found) = myapp(&op);
    found.store().read(&op).unwrap();
    op.edit_elsewhere(&id, &edited());
    let base = found.store().read_for_write(&op).unwrap();
    assert_eq!(base.text, edited());
}

#[test]
fn a_base_read_from_ops_cache_never_overwrites_a_newer_edit() {
    let op = FakeOp::default();
    let (id, found) = myapp(&op);
    found.store().read(&op).unwrap();
    op.edit_elsewhere(&id, &edited());
    let stale = found.store().read(&op).unwrap();
    let res = found.store().replace(&op, &stale, TOML).unwrap();
    assert!(matches!(res, Replaced::Changed(_)));
}

#[test]
fn every_read_a_manifest_write_checks_against_bypasses_the_cache() {
    let op = FakeOp::default();
    let (_, found) = myapp(&op);
    let base = found.store().read_for_write(&op).unwrap();
    found.store().replace(&op, &base, &edited()).unwrap();
    let cached = op
        .calls
        .borrow()
        .iter()
        .filter(|c| c.args.starts_with(&["item".into(), "get".into()]))
        .skip(1)
        .any(|c| !c.args.iter().any(|a| a == "--cache=false"));
    assert!(!cached);
}

#[test]
fn an_edit_landing_with_a_manifest_write_is_config_changed() {
    let op = FakeOp::default();
    let (_, found) = myapp(&op);
    let base = found.store().read_for_write(&op).unwrap();
    op.racing_edit.set(Some(1));
    let e = save(found.store(), &op, &base, &edited()).unwrap_err();
    assert_eq!(e.code(), crate::error::Code::ConfigChanged);
}

#[test]
fn an_edit_landing_with_a_manifest_write_is_never_retried() {
    let op = FakeOp::default();
    let (_, found) = myapp(&op);
    let base = found.store().read_for_write(&op).unwrap();
    op.racing_edit.set(Some(1));
    let _ = save(found.store(), &op, &base, &edited());
    assert_eq!(op.count(&["op", "item", "edit"]), 1);
}

#[test]
fn a_manifest_write_one_version_later_is_saved() {
    let op = FakeOp::default();
    let (_, found) = myapp(&op);
    let base = found.store().read_for_write(&op).unwrap();
    assert!(save(found.store(), &op, &base, &edited()).is_ok());
}

#[test]
fn a_manifest_write_under_a_service_account_is_refused() {
    let op = FakeOp::default();
    let (_, found) = myapp(&op);
    let base = found.store().read(&op).unwrap();
    let env = crate::host::FakeEnv::new("linux").var_val("OP_SERVICE_ACCOUNT_TOKEN", "dummy");
    let e = under(env, || found.store().replace(&op, &base, &edited())).unwrap_err();
    assert_eq!(e.code(), crate::error::Code::PolicyRefused);
}

#[test]
fn a_manifest_write_in_ci_writes_nothing() {
    let op = FakeOp::default();
    let (_, found) = myapp(&op);
    let base = found.store().read(&op).unwrap();
    let env = crate::host::FakeEnv::new("linux").var("CI");
    let _ = under(env, || found.store().replace(&op, &base, &edited()));
    assert_eq!(op.count(&["op", "item", "edit"]), 0);
}

#[test]
fn a_refused_manifest_write_names_opv_login() {
    let op = FakeOp::default();
    let (_, found) = myapp(&op);
    let env = crate::host::FakeEnv::new("linux").var("CI");
    let e = under(env, || found.store().read_for_write(&op)).unwrap_err();
    assert_eq!(e.next_step(), Some("opv login"));
}

#[test]
fn creating_a_manifest_under_a_service_account_creates_nothing() {
    let op = FakeOp::default();
    let env = crate::host::FakeEnv::new("linux").var_val("OP_SERVICE_ACCOUNT_TOKEN", "dummy");
    let _ = under(env, || {
        create_manifest(&op, "myapp-dev", "myapp", Some(REPO), &[], TOML, None)
    });
    assert_eq!(op.count(&["op", "item", "create"]), 0);
}

/// A fake whose writes come back `Refused` (a definite failure, nothing changed).
struct RefusedWrites<'a>(&'a FakeOp);

impl CommandRunner for RefusedWrites<'_> {
    fn read(&self, call: &Call, refused: &[i32]) -> std::io::Result<crate::runner::Outcome> {
        self.0.read(call, refused)
    }
    fn write(&self, _: &Call) -> std::io::Result<crate::runner::Outcome> {
        Ok(crate::runner::Outcome::Refused(
            crate::runner::Output::failure(1),
        ))
    }
    fn probe(
        &self,
        call: &Call,
        limit: std::time::Duration,
    ) -> std::io::Result<crate::runner::Output> {
        self.0.probe(call, limit)
    }
    fn pause(&self, _: std::time::Duration, _: &str) {}
    fn note(&self, _: &str) {}
    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> std::io::Result<i32> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

#[test]
fn a_refused_manifest_write_is_a_definite_failure() {
    let op = FakeOp::default();
    let (_, found) = myapp(&op);
    let base = found.store().read_for_write(&op).unwrap();
    let e = found
        .store()
        .replace(&RefusedWrites(&op), &base, &edited())
        .unwrap_err();
    assert_ne!(e.code(), crate::error::Code::OutcomeUnknown, "{e:?}");
}

#[test]
fn a_dot_opv_account_that_reads_as_a_flag_is_refused() {
    let res = parse_dot_opv("project = \"myapp\"\naccount = \"-x\"\n", Path::new(".opv"));
    assert!(res.is_err());
}

#[test]
fn a_dot_opv_sign_in_address_is_accepted() {
    let res = parse_dot_opv(
        "project = \"myapp\"\naccount = \"team.1password.com\"\n",
        Path::new(".opv"),
    );
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn a_single_path_scoped_manifest_is_not_used_from_a_sibling_directory() {
    let op = FakeOp::with_remote("git@github.com:acme/myapp.git");
    let dir = monorepo(&op);
    put(&op, "myapp-dev", "api", &repo_tags(&["apps/api"]));
    let start = dir.path().join("apps/web");
    let e = locate(&req(&start), &op).unwrap_err();
    assert_eq!(e.next_step(), Some("OPV_PROJECT=api opv <command>"));
}

#[test]
fn a_single_path_scoped_manifest_is_used_inside_its_path() {
    let op = FakeOp::with_remote("git@github.com:acme/myapp.git");
    let dir = monorepo(&op);
    put(&op, "myapp-dev", "api", &repo_tags(&["apps/api"]));
    let start = dir.path().join("apps/api/src");
    assert_eq!(title_of(locate(&req(&start), &op)), "opv · api");
}

#[test]
fn a_single_manifest_without_paths_covers_the_whole_repository() {
    let op = FakeOp::with_remote("git@github.com:acme/myapp.git");
    let dir = monorepo(&op);
    put(&op, "myapp-dev", "whole", &repo_tags(&[]));
    let start = dir.path().join("apps/web");
    assert_eq!(title_of(locate(&req(&start), &op)), "opv · whole");
}

fn in_account(op: &FakeOp, text: &str) -> Fleet {
    let id = op.insert(
        "myapp-dev",
        template(&manifest_title("myapp"), "myapp", &[], text),
    );
    let row = Row {
        id,
        title: manifest_title("myapp"),
        tags: Vec::new(),
        version: 1,
        vault: crate::adapters::onepassword_manifest::VaultRef {
            id: "vdev0000000000000000000001".into(),
            name: "myapp-dev".into(),
        },
    };
    Found::Manifest(ManifestStore::from_row(
        &row,
        Some("work".into()),
        Matched::Given,
    ))
    .load(op)
    .unwrap()
}

#[test]
fn a_manifest_in_another_account_passes_it_to_its_environments() {
    let fleet = in_account(&FakeOp::default(), TOML);
    assert_eq!(fleet.environments["dev"].account.as_deref(), Some("work"));
}

#[test]
fn an_environments_own_account_wins_over_the_manifests() {
    let text = TOML.replace(
        "item_id = \"app\"\n",
        "item_id = \"app\"\naccount = \"home\"\n",
    );
    let fleet = in_account(&FakeOp::default(), &text);
    assert_eq!(fleet.environments["dev"].account.as_deref(), Some("home"));
}
