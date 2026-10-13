use super::*;
use crate::ui::model::Snapshot;

fn app() -> App {
    App::new(Snapshot::gather(&crate::ui::model::tests::Fixtures))
}

fn press(app: &mut App, keys: &[Key]) -> Effect {
    let mut last = Effect::None;
    for k in keys {
        last = app.handle(*k);
    }
    last
}

#[test]
fn the_sidebar_lists_every_configured_environment() {
    let envs: Vec<Nav> = app()
        .nav
        .into_iter()
        .filter(|n| matches!(n, Nav::Env(_)))
        .collect();
    assert_eq!(envs, [Nav::Env("local".into()), Nav::Env("ci".into())]);
}

#[test]
fn enter_on_an_environment_opens_it() {
    let mut a = app();
    press(&mut a, &[Key::Down, Key::Down, Key::Enter]);
    assert_eq!(a.screen, Screen::Env("local".into()));
}

#[test]
fn escape_goes_back() {
    let mut a = app();
    press(&mut a, &[Key::Down, Key::Down, Key::Enter, Key::Esc]);
    assert_eq!(a.screen, Screen::Overview);
}

#[test]
fn sync_on_a_deployed_environment_starts_with_its_plan() {
    let mut a = app();
    let e = press(&mut a, &[Key::Down, Key::Down, Key::Down, Key::Char('s')]);
    assert_eq!(e, Effect::Plan { env: "ci".into() });
}

#[test]
fn sync_on_a_local_environment_explains_there_is_nothing_to_sync() {
    let mut a = app();
    press(&mut a, &[Key::Down, Key::Down, Key::Char('s')]);
    assert!(a.status.contains("local only"), "{}", a.status);
}

fn plan_doc(id: Option<&str>, findings: u64) -> serde_json::Value {
    serde_json::json!({"stage": ["API_TOKEN"], "prune": [], "totals": {"findings": findings}, "plan_id": id})
}

#[test]
fn a_confirmed_sync_runs_exactly_the_reviewed_plan() {
    let mut a = app();
    a.confirm_sync("ci", &plan_doc(Some("abc123"), 0));
    let e = press(&mut a, &[Key::Enter]);
    assert_eq!(
        e,
        Effect::Run(vec![
            "sync".into(),
            "ci".into(),
            "--expect-plan".into(),
            "abc123".into()
        ])
    );
}

#[test]
fn a_guarded_environment_needs_its_name_typed() {
    let mut a = app();
    a.snap
        .envs
        .iter_mut()
        .for_each(|e| e.guarded = e.key == "ci");
    a.confirm_sync("ci", &plan_doc(Some("abc123"), 0));
    assert_eq!(press(&mut a, &[Key::Enter]), Effect::None);
}

#[test]
fn typing_the_guarded_name_confirms() {
    let mut a = app();
    a.snap
        .envs
        .iter_mut()
        .for_each(|e| e.guarded = e.key == "ci");
    a.confirm_sync("ci", &plan_doc(Some("abc123"), 0));
    let e = press(&mut a, &[Key::Char('c'), Key::Char('i'), Key::Enter]);
    assert!(matches!(e, Effect::Run(_)));
}

#[test]
fn a_plan_with_findings_cannot_be_applied() {
    let mut a = app();
    a.confirm_sync("ci", &plan_doc(None, 2));
    assert_eq!(press(&mut a, &[Key::Enter]), Effect::None);
}

#[test]
fn escape_cancels_a_confirmation_and_changes_nothing() {
    let mut a = app();
    a.confirm_sync("ci", &plan_doc(Some("abc123"), 0));
    press(&mut a, &[Key::Esc]);
    assert!(a.modal.is_none() && a.status.contains("nothing was changed"));
}

#[test]
fn enter_on_a_key_row_opens_its_detail() {
    let mut a = app();
    press(&mut a, &[Key::Down, Key::Down, Key::Enter, Key::Enter]);
    assert!(matches!(a.screen, Screen::Key { .. }));
}

// #94: the adoption review ---------------------------------------------------------------

fn adopt_doc() -> serde_json::Value {
    serde_json::json!({"rows": [
        {"found": ["API_TOKEN"], "product": "api", "key": "API_TOKEN", "action": "import"},
        {"found": ["APP_NAME"], "product": "api", "key": "APP_NAME", "action": "differs"},
        {"found": ["STRAY"], "product": null, "key": null, "action": "not_declared"}
    ]})
}

fn reviewing() -> App {
    let mut a = app();
    a.open_adopt("local", "dev.env", &adopt_doc());
    a
}

#[test]
fn a_file_name_opens_the_review_read_only() {
    let mut a = app();
    a.modal = Some(Modal::Input {
        prompt: String::new(),
        value: "dev.env".into(),
        env: "local".into(),
    });
    assert_eq!(
        a.handle(Key::Enter),
        Effect::AdoptPlan {
            env: "local".into(),
            from: "dev.env".into()
        }
    );
}

#[test]
fn an_empty_file_name_reads_nothing() {
    let mut a = app();
    a.modal = Some(Modal::Input {
        prompt: String::new(),
        value: "  ".into(),
        env: "local".into(),
    });
    assert_eq!(a.handle(Key::Enter), Effect::None);
}

#[test]
fn the_review_opens_on_its_screen() {
    assert_eq!(
        reviewing().screen,
        Screen::Adopt {
            env: "local".into(),
            from: "dev.env".into()
        }
    );
}

#[test]
fn enter_changes_the_selected_keys_decision() {
    let mut a = reviewing();
    a.handle(Key::Enter);
    assert_eq!(
        a.adopt[0].decision,
        Some(crate::ui::adopt_review::Decision::Skip)
    );
}

#[test]
fn apply_shows_the_exact_command_before_it_runs() {
    let mut a = reviewing();
    press(&mut a, &[Key::Down, Key::Enter, Key::Char('y')]);
    let Some(Modal::Confirm { command, .. }) = &a.modal else {
        panic!("no confirmation")
    };
    assert_eq!(
        command,
        &[
            "adopt",
            "local",
            "--from",
            "dev.env",
            "--replace",
            "api/APP_NAME",
            "--apply"
        ]
    );
}

#[test]
fn confirming_runs_the_shown_command() {
    let mut a = reviewing();
    press(&mut a, &[Key::Char('y')]);
    assert_eq!(
        a.handle(Key::Enter),
        Effect::Run(
            ["adopt", "local", "--from", "dev.env", "--apply"]
                .map(String::from)
                .to_vec()
        )
    );
}

#[test]
fn nothing_to_write_opens_no_confirmation() {
    let mut a = reviewing();
    press(&mut a, &[Key::Enter, Key::Char('y')]);
    assert!(a.modal.is_none());
}

#[test]
fn down_stops_at_the_last_found_row() {
    let mut a = reviewing();
    press(&mut a, &[Key::Down, Key::Down, Key::Down, Key::Down]);
    assert_eq!(a.row, 2);
}
