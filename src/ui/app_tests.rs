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
fn adopting_asks_for_the_file_then_shows_the_command_first() {
    let mut a = app();
    press(&mut a, &[Key::Down, Key::Down, Key::Char('i')]);
    for ch in ".env".chars() {
        a.handle(Key::Char(ch));
    }
    let e = press(&mut a, &[Key::Enter, Key::Enter]);
    assert_eq!(
        e,
        Effect::Run(vec![
            "adopt".into(),
            "local".into(),
            "--from".into(),
            ".env".into()
        ])
    );
}

#[test]
fn enter_on_a_key_row_opens_its_detail() {
    let mut a = app();
    press(&mut a, &[Key::Down, Key::Down, Key::Enter, Key::Enter]);
    assert!(matches!(a.screen, Screen::Key { .. }));
}
