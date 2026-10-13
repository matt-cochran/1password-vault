//! Frames drawn into ratatui's in-memory backend from the recorded documents.

use ratatui::Terminal;
use ratatui::backend::TestBackend;

use super::*;
use crate::ui::app::{App, Key, Screen};
use crate::ui::model::Snapshot;

fn app() -> App {
    App::new(Snapshot::gather(&crate::ui::model::tests::Fixtures))
}

/// The frame as text, `w` × `h` cells.
fn frame(app: &App, w: u16, h: u16) -> String {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| draw(f, app)).unwrap();
    let buf = t.backend().buffer().clone();
    (0..h)
        .map(|y| {
            (0..w)
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn every_screen() -> Vec<App> {
    let screens = [
        Screen::Overview,
        Screen::Shared,
        Screen::Env("local".into()),
        Screen::Env("ci".into()),
        Screen::Product("api".into()),
        Screen::Key {
            product: "api".into(),
            key: "API_TOKEN".into(),
        },
        Screen::Accounts,
    ];
    screens
        .into_iter()
        .map(|s| {
            let mut a = app();
            a.screen = s;
            a
        })
        .collect()
}

#[test]
fn every_screen_draws_at_a_common_size() {
    for a in every_screen() {
        frame(&a, 120, 36);
    }
}

#[test]
fn every_screen_draws_in_a_narrow_terminal() {
    for a in every_screen() {
        frame(&a, 60, 20);
    }
}

#[test]
fn the_overview_shows_each_environment_by_its_title() {
    let f = frame(&app(), 140, 36);
    assert!(
        f.contains("Local development") && f.contains("CI (GitHub)"),
        "{f}"
    );
}

#[test]
fn no_screen_shows_a_value() {
    // The recorded run's markers and config value.
    for a in every_screen() {
        let f = frame(&a, 140, 40);
        assert!(!f.contains("OPVSMOKE") && !f.contains("smoke-app"), "{f}");
    }
}

#[test]
fn a_secret_shows_masked_with_its_state() {
    let mut a = app();
    a.screen = Screen::Product("api".into());
    assert!(frame(&a, 140, 36).contains("••••"));
}

#[test]
fn a_personal_key_is_marked_as_yours() {
    let mut a = app();
    a.screen = Screen::Product("api".into());
    assert!(frame(&a, 140, 36).contains("(yours)"));
}

#[test]
fn the_sync_confirmation_names_the_command_it_runs() {
    let mut a = app();
    a.confirm_sync(
        "ci",
        &serde_json::json!({"stage": ["API_TOKEN"], "prune": [], "totals": {"findings": 0}, "plan_id": "abc123"}),
    );
    assert!(frame(&a, 120, 36).contains("runs: opv sync ci --expect-plan abc123"));
}

#[test]
fn the_key_bar_lists_the_keys() {
    let mut a = app();
    a.handle(Key::Down);
    assert!(frame(&a, 200, 36).contains("q quit"));
}

#[test]
fn the_key_screen_shows_a_settings_finding_with_its_sentence() {
    let mut a = app();
    a.snap.findings.push(crate::ui::model::Finding {
        code: "same_value_across_environments".into(),
        environment: Some("local".into()),
        product: Some("api".into()),
        key: Some("API_TOKEN".into()),
        blocking: false,
        actor: "owner".into(),
        effect: "writes_1password".into(),
        prerequisite: "opv open api/API_TOKEN --env local".into(),
        message: Some("api/API_TOKEN has the same value in local and ci".into()),
    });
    a.screen = Screen::Key {
        product: "api".into(),
        key: "API_TOKEN".into(),
    };
    assert!(frame(&a, 160, 40).contains("has the same value in local and ci"));
}

#[test]
fn the_adoption_review_shows_each_key_and_decision() {
    let mut a = app();
    a.open_adopt(
        "local",
        "dev.env",
        &serde_json::json!({"rows": [
            {"found": ["API_TOKEN"], "product": "api", "key": "API_TOKEN", "action": "differs"}
        ]}),
    );
    assert!(frame(&a, 140, 30).contains("keep 1Password"));
}

#[test]
fn the_declare_a_key_form_draws_its_fields() {
    let mut a = app();
    a.handle(Key::Char('+'));
    assert!(frame(&a, 140, 40).contains("environments"));
}
