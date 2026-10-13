//! The configuration forms (#97): typing, choosing, submitting, cancelling.

use super::*;

fn envs() -> Vec<String> {
    vec!["dev".into(), "prod".into()]
}

fn type_in(f: &mut FormState, text: &str) {
    for c in text.chars() {
        f.handle(Key::Char(c));
    }
}

/// The add-key form on api with the key typed.
fn key_form(key: &str) -> FormState {
    let mut f = FormState::add_key(envs(), true, Some("api".into()), None);
    type_in(&mut f, key);
    f
}

#[test]
fn the_cursor_starts_on_the_key_name() {
    assert_eq!(key_form("").rows()[key_form("").at], Row::Key);
}

#[test]
fn a_typed_key_becomes_the_command() {
    let mut f = key_form("STRIPE_KEY");
    assert_eq!(
        f.handle(Key::Enter),
        Outcome::Command(
            ["add", "api/STRIPE_KEY", "--kind", "secret"]
                .map(String::from)
                .to_vec()
        )
    );
}

#[test]
fn space_on_kind_makes_it_config() {
    let mut f = key_form("LOG_LEVEL");
    f.handle(Key::Down);
    f.handle(Key::Char(' '));
    assert!(f.command().unwrap().contains(&"config".to_string()));
}

#[test]
fn space_on_an_environment_selects_it() {
    let mut f = key_form("STRIPE_KEY");
    f.handle(Key::Down);
    f.handle(Key::Down);
    f.handle(Key::Char(' '));
    assert!(f.command().unwrap().contains(&"dev".to_string()));
}

#[test]
fn an_environment_preset_from_the_screen_is_selected() {
    let mut f = FormState::add_key(envs(), true, Some("api".into()), Some("prod".into()));
    type_in(&mut f, "X");
    assert!(f.command().unwrap().contains(&"prod".to_string()));
}

#[test]
fn an_invalid_key_shows_why_and_keeps_the_form_open() {
    let mut f = key_form("lower");
    assert_eq!(f.handle(Key::Enter), Outcome::Editing);
}

#[test]
fn an_invalid_key_sets_the_error() {
    let mut f = key_form("lower");
    f.handle(Key::Enter);
    assert!(f.error.is_some());
}

#[test]
fn esc_cancels() {
    assert_eq!(key_form("X").handle(Key::Esc), Outcome::Cancelled);
}

#[test]
fn backspace_removes_a_typed_character() {
    let mut f = key_form("ABC");
    f.handle(Key::Backspace);
    assert_eq!(f.command().unwrap()[1], "api/AB");
}

#[test]
fn the_simple_profile_has_no_product_row() {
    let f = FormState::add_key(envs(), false, None, None);
    assert!(!f.rows().contains(&Row::Product));
}

#[test]
fn a_new_environment_becomes_init_add_env() {
    let mut f = FormState::add_env(envs());
    type_in(&mut f, "staging");
    assert_eq!(
        f.handle(Key::Enter),
        Outcome::Command(["init", "staging", "--add-env"].map(String::from).to_vec())
    );
}

#[test]
fn an_existing_environment_name_is_refused() {
    let mut f = FormState::add_env(envs());
    type_in(&mut f, "dev");
    assert_eq!(f.handle(Key::Enter), Outcome::Editing);
}
