use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::*;

fn ev(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
    KeyEvent::new(code, modifiers)
}

#[test]
fn ctrl_c_is_an_interrupt() {
    assert_eq!(
        key_of(ev(KeyCode::Char('c'), KeyModifiers::CONTROL)),
        Some(Key::Interrupt)
    );
}

#[test]
fn ctrl_s_is_not_sync() {
    assert_eq!(key_of(ev(KeyCode::Char('s'), KeyModifiers::CONTROL)), None);
}

#[test]
fn alt_q_is_not_quit() {
    assert_eq!(key_of(ev(KeyCode::Char('q'), KeyModifiers::ALT)), None);
}

#[test]
fn shift_e_is_a_capital_e() {
    assert_eq!(
        key_of(ev(KeyCode::Char('E'), KeyModifiers::SHIFT)),
        Some(Key::Char('E'))
    );
}

#[test]
fn a_plain_letter_is_that_letter() {
    assert_eq!(
        key_of(ev(KeyCode::Char('s'), KeyModifiers::NONE)),
        Some(Key::Char('s'))
    );
}
