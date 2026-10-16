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

#[cfg(unix)]
#[test]
fn a_failed_readys_exit_code_is_passed_on() {
    // 07.05: `opv ui` without a terminal ends with ready's own exit code, never "1 finding".
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(exit_code(std::process::ExitStatus::from_raw(7 << 8)), 7);
}

#[cfg(unix)]
#[test]
fn a_signal_is_passed_on_as_128_plus_the_signal() {
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(exit_code(std::process::ExitStatus::from_raw(2)), 130);
}

#[test]
fn opv_that_cannot_start_is_a_catalog_cause() {
    // C11: the cause comes from the catalog, never free text.
    assert!(matches!(
        start_failed(std::io::ErrorKind::NotFound),
        Error::Catalog(..)
    ));
}

#[test]
fn a_terminal_that_stops_working_is_a_catalog_cause() {
    assert!(matches!(io_err(&"broken pipe"), Error::Catalog(..)));
}
