//! Masked entry: a fixed mask once anything is entered, never the length.

use super::*;

fn typed(keys: Vec<Key>) -> Masked {
    let mut m = Masked::default();
    for k in keys {
        m.apply(k);
    }
    m
}

#[test]
fn an_empty_field_shows_nothing() {
    assert_eq!(Masked::default().display(), "");
}

#[test]
fn one_typed_character_shows_the_mask() {
    assert_eq!(typed(vec![Key::Char('a')]).display(), MASK);
}

#[test]
fn a_paste_shows_the_mask() {
    assert_eq!(
        typed(vec![Key::Paste("sk_live_abc".into())]).display(),
        MASK
    );
}

#[test]
fn the_mask_does_not_grow_with_the_input() {
    let short = typed(vec![Key::Paste("x".into())]).display();
    let long = typed(vec![Key::Paste("x".repeat(500))]).display();
    assert_eq!(short, long);
}

#[test]
fn a_pasted_trailing_newline_is_not_kept() {
    let m = typed(vec![Key::Paste("token\n".into())]);
    assert_eq!(m.into_secret().expose(), "token");
}

#[test]
fn backspace_to_empty_hides_the_mask() {
    assert_eq!(typed(vec![Key::Char('a'), Key::Backspace]).display(), "");
}

#[test]
fn clear_empties_the_field() {
    assert_eq!(
        typed(vec![Key::Paste("abc".into()), Key::Clear]).display(),
        ""
    );
}

#[test]
fn enter_finishes() {
    assert_eq!(Masked::default().apply(Key::Enter), Step::Done);
}

#[test]
fn cancel_stops() {
    assert_eq!(Masked::default().apply(Key::Cancel), Step::Cancelled);
}

#[test]
fn control_characters_are_never_kept() {
    let m = typed(vec![Key::Char('a'), Key::Char('\u{1b}'), Key::Char('b')]);
    assert_eq!(m.into_secret().expose(), "ab");
}
