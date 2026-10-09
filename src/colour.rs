//! Colour for state words on a terminal (P17). Only fixed state words are wrapped in
//! escape codes: doctor's leading `ok`/`warn`/`FAIL`/`skip`, and the row state
//! (`saved`, `missing`, `wrong kind`, `failed`, `skipped`) in the status/plan table and in
//! check lines. Nothing value-derived is ever coloured, and the bytes between the escape
//! codes are exactly what would be printed without colour. Off the terminal, with
//! `NO_COLOR` set or with `--color never`, the painter is not used at all, so piped output,
//! JSON and the goldens are byte-identical.

use std::ffi::OsString;
use std::io::{self, Write};

/// `--color <WHEN>`: `auto` colours only when stdout is a terminal and NO_COLOR is
/// unset or empty; `always` colours even when piped; `never` never colours.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

/// Whether to colour, from the flag, whether stdout is a terminal and `NO_COLOR`
/// (<https://no-color.org>: any non-empty value disables colour under `auto`).
pub fn enabled(choice: ColorChoice, stdout_is_tty: bool, no_color: Option<OsString>) -> bool {
    match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => stdout_is_tty && no_color.is_none_or(|v| v.is_empty()),
    }
}

const RESET: &str = "\x1b[0m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const DIM: &str = "\x1b[2m";

/// Doctor's leading status words.
const DOCTOR: [(&str, &str); 4] = [
    ("ok", GREEN),
    ("warn", YELLOW),
    ("FAIL", RED),
    ("skip", DIM),
];

/// Row states, as printed by `state_label` (a failing rule starts with `failed`).
const STATES: [(&str, &str); 5] = [
    ("saved", GREEN),
    ("missing", RED),
    ("wrong kind", RED),
    ("failed", RED),
    ("skipped", DIM),
];

/// A line-buffered writer that colours state words in complete lines.
pub struct Painter<W: Write> {
    inner: W,
    buf: Vec<u8>,
    /// Byte offset of the STATE column while inside a status/plan table.
    state_col: Option<usize>,
}

impl<W: Write> Painter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            state_col: None,
        }
    }

    fn emit_lines(&mut self) -> io::Result<()> {
        while let Some(end) = self.buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=end).collect();
            let painted = match std::str::from_utf8(&line[..end]) {
                Ok(text) => {
                    let mut p = self.paint(text);
                    p.push('\n');
                    p.into_bytes()
                }
                Err(_) => line,
            };
            self.inner.write_all(&painted)?;
        }
        Ok(())
    }

    fn paint(&mut self, line: &str) -> String {
        if (line.starts_with("PRODUCT ") || line.starts_with("KEY "))
            && let Some(col) = line.find("  STATE")
        {
            self.state_col = Some(col + 2);
            return line.to_string();
        }
        if let Some(col) = self.state_col {
            if line[..col.min(line.len())].ends_with("  ")
                && let Some(p) = paint_word_at(line, col, &STATES, word_end)
            {
                return p;
            }
            if line.starts_with("    guidance: ") {
                return line.to_string();
            }
            self.state_col = None;
        }
        if let Some(p) = paint_word_at(line, 0, &DOCTOR, |rest| rest.starts_with(' ')) {
            return p;
        }
        // check: `product/KEY: <state>` (no spaces in the label).
        if let Some(i) = line.find(": ")
            && !line[..i].is_empty()
            && !line[..i].contains(char::is_whitespace)
            && let Some(p) = paint_word_at(line, i + 2, &STATES, word_end)
        {
            return p;
        }
        line.to_string()
    }
}

/// A state word ends at the end of the line, a space or an opening bracket.
fn word_end(rest: &str) -> bool {
    rest.is_empty() || rest.starts_with(' ') || rest.starts_with('(')
}

/// `line` with the first of `words` that starts at byte `at` (and is followed by text
/// accepted by `ends`) wrapped in its colour; `None` when none matches.
fn paint_word_at(
    line: &str,
    at: usize,
    words: &[(&str, &str)],
    ends: impl Fn(&str) -> bool,
) -> Option<String> {
    let tail = line.get(at..)?;
    let (word, colour) = words
        .iter()
        .find(|(w, _)| tail.starts_with(w) && ends(&tail[w.len()..]))?;
    Some(format!(
        "{}{colour}{word}{RESET}{}",
        &line[..at],
        &tail[word.len()..]
    ))
}

impl<W: Write> Write for Painter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        self.emit_lines()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit_lines()?;
        if !self.buf.is_empty() {
            let rest = std::mem::take(&mut self.buf);
            self.inner.write_all(&rest)?;
        }
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn painted(text: &str) -> String {
        let mut p = Painter::new(Vec::new());
        p.write_all(text.as_bytes()).unwrap();
        p.flush().unwrap();
        String::from_utf8(p.inner).unwrap()
    }

    fn plain(s: &str) -> String {
        regex::Regex::new("\x1b\\[[0-9;]*m")
            .unwrap()
            .replace_all(s, "")
            .into_owned()
    }

    #[test]
    fn auto_with_no_color_set_is_off_on_a_terminal() {
        assert!(!enabled(ColorChoice::Auto, true, Some("1".into())));
    }

    #[test]
    fn auto_off_a_terminal_is_off() {
        assert!(!enabled(ColorChoice::Auto, false, None));
    }

    #[test]
    fn auto_on_a_terminal_is_on() {
        assert!(enabled(ColorChoice::Auto, true, Some("".into())));
    }

    #[test]
    fn always_is_on_when_piped_with_no_color() {
        assert!(enabled(ColorChoice::Always, false, Some("1".into())));
    }

    #[test]
    fn never_is_off_on_a_terminal() {
        assert!(!enabled(ColorChoice::Never, true, None));
    }

    #[test]
    fn doctor_status_word_is_coloured() {
        assert_eq!(
            painted("FAIL  op: not found\n"),
            format!("{RED}FAIL{RESET}  op: not found\n")
        );
    }

    #[test]
    fn table_state_cell_is_coloured() {
        let t = "PRODUCT  KEY  KIND    STATE    TARGET\napi      K    secret  missing  absent\n";
        assert!(
            painted(t).contains(&format!("secret  {RED}missing{RESET}  absent")),
            "{}",
            painted(t)
        );
    }

    #[test]
    fn check_line_state_is_coloured() {
        assert_eq!(
            painted("api/K: failed prefix (expected prefix sk-)\n"),
            format!("api/K: {RED}failed{RESET} prefix (expected prefix sk-)\n")
        );
    }

    #[test]
    fn painting_only_adds_escape_codes() {
        let t = "PRODUCT  KEY  KIND    STATE    TARGET\napi      K    secret  saved    -\n    guidance: x\napi      L    config  skipped  -\n1 saved, 0 findings\nwarn  fly auth: token\npartial";
        assert_eq!(plain(&painted(t)), t);
    }

    #[test]
    fn a_key_named_like_a_state_is_not_coloured() {
        let t = "PRODUCT  KEY      KIND    STATE  TARGET\napi      missing  secret  saved  -\n";
        assert!(
            !painted(t).contains(&format!("{RED}missing")),
            "{}",
            painted(t)
        );
    }
}
