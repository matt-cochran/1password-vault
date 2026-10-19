//! The configuration forms of `opv ui` (#97): declare a key, add an environment. A form only
//! collects names and choices; on submit it is validated and becomes the exact
//! `opv propose key --write` / `opv propose env --write` command ([`super::config_forms`]), which
//! the UI shows and runs after a confirmation like every other write. A form never holds a
//! value.

use super::app::Key;
use super::config_forms::{AddEnvForm, AddKeyForm, KindChoice, add_env_command, add_key_command};

/// One row of a form, in the order the cursor moves through them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Row {
    Product,
    Key,
    Kind,
    /// The n-th environment's checkbox.
    Env(usize),
    Guidance,
    Personal,
    AllowSame,
    EnvName,
}

/// Which form is open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Form {
    AddKey(AddKeyForm),
    AddEnv(AddEnvForm),
}

/// A form being filled in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormState {
    pub form: Form,
    /// Every declared environment (the add-key checkboxes; the add-env duplicates check).
    pub envs: Vec<String>,
    pub at: usize,
    /// The last validation error, shown under the form.
    pub error: Option<String>,
}

/// What a key press did to a form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Still editing.
    Editing,
    /// Esc: closed, nothing run.
    Cancelled,
    /// Submitted and valid: the command to confirm and run.
    Command(Vec<String>),
}

impl FormState {
    /// The add-key form, with `product` and `env` preset from the screen it was opened on.
    pub fn add_key(envs: Vec<String>, product: Option<String>, env: Option<String>) -> Self {
        let environments = env.into_iter().collect();
        FormState {
            form: Form::AddKey(AddKeyForm {
                product,
                key: String::new(),
                kind: KindChoice::Secret,
                environments,
                guidance: String::new(),
                personal: false,
                allow_same_value: false,
            }),
            envs,
            at: 0,
            error: None,
        }
        .start()
    }

    /// The add-environment form.
    pub fn add_env(envs: Vec<String>) -> Self {
        FormState {
            form: Form::AddEnv(AddEnvForm {
                name: String::new(),
            }),
            envs,
            at: 0,
            error: None,
        }
    }

    /// Put the cursor on the first row that needs typing.
    fn start(mut self) -> Self {
        let rows = self.rows();
        self.at = rows.iter().position(|r| *r == Row::Key).unwrap_or(0);
        self
    }

    /// The rows of the open form, in order.
    pub fn rows(&self) -> Vec<Row> {
        match &self.form {
            Form::AddKey(_) => {
                let mut v = Vec::new();
                v.extend([Row::Product, Row::Key, Row::Kind]);
                v.extend((0..self.envs.len()).map(Row::Env));
                v.extend([Row::Guidance, Row::Personal, Row::AllowSame]);
                v
            }
            Form::AddEnv(_) => vec![Row::EnvName],
        }
    }

    /// The text a row types into, if it is a text row.
    fn text_mut(&mut self, row: Row) -> Option<&mut String> {
        match (&mut self.form, row) {
            (Form::AddKey(f), Row::Product) => Some(f.product.get_or_insert_with(String::new)),
            (Form::AddKey(f), Row::Key) => Some(&mut f.key),
            (Form::AddKey(f), Row::Guidance) => Some(&mut f.guidance),
            (Form::AddEnv(f), Row::EnvName) => Some(&mut f.name),
            _ => None,
        }
    }

    /// Flip a choice row (kind, an environment, personal, allow_same_value).
    fn flip(&mut self, row: Row) {
        let envs = self.envs.clone();
        let Form::AddKey(f) = &mut self.form else {
            return;
        };
        match row {
            Row::Kind => {
                f.kind = match f.kind {
                    KindChoice::Secret => KindChoice::Config,
                    KindChoice::Config => KindChoice::Secret,
                }
            }
            Row::Env(i) => {
                if let Some(e) = envs.get(i) {
                    if let Some(pos) = f.environments.iter().position(|x| x == e) {
                        f.environments.remove(pos);
                    } else {
                        f.environments.push(e.clone());
                        // Keep the configuration's order.
                        f.environments.sort_by_key(|x| {
                            envs.iter().position(|y| y == x).unwrap_or(usize::MAX)
                        });
                    }
                }
            }
            Row::Personal => f.personal = !f.personal,
            Row::AllowSame => f.allow_same_value = !f.allow_same_value,
            _ => {}
        }
    }

    /// The command this form builds, or why it cannot yet.
    pub fn command(&self) -> Result<Vec<String>, String> {
        match &self.form {
            Form::AddKey(f) => {
                let mut f = f.clone();
                if f.product.as_deref().is_some_and(str::is_empty) {
                    f.product = None;
                }
                add_key_command(&f).map(propose_key)
            }
            Form::AddEnv(f) => add_env_command(f, &self.envs),
        }
    }

    /// Handle one key: move (↑↓, tab), type into a text row, flip a choice (space), submit
    /// (enter), cancel (esc).
    pub fn handle(&mut self, key: Key) -> Outcome {
        let rows = self.rows();
        let row = rows.get(self.at).copied();
        match key {
            Key::Esc | Key::Interrupt => return Outcome::Cancelled,
            Key::Up => self.at = self.at.saturating_sub(1),
            Key::Down | Key::Tab => self.at = (self.at + 1).min(rows.len().saturating_sub(1)),
            Key::Enter => match self.command() {
                Ok(c) => return Outcome::Command(c),
                Err(e) => self.error = Some(e),
            },
            Key::Backspace => {
                if let Some(t) = row.and_then(|r| self.text_mut(r)) {
                    t.pop();
                }
            }
            Key::Char(' ') if row.is_some_and(|r| self.is_choice(r)) => {
                self.flip(row.expect("checked"));
            }
            Key::Char(c) => {
                if let Some(t) = row.and_then(|r| self.text_mut(r)) {
                    t.push(c);
                }
            }
            Key::Left | Key::Right => {
                if let Some(r) = row.filter(|r| self.is_choice(*r)) {
                    self.flip(r);
                }
            }
        }
        Outcome::Editing
    }

    fn is_choice(&self, row: Row) -> bool {
        matches!(
            row,
            Row::Kind | Row::Env(_) | Row::Personal | Row::AllowSame
        )
    }

    /// One line per row for drawing: (label, current text, selected).
    pub fn lines(&self) -> Vec<(String, String, bool)> {
        let check = |b: bool| if b { "[x]" } else { "[ ]" };
        self.rows()
            .into_iter()
            .enumerate()
            .map(|(i, r)| {
                let (label, text) = match (&self.form, r) {
                    (Form::AddKey(f), Row::Product) => {
                        ("product".to_string(), f.product.clone().unwrap_or_default())
                    }
                    (Form::AddKey(f), Row::Key) => ("key".into(), f.key.clone()),
                    (Form::AddKey(f), Row::Kind) => (
                        "kind".into(),
                        match f.kind {
                            KindChoice::Secret => "secret (concealed)".into(),
                            KindChoice::Config => "config (text)".into(),
                        },
                    ),
                    (Form::AddKey(f), Row::Env(n)) => {
                        let e = self.envs.get(n).cloned().unwrap_or_default();
                        let on = f.environments.contains(&e);
                        (
                            if n == 0 { "environments" } else { "" }.to_string(),
                            format!("{} {e}", check(on)),
                        )
                    }
                    (Form::AddKey(f), Row::Guidance) => ("guidance".into(), f.guidance.clone()),
                    (Form::AddKey(f), Row::Personal) => (
                        "personal".into(),
                        format!("{} each person's own value (local only)", check(f.personal)),
                    ),
                    (Form::AddKey(f), Row::AllowSame) => (
                        "same value".into(),
                        format!(
                            "{} intended in several environments",
                            check(f.allow_same_value)
                        ),
                    ),
                    (Form::AddEnv(f), Row::EnvName) => ("name".into(), f.name.clone()),
                    _ => (String::new(), String::new()),
                };
                (label, text, i == self.at)
            })
            .collect()
    }

    /// The form's title.
    pub fn title(&self) -> &'static str {
        match self.form {
            Form::AddKey(_) => "Declare a key",
            Form::AddEnv(_) => "Add an environment",
        }
    }
}

/// The `opv propose key <[p/]KEY> … --write` command the add-key form runs: the key form's
/// flags, under the one 0.12.0 interface (Part V, `ui-remap`). `--write` commits the
/// contract diff; the UI then runs `opv apply` (see [`super::run`]).
fn propose_key(add: Vec<String>) -> Vec<String> {
    // `add_key_command` returns ["add", label, flags…]; keep everything after `add`.
    let mut out = vec!["propose".to_string(), "key".to_string()];
    out.extend(add.into_iter().skip(1));
    out.push("--write".to_string());
    out
}

#[cfg(test)]
#[path = "forms_tests.rs"]
mod tests;
