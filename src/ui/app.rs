//! The state of `opv ui` and what each key does (#82). Pure: a key goes in, the new state and
//! at most one [`Effect`] come out, so every interaction is testable without a terminal.
//! Every action that changes something is an `opv` command shown in full before it runs, and
//! a write always passes through a plan and an explicit confirmation (typing the environment
//! name for a guarded one).

use super::model::Snapshot;

/// Which screen the main pane shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    Overview,
    Shared,
    /// One environment's products and keys.
    Env(String),
    /// One product's keys × environments.
    Product(String),
    /// One key: where it lands, why it is blocked, its actions.
    Key {
        product: String,
        key: String,
    },
    Accounts,
    /// What opv last wrote to an environment's target (#95), from `opv history --json`.
    History(String),
    /// Who can read each environment's vault (#96), from `opv access --json`.
    Access,
    /// The adoption review (#94): what `opv adopt <env> --from <from>` found, per key.
    Adopt {
        env: String,
        from: String,
    },
}

/// One sidebar entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nav {
    Overview,
    Shared,
    /// Who can read each environment's vault (#96).
    Access,
    Env(String),
    Product(String),
}

/// A question over the main pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
    /// Run `command` once confirmed. `lines` say what it changes (a plan, names only);
    /// `guard` is the text to type first (a guarded environment's name).
    Confirm {
        title: String,
        lines: Vec<String>,
        command: Vec<String>,
        guard: Option<String>,
        typed: String,
    },
    /// A configuration form (#97): declare a key or add an environment.
    Form(super::forms::FormState),
    /// Ask for one line (an adoption file path), then build the command from it.
    Input {
        prompt: String,
        value: String,
        env: String,
    },
}

/// What the event loop does after a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    None,
    Quit,
    /// Read every document again.
    Refresh,
    /// Run `opv <args>` with `--json` and open the sync confirmation with its plan.
    Plan {
        env: String,
    },
    /// Run `opv <args>` in the person's terminal (prompts and output as on the CLI), then
    /// refresh.
    Run(Vec<String>),
    /// Read `opv account list --json` for the accounts screen.
    LoadAccounts,
    /// Read `opv history <env> --json` for the history screen (#95).
    LoadHistory(String),
    /// Read `opv access --json` for the access screen (#96).
    LoadAccess,
    /// Read `opv adopt <env> --from <from> --json` and open the adoption review (#94).
    AdoptPlan {
        env: String,
        from: String,
    },
}

/// A key, independent of the terminal library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Left,
    Right,
    Enter,
    Esc,
    Tab,
    Backspace,
    Char(char),
    /// Ctrl-C: leave `opv ui` from anywhere (nothing is written).
    Interrupt,
}

/// The whole UI state.
pub struct App {
    pub snap: Snapshot,
    pub screen: Screen,
    /// Previous screens, for `Esc`.
    pub back: Vec<Screen>,
    pub nav: Vec<Nav>,
    pub nav_at: usize,
    /// The selected row of the main pane.
    pub row: usize,
    /// True while the sidebar has the focus.
    pub in_nav: bool,
    pub modal: Option<Modal>,
    /// One line for the person: the last command, what `c` copied, a problem.
    pub status: String,
    /// `opv account list --json`, once loaded, or why it could not be.
    pub accounts: Option<Loaded<super::docs::AccountsDoc>>,
    /// The adoption review's rows and decisions (#94).
    pub adopt: Vec<super::adopt_review::ReviewRow>,
    /// `opv history <env> --json`, once loaded (#95), or why it could not be.
    pub history: Option<Loaded<super::docs::HistoryDoc>>,
    /// `opv access --json`, once loaded (#96), or why it could not be.
    pub access: Option<Loaded<super::docs::AccessDoc>>,
}

/// A document a screen shows, or the error that stopped it, with its steps (07.02).
pub type Loaded<T> = Result<T, super::docs::Failure>;

impl App {
    pub fn new(snap: Snapshot) -> App {
        let mut app = App {
            snap,
            screen: Screen::Overview,
            back: Vec::new(),
            nav: Vec::new(),
            nav_at: 0,
            row: 0,
            in_nav: true,
            modal: None,
            status: String::new(),
            accounts: None,
            adopt: Vec::new(),
            history: None,
            access: None,
        };
        app.rebuild_nav();
        app
    }

    /// Replace the snapshot (after a refresh), keeping the screen.
    pub fn refreshed(&mut self, snap: Snapshot) {
        self.snap = snap;
        self.rebuild_nav();
        self.nav_at = self.nav_at.min(self.nav.len().saturating_sub(1));
    }

    fn rebuild_nav(&mut self) {
        let mut nav = vec![Nav::Overview, Nav::Shared, Nav::Access];
        nav.extend(self.snap.envs.iter().map(|e| Nav::Env(e.key.clone())));
        nav.extend(
            self.snap
                .product_names()
                .into_iter()
                .map(|p| Nav::Product(p.to_string())),
        );
        self.nav = nav;
    }

    pub(crate) fn open(&mut self, screen: Screen) {
        if self.screen != screen {
            self.back.push(std::mem::replace(&mut self.screen, screen));
        }
        self.row = 0;
    }

    /// The rows the main pane lists, for selection: keys of a product or environment.
    pub fn main_rows(&self) -> Vec<(String, String)> {
        match &self.screen {
            Screen::Product(p) => self
                .snap
                .products
                .iter()
                .filter(|x| &x.name == p)
                .flat_map(|x| x.keys.iter().map(|k| (x.name.clone(), k.name.clone())))
                .collect(),
            Screen::Env(e) => self
                .snap
                .products
                .iter()
                .flat_map(|p| {
                    p.keys
                        .iter()
                        .filter(|k| k.environments.contains(e))
                        .map(|k| (p.name.clone(), k.name.clone()))
                })
                .collect(),
            Screen::Shared => self
                .snap
                .products
                .iter()
                .filter(|p| p.source_only)
                .flat_map(|p| p.keys.iter().map(|k| (p.name.clone(), k.name.clone())))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The environment the current screen is about, when there is one.
    pub fn current_env(&self) -> Option<String> {
        match &self.screen {
            Screen::Env(e) => Some(e.clone()),
            _ => match self.nav.get(self.nav_at) {
                Some(Nav::Env(e)) if self.in_nav => Some(e.clone()),
                _ => None,
            },
        }
    }

    /// Handle one key.
    pub fn handle(&mut self, key: Key) -> Effect {
        if key == Key::Interrupt {
            return Effect::Quit;
        }
        if self.modal.is_some() {
            return self.handle_modal(key);
        }
        if let Screen::Adopt { env, from } = &self.screen
            && !self.in_nav
            && let Some(effect) = self.handle_adopt(key, env.clone(), from.clone())
        {
            return effect;
        }
        match key {
            Key::Char('q') => return Effect::Quit,
            Key::Char('r') => return Effect::Refresh,
            Key::Tab | Key::Left | Key::Right => self.in_nav = !self.in_nav,
            Key::Up if self.in_nav => self.nav_at = self.nav_at.saturating_sub(1),
            Key::Down if self.in_nav => {
                self.nav_at = (self.nav_at + 1).min(self.nav.len().saturating_sub(1))
            }
            Key::Up => self.row = self.row.saturating_sub(1),
            Key::Down => self.row = (self.row + 1).min(self.main_rows().len().saturating_sub(1)),
            Key::Enter if self.in_nav => {
                let screen = match self.nav.get(self.nav_at) {
                    Some(Nav::Overview) => Screen::Overview,
                    Some(Nav::Shared) => Screen::Shared,
                    Some(Nav::Access) => {
                        self.open(Screen::Access);
                        self.in_nav = false;
                        self.access = None;
                        return Effect::LoadAccess;
                    }
                    Some(Nav::Env(e)) => Screen::Env(e.clone()),
                    Some(Nav::Product(p)) => Screen::Product(p.clone()),
                    None => return Effect::None,
                };
                self.open(screen);
                self.in_nav = false;
            }
            Key::Enter => {
                if let Some((product, key)) = self.main_rows().get(self.row).cloned() {
                    self.open(Screen::Key { product, key });
                }
            }
            Key::Esc => {
                if let Some(prev) = self.back.pop() {
                    self.screen = prev;
                    self.row = 0;
                }
            }
            Key::Char('a') => {
                self.open(Screen::Accounts);
                return Effect::LoadAccounts;
            }
            Key::Char('s') => {
                if let Some(env) = self.current_env() {
                    if self.snap.env(&env).is_some_and(|e| e.deployed()) {
                        return Effect::Plan { env };
                    }
                    self.status = format!(
                        "{env} is local only: nothing to sync (opv run {env} -- <command>)"
                    );
                }
            }
            Key::Char('i') => {
                if let Some(env) = self.current_env() {
                    self.modal = Some(Modal::Input {
                        prompt: format!("Adopt existing values into {env} from which file?"),
                        value: String::new(),
                        env,
                    });
                }
            }
            Key::Char('o') => {
                if let Screen::Key { product, key } = &self.screen {
                    return Effect::Run(self.open_command(product, key));
                }
            }
            Key::Char('n') => {
                if let Some((actor, command)) = self.snap.next.clone() {
                    match command.strip_prefix("opv ") {
                        Some(rest) => {
                            self.modal = Some(Modal::Confirm {
                                title: format!("Next step ({actor})"),
                                lines: vec![format!("runs: {command}")],
                                command: split(rest),
                                guard: None,
                                typed: String::new(),
                            })
                        }
                        None => self.status = format!("next ({actor}): {command}"),
                    }
                }
            }
            Key::Char('+') => {
                let envs: Vec<String> = self.snap.envs.iter().map(|e| e.key.clone()).collect();
                let product = match &self.screen {
                    Screen::Product(p) => Some(p.clone()),
                    Screen::Key { product, .. } => Some(product.clone()),
                    _ => None,
                };
                let env = match &self.screen {
                    Screen::Env(e) => Some(e.clone()),
                    _ => None,
                };
                self.modal = Some(Modal::Form(super::forms::FormState::add_key(
                    envs, product, env,
                )));
            }
            Key::Char('h') => {
                if let Some(env) = self.current_env() {
                    if self.snap.env(&env).is_some_and(|e| e.deployed()) {
                        self.history = None;
                        self.open(Screen::History(env.clone()));
                        return Effect::LoadHistory(env);
                    }
                    self.status =
                        format!("{env} has no target: opv writes nothing outside 1Password for it");
                }
            }
            Key::Char('E') => {
                let envs = self.snap.envs.iter().map(|e| e.key.clone()).collect();
                self.modal = Some(Modal::Form(super::forms::FormState::add_env(envs)));
            }
            Key::Char('e') => {
                self.modal = Some(Modal::Confirm {
                    title: "Edit the configuration".into(),
                    lines: vec![
                        "opens it in $VISUAL/$EDITOR, validates it and shows the diff before \
                         saving; refuses when someone changed it meanwhile"
                            .into(),
                        "runs: opv config edit".into(),
                    ],
                    command: vec!["config".into(), "edit".into()],
                    guard: None,
                    typed: String::new(),
                });
            }
            Key::Char('c') => {
                self.status = match &self.snap.next {
                    Some((_, c)) => format!("command: {c}"),
                    None => "nothing to copy".into(),
                };
            }
            _ => {}
        }
        Effect::None
    }

    /// Open the adoption review from `opv adopt <env> --from <from> --json` (#94).
    pub fn open_adopt(&mut self, env: &str, from: &str, doc: &super::docs::AdoptDoc) {
        let snap = &self.snap;
        let immutable = |p: &str, k: &str| {
            snap.products
                .iter()
                .find(|x| x.name == p)
                .and_then(|x| x.keys.iter().find(|y| y.name == k))
                .is_some_and(|y| y.immutable)
        };
        let label = |p: &str, k: &str| self.label(p, k);
        self.adopt = super::adopt_review::rows_from(doc, &label, &immutable);
        self.open(Screen::Adopt {
            env: env.to_string(),
            from: from.to_string(),
        });
        self.in_nav = false;
    }

    /// Keys of the adoption review: move, change the selected key's decision, apply. `None`
    /// for a key the review does not use (handled as everywhere else).
    fn handle_adopt(&mut self, key: Key, env: String, from: String) -> Option<Effect> {
        use super::adopt_review::{command, toggle, writes};
        match key {
            Key::Up => self.row = self.row.saturating_sub(1),
            Key::Down => self.row = (self.row + 1).min(self.adopt.len().saturating_sub(1)),
            Key::Enter | Key::Char(' ') => {
                if let Some(row) = self.adopt.get_mut(self.row) {
                    row.decision = toggle(row);
                }
            }
            Key::Char('y') => {
                let n = writes(&self.adopt);
                if n == 0 {
                    self.status = "nothing to write: every key is kept or skipped".into();
                    return Some(Effect::None);
                }
                let args = command(&env, &from, &self.adopt);
                let guarded = self.snap.env(&env).is_some_and(|e| e.guarded);
                self.modal = Some(Modal::Confirm {
                    title: format!("Adopt into {env}"),
                    lines: vec![
                        format!(
                            "writes {n} field(s) in 1Password, read back and verified; a replaced value is kept in opv · kept"
                        ),
                        "never syncs or deploys; your apps keep their secrets until you sync"
                            .into(),
                        format!("runs: {}", command_line(&args)),
                    ],
                    command: args,
                    guard: guarded.then(|| env.clone()),
                    typed: String::new(),
                });
            }
            _ => return None,
        }
        Some(Effect::None)
    }

    /// `product/KEY`.
    pub fn label(&self, product: &str, key: &str) -> String {
        crate::domain::key_label(product, key)
    }

    /// What `o` runs on the key screen of `product/key`: `opv open` in the first
    /// environment the key is declared for.
    pub fn open_command(&self, product: &str, key: &str) -> Vec<String> {
        let mut cmd = vec!["open".to_string(), self.label(product, key)];
        if let Some(e) = self.key_env(product, key) {
            cmd.push("--env".into());
            cmd.push(e);
        }
        cmd
    }

    /// The first environment `product/key` is declared for.
    fn key_env(&self, product: &str, key: &str) -> Option<String> {
        self.snap
            .products
            .iter()
            .find(|p| p.name == product)
            .and_then(|p| p.keys.iter().find(|k| k.name == key))
            .and_then(|k| k.environments.first().cloned())
    }

    /// The sync confirmation for `env`, from `opv plan <env> --json`.
    pub fn confirm_sync(&mut self, env: &str, plan: &super::docs::RowsDoc) {
        let id = plan.plan_id.clone();
        let mut lines = Vec::new();
        lines.push(if plan.stage.is_empty() {
            "writes nothing".to_string()
        } else {
            format!("writes: {}", plan.stage.join(", "))
        });
        if !plan.prune.is_empty() {
            lines.push(format!(
                "would prune (not done here): {}",
                plan.prune.join(", ")
            ));
        }
        let findings = plan.totals.findings;
        if findings > 0 {
            lines.push(format!(
                "{findings} finding(s) block this sync: fix them first (see the overview)"
            ));
        }
        let mut command = vec!["sync".to_string(), env.to_string()];
        match &id {
            Some(id) => {
                command.push("--expect-plan".into());
                command.push(id.clone());
                lines.push(format!(
                    "plan {id}: exactly this plan, or nothing is written"
                ));
            }
            None => lines.push("no plan id: the plan has findings".into()),
        }
        let guarded = self.snap.env(env).is_some_and(|e| e.guarded);
        let blocked = findings > 0 || id.is_none();
        if !blocked {
            lines.push(format!("runs: {}", command_line(&command)));
        }
        self.modal = Some(Modal::Confirm {
            title: format!(
                "Sync {}",
                self.snap.env(env).map_or(env, |e| e.title.as_str())
            ),
            lines,
            command,
            guard: guarded.then(|| env.to_string()),
            typed: String::new(),
        });
        if blocked {
            // Nothing can be applied: the confirmation only explains why.
            if let Some(Modal::Confirm { command, .. }) = &mut self.modal {
                command.clear();
            }
        }
    }

    fn handle_modal(&mut self, key: Key) -> Effect {
        let Some(modal) = self.modal.as_mut() else {
            return Effect::None;
        };
        if let Modal::Form(form) = modal {
            match form.handle(key) {
                super::forms::Outcome::Editing => {}
                super::forms::Outcome::Cancelled => {
                    self.modal = None;
                    self.status = "cancelled; nothing was changed".into();
                }
                super::forms::Outcome::Command(command) => {
                    let what = form.title();
                    let effect = if command.iter().any(|w| w == "--add-env") {
                        // `opv init <env> --add-env` also creates the environment's vault and
                        // item when they are missing (07.25).
                        "adds the environment to the configuration and creates its 1Password \
                         vault and item if they are missing (no value), validated first: a \
                         refused change writes nothing"
                    } else {
                        "edits the configuration (no value), validated first: a refused \
                         change writes nothing"
                    };
                    self.modal = Some(Modal::Confirm {
                        title: what.into(),
                        lines: vec![effect.into(), format!("runs: {}", command_line(&command))],
                        command,
                        guard: None,
                        typed: String::new(),
                    });
                }
            }
            return Effect::None;
        }
        match (modal, key) {
            (_, Key::Esc) => {
                self.modal = None;
                self.status = "cancelled; nothing was changed".into();
            }
            (Modal::Confirm { typed, .. }, Key::Char(ch)) => typed.push(ch),
            (Modal::Confirm { typed, .. }, Key::Backspace) => {
                typed.pop();
            }
            (
                Modal::Confirm {
                    command,
                    guard,
                    typed,
                    ..
                },
                Key::Enter,
            ) => {
                if command.is_empty() {
                    self.modal = None;
                    return Effect::None;
                }
                if guard.as_ref().is_some_and(|g| g != typed) {
                    self.status = "type the environment's name to confirm".into();
                    return Effect::None;
                }
                let command = command.clone();
                self.modal = None;
                return Effect::Run(command);
            }
            (Modal::Input { value, .. }, Key::Char(ch)) => value.push(ch),
            (Modal::Input { value, .. }, Key::Backspace) => {
                value.pop();
            }
            (Modal::Input { value, env, .. }, Key::Enter) => {
                let (from, env) = (value.trim().to_string(), env.clone());
                self.modal = None;
                if from.is_empty() {
                    self.status = "no file given; nothing was read".into();
                    return Effect::None;
                }
                // Read-only: the review shows what would come in; nothing is written yet.
                return Effect::AdoptPlan { env, from };
            }
            _ => {}
        }
        Effect::None
    }
}

/// `opv <args>` as one line a person can paste into a shell: a word with a space, quote or
/// other shell character is single-quoted.
pub fn command_line(args: &[String]) -> String {
    let mut line = String::from("opv");
    for a in args {
        line.push(' ');
        let plain = !a.is_empty()
            && a.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_./:,=@%+".contains(c));
        if plain {
            line.push_str(a);
        } else {
            line.push('\'');
            line.push_str(&a.replace('\'', "'\\''"));
            line.push('\'');
        }
    }
    line
}

/// A command line into words (opv's `next` commands quote nothing that needs a shell).
fn split(s: &str) -> Vec<String> {
    s.split_whitespace().map(str::to_string).collect()
}

#[cfg(test)]
#[path = "app_tests.rs"]
mod tests;
