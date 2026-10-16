//! `opv login` (FR-40): which account, the signed-in child and its exit code.

use std::cell::RefCell;
use std::collections::VecDeque;

use super::*;
use crate::app::setup::SessionCheck;
use crate::cause::AccountId;
use crate::config;
use crate::domain::SecretValue;
use crate::runner::Output;

/// A fake `op`, answering by command: `--version` 2.40.0; `vault list` from `vault_lists`
/// (then success); `account list` one account; the session check for an account from
/// `sessions` (then signed in).
struct Fake {
    vault_lists: RefCell<VecDeque<Output>>,
    sessions: RefCell<VecDeque<SessionCheck>>,
    checked: RefCell<Vec<String>>,
    account: Option<String>,
    sign_ins: Vec<Option<String>>,
    added: Vec<Option<String>>,
    shorthands: Vec<String>,
    child_code: i32,
    children: RefCell<Vec<Vec<String>>>,
}

impl Fake {
    fn signed_in(child_code: i32) -> Self {
        Self {
            vault_lists: RefCell::default(),
            sessions: RefCell::default(),
            checked: RefCell::default(),
            account: None,
            sign_ins: Vec::new(),
            added: Vec::new(),
            shorthands: Vec::new(),
            child_code,
            children: RefCell::default(),
        }
    }

    /// No session for the account asked for; signed in after op's prompt.
    fn signed_out() -> Self {
        Self::with_sessions([SessionCheck::NotSignedIn])
    }

    /// The session checks answer `sessions` in turn, then signed in.
    fn with_sessions(sessions: impl IntoIterator<Item = SessionCheck>) -> Self {
        let f = Self::signed_in(0);
        *f.sessions.borrow_mut() = sessions.into_iter().collect();
        f
    }
}

impl Backend for Fake {
    fn native(&self) -> Result<(), Error> {
        Ok(())
    }
    fn call(&self, args: &[&str], _stdin: Option<&[u8]>) -> Result<Output, Error> {
        Ok(match args.first() {
            Some(&"--version") => Output::success(b"2.40.0".to_vec()),
            Some(&"vault") => self
                .vault_lists
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Output::success(b"[]".to_vec())),
            Some(&"account") => Output::success(br#"[{"url":"x"}]"#.to_vec()),
            _ => panic!("unexpected op call {args:?}"),
        })
    }
    fn session_for(&self, account: &str) -> SessionCheck {
        self.checked.borrow_mut().push(account.to_string());
        self.sessions
            .borrow_mut()
            .pop_front()
            .unwrap_or(SessionCheck::SignedIn)
    }
    fn current_account(&self) -> Option<String> {
        self.account.clone()
    }
    fn sign_in(&mut self, account: Option<&str>, _add: bool) -> Result<(), Error> {
        self.sign_ins.push(account.map(str::to_owned));
        Ok(())
    }
    fn use_account(&mut self, account: Option<&str>) {
        self.account = account.map(str::to_owned);
    }
    fn account_label(&self, account: &str) -> String {
        if account == "ALABS000000000000000000001" {
            "me@labs.example".to_string()
        } else {
            account.to_string()
        }
    }
    fn add_account(&mut self, email: Option<&str>, shorthand: &str) -> Result<(), Error> {
        self.added.push(email.map(str::to_owned));
        self.shorthands.push(shorthand.to_owned());
        Ok(())
    }
    fn child(&self, command: &[String]) -> Result<i32, Error> {
        self.children.borrow_mut().push(command.to_vec());
        Ok(self.child_code)
    }
}

#[derive(Default)]
struct Ui {
    shown: Vec<String>,
    asked: Vec<Vec<String>>,
    prompts: Vec<String>,
    pick: usize,
}

impl Interaction for Ui {
    fn show(&mut self, m: &str) -> Result<(), Error> {
        self.shown.push(m.into());
        Ok(())
    }
    fn confirm(&mut self, _: &str) -> Result<bool, Error> {
        panic!("login never asks to confirm")
    }
    fn secret(&mut self, _: &str) -> Result<SecretValue, Error> {
        panic!("login never reads a secret")
    }
    fn choose(&mut self, prompt: &str, choices: &[String]) -> Result<String, Error> {
        self.prompts.push(prompt.to_string());
        self.asked.push(choices.to_vec());
        Ok(choices[self.pick].clone())
    }
}

fn fleet(dev_account: Option<&str>, prod_account: Option<&str>) -> Fleet {
    let line = |a: Option<&str>| a.map_or(String::new(), |a| format!("account = \"{a}\"\n"));
    config::parse(&format!(
        "[environments.dev]\n{}[environments.prod]\n{}",
        line(dev_account),
        line(prod_account)
    ))
    .unwrap()
}

fn cmd(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

#[test]
fn login_with_an_environment_uses_its_account() {
    let f = fleet(Some("home.1password.com"), Some("work.1password.com"));
    let mut b = Fake::signed_in(0);
    run(Some(&f), Some("prod"), &[], &mut b, &mut Ui::default()).unwrap();
    assert_eq!(b.account.as_deref(), Some("work.1password.com"));
}

#[test]
fn login_signs_in_to_the_environment_account_when_signed_out() {
    let f = fleet(None, Some("work.1password.com"));
    let mut b = Fake::signed_out();
    run(Some(&f), Some("prod"), &[], &mut b, &mut Ui::default()).unwrap();
    assert_eq!(b.sign_ins, vec![Some("work.1password.com".to_string())]);
}

#[test]
fn login_without_an_environment_uses_the_shared_account() {
    let f = fleet(Some("work.1password.com"), Some("work.1password.com"));
    let mut b = Fake::signed_in(0);
    run(Some(&f), None, &[], &mut b, &mut Ui::default()).unwrap();
    assert_eq!(b.account.as_deref(), Some("work.1password.com"));
}

#[test]
fn login_without_configuration_uses_the_default_account() {
    let mut b = Fake::signed_in(0);
    run(None, None, &[], &mut b, &mut Ui::default()).unwrap();
    assert_eq!(b.account, None);
}

#[test]
fn login_without_an_environment_asks_when_accounts_differ() {
    let f = fleet(Some("home.1password.com"), Some("work.1password.com"));
    let mut ui = Ui::default();
    account(Some(&f), None, &mut ui).unwrap();
    assert_eq!(
        ui.asked,
        vec![vec![
            "dev (home.1password.com)".to_string(),
            "prod (work.1password.com)".to_string()
        ]]
    );
}

#[test]
fn login_uses_the_account_of_the_chosen_environment() {
    let f = fleet(Some("home.1password.com"), Some("work.1password.com"));
    let mut ui = Ui {
        pick: 1,
        ..Ui::default()
    };
    let got = account(Some(&f), None, &mut ui).unwrap();
    assert_eq!(got.as_deref(), Some("work.1password.com"));
}

#[test]
fn login_command_exit_code_is_passed_through() {
    let f = fleet(None, None);
    let mut b = Fake::signed_in(42);
    let code = run(
        Some(&f),
        Some("dev"),
        &cmd(&["opv", "check", "dev"]),
        &mut b,
        &mut Ui::default(),
    )
    .unwrap();
    assert_eq!(code, 42);
}

#[test]
fn login_without_a_command_opens_a_terminal() {
    let f = fleet(None, None);
    let mut b = Fake::signed_in(0);
    run(Some(&f), Some("dev"), &[], &mut b, &mut Ui::default()).unwrap();
    assert_eq!(*b.children.borrow(), vec![Vec::<String>::new()]);
}

#[test]
fn login_to_an_unknown_environment_is_a_configuration_error() {
    let f = fleet(None, None);
    let e = run(
        Some(&f),
        Some("qa"),
        &[],
        &mut Fake::signed_in(0),
        &mut Ui::default(),
    )
    .unwrap_err();
    assert_eq!(e.exit_code(), 2);
}

// --- choosing the project's account in one command (found in a fresh-account run-through)

const ONE: &str = r#"[{"url":"my.1password.com","email":"me@family.example","account_uuid":"AFAMILY0000000000000000001"}]"#;
const BOTH: &str = r#"[{"url":"my.1password.com","email":"me@family.example","account_uuid":"AFAMILY0000000000000000001"},{"url":"my.1password.com","email":"me@labs.example","account_uuid":"ALABS000000000000000000001"}]"#;

fn lists(replies: &[&str]) -> crate::runner::fake::FakeRunner {
    crate::runner::fake::FakeRunner::new(replies.iter().map(|j| Output::success(j.to_string())))
}

fn wsl() -> crate::host::Host {
    crate::host::Host::from_env(&crate::host::FakeEnv::new("linux").var("WSL_DISTRO_NAME"))
}

/// An email op does not know yet is added at op's prompts, inside opv login.
#[test]
fn an_unknown_email_is_added_by_login_itself() {
    let dir = tempfile::tempdir().unwrap();
    let mut b = Fake::signed_in(0);
    crate::host::with_test_host(wsl(), || {
        choose_account(
            &lists(&[ONE, BOTH]),
            Some("me@labs.example"),
            false,
            dir.path(),
            &mut b,
            &mut Ui::default(),
        )
        .unwrap()
    });
    assert_eq!(b.added, [Some("me@labs.example".to_string())]);
}

#[test]
fn the_added_account_is_recorded_for_the_project() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".git")).unwrap();
    let mut b = Fake::signed_in(0);
    crate::host::with_test_host(wsl(), || {
        choose_account(
            &lists(&[ONE, BOTH]),
            Some("me@labs.example"),
            false,
            dir.path(),
            &mut b,
            &mut Ui::default(),
        )
        .unwrap()
    });
    assert_eq!(
        crate::config_store::pointer_account(dir.path()).as_deref(),
        Some("ALABS000000000000000000001")
    );
}

/// Several accounts and none chosen: a menu, with "add another" where op keeps its own.
#[test]
fn several_accounts_offer_a_menu_with_add_another() {
    let dir = tempfile::tempdir().unwrap();
    let mut ui = Ui::default();
    crate::host::with_test_host(wsl(), || {
        choose_account(
            &lists(&[BOTH]),
            None,
            false,
            dir.path(),
            &mut Fake::signed_in(0),
            &mut ui,
        )
        .unwrap()
    });
    assert_eq!(
        ui.asked[0],
        [
            "me@family.example (my.1password.com)",
            "me@labs.example (my.1password.com)",
            "Add another 1Password account"
        ]
    );
}

// --- a second account at the same sign-in address (found live: personal and business
// accounts are both at my.1password.com, and op names each one `my` unless told otherwise)

const MY: &str = r#"[{"url":"my.1password.com","email":"me@family.example","account_uuid":"AFAMILY0000000000000000001","shorthand":"my"}]"#;
const MY_AND_LABS: &str = r#"[{"url":"my.1password.com","email":"me@family.example","account_uuid":"AFAMILY0000000000000000001","shorthand":"my"},{"url":"my.1password.com","email":"me@labs.example","account_uuid":"ALABS000000000000000000001","shorthand":"labs"}]"#;

#[test]
fn an_added_account_is_named_after_its_email_domain() {
    let dir = tempfile::tempdir().unwrap();
    let mut b = Fake::signed_in(0);
    crate::host::with_test_host(wsl(), || {
        choose_account(
            &lists(&[MY, MY_AND_LABS]),
            Some("me@labs.example"),
            false,
            dir.path(),
            &mut b,
            &mut Ui::default(),
        )
        .unwrap()
    });
    assert_eq!(b.shorthands, ["labs"]);
}

#[test]
fn an_added_accounts_name_never_repeats_one_already_on_the_machine() {
    let taken: Vec<crate::adapters::onepassword_manifest::Account> =
        serde_json::from_str(MY_AND_LABS).unwrap();
    assert_eq!(free_shorthand(Some("you@labs.example"), &taken), "labs-2");
}

#[test]
fn an_account_added_without_an_email_is_named_account() {
    assert_eq!(free_shorthand(None, &[]), "account");
}

/// Found live: "Signed in to 6AINMAIK…" named the account by an ID no person recognises.
#[test]
fn the_signed_in_message_names_the_account_by_its_email() {
    let mut ui = Ui::default();
    run_or(
        None,
        Some("ALABS000000000000000000001"),
        None,
        &[],
        &mut Fake::signed_in(0),
        &mut ui,
    )
    .unwrap();
    assert!(
        ui.shown
            .iter()
            .any(|m| m.starts_with("Signed in to me@labs.example."))
    );
}

// --- #79: the menu even with one account, add another, WSL (FR-50) ----------------------

fn mac() -> crate::host::Host {
    crate::host::Host::from_env(&crate::host::FakeEnv::new("macos"))
}

/// One account and no choice recorded: still a menu, so the person sees which account it is.
#[test]
fn one_account_still_offers_a_menu_with_add_another() {
    let dir = tempfile::tempdir().unwrap();
    let mut ui = Ui::default();
    crate::host::with_test_host(wsl(), || {
        choose_account(
            &lists(&[ONE]),
            None,
            false,
            dir.path(),
            &mut Fake::signed_in(0),
            &mut ui,
        )
        .unwrap()
    });
    assert_eq!(
        ui.asked[0],
        [
            "me@family.example (my.1password.com)",
            "Add another 1Password account"
        ]
    );
}

#[test]
fn the_wsl_menu_says_the_windows_apps_accounts_are_not_listed() {
    let dir = tempfile::tempdir().unwrap();
    let mut ui = Ui::default();
    crate::host::with_test_host(wsl(), || {
        choose_account(
            &lists(&[ONE]),
            None,
            false,
            dir.path(),
            &mut Fake::signed_in(0),
            &mut ui,
        )
        .unwrap()
    });
    assert!(
        ui.prompts[0].contains("Windows 1Password app"),
        "{}",
        ui.prompts[0]
    );
}

#[test]
fn a_recorded_account_never_shows_a_menu() {
    let dir = tempfile::tempdir().unwrap();
    crate::config_store::record_account(dir.path(), "AFAMILY0000000000000000001").unwrap();
    let mut ui = Ui::default();
    crate::host::with_test_host(wsl(), || {
        choose_account(
            &lists(&[ONE]),
            None,
            false,
            dir.path(),
            &mut Fake::signed_in(0),
            &mut ui,
        )
        .unwrap()
    });
    assert!(ui.asked.is_empty());
}

#[test]
fn login_add_adds_the_named_account_at_ops_prompts() {
    let dir = tempfile::tempdir().unwrap();
    let mut b = Fake::signed_in(0);
    crate::host::with_test_host(wsl(), || {
        choose_account(
            &lists(&[ONE, BOTH]),
            Some("me@labs.example"),
            true,
            dir.path(),
            &mut b,
            &mut Ui::default(),
        )
        .unwrap()
    });
    assert_eq!(b.added, [Some("me@labs.example".to_string())]);
}

/// On macOS op uses the app's accounts: adding one is done in the app, said plainly.
#[test]
fn login_add_where_the_app_holds_the_accounts_explains_where_to_add() {
    let dir = tempfile::tempdir().unwrap();
    let e = crate::host::with_test_host(mac(), || {
        choose_account(
            &lists(&[ONE]),
            None,
            true,
            dir.path(),
            &mut Fake::signed_in(0),
            &mut Ui::default(),
        )
        .unwrap_err()
    });
    assert_eq!(e.code(), crate::error::Code::AccountNotRegistered);
}

fn wsl_windows_op() -> crate::host::Host {
    crate::host::Host::from_env(
        &crate::host::FakeEnv::new("linux")
            .var("WSL_DISTRO_NAME")
            .op_windows_exe(),
    )
}

/// In WSL with the Windows `op.exe`, `opv login --add` sends the person to the Windows app,
/// never to op's own prompt.
#[test]
fn login_add_in_wsl_with_windows_op_directs_to_the_windows_app() {
    let dir = tempfile::tempdir().unwrap();
    let e = crate::host::with_test_host(wsl_windows_op(), || {
        choose_account(
            &lists(&[ONE]),
            None,
            true,
            dir.path(),
            &mut Fake::signed_in(0),
            &mut Ui::default(),
        )
        .unwrap_err()
    });
    assert_eq!(e.code(), crate::error::Code::AccountNotRegistered);
}

/// #160: `op whoami --account <id>` succeeds for the account while `op vault list` fails.
fn signed_in_vault_list_failing() -> Fake {
    let f = Fake::signed_in(0);
    *f.vault_lists.borrow_mut() = [Output::failure(1)].into();
    f
}

#[test]
fn login_runs_no_command_when_the_vault_list_fails_under_a_live_session() {
    let f = fleet(Some(B), None);
    let mut b = signed_in_vault_list_failing();
    let _ = run(
        Some(&f),
        Some("dev"),
        &cmd(&["opv", "access", "dev"]),
        &mut b,
        &mut Ui::default(),
    );
    assert!(b.children.borrow().is_empty());
}

#[test]
fn a_failed_vault_list_under_a_live_session_never_steps_to_login() {
    let f = fleet(Some(B), None);
    let mut b = signed_in_vault_list_failing();
    let e = run(
        Some(&f),
        Some("dev"),
        &cmd(&["opv", "access", "dev"]),
        &mut b,
        &mut Ui::default(),
    )
    .unwrap_err();
    assert_eq!(e.next_step(), Some("opv account list"));
}

/// #157: account_not_registered exits 7 (auth), as its code says.
#[test]
fn an_account_added_in_the_app_is_an_auth_error() {
    let dir = tempfile::tempdir().unwrap();
    let e = crate::host::with_test_host(mac(), || {
        choose_account(
            &lists(&[ONE]),
            None,
            true,
            dir.path(),
            &mut Fake::signed_in(0),
            &mut Ui::default(),
        )
        .unwrap_err()
    });
    assert_eq!(e.exit_code(), e.code().exit_code());
}

/// `opv login` with an `op account list` that fails.
fn login_with_a_failing_account_list(b: &mut Fake) -> Error {
    let dir = tempfile::tempdir().unwrap();
    let r = crate::runner::fake::FakeRunner::new([Output::failure(1)]);
    crate::host::with_test_host(wsl(), || {
        choose_account(&r, None, false, dir.path(), b, &mut Ui::default()).unwrap_err()
    })
}

/// #157: a failed account list never starts adding an account.
#[test]
fn a_failing_account_list_adds_no_account() {
    let mut b = Fake::signed_in(0);
    let _ = login_with_a_failing_account_list(&mut b);
    assert!(b.added.is_empty());
}

#[test]
fn a_failing_account_list_steps_to_doctor() {
    let e = login_with_a_failing_account_list(&mut Fake::signed_in(0));
    assert_eq!(e.next_step(), Some("opv doctor"));
}

// --- #160: the session is checked for the account asked for, by ID ------------------------

/// Account B (recorded case 11's `<ACCOUNT_1>`), asked for while only A holds a session.
const B: &str = "ALABS000000000000000000001";
/// Account A, whose session is live on the same sign-in address.
const A: &str = "AFAMILY0000000000000000001";

/// Recorded case 11: `op whoami --account B` says "no active session found for account B"
/// while plain `op whoami` answers for A.
fn a_live() -> SessionCheck {
    SessionCheck::OtherAccountLive {
        live: AccountId::new(A),
    }
}

/// `opv login --account B` (the account chosen, nothing in the configuration).
fn login_to_b(b: &mut Fake) -> Result<i32, Error> {
    run_or(None, Some(B), None, &[], b, &mut Ui::default())
}

#[test]
fn login_checks_the_session_of_the_account_asked_for() {
    let mut b = Fake::signed_in(0);
    login_to_b(&mut b).unwrap();
    assert_eq!(*b.checked.borrow(), [B]);
}

#[test]
fn a_live_session_for_another_account_prompts_for_the_one_asked_for() {
    let mut b = Fake::with_sessions([a_live()]);
    login_to_b(&mut b).unwrap();
    assert_eq!(b.sign_ins, [Some(B.to_string())]);
}

#[test]
fn a_session_check_that_cannot_tell_prompts_for_the_account() {
    let mut b = Fake::with_sessions([SessionCheck::Undetermined]);
    login_to_b(&mut b).unwrap();
    assert_eq!(b.sign_ins, [Some(B.to_string())]);
}

#[test]
fn a_live_session_for_the_account_asked_for_needs_no_prompt() {
    let mut b = Fake::signed_in(0);
    login_to_b(&mut b).unwrap();
    assert!(b.sign_ins.is_empty());
}

/// The sign-in to B left A's session the only live one.
fn still_other_account() -> Error {
    login_to_b(&mut Fake::with_sessions([a_live(), a_live()])).unwrap_err()
}

#[test]
fn a_failed_check_after_signing_in_is_op_not_signed_in() {
    assert_eq!(
        still_other_account().code(),
        crate::error::Code::OpNotSignedIn
    );
}

#[test]
fn a_failed_check_steps_to_login_with_the_account_id() {
    assert_eq!(
        still_other_account().next_step(),
        Some("opv login --account ALABS000000000000000000001")
    );
}

#[test]
fn a_failed_check_names_the_account_whose_session_is_live() {
    let text = still_other_account().text().to_string();
    assert!(
        text.contains("signed in to account AFAMILY0000000000000000001, not account ALABS"),
        "{text}"
    );
}

#[test]
fn a_failed_check_never_mentions_a_setup_vault() {
    assert!(!still_other_account().text().contains("setup vault"));
}

#[test]
fn a_failed_check_runs_no_command() {
    let mut b = Fake::with_sessions([a_live(), a_live()]);
    let _ = run_or(
        None,
        Some(B),
        None,
        &cmd(&["opv", "check"]),
        &mut b,
        &mut Ui::default(),
    );
    assert!(b.children.borrow().is_empty());
}

// --- #160: no account recorded, the person picks one; never op's default -----------------

#[test]
fn bare_login_with_nothing_recorded_uses_the_account_picked() {
    let dir = tempfile::tempdir().unwrap();
    let mut b = Fake::signed_in(0);
    let mut ui = Ui {
        pick: 1,
        ..Ui::default()
    };
    crate::host::with_test_host(wsl(), || {
        choose_account(&lists(&[BOTH]), None, false, dir.path(), &mut b, &mut ui).unwrap()
    });
    assert_eq!(b.account.as_deref(), Some(B));
}

#[test]
fn the_chosen_account_is_signed_in_when_nothing_else_names_one() {
    let mut b = Fake::signed_out();
    b.use_account(Some(B));
    run_or(None, None, None, &[], &mut b, &mut Ui::default()).unwrap();
    assert_eq!(b.sign_ins, [Some(B.to_string())]);
}

#[test]
fn an_environment_without_an_account_uses_the_recorded_one() {
    let f = fleet(None, None);
    let got = account_or(Some(&f), Some(B), Some("dev"), &mut Ui::default()).unwrap();
    assert_eq!(got.as_deref(), Some(B));
}

#[test]
fn environments_without_accounts_use_the_recorded_one() {
    let f = fleet(None, None);
    let got = account_or(Some(&f), Some(B), None, &mut Ui::default()).unwrap();
    assert_eq!(got.as_deref(), Some(B));
}

// --- #153: a one-off login outside a project records nothing -----------------------------

/// `opv login --account me@labs.example` in a folder with no repository and no `.opv`.
fn login_outside_a_project(b: &mut Fake) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    crate::host::with_test_host(wsl(), || {
        choose_account(
            &lists(&[BOTH]),
            Some("me@labs.example"),
            false,
            dir.path(),
            b,
            &mut Ui::default(),
        )
        .unwrap()
    });
    dir
}

#[test]
fn a_one_off_login_outside_a_project_writes_no_dot_opv() {
    let dir = login_outside_a_project(&mut Fake::signed_in(0));
    assert!(!dir.path().join(".opv").exists());
}

#[test]
fn a_one_off_login_outside_a_project_still_uses_the_account() {
    let mut b = Fake::signed_in(0);
    let _dir = login_outside_a_project(&mut b);
    assert_eq!(b.account.as_deref(), Some(B));
}

// --- the signed-in terminal's banner (recorded case 04) ----------------------------------

#[test]
fn the_banner_says_the_terminal_sets_op_account() {
    assert!(banner(" to me@labs.example", Some(B)).contains("It sets OP_ACCOUNT=ALABS"));
}

#[test]
fn the_banner_says_how_to_sign_out_of_every_account() {
    assert!(banner(" to me@labs.example", Some(B)).contains("env -u OP_ACCOUNT op signout --all"));
}

#[test]
fn the_signed_in_terminal_shows_the_banner() {
    let mut ui = Ui::default();
    run_or(None, Some(B), None, &[], &mut Fake::signed_in(0), &mut ui).unwrap();
    assert!(ui.shown.iter().any(|m| m.contains("op signout --all")));
}

// --- #150: a 1Password write without a person's session ----------------------------------

fn target_add() -> Vec<String> {
    cmd(&["target", "add", "staging", "fleet", "--fly-app", "my app"])
}

#[test]
fn a_write_without_a_session_steps_to_the_same_command_inside_login() {
    let e = write_needs_session("opv target add", Some(B), &target_add());
    assert_eq!(
        e.next_step(),
        Some(
            "opv login --account ALABS000000000000000000001 -- opv target add staging fleet \
             --fly-app 'my app'"
        )
    );
}

/// In a person's terminal, `op_not_signed_in` is what opv answers with 1Password's prompt.
#[test]
fn a_write_without_a_session_is_op_not_signed_in() {
    let e = write_needs_session("opv target add", Some(B), &target_add());
    assert_eq!(e.code(), crate::error::Code::OpNotSignedIn);
}

#[test]
fn a_write_without_a_session_says_an_earlier_sign_in_does_not_carry_over() {
    let e = write_needs_session("opv target add", Some(B), &target_add());
    assert!(e.text().contains("does not carry over"), "{}", e.text());
}

#[test]
fn the_dry_run_says_the_write_needs_a_login_session() {
    let mut dry = target_add();
    dry.push("--dry-run".into());
    assert!(dry_run_session_note(Some(B), &dry).contains(
        "opv login --account ALABS000000000000000000001 -- opv target add staging fleet \
         --fly-app 'my app'"
    ));
}

/// Under the MCP server there is no command line to repeat: the step is the login alone.
#[test]
fn a_write_with_no_command_line_steps_to_login_with_the_account() {
    let e = write_needs_session("opv target add", Some(B), &[]);
    assert_eq!(
        e.next_step(),
        Some("opv login --account ALABS000000000000000000001")
    );
}
