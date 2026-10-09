//! `opv login` (FR-40): which account, the signed-in child and its exit code.

use std::cell::RefCell;
use std::collections::VecDeque;

use super::*;
use crate::config;
use crate::domain::SecretValue;
use crate::runner::Output;

/// A fake `op`. Signed in: version, then a vault list that succeeds.
struct Fake {
    replies: RefCell<VecDeque<Output>>,
    account: Option<String>,
    sign_ins: Vec<Option<String>>,
    child_code: i32,
    children: RefCell<Vec<Vec<String>>>,
}

impl Fake {
    fn signed_in(child_code: i32) -> Self {
        Self {
            replies: RefCell::new(
                [
                    Output::success(b"2.40.0".to_vec()),
                    Output::success(b"[]".to_vec()),
                ]
                .into(),
            ),
            account: None,
            sign_ins: Vec::new(),
            child_code,
            children: RefCell::default(),
        }
    }

    /// Version; vault list and whoami fail; one account; the vault list after sign-in.
    fn signed_out() -> Self {
        let f = Self::signed_in(0);
        *f.replies.borrow_mut() = [
            Output::success(b"2.40.0".to_vec()),
            Output::failure(1),
            Output::failure(1),
            Output::success(br#"[{"url":"x"}]"#.to_vec()),
            Output::success(b"[]".to_vec()),
        ]
        .into();
        f
    }
}

impl Backend for Fake {
    fn native(&self) -> Result<(), Error> {
        Ok(())
    }
    fn call(&self, _args: &[&str], _stdin: Option<&[u8]>) -> Result<Output, Error> {
        Ok(self
            .replies
            .borrow_mut()
            .pop_front()
            .expect("unexpected op call"))
    }
    fn sign_in(&mut self, account: Option<&str>, _add: bool) -> Result<(), Error> {
        self.sign_ins.push(account.map(str::to_owned));
        Ok(())
    }
    fn use_account(&mut self, account: Option<&str>) {
        self.account = account.map(str::to_owned);
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
    fn choose(&mut self, _: &str, choices: &[String]) -> Result<String, Error> {
        self.asked.push(choices.to_vec());
        Ok(choices[self.pick].clone())
    }
}

fn fleet(dev_account: Option<&str>, prod_account: Option<&str>) -> Fleet {
    let line = |a: Option<&str>| a.map_or(String::new(), |a| format!("account = \"{a}\"\n"));
    config::parse(&format!(
        "[profile]\nkind = \"simple\"\n[environments.dev]\nvault_id = \"vdev\"\nitem_id = \
         \"idev\"\n{}[environments.prod]\nvault_id = \"vprd\"\nitem_id = \"iprd\"\n{}",
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
