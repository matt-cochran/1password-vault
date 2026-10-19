//! Owner-guided, resumable local setup. Existing automation commands never prompt.
use super::setup_recipe::{Field, Recipe};
use crate::adapters::onepassword::{Failed, WipeOnDrop, serialize_exact};
use crate::adapters::onepassword_diagnose::Facts;
pub use crate::adapters::onepassword_diagnose::SessionCheck;
use crate::cause::{
    AccountId, Cause, Closest, ConfigSource, CreateKind, DiagnoseContext, EnvName, FieldRule,
    GivenBy, InputKind, IoKind, ItemId, NoTerminal, NotEditable, ProductName, Refind, ResourceKind,
    ResourceName, ResourceRef, StoreObject, System, Unusable, ValueRow, ValueState, VaultId,
};
use crate::config;
use crate::domain::{Kind, SecretValue};
use crate::error::Error;
use crate::runner::{Call, Output};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub trait Backend {
    fn native(&self) -> Result<(), Error>;
    fn call(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Output, Error>;
    /// One read-only call, never retried: a status check whose failure is the answer
    /// (`op whoami` before signing in, #142).
    fn probe(&self, args: &[&str]) -> Result<Output, Error> {
        self.call(args, None)
    }
    fn sign_in(&mut self, account: Option<&str>, add_account: bool) -> Result<(), Error>;
    /// Add a 1Password account to this machine's `op` at op's own prompts and sign in to
    /// it in the same step (`opv login`, found in a fresh-account run-through: the person
    /// otherwise had to leave opv for `op account add`). `email` pre-fills op's question;
    /// `shorthand` is a name no account on this machine has yet (op otherwise names every
    /// account at my.1password.com `my`, so a second one, personal beside business, fails).
    fn add_account(&mut self, _email: Option<&str>, _shorthand: &str) -> Result<(), Error> {
        self.sign_in(None, true)
    }
    /// How to name `account` (an ID) to the person: the email op knows it by, when it does.
    fn account_label(&self, account: &str) -> String {
        account.to_string()
    }
    /// Use `account` for every later call (`opv login`, FR-40).
    fn use_account(&mut self, _account: Option<&str>) {}
    /// The account this backend's calls use ([`Backend::use_account`] or a sign-in), if any.
    fn current_account(&self) -> Option<String> {
        None
    }
    /// #160: whether op holds a session for `account` itself, checked by `op whoami
    /// --account <account>`; a live session for any other account is never this one's. The
    /// runtime uses [`crate::adapters::onepassword_diagnose::session_for`], which also names
    /// the account whose session is live.
    fn session_for(&self, account: &str) -> SessionCheck {
        match self.probe(&["whoami", "--account", account, "--format", "json"]) {
            Ok(o) if o.status == 0 => SessionCheck::SignedIn,
            Ok(_) => SessionCheck::NotSignedIn,
            Err(_) => SessionCheck::Undetermined,
        }
    }
    /// Run `command` signed in (a signed-in shell when empty); its exit code (`opv login`).
    fn child(&self, _command: &[String]) -> Result<i32, Error> {
        Err(Cause::Bug {
            site: "login: this backend cannot start a command",
        }
        .into())
    }
}
pub trait Interaction {
    fn show(&mut self, message: &str) -> Result<(), Error>;
    fn confirm(&mut self, question: &str) -> Result<bool, Error>;
    fn secret(&mut self, title: &str) -> Result<SecretValue, Error>;
    /// One of `choices`, picked by the person. An interaction that cannot ask (no
    /// terminal) refuses: the choice needs a person at a terminal.
    fn choose(&mut self, _question: &str, _choices: &[String]) -> Result<String, Error> {
        Err(Cause::NeedsTerminal {
            why: NoTerminal::NoTty,
        }
        .into())
    }
}

#[derive(Deserialize)]
struct Name {
    id: String,
    #[serde(default, alias = "title")]
    name: String,
}

/// The `op` call `args` exited 0 with a reply opv cannot use (a list that is not JSON, an
/// invalid ID): what the runner saw of it, never its contents.
fn unreadable_reply(args: &[&str]) -> Error {
    match crate::runner::take_unusable_reply(&Call::new("op", args)) {
        Some(seen) => Cause::UnexpectedOutput {
            system: System::OnePassword,
            at: None,
            problem: crate::cause::OutputProblem::Unparseable,
            during: crate::cause::During::Read,
            seen,
        }
        .into(),
        None => Cause::Bug {
            site: "setup: op is not an observed system",
        }
        .into(),
    }
}

/// The `op` call `args` failed (05.26, #159): the cause comes from op's own reply, through
/// the 1Password diagnosis, with the reply as evidence. Taken right after the call, before
/// any other call replaces what the runner observed.
fn op_failed(ctx: &DiagnoseContext, facts: &Facts) -> Error {
    match crate::runner::take_observed() {
        Some(seen) => {
            let failed = Failed::with_reply(seen);
            let cause = failed.diagnosed(ctx, facts);
            failed.report(cause)
        }
        // Every `op` call setup makes goes through the runner, which observes a failure.
        None => Cause::Bug {
            site: "setup: a failed op call left no observation",
        }
        .into(),
    }
}

/// What an `op` call of setup is about, for the diagnosis.
fn op_context(
    account: Option<&str>,
    resource: Option<ResourceRef>,
    write: bool,
) -> DiagnoseContext {
    DiagnoseContext {
        resource,
        write,
        account: account.map(AccountId::new),
        ..DiagnoseContext::default()
    }
}

/// A vault of the account, by ID or title.
fn vault_ref(vault: &str, account: Option<&str>) -> ResourceRef {
    ResourceRef {
        kind: ResourceKind::Vault,
        name: ResourceName::new(vault),
        scope: account.map(str::to_string),
    }
}

/// An item of `vault`, by ID or title.
fn item_ref(item: &str, vault: &str) -> ResourceRef {
    ResourceRef {
        kind: ResourceKind::Item,
        name: ResourceName::new(item),
        scope: Some(vault.to_string()),
    }
}

fn list(output: &Output, args: &[&str]) -> Result<Vec<Name>, Error> {
    serde_json::from_slice(&output.stdout).map_err(|_| unreadable_reply(args))
}

/// The title (of a vault or an item) more than one object has (F4): the person renames
/// the duplicate or names another title in the recipe.
fn duplicate_title(title: &str) -> Error {
    Cause::ItemUnusable {
        vault: None,
        title: title.to_string(),
        problem: crate::cause::ItemProblem::DuplicateTitle,
    }
    .into()
}

fn match_name(rows: Vec<Name>, name: &str, args: &[&str]) -> Result<Option<String>, Error> {
    let mut matches = rows.into_iter().filter(|r| r.name == name);
    let first = matches.next();
    if matches.next().is_some() {
        return Err(duplicate_title(name));
    }
    if let Some(row) = first {
        if !config::is_id(&row.id) {
            return Err(unreadable_reply(args));
        }
        Ok(Some(row.id))
    } else {
        Ok(None)
    }
}

/// `args` run and finished with exit 0, else the diagnosed failure (05.26): `ctx` names the
/// vault or item the call is about.
fn successful(
    backend: &dyn Backend,
    args: &[&str],
    input: Option<&[u8]>,
    ctx: &DiagnoseContext,
    facts: &Facts,
) -> Result<Output, Error> {
    let output = backend.call(args, input)?;
    if output.status != 0 {
        return Err(op_failed(ctx, facts));
    }
    Ok(output)
}

/// The version of `op` (05.29: never "Linux/native" on another platform, never "rerun
/// setup" from `opv login`).
fn version(backend: &dyn Backend) -> Result<String, Error> {
    let output = backend.call(&["--version"], None)?;
    let value = std::str::from_utf8(&output.stdout)
        .ok()
        .map(str::trim)
        .unwrap_or("");
    let numbers = value
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok();
    let unusable = |why| -> Error {
        Cause::ToolUnusable {
            tool: "op".into(),
            why,
        }
        .into()
    };
    let Some(numbers) = numbers.filter(|n| output.status == 0 && n.len() == 3) else {
        return Err(unusable(Unusable::VersionUnreadable));
    };
    let min = super::doctor::OP_TESTED_MIN;
    if (numbers[0], numbers[1], numbers[2]) < min {
        return Err(unusable(Unusable::TooOld {
            have: value.to_owned(),
            min: format!("{}.{}.{}", min.0, min.1, min.2),
        }));
    }
    Ok(value.to_owned())
}

/// Authentication stays in the owner process, never in a printed export command.
pub fn prepare(
    account: Option<&str>,
    backend: &mut dyn Backend,
    ui: &mut dyn Interaction,
) -> Result<Output, Error> {
    sign_in(account, backend, ui)
}

/// `op vault list`, as every sign-in check of setup and login runs it.
const VAULT_LIST: [&str; 4] = ["vault", "list", "--format", "json"];

/// Signed in, with a vault listing. With an account, the session is checked for that
/// account by ID (#160): a live session for any other account, on the same sign-in address
/// or not, is never taken for it, and op's prompt for `account` follows. Without one, only a
/// vault list that works shows a session; a bare `op whoami` never does (it answers for
/// op's default account). A vault list that fails once signed in is diagnosed from op's own
/// reply ([`vault_list_failed`]).
fn sign_in(
    account: Option<&str>,
    backend: &mut dyn Backend,
    ui: &mut dyn Interaction,
) -> Result<Output, Error> {
    // H3 (#160): an empty account is none; op is never asked about `--account ""`.
    let account = account.filter(|a| !a.trim().is_empty());
    backend.native()?;
    ui.show(&format!("1Password CLI: ready ({})", version(backend)?))?;
    match account {
        Some(a) => {
            if backend.session_for(a) == SessionCheck::SignedIn {
                let vaults = backend.call(&VAULT_LIST, None)?;
                if vaults.status == 0 {
                    return Ok(vaults);
                }
                let failed = vault_list_failed(account);
                // #167: a stale `OP_SESSION_*` can make a plain `op whoami` still name the
                // account while its vault list says no one is signed in. That is not an
                // answer to return; it is the sign-in op asks for.
                if failed.code_str() != "op_not_signed_in" {
                    return Err(failed);
                }
                // The stale list is expected to fail: its reply attaches to nothing.
                let _ = crate::runner::take_observed();
                let _ = crate::runner::take_failure_excerpt();
            }
            start_sign_in(Some(a), backend, ui)?;
            match backend.session_for(a) {
                // A check that could not tell leaves it to the vault list below.
                SessionCheck::SignedIn | SessionCheck::Undetermined => {}
                check => return Err(not_signed_in_to(a, &check)),
            }
        }
        None => {
            let vaults = backend.call(&VAULT_LIST, None)?;
            if vaults.status == 0 {
                return Ok(vaults);
            }
            // The unsigned list is expected to fail: its reply attaches to nothing.
            let _ = crate::runner::take_observed();
            let _ = crate::runner::take_failure_excerpt();
            start_sign_in(None, backend, ui)?;
        }
    }
    let vaults = backend.call(&VAULT_LIST, None)?;
    if vaults.status != 0 {
        // 05.08: op's reply, not "rerun setup", says why (a sign-in that did not finish,
        // an expired session, an outage).
        return Err(vault_list_failed(account));
    }
    Ok(vaults)
}

/// op's own sign-in prompt for `account` (adding the first account first, when op knows
/// none). The password goes only to op.
fn start_sign_in(
    account: Option<&str>,
    backend: &mut dyn Backend,
    ui: &mut dyn Interaction,
) -> Result<(), Error> {
    ui.show("Sign in to 1Password. Your password goes only to its own prompt.")?;
    let accounts = backend.call(&["account", "list", "--format", "json"], None)?;
    let none = accounts.status == 0
        && serde_json::from_slice::<Vec<serde::de::IgnoredAny>>(&accounts.stdout)
            .is_ok_and(|a| a.is_empty());
    if none {
        ui.show("First, add your 1Password account at its prompts. Find its details in your 1Password Emergency Kit.")?;
        backend.sign_in(account, true)?;
    }
    backend.sign_in(account, false)
}

/// #160: op still holds no session for `account` after its sign-in, perhaps because the
/// live session belongs to another account on the same sign-in address. The step signs in
/// to that account by ID: never a bare `opv login` (op's default account), never a vault.
pub(crate) fn not_signed_in_to(account: &str, check: &SessionCheck) -> Error {
    use crate::cause::{AccountId, Cause, SessionState, System};
    let state = match check {
        SessionCheck::OtherAccountLive { live } => {
            SessionState::OtherAccount { live: live.clone() }
        }
        _ => SessionState::SignedOut,
    };
    Cause::NotSignedIn {
        system: System::OnePassword,
        account: Some(AccountId::new(account)),
        state,
    }
    .into()
}

/// `op vault list` failed once signed in (#157, #159, #160): the cause is what op said,
/// through the 1Password diagnosis (a signed-out reply is `op_not_signed_in`, an unknown
/// account `account_not_registered`), never one chosen here. Called right after the call.
fn vault_list_failed(account: Option<&str>) -> Error {
    op_failed(
        &op_context(account, None, false),
        &Facts::from_process_env(),
    )
}

/// The child `op signin` (or `op account add`) for `account` (#153, recorded case 13): the
/// account goes in `--account` only. `OP_ACCOUNT` (op reads it as `--account`, recorded
/// case 04), `OP_SESSION` and every inherited `OP_SESSION_*` (`inherited`: the names in
/// opv's environment) are removed, so a session for another account on the same sign-in
/// address never decides what op does. `--force` asks op for a fresh assignment.
pub fn signin_command(
    account: Option<&str>,
    add_account: bool,
    inherited: impl IntoIterator<Item = std::ffi::OsString>,
) -> std::process::Command {
    let mut command = std::process::Command::new("op");
    command.args(if add_account {
        ["account", "add"].as_slice()
    } else {
        ["signin", "--force"].as_slice()
    });
    if let Some(account) = account
        && !add_account
    {
        command.args(["--account", account]);
    }
    command
        .env_remove("OP_ACCOUNT")
        .env_remove("OP_SESSION")
        .env("OP_DEBUG", "false");
    for name in inherited {
        if name.to_str().is_some_and(|n| n.starts_with("OP_SESSION_")) {
            command.env_remove(&name);
        }
    }
    command
}

/// How setup names the account it uses: by its label when one was chosen, else the
/// signed-in account.
fn account_name(backend: &dyn Backend, account: Option<&str>) -> String {
    match account {
        Some(a) => format!("1Password account {}", backend.account_label(a)),
        None => "the signed-in 1Password account".to_string(),
    }
}

/// The `op item get` whose reply setup lays out (names only, for an unusable reply).
const ITEM_GET: [&str; 2] = ["item", "get"];

/// The setting `field` of `env` whose field in the item cannot be used as it is (wrong
/// type, given twice): the person fixes it in 1Password.
fn field_to_fix(env: &str, field: &Field, state: ValueState) -> Error {
    Cause::ValuesNeeded {
        env: EnvName::new(env),
        rows: vec![ValueRow {
            product: ProductName::new(field.product.as_str()),
            key: crate::cause::KeyName::new(field.key.as_str()),
            target: None,
            state,
        }],
    }
    .into()
}

fn field_indices(
    doc: &mut Value,
    definitions: &[Field],
    recipe: &Recipe,
) -> Result<Vec<usize>, Error> {
    if doc.get("category").and_then(Value::as_str) != Some("SECURE_NOTE") {
        return Err(Cause::ItemUnusable {
            vault: Some(crate::cause::VaultId::new(&recipe.vault)),
            title: recipe.item.clone(),
            problem: crate::cause::ItemProblem::WrongCategory,
        }
        .into());
    }
    if doc.get("fields").is_none() {
        doc["fields"] = json!([]);
    }
    if !doc["fields"].is_array() {
        return Err(unreadable_reply(&ITEM_GET));
    }
    if doc.get("sections").is_none() {
        doc["sections"] = json!([]);
    }
    if !doc["sections"].is_array() {
        return Err(unreadable_reply(&ITEM_GET));
    }
    let mut indices = Vec::new();
    for definition in definitions {
        let matches: Vec<_> = doc["fields"]
            .as_array()
            .expect("fields")
            .iter()
            .enumerate()
            .filter(|(_, field)| {
                let section = field
                    .get("section")
                    .and_then(|s| s.get("label"))
                    .and_then(Value::as_str);
                field.get("label").and_then(Value::as_str) == Some(&definition.key)
                    && section == Some(definition.product.as_str())
            })
            .map(|(i, _)| i)
            .collect();
        if matches.len() > 1 {
            return Err(field_to_fix(
                &recipe.environment,
                definition,
                ValueState::RuleFailed {
                    rule: "one field per setting: rename or remove the duplicate field",
                    reason: None,
                },
            ));
        }
        if let Some(&index) = matches.first() {
            let expected = match definition.kind {
                Kind::Secret => "CONCEALED",
                Kind::Config => "STRING",
            };
            let ty = doc["fields"][index].get("type").and_then(Value::as_str);
            // Config kept concealed is accepted as it is (FR-43).
            if ty != Some(expected) && !(definition.kind == Kind::Config && ty == Some("CONCEALED"))
            {
                let state = match definition.kind {
                    Kind::Secret => ValueState::StoredAsText,
                    Kind::Config => ValueState::RuleFailed {
                        rule: "a Text field: change its type in 1Password, keeping the value",
                        reason: None,
                    },
                };
                return Err(field_to_fix(&recipe.environment, definition, state));
            }
            indices.push(index);
        } else {
            let field_id = unique_id(&doc["fields"], &format!("opv_{}", definition.key));
            let mut field = json!({"id":field_id,"label":definition.key,"type":match definition.kind {Kind::Secret=>"CONCEALED",Kind::Config=>"STRING"},"value":""});
            // Each product's fields live in its own section (FR-43).
            let product = &definition.product;
            let sections = doc["sections"].as_array_mut().expect("sections");
            let section = if let Some(section) = sections
                .iter()
                .find(|s| s.get("label").and_then(Value::as_str) == Some(product))
            {
                section.clone()
            } else {
                let section = json!({"id":unique_id(&Value::Array(sections.clone()), &format!("opv_{product}")),"label":product});
                sections.push(section.clone());
                section
            };
            field["section"] = section;
            let fields = doc["fields"].as_array_mut().expect("fields");
            indices.push(fields.len());
            fields.push(field);
        }
    }
    Ok(indices)
}

fn unique_id(rows: &Value, base: &str) -> String {
    let mut candidate = base.to_owned();
    let mut suffix = 1;
    while rows.as_array().is_some_and(|rows| {
        rows.iter()
            .any(|row| row.get("id").and_then(Value::as_str) == Some(&candidate))
    }) {
        candidate = format!("{base}_{suffix}");
        suffix += 1;
    }
    candidate
}

fn has_value(doc: &Value, index: usize) -> bool {
    doc["fields"][index]
        .get("value")
        .and_then(Value::as_str)
        .is_some_and(|v| !v.is_empty())
}

/// The recipe's `legacy_env` with a leading `~/` expanded; `recipe_path` is named when no
/// home directory is set.
fn expanded(path: &Path, recipe_path: &Path) -> Result<PathBuf, Error> {
    if let Some(tail) = path.to_str().and_then(|s| s.strip_prefix("~/")) {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .ok_or_else(|| -> Error {
                Cause::InputInvalid {
                    path: recipe_path.to_path_buf(),
                    kind: InputKind::SetupRecipe,
                    at: None,
                    field: "legacy_env".into(),
                    rule: FieldRule::Type {
                        expected: "a path without ~ while neither HOME nor USERPROFILE is set",
                    },
                }
                .into()
            })?;
        Ok(PathBuf::from(home).join(tail))
    } else {
        Ok(path.to_owned())
    }
}

/// The input file `path` could not be read (F4): `InputUnreadable`, naming the file and
/// the I/O failure, never its contents.
fn input_unreadable(path: &Path, kind: InputKind, io: std::io::ErrorKind) -> Error {
    Cause::InputUnreadable {
        path: path.to_path_buf(),
        kind,
        io: IoKind::from(io),
    }
    .into()
}

/// The input file `path` (a dotenv file, a setup recipe) cannot be used as it is, named
/// with what it must be (05.09, 05.21). Never its contents.
fn input_unusable(path: &Path, kind: InputKind, expected: &'static str) -> Error {
    Cause::InputInvalid {
        path: path.to_path_buf(),
        kind,
        at: None,
        field: "the file".into(),
        rule: FieldRule::Type { expected },
    }
    .into()
}

/// The literal assignments of the dotenv file `path` (`init --from`, `adopt --from` and
/// setup's import): private, regular, under 1 MiB, UTF-8. Every refusal names the file
/// (05.09); nothing is imported from a file refused.
pub(crate) fn read_legacy(path: &Path) -> Result<BTreeMap<String, SecretValue>, Error> {
    let info = fs::symlink_metadata(path)
        .map_err(|e| input_unreadable(path, InputKind::Dotenv, e.kind()))?;
    if !info.file_type().is_file() || info.len() > 1024 * 1024 {
        return Err(input_unusable(
            path,
            InputKind::Dotenv,
            "a regular file (not a link or folder) under 1 MiB",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = info.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(Cause::LocalFileTooOpen {
                path: path.to_path_buf(),
                mode,
                want: 0o600,
            }
            .into());
        }
    }
    let raw = Zeroizing::new(
        fs::read_to_string(path)
            .map_err(|_| input_unusable(path, InputKind::Dotenv, "UTF-8 text"))?,
    );
    super::setup_import::parse_at(path, &raw)
}

/// The configuration `path` (setup's output) must already hold exactly what the recipe
/// declares: setup never overwrites it. `recipe_path` is what generates it.
fn config_compatible(path: &Path, expected: &str, recipe_path: &Path) -> Result<(), Error> {
    if path.exists() && config::load(path)? != config::parse(expected)? {
        return Err(Cause::ConfigNotEditable {
            source: ConfigSource::File {
                path: path.to_path_buf(),
                given_by: GivenBy::Discovered,
            },
            reason: NotEditable::Generated {
                generator: Some(recipe_path.to_path_buf()),
                diff: None,
            },
        }
        .into());
    }
    Ok(())
}

/// `opv setup` as the person ran it, rebuilt from its arguments (05.32, X1): every flag
/// kept, the product the run settled on included, the recipe always named.
fn setup_command(
    recipe_path: &Path,
    output_override: Option<&Path>,
    account: Option<&str>,
    product: &str,
) -> crate::cause::Cmd {
    let mut args = vec!["--recipe".to_string(), recipe_path.display().to_string()];
    if let Some(o) = output_override {
        args.extend(["--config".to_string(), o.display().to_string()]);
    }
    if let Some(a) = account {
        args.extend(["--account".to_string(), a.to_string()]);
    }
    args.extend(["--product".to_string(), product.to_string()]);
    crate::cause::Cmd {
        command: vec!["setup".into()],
        args,
    }
}

/// `Next: <command>`, the closing line of a setup that stopped or left fields to fill.
fn show_next(ui: &mut dyn Interaction, next: &crate::cause::Cmd) -> Result<(), Error> {
    ui.show(&format!("Next: {}", crate::cause::render::cmd_text(next)))
}

/// What 1Password holds for this setup when the person stops before saving (C1, X26): none
/// of this run's entries, and the fields saved by an earlier run, named.
fn nothing_saved_line(saved_before: &[&str]) -> String {
    if saved_before.is_empty() {
        "Stopped before saving: nothing from this run was saved in 1Password.".to_string()
    } else {
        format!(
            "Stopped before saving: nothing from this run was saved in 1Password. Saved there \
             by an earlier setup: {}.",
            saved_before.join(", ")
        )
    }
}

/// `e`, after saying exactly what is saved (C1) when it is the person stopping at a prompt.
fn said_what_is_saved(e: Error, saved_before: &[&str], ui: &mut dyn Interaction) -> Error {
    let declined = matches!(
        e.cause(),
        Some((
            Cause::Guard {
                guard: crate::cause::Guard::Declined
            },
            _
        ))
    );
    if declined {
        let _ = ui.show(&nothing_saved_line(saved_before));
    }
    e
}

/// The product setup works on: `product` when the recipe declares it, the recipe's only
/// product, or the person's pick. A product the recipe does not declare is never retried
/// as given (05.21): with one product the recipe could mean (its only one, or the one close
/// match, X2) the step is the same setup with that product and every flag kept; otherwise
/// the person picks one of the recipe's products.
fn selected_product(
    products: &[String],
    product: Option<&str>,
    again: impl Fn(&str) -> crate::cause::Cmd,
    ui: &mut dyn Interaction,
) -> Result<String, Error> {
    match (products, product) {
        (_, Some(p)) if products.iter().any(|v| v == p) => Ok(p.to_owned()),
        (_, Some(p)) => {
            let names = products.iter().map(String::as_str);
            let close = match products {
                [one] => vec![one.as_str()],
                _ => super::suggest::close(p, names),
            };
            Err(match Closest::unique(&close) {
                Some(c) => Cause::Usage {
                    problem: crate::cause::UsageProblem::UseInstead {
                        command: again(c.as_str()),
                    },
                },
                None => Cause::ChoiceRequired {
                    flag: "--product".into(),
                    candidates: products.to_vec(),
                },
            }
            .into())
        }
        ([one], None) => Ok(one.clone()),
        (_, None) => ui.choose("Which product are you working on?", products),
    }
}

/// Return 0 when ready, 8 when saved with missing fields, 6 when the owner stops. Every
/// non-zero exit ends with the setup command to run again (05.32).
pub fn run(
    recipe_path: &Path,
    output_override: Option<&Path>,
    account: Option<&str>,
    product: Option<&str>,
    backend: &mut dyn Backend,
    ui: &mut dyn Interaction,
) -> Result<i32, Error> {
    let text = fs::read_to_string(recipe_path)
        .map_err(|e| input_unreadable(recipe_path, InputKind::SetupRecipe, e.kind()))?;
    // C8: the recipe's errors name the recipe file itself.
    let recipe = Recipe::parse_at(recipe_path, &text)?;
    let products: Vec<_> = recipe
        .fields
        .iter()
        .map(|f| f.product.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let selected = selected_product(
        &products,
        product,
        |p| setup_command(recipe_path, output_override, account, p),
        ui,
    )?;
    let again = setup_command(recipe_path, output_override, account, &selected);
    let active: Vec<_> = recipe
        .fields
        .iter()
        .filter(|f| f.product == selected)
        .cloned()
        .collect();
    let parent = recipe_path.parent().unwrap_or_else(|| Path::new("."));
    let output = output_override
        .map(Path::to_owned)
        .unwrap_or_else(|| parent.join(&recipe.output));
    if output.exists() {
        let existing = config::load(&output)?;
        let env = existing.environment(&recipe.environment)?;
        // The recipe writes one item (its one boundary); compare against the first recorded.
        // 05.28: no step inside the text; the cause's own step is the structure route.
        let at = env
            .bound_boundaries()
            .next()
            .map(|(_, b)| b)
            .ok_or_else(|| -> Error {
                Cause::BoundaryMissing {
                    env: EnvName::new(recipe.environment.as_str()),
                    product: ProductName::new(selected.as_str()),
                    source: ConfigSource::File {
                        path: output.clone(),
                        given_by: match output_override {
                            Some(_) => GivenBy::Flag {
                                flag: "--config".into(),
                            },
                            None => GivenBy::Discovered,
                        },
                    },
                }
                .into()
            })?;
        config_compatible(
            &output,
            &recipe.manifest(&at.vault_id, &at.item_id)?,
            recipe_path,
        )?;
    }
    ui.show(&format!("\n{}\nWe will save your existing settings in 1Password and prepare local commands.\nNo infrastructure will be applied or deployed.\n", recipe.title))?;
    let vaults = prepare(account, backend, ui)?;
    let vault = match_name(list(&vaults, &VAULT_LIST)?, &recipe.vault, &VAULT_LIST)?.ok_or_else(
        || -> Error {
            // #157: the account it was looked for in is named.
            Cause::InputInvalid {
                path: recipe_path.to_path_buf(),
                kind: InputKind::SetupRecipe,
                at: None,
                field: format!(
                    "vault {:?} (looked for in {})",
                    recipe.vault,
                    account_name(backend, account)
                ),
                rule: FieldRule::Type {
                    expected: "the title of a vault in that account (create it in the 1Password \
                           app, or sign in to the account that holds it)",
                },
            }
            .into()
        },
    )?;
    ui.show(&format!("Signed in. Using vault {}.", recipe.vault))?;
    let list_items = ["item", "list", "--vault", &vault, "--format", "json"];
    let items = successful(
        backend,
        &list_items,
        None,
        &op_context(account, Some(vault_ref(&vault, account)), false),
        &Facts::from_process_env(),
    )?;
    let mut item_id = match_name(list(&items, &list_items)?, &recipe.item, &list_items)?;
    let raw = if let Some(id) = &item_id {
        read_fresh(backend, id, &vault, account)?
    } else {
        ui.show(&format!(
            "Your setup item is missing. I can create {} and its fields for you.",
            recipe.item
        ))?;
        Output::success(br#"{"category":"SECURE_NOTE","fields":[],"sections":[]}"#.to_vec())
    };
    let before = {
        let original = WipeOnDrop(
            serde_json::from_slice(&raw.stdout).map_err(|_| unreadable_reply(&ITEM_GET))?,
        );
        serialize_exact(&original.0)?
    };
    let (mut doc, mut indices) = laid_out(
        &recipe,
        &vault,
        item_id.as_deref(),
        &raw.stdout,
        &active,
        ui,
    )?;
    // C1: the fields 1Password already holds a value for, saved by an earlier setup.
    let saved_before: Vec<&str> = active
        .iter()
        .zip(&indices)
        .filter(|(_, i)| has_value(&doc.0, **i))
        .map(|(f, _)| f.title.as_str())
        .collect();
    let mut import = BTreeMap::new();
    if let Some(path) = &recipe.legacy_env {
        let path = expanded(path, recipe_path)?;
        let path = if path.is_absolute() {
            path
        } else {
            parent.join(path)
        };
        if path.exists() && indices.iter().any(|&i| !has_value(&doc.0, i)) {
            ui.show(&format!("\nFound existing settings at {}. We can copy only missing declared values; the file stays intact.", path.display()))?;
            let copy = ui
                .confirm("Copy these existing settings privately?")
                .map_err(|e| said_what_is_saved(e, &saved_before, ui))?;
            if copy {
                match read_legacy(&path) {
                    Ok(values) => import = values,
                    Err(error) => ui.show(&format!("{error}\nContinue below without importing. Your original file is unchanged; fill the missing values privately in 1Password."))?,
                }
            }
        }
    }
    // The values copied or typed in this run, by position in `active`: kept in memory (and
    // wiped on drop) so a re-plan on a fresher item does not ask for them again.
    let mut entered: Vec<(usize, SecretValue)> = Vec::new();
    for (n, (field, &index)) in active.iter().zip(&indices).enumerate() {
        if has_value(&doc.0, index) {
            ui.show(&format!("Saved: {} (existing value kept)", field.title))?;
            continue;
        }
        if let Some(value) = import.get(&field.key).filter(|v| !v.expose().is_empty()) {
            doc.0["fields"][index]["value"] = Value::String(value.expose().to_owned());
            entered.push((n, SecretValue::new(value.expose().to_owned())));
            ui.show(&format!("Copied: {} (value hidden)", field.title))?;
            continue;
        }
        ui.show(&format!(
            "\n{}\n{}\nWhere to find it: {}",
            field.title, field.description, field.source
        ))?;
        if field.multiline {
            ui.show("This needs its exact complete multiline value. Use the private file import, or finish this field in the 1Password app. We will not generate a replacement.")?;
        } else {
            ui.show("Enter the existing value privately, or press Enter to finish it later.")?;
            let value = ui
                .secret(&field.title)
                .map_err(|e| said_what_is_saved(e, &saved_before, ui))?;
            if !value.expose().is_empty() {
                doc.0["fields"][index]["value"] = Value::String(value.expose().to_owned());
                entered.push((n, value));
            }
        }
    }
    drop(import);
    let payload = serialize_exact(&doc.0)?;
    let mut saved = false;
    if item_id.is_none() || *payload != *before {
        let save = confirm_save(&recipe, &active, &indices, &doc.0, ui)
            .map_err(|e| said_what_is_saved(e, &saved_before, ui))?;
        if !save {
            ui.show(&nothing_saved_line(&saved_before))?;
            show_next(ui, &again)?;
            return Ok(6);
        }
        if let Some(id) = &item_id {
            config_compatible(&output, &recipe.manifest(&vault, id)?, recipe_path)?;
            // The owner may have spent a long time at the prompts: the item is read again,
            // fresh, and never overwritten if it moved on since setup read it.
            let mut base = read_fresh(backend, id, &vault, account)?;
            if changed_since(&raw.stdout, &base.stdout)? {
                ui.show("\nThe item changed in 1Password while setup was open, so nothing was saved. Setup read it again: what 1Password holds now is kept, and your entries fill only the settings that are still empty.")?;
                (doc, indices) = laid_out(
                    &recipe,
                    &vault,
                    item_id.as_deref(),
                    &base.stdout,
                    &active,
                    ui,
                )?;
                let mut theirs = Vec::new();
                for (n, value) in &entered {
                    let index = indices[*n];
                    if has_value(&doc.0, index) {
                        theirs.push(active[*n].title.as_str());
                    } else {
                        doc.0["fields"][index]["value"] = Value::String(value.expose().to_owned());
                    }
                }
                if !theirs.is_empty() {
                    ui.show(&format!(
                        "Already filled in 1Password, so your entry was not used: {}.",
                        theirs.join(", ")
                    ))?;
                }
                let save = confirm_save(&recipe, &active, &indices, &doc.0, ui)
                    .map_err(|e| said_what_is_saved(e, &saved_before, ui))?;
                if !save {
                    ui.show(&nothing_saved_line(&saved_before))?;
                    show_next(ui, &again)?;
                    return Ok(6);
                }
                let again = read_fresh(backend, id, &vault, account)?;
                if changed_since(&base.stdout, &again.stdout)? {
                    return Err(Cause::ChangedBeforeWrite {
                        object: StoreObject::Item {
                            vault: VaultId::new(vault.as_str()),
                            item: ItemId::new(id.as_str()),
                        },
                    }
                    .into());
                }
                base = again;
            }
            drop(entered);
            let payload = serialize_exact(&doc.0)?;
            let unchanged = {
                let now = WipeOnDrop(
                    serde_json::from_slice(&base.stdout)
                        .map_err(|_| unreadable_reply(&ITEM_GET))?,
                );
                *serialize_exact(&now.0)? == *payload
            };
            if !unchanged {
                let echoed = successful(
                    backend,
                    &["item", "edit", id, "--vault", &vault, "--format", "json"],
                    Some(&payload),
                    &op_context(account, Some(item_ref(id, &vault)), true),
                    &Facts {
                        item_readable: true,
                        ..Facts::from_process_env()
                    },
                )?;
                saved = true;
                verify_saved(backend, id, &vault, account, &base.stdout, &payload, echoed)
                    .map_err(|e| said_saved(e, &recipe, &active, &indices, &doc.0, ui))?;
            }
        } else {
            let create = [
                "item",
                "create",
                "-",
                "--vault",
                &vault,
                "--title",
                &recipe.item,
                "--format",
                "json",
            ];
            let mut ctx = op_context(account, Some(vault_ref(&vault, account)), true);
            // setup finds its item again by title, so a re-run never duplicates it (X5).
            ctx.create = Some((
                CreateKind::ItemWithSecrets,
                recipe.item.clone(),
                Refind::ByTitle,
            ));
            let created = successful(
                backend,
                &create,
                Some(&payload),
                &ctx,
                &Facts::from_process_env(),
            )?;
            let unknown = || -> Error {
                match crate::runner::take_unusable_reply(&Call::new("op", &create)) {
                    Some(seen) => Cause::CreateOutcomeUnknown {
                        system: System::OnePassword,
                        kind: CreateKind::ItemWithSecrets,
                        name: recipe.item.clone(),
                        refind: Refind::ByTitle,
                        seen,
                    }
                    .into(),
                    None => Cause::Bug {
                        site: "setup: op is not an observed system",
                    }
                    .into(),
                }
            };
            let created =
                WipeOnDrop(serde_json::from_slice(&created.stdout).map_err(|_| unknown())?);
            item_id = created
                .0
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| config::is_id(id))
                .map(str::to_owned);
            if item_id.is_none() {
                return Err(unknown());
            }
            saved = true;
        }
    }
    let missing = missing_titles(&active, &indices, &doc.0);
    // Actual value/rule validation is deliberately explicit: the check, with this run's
    // configuration and product (X1).
    let check = missing.is_empty().then(|| crate::cause::Cmd {
        command: vec!["ready".into()],
        args: vec![
            "--config".into(),
            output.display().to_string(),
            recipe.environment.clone(),
        ],
    });
    let finished = finish(
        &recipe,
        recipe_path,
        &output,
        &vault,
        item_id.as_deref().expect("existing or created"),
        check.as_ref(),
        ui,
    );
    match finished {
        Ok(()) if missing.is_empty() => Ok(0),
        Ok(()) => {
            ui.show(&format!("Saved progress. Still needed: {}.\nFill those fields privately in 1Password, or run setup again. No infrastructure changed.", missing.join(", ")))?;
            show_next(ui, &again)?;
            Ok(8)
        }
        // C1: what the save already put in 1Password is said, whatever failed after it.
        Err(e) if saved => Err(said_saved(e, &recipe, &active, &indices, &doc.0, ui)),
        Err(e) => Err(e),
    }
}

/// `e`, after saying which fields the save put in 1Password (C1).
fn said_saved(
    e: Error,
    recipe: &Recipe,
    active: &[Field],
    indices: &[usize],
    doc: &Value,
    ui: &mut dyn Interaction,
) -> Error {
    let filled: Vec<&str> = active
        .iter()
        .zip(indices)
        .filter(|(_, i)| has_value(doc, **i))
        .map(|(f, _)| f.title.as_str())
        .collect();
    let _ = ui.show(&format!(
        "Saved in 1Password: item {} in vault {}{}.",
        recipe.item,
        recipe.vault,
        if filled.is_empty() {
            String::new()
        } else {
            format!(", with {}", filled.join(", "))
        }
    ));
    e
}

/// After the item is saved (or found complete): write the local configuration and say what
/// is ready; with every setting filled, `check` is the next step.
fn finish(
    recipe: &Recipe,
    recipe_path: &Path,
    output: &Path,
    vault: &str,
    item_id: &str,
    check: Option<&crate::cause::Cmd>,
    ui: &mut dyn Interaction,
) -> Result<(), Error> {
    let manifest = recipe.manifest(vault, item_id)?;
    config::parse(&manifest)?;
    config_compatible(output, &manifest, recipe_path)?;
    if !output.exists() {
        super::init::write_config(output, &manifest, false)?;
    }
    ui.show(&format!(
        "\nLocal configuration ready: {} (IDs and declarations only)",
        output.display()
    ))?;
    if let Some(check) = check {
        ui.show("All settings are saved.")?;
        // Never claim the external provider credentials work merely because their fields
        // are filled.
        ui.show("The check validates field types and rules. Provider access is verified by the command you run next.")?;
        show_next(ui, check)?;
    }
    Ok(())
}

/// The setup item laid out for `active`: tidied to the convention first when a person runs
/// setup on an existing item (FR-43; saved with the progress, only if the owner confirms;
/// nothing is deleted, old copies go to "opv · kept"), then every active field found or
/// added. Returns the document and each active field's index in it.
fn laid_out(
    recipe: &Recipe,
    vault: &str,
    item_id: Option<&str>,
    raw: &[u8],
    active: &[Field],
    ui: &mut dyn Interaction,
) -> Result<(WipeOnDrop, Vec<usize>), Error> {
    let tidied = match item_id {
        Some(id) if super::tidy::active() => tidy_layout(recipe, vault, id, raw, ui)?,
        _ => None,
    };
    let mut doc = WipeOnDrop(
        serde_json::from_slice(tidied.as_deref().map_or(raw, |t| &t[..]))
            .map_err(|_| unreadable_reply(&ITEM_GET))?,
    );
    drop(tidied);
    let indices = field_indices(&mut doc.0, active, recipe)?;
    Ok((doc, indices))
}

/// The titles of the active fields still without a value.
fn missing_titles<'a>(active: &'a [Field], indices: &[usize], doc: &Value) -> Vec<&'a str> {
    active
        .iter()
        .zip(indices)
        .filter(|(_, i)| !has_value(doc, **i))
        .map(|(f, _)| f.title.as_str())
        .collect()
}

/// Say what a save would hold and ask the owner once.
fn confirm_save(
    recipe: &Recipe,
    active: &[Field],
    indices: &[usize],
    doc: &Value,
    ui: &mut dyn Interaction,
) -> Result<bool, Error> {
    let missing = missing_titles(active, indices, doc).len();
    ui.show(&format!(
        "\nSave {} in {}. {} of {} settings filled. Existing filled values are kept.",
        recipe.item,
        recipe.vault,
        indices.len() - missing,
        indices.len()
    ))?;
    ui.confirm("Save this progress in 1Password?")
}

/// The setup item read straight from 1Password, never from `op`'s cache (C1); a failed
/// read is diagnosed from op's reply, naming the item and its vault (05.26).
fn read_fresh(
    backend: &dyn Backend,
    id: &str,
    vault: &str,
    account: Option<&str>,
) -> Result<Output, Error> {
    let args = [
        "item",
        "get",
        id,
        "--vault",
        vault,
        "--format",
        "json",
        crate::adapters::onepassword::NO_CACHE,
    ];
    let output = successful(
        backend,
        &args,
        None,
        &op_context(account, Some(item_ref(id, vault)), false),
        &Facts::from_process_env(),
    )?;
    // 09.74, C20: setup's item read shape-checks op's reply exactly as the op reader does,
    // while the runner still holds the call, so JSON of another shape is this call's
    // `UnexpectedOutput` rather than being read as an item.
    crate::adapters::onepassword_tidy::check(&output.stdout)
        .map_err(|e| crate::adapters::onepassword::unreadable_reply(&args, &e))?;
    Ok(output)
}

/// True when `now` is a later state of the item than `then`: another version, or (when
/// either has no version) different content.
fn changed_since(then: &[u8], now: &[u8]) -> Result<bool, Error> {
    use crate::adapters::onepassword::item_version;
    if let (Some(a), Some(b)) = (item_version(then), item_version(now)) {
        return Ok(a != b);
    }
    let a = WipeOnDrop(serde_json::from_slice(then).map_err(|_| unreadable_reply(&ITEM_GET))?);
    let b = WipeOnDrop(serde_json::from_slice(now).map_err(|_| unreadable_reply(&ITEM_GET))?);
    Ok(a.0 != b.0)
}

/// After the edit (as the tidy does, I5): the item must be exactly one version past `base`,
/// the read the edit was built from, and hold every field setup wrote or kept. The echoed
/// item is used when it carries a version, else the item is read again, fresh.
fn verify_saved(
    backend: &dyn Backend,
    id: &str,
    vault: &str,
    account: Option<&str>,
    base: &[u8],
    payload: &[u8],
    echoed: Output,
) -> Result<(), Error> {
    use crate::adapters::onepassword::item_version;
    let after = match item_version(&echoed.stdout) {
        Some(_) => echoed,
        None => read_fresh(backend, id, vault, account)?,
    };
    let expected = item_version(base).map(|v| v + 1);
    let got = item_version(&after.stdout);
    let object = || StoreObject::Item {
        vault: VaultId::new(vault),
        item: ItemId::new(id),
    };
    if expected.is_some() && got != expected {
        // Another edit landed together with setup's; setup did not retry.
        return Err(Cause::ConcurrentEdit { object: object() }.into());
    }
    let fields = crate::adapters::onepassword_tidy::lost(base, payload, &after.stdout)?;
    if !fields.is_empty() {
        return Err(Cause::ReadBackMissing {
            vault: VaultId::new(vault),
            item: ItemId::new(id),
            // G2 (F4d): the fields by label, never a count.
            fields,
            by: crate::cause::Cmd {
                command: vec!["setup".into()],
                args: Vec::new(),
            },
        }
        .into());
    }
    Ok(())
}

/// The existing item tidied to the convention (FR-43), or `None` when it already follows it.
fn tidy_layout(
    recipe: &Recipe,
    vault: &str,
    item_id: &str,
    raw: &[u8],
    ui: &mut dyn Interaction,
) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
    use crate::adapters::onepassword_tidy;
    use crate::domain::convention;
    let fleet = config::parse(&recipe.manifest(vault, item_id)?)?;
    let (layout, _) = onepassword_tidy::parse(raw)?;
    let plan = convention::plan(&layout, &fleet, &recipe.environment, &super::tidy::today());
    if plan.is_empty() {
        return Ok(None);
    }
    ui.show(&format!(
        "Tidying the item to opv's layout: {}.",
        plan.summary()
    ))?;
    onepassword_tidy::apply(raw, &plan).map(Some)
}

#[cfg(test)]
#[path = "setup_tests.rs"]
mod tests;
