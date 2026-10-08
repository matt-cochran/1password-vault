use super::*;
use std::cell::RefCell;
use std::collections::VecDeque;

type RecordedCalls = Vec<(Vec<String>, Option<Vec<u8>>)>;
struct Fake {
    replies: RefCell<VecDeque<Output>>,
    calls: RefCell<RecordedCalls>,
    logins: Vec<bool>,
}
impl Fake {
    fn new(replies: Vec<Output>) -> Self {
        Self {
            replies: RefCell::new(replies.into()),
            calls: RefCell::new(Vec::new()),
            logins: Vec::new(),
        }
    }
}
impl Backend for Fake {
    fn native(&self) -> Result<(), Error> {
        Ok(())
    }
    fn call(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Output, Error> {
        self.calls.borrow_mut().push((
            args.iter().map(|s| s.to_string()).collect(),
            stdin.map(<[u8]>::to_vec),
        ));
        Ok(self
            .replies
            .borrow_mut()
            .pop_front()
            .expect("unexpected call"))
    }
    fn sign_in(&mut self, _: Option<&str>, add: bool) -> Result<(), Error> {
        self.logins.push(add);
        Ok(())
    }
}
struct Ui {
    confirms: VecDeque<bool>,
    values: VecDeque<SecretValue>,
    messages: Vec<String>,
}
impl Ui {
    fn new(confirms: Vec<bool>, values: &[&str]) -> Self {
        Self {
            confirms: confirms.into(),
            values: values
                .iter()
                .map(|s| SecretValue::new((*s).into()))
                .collect(),
            messages: Vec::new(),
        }
    }
}
impl Interaction for Ui {
    fn show(&mut self, s: &str) -> Result<(), Error> {
        self.messages.push(s.into());
        Ok(())
    }
    fn confirm(&mut self, s: &str) -> Result<bool, Error> {
        self.messages.push(s.into());
        Ok(self.confirms.pop_front().expect("unexpected confirmation"))
    }
    fn secret(&mut self, _: &str) -> Result<SecretValue, Error> {
        Ok(self.values.pop_front().expect("unexpected value prompt"))
    }
}
fn ok(value: &str) -> Output {
    Output::success(value.as_bytes().to_vec())
}
fn recipe(dir: &Path) -> PathBuf {
    let path = dir.join("opv.setup.toml");
    fs::write(&path, "title='Local example'\nenvironment='dev'\nvault='Development'\nitem='api'\n[[fields]]\nkey='API_KEY'\ntitle='Provider login'\ndescription='Lets this API call its provider.'\nsource='Your provider dashboard.'\n").unwrap();
    path
}
fn metadata() -> Vec<Output> {
    vec![
        ok("2.40.0"),
        ok(r#"[{"id":"vault-id","name":"Development"}]"#),
    ]
}

#[test]
fn missing_item_is_created_with_hidden_input_and_metadata_only_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut replies = metadata();
    replies.extend([
        ok("[]"),
        ok(r#"{"id":"item-id","fields":[{"value":"synthetic-private"}]}"#),
    ]);
    let mut backend = Fake::new(replies);
    let mut ui = Ui::new(vec![true], &["synthetic-private"]);
    assert_eq!(
        run(&path, None, None, None, &mut backend, &mut ui).unwrap(),
        0
    );
    let output = fs::read_to_string(dir.path().join("secrets.toml")).unwrap();
    assert!(!output.contains("synthetic-private"));
    assert!(!ui.messages.join("\n").contains("synthetic-private"));
    let calls = backend.calls.borrow();
    assert!(
        !format!("{:?}", calls.iter().map(|c| &c.0).collect::<Vec<_>>())
            .contains("synthetic-private")
    );
    let body: Value = serde_json::from_slice(calls.last().unwrap().1.as_ref().unwrap()).unwrap();
    assert_eq!(body["fields"][0]["value"], "synthetic-private");
    assert_eq!(calls.last().unwrap().0[1], "create");
}

#[test]
fn skipping_a_value_saves_resumable_progress_and_exits_findings() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut replies = metadata();
    replies.extend([ok("[]"), ok(r#"{"id":"item-id"}"#)]);
    let mut backend = Fake::new(replies);
    let mut ui = Ui::new(vec![true], &[""]);
    assert_eq!(
        run(&path, None, None, None, &mut backend, &mut ui).unwrap(),
        8
    );
    assert!(ui.messages.join("\n").contains("Provider login"));
    assert!(ui.messages.join("\n").contains("Saved progress"));
    assert!(dir.path().join("secrets.toml").exists());
}

#[test]
fn repeated_setup_keeps_existing_value_and_makes_no_write_or_prompt() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut replies = metadata();
    replies.extend([ok(r#"[{"id":"item-id","title":"api"}]"#),ok(r#"{"category":"SECURE_NOTE","sections":[],"fields":[{"id":"key","label":"API_KEY","type":"CONCEALED","value":"synthetic-existing"}]}"#)]);
    let mut backend = Fake::new(replies);
    let mut ui = Ui::new(vec![], &[]);
    assert_eq!(
        run(&path, None, None, None, &mut backend, &mut ui).unwrap(),
        0
    );
    assert!(
        !backend
            .calls
            .borrow()
            .iter()
            .any(|c| c.0.get(1).is_some_and(|s| s == "edit" || s == "create"))
    );
    assert!(!ui.messages.join("\n").contains("synthetic-existing"));
}

#[test]
fn cancel_before_create_does_not_write_item_or_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut replies = metadata();
    replies.push(ok("[]"));
    let mut backend = Fake::new(replies);
    let mut ui = Ui::new(vec![false], &[""]);
    assert_eq!(
        run(&path, None, None, None, &mut backend, &mut ui).unwrap(),
        6
    );
    assert!(!dir.path().join("secrets.toml").exists());
    assert_eq!(backend.calls.borrow().len(), 3);
}

#[test]
fn failed_authentication_is_repaired_then_vault_access_is_verified() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut backend = Fake::new(vec![
        ok("2.40.0"),
        Output::failure(1),
        Output::failure(1),
        ok("[]"),
        ok(r#"[{"id":"vault-id","name":"Development"}]"#),
        ok("[]"),
        ok(r#"{"id":"item-id"}"#),
    ]);
    let mut ui = Ui::new(vec![true], &[""]);
    assert_eq!(
        run(&path, None, None, None, &mut backend, &mut ui).unwrap(),
        8
    );
    assert_eq!(backend.logins, vec![true, false]);
}

#[test]
fn wrong_kind_has_specific_repair_and_preserves_existing_item() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut replies = metadata();
    replies.extend([ok(r#"[{"id":"item-id","title":"api"}]"#),ok(r#"{"category":"SECURE_NOTE","fields":[{"label":"API_KEY","type":"STRING","value":"synthetic-private"}]}"#)]);
    let mut backend = Fake::new(replies);
    let mut ui = Ui::new(vec![], &[]);
    let error = run(&path, None, None, None, &mut backend, &mut ui).unwrap_err();
    assert!(error.to_string().contains("Password / concealed"));
    assert!(!error.to_string().contains("synthetic-private"));
    assert_eq!(backend.calls.borrow().len(), 4);
}

#[test]
fn conflicting_configuration_is_refused_before_any_vendor_call() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let recipe = Recipe::parse(&fs::read_to_string(&path).unwrap()).unwrap();
    fs::write(
        dir.path().join("secrets.toml"),
        recipe
            .manifest("other-vault", "other-item")
            .unwrap()
            .replace("API_KEY", "OTHER_KEY"),
    )
    .unwrap();
    let mut backend = Fake::new(vec![]);
    let mut ui = Ui::new(vec![], &[]);
    assert!(run(&path, None, None, None, &mut backend, &mut ui).is_err());
    assert!(backend.calls.borrow().is_empty());
}

#[test]
fn duplicate_vault_is_refused_without_guessing_or_writing() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut backend = Fake::new(vec![
        ok("2.40.0"),
        ok(r#"[{"id":"a","name":"Development"},{"id":"b","name":"Development"}]"#),
    ]);
    let mut ui = Ui::new(vec![], &[]);
    let error = run(&path, None, None, None, &mut backend, &mut ui).unwrap_err();
    assert!(error.to_string().contains("Rename the duplicate"));
    assert_eq!(backend.calls.borrow().len(), 2);
}

#[test]
fn shared_keys_have_unique_ids_and_keep_product_sections() {
    let recipe = Recipe::parse("title='Products'\nenvironment='dev'\nvault='Development'\nitem='api'\n[[fields]]\nkey='API_KEY'\nproduct='one'\ntitle='One login'\ndescription='For one.'\nsource='Dashboard.'\n[[fields]]\nkey='API_KEY'\nproduct='two'\ntitle='Two login'\ndescription='For two.'\nsource='Dashboard.'\n").unwrap();
    let mut doc = json!({"category":"SECURE_NOTE","fields":[],"sections":[]});
    let indices = field_indices(&mut doc, &recipe.fields).unwrap();
    assert_ne!(
        doc["fields"][indices[0]]["id"],
        doc["fields"][indices[1]]["id"]
    );
    assert_eq!(doc["fields"][indices[1]]["section"]["label"], "two");
    assert_eq!(field_indices(&mut doc, &recipe.fields).unwrap(), indices);
}

#[test]
fn product_setup_prompts_only_selected_product_but_declares_all_managed_names() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("opv.setup.toml");
    fs::write(&path, "title='Products'\nenvironment='dev'\nvault='Development'\nitem='api'\n[[fields]]\nkey='ONE_KEY'\nproduct='one'\ntitle='One login'\ndescription='For one.'\nsource='Dashboard.'\n[[fields]]\nkey='TWO_KEY'\nproduct='two'\ntitle='Two login'\ndescription='For two.'\nsource='Dashboard.'\n").unwrap();
    let mut replies = metadata();
    replies.extend([ok("[]"), ok(r#"{"id":"item-id"}"#)]);
    let mut backend = Fake::new(replies);
    let mut ui = Ui::new(vec![true], &["synthetic-one"]);
    assert_eq!(
        run(&path, None, None, Some("one"), &mut backend, &mut ui).unwrap(),
        0
    );
    let config = fs::read_to_string(dir.path().join("secrets.toml")).unwrap();
    assert!(config.contains("ONE_KEY") && config.contains("TWO_KEY"));
    assert!(!ui.messages.join("\n").contains("Two login"));
    let calls = backend.calls.borrow();
    let body: Value = serde_json::from_slice(calls.last().unwrap().1.as_ref().unwrap()).unwrap();
    assert_eq!(body["fields"].as_array().unwrap().len(), 1);
}
