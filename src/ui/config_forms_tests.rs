use super::*;

/// `["a", "b"]` as a `Vec<String>` for command comparisons.
fn v(parts: &[&str]) -> Vec<String> {
    parts.iter().copied().map(str::to_string).collect()
}

/// A fleet key form with everything unset, so a test only states what it exercises.
fn key_form() -> AddKeyForm {
    AddKeyForm {
        product: Some("api".to_string()),
        key: "TOKEN".to_string(),
        kind: KindChoice::Secret,
        environments: Vec::new(),
        guidance: String::new(),
        personal: false,
        allow_same_value: false,
    }
}

/// An environment form with everything unset, so a test only states what it exercises.
fn env_form() -> AddEnvForm {
    AddEnvForm {
        name: "dev".to_string(),
    }
}

// ---- add_key_command: the command ----

#[test]
fn add_key_builds_the_full_fleet_command_in_order() {
    let form = AddKeyForm {
        product: Some("api".to_string()),
        key: "TOKEN".to_string(),
        kind: KindChoice::Secret,
        environments: vec!["dev".to_string(), "prod".to_string()],
        guidance: "  fill it at the portal  ".to_string(),
        personal: true,
        allow_same_value: false,
    };
    assert_eq!(
        add_key_command(&form),
        Ok(v(&[
            "add",
            "api/TOKEN",
            "--kind",
            "secret",
            "--env",
            "dev,prod",
            "--guidance",
            "fill it at the portal",
            "--personal",
        ]))
    );
}

#[test]
fn add_key_writes_the_config_kind_choice() {
    let form = AddKeyForm {
        kind: KindChoice::Config,
        ..key_form()
    };
    assert_eq!(
        add_key_command(&form),
        Ok(v(&["add", "api/TOKEN", "--kind", "config"]))
    );
}

#[test]
fn add_key_adds_allow_same_value_when_set() {
    let form = AddKeyForm {
        allow_same_value: true,
        ..key_form()
    };
    assert_eq!(
        add_key_command(&form),
        Ok(v(&[
            "add",
            "api/TOKEN",
            "--kind",
            "secret",
            "--allow-same-value",
        ]))
    );
}

// ---- add_key_command: the refusals ----

#[test]
fn add_key_rejects_a_key_that_is_not_uppercase() {
    let form = AddKeyForm {
        key: "token".to_string(),
        ..key_form()
    };
    assert_eq!(
        add_key_command(&form),
        Err(
            "key \"token\" is not a valid name: start with a capital letter and use A-Z, 0-9 or _."
                .to_string()
        )
    );
}

#[test]
fn add_key_rejects_an_empty_key() {
    let form = AddKeyForm {
        key: String::new(),
        ..key_form()
    };
    assert_eq!(
        add_key_command(&form),
        Err(
            "key \"\" is not a valid name: start with a capital letter and use A-Z, 0-9 or _."
                .to_string()
        )
    );
}

#[test]
fn add_key_rejects_a_product_that_is_not_lowercase() {
    let form = AddKeyForm {
        product: Some("API".to_string()),
        ..key_form()
    };
    assert_eq!(
        add_key_command(&form),
        Err(
            "product \"API\" is not a valid name: start with a lowercase letter and use \
             a-z, 0-9, _ or -."
                .to_string()
        )
    );
}

#[test]
fn add_key_rejects_an_empty_product() {
    let form = AddKeyForm {
        product: Some(String::new()),
        ..key_form()
    };
    assert_eq!(
        add_key_command(&form),
        Err(
            "product \"\" is not a valid name: start with a lowercase letter and use \
             a-z, 0-9, _ or -."
                .to_string()
        )
    );
}

#[test]
fn add_key_without_a_product_is_refused() {
    let form = AddKeyForm {
        product: None,
        ..key_form()
    };
    assert_eq!(
        add_key_command(&form),
        Err("keys are declared per product: use PRODUCT/KEY.".to_string())
    );
}

#[test]
fn add_key_rejects_personal_with_allow_same_value() {
    let form = AddKeyForm {
        personal: true,
        allow_same_value: true,
        ..key_form()
    };
    assert_eq!(
        add_key_command(&form),
        Err("personal and allow_same_value cannot both be set.".to_string())
    );
}

#[test]
fn add_key_rejects_personal_with_a_config_key() {
    let form = AddKeyForm {
        kind: KindChoice::Config,
        personal: true,
        ..key_form()
    };
    assert_eq!(
        add_key_command(&form),
        Err("personal keys must be secret, not config.".to_string())
    );
}

// ---- add_env_command ----

#[test]
fn add_env_builds_the_written_proposal_of_the_environment() {
    let form = AddEnvForm {
        name: "staging".to_string(),
    };
    assert_eq!(
        add_env_command(&form, &[]),
        Ok(v(&["propose", "env", "staging", "--write"]))
    );
}

#[test]
fn add_env_rejects_a_name_with_a_space() {
    let form = AddEnvForm {
        name: "bad name".to_string(),
        ..env_form()
    };
    assert_eq!(
        add_env_command(&form, &[]),
        Err(
            "environment name \"bad name\" is not a valid name: start with a letter or digit \
             and use A-Z, a-z, 0-9, _ or -."
                .to_string()
        )
    );
}

#[test]
fn add_env_rejects_an_empty_name() {
    let form = AddEnvForm {
        name: String::new(),
        ..env_form()
    };
    assert_eq!(
        add_env_command(&form, &[]),
        Err(
            "environment name \"\" is not a valid name: start with a letter or digit \
             and use A-Z, a-z, 0-9, _ or -."
                .to_string()
        )
    );
}

#[test]
fn add_env_rejects_a_name_already_declared() {
    let existing = vec!["dev".to_string(), "prod".to_string()];
    assert_eq!(
        add_env_command(&env_form(), &existing),
        Err("environment dev already exists.".to_string())
    );
}

// ---- refusals describe the naming rule in words, never a pattern ----

#[test]
fn add_key_refusal_states_the_naming_rule_without_a_pattern() {
    let form = AddKeyForm {
        key: "token".to_string(),
        ..key_form()
    };
    let message = add_key_command(&form).unwrap_err();
    assert!(message.contains("start with a capital letter"), "{message}");
}

#[test]
fn add_key_product_refusal_states_the_naming_rule_without_a_pattern() {
    let form = AddKeyForm {
        product: Some("API".to_string()),
        ..key_form()
    };
    let message = add_key_command(&form).unwrap_err();
    assert!(
        message.contains("start with a lowercase letter"),
        "{message}"
    );
}

#[test]
fn add_env_refusal_states_the_naming_rule_without_a_pattern() {
    let form = AddEnvForm {
        name: "bad name".to_string(),
        ..env_form()
    };
    let message = add_env_command(&form, &[]).unwrap_err();
    assert!(
        message.contains("start with a letter or digit"),
        "{message}"
    );
}
