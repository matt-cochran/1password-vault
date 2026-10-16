use super::*;

/// A command's own document as `--json` frames it on success.
fn framed<T: serde::Serialize>(doc: &T) -> Vec<u8> {
    crate::json::finish(&serde_json::to_vec(doc).unwrap(), Ok(()), false)
}

/// The UI fixture configuration, parsed by opv.
fn fleet() -> crate::domain::Fleet {
    crate::config::parse(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ui/config.toml"),
        )
        .unwrap(),
    )
    .unwrap()
}

fn missing_row(product: &str, key: &str, target: crate::domain::TargetState) -> crate::domain::Row {
    crate::domain::Row {
        product: product.into(),
        key: key.into(),
        kind: crate::domain::Kind::Secret,
        state: crate::domain::KeyState::Missing,
        target,
        guidance: String::new(),
        source: None,
        shared_by: Vec::new(),
    }
}

fn account_report() -> AccountsDoc {
    AccountsDoc {
        discovery: "op_account_list".into(),
        platform: "linux".into(),
        cli_accounts_only: false,
        selected: Some(crate::app::account::Selected {
            account_id: "ACC1".into(),
            by: "flag".into(),
            source: "--account".into(),
        }),
        accounts: vec![crate::app::account::AccountRow {
            account_id: "ACC1".into(),
            user_id: "U1".into(),
            email: "a@example.com".into(),
            address: "example.1password.com".into(),
            shorthand: "ex".into(),
            source: "cli".into(),
            signed_in: Some(true),
            selected: true,
        }],
        findings: Vec::new(),
        next: None,
    }
}

/// `status ci --json` as `write_json` writes it for one target, with a plan id.
fn status_document() -> Vec<u8> {
    let fleet = fleet();
    let plan = crate::domain::SyncPlan {
        rows: vec![missing_row(
            "api",
            "API_TOKEN",
            crate::domain::TargetState::Absent,
        )],
        extras: Vec::new(),
        stage: Vec::new(),
        held_immutable: Vec::new(),
        prune: Vec::new(),
        held_from_prune: Vec::new(),
        config: Default::default(),
        concealed_config: Vec::new(),
        drift: Vec::new(),
        undelivered: Vec::new(),
        unreferenced_sources: Vec::new(),
        tidy: Vec::new(),
        tidy_error: None,
    };
    let parts = [crate::app::JsonPart {
        target: "app",
        plan: &plan,
        pinned: None,
        rotate: None,
        vars: None,
    }];
    let mut out = Vec::new();
    crate::app::write_json(
        &mut out,
        &fleet,
        "ci",
        &parts,
        None,
        &crate::app::JsonExtra {
            plan_id: Some("plan-1"),
            ..Default::default()
        },
    )
    .unwrap();
    out
}

/// What the CLI writes, read back as the UI reads it: one test per document.
mod documents_round_trip {
    use super::*;

    #[test]
    fn ready_receipt_findings() {
        let account = account_report();
        let inputs = crate::app::ready::Inputs {
            config_source: Some("secrets.toml".into()),
            account: &account,
            envs: vec![crate::app::ready::EnvInput {
                name: "local".into(),
                target: None,
                rows: Ok(vec![missing_row(
                    "api",
                    "API_TOKEN",
                    crate::domain::TargetState::Unknown,
                )]),
                title: None,
                audience: None,
            }],
            personal: Default::default(),
            health: Vec::new(),
        };
        let receipt = crate::app::ready::receipt(&inputs, "0.10.0");
        let doc: ReadyDoc = parse(&framed(&receipt)).unwrap();
        assert_eq!(doc.findings, receipt.findings);
    }

    #[test]
    fn status_rows_target_state() {
        let doc: RowsDoc = parse(&status_document()).unwrap();
        assert_eq!(doc.rows[0].target_state.as_deref(), Some("absent"));
    }

    #[test]
    fn status_rows_target_name() {
        let doc: RowsDoc = parse(&status_document()).unwrap();
        assert_eq!(doc.rows[0].target.as_deref(), Some("app"));
    }

    #[test]
    fn plan_id() {
        let doc: RowsDoc = parse(&status_document()).unwrap();
        assert_eq!(doc.plan_id.as_deref(), Some("plan-1"));
    }

    #[test]
    fn findings_keep_their_rows() {
        let e: crate::error::Error = crate::cause::Cause::ValuesNeeded {
            env: crate::cause::EnvName::new("ci"),
            rows: Vec::new(),
        }
        .into();
        let out = crate::json::finish(&status_document(), Err(&e), false);
        assert!(parse::<RowsDoc>(&out).is_ok());
    }

    #[test]
    fn history_rows_of_several_targets() {
        let keys = [crate::domain::history::KeyRef {
            product: "api",
            key: "API_TOKEN",
            name: "API_TOKEN",
        }];
        let rows = crate::domain::history::build(&keys, &[], &Default::default());
        let doc = serde_json::json!({
            "schema_version": 2,
            "environment": "prod",
            "targets": [
                {"name": "api", "target": "fly", "latest": null, "rows": rows},
                {"name": "ci", "target": "github", "latest": null, "rows": rows},
            ],
        });
        let read: HistoryDoc = parse(&serde_json::to_vec(&doc).unwrap()).unwrap();
        assert_eq!(read.parts()[1].rows[0].state, rows[0].state);
    }

    #[test]
    fn access_report() {
        use crate::domain::access_plan::{Grant, GrantCheck, GrantState, Permission, Principal};
        let report = AccessReport {
            checks: vec![GrantCheck {
                grant: Grant {
                    principal: Principal::CiReader {
                        environment: "ci".into(),
                    },
                    service_account: "app-ci-reader".into(),
                    vault_id: "vsmoke".into(),
                    permission: Permission::Read,
                },
                state: GrantState::Missing,
            }],
            extra: Vec::new(),
            checked: 1,
            unclassified: 0,
        };
        let doc = serde_json::json!({ "environments": [{
            "environment": "ci", "report": report, "commands": [], "findings": [],
        }]});
        let read: AccessDoc = parse(&framed(&doc)).unwrap();
        assert_eq!(read.environments[0].report, report);
    }

    #[test]
    fn account_report_round_trips() {
        let report = account_report();
        let read: AccountsDoc = parse(&framed(&report)).unwrap();
        assert_eq!(read, report);
    }

    #[test]
    fn configuration_export() {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ui/config.toml"),
        )
        .unwrap();
        let value: toml::Value = toml::from_str(&text).unwrap();
        let exported = serde_json::to_vec_pretty(&value).unwrap();
        assert_eq!(
            parse_config(&exported).unwrap().environments.keys().count(),
            2
        );
    }

    #[test]
    fn a_catalog_failure_is_an_error() {
        let cause = crate::cause::Cause::NeedsTerminal {
            why: crate::cause::NoTerminal::NoTty,
        };
        let message = cause.message();
        let e = crate::error::Error::from(cause);
        let out = crate::json::finish(b"", Err(&e), false);
        assert!(matches!(parse::<ReadyDoc>(&out), Err(Failure::Error(d)) if d.message == message));
    }
}

#[test]
fn a_failure_document_is_never_data() {
    let out = br#"{"schema_version":2,"ok":false,"exit_code":7,"rows":[],"totals":{"findings":0},"error":{"code":"op_not_signed_in","message":"not signed in","next":"opv login"}}"#;
    assert!(parse::<RowsDoc>(out).is_err());
}

#[test]
fn a_failure_shows_its_steps() {
    let f = Failure::Error(ErrorDoc {
        code: "op_not_signed_in".into(),
        message: "1Password CLI is not signed in".into(),
        act: Some("unlock the 1Password app".into()),
        next: Some("opv login".into()),
    });
    assert_eq!(
        f.to_string(),
        "1Password CLI is not signed in · Do: unlock the 1Password app · Next: opv login"
    );
}

#[test]
fn no_json_is_no_document() {
    assert!(matches!(
        parse::<RowsDoc>(b"opv: oops"),
        Err(Failure::NoDocument(_))
    ));
}
