//! Access planning (FR-59): one behavioural outcome per test, observed through the public
//! API. Only service-account names appear; no value, digest or fingerprint is ever built.

use super::*;
use crate::domain::access::Reader;

/// A target's needs with `vaults` as its boundary vaults.
fn target<'a>(
    environment: &'a str,
    name: &'a str,
    vaults: &[&'a str],
    state: &'a str,
) -> TargetNeeds<'a> {
    TargetNeeds {
        environment,
        target: name,
        boundary_vaults: vaults.iter().copied().collect(),
        state_vault: state,
    }
}

/// A CI entry's needs with `vaults` as its boundary vaults.
fn ci_needs<'a>(environment: &'a str, vaults: &[&'a str]) -> CiNeeds<'a> {
    CiNeeds {
        environment,
        boundary_vaults: vaults.iter().copied().collect(),
    }
}

fn deploy(environment: &str, name: &str) -> Principal {
    Principal::Deploy {
        environment: environment.to_string(),
        target: name.to_string(),
    }
}

fn ci(environment: &str) -> Principal {
    Principal::CiReader {
        environment: environment.to_string(),
    }
}

fn grant(principal: Principal, account: &str, vault_id: &str, permission: Permission) -> Grant {
    Grant {
        principal,
        service_account: account.to_string(),
        vault_id: vault_id.to_string(),
        permission,
    }
}

fn reader(name: &str, read_only: bool) -> Reader {
    Reader {
        name: name.to_string(),
        read_only,
    }
}

// --- account names -----------------------------------------------------------------

#[test]
fn deploy_account_names_the_target_identity() {
    assert_eq!(
        deploy_account("shop", "prod", "web"),
        "shop-prod-web-deploy"
    );
}

#[test]
fn ci_account_names_the_environment_reader() {
    assert_eq!(ci_account("shop", "prod"), "shop-prod-ci");
}

// --- required ----------------------------------------------------------------------

#[test]
fn a_target_reads_each_boundary_vault_and_writes_its_state_vault() {
    let grants = required(
        "shop",
        &[target("prod", "web", &["shared", "web"], "web-state")],
        &[],
    );
    assert_eq!(
        grants,
        [
            grant(
                deploy("prod", "web"),
                "shop-prod-web-deploy",
                "shared",
                Permission::Read
            ),
            grant(
                deploy("prod", "web"),
                "shop-prod-web-deploy",
                "web",
                Permission::Read
            ),
            grant(
                deploy("prod", "web"),
                "shop-prod-web-deploy",
                "web-state",
                Permission::ReadWrite
            ),
        ]
    );
}

#[test]
fn a_ci_reader_reads_each_boundary_vault() {
    let grants = required("shop", &[], &[ci_needs("prod", &["shared", "web"])]);
    assert_eq!(
        grants,
        [
            grant(ci("prod"), "shop-prod-ci", "shared", Permission::Read),
            grant(ci("prod"), "shop-prod-ci", "web", Permission::Read),
        ]
    );
}

#[test]
fn required_sorts_deploy_grants_before_ci_grants_and_by_vault_id() {
    let grants = required(
        "shop",
        &[target("prod", "web", &["b"], "sb")],
        &[ci_needs("prod", &["a", "c"])],
    );
    let vaults: Vec<&str> = grants.iter().map(|grant| grant.vault_id.as_str()).collect();
    assert_eq!(vaults, ["b", "sb", "a", "c"]);
}

#[test]
fn required_removes_a_repeated_ci_grant() {
    let grants = required(
        "shop",
        &[],
        &[ci_needs("prod", &["shared"]), ci_needs("prod", &["shared"])],
    );
    assert_eq!(
        grants,
        [grant(
            ci("prod"),
            "shop-prod-ci",
            "shared",
            Permission::Read
        )]
    );
}

// --- compare: state of one grant ---------------------------------------------------

#[test]
fn a_grant_on_an_unobserved_vault_is_not_visible() {
    let grants = [grant(
        deploy("prod", "web"),
        "shop-prod-web-deploy",
        "b",
        Permission::Read,
    )];
    assert_eq!(
        compare(&grants, &[]).checks[0].state,
        GrantState::NotVisible
    );
}

#[test]
fn a_vault_with_unknown_readers_is_not_visible() {
    let grants = [grant(
        deploy("prod", "web"),
        "shop-prod-web-deploy",
        "b",
        Permission::Read,
    )];
    let observed = [ObservedVault {
        vault_id: "b",
        readers: None,
    }];
    assert_eq!(
        compare(&grants, &observed).checks[0].state,
        GrantState::NotVisible
    );
}

#[test]
fn a_grant_with_no_matching_reader_is_missing() {
    let grants = [grant(
        deploy("prod", "web"),
        "shop-prod-web-deploy",
        "b",
        Permission::Read,
    )];
    let readers = [reader("someone-else", true)];
    let observed = [ObservedVault {
        vault_id: "b",
        readers: Some(&readers),
    }];
    assert_eq!(
        compare(&grants, &observed).checks[0].state,
        GrantState::Missing
    );
}

#[test]
fn a_read_grant_whose_reader_can_write_needs_read_only() {
    let grants = [grant(
        deploy("prod", "web"),
        "shop-prod-web-deploy",
        "b",
        Permission::Read,
    )];
    let readers = [reader("shop-prod-web-deploy", false)];
    let observed = [ObservedVault {
        vault_id: "b",
        readers: Some(&readers),
    }];
    assert_eq!(
        compare(&grants, &observed).checks[0].state,
        GrantState::ReadOnlyNeeded
    );
}

#[test]
fn a_read_grant_whose_reader_is_read_only_is_present() {
    let grants = [grant(
        deploy("prod", "web"),
        "shop-prod-web-deploy",
        "b",
        Permission::Read,
    )];
    let readers = [reader("shop-prod-web-deploy", true)];
    let observed = [ObservedVault {
        vault_id: "b",
        readers: Some(&readers),
    }];
    assert_eq!(
        compare(&grants, &observed).checks[0].state,
        GrantState::Present
    );
}

#[test]
fn a_read_write_grant_whose_reader_can_write_is_present() {
    let grants = [grant(
        deploy("prod", "web"),
        "shop-prod-web-deploy",
        "b",
        Permission::ReadWrite,
    )];
    let readers = [reader("shop-prod-web-deploy", false)];
    let observed = [ObservedVault {
        vault_id: "b",
        readers: Some(&readers),
    }];
    assert_eq!(
        compare(&grants, &observed).checks[0].state,
        GrantState::Present
    );
}

// --- compare: extra readers --------------------------------------------------------

#[test]
fn an_observed_reader_no_grant_names_is_extra() {
    let grants = [grant(
        deploy("prod", "web"),
        "shop-prod-web-deploy",
        "b",
        Permission::Read,
    )];
    let readers = [
        reader("shop-prod-web-deploy", true),
        reader("stranger", false),
    ];
    let observed = [ObservedVault {
        vault_id: "b",
        readers: Some(&readers),
    }];
    assert_eq!(
        compare(&grants, &observed).extra,
        [Extra {
            vault_id: "b".to_string(),
            service_account: "stranger".to_string(),
        }]
    );
}

#[test]
fn extra_lists_readers_of_a_vault_no_grant_needs() {
    let readers = [reader("stranger", false)];
    let observed = [ObservedVault {
        vault_id: "b",
        readers: Some(&readers),
    }];
    assert_eq!(
        compare(&[], &observed).extra,
        [Extra {
            vault_id: "b".to_string(),
            service_account: "stranger".to_string(),
        }]
    );
}

#[test]
fn extra_is_empty_when_every_reader_is_named() {
    let grants = [grant(
        deploy("prod", "web"),
        "shop-prod-web-deploy",
        "b",
        Permission::Read,
    )];
    let readers = [reader("shop-prod-web-deploy", true)];
    let observed = [ObservedVault {
        vault_id: "b",
        readers: Some(&readers),
    }];
    assert!(compare(&grants, &observed).extra.is_empty());
}

#[test]
fn extra_sorts_by_vault_id_then_service_account() {
    let first = [reader("z", true), reader("a", true)];
    let second = [reader("m", true)];
    let observed = [
        ObservedVault {
            vault_id: "b",
            readers: Some(&first),
        },
        ObservedVault {
            vault_id: "a",
            readers: Some(&second),
        },
    ];
    assert_eq!(
        compare(&[], &observed).extra,
        [
            Extra {
                vault_id: "a".to_string(),
                service_account: "m".to_string(),
            },
            Extra {
                vault_id: "b".to_string(),
                service_account: "a".to_string(),
            },
            Extra {
                vault_id: "b".to_string(),
                service_account: "z".to_string(),
            },
        ]
    );
}

// --- compare: checks and counts ----------------------------------------------------

#[test]
fn checks_keep_the_required_order() {
    let grants = [
        grant(
            deploy("prod", "web"),
            "shop-prod-web-deploy",
            "b",
            Permission::Read,
        ),
        grant(
            deploy("prod", "web"),
            "shop-prod-web-deploy",
            "a",
            Permission::Read,
        ),
    ];
    let readers = [reader("shop-prod-web-deploy", true)];
    let observed = [
        ObservedVault {
            vault_id: "a",
            readers: Some(&readers),
        },
        ObservedVault {
            vault_id: "b",
            readers: Some(&readers),
        },
    ];
    let report = compare(&grants, &observed);
    let order: Vec<&str> = report
        .checks
        .iter()
        .map(|check| check.grant.vault_id.as_str())
        .collect();
    assert_eq!(order, ["b", "a"]);
}

#[test]
fn checked_counts_grants_that_have_a_visible_vault() {
    let grants = [
        grant(
            deploy("prod", "web"),
            "shop-prod-web-deploy",
            "a",
            Permission::Read,
        ),
        grant(
            deploy("prod", "web"),
            "shop-prod-web-deploy",
            "b",
            Permission::Read,
        ),
    ];
    let readers_a = [reader("shop-prod-web-deploy", true)];
    let readers_b = [reader("someone-else", true)];
    let observed = [
        ObservedVault {
            vault_id: "a",
            readers: Some(&readers_a),
        },
        ObservedVault {
            vault_id: "b",
            readers: Some(&readers_b),
        },
    ];
    assert_eq!(compare(&grants, &observed).checked, 2);
}

#[test]
fn checked_excludes_grants_whose_vault_is_not_visible() {
    let grants = [
        grant(
            deploy("prod", "web"),
            "shop-prod-web-deploy",
            "a",
            Permission::Read,
        ),
        grant(
            deploy("prod", "web"),
            "shop-prod-web-deploy",
            "b",
            Permission::Read,
        ),
    ];
    let readers_a = [reader("shop-prod-web-deploy", true)];
    let observed = [ObservedVault {
        vault_id: "a",
        readers: Some(&readers_a),
    }];
    assert_eq!(compare(&grants, &observed).checked, 1);
}

#[test]
fn unclassified_counts_grants_whose_vault_is_not_visible() {
    let grants = [
        grant(
            deploy("prod", "web"),
            "shop-prod-web-deploy",
            "a",
            Permission::Read,
        ),
        grant(
            deploy("prod", "web"),
            "shop-prod-web-deploy",
            "b",
            Permission::Read,
        ),
    ];
    let readers_a = [reader("shop-prod-web-deploy", true)];
    let observed = [ObservedVault {
        vault_id: "a",
        readers: Some(&readers_a),
    }];
    assert_eq!(compare(&grants, &observed).unclassified, 1);
}

// --- create_command ----------------------------------------------------------------

#[test]
fn create_command_is_none_for_no_grants() {
    assert_eq!(create_command(&[]), None);
}

#[test]
fn create_command_creates_the_account_with_its_vault_grants_and_expiry() {
    let grants = [
        grant(
            deploy("prod", "web"),
            "shop-prod-web-deploy",
            "b",
            Permission::Read,
        ),
        grant(
            deploy("prod", "web"),
            "shop-prod-web-deploy",
            "sb",
            Permission::ReadWrite,
        ),
    ];
    assert_eq!(
        create_command(&grants).as_deref(),
        Some(
            "op service-account create \"shop-prod-web-deploy\" --vault b:read_items \
             --vault sb:read_items,write_items --expires-in 90d"
        )
    );
}
