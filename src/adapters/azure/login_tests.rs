//! Azure deploy credentials (FR-40, SR-3, SR-4). The RAM check is injected, so these run
//! on any Unix with a temporary directory standing in for `$XDG_RUNTIME_DIR`.

use super::*;
use crate::ramdir::private_dir;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;
use crate::runner::signals;

const SECRET: &str = "sp-secret-FIXTUREVALUE";

fn values() -> BTreeMap<String, SecretValue> {
    [
        ("AZURE_TENANT_ID", "00000000-0000-0000-0000-00000000000a"),
        ("AZURE_CLIENT_ID", "00000000-0000-0000-0000-00000000000b"),
        ("AZURE_CLIENT_SECRET", SECRET),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), SecretValue::new(v.into())))
    .collect()
}

fn ram(_: &Path) -> io::Result<bool> {
    Ok(true)
}

fn login_in(runtime: &Path) -> AzureLogin {
    start_in(Some(runtime.as_os_str().to_owned()), &ram).unwrap()
}

#[test]
fn non_ram_runtime_dir_is_refused_before_anything_is_read() {
    let tmp = tempfile::tempdir().unwrap();
    let e = match start_in(Some(tmp.path().as_os_str().to_owned()), &|_| Ok(false)) {
        Err(e) => e,
        Ok(_) => panic!("a disk-backed directory must be refused"),
    };
    assert_eq!(
        e.cause().map(|(c, _)| c.clone()),
        Some(Cause::RamDirUnavailable {
            remote: None,
            why: RamDir::NotTmpfs,
            purpose: RamPurpose::AzureDeployCredentials,
            env: None,
            product: None,
        })
    );
}

/// A runtime directory given as a relative path is named as such, not as a disk folder.
#[test]
fn relative_runtime_dir_is_refused_as_not_absolute() {
    let e = match start_in(Some("run/user".into()), &ram) {
        Err(e) => e,
        Ok(_) => panic!("a relative runtime directory must be refused"),
    };
    assert!(matches!(
        e.cause(),
        Some((
            Cause::RamDirUnavailable {
                why: RamDir::NotAbsolute,
                ..
            },
            _
        ))
    ));
}

#[test]
fn missing_runtime_dir_is_refused() {
    assert!(start_in(None, &ram).is_err());
}

#[test]
fn run_dir_is_private_and_inside_the_runtime_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let l = login_in(tmp.path());
    assert!(l.dir().starts_with(tmp.path()) && private_dir(l.dir()));
}

#[test]
fn secret_goes_on_stdin_only() {
    let tmp = tempfile::tempdir().unwrap();
    let mut l = login_in(tmp.path());
    let r = FakeRunner::new([Output::success(Vec::new())]);
    l.sign_in(values(), &r).unwrap();
    let calls = r.calls.borrow();
    assert_eq!(
        (
            calls[0].stdin.as_deref(),
            r.argv_contains(SECRET),
            calls[0].env.iter().any(|(_, v)| v.contains(SECRET))
        ),
        (Some(SECRET.as_bytes()), false, false)
    );
}

#[test]
fn login_is_a_service_principal_sign_in_reading_the_secret_from_stdin() {
    let tmp = tempfile::tempdir().unwrap();
    let mut l = login_in(tmp.path());
    let r = FakeRunner::new([Output::success(Vec::new())]);
    l.sign_in(values(), &r).unwrap();
    let args = r.calls.borrow()[0].args.join(" ");
    assert_eq!(
        args,
        "login --service-principal --username=00000000-0000-0000-0000-00000000000b \
         --tenant=00000000-0000-0000-0000-00000000000a -p @/dev/stdin \
         --allow-no-subscriptions --only-show-errors -o none"
    );
}

#[test]
fn login_call_uses_the_private_config_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let mut l = login_in(tmp.path());
    let r = FakeRunner::new([Output::success(Vec::new())]);
    l.sign_in(values(), &r).unwrap();
    let dir = l.dir().to_str().unwrap().to_string();
    assert!(
        r.calls.borrow()[0]
            .env
            .contains(&("AZURE_CONFIG_DIR".to_string(), dir))
    );
}

#[test]
fn every_az_call_gets_the_config_dir_and_no_other_program_does() {
    let tmp = tempfile::tempdir().unwrap();
    let l = login_in(tmp.path());
    let dir = l.dir().to_str().unwrap().to_string();
    assert_eq!(
        (l.env("az").first().copied(), l.env("op"), l.env("flyctl")),
        (Some(("AZURE_CONFIG_DIR", dir.as_str())), vec![], vec![])
    );
}

/// 06.18: a failed service-principal sign-in may be rejected credentials, no network or
/// something else; with no recording of az's wording, opv shows az's reply rather than
/// blame the credentials.
#[test]
fn failed_service_principal_sign_in_is_not_blamed_on_the_credentials() {
    let tmp = tempfile::tempdir().unwrap();
    let mut l = login_in(tmp.path());
    let r = FakeRunner::new([Output::failure(1)]);
    let e = l.sign_in(values(), &r).unwrap_err();
    assert_eq!(e.code_str(), "unrecognized_failure");
}

#[test]
fn failed_sign_in_never_shows_the_secret() {
    let tmp = tempfile::tempdir().unwrap();
    let mut l = login_in(tmp.path());
    let r = FakeRunner::new([Output::failure(1)]);
    let e = l.sign_in(values(), &r).unwrap_err();
    assert!(!format!("{e:?}").contains(SECRET), "{e:?}");
}

#[test]
fn dir_is_removed_after_success() {
    let tmp = tempfile::tempdir().unwrap();
    let mut l = login_in(tmp.path());
    l.sign_in(values(), &FakeRunner::new([Output::success(Vec::new())]))
        .unwrap();
    let dir = l.dir().to_path_buf();
    drop(l);
    assert!(!dir.exists());
}

#[test]
fn dir_is_removed_after_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let mut l = login_in(tmp.path());
    let dir = l.dir().to_path_buf();
    std::fs::write(dir.join("service_principal_entries.json"), "{}").unwrap();
    let _ = l.sign_in(values(), &FakeRunner::new([Output::failure(1)]));
    drop(l);
    assert!(!dir.exists());
}

#[test]
fn dir_is_removed_on_a_signal() {
    let tmp = tempfile::tempdir().unwrap();
    let l = login_in(tmp.path());
    let dir = l.dir().to_path_buf();
    // What the SIGINT/SIGTERM handler runs before it exits (the drop never happens).
    signals::run_cleanups_where(|d| d == dir);
    let gone = !dir.exists();
    std::mem::forget(l);
    assert!(gone);
}

#[test]
fn stale_dir_of_a_dead_run_is_swept() {
    let tmp = tempfile::tempdir().unwrap();
    let stale = tmp.path().join(format!("{DIR_PREFIX}{}-dead", i32::MAX));
    std::fs::create_dir(&stale).unwrap();
    let _l = login_in(tmp.path());
    assert!(!stale.exists());
}

#[test]
fn dir_of_a_live_run_is_kept() {
    let tmp = tempfile::tempdir().unwrap();
    let live = tmp
        .path()
        .join(format!("{DIR_PREFIX}{}-live", std::process::id()));
    std::fs::create_dir(&live).unwrap();
    let _l = login_in(tmp.path());
    assert!(live.exists());
}

#[test]
fn plaintext_store_is_refused_on_windows() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("service_principal_entries.json"), "{}").unwrap();
    assert!(check_store(tmp.path(), true).is_err());
}

/// I5: a plaintext store is az's unencrypted secret, never a private-folder failure.
#[test]
fn plaintext_store_is_named_as_an_unencrypted_secret() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("service_principal_entries.json"), "{}").unwrap();
    assert!(matches!(
        check_store(tmp.path(), true).unwrap_err().cause(),
        Some((
            Cause::ToolUnusable {
                why: Unusable::StoredSecretUnencrypted,
                ..
            },
            _
        ))
    ));
}

#[test]
fn encrypted_store_is_accepted_on_windows() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("service_principal_entries.bin"), "x").unwrap();
    assert!(check_store(tmp.path(), true).is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn ram_check_rejects_a_disk_directory() {
    // The crate directory is on a disk file system on every developer machine and runner.
    assert!(!ram_backed(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap());
}

/// Every az call of the run (read, write, probe) carries the private config dir.
#[test]
fn every_az_call_through_the_environment_runner_uses_the_config_dir() {
    use crate::runner::{Call, CommandRunner};
    let tmp = tempfile::tempdir().unwrap();
    let mut l = login_in(tmp.path());
    let r = FakeRunner::new((0..4).map(|_| Output::success(Vec::new())));
    l.sign_in(values(), &r).unwrap();
    let dir = l.dir().to_str().unwrap().to_string();
    let runner = crate::app::signin::EnvRunner::new(&r, None).with_login(Box::new(l));
    let args = ["keyvault", "secret", "list"];
    runner.read(&Call::new("az", &args), &[]).unwrap();
    runner.write(&Call::new("az", &args)).unwrap();
    runner
        .probe(&Call::new("az", &args), std::time::Duration::from_secs(1))
        .unwrap();
    let want = ("AZURE_CONFIG_DIR".to_string(), dir);
    assert!(r.calls.borrow().iter().all(|c| c.env.contains(&want)));
}

/// The item read refuses an item without every declared field before sign-in, so sign-in
/// given one is opv's own bug (it used to be worded as the person's item).
#[test]
fn a_missing_credential_field_is_an_internal_error() {
    let tmp = tempfile::tempdir().unwrap();
    let mut l = login_in(tmp.path());
    let mut v = values();
    v.remove("AZURE_CLIENT_ID");
    let e = l.sign_in(v, &FakeRunner::default()).unwrap_err();
    assert_eq!(e.exit_code(), 70);
}

/// I5: a tenant ID that looks like an option is refused by opv before az runs.
#[test]
fn a_tenant_id_that_looks_like_an_option_is_refused_before_az_runs() {
    let tmp = tempfile::tempdir().unwrap();
    let mut l = login_in(tmp.path());
    let mut v = values();
    v.insert("AZURE_TENANT_ID".into(), SecretValue::new("--debug".into()));
    let r = FakeRunner::default();
    let _ = l.sign_in(v, &r);
    assert!(r.calls.borrow().is_empty());
}

/// I5: a malformed tenant ID is opv's own refusal (it was left to az, then unrecognized).
#[test]
fn a_malformed_tenant_id_is_input_invalid() {
    let tmp = tempfile::tempdir().unwrap();
    let mut l = login_in(tmp.path());
    let mut v = values();
    v.insert(
        "AZURE_TENANT_ID".into(),
        SecretValue::new("not an id!".into()),
    );
    let e = l.sign_in(v, &FakeRunner::default()).unwrap_err();
    assert_eq!(e.code_str(), "input_invalid");
}

/// I5: a client ID that is not a GUID is refused, naming AZURE_CLIENT_ID.
#[test]
fn a_malformed_client_id_names_the_field() {
    let tmp = tempfile::tempdir().unwrap();
    let mut l = login_in(tmp.path());
    let mut v = values();
    v.insert("AZURE_CLIENT_ID".into(), SecretValue::new("my-app".into()));
    let e = l.sign_in(v, &FakeRunner::default()).unwrap_err();
    assert!(
        e.to_string().contains("AZURE_CLIENT_ID must be a GUID"),
        "{e}"
    );
}

/// I5: a tenant given by its domain is accepted.
#[test]
fn a_tenant_domain_is_accepted() {
    let tmp = tempfile::tempdir().unwrap();
    let mut l = login_in(tmp.path());
    let mut v = values();
    v.insert(
        "AZURE_TENANT_ID".into(),
        SecretValue::new("contoso.onmicrosoft.com".into()),
    );
    let r = FakeRunner::new([Output::success(Vec::new())]);
    assert!(l.sign_in(v, &r).is_ok());
}

/// I5: under deploy credentials, a malformed ID names the item it is in.
#[test]
fn a_malformed_id_names_the_deploy_credentials_item() {
    use crate::cause::{EnvName, ItemId, TargetName, VaultId};
    let tmp = tempfile::tempdir().unwrap();
    let mut l = login_in(tmp.path());
    let mut v = values();
    v.insert("AZURE_CLIENT_ID".into(), SecretValue::new("my-app".into()));
    let p = Principal::DeployCredentials {
        vault: VaultId::new("ops"),
        item: ItemId::new("azure-prod"),
        env: EnvName::new("prod"),
        target: TargetName::new("web"),
    };
    let e = crate::runner::under_deploy(p, || l.sign_in(v, &FakeRunner::default())).unwrap_err();
    assert!(e.to_string().contains("op://ops/azure-prod"), "{e}");
}

#[test]
fn an_unanswered_az_login_is_provider_unavailable() {
    let tmp = tempfile::tempdir().unwrap();
    let mut l = login_in(tmp.path());
    let r = FakeRunner::default();
    r.push_unknown("timeout");
    let e = l.sign_in(values(), &r).unwrap_err();
    assert_eq!(e.code(), crate::error::Code::ProviderUnavailable);
}
