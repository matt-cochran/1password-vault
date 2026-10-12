//! Azure deploy credentials (FR-40, SR-3, SR-4). The RAM check is injected, so these run
//! on any Unix with a temporary directory standing in for `$XDG_RUNTIME_DIR`.

use super::*;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

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
    let (text, next) = NO_RAM_DIR.split_once("\n  next: ").unwrap();
    assert_eq!(
        (e.exit_code(), e.text(), e.next_step()),
        (6, text, Some(next))
    );
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
        "login --service-principal -u 00000000-0000-0000-0000-00000000000b -t \
         00000000-0000-0000-0000-00000000000a -p @/dev/stdin --only-show-errors -o none"
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

#[test]
fn rejected_credentials_are_an_auth_error_without_the_secret() {
    let tmp = tempfile::tempdir().unwrap();
    let mut l = login_in(tmp.path());
    let r = FakeRunner::new([Output::failure(1)]);
    let e = l.sign_in(values(), &r).unwrap_err();
    assert!(e.exit_code() == 7 && !e.to_string().contains(SECRET), "{e}");
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
    assert_eq!(check_store(tmp.path(), true).unwrap_err().exit_code(), 6);
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
