//! The sealed target end to end (#271, design `sealed-target` §10, §12 E1): the real `opv`
//! binary seals the web product of `prod` with `opv sync`, and `opv unseal` verifies and runs
//! it, with no 1Password at the runtime.
//!
//! **The world.** `tests/e2e/app/world.json` holds the target's deploy credentials: a
//! 1Password SSH Key item (D13) carrying the fixture signer of `tests/fixtures/sealed/kat/`
//! (`SSHKEY` field, OpenSSH form in `ssh_formats.openssh.value`, PKCS#8 in `value`), and the
//! state vault with the target's `web` delivery item. The target itself is appended to
//! `secrets.toml` here, in the downstream's shape (§5.8): one bundle per environment and
//! product, a named trust group, and `--sealed-root` for a separate store checkout. The age
//! recipient is the fixture identity's, so `opv unseal` opens what `opv sync` sealed.
//!
//! **No value.** Every world value is a marker; `--exec` prints variable names and file
//! paths only, and a value is compared inside the child (`[ "$A" = "$B" ]`), never printed.
//! Bundles hold ciphertext; the snapshot holds names, fingerprints and refusals.
//!
//! **Linux only** for the runs that open a bundle with file keys: the runtime folder must be
//! RAM-backed (`XDG_RUNTIME_DIR` in `/dev/shm`), as for `opv run` (design §5.5).

use std::path::Path;

use serde_json::Value;

#[cfg(target_os = "linux")]
use crate::coverage::updating;
use crate::coverage::{Run, Scenario, scenario_snapshots};

/// The scenario snapshots this module writes (`tests/e2e/snapshots/scenarios/`).
pub(crate) const SNAPSHOTS: &[&str] = &["sealed"];

const TARGET: &str = "box";
/// The deploy credentials: the SSH Key item holding the fixture signer.
const SIGNER_VAULT: &str = "vE2ESEALSIGNER000000000001";
const SIGNER_ITEM: &str = "iE2ESEALSIGNERPROD00000001";
/// The target's state vault and its `web` delivery item (FR-13, FR-58).
const STATE_VAULT: &str = "vE2ESTATEBOX00000000000001";
const DELIVERY_ITEM: &str = "iE2EDELIVERYWEBBOX00000001";
/// The value boundaries of `prod`: one values read each per seal (acceptance 2).
const BOUNDARIES: &[&str] = &["iE2ESHAREDPROD0000000000001", "iE2EWEBPROD000000000000001"];
/// Where the bundle lands, relative to the scenario root.
const BUNDLE: &str = "project/sealed/prod/web.opv-sealed";

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

fn kat(name: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sealed/kat")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// `ssh-ed25519 <base64>` of the fixture signer, without its comment.
fn signer_public() -> String {
    kat("signer_ed25519.pub")
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

/// A second ed25519 key, the one a staging target would sign with: never `sealed.signer`
/// of `prod`.
fn staging_key() -> String {
    use ssh_key::private::Ed25519Keypair;
    let key = ssh_key::PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
    key.to_openssh(ssh_key::LineEnding::LF)
        .expect("openssh")
        .to_string()
}

/// The target section, appended to `secrets.toml`; its ids go to `secrets.bindings.toml`.
fn box_target() -> String {
    let recipient = kat("age-recipient.txt");
    format!(
        r#"
# The sealed target (#271): one signed, encrypted bundle per product, opened at the
# runtime by opv unseal with no 1Password.
[environments.prod.targets.{TARGET}]
products = ["web"]
roles = ["serve"]
deploy_credentials = "op://{SIGNER_VAULT}/{SIGNER_ITEM}"
state_vault_id = "{STATE_VAULT}"
delivery_items.web = "{DELIVERY_ITEM}"
sealed.out = "sealed/prod/{{product}}.opv-sealed"
sealed.env_name = "{{KEY}}"
sealed.recipients = ["{}"]
sealed.signer = "{}"
sealed.trust_group = "platform-prod"
"#,
        recipient.trim(),
        signer_public(),
    )
}

/// The app with the sealed target, every world value marked.
pub(crate) fn app() -> Scenario {
    Scenario::new()
        .marked()
        .config(|c| format!("{c}{}", box_target()))
}

/// [`app`] after one `opv sync prod --target box`.
pub(crate) fn sealed_app() -> Scenario {
    let s = app();
    let run = s.opv(&sync_args());
    assert_eq!(
        run.code,
        Some(0),
        "first sync: {}{}",
        run.stdout,
        run.stderr
    );
    s
}

/// [`sealed_app`] with one byte of the bundle's signed header changed (the product name),
/// as a merge or a hand edit would.
pub(crate) fn tampered_app() -> Scenario {
    let s = sealed_app();
    let path = s.path(BUNDLE);
    let mut bytes = std::fs::read(&path).expect("bundle");
    let field = b"\"product\":\"web\"";
    let at = bytes
        .windows(field.len())
        .position(|w| w == field)
        .expect("product in the header");
    bytes[at + 12] = b'X';
    std::fs::write(&path, bytes).expect("bundle");
    s
}

/// [`app`] while another seal of the placement holds the bundle's lock: this test process
/// takes the advisory lock on `<bundle>.lock` and keeps it for its own life (the scenario
/// directory is unique, so nothing else ever waits on it).
pub(crate) fn locked_app() -> Scenario {
    let s = app().file(&format!("{BUNDLE}.lock"), "");
    let held = std::fs::OpenOptions::new()
        .write(true)
        .open(s.path(&format!("{BUNDLE}.lock")))
        .expect("lock file");
    rustix::fs::flock(&held, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .expect("the lock");
    std::mem::forget(held);
    s
}

pub(crate) fn sync_args() -> Vec<String> {
    args(&["sync", "prod", "--confirm", "prod", "--target", TARGET])
}

/// The runtime's files: the `allowed_signers` line for `principal` and the age identity, both
/// inside the scenario so no path depends on the checkout.
fn runtime_files(s: Scenario, principal: &str) -> Scenario {
    s.file(
        "runtime/allowed_signers",
        &format!(
            "{principal} namespaces=\"opv-sealed\" {}\n",
            signer_public()
        ),
    )
    .file("runtime/identity.txt", &kat("age-identity.txt"))
    .mode("runtime/identity.txt", 0o400)
}

/// `opv unseal <bundle> --env prod --product web --signers … <rest>`.
pub(crate) fn unseal_args(rest: &[&str]) -> Vec<String> {
    let mut a = args(&[
        "unseal",
        &format!("{{root}}/{BUNDLE}"),
        "--env",
        "prod",
        "--product",
        "web",
        "--signers",
        "{root}/runtime/allowed_signers",
    ]);
    a.extend(args(rest));
    a
}

const IDENTITY: &[&str] = &["--identity-file", "{root}/runtime/identity.txt"];

/// [`tampered_app`] with the runtime's files, for `opv unseal`.
pub(crate) fn tampered_runtime() -> Scenario {
    runtime_files(tampered_app(), "prod")
}

/// `opv unseal` of the tampered bundle with the identity: refused before decryption.
pub(crate) fn unseal_identity_args() -> Vec<String> {
    let mut a = unseal_args(&[]);
    a.extend(args(IDENTITY));
    a
}

/// The scenario's `calls.log`.
fn calls(s: &Scenario) -> String {
    std::fs::read_to_string(s.path("world/calls.log")).unwrap_or_default()
}

/// The `op item get <item>` calls of the log, less the fresh re-reads (`--cache=false`) the
/// delivery recording makes after the write (FR-13, FR-58).
fn value_reads(s: &Scenario, item: &str) -> usize {
    calls(s)
        .lines()
        .filter(|l| l.starts_with(&format!("op item get {item} ")) && !l.contains("--cache=false"))
        .count()
}

fn bundle_bytes(s: &Scenario, rel: &str) -> Vec<u8> {
    std::fs::read(s.path(rel)).unwrap_or_default()
}

/// The single JSON document a `--json` run printed.
fn document(run: &Run) -> Value {
    serde_json::from_str(&run.stdout).unwrap_or_else(|_| panic!("{}{}", run.stdout, run.stderr))
}

// --- sealing (portable: no runtime folder) ---------------------------------------------------

/// The st-p3 warning, on the real binary: `opv sync --target box` signs in with the target's
/// SSH Key item before it seals, as for every target with deploy credentials. No internal
/// error.
#[test]
fn sync_signs_in_with_the_targets_ssh_key_and_seals() {
    let s = app();
    let run = s.opv(&sync_args());
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    assert!(s.path(BUNDLE).is_file(), "no bundle: {}", run.stderr);
    assert_eq!(value_reads(&s, SIGNER_ITEM), 1, "{}", calls(&s));
}

#[test]
fn one_values_read_per_scope() {
    let s = sealed_app();
    for item in BOUNDARIES {
        assert_eq!(value_reads(&s, item), 1, "{item}: {}", calls(&s));
    }
}

#[test]
fn a_second_sync_with_no_change_seals_nothing() {
    let s = sealed_app();
    let before = bundle_bytes(&s, BUNDLE);
    let run = s.opv(&sync_args());
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    assert!(run.stdout.contains("written 0 "), "{}", run.stdout);
    assert_eq!(bundle_bytes(&s, BUNDLE), before, "the bundle was rewritten");
}

#[test]
fn sealed_root_writes_under_the_given_directory() {
    let s = app().file("store/README", "the store checkout\n");
    let mut a = sync_args();
    a.extend(args(&["--sealed-root", "{root}/store"]));
    let run = s.opv(&a);
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    assert!(s.path("store/sealed/prod/web.opv-sealed").is_file());
    assert!(
        !s.path(BUNDLE).exists(),
        "written beside the configuration too"
    );
}

/// `{root}/store` after `opv sync --sealed-root {root}/store` (D12): the bundle is there only.
fn rooted_app() -> Scenario {
    let s = app().file("store/README", "the store checkout\n");
    let mut a = sync_args();
    a.extend(args(&["--sealed-root", "{root}/store"]));
    let run = s.opv(&a);
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    s
}

/// D12: `opv status --sealed-root` reads the bundle under the root, so every name is on it.
#[test]
fn status_with_sealed_root_reports_the_bundle_written_there() {
    let s = rooted_app();
    let run = s.opv(&args(&[
        "status",
        "prod",
        "--target",
        TARGET,
        "--sealed-root",
        "{root}/store",
    ]));
    assert!(
        run.stdout.contains("0 not yet on sealed bundle"),
        "{}{}",
        run.stdout,
        run.stderr
    );
}

/// D12: `opv plan --sealed-root` derives the plan id the sync under the same root checks.
#[test]
fn plan_with_sealed_root_gives_the_plan_id_of_the_sync() {
    let s = rooted_app();
    let root = ["--sealed-root", "{root}/store"];
    let mut plan = args(&["plan", "prod", "--target", TARGET, "--json"]);
    plan.extend(args(&root));
    let planned = s.opv(&plan);
    let id = document(&planned)["plan_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{}{}", planned.stdout, planned.stderr))
        .to_string();
    let mut sync = sync_args();
    sync.extend(args(&root));
    sync.extend(args(&["--expect-plan", &id]));
    let run = s.opv(&sync);
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
}

/// D12: `opv delivery verify --sealed-root` checks the bundle under the root.
#[test]
fn delivery_verify_with_sealed_root_verifies_the_bundle_written_there() {
    let s = rooted_app();
    let run = s.opv(&args(&[
        "delivery",
        "verify",
        "prod",
        "--product",
        "web",
        "--target",
        TARGET,
        "--sealed-root",
        "{root}/store",
    ]));
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
}

#[test]
fn a_staging_signer_is_refused_for_the_prod_target_before_any_value_read() {
    let s = staging_signed();
    let run = s.opv(&args(&[
        "sync",
        "prod",
        "--confirm",
        "prod",
        "--target",
        TARGET,
        "--json",
    ]));
    assert_eq!(run.code, Some(2), "{}{}", run.stdout, run.stderr);
    assert_eq!(document(&run)["error"]["code"], "input_invalid");
    for item in BOUNDARIES {
        assert_eq!(value_reads(&s, item), 0, "{item} was read: {}", calls(&s));
    }
    assert!(!s.path(BUNDLE).exists());
}

/// The prod target's SSH Key item holding the staging key instead of `sealed.signer`'s.
fn staging_signed() -> Scenario {
    let private = staging_key();
    app().world(move |w| {
        for item in w["op"]["items"].as_array_mut().expect("items") {
            if item["id"] == SIGNER_ITEM {
                item["fields"][0]["ssh_formats"]["openssh"]["value"] = Value::from(private.clone());
            }
        }
    })
}

/// The staging runtime's own age recipient (a test key, not the fixture identity's).
const STAGING_RECIPIENT: &str = "age13ts5aywwye8k4qr653hu89n89lt2eexd7szjadl9u3m47fzneggstxdxvs";

/// A staging target signing with prod's key, in another trust group: refused when the
/// configuration loads, before any call (T1, D11).
fn staging_shares_the_signer() -> Scenario {
    app().config(|c| {
        format!(
            "{c}
[environments.staging]
title = \"Staging\"
order = 3

[environments.staging.targets.{TARGET}]
products = [\"web\"]
roles = [\"serve\"]
deploy_credentials = \"op://{SIGNER_VAULT}/{SIGNER_ITEM}\"
state_vault_id = \"{STATE_VAULT}\"
sealed.out = \"sealed/staging/{{product}}.opv-sealed\"
sealed.env_name = \"{{KEY}}\"
sealed.recipients = [\"{}\"]
sealed.signer = \"{}\"
sealed.trust_group = \"platform-staging\"
",
            STAGING_RECIPIENT,
            signer_public()
        )
    })
}

#[test]
fn a_signer_shared_with_staging_is_refused_at_load() {
    let s = staging_shares_the_signer();
    let run = s.opv(&args(&[
        "sync",
        "prod",
        "--confirm",
        "prod",
        "--target",
        TARGET,
        "--json",
    ]));
    assert_eq!(run.code, Some(2), "{}{}", run.stdout, run.stderr);
    assert_eq!(document(&run)["error"]["code"], "sealed_signer_shared");
    assert_eq!(calls(&s), "", "a call was made");
}

#[test]
fn a_tampered_bundle_is_refused_by_sync_and_left_alone() {
    let s = tampered_app();
    let before = bundle_bytes(&s, BUNDLE);
    let mut a = sync_args();
    a.push("--json".into());
    let run = s.opv(&a);
    assert_eq!(run.code, Some(2), "{}{}", run.stdout, run.stderr);
    assert_eq!(document(&run)["error"]["code"], "input_invalid");
    assert_eq!(bundle_bytes(&s, BUNDLE), before, "the bundle was replaced");
}

/// A tampered bundle costs no 1Password values read: it is refused before the read.
#[test]
fn a_tampered_bundle_is_refused_before_any_value_read() {
    let s = tampered_app();
    std::fs::write(s.path("world/calls.log"), "").expect("calls.log");
    s.opv(&sync_args());
    let reads: usize = BOUNDARIES.iter().map(|item| value_reads(&s, item)).sum();
    assert_eq!(reads, 0, "{}", calls(&s));
}

#[test]
fn a_held_lock_refuses_the_write_and_writes_no_bundle() {
    let s = locked_app();
    let mut a = sync_args();
    a.push("--json".into());
    let run = s.opv(&a);
    assert_eq!(run.code, Some(6), "{}{}", run.stdout, run.stderr);
    assert_eq!(document(&run)["error"]["code"], "local_io_failed");
    assert!(!s.path(BUNDLE).exists());
    assert!(
        s.path(&format!("{BUNDLE}.lock")).exists(),
        "another's lock removed"
    );
}

#[test]
fn a_tampered_bundle_is_refused_by_unseal_before_decryption() {
    let s = tampered_runtime();
    let mut a = unseal_identity_args();
    a.push("--json".into());
    let run = s.opv(&a);
    assert_eq!(run.code, Some(6), "{}{}", run.stdout, run.stderr);
    let doc = document(&run);
    assert_eq!(doc["error"]["code"], "sealed_signature_invalid");
    assert!(
        doc["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("nothing was decrypted"))
    );
}

#[test]
fn a_signers_line_for_staging_only_is_refused_for_a_prod_bundle() {
    let s = runtime_files(sealed_app(), "staging");
    let mut a = unseal_identity_args();
    a.push("--json".into());
    let run = s.opv(&a);
    assert_eq!(run.code, Some(6), "{}{}", run.stdout, run.stderr);
    assert_eq!(document(&run)["error"]["code"], "sealed_signature_invalid");
}

// --- the runtime (Linux: a RAM-backed runtime folder) ----------------------------------------

/// A RAM-backed `XDG_RUNTIME_DIR` (file keys, design §5.5), kept for the scenario's life.
#[cfg(target_os = "linux")]
struct Ram(tempfile::TempDir);

#[cfg(target_os = "linux")]
fn ram() -> Ram {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::Builder::new()
        .prefix("opv-e2e-ram.")
        .tempdir_in("/dev/shm")
        .expect("a folder in /dev/shm");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).expect("chmod");
    Ram(dir)
}

#[cfg(target_os = "linux")]
fn with_ram(s: Scenario, ram: &Ram) -> Scenario {
    s.var("XDG_RUNTIME_DIR", &ram.0.path().display().to_string())
}

/// What the child sees: its variable names, then its file keys' paths (never a value).
#[cfg(target_os = "linux")]
const SHOW: &str = "env | cut -d= -f1 | sort; cd \"$WEB_SECRETS_DIR\" && find . -type f | sort";

#[cfg(target_os = "linux")]
mod runtime {
    use super::*;

    const WEB_PROD_ITEM: &str = "iE2EWEBPROD000000000000001";

    /// The names the `serve` role seals for `web` in `prod`, in bundle order.
    const SEALED: &[&str] = &[
        "API_KEY",
        "DATABASE_URL",
        "LOG_LEVEL",
        "OTEL_RESOURCE",
        "SESSION_SECRET",
        "TLS_CERTIFICATE",
        "TLS_PRIVATE_KEY",
    ];

    /// The variables among them; the rest are file keys.
    const VARIABLES: &[&str] = &["API_KEY", "DATABASE_URL", "LOG_LEVEL", "SESSION_SECRET"];

    /// The names a verified bundle lists (`opv unseal … --verify-only --json`).
    fn listed(s: &Scenario) -> Vec<String> {
        let run = s.opv(&unseal_args(&["--verify-only", "--json"]));
        document(&run)["names"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|n| n["name"].as_str().map(str::to_string))
            .collect()
    }

    /// A key retired (#179: `lifecycle = "retiring"`, no longer read at `HEAD`) leaves the next
    /// bundle, which holds every other name again (T3).
    fn retired() -> Scenario {
        let s = sealed_app()
            .config(|c| {
                c.replacen(
                    "[products.web.keys.LOG_LEVEL]\n",
                    "[products.web.keys.LOG_LEVEL]\nlifecycle = \"retiring\"\n",
                    1,
                )
            })
            .git_checkout()
            .tracked(
                "src/main.rs",
                "fn main() {\n    let _ = std::env::var(\"API_KEY\");\n}\n",
            )
            .committed();
        runtime_files(s, "prod")
    }

    fn retire_args() -> Vec<String> {
        let mut a = sync_args();
        a.extend(args(&["--prune", "--retire"]));
        a
    }

    #[test]
    fn seal_then_verify_only_accepts() {
        let ram = ram();
        let s = with_ram(runtime_files(sealed_app(), "prod"), &ram);
        let run = s.opv(&unseal_args(&["--verify-only"]));
        assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
        let mut a = unseal_identity_args();
        a.push("--verify-only".into());
        assert_eq!(s.opv(&a).code, Some(0), "with the identity");
        assert_eq!(listed(&s), SEALED);
    }

    #[test]
    fn unseal_exec_delivers_the_variables_and_files() {
        let ram = ram();
        let s = with_ram(runtime_files(sealed_app(), "prod"), &ram);
        let mut a = unseal_identity_args();
        a.extend(args(&["--exec", "--", "sh", "-c", SHOW]));
        let run = s.opv(&a);
        assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
        let seen: Vec<&str> = run.stdout.lines().collect();
        for name in VARIABLES {
            assert!(seen.contains(name), "{name} missing: {}", run.stdout);
        }
        for file in ["./otel/resource", "./tls/certificate", "./tls/private-key"] {
            assert!(seen.contains(&file), "{file} missing: {}", run.stdout);
        }
        assert!(!seen.iter().any(|n| n.starts_with("OP_")), "{}", run.stdout);
        assert!(!seen.contains(&"MIGRATION_TOKEN"), "another role's key");
        // The RAM folder is gone after the child exits.
        assert_eq!(std::fs::read_dir(ram.0.path()).expect("ram").count(), 0);
    }

    #[test]
    fn unseal_exec_delivers_1passwords_exact_value() {
        let ram = ram();
        let s = runtime_files(sealed_app(), "prod");
        let world: Value = serde_json::from_str(
            &std::fs::read_to_string(s.path("world/world.json")).expect("world"),
        )
        .expect("world");
        let want = world["op"]["items"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|i| i["id"] == WEB_PROD_ITEM)
            .flat_map(|i| i["fields"].as_array().into_iter().flatten())
            .find(|f| f["label"] == "API_KEY")
            .and_then(|f| f["value"].as_str())
            .expect("API_KEY")
            .to_string();
        let s = with_ram(s, &ram).var("E2E_WANT_API_KEY", &want);
        let mut a = unseal_identity_args();
        a.extend(args(&[
            "--exec",
            "--",
            "sh",
            "-c",
            "[ \"$API_KEY\" = \"$E2E_WANT_API_KEY\" ] && echo same",
        ]));
        let run = s.opv(&a);
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        assert_eq!(run.stdout.trim(), "same");
    }

    #[test]
    fn a_retired_key_reseals_the_whole_set_without_it() {
        let ram = ram();
        let s = with_ram(retired(), &ram);
        let run = s.opv(&retire_args());
        assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
        let want: Vec<&str> = SEALED
            .iter()
            .copied()
            .filter(|n| *n != "LOG_LEVEL")
            .collect();
        assert_eq!(listed(&s), want);
    }

    // --- the snapshot ------------------------------------------------------------------------

    /// What a snapshot must not depend on beyond [`Scenario::normalize`]: when a bundle was
    /// sealed (its revision is the Unix time), the plan id, the delivery revision.
    fn steady(text: &str) -> String {
        let rules = [
            (r"\brevision \d{9,}", "revision <revision>"),
            (r#""revision":\d{9,}"#, r#""revision":"<revision>""#),
            (r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", "<time>"),
            (r"\bplan [0-9a-f]{8}\b", "plan <id>"),
            (r#""plan_id":"[0-9a-f]+""#, r#""plan_id":"<id>""#),
            (r"--expect-plan [0-9a-f]{8}\b", "--expect-plan <id>"),
            (r"\bdrv-[a-z0-9]+\b", "drv-<id>"),
            (
                &format!(r"\bby opv {}\b", regex::escape(env!("CARGO_PKG_VERSION"))),
                "by opv <version>",
            ),
        ];
        let mut out = text.to_string();
        for (pattern, with) in rules {
            out = regex::Regex::new(pattern)
                .expect("regex")
                .replace_all(&out, with)
                .into_owned();
        }
        out
    }

    fn section(snap: &mut String, label: &str, run: &Run) {
        snap.push_str(&format!(
            "\n## {label} exit: {}\n## {label} stdout\n{}\n## {label} stderr\n{}",
            run.code.map_or("killed".into(), |c| c.to_string()),
            steady(&run.stdout),
            steady(&run.stderr),
        ));
    }

    fn json(mut a: Vec<String>) -> Vec<String> {
        let at = a.iter().position(|x| x == "--").unwrap_or(a.len());
        a.insert(at, "--json".into());
        a
    }

    fn transcript() -> String {
        let mut snap =
            String::from("# sealed: seal with opv sync, verify and run with opv unseal\n");
        let ram = ram();
        // Seal, then a second sync with no change seals nothing.
        let s = with_ram(runtime_files(app(), "prod"), &ram);
        section(&mut snap, "first opv sync", &s.opv(&sync_args()));
        section(&mut snap, "second opv sync", &s.opv(&sync_args()));
        section(
            &mut snap,
            "opv status",
            &s.opv(&args(&["status", "prod", "--target", TARGET])),
        );
        // The runtime: verify without decrypting, inspect, run.
        section(
            &mut snap,
            "unseal --verify-only",
            &s.opv(&unseal_args(&["--verify-only"])),
        );
        section(
            &mut snap,
            "unseal --verify-only --json",
            &s.opv(&json(unseal_args(&["--verify-only"]))),
        );
        section(&mut snap, "unseal", &s.opv(&unseal_identity_args()));
        let mut exec = unseal_identity_args();
        exec.extend(args(&["--exec", "--", "sh", "-c", SHOW]));
        section(&mut snap, "unseal --exec (names only)", &s.opv(&exec));
        // A retired key: the whole set again, without it.
        let r = with_ram(retired(), &ram);
        section(
            &mut snap,
            "retired opv sync --prune --retire",
            &r.opv(&retire_args()),
        );
        section(
            &mut snap,
            "retired unseal --verify-only",
            &r.opv(&unseal_args(&["--verify-only"])),
        );
        // `--sealed-root`: the store checkout.
        let mut rooted = sync_args();
        rooted.extend(args(&["--sealed-root", "{root}/store"]));
        section(
            &mut snap,
            "opv sync --sealed-root",
            &app()
                .file("store/README", "the store checkout\n")
                .opv(&rooted),
        );
        // Refusals.
        section(
            &mut snap,
            "staging signer opv sync --json",
            &staging_signed().opv(&json(sync_args())),
        );
        section(
            &mut snap,
            "signer shared with staging opv sync --json",
            &staging_shares_the_signer().opv(&json(sync_args())),
        );
        section(
            &mut snap,
            "tampered opv sync --json",
            &tampered_app().opv(&json(sync_args())),
        );
        section(
            &mut snap,
            "tampered unseal --json",
            &tampered_runtime().opv(&json(unseal_identity_args())),
        );
        section(
            &mut snap,
            "staging-only signers unseal --json",
            &runtime_files(sealed_app(), "staging").opv(&json(unseal_identity_args())),
        );
        section(
            &mut snap,
            "lock held opv sync --json",
            &locked_app().opv(&json(sync_args())),
        );
        snap
    }

    #[test]
    fn the_sealed_target_matches_its_snapshot() {
        let got = transcript();
        let path = scenario_snapshots().join(format!("{}.snap", SNAPSHOTS[0]));
        if updating() {
            std::fs::write(&path, &got).expect("write snapshot");
            return;
        }
        let want = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(
            got,
            want,
            "{} differs from its snapshot; review and rerun with UPDATE_SNAPSHOTS=1",
            path.display()
        );
    }
}

// --- the canary ------------------------------------------------------------------------------

/// No snapshot holds a value, the signing key or the identity.
#[test]
fn no_snapshot_holds_a_value_or_a_key() {
    let snapshot = scenario_snapshots().join(format!("{}.snap", SNAPSHOTS[0]));
    let text = std::fs::read_to_string(&snapshot).unwrap_or_default();
    let identity = kat("age-identity.txt");
    let secret_line = identity
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .expect("identity");
    for canary in [
        crate::coverage::MARK,
        "test-marker-e2e-",
        "PRIVATE KEY",
        secret_line,
    ] {
        assert!(!text.contains(canary), "a value leaked ({canary})");
    }
}
