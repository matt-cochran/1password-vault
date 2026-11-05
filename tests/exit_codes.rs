//! Exit codes (FR-64, #265): every code `Cause::exit_code` returns is listed in `--help` and
//! in docs/usage.md, and a `--json` document that cannot be written exits 74 instead of 0.
//! One assertion each.

use std::process::{Command, Output, Stdio};

/// Every number `Cause::exit_code` can return, read from its code (comments aside): its literals, and
/// each `EXIT_*` constant it names as that constant's value (`128 + signal` lists 128).
fn codes_in_source() -> Vec<String> {
    let src = include_str!("../src/cause/mod.rs");
    let start = src
        .find("pub fn exit_code(&self)")
        .expect("Cause::exit_code");
    let end = start + src[start..].find("pub fn retry").expect("Cause::retry");
    let constant = regex::Regex::new(r"pub const (EXIT_[A-Z_]+): i32 = (\d+);").unwrap();
    let comment = regex::Regex::new(r"//.*").unwrap();
    let mut body = comment.replace_all(&src[start..end], "").into_owned();
    for c in constant.captures_iter(src) {
        body = body.replace(&c[1], &c[2]);
    }
    let number = regex::Regex::new(r"\b\d+\b").unwrap();
    let mut out: Vec<String> = number
        .find_iter(&body)
        .map(|m| m.as_str().to_string())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The codes in `codes_in_source` that `text` does not name as a whole number.
fn missing_from(text: &str) -> Vec<String> {
    codes_in_source()
        .into_iter()
        .filter(|c| {
            !regex::Regex::new(&format!(r"\b{c}\b"))
                .unwrap()
                .is_match(text)
        })
        .collect()
}

fn opv() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_opv"));
    c.env_remove("GITHUB_STEP_SUMMARY")
        .env_remove("OP_SERVICE_ACCOUNT_TOKEN")
        .env_remove("OPV_CONFIG")
        .env_remove("OPV_PRODUCT")
        .env("OPV_NO_SKILL", "1")
        // An empty PATH guarantees no real `op` or target CLI can run from these tests.
        .env("PATH", "")
        .stdin(Stdio::null());
    c
}

fn help_exit_block() -> String {
    let out = opv().arg("--help").output().unwrap();
    let help = String::from_utf8(out.stdout).unwrap();
    let start = help.find("Exit codes:").expect("an Exit codes block");
    let end = start
        + help[start..]
            .find("Environment:")
            .expect("Environment block");
    help[start..end].to_string()
}

fn usage_exit_section() -> String {
    let usage = include_str!("../docs/usage.md");
    let start = usage
        .find("\n## Exit codes")
        .expect("an Exit codes section");
    let end = start
        + 1
        + usage[start + 1..]
            .find("\n## ")
            .unwrap_or(usage.len() - start - 1);
    usage[start..end].to_string()
}

#[test]
fn exit_codes_help_lists_every_code() {
    assert_eq!(missing_from(&help_exit_block()), Vec::<String>::new());
}

#[test]
fn exit_codes_usage_lists_every_code() {
    assert_eq!(missing_from(&usage_exit_section()), Vec::<String>::new());
}

/// `opv version` with its stdout on a pipe whose reader is already gone.
fn to_closed_pipe(args: &[&str]) -> Output {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    opv()
        .args(args)
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

#[test]
fn json_to_a_closed_pipe_exits_74() {
    assert_eq!(
        to_closed_pipe(&["version", "--json"]).status.code(),
        Some(74)
    );
}

#[test]
fn json_to_a_closed_pipe_says_first_how_the_command_ended() {
    let out = to_closed_pipe(&["version", "--json"]);
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.starts_with("opv: version finished (ok);"),
        "{stderr}"
    );
}

#[test]
fn text_to_a_closed_pipe_exits_0() {
    assert_eq!(to_closed_pipe(&["version"]).status.code(), Some(0));
}

#[cfg(target_os = "linux")]
#[test]
fn json_to_a_full_device_exits_74() {
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let out = opv()
        .args(["version", "--json"])
        .stdout(full)
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(74));
}

#[test]
fn verbose_json_names_the_delivered_document() {
    let out = opv()
        .args(["version", "--json", "--verbose"])
        .output()
        .unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    let want = format!(
        "stdout: one JSON document, {} bytes, delivered",
        out.stdout.len()
    );
    assert!(stderr.contains(&want), "{stderr}");
}

/// #276: `target list --json` prints a top-level array, a document since before 0.17.4.
#[test]
fn target_list_json_exits_zero() {
    let out = opv()
        .args([
            "--config",
            "tests/fixtures/secrets.toml",
            "target",
            "list",
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
}
