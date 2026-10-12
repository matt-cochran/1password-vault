//! Exercise the actual owner console through a pseudo-terminal with a fake CLI.
#[cfg(unix)]
#[test]
fn guided_console_hides_input_and_resumes_without_extra_confirmation() {
    let status = std::process::Command::new("python3")
        .arg("tests/console_walkthrough.py")
        .arg(env!("CARGO_BIN_EXE_opv"))
        .status()
        .expect("Python 3 is required for the Unix console test");
    assert!(status.success());
}
