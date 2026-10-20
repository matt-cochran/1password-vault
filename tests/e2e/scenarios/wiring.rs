//! 0.13.0 features each proven by unit tests but never reached through the real command
//! (#175, #176, #179): the real `opv` binary, and `opv mcp serve` where an assistant reaches
//! the same feature, against `opv-sim` on the test application in `tests/e2e/app`.
//!
//! 1. #175: `opv needs --scan <dir>` reads Ruby and C/C++ sources: their names are reported
//!    with `file:line` and the coverage lists `ruby` and `c`;
//! 2. #176: `opv propose setup --names-from .env` into a project that already has a contract
//!    proposes only the names it does not declare and keeps its environment table, on the
//!    command line and through `opv_propose`;
//! 3. #179: an `extend` intent (`opv propose --intent`) reads the configuration and returns
//!    the contract diff and its plan id, the same document `opv_propose` answers.

use serde_json::{Value, json};

use crate::coverage::{MARK, Scenario};

fn document(stdout: &str) -> Value {
    serde_json::from_str(stdout.trim()).unwrap_or_else(|_| panic!("not one document: {stdout}"))
}

// --- #175: Ruby and C/C++ scanners ------------------------------------------------------------

const RUBY: &str = "url = ENV['RUBY_ONLY_NAME']\nkey = ENV.fetch(\"API_KEY\")\n";
const C_SOURCE: &str =
    "#include <stdlib.h>\nint main(void) {\n    return getenv(\"C_ONLY_NAME\") == 0;\n}\n";

#[test]
fn needs_scan_reports_ruby_and_c_reads() {
    let s = Scenario::new()
        .marked()
        .file("project/code/app.rb", RUBY)
        .file("project/code/main.c", C_SOURCE);
    let run = s.opv(&[
        "needs".into(),
        "--scan".into(),
        "code".into(),
        "--json".into(),
    ]);
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    let doc = document(&run.stdout);
    let row = |name: &str| {
        doc["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == name)
            .cloned()
            .unwrap_or_else(|| panic!("no row for {name}: {doc}"))
    };
    assert_eq!(row("RUBY_ONLY_NAME")["state"], "undeclared");
    assert_eq!(row("RUBY_ONLY_NAME")["files"], json!(["app.rb:1"]));
    assert_eq!(row("C_ONLY_NAME")["state"], "undeclared");
    assert_eq!(row("C_ONLY_NAME")["files"], json!(["main.c:3"]));
    assert_eq!(row("API_KEY")["state"], "declared");
    let languages = &doc["coverage"]["languages"];
    for language in ["c", "ruby"] {
        assert!(
            languages.as_array().unwrap().iter().any(|l| l == language),
            "coverage lacks {language}: {languages}"
        );
    }
    assert!(!run.stdout.contains(MARK) && !run.stderr.contains(MARK));
}
