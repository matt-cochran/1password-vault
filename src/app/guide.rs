//! `opv guide agent` (A10): the agent setup guide embedded in the binary, so an assistant
//! reads the guide for the version it drives instead of the one on `main`. The text is
//! `docs/agent-setup.md` itself; only its relative links are made absolute, pointing at the
//! docs of this release.

use std::io::Write;

use super::write_err;
use crate::error::Error;

/// `docs/agent-setup.md` as built into this binary.
const AGENT_SETUP: &str = include_str!("../../docs/agent-setup.md");

/// The docs of this release, for links in the printed guide.
fn docs_base() -> String {
    format!(
        "https://github.com/matt-cochran/1password-vault/blob/v{}/docs/",
        env!("CARGO_PKG_VERSION")
    )
}

/// The agent setup guide with every relative `](page.md…)` link pointing at this release.
pub fn agent() -> String {
    let base = docs_base();
    let mut out = String::with_capacity(AGENT_SETUP.len() + 512);
    let mut rest = AGENT_SETUP;
    while let Some(at) = rest.find("](") {
        let (head, tail) = rest.split_at(at + 2);
        out.push_str(head);
        let relative = !tail.starts_with("http") && !tail.starts_with('#');
        if relative {
            match tail.strip_prefix("../") {
                Some(up) => {
                    out.push_str(base.trim_end_matches("docs/"));
                    rest = up;
                    continue;
                }
                None => out.push_str(&base),
            }
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

/// Print the agent setup guide.
pub fn run(out: &mut dyn Write) -> Result<(), Error> {
    out.write_all(agent().as_bytes()).map_err(write_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_guide_is_the_agent_setup_doc() {
        let doc = std::fs::read_to_string("docs/agent-setup.md").unwrap();
        assert_eq!(AGENT_SETUP, doc);
    }

    #[test]
    fn agent_guide_links_point_at_this_release() {
        let want = format!("]({}configuration.md", docs_base());
        assert!(agent().contains(&want), "{}", agent());
    }

    #[test]
    fn agent_guide_keeps_no_relative_doc_link() {
        let g = agent();
        assert!(
            !g.contains("](configuration.md") && !g.contains("](usage.md"),
            "{g}"
        );
    }
}
