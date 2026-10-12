//! `opv completions <shell>` (P13): a static completion script for the clap command tree.
//! Completes commands and flags only; it reads no configuration and calls no CLI.

use std::io::Write;

use clap::Command;

/// Shells `opv completions` writes a script for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    Powershell,
}

impl From<Shell> for clap_complete::Shell {
    fn from(s: Shell) -> Self {
        match s {
            Shell::Bash => Self::Bash,
            Shell::Zsh => Self::Zsh,
            Shell::Fish => Self::Fish,
            Shell::Powershell => Self::PowerShell,
        }
    }
}

/// Write the completion script for `shell` to `out`.
pub fn write(shell: Shell, cmd: &mut Command, out: &mut dyn Write) {
    clap_complete::generate(clap_complete::Shell::from(shell), cmd, "opv", out);
}

/// Help text: one install line per shell.
pub const INSTALL: &str = "\
Install:
  bash        opv completions bash > ~/.local/share/bash-completion/completions/opv
  zsh         opv completions zsh > \"${fpath[1]}/_opv\"   # then restart zsh
  fish        opv completions fish > ~/.config/fish/completions/opv.fish
  powershell  opv completions powershell | Out-String | Invoke-Expression   # add to $PROFILE";
