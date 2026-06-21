//! The `vox` command-line surface (ADR-015 §"Distribution").
//!
//! The interactive TUI is the default (`vox` or `vox tui`); `vox completions
//! <shell>` and `vox man` emit shell completions and a man page (built from the
//! same clap model, so they never drift from the real flags). [`run`] is the
//! single entry the binary calls.

use std::io;
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};

use crate::app::{run_tui, OfflineCore};

/// Vox Lux — serverless, end-to-end-encrypted terminal client.
#[derive(Parser)]
#[command(name = "vox", version, about, long_about = None)]
pub struct Cli {
    /// The subcommand; omitted launches the interactive TUI.
    #[command(subcommand)]
    command: Option<Cmd>,
}

/// Top-level subcommands.
#[derive(Subcommand)]
enum Cmd {
    /// Run the interactive terminal client (the default).
    Tui,
    /// Print shell completions for SHELL to stdout.
    Completions {
        /// The shell to generate completions for (bash, zsh, fish, …).
        shell: clap_complete::Shell,
    },
    /// Print the roff man page to stdout.
    Man,
}

/// Parse arguments and dispatch. Returns the process exit code.
#[must_use]
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Cmd::Tui) {
        Cmd::Tui => match run_tui(OfflineCore::default()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("vox: {e}");
                ExitCode::FAILURE
            }
        },
        Cmd::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "vox", &mut io::stdout());
            ExitCode::SUCCESS
        }
        Cmd::Man => match render_man() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("vox: man generation failed: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

fn render_man() -> io::Result<()> {
    clap_mangen::Man::new(Cli::command()).render(&mut io::stdout())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        // clap's own invariants (no duplicate flags, valid subcommands) — panics on
        // a malformed definition, so this is a real structural check.
        Cli::command().debug_assert();
    }

    #[test]
    fn man_renders_without_error() {
        // Render into a buffer to confirm the man model is well-formed.
        let mut buf: Vec<u8> = Vec::new();
        clap_mangen::Man::new(Cli::command())
            .render(&mut buf)
            .unwrap();
        assert!(!buf.is_empty());
        assert!(String::from_utf8_lossy(&buf).contains("vox"));
    }

    #[test]
    fn completions_generate_for_bash() {
        let mut cmd = Cli::command();
        let mut buf: Vec<u8> = Vec::new();
        clap_complete::generate(clap_complete::Shell::Bash, &mut cmd, "vox", &mut buf);
        assert!(!buf.is_empty());
    }
}
