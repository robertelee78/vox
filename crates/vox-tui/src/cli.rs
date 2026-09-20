//! The `vox` command-line surface (ADR-015 §"Distribution").
//!
//! The interactive TUI is the default (`vox` or `vox tui`); `vox completions
//! <shell>` and `vox man` emit shell completions and a man page (built from the
//! same clap model, so they never drift from the real flags). [`run`] is the
//! single entry the binary calls. The TUI always runs an embedded node over a
//! profile (ADR-016 M13): `--profile`, `--data-dir`, `--config-dir` select it
//! (ADR-015 precedence: flags > env > defaults; env `VOX_DATA_DIR` /
//! `VOX_CONFIG_DIR`, then XDG).

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand};
use vox_core::nat::bootstrap::BootstrapSet;
use vox_core::node::link::merge_anchor_spec;
use vox_core::node::paths::{Paths, DEFAULT_PROFILE};

use crate::app::run_live;

/// Profile selection shared by the interactive commands.
#[derive(Args, Debug, Clone)]
pub struct ProfileArgs {
    /// Profile name (one identity per profile).
    #[arg(long, env = "VOX_PROFILE", default_value = DEFAULT_PROFILE)]
    pub profile: String,
    /// Data directory root (holds `<profile>/vault.cbor` and `store.redb`).
    #[arg(long, env = "VOX_DATA_DIR")]
    pub data_dir: Option<PathBuf>,
    /// Config directory.
    #[arg(long, env = "VOX_CONFIG_DIR")]
    pub config_dir: Option<PathBuf>,
    /// Address to bind for peer connections (`ip:port`; port 0 picks one).
    ///
    /// This is only where the socket binds. What the node *advertises* is worked out
    /// separately by the ADR-012 ladder — its routable address, a gateway-mapped
    /// address when one can be had, and loopback — so the wildcard default is correct
    /// and needs no configuration.
    #[arg(long, env = "VOX_LISTEN", default_value = DEFAULT_LISTEN)]
    pub listen: SocketAddr,
    /// An anchor to publish to, read from and reach peers through, as
    /// `<fingerprint>@<multiaddr>` (repeatable; `VOX_ANCHORS` takes a comma-separated
    /// list). The user's own always-on node, typically (ADR-012 §"Bootstrap").
    #[arg(long = "anchor", env = "VOX_ANCHORS", value_delimiter = ',')]
    pub anchors: Vec<String>,
}

impl ProfileArgs {
    /// Resolve (and create) the profile paths.
    pub fn paths(&self) -> vox_core::error::Result<Paths> {
        Paths::resolve(
            &self.profile,
            self.data_dir.as_deref(),
            self.config_dir.as_deref(),
        )
    }

    /// The configured anchors, parsed and merged by identity.
    pub fn anchor_set(&self) -> vox_core::error::Result<BootstrapSet> {
        let mut set = BootstrapSet::new();
        for spec in &self.anchors {
            if spec.trim().is_empty() {
                continue;
            }
            merge_anchor_spec(&mut set, spec)?;
        }
        Ok(set)
    }
}

/// The default bind address: every interface, kernel-chosen port. The bound address
/// is not what peers are told to dial (see [`ProfileArgs::listen`]), so binding
/// broadly is right.
const DEFAULT_LISTEN: &str = "0.0.0.0:0";

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
    Tui(ProfileArgs),
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
    let default_tui = Cmd::Tui(ProfileArgs {
        profile: DEFAULT_PROFILE.to_owned(),
        data_dir: std::env::var_os("VOX_DATA_DIR").map(PathBuf::from),
        config_dir: std::env::var_os("VOX_CONFIG_DIR").map(PathBuf::from),
        listen: DEFAULT_LISTEN
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
        anchors: std::env::var("VOX_ANCHORS")
            .map(|v| v.split(',').map(str::to_owned).collect())
            .unwrap_or_default(),
    });
    match cli.command.unwrap_or(default_tui) {
        Cmd::Tui(args) => {
            let paths = match args.paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let anchors = match args.anchor_set() {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("vox: --anchor: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match run_live(paths, args.listen, anchors) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("vox: {e}");
                    ExitCode::FAILURE
                }
            }
        }
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
