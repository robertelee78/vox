//! The `vox` command-line surface (ADR-015 §"Distribution").
//!
//! The interactive TUI is the default (`vox` or `vox tui`); `vox node` runs the
//! headless anchor (ADR-016 M15.2a); `vox update` replaces the binary from GitHub
//! Releases and `vox shell-setup` puts it on `PATH` with completion (ADR-015
//! §"Install and update"); `vox completions <shell>` and `vox man` emit shell
//! completions and a man page (built from the same clap model, so they never
//! drift from the real flags). [`run`] is the single entry the binary calls. The TUI always runs an embedded node over a
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

use crate::app::{run_live, run_node};

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

/// The room args of whichever `service` subcommand this is.
fn sub_room(sub: &ServiceCmd) -> &RoomArgs {
    match sub {
        ServiceCmd::Add(a) => &a.room,
        ServiceCmd::Remove(r) => &r.room,
        ServiceCmd::List(r) => r,
    }
}

/// The shape every one-shot tunnel verb shares: resolve the profile, collect the two
/// passphrases, open the room, run the verb, report.
fn run_tunnel_verb<F, Fut>(room: RoomArgs, body: F) -> ExitCode
where
    F: FnOnce(vox_core::node::actor::NodeHandle, vox_core::hash::Digest32) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), crate::app::AppError>>,
{
    let paths = match room.profile.paths() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vox: {e}");
            return ExitCode::FAILURE;
        }
    };
    let anchors = match room.profile.anchor_set() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("vox: --anchor: {e}");
            return ExitCode::FAILURE;
        }
    };
    let identity = match crate::tunnel_cli::passphrase_or_prompt(
        room.identity_passphrase.as_ref(),
        "identity passphrase",
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vox: {e}");
            return ExitCode::FAILURE;
        }
    };
    let room_pp = match crate::tunnel_cli::passphrase_or_prompt(
        room.passphrase.as_ref(),
        "room passphrase",
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vox: {e}");
            return ExitCode::FAILURE;
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("vox: {e}");
            return ExitCode::FAILURE;
        }
    };
    let target = crate::tunnel_cli::RoomTarget {
        paths,
        listen: room.profile.listen,
        anchors,
        identity_passphrase: identity,
        room: room.room.clone(),
        room_passphrase: room_pp,
    };
    let outcome = rt.block_on(async move { crate::tunnel_cli::with_room(target, body).await });
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vox: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The shape the room-*making* verbs share (`vox serve`, `vox connect`): resolve the
/// profile, unlock the identity — creating it on first use — and run the verb.
///
/// Unlike [`run_tunnel_verb`] these do not open an existing room: `serve` is about to
/// create one and `connect` is about to join one, so neither has a room id or a room
/// passphrase to collect up front.
fn run_new_room_verb<F, Fut>(
    profile: ProfileArgs,
    identity_passphrase: Option<String>,
    body: F,
) -> ExitCode
where
    F: FnOnce(vox_core::node::actor::NodeHandle, BootstrapSet) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), crate::app::AppError>>,
{
    let paths = match profile.paths() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vox: {e}");
            return ExitCode::FAILURE;
        }
    };
    let anchors = match profile.anchor_set() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("vox: --anchor: {e}");
            return ExitCode::FAILURE;
        }
    };
    let identity = match crate::tunnel_cli::identity_passphrase_for(&paths, identity_passphrase) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vox: {e}");
            return ExitCode::FAILURE;
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("vox: {e}");
            return ExitCode::FAILURE;
        }
    };
    let listen = profile.listen;
    let anchors_for_body = anchors.clone();
    let outcome = rt.block_on(async move {
        let node = crate::tunnel_cli::open_profile(paths, listen, anchors, &identity).await?;
        body(node, anchors_for_body).await
    });
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vox: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `vox service …`
#[derive(Subcommand, Clone)]
enum ServiceCmd {
    /// Offer a local TCP service in a room.
    Add(ServiceAddArgs),
    /// Stop offering a service.
    Remove(ServiceRemoveArgs),
    /// List the services offered in a room.
    List(RoomArgs),
}

/// Selecting a room, by the prefix of its channelID as `vox` prints it.
#[derive(Args, Debug, Clone)]
pub struct RoomArgs {
    #[command(flatten)]
    pub profile: ProfileArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// The room's passphrase. Prompted for (unechoed) when omitted, which is the way
    /// to give it: a passphrase in a flag is in the shell's history.
    #[arg(long, env = "VOX_ROOM_PASSPHRASE")]
    pub passphrase: Option<String>,
    /// The identity passphrase. Prompted for when omitted.
    #[arg(long, env = "VOX_IDENTITY_PASSPHRASE")]
    pub identity_passphrase: Option<String>,
}

/// `vox service add`
#[derive(Args, Debug, Clone)]
pub struct ServiceAddArgs {
    #[command(flatten)]
    pub room: RoomArgs,
    /// The service tag members will dial, e.g. `ssh`.
    pub tag: String,
    /// The local address the service listens on, e.g. `127.0.0.1:22`.
    pub local: SocketAddr,
}

/// `vox service remove`
#[derive(Args, Debug, Clone)]
pub struct ServiceRemoveArgs {
    #[command(flatten)]
    pub room: RoomArgs,
    /// The service tag to stop offering.
    pub tag: String,
}

/// `vox forward`
#[derive(Args, Debug, Clone)]
pub struct ForwardArgs {
    #[command(flatten)]
    pub room: RoomArgs,
    /// The member hosting the service (its fingerprint, or a unique prefix).
    pub host: String,
    /// The service tag to reach.
    pub tag: String,
    /// Where to listen locally; port 0 picks one.
    #[arg(default_value = "127.0.0.1:0")]
    pub local: SocketAddr,
}

/// `vox grant`
#[derive(Args, Debug, Clone)]
pub struct GrantArgs {
    #[command(flatten)]
    pub room: RoomArgs,
    /// The member being granted (fingerprint or unique prefix).
    pub member: String,
    /// The service tag they may dial.
    pub tag: String,
    /// Also let them offer the service themselves.
    #[arg(long)]
    pub may_bind: bool,
    /// How long the grant lasts, in days.
    #[arg(long, default_value_t = 365)]
    pub days: u64,
}

/// `vox serve`
#[derive(Args, Debug, Clone)]
pub struct ServeArgs {
    #[command(flatten)]
    pub profile: ProfileArgs,
    /// The local TCP port to offer. It is also the service's name: guests reach it at
    /// this port of the room's `.vox` hostname.
    pub port: u16,
    /// The local endpoint to carry connections to, when it is not `127.0.0.1:<port>`.
    #[arg(long)]
    pub at: Option<SocketAddr>,
    /// A local name for the room (this device only; never leaves it).
    #[arg(long, default_value = "service")]
    pub name: String,
    /// The identity passphrase. Prompted for when omitted.
    #[arg(long, env = "VOX_IDENTITY_PASSPHRASE")]
    pub identity_passphrase: Option<String>,
}

/// `vox connect`
#[derive(Args, Debug, Clone)]
pub struct ConnectArgs {
    #[command(flatten)]
    pub profile: ProfileArgs,
    /// The `vox://…` address you were given.
    pub address: String,
    /// The room passphrase. Prompted for (unechoed) when omitted, which is the way to
    /// give it: a passphrase in a flag is in the shell's history.
    #[arg(long, env = "VOX_ROOM_PASSPHRASE")]
    pub passphrase: Option<String>,
    /// A local name for the room (this device only).
    #[arg(long, default_value = "service")]
    pub name: String,
    /// The identity passphrase. Prompted for when omitted.
    #[arg(long, env = "VOX_IDENTITY_PASSPHRASE")]
    pub identity_passphrase: Option<String>,
}

/// `vox up`
#[derive(Args, Debug, Clone)]
pub struct UpArgs {
    #[command(flatten)]
    pub room: RoomArgs,
    /// Where the proxy listens. Loopback only, and a port above 1024 — nothing here needs
    /// privilege.
    #[arg(long, default_value = "127.0.0.1:1080")]
    pub bind: SocketAddr,
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
    /// Run a headless node: the always-on anchor that serves the board, coordinates
    /// hole punches and carries circuits for your rooms. It holds no room and can
    /// read nothing; its identity is a key file in the profile directory, created on
    /// first run. Prints the `<fingerprint>@<multiaddr>` to give clients as `--anchor`.
    Node(ProfileArgs),
    /// Offer a local TCP port as a room-bound service, in one command (ADR-017).
    ///
    /// Creates a room whose genesis grants every member the right to reach that port —
    /// so joining the room *is* the authorization and you never wait to grant anyone
    /// anything — offers the port in it, and prints the address, the machine-generated
    /// passphrase and the `.vox` hostname it answers on. Runs until interrupted,
    /// reporting who reaches the service (the service itself cannot tell you: every Vox
    /// client arrives at it from loopback).
    Serve(ServeArgs),
    /// Join a room from the address you were given, and print the name its services
    /// answer on (ADR-017). One-shot: joining is durable, so there is nothing to keep
    /// running — `vox up` is what makes the name resolve.
    Connect(ConnectArgs),
    /// Offer a local TCP service to a room, or list what is offered (ADR-013).
    ///
    /// A service is dark by default: offering it grants nobody reach. Members reach it
    /// only once they hold `dial:<tag>`, which `vox grant` puts on the room's log.
    #[command(subcommand)]
    Service(ServiceCmd),
    /// Bring up the local entry point for a room's services: a SOCKS5 proxy that resolves
    /// the room's `.vox` name (ADR-017).
    ///
    /// This is how a tool reaches a room-bound service by name — the same shape a Tor user
    /// reaches a `.onion` through, and for the same reason: it needs no privilege of any
    /// kind. `ssh` is pointed at it with one `ProxyCommand` line, which `vox up` prints;
    /// most other tools take `ALL_PROXY=socks5h://…`. Runs until interrupted.
    Up(UpArgs),
    /// Forward a local port to a member's service over the overlay — `ssh` over Vox
    /// (ADR-013). Runs until interrupted.
    Forward(ForwardArgs),
    /// Grant a member the capability to dial one of your services, as a fact on the
    /// room's log (ADR-007/ADR-013).
    Grant(GrantArgs),
    /// Put `vox` on PATH and install tab completion for your shell.
    ///
    /// `install.sh` and `vox update` run this for you. It writes the completion script into
    /// your shell's own autoload directory and maintains one marked block at the end of your
    /// shell's startup file — at the end, so it wins the PATH race against version managers
    /// that prepend their shims earlier in the same file. Idempotent; `--remove` undoes it
    /// exactly; `VOX_NO_SHELL_SETUP=1` skips it.
    ShellSetup {
        /// Remove everything `vox shell-setup` installed.
        #[arg(long)]
        remove: bool,
    },
    /// Replace this `vox` with the latest GitHub release (ADR-015).
    ///
    /// Fetches the per-target release record, verifies the download's size and SHA-256 against
    /// it before anything is renamed, keeps the binary it replaced as `.vox-previous`, and
    /// refreshes your shell completions. Only an install `install.sh` or a previous `vox
    /// update` made is replaced in place; a build from source is refused, not overwritten.
    Update {
        /// Report whether a newer release exists, and change nothing.
        #[arg(long)]
        check: bool,
        /// Put the binary this replaced back, and swap the two, so it is reversible again.
        #[arg(long, conflicts_with = "check")]
        rollback: bool,
    },
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
        Cmd::Node(args) => {
            let paths = match args.paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox node: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let anchors = match args.anchor_set() {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("vox node: --anchor: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match run_node(paths, args.listen, anchors) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("vox node: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Serve(args) => {
            let a = args.clone();
            run_new_room_verb(
                args.profile.clone(),
                args.identity_passphrase.clone(),
                move |node, anchors| async move {
                    crate::tunnel_cli::serve(&node, &anchors, &a.name, a.port, a.at).await
                },
            )
        }
        Cmd::Connect(args) => {
            let room_pp = match crate::tunnel_cli::passphrase_or_prompt(
                args.passphrase.as_ref(),
                "room passphrase",
            ) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let a = args.clone();
            run_new_room_verb(
                args.profile.clone(),
                args.identity_passphrase.clone(),
                move |node, _anchors| async move {
                    crate::tunnel_cli::connect(&node, &a.address, &a.name, &room_pp).await
                },
            )
        }
        Cmd::Service(sub) => run_tunnel_verb(sub_room(&sub).clone(), move |node, cid| {
            let sub = sub.clone();
            async move {
                match &sub {
                    ServiceCmd::Add(a) => {
                        crate::tunnel_cli::service_add(&node, cid, &a.tag, a.local).await
                    }
                    ServiceCmd::Remove(r) => {
                        crate::tunnel_cli::service_remove(&node, cid, &r.tag).await
                    }
                    ServiceCmd::List(_) => {
                        crate::tunnel_cli::service_list(&node, cid);
                        Ok(())
                    }
                }
            }
        }),
        Cmd::Grant(args) => {
            let a = args.clone();
            run_tunnel_verb(args.room.clone(), move |node, cid| async move {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or_default();
                crate::tunnel_cli::grant(&node, cid, &a.member, &a.tag, a.may_bind, a.days, now)
                    .await
            })
        }
        Cmd::Up(args) => {
            let bind = args.bind;
            run_tunnel_verb(args.room.clone(), move |node, cid| async move {
                crate::tunnel_cli::up(&node, cid, bind).await
            })
        }
        Cmd::Forward(args) => {
            let a = args.clone();
            run_tunnel_verb(args.room.clone(), move |node, cid| async move {
                crate::tunnel_cli::forward(&node, cid, &a.host, &a.tag, a.local).await
            })
        }
        Cmd::ShellSetup { remove } => crate::shell::run(remove),
        Cmd::Update { check, rollback } => match crate::update::run(check, rollback) {
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
