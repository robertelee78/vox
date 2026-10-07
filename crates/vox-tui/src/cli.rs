//! The `vox` command-line surface (ADR-015 §"Distribution").
//!
//! The interactive TUI is the default (`vox` or `vox tui`); `vox node` runs the
//! headless anchor (ADR-016 M15.2a); `vox update` replaces the binary from GitHub
//! Releases and `vox shell-setup` puts it on `PATH` with completion (ADR-015
//! §"Install and update"); `vox completions <shell>` and `vox man` emit shell
//! completions and a man page (built from the same clap model, so they never
//! drift from the real flags). [`run`] is the single entry the binary calls. Every verb is a
//! client of the account's daemon (ADR-026 S-3): `--node` names the node it acts as, and
//! `--data-dir`, `--config-dir` the account (ADR-015 precedence: flags > env > defaults; env
//! `VOX_NODE`, `VOX_DATA_DIR`, `VOX_CONFIG_DIR`, then XDG).

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, CommandFactory, Parser, Subcommand};
use vox_core::node::paths::Paths;

use crate::app::{run_live, run_node, AppError};

pub use crate::client::NodeArgs;

/// Run a verb that holds a session on the daemon: `serve`, `connect`, `up`,
/// `forward`.
///
/// **The whole run races every stop signal, from before the first prompt**: the
/// passphrase prompts run on a blocking thread inside `work`. A server's stop (`vox serve`) is its
/// normal end and exits 0, as a service manager expects of a service it stopped; any other verb
/// stopped before it finished exits 128 + the signal's number, saying what it waited for.
/// Stopping the client leaves the node as the daemon has it: the hold this verb took
/// goes with its connection (L-3), and nothing here has a node to shut down.
fn run_session<Fut>(waiting: std::sync::Arc<crate::tunnel_cli::Waiting>, work: Fut) -> ExitCode
where
    Fut: std::future::Future<Output = Result<(), crate::app::AppError>>,
{
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
    let (outcome, stopped) = rt.block_on(async move {
        // Taken here, before the work is first polled, so before its first prompt.
        let stop = crate::app::stop_requested("vox");
        tokio::select! {
            signal = stop => {
                let why = if waiting.serves() {
                    crate::app::say(format_args!("vox: stopped by {}", signal.name()));
                    crate::app::say(format_args!("vox: stopping"));
                    Ok(())
                } else if waiting.held() {
                    // A held client (`vox up`, `vox forward`, `vox lan up`): stopped as a client
                    // is, 128 + the signal's number, saying which signal (V210-108).
                    Err(crate::app::AppError::stopped_by(signal))
                } else {
                    Err(waiting.stopped_by(signal))
                };
                (why, true)
            }
            done = work => (done, false),
        }
    });
    if stopped {
        // A prompt stopped part-way leaves the terminal in raw mode: no echo, no line editing, in
        // the shell it hands back to. Nothing to undo when no prompt was open.
        let _ = crossterm::terminal::disable_raw_mode();
    }
    let code = match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Not `eprintln!`: after a hangup stderr can be a terminal that is gone, and a write
            // that fails there must not turn the reason into a panic.
            use std::io::Write as _;
            let _ = writeln!(io::stderr(), "vox: {e}");
            e.exit_code()
        }
    };
    // **A stop is not a wait for the work it abandoned.** Dropping the runtime waits for its
    // blocking threads, and one can still be reading the terminal.
    if stopped {
        rt.shutdown_background();
    }
    code
}

/// The identity passphrase sources a held verb was given.
fn pass(flag: Option<String>, file: Option<std::path::PathBuf>) -> crate::client::Pass {
    crate::client::Pass { flag, file }
}

/// The service label a person's spec names: `53/udp` is `udp/53`, and
/// anything that is not a port spec is used as the tag it already is.
fn label_of(spec: &str) -> String {
    vox_core::tunnel::udp::service_label(spec).unwrap_or_else(|| spec.to_owned())
}

/// Run a verb that attaches to the node through the daemon already holding it.
fn run_attached<Fut>(body: Fut) -> ExitCode
where
    Fut: std::future::Future<Output = Result<(), crate::app::AppError>>,
{
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
    match rt.block_on(body) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vox: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The name `vox trust add` files an identity under: `--name`, or asked for on a
/// terminal. With neither it is refused at once: every identity under one default name could
/// not be told apart, nor addressed.
fn trust_name(a: &TrustAddArgs) -> Result<String, crate::app::AppError> {
    use std::io::{BufRead as _, IsTerminal as _, Write as _};
    if let Some(n) = a.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
        return Ok(n.to_owned());
    }
    if !std::io::stdin().is_terminal() {
        return Err(crate::app::AppError::Usage(
            "name it: vox trust add <fingerprint> --name <your name for it>".into(),
        ));
    }
    let mut err = std::io::stderr();
    let _ = write!(err, "Your name for {}: ", a.fingerprint.trim());
    let _ = err.flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    match line.trim() {
        "" => Err(crate::app::AppError::Usage(
            "no name given; nothing was trusted".into(),
        )),
        n => Ok(n.to_owned()),
    }
}

/// Run a trust verb against the daemon already holding this node.
fn run_trust_over_socket(sub: TrustCmd) -> ExitCode {
    let name = match &sub {
        TrustCmd::Add(a) => match trust_name(a) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("vox: {e}");
                return ExitCode::FAILURE;
            }
        },
        _ => String::new(),
    };
    let (profile, pass, pass_file) = match &sub {
        TrustCmd::List(a) => (
            a.profile.clone(),
            a.identity_passphrase.clone(),
            a.identity_passphrase_file.clone(),
        ),
        TrustCmd::Add(a) => (
            a.profile.clone(),
            a.identity_passphrase.clone(),
            a.identity_passphrase_file.clone(),
        ),
        TrustCmd::Remove(a) => (
            a.profile.clone(),
            a.identity_passphrase.clone(),
            a.identity_passphrase_file.clone(),
        ),
        TrustCmd::Rename(a) => (
            a.profile.clone(),
            a.identity_passphrase.clone(),
            a.identity_passphrase_file.clone(),
        ),
        TrustCmd::Drive(a) | TrustCmd::Read(a) => (
            a.profile.clone(),
            a.identity_passphrase.clone(),
            a.identity_passphrase_file.clone(),
        ),
    };
    let paths = match profile.paths() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vox: {e}");
            return ExitCode::FAILURE;
        }
    };
    // **A keyring change's passphrase is typed** (ADR-028 K-13): a read needs none, and a change
    // asks for it at the terminal only when the node says it is needed (V210-159, V210-165). A
    // passphrase given on the command line or in a file is refused, saying so.
    if !matches!(sub, TrustCmd::List(_)) {
        if pass.is_some() {
            eprintln!(
                "vox: --identity-passphrase is refused: a keyring change's passphrase is typed at \
                 a terminal"
            );
            return ExitCode::FAILURE;
        }
        if pass_file.is_some() {
            eprintln!(
                "vox: --identity-passphrase-file is refused: a keyring change's passphrase is \
                 typed at a terminal, never read from a file"
            );
            return ExitCode::FAILURE;
        }
    }
    drop((pass, pass_file));
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
    let outcome = rt.block_on(async move {
        match sub {
            TrustCmd::List(_) => crate::room_cli::trust_list(&paths).await,
            TrustCmd::Add(a) => {
                let target = crate::tunnel_cli::parse_fingerprint(&a.fingerprint)?;
                crate::room_cli::trust_add(&paths, target, &name, a.history == "full", a.drive)
                    .await
            }
            TrustCmd::Remove(a) => {
                let target = crate::tunnel_cli::parse_fingerprint(&a.fingerprint)?;
                crate::room_cli::trust_remove(&paths, target).await
            }
            TrustCmd::Rename(a) => {
                crate::room_cli::trust_rename(&paths, &a.fingerprint, &a.name).await
            }
            TrustCmd::Drive(a) => {
                crate::room_cli::trust_capability(&paths, &a.fingerprint, true).await
            }
            TrustCmd::Read(a) => {
                crate::room_cli::trust_capability(&paths, &a.fingerprint, false).await
            }
        }
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
    ///
    /// Only a room this node holds open. Listing opens no room, so it asks for no room
    /// passphrase, and a room you closed stays closed.
    List(ServiceListArgs),
}

/// `vox lan` — the family LAN.
#[derive(Subcommand, Debug, Clone)]
enum LanCmd {
    /// Create LAN interfaces for `vox lan up`, as root. Run it with `sudo`: it serves only
    /// the person who ran `sudo` (or, run by Vox.app's login-time helper, the person who owns
    /// Vox.app), accepts only LAN addresses (`100.64.0.0/10`,
    /// `fd00::/8`), opens no node and touches no network. Runs until interrupted;
    /// interfaces it made live exactly as long as the `vox lan up` holding them.
    Helper(LanHelperArgs),
    /// Bring this machine onto a room's LAN, through the helper. Run it as yourself, not
    /// with `sudo`. Runs until interrupted, and the interface goes with it.
    Up(Box<LanUpArgs>),
}

/// `vox lan helper`
#[derive(Args, Debug, Clone)]
pub struct LanHelperArgs {
    /// Where to listen.
    #[arg(long, default_value = crate::lan_cli::DEFAULT_HELPER_SOCKET)]
    pub socket: PathBuf,
    /// Serve the person who owns the Vox.app this `vox` is inside, as the app's login-time
    /// helper does, instead of the person who ran `sudo`. Refused for a Vox.app
    /// owned by root, one with a directory or file down to this `vox` that others may write,
    /// or one not signed by the same Developer ID team as this `vox`.
    #[arg(long)]
    pub serve_bundle_owner: bool,
}

/// `vox lan up`
#[derive(Args, Debug, Clone)]
pub struct LanUpArgs {
    #[command(flatten)]
    pub room: RoomArgs,
    /// The helper's socket.
    #[arg(long, default_value = crate::lan_cli::DEFAULT_HELPER_SOCKET)]
    pub helper_socket: PathBuf,
    /// Write the plan, the links and the counters here as JSON, twice a second.
    #[arg(long)]
    pub stats_file: Option<PathBuf>,
    /// Local ports members may reach over the LAN, comma-separated (`--allow 32400,8009`).
    /// **None by default**: without it nothing on this machine is reachable over the LAN,
    /// while discovery (mDNS, SSDP, broadcast) still flows and replies to what this machine
    /// sends still come back. ICMP echo always passes.
    #[arg(long, value_delimiter = ',')]
    pub allow: Vec<u16>,
    /// Serve Prometheus metrics at this address, as `vox daemon --metrics` does.
    /// Loopback only: the counters name every peer and room this node talks to.
    #[arg(long)]
    pub metrics: Option<SocketAddr>,
}

/// `vox app` — app streams from a shell, over a running node.
#[derive(Subcommand, Debug, Clone)]
enum AppCmd {
    /// Wait for one app stream speaking `label` in `room`, accept it, and pipe it to
    /// stdin and stdout.
    Listen(AppListenArgs),
    /// Open an app stream to `peer`, speaking the first of the labels it listens for,
    /// and pipe it to stdin and stdout.
    Open(AppOpenArgs),
}

/// `vox app listen`
#[derive(Args, Debug, Clone)]
pub struct AppListenArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// The label to listen for, `name/vN`.
    pub label: String,
}

/// `vox app open`
#[derive(Args, Debug, Clone)]
pub struct AppOpenArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// The member to open to (fingerprint, or a unique prefix).
    pub peer: String,
    /// The labels to offer, in preference order (at most 8).
    #[arg(required = true)]
    pub labels: Vec<String>,
    /// Also bind a datagram flow: each stdin line goes as one datagram, and each
    /// datagram received is printed as one line.
    #[arg(long)]
    pub datagrams: bool,
}

/// `vox room` — the agent-comms verbs, over a running node.
#[derive(Subcommand, Debug, Clone)]
enum RoomCmd {
    /// Append a message to a room.
    ///
    /// With no text, or `-`, the message is read from stdin — which is the form to
    /// use for an agent-comms envelope, because JSON on a command line is where
    /// quoting goes wrong.
    ///
    /// A message carrying a link gets a link card: this node fetches the page of its first
    /// http(s) link once, and its title, description and an image of at most 16 KB travel in the
    /// message, so no reader's node reaches the site. That fetch tells the linked site this
    /// machine's IP address. Only public addresses are fetched: a link to this machine or a
    /// private network goes without a card. `--no-card` posts without one.
    Post(RoomPostArgs),
    /// Print a room's messages. The first column is the entry hash, which is the
    /// cursor: pass the last one back as `--since` to read only what is new.
    Read(RoomReadArgs),
    /// Print new messages as they arrive, until stopped.
    ///
    /// SIGINT (Ctrl-C), SIGTERM, SIGHUP or SIGQUIT each stops it cleanly.
    ///
    /// With `--since`, first every message after that cursor, then every new one —
    /// **with no gap across a lag or a restart**. Persist the last entry
    /// hash you processed and pass it back to resume. `--json` prints one
    /// `vox.room.row/1` object per line.
    Tail(RoomTailArgs),
    /// Print the fingerprints of the room's members.
    Roster(RoomRefArgs),
    /// The room's Sessions: one per harness session working in the room, each by your
    /// name for its node, the session's name and its short id; open ones first, ended ones apart.
    Sessions(RoomSessionsArgs),
    /// Read one Session of the room: what that harness session did, one line per activity.
    ///
    /// Tool calls with what they returned, the replies, the end of each turn, what was typed at
    /// the terminal or in Vox, approvals and questions with who answered them, files either way.
    /// `--details` prints each entry's full input and output under its line. Only members the
    /// session's node trusts with drive see inside a Session; anyone else is told so.
    Session(RoomSessionArgs),
    /// Ask a member's node which agent sessions it holds, and whether each can be reached.
    ///
    /// The ping is answered by that node's **daemon**, never by a model: it lists each session,
    /// whether an urgent message interrupts it, and when it last read. Pings and answers are
    /// never shown to a model and wake no one. A node answers only a member it trusts, so no
    /// answer cannot tell an offline node and missing trust in either direction apart, and says
    /// so. Exits 1 when no answer comes within `--wait`.
    ///
    /// For example:
    ///
    /// vox room ping <room> carol
    Ping(RoomPingArgs),
    /// List the rooms this node holds.
    List(NodeArgs),
    /// Take a unit of work, so no other agent starts it.
    ///
    /// The room is the record of who holds what. Holding an item is not progress: the
    /// attempt itself is recorded on the GitHub issue through awa.
    ///
    /// A claim is a post in the room: ownership is whatever the room's log resolves
    /// to, the same on every member. It says "you hold it" (exit 0) only once every
    /// other member has the claim and resolves it the same way. Of two claims made at
    /// once, the one the room orders first wins, and the other is told at once who got
    /// it (exit 1). A member that cannot be reached, or does not agree yet, is named
    /// and the exit status is 5; the claim stays posted. `--ttl` is what makes an
    /// agent that dies holding work release it without anyone noticing it died.
    ///
    /// Ownership is per **session**: the session comes from `--session`,
    /// `VOX_SESSION`, or the harness (`CLAUDE_CODE_SESSION_ID`, `CODEX_THREAD_ID`).
    /// Every participant must run this exact vox version, or the claim is refused
    /// with exit status 3. A claim also completes a handoff pending for this session.
    Claim(ClaimArgs),
    /// Give a unit of work up. Only the exact holding session's release counts, and
    /// releasing means neither done nor failed.
    Release(ResourceArgs),
    /// Relinquish a unit of work and reserve it for another harness, named by
    /// fingerprint; it completes when an eligible session of it claims it.
    Handoff(HandoffArgs),
    /// Refuse a handoff pending for this session. The work is freed, not returned.
    Decline(ResourceArgs),
    /// Extend this session's current holding by its original `--ttl`.
    Renew(ResourceArgs),
    /// Show what is held or pending, by whom, until when — and whether coordination
    /// is refused because a participant runs another vox version.
    Board(RoomBoardArgs),
    /// Join a room from a `vox://` address, over a running node. The room keeps its own name,
    /// the one its creator or an admin gave it.
    ///
    /// The passphrase is asked for at the terminal, or read from `--passphrase-file`
    /// (`-` reads stdin); never argv, which anything that can run `ps` would see:
    ///
    /// For example:
    ///
    /// echo 'the room passphrase' | vox room join --passphrase-file - vox://…
    ///
    /// This is what makes agent comms usable on a host with no terminal: `vox
    /// daemon` lets a node hold rooms unattended, and this is how a room gets
    /// onto it. Joining grants nothing — whether anyone can read you is their
    /// decision, made with `vox trust`.
    Join(JoinRoomArgs),
    /// Create a room on a running node, under a name every member sees. Passphrase at the
    /// terminal, or from `--passphrase-file` (`-` reads stdin).
    Create(CreateRoomArgs),
    /// Give a room a new name, for every member. Only the room's creator or an admin may, and it
    /// asks for the identity passphrase for that reason.
    ///
    /// The name is one DNS label (a-z, 0-9 and `-`), because it is the room part of every service
    /// address in the room.
    Rename(RenameArgs),
    /// Set how long the room keeps messages: `1h`, `1w`, `1m` (a month), a number of
    /// seconds, or `forever`.
    ///
    /// It applies to **everything already in the room**, on every member, as the change
    /// reaches them: shortening it deletes older messages. Only the room's admin may, and it
    /// asks for the identity passphrase for that reason. A node can keep less than its room
    /// (the `retention` file in its config directory); the shorter wins. This is look and
    /// feel, not a security property: a modified node can keep everything.
    Retention(RetentionArgs),
    /// Print a room's link, for someone else to `vox room join` with.
    ///
    /// The link is rendezvous information, not a credential — no passphrase,
    /// and joining with it grants nothing. Goes to stdout so it pipes; the
    /// warnings go to stderr so they do not.
    Link(RoomRefArgs),
    /// Leave a room: the other members are told, then the room is deleted from this node.
    ///
    /// Waits up to 30 s for another member to take the news. If none can be told by then, it
    /// says so, and the node leaves as soon as one can. Joining again later works.
    Leave(RoomRefArgs),
    /// End a room for everyone. Only the room's creator, or an admin it named, may.
    ///
    /// Every member's node takes no new message in it from then on, passes the end on, and
    /// deletes the room.
    End(RoomRefArgs),
    /// Make a member an admin of a room, take it back, or list the admins:
    /// `vox room admin add|remove <room> <member>`, `vox room admin list <room>`.
    ///
    /// Only the room's creator may add or remove an admin. An admin may end the room for
    /// everyone (`vox room end`).
    Admin(AdminArgs),
    /// Collect a file offered in this room, verifying it against the announced
    /// SHA-256 before it is usable.
    ///
    /// A mismatch removes the partial file rather than leaving something that
    /// looks complete — a truncated `nc` transfer is the classic way this bites.
    Get(GetFileArgs),
}

/// `vox room join`
#[derive(Args, Debug, Clone)]
pub struct JoinRoomArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The `vox://` address you were given.
    pub link: String,
    /// Read the room passphrase from this file; `-` reads it from stdin. Without it, it is
    /// asked for at the terminal, and with no terminal the command fails at once.
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
}

/// `vox room create`
#[derive(Args, Debug, Clone)]
pub struct CreateRoomArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's name, which every member sees: one DNS label (a-z, 0-9 and `-`), because it
    /// is the room part of every service address in it. Its creator or an admin can change it
    /// with `vox room rename`.
    #[arg(long)]
    pub name: String,
    /// Read the new room's passphrase from this file; `-` reads it from stdin. Without it, it
    /// is asked for twice at the terminal, and with no terminal the command fails at once.
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
    /// End the room by itself after this long with nothing said in it: `1h`, `1w`, `1m`
    /// (a month), or a number of seconds. Off unless given.
    #[arg(long)]
    pub idle_end: Option<String>,
}

/// `vox room admin`
#[derive(Args, Debug, Clone)]
pub struct AdminArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// `add`, `remove` or `list`.
    pub action: String,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// The member, by fingerprint or a unique prefix of it (for `add` and `remove`).
    pub member: Option<String>,
}

/// `vox room rename`
#[derive(Args, Debug, Clone)]
pub struct RenameArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room: its name, or its id or a unique prefix of it.
    pub room: String,
    /// The new name: one DNS label (a-z, 0-9 and `-`). Asks for no passphrase.
    pub name: String,
}

/// `vox room retention`
#[derive(Args, Debug, Clone)]
pub struct RetentionArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// `1h`, `1w`, `1m` (a month), a number of seconds, or `forever`. Asks for no passphrase.
    pub duration: String,
}

/// `vox room get`
#[derive(Args, Debug, Clone)]
pub struct GetFileArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// The file's name, or a prefix of its SHA-256, or its service tag.
    pub file: String,
    /// The directory to put it in, under the sender's name made safe. Without it (or --out),
    /// the file lands in the node's files directory for the room:
    /// `<data root>/nodes/<node>/files/<room id>/`, and is deleted when its message expires.
    #[arg(long, conflicts_with = "out")]
    pub dir: Option<PathBuf>,
    /// An exact path to write it to instead. Refused if something is already there.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

/// `vox daemon`
#[derive(Args, Debug, Clone)]
pub struct DaemonArgs {
    #[command(flatten)]
    pub profile: AccountArgs,
    /// Read the passphrases from this file, for a service manager that prefers one: the
    /// identity passphrase on the first line, then any room lines. Without it the identity
    /// passphrase is taken from `VOX_IDENTITY_PASSPHRASE`, else asked for at the terminal,
    /// else read from stdin.
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
    /// Serve Prometheus metrics at this address. Loopback only: the
    /// counters name every peer and room this node talks to.
    #[arg(long)]
    pub metrics: Option<SocketAddr>,
    /// The node to attach in the foreground. Without it: the only node on disk,
    /// else `default` when there is none, else no node (the daemon runs with none).
    #[arg(long, env = "VOX_NODE")]
    pub node: Option<String>,
    /// Start the daemon in the background and return once it answers; its output goes to
    /// `<data root>/.daemon/log`. It exits once it has no attached node and no client.
    #[arg(long, conflicts_with_all = ["keep", "passphrase_file"])]
    pub detach: bool,
    /// Keep the foreground node attached across daemon restarts (`.daemon/attach`).
    /// Its passphrase comes from `--passphrase-file` then, or it has none.
    #[arg(long)]
    pub keep: bool,
    /// For a service manager, such as the macOS login item: no foreground node and nothing
    /// asked for, running until stopped; kept nodes attach as always. With a daemon already
    /// running for this data root it says so and waits, serving once that one stops.
    #[arg(long, conflicts_with_all = ["node", "keep", "passphrase_file", "detach"])]
    pub no_node: bool,
    /// How a client starts the daemon: its own session, no foreground node, and an
    /// exit once nothing is attached and no client is connected.
    #[arg(long = "as-detached", hide = true)]
    pub as_detached: bool,
    /// How the macOS app's login item runs it (launchd, which restarts it after a failed exit):
    /// a start refused for good (run as root, or a data root this version does not read) is
    /// written to `~/Library/Logs/Vox/login-item.log` and ends with status 0, so launchd does not
    /// start it again every ten seconds; the app quotes that line.
    #[arg(long = "login-item", hide = true)]
    pub login_item: bool,
    /// Where the `.vox` SOCKS5 proxy listens while a node is attached. Loopback only.
    #[arg(long, env = "VOX_PROXY", default_value = crate::daemon_proxy::DEFAULT_PROXY)]
    pub proxy: SocketAddr,
}

/// `vox tunnel …`.
#[derive(Subcommand, Debug, Clone)]
pub enum TunnelCmd {
    /// Close live tunnels: one by its number, or a member's — all of them, or those to one
    /// service. `vox status` lists them, with their numbers.
    ///
    /// On the host, this closes a member's sessions to your services; on a guest, a session your
    /// `vox up` or `vox forward` carries. Nobody is untrusted and no service is removed: the
    /// member can open a new tunnel at once. The far end is told the tunnel was closed.
    Close(TunnelCloseArgs),
}

/// `vox tunnel close`
#[derive(Args, Debug, Clone)]
pub struct TunnelCloseArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The member whose tunnels to close: their id as `vox status` prints it, or the start of it.
    #[arg(required_unless_present = "id")]
    pub member: Option<String>,
    /// Only the member's tunnels to this service (a port, or an offer's tag).
    pub service: Option<String>,
    /// One tunnel, by the number `vox status` shows for it.
    #[arg(long, conflicts_with_all = ["member", "service"])]
    pub id: Option<u64>,
}

/// `vox share`
#[derive(Args, Debug, Clone)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
pub struct ShareArgs {
    /// `vox share stop|list`; without one, `vox share ROOM PATH` shares.
    #[command(subcommand)]
    pub cmd: Option<ShareCmd>,
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    #[arg(required = true)]
    pub room: Option<String>,
    /// The file or folder to share. A folder's announcement lists every file in it, and a
    /// member pulling it again fetches only the files that changed.
    #[arg(required = true)]
    pub path: Option<PathBuf>,
    /// Address a member of the room: your name for it (`vox trust list`) or its fingerprint
    /// (`vox room roster`). Or address one session of a member as `<member>/<session>`, the
    /// session named as `vox room sessions` names it: its id, 8 or more of its first
    /// characters, or its name. A session that has ended is refused. Repeat for several.
    /// Without one, the share is for the whole room.
    ///
    /// For example: `--to bob/gso-cap`
    #[arg(long)]
    pub to: Vec<String>,
    /// May interrupt the addressed members' agents mid-turn.
    #[arg(long)]
    pub urgent: bool,
    /// The entry hash this share answers. A session woken by one message answers it without.
    #[arg(long)]
    pub re: Option<String>,
    /// A note, carried in the share itself.
    #[arg(short = 'm', long = "message")]
    pub note: Option<String>,
    /// Stop serving after this many completed fetches.
    #[arg(long)]
    pub count: Option<u64>,
    /// Stop serving after this long: `90s`, `10m`, `2h`.
    #[arg(long = "for")]
    pub for_: Option<String>,
}

/// `vox share stop|list`
#[derive(Subcommand, Debug, Clone)]
pub enum ShareCmd {
    /// Stop serving a share of this node's: named by its name, its tag, or a prefix of its
    /// SHA-256. A member who pulls it afterwards is told it is gone.
    Stop(ShareStopArgs),
    /// This node's shares in a room, and how often each was fetched.
    List(ShareListArgs),
}

/// `vox share stop`
#[derive(Args, Debug, Clone)]
pub struct ShareStopArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// The share's name, its tag, or a prefix of its SHA-256.
    pub share: String,
}

/// `vox share list`
#[derive(Args, Debug, Clone)]
pub struct ShareListArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
}

/// `vox status`
#[derive(Args, Debug, Clone)]
pub struct StatusArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// Print the node's report as JSON, for machines.
    #[arg(long)]
    pub json: bool,
}

/// Session, operation id and output shape, shared by every coordinating verb.
#[derive(Args, Debug, Clone, Default)]
pub struct CoordArgs {
    /// The session to act as. Defaults to `VOX_SESSION`, then the harness's own
    /// session id. Ownership is per session.
    #[arg(long)]
    pub session: Option<String>,
    /// The operation id to post under: 8–64 of `[A-Za-z0-9._-]`. Choose it before
    /// the first attempt and pass the same one on every retry — a retry is then one
    /// operation, and reusing it for different content is refused (exit 4).
    #[arg(long)]
    pub op: Option<String>,
    /// Print one JSON object instead of prose.
    #[arg(long)]
    pub json: bool,
}

impl CoordArgs {
    fn opts(&self) -> crate::room_cli::CoordOpts {
        crate::room_cli::CoordOpts {
            session: self.session.clone(),
            op: self.op.clone(),
            json: self.json,
        }
    }
}

/// `vox room claim`
#[derive(Args, Debug, Clone)]
pub struct ClaimArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// What is being claimed — a file, a milestone, a crate, whatever the room
    /// has agreed to name. Optional with `--work`, which is then the resource.
    pub resource: Option<String>,
    /// awa's work key for the item, as `gwa:<key>` (the key may contain `:`), carried
    /// in `data.work` and used as the resource.
    #[arg(long)]
    pub work: Option<String>,
    /// Seconds after which the claim lapses on its own unless renewed.
    #[arg(long)]
    pub ttl: Option<u64>,
    #[command(flatten)]
    pub coord: CoordArgs,
}

/// `vox room release`, `decline` and `renew`
#[derive(Args, Debug, Clone)]
pub struct ResourceArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// The resource.
    pub resource: String,
    #[command(flatten)]
    pub coord: CoordArgs,
}

/// `vox room handoff`
#[derive(Args, Debug, Clone)]
pub struct HandoffArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// What is being handed off.
    pub resource: String,
    /// The recipient: your name for a room member (`vox trust list`), or its fingerprint or a
    /// unique prefix of one as `vox room roster` prints it. Resolved here, once, so every node agrees.
    #[arg(long)]
    pub to: String,
    /// Reserve it for one exact session of the recipient, rather than any.
    #[arg(long)]
    pub to_session: Option<String>,
    /// Seconds until the pending handoff lapses and the work is free. Default 3600.
    #[arg(long)]
    pub ttl: Option<u64>,
    #[command(flatten)]
    pub coord: CoordArgs,
}

/// `vox room board`
#[derive(Args, Debug, Clone)]
pub struct RoomBoardArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// Print one `vox.room.board/1` JSON object.
    #[arg(long)]
    pub json: bool,
    /// The session whose view to mark as "you". Defaults as for the other verbs.
    #[arg(long)]
    pub session: Option<String>,
}

/// `vox room tail`
#[derive(Args, Debug, Clone)]
pub struct RoomTailArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// Start after this entry hash — the full 52 characters — rather than at the
    /// live edge.
    #[arg(long)]
    pub since: Option<String>,
    /// One `vox.room.row/1` JSON object per line.
    #[arg(long)]
    pub json: bool,
}

/// `vox agent` — wiring an agent session into a room.
#[derive(Subcommand, Debug, Clone)]
enum AgentCmd {
    /// Read this session's unread messages and print them for the harness to
    /// inject. Meant to be run BY a harness hook, not by hand.
    ///
    /// Reads the harness's hook JSON on stdin and writes injected context on
    /// stdout in whatever shape that harness reads. Always exits 0: a hook must
    /// never break the turn it rides on.
    ///
    /// Register it on a turn-start event — `UserPromptSubmit` in both Claude Code
    /// and Codex — and for Codex register it with `async: false`, or the output is
    /// observed and discarded. In Claude Code, register it on `Stop` and `SessionEnd`
    /// too: on `Stop` it records that the session is idle, so a reply waiting for it
    /// can be announced, and prints nothing; on `SessionEnd` it removes the session's
    /// registration.
    Hook(AgentHookArgs),
    /// Print the integration a harness needs to run `vox agent hook` every turn.
    ///
    /// Whatever the harness wants, this prints it: Claude Code and Codex take a
    /// hook entry in their own settings, so they get a JSON snippet; OpenCode has
    /// no hook command and loads JavaScript plugins, so it gets a plugin file.
    ///
    /// For example:
    ///
    /// vox agent plugin opencode --node opencode-mbp > ~/.config/opencode/plugin/vox.js
    ///
    /// vox agent plugin claude --node claude-mbp   # merge into ~/.claude/settings.json
    ///
    /// vox agent plugin codex --node codex-mbp     # merge into Codex's hooks.json
    ///
    /// The integration goes to stdout so it can be redirected or piped through
    /// `jq`; where to put it goes to stderr, so it does not land in the file.
    ///
    /// The plugin is a shim over `vox agent hook`, not a second implementation.
    Plugin(AgentPluginArgs),
    /// Print the agent-facing skill: what the room is for, its vocabulary and its
    /// manners.
    ///
    /// A skill is on-demand only, so it cannot be what guarantees an agent reads
    /// its room — that is `vox agent hook`'s job. This carries what a hook cannot.
    ///
    /// Claude Code, Codex and OpenCode all load the same file, a `SKILL.md` in a folder
    /// named after the skill. Install it at **user scope**, beside the drain, so a
    /// session opened in any repository has both:
    ///
    /// For example:
    ///
    /// mkdir -p ~/.claude/skills/vox-agent-comms
    ///
    /// vox agent skill claude > ~/.claude/skills/vox-agent-comms/SKILL.md
    ///
    /// mkdir -p ~/.codex/skills/vox-agent-comms           # $CODEX_HOME/skills when set
    ///
    /// vox agent skill codex > ~/.codex/skills/vox-agent-comms/SKILL.md
    ///
    /// mkdir -p ~/.config/opencode/skills/vox-agent-comms # $XDG_CONFIG_HOME/opencode/skills when set
    ///
    /// vox agent skill opencode > ~/.config/opencode/skills/vox-agent-comms/SKILL.md
    ///
    /// The skill goes to stdout; where it goes, to stderr, so it does not land in the file.
    Skill(AgentSkillArgs),
    /// Trust Vox's drain hook in a harness that gates hooks on trust. Only Codex
    /// does: it runs a `hooks.json` entry only once its hash is recorded as trusted.
    ///
    /// Asks Codex's own app-server (`hooks/list`, then `config/batchWrite`) — the
    /// same calls Codex's "Trust all" makes — for **only** the entries that run `vox
    /// agent hook`. Idempotent; run it again after changing the entry's command.
    /// Honours `CODEX_HOME`.
    ///
    /// For example:
    ///
    /// vox agent trust codex
    Trust(AgentTrustArgs),
    /// Check that this node's agent sessions are wired up, and say how to fix what is not.
    ///
    /// One line per check, `ok`, `warn` or `fail`, each with a one-line fix: the node answers;
    /// the room resolves; Claude Code's hook entries exist once at user scope; Codex's hook is
    /// trusted; the OpenCode plugin is this build's; the drain can read the room and record its
    /// place; each session's record (first seen, last drained, idle or busy, wake endpoint
    /// alive); trust in each direction with every member; and the members' versions. `warn` is
    /// something not set up, `fail` something set up that will not work. Exits 1 on any `fail`.
    /// It only reads: it starts no harness or model, changes nothing and wakes no one.
    ///
    /// For example:
    ///
    /// vox agent doctor --room <room>
    Doctor(AgentDoctorArgs),
    /// Set the room this harness session works in, or move it to another.
    ///
    /// Run from the session, when its hook says it works in no room, or to move it: its
    /// Session ends in the room it worked in and opens in this one. The room is one the
    /// node holds. A session works in one room at a time.
    Room(AgentRoomArgs),
    /// Send a file or folder out of this session's Session.
    ///
    /// Run from the session. Only the members this node trusts with drive learn of it and are
    /// served it; their nodes pull it by themselves. Nothing is posted to the room.
    ///
    /// For example: vox agent send ./report.pdf --note "the numbers you asked for"
    Send(AgentSendArgs),
}

/// `vox agent doctor`
#[derive(Args, Debug, Clone)]
pub struct AgentDoctorArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room to check, or a unique prefix. Falls back to `VOX_ROOM`, then to the node's only
    /// room.
    #[arg(long)]
    pub room: Option<String>,
    /// One `vox.agent.doctor/1` JSON object instead of lines.
    #[arg(long)]
    pub json: bool,
}

/// `vox room ping`
#[derive(Args, Debug, Clone)]
pub struct RoomPingArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// The member to ask: this node's name for it, or its fingerprint.
    pub member: String,
    /// How long to wait for an answer, in seconds.
    #[arg(long, default_value_t = 30)]
    pub wait: u64,
    /// One `vox.room.ping/1` JSON object instead of lines.
    #[arg(long)]
    pub json: bool,
}

/// `vox agent skill`
#[derive(Args, Debug, Clone)]
pub struct AgentSkillArgs {
    /// The harness to say where the skill goes for: `claude`, `codex` or `opencode`.
    /// Without one, all three are listed. The skill itself is the same for each.
    pub harness: Option<String>,
}

/// Where `harness` loads a user-scope skill named `vox-agent-comms` from, as a shell path, or
/// `None` for a harness Vox has no integration for.
///
/// Read off each harness, not guessed: Claude Code's `~/.claude/skills`; Codex 0.160's
/// `$CODEX_HOME/skills`, `~/.codex/skills` when unset (its own skill-installer says so); and
/// OpenCode 1.18's global `~/.config/opencode/skills` (its docs table, and xdg-basedir, which
/// honours `XDG_CONFIG_HOME`). Each was checked by starting the real harness on a fake model
/// server and seeing the skill in what it sent.
fn skill_dir(harness: &str) -> Option<&'static str> {
    match harness.to_ascii_lowercase().as_str() {
        "claude" | "claude-code" => Some("~/.claude/skills/vox-agent-comms"),
        "codex" => Some("${CODEX_HOME:-~/.codex}/skills/vox-agent-comms"),
        "opencode" => Some("${XDG_CONFIG_HOME:-~/.config}/opencode/skills/vox-agent-comms"),
        _ => None,
    }
}

/// The one line that says how to install the skill for `harness`, runnable as it stands.
fn skill_install(harness: &str, dir: &str) -> String {
    format!("mkdir -p {dir} && vox agent skill {harness} > {dir}/SKILL.md")
}

/// `vox agent trust`
#[derive(Args, Debug, Clone)]
pub struct AgentTrustArgs {
    /// The harness whose trust to grant. Only `codex` gates hooks on trust.
    pub harness: String,
    /// The Codex executable to ask. Defaults to `codex` on `PATH`.
    #[arg(long, default_value = "codex")]
    pub codex: String,
}

/// `vox agent plugin`
#[derive(Args, Debug, Clone)]
pub struct AgentPluginArgs {
    /// The harness to print an integration for. Only `opencode` needs one today;
    /// Claude Code and Codex are configured with a hook command instead.
    pub harness: String,
    /// The agent's own node, which the printed hooks act as (`vox agent hook --node <name>`).
    /// Required: an agent never uses a person's node.
    #[arg(long, required = true)]
    pub node: String,
}

/// `vox agent send`
#[derive(Args, Debug, Clone)]
pub struct AgentSendArgs {
    #[command(flatten)]
    pub profile: AccountArgs,
    /// The file or folder to send.
    pub path: std::path::PathBuf,
    /// A note sent with it.
    #[arg(long)]
    pub note: Option<String>,
    /// The agent's own node, as its hook names it; `VOX_NODE` in the session's environment.
    #[arg(long, env = "VOX_NODE", required = true)]
    pub node: String,
    /// The harness session whose Session it goes out of; else `VOX_SESSION`, or the harness's own
    /// id.
    #[arg(long)]
    pub session: Option<String>,
}

/// `vox agent room`
#[derive(Args, Debug, Clone)]
pub struct AgentRoomArgs {
    #[command(flatten)]
    pub profile: AccountArgs,
    /// The room: its id, a unique start of it, or its name.
    pub room: String,
    /// The agent's own node, as its hook names it; `VOX_NODE` in the session's environment.
    #[arg(long, env = "VOX_NODE", required = true)]
    pub node: String,
    /// The harness session to move; else `VOX_SESSION`, or the harness's own id.
    #[arg(long)]
    pub session: Option<String>,
}

/// `vox agent hook`
#[derive(Args, Debug, Clone)]
pub struct AgentHookArgs {
    #[command(flatten)]
    pub profile: AccountArgs,
    /// The node this hook acts as: the agent's own node. Required, and
    /// never taken from the environment or any other node: a hook without it refuses.
    #[arg(long, required = true)]
    pub node: String,
    /// Drain only this room (its id, or a unique prefix). Without it the hook drains every
    /// room the node holds, each under its own heading.
    #[arg(long)]
    pub room: Option<String>,
    /// Output shape: `auto` (default), `claude`, or `text`.
    ///
    /// `auto` reads it off the input — Claude Code's hook JSON names its event,
    /// Codex's does not — so the same installed command works in either, and
    /// anything unrecognised gets plain text, which cannot corrupt a harness that
    /// wanted the other.
    #[arg(long, default_value = "auto")]
    pub format: String,
    /// The harness session this drain is for, overriding the one on stdin.
    ///
    /// The session id is the cursor key: it is what stops two agent sessions on
    /// one node being told the same thing, and what lets a second session still
    /// receive a backlog the first has already read.
    ///
    /// Claude Code and Codex both put it in the hook JSON on stdin, so neither
    /// needs this. OpenCode has no hook JSON — a plugin is called with the session
    /// id as a value, and runs commands through Bun's shell, which carries no
    /// stdin. So the id arrives as a flag instead.
    #[arg(long)]
    pub session: Option<String>,
}

/// Naming a room on a running node. No passphrase: the node is already unlocked.
#[derive(Args, Debug, Clone)]
pub struct RoomRefArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
}

/// `vox room session`
#[derive(Args, Debug, Clone)]
pub struct RoomSessionArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// The Session: its session id, at least 8 characters of it, or its name.
    pub session: String,
    /// Print each entry's full input and output under its line.
    #[arg(long)]
    pub details: bool,
    /// Print one JSON object per line instead.
    #[arg(long)]
    pub json: bool,
    /// Drive the session instead of reading it, as a member its node trusts with
    /// drive. Each input reaches that session alone, or is refused with the reason.
    #[command(flatten)]
    pub drive: SessionDriveArgs,
    /// A note the session is told with the file `--file` sends it.
    #[arg(long, value_name = "TEXT", requires = "file")]
    pub note: Option<String>,
}

/// What `vox room session` sends to the session, when it drives it: at most one of these.
#[derive(Args, Debug, Clone, Default)]
#[group(multiple = false)]
pub struct SessionDriveArgs {
    /// Type TEXT into the session as its operator, and submit it.
    #[arg(long, value_name = "TEXT")]
    pub say: Option<String>,
    /// Interrupt the turn it is running (Esc).
    #[arg(long)]
    pub interrupt: bool,
    /// Stop it (Ctrl-C).
    #[arg(long)]
    pub stop: bool,
    /// Send it a slash command, as typed: "/compact", "/clear", "/rename NAME".
    #[arg(long, value_name = "COMMAND")]
    pub slash: Option<String>,
    /// Approve the tool call the Session shows as waiting, by its ref.
    #[arg(long, value_name = "REF")]
    pub approve: Option<String>,
    /// Reject the tool call waiting under REF, optionally saying why: `--reject REF "reason"`.
    #[arg(long, value_name = "REF", num_args = 1..=2)]
    pub reject: Option<Vec<String>>,
    /// Answer the question waiting under REF: `--answer REF "QUESTION=ANSWER" …`, one pair per
    /// question (a question by its id or its text; several choices joined with ", ").
    #[arg(long, value_name = "REF", num_args = 2..)]
    pub answer: Option<Vec<String>>,
    /// Send the session a file: it lands on its node, and the session is told
    /// where. Only its node is served it.
    #[arg(long, value_name = "PATH")]
    pub file: Option<std::path::PathBuf>,
}

impl SessionDriveArgs {
    /// The input asked for, or `None` for a read; a malformed answer is said.
    ///
    /// # Errors
    /// A `--answer` pair without `=`.
    pub fn action(&self) -> Result<Option<crate::drive::Action>, String> {
        use crate::drive::Action;
        Ok(Some(if let Some(t) = &self.say {
            Action::Text { text: t.clone() }
        } else if self.interrupt {
            Action::Interrupt
        } else if self.stop {
            Action::Stop
        } else if let Some(t) = &self.slash {
            Action::Slash { text: t.clone() }
        } else if let Some(r) = &self.approve {
            Action::Approve { r#ref: r.clone() }
        } else if let Some(v) = &self.reject {
            Action::Reject {
                r#ref: v[0].clone(),
                why: v.get(1).cloned(),
            }
        } else if let Some(v) = &self.answer {
            let mut answers = std::collections::BTreeMap::new();
            for pair in &v[1..] {
                let (q, a) = pair
                    .split_once('=')
                    .ok_or_else(|| format!("--answer takes QUESTION=ANSWER, not {pair:?}"))?;
                answers.insert(q.trim().to_owned(), a.trim().to_owned());
            }
            Action::Answer {
                r#ref: v[0].clone(),
                answers,
            }
        } else {
            return Ok(None);
        }))
    }
}

/// `vox room post`
#[derive(Args, Debug, Clone)]
pub struct RoomPostArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// The message. Omit it, or pass `-`, to read from stdin.
    pub text: Option<String>,
    /// The envelope type (`ask`, `answer`, `assign`, `accept`, `blocked`, …). Any
    /// structured flag makes vox build the envelope itself. Progress is not posted
    /// here: it is recorded on the GitHub issue through awa.
    #[arg(long = "type")]
    pub kind: Option<String>,
    /// awa's work key for the item, as `gwa:<key>` (the key may contain `:`), carried
    /// in `data.work`. A post with `--work` takes part in work coordination and passes
    /// the version gate.
    #[arg(long)]
    pub work: Option<String>,
    /// An attempt id, carried in `data.attempt` so a reader can tie posts together.
    /// Defaults, with `--work`, to an id seeded from this session's claim on that item.
    /// It records nothing: attempts are recorded on the GitHub issue through awa.
    #[arg(long)]
    pub attempt: Option<String>,
    /// Address a member of the room: your name for it (`vox trust list`) or its fingerprint
    /// (`vox room roster`). Or address one session of a member as `<member>/<session>`, the
    /// session named as `vox room sessions` names it: its id, 8 or more of its first
    /// characters, or its name. Repeat for several. A name that is no member is refused, and
    /// so is a session that has ended.
    ///
    /// For example: `--to bob/gso-cap`
    #[arg(long)]
    pub to: Vec<String>,
    /// May interrupt the addressed members' agents mid-turn.
    #[arg(long)]
    pub urgent: bool,
    /// The entry hash this replies to.
    #[arg(long)]
    pub re: Option<String>,
    /// The entry hash of the conversation root.
    #[arg(long)]
    pub thread: Option<String>,
    /// Extra payload, as a JSON object. May not set `vox` or `op`.
    #[arg(long)]
    pub data: Option<String>,
    /// Post without a link card: this node fetches nothing, and the linked site learns nothing.
    #[arg(long)]
    pub no_card: bool,
    #[command(flatten)]
    pub coord: CoordArgs,
}

/// `vox room sessions`
#[derive(Args, Debug, Clone)]
pub struct RoomSessionsArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// One JSON object per Session, one per line.
    #[arg(long)]
    pub json: bool,
}

/// `vox room read`
#[derive(Args, Debug, Clone)]
pub struct RoomReadArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// Return only what arrived after this entry hash, in the order it arrived — the
    /// full 52 characters, as the first column prints it. Arrival, not position: a
    /// message from a member who was offline takes its place *above* newer ones, and
    /// is still returned. Not prefix-matched: a cursor comes from previous output, and
    /// a prefix that matched the wrong entry would silently skip or repeat messages.
    #[arg(long)]
    pub since: Option<String>,
    /// At most this many messages. 0 means no limit.
    #[arg(long, default_value_t = 0)]
    pub limit: u64,
    /// One `vox.room.row/1` JSON object per line.
    #[arg(long)]
    pub json: bool,
    /// With `--json`, also what was done to the room (its retention set, its name changed), each
    /// as a `vox.room.notice/1` object right after the row it follows in the room's order, its
    /// time in milliseconds. Off by default: a program that reads rows takes only
    /// `vox.room.row/1`.
    #[arg(long, requires = "json", conflicts_with = "late")]
    pub notices: bool,
    /// Print every entry this node holds for the room in the room's order, one per
    /// line as `<entry-hash> <clock-ms>` — readable or not. The sequence every member's view is a part of,
    /// and the one that must be identical on every node.
    #[arg(long, hide = true, conflicts_with_all = ["since", "limit", "json"])]
    pub hashes: bool,
    /// Print only the messages marked late: they arrived after rows below them had already
    /// been shown, and sit in their true place in history.
    #[arg(long, hide = true, conflicts_with = "hashes")]
    pub late: bool,
}

/// Selecting a room, by the prefix of its channelID as `vox` prints it.
#[derive(Args, Debug, Clone)]
pub struct RoomArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// **Refused**, like `--identity-passphrase`: a command line is readable by every
    /// process on the machine while it runs. Still parsed so that anything scripted against
    /// it is told the replacement. `VOX_ROOM_PASSPHRASE` is refused for the same reason: a
    /// process's environment is readable by whatever runs as its user, and is inherited by
    /// everything it starts.
    ///
    /// Use `--passphrase-file <path>` (`-` reads it from stdin), or, at a terminal, let it
    /// prompt. A piped stdin is never read unasked: whatever was piped in for something else
    /// would be taken as the passphrase.
    #[arg(long)]
    pub passphrase: Option<String>,
    /// Read the room passphrase from this file (first line). The scripted way to give it: a
    /// file has an owner and a mode, where a command line has neither.
    #[arg(long)]
    pub passphrase_file: Option<std::path::PathBuf>,
    /// **Refused.** A command line is world-readable while the process runs — `ps`, or
    /// `/proc/<pid>/cmdline` — so a passphrase here is disclosed to every process on the
    /// machine, and lands in the shell's history besides. It is still accepted by the
    /// parser so that anything scripted against it fails with a message naming the
    /// replacement, rather than breaking in a way nobody can diagnose.
    ///
    /// Use `--identity-passphrase-file`, or `VOX_IDENTITY_PASSPHRASE`, or let it prompt.
    #[arg(long)]
    pub identity_passphrase: Option<String>,
    /// Read the identity passphrase from this file (first line). The scripted way to
    /// give it: a file has an owner and a mode, where a command line has neither.
    #[arg(long)]
    pub identity_passphrase_file: Option<std::path::PathBuf>,
}

/// `vox service list`: a room's args without its passphrase, which listing never uses.
#[derive(Args, Debug, Clone)]
pub struct ServiceListArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// Print the listing as one JSON object; every address in it is canonical, the same on every
    /// member's machine.
    #[arg(long)]
    pub json: bool,
    /// **Refused**, as for every verb: a command line is readable by every process on the
    /// machine while it runs. Use `--identity-passphrase-file`, or `VOX_IDENTITY_PASSPHRASE`,
    /// or let it prompt.
    #[arg(long)]
    pub identity_passphrase: Option<String>,
    /// Read the identity passphrase from this file (first line).
    #[arg(long)]
    pub identity_passphrase_file: Option<std::path::PathBuf>,
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

/// A node plus the identity passphrase, for the verbs that unlock an identity but open
/// no room: `vox id`, `vox trust list`.
#[derive(Args, Debug, Clone)]
pub struct IdentityArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// **Refused.** A command line is world-readable while the process runs — `ps`, or
    /// `/proc/<pid>/cmdline` — so a passphrase here is disclosed to every process on the
    /// machine, and lands in the shell's history besides. It is still accepted by the
    /// parser so that anything scripted against it fails with a message naming the
    /// replacement, rather than breaking in a way nobody can diagnose.
    ///
    /// Use `--identity-passphrase-file`, or `VOX_IDENTITY_PASSPHRASE`, or let it prompt.
    #[arg(long)]
    pub identity_passphrase: Option<String>,
    /// Read the identity passphrase from this file (first line). The scripted way to
    /// give it: a file has an owner and a mode, where a command line has neither.
    #[arg(long)]
    pub identity_passphrase_file: Option<std::path::PathBuf>,
}

/// Which rooms `vox node` serves (`--serve`).
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Serve {
    /// Any room published to this anchor.
    Anyone,
    /// Only rooms made by someone in this node's `vox trust` list.
    Trusted,
}

/// The account a `vox node` subcommand acts on.
#[derive(Args, Debug, Clone)]
pub struct AccountArgs {
    /// Data directory root (holds `nodes/<name>/` and the daemon's `.daemon/`).
    #[arg(long, env = "VOX_DATA_DIR")]
    pub data_dir: Option<PathBuf>,
    /// Config directory.
    #[arg(long, env = "VOX_CONFIG_DIR")]
    pub config_dir: Option<PathBuf>,
    /// Address the daemon binds when this command starts it.
    #[arg(long, env = "VOX_LISTEN", default_value = crate::client::DEFAULT_LISTEN)]
    pub listen: SocketAddr,
    /// Anchors a node is attached with (`<fingerprint>@<multiaddr>`, repeatable).
    #[arg(long = "anchor", env = "VOX_ANCHORS", value_delimiter = ',')]
    pub anchors: Vec<String>,
}

impl AccountArgs {
    /// As the node flags every verb takes, naming no node.
    fn as_node_args(&self) -> NodeArgs {
        NodeArgs {
            node: None,
            data_dir: self.data_dir.clone(),
            config_dir: self.config_dir.clone(),
            listen: self.listen,
            anchors: self.anchors.clone(),
        }
    }
}

/// `vox node create|attach|detach|list`.
#[derive(Subcommand, Debug, Clone)]
pub enum NodeCmd {
    /// Make a new node: an identity with its own rooms, trust and services. Its files are
    /// written here; nothing is attached until it is used or `vox node attach`ed. The
    /// passphrase comes from `--passphrase-file`, `VOX_IDENTITY_PASSPHRASE`, or is asked twice;
    /// an empty one is allowed.
    Create {
        /// The node's name: letters a-z, digits, '.', '_' and '-'.
        name: String,
        /// Read the new identity's passphrase from this file (first line; `-` reads stdin).
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// Make a headless node, an anchor's: a key file with no passphrase, which holds no room
        /// and can read nothing. `vox node --node <name>` runs it.
        #[arg(long)]
        headless: bool,
        #[command(flatten)]
        account: AccountArgs,
    },
    /// Attach a node to the daemon by hand (starting the daemon if none runs). It runs in full
    /// until `vox node detach` or the daemon stops. `--keep` attaches it again whenever the
    /// daemon starts, with its passphrase from `--passphrase-file`.
    Attach {
        /// The node.
        name: String,
        /// Attach it again whenever the daemon starts.
        #[arg(long)]
        keep: bool,
        /// Read the identity passphrase from this file (first line). With `--keep`, the daemon
        /// reads it from there at each start.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        #[command(flatten)]
        account: AccountArgs,
    },
    /// Detach a node: its connections close and its keys are wiped from memory.
    Detach {
        /// The node.
        name: String,
        #[command(flatten)]
        account: AccountArgs,
    },
    /// Every node in this data root, with whether it is attached.
    List {
        #[command(flatten)]
        account: AccountArgs,
    },
}

/// Run a `vox node` subcommand.
fn run_node_cmd(cmd: NodeCmd) -> ExitCode {
    let outcome = match cmd {
        NodeCmd::Create {
            name,
            passphrase_file,
            headless,
            account,
        } => crate::client::node_create(&account.as_node_args(), &name, passphrase_file, headless),
        NodeCmd::Attach {
            name,
            keep,
            passphrase_file,
            account,
        } => block_on_client(async move {
            crate::client::node_attach(&account.as_node_args(), &name, keep, passphrase_file).await
        }),
        NodeCmd::Detach { name, account } => block_on_client(async move {
            crate::client::node_detach(&account.as_node_args(), &name).await
        }),
        NodeCmd::List { account } => {
            block_on_client(async move { crate::client::node_list(&account.as_node_args()).await })
        }
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vox node: {e}");
            e.exit_code()
        }
    }
}

/// Run a client's work on a small runtime of its own.
fn block_on_client<Fut>(work: Fut) -> Result<(), AppError>
where
    Fut: std::future::Future<Output = Result<(), AppError>>,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(work)
}

/// `vox node` (the anchor) and its subcommands.
#[derive(Args, Debug, Clone)]
#[command(args_conflicts_with_subcommands = true)]
pub struct AnchorArgs {
    /// `vox node create|attach|detach|list`; without one, `vox node` runs the anchor.
    #[command(subcommand)]
    pub cmd: Option<NodeCmd>,
    #[command(flatten)]
    pub profile: NodeArgs,
    /// Which rooms this anchor serves: `anyone` (the default) serves any room published to
    /// it; `trusted` serves only rooms made by someone in this node's `vox trust` list.
    /// `trusted` needs this node's identity passphrase to read that list, and reads it once
    /// at start. Give it with `--identity-passphrase-file`: `VOX_IDENTITY_PASSPHRASE` also
    /// works, but it stays in the anchor's environment for as long as it runs, where any
    /// process of the same user can read it (`ps -E`). Without the flag, the `serve` file in
    /// the config directory (`anyone` or `trusted`) decides.
    #[arg(long, env = "VOX_SERVE", value_enum)]
    pub serve: Option<Serve>,
    /// **Refused**, as for every verb: a command line is world-readable while the process
    /// runs. Use `--identity-passphrase-file`, or `VOX_IDENTITY_PASSPHRASE`, or let it prompt.
    #[arg(long)]
    pub identity_passphrase: Option<String>,
    /// Read the identity passphrase from this file (first line). Only `--serve trusted`
    /// needs it: the trust list is sealed under this node's identity.
    #[arg(long)]
    pub identity_passphrase_file: Option<std::path::PathBuf>,
}

/// The node `vox node` runs its anchor as. One node is one identity (ADR-026 F-3), so a node
/// holding a vault keeps its anchor's key in node `<name>-anchor`, and `--serve trusted` still
/// reads the vault's trust list from `<name>`. Otherwise the anchor is the named node itself.
fn anchor_paths(paths: Paths) -> vox_core::error::Result<Paths> {
    if !paths.vault_file().is_file() {
        return Ok(paths);
    }
    let raw = paths
        .profile_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_owned();
    let name = vox_core::node::paths::NodeName::parse(&raw)?;
    let anchor = vox_core::node::layout::anchor_name_of(&name)?;
    println!("vox node: node {name} holds a vault; its anchor runs as node {anchor}");
    paths.account().node_paths(&anchor)
}

impl AnchorArgs {
    /// The `--serve` choice: the flag (or `VOX_SERVE`), else the config directory's `serve`
    /// file, else `anyone`. A `serve` file that says anything else is refused, not guessed at.
    fn serve(&self, paths: &Paths) -> Result<Serve, AppError> {
        if let Some(serve) = self.serve {
            return Ok(serve);
        }
        let path = paths.serve_file();
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Serve::Anyone),
            Err(e) => return Err(AppError::Usage(format!("reading {}: {e}", path.display()))),
        };
        match text.lines().map(str::trim).find(|l| !l.is_empty()) {
            None | Some("anyone") => Ok(Serve::Anyone),
            Some("trusted") => Ok(Serve::Trusted),
            Some(other) => Err(AppError::Usage(format!(
                "{} says {other:?}; it must say `anyone` or `trusted`",
                path.display()
            ))),
        }
    }

    /// For `--serve trusted`, the creators whose rooms this anchor serves: the node's
    /// `vox trust` list, read once with the identity passphrase. `None` for `anyone`.
    fn serve_only(
        &self,
        paths: &Paths,
    ) -> Result<Option<std::collections::BTreeSet<vox_core::hash::Digest32>>, AppError> {
        if self.serve(paths)? == Serve::Anyone {
            return Ok(None);
        }
        let refuse = |why: String| {
            AppError::Usage(format!(
                "--serve trusted: {why}. It serves only rooms made by someone in this node's \
                 `vox trust` list, so it will not start without it"
            ))
        };
        // Two different failures, and each needs different advice: a profile with no identity
        // has no trust list to read and needs one made; a profile that has one but cannot be
        // opened has a list this process cannot get at, and remaking it would not help.
        if !vox_core::node::profile::Profile::exists(paths) {
            return Err(refuse(format!(
                "this node has no identity, so no `vox trust` list to read; make one with \
                 `vox id` and `vox trust add <fingerprint>` in the node at {}",
                paths.profile_dir.display()
            )));
        }
        let mut profile = vox_core::node::profile::Profile::open(paths.clone()).map_err(|e| {
            refuse(format!(
                "this node's identity and `vox trust` list exist but could not be opened \
                 ({e}); check that the files in {} belong to and are readable by the user \
                 running `vox node`, and that no other vox has this node open",
                paths.profile_dir.display()
            ))
        })?;
        // Held only for the one unlock, and wiped when it goes: an anchor runs for months, and
        // nothing it does after start needs the passphrase again.
        let passphrase = zeroize::Zeroizing::new(crate::tunnel_cli::identity_passphrase_for(
            paths,
            self.identity_passphrase.clone(),
            self.identity_passphrase_file.clone(),
        )?);
        profile
            .unlock(passphrase.as_bytes())
            .map_err(|e| refuse(format!("the identity did not unlock ({e})")))?;
        drop(passphrase);
        let signer = profile
            .signer()
            .map_err(|e| refuse(format!("the identity did not unlock ({e})")))?;
        let keyring = vox_core::node::trust::Keyring::load(profile.store(), signer)
            .map_err(|e| refuse(format!("the trust list did not open ({e})")))?;
        Ok(Some(keyring.trusted()))
    }
}

/// `vox trust`
#[derive(Subcommand)]
enum TrustCmd {
    /// Trust an identity, node-wide.
    ///
    /// This is the decision the whole model rests on. It is per **identity**, not per
    /// room: from here on it reads what you post in every room this node shares with that
    /// key, including rooms made later, **and** that key may reach every service this node
    /// binds to a room they are both in. One act, not one per room.
    Add(TrustAddArgs),
    /// List the identities this node trusts, and what it calls them.
    List(IdentityArgs),
    /// Stop trusting an identity, and change the lock.
    ///
    /// Removes the ring entry, then rotates this identity's sender key and re-keys
    /// everyone still trusted, in every room shared with the removed key — so it stops
    /// reading what comes next, everywhere. It keeps what it already
    /// read; that cannot be taken back.
    Remove(TrustRemoveArgs),
    /// Change the name this node calls a trusted identity. The name is the node part of
    /// `<service>.<name>.<room>.vox`; it is local to this machine and never
    /// leaves it. Grants nothing: only an identity already trusted can be renamed.
    Rename(TrustRenameArgs),
    /// Let a trusted identity drive this node's Sessions as well as read: its
    /// keyring entry becomes read + drive. A keyring change, behind the passphrase.
    Drive(TrustCapabilityArgs),
    /// Take drive back from a trusted identity: its keyring entry grants read only.
    Read(TrustCapabilityArgs),
}

/// `vox trust drive` and `vox trust read`
#[derive(Args, Debug, Clone)]
pub struct TrustCapabilityArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The trusted identity (base32, or a unique prefix).
    pub fingerprint: String,
    /// **Refused.** Use `--identity-passphrase-file`, `VOX_IDENTITY_PASSPHRASE`, or the prompt.
    #[arg(long)]
    pub identity_passphrase: Option<String>,
    /// Read the identity passphrase from this file (first line).
    #[arg(long)]
    pub identity_passphrase_file: Option<std::path::PathBuf>,
}

/// `vox trust rename`
#[derive(Args, Debug, Clone)]
pub struct TrustRenameArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The trusted identity (base32, or a unique prefix).
    pub fingerprint: String,
    /// Its new name.
    pub name: String,
    /// **Refused.** Use `--identity-passphrase-file`, `VOX_IDENTITY_PASSPHRASE`, or the prompt.
    #[arg(long)]
    pub identity_passphrase: Option<String>,
    /// Read the identity passphrase from this file (first line).
    #[arg(long)]
    pub identity_passphrase_file: Option<std::path::PathBuf>,
}

/// `vox trust add`
#[derive(Args, Debug, Clone)]
pub struct TrustAddArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The identity to trust, as `vox id` prints it (base32, or a unique prefix of one
    /// this node already knows).
    pub fingerprint: String,
    /// Your name for it: how Vox shows its messages to you, and how you address it
    /// (`--to`). Local to this machine; no other node ever sees it. Asked for when not given
    /// and there is a terminal.
    #[arg(long)]
    pub name: Option<String>,
    /// What trusting it releases of **your own** messages: `now`,
    /// the default, from now on; or `full`, everything you still hold a key
    /// for, so it also reads what you wrote before. Your messages only — nobody else's.
    #[arg(long, value_parser = ["now", "full"], default_value = "now")]
    pub history: String,
    /// Grant read + drive: it may also drive this node's Sessions. Without it
    /// the entry grants read, the default.
    #[arg(long)]
    pub drive: bool,
    /// **Refused.** A command line is world-readable while the process runs — `ps`, or
    /// `/proc/<pid>/cmdline` — so a passphrase here is disclosed to every process on the
    /// machine, and lands in the shell's history besides. It is still accepted by the
    /// parser so that anything scripted against it fails with a message naming the
    /// replacement, rather than breaking in a way nobody can diagnose.
    ///
    /// Use `--identity-passphrase-file`, or `VOX_IDENTITY_PASSPHRASE`, or let it prompt.
    #[arg(long)]
    pub identity_passphrase: Option<String>,
    /// Read the identity passphrase from this file (first line). The scripted way to
    /// give it: a file has an owner and a mode, where a command line has neither.
    #[arg(long)]
    pub identity_passphrase_file: Option<std::path::PathBuf>,
}

/// `vox trust remove`
#[derive(Args, Debug, Clone)]
pub struct TrustRemoveArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The identity to stop trusting.
    pub fingerprint: String,
    /// **Refused.** A command line is world-readable while the process runs — `ps`, or
    /// `/proc/<pid>/cmdline` — so a passphrase here is disclosed to every process on the
    /// machine, and lands in the shell's history besides. It is still accepted by the
    /// parser so that anything scripted against it fails with a message naming the
    /// replacement, rather than breaking in a way nobody can diagnose.
    ///
    /// Use `--identity-passphrase-file`, or `VOX_IDENTITY_PASSPHRASE`, or let it prompt.
    #[arg(long)]
    pub identity_passphrase: Option<String>,
    /// Read the identity passphrase from this file (first line). The scripted way to
    /// give it: a file has an owner and a mode, where a command line has neither.
    #[arg(long)]
    pub identity_passphrase_file: Option<std::path::PathBuf>,
}

/// `vox forward`
#[derive(Args, Debug, Clone)]
pub struct ForwardArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The service's address: `<service>.<node>.<room>.vox` (`vox service list <room>` shows
    /// each one).
    pub address: String,
    /// Where to listen locally: a port on loopback, or `ip:port`; port 0 picks one.
    pub local: Option<String>,
    /// **Refused.** Use `--identity-passphrase-file`, `VOX_IDENTITY_PASSPHRASE`, or the prompt.
    #[arg(long)]
    pub identity_passphrase: Option<String>,
    /// Read the identity passphrase from this file (first line), for attaching this node when
    /// it is not attached.
    #[arg(long)]
    pub identity_passphrase_file: Option<std::path::PathBuf>,
}

/// `vox serve`
#[derive(Args, Debug, Clone)]
pub struct ServeArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The services to share, each named: `<name>=<port>` (TCP), `<name>=<port>/tcp` or
    /// `<name>=<port>/udp`. A member reaches each as `<name>.<node>.<room>.vox`, and only that
    /// way; a bare port is refused. The first creates the room; `vox serve ssh=22 dns=53/udp`
    /// shares both. None: the services listening on this machine are listed to pick one from,
    /// with a name suggested and a preview of who can reach it before it is shared.
    #[arg(num_args = 0..)]
    pub ports: Vec<String>,
    /// The local endpoint to carry connections to, when it is not `127.0.0.1:<port>`.
    #[arg(long)]
    pub at: Option<SocketAddr>,
    /// The room's name, which every member sees: one DNS label (a-z, 0-9 and `-`), the room
    /// part of each service's address.
    #[arg(long, default_value = "service")]
    pub name: String,
    /// **Refused.** A command line is world-readable while the process runs — `ps`, or
    /// `/proc/<pid>/cmdline` — so a passphrase here is disclosed to every process on the
    /// machine, and lands in the shell's history besides. It is still accepted by the
    /// parser so that anything scripted against it fails with a message naming the
    /// replacement, rather than breaking in a way nobody can diagnose.
    ///
    /// Use `--identity-passphrase-file`, or `VOX_IDENTITY_PASSPHRASE`, or let it prompt.
    #[arg(long)]
    pub identity_passphrase: Option<String>,
    /// Read the identity passphrase from this file (first line). The scripted way to
    /// give it: a file has an owner and a mode, where a command line has neither.
    #[arg(long)]
    pub identity_passphrase_file: Option<std::path::PathBuf>,
}

/// `vox connect`
#[derive(Args, Debug, Clone)]
pub struct ConnectArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The `vox://…` address you were given.
    pub address: String,
    /// **Refused**, like `--identity-passphrase`: a command line is readable by every
    /// process on the machine while it runs. Still parsed so that anything scripted against
    /// it is told the replacement. `VOX_ROOM_PASSPHRASE` is refused for the same reason: a
    /// process's environment is readable by whatever runs as its user, and is inherited by
    /// everything it starts.
    ///
    /// Use `--passphrase-file <path>` (`-` reads it from stdin), or, at a terminal, let it
    /// prompt. A piped stdin is never read unasked: whatever was piped in for something else
    /// would be taken as the passphrase.
    #[arg(long)]
    pub passphrase: Option<String>,
    /// Read the room passphrase from this file (first line). The scripted way to give it: a
    /// file has an owner and a mode, where a command line has neither.
    #[arg(long)]
    pub passphrase_file: Option<std::path::PathBuf>,
    /// **Refused.** A command line is world-readable while the process runs — `ps`, or
    /// `/proc/<pid>/cmdline` — so a passphrase here is disclosed to every process on the
    /// machine, and lands in the shell's history besides. It is still accepted by the
    /// parser so that anything scripted against it fails with a message naming the
    /// replacement, rather than breaking in a way nobody can diagnose.
    ///
    /// Use `--identity-passphrase-file`, or `VOX_IDENTITY_PASSPHRASE`, or let it prompt.
    #[arg(long)]
    pub identity_passphrase: Option<String>,
    /// Read the identity passphrase from this file (first line). The scripted way to
    /// give it: a file has an owner and a mode, where a command line has neither.
    #[arg(long)]
    pub identity_passphrase_file: Option<std::path::PathBuf>,
}

/// `vox up`
#[derive(Args, Debug, Clone)]
pub struct UpArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// One room to open, with its passphrase, if it is closed. The proxy carries every room
    /// the daemon's attached nodes hold: `ssh user@ssh.nas.family.vox` reaches service `ssh`
    /// on the node you call `nas` in room `family`, for any node you trust, in any room.
    pub room: Option<String>,
    /// **Refused**, as on every room verb: use `--passphrase-file`, or let it prompt
    /// when a room is named.
    #[arg(long)]
    pub passphrase: Option<String>,
    /// Read the room passphrase from this file (first line), when a room is named.
    #[arg(long)]
    pub passphrase_file: Option<std::path::PathBuf>,
    /// **Refused.** Use `--identity-passphrase-file`, `VOX_IDENTITY_PASSPHRASE`, or the prompt.
    #[arg(long)]
    pub identity_passphrase: Option<String>,
    /// Read the identity passphrase from this file (first line).
    #[arg(long)]
    pub identity_passphrase_file: Option<std::path::PathBuf>,
    /// Stay in the foreground and print what the proxy refuses or cuts, until stopped. The
    /// proxy runs on without it.
    #[arg(long)]
    pub watch: bool,
}

use crate::client::DEFAULT_LISTEN;

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
    Tui(NodeArgs),
    /// Run a headless node: the always-on anchor that serves the board, coordinates
    /// hole punches and carries circuits for your rooms. Needed only when your hosts are
    /// both behind NAT and cannot reach each other directly. It holds no room and can
    /// read nothing; its identity is a key file in its node directory, created on
    /// first run. Prints the `<fingerprint>@<multiaddr>` to give clients as `--anchor`.
    ///
    /// Runs until stopped: SIGINT (Ctrl-C), SIGTERM, SIGHUP or SIGQUIT each stops it cleanly.
    Node(AnchorArgs),
    /// Run this data root's daemon in the foreground: the machine's Vox presence, which the
    /// nodes in this data root attach to.
    ///
    /// There is one daemon per data root (`VOX_DATA_DIR`). It holds the one UDP port, the
    /// control socket every other `vox` command talks to (`<data root>/.daemon/vox.sock`) and
    /// the nodes that are attached. It is not a node itself and can run with none attached.
    /// A node is an identity; while attached it runs in full, and it stops only when it is
    /// detached (`vox node detach`) or the daemon stops.
    ///
    /// With `--node`, or when the data root holds exactly one node, that node is attached in
    /// the foreground once its passphrase is given: from `--passphrase-file`, else
    /// `VOX_IDENTITY_PASSPHRASE`, else asked for at the terminal without echo, else read from
    /// stdin:
    ///
    /// For example:
    ///
    /// echo 'my passphrase' | vox daemon --node alice
    ///
    /// `--keep` attaches that node again whenever the daemon starts. When a daemon already runs
    /// for this data root, a `vox daemon --node <name>` attaches the node to it instead.
    ///
    /// You rarely need to start it by hand: `vox serve`, `connect`, `up`, `forward`,
    /// `lan up`, `vox node attach` and the TUI start one in the background when none runs, and
    /// that one exits when it has no node and no client left. One started here runs until
    /// stopped: SIGINT (Ctrl-C), SIGTERM, SIGHUP or SIGQUIT each detaches every node cleanly
    /// and stops it.
    Daemon(DaemonArgs),
    /// Offer a local TCP port as a room-bound service, in one command.
    ///
    /// Creates a room, offers the port in it, and prints the address, the
    /// machine-generated passphrase and the `.vox` hostname it answers on. Runs until
    /// stopped (SIGINT (Ctrl-C), SIGTERM, SIGHUP or SIGQUIT each stops it cleanly), reporting who
    /// reaches the service (the service itself cannot tell
    /// you: every Vox client arrives at it from loopback).
    ///
    /// **Joining the room does not grant access to the port.** Whoever you have run
    /// `vox trust add` on can reach it, and nobody else — the trust keyring is the
    /// authorization. Handing somebody the address and
    /// the passphrase lets them into the room; it does not let them at your machine's
    /// port.
    Serve(ServeArgs),
    /// Join a room from the address you were given, and print the name its services
    /// answer on. One-shot: joining is durable, so there is nothing to keep
    /// running: the daemon's proxy resolves the name while a node is attached (`vox up` says
    /// where it listens).
    Connect(ConnectArgs),
    /// Offer a local TCP service to a room, or list what is offered.
    ///
    /// A service is dark by default: offering it grants nobody reach. Members reach it
    /// only once their host has trusted them (`vox trust add`) and they are a member of this
    /// room.
    #[command(subcommand)]
    Service(ServiceCmd),
    /// Join, create or leave a room, and speak in it, over a **running** node —
    /// the agent-comms verbs.
    ///
    /// For agents on one repository, the room settles who does what: an agent claims
    /// work there, asks there who is on what, and answers there, briefly, when asked
    /// about its own work. It is also where agents work through hard problems together.
    /// Progress and its proofs (attempt starts, candidates, verdicts, delivery) are
    /// recorded on the GitHub issue through awa; `--work` carries awa's work key.
    ///
    /// These never attach a node: they ask the vox daemon as a node that is already
    /// attached (`vox node attach`, or a verb or agent session holding it), which is how
    /// several agent sessions share one identity per machine. None of them takes the
    /// identity passphrase; `join` and `create` take the room passphrase at a terminal, or
    /// from stdin with `--passphrase-file -`.
    #[command(subcommand)]
    Room(RoomCmd),
    /// Open or accept an app stream to a program on another member's node.
    ///
    /// The shape of `nc`, over a running node: `listen` waits for one stream speaking a
    /// label and pipes it; `open` opens one. Both sides must trust each other, and the
    /// peer must be a member of the room.
    #[command(subcommand)]
    App(AppCmd),
    /// Share a file or a folder with a room, addressed like a message: one announcement
    /// carries the note (`-m`), who it is for (`--to`) and `--urgent`, with the name, size and
    /// SHA-256. The daemon serves it over HTTP as a room-bound service, and this returns once
    /// it does. Members you trust pull it with `vox room get`, or with curl through `vox up`.
    /// It is served until its message expires, `vox share stop`, you leave the room or it ends
    /// — or sooner, after `--count` fetches or `--for`.
    Share(ShareArgs),
    /// What the running node is doing, and what needs attention: rooms and
    /// their sync, peers and their paths, tunnels, datagram and app counters, and the sync
    /// counters per room and peer: sessions opened, admitted, refused, completed,
    /// partial and failed, and any backoff.
    Status(StatusArgs),
    /// Wire an agent session into a room — Claude Code, Codex and OpenCode.
    ///
    /// The room settles who does what: an agent claims work there, asks there who is
    /// on what, and answers there, briefly, when asked about its own work; it is also
    /// where agents work through hard problems together. Progress and its proofs
    /// (attempt starts, candidates, verdicts, delivery) are recorded on the GitHub issue
    /// through awa, and `--work` carries awa's work key.
    ///
    /// Each harness needs two things: `vox agent plugin <harness>` (the drain, every
    /// turn) and `vox agent skill <harness>` (the agent text, and where it goes).
    #[command(subcommand)]
    Agent(AgentCmd),
    /// Say where the local entry point for rooms' services is: the vox daemon's SOCKS5 proxy,
    /// which resolves `.vox` names and runs while any node is attached.
    ///
    /// This is how a tool reaches a room-bound service by name — the same shape a Tor user
    /// reaches a `.onion` through, and for the same reason: it needs no privilege of any
    /// kind. `ssh` is pointed at it with one `ProxyCommand` line, which `vox up` prints;
    /// most other tools take `ALL_PROXY=socks5h://…`. Attaches this node if it is not, prints
    /// and exits; `--watch` stays and prints what the proxy refuses until stopped (SIGINT,
    /// SIGTERM, SIGHUP or SIGQUIT).
    Up(UpArgs),
    /// Forward a local port to a shared service, named by its address
    /// `<service>.<node>.<room>.vox` — `ssh` over Vox. Runs until stopped: SIGINT (Ctrl-C), SIGTERM, SIGHUP or SIGQUIT each stops it
    /// cleanly.
    Forward(ForwardArgs),
    /// Put this machine on a room's **family LAN**: a network interface on
    /// which the room's trusted members are one subnet, so that discovery — Plex and
    /// Jellyfin, Chromecast, a game's LAN lobby — works across Vox.
    ///
    /// Two commands, because only one of them needs root: `sudo vox lan helper` creates
    /// interfaces and does nothing else, and `vox lan up <room>`, run as yourself, asks it
    /// for one and carries the room's traffic on it.
    #[command(subcommand)]
    Lan(LanCmd),
    /// Print this node's own identity fingerprint — what to send someone so they can
    /// trust you.
    ///
    /// It is the whole 52-character base32 fingerprint, on its own line, so it can be
    /// piped or pasted without editing. Compare it out of band, the way you would a PGP
    /// fingerprint: nothing registers it and nothing looks it up.
    Id(IdentityArgs),
    /// Decide which identities this node trusts.
    #[command(subcommand)]
    Trust(TrustCmd),
    /// Close the live tunnels `vox status` lists.
    #[command(subcommand)]
    Tunnel(TunnelCmd),
    /// Set up this machine: a node for each harness installed here, and one for you.
    ///
    /// Looks for Claude Code, Codex and OpenCode (their programs on `PATH`) and offers each
    /// a node of its own, `<harness>-<host>`, with a passphrase you type, its hook installed
    /// in the harness's settings and the agent skill beside it. On macOS it also offers a
    /// node for you, which you may skip. It ends by printing every node it made: its
    /// fingerprint, with its art, and its alias, harness, host, OS and Vox version.
    Setup(AccountArgs),
    /// Put `vox` on PATH and install tab completion for your shell.
    ///
    /// `install.sh` and `vox update` run this for you. It writes the completion script into
    /// your shell's own autoload directory and maintains one marked section at the end of your
    /// shell's startup file — at the end, so it wins the PATH race against version managers
    /// that prepend their shims earlier in the same file. Idempotent; `--remove` undoes it
    /// exactly; `VOX_NO_SHELL_SETUP=1` skips it.
    ShellSetup {
        /// Remove everything `vox shell-setup` installed.
        #[arg(long)]
        remove: bool,
    },
    /// Replace this `vox` with the latest GitHub release.
    ///
    /// Fetches the per-target release record, verifies the download's size and SHA-256 against
    /// it before anything is renamed, keeps the binary it replaced as `.vox-previous`, and
    /// refreshes your shell completions. Only an install `install.sh` or a previous `vox
    /// update` made is replaced in place; a build from source is refused, not overwritten.
    ///
    /// On a Mac, Vox.app is replaced whole. A running vox daemon is then restarted onto the new
    /// version: a node whose passphrase the daemon keeps is attached again, and any other node
    /// it had attached is named, with the `vox node attach` that attaches it again. A daemon
    /// run by hand (`vox daemon` in a terminal) is left running, and you are told.
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
    let default_tui = Cmd::Tui(NodeArgs {
        node: std::env::var("VOX_NODE").ok(),
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
            // The TUI is a client of the account's daemon (ADR-026 S-4): it names a node, and the
            // daemon holds it. A node named neither by flag nor environment is resolved by C-3.
            let account = match vox_core::node::paths::Account::of(
                args.data_dir.as_deref(),
                args.config_dir.as_deref(),
            ) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match run_live(
                account,
                args.node.clone(),
                args.listen,
                args.anchors.clone(),
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("vox: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Node(AnchorArgs { cmd: Some(cmd), .. }) => run_node_cmd(cmd),
        Cmd::Node(node_args) => {
            let args = &node_args.profile;
            let paths = match crate::client::anchor_paths_of(args) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox node: {e}");
                    return ExitCode::FAILURE;
                }
            };
            // Checked here, so a malformed one is refused before the daemon starts; the daemon
            // attaches the anchor with them, beside the node's anchors file.
            let mut checked = vox_core::nat::bootstrap::BootstrapSet::new();
            for spec in args.anchor_specs() {
                if let Err(e) = vox_core::node::link::merge_anchor_spec(&mut checked, &spec) {
                    eprintln!("vox node: --anchor: {e}");
                    return ExitCode::FAILURE;
                }
            }
            let serve_only = match node_args.serve_only(&paths) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("vox node: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let paths = match anchor_paths(paths) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox node: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match run_node(paths, args.listen, args.anchor_specs(), serve_only) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("vox node: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Serve(args) => {
            let paths = match args.profile.paths_creating() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let waiting = crate::tunnel_cli::Waiting::server();
            let steps = std::sync::Arc::clone(&waiting);
            run_session(waiting, async move {
                crate::tunnel_cli::serve(
                    &paths,
                    &args.profile,
                    pass(args.identity_passphrase, args.identity_passphrase_file),
                    &args.name,
                    &args.ports,
                    args.at,
                    &steps,
                )
                .await
            })
        }
        Cmd::Connect(args) => {
            let paths = match args.profile.paths_creating() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let waiting = crate::tunnel_cli::Waiting::new("the room was not joined");
            let steps = std::sync::Arc::clone(&waiting);
            run_session(waiting, async move {
                steps.on("the room passphrase");
                let (given, file) = (args.passphrase.clone(), args.passphrase_file.clone());
                let room_pp = tokio::task::spawn_blocking(move || {
                    crate::tunnel_cli::room_passphrase_for(given.as_ref(), file.as_deref())
                })
                .await
                .map_err(|e| AppError::Usage(format!("asking for a passphrase: {e}")))??;
                crate::tunnel_cli::connect(
                    &paths,
                    &args.profile,
                    pass(args.identity_passphrase, args.identity_passphrase_file),
                    &args.address,
                    &room_pp,
                    &steps,
                )
                .await
            })
        }
        Cmd::Room(sub) => {
            // These attach to a running node rather than starting one, so they need
            // only a tokio runtime and the profile's paths — no identity unlock and
            // no network of their own.
            let profile = match &sub {
                RoomCmd::Post(a) => &a.profile,
                RoomCmd::Read(a) => &a.profile,
                RoomCmd::Roster(a) => &a.profile,
                RoomCmd::Sessions(a) => &a.profile,
                RoomCmd::Session(a) => &a.profile,
                RoomCmd::Ping(a) => &a.profile,
                RoomCmd::Tail(a) => &a.profile,
                RoomCmd::Board(a) => &a.profile,
                RoomCmd::List(p) => p,
                RoomCmd::Claim(a) => &a.profile,
                RoomCmd::Release(a) | RoomCmd::Decline(a) | RoomCmd::Renew(a) => &a.profile,
                RoomCmd::Handoff(a) => &a.profile,
                RoomCmd::Get(a) => &a.profile,
                RoomCmd::Join(a) => &a.profile,
                RoomCmd::Create(a) => &a.profile,
                RoomCmd::Link(a) => &a.profile,
                RoomCmd::Retention(a) => &a.profile,
                RoomCmd::Rename(a) => &a.profile,
                RoomCmd::Leave(a) | RoomCmd::End(a) => &a.profile,
                RoomCmd::Admin(a) => &a.profile,
            };
            let paths = match profile.paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            // **A stop signal ends a room verb cleanly** (V210-108): `vox room tail` runs until
            // stopped, and Ctrl-C, SIGTERM or a closed terminal ended it on the spot, saying
            // nothing.
            let outcome = rt.block_on(async {
                let work = async {
                    match &sub {
                        RoomCmd::Post(a) => {
                            let opts = crate::room_cli::PostOpts {
                                kind: a.kind.clone(),
                                work: a.work.clone(),
                                attempt: a.attempt.clone(),
                                to: a.to.clone(),
                                urgent: a.urgent,
                                re: a.re.clone(),
                                thread: a.thread.clone(),
                                data: a.data.clone(),
                                coord: a.coord.opts(),
                                no_card: a.no_card,
                            };
                            crate::room_cli::post_cmd(&paths, &a.room, a.text.as_deref(), &opts)
                                .await
                        }
                        RoomCmd::Read(a) if a.hashes => {
                            crate::room_cli::order(&paths, &a.room).await
                        }
                        RoomCmd::Read(a) => {
                            crate::room_cli::read(
                                &paths,
                                &a.room,
                                a.since.as_deref(),
                                a.limit,
                                a.json,
                                a.late,
                                a.notices,
                            )
                            .await
                        }
                        RoomCmd::Tail(a) => {
                            crate::room_cli::tail(&paths, &a.room, a.since.as_deref(), a.json).await
                        }
                        RoomCmd::Roster(a) => crate::room_cli::roster(&paths, &a.room).await,
                        RoomCmd::Session(a) if a.drive.file.is_some() => {
                            crate::drive::run_file(
                                &paths,
                                &a.room,
                                &a.session,
                                a.drive.file.as_deref().unwrap_or(std::path::Path::new("")),
                                a.note.as_deref(),
                            )
                            .await
                        }
                        RoomCmd::Session(a) => match a.drive.action() {
                            Err(e) => Err(crate::app::AppError::Usage(e)),
                            Ok(Some(action)) => {
                                crate::drive::run(&paths, &a.room, &a.session, action).await
                            }
                            Ok(None) => {
                                crate::session_cli::show(
                                    &paths, &a.room, &a.session, a.details, a.json,
                                )
                                .await
                            }
                        },
                        RoomCmd::Sessions(a) => {
                            crate::room_cli::sessions(&paths, &a.room, a.json).await
                        }
                        RoomCmd::Ping(a) => {
                            crate::ping::ping(
                                &paths,
                                &a.room,
                                &a.member,
                                std::time::Duration::from_secs(a.wait),
                                a.json,
                            )
                            .await
                        }
                        RoomCmd::List(_) => crate::room_cli::list(&paths).await,
                        RoomCmd::Claim(a) => {
                            crate::room_cli::claim_resource(
                                &paths,
                                &a.room,
                                a.resource.as_deref(),
                                a.work.as_deref(),
                                a.ttl,
                                &a.coord.opts(),
                            )
                            .await
                        }
                        RoomCmd::Release(a) => {
                            crate::room_cli::release_resource(
                                &paths,
                                &a.room,
                                &a.resource,
                                &a.coord.opts(),
                            )
                            .await
                        }
                        RoomCmd::Decline(a) => {
                            crate::room_cli::decline_resource(
                                &paths,
                                &a.room,
                                &a.resource,
                                &a.coord.opts(),
                            )
                            .await
                        }
                        RoomCmd::Renew(a) => {
                            crate::room_cli::renew_resource(
                                &paths,
                                &a.room,
                                &a.resource,
                                &a.coord.opts(),
                            )
                            .await
                        }
                        RoomCmd::Handoff(a) => {
                            crate::room_cli::handoff_resource(
                                &paths,
                                &a.room,
                                &a.resource,
                                &a.to,
                                a.to_session.as_deref(),
                                a.ttl,
                                &a.coord.opts(),
                            )
                            .await
                        }
                        RoomCmd::Board(a) => {
                            crate::room_cli::board(&paths, &a.room, a.json, a.session.as_deref())
                                .await
                        }
                        RoomCmd::Join(a) => {
                            crate::room_cli::join(&paths, &a.link, a.passphrase_file.as_deref())
                                .await
                        }
                        RoomCmd::Create(a) => {
                            crate::room_cli::create(
                                &paths,
                                &a.name,
                                a.passphrase_file.as_deref(),
                                a.idle_end.as_deref(),
                            )
                            .await
                        }
                        RoomCmd::Link(a) => crate::room_cli::link(&paths, &a.room).await,
                        RoomCmd::Leave(a) => crate::room_cli::leave(&paths, &a.room).await,
                        RoomCmd::End(a) => crate::room_cli::end(&paths, &a.room).await,
                        RoomCmd::Admin(a) => {
                            crate::room_cli::admin(&paths, &a.action, &a.room, a.member.as_deref())
                                .await
                        }
                        RoomCmd::Rename(a) => {
                            crate::room_cli::rename(&paths, &a.room, &a.name).await
                        }
                        RoomCmd::Retention(a) => {
                            crate::room_cli::retention(&paths, &a.room, &a.duration).await
                        }
                        RoomCmd::Get(a) => {
                            crate::room_cli::get_file(
                                &paths,
                                &a.room,
                                &a.file,
                                a.dir.as_deref(),
                                a.out.as_deref(),
                            )
                            .await
                        }
                    }
                };
                let stop = crate::app::stop_requested("vox room");
                tokio::select! {
                    done = work => done,
                    signal = stop => Err(crate::app::AppError::stopped_by(signal)),
                }
            });
            match outcome {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    // Not `eprintln!`: after a hangup stderr can be a terminal that is gone.
                    use std::io::Write as _;
                    let _ = writeln!(io::stderr(), "vox: {e}");
                    // 3 = version refusal, 4 = operation conflict (ADR-021 §5, §6).
                    e.exit_code()
                }
            }
        }
        Cmd::Share(ShareArgs { cmd: Some(sub), .. }) => {
            let profile = match &sub {
                ShareCmd::Stop(a) => &a.profile,
                ShareCmd::List(a) => &a.profile,
            };
            let paths = match profile.paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            run_attached(async move {
                match &sub {
                    ShareCmd::Stop(a) => crate::share_cli::stop(&paths, &a.room, &a.share).await,
                    ShareCmd::List(a) => crate::share_cli::list(&paths, &a.room).await,
                }
            })
        }
        Cmd::Share(args) => {
            let paths = match args.profile.paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let (Some(room), Some(path)) = (args.room.clone(), args.path.clone()) else {
                eprintln!("vox: vox share needs a room and a path");
                return ExitCode::FAILURE;
            };
            let for_ = match args
                .for_
                .as_deref()
                .map(crate::share_cli::parse_for)
                .transpose()
            {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("vox: --for {e}");
                    return ExitCode::FAILURE;
                }
            };
            let opts = crate::share_cli::ShareOpts {
                to: args.to.clone(),
                urgent: args.urgent,
                re: args.re.clone(),
                note: args.note.clone(),
                count: args.count,
                for_,
            };
            run_attached(async move { crate::share_cli::share(&paths, &room, &path, &opts).await })
        }
        Cmd::Tunnel(TunnelCmd::Close(args)) => {
            let at = match args
                .profile
                .paths()
                .map_err(AppError::from)
                .and_then(|p| crate::client::one_shot(&p))
            {
                Ok(at) => at,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let which = vox_core::transport::quic::TunnelSelector {
                id: args.id,
                member: args.member.clone(),
                service: args.service.clone(),
            };
            // Only this node's own tunnels: the daemon answers it as the node the `Use` names
            // (ADR-026 P-1, §10.4).
            match rt.block_on(vox_core::node::status::request_close(&at, &which)) {
                Ok((0, refused)) if !refused.is_empty() => {
                    eprintln!("vox: {refused}");
                    ExitCode::FAILURE
                }
                Ok((0, _)) => {
                    eprintln!(
                        "vox: no live tunnel matches that — `vox status` lists them, with their \
                         numbers"
                    );
                    ExitCode::FAILURE
                }
                Ok((n, said)) => {
                    println!("vox: closed {n} tunnel(s)\n{said}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("vox: {}", crate::client::said(&at, e));
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Status(args) => {
            let paths = match args.profile.paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match rt.block_on(crate::status_cli::status(&paths, args.json)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("vox: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::App(sub) => {
            let profile = match &sub {
                AppCmd::Listen(a) => &a.profile,
                AppCmd::Open(a) => &a.profile,
            };
            let paths = match profile.paths() {
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
            let outcome = rt.block_on(async {
                match &sub {
                    AppCmd::Listen(a) => crate::app_cli::listen(&paths, &a.room, &a.label).await,
                    AppCmd::Open(a) => {
                        crate::app_cli::open(
                            &paths,
                            &a.room,
                            &a.peer,
                            a.labels.clone(),
                            a.datagrams,
                        )
                        .await
                    }
                }
            });
            // Not `rt` dropping: stdin's reader thread may still be blocked in a read, and
            // the runtime would wait for it.
            rt.shutdown_background();
            match outcome {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("vox: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Agent(AgentCmd::Send(args)) => {
            let outcome = vox_core::node::paths::NodeName::parse(&args.node)
                .map_err(AppError::from)
                .and_then(|node| {
                    let account = vox_core::node::paths::Account::of(
                        args.profile.data_dir.as_deref(),
                        args.profile.config_dir.as_deref(),
                    )?;
                    vox_core::node::layout::refuse_old_layout(&account)?;
                    block_on_client(async move {
                        crate::agent_send::run(
                            &account,
                            &node,
                            args.session.as_deref(),
                            &args.path,
                            args.note.as_deref(),
                        )
                        .await
                    })
                });
            match outcome {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("vox: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Agent(AgentCmd::Room(args)) => {
            let outcome = vox_core::node::paths::NodeName::parse(&args.node)
                .map_err(AppError::from)
                .and_then(|node| {
                    let account = vox_core::node::paths::Account::of(
                        args.profile.data_dir.as_deref(),
                        args.profile.config_dir.as_deref(),
                    )?;
                    vox_core::node::layout::refuse_old_layout(&account)?;
                    block_on_client(async move {
                        crate::agent_room::run(&account, &node, args.session.as_deref(), &args.room)
                            .await
                    })
                });
            match outcome {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("vox: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Agent(AgentCmd::Hook(args)) => {
            let node = match vox_core::node::paths::NodeName::parse(&args.node) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("vox: --node: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let account = match vox_core::node::paths::Account::of(
                args.profile.data_dir.as_deref(),
                args.profile.config_dir.as_deref(),
            ) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            // A data root this version does not read is refused first (#423), as for every verb.
            if let Err(e) = vox_core::node::layout::refuse_old_layout(&account) {
                eprintln!("vox: {e}");
                return ExitCode::FAILURE;
            }
            let paths = match account.node_paths(&node) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let daemon = crate::agent_hook::Daemon {
                account,
                node,
                listen: args.profile.listen,
                anchors: args.profile.anchors.clone(),
            };
            let format = match args.format.parse() {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("vox: --format: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                // Even this is not worth failing a turn over.
                return ExitCode::SUCCESS;
            };
            let _ = rt.block_on(crate::agent_hook::run(
                &paths,
                &daemon,
                args.room.as_deref(),
                format,
                args.session.as_deref(),
            ));
            // Always success: a hook that fails must not break the turn.
            ExitCode::SUCCESS
        }
        Cmd::Daemon(args) => match crate::daemon::run(&args) {
            Ok(()) => ExitCode::SUCCESS,
            // Not `eprintln!`: after a hangup stderr can be a terminal that is gone, and a
            // write that fails there must not turn the reason into a panic.
            Err(e) => {
                use std::io::Write as _;
                let _ = writeln!(io::stderr(), "vox: {e}");
                e.exit_code()
            }
        },
        Cmd::Agent(AgentCmd::Doctor(args)) => {
            let paths = match args.profile.paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match rt.block_on(crate::doctor::doctor(
                &paths,
                args.room.as_deref(),
                args.json,
            )) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("vox: {e}");
                    e.exit_code()
                }
            }
        }
        Cmd::Agent(AgentCmd::Skill(args)) => {
            // Where it goes, on stderr so it does not land in the file (V210-121, V210-166):
            // user scope, beside the drain, so every repository gets both.
            let named: Vec<&str> = match &args.harness {
                Some(h) if skill_dir(h).is_none() => {
                    eprintln!("vox: no integration for {h:?}. Known: claude, codex, opencode.");
                    return ExitCode::FAILURE;
                }
                Some(h) => vec![h.as_str()],
                None => vec!["claude", "codex", "opencode"],
            };
            print!("{}", crate::agent_hook::AGENT_SKILL);
            if named.len() == 1 {
                let h = named[0];
                let dir = skill_dir(h).unwrap_or_default();
                eprintln!("vox: install at user scope: {}", skill_install(h, dir));
            } else {
                eprintln!("vox: each harness loads this same file from its own skills folder:");
                for h in named {
                    let dir = skill_dir(h).unwrap_or_default();
                    eprintln!("     {h:<8} {}", skill_install(h, dir));
                }
            }
            ExitCode::SUCCESS
        }
        Cmd::Agent(AgentCmd::Trust(args)) => match args.harness.to_ascii_lowercase().as_str() {
            "codex" => match crate::codex_trust::trust(&args.codex) {
                Ok(r) if r.found == 0 => {
                    eprintln!(
                        "vox: Codex has no hook running `vox agent hook` — add the entry \
                         `vox agent plugin codex` prints to its hooks.json first."
                    );
                    ExitCode::FAILURE
                }
                Ok(r) => {
                    for (key, command) in &r.entries {
                        println!("vox: trusted {command:?} ({key})");
                    }
                    println!(
                        "vox: {} Vox hook entr{} in Codex; {} newly trusted, the rest already were.",
                        r.found,
                        if r.found == 1 { "y" } else { "ies" },
                        r.trusted_now
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("vox: {e}");
                    ExitCode::FAILURE
                }
            },
            "claude" | "claude-code" | "opencode" => {
                println!(
                    "vox: {} does not gate hooks on trust; nothing to do.",
                    args.harness
                );
                ExitCode::SUCCESS
            }
            other => {
                eprintln!("vox: no integration for {other:?}. Known: claude, codex, opencode.");
                ExitCode::FAILURE
            }
        },
        Cmd::Agent(AgentCmd::Plugin(args)) => {
            let node = match vox_core::node::paths::NodeName::parse(&args.node) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("vox: --node: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match args.harness.to_ascii_lowercase().as_str() {
                "opencode" => {
                    print!("{}", crate::agent_hook::opencode_plugin(&node));
                    eprintln!(
                    "vox: save that as ${{XDG_CONFIG_HOME:-~/.config}}/opencode/plugin/vox.js, and install the skill \
                     beside it: {}\n     The plugin drains every room the node holds.",
                    skill_install("opencode", skill_dir("opencode").unwrap_or_default())
                );
                    ExitCode::SUCCESS
                }
                // **Print the thing, do not describe it.** These take a hook entry rather than
                // a plugin file, and this used to answer with a sentence saying so — while its
                // own `--help` promised "a JSON snippet". So the one command a person runs to
                // wire an agent in left them to invent the settings shape themselves, for the
                // feature ADR-020 exists to deliver. The snippet goes to stdout so it can be
                // redirected or piped to `jq`; where to put it goes to stderr so it does not
                // land in the file.
                "claude" | "claude-code" => {
                    // `UserPromptSubmit` drains the room; `Stop` records that a turn ended, so an
                    // unread reply can be announced to an idle session; `SessionEnd` removes the
                    // session's registration (V030-20).
                    print!("{}", crate::agent_hook::claude_settings(&node));
                    eprintln!(
                        "vox: merge that into ~/.claude/settings.json (user scope, so a session \
                     opened in any repository hears its rooms; `env` names the node every `vox` \
                     the agent runs acts as), and install the skill beside it: {}\n     The \
                     hook drains every room the node holds.",
                        skill_install("claude", skill_dir("claude").unwrap_or_default())
                    );
                    ExitCode::SUCCESS
                }
                // The entry is a matcher group holding `hooks`, as Claude Code's is: Codex 0.160
                // lists a bare `{ "command": … }` entry as no hook at all, so the room never
                // drained (V210-169).
                "codex" => {
                    print!("{}", crate::agent_hook::codex_hooks(&node));
                    eprintln!(
                    "vox: merge that into Codex's hooks.json, then run `vox agent trust codex` \
                     — Codex runs a hook only once it is trusted.\n     Codex sets no \
                     environment for its shell from here: pass `--node {node}` to every `vox` \
                     the agent runs.\n     `async` MUST be false: \
                     an async hook's output is observed and discarded, so the room would \
                     drain into nothing.\n     The hook drains every room the node holds.\n     \
                     Vox never interrupts a Codex session: an urgent message to one waits \
                     for its next turn, and a poster on the same node is told so.\n     \
                     Install the skill beside it: {}",
                    skill_install("codex", skill_dir("codex").unwrap_or_default())
                );
                    ExitCode::SUCCESS
                }
                other => {
                    eprintln!("vox: no integration for {other:?}. Known: claude, codex, opencode.");
                    ExitCode::FAILURE
                }
            }
        }
        // Ask the running node when there is one, as `vox service remove` does (V030-06): the
        // profile is not ours to open while a daemon holds it, and stopping the daemon to add a
        // service, then starting it again with every room's passphrase, is not something a person
        // should have to do. The daemon holds the room open already, so no passphrase is asked.
        // **Asked of the daemon, as the node** (ADR-026 S-3): a service is kept by the node, so it
        // is offered again whenever the node attaches (V030-06), and the room it is offered in is
        // one the node holds open. Nothing here opens a room or asks for a passphrase.
        Cmd::Service(sub) => {
            let given = match &sub {
                ServiceCmd::Add(a) => a.room.passphrase.as_ref(),
                ServiceCmd::Remove(r) => r.room.passphrase.as_ref(),
                ServiceCmd::List(_) => None,
            };
            if let Err(e) = crate::tunnel_cli::refuse_disclosed_room_passphrase(given) {
                eprintln!("vox: {e}");
                return ExitCode::FAILURE;
            }
            let profile = match &sub {
                ServiceCmd::Add(a) => &a.room.profile,
                ServiceCmd::Remove(r) => &r.room.profile,
                ServiceCmd::List(r) => &r.profile,
            };
            let paths = match profile.paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            run_attached(async move {
                match &sub {
                    ServiceCmd::Add(a) => {
                        crate::room_cli::service_add(
                            &paths,
                            &a.room.room,
                            &label_of(&a.tag),
                            a.local,
                        )
                        .await
                    }
                    ServiceCmd::Remove(r) => {
                        crate::room_cli::service_remove(&paths, &r.room.room, &label_of(&r.tag))
                            .await
                    }
                    ServiceCmd::List(r) => {
                        crate::room_cli::service_list(&paths, &r.room, r.json).await
                    }
                }
            })
        }
        // **The fingerprint is read, never served by a node of this verb's own** (ADR-026 S-3):
        // from the daemon when the node is attached, else from the node's files, which hold it
        // in the clear. A node with no identity has one made here first (C-5).
        Cmd::Id(args) => {
            let paths = match args.profile.paths_creating() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match crate::room_cli::print_identity(
                &paths,
                args.identity_passphrase.clone(),
                args.identity_passphrase_file.clone(),
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("vox: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        // **Always asked of the daemon, as the node** (ADR-026 S-3): a read needs no passphrase,
        // and a change needs it only once 30 minutes have passed since it was last entered, when
        // this asks for it (V210-159, N-2). Whoever runs as this user is this user; the socket's
        // owner check is the boundary.
        Cmd::Trust(sub) => run_trust_over_socket(sub),
        Cmd::Up(args) => {
            if let Err(e) =
                crate::tunnel_cli::refuse_disclosed_room_passphrase(args.passphrase.as_ref())
            {
                eprintln!("vox: {e}");
                return ExitCode::FAILURE;
            }
            let paths = match args.profile.paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let waiting = crate::tunnel_cli::Waiting::client();
            let steps = std::sync::Arc::clone(&waiting);
            run_session(waiting, async move {
                let room_pp = match &args.passphrase_file {
                    Some(f) => {
                        let text = crate::tunnel_cli::passphrase_file_text(f)?;
                        Some(text.lines().next().unwrap_or_default().to_owned())
                    }
                    None => None,
                };
                let room = args.room.as_deref().map(|r| (r, room_pp.as_deref()));
                crate::tunnel_cli::up(
                    &paths,
                    &args.profile,
                    pass(args.identity_passphrase, args.identity_passphrase_file),
                    room,
                    args.watch,
                    &steps,
                )
                .await
            })
        }
        // One shape: a service's address, `vox forward <service>.<node>.<room>.vox [<local>]`
        // (V030-25), resolved and carried by the daemon as this node. The three-word form,
        // `vox forward <room> <member> <service>`, is gone with the in-process node it needed.
        Cmd::Forward(args) => {
            let paths = match args.profile.paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let name = args.address.trim().to_ascii_lowercase();
            if !name.ends_with(".vox") {
                eprintln!(
                    "vox: forward a service by its address: vox forward \
                     <service>.<node>.<room>.vox [<local>]  (`vox service list <room>` shows each)"
                );
                return ExitCode::FAILURE;
            }
            let local = args
                .local
                .clone()
                .unwrap_or_else(|| "127.0.0.1:0".to_owned());
            let waiting = crate::tunnel_cli::Waiting::client();
            let steps = std::sync::Arc::clone(&waiting);
            run_session(waiting, async move {
                crate::tunnel_cli::forward_named(
                    &paths,
                    &args.profile,
                    pass(args.identity_passphrase, args.identity_passphrase_file),
                    &name,
                    &local,
                    &steps,
                )
                .await
            })
        }
        Cmd::Lan(LanCmd::Helper(a)) => {
            match crate::lan_cli::run_helper(&a.socket, a.serve_bundle_owner) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("vox lan helper: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Lan(LanCmd::Up(a)) => {
            if let Err(e) =
                crate::tunnel_cli::refuse_disclosed_room_passphrase(a.room.passphrase.as_ref())
            {
                eprintln!("vox: {e}");
                return ExitCode::FAILURE;
            }
            // Asked before the node is touched: without a helper nothing here can work, and a
            // refusal should leave nothing behind.
            if let Err(why) = crate::lan_cli::helper_answers(&a.helper_socket) {
                eprintln!("vox: {why}");
                return ExitCode::FAILURE;
            }
            let paths = match a.room.profile.paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let waiting = crate::tunnel_cli::Waiting::client();
            let steps = std::sync::Arc::clone(&waiting);
            run_session(waiting, async move {
                crate::lan_cli::up_held(&paths, &a, &steps).await
            })
        }
        Cmd::Setup(account) => match crate::setup::run(&account.as_node_args()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("vox: {e}");
                ExitCode::FAILURE
            }
        },
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
