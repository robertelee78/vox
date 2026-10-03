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

/// Run a verb that holds a session on the daemon (ADR-026 L-7): `serve`, `connect`, `up`,
/// `forward`.
///
/// **The whole run races every stop signal, from before the first prompt** (V210-108): the
/// passphrase prompts run on a blocking thread inside `work`. A server's stop (`vox serve`) is its
/// normal end and exits 0, as a service manager expects of a service it stopped; any other verb
/// stopped before it finished exits 128 + the signal's number, saying what it waited for
/// (V210-85). Stopping the client leaves the node as the daemon has it: the hold this verb took
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

/// The service label a person's spec names: `53/udp` is `udp/53` (ADR-022 decision 6), and
/// anything that is not a port spec is used as the tag it already is.
fn label_of(spec: &str) -> String {
    vox_core::tunnel::udp::service_label(spec).unwrap_or_else(|| spec.to_owned())
}

/// Run a verb that attaches to the node already holding the profile.
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

/// The name `vox trust add` files an identity under (V210-162): `--name`, or asked for on a
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

/// Run a trust verb against the node that is already holding this profile.
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
    };
    let paths = match profile.paths() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vox: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Only what the command line gave. A read needs none, and a change asks for it only when
    // the node says it is needed (V210-159, V210-165).
    let given = match crate::tunnel_cli::identity_passphrase_given(pass, pass_file) {
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
    let outcome = rt.block_on(async move {
        match sub {
            TrustCmd::List(_) => crate::room_cli::trust_list(&paths).await,
            TrustCmd::Add(a) => {
                let target = crate::tunnel_cli::parse_fingerprint(&a.fingerprint)?;
                crate::room_cli::trust_add(&paths, target, &name, given, a.history == "full").await
            }
            TrustCmd::Remove(a) => {
                let target = crate::tunnel_cli::parse_fingerprint(&a.fingerprint)?;
                crate::room_cli::trust_remove(&paths, target, given).await
            }
            TrustCmd::Rename(a) => {
                crate::room_cli::trust_rename(&paths, &a.fingerprint, &a.name, given).await
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
    /// Only a room this profile holds open. Listing opens no room, so it asks for no room
    /// passphrase, and a room you closed stays closed.
    List(ServiceListArgs),
}

/// `vox lan` — the family LAN.
#[derive(Subcommand, Debug, Clone)]
enum LanCmd {
    /// Create LAN interfaces for `vox lan up`, as root. Run it with `sudo`: it serves only
    /// the person who ran `sudo`, accepts only LAN addresses (`100.64.0.0/10`,
    /// `fd00::/8`), opens no profile and touches no network. Runs until interrupted;
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
    /// Serve Prometheus metrics at this address, as `vox daemon --metrics` does (PRD-001 R38).
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
    Post(RoomPostArgs),
    /// Print a room's messages. The first column is the entry hash, which is the
    /// cursor: pass the last one back as `--since` to read only what is new.
    Read(RoomReadArgs),
    /// Print new messages as they arrive, until stopped.
    ///
    /// SIGINT (Ctrl-C), SIGTERM, SIGHUP or SIGQUIT each stops it cleanly.
    ///
    /// With `--since`, first every message after that cursor, then every new one —
    /// **with no gap across a lag or a restart** (ADR-021 §7). Persist the last entry
    /// hash you processed and pass it back to resume. `--json` prints one
    /// `vox.room.row/1` object per line.
    Tail(RoomTailArgs),
    /// Print the fingerprints of the room's members.
    Roster(RoomRefArgs),
    /// Ask a member's node which agent sessions it holds, and whether each can be reached
    /// (V030-16).
    ///
    /// The ping is answered by that node's **daemon**, never by a model: it lists each session,
    /// whether an urgent message interrupts it, and when it last read. Pings and answers are
    /// never shown to a model and wake no one. A node answers only a member it trusts, so no
    /// answer cannot tell an offline node and missing trust in either direction apart, and says
    /// so. Exits 1 when no answer comes within `--wait`.
    ///
    /// ```text
    /// vox room ping <room> carol
    /// ```
    Ping(RoomPingArgs),
    /// List the rooms this node holds.
    List(NodeArgs),
    /// Take a unit of work, so no other agent starts it (ADR-020 §5).
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
    /// Ownership is per **session** (ADR-021 §4): the session comes from `--session`,
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
    /// Offer a file to the room and announce it (ADR-020 §11).
    ///
    /// The bytes never enter the log: they ride a room-bound service, and what
    /// goes on the log is a signed announcement carrying the name, the size and
    /// the **SHA-256**. Runs until stopped (SIGINT (Ctrl-C), SIGTERM, SIGHUP or SIGQUIT each stops
    /// it cleanly), because the bytes are served
    /// live — the announcement outlives the offer, so an agent that wakes late
    /// sees what was sent and is told plainly if it can no longer be collected.
    ///
    /// Nobody is granted anything: whoever can read the announcement can reach
    /// the bytes, because both are gated on this node's trust keyring.
    Send(SendFileArgs),
    /// Join a room from a `vox://` address, over a running node (ADR-020 §12).
    ///
    /// The passphrase is asked for at the terminal, or read from `--passphrase-file`
    /// (`-` reads stdin); never argv, which anything that can run `ps` would see:
    ///
    /// ```text
    /// echo 'the room passphrase' | vox room join --passphrase-file - vox://… --name mission
    /// ```
    ///
    /// This is what makes agent comms usable on a host with no terminal: `vox
    /// daemon` lets a node hold rooms unattended, and this is how a room gets
    /// onto it. Joining grants nothing — whether anyone can read you is their
    /// decision, made with `vox trust`.
    Join(JoinRoomArgs),
    /// Create a room on a running node. Passphrase at the terminal, or from
    /// `--passphrase-file` (`-` reads stdin).
    Create(CreateRoomArgs),
    /// Set how long the room keeps messages: `1h`, `1w`, `1m` (a month), a number of
    /// seconds, or `forever` (PRD-001 R7).
    ///
    /// It applies to **everything already in the room**, on every member, as the change
    /// reaches them: shortening it deletes older messages. Only the room's admin may, and it
    /// asks for the identity passphrase for that reason. A node can keep less than its room
    /// (the `retention` file in its config directory); the shorter wins. This is look and
    /// feel, not a security property: a modified node can keep everything.
    Retention(RetentionArgs),
    /// Print a room's address, for someone else to `vox room join` with.
    ///
    /// The address is rendezvous information, not a credential — no passphrase,
    /// and joining with it grants nothing. Goes to stdout so it pipes; the
    /// warnings go to stderr so they do not.
    Invite(RoomRefArgs),
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
    /// A local name for the room. Never leaves this device.
    #[arg(long, default_value = "room")]
    pub name: String,
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
    /// A local name for the room. Never leaves this device.
    #[arg(long, default_value = "room")]
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

/// `vox room retention`
#[derive(Args, Debug, Clone)]
pub struct RetentionArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// `1h`, `1w`, `1m` (a month), a number of seconds, or `forever`.
    pub duration: String,
    /// **Refused**, as on `vox trust add`: a command line is world-readable.
    #[arg(long)]
    pub identity_passphrase: Option<String>,
    /// Read the identity passphrase from this file (first line).
    #[arg(long)]
    pub identity_passphrase_file: Option<std::path::PathBuf>,
}

/// `vox room send`
#[derive(Args, Debug, Clone)]
pub struct SendFileArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// The file to offer.
    pub path: PathBuf,
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
    /// The directory to put it in, under the sender's name made safe. Defaults to the
    /// directory named in the profile's `downloads` config file, else `~/Downloads`.
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
    /// Serve Prometheus metrics at this address (PRD-001 R38). Loopback only: the
    /// counters name every peer and room this node talks to.
    #[arg(long)]
    pub metrics: Option<SocketAddr>,
    /// The node to attach in the foreground (ADR-026 C-3). Without it: the only node on disk,
    /// else `default` when there is none, else no node (the daemon runs with none).
    #[arg(long, env = "VOX_NODE")]
    pub node: Option<String>,
    /// Start the daemon in the background and return once it answers; its output goes to
    /// `<data root>/.daemon/log`. It exits once it has no attached node and no client.
    #[arg(long, conflicts_with_all = ["keep", "passphrase_file"])]
    pub detach: bool,
    /// Keep the foreground node attached across daemon restarts (`.daemon/attach`, ADR-026 L-4).
    /// Its passphrase comes from `--passphrase-file` then, or it has none.
    #[arg(long)]
    pub keep: bool,
    /// How a client starts the daemon (ADR-026 S-2): its own session, no foreground node, and an
    /// exit once nothing is attached and no client is connected.
    #[arg(long = "as-detached", hide = true)]
    pub as_detached: bool,
}

/// `vox tunnel …` (V030-11).
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
pub struct ShareArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// The file or folder to share. A folder is served as one tar.
    pub path: PathBuf,
    /// Stop after this many completed fetches.
    #[arg(long)]
    pub count: Option<u64>,
    /// Stop after this long: `90s`, `10m`, `2h`.
    #[arg(long = "for")]
    pub for_: Option<String>,
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

/// Session, operation id and output shape, shared by every coordinating verb
/// (ADR-021 §4, §6).
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
    /// in `data.work` and used as the resource (ADR-021 §2).
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
    /// ```text
    /// vox agent plugin opencode > ~/.config/opencode/plugin/vox.js
    /// vox agent plugin claude            # merge into ~/.claude/settings.json
    /// vox agent plugin codex             # merge into Codex's hooks.json
    /// ```
    ///
    /// The integration goes to stdout so it can be redirected or piped through
    /// `jq`; where to put it goes to stderr, so it does not land in the file.
    ///
    /// The plugin is a shim over `vox agent hook`, not a second implementation.
    Plugin(AgentPluginArgs),
    /// Print the agent-facing skill: what the room is for, its vocabulary and its
    /// manners (ADR-020 §8).
    ///
    /// A skill is on-demand only, so it cannot be what guarantees an agent reads
    /// its room — that is `vox agent hook`'s job. This carries what a hook cannot.
    ///
    /// Claude Code, Codex and OpenCode all load the same file, a `SKILL.md` in a folder
    /// named after the skill. Install it at **user scope**, beside the drain, so a
    /// session opened in any repository has both:
    ///
    /// ```text
    /// mkdir -p ~/.claude/skills/vox-agent-comms
    /// vox agent skill claude > ~/.claude/skills/vox-agent-comms/SKILL.md
    /// mkdir -p ~/.codex/skills/vox-agent-comms           # $CODEX_HOME/skills when set
    /// vox agent skill codex > ~/.codex/skills/vox-agent-comms/SKILL.md
    /// mkdir -p ~/.config/opencode/skills/vox-agent-comms # $XDG_CONFIG_HOME/opencode/skills when set
    /// vox agent skill opencode > ~/.config/opencode/skills/vox-agent-comms/SKILL.md
    /// ```
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
    /// ```text
    /// vox agent trust codex
    /// ```
    Trust(AgentTrustArgs),
    /// Check that this node's agent sessions are wired up, and say how to fix what is not
    /// (V030-16).
    ///
    /// One line per check, `ok`, `warn` or `fail`, each with a one-line fix: the node answers;
    /// the room resolves; Claude Code's hook entries exist once at user scope; Codex's hook is
    /// trusted; the OpenCode plugin is this build's; the drain can read the room and record its
    /// place; each session's record (first seen, last drained, idle or busy, wake endpoint
    /// alive); trust in each direction with every member; and the members' versions. `warn` is
    /// something not set up, `fail` something set up that will not work. Exits 1 on any `fail`.
    /// It only reads: it starts no harness or model, changes nothing and wakes no one.
    ///
    /// ```text
    /// vox agent doctor --room <room>
    /// ```
    Doctor(AgentDoctorArgs),
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
/// server and seeing the skill in what it sent (V210-166).
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
    /// The agent's own node, which the printed hooks act as (`vox agent hook --node <name>`,
    /// ADR-020 2.1). Required: an agent never uses a person's node.
    #[arg(long, required = true)]
    pub node: String,
}

/// `vox agent hook`
#[derive(Args, Debug, Clone)]
pub struct AgentHookArgs {
    #[command(flatten)]
    pub profile: AccountArgs,
    /// The node this hook acts as: the agent's own node (ADR-020 2.1, ADR-026 N-6). Required, and
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
    /// (`vox room roster`). Repeat for several. A name that is no member is refused.
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
    #[command(flatten)]
    pub coord: CoordArgs,
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
    /// Print every entry this node holds for the room in the room's order, one per
    /// line as `<entry-hash> <clock-ms>` — readable or not. The sequence every member's view is a part of,
    /// and the one that must be identical on every node (PRD-001 R13).
    #[arg(long, hide = true, conflicts_with_all = ["since", "limit", "json"])]
    pub hashes: bool,
    /// Print only the messages marked late: they arrived after rows below them had already
    /// been shown, and sit in their true place in history (ADR-023 decision 1).
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
    /// everything it starts (V210-72).
    ///
    /// Use `--passphrase-file`, or let it prompt (it reads a line from stdin when stdin is
    /// not a terminal).
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

/// `vox service list`: a room's args without its passphrase, which listing never uses (V210-149).
#[derive(Args, Debug, Clone)]
pub struct ServiceListArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
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

/// A profile plus the identity passphrase, for the verbs that unlock an identity but open
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
    /// Only rooms made by someone in this profile's `vox trust` list.
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
    /// Address the daemon binds when this command starts it (ADR-026 D-3).
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

/// `vox node create|attach|detach|list` (ADR-026 §3).
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
            account,
        } => crate::client::node_create(&account.as_node_args(), &name, passphrase_file),
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
    /// it; `trusted` serves only rooms made by someone in this profile's `vox trust` list.
    /// `trusted` needs this profile's identity passphrase to read that list, and reads it once
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
    /// needs it: the trust list is sealed under this profile's identity.
    #[arg(long)]
    pub identity_passphrase_file: Option<std::path::PathBuf>,
}

/// The node `vox node` runs its anchor as. One node is one identity (ADR-026 F-3), so a node
/// holding a vault keeps its anchor's key in node `<name>-anchor` — where the migration put the
/// key of a directory that held both — and `--serve trusted` still reads the vault's trust list
/// from `<name>`. Otherwise the anchor is the named node itself.
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

    /// For `--serve trusted`, the creators whose rooms this anchor serves: the profile's
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
                "--serve trusted: {why}. It serves only rooms made by someone in this profile's \
                 `vox trust` list, so it will not start without it"
            ))
        };
        // Two different failures, and each needs different advice: a profile with no identity
        // has no trust list to read and needs one made; a profile that has one but cannot be
        // opened has a list this process cannot get at, and remaking it would not help.
        if !vox_core::node::profile::Profile::exists(paths) {
            return Err(refuse(format!(
                "this profile has no identity, so no `vox trust` list to read; make one with \
                 `vox id` and `vox trust add <fingerprint>` in the profile at {}",
                paths.profile_dir.display()
            )));
        }
        let mut profile = vox_core::node::profile::Profile::open(paths.clone()).map_err(|e| {
            refuse(format!(
                "this profile's identity and `vox trust` list exist but could not be opened \
                 ({e}); check that the files in {} belong to and are readable by the user \
                 running `vox node`, and that no other vox has this profile open",
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
    /// room: from here on every room this node shares with that key auto-consents to it,
    /// including rooms made later, **and** that key may reach every service this node
    /// binds to a room they are both in (ADR-017 decision 3). One act, not one per room.
    Add(TrustAddArgs),
    /// List the identities this node trusts, and what it calls them.
    List(IdentityArgs),
    /// Stop trusting an identity, and change the lock.
    ///
    /// Removes the ring entry, then rotates this identity's sender key and re-keys
    /// everyone still trusted, in every room shared with the removed key — so it stops
    /// reading what comes next, everywhere (ADR-017 M17.14). It keeps what it already
    /// read; that cannot be taken back.
    Remove(TrustRemoveArgs),
    /// Change the name this node calls a trusted identity. The name is what
    /// `<name>.<room>.vox` reaches (PRD-001 R20); it is local to this machine and never
    /// leaves it. Grants nothing: only an identity already trusted can be renamed.
    Rename(TrustRenameArgs),
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
    /// What each consent to it releases of **your own** messages (PRD-001 R12): `now`,
    /// the default, from this approval onward; or `full`, everything you still hold a key
    /// for, so it also reads what you wrote before. Your messages only — nobody else's.
    #[arg(long, value_parser = ["now", "full"], default_value = "now")]
    pub history: String,
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
    /// shares both.
    #[arg(required = true, num_args = 1..)]
    pub ports: Vec<String>,
    /// The local endpoint to carry connections to, when it is not `127.0.0.1:<port>`.
    #[arg(long)]
    pub at: Option<SocketAddr>,
    /// A local name for the room (this device only; never leaves it).
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
    /// everything it starts (V210-72).
    ///
    /// Use `--passphrase-file`, or let it prompt (it reads a line from stdin when stdin is
    /// not a terminal).
    #[arg(long)]
    pub passphrase: Option<String>,
    /// Read the room passphrase from this file (first line). The scripted way to give it: a
    /// file has an owner and a mode, where a command line has neither.
    #[arg(long)]
    pub passphrase_file: Option<std::path::PathBuf>,
    /// A local name for the room (this device only).
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

/// `vox up`
#[derive(Args, Debug, Clone)]
pub struct UpArgs {
    #[command(flatten)]
    pub profile: NodeArgs,
    /// One room to open and carry, with its passphrase. Omitted, the proxy runs inside
    /// the node already holding this profile (`vox daemon`) and carries every room it
    /// holds: `ssh nas.family.vox` for any node you trust, in any room (PRD-001 R20).
    pub room: Option<String>,
    /// **Refused**, as on every room verb (V210-72): use `--passphrase-file`, or let it prompt
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
    /// Where the proxy listens. Loopback only, and a port above 1024 — nothing here needs
    /// privilege.
    #[arg(long, default_value = "127.0.0.1:1080")]
    pub bind: SocketAddr,
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
    /// read nothing; its identity is a key file in the profile directory, created on
    /// first run. Prints the `<fingerprint>@<multiaddr>` to give clients as `--anchor`.
    ///
    /// Runs until stopped: SIGINT (Ctrl-C), SIGTERM, SIGHUP or SIGQUIT each stops it cleanly.
    Node(AnchorArgs),
    /// Run this profile's node without a terminal, so agent sessions can attach
    /// (ADR-020 §12).
    ///
    /// The TUI is the only other thing that serves the agent-comms control socket,
    /// and it needs a terminal and locks the node when that terminal goes away. A
    /// `vox node` is an anchor: it holds no room and can read nothing. This is the
    /// third shape — an unlocked node holding this profile's rooms, serving the
    /// socket, with nothing attached to a tty.
    ///
    /// At a terminal it asks for the identity passphrase, without echo, and serves once
    /// it is typed. Otherwise it takes it from `VOX_IDENTITY_PASSPHRASE`, or
    /// `--passphrase-file`, or stdin:
    ///
    /// ```text
    /// echo 'my passphrase' | vox daemon
    /// ```
    ///
    /// Unlike the TUI it does not lock on SIGHUP: SIGINT (Ctrl-C), SIGTERM, SIGHUP or SIGQUIT each
    /// stops it cleanly.
    Daemon(DaemonArgs),
    /// Offer a local TCP port as a room-bound service, in one command (ADR-017).
    ///
    /// Creates a room, offers the port in it, and prints the address, the
    /// machine-generated passphrase and the `.vox` hostname it answers on. Runs until
    /// stopped (SIGINT (Ctrl-C), SIGTERM, SIGHUP or SIGQUIT each stops it cleanly), reporting who
    /// reaches the service (the service itself cannot tell
    /// you: every Vox client arrives at it from loopback).
    ///
    /// **Joining the room does not grant access to the port.** Whoever you have run
    /// `vox trust add` on can reach it, and nobody else — the trust keyring is the
    /// authorization (ADR-017 decision 3, M17.6/M17.7). Handing somebody the address and
    /// the passphrase lets them into the room; it does not let them at your machine's
    /// port.
    ///
    /// This said the opposite until 2026-09-22 — that the room's genesis granted every
    /// member the right to dial, so "joining the room *is* the authorization and you
    /// never wait to grant anyone anything". That model was withdrawn in ADR-017's third
    /// revision, along with the genesis service grant and the `vox grant` verb, and the
    /// text outlived it. A person reading it would have believed that sharing an address
    /// was all it took to let somebody at a local port.
    Serve(ServeArgs),
    /// Join a room from the address you were given, and print the name its services
    /// answer on (ADR-017). One-shot: joining is durable, so there is nothing to keep
    /// running — `vox up` is what makes the name resolve.
    Connect(ConnectArgs),
    /// Offer a local TCP service to a room, or list what is offered (ADR-013).
    ///
    /// A service is dark by default: offering it grants nobody reach. Members reach it
    /// only once their host has trusted them (`vox trust add`) and they are a member of this
    /// room — the ring-keyed gate of ADR-017 decision 3 as revised. `dial:` capabilities and
    /// `vox grant` are withdrawn with the model that needed them (M17.7).
    #[command(subcommand)]
    Service(ServiceCmd),
    /// Join, create or leave a room, and speak in it, over a **running** node (ADR-020) —
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
    /// Open or accept an app stream to a program on another member's node (ADR-022).
    ///
    /// The shape of `nc`, over a running node: `listen` waits for one stream speaking a
    /// label and pipes it; `open` opens one. Both sides must trust each other, and the
    /// peer must be a member of the room.
    #[command(subcommand)]
    App(AppCmd),
    /// Share a file or a folder with a room: served over HTTP as a room-bound service,
    /// announced with its name, size and SHA-256 (PRD-001 R18). Members you trust pull
    /// it with `vox room get`, or with curl through `vox up`. Stops after `--count`
    /// fetches, after `--for`, or on ^C.
    Share(ShareArgs),
    /// What the running node is doing, and what needs attention (PRD-001 R35): rooms and
    /// their sync, peers and their paths, tunnels, datagram and app counters, and the sync
    /// counters per room and peer (ADR-025): sessions opened, admitted, refused, completed,
    /// partial and failed, and any backoff.
    Status(StatusArgs),
    /// Wire an agent session into a room (ADR-020) — Claude Code, Codex and OpenCode.
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
    /// Bring up the local entry point for a room's services: a SOCKS5 proxy that resolves
    /// the room's `.vox` name (ADR-017).
    ///
    /// This is how a tool reaches a room-bound service by name — the same shape a Tor user
    /// reaches a `.onion` through, and for the same reason: it needs no privilege of any
    /// kind. `ssh` is pointed at it with one `ProxyCommand` line, which `vox up` prints;
    /// most other tools take `ALL_PROXY=socks5h://…`. Runs until stopped: SIGINT (Ctrl-C),
    /// SIGTERM, SIGHUP or SIGQUIT each stops it cleanly.
    Up(UpArgs),
    /// Forward a local port to a member's service over the overlay — `ssh` over Vox
    /// (ADR-013). Runs until stopped: SIGINT (Ctrl-C), SIGTERM, SIGHUP or SIGQUIT each stops it
    /// cleanly.
    Forward(ForwardArgs),
    /// Put this machine on a room's **family LAN** (PRD-001 R28): a network interface on
    /// which the room's trusted members are one subnet, so that discovery — Plex and
    /// Jellyfin, Chromecast, a game's LAN lobby — works across Vox.
    ///
    /// Two commands, because only one of them needs root: `sudo vox lan helper` creates
    /// interfaces and does nothing else, and `vox lan up <room>`, run as yourself, asks it
    /// for one and carries the room's traffic on it.
    #[command(subcommand)]
    Lan(LanCmd),
    /// Print this profile's own identity fingerprint — what to send someone so they can
    /// trust you (ADR-002).
    ///
    /// It is the whole 52-character base32 fingerprint, on its own line, so it can be
    /// piped or pasted without editing. Verify it out of band, the way you would a PGP
    /// fingerprint: nothing registers it and nothing looks it up.
    Id(IdentityArgs),
    /// Decide which identities this node trusts (ADR-020 §3, ADR-017 decision 3).
    #[command(subcommand)]
    Trust(TrustCmd),
    /// Close the live tunnels `vox status` lists (V030-11).
    #[command(subcommand)]
    Tunnel(TunnelCmd),
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
            let paths = match args.paths_creating() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox node: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let anchors = match args.anchor_set_lenient() {
                Ok((a, None)) => a,
                // An anchor may run with no anchor of its own, but it says why it has none.
                Ok((a, Some(unusable))) => {
                    eprintln!("vox node: {unusable}; running with no anchor of its own");
                    a
                }
                Err(e) => {
                    eprintln!("vox node: --anchor: {e}");
                    return ExitCode::FAILURE;
                }
            };
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
            match run_node(paths, args.listen, anchors, serve_only) {
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
                    &args.name,
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
                RoomCmd::Ping(a) => &a.profile,
                RoomCmd::Tail(a) => &a.profile,
                RoomCmd::Board(a) => &a.profile,
                RoomCmd::List(p) => p,
                RoomCmd::Claim(a) => &a.profile,
                RoomCmd::Release(a) | RoomCmd::Decline(a) | RoomCmd::Renew(a) => &a.profile,
                RoomCmd::Handoff(a) => &a.profile,
                RoomCmd::Send(a) => &a.profile,
                RoomCmd::Get(a) => &a.profile,
                RoomCmd::Join(a) => &a.profile,
                RoomCmd::Create(a) => &a.profile,
                RoomCmd::Invite(a) => &a.profile,
                RoomCmd::Retention(a) => &a.profile,
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
            // nothing. `vox room send` handles its own stop, because it withdraws its offer first.
            let handles_its_own_stop = matches!(sub, RoomCmd::Send(_));
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
                            )
                            .await
                        }
                        RoomCmd::Tail(a) => {
                            crate::room_cli::tail(&paths, &a.room, a.since.as_deref(), a.json).await
                        }
                        RoomCmd::Roster(a) => crate::room_cli::roster(&paths, &a.room).await,
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
                        RoomCmd::Send(a) => {
                            crate::room_cli::send_file(&paths, &a.room, &a.path).await
                        }
                        RoomCmd::Join(a) => {
                            crate::room_cli::join(
                                &paths,
                                &a.link,
                                &a.name,
                                a.passphrase_file.as_deref(),
                            )
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
                        RoomCmd::Invite(a) => crate::room_cli::invite(&paths, &a.room).await,
                        RoomCmd::Leave(a) => crate::room_cli::leave(&paths, &a.room).await,
                        RoomCmd::End(a) => crate::room_cli::end(&paths, &a.room).await,
                        RoomCmd::Admin(a) => {
                            crate::room_cli::admin(&paths, &a.action, &a.room, a.member.as_deref())
                                .await
                        }
                        RoomCmd::Retention(a) => {
                            let identity = crate::tunnel_cli::identity_passphrase_for(
                                &paths,
                                a.identity_passphrase.clone(),
                                a.identity_passphrase_file.clone(),
                            )?;
                            crate::room_cli::retention(&paths, &a.room, &a.duration, &identity)
                                .await
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
                if handles_its_own_stop {
                    work.await
                } else {
                    let stop = crate::app::stop_requested("vox room");
                    tokio::select! {
                        done = work => done,
                        signal = stop => Err(crate::app::AppError::stopped_by(signal)),
                    }
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
        Cmd::Share(args) => {
            let paths = match args.profile.paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
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
            run_attached(async move {
                crate::share_cli::share(&paths, &args.room, &args.path, args.count, for_).await
            })
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
            let hook = format!("vox agent hook --node {node}");
            match args.harness.to_ascii_lowercase().as_str() {
                "opencode" => {
                    print!(
                        "{}",
                        crate::agent_hook::OPENCODE_PLUGIN.replace(
                            "agent hook --format",
                            &format!("agent hook --node {node} --format")
                        )
                    );
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
                    print!(
                        "{}",
                        crate::agent_hook::CLAUDE_HOOKS
                            .replace("\"vox agent hook\"", &format!("\"{hook}\""))
                    );
                    eprintln!(
                        "vox: merge that into ~/.claude/settings.json (user scope, so a session \
                     opened in any repository hears its rooms), and install the skill beside \
                     it: {}\n     The hook drains every room the node holds.",
                        skill_install("claude", skill_dir("claude").unwrap_or_default())
                    );
                    ExitCode::SUCCESS
                }
                // The entry is a matcher group holding `hooks`, as Claude Code's is: Codex 0.160
                // lists a bare `{ "command": … }` entry as no hook at all, so the room never
                // drained (V210-169).
                "codex" => {
                    println!(
                        "{{\n  \"hooks\": {{\n    \"UserPromptSubmit\": [\n      {{\n        \
                     \"hooks\": [\n          {{ \"type\": \"command\", \"command\": \
                     \"{hook}\", \"async\": false }}\n        ]\n      }}\n    ]\n  \
                     }}\n}}"
                    );
                    eprintln!(
                    "vox: merge that into Codex's hooks.json, then run `vox agent trust codex` \
                     — Codex runs a hook only once it is trusted.\n     `async` MUST be false: \
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
                    ServiceCmd::List(r) => crate::room_cli::service_list(&paths, &r.room).await,
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
            let paths = match args.profile.paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let waiting = crate::tunnel_cli::Waiting::server();
            let steps = std::sync::Arc::clone(&waiting);
            run_session(waiting, async move {
                if args.passphrase.is_some() {
                    return Err(AppError::Usage(format!(
                        "--passphrase is refused: a command line is readable by every process on \
                         this machine. {}",
                        crate::tunnel_cli::GIVE_ROOM_PASSPHRASE
                    )));
                }
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
                    args.bind,
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
            let waiting = crate::tunnel_cli::Waiting::server();
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
        Cmd::Lan(LanCmd::Helper(a)) => match crate::lan_cli::run_helper(&a.socket) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("vox lan helper: {e}");
                ExitCode::FAILURE
            }
        },
        Cmd::Lan(LanCmd::Up(a)) => {
            // Asked before the node is touched: without a helper nothing here can work, and a
            // refusal should leave nothing behind.
            if !crate::lan_cli::helper_reachable(&a.helper_socket) {
                eprintln!("vox: {}", crate::lan_cli::no_helper(&a.helper_socket));
                return ExitCode::FAILURE;
            }
            let paths = match a.room.profile.paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let waiting = crate::tunnel_cli::Waiting::server();
            let steps = std::sync::Arc::clone(&waiting);
            run_session(waiting, async move {
                crate::lan_cli::up_held(&paths, &a, &steps).await
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
