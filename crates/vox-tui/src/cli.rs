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
use vox_core::node::link::{merge_anchor_spec, merge_anchors_file};
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
        // The profile's anchors file first, then `--anchor` on top (ADR-017 decision 7,
        // M17.4). Both merge into one set rather than one replacing the other: an anchor
        // is additive — more introducers is strictly better reachability — and a person
        // who adds one on the command line almost never means "and forget the one I
        // configured". `vox node` writes its own spec into that file, so a client on the
        // same machine as its anchor needs no flag at all, which was the whole point.
        merge_anchors_file(&mut set, &self.paths()?.anchors_file())?;
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
            eprintln!("vox: {e}");
            return ExitCode::FAILURE;
        }
    };
    // **Not `passphrase_or_prompt`.** Removing clap's `env` from the flag — so a flag
    // could be refused while the variable still worked — left this caller reading the
    // flag only, and the flag is now always `None`. So `VOX_IDENTITY_PASSPHRASE` stopped
    // working for every tunnel verb (`service`, `forward`, `up`) and they
    // answered `Failed(WrongPassphrase)`, which sends a person to check a passphrase that
    // was never read. One helper reads the flag, the file, the variable and the prompt,
    // in that order; every caller uses it.
    let identity = match crate::tunnel_cli::identity_passphrase_for(
        &paths,
        room.identity_passphrase.clone(),
        room.identity_passphrase_file.clone(),
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
    identity_passphrase_file: Option<std::path::PathBuf>,
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
            eprintln!("vox: {e}");
            return ExitCode::FAILURE;
        }
    };
    let identity = match crate::tunnel_cli::identity_passphrase_for(
        &paths,
        identity_passphrase,
        identity_passphrase_file,
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

/// Whether a node is already serving this profile.
fn node_answers(profile: &ProfileArgs) -> bool {
    let Ok(paths) = profile.paths() else {
        return false;
    };
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };
    rt.block_on(crate::room_cli::node_is_running(&paths))
}

/// The service label a person's spec names: `53/udp` is `udp/53` (ADR-022 decision 6), and
/// anything that is not a port spec is used as the tag it already is.
fn label_of(spec: &str) -> String {
    vox_core::tunnel::udp::service_label(spec).unwrap_or_else(|| spec.to_owned())
}

/// Whether a node is already serving this profile, so a trust verb should ask it.
fn trust_over_socket(sub: &TrustCmd) -> bool {
    let profile = match sub {
        TrustCmd::List(a) => &a.profile,
        TrustCmd::Add(a) => &a.profile,
        TrustCmd::Remove(a) => &a.profile,
    };
    let Ok(paths) = profile.paths() else {
        return false;
    };
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };
    rt.block_on(crate::room_cli::node_is_running(&paths))
}

/// Run a trust verb against the node that is already holding this profile.
fn run_trust_over_socket(sub: TrustCmd) -> ExitCode {
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
    };
    let paths = match profile.paths() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("vox: {e}");
            return ExitCode::FAILURE;
        }
    };
    let identity = match crate::tunnel_cli::identity_passphrase_for(&paths, pass, pass_file) {
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
            TrustCmd::List(_) => crate::room_cli::trust_list(&paths, &identity).await,
            TrustCmd::Add(a) => {
                let target = crate::tunnel_cli::parse_fingerprint(&a.fingerprint)?;
                crate::room_cli::trust_add(&paths, target, &a.name, &identity).await
            }
            TrustCmd::Remove(a) => {
                let target = crate::tunnel_cli::parse_fingerprint(&a.fingerprint)?;
                crate::room_cli::trust_remove(&paths, target, &identity).await
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
    List(RoomArgs),
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
    /// Print new messages as they arrive, until interrupted.
    Tail(RoomRefArgs),
    /// Print the fingerprints of the room's members.
    Roster(RoomRefArgs),
    /// List the rooms this node holds.
    List(ProfileArgs),
    /// Take a unit of work, so no other agent starts it (ADR-020 §5).
    ///
    /// A claim is a **message, not a lock**: nothing is reserved in the node.
    /// Ownership is whatever the room's log resolves to, so every member computes
    /// the same answer with nobody coordinating. `--ttl` is what makes an agent
    /// that dies holding work release it without anyone noticing it died.
    Claim(ClaimArgs),
    /// Give a unit of work up. Only the current owner's release counts.
    Release(ResourceArgs),
    /// Pass a unit of work to another agent by petname.
    Handoff(HandoffArgs),
    /// Show what is taken, by whom, and until when.
    Board(RoomRefArgs),
    /// Offer a file to the room and announce it (ADR-020 §11).
    ///
    /// The bytes never enter the log: they ride a room-bound service, and what
    /// goes on the log is a signed announcement carrying the name, the size and
    /// the **SHA-256**. Runs until interrupted, because the bytes are served
    /// live — the announcement outlives the offer, so an agent that wakes late
    /// sees what was sent and is told plainly if it can no longer be collected.
    ///
    /// Nobody is granted anything: whoever can read the announcement can reach
    /// the bytes, because both are gated on this node's trust keyring.
    Send(SendFileArgs),
    /// Join a room from a `vox://` address, over a running node (ADR-020 §12).
    ///
    /// The passphrase is read from **stdin**, never argv, which anything that can
    /// run `ps` would see:
    ///
    /// ```text
    /// echo 'the room passphrase' | vox room join vox://… --name mission
    /// ```
    ///
    /// This is what makes agent comms usable on a host with no terminal: `vox
    /// daemon` lets a node hold rooms unattended, and this is how a room gets
    /// onto it. Joining grants nothing — whether anyone can read you is their
    /// decision, made with `vox trust`.
    Join(JoinRoomArgs),
    /// Create a room on a running node. Passphrase on stdin.
    Create(CreateRoomArgs),
    /// Print a room's address, for someone else to `vox room join` with.
    ///
    /// The address is rendezvous information, not a credential — no passphrase,
    /// and joining with it grants nothing. Goes to stdout so it pipes; the
    /// warnings go to stderr so they do not.
    Invite(RoomRefArgs),
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
    pub profile: ProfileArgs,
    /// The `vox://` address you were given.
    pub link: String,
    /// A local name for the room. Never leaves this device.
    #[arg(long, default_value = "room")]
    pub name: String,
}

/// `vox room create`
#[derive(Args, Debug, Clone)]
pub struct CreateRoomArgs {
    #[command(flatten)]
    pub profile: ProfileArgs,
    /// A local name for the room. Never leaves this device.
    #[arg(long, default_value = "room")]
    pub name: String,
}

/// `vox room send`
#[derive(Args, Debug, Clone)]
pub struct SendFileArgs {
    #[command(flatten)]
    pub profile: ProfileArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// The file to offer.
    pub path: PathBuf,
}

/// `vox room get`
#[derive(Args, Debug, Clone)]
pub struct GetFileArgs {
    #[command(flatten)]
    pub profile: ProfileArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// The file's name, or a prefix of its SHA-256, or its service tag.
    pub file: String,
    /// Where to write it. Defaults to the announced name in the current directory.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

/// `vox daemon`
#[derive(Args, Debug, Clone)]
pub struct DaemonArgs {
    #[command(flatten)]
    pub profile: ProfileArgs,
    /// Read the passphrase from this file instead of stdin, for a service manager
    /// that prefers one. The file should contain the passphrase and nothing else.
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
}

/// `vox room claim`
#[derive(Args, Debug, Clone)]
pub struct ClaimArgs {
    #[command(flatten)]
    pub profile: ProfileArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// What is being claimed — a file, a milestone, a crate, whatever the room
    /// has agreed to name.
    pub resource: String,
    /// Seconds after which the claim lapses on its own.
    #[arg(long)]
    pub ttl: Option<u64>,
}

/// `vox room release`
#[derive(Args, Debug, Clone)]
pub struct ResourceArgs {
    #[command(flatten)]
    pub profile: ProfileArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// What is being released.
    pub resource: String,
}

/// `vox room handoff`
#[derive(Args, Debug, Clone)]
pub struct HandoffArgs {
    #[command(flatten)]
    pub profile: ProfileArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// What is being handed off.
    pub resource: String,
    /// The recipient's petname, as you know them.
    #[arg(long)]
    pub to: String,
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
    /// observed and discarded.
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
    /// Print the agent-facing skill: the conventions, vocabulary and manners of a
    /// shared room (ADR-020 §8).
    ///
    /// A skill is on-demand only, so it cannot be what guarantees an agent reads
    /// its room — that is `vox agent hook`'s job. This carries what a hook cannot.
    ///
    /// ```text
    /// vox agent skill > .claude/skills/vox-agent-comms/SKILL.md
    /// ```
    Skill,
}

/// `vox agent plugin`
#[derive(Args, Debug, Clone)]
pub struct AgentPluginArgs {
    /// The harness to print an integration for. Only `opencode` needs one today;
    /// Claude Code and Codex are configured with a hook command instead.
    pub harness: String,
}

/// `vox agent hook`
#[derive(Args, Debug, Clone)]
pub struct AgentHookArgs {
    #[command(flatten)]
    pub profile: ProfileArgs,
    /// The room to drain, or a unique prefix. Falls back to `VOX_ROOM`, which is
    /// usually the easier place to put it since a hook's arguments are fixed at
    /// install time while its environment is not.
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
    pub profile: ProfileArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
}

/// `vox room post`
#[derive(Args, Debug, Clone)]
pub struct RoomPostArgs {
    #[command(flatten)]
    pub profile: ProfileArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// The message. Omit it, or pass `-`, to read from stdin.
    pub text: Option<String>,
}

/// `vox room read`
#[derive(Args, Debug, Clone)]
pub struct RoomReadArgs {
    #[command(flatten)]
    pub profile: ProfileArgs,
    /// The room's id, or a unique prefix of it.
    pub room: String,
    /// Return only what follows this entry hash — the full 64 characters, as the
    /// first column prints it. Not prefix-matched: a cursor comes from previous
    /// output, and a prefix that matched the wrong entry would silently skip or
    /// repeat messages.
    #[arg(long)]
    pub since: Option<String>,
    /// At most this many messages. 0 means no limit.
    #[arg(long, default_value_t = 0)]
    pub limit: u64,
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
    pub profile: ProfileArgs,
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
}

/// `vox trust add`
#[derive(Args, Debug, Clone)]
pub struct TrustAddArgs {
    #[command(flatten)]
    pub profile: ProfileArgs,
    /// The identity to trust, as `vox id` prints it (base32, or a unique prefix of one
    /// this node already knows).
    pub fingerprint: String,
    /// What this node will call it. Local to this machine; nothing is registered and no
    /// other node ever sees it.
    #[arg(long, default_value = "peer")]
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

/// `vox trust remove`
#[derive(Args, Debug, Clone)]
pub struct TrustRemoveArgs {
    #[command(flatten)]
    pub profile: ProfileArgs,
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
    pub room: RoomArgs,
    /// The member hosting the service (its fingerprint, or a unique prefix). When the room
    /// is given as `<name>.vox` the host is the name's, and this is the service instead.
    pub host: String,
    /// The service to reach: `<port>`, `<port>/udp`, or any tag the host serves. With a
    /// `<name>.vox` room, the local port to listen on.
    pub tag: String,
    /// Where to listen locally; port 0 picks one.
    #[arg(default_value = "127.0.0.1:0")]
    pub local: SocketAddr,
}

/// `vox serve`
#[derive(Args, Debug, Clone)]
pub struct ServeArgs {
    #[command(flatten)]
    pub profile: ProfileArgs,
    /// The ports to offer: `<port>` (TCP), `<port>/tcp` or `<port>/udp`. The port is also
    /// the service's name: guests reach it at this port of the room's `.vox` hostname.
    /// The first creates the room; `vox serve 53 53/udp` serves both.
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
    /// Run this profile's node without a terminal, so agent sessions can attach
    /// (ADR-020 §12).
    ///
    /// The TUI is the only other thing that serves the agent-comms control socket,
    /// and it needs a terminal and locks the node when that terminal goes away. A
    /// `vox node` is an anchor: it holds no room and can read nothing. This is the
    /// third shape — an unlocked node holding this profile's rooms, serving the
    /// socket, with nothing attached to a tty.
    ///
    /// The passphrase is read from **stdin**, deliberately not from the
    /// environment, which is readable by anything running as the same user:
    ///
    /// ```text
    /// echo 'my passphrase' | vox daemon
    /// ```
    ///
    /// Unlike the TUI it does not lock on SIGHUP, which is the point. SIGINT and
    /// SIGTERM stop it.
    Daemon(DaemonArgs),
    /// Offer a local TCP port as a room-bound service, in one command (ADR-017).
    ///
    /// Creates a room, offers the port in it, and prints the address, the
    /// machine-generated passphrase and the `.vox` hostname it answers on. Runs until
    /// interrupted, reporting who reaches the service (the service itself cannot tell
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
    /// Speak in a room over a **running** node (ADR-020) — the agent-comms verbs.
    ///
    /// Unlike every other verb, these do not start a node: they attach to the
    /// control socket of one that is already running and already unlocked, which
    /// is how several agent sessions share one identity per machine. Nothing here
    /// takes a passphrase, and nothing here creates, joins or leaves a room.
    #[command(subcommand)]
    Room(RoomCmd),
    /// Wire an agent session into a room (ADR-020) — harness-agnostic.
    #[command(subcommand)]
    Agent(AgentCmd),
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
                    eprintln!("vox: {e}");
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
                args.identity_passphrase_file.clone(),
                move |node, anchors| async move {
                    crate::tunnel_cli::serve(&node, &anchors, &a.name, &a.ports, a.at).await
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
                args.identity_passphrase_file.clone(),
                move |node, _anchors| async move {
                    crate::tunnel_cli::connect(&node, &a.address, &a.name, &room_pp).await
                },
            )
        }
        Cmd::Room(sub) => {
            // These attach to a running node rather than starting one, so they need
            // only a tokio runtime and the profile's paths — no identity unlock and
            // no network of their own.
            let profile = match &sub {
                RoomCmd::Post(a) => &a.profile,
                RoomCmd::Read(a) => &a.profile,
                RoomCmd::Tail(a) | RoomCmd::Roster(a) | RoomCmd::Board(a) => &a.profile,
                RoomCmd::List(p) => p,
                RoomCmd::Claim(a) => &a.profile,
                RoomCmd::Release(a) => &a.profile,
                RoomCmd::Handoff(a) => &a.profile,
                RoomCmd::Send(a) => &a.profile,
                RoomCmd::Get(a) => &a.profile,
                RoomCmd::Join(a) => &a.profile,
                RoomCmd::Create(a) => &a.profile,
                RoomCmd::Invite(a) => &a.profile,
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
            let outcome = rt.block_on(async {
                match &sub {
                    RoomCmd::Post(a) => {
                        crate::room_cli::post(&paths, &a.room, a.text.as_deref()).await
                    }
                    RoomCmd::Read(a) => {
                        crate::room_cli::read(&paths, &a.room, a.since.as_deref(), a.limit).await
                    }
                    RoomCmd::Tail(a) => crate::room_cli::tail(&paths, &a.room).await,
                    RoomCmd::Roster(a) => crate::room_cli::roster(&paths, &a.room).await,
                    RoomCmd::List(_) => crate::room_cli::list(&paths).await,
                    RoomCmd::Claim(a) => {
                        crate::room_cli::claim_resource(&paths, &a.room, &a.resource, a.ttl).await
                    }
                    RoomCmd::Release(a) => {
                        crate::room_cli::release_resource(&paths, &a.room, &a.resource).await
                    }
                    RoomCmd::Handoff(a) => {
                        crate::room_cli::handoff_resource(&paths, &a.room, &a.resource, &a.to).await
                    }
                    RoomCmd::Board(a) => crate::room_cli::board(&paths, &a.room).await,
                    RoomCmd::Send(a) => crate::room_cli::send_file(&paths, &a.room, &a.path).await,
                    RoomCmd::Join(a) => crate::room_cli::join(&paths, &a.link, &a.name).await,
                    RoomCmd::Create(a) => crate::room_cli::create(&paths, &a.name).await,
                    RoomCmd::Invite(a) => crate::room_cli::invite(&paths, &a.room).await,
                    RoomCmd::Get(a) => {
                        crate::room_cli::get_file(&paths, &a.room, &a.file, a.out.as_deref()).await
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
        Cmd::Agent(AgentCmd::Hook(args)) => {
            let paths = match args.profile.paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
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
                args.room.as_deref(),
                format,
                args.session.as_deref(),
            ));
            // Always success: a hook that fails must not break the turn.
            ExitCode::SUCCESS
        }
        Cmd::Daemon(args) => {
            let paths = match args.profile.paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let anchors = match args.profile.anchor_set() {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match crate::app::run_daemon(
                paths,
                args.profile.listen,
                anchors,
                args.profile.anchors.clone(),
                args.passphrase_file.clone(),
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("vox: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Agent(AgentCmd::Skill) => {
            print!("{}", crate::agent_hook::AGENT_SKILL);
            ExitCode::SUCCESS
        }
        Cmd::Agent(AgentCmd::Plugin(args)) => match args.harness.to_ascii_lowercase().as_str() {
            "opencode" => {
                print!("{}", crate::agent_hook::OPENCODE_PLUGIN);
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
                println!(
                    "{{\n  \"hooks\": {{\n    \"UserPromptSubmit\": [\n      {{\n        \
                     \"hooks\": [\n          {{ \"type\": \"command\", \"command\": \
                     \"vox agent hook\" }}\n        ]\n      }}\n    ]\n  }}\n}}"
                );
                eprintln!(
                    "vox: merge that into ~/.claude/settings.json, or .claude/settings.json \
                     in a project.\n     Set VOX_ROOM in the session's environment, or pass \
                     --room to the hook, so it knows which room to drain."
                );
                ExitCode::SUCCESS
            }
            "codex" => {
                println!(
                    "{{\n  \"hooks\": {{\n    \"UserPromptSubmit\": [\n      {{ \
                     \"command\": \"vox agent hook\", \"async\": false }}\n    ]\n  \
                     }}\n}}"
                );
                eprintln!(
                    "vox: merge that into Codex's hooks.json.\n     `async` MUST be false: an \
                     async hook's output is observed and discarded, so the room would drain \
                     into nothing.\n     Set VOX_ROOM in the session's environment, or pass \
                     --room to the hook."
                );
                ExitCode::SUCCESS
            }
            other => {
                eprintln!("vox: no integration for {other:?}. Known: claude, codex, opencode.");
                ExitCode::FAILURE
            }
        },
        // Ask the running node when there is one, like `vox trust`: the profile is not ours to
        // open while it runs, and a running host is the case R22 is about.
        Cmd::Service(ServiceCmd::Remove(r)) if node_answers(&r.room.profile) => {
            let paths = match r.room.profile.paths() {
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
            match rt.block_on(crate::room_cli::service_remove(
                &paths,
                &r.room.room,
                &label_of(&r.tag),
            )) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("vox: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Service(sub) => run_tunnel_verb(sub_room(&sub).clone(), move |node, cid| {
            let sub = sub.clone();
            async move {
                match &sub {
                    ServiceCmd::Add(a) => {
                        crate::tunnel_cli::service_add(&node, cid, &label_of(&a.tag), a.local).await
                    }
                    ServiceCmd::Remove(r) => {
                        crate::tunnel_cli::service_remove(&node, cid, &label_of(&r.tag)).await
                    }
                    ServiceCmd::List(_) => {
                        crate::tunnel_cli::service_list(&node, cid);
                        Ok(())
                    }
                }
            }
        }),
        // Ask the running node when there is one: a fingerprint is public, the hello
        // already carries it, and needing the profile to yourself to read your own name
        // was the most gratuitous case of the busy-profile problem.
        Cmd::Id(args) if node_answers(&args.profile) => {
            let paths = match args.profile.paths() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("vox: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            else {
                eprintln!("vox: could not start a runtime");
                return ExitCode::FAILURE;
            };
            match rt.block_on(crate::room_cli::print_identity(&paths)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("vox: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Id(args) => run_new_room_verb(
            args.profile.clone(),
            args.identity_passphrase.clone(),
            args.identity_passphrase_file.clone(),
            move |node, _anchors| async move {
                let Some(id) = node.view().identity else {
                    return Err(crate::app::AppError::Usage(
                        "this profile has no identity yet".into(),
                    ));
                };
                // The whole fingerprint, alone on the line, so it pipes and pastes without
                // editing. A person is about to send this to someone who will type it into
                // `vox trust add`.
                println!("{}", vox_core::node::link::b32_encode(&id.fingerprint));
                Ok(())
            },
        ),
        // **Ask the running node when there is one.** These three used to spawn a node of
        // their own, which redb refuses while a `vox daemon` holds the profile — so the
        // one command a person cannot skip, deciding who may read them, was unavailable
        // exactly when they were setting up agent comms. Over the socket the request
        // carries the identity passphrase and the node checks it, so an agent session
        // that can reach the socket still cannot edit the keyring (ADR-020 §7).
        Cmd::Trust(sub) if trust_over_socket(&sub) => run_trust_over_socket(sub),
        Cmd::Trust(TrustCmd::List(args)) => run_new_room_verb(
            args.profile.clone(),
            args.identity_passphrase.clone(),
            args.identity_passphrase_file.clone(),
            move |node, _anchors| async move {
                let trusted = node.view().trusted;
                if trusted.is_empty() {
                    println!("vox: this node trusts nobody yet.");
                    println!("     ask them for `vox id` and run `vox trust add <fingerprint>`");
                    return Ok(());
                }
                for (fp, petname) in trusted {
                    println!("{}  {petname}", vox_core::node::link::b32_encode(&fp));
                }
                Ok(())
            },
        ),
        Cmd::Trust(TrustCmd::Add(args)) => {
            let a = args.clone();
            run_new_room_verb(
                args.profile.clone(),
                args.identity_passphrase.clone(),
                args.identity_passphrase_file.clone(),
                move |node, _anchors| async move {
                    crate::tunnel_cli::trust_add(&node, &a.fingerprint, &a.name).await
                },
            )
        }
        Cmd::Trust(TrustCmd::Remove(args)) => {
            let a = args.clone();
            run_new_room_verb(
                args.profile.clone(),
                args.identity_passphrase.clone(),
                args.identity_passphrase_file.clone(),
                move |node, _anchors| async move {
                    crate::tunnel_cli::trust_remove(&node, &a.fingerprint).await
                },
            )
        }
        Cmd::Up(args) => {
            let bind = args.bind;
            run_tunnel_verb(args.room.clone(), move |node, cid| async move {
                crate::tunnel_cli::up(&node, cid, bind).await
            })
        }
        Cmd::Forward(args) => {
            // Two shapes. `vox forward <room> <host> <service> [local]`, and the `.vox` one
            // ADR-022 names: `vox forward <name>.vox <service> [<local-port>]`, where the
            // name gives both the room and its host (the genesis creator, ADR-017), so the
            // positionals shift left by one.
            let mut room = args.room.clone();
            let (host, tag, local) = if room.room.trim().ends_with(".vox") {
                let cid = match vox_core::node::link::channel_of_hostname(&room.room) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("vox: {}: {e}", room.room);
                        return ExitCode::FAILURE;
                    }
                };
                room.room = vox_core::node::link::b32_encode(&cid);
                let local = match args.tag.parse::<u16>() {
                    Ok(port) => SocketAddr::from(([127, 0, 0, 1], port)),
                    Err(_) => match args.tag.parse::<SocketAddr>() {
                        Ok(a) => a,
                        Err(_) => {
                            eprintln!(
                                "vox: {:?} is not a local port or address to listen on",
                                args.tag
                            );
                            return ExitCode::FAILURE;
                        }
                    },
                };
                (None, args.host.clone(), local)
            } else {
                (Some(args.host.clone()), args.tag.clone(), args.local)
            };
            run_tunnel_verb(room, move |node, cid| async move {
                crate::tunnel_cli::forward(&node, cid, host.as_deref(), &tag, local).await
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
