//! The verbs that hold a session (ADR-013, ADR-017, ADR-026 L-7): `vox serve`, `vox connect`,
//! `vox up` and `vox forward`, and the passphrase and advice helpers every verb shares.
//!
//! None of them hosts a node (ADR-026 S-3): each holds its node on the daemon over one connection
//! (`crate::client::hold`), asks the daemon to do the work, prints what the node says, and ends
//! when it is stopped, or non-zero when the daemon or the node goes from under it.

use std::net::SocketAddr;
use std::time::Instant;

use vox_core::hash::Digest32;
use vox_core::node::actor::NodeHandle;
use vox_core::node::api::{Fault, NodeCommand, NodeEvent, Outcome};
use vox_core::node::ipc::{Frame, IpcClient, Request};
use vox_core::node::link::{b32_decode, b32_encode};
use vox_core::node::paths::Paths;

use crate::app::AppError;

/// Groups in a generated room passphrase — 100 bits (ADR-017 decision 4).
const PASSPHRASE_GROUPS: usize = vox_core::node::passphrase::DEFAULT_GROUPS;

/// How the verbs identify a room or a member: the full base32 rendering, or any
/// unique prefix of it (what a person can reasonably retype from a screen).
pub fn resolve_prefix(prefix: &str, among: &[Digest32]) -> Result<Digest32, AppError> {
    let needle = prefix.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return Err(AppError::Usage("an empty id matches nothing".into()));
    }
    let matches: Vec<Digest32> = among
        .iter()
        .copied()
        .filter(|d| b32_encode(d).starts_with(&needle))
        .collect();
    match matches.as_slice() {
        [one] => Ok(*one),
        [] => Err(AppError::Usage(format!("nothing here matches {needle:?}"))),
        many => Err(AppError::Usage(format!(
            "{needle:?} matches {} things; use more characters",
            many.len()
        ))),
    }
}

/// The text of a passphrase file, or of stdin when the path is `-`: the explicit way to pipe a
/// passphrase in. Wiped on drop, so only the copy a caller takes outlives the read.
pub fn passphrase_file_text(
    path: &std::path::Path,
) -> Result<zeroize::Zeroizing<String>, AppError> {
    use std::io::Read as _;
    let mut text = zeroize::Zeroizing::new(String::new());
    if path == std::path::Path::new("-") {
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|e| AppError::Usage(format!("reading stdin: {e}")))?;
    } else {
        std::fs::File::open(path)
            .and_then(|mut f| f.read_to_string(&mut text))
            .map_err(|e| AppError::Usage(format!("reading {}: {e}", path.display())))?;
    }
    Ok(text)
}

/// How to give the identity passphrase without a terminal, for every message that needs one.
pub const GIVE_IDENTITY_PASSPHRASE: &str =
    "Use --identity-passphrase-file <path> (`-` reads stdin), or VOX_IDENTITY_PASSPHRASE.";

/// The identity passphrase the command line gave, without asking anyone: `--identity-passphrase-
/// file`, else `VOX_IDENTITY_PASSPHRASE`. `None` when neither did.
pub fn identity_passphrase_given(
    given: Option<String>,
    file: Option<std::path::PathBuf>,
) -> Result<Option<String>, AppError> {
    // **A passphrase on a command line is disclosed to the whole machine.** `ps` and
    // `/proc/<pid>/cmdline` are world-readable while a process runs, so `--identity-
    // passphrase secret` hands the identity to every other process on the box, including
    // ones running as other users on a default configuration. It is refused rather than
    // removed so that anything scripted against it says what to do instead of failing to
    // parse, which is the failure nobody can diagnose.
    if given.is_some() {
        return Err(AppError::Usage(
            "--identity-passphrase is refused: a command line is world-readable while the \
             process runs (`ps`, /proc/<pid>/cmdline), so the passphrase would be \
             disclosed to every process on this machine, and kept in the shell's history.\n\
             \x20      Use --identity-passphrase-file <path>, or VOX_IDENTITY_PASSPHRASE, \
             or omit it and be prompted."
                .into(),
        ));
    }
    // **An empty passphrase is a passphrase** (V030-36, decider 2026-10-02: "technically
    // optional"). An empty file, or the variable set to nothing, gives none on purpose, which is
    // not the same as giving no source at all: that still asks, or fails without a terminal.
    if let Some(path) = file {
        let text = passphrase_file_text(&path)?;
        let first = text.lines().next().unwrap_or_default();
        return Ok(Some(encouraged(first.to_owned(), "identity")));
    }
    // Read the variable here rather than through clap's `env`, because clap merges a flag
    // and its variable into one value and the whole point is to tell them apart.
    if let Ok(p) = std::env::var("VOX_IDENTITY_PASSPHRASE") {
        return Ok(Some(encouraged(p, "identity")));
    }
    Ok(None)
}

/// Ask at the terminal for the identity passphrase of a profile that has one, or, with no
/// terminal, fail at once saying how to give it (V210-165). Stdin that is not a terminal is never
/// read for it unasked: an agent's harness leaves stdin open and writes nothing, and a read there
/// waited for ever, saying nothing.
pub fn ask_identity_passphrase() -> Result<String, AppError> {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(AppError::Usage(format!(
            "this needs the identity passphrase, and there is no terminal to ask at.\n\
             \x20      {GIVE_IDENTITY_PASSPHRASE}"
        )));
    }
    Ok(encouraged(
        prompt_passphrase("identity passphrase")?,
        "identity",
    ))
}

/// Collect the identity passphrase, asking for confirmation when the profile has no
/// identity yet and this will therefore *create* one.
///
/// The confirmation is not politeness. A profile's identity is unlocked by this
/// passphrase and by nothing else (ADR-010's double lock), so a typo on first use does
/// not produce a warning later — it produces an identity nobody can ever open.
pub fn identity_passphrase_for(
    paths: &Paths,
    given: Option<String>,
    file: Option<std::path::PathBuf>,
) -> Result<String, AppError> {
    if let Some(p) = identity_passphrase_given(given, file)? {
        return Ok(p);
    }
    if vox_core::node::profile::Profile::exists(paths) {
        return ask_identity_passphrase();
    }
    // **Without a terminal there is nobody to ask twice.**
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(AppError::Usage(
            "this profile has no identity yet, and there is no terminal to ask at.\n\
             \x20      Make one at a terminal with `vox id`, or give its new passphrase with \
             --identity-passphrase-file <path> (`-` reads stdin) or VOX_IDENTITY_PASSPHRASE."
                .into(),
        ));
    }
    println!("vox: this profile has no identity yet; creating one.");
    let first = prompt_passphrase("new identity passphrase")?;
    let again = prompt_passphrase("again")?;
    if first != again {
        return Err(AppError::Usage(
            "the two passphrases differ; nothing was created".into(),
        ));
    }
    Ok(encouraged(first, "identity"))
}

/// What a CLI verb says on stderr when creating or unlocking the identity waits for another vox
/// holding the profile (V210-100). It names no particular remedy beyond the one that is true
/// wherever that vox runs: under a shell's job control `fg` resumes a stopped one, but a daemon
/// under tmux or a service manager is resumed its own way.
/// It names the cause in the words a refusal uses (`Fault::ProfileBusy`, V210-114), so a person
/// sees one phrase for one cause.
pub const WAITING_FOR_PROFILE: &str =
    "vox: waiting: another vox holds this profile open, and only \
     one at a time may write it\n       this goes on as soon as that one is done; if that vox is \
     stopped (e.g. with Ctrl-Z), resume it";

/// Say [`WAITING_FOR_PROFILE`] on stderr: what a verb's node calls if opening the profile waits
/// for another vox holding it.
pub fn say_waiting() {
    eprintln!("{WAITING_FOR_PROFILE}");
}

/// Apply `cmd` (creating or unlocking the identity), and if the node says it is waiting for
/// another vox holding the profile, say so on stderr — once, while it waits.
/// Which kind of socket a failed bind was for, so it can be asked again (V210-134).
#[derive(Clone, Copy)]
pub(crate) enum Socket {
    /// The node's QUIC port (`--listen`).
    Udp,
    /// A local TCP port: `vox up --bind`, a forward's local port.
    Tcp,
}

/// What the operating system says now when `addr` is bound as `socket`, quoted after a failed
/// bind so the person reads its own words (V210-134): the node's [`Fault`] names the cause
/// but cannot carry the text. `None` if the address binds now (it was freed in between).
pub(crate) fn bind_said(addr: SocketAddr, socket: Socket) -> Option<String> {
    let err = match socket {
        Socket::Udp => std::net::UdpSocket::bind(addr).err(),
        Socket::Tcp => std::net::TcpListener::bind(addr).err(),
    }?;
    Some(err.to_string())
}

/// The message for a failed bind of `addr`: what `fault` names, and the operating system's own
/// words (V210-134). `None` if `fault` is not a failed bind.
pub(crate) fn bind_failure(addr: SocketAddr, socket: Socket, fault: Fault) -> Option<String> {
    if !fault.is_bind() {
        return None;
    }
    let what = match (fault, socket) {
        (Fault::AddressInUse, Socket::Udp) => {
            "something else already holds that UDP port".to_owned()
        }
        (Fault::AddressInUse, Socket::Tcp) => {
            "that port is already in use: another program holds it".to_owned()
        }
        (Fault::AddressNotHere, _) => format!("{} is not an address of this machine", addr.ip()),
        _ => "it could not be listened on".to_owned(),
    };
    let said = bind_said(addr, socket)
        .map(|os| format!(" (the system says: {os})"))
        .unwrap_or_default();
    let remedy = match fault {
        Fault::AddressInUse => format!(
            "\n       Pick another, or stop whatever holds it (`lsof -i :{}` names it).",
            addr.port()
        ),
        Fault::AddressNotHere => "\n       Use an address this machine has (`ifconfig` lists \
                                  them), or 127.0.0.1."
            .to_owned(),
        _ => String::new(),
    };
    Some(format!("{what}{said}{remedy}"))
}

/// The message for a local TCP address the daemon could not bind for this verb (`vox up --bind`,
/// a forward's local port): asked of the operating system here, which shares the daemon's view of
/// this machine's ports, so the person reads why (V210-134). `None` if it binds now.
fn tcp_bind_failure(addr: SocketAddr) -> Option<String> {
    let fault = match std::net::TcpListener::bind(addr).err()?.kind() {
        std::io::ErrorKind::AddrInUse => Fault::AddressInUse,
        std::io::ErrorKind::AddrNotAvailable => Fault::AddressNotHere,
        _ => return None,
    };
    bind_failure(addr, Socket::Tcp, fault)
}

pub async fn apply_saying_waits(node: &NodeHandle, cmd: NodeCommand) -> Outcome {
    let mut events = node.subscribe();
    let apply = node.apply(cmd);
    tokio::pin!(apply);
    let mut said = false;
    loop {
        tokio::select! {
            out = &mut apply => return out,
            ev = events.next(), if !said => match ev {
                Some(vox_core::node::actor::EventStreamItem::Event(NodeEvent::WaitingForProfile)) => {
                    eprintln!("{WAITING_FOR_PROFILE}");
                    said = true;
                }
                // Said while the verb waits: the node picks its port as it unlocks (V210-167).
                Some(vox_core::node::actor::EventStreamItem::Event(NodeEvent::NodeNote { note })) => {
                    eprintln!("vox: {note}");
                }
                Some(_) => {}
                // The actor is gone; the apply answers for itself.
                None => said = true,
            },
        }
    }
}

/// A `vox serve` spec, `<name>=<port>[/tcp|/udp]`: the port, and the service's tag — its name,
/// or `udp/<name>` for a UDP service (ADR-022 decision 6).
///
/// # Errors
/// A bare port, with how to name it (V030-25: "a share must be named"), or a name or port that
/// is not one.
pub fn named_spec(spec: &str) -> Result<(u16, String), AppError> {
    let Some((name, port_spec)) = spec.split_once('=') else {
        return Err(AppError::Usage(format!(
            "{spec:?} has no name: every shared service is named, and reached as \
             <name>.<node>.<room>.vox\n       name it as <name>=<port>, e.g. `vox serve ssh=22`"
        )));
    };
    let label = vox_core::tunnel::udp::service_label(port_spec).ok_or_else(|| {
        AppError::Usage(format!(
            "{port_spec:?} is not a port: use <name>=<port>, <name>=<port>/tcp or <name>=<port>/udp"
        ))
    })?;
    let port = label
        .trim_start_matches("udp/")
        .parse()
        .map_err(|_| AppError::Usage(format!("{port_spec:?} is not a port")))?;
    let name = vox_core::node::resolver::label_of(name);
    if name.is_empty() || name.len() > vox_core::governance::share::MAX_SERVICE_NAME {
        return Err(AppError::Usage(format!(
            "{spec:?}: a service's name is letters, digits and `-`, at most 63 of them"
        )));
    }
    let tag = if vox_core::tunnel::udp::is_udp(&label) {
        format!("udp/{name}")
    } else {
        name
    };
    Ok((port, tag))
}

/// What `vox service list` prints, from a node this verb opened or from the daemon: the services
/// shared in the room by every member, each with its address as this node writes it and who
/// shared it (V030-25), then what this node itself offers there and where.
pub fn print_services(
    room: &str,
    channel_id: &Digest32,
    services: &[(String, String)],
    shared: &[(String, String, bool)],
) {
    if shared.is_empty() {
        println!("vox: nothing is shared in {room} ({})", short(channel_id));
    } else {
        println!("vox: shared in {room} ({})", short(channel_id));
        for (address, who, udp) in shared {
            let udp = if *udp { "  (udp)" } else { "" };
            println!("  {address}  by {who}{udp}");
        }
    }
    if services.is_empty() {
        println!("vox: no services offered in {}", short(channel_id));
        return;
    }
    println!("vox: services offered in {room} ({})", short(channel_id));
    for (tag, addr) in services {
        println!("  {tag}  →  {addr}");
    }
}

/// What a one-shot verb is waiting for, and since when: what it says when it is stopped before it
/// finishes (V210-85).
///
/// A `vox connect` stopped by Ctrl-C, a SIGTERM or a hangup died on the signal's default action and
/// printed nothing, so a person — or a proof reading its stderr — got a non-zero exit with no reason
/// at all, after however long it had been joining. A SIGKILL cannot be answered; these can.
pub struct Waiting {
    started: Instant,
    /// What the verb could not finish without.
    outcome: &'static str,
    now: std::sync::Mutex<(String, Instant)>,
    /// A server's verb (`vox serve`): being stopped is how it ends, so a stop is a clean exit, not
    /// an error (V210-108).
    serves: bool,
}

impl Waiting {
    /// Start the clock. `outcome` is what did not happen if the verb is stopped: `the room was not
    /// joined`.
    #[must_use]
    pub fn new(outcome: &'static str) -> std::sync::Arc<Self> {
        let now = Instant::now();
        std::sync::Arc::new(Self {
            started: now,
            outcome,
            now: std::sync::Mutex::new((String::from("the verb to start"), now)),
            serves: false,
        })
    }

    /// [`Waiting::new`] for a server's verb, which runs until it is stopped: a stop is its normal
    /// end and exits 0, as a service manager expects of a service it stopped (V210-108).
    #[must_use]
    pub fn server() -> std::sync::Arc<Self> {
        let now = Instant::now();
        std::sync::Arc::new(Self {
            started: now,
            outcome: "it was serving",
            now: std::sync::Mutex::new((String::from("the verb to start"), now)),
            serves: true,
        })
    }

    /// Whether a stop is this verb's normal end (see [`Waiting::server`]).
    #[must_use]
    pub fn serves(&self) -> bool {
        self.serves
    }

    /// The verb now waits for `what`.
    pub fn on(&self, what: impl Into<String>) {
        if let Ok(mut now) = self.now.lock() {
            *now = (what.into(), Instant::now());
        }
    }

    /// The error a verb stopped by `signal` ends with: how long it ran, what did not happen, and
    /// what it had been waiting for, for how long. Exits 128 + the signal's number, as a shell
    /// reports a process the signal killed.
    #[must_use]
    pub fn stopped_by(&self, signal: crate::app::StopSignal) -> AppError {
        let (what, since) = self
            .now
            .lock()
            .map(|n| (n.0.clone(), n.1))
            .unwrap_or_else(|_| (String::from("something it cannot name"), self.started));
        AppError::Refused {
            code: signal.exit_code(),
            message: format!(
                "stopped by {} after {:.1}s — {}\n       it had waited {:.1}s for {what}",
                signal.name(),
                self.started.elapsed().as_secs_f64(),
                self.outcome,
                since.elapsed().as_secs_f64(),
            ),
        }
    }
}

/// Print an event that tells the person why something is not working, and say nothing otherwise.
///
/// **Every one-shot verb waits for exactly one event and discarded the rest.** `forward`, `invite`,
/// `connect` and `up` each sat in a `match node.next_event()` with a `Some(ref other) => say_if_it_explains_a_failure(other),` arm, so a node
/// that was reporting precisely what had gone wrong was talking into a loop that threw it away. The
/// verb then failed with a bare `Fault` and the reason — which the node had gone to some trouble to
/// produce — reached nobody. That is the same silent-failure shape as dropping an `Err`, one layer
/// further out, and it is why `vox forward` through an anchor could be driven to failure on demand
/// and still say nothing about which rung refused it.
pub(crate) fn say_if_it_explains_a_failure(ev: &NodeEvent) {
    match ev {
        NodeEvent::PeerUnreachable { peer, why } => {
            eprintln!(
                "vox: could not reach {} — {why}",
                crate::ident::author_id(peer)
            );
        }
        NodeEvent::JoinFailed { reason } => {
            eprintln!("vox: a join did not complete — {reason}");
        }
        NodeEvent::AddressWithheld { reason, .. } => {
            eprintln!("vox: the address was not handed out — {reason}");
        }
        NodeEvent::AddressNote { note, .. } => {
            eprintln!("vox: {note}");
        }
        NodeEvent::RoomNotRemembered { channel_id, why } => {
            eprintln!(
                "vox: room {} is open, but will not reopen by itself after a restart — {why}",
                short(channel_id)
            );
        }
        NodeEvent::JoinSteps { joined, steps } => {
            eprintln!(
                "vox: join {} — {steps}",
                if *joined { "got in" } else { "did not get in" }
            );
        }
        NodeEvent::PublishRefused {
            channel_id,
            what,
            why,
        } => {
            eprintln!(
                "vox: a board would not take {what} for room {} — {why}",
                short(channel_id)
            );
        }
        NodeEvent::KeyNotTaken {
            channel_id,
            peer,
            why,
        } => {
            eprintln!(
                "vox: {} did not take our key for room {} — {why}; it is sent again",
                crate::ident::author_id(peer),
                short(channel_id)
            );
        }
        NodeEvent::StillRelayed { peer, reason } => {
            eprintln!(
                "vox: still relayed to {} — {reason}",
                crate::ident::author_id(peer)
            );
        }
        NodeEvent::ProxyRefused { reason } => {
            eprintln!("vox: tunnel refused or cut — {reason}");
        }
        NodeEvent::TunnelClosed { reason } => {
            eprintln!("vox: tunnel closed — {reason}");
        }
        NodeEvent::SyncFailed {
            channel_id,
            peer,
            reason,
        } => {
            eprintln!(
                "vox: sync of room {} with {} did not complete — {reason}",
                short(channel_id),
                crate::ident::author_id(peer)
            );
        }
        NodeEvent::Stalled { what, millis } => {
            eprintln!("vox: busy {millis}ms — {what} — nobody could be answered");
        }
        NodeEvent::PublishCured { channel_id, what } => {
            eprintln!(
                "vox: {what} for room {} was taken on a republish, after the board refused it as stale",
                short(channel_id)
            );
        }
        NodeEvent::ConnectionNote { peer, note } => {
            eprintln!(
                "vox: connection to {} — {note}",
                crate::ident::author_id(peer)
            );
        }
        NodeEvent::NodeNote { note } => eprintln!("vox: {note}"),
        NodeEvent::RetentionAboveRoom {
            channel_id,
            node,
            room,
        } => {
            eprintln!(
                "vox: warning: this node's retention file asks to keep room {} for {}, longer than \
                 the room keeps it ({}); a member may keep less than the room, never more, so the \
                 room's {} is in force",
                short(channel_id),
                vox_core::node::retention::describe(*node),
                vox_core::node::retention::describe(*room),
                vox_core::node::retention::describe(*room)
            );
        }
        _ => {}
    }
}

/// [`join_advice`], told what the join said about itself: `said` is its reason and its steps.
///
/// **A member reached and then silent is not a member never reached** (V210-85). A join exchange
/// that ran out of time ends as `Unreachable`, the fault of a member nobody could reach, and its
/// advice — "no member it knows could be reached … ask a member to come online" — sent a person to
/// bring online a member that had been online and reached, and then stopped answering. A join that
/// got as far as the exchange says so in its steps (`<member>: exchange …`).
///
/// **A board that failed is named for what it was** (V210-107). `BoardUnreachable`'s one sentence
/// said "the anchor could not be reached" when the board that failed was the room's host, and its
/// replacement named "the room's host nor any anchor" whatever was tried. The node names each board
/// it tried as the room's host or an anchor (`Joiner::boards_tried`), so the advice follows it: a
/// host that did not answer is the host, an anchor is named only when one was tried, and a board
/// that answered and then closed is not called unreachable.
pub(crate) fn join_advice_after(fault: Option<Fault>, said: &str) -> &'static str {
    let reached = said.contains(": exchange: ") || said.contains(": exchange (incl. solve) ");
    match fault {
        Some(Fault::Unreachable) if reached => {
            "a member was reached, but did not answer the join exchange in time\n       your passphrase was never checked — this is not a verdict on it\n       the member may have gone offline part-way, or be too busy to answer; try again while it is online"
        }
        Some(Fault::BoardUnreachable) => board_unreachable_advice(said),
        other => join_advice(other),
    }
}

/// `BoardUnreachable`'s advice, naming the board that failed from what the node said about it.
/// With nothing said (the reason was lost), [`join_advice`]'s, which names neither.
fn board_unreachable_advice(said: &str) -> &'static str {
    let host = said.contains("the room's host ");
    let anchor = said.contains("anchor ");
    if said.contains("then its connection closed before the room was fetched") {
        return if host {
            "the room's host answered, then its connection closed before the room was read, so no member was asked\n       your passphrase was never checked — this is not a verdict on it\n       run the join again; if it repeats, the host is going offline or losing its connection"
        } else {
            "the anchor answered, then its connection closed before the room was read, so no member was asked\n       your passphrase was never checked — this is not a verdict on it\n       run the join again; if it repeats, the anchor is going offline or losing its connection"
        };
    }
    if said.contains("names only this node") {
        return "the address names only this node itself, so there was no board to ask\n       check it is the address you were sent, not one this node made";
    }
    if !said.contains("no answer from ") {
        return join_advice(Some(Fault::BoardUnreachable));
    }
    match (host, anchor) {
        (true, false) => {
            "the room's host did not answer, so no member was asked\n       your passphrase was never checked — this is not a verdict on it\n       check that the host is running and that this machine can reach its address"
        }
        (false, true) => {
            "no anchor tried for the room answered, and the address does not name the room's host, so no member was asked\n       your passphrase was never checked — this is not a verdict on it\n       check that the anchor is running (`vox node`) and that this machine can reach it, or ask the host for an address that names the host itself"
        }
        _ => {
            "neither the room's host nor any anchor tried for it answered, so no member was asked\n       your passphrase was never checked — this is not a verdict on it\n       check that the host is running and that this machine can reach its address; an anchor matters only when the host cannot be reached directly"
        }
    }
}

/// What to tell a person whose join failed, chosen by the fault the node reported.
///
/// Shared by `vox connect` (which runs its own node) and `vox room join` (which asks a running
/// daemon over its socket). The second printed the bare `Outcome` — `cannot join:
/// Failed(Refused)` — for a wrong passphrase, until the real-binary proof that replaced
/// `node_m14_gate` typed a wrong passphrase and read what came back. One function, so the two
/// verbs cannot drift apart again.
pub(crate) fn join_advice(fault: Option<Fault>) -> &'static str {
    match fault {
        Some(Fault::WrongPassphrase) => {
            "the room passphrase is wrong\n       the address is not in question — this is the passphrase alone"
        }
        Some(Fault::BadLink) => {
            "that address will not parse, or names a room this node cannot use\n       this one IS the address — check you copied all of it"
        }
        // **Do not claim the address is fine here.** A board with nothing for the room cannot tell
        // "its host has not published it yet" from "that room does not exist": an invite link
        // carries no checksum, so a room id with one mistyped character still parses, reaches the
        // board, and finds nothing. The first version of this advice said "the address is fine",
        // the same false confidence `Unreachable` below refuses about the passphrase. Name both
        // causes and what settles each.
        Some(Fault::RoomNotOnBoard) => {
            "either its host has not published the room there yet (the host must be online; then run this again)\n       or the room part of the address is wrong: check it against the address you were sent"
        }
        // **Do not claim the passphrase is fine here.** Nobody answered, so nobody
        // checked it — a wrong passphrase against an offline room reaches exactly this
        // branch. The first version of this fix said "NOT the address or the
        // passphrase", which is the same false confidence as the sentence it replaced,
        // pointed the other way. Say what was and was not established.
        //
        // **And say which side was unreachable (#192).** One sentence covered both, and it said
        // "every member the board knows is offline" when the board itself had never answered: a
        // claim about members, made with no word from the board about any of them.
        //
        // **And do not blame an anchor (V210-107).** The boards a join tries are the link's
        // entries — the room's host itself among them — and any anchors; a link from a host with
        // no anchor names only the host. This said "the anchor could not be reached" and sent the
        // person to check `vox node`, which they may never have needed. When the node said which
        // boards it tried, [`join_advice_after`] names the one that failed; this is for a join
        // whose reason was lost, so it names neither.
        Some(Fault::BoardUnreachable) => {
            "no board the join tried could be read — the room's host, or an anchor if one was tried — so no member was asked\n       your passphrase was never checked — this is not a verdict on it\n       check that the host is running and that this machine can reach its address"
        }
        Some(Fault::Unreachable) => {
            "the room's board answered, but no member it names could be reached\n       your passphrase was never checked — this is not a verdict on it\n       ask a member to come online"
        }
        Some(Fault::SolveTooSlow) => Fault::SolveTooSlow.explain(),
        Some(Fault::MembersBusy) => Fault::MembersBusy.explain(),
        Some(Fault::RoomFull) => Fault::RoomFull.explain(),
        Some(Fault::NotAdmittedAfterJoin) => Fault::NotAdmittedAfterJoin.explain(),
        // Measured, not assumed: a wrong room passphrase against a LIVE member arrives
        // here as `Refused`, not as `WrongPassphrase` — the passphrase is proved to the
        // responder, so it is the responder that says no. Leading with "the refusal is
        // the thing to chase" was true and useless at the one moment a person most
        // needs a suggestion. Name the likely cause first, without pretending it is the
        // only one.
        Some(Fault::Refused) => {
            "a member answered and refused the join\n       usually the room passphrase is wrong — it is checked by them, not by you,\n       so a typo arrives here rather than as a passphrase error\n       if you are sure of it, they may have revoked you, or be on a different room"
        }
        Some(Fault::NotNetworked) => {
            "this node is not networked, or its identity is locked\n       nothing about the room is in question"
        }
        // **Locked is not "no identity"** (V210-94). A join a lock cut short, or one asked of a
        // locked node, has an identity to join as; it was told to run `vox id`, which would make
        // a second one.
        Some(Fault::Locked) => {
            "this profile's identity is locked: a lock stopped the join, or it was locked already\n       unlock it (open `vox tui`, or start `vox daemon`), then run the join again"
        }
        Some(Fault::NoIdentity) => {
            "this profile has no identity yet, so there is nobody to join as\n       run `vox id` to make one"
        }
        // Joining a room this node already holds used to say `Failed(IdentityExists)`.
        Some(Fault::AlreadyMember) => Fault::AlreadyMember.explain(),
        // Every other fault says what it is. They all fell to "the node did not say why" here,
        // a claim that was false whenever the node had named one (V210-83).
        Some(other) => other.explain(),
        None => "the node did not say why, which is itself worth reporting",
    }
}

/// The fault named in a daemon's reply to a join (`"Failed(Refused)"`), for the verbs that reach
/// the node over its control socket, where only the outcome's name crosses the wire. The name is
/// the reply's first line; a failed join's steps follow it (see [`join_detail`]).
///
/// **Every fault, not the ones a join was expected to meet** (V210-83). It knew ten, and a join
/// that failed for any other — the store, the node shutting down, a bug — printed the enum's name
/// to the person: `cannot join: Failed(Storage)`.
///
/// **And every fault added since** (V210-114): its own table here knew the 28 of V210-83, and
/// `ProfileBusy`, `IdentityFileUnwritable` and `NotAdmitted`, added after it, fell out of it. The
/// names now come from [`Fault::from_name`], made from the one list that `Fault::name` must cover.
pub(crate) fn fault_named(reason: &str) -> Option<Fault> {
    let first = reason.lines().next().unwrap_or_default();
    let name = first.trim().strip_prefix("Failed(")?.strip_suffix(')')?;
    Fault::from_name(name)
}

/// What a daemon's reply to a failed join says after the fault's name: its `steps: …` and
/// `said: …` lines, each indented under the advice as the house style indents a second line.
/// Empty when the reply carried none.
pub(crate) fn join_detail(reason: &str) -> String {
    reason
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .map(|l| format!("\n       {}", l.trim()))
        .collect()
}

/// [`short`], reachable from the other CLI modules that report a peer.
pub(crate) fn short_id_of(d: &Digest32) -> String {
    short(d)
}

/// The first 12 characters of a fingerprint, as `vox` shows ids on screen.
fn short(d: &Digest32) -> String {
    b32_encode(d).chars().take(12).collect()
}

/// Read a passphrase from the terminal without echoing it (ADR-015: a passphrase is
/// never shown, never in a flag, never in the shell's history).
///
/// **Only from a terminal** (V210-165). It fell back to a line of stdin when stdin was not one,
/// and an agent's harness leaves stdin open and writes nothing: the read waited for ever, saying
/// nothing. Without a terminal this fails at once; a script names its source instead, a file or
/// `-` for stdin.
pub fn prompt_passphrase(what: &str) -> Result<String, AppError> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
    use std::io::{IsTerminal, Write};

    if !std::io::stdin().is_terminal() {
        return Err(AppError::Usage(format!(
            "this needs the {what}, and there is no terminal to ask at"
        )));
    }
    print!("{what}: ");
    std::io::stdout().flush().map_err(AppError::Io)?;
    enable_raw_mode().map_err(AppError::Io)?;
    let mut out = String::new();
    let result = loop {
        match event::read() {
            Ok(Event::Key(k)) if k.kind != KeyEventKind::Release => match k.code {
                KeyCode::Enter => break Ok(()),
                KeyCode::Backspace => {
                    out.pop();
                }
                // Ctrl-C at a passphrase prompt means "no", not "empty passphrase".
                KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                    break Err(AppError::Usage("cancelled".into()))
                }
                KeyCode::Char(c) => out.push(c),
                _ => {}
            },
            Ok(_) => {}
            Err(e) => break Err(AppError::Io(e)),
        }
    };
    disable_raw_mode().map_err(AppError::Io)?;
    println!();
    result.map(|()| out)
}

/// The room passphrase: from `--passphrase-file` (`-` for stdin), else asked for at the terminal;
/// with no terminal, it fails at once saying how to give it (V210-165).
///
/// **Never from argv or the environment** (V210-72). A command line is readable by every
/// process on the machine while it runs (`ps`, `/proc/<pid>/cmdline`), and an environment
/// by whatever runs as the user and everything the process starts. Both are refused with
/// the replacement named, rather than ignored, so a script using them is told why and does
/// not go on to wait at a prompt.
pub fn room_passphrase_for(
    given: Option<&String>,
    file: Option<&std::path::Path>,
) -> Result<String, AppError> {
    if given.is_some() {
        return Err(AppError::Usage(
            "--passphrase is refused: a command line is world-readable while the process \
             runs (`ps`, /proc/<pid>/cmdline), so the room passphrase would be disclosed to \
             every process on this machine, and kept in the shell's history.\n\
             \x20      Use --passphrase-file <path>, or omit it and be prompted."
                .into(),
        ));
    }
    if std::env::var_os("VOX_ROOM_PASSPHRASE").is_some() {
        return Err(AppError::Usage(
            "VOX_ROOM_PASSPHRASE is refused: an environment is readable by whatever runs as \
             you and is inherited by every process this one starts. Unset it.\n\
             \x20      Use --passphrase-file <path>, or omit it and be prompted."
                .into(),
        ));
    }
    // An empty file gives an empty passphrase on purpose (V030-36); no source at all still asks.
    if let Some(path) = file {
        let text = passphrase_file_text(path)?;
        let first = text.lines().next().unwrap_or_default();
        return Ok(encouraged(first.to_owned(), "room"));
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(AppError::Usage(format!(
            "this needs the room passphrase, and there is no terminal to ask at.\n\
             \x20      {GIVE_ROOM_PASSPHRASE}"
        )));
    }
    Ok(encouraged(prompt_passphrase("room passphrase")?, "room"))
}

/// `passphrase`, after one line on stderr encouraging one when it is empty (V030-36).
///
/// **An empty passphrase is accepted, not refused** (decider 2026-10-02: "passphrase is a good
/// idea, but is technically optional"). The node takes one; a client may only encourage. `what`
/// is `identity` or `room`.
pub fn encouraged<S: AsRef<str>>(passphrase: S, what: &str) -> S {
    if passphrase.as_ref().is_empty() {
        eprintln!("vox: no {what} passphrase; going on without one. A passphrase is encouraged.");
    }
    passphrase
}

/// How to give a room passphrase without a terminal.
pub const GIVE_ROOM_PASSPHRASE: &str = "Use --passphrase-file <path> (`-` reads stdin).";

/// A full base32 fingerprint, for a caller with no node to resolve a prefix against.
///
/// The socket path deliberately refuses prefixes rather than guessing: resolving one needs
/// the node's view of who it knows, and trusting the wrong key is exactly the mistake this
/// model exists to prevent. The error says what to paste.
///
/// # Errors
/// [`AppError::Usage`] if the text is not a whole fingerprint.
pub fn parse_fingerprint(fingerprint: &str) -> Result<Digest32, AppError> {
    b32_decode(fingerprint, "trust fingerprint").map_err(|_| {
        AppError::Usage(format!(
            "{fingerprint:?} is not a whole fingerprint. Paste the 52-character one that \
             `vox id` prints on their machine — a prefix is only resolved when this \
             command starts its own node, and a node is already running for this profile."
        ))
    })
}

// ---- the verbs that hold a session, as clients of the daemon (ADR-026 L-7, S-3) ---------------

/// A held verb's reply to one request: `Ok` or the node's reason.
fn ok_or(reply: vox_core::error::Result<Frame>, doing: &str) -> Result<(), AppError> {
    match reply {
        Ok(Frame::Ok) => Ok(()),
        Ok(Frame::Error { reason }) => Err(AppError::Usage(format!("{doing}: {reason}"))),
        Ok(other) => Err(AppError::Usage(format!("{doing}: unexpected reply {other:?}"))),
        Err(e) => Err(AppError::Usage(format!("{doing}: {e}"))),
    }
}

/// Every room the node holds, by id.
async fn room_ids(client: &mut IpcClient) -> Result<Vec<Digest32>, AppError> {
    match client.rooms().await {
        Ok(Frame::Rooms { rooms }) => Ok(rooms.into_iter().map(|r| r.0).collect()),
        Ok(Frame::Error { reason }) => Err(AppError::Usage(reason)),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(e.to_string())),
    }
}

/// Follow a held verb's node until the daemon closes the holding connection or the node
/// detaches, saying on the way what explains a failure, and what `each` prints (L-7).
async fn follow(
    held: &mut crate::client::Held,
    mut events: IpcClient,
    mut each: impl FnMut(&NodeEvent),
) -> AppError {
    let closed = crate::client::hold_until_closed(&mut held.client);
    tokio::pin!(closed);
    loop {
        tokio::select! {
            why = &mut closed => return why,
            ev = events.next() => match ev {
                Ok(Some(Frame::Event(ev))) => {
                    each(&ev);
                    say_if_it_explains_a_failure(&ev);
                }
                Ok(Some(_)) => {}
                // The subscription ends with the node; the holding connection says why.
                Ok(None) | Err(_) => return (&mut closed).await,
            },
        }
    }
}

/// `vox serve <name>=<port>[/udp] …` — create a room, share the named services in it, and serve
/// until stopped (ADR-017 decisions 3 and 4; ADR-022 decision 6 for `/udp`; V030-25), as a client
/// of the daemon holding this node (ADR-026 L-7).
///
/// **Every share is named**: the name is the `<service>` of `<service>.<node>.<room>.vox`, the
/// only way it is reached. A bare port is refused, saying how to name it. The first spec creates
/// the room; any further ones are added to it (`vox serve dns=53 dns-udp=53/udp`). `--at`
/// applies to every spec.
///
/// Prints three things and says plainly that two of them must travel separately: the
/// address is a rendezvous, and the passphrase is what turns it into access (ADR-005).
///
/// # Errors
/// A spec that is not one, the node not held, or the room or its address not made. Once serving,
/// it ends only with the daemon or the node's detach, which is an error (L-7); a stop signal ends
/// it in its runner.
pub async fn serve(
    paths: &Paths,
    args: &crate::client::NodeArgs,
    pass: crate::client::Pass,
    name: &str,
    specs: &[String],
    at: Option<SocketAddr>,
    waiting: &Waiting,
) -> Result<(), AppError> {
    // Parsed before anything is created: a typo must not leave a half-made room.
    let mut services: Vec<(u16, String)> = Vec::with_capacity(specs.len());
    for spec in specs {
        let (port, label) = named_spec(spec)?;
        let name = vox_core::node::channel::service_name(&label);
        if services
            .iter()
            .any(|(_, l)| vox_core::node::channel::service_name(l) == name)
        {
            return Err(AppError::Usage(format!(
                "{name:?} is named twice: each service shared in a room needs its own name"
            )));
        }
        services.push((port, label));
    }
    if services.is_empty() {
        return Err(AppError::Usage(
            "name at least one service to share: vox serve <name>=<port>, e.g. vox serve ssh=22"
                .into(),
        ));
    }
    let mut held = crate::client::hold(paths, args, pass, true, Some(waiting)).await?;
    crate::ident::load_names(&mut held.client).await;
    // Taken before the room is made, so who reaches it from the first moment is said.
    let events = crate::client::events(&held.at).await?;
    waiting.on("the room to be created");
    // **No anchor, no refusal** (V210-96, C1): a host on a LAN or on this machine is found
    // directly by a guest there, and an anchor bridges only hosts that cannot otherwise find each
    // other. Whether the address would lead anywhere is the node's to say when it mints it.
    let passphrase = vox_core::node::passphrase::generate(PASSPHRASE_GROUPS)?;
    let before = room_ids(&mut held.client).await?;
    ok_or(
        held.client
            .request(&Request::Create {
                local_name: name.to_owned(),
                passphrase: passphrase.as_str().to_owned(),
            })
            .await,
        "cannot create the room",
    )?;
    let channel_id = room_ids(&mut held.client)
        .await?
        .into_iter()
        .find(|id| !before.contains(id))
        .ok_or_else(|| AppError::Usage("the room was not created".into()))?;
    for (port, label) in &services {
        let local = at.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], *port)));
        ok_or(
            held.client
                .request(&Request::AddService {
                    channel_id,
                    service_tag: label.clone(),
                    local: local.to_string(),
                    persist: true,
                })
                .await,
            &format!("cannot serve {label}"),
        )?;
    }
    // Answered once the room is on a board the address names (V210-96): printed before, a guest
    // who joined at once was told the board had nothing for the room.
    waiting.on("the room's address");
    let url = match held.client.request(&Request::Invite { channel_id }).await {
        Ok(Frame::Link { url, note }) => {
            if !note.is_empty() {
                eprintln!("vox: {note}");
            }
            url
        }
        Ok(Frame::Error { reason }) => {
            return Err(AppError::Usage(format!("cannot mint an address: {reason}")))
        }
        Ok(other) => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    waiting.on("the vox daemon to stop");

    println!("room       {}", b32_encode(&channel_id));
    println!("address    {url}");
    println!("passphrase {}", passphrase.as_str());
    println!("           ^ send this by a different channel than the address");
    println!();
    // The address with the fingerprints in the node and room places: what any member can use
    // as printed, or with its own aliases for this node and this room (V030-25).
    let me = held.me.as_ref().map(b32_encode).unwrap_or_default();
    for (port, label) in &services {
        let endpoint = at.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], *port)));
        let proto = if vox_core::tunnel::udp::is_udp(label) {
            " (udp)"
        } else {
            ""
        };
        println!(
            "sharing {endpoint} as {}.{me}.{}.vox{proto}",
            vox_core::node::channel::service_name(label),
            b32_encode(&channel_id)
        );
    }
    // **Not "anyone who joins with both".** That was true of the withdrawn model, where a
    // room's genesis authorized every admitted member and joining WAS the authorization
    // (ADR-017 decision 3 as revised, M17.7).
    println!();
    println!("who can reach it: the identities you have trusted, once they join.");
    println!("  a joiner with the address and the passphrase reaches NOTHING until then");
    println!("  ask them for `vox id`, then run `vox trust add <fingerprint>`");
    println!("  `vox trust list` shows who you have decided about");
    println!("Ctrl-C to stop");

    // Until stopped: report who reaches the service. The service itself cannot say — every Vox
    // client arrives at it from loopback (ADR-017 decision 6).
    Err(follow(&mut held, events, |ev| match ev {
        NodeEvent::TunnelServed {
            client,
            service_tag,
            ..
        } => println!(
            "vox: {} reached {service_tag:?}",
            crate::ident::author_id(client)
        ),
        NodeEvent::PeerJoined { channel_id: c, peer } if *c == channel_id => {
            println!("vox: {} joined", crate::ident::author_id(peer));
        }
        _ => {}
    })
    .await)
}

/// `vox connect <address>` — join the room an address names, and print the name its services
/// answer on (ADR-017 decision 4), as a client of the daemon holding this node while it joins.
///
/// One-shot: joining is a durable act recorded in the node, so there is nothing to keep running.
/// What makes the printed name resolve is `vox up` (decision 5).
///
/// # Errors
/// The node not held, or the join's failure with what refused it.
#[allow(clippy::too_many_arguments)]
pub async fn connect(
    paths: &Paths,
    args: &crate::client::NodeArgs,
    pass: crate::client::Pass,
    url: &str,
    name: &str,
    room_passphrase: &str,
    waiting: &Waiting,
) -> Result<(), AppError> {
    let mut held = crate::client::hold(paths, args, pass, true, Some(waiting)).await?;
    // Taken before the join, so its first step is not raised before anyone listens.
    let mut steps = crate::client::events(&held.at).await?;
    waiting.on("the node to take the join");
    let request = Request::Join {
        link: url.to_owned(),
        local_name: name.to_owned(),
        // Canonicalization is the node's, at its one boundary — see `actor::room_passphrase`.
        passphrase: room_passphrase.to_owned(),
    };
    let join = held.client.request(&request);
    tokio::pin!(join);
    // A join that waits — for a host to publish its room at its boards (V210-143) — says what it
    // waits for, once, rather than sitting silent for up to half a minute.
    let mut said_waiting = std::collections::HashSet::new();
    let mut following = true;
    let reply = loop {
        tokio::select! {
            reply = &mut join => break reply,
            ev = steps.next(), if following => match ev {
                Ok(Some(Frame::Event(NodeEvent::JoinStep { step }))) => {
                    if step.starts_with("waiting:") && said_waiting.insert(step.clone()) {
                        eprintln!("vox: {step}");
                    }
                    waiting.on(step);
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => following = false,
            },
        }
    };
    match reply {
        Ok(Frame::Ok) => {}
        // The node sends the outcome's name, with its steps and what each responder said; turn
        // it into the guidance a person can act on (V29-12, #192).
        Ok(Frame::Error { reason }) => {
            return Err(AppError::Usage(match fault_named(&reason) {
                Some(fault) => format!(
                    "cannot join: {}{}",
                    join_advice_after(Some(fault), &reason),
                    join_detail(&reason)
                ),
                None => format!("cannot join: {reason}"),
            }))
        }
        Ok(Frame::NodeDetached { node }) => {
            return Err(AppError::Usage(format!(
                "node {node} was detached from the vox daemon while it joined"
            )))
        }
        Ok(other) => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    }
    let channel_id = vox_core::node::link::InviteLink::parse(url)
        .map_err(|e| AppError::Usage(format!("joined, but the address no longer reads: {e}")))?
        .channel_id;
    println!(
        "joined. `vox service list {}` shows what is shared here",
        short(&channel_id)
    );
    println!("        reach a service as <service>.<node>.<room>.vox, with `vox up` running");
    Ok(())
}

/// `vox up [<room>]` — the local entry point: a SOCKS5 proxy, run by the daemon for this node,
/// carrying every room the node holds (PRD-001 R20, ADR-017 decision 5) until stopped. A room
/// named with its passphrase is opened first, if it is closed.
///
/// Prints the `ProxyCommand` block rather than writing it: `~/.ssh/config` is the user's file,
/// and a tool that edits it unasked is a tool that will one day edit it wrongly.
///
/// # Errors
/// The node not held, the room not opened, or the proxy not bound. Once up, it ends only with the
/// daemon or the node's detach, which is an error (L-7).
pub async fn up(
    paths: &Paths,
    args: &crate::client::NodeArgs,
    pass: crate::client::Pass,
    room: Option<(&str, Option<&str>)>,
    bind: SocketAddr,
    waiting: &Waiting,
) -> Result<(), AppError> {
    let mut held = crate::client::hold(paths, args, pass, false, Some(waiting)).await?;
    if let Some((prefix, room_passphrase)) = room {
        open_named_room(&mut held.client, prefix, room_passphrase).await?;
    }
    waiting.on("the proxy to bind");
    let mut up = vox_core::node::nameipc::up(&held.at, bind)
        .await
        .map_err(|e| match e {
            vox_core::error::Error::AppRefused(reason) => AppError::Usage(format!(
                "cannot bring the proxy up on {bind}: {}",
                tcp_bind_failure(bind).unwrap_or(reason)
            )),
            other => crate::client::said(&held.at, other),
        })?;
    let bound = up.bound;
    println!("vox up on {bound} — carrying every room this node holds");
    println!();
    println!("add this to ~/.ssh/config, once, for every room there will ever be:");
    println!();
    for line in vox_core::node::up::ssh_config_hint(bound).lines() {
        println!("    {line}");
    }
    println!();
    println!(
        "then:  ssh user@<service>.<node>.<room>.vox   (`vox service list <room>` shows each one)"
    );
    println!("other tools:  ALL_PROXY=socks5h://{bound}");
    println!("Ctrl-C to stop");
    waiting.on("the vox daemon to stop");
    let closed = crate::client::hold_until_closed(&mut held.client);
    tokio::pin!(closed);
    loop {
        tokio::select! {
            why = &mut closed => return Err(why),
            note = up.next_note() => match note {
                Some(note) => eprintln!("vox: {note}"),
                None => return Err((&mut closed).await),
            },
        }
    }
}

/// Open the room `prefix` names among the node's rooms with its passphrase, if it is closed.
pub(crate) async fn open_named_room(
    client: &mut IpcClient,
    prefix: &str,
    room_passphrase: Option<&str>,
) -> Result<Digest32, AppError> {
    let rooms = match client.rooms().await {
        Ok(Frame::Rooms { rooms }) => rooms,
        Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
        Ok(other) => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    if rooms.is_empty() {
        return Err(AppError::Usage("this node holds no rooms".into()));
    }
    let by_name: Vec<Digest32> = rooms
        .iter()
        .filter(|r| r.1 == prefix)
        .map(|r| r.0)
        .collect();
    let channel_id = match by_name.as_slice() {
        [one] => *one,
        _ => resolve_prefix(prefix, &rooms.iter().map(|r| r.0).collect::<Vec<_>>())?,
    };
    let open = rooms.iter().any(|r| r.0 == channel_id && r.2);
    if open {
        return Ok(channel_id);
    }
    let Some(room_passphrase) = room_passphrase else {
        return Err(AppError::Usage(format!(
            "room {} is closed; give its passphrase to open it. {GIVE_ROOM_PASSPHRASE}",
            short(&channel_id)
        )));
    };
    ok_or(
        client
            .request(&Request::OpenRoom {
                channel_id,
                passphrase: room_passphrase.to_owned(),
            })
            .await,
        "cannot open that room",
    )?;
    Ok(channel_id)
}

/// `vox forward <service>.<node>.<room>.vox [<local>]`: resolved and carried by the daemon for
/// this node, until stopped (V030-25, ADR-026 L-7).
///
/// # Errors
/// The node not held, the name leading nowhere, or the forward not bound. Once forwarding, it ends
/// only with the daemon or the node's detach, which is an error.
pub async fn forward_named(
    paths: &Paths,
    args: &crate::client::NodeArgs,
    pass: crate::client::Pass,
    name: &str,
    local: &str,
    waiting: &Waiting,
) -> Result<(), AppError> {
    let mut held = crate::client::hold(paths, args, pass, false, Some(waiting)).await?;
    waiting.on("the name to resolve");
    let (channel_id, host, service) = vox_core::node::nameipc::resolve(&held.at, name)
        .await
        .map_err(|e| AppError::Usage(format!("{name}: {e}")))?;
    // A bare port means loopback; `127.0.0.1:0` picks one.
    let local = match local.parse::<u16>() {
        Ok(port) => format!("127.0.0.1:{port}"),
        Err(_) => local.to_owned(),
    };
    let local_addr: Option<SocketAddr> = local.parse().ok();
    let events = crate::client::events(&held.at).await?;
    waiting.on("the forward to bind");
    let first_attempt = Instant::now();
    let bound = match held
        .client
        .request(&Request::Forward {
            channel_id,
            host,
            service_tag: service.clone(),
            local,
        })
        .await
    {
        Ok(Frame::Bound { local }) => local,
        Ok(Frame::Error { reason }) => {
            return Err(AppError::Usage(
                match local_addr.and_then(|a| tcp_bind_failure(a).map(|why| (a, why))) {
                    Some((a, why)) => format!("cannot forward to {a}: {why}"),
                    None => format!("{name}: {reason}"),
                },
            ));
        }
        Ok(other) => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    eprintln!(
        "vox: bound in {} ms",
        first_attempt.elapsed().as_millis()
    );
    println!(
        "vox: forwarding {bound} to {service} on {name} ({})",
        short(&host)
    );
    println!("Ctrl-C to stop");
    waiting.on("the vox daemon to stop");
    // Keep reading events while forwarding, so a connection the host refused or cut says why here
    // (PRD-001 R23); the application only ever sees its socket reset.
    Err(follow(&mut held, events, |_| {}).await)
}
