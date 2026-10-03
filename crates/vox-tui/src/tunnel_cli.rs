//! The one-shot tunnel verbs (ADR-013, M16.1): `vox service add|remove|list` and
//! `vox forward`.
//!
//! Each one spawns the node, unlocks the identity, opens the room, does its work and
//! leaves — except `forward`, which serves until interrupted, because a forwarded port
//! is only useful while something is listening on it.
//!
//! All of them need the room's passphrase, because a room's services and its
//! governance live inside the SEK-sealed store (ADR-010's double lock): there is no
//! way to offer a service, or to grant reach, without opening the room.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use vox_core::hash::Digest32;
use vox_core::node::actor::{Bind, EventStreamItem, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{Fault, NodeCommand, NodeEvent, Outcome, Secret};
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

/// Spawn a node and make its identity usable: unlock an existing one, or create one on
/// first use. Returns the running handle.
///
/// The room-making verbs need this instead of the room-opening preamble the one-shot
/// verbs share: `serve` is about to create a room and `connect` to join one, so neither
/// has a room to open yet.
/// What to say when another `vox` already holds this profile.
///
/// Shared by both spawn paths: the first version of this covered `open_profile` only, so
/// `serve`, `connect`, `service`, `forward` and `up` — which go through
/// `open_room` — still got the bare "another vox already has this profile open" with no
/// remedy, which is the message the fix existed to replace.
///
/// **A holder that is only slow is not told to stop** (V210-100). A `vox daemon` or `vox tui`
/// answers on the control socket and keeps the profile for as long as it runs, so stopping it, or
/// asking it through `vox room …`, is the remedy. Any other holder is a `vox node` (which serves
/// no socket) or a command that has not finished while this one waited (up to
/// [`PROFILE_PATIENCE`](vox_core::node::profile::PROFILE_PATIENCE)) — slow, or stopped — and the
/// true thing to say is that it is still using the profile, and how to find it: the lock is the
/// profile directory held open, so `lsof` on it names the process.
fn profile_busy(paths: &Paths) -> AppError {
    let socket = paths.socket_file();
    if vox_core::node::profile::holder_serves(&socket) {
        return AppError::Usage(format!(
            "a vox is already running for this profile, and only one at a time may hold it.\n\
             \x20      Its control socket is {}\n\
             \x20      Stop that node to run this command, or use the `vox room …` verbs, \
             which ask the running node instead of starting a second one.",
            socket.display()
        ));
    }
    AppError::Usage(format!(
        "another vox is still using this profile, and only one at a time may hold it.\n\
         \x20      It is a command that has not finished (a slow one, or one stopped, e.g. with \
         Ctrl-Z, which goes on once resumed), or a `vox node` on this profile, which holds it \
         until it stops.\n\
         \x20      To see which process it is: lsof {}\n\
         \x20      Run this command again once it is done.",
        paths.profile_dir.display()
    ))
}

/// Serve this profile's control socket for as long as the returned guard lives.
///
/// **Whatever holds a profile answers for it** (V210-83, ported from v0.3.0's #236). A one-shot
/// verb — `serve`, `connect`, `service`, `forward`, `up` — holds the profile for as long as it
/// runs, and served nothing: `vox status`, `vox trust add/remove` and the `vox room …` verbs were
/// refused with `profile_busy`'s message, which named a control socket that did not exist and a
/// remedy that did not work. `vox serve` even printed `vox trust add <fingerprint>` as the next
/// step, which could not be done while it ran. Now the running node answers on the socket the
/// message names, as a `vox daemon`'s does.
///
/// **A socket that cannot be bound is reported, not fatal** (V210-83), as in the TUI. The verb's
/// job — hosting a service, forwarding a port — does not depend on the socket, and a path another
/// user can occupy first (the `$TMPDIR/vox-<uid>` fallback, `/tmp` on Linux) must not be able to
/// stop it. A socket or directory that is not this user's is never used: `bind_at` refuses it.
pub fn serve_control_socket(
    node: &NodeHandle,
    socket: std::path::PathBuf,
) -> Option<vox_core::node::ipc::IpcServer> {
    match vox_core::node::ipc::bind_at(node.clone(), socket) {
        Ok(server) => Some(server),
        Err(e) => {
            eprintln!(
                "vox: control socket unavailable ({e}); this node runs on, but `vox trust`, \
                 `vox room` and `vox status` will not reach it while it does"
            );
            None
        }
    }
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

pub async fn open_profile(
    paths: Paths,
    listen: SocketAddr,
    anchors: vox_core::nat::bootstrap::BootstrapSet,
    identity_passphrase: &str,
) -> Result<NodeHandle, AppError> {
    let existed = vox_core::node::profile::Profile::exists(&paths);
    let cfg = NodeConfig::new()
        .bind(Bind::Addr(listen))
        .anchors(anchors)
        .on_profile_wait(say_waiting);
    let for_busy = paths.clone();
    let node = match Node::spawn_config(paths, cfg) {
        Ok(n) => n,
        // **A profile that is busy is not a profile that is broken.** redb is
        // single-writer, so a running `vox daemon` or `vox tui` holds this profile for
        // as long as it runs — and every verb that spawns its own node therefore failed
        // with "store open: Database already open. Cannot acquire lock.", which names a
        // storage engine and no remedy. Running a daemon is the documented way to run
        // agent comms, so this was the ordinary case, not an edge one.
        Err(vox_core::error::Error::ProfileBusy) => return Err(profile_busy(&for_busy)),
        Err(e) => return Err(e.into()),
    };
    let secret = Secret::new(identity_passphrase.as_bytes().to_vec());
    let out = if existed {
        apply_saying_waits(&node, NodeCommand::Unlock { passphrase: secret }).await
    } else {
        apply_saying_waits(&node, NodeCommand::CreateIdentity { passphrase: secret }).await
    };
    // **Another vox made it first** (V210-91): there was no identity when this one looked,
    // and there is one now, so it was created by a vox started at the same moment. Nothing
    // was created here; saying only "already has an identity" read as a stale profile.
    if !existed && out == Outcome::Failed(Fault::IdentityExists) {
        return Err(AppError::Usage(
            "another vox created this profile's identity at the same time; nothing was \
             created here.\n\
             \x20      Run `vox id` again to see the identity it made."
                .into(),
        ));
    }
    if out == Outcome::Failed(Fault::ProfileBusy) {
        return Err(profile_busy(&for_busy));
    }
    if let Outcome::Failed(fault) = out {
        if let Some(why) = bind_failure(listen, Socket::Udp, fault) {
            return Err(AppError::Usage(format!("cannot listen on {listen}: {why}")));
        }
    }
    if !out.is_done() {
        return Err(AppError::Usage(format!(
            "cannot open this profile's identity: {out}"
        )));
    }
    Ok(node)
}

/// Spawn a node, unlock it, and open one room — the preamble every verb shares.
///
/// With no room passphrase it opens nothing: the room is resolved among the profile's rooms and
/// left as the unlock left it, open if the profile holds it open, closed if it was closed on
/// purpose (`vox service list`, V210-149).
async fn open_room(
    paths: Paths,
    listen: SocketAddr,
    anchors: vox_core::nat::bootstrap::BootstrapSet,
    identity_passphrase: &str,
    room_prefix: &str,
    room_passphrase: Option<&str>,
) -> Result<(NodeHandle, Digest32), AppError> {
    let cfg = NodeConfig::new()
        .bind(Bind::Addr(listen))
        .anchors(anchors)
        .on_profile_wait(say_waiting);
    let for_busy = paths.clone();
    let node = match Node::spawn_config(paths, cfg) {
        Ok(n) => n,
        Err(vox_core::error::Error::ProfileBusy) => return Err(profile_busy(&for_busy)),
        Err(e) => return Err(e.into()),
    };
    let out = apply_saying_waits(
        &node,
        NodeCommand::Unlock {
            passphrase: Secret::new(identity_passphrase.as_bytes().to_vec()),
        },
    )
    .await;
    if out == Outcome::Failed(Fault::ProfileBusy) {
        return Err(profile_busy(&for_busy));
    }
    if let Outcome::Failed(fault) = out {
        if let Some(why) = bind_failure(listen, Socket::Udp, fault) {
            return Err(AppError::Usage(format!("cannot listen on {listen}: {why}")));
        }
    }
    if !out.is_done() {
        return Err(AppError::Usage(format!(
            "cannot unlock this profile: {out}"
        )));
    }
    let known: Vec<Digest32> = node.view().channels.iter().map(|c| c.channel_id).collect();
    if known.is_empty() {
        return Err(AppError::Usage("this profile holds no rooms".into()));
    }
    let channel_id = resolve_prefix(room_prefix, &known)?;
    let Some(room_passphrase) = room_passphrase else {
        return Ok((node, channel_id));
    };
    let out = node
        .apply(NodeCommand::OpenChannel {
            channel_id,
            passphrase: Secret::new(room_passphrase.as_bytes().to_vec()),
        })
        .await;
    if !out.is_done() {
        return Err(AppError::Usage(format!("cannot open that room: {out}")));
    }
    Ok((node, channel_id))
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

/// `vox service add`
pub async fn service_add(
    node: &NodeHandle,
    channel_id: Digest32,
    tag: &str,
    local: SocketAddr,
) -> Result<(), AppError> {
    let out = node
        .apply(NodeCommand::AddService {
            channel_id,
            service_tag: tag.to_owned(),
            local,
            persist: true,
        })
        .await;
    if !out.is_done() {
        return Err(AppError::Usage(format!("cannot offer {tag:?}: {out}")));
    }
    println!(
        "vox: offering {tag:?} at {local} in room {}",
        short(&channel_id)
    );
    // Not `vox grant` — there is nothing to grant under the ring-keyed gate (ADR-017
    // decision 3 as revised, M17.7). Printing an instruction that cannot be carried out is
    // the same class of error as `vox serve`'s "anyone who joins with both may reach it".
    // Found by the agent-comms session reading its own strings against the new model.
    println!("     it is dark until you `vox trust add` someone — and they join this room");
    Ok(())
}

/// `vox service remove`
pub async fn service_remove(
    node: &NodeHandle,
    channel_id: Digest32,
    tag: &str,
) -> Result<(), AppError> {
    let out = node
        .apply(NodeCommand::RemoveService {
            channel_id,
            service_tag: tag.to_owned(),
        })
        .await;
    // The node's own reason, not "was not offered": a room that is not open, or a store that
    // failed, was reported as a tag that was never there (V210-83).
    if !out.is_done() {
        return Err(AppError::Usage(format!("cannot remove {tag:?}: {out}")));
    }
    println!("vox: no longer offering {tag:?}");
    Ok(())
}

/// `vox service list`, on a node this verb unlocked and which opened no room for it.
///
/// # Errors
/// If the profile does not hold the room open (V210-149): it fails, non-zero, rather than
/// printing a reason and exiting 0 for a script to read as success. The words are the ones a
/// running daemon answers the same request with, so the two say the same thing.
pub async fn service_list(node: &NodeHandle, channel_id: Digest32) -> Result<(), AppError> {
    let Some(detail) = node.open_detail(channel_id).await else {
        let view = node.view();
        let name = view
            .channels
            .iter()
            .find(|c| c.channel_id == channel_id)
            .and_then(|c| c.local_name.clone())
            .unwrap_or_default();
        return Err(crate::room_cli::room_closed(&channel_id, &name));
    };
    let services: Vec<(String, String)> = detail
        .services
        .iter()
        .map(|(tag, addr)| (tag.clone(), addr.to_string()))
        .collect();
    let shared = node.shared_in(channel_id).await.unwrap_or_default();
    print_services(&detail.local_name, &channel_id, &services, &shared);
    Ok(())
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

/// How long a node this verb unlocked waits for the rooms it holds open to reopen before a
/// name that matches none of them is final: they reopen off the actor, one at a time (#208).
const REOPEN_PATIENCE: Duration = Duration::from_secs(20);

/// `vox forward <service>.<node>.<room>.vox [<local>]` on a node this verb unlocked: the name is
/// resolved against the rooms the profile holds open (reopened at unlock) and its keyring, then
/// forwarded as the daemon would (V030-25).
///
/// # Errors
/// If the name leads nowhere — with the resolver's reason — or the forward fails.
pub async fn forward_address(
    node: &NodeHandle,
    name: &str,
    local: SocketAddr,
) -> Result<(), AppError> {
    let deadline = Instant::now() + REOPEN_PATIENCE;
    let mut room = loop {
        match node.resolve_name(name).await {
            Ok(room) => break room,
            // A room still reopening may be the one named: wait while any is closed.
            Err(why)
                if Instant::now() < deadline && node.view().channels.iter().any(|c| !c.open) =>
            {
                let _ = why;
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(why) => return Err(AppError::Usage(format!("{name}: {why}"))),
        }
    };
    // **Which transport is the share's to say**, on the room's log (V030-25). A room joined by a
    // one-shot verb may not hold the statement yet: it arrives with the room's first sync with
    // its sharer, which this node starts as soon as the room is open. Until it is here the name
    // reads as a TCP service, which for a UDP share is a forward that never answers, so wait for
    // it a while; a name no share carries is the host's to refuse.
    let wanted = vox_core::node::channel::service_name(&room.service).to_owned();
    let share_deadline = Instant::now() + SHARE_PATIENCE;
    while Instant::now() < share_deadline {
        let known = node
            .view()
            .open_channels
            .iter()
            .find(|d| d.channel_id == room.channel_id)
            .is_some_and(|d| {
                d.shares
                    .iter()
                    .any(|s| s.host == room.host && s.name == wanted)
            });
        if known {
            if let Ok(again) = node.resolve_name(name).await {
                room = again;
            }
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    forward(node, room.channel_id, room.host, &room.service, local).await
}

/// How long a node this verb unlocked waits for the share a name names to arrive on the room's
/// log, before forwarding to the name as given: see [`forward_address`].
const SHARE_PATIENCE: Duration = Duration::from_secs(15);

/// `vox forward` — serves until interrupted.
pub async fn forward(
    node: &NodeHandle,
    channel_id: Digest32,
    host: Digest32,
    service: &str,
    local: SocketAddr,
) -> Result<(), AppError> {
    // `53/udp` is the service `udp/53`; anything that is not a port spec is a tag as is.
    let label = vox_core::tunnel::udp::service_label(service).unwrap_or_else(|| service.to_owned());
    let tag = label.as_str();
    // **Retried until the host becomes reachable, not asked once.**
    //
    // `forward` is a one-shot verb: it starts a node, opens the room and dials, all inside a few
    // seconds. At the moment of that dial the node has usually not finished connecting to the
    // room's anchor — so `helpers()` is empty, no circuit rung can be built, and the only rung
    // tried is a direct dial, which cannot work between two peers behind NATs. The command then
    // returned `Unreachable` immediately. Measured against a real always-on anchor: four build
    // configurations, four failures, `direct=0 helpers=0 peers=0` at the moment of the dial.
    //
    // `vox up` already solved this and `forward` never got the same treatment: `up` binds before it
    // can reach the host **deliberately** and waits inside the request
    // (`node::up::reach_host_with_patience`, `HOST_PATIENCE`). This is that patience, applied from
    // out here rather than on the actor — the node keeps running between attempts, so the anchor
    // connection it needs is established by the work this loop is waiting for, and the actor is
    // never blocked for more than one attempt.
    let deadline = Instant::now() + vox_core::node::up::HOST_PATIENCE;
    let mut said = false;
    // **How long reaching the host took, said** (PRD-001 R42, #167). Counted from the first
    // attempt — after this node has unlocked and opened the room, the two Argon2id steps a person
    // waits for at the prompt — to the attempt that got through, every retry included: that is
    // the wait R42 bounds ("a first connection to a peer, including NAT traversal, under 2 s"),
    // and without it a slow first connection was indistinguishable from a slow unlock.
    let first_attempt = Instant::now();
    let mut attempts = 0u32;
    let out = loop {
        attempts += 1;
        let out = node
            .apply(NodeCommand::Forward {
                channel_id,
                host,
                service_tag: tag.to_owned(),
                local,
            })
            .await;
        // Only a missing path is worth waiting out. A port in use, a closed room or a
        // non-loopback address is this machine's to fix, and five minutes of "waiting for a
        // path" hid it (PRD-001 R36).
        if out.is_done()
            || Instant::now() >= deadline
            || !matches!(out, Outcome::Failed(Fault::Unreachable))
        {
            break out;
        }
        // Drain whatever the node has to say about the attempt that just failed, so a person
        // watching sees which rung refused rather than a silent wait.
        while let Ok(Some(ev)) =
            tokio::time::timeout(Duration::from_millis(50), node.next_event()).await
        {
            say_if_it_explains_a_failure(&ev);
        }
        if !said {
            eprintln!(
                "vox: {} is not reachable yet — waiting for a path (up to {:?})",
                crate::ident::author_id(&host),
                vox_core::node::up::HOST_PATIENCE
            );
            said = true;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    if !out.is_done() {
        // Not "do you hold dial:<tag>": that capability was withdrawn with the rest of
        // the model in ADR-017's third revision, and nothing has consulted it since
        // M17.7. The message asked a person to check a permission that cannot be held
        // and cannot be granted — `vox grant`, the only thing that issued it, is
        // withdrawn too. What actually decides is the host's keyring, and the host is
        // the only one who can change it.
        if let Outcome::Failed(fault) = out {
            if let Some(why) = bind_failure(local, Socket::Tcp, fault) {
                return Err(AppError::Usage(format!("cannot forward to {local}: {why}")));
            }
        }
        if !matches!(out, Outcome::Failed(Fault::Unreachable | Fault::Refused)) {
            return Err(AppError::Usage(format!("cannot forward to {local}: {out}")));
        }
        return Err(AppError::Usage(format!(
            "cannot forward: {out}\n       Two things it could be: {} is not reachable \
             right now, or they have not run `vox trust add` on you.\n       Reach is \
             the HOST's decision (ADR-017 decision 3) — there is nothing you can grant \
             yourself.",
            crate::ident::author_id(&host)
        )));
    }
    eprintln!(
        "vox: reached {} in {} ms ({attempts} attempt{})",
        crate::ident::author_id(&host),
        first_attempt.elapsed().as_millis(),
        if attempts == 1 { "" } else { "s" }
    );
    // The bound port comes back as an event, since port 0 is resolved by the OS.
    let bound = loop {
        match node.next_event().await {
            Some(NodeEvent::Forwarding { local, .. }) => break local,
            Some(ref other) => say_if_it_explains_a_failure(other),
            None => return Err(AppError::Usage("the node stopped".into())),
        }
    };
    println!(
        "vox: {bound} → {tag:?} on {}",
        crate::ident::author_id(&host)
    );
    println!("     e.g.  ssh -p {} user@{}", bound.port(), bound.ip());
    println!("     Ctrl-C to stop");
    // Keep reading events while forwarding, so a connection the host refused or cut says
    // why here (PRD-001 R23). The application only ever sees its socket reset; waiting on
    // Ctrl-C alone left the reason in a queue nobody read. A stop signal ends the run in
    // `with_room` (V210-108).
    while let Some(ev) = node.next_event().await {
        say_if_it_explains_a_failure(&ev);
    }
    println!("vox: stopping the forward");
    let _ = node.apply(NodeCommand::StopForward { local: bound }).await;
    let _ = node.apply(NodeCommand::Shutdown).await;
    Ok(())
}

/// `vox serve <name>=<port>[/udp] …` — create a room, share the named services in it, and serve
/// until interrupted (ADR-017 decisions 3 and 4; ADR-022 decision 6 for `/udp`; V030-25).
///
/// **Every share is named**: the name is the `<service>` of `<service>.<node>.<room>.vox`, the
/// only way it is reached. A bare port is refused, saying how to name it. The first spec creates
/// the room; any further ones are added to it (`vox serve dns=53 dns-udp=53/udp`). `--at`
/// applies to every spec.
///
/// Prints three things and says plainly that two of them must travel separately: the
/// address is a rendezvous, and the passphrase is what turns it into access (ADR-005).
pub async fn serve(
    node: &NodeHandle,
    name: &str,
    specs: &[String],
    at: Option<SocketAddr>,
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
    let Some((port, first)) = services.first().cloned() else {
        return Err(AppError::Usage(
            "name at least one service to share: vox serve <name>=<port>, e.g. vox serve ssh=22"
                .into(),
        ));
    };
    // **No anchor, no refusal** (V210-96, C1): a host on a LAN or on this machine is found
    // directly by a guest there, and an anchor bridges only hosts that cannot otherwise find each
    // other. Whether the address would lead anywhere is the node's to say when it mints it:
    // `NodeEvent::AddressNote`, or `NodeEvent::AddressWithheld` when it would name no route at all.
    let passphrase = vox_core::node::passphrase::generate(PASSPHRASE_GROUPS)?;
    let before: Vec<Digest32> = node.view().channels.iter().map(|c| c.channel_id).collect();
    let out = node
        .apply(NodeCommand::Serve {
            local_name: name.to_owned(),
            passphrase: Secret::new(passphrase.as_bytes().to_vec()),
            name: vox_core::node::channel::service_name(&first).to_owned(),
            port,
            udp: vox_core::tunnel::udp::is_udp(&first),
            at,
        })
        .await;
    if !out.is_done() {
        return Err(AppError::Usage(format!("cannot serve port {port}: {out}")));
    }
    let channel_id = node
        .view()
        .channels
        .iter()
        .map(|c| c.channel_id)
        .find(|id| !before.contains(id))
        .ok_or_else(|| AppError::Usage("the room was not created".into()))?;

    for (port, label) in services.iter().skip(1) {
        let local = at.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], *port)));
        let out = node
            .apply(NodeCommand::AddService {
                channel_id,
                service_tag: label.clone(),
                local,
                persist: true,
            })
            .await;
        if !out.is_done() {
            return Err(AppError::Usage(format!("cannot serve {label}: {out:?}")));
        }
    }

    // Answered once the room is on a board the address names (V210-96): printed before, a guest
    // who joined at once was told the board had nothing for the room.
    let out = node.apply(NodeCommand::Invite { channel_id }).await;
    if !out.is_done() {
        // With why, which the node says anchor by anchor, in place of the fault's general advice
        // (which speaks of an anchor even when none was named).
        let mut why = out.to_string();
        while let Ok(Some(ev)) =
            tokio::time::timeout(std::time::Duration::from_secs(1), node.next_event()).await
        {
            if let NodeEvent::AddressWithheld { reason, .. } = ev {
                why = format!("the address was not handed out: {reason}");
                break;
            }
        }
        return Err(AppError::Usage(format!("cannot mint an address: {why}")));
    }
    let url = loop {
        match node.next_event().await {
            Some(NodeEvent::InviteLink { url, .. }) => break url,
            Some(ref other) => say_if_it_explains_a_failure(other),
            None => return Err(AppError::Usage("the node stopped".into())),
        }
    };

    println!("room       {}", b32_encode(&channel_id));
    println!("address    {url}");
    println!("passphrase {}", passphrase.as_str());
    println!("           ^ send this by a different channel than the address");
    println!();
    // The address with the fingerprints in the node and room places: what any member can use
    // as printed, or with its own aliases for this node and this room (V030-25).
    let me = node
        .view()
        .identity
        .as_ref()
        .map(|i| b32_encode(&i.fingerprint))
        .unwrap_or_default();
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
    // (ADR-017 decision 3 as revised, M17.7). Printing it now would tell a person the
    // opposite of what the binary does, which is the class of error this whole revision is
    // about.
    println!();
    println!("who can reach it: the identities you have trusted, once they join.");
    println!("  a joiner with the address and the passphrase reaches NOTHING until then");
    println!("  ask them for `vox id`, then run `vox trust add <fingerprint>`");
    println!("  `vox trust list` shows who you have decided about");
    println!("Ctrl-C to stop");

    // Until stopped: report who reaches the service. The service itself cannot say
    // — every Vox client arrives at it from loopback (ADR-017 decision 6). A stop signal ends the
    // run in the verb's runner, which raced it from before the identity was unlocked (V210-108).
    loop {
        match node.next_event().await {
            Some(NodeEvent::TunnelServed {
                client,
                service_tag,
                ..
            }) => {
                println!(
                    "vox: {} reached {service_tag:?}",
                    crate::ident::author_id(&client)
                );
            }
            Some(NodeEvent::PeerJoined { peer, .. }) => {
                println!("vox: {} joined", crate::ident::author_id(&peer));
            }
            Some(ref other) => say_if_it_explains_a_failure(other),
            None => return Err(AppError::Usage("the node stopped".into())),
        }
    }
}

/// `vox connect <address>` — join the room an address names, and print the name its
/// services answer on (ADR-017 decision 4).
///
/// One-shot: joining is a durable act recorded in the profile, so there is nothing to
/// keep running. What makes the printed name resolve is `vox up` (decision 5).
///
/// `waiting` is kept on the step the join is in, so a `vox connect` stopped part-way says
/// where it was (V210-85).
pub async fn connect(
    node: &NodeHandle,
    url: &str,
    name: &str,
    room_passphrase: &str,
    waiting: &Waiting,
) -> Result<(), AppError> {
    // Taken before the command, so the join's first step is not raised before anyone listens.
    let mut steps = node.subscribe();
    waiting.on("the node to take the join");
    let join = node.apply(NodeCommand::JoinChannel {
        link: url.to_owned(),
        local_name: name.to_owned(),
        // Canonicalization is the node's, at its one boundary — see
        // `actor::room_passphrase`. Doing it here as well would be a second place
        // for the two sides to disagree.
        passphrase: Secret::new(room_passphrase.as_bytes().to_vec()),
    });
    tokio::pin!(join);
    // A join that waits — for a host to publish its room at its boards (V210-143) — says what it
    // waits for, once, rather than sitting silent for up to half a minute.
    let mut said_waiting = std::collections::HashSet::new();
    let out = loop {
        tokio::select! {
            out = &mut join => break out,
            item = steps.next() => match item {
                Some(EventStreamItem::Event(NodeEvent::JoinStep { step })) => {
                    if step.starts_with("waiting:") && said_waiting.insert(step.clone()) {
                        eprintln!("vox: {step}");
                    }
                    waiting.on(step);
                }
                Some(_) => {}
                None => break (&mut join).await,
            },
        }
    };
    if !out.is_done() {
        return Err(AppError::Usage(why_a_join_failed(node, out).await));
    }
    // **`Done` is the join.** This waited on the event stream for `Joined`, with no bound — and
    // that stream drops its oldest events under a burst, so a `Joined` lost there left `vox
    // connect` waiting for good, saying nothing. The node raises `Joined` and the join's steps
    // before it answers, so what they explain is already queued: say it, and take the room from
    // the address the node just joined by.
    while let Some(ev) = node.try_next_event() {
        say_if_it_explains_a_failure(&ev);
    }
    let channel_id = vox_core::node::link::InviteLink::parse(url)
        .map_err(|e| AppError::Usage(format!("joined, but the address no longer reads: {e}")))?
        .channel_id;
    println!(
        "joined. `vox service list {}` shows what is shared here",
        short(&channel_id)
    );
    println!("        reach a service as <service>.<node>.<room>.vox, with `vox up` running");
    let _ = node.apply(NodeCommand::Shutdown).await;
    Ok(())
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

/// `vox up` — the local entry point: a SOCKS5 proxy carrying one room's services
/// (ADR-017 decision 5). Runs until interrupted.
///
/// Prints the `ProxyCommand` block rather than writing it: `~/.ssh/config` is the user's
/// file, and a tool that edits it unasked is a tool that will one day edit it wrongly.
pub async fn up(node: &NodeHandle, channel_id: Digest32, bind: SocketAddr) -> Result<(), AppError> {
    let out = node.apply(NodeCommand::Up { channel_id, bind }).await;
    if let Outcome::Failed(fault) = out {
        if let Some(why) = bind_failure(bind, Socket::Tcp, fault) {
            return Err(AppError::Usage(format!(
                "cannot bring the proxy up on {bind}: {why}"
            )));
        }
    }
    if !out.is_done() {
        return Err(AppError::Usage(format!(
            "cannot bring the proxy up on {bind}: {out}"
        )));
    }
    let (hostname, bound) = loop {
        match node.next_event().await {
            Some(NodeEvent::ProxyUp { hostname, bind, .. }) => break (hostname, bind),
            Some(ref other) => say_if_it_explains_a_failure(other),
            None => return Err(AppError::Usage("the node stopped".into())),
        }
    };
    println!("vox up on {bound} — carrying {hostname}");
    println!();
    println!("add this to ~/.ssh/config, once, for every room there will ever be:");
    println!();
    for line in vox_core::node::up::ssh_config_hint(bound).lines() {
        println!("    {line}");
    }
    println!();
    println!("then:  ssh user@{hostname}");
    println!("other tools:  ALL_PROXY=socks5h://{bound}");
    println!("Ctrl-C to stop");
    // Until stopped — a stop signal ends the run in `with_room` (V210-108) — keep reading events
    // so a session cut by the host withdrawing our reach says so (ADR-017 M17.11). Without this
    // the proxy stays up and silent and the person sees only `ssh` dying, which reads as a network
    // fault and invites a retry that cannot succeed.
    while let Some(ev) = node.next_event().await {
        match ev {
            NodeEvent::ReachWithdrawn { port, .. } => {
                println!("vox: the host withdrew access to port {port} — that session was cut");
                println!("     nothing to retry: ask them to trust this identity again");
            }
            ref other => say_if_it_explains_a_failure(other),
        }
    }
    println!("vox: stopping the proxy");
    let _ = node.apply(NodeCommand::Shutdown).await;
    Ok(())
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
        _ => {}
    }
}

/// Explain a failed join in terms of what actually refused it.
///
/// This used to be `"cannot join: {out:?} — check the address and the passphrase"`, and
/// that sentence was **wrong in the case that matters**. A BASE run of the stranger-join
/// proof produced it verbatim while Carol held the correct address and the correct
/// passphrase, for a room that was alive with a member in it: the product sent her to
/// check the two things that were already right, and said nothing about the one thing
/// that was not.
///
/// `Fault` is a single token with no room for a reason, so the node sends the reason
/// separately as [`NodeEvent::JoinFailed`] — and the old code returned before ever
/// reading it. So this drains what the node already took the trouble to say, and only
/// then falls back to advice, chosen by the fault rather than by guesswork.
async fn why_a_join_failed(node: &NodeHandle, out: Outcome) -> String {
    // The reason usually lands within a tick; a join that failed has nothing else to
    // do, so a short bounded drain costs nothing and is the difference between a
    // diagnosis and a shrug.
    let mut said: Vec<String> = Vec::new();
    while let Ok(Some(ev)) =
        tokio::time::timeout(Duration::from_millis(600), node.next_event()).await
    {
        match ev {
            NodeEvent::JoinFailed { reason } => {
                said.push(reason);
                break;
            }
            NodeEvent::PeerUnreachable { peer, why } => {
                said.push(format!(
                    "could not reach {} — {why}",
                    crate::ident::author_id(&peer)
                ));
            }
            ref other => say_if_it_explains_a_failure(other),
        }
    }

    // House style: one short line saying what happened, then an indented line saying
    // what to actually do. A paragraph is not a better error message than a sentence —
    // the first version of this fix was four lines of prose and read like documentation
    // at exactly the moment somebody is stuck.
    let fault = match out {
        Outcome::Failed(fault) => Some(fault),
        Outcome::Done | Outcome::Bound(_) => None,
    };
    let advice = join_advice_after(fault, &said.join("; "));

    if said.is_empty() {
        format!("cannot join: {advice}")
    } else {
        format!("cannot join: {} — {advice}", said.join("; "))
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

/// Everything a one-shot verb needs to find and open its room.
pub struct RoomTarget {
    /// The profile's paths.
    pub paths: Paths,
    /// Where the node binds while the verb runs.
    pub listen: SocketAddr,
    /// The anchors, if any, that bridge this node to peers it cannot reach directly.
    pub anchors: vox_core::nat::bootstrap::BootstrapSet,
    /// The identity passphrase.
    pub identity_passphrase: String,
    /// The room's id, or a unique prefix.
    pub room: String,
    /// The room's passphrase, or `None` for a verb that opens no room.
    pub room_passphrase: Option<String>,
}

/// Shared entry: open the room, run `body`, shut down.
///
/// **The whole run races every stop signal** (V210-108): SIGINT, SIGTERM, SIGHUP and SIGQUIT, from
/// before the room is opened. `vox up` and `vox forward` run until stopped, and they listened for
/// Ctrl-C alone: SIGTERM and SIGHUP — a service manager's stop, a closed tmux pane or ssh session —
/// took the default action and ended them on the spot, saying nothing. A stop now ends the verb
/// with [`AppError::stopped_by`], after the node is shut down so its peers are told it went.
///
/// `stop` is the caller's `stop_requested`, taken before its passphrase prompts, so
/// one listener covers the whole run.
pub async fn with_room<F, Fut>(
    target: RoomTarget,
    mut stop: std::pin::Pin<&mut impl std::future::Future<Output = crate::app::StopSignal>>,
    body: F,
) -> Result<(), AppError>
where
    F: FnOnce(NodeHandle, Digest32) -> Fut,
    Fut: std::future::Future<Output = Result<(), AppError>>,
{
    let socket = target.paths.socket_file();
    let opening = open_room(
        target.paths,
        target.listen,
        target.anchors,
        &target.identity_passphrase,
        &target.room,
        target.room_passphrase.as_deref(),
    );
    let (node, channel_id) = tokio::select! {
        opened = opening => opened?,
        signal = &mut stop => return Err(AppError::stopped_by(signal)),
    };
    let _control = serve_control_socket(&node, socket);
    let handle = node.clone();
    let result = tokio::select! {
        done = body(node, channel_id) => done,
        signal = &mut stop => {
            crate::app::say(format_args!("vox: stopping"));
            // Bounded: the node handles one thing at a time, and what it was doing can be a
            // round trip to a peer that has gone (see `app::run_daemon`). A stop has to mean stop.
            let _ = tokio::time::timeout(STOP_PATIENCE, handle.apply(NodeCommand::Shutdown)).await;
            return Err(AppError::stopped_by(signal));
        }
    };
    // The verbs are one-shot; `forward` shuts the node down itself when it ends, and a second
    // shutdown is harmless.
    let _ = handle.apply(NodeCommand::Shutdown).await;
    result
}

/// How long a stopped verb waits for its node to shut down before it exits anyway. A clean
/// shutdown takes milliseconds; this is for a node stuck on a peer that vanished.
const STOP_PATIENCE: Duration = Duration::from_secs(5);

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

/// `vox trust add` — decide that an identity may read this node, and reach its services.
///
/// The decision is per **identity** and node-wide: every room this node shares with that
/// key auto-consents to it from here on, including rooms made later, and that key may reach
/// every service this node binds to a room they are both in (ADR-020 §3, ADR-017 decision
/// 3). It is deliberately one act rather than one per room — which is what makes it usable
/// for a person with five agents, and what a person must understand before running it, so
/// the output says what was granted rather than only that something was.
///
/// `fingerprint` is the whole base32 fingerprint, or a unique prefix of one this node
/// already knows as a member somewhere. A prefix that matches nothing is refused rather than
/// guessed at: trusting the wrong key is precisely the mistake this model exists to prevent.
pub async fn trust_add(
    node: &NodeHandle,
    fingerprint: &str,
    petname: &str,
    full_history: bool,
) -> Result<(), AppError> {
    let target = resolve_trust_target(node, fingerprint)?;
    crate::ident::check_new_name(&node.view().trusted, &target, petname)?;
    let out = node
        .apply(NodeCommand::TrustWith {
            fingerprint: target,
            petname: petname.to_owned(),
            history: if full_history {
                vox_core::node::trust::HistoryGrant::Full
            } else {
                vox_core::node::trust::HistoryGrant::Now
            },
        })
        .await;
    if !out.is_done() {
        return Err(AppError::Usage(format!(
            "cannot trust that identity: {out}"
        )));
    }
    println!("vox: trusting {} as {petname:?}", short(&target));
    if full_history {
        println!("     with full history: it may also read what you wrote before now");
    }
    println!("     it may now read what you write in every room you share — now and later");
    println!("     and you read what it writes, once it trusts you too");
    println!("     and reach every service you bind to a room you are both in");
    println!("     `vox trust remove` undoes it and changes the lock everywhere");
    Ok(())
}

/// `vox up` with no room: the proxy runs inside the node already holding this profile
/// and carries every room it holds, until ^C (PRD-001 R20).
pub async fn up_all(paths: &Paths, bind: SocketAddr) -> Result<(), AppError> {
    let sock = paths.socket_file();
    let mut up = vox_core::node::nameipc::up(&sock, bind)
        .await
        .map_err(|e| {
            AppError::Usage(format!(
                "`vox up` without a room runs inside the node holding this profile, and {}: {e}\n\
             \x20      start one with `vox daemon`, or name a room: `vox up <room>`",
                sock.display()
            ))
        })?;
    let bound = up.bound;
    println!("vox up on {bound} — carrying every room this node holds");
    println!();
    println!("add this to ~/.ssh/config, once:");
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
    // One Ctrl-C listener for the whole loop: one made per turn misses a SIGINT that
    // lands in the same turn as another arm (see `app::run_node`).
    let interrupted = tokio::signal::ctrl_c();
    tokio::pin!(interrupted);
    loop {
        tokio::select! {
            _ = &mut interrupted => break,
            note = up.next_note() => match note {
                Some(note) => eprintln!("vox: {note}"),
                None => {
                    return Err(AppError::Usage("the node stopped, and the proxy with it".into()));
                }
            },
        }
    }
    println!("vox: stopping the proxy");
    Ok(())
}

/// `vox forward <service>.<node>.<room>.vox [<local>]`: resolved and carried by the node
/// already holding this profile, until ^C (V030-25).
pub async fn forward_named(paths: &Paths, name: &str, local: &str) -> Result<(), AppError> {
    let sock = paths.socket_file();
    let (channel_id, host, service) = vox_core::node::nameipc::resolve(&sock, name)
        .await
        .map_err(|e| AppError::Usage(format!("{name}: {e}")))?;
    // A bare port means loopback; `127.0.0.1:0` picks one.
    let local = match local.parse::<u16>() {
        Ok(port) => format!("127.0.0.1:{port}"),
        Err(_) => local.to_owned(),
    };
    let mut client = vox_core::node::ipc::IpcClient::open(&sock)
        .await
        .map_err(|e| AppError::Usage(e.to_string()))?;
    let bound = match client
        .request(&vox_core::node::ipc::Request::Forward {
            channel_id,
            host,
            service_tag: service.clone(),
            local,
        })
        .await
    {
        Ok(vox_core::node::ipc::Frame::Bound { local }) => local,
        Ok(vox_core::node::ipc::Frame::Error { reason }) => {
            return Err(AppError::Usage(format!("{name}: {reason}")))
        }
        Ok(other) => return Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    println!(
        "vox: forwarding {bound} to {service} on {name} ({})",
        short(&host)
    );
    println!("Ctrl-C to stop");
    let _ = tokio::signal::ctrl_c().await;
    let _ = client
        .request(&vox_core::node::ipc::Request::StopForward { local: bound })
        .await;
    Ok(())
}

/// `vox trust rename` — change the name this node calls a trusted identity.
///
/// Only an identity already in the ring: renaming must never be a way to trust.
pub async fn trust_rename(
    node: &NodeHandle,
    fingerprint: &str,
    name: &str,
) -> Result<(), AppError> {
    let target = resolve_trust_target(node, fingerprint)?;
    if !node.view().trusted.iter().any(|(fp, _)| *fp == target) {
        return Err(AppError::Usage(format!(
            "{} is not trusted, so it has no name to change — `vox trust add` it first",
            short(&target)
        )));
    }
    let out = node
        .apply(NodeCommand::Trust {
            fingerprint: target,
            petname: name.to_owned(),
        })
        .await;
    if !out.is_done() {
        return Err(AppError::Usage(format!(
            "cannot rename that identity: {out:?}"
        )));
    }
    println!(
        "vox: {} is now {name:?} — what it shares is reachable as <service>.{}.<room>.vox",
        short(&target),
        vox_core::node::resolver::label_of(name)
    );
    Ok(())
}

/// `vox trust remove` — stop trusting an identity, and change the lock.
///
/// Removes the ring entry, then rotates this identity's sender key and re-keys everyone
/// still trusted, in every room shared with the removed key (ADR-017 M17.14). It keeps what
/// it already read — that cannot be recalled, and saying so is more useful than implying
/// otherwise.
pub async fn trust_remove(node: &NodeHandle, fingerprint: &str) -> Result<(), AppError> {
    let target = resolve_trust_target(node, fingerprint)?;
    let out = node
        .apply(NodeCommand::Untrust {
            fingerprint: target,
        })
        .await;
    if !out.is_done() {
        // `NotConsented` from `Untrust` has one meaning: the identity is not in the ring.
        return Err(AppError::Usage(match out {
            Outcome::Failed(Fault::NotConsented) => format!(
                "{} is not in your trust keyring, so there is nothing to remove\n       \
                 `vox trust list` shows who is",
                short(&target)
            ),
            other => format!("cannot stop trusting that identity: {other}"),
        }));
    }
    println!("vox: no longer trusting {}", short(&target));
    println!("     it reads nothing you write from now on, in any room you share");
    println!("     what it already read stays read — that cannot be taken back");
    Ok(())
}

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

/// Resolve a fingerprint argument: a full base32 fingerprint, or a unique prefix of one this
/// node already knows — a member of some room it holds, or an identity it already trusts.
///
/// A full fingerprint is accepted even when unknown, because that is the normal case: a
/// person pastes what `vox id` printed on someone else's machine, before any room is shared.
fn resolve_trust_target(node: &NodeHandle, fingerprint: &str) -> Result<Digest32, AppError> {
    if let Ok(full) = b32_decode(fingerprint, "trust fingerprint") {
        return Ok(full);
    }
    let view = node.view();
    let mut known: Vec<Digest32> = view.trusted.iter().map(|(fp, _)| *fp).collect();
    for ch in &view.open_channels {
        known.extend(ch.members.iter().copied());
    }
    known.sort_unstable();
    known.dedup();
    resolve_prefix(fingerprint, &known)
}
