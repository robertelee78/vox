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
use vox_core::nat::bootstrap::BootstrapSet;
use vox_core::nat::multiaddr::Multiaddr;
use vox_core::nat::reachability::is_routable;
use vox_core::node::actor::{Bind, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{Fault, NodeCommand, NodeEvent, Outcome, Secret};
use vox_core::node::link::{b32_decode, b32_encode, vox_hostname};
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
    if let Some(path) = file {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| AppError::Usage(format!("reading {}: {e}", path.display())))?;
        let first = text.lines().next().unwrap_or_default();
        if first.is_empty() {
            return Err(AppError::Usage(format!(
                "{} is empty; an identity passphrase cannot be",
                path.display()
            )));
        }
        return Ok(first.to_owned());
    }
    // Read the variable here rather than through clap's `env`, because clap merges a flag
    // and its variable into one value and the whole point is to tell them apart.
    if let Ok(p) = std::env::var("VOX_IDENTITY_PASSPHRASE") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    let exists = vox_core::node::profile::Profile::exists(paths);
    if exists {
        let p = prompt_passphrase("identity passphrase")?;
        // Without a terminal `prompt_passphrase` reads a line, and a closed or empty
        // stdin yields "" — which would otherwise be tried as a passphrase and reported
        // as a wrong one, sending a person to look at their passphrase instead of at the
        // fact that they never supplied it.
        if p.is_empty() {
            return Err(AppError::Usage(
                "no identity passphrase: nothing on stdin and no terminal to prompt at.\n\
                 \x20      Use --identity-passphrase-file <path> or VOX_IDENTITY_PASSPHRASE."
                    .into(),
            ));
        }
        return Ok(p);
    }
    // **Without a terminal there is nobody to ask twice.** `prompt_passphrase` falls back
    // to reading a line, so a closed stdin yielded "" and this printed "creating one",
    // asked for a confirmation nobody could give, and then said "an empty identity
    // passphrase" — three lines, none of which say what to do, after announcing a
    // creation that did not happen.
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(AppError::Usage(
            "this profile has no identity yet, and there is no terminal to ask at.\n\
             \x20      Make one interactively:  vox id\n\
             \x20      Or give the passphrase:  --identity-passphrase-file <path>, or \
             VOX_IDENTITY_PASSPHRASE"
                .into(),
        ));
    }
    println!("vox: this profile has no identity yet; creating one.");
    let first = prompt_passphrase("new identity passphrase")?;
    if first.is_empty() {
        return Err(AppError::Usage(
            "an empty identity passphrase; nothing was created".into(),
        ));
    }
    let again = prompt_passphrase("again")?;
    if first != again {
        return Err(AppError::Usage(
            "the two passphrases differ; nothing was created".into(),
        ));
    }
    Ok(first)
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
fn profile_busy(socket: &std::path::Path) -> AppError {
    AppError::Usage(format!(
        "a vox is already running for this profile, and only one at a time may hold it.\n\
         \x20      Its control socket is {}\n\
         \x20      Stop that node to run this command, or use the `vox room …` verbs, \
         which ask the running node instead of starting a second one.",
        socket.display()
    ))
}

pub async fn open_profile(
    paths: Paths,
    listen: SocketAddr,
    anchors: vox_core::nat::bootstrap::BootstrapSet,
    identity_passphrase: &str,
) -> Result<NodeHandle, AppError> {
    let existed = vox_core::node::profile::Profile::exists(&paths);
    let cfg = NodeConfig::new().bind(Bind::Addr(listen)).anchors(anchors);
    let socket = paths.socket_file();
    let node = match Node::spawn_config(paths, cfg) {
        Ok(n) => n,
        // **A profile that is busy is not a profile that is broken.** redb is
        // single-writer, so a running `vox daemon` or `vox tui` holds this profile for
        // as long as it runs — and every verb that spawns its own node therefore failed
        // with "store open: Database already open. Cannot acquire lock.", which names a
        // storage engine and no remedy. Running a daemon is the documented way to run
        // agent comms, so this was the ordinary case, not an edge one.
        Err(vox_core::error::Error::ProfileBusy) => return Err(profile_busy(&socket)),
        Err(e) => return Err(e.into()),
    };
    let secret = Secret::new(identity_passphrase.as_bytes().to_vec());
    let out = if existed {
        node.apply(NodeCommand::Unlock { passphrase: secret }).await
    } else {
        node.apply(NodeCommand::CreateIdentity { passphrase: secret })
            .await
    };
    if !out.is_done() {
        return Err(AppError::Usage(format!(
            "cannot open this profile's identity: {out}"
        )));
    }
    Ok(node)
}

/// Spawn a node, unlock it, and open one room — the preamble every verb shares.
async fn open_room(
    paths: Paths,
    listen: SocketAddr,
    anchors: vox_core::nat::bootstrap::BootstrapSet,
    identity_passphrase: &str,
    room_prefix: &str,
    room_passphrase: &str,
) -> Result<(NodeHandle, Digest32), AppError> {
    let cfg = NodeConfig::new().bind(Bind::Addr(listen)).anchors(anchors);
    let socket = paths.socket_file();
    let node = match Node::spawn_config(paths, cfg) {
        Ok(n) => n,
        Err(vox_core::error::Error::ProfileBusy) => return Err(profile_busy(&socket)),
        Err(e) => return Err(e.into()),
    };
    let out = node
        .apply(NodeCommand::Unlock {
            passphrase: Secret::new(identity_passphrase.as_bytes().to_vec()),
        })
        .await;
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
    if !out.is_done() {
        return Err(AppError::Usage(format!("{tag:?} was not offered here")));
    }
    println!("vox: no longer offering {tag:?}");
    Ok(())
}

/// `vox service list`
pub fn service_list(node: &NodeHandle, channel_id: Digest32) {
    let view = node.view();
    let Some(detail) = view
        .open_channels
        .iter()
        .find(|d| d.channel_id == channel_id)
    else {
        println!("vox: that room is not open");
        return;
    };
    if detail.services.is_empty() {
        println!("vox: no services offered in {}", short(&channel_id));
        return;
    }
    println!(
        "vox: services offered in {} ({})",
        detail.local_name,
        short(&channel_id)
    );
    for (tag, addr) in &detail.services {
        println!("  {tag}  →  {addr}");
    }
}

/// `vox forward` — serves until interrupted.
pub async fn forward(
    node: &NodeHandle,
    channel_id: Digest32,
    host_prefix: &str,
    tag: &str,
    local: SocketAddr,
) -> Result<(), AppError> {
    let view = node.view();
    let members: Vec<Digest32> = view
        .open_channels
        .iter()
        .find(|d| d.channel_id == channel_id)
        .map(|d| d.members.clone())
        .unwrap_or_default();
    let host = resolve_prefix(host_prefix, &members)?;
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
    let out = loop {
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
    // Ctrl-C alone left the reason in a queue nobody read.
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            ev = node.next_event() => match ev {
                Some(ref ev) => say_if_it_explains_a_failure(ev),
                None => break,
            },
        }
    }
    println!("vox: stopping the forward");
    let _ = node.apply(NodeCommand::StopForward { local: bound }).await;
    let _ = node.apply(NodeCommand::Shutdown).await;
    Ok(())
}

/// Whether this node could be reached by someone who was handed its address — a
/// routable advertised endpoint, or an anchor that will relay for it.
///
/// `vox serve` refuses to start when neither holds (ADR-017 decision 4): minting an
/// address nobody can use is worse than saying so, because the host would hand it out
/// and only learn later.
fn reachable_or_relayed(node: &NodeHandle, anchors: &BootstrapSet) -> bool {
    if !anchors.nodes().is_empty() {
        return true;
    }
    node.view().listening.iter().any(|text| {
        Multiaddr::parse(text)
            .ok()
            .and_then(|m| m.socket_addr())
            .is_some_and(|sa: SocketAddr| is_routable(&sa.ip()))
    })
}

/// `vox serve <port>` — create a service room, offer the port in it, and serve until
/// interrupted (ADR-017 decisions 3 and 4).
///
/// Prints three things and says plainly that two of them must travel separately: the
/// address is a rendezvous, and the passphrase is what turns it into access (ADR-005).
pub async fn serve(
    node: &NodeHandle,
    anchors: &BootstrapSet,
    name: &str,
    port: u16,
    at: Option<SocketAddr>,
) -> Result<(), AppError> {
    if !reachable_or_relayed(node, anchors) {
        return Err(AppError::Usage(
            "this machine has no address a guest could reach and no anchor to relay \
             through.\n       Run `vox node` somewhere reachable and pass its \
             `<fingerprint>@<multiaddr>` here as --anchor,\n       or open a port on \
             your router. Refusing to mint an address nobody can use."
                .into(),
        ));
    }
    let passphrase = vox_core::node::passphrase::generate(PASSPHRASE_GROUPS)?;
    let before: Vec<Digest32> = node.view().channels.iter().map(|c| c.channel_id).collect();
    let out = node
        .apply(NodeCommand::Serve {
            local_name: name.to_owned(),
            passphrase: Secret::new(passphrase.as_bytes().to_vec()),
            port,
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

    let out = node.apply(NodeCommand::Invite { channel_id }).await;
    if !out.is_done() {
        return Err(AppError::Usage(format!("cannot mint an address: {out}")));
    }
    let url = loop {
        match node.next_event().await {
            Some(NodeEvent::InviteLink { url, .. }) => break url,
            Some(ref other) => say_if_it_explains_a_failure(other),
            None => return Err(AppError::Usage("the node stopped".into())),
        }
    };

    let endpoint = at.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], port)));
    println!("room       {}", b32_encode(&channel_id));
    println!("address    {url}");
    println!("passphrase {}", passphrase.as_str());
    println!("           ^ send this by a different channel than the address");
    println!();
    println!(
        "serving {endpoint} at port {port} of {}",
        vox_hostname(&channel_id)
    );
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

    // Until interrupted: report who reaches the service. The service itself cannot say
    // — every Vox client arrives at it from loopback (ADR-017 decision 6).
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            event = node.next_event() => match event {
                Some(NodeEvent::TunnelServed { client, service_tag, .. }) => {
                    println!("vox: {} reached {service_tag:?}", crate::ident::author_id(&client));
                }
                Some(NodeEvent::PeerJoined { peer, .. }) => {
                    println!("vox: {} joined", crate::ident::author_id(&peer));
                }
                Some(ref other) => say_if_it_explains_a_failure(other),
                None => return Err(AppError::Usage("the node stopped".into())),
            },
        }
    }
    println!("vox: stopping");
    let _ = node.apply(NodeCommand::Shutdown).await;
    Ok(())
}

/// `vox connect <address>` — join the room an address names, and print the name its
/// services answer on (ADR-017 decision 4).
///
/// One-shot: joining is a durable act recorded in the profile, so there is nothing to
/// keep running. What makes the printed name resolve is `vox up` (decision 5).
pub async fn connect(
    node: &NodeHandle,
    url: &str,
    name: &str,
    room_passphrase: &str,
) -> Result<(), AppError> {
    let out = node
        .apply(NodeCommand::JoinChannel {
            link: url.to_owned(),
            local_name: name.to_owned(),
            // Canonicalization is the node's, at its one boundary — see
            // `actor::room_passphrase`. Doing it here as well would be a second place
            // for the two sides to disagree.
            passphrase: Secret::new(room_passphrase.as_bytes().to_vec()),
        })
        .await;
    if !out.is_done() {
        return Err(AppError::Usage(why_a_join_failed(node, out).await));
    }
    let channel_id = loop {
        match node.next_event().await {
            Some(NodeEvent::Joined { channel_id, .. }) => break channel_id,
            Some(ref other) => say_if_it_explains_a_failure(other),
            None => return Err(AppError::Usage("the node stopped".into())),
        }
    };
    println!("joined. reachable as {}", vox_hostname(&channel_id));
    println!("        run `vox up` on this machine to make that name resolve");
    let _ = node.apply(NodeCommand::Shutdown).await;
    Ok(())
}

/// `vox up` — the local entry point: a SOCKS5 proxy carrying one room's services
/// (ADR-017 decision 5). Runs until interrupted.
///
/// Prints the `ProxyCommand` block rather than writing it: `~/.ssh/config` is the user's
/// file, and a tool that edits it unasked is a tool that will one day edit it wrongly.
pub async fn up(node: &NodeHandle, channel_id: Digest32, bind: SocketAddr) -> Result<(), AppError> {
    let out = node.apply(NodeCommand::Up { channel_id, bind }).await;
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
    // Wait on Ctrl-C, but keep reading events so a session cut by the host withdrawing our
    // reach says so (ADR-017 M17.11). Without this the proxy stays up and silent and the
    // person sees only `ssh` dying, which reads as a network fault and invites a retry that
    // cannot succeed.
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            ev = node.next_event() => match ev {
                Some(NodeEvent::ReachWithdrawn { port, .. }) => {
                    println!("vox: the host withdrew access to port {port} — that session was cut");
                    println!("     nothing to retry: ask them to trust this identity again");
                }
                Some(ref other) => say_if_it_explains_a_failure(other),
                None => break,
            },
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
    let advice = join_advice(match out {
        Outcome::Failed(fault) => Some(fault),
        Outcome::Done => None,
    });

    if said.is_empty() {
        format!("cannot join: {advice}")
    } else {
        format!("cannot join: {} — {advice}", said.join("; "))
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
        Some(Fault::Unreachable) => {
            "nobody who can answer for this room could be reached\n       so your passphrase was never checked — this is not a verdict on it\n       every member the board knows is offline: ask one to come online, or check\n       `vox node` on the anchor shows more than `1m` for this room"
        }
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
        Some(Fault::Locked | Fault::NoIdentity) => {
            "this profile has no unlocked identity, so there is nobody to join as\n       run `vox id` to make one"
        }
        // Joining a room this node already holds used to say `Failed(IdentityExists)`.
        Some(Fault::AlreadyMember) => Fault::AlreadyMember.explain(),
        _ => "the node did not say why, which is itself worth reporting",
    }
}

/// The fault named in a daemon's reply to a join (`"Failed(Refused)"`), for the verbs that reach
/// the node over its control socket, where only the outcome's name crosses the wire.
pub(crate) fn fault_named(reason: &str) -> Option<Fault> {
    let name = reason.trim().strip_prefix("Failed(")?.strip_suffix(')')?;
    Some(match name {
        "WrongPassphrase" => Fault::WrongPassphrase,
        "BadLink" => Fault::BadLink,
        "RoomNotOnBoard" => Fault::RoomNotOnBoard,
        "Unreachable" => Fault::Unreachable,
        "Refused" => Fault::Refused,
        "NotNetworked" => Fault::NotNetworked,
        "Locked" => Fault::Locked,
        "NoIdentity" => Fault::NoIdentity,
        "AlreadyMember" => Fault::AlreadyMember,
        _ => return None,
    })
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
    /// The anchors to reach the swarm through.
    pub anchors: vox_core::nat::bootstrap::BootstrapSet,
    /// The identity passphrase.
    pub identity_passphrase: String,
    /// The room's id, or a unique prefix.
    pub room: String,
    /// The room's passphrase.
    pub room_passphrase: String,
}

/// Shared entry: open the room, run `body`, shut down.
pub async fn with_room<F, Fut>(target: RoomTarget, body: F) -> Result<(), AppError>
where
    F: FnOnce(NodeHandle, Digest32) -> Fut,
    Fut: std::future::Future<Output = Result<(), AppError>>,
{
    let (node, channel_id) = open_room(
        target.paths,
        target.listen,
        target.anchors,
        &target.identity_passphrase,
        &target.room,
        &target.room_passphrase,
    )
    .await?;
    let handle = node.clone();
    let result = body(node, channel_id).await;
    // The verbs are one-shot; `forward` shuts the node down itself when the person
    // interrupts it, and a second shutdown is harmless.
    let _ = handle.apply(NodeCommand::Shutdown).await;
    result
}

/// Read a passphrase from the terminal without echoing it (ADR-015: a passphrase is
/// never shown, never in a flag, never in the shell's history). Falls back to a plain
/// line when stdin is not a terminal, so the verbs remain scriptable through a pipe.
pub fn prompt_passphrase(what: &str) -> Result<String, AppError> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
    use std::io::{IsTerminal, Write};

    if !std::io::stdin().is_terminal() {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(AppError::Io)?;
        return Ok(line.trim_end_matches(['\n', '\r']).to_owned());
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

/// A passphrase given by flag or environment, else prompted for.
pub fn passphrase_or_prompt(given: Option<&String>, what: &str) -> Result<String, AppError> {
    match given {
        Some(p) => Ok(p.clone()),
        None => prompt_passphrase(what),
    }
}

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
) -> Result<(), AppError> {
    let target = resolve_trust_target(node, fingerprint)?;
    let out = node
        .apply(NodeCommand::Trust {
            fingerprint: target,
            petname: petname.to_owned(),
        })
        .await;
    if !out.is_done() {
        return Err(AppError::Usage(format!(
            "cannot trust that identity: {out}"
        )));
    }
    println!("vox: trusting {} as {petname:?}", short(&target));
    println!("     it may now read what you write in every room you share — now and later");
    println!("     and reach every service you bind to a room you are both in");
    println!("     `vox trust remove` undoes it and changes the lock everywhere");
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
