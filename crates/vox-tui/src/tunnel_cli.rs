//! The one-shot tunnel verbs (ADR-013, M16.1): `vox service add|remove|list`,
//! `vox grant`, `vox forward`.
//!
//! Each one spawns the node, unlocks the identity, opens the room, does its work and
//! leaves — except `forward`, which serves until interrupted, because a forwarded port
//! is only useful while something is listening on it.
//!
//! All of them need the room's passphrase, because a room's services and its
//! governance live inside the SEK-sealed store (ADR-010's double lock): there is no
//! way to offer a service, or to grant reach, without opening the room.

use std::net::SocketAddr;

use vox_core::hash::Digest32;
use vox_core::nat::bootstrap::BootstrapSet;
use vox_core::nat::multiaddr::Multiaddr;
use vox_core::nat::reachability::is_routable;
use vox_core::node::actor::{Bind, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::link::{b32_encode, vox_hostname};
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
pub fn identity_passphrase_for(paths: &Paths, given: Option<String>) -> Result<String, AppError> {
    if let Some(p) = given {
        return Ok(p);
    }
    let exists = vox_core::node::profile::Profile::exists(paths);
    if exists {
        return prompt_passphrase("identity passphrase");
    }
    println!("vox: this profile has no identity yet; creating one.");
    let first = prompt_passphrase("new identity passphrase")?;
    let again = prompt_passphrase("again")?;
    if first != again {
        return Err(AppError::Usage(
            "the two passphrases differ; nothing was created".into(),
        ));
    }
    if first.is_empty() {
        return Err(AppError::Usage("an empty identity passphrase".into()));
    }
    Ok(first)
}

/// Spawn a node and make its identity usable: unlock an existing one, or create one on
/// first use. Returns the running handle.
///
/// The room-making verbs need this instead of the room-opening preamble the one-shot
/// verbs share: `serve` is about to create a room and `connect` to join one, so neither
/// has a room to open yet.
pub async fn open_profile(
    paths: Paths,
    listen: SocketAddr,
    anchors: vox_core::nat::bootstrap::BootstrapSet,
    identity_passphrase: &str,
) -> Result<NodeHandle, AppError> {
    let existed = vox_core::node::profile::Profile::exists(&paths);
    let cfg = NodeConfig::new().bind(Bind::Addr(listen)).anchors(anchors);
    let node = Node::spawn_config(paths, cfg)?;
    let secret = Secret::new(identity_passphrase.as_bytes().to_vec());
    let out = if existed {
        node.apply(NodeCommand::Unlock { passphrase: secret }).await
    } else {
        node.apply(NodeCommand::CreateIdentity { passphrase: secret })
            .await
    };
    if !out.is_done() {
        return Err(AppError::Usage(format!(
            "cannot open this profile's identity: {out:?}"
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
    let node = Node::spawn_config(paths, cfg)?;
    let out = node
        .apply(NodeCommand::Unlock {
            passphrase: Secret::new(identity_passphrase.as_bytes().to_vec()),
        })
        .await;
    if !out.is_done() {
        return Err(AppError::Usage(format!(
            "cannot unlock this profile: {out:?}"
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
        return Err(AppError::Usage(format!("cannot open that room: {out:?}")));
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
        return Err(AppError::Usage(format!(
            "cannot offer {tag:?}: {out:?} — you need bind:{tag} in this room"
        )));
    }
    println!(
        "vox: offering {tag:?} at {local} in room {}",
        short(&channel_id)
    );
    println!("     it is dark until you `vox grant` someone dial:{tag}");
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

/// `vox grant`
pub async fn grant(
    node: &NodeHandle,
    channel_id: Digest32,
    member_prefix: &str,
    tag: &str,
    may_bind: bool,
    days: u64,
    now: u64,
) -> Result<(), AppError> {
    let view = node.view();
    let members: Vec<Digest32> = view
        .open_channels
        .iter()
        .find(|d| d.channel_id == channel_id)
        .map(|d| d.members.clone())
        .unwrap_or_default();
    let target = resolve_prefix(member_prefix, &members)?;
    let expiry = now.saturating_add(days.saturating_mul(86_400));
    let out = node
        .apply(NodeCommand::GrantTunnel {
            channel_id,
            target,
            service_tag: tag.to_owned(),
            may_bind,
            expiry,
        })
        .await;
    if !out.is_done() {
        return Err(AppError::Usage(format!("cannot grant: {out:?}")));
    }
    println!(
        "vox: {} may now dial {tag:?}{}",
        short(&target),
        if may_bind { " (and offer it)" } else { "" }
    );
    println!("     the grant is on the room's log; every member converges on it");
    Ok(())
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
    let out = node
        .apply(NodeCommand::Forward {
            channel_id,
            host,
            service_tag: tag.to_owned(),
            local,
        })
        .await;
    if !out.is_done() {
        return Err(AppError::Usage(format!(
            "cannot forward: {out:?} — is {} reachable, and do you hold dial:{tag}?",
            short(&host)
        )));
    }
    // The bound port comes back as an event, since port 0 is resolved by the OS.
    let bound = loop {
        match node.next_event().await {
            Some(NodeEvent::Forwarding { local, .. }) => break local,
            Some(_) => {}
            None => return Err(AppError::Usage("the node stopped".into())),
        }
    };
    println!("vox: {bound} → {tag:?} on {}", short(&host));
    println!("     e.g.  ssh -p {} user@{}", bound.port(), bound.ip());
    println!("     Ctrl-C to stop");
    let _ = tokio::signal::ctrl_c().await;
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
        return Err(AppError::Usage(format!(
            "cannot serve port {port}: {out:?}"
        )));
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
        return Err(AppError::Usage(format!("cannot mint an address: {out:?}")));
    }
    let url = loop {
        match node.next_event().await {
            Some(NodeEvent::InviteLink { url, .. }) => break url,
            Some(_) => {}
            None => return Err(AppError::Usage("the node stopped".into())),
        }
    };

    let endpoint = at.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], port)));
    println!("room       {}", b32_encode(&channel_id));
    println!("address    {url}");
    println!("passphrase {}", passphrase.as_str());
    println!("           ^ send this by a different channel than the address");
    println!();
    println!("serving {endpoint}. anyone who joins with both may reach it, at");
    println!("port {port} of {}", vox_hostname(&channel_id));
    println!("Ctrl-C to stop");

    // Until interrupted: report who reaches the service. The service itself cannot say
    // — every Vox client arrives at it from loopback (ADR-017 decision 6).
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            event = node.next_event() => match event {
                Some(NodeEvent::TunnelServed { client, service_tag, .. }) => {
                    println!("vox: {} reached {service_tag:?}", short(&client));
                }
                Some(NodeEvent::PeerJoined { peer, .. }) => {
                    println!("vox: {} joined", short(&peer));
                }
                Some(_) => {}
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
            passphrase: Secret::new(
                vox_core::node::passphrase::normalize(room_passphrase)
                    .as_bytes()
                    .to_vec(),
            ),
        })
        .await;
    if !out.is_done() {
        return Err(AppError::Usage(format!(
            "cannot join: {out:?} — check the address and the passphrase"
        )));
    }
    let channel_id = loop {
        match node.next_event().await {
            Some(NodeEvent::Joined { channel_id, .. }) => break channel_id,
            Some(_) => {}
            None => return Err(AppError::Usage("the node stopped".into())),
        }
    };
    println!("joined. reachable as {}", vox_hostname(&channel_id));
    println!("        run `vox up` on this machine to make that name resolve");
    let _ = node.apply(NodeCommand::Shutdown).await;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prefix_resolves_only_when_it_is_unique() {
        let a = [0x11; 32];
        let b = [0x12; 32];
        let among = vec![a, b];
        // The full rendering always resolves.
        assert_eq!(resolve_prefix(&b32_encode(&a), &among).unwrap(), a);
        // A prefix that separates them resolves; one that does not is refused with a
        // count rather than a guess.
        let (ta, tb) = (b32_encode(&a), b32_encode(&b));
        let split = ta
            .chars()
            .zip(tb.chars())
            .position(|(x, y)| x != y)
            .expect("the two renderings differ");
        assert_eq!(resolve_prefix(&ta[..=split], &among).unwrap(), a);
        assert!(resolve_prefix(&ta[..split], &among).is_err(), "ambiguous");
        assert!(resolve_prefix("", &among).is_err());
        assert!(resolve_prefix("zzzz", &among).is_err());
        // Case does not matter: a link or a screen may have been upper-cased.
        assert_eq!(resolve_prefix(&ta.to_uppercase(), &among).unwrap(), a);
    }
}
