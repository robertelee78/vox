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
use vox_core::node::actor::{Bind, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::link::b32_encode;
use vox_core::node::paths::Paths;

use crate::app::AppError;

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
