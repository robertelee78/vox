//! Resolving `.vox` names on this machine (ADR-017 decision 12; V030-25).
//!
//! ## Only `<service>.<node>.<room>.vox` connects
//! A node shares a service with a room, and that service is reached as
//! `<service>.<node>.<room>.vox`, and only that way:
//!
//! - **`<service>`** is the name the sharing node gave the service (`vox serve nas-ssh=22`), or the
//!   service's fingerprint ([`crate::governance::share::service_fingerprint`]).
//! - **`<node>`** is **this machine's** alias for the sharing node — the name it was given in this
//!   node's trust keyring — or its fingerprint.
//! - **`<room>`** is **this machine's** alias for the room — its local name — or its id.
//!
//! The aliases are local pointers to a fingerprint, like a CNAME, meaningful only here: two
//! machines may call the same node different things and both reach the same service. Nothing is
//! published, registered or global.
//!
//! **Nothing shorter is an address.** "You can't ever ssh to a room", and "you can't ever ssh to a
//! node" (decider, 2026-10-02): `<room>.vox`, `<node>.<room>.vox` and the old `<room-id>.vox`
//! resolve to nothing. The answer names no service and lists nothing; the client gets no
//! connection.
//!
//! A three-part name whose words match nothing here, or more than one thing, is refused with a
//! sentence saying which, for this machine's operator only: they are this machine's own words, so
//! saying so discloses nothing.
//!
//! The name resolves to a room, a member and a service name, and the tunnel asks that member for
//! the service by name. Whether it is offered, and whether this node may reach it, is the
//! **host's** decision alone (ADR-017 decision 3): resolving grants nothing.
//!
//! ## Nothing is looked up off the machine
//! A name resolves from data this node already holds — its rooms, their members and the shares
//! their logs carry, and its keyring — or not at all.
//!
//! ## No DNS, because the proxy does not need it
//! Vox takes Tor's documented default, a `SocksPort`: under it a `.vox` name never goes near a
//! resolver, because SOCKS5 carries the hostname itself. (A client misconfigured for plain
//! `socks5` will ask the system resolver about a `.vox` name first; that leak is accepted,
//! PRD-001 R21.)

use std::collections::BTreeMap;

use crate::governance::share::service_fingerprint;
use crate::hash::Digest32;
use crate::node::link::{b32_decode, b32_encode};

/// Where a `.vox` address leads: the room whose gate applies, the member to reach, and the
/// service to ask it for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRoom {
    /// The room.
    pub channel_id: Digest32,
    /// The member sharing the service.
    pub host: Digest32,
    /// The service's tag, as the host's gate looks it up: its name, or `udp/<name>` for a
    /// service its sharer stated is UDP (ADR-022 decision 6).
    pub service: String,
    /// What the room's log says of the share (PRD-001 R23: a refusal is immediate).
    pub share: ShareState,
}

/// What this node's copy of a room's log says of the share an address names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareState {
    /// The log carries it.
    Stated,
    /// The room has synced since this node joined it, and its log carries no such share: the
    /// address leads nowhere, and a forward says so at once.
    Absent,
    /// The room has not synced since this node joined it: the statement may still be on its way.
    NotYetKnown,
}

/// One room this machine holds, as naming needs it.
#[derive(Debug, Clone, Default)]
struct NamedRoom {
    /// This machine's local name for it, as a DNS label.
    label: String,
    /// Its current members.
    members: Vec<Digest32>,
    /// Whether it has synced since this node joined it.
    synced: bool,
    /// The services its log says are shared: `(sharer, name, udp)`.
    shares: Vec<(Digest32, String, bool)>,
}

/// The `.vox` names this machine can resolve.
///
/// A snapshot, taken from the node when a name is asked for: it never reaches back into
/// live channel state while answering.
#[derive(Debug, Clone, Default)]
pub struct VoxResolver {
    /// Every room this machine holds, by id.
    rooms: BTreeMap<Digest32, NamedRoom>,
    /// Trusted identities and this machine's name for each, as a DNS label.
    names: BTreeMap<Digest32, String>,
}

/// A petname or room name as a DNS label: lowercase, with spaces and anything else a
/// label cannot hold turned into `-`, so `My NAS` is `my-nas`.
#[must_use]
pub fn label_of(name: &str) -> String {
    let mut out = String::new();
    for c in name.trim().chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_owned()
}

/// What a name that is not `<service>.<node>.<room>.vox` resolves to: nothing. The sentence is
/// for this machine's operator and names no service.
fn nothing(hostname: &str) -> String {
    format!("{hostname} resolves to nothing: a .vox address is <service>.<node>.<room>.vox")
}

impl VoxResolver {
    /// An empty resolver: every name resolves to nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a room this machine holds, under its local name, with its members.
    pub fn add_room(&mut self, channel_id: Digest32, local_name: &str, members: &[Digest32]) {
        let room = self.rooms.entry(channel_id).or_default();
        room.label = label_of(local_name);
        room.members = members.to_vec();
    }

    /// Record whether `channel_id` has synced since this node joined it.
    pub fn set_synced(&mut self, channel_id: Digest32, synced: bool) {
        self.rooms.entry(channel_id).or_default().synced = synced;
    }

    /// Record that `host` shares `name` in `channel_id`, so its fingerprint resolves.
    pub fn add_share(&mut self, channel_id: Digest32, host: Digest32, name: &str, udp: bool) {
        self.rooms
            .entry(channel_id)
            .or_default()
            .shares
            .push((host, name.to_owned(), udp));
    }

    /// Name a trusted identity, as this node's keyring does.
    pub fn name(&mut self, fingerprint: Digest32, petname: &str) {
        self.names.insert(fingerprint, label_of(petname));
    }

    /// How this machine names `node`: its alias when it has one, else its fingerprint.
    #[must_use]
    pub fn alias_of(&self, node: &Digest32) -> String {
        match self.names.get(node) {
            Some(alias) if !alias.is_empty() => alias.clone(),
            _ => b32_encode(node),
        }
    }

    /// The address of `name` shared by `host` in `channel_id`, **as this machine writes it**:
    /// its own alias for the node and the room where it has a unique one, the fingerprint and
    /// the room id where it has not.
    #[must_use]
    pub fn address_of(&self, channel_id: &Digest32, host: &Digest32, name: &str) -> String {
        let node = match self.names.get(host) {
            Some(alias)
                if !alias.is_empty()
                    && self.names.values().filter(|n| *n == alias).count() == 1 =>
            {
                alias.clone()
            }
            _ => b32_encode(host),
        };
        let room = match self.rooms.get(channel_id) {
            Some(r)
                if !r.label.is_empty()
                    && self.rooms.values().filter(|o| o.label == r.label).count() == 1 =>
            {
                r.label.clone()
            }
            _ => b32_encode(channel_id),
        };
        format!("{name}.{node}.{room}.vox")
    }

    /// Resolve `<service>.<node>.<room>.vox`, or say why it leads nowhere.
    ///
    /// # Errors
    /// A sentence for this machine's operator: that the name is no address at all, or which of
    /// its three parts matched nothing here, or more than one thing.
    pub fn lookup(&self, hostname: &str) -> Result<ServiceRoom, String> {
        let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        let Some(labels) = host.strip_suffix(".vox") else {
            return Err(format!("{hostname} is not a .vox name"));
        };
        let [service, node, room] = labels.split('.').collect::<Vec<_>>()[..] else {
            return Err(nothing(hostname));
        };
        if service.is_empty() {
            return Err(nothing(hostname));
        }
        let channel_id = self.room(room)?;
        let host = self.node(node, room, &channel_id)?;
        let (service, stated) = self.service(service, &channel_id, &host);
        let share = if stated {
            ShareState::Stated
        } else if self.rooms.get(&channel_id).is_some_and(|r| r.synced) {
            ShareState::Absent
        } else {
            ShareState::NotYetKnown
        };
        Ok(ServiceRoom {
            channel_id,
            host,
            service,
            share,
        })
    }

    /// The service a `<service>` label names, as the tag the host's gate looks it up by: a
    /// share's name when the label is that share's name or fingerprint (`udp/<name>` for a UDP
    /// share), else the label as the name; and whether the log states it. Whether the host offers
    /// it is the host's to say.
    fn service(&self, label: &str, channel_id: &Digest32, host: &Digest32) -> (String, bool) {
        let fp = b32_decode(label, "vox service").ok();
        let share = self.rooms.get(channel_id).and_then(|r| {
            r.shares.iter().find(|(h, n, _)| {
                h == host && (n == label || fp == Some(service_fingerprint(channel_id, h, n)))
            })
        });
        match share {
            Some((_, name, true)) => (format!("udp/{name}"), true),
            Some((_, name, false)) => (name.clone(), true),
            None => (label.to_owned(), false),
        }
    }

    fn room(&self, label: &str) -> Result<Digest32, String> {
        // A room id works in the room's place.
        if let Ok(id) = b32_decode(label, "vox room") {
            if self.rooms.contains_key(&id) {
                return Ok(id);
            }
        }
        let hits: Vec<Digest32> = self
            .rooms
            .iter()
            .filter(|(_, r)| r.label == label)
            .map(|(id, _)| *id)
            .collect();
        match hits.as_slice() {
            [one] => Ok(*one),
            [] => {
                let known: Vec<&str> = self.rooms.values().map(|r| r.label.as_str()).collect();
                Err(format!(
                    "no room on this machine is called `{label}` (its rooms: {})",
                    if known.is_empty() {
                        "none".to_owned()
                    } else {
                        known.join(", ")
                    }
                ))
            }
            many => Err(format!(
                "`{label}` is the name of {} rooms on this machine; use one's id instead \
                 (`vox room list`)",
                many.len()
            )),
        }
    }

    fn node(
        &self,
        label: &str,
        room_label: &str,
        channel_id: &Digest32,
    ) -> Result<Digest32, String> {
        let members = self
            .rooms
            .get(channel_id)
            .map(|r| r.members.as_slice())
            .unwrap_or_default();
        // A node's fingerprint works in its alias's place.
        if let Ok(fp) = b32_decode(label, "vox node") {
            return if members.contains(&fp) {
                Ok(fp)
            } else {
                Err(format!("that node is not a member of `{room_label}`"))
            };
        }
        let named: Vec<Digest32> = self
            .names
            .iter()
            .filter(|(_, n)| n.as_str() == label)
            .map(|(fp, _)| *fp)
            .collect();
        if named.is_empty() {
            return Err(format!(
                "no node you trust is called `{label}` — only trusted nodes have names here \
                 (`vox trust add <fingerprint> --name {label}`)"
            ));
        }
        let hits: Vec<Digest32> = named
            .into_iter()
            .filter(|fp| members.contains(fp))
            .collect();
        match hits.as_slice() {
            [one] => Ok(*one),
            [] => Err(format!(
                "`{label}` is a node you trust, but not a member of `{room_label}`"
            )),
            many => Err(format!(
                "`{label}` names {} nodes you trust in `{room_label}`; rename one \
                 (`vox trust rename <fingerprint> <name>`): {}",
                many.len(),
                many.iter()
                    .map(|fp| b32_encode(fp).chars().take(12).collect::<String>())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }
}
