//! Resolving `.vox` names on this machine (ADR-017 decisions 4, 5 and 7; PRD-001 R20).
//!
//! ## Local names: `<node>.<room>.vox` (ADR-017 decision 7)
//! `ssh nas.family.vox` reaches the node **this machine** calls `nas` — the petname it was
//! given in this node's trust keyring when it was trusted — through the room **this
//! machine** calls `family`, its local room name. Both halves are this machine's own
//! words: nothing is published, nothing is global, and the same node reached through two
//! rooms has two names. The name resolves to *that member*, so a service any member of a
//! room offers is reachable, not only the creator's.
//!
//! A name that matches nothing, or more than one thing, is refused with a sentence
//! saying which — this machine's own names, so saying so discloses nothing. Only trusted
//! nodes have names, so a node that is not trusted cannot be named.
//!
//! The older form below, `<room-id>.vox` for a room's creator, still resolves.
//!
//! `ssh user@<52-char-base32>.vox` reaches the local SOCKS proxy with the **name**, not
//! an address (`socks5h`: the proxy resolves it). This module is what the proxy resolves
//! it with.
//!
//! ## Nothing is looked up off the machine
//! A name resolves from data this node already holds, or not at all:
//!
//! 1. the 52 characters decode to a **channelID** — nothing is consulted to learn it,
//!    because the name *is* the identifier ([`crate::node::link::channel_of_hostname`]);
//! 2. that channelID names a room this node has joined, whose **genesis** it holds;
//! 3. the genesis names the room's creator, which is its host, and that is who to dial.
//!
//! So the chain is self-certifying end to end: the name commits to the room by hash and
//! the room commits to the host by the signed genesis. There is no directory, no
//! registration, no trust-on-first-use and no global namespace — and a name for a room
//! this machine has not joined does not resolve *at all*, which is strictly more than Tor
//! offers, where any `.onion` is resolvable by anyone.
//!
//! ## Why the host is the genesis creator
//! A service room is created by the machine that offers the service (`vox serve`,
//! ADR-017 decision 4), so its creator *is* its host — and the creator is the one fact
//! about a room that is immutable, self-validating and known to every member with no
//! extra state and no advertisement to wait for.
//!
//! This holds **only for a room that carries a genesis service grant**. In a chat room
//! with a service added later the host may be any member, which the genesis does not say,
//! so such a room has no `.vox` name and is reached with `vox forward <member>/<tag>`
//! (ADR-017 decision 4). [`VoxResolver`] therefore refuses to name a room without a grant
//! rather than guessing at its creator.
//!
//! ## No DNS, because the proxy does not need it
//! Tor's client side offers three mechanisms (`doc/man/tor.1.txt`): `SocksPort`,
//! unprivileged and requiring the tool to be proxy-aware; `DNSPort` +
//! `AutomapHostsOnResolve`, which hands out a virtual address per name; and `TransPort`,
//! which "requires OS support for transparent proxies, such as BSDs' pf or Linux's
//! IPTables". Vox takes the first, which is Tor's own documented default — and under it a
//! `.vox` name never goes near a resolver, because SOCKS5 carries the hostname itself.
//! (A client misconfigured for plain `socks5` will ask the system resolver about a `.vox`
//! name first; that leak is accepted, PRD-001 R21.)

use std::collections::BTreeMap;

use crate::governance::genesis::Genesis;
use crate::hash::Digest32;
use crate::node::link::{b32_decode, b32_encode, channel_of_hostname};

/// Where a `.vox` name leads: the room whose gate applies, and the member to reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceRoom {
    /// The room.
    pub channel_id: Digest32,
    /// The member to dial: the one the name names, or for `<room-id>.vox` the genesis
    /// creator (see the module docs).
    pub host: Digest32,
}

/// One room this machine holds, as naming needs it.
#[derive(Debug, Clone, Default)]
struct NamedRoom {
    /// This machine's local name for it, as a DNS label.
    label: String,
    /// Its current members.
    members: Vec<Digest32>,
}

/// The `.vox` names this machine can resolve.
///
/// A snapshot, taken from the node when a name is asked for: it never reaches back into
/// live channel state while answering.
#[derive(Debug, Clone, Default)]
pub struct VoxResolver {
    /// `<room-id>.vox`: rooms with a genesis service grant, to their creator.
    by_channel: BTreeMap<Digest32, ServiceRoom>,
    /// `<node>.<room>.vox`: every room this machine holds, by id.
    rooms: BTreeMap<Digest32, NamedRoom>,
    /// Trusted identities and this machine's name for each, as a DNS label.
    names: BTreeMap<Digest32, String>,
}

/// A petname or room name as a DNS label: lowercase, with spaces and anything else a
/// label cannot hold turned into `-`, so `My NAS` is `my-nas.family.vox`.
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

impl VoxResolver {
    /// An empty resolver: every name is refused.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a room by its genesis, for the `<room-id>.vox` form, if it is a service room.
    ///
    /// Returns whether it was added. A room whose genesis carries no service grant is
    /// **not** added: its host is not determined by the genesis, so that form has nothing
    /// to name. Its members are still named by the `<node>.<room>.vox` form.
    pub fn insert(&mut self, genesis: &Genesis) -> bool {
        if genesis.body.service_grant.is_empty() {
            return false;
        }
        let room = ServiceRoom {
            channel_id: genesis.channel_id(),
            host: genesis.creator_pubkey().fingerprint(),
        };
        self.by_channel.insert(room.channel_id, room);
        true
    }

    /// Add a room this machine holds, under its local name, with its members.
    pub fn add_room(&mut self, channel_id: Digest32, local_name: &str, members: &[Digest32]) {
        self.rooms.insert(
            channel_id,
            NamedRoom {
                label: label_of(local_name),
                members: members.to_vec(),
            },
        );
    }

    /// Name a trusted identity, as this node's keyring does.
    pub fn name(&mut self, fingerprint: Digest32, petname: &str) {
        self.names.insert(fingerprint, label_of(petname));
    }

    /// The room a `<room-id>.vox` hostname names, or `None`.
    #[must_use]
    pub fn resolve(&self, hostname: &str) -> Option<&ServiceRoom> {
        let channel_id = channel_of_hostname(hostname).ok()?;
        self.by_channel.get(&channel_id)
    }

    /// Resolve either form, or say why not.
    ///
    /// # Errors
    /// A sentence for this machine's operator: which part of the name matched nothing,
    /// or matched more than one thing.
    pub fn lookup(&self, hostname: &str) -> Result<ServiceRoom, String> {
        let host = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        let Some(labels) = host.strip_suffix(".vox") else {
            return Err(format!("{hostname} is not a .vox name"));
        };
        match labels.split('.').collect::<Vec<_>>().as_slice() {
            [room_id] => {
                let channel_id = b32_decode(room_id, "vox hostname").map_err(|_| {
                    format!(
                        "{hostname}: name a node as <node>.<room>.vox — `{room_id}` alone is \
                         neither a room id nor a node"
                    )
                })?;
                self.by_channel.get(&channel_id).copied().ok_or_else(|| {
                    format!(
                        "{hostname}: that room id is not a room on this machine with a host of \
                         its own; name the member instead, as <node>.<room>.vox"
                    )
                })
            }
            [node, room] => {
                let channel_id = self.room(room)?;
                let host = self.node(node, room, &channel_id)?;
                Ok(ServiceRoom { channel_id, host })
            }
            _ => Err(format!("{hostname}: a .vox name is <node>.<room>.vox")),
        }
    }

    fn room(&self, label: &str) -> Result<Digest32, String> {
        // A room id works in the room's place, for a room with no usable local name.
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
        let members = self
            .rooms
            .get(channel_id)
            .map(|r| r.members.as_slice())
            .unwrap_or_default();
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

    /// How many rooms have a `<room-id>.vox` name here.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_channel.len()
    }

    /// Whether no room has a `<room-id>.vox` name here.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_channel.is_empty()
    }
}
