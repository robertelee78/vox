//! The live core binding (ADR-016 M13.5): the TUI's [`CoreHandle`] over an
//! embedded `vox-core` node.
//!
//! [`LiveCore`] holds a [`NodeHandle`] and the runtime handle the node runs on.
//! It **projects** the node's client-agnostic [`NodeView`] into the TUI's
//! [`ViewModel`] and maps each UI [`Command`] onto [`NodeCommand`]s, blocking the
//! (synchronous, crossterm-owning) UI thread on the node's typed reply. UI-local
//! state that is not the node's business lives here: which channel is on screen,
//! and unread counts (driven by the node's ordered [`NodeEvent`]s).
//!
//! Secrets cross exactly once, inward: a [`SecretString`] from a masked prompt
//! becomes the node's zeroizing [`Secret`] and is dropped. Every outcome maps to
//! the closed [`CommandStatus`] / [`UiError`] set — no free text from the core.
//!
//! Consent, reachability and sync are the node's own state, never assumed (V210-82): consent is
//! who this identity consents to on the room's log, a room is online when the node holds a
//! connection to another of its members, and sync says how many peers it is connected to.
//! Verification is shown as unverified for every other member: the node exposes no safety code to
//! compare, so there is nothing a mark could rest on, and the TUI offers no `:verify` (V210-155):
//! it offers only commands vox supports.

use std::collections::BTreeMap;

use secrecy::{ExposeSecret, SecretString};
use vox_core::hash::Digest32;
use vox_core::node::actor::{EventStreamItem, NodeHandle};
use vox_core::node::api::{Fault, NodeCommand, NodeEvent, NodeView, Outcome, Secret};

use crate::app::CoreHandle;
use crate::viewmodel::{
    ChannelSummary, ChannelView, Command, CommandStatus, MemberView, MessageView, OutboundConsent,
    Reachability, SyncStatus, UiError, Verification, ViewModel,
};

/// The TUI's binding to a running node.
pub struct LiveCore {
    node: NodeHandle,
    rt: tokio::runtime::Handle,
    /// The channel on screen (drives `ViewModel::active` and unread resets).
    active: Option<Digest32>,
    /// Unread counts per channel (incremented by `NewEntry` off-screen).
    unread: BTreeMap<Digest32, usize>,
    /// The most recent network notice to show (an invite link, a join, a consent).
    /// Public facts only — see [`ViewModel::notice`].
    notice: Option<String>,
    /// The on-screen room's timeline as last projected (V210-120). See [`Projected`].
    projected: Option<Projected>,
}

/// The on-screen room's timeline as projected for the UI, and what it was projected from.
///
/// **A frame costs what changed, not the room's history.** Every frame projected the room's whole
/// timeline again — every row's text copied, every author named — so in a long room the TUI spent
/// each frame on rows nobody had changed. A room's timeline only grows at its end, so the rows
/// added since are projected and appended; anything else (another room, a reopened one, a changed
/// keyring, which renames authors) projects it whole again.
struct Projected {
    channel_id: Digest32,
    me: Option<Digest32>,
    trusted: Vec<(Digest32, String)>,
    /// How many of the node's rows are projected, and the newest of them.
    len: usize,
    last: Option<Digest32>,
    rows: std::sync::Arc<Vec<MessageView>>,
}

impl std::fmt::Debug for LiveCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveCore")
            .field("active", &self.active.map(|a| short_id(&a)))
            .finish_non_exhaustive()
    }
}

/// Short display form of a fingerprint (first 8 hex chars).
#[must_use]
pub fn short_id(id: &Digest32) -> String {
    let mut s = String::with_capacity(8);
    for b in &id[..4] {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

impl LiveCore {
    /// A member as the TUI names it: its keyring petname, else its fingerprint marked as not in
    /// the keyring (`crate::ident`, #198).
    fn member_name(&self, fp: &Digest32) -> String {
        crate::ident::member_name(&self.node.view().trusted, fp)
    }

    /// Bind to `node`, which runs on the runtime `rt`.
    #[must_use]
    pub fn new(node: NodeHandle, rt: tokio::runtime::Handle) -> Self {
        Self {
            notice: None,
            node,
            rt,
            active: None,
            unread: BTreeMap::new(),
            projected: None,
        }
    }

    /// The underlying node handle (for the loop's lock/shutdown paths).
    #[must_use]
    pub fn node(&self) -> &NodeHandle {
        &self.node
    }

    fn secret(s: &SecretString) -> Secret {
        Secret::new(s.expose_secret().as_bytes().to_vec())
    }

    /// [`LiveCore::send`] that also watches the node's events while the command runs, calling
    /// `waiting` (on this thread, between polls) when the node says it is waiting for another vox
    /// holding the profile.
    fn send_noting(&self, cmd: NodeCommand, waiting: &mut dyn FnMut()) -> CommandStatus {
        let node = &self.node;
        let out = self.rt.block_on(async {
            let mut events = node.subscribe();
            let apply = node.apply(cmd);
            tokio::pin!(apply);
            let mut said = false;
            loop {
                tokio::select! {
                    out = &mut apply => break out,
                    ev = events.next(), if !said => match ev {
                        Some(EventStreamItem::Event(NodeEvent::WaitingForProfile)) => {
                            waiting();
                            said = true;
                        }
                        Some(_) => {}
                        None => said = true,
                    },
                }
            }
        });
        match out {
            Outcome::Done | Outcome::Bound(_) => CommandStatus::Done,
            Outcome::Failed(f) => CommandStatus::Failed(ui_error(f)),
        }
    }

    fn send(&self, cmd: NodeCommand) -> CommandStatus {
        match self.rt.block_on(self.node.apply(cmd)) {
            Outcome::Done | Outcome::Bound(_) => CommandStatus::Done,
            Outcome::Failed(f) => CommandStatus::Failed(ui_error(f)),
        }
    }

    /// Fold the node's ordered events into UI-local state (unread counts).
    fn drain_events(&mut self) {
        while let Some(ev) = self.node.try_next_event() {
            match ev {
                NodeEvent::NewEntry { channel_id, .. } => {
                    if self.active != Some(channel_id) {
                        *self.unread.entry(channel_id).or_insert(0) += 1;
                    }
                }
                NodeEvent::Locked | NodeEvent::Shutdown => {
                    self.active = None;
                }
                NodeEvent::ChannelClosed { channel_id } => {
                    if self.active == Some(channel_id) {
                        self.active = None;
                    }
                }
                NodeEvent::Unlocked | NodeEvent::ChannelOpened { .. } => {}
                // The network events, surfaced as short public notices. A link, a
                // fingerprint prefix and a count are all public facts; nothing here
                // can carry plaintext or key material (ADR-015).
                NodeEvent::InviteLink { url, .. } => {
                    self.notice = Some(format!("invite link: {url}"));
                }
                NodeEvent::AddressNote { note, .. } => {
                    self.notice = Some(note);
                }
                NodeEvent::AddressWithheld { reason, .. } => {
                    self.notice = Some(format!("no invite link: {reason}"));
                }
                NodeEvent::Joined { responder, .. } => {
                    self.notice = Some(format!("joined via {}", self.member_name(&responder)));
                }
                NodeEvent::PeerJoined { peer, .. } => {
                    self.notice = Some(format!(
                        "{} joined — they read nothing until you consent",
                        self.member_name(&peer)
                    ));
                }
                NodeEvent::Consented { target, .. } => {
                    self.notice = Some(format!("consented to {}", self.member_name(&target)));
                }
                NodeEvent::SenderKeyReceived {
                    peer, backfilled, ..
                } => {
                    self.notice = Some(if backfilled > 0 {
                        format!(
                            "{} consented to you — {backfilled} earlier message(s) now readable",
                            self.member_name(&peer)
                        )
                    } else {
                        format!("{} consented to you", self.member_name(&peer))
                    });
                }
                NodeEvent::Synced {
                    channel_id,
                    rendered,
                    ..
                } => {
                    if rendered > 0 && self.active != Some(channel_id) {
                        *self.unread.entry(channel_id).or_insert(0) += rendered as usize;
                    }
                }
                #[allow(unreachable_patterns)]
                _ => {}
            }
        }
    }

    /// The on-screen room's timeline for the UI, extended by the rows the node added since the last
    /// frame (see [`Projected`]).
    fn project_timeline(
        &mut self,
        d: &vox_core::node::api::ChannelDetail,
        me: Option<Digest32>,
        trusted: &[(Digest32, String)],
    ) -> std::sync::Arc<Vec<MessageView>> {
        let view_of = |r: &vox_core::node::api::MessageRow| MessageView {
            author: r.author,
            author_nick: if me == Some(r.author) {
                "you".to_owned()
            } else {
                crate::ident::member_name(trusted, &r.author)
            },
            // Displayed as a time of day, so seconds; the full precision is kept for ordering.
            timestamp: r.created_millis / 1_000,
            body: Some(r.text.clone()),
        };
        let from = match &self.projected {
            Some(p)
                if p.channel_id == d.channel_id
                    && p.me == me
                    && p.trusted.as_slice() == trusted
                    && p.len > 0
                    && p.len <= d.timeline.len()
                    && d.timeline.get(p.len - 1).map(|r| r.entry_hash) == p.last =>
            {
                Some(p.len)
            }
            _ => None,
        };
        let rows = match (from, self.projected.take()) {
            (Some(n), Some(mut p)) => {
                if n < d.timeline.len() {
                    // In place when the last frame's view model is gone, as it is between frames.
                    std::sync::Arc::make_mut(&mut p.rows)
                        .extend(d.timeline.iter_from(n).map(view_of));
                }
                p.rows
            }
            _ => std::sync::Arc::new(d.timeline.iter().map(view_of).collect()),
        };
        self.projected = Some(Projected {
            channel_id: d.channel_id,
            me,
            trusted: trusted.to_vec(),
            len: d.timeline.len(),
            last: d.timeline.last().map(|r| r.entry_hash),
            rows: std::sync::Arc::clone(&rows),
        });
        rows
    }

    fn project(&mut self, nv: &NodeView) -> ViewModel {
        let me = nv.identity.as_ref().map(|i| i.fingerprint);
        // A room is reachable when this node holds a connection to another of its members. A
        // closed room's members are under its lock, and this node does not sync it: offline.
        let reachability = |cid: &Digest32| {
            let online = nv.open_channels.iter().any(|d| {
                d.channel_id == *cid
                    && d.members
                        .iter()
                        .any(|m| me != Some(*m) && nv.connected_peers.binary_search(m).is_ok())
            });
            if online {
                Reachability::Online
            } else {
                Reachability::Offline
            }
        };
        let channels = nv
            .channels
            .iter()
            .map(|c| ChannelSummary {
                open: c.open,
                channel_id: c.channel_id,
                local_name: c
                    .local_name
                    .clone()
                    .unwrap_or_else(|| format!("(locked {})", short_id(&c.channel_id))),
                unread: self.unread.get(&c.channel_id).copied().unwrap_or(0),
                reachability: reachability(&c.channel_id),
            })
            .collect();
        let timeline = self.active.and_then(|cid| {
            let d = nv.open_channels.iter().find(|d| d.channel_id == cid)?;
            Some(self.project_timeline(d, me, &nv.trusted))
        });
        let active = self.active.and_then(|cid| {
            nv.open_channels
                .iter()
                .find(|d| d.channel_id == cid)
                .map(|d| ChannelView {
                    channel_id: d.channel_id,
                    local_name: d.local_name.clone(),
                    members: d
                        .members
                        .iter()
                        .map(|m| {
                            let is_me = me == Some(*m);
                            MemberView {
                                id: *m,
                                nickname: if is_me {
                                    "you".to_owned()
                                } else {
                                    crate::ident::member_name(&nv.trusted, m)
                                },
                                // Nothing to compare yet (see the module doc), so nobody else
                                // is shown verified.
                                verification: if is_me {
                                    Verification::Verified
                                } else {
                                    Verification::UnverifiedTofu
                                },
                                // Off the room's log: granted only where this node released its key,
                                // which it does only to a member its keyring trusts (V210-148).
                                outbound: if is_me || d.consented.binary_search(m).is_ok() {
                                    OutboundConsent::Granted
                                } else {
                                    OutboundConsent::Revoked
                                },
                                // Safety codes need both parties' public keys; the
                                // node exposes them with the member bundle work (M14).
                                safety_code: String::new(),
                            }
                        })
                        .collect(),
                    timeline: timeline.clone().unwrap_or_default(),
                    // **Every member held back, each on its own line** (V210-66): once one notice in
                    // the one-line hint bar, where a second was cut off at the screen's edge.
                    held_back: d
                        .equivocations
                        .iter()
                        .map(|(author, seq)| {
                            crate::ident::equivocation_notice(
                                &crate::ident::member_name(&nv.trusted, author),
                                *seq,
                            )
                        })
                        .collect(),
                    reachability: reachability(&cid),
                })
        });
        ViewModel {
            notice: self.notice.clone(),
            channels,
            active,
            sync: match nv.connected_peers.len() {
                0 => SyncStatus::Idle,
                n => SyncStatus::Connected(n),
            },
            locked: nv.locked,
            locking: nv.locking,
            mlock_active: nv.mlock_active,
            has_identity: nv.identity.is_some(),
        }
    }
}

/// Map a node [`Fault`] onto the UI's closed error set.
#[must_use]
pub fn ui_error(f: Fault) -> UiError {
    match f {
        Fault::NoIdentity => UiError::NoIdentity,
        Fault::IdentityExists => UiError::IdentityExists,
        Fault::ProfileBusy => UiError::ProfileBusy,
        Fault::Locked => UiError::Locked,
        Fault::WrongPassphrase => UiError::WrongPassphrase,
        Fault::UnknownChannel | Fault::ChannelNotOpen => UiError::ChannelNotOpen,
        Fault::TooLong => UiError::TooLong,
        Fault::KeyringFull => UiError::KeyringFull,
        Fault::Storage | Fault::IdentityFileUnwritable => UiError::Storage,
        Fault::SealedUnreadable => UiError::SealedUnreadable,
        Fault::ShuttingDown | Fault::Internal => UiError::Internal,
        // A link that will not parse is malformed input, not a network failure.
        Fault::BadLink => UiError::Malformed,
        // Nobody has published the room where we looked: a reachability problem, not bad input.
        Fault::Unreachable | Fault::BoardUnreachable | Fault::RoomNotOnBoard => {
            UiError::Unreachable
        }
        Fault::SolveTooSlow => UiError::JoinPowTooSlow,
        Fault::MembersBusy => UiError::JoinMembersBusy,
        Fault::Refused => UiError::Refused,
        Fault::NotAdmitted => UiError::NotAdmitted,
        Fault::NotConsented => UiError::NotConsented,
        Fault::NotNetworked => UiError::NotNetworked,
        Fault::AddressInUse => UiError::AddressInUse,
        Fault::AddressNotHere => UiError::AddressNotHere,
        Fault::BindFailed => UiError::BindFailed,
        Fault::AlreadyMember => UiError::AlreadyMember,
        #[allow(unreachable_patterns)]
        _ => UiError::Internal,
    }
}

impl CoreHandle for LiveCore {
    fn view(&mut self) -> ViewModel {
        self.drain_events();
        let nv = self.node.view();
        // If the channel on screen is no longer open (lock/close), fall back.
        if let Some(cid) = self.active {
            if !nv.open_channels.iter().any(|d| d.channel_id == cid) {
                self.active = None;
            }
        }
        self.project(&nv)
    }

    fn apply(&mut self, command: Command) -> CommandStatus {
        self.apply_noting(command, &mut || {})
    }

    fn apply_noting(&mut self, command: Command, waiting: &mut dyn FnMut()) -> CommandStatus {
        match command {
            Command::CreateIdentity { passphrase } => {
                // **Another vox made it first** (V210-100, as the CLI says since V210-91): this
                // node holds no identity, so one that exists now was created by another vox
                // after this one started. "Already exists" read as a stale profile.
                let had = self.node.view().identity.is_some();
                match self.send_noting(
                    NodeCommand::CreateIdentity {
                        passphrase: Self::secret(&passphrase),
                    },
                    waiting,
                ) {
                    CommandStatus::Failed(UiError::IdentityExists) if !had => {
                        CommandStatus::Failed(UiError::IdentityMadeElsewhere)
                    }
                    other => other,
                }
            }
            Command::Unlock { passphrase } => self.send_noting(
                NodeCommand::Unlock {
                    passphrase: Self::secret(&passphrase),
                },
                waiting,
            ),
            Command::Lock => {
                self.active = None;
                self.send(NodeCommand::Lock)
            }
            Command::CreateChannel {
                local_name,
                passphrase,
            } => self.send(NodeCommand::CreateChannel {
                local_name,
                passphrase: Self::secret(&passphrase),
            }),
            Command::OpenChannel {
                channel_id,
                passphrase,
            } => self.send(NodeCommand::OpenChannel {
                channel_id,
                passphrase: Self::secret(&passphrase),
            }),
            Command::CloseChannel { channel_id } => {
                if self.active == Some(channel_id) {
                    self.active = None;
                }
                self.send(NodeCommand::CloseChannel { channel_id })
            }
            Command::SelectChannel { channel_id } => {
                self.active = channel_id;
                if let Some(cid) = channel_id {
                    self.unread.remove(&cid);
                }
                CommandStatus::Done
            }
            Command::SendText { channel_id, text } => {
                self.send(NodeCommand::SendText { channel_id, text })
            }
            Command::Join {
                local_name,
                link,
                passphrase,
            } => self.send(NodeCommand::JoinChannel {
                link,
                local_name,
                passphrase: Self::secret(&passphrase),
            }),
            Command::Invite { channel_id } => self.send(NodeCommand::Invite { channel_id }),
        }
    }

    fn startup_notice(&self) -> Option<String> {
        None
    }
}
