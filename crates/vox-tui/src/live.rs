//! The live core binding (ADR-016 M13.5): the TUI's [`CoreHandle`] over an
//! embedded `vox-core` node.
//!
//! [`LiveCore`] holds a [`NodeHandle`] and the runtime handle the node runs on.
//! It **projects** the node's client-agnostic [`NodeView`] into the TUI's
//! [`ViewModel`] and maps each UI [`Command`] onto [`NodeCommand`]s, blocking the
//! (synchronous, crossterm-owning) UI thread on the node's typed reply. UI-local
//! state that is not the node's business lives here: which channel is on screen,
//! unread counts (driven by the node's ordered [`NodeEvent`]s), and this
//! device's verification marks (ADR-015: verification is a local judgement).
//!
//! Secrets cross exactly once, inward: a [`SecretString`] from a masked prompt
//! becomes the node's zeroizing [`Secret`] and is dropped. Every outcome maps to
//! the closed [`CommandStatus`] / [`UiError`] set — no free text from the core.
//!
//! M13 is single-device: reachability is honestly `Offline`, sync `Idle`, and the
//! verbs that need a network (join, consent) report `NotNetworked`. Revocation needs
//! none — it rotates a local key — so it reaches the node regardless. The ADR-015
//! visibility and block verbs report `NotAvailableYet`.

use std::collections::{BTreeMap, BTreeSet};

use secrecy::{ExposeSecret, SecretString};
use vox_core::hash::Digest32;
use vox_core::node::actor::NodeHandle;
use vox_core::node::api::{Fault, NodeCommand, NodeEvent, NodeView, Outcome, Secret};

use crate::app::CoreHandle;
use crate::viewmodel::{
    ChannelSummary, ChannelView, Command, CommandStatus, InboundVisibility, MemberView,
    MessageView, OutboundConsent, Reachability, SyncStatus, UiError, Verification, ViewModel,
};

/// The TUI's binding to a running node.
pub struct LiveCore {
    node: NodeHandle,
    rt: tokio::runtime::Handle,
    /// The channel on screen (drives `ViewModel::active` and unread resets).
    active: Option<Digest32>,
    /// Unread counts per channel (incremented by `NewEntry` off-screen).
    unread: BTreeMap<Digest32, usize>,
    /// Local verification marks: `(channel, member)` pairs this device verified.
    verified: BTreeSet<(Digest32, Digest32)>,
    /// The most recent network notice to show (an invite link, a join, a consent).
    /// Public facts only — see [`ViewModel::notice`].
    notice: Option<String>,
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
    /// Bind to `node`, which runs on the runtime `rt`.
    #[must_use]
    pub fn new(node: NodeHandle, rt: tokio::runtime::Handle) -> Self {
        Self {
            notice: None,
            node,
            rt,
            active: None,
            unread: BTreeMap::new(),
            verified: BTreeSet::new(),
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

    fn send(&self, cmd: NodeCommand) -> CommandStatus {
        match self.rt.block_on(self.node.apply(cmd)) {
            Outcome::Done => CommandStatus::Done,
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
                NodeEvent::Joined { responder, .. } => {
                    self.notice = Some(format!("joined via {}", short_id(&responder)));
                }
                NodeEvent::PeerJoined { peer, .. } => {
                    self.notice = Some(format!(
                        "{} joined — they read nothing until you consent",
                        short_id(&peer)
                    ));
                }
                NodeEvent::Consented { target, .. } => {
                    self.notice = Some(format!("consented to {}", short_id(&target)));
                }
                NodeEvent::SenderKeyReceived {
                    peer, backfilled, ..
                } => {
                    self.notice = Some(if backfilled > 0 {
                        format!(
                            "{} consented to you — {backfilled} earlier message(s) now readable",
                            short_id(&peer)
                        )
                    } else {
                        format!("{} consented to you", short_id(&peer))
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

    fn project(&self, nv: &NodeView) -> ViewModel {
        let me = nv.identity.as_ref().map(|i| i.fingerprint);
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
                // M13: no network — never claim otherwise.
                reachability: Reachability::Offline,
            })
            .collect();
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
                                nickname: if is_me { "you".to_owned() } else { short_id(m) },
                                verification: if is_me || self.verified.contains(&(cid, *m)) {
                                    Verification::Verified
                                } else {
                                    Verification::UnverifiedTofu
                                },
                                outbound: OutboundConsent::Granted,
                                inbound: InboundVisibility::Visible,
                                blocked: false,
                                // Safety codes need both parties' public keys; the
                                // node exposes them with the member bundle work (M14).
                                safety_code: String::new(),
                            }
                        })
                        .collect(),
                    timeline: d
                        .timeline
                        .iter()
                        .map(|r| MessageView {
                            author: r.author,
                            author_nick: if me == Some(r.author) {
                                "you".to_owned()
                            } else {
                                short_id(&r.author)
                            },
                            timestamp: r.created_secs,
                            body: Some(r.text.clone()),
                        })
                        .collect(),
                    reachability: Reachability::Offline,
                })
        });
        ViewModel {
            notice: self.notice.clone(),
            channels,
            active,
            sync: SyncStatus::Idle,
            locked: nv.locked,
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
        Fault::Locked => UiError::Locked,
        Fault::WrongPassphrase => UiError::WrongPassphrase,
        Fault::UnknownChannel | Fault::ChannelNotOpen => UiError::ChannelNotOpen,
        Fault::TooLong => UiError::TooLong,
        Fault::Storage => UiError::Storage,
        Fault::ShuttingDown | Fault::Internal => UiError::Internal,
        // A link that will not parse is malformed input, not a network failure.
        Fault::BadLink => UiError::Malformed,
        Fault::Unreachable => UiError::Unreachable,
        Fault::Refused => UiError::Refused,
        Fault::NotConsented => UiError::NotConsented,
        Fault::NotNetworked => UiError::NotNetworked,
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
        match command {
            Command::CreateIdentity { passphrase } => self.send(NodeCommand::CreateIdentity {
                passphrase: Self::secret(&passphrase),
            }),
            Command::Unlock { passphrase } => self.send(NodeCommand::Unlock {
                passphrase: Self::secret(&passphrase),
            }),
            Command::Lock => {
                self.active = None;
                self.send(NodeCommand::Lock)
            }
            Command::CreateChannel {
                local_name,
                passphrase,
                deniable,
            } => {
                if deniable {
                    // ADR-009 is implemented but not enabled for shipping.
                    return CommandStatus::Failed(UiError::NotAvailableYet);
                }
                self.send(NodeCommand::CreateChannel {
                    local_name,
                    passphrase: Self::secret(&passphrase),
                })
            }
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
            Command::MarkVerified { channel_id, member } => {
                self.verified.insert((channel_id, member));
                CommandStatus::Done
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
            // ADR-007: consent is per-sender and human-initiated. This is the human
            // act; the node delivers the sender key and records the grant.
            Command::GrantConsent { channel_id, member } => self.send(NodeCommand::Consent {
                channel_id,
                target: member,
            }),
            // ADR-007 revocation: rotating this identity's sender key to a generation
            // the member holds no key for. Forward-only, and honest about it — what
            // they already received is not recalled.
            Command::RevokeConsent { channel_id, member } => self.send(NodeCommand::Revoke {
                channel_id,
                target: member,
            }),
            Command::SetVisibility { .. } | Command::Block { .. } | Command::Unblock { .. } => {
                CommandStatus::Failed(UiError::NotAvailableYet)
            }
        }
    }

    fn startup_notice(&self) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vox_core::atrest::sek::Argon2Profile;
    use vox_core::node::actor::Node;
    use vox_core::node::paths::Paths;

    fn live(tmp: &tempfile::TempDir) -> (tokio::runtime::Runtime, LiveCore) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let paths = Paths::resolve("t", Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();
        let clock: vox_core::node::actor::Clock = std::sync::Arc::new(|| 1_700_000_000);
        // The production Argon2id profile (the reduced one is `cfg(test)`-only inside
        // vox-core by design): ~0.3 s per derivation in release, ~4.6 s in debug —
        // hence `#[ignore]` below; CI runs it in release.
        let node = rt
            .block_on(async { Node::spawn_with(paths, clock, Argon2Profile::default()) })
            .unwrap();
        let core = LiveCore::new(node, rt.handle().clone());
        (rt, core)
    }

    fn secret(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    #[test]
    #[ignore = "production Argon2id (4 derivations ≈ 20 s in debug); CI runs it in release"]
    fn live_core_projects_the_single_device_lifecycle() {
        let tmp = tempfile::tempdir().unwrap();
        let (_rt, mut core) = live(&tmp);
        assert!(
            core.startup_notice().is_none(),
            "a live core announces nothing"
        );
        let vm = core.view();
        assert!(!vm.has_identity && vm.locked && vm.channels.is_empty());

        assert_eq!(
            core.apply(Command::CreateIdentity {
                passphrase: secret("id")
            }),
            CommandStatus::Done
        );
        assert_eq!(
            core.apply(Command::CreateIdentity {
                passphrase: secret("id")
            }),
            CommandStatus::Failed(UiError::IdentityExists)
        );
        let vm = core.view();
        assert!(vm.has_identity && !vm.locked);

        assert_eq!(
            core.apply(Command::CreateChannel {
                local_name: "fam".into(),
                passphrase: secret("ch"),
                deniable: false
            }),
            CommandStatus::Done
        );
        assert_eq!(
            core.apply(Command::CreateChannel {
                local_name: "d".into(),
                passphrase: secret("ch"),
                deniable: true
            }),
            CommandStatus::Failed(UiError::NotAvailableYet)
        );
        let vm = core.view();
        assert_eq!(vm.channels.len(), 1);
        let cid = vm.channels[0].channel_id;
        assert!(vm.channels[0].open);
        assert_eq!(vm.channels[0].local_name, "fam");
        assert_eq!(
            vm.channels[0].reachability,
            Reachability::Offline,
            "M13 never claims a network"
        );
        assert!(vm.active.is_none(), "nothing on screen until selected");

        // Select → active projected with members and timeline; unread resets.
        assert_eq!(
            core.apply(Command::SelectChannel {
                channel_id: Some(cid)
            }),
            CommandStatus::Done
        );
        assert_eq!(
            core.apply(Command::SendText {
                channel_id: cid,
                text: "hi".into()
            }),
            CommandStatus::Done
        );
        let vm = core.view();
        let active = vm.active.as_ref().unwrap();
        assert_eq!(active.local_name, "fam");
        assert_eq!(active.members.len(), 1);
        assert_eq!(active.members[0].nickname, "you");
        assert_eq!(active.members[0].verification, Verification::Verified);
        assert_eq!(active.timeline.len(), 1);
        assert_eq!(active.timeline[0].body.as_deref(), Some("hi"));
        assert_eq!(active.timeline[0].author_nick, "you");
        assert_eq!(
            vm.channels[0].unread, 0,
            "on-screen channel accrues no unread"
        );

        // Off-screen: a new entry counts as unread; selecting clears it.
        assert_eq!(
            core.apply(Command::SelectChannel { channel_id: None }),
            CommandStatus::Done
        );
        assert_eq!(
            core.apply(Command::SendText {
                channel_id: cid,
                text: "later".into()
            }),
            CommandStatus::Done
        );
        let vm = core.view();
        assert_eq!(vm.channels[0].unread, 1);
        assert!(vm.active.is_none());
        assert_eq!(
            core.apply(Command::SelectChannel {
                channel_id: Some(cid)
            }),
            CommandStatus::Done
        );
        assert_eq!(core.view().channels[0].unread, 0);

        // Consent is wired to the node now (M14.7g); this core has no network, so the
        // node says so rather than the client pretending the verb does not exist.
        assert_eq!(
            core.apply(Command::GrantConsent {
                channel_id: cid,
                member: [1; 32]
            }),
            CommandStatus::Failed(UiError::NotNetworked)
        );
        // Revocation reaches the node now (M18.1) and needs no network — so on a
        // single-device channel with nobody consented to, the honest answer is that
        // there is nothing to revoke.
        assert_eq!(
            core.apply(Command::RevokeConsent {
                channel_id: cid,
                member: [1; 32]
            }),
            CommandStatus::Failed(UiError::NotConsented)
        );

        // Lock: locked, active cleared, channel listed closed by short id.
        assert_eq!(core.apply(Command::Lock), CommandStatus::Done);
        let vm = core.view();
        assert!(vm.locked && vm.active.is_none());
        assert!(!vm.channels[0].open);
        assert!(vm.channels[0].local_name.starts_with("(locked "));
        assert_eq!(
            core.apply(Command::SendText {
                channel_id: cid,
                text: "x".into()
            }),
            CommandStatus::Failed(UiError::ChannelNotOpen)
        );
        assert_eq!(
            core.apply(Command::Unlock {
                passphrase: secret("wrong")
            }),
            CommandStatus::Failed(UiError::WrongPassphrase)
        );
        assert_eq!(
            core.apply(Command::Unlock {
                passphrase: secret("id")
            }),
            CommandStatus::Done
        );
        assert_eq!(
            core.apply(Command::OpenChannel {
                channel_id: cid,
                passphrase: secret("ch")
            }),
            CommandStatus::Done
        );
        assert_eq!(
            core.apply(Command::SelectChannel {
                channel_id: Some(cid)
            }),
            CommandStatus::Done
        );
        assert_eq!(core.view().active.as_ref().unwrap().timeline.len(), 2);
        assert_eq!(
            core.apply(Command::CloseChannel { channel_id: cid }),
            CommandStatus::Done
        );
        assert!(core.view().active.is_none());
    }

    #[test]
    fn short_id_is_eight_hex_chars() {
        assert_eq!(short_id(&[0xAB; 32]), "abababab");
    }
    #[test]
    fn the_network_verbs_reach_the_node_and_the_unimplemented_ones_say_so() {
        // The M14 verbs are wired: a bad link is refused *by the node* (BadLink),
        // which proves the command reached it rather than being stubbed out.
        let tmp = tempfile::tempdir().unwrap();
        let (rt, mut core) = live(&tmp);
        let _guard = rt.enter();
        assert_eq!(
            core.apply(Command::CreateIdentity {
                passphrase: SecretString::from("id-pp".to_owned())
            }),
            CommandStatus::Done
        );
        let joined = core.apply(Command::Join {
            local_name: "team".into(),
            link: "not-a-vox-link".into(),
            passphrase: SecretString::from("ch-pp".to_owned()),
        });
        assert_eq!(
            joined,
            CommandStatus::Failed(UiError::Malformed),
            "a malformed link is refused by the node, not stubbed"
        );
        // This core's node is not networked (the test helper spawns it without a
        // listen address), and consent and invite say exactly that rather than a
        // placeholder — the node answered.
        assert_eq!(
            core.apply(Command::GrantConsent {
                channel_id: [3; 32],
                member: [4; 32],
            }),
            CommandStatus::Failed(UiError::NotNetworked)
        );
        assert_eq!(
            core.apply(Command::Invite {
                channel_id: [3; 32]
            }),
            CommandStatus::Failed(UiError::NotNetworked)
        );
        // Revocation reaches the node (M18.1). Unlike every other verb here it does
        // **not** need the network — rotating the sender key and recording the fact
        // are local acts, and the re-keys follow when peers are reachable — so the
        // only thing missing is the channel.
        assert_eq!(
            core.apply(Command::RevokeConsent {
                channel_id: [3; 32],
                member: [4; 32],
            }),
            CommandStatus::Failed(UiError::ChannelNotOpen)
        );
        // The ADR-015 visibility verbs are still honestly reported as not available
        // rather than silently accepted.
        for cmd in [
            Command::Block {
                channel_id: [3; 32],
                member: [4; 32],
            },
            Command::Unblock {
                channel_id: [3; 32],
                member: [4; 32],
            },
        ] {
            assert_eq!(
                core.apply(cmd),
                CommandStatus::Failed(UiError::NotAvailableYet)
            );
        }
    }
}
