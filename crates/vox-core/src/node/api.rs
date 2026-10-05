//! The node's typed boundary (ADR-016 §"The `Node`: one actor, one writer, one
//! secrets boundary").
//!
//! These are the only types that cross between the node and a client. They carry
//! **public facts and already-rendered text only** — fingerprints, names,
//! timestamps, decrypted message bodies, enum state — never a key, an SKDM, a
//! SEK, a `self_seed` or a passphrase. The one secret-bearing *input* (a
//! passphrase) is a [`Secret`], a zeroizing buffer the node wipes after use.
//! Outcomes are a closed enum ([`Outcome`] / [`Fault`]) with no free text, so the
//! status channel cannot leak plaintext or secret detail (the ADR-015 rule,
//! applied at the node).
//!
//! Clients project their own UI model from a [`NodeView`]: the Rust TUI maps it
//! to its `ViewModel`, the macOS client to its SwiftUI state. The node never
//! depends on a UI type.

use zeroize::Zeroizing;

use crate::hash::Digest32;

/// A secret input (passphrase bytes); zeroized on drop.
pub type Secret = Zeroizing<Vec<u8>>;

/// Public facts about the profile's identity (available while locked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityInfo {
    /// The composite-identity fingerprint.
    pub fingerprint: Digest32,
    /// Creation time (seconds since the Unix epoch).
    pub created: u64,
}

/// A channel known to this profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelSummary {
    /// The channelID.
    pub channel_id: Digest32,
    /// The local name — known only once the channel is **open** (it lives inside
    /// the SEK-sealed manifest, ADR-010 double-lock), else `None`.
    pub local_name: Option<String>,
    /// Whether the channel is open (SEK unlocked) in this session.
    pub open: bool,
    /// Number of accepted log entries (0 while closed).
    pub entries: u64,
    /// Whether the room is over for this node, in plain words (V030-08): this identity left it,
    /// or it ended. `None` while it is going on, and while it is closed.
    pub over: Option<String>,
}

/// A rendered, render-gated message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRow {
    /// The ADR-008 entry hash.
    pub entry_hash: Digest32,
    /// The author's fingerprint.
    pub author: Digest32,
    /// The author's recorded send time, **milliseconds** since the Unix epoch.
    ///
    /// Milliseconds because this value orders ADR-020 work-board claims, and whole seconds put
    /// two agents racing for the same item in the same bucket, where the winner fell to a hash
    /// tie-break instead of to who asked first. Divide by 1000 for display.
    pub created_millis: u64,
    /// The text.
    pub text: String,
    /// When this node rendered it, as a number that only grows; local, and not the
    /// room's order ([`crate::node::channel::Rendered::arrival`]).
    pub arrival: u64,
    /// It took its place above a row this node had already shown: it arrived late
    /// (ADR-023 decision 1).
    pub late: bool,
    /// **Not received yet** (V030-10): this node holds the message's signed envelope and is still
    /// asking for its body, which has not expired here. `text` is empty and `arrival` is `0`, so a
    /// read from a cursor never yields it; the message replaces it when the body arrives.
    pub owed: bool,
}

/// What a person is shown in place of a message whose body is owed ([`MessageRow::owed`],
/// V030-10).
pub const NOT_RECEIVED_YET: &str = "(not received yet)";

/// Rows the view carries, oldest first, in shared chunks (V210-120): a room's timeline, and the
/// positions of its structured posts.
///
/// **A new message costs what it adds, not what came before it.** Each new row was published by
/// rebuilding the room's whole timeline, so the work a node did per message grew with the room's
/// history: a member reading a long room behind a burst spent seconds on rows nobody had changed.
/// Rows are held in shared, immutable chunks. A message adds a small chunk, small chunks merge
/// into larger ones only up to [`Timeline::CHUNK`] rows, and a full chunk is never copied again.
/// So an append copies at most a chunk's worth of rows, and a clone of the view copies one pointer
/// per chunk.
#[derive(Clone)]
pub struct Chunks<T> {
    chunks: Vec<std::sync::Arc<[T]>>,
    len: usize,
}

/// A room's rendered timeline: [`Chunks`] of its rows.
pub type Timeline = Chunks<MessageRow>;

impl<T> Default for Chunks<T> {
    fn default() -> Self {
        Self {
            chunks: Vec::new(),
            len: 0,
        }
    }
}

impl<T: Clone> Chunks<T> {
    /// The most rows a chunk holds before it is frozen.
    pub const CHUNK: usize = 1024;

    /// How many rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether there are no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Every row, oldest first.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &T> + '_ {
        self.chunks.iter().flat_map(|c| c.iter())
    }

    /// Every row from position `start` on, oldest first, skipping whole chunks before it.
    pub fn iter_from(&self, start: usize) -> impl Iterator<Item = &T> + '_ {
        let mut skip = start;
        self.chunks.iter().flat_map(move |c| {
            let from = skip.min(c.len());
            skip -= from;
            c[from..].iter()
        })
    }

    /// The row at position `i`, oldest first.
    #[must_use]
    pub fn get(&self, mut i: usize) -> Option<&T> {
        for c in &self.chunks {
            if i < c.len() {
                return c.get(i);
            }
            i -= c.len();
        }
        None
    }

    /// The oldest row.
    #[must_use]
    pub fn first(&self) -> Option<&T> {
        self.chunks.first().and_then(|c| c.first())
    }

    /// The newest row.
    #[must_use]
    pub fn last(&self) -> Option<&T> {
        self.chunks.last().and_then(|c| c.last())
    }

    /// This timeline with `rows` added after its newest row. Nothing already held is copied but
    /// the open chunks that the new rows merge into, which are at most [`Self::CHUNK`] rows.
    #[must_use]
    pub fn appended(&self, rows: impl IntoIterator<Item = T>) -> Self {
        let added: std::sync::Arc<[T]> = rows.into_iter().collect();
        if added.is_empty() {
            return self.clone();
        }
        let mut next = self.clone();
        next.len += added.len();
        next.chunks.push(added);
        // Merge the newest chunks while the older of the two is no larger than the newer, as a
        // binary counter carries, and never into a chunk past `CHUNK`: chunks stay few, and an
        // append copies a bounded number of rows.
        while let [.., older, newer] = next.chunks.as_slice() {
            if older.len() > newer.len() || older.len() + newer.len() > Self::CHUNK {
                break;
            }
            let merged: std::sync::Arc<[T]> = older.iter().chain(newer.iter()).cloned().collect();
            next.chunks.pop();
            next.chunks.pop();
            next.chunks.push(merged);
        }
        next
    }

    /// Whether both hold the very same chunks: equal without reading a row.
    fn shares_chunks(&self, other: &Self) -> bool {
        self.len == other.len
            && self.chunks.len() == other.chunks.len()
            && self
                .chunks
                .iter()
                .zip(&other.chunks)
                .all(|(a, b)| std::sync::Arc::ptr_eq(a, b))
    }
}

impl<T: Clone> FromIterator<T> for Chunks<T> {
    fn from_iter<I: IntoIterator<Item = T>>(rows: I) -> Self {
        let mut t = Self::default();
        let mut chunk = Vec::with_capacity(Self::CHUNK);
        for row in rows {
            chunk.push(row);
            if chunk.len() == Self::CHUNK {
                t.len += chunk.len();
                t.chunks.push(std::mem::take(&mut chunk).into());
            }
        }
        if !chunk.is_empty() {
            t.len += chunk.len();
            t.chunks.push(chunk.into());
        }
        t
    }
}

impl<'a, T: Clone> IntoIterator for &'a Chunks<T> {
    type Item = &'a T;
    type IntoIter = Box<dyn DoubleEndedIterator<Item = &'a T> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

impl<T: Clone + PartialEq> PartialEq for Chunks<T> {
    fn eq(&self, other: &Self) -> bool {
        self.shares_chunks(other) || (self.len == other.len && self.iter().eq(other.iter()))
    }
}

impl<T: Clone + Eq> Eq for Chunks<T> {}

impl<T: Clone + std::fmt::Debug> std::fmt::Debug for Chunks<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// Where a room's **structured posts** sit in its timeline (V210-120): by `type`, and by
/// operation id.
///
/// A structured post is a body that parses as a JSON object with a string `type`; it may carry an
/// operation id, a string at `data.op`. Nothing here knows what any `type` or id means: a client
/// names the types and ids it wants ([`crate::node::ipc::Request::Structured`]) and is served those
/// rows. A client that needed a room's claims, or the posts under one operation id, read every row
/// of the room for them, every time, so its work grew with the room's history. Filled as rows are
/// added, never rebuilt, and shared like the timeline.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct StructuredIndex {
    /// Positions in the timeline, oldest first, of the posts of each `type`.
    pub by_type: std::collections::BTreeMap<String, Chunks<u32>>,
    /// The posts carrying an operation id, by a hash of the id.
    pub by_op: OpRuns,
}

impl std::fmt::Debug for StructuredIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StructuredIndex")
            .field(
                "by_type",
                &self
                    .by_type
                    .iter()
                    .map(|(t, c)| (t, c.len()))
                    .collect::<Vec<_>>(),
            )
            .field("by_op", &self.by_op.len())
            .finish()
    }
}

/// `(hash of an operation id, position)` pairs in sorted runs, each run sorted by hash.
///
/// A new post's pair becomes a run of one, and the newest two runs merge while the older is no
/// longer than the newer, as a binary counter carries: so there are about log2(n) runs, an append
/// does amortized O(log n) work, a lookup is a binary search in each run, and a clone copies one
/// pointer per run. (The ids are many, one or a few per post, so a map of them would be copied
/// whole on every append the view is shared across.)
#[derive(Clone, Default, PartialEq, Eq)]
pub struct OpRuns {
    runs: Vec<std::sync::Arc<[(u64, u32)]>>,
    len: usize,
}

impl OpRuns {
    /// How many pairs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// These runs with `pairs` added.
    #[must_use]
    pub fn appended(&self, mut pairs: Vec<(u64, u32)>) -> Self {
        if pairs.is_empty() {
            return self.clone();
        }
        pairs.sort_unstable();
        let mut next = self.clone();
        next.len += pairs.len();
        next.runs.push(pairs.into());
        while let [.., older, newer] = next.runs.as_slice() {
            if older.len() > newer.len() {
                break;
            }
            let mut merged: Vec<(u64, u32)> = Vec::with_capacity(older.len() + newer.len());
            let (mut i, mut j) = (0, 0);
            while i < older.len() && j < newer.len() {
                if older[i] <= newer[j] {
                    merged.push(older[i]);
                    i += 1;
                } else {
                    merged.push(newer[j]);
                    j += 1;
                }
            }
            merged.extend_from_slice(&older[i..]);
            merged.extend_from_slice(&newer[j..]);
            next.runs.pop();
            next.runs.pop();
            next.runs.push(merged.into());
        }
        next
    }

    /// The positions of the posts whose id hashes to `hash`, in no order. A hash can collide, so
    /// a caller checks the id itself.
    #[must_use]
    pub fn find(&self, hash: u64) -> Vec<u32> {
        let mut out = Vec::new();
        for run in &self.runs {
            let from = run.partition_point(|(h, _)| *h < hash);
            out.extend(
                run[from..]
                    .iter()
                    .take_while(|(h, _)| *h == hash)
                    .map(|(_, p)| *p),
            );
        }
        out
    }
}

impl std::fmt::Debug for OpRuns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpRuns({} in {} runs)", self.len, self.runs.len())
    }
}

/// The hash an operation id is indexed by: FNV-1a, 64 bits. Not a security boundary: a collision
/// only serves a client a row it then discards.
#[must_use]
pub fn op_hash(op: &str) -> u64 {
    op.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// A structured post's `type` and operation id, or `None` for any other body.
#[must_use]
pub fn structured_kind(text: &str) -> Option<(String, Option<String>)> {
    let trimmed = text.trim_start();
    if !trimmed.starts_with('{') {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    let kind = value.get("type")?.as_str()?.to_owned();
    let op = value
        .get("data")
        .and_then(|d| d.get("op"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    Some((kind, op))
}

impl StructuredIndex {
    /// This index with the bodies of the rows at `start..` of a timeline added.
    #[must_use]
    pub fn appended<'a>(&self, start: usize, texts: impl IntoIterator<Item = &'a String>) -> Self {
        let mut by_type: std::collections::BTreeMap<String, Vec<u32>> =
            std::collections::BTreeMap::new();
        let mut ops = Vec::new();
        for (i, text) in texts.into_iter().enumerate() {
            let Some((kind, op)) = structured_kind(text) else {
                continue;
            };
            let at = u32::try_from(start + i).unwrap_or(u32::MAX);
            by_type.entry(kind).or_default().push(at);
            if let Some(op) = op {
                ops.push((op_hash(&op), at));
            }
        }
        let mut next = self.clone();
        for (kind, at) in by_type {
            let entry = next.by_type.entry(kind).or_default();
            *entry = entry.appended(at);
        }
        next.by_op = next.by_op.appended(ops);
        next
    }

    /// The positions of the posts of any type in `types`, and of those whose operation id hashes
    /// like one in `ops`, oldest first, each once.
    #[must_use]
    pub fn positions(&self, types: &[String], ops: &[String]) -> Vec<u32> {
        let mut out: Vec<u32> = types
            .iter()
            .filter_map(|t| self.by_type.get(t))
            .flat_map(|c| c.iter().copied())
            .collect();
        for op in ops {
            out.extend(self.by_op.find(op_hash(op)));
        }
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// An open channel's full state for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelDetail {
    /// The channelID.
    pub channel_id: Digest32,
    /// The local name.
    pub local_name: String,
    /// The current epoch.
    pub epoch: u64,
    /// Members, in fingerprint order.
    pub members: Vec<Digest32>,
    /// The render-gated timeline, oldest first. Shared, not copied: every clone of the view — each
    /// IPC read page takes one — used to copy every room's whole timeline (V210-71); and a new
    /// message adds its row without rebuilding the rest (V210-120).
    pub timeline: Timeline,
    /// Every entry this node holds for the channel, readable or not, in the room's one
    /// order (PRD-001 R13), each with the clock that placed it (ms). `timeline` is this
    /// sequence restricted to rendered rows.
    pub order: Vec<(Digest32, u64)>,
    /// Where its structured posts sit in `timeline`, by `type` (V210-120).
    pub structured: StructuredIndex,
    /// The services this node offers in this channel: `(service_tag, local address)`
    /// in tag order (ADR-013 Bind config — host configuration, not authorization).
    pub services: Vec<(String, std::net::SocketAddr)>,
    /// The services shared in this channel by every member, as its log says (V030-25).
    pub shares: Vec<crate::node::channel::Share>,
    /// Whether this node has completed the room's first sync since joining it (V210-164): until
    /// then its log may not yet hold what the room's members have written, shares included.
    pub synced: bool,
    /// The members this node holds back for equivocating in this room (V210-63): each
    /// `(author, seq)` at which two different messages signed by that author were seen.
    pub equivocations: Vec<(Digest32, u64)>,
    /// The room's genesis creator, its root admin (ADR-007).
    pub creator: Digest32,
    /// Who this identity consents to reading it here (ADR-007), in fingerprint order. Read off
    /// the log, so a revocation takes one out; what a client shows as consent (V210-82).
    pub consented: Vec<Digest32>,
    /// The room's admins, its creator first (V030-08): who may end it.
    pub admins: Vec<Digest32>,
    /// The other members that consent to this identity reading them here, in fingerprint order:
    /// the inbound half of `consented`, off the log the same way (V030-17).
    pub consenting: Vec<Digest32>,
    /// The retention this node applies here, seconds (`0` forever): the shorter of the room's
    /// and the node's own (ADR-023 decision 2). What `vox status` reports. Carried in the view
    /// so a reader never has to take the room's lock, which a sync session holds while it runs.
    pub retention: u64,
    /// How many generations of this node's own sender key it still holds here (PRD-001 R14).
    pub key_generations: usize,
    /// How many generations of other members' sender keys it holds here (PRD-001 R14 on the
    /// receiving side).
    pub received_key_generations: usize,
    /// Authors this node froze here for signing two entries at one position (ADR-008).
    pub frozen: Vec<Digest32>,
    /// Entries this node refused here as at or below their author's checkpoint since it opened
    /// the room (ADR-023 decision 3).
    pub refused_below_checkpoint: u64,
}

/// The node's latest-wins view (published over a `watch`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NodeView {
    /// The profile's identity, or `None` before one is created.
    pub identity: Option<IdentityInfo>,
    /// Whether the identity is locked (no signer in memory).
    pub locked: bool,
    /// Whether a lock is under way: the identity is locked and refuses new work, and the node is
    /// waiting for work that still held a secret to finish and wipe it (V210-94). `locked` turns
    /// true when it has.
    pub locking: bool,
    /// Whether every open channel's SEK is `mlock`ed (`true` when none are open).
    /// `false` surfaces the documented zeroize-only degradation (ADR-010/015).
    pub mlock_active: bool,
    /// The endpoints this node is listening on, in ADR-012 multiaddr text form —
    /// empty when it is not networked or is locked (binding needs the identity).
    /// Public information: it is what an invite link advertises.
    pub listening: Vec<String>,
    /// Every channel in the profile, in channelID order.
    pub channels: Vec<ChannelSummary>,
    /// The open channels' detail, in channelID order.
    pub open_channels: Vec<ChannelDetail>,
    /// The live forwards, in bound-address order (ADR-013 Dial).
    pub forwards: Vec<ForwardInfo>,
    /// The trust keyring: `(fingerprint, petname)` in fingerprint order, empty
    /// while locked because the keyring is sealed under the identity (ADR-020 §3).
    pub trusted: Vec<(Digest32, String)>,
    /// Peers this node currently reaches **through a relay** rather than directly.
    ///
    /// Worth surfacing rather than hiding: a relayed path means a third party is carrying
    /// the packets — it cannot read them, but it can see that two identities are talking,
    /// and it costs a hop of latency. An operator who cannot tell the difference cannot
    /// reason about either. `tailscale status` shows the same distinction for the same
    /// reason.
    pub relayed_peers: Vec<Digest32>,
    /// How many circuits this node is carrying **for other peers** right now.
    pub relaying: usize,
    /// How many peers this node currently has a live connection to, by any path.
    ///
    /// The one number that separates "this node has not finished starting", or "this node
    /// is wedged", from "this node cannot reach that particular peer". An anchor with zero
    /// is an anchor doing nothing at all, and without this nobody could see that from
    /// outside — which is how one sat wedged for an hour looking healthy.
    pub connected: usize,
    /// Those peers, in fingerprint order: which of a room's members this node reaches now
    /// (V210-82).
    pub connected_peers: Vec<Digest32>,
    /// The anchors and room hosts' boards this node holds a connection to now, each with the note
    /// said when it was made ("connected to this anchor"): what a client that subscribes after the
    /// connection was made is told first, since it missed the note itself.
    pub boards_connected: Vec<(Digest32, String)>,
    /// Every channel this node's **board** holds a genesis for — the channels it
    /// anchors, whether or not it is a member — in channelID order. What an anchor
    /// can say about itself: which rooms it serves and how many members it knows of
    /// each, never what any of them said.
    pub anchoring: Vec<AnchoredChannel>,
}

/// A live local port forwarded to a member's service (ADR-013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardInfo {
    /// The channel the capability is claimed under.
    pub channel_id: Digest32,
    /// The member hosting the service.
    pub host: Digest32,
    /// The service tag.
    pub service_tag: String,
    /// The local address accepting connections.
    pub local: std::net::SocketAddr,
}

/// A channel this node's board serves (ADR-016 M15.2a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredChannel {
    /// The channelID.
    pub channel_id: Digest32,
    /// Members the board knows by a live record: the creator, and everyone a member
    /// has vouched for.
    pub members: usize,
    /// Joiners with a live pre-join announcement.
    pub pending: usize,
    /// The address each member's live record on this board names, as the board would hand it to
    /// any member asking where that member is (V210-51, #230): what `vox node` prints so an
    /// operator — and a proof — can see which of a member's processes the board points at.
    pub holding: Vec<(Digest32, Vec<String>)>,
}

/// A command from a client to the node.
#[derive(Debug)]
pub enum NodeCommand {
    /// Create the profile's identity (fails if one exists).
    CreateIdentity {
        /// The identity passphrase.
        passphrase: Secret,
    },
    /// Check the identity passphrase without changing anything.
    ///
    /// Exists so a request arriving over the control socket can prove the caller holds
    /// the identity passphrase before it is allowed to change the trust keyring. ADR-020
    /// §7 keeps keyring edits off the socket because an agent session runs model-authored
    /// code; this is what lets the *operator* make them through a daemon they are already
    /// running, without widening that door for the agent.
    VerifyPassphrase {
        /// The identity passphrase to check.
        passphrase: Secret,
    },
    /// A keyring change (`Trust`, `TrustWith`, `Rename`, `Untrust`) whose caller has just
    /// proved the identity passphrase: [`NodeCommand::VerifyPassphrase`] answered `Done` for it.
    /// It is made whatever the keyring window says, and the window starts again (V210-159). The
    /// window is for a change made **without** the passphrase; one made with it is never asked
    /// for it again, however several checks passing at once raced to restart the window. The
    /// daemon builds it only after the check; nothing on the control socket names it.
    Proved {
        /// The keyring change. Anything else is refused as an internal fault.
        change: Box<NodeCommand>,
    },
    /// Merge more anchors into the configured set, and dial any not yet connected.
    ///
    /// The set is resolved when configuration is read, so a long-running node holds the
    /// addresses it got at startup. An anchor named by hostname — which is the point of
    /// naming one by hostname — moves when its ISP decides, and the node would keep
    /// redialling the old address for ever. This is how a re-resolved set reaches a node
    /// that is already running.
    AddAnchors {
        /// The freshly resolved anchors to merge in.
        anchors: crate::nat::bootstrap::BootstrapSet,
    },
    /// Unlock the identity.
    Unlock {
        /// The identity passphrase.
        passphrase: Secret,
    },
    /// Create a channel (needs the unlocked identity).
    CreateChannel {
        /// The local (device-only) name.
        local_name: String,
        /// The channel passphrase (the second lock factor).
        passphrase: Secret,
    },
    /// Open a channel: double-lock unwrap of its SEK.
    OpenChannel {
        /// The channelID.
        channel_id: Digest32,
        /// The channel passphrase.
        passphrase: Secret,
    },
    /// Close an open channel (wipes its SEK).
    CloseChannel {
        /// The channelID.
        channel_id: Digest32,
    },
    /// Leave a room (V210-164): say so in the room, and once another member has that, delete
    /// the room from this node (the decider, 2026-10-03: "leave deletes it"). Answered then, or
    /// with [`Fault::LeaveNotHeard`] when no member took it within 30 s; the room goes once one
    /// does.
    LeaveRoom {
        /// The channelID.
        channel_id: Digest32,
    },
    /// Make a member an admin of a room, or take it back (V030-08). Only its creator may.
    SetAdmin {
        /// The channelID.
        channel_id: Digest32,
        /// The member.
        member: Digest32,
        /// `true` to add, `false` to remove.
        admin: bool,
    },
    /// End a room for everyone (V030-08). Only its creator may.
    EndRoom {
        /// The channelID.
        channel_id: Digest32,
    },
    /// Choose a room's idle end (V030-08): it ends after `idle_secs` with nothing said in it.
    /// Only its creator may; `vox room create --idle-end` is where it does.
    ChooseIdleEnd {
        /// The channelID.
        channel_id: Digest32,
        /// The idle end, in seconds (more than 0).
        idle_secs: u64,
    },
    /// Author a text message in an open channel.
    SendText {
        /// The channelID.
        channel_id: Digest32,
        /// The text.
        text: String,
    },
    /// Produce a `vox://` invite link for a channel this node holds open, naming this
    /// node, and any anchors the room uses, as where to reach the room, with this node as
    /// responder. The link arrives as
    /// [`NodeEvent::InviteLink`]; it carries no secret (ADR-016).
    Invite {
        /// The channel to invite to.
        channel_id: Digest32,
    },
    /// Join a channel from an invite link. The passphrase is collected by the client
    /// out of band and is **never** in the link.
    JoinChannel {
        /// The `vox://` link.
        link: String,
        /// The local (device-only) name to give the channel.
        local_name: String,
        /// The channel passphrase.
        passphrase: Secret,
    },
    /// Trust an identity node-wide, under a local petname (ADR-020 §3).
    ///
    /// The decision is per **identity**, not per room: from here on, every room
    /// this node shares with `fingerprint` auto-consents to it, including rooms
    /// created later. That is what makes an agent's first contact a one-time act
    /// instead of an act per room.
    Trust {
        /// The identity to trust.
        fingerprint: Digest32,
        /// What this node will call it. Local; nothing is registered.
        petname: String,
    },
    /// Rename an identity already trusted, keeping its history grant (PRD-001 R12). Fails
    /// with [`Fault::NotConsented`] for an identity that is not trusted.
    Rename {
        /// The trusted identity.
        fingerprint: Digest32,
        /// Its new petname.
        petname: String,
    },
    /// [`NodeCommand::Trust`], choosing what each consent releases of **this node's own**
    /// messages (PRD-001 R12): [`HistoryGrant::Now`](crate::node::trust::HistoryGrant),
    /// the default, or `Full` — every generation of this node's sender key still held,
    /// at its origin, so the newcomer reads what was written before the approval too.
    TrustWith {
        /// The identity to trust.
        fingerprint: Digest32,
        /// What this node will call it. Local; nothing is registered.
        petname: String,
        /// What its consents release.
        history: crate::node::trust::HistoryGrant,
    },
    /// Stop trusting an identity node-wide, and **change the lock** (ADR-020 §3).
    ///
    /// Removes the ring entry, then rotates this identity's sender key and re-keys
    /// everyone still in the ring, in **every** room shared with the removed party
    /// — reusing ADR-007's revocation machinery (M18.1). The removed party keeps
    /// the history it already holds, which is unavoidable, and reads nothing
    /// published afterwards.
    ///
    /// The ring edit lands unconditionally; the re-keys are best-effort and
    /// retried on the tick for whoever is offline, so removal is a network act
    /// rather than a local flag.
    Untrust {
        /// The identity to stop trusting.
        fingerprint: Digest32,
    },
    /// Create a **service room** and offer one local TCP service in it, in one act
    /// (ADR-017 decisions 3 and 4) — what `vox serve <port>` does.
    ///
    /// The room's genesis confers nothing (PRD-001 R44): who may reach the service is the
    /// host's own dial gate, its trust keyring and the room's current authors. The service is
    /// declared in the same step, because a room created for a service that does not exist
    /// yet is a room that lies. Nothing is exposed implicitly: the port named here is the
    /// only thing reachable, and only by members the host trusts.
    ///
    /// Fails without creating anything if the room cannot be created *or* the service
    /// cannot be offered — a half-made service room would hand out an address for
    /// nothing.
    Serve {
        /// The local (device-only) name for the room.
        local_name: String,
        /// The room passphrase — machine-generated by the caller
        /// ([`crate::node::passphrase::generate`]), never chosen.
        passphrase: Secret,
        /// The service's name, as its sharer gives it (V030-25): the `<service>` of
        /// `<service>.<node>.<room>.vox`, and the tag the host's gate looks it up by.
        name: String,
        /// The service's port: where it listens on this machine unless `at` says otherwise.
        port: u16,
        /// Whether the service is UDP: served as `udp/<name>` rather than `<name>`
        /// (ADR-022 decision 6). Its address is the same either way.
        udp: bool,
        /// The local endpoint to carry connections to. Defaults to
        /// `127.0.0.1:<port>` — the same port, which is the case worth optimising.
        at: Option<std::net::SocketAddr>,
    },
    /// Bring up the local entry point for a room's services: a SOCKS5 proxy on `bind`
    /// that resolves that room's `.vox` name and carries connections to its host
    /// (ADR-017 decision 5) — what `vox up` runs.
    ///
    /// Needs no privilege: loopback, a port above 1024, no device, no route and no
    /// resolver entry. A tool reaches it the way a Tor user reaches `SocksPort` — `ssh`
    /// through a `ProxyCommand`, most others through `ALL_PROXY=socks5h://…`.
    ///
    /// The room must be open, because its `.vox` name is derived from the genesis inside
    /// the sealed store (ADR-010's double lock), and only a room this node holds has a
    /// name at all.
    Up {
        /// The room whose services this proxy carries.
        channel_id: Digest32,
        /// Where to listen. Loopback only; `0` picks a port.
        bind: std::net::SocketAddr,
    },
    /// Offer a local TCP service to a channel (ADR-013 Bind). Host configuration only:
    /// who may *reach* it is this node's trust keyring intersected with the room's
    /// authors (ADR-017 decision 3), never anything on the room's log.
    AddService {
        /// The channel the service is offered in.
        channel_id: Digest32,
        /// The service tag peers dial (the `<tag>` of `dial:<tag>`).
        service_tag: String,
        /// The local address the service listens on.
        local: std::net::SocketAddr,
        /// Whether the offer outlives this node's run. `false` for an offer that lasts
        /// only as long as the process that made it (`vox room send`, V210-72).
        persist: bool,
    },
    /// Stop offering a service.
    RemoveService {
        /// The channel.
        channel_id: Digest32,
        /// The service tag.
        service_tag: String,
    },
    /// Forward a local TCP port to a member's service over the overlay (ADR-013
    /// Dial). Answers [`NodeEvent::Forwarding`] with the port actually bound.
    Forward {
        /// The channel whose capability this claims.
        channel_id: Digest32,
        /// The member hosting the service.
        host: Digest32,
        /// The service tag to reach.
        service_tag: String,
        /// Where to listen locally (port 0 picks one).
        local: std::net::SocketAddr,
    },
    /// Stop a forward and release its port.
    StopForward {
        /// The local address the forward is listening on.
        local: std::net::SocketAddr,
    },
    /// Set a room's retention (PRD-001 R7, ADR-023 decision 2): `ttl` seconds, `0` for
    /// forever, as an ADR-007 policy-update. Only the room's admin may; it applies to what is
    /// already stored.
    SetRetention {
        /// The channel.
        channel_id: Digest32,
        /// Seconds a message body is kept; `0` keeps it forever.
        ttl: u64,
    },
    /// Reconcile a channel's log with the members this node can reach (ADR-008
    /// frontier sync).
    Sync {
        /// The channel.
        channel_id: Digest32,
    },
    /// Ask every other member of a room whether it holds this node's post `entry`, and which
    /// posts of `types` it holds (V210-168): the agreement a claim waits for before it says "you
    /// hold it". The report goes on `report`; the outcome is `Done` once it is sent.
    Agree {
        /// The room.
        channel_id: Digest32,
        /// This node's post every member must hold.
        entry: Digest32,
        /// The `type`s whose posts are compared.
        types: Vec<String>,
        /// Where the report goes.
        report: tokio::sync::oneshot::Sender<crate::node::agreestream::Report>,
    },
    /// Stop the actor (locks first).
    Shutdown,
    /// Change nothing and answer `Done`: proof that the actor is taking commands. A control
    /// client waiting on a long request asks it, to tell a node at work from a stuck one
    /// (V210-83).
    Ping,
}

/// Why a command did not succeed — closed, machine-stable, redaction-safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Fault {
    /// The profile has no identity yet.
    NoIdentity,
    /// The profile already has an identity.
    IdentityExists,
    /// The identity is locked.
    Locked,
    /// Wrong passphrase (identity or channel), or a tampered vault/wrap.
    WrongPassphrase,
    /// No such channel in this profile.
    UnknownChannel,
    /// The channel is not open.
    ChannelNotOpen,
    /// An input exceeded its bound (name or text length).
    TooLong,
    /// A trust add or remove needs the identity passphrase again: it was last entered more than
    /// [`KEYRING_WINDOW_SECS`](crate::node::actor::KEYRING_WINDOW_SECS) ago (V210-159). Not
    /// [`Fault::WrongPassphrase`]: none was given, and the client asks for it and tries again.
    PassphraseNeeded,
    /// The trust keyring already holds its maximum number of identities
    /// (`trust::MAX_TRUSTED`). Not [`Fault::TooLong`]: nothing the person typed was too
    /// long, and "longer than this field allows" sent them looking at the petname.
    KeyringFull,
    /// The store failed; the channel may be poisoned until reopened.
    Storage,
    /// Another vox holds this profile's store open for writing, and only one at a time may.
    /// Not [`Fault::Internal`], which is how an unlock that met one was reported (V210-100):
    /// nothing was wrong with vox or the profile, and stopping the other one is the remedy.
    ProfileBusy,
    /// Making an identity, its file (`vault.cbor`) could not be written. Not [`Fault::Storage`],
    /// which named the store when the store was fine (V210-77).
    IdentityFileUnwritable,
    /// A member's own retention for a room could not be saved: its file (`retention`, in the
    /// node's configuration directory) could not be written. Not [`Fault::Storage`], which named
    /// the store.
    RetentionFileUnwritable,
    /// The identity passphrase was right, but something this identity sealed (its trust
    /// keyring, pending consents or prekey ring) will not open under it: the data was altered,
    /// or written by another identity. Not [`Fault::WrongPassphrase`], which sent a person to
    /// retype a passphrase that had just been proved correct (V210-40).
    SealedUnreadable,
    /// The node is shutting down.
    ShuttingDown,
    /// This node is not networked, or is locked, so it cannot reach anyone.
    NotNetworked,
    /// An invite link would not parse, or named a channel/anchor this node cannot
    /// use.
    BadLink,
    /// A join reached a board, and the board has nothing for the room: either its host has not
    /// published the room there yet (it is offline, or its publish has not landed), or the room id
    /// in the address is wrong — a link carries no checksum, so a mistyped room id still parses.
    /// The board cannot tell the two apart, so neither can this.
    ///
    /// **Not [`Fault::BadLink`].** This was reported as one, so a person whose host had simply
    /// not reached the anchor yet was told the address would not parse and to check they had
    /// copied all of it — the one thing that was not wrong. Measured on a relayed join: the
    /// board was reached after 20s, held nothing for the room, and the advice pointed at the
    /// address.
    RoomNotOnBoard,
    /// A join could not reach any board: every board it knew of — the link's entries, the room's
    /// host among them, and this node's anchors — failed to answer within the join's patience,
    /// or stopped answering while it read the room. No member was asked anything.
    ///
    /// **Not [`Fault::Unreachable`].** A join reported both as one, and the CLI's words for it
    /// said "every member the board knows is offline" — a claim about members, made when the
    /// board itself was never reached (#192). The two need different fixes: a host (or the anchor
    /// it uses) that is down or out of reach, or a member that is.
    BoardUnreachable,
    /// A peer could not be reached (no live endpoint, or the dial failed).
    Unreachable,
    /// A member answered a join and waited for its proof of work, and this device took longer to
    /// solve it than the member waits (V210-87). **Not [`Fault::Unreachable`]**, which is how it
    /// was reported: the member had been reached, and had waited.
    SolveTooSlow,
    /// Every member that answered was already answering as many joins as it takes at once
    /// (V210-92). **Not [`Fault::Refused`]**, which a joiner reads as a wrong passphrase: this one
    /// was never checked.
    MembersBusy,
    /// A member answered and checked the passphrase, and the room already holds as many members as
    /// a room can, so it could not admit the joiner. **Not [`Fault::Refused`]**, which reads as a
    /// wrong passphrase, and never a success: this was told it had joined, and exited 0.
    RoomFull,
    /// A member accepted the passphrase and then could not admit the joiner: it was locked or
    /// closing mid-join, or its store refused the write (V210-128). **Not [`Fault::Refused`]**,
    /// whose advice is "usually the passphrase is wrong": this one was accepted.
    NotAdmittedAfterJoin,
    /// The remote refused: a join was refused, or a record was rejected.
    Refused,
    /// A consent named a member this node has not admitted to the room (yet): it holds no
    /// verified key for them, so it cannot know it would release to the right party. Not
    /// [`Fault::UnknownChannel`], which said "no such room" about a room this node holds
    /// (V210-78).
    NotAdmitted,
    /// There is no consent to withdraw: the target was never consented to, or the
    /// consent has already been revoked (ADR-007 — consent is single-writer, so this
    /// is a settled fact, not a race).
    NotConsented,
    /// The target is not in this node's trust keyring, so this node releases it no key
    /// (V210-148). A key goes only to a member the owner trusts: there are rooms, nodes and
    /// trust, and no per-room grant beside them. The node refuses whatever a client asks, so
    /// no client can hand a key to someone its owner never trusted.
    NotTrusted,
    /// The requested local bind address is not a loopback address. A forward carries
    /// traffic into a room *this* machine is a member of, so binding it anywhere the
    /// network can reach would hand that membership to whoever reaches the port
    /// (ADR-013; the same rule `vox up` enforces).
    NotLoopback,
    /// A local address this node was asked to listen on is held by another program: the
    /// node's `--listen` port, a `vox up --bind`, a forward's local port.
    AddressInUse,
    /// A local address this node was asked to listen on is not an address of this machine
    /// (V210-134). Not [`Fault::AddressInUse`], which sent people looking for a program that
    /// did not exist.
    AddressNotHere,
    /// A local address this node was asked to listen on could not be bound for a reason that is
    /// neither of the two above (V210-134); the front end quotes the operating system.
    BindFailed,
    /// A join named a room this profile already holds.
    AlreadyMember,
    /// A room this node joined has not synced with another member yet, so nothing is written
    /// to it (V210-164).
    RoomNotSynced,
    /// A leave was written, but no other member of the room took it within the wait: the room
    /// is held until one does (V210-164).
    LeaveNotHeard,
    /// A leave was overtaken: this node wrote in the room after it, or joined it again, so it is
    /// in the room again (V210-164).
    LeaveUndone,
    /// `vox up` was asked for a room that offers no service by name: its host is not fixed by
    /// the room's genesis, so there is no `.vox` name to resolve (ADR-017 decision 4).
    NotAServiceRoom,
    /// The change is the room admin's to make — a holder of the `policy` capability — and
    /// this identity is not one (PRD-001 R7: setting a room's retention).
    NotAdmin,
    /// A member who is not the room's creator or an admin asked to keep the room's messages
    /// **longer** than the room does (V030-32). A member may set a shorter retention, which
    /// governs only their own node; never a longer one.
    AboveRoomRetention,
    /// The room is over: its creator ended it, or its idle end ran out (V030-08). It takes no
    /// new message.
    RoomEnded,
    /// Only the room's creator may do that — end the room (or an admin it delegated), or choose
    /// its idle end (V030-08).
    NotCreator,
    /// Only the room's creator adds or removes an admin (#319); an admin may not.
    NotRoomCreator,
    /// The member named is not an admin of the room, so there is no admin to take back (V030-08).
    NotAnAdmin,
    /// A join reached a room that has ended (V030-08): a member said so before checking anything,
    /// or a board that took the room off at its end did (V030-14).
    JoinedRoomEnded,
    /// The member a join reached has left the room (V030-08), so it answers no join for it.
    ResponderLeft,
    /// The room's stored log was written by vox before v0.3.0, whose message format changed;
    /// v0.3.0 does not read it, and the room is made again (decider, 2026-09-29, #226).
    RoomFromBeforeV030,
    /// A service removal named a tag this room does not offer. Not [`Fault::UnknownChannel`],
    /// which said "no such room on this node" about a room that was right there (V210-83).
    NotOffered,
    /// A share named a service this node already shares in the room under that name (V030-25):
    /// names are unique per node per room, because the name is the address.
    NameTaken,
    /// A forward was to be stopped at a local address where no forward is listening. Not
    /// [`Fault::UnknownChannel`] either: no room was named at all (V210-83).
    NoSuchForward,
    /// A tunnel was refused because the connection to that member already carries
    /// [`TUNNELS_PER_PEER`](crate::transport::quic::TUNNELS_PER_PEER) tunnels (V210-81). Not
    /// [`Fault::Unreachable`]: the member was reached, and closing a tunnel is the remedy.
    TunnelLimit,
    /// An internal invariant failed (a bug, never user input).
    Internal,
}

impl Fault {
    /// What this fault means to a person, and what to do about it, in the house style: one
    /// short line saying what happened, then indented lines saying what to do.
    ///
    // `Fault::TunnelLimit`'s explanation names the cap in words, as `Error::TunnelLimit` does.
    const _TUNNEL_CAP_NAMED: () = assert!(crate::transport::quic::TUNNELS_PER_PEER == 16);
    // `Fault::PassphraseNeeded`'s explanation names the window in words.
    const _KEYRING_WINDOW_NAMED: () = assert!(crate::node::actor::KEYRING_WINDOW_SECS == 30 * 60);

    /// **Why this exists (PRD-001 R36).** A `Fault` is a closed token, and every surface that
    /// had one printed it with `{:?}` — so a person saw `Failed(Refused)`, `Failed(Internal)`,
    /// `Failed(NotConsented)`: the name of an enum variant, not a cause. The token stays
    /// machine-stable for code that matches on it; this is its reading for everyone else.
    #[must_use]
    pub fn explain(self) -> &'static str {
        match self {
            Fault::NoIdentity => {
                "this node has no identity yet\n       create one with `vox id` (or start `vox tui`)"
            }
            Fault::IdentityExists => "this node already has an identity",
            Fault::Locked => {
                "the identity is locked\n       unlock it: pipe the identity passphrase to `vox daemon`, or run `vox tui`"
            }
            Fault::WrongPassphrase => "the passphrase is wrong",
            Fault::PassphraseNeeded => {
                "changing who you trust needs your identity passphrase again: it was last entered more than 30 minutes ago\n       give it, and the change is made: `vox trust` asks at a terminal, or takes --identity-passphrase-file or VOX_IDENTITY_PASSPHRASE"
            }
            Fault::UnknownChannel => {
                "no such room on this node\n       `vox room list` shows the rooms it holds"
            }
            Fault::ChannelNotOpen => {
                "that room is not open on this node\n       open it with its passphrase: a line `<room> <passphrase>` to `vox daemon`, or in `vox tui`"
            }
            Fault::TooLong => "that is longer than this field allows",
            // The cap in force, read once (#85): a test build's lowered cap is never called 1,024.
            Fault::KeyringFull => {
                static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
                TEXT.get_or_init(|| {
                    format!(
                        "your trust keyring is full ({} identities)\n       remove one with \
                         `vox trust remove <fingerprint>`, then add again",
                        crate::node::trust::trust_cap_words()
                    )
                })
            }
            Fault::Storage => {
                "the node's store could not be read or written\n       check free disk space, and that the data directory is writable and its files undamaged"
            }
            Fault::ProfileBusy => {
                "another vox holds this node open, and only one at a time may write it\n       run this again once that one is done; a `vox daemon` or `vox tui` holds it until stopped, and the `vox room …` verbs ask it instead"
            }
            Fault::RetentionFileUnwritable => {
                "your retention for this room could not be saved: the node's retention file (`retention`, in its configuration directory) could not be written\n       check free disk space, and that the configuration directory is writable; then run it again"
            }
            Fault::IdentityFileUnwritable => {
                "the node's identity file (vault.cbor) could not be written, so no identity was made\n       check free disk space, and that the data directory is writable; then run it again"
            }
            Fault::SealedUnreadable => {
                "the identity passphrase is right, but this node's trust keyring, pending \
                 trust grants or prekey ring will not open under it\n       the store was altered, \
                 or copied from another identity's profile"
            }
            Fault::ShuttingDown => "the node is shutting down",
            Fault::NotNetworked => {
                "this node is not on the network (it is locked, or was started without a listen address)"
            }
            Fault::BadLink => {
                "that address will not parse, or names a room this node cannot use\n       check you copied the whole vox:// address"
            }
            Fault::RoomNotOnBoard => {
                "the board holds nothing for that room\n       either its host has not published it there yet (the host must be online; then try again)\n       or the room part of the address is wrong: check it against the address you were sent"
            }
            Fault::BoardUnreachable => {
                "no board the join tried could be read — the room's host, or an anchor if one was tried — so no member was asked\n       check that the host is running and that this machine can reach its address"
            }
            Fault::Unreachable => {
                "the peer could not be reached — nobody answered on any path\n       it may be offline; the node's log names each path it tried"
            }
            Fault::SolveTooSlow => {
                "a member answered, but this device took longer to solve the join's proof of work than the member waits\n       your passphrase was never checked — this is not a verdict on it\n       run the join again when this device is less busy"
            }
            Fault::MembersBusy => {
                "a member answered, but it is busy answering other joins\n       your passphrase was never checked — this is not a verdict on it\n       try the join again shortly"
            }
            Fault::RoomFull => {
                "the room is full, so you were not admitted\n       your passphrase was accepted; the room takes no more members"
            }
            Fault::NotAdmittedAfterJoin => {
                "a member accepted your passphrase, then could not admit you, so you were not admitted\n       the member may have been locking or closing; run the join again while it is running"
            }
            Fault::Refused => "the other side refused",
            Fault::NotAdmitted => {
                "that member is not admitted to the room on this node yet\n       it is, once this node syncs their records; then try again"
            }
            Fault::NotConsented => {
                "there is nothing to withdraw: that identity was never trusted, or already is not"
            }
            Fault::NotTrusted => {
                "that identity is not in your trust keyring, so it is given no key to read you\n       run `vox trust add <fingerprint>` if you mean it to read you"
            }
            Fault::NotLoopback => {
                "a local port for Vox must be on loopback (127.0.0.1 or ::1)\n       anything else would hand this room's membership to whoever reaches the port"
            }
            Fault::AddressInUse => {
                "a local port it needs is already in use: another program holds it\n       pick another port, or stop whatever holds it (`lsof -i :<port>` names it)"
            }
            Fault::AddressNotHere => {
                "a local address it was asked to use is not an address of this machine\n       use one this machine has (`ifconfig` lists them), or 127.0.0.1"
            }
            Fault::BindFailed => "a local address it was asked to use could not be listened on",
            Fault::AlreadyMember => {
                "this node already holds that room — there is nothing to join\n       `vox room list` shows it; open it with its passphrase if it is closed"
            }
            Fault::RoomNotSynced => {
                "this room was joined and has not yet synced with another member, so nothing can be written to it\n       try again once a member is reachable"
            }
            Fault::LeaveNotHeard => {
                "no other member of the room could be told within 30s, so this node still holds it\n       it leaves as soon as one can be told, and the members see it then"
            }
            Fault::LeaveUndone => {
                "something was written in the room from this node after the leave, so it is in the room again\n       run `vox room leave` again to leave"
            }
            Fault::NotAServiceRoom => {
                "that room offers no service by name, so it has no .vox name to resolve\n       reach a shared service by its address, `vox forward <service>.<node>.<room>.vox`"
            }
            Fault::AboveRoomRetention => {
                "a member may keep this room's messages for less time than the room does, never longer\n       ask the room's creator or an admin (`vox room admin list`) to change the room's retention"
            }
            Fault::NotAdmin => {
                "only the room's admin may change that, and this identity is not its admin\n       the room's creator and the admins it named are; `vox room admin list` shows who"
            }
            Fault::RoomEnded => {
                "this room has ended — its creator or an admin ended it, or nothing was said in it for the idle end its creator chose — so it takes no new message\n       this node deletes it once it has passed the end on"
            }
            Fault::NotCreator => {
                "only the room's creator, or an admin it delegated, may do that — and this identity is neither"
            }
            Fault::JoinedRoomEnded => {
                "that room has ended — a member or its board said so — so it takes nobody in\n       your passphrase was never checked; the room is over, not your access to it"
            }
            Fault::ResponderLeft => {
                "the member that answered has left that room, so it lets nobody in\n       your passphrase was never checked; ask a member still in the room for an address"
            }
            Fault::NotRoomCreator => {
                "only the room's creator adds or removes an admin, and this identity did not create the room"
            }
            Fault::NotAnAdmin => {
                "that member is not an admin of the room\n       `vox room admin list` shows who is"
            }
            Fault::RoomFromBeforeV030 => {
                "this room was made by vox before v0.3.0, and its message format changed, so this vox cannot open it\n       make the room again (`vox room create`) and give its members its room link (`vox room link`)"
            }
            Fault::NotOffered => {
                "that service is not offered in this room\n       check its name: it is the tag that was given to `vox service add`"
            }
            Fault::NameTaken => {
                "you already share a service under that name in this room\n       choose another name, or `vox service remove` the one you share first"
            }
            Fault::NoSuchForward => "no forward is listening at that local address",
            Fault::TunnelLimit => {
                "16 tunnels are already open to this member\n       to free one: `vox tunnel close` it (`vox status` lists every tunnel, its number, and when it last moved), close the program using it, or restart the `vox up` or `vox forward` carrying it; on the host, `vox service remove` the service, or `vox trust remove` the member"
            }
            Fault::Internal => {
                "an internal error — a bug in vox, not something you did\n       the node's log has the detail; please report it"
            }
        }
    }
}

impl Fault {
    /// The fault whose [`Fault::explain`] is `text`, or that `text` names as `Failed(<name>)` (the
    /// join's answer, V210-114), if there is one: how a client of the daemon gets back the typed
    /// fault a request failed with.
    #[must_use]
    pub fn from_explanation(text: &str) -> Option<Self> {
        let first = text.lines().next().unwrap_or_default();
        if let Some(name) = first
            .strip_prefix("Failed(")
            .and_then(|r| r.strip_suffix(')'))
        {
            return Self::from_name(name);
        }
        // A fault's explanation may run to a second line of advice; its first line names it.
        Self::ALL
            .iter()
            .copied()
            .find(|f| f.explain().lines().next() == Some(first))
    }
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.explain())
    }
}

/// A fault's name and its way back from one, made from **one list** (V210-114).
///
/// A daemon names the fault of a failed join over its control socket (`Failed(ProfileBusy)`),
/// and `vox room join` turns the name back into the fault to say what it means. That was a table
/// of its own in the CLI, and every fault added after it was written fell out of it unseen:
/// `ProfileBusy`, `IdentityFileUnwritable` and `NotAdmitted` reached the person as a bare
/// `Failed(…)`, not as their cause. Here [`Fault::name`]'s match is exhaustive, so a fault that is
/// not on the list does not build, and [`Fault::from_name`] is made from the same list.
macro_rules! fault_names {
    ($($fault:ident),* $(,)?) => {
        impl Fault {
            /// This fault's name, as its `Debug` writes it: what crosses the control socket.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $(Fault::$fault => stringify!($fault),)*
                }
            }

            /// Every fault, so a client given only a fault's explanation over the control socket
            /// can tell which it was ([`Fault::from_explanation`]).
            pub const ALL: &'static [Fault] = &[$(Fault::$fault,)*];

            /// The fault named `name` (as [`Fault::name`] gives it), if there is one.
            #[must_use]
            pub fn from_name(name: &str) -> Option<Self> {
                match name {
                    $(stringify!($fault) => Some(Fault::$fault),)*
                    _ => None,
                }
            }
        }
    };
}

fault_names!(
    NoIdentity,
    IdentityExists,
    Locked,
    WrongPassphrase,
    PassphraseNeeded,
    UnknownChannel,
    ChannelNotOpen,
    TooLong,
    KeyringFull,
    Storage,
    ProfileBusy,
    IdentityFileUnwritable,
    RetentionFileUnwritable,
    SealedUnreadable,
    ShuttingDown,
    NotNetworked,
    BadLink,
    RoomNotOnBoard,
    BoardUnreachable,
    Unreachable,
    SolveTooSlow,
    MembersBusy,
    RoomFull,
    NotAdmittedAfterJoin,
    Refused,
    NotAdmitted,
    NotConsented,
    NotTrusted,
    NotLoopback,
    AddressInUse,
    AddressNotHere,
    BindFailed,
    AlreadyMember,
    RoomNotSynced,
    LeaveNotHeard,
    LeaveUndone,
    NotAServiceRoom,
    NotOffered,
    NameTaken,
    NoSuchForward,
    NotAdmin,
    AboveRoomRetention,
    RoomFromBeforeV030,
    RoomEnded,
    NotCreator,
    NotAnAdmin,
    NotRoomCreator,
    JoinedRoomEnded,
    ResponderLeft,
    TunnelLimit,
    Internal,
);

/// The result of a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The command succeeded.
    Done,
    /// A forward was bound, at this address: the answer to [`NodeCommand::Forward`] **names the
    /// forward it opened**. It used to be `Done` alone, and a caller took the address from the
    /// next `Forwarding` event, which is any forward's. Two `vox room get`s at once could then be
    /// handed the same one; the first to finish stopped it, and the second, still connecting, was
    /// refused (`connecting to the forward: Connection refused`), while the other forward was
    /// never stopped at all.
    Bound(std::net::SocketAddr),
    /// A member who is not the room's creator or an admin set their **own** node's retention
    /// for a room, at or below the room's (V030-32): `own` seconds here, while the room keeps
    /// `room` (`0` = forever). It changes nothing on any other node. `own == room` means the
    /// member's own line was cleared: their node follows the room's retention again.
    OwnRetention {
        /// This node's retention for the room now, seconds.
        own: u64,
        /// The room's retention, seconds (`0` = forever).
        room: u64,
    },
    /// The command failed for the given reason.
    Failed(Fault),
}

impl Fault {
    /// The fault a failed local bind is, by its cause (V210-134).
    #[must_use]
    pub fn of_bind(cause: crate::error::BindCause) -> Self {
        match cause {
            crate::error::BindCause::InUse => Fault::AddressInUse,
            crate::error::BindCause::NotHere => Fault::AddressNotHere,
            crate::error::BindCause::Other => Fault::BindFailed,
        }
    }

    /// Whether this is a failed local bind.
    #[must_use]
    pub fn is_bind(self) -> bool {
        matches!(
            self,
            Fault::AddressInUse | Fault::AddressNotHere | Fault::BindFailed
        )
    }
}

impl Outcome {
    /// Whether the command succeeded.
    #[must_use]
    pub fn is_done(self) -> bool {
        matches!(
            self,
            Outcome::Done | Outcome::Bound(_) | Outcome::OwnRetention { .. }
        )
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::Done => f.write_str("done"),
            Outcome::Bound(local) => write!(f, "bound at {local}"),
            Outcome::OwnRetention { own, room } => write!(
                f,
                "this node keeps the room's messages for {own} s; the room keeps them for {room} s"
            ),
            Outcome::Failed(fault) => f.write_str(fault.explain()),
        }
    }
}

/// An ordered node → client event (never coalesced).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeEvent {
    /// Creating the identity has waited more than a second for another vox that holds this
    /// profile's lock (it is creating the identity, or holds the profile, or is stopped while
    /// doing so). Sent once per wait; the command goes on when the lock is free. Each front end
    /// says it in its own place: the CLI on stderr, the TUI in its status line (V210-100). A wait
    /// to open an existing profile comes before the node exists, and is said through
    /// [`NodeConfig::on_profile_wait`](crate::node::actor::NodeConfig::on_profile_wait).
    WaitingForProfile,
    /// A new rendered entry in a channel.
    NewEntry {
        /// The channel.
        channel_id: Digest32,
        /// The rendered entry.
        row: MessageRow,
    },
    /// A channel was opened.
    ChannelOpened {
        /// The channel.
        channel_id: Digest32,
    },
    /// A channel was closed.
    ChannelClosed {
        /// The channel.
        channel_id: Digest32,
    },
    /// A room this node holds ended, and the end has been passed on (V030-08): `handed` of
    /// `members` members were synced with after it; the rest learn it from them, or from an
    /// anchor. The room is deleted from this node next ([`NodeEvent::RoomRemoved`]).
    RoomEnded {
        /// The room.
        channel_id: Digest32,
        /// Members synced with after the end.
        handed: usize,
        /// Members it had to pass it to.
        members: usize,
    },
    /// Everything this node held of a room was deleted: it left the room (V210-164), or the
    /// room ended (the decider, 2026-10-03).
    RoomRemoved {
        /// The room.
        channel_id: Digest32,
    },
    /// A peer completed an ADR-005 join against this node, which verified its
    /// identity and admitted it as a log author. It can read nothing until this
    /// user consents (ADR-007).
    PeerJoined {
        /// The channel joined.
        channel_id: Digest32,
        /// The joiner's verified identity fingerprint.
        peer: Digest32,
    },
    /// A sender key this node delivered was not taken by `peer`, so it is owed again and
    /// re-sent on the tick. Said rather than hidden: a member who never gets the key cannot
    /// read, and the cause is on the recipient's side.
    KeyNotTaken {
        /// The channel.
        channel_id: Digest32,
        /// The member it was for.
        peer: Digest32,
        /// What the recipient's side said.
        why: String,
    },
    /// A peer's sender key arrived, so that peer's messages become readable. Any
    /// message already held as ciphertext was backfilled.
    SenderKeyReceived {
        /// The channel.
        channel_id: Digest32,
        /// The author who released the key.
        peer: Digest32,
        /// How many already-stored messages became readable.
        backfilled: u64,
    },
    /// A tunnel this node was **carrying** was cut because the host withdrew our reach
    /// (ADR-017 M17.11).
    ///
    /// Distinct from an ordinary disconnect on purpose. A dial that is refused says
    /// nothing about why — a refusal must stay indistinguishable from "no such service"
    /// — but a session that was *established* and is then cut already tells the peer it
    /// had reach, so naming the reason leaks nothing and stops the tool retrying against
    /// a decision that will not change.
    ReachWithdrawn {
        /// The room the service was bound to.
        channel_id: Digest32,
        /// The port that was being carried, which is the service tag.
        port: u16,
    },
    /// A sync session with `peer` for `channel_id` did not complete, and why: the peer's coded
    /// reason when it refused (a collision reads "the peer was busy syncing this room"), or the
    /// transport's (#202, PRD-001 R36).
    SyncFailed {
        /// The room.
        channel_id: Digest32,
        /// The peer the session was with.
        peer: Digest32,
        /// What went wrong, in words.
        reason: String,
    },
    /// A room is open, but it could not be added to the rooms this node reopens by itself
    /// (#208), so it will be closed after a restart until it is opened again.
    ///
    /// Not a failure of the command that opened it: the room exists and is open, and saying
    /// the command failed would leave a room in the store that its creator was told does not
    /// exist.
    RoomNotRemembered {
        /// The room.
        channel_id: Digest32,
        /// Why it could not be remembered, in words.
        why: String,
    },
    /// This node was unable to answer anybody for a noticeable time, and what it was doing.
    ///
    /// The actor is the only writer of channel state, so whatever it awaits stops the node
    /// answering *everyone* — a request arriving in that window waits out its own patience and
    /// reports this node as unreachable when it was merely busy. That failure is indistinguishable
    /// from a network problem at the far end, which is why the node has to say it about itself.
    Stalled {
        /// What the node was doing.
        what: String,
        /// How long it was unable to answer, in milliseconds.
        millis: u64,
    },
    /// A record this node tried to put on a board was not accepted, and the board said why.
    ///
    /// Publishing is how a member becomes findable: its bundle carries the key every other
    /// member admits it as a log author with, so a record that does not land means a member that
    /// nobody can reconcile with — which then shows up as "unreachable", three layers away and
    /// on the wrong node. Every one of these puts used to be `let _ = client.put(..).await`, so a
    /// board that refused a record refused it in complete silence.
    ///
    /// Not every refusal is a fault: the ADR-012 refresh floor declines a replacement that is
    /// merely too soon, which means the previous announcement is still live and being announced
    /// is all the put was for. It is reported anyway, because "still announced" and "never
    /// announced" are the two cases this silence was hiding, and only one of them is fine.
    PublishRefused {
        /// The room the record was for.
        channel_id: Digest32,
        /// Which record it was — the genesis, an address, a bundle, or a mirrored one.
        what: String,
        /// What the board said.
        why: String,
    },
    /// A board took one of this node's own records on a republish, after refusing it as stale
    /// (V210-51, #230): the refusal happened, and was mended. Said once per refusal.
    PublishCured {
        /// The room the record was for.
        channel_id: Digest32,
        /// Which record it was, and which board (`our address (board …)`).
        what: String,
    },
    /// This node's own `retention` file asks to keep a room's messages for longer than the room
    /// does (V030-32). A node may keep less than its room, never more, so the room's value is the
    /// one in force: said once, so its operator knows the file line has no effect.
    RetentionAboveRoom {
        /// The room.
        channel_id: Digest32,
        /// What the node's file asks for, seconds.
        node: u64,
        /// What the room keeps, seconds.
        room: u64,
    },
    /// What happened to a connection to `peer`, said so a failure that recurs names itself (#229,
    /// after #232's CI reds): a newcomer that lost the one-connection-per-peer tie-break, a
    /// retired connection closed, an anchor connection lost or redialled, a reach that waited for
    /// another and what it did next. Diagnostics, never a decision.
    ConnectionNote {
        /// The peer the connection is to.
        peer: Digest32,
        /// What happened, for the operator.
        note: String,
    },
    /// Something about this node itself an operator should know (V210-167): that its usual port
    /// was taken and it listens on another this run, or that a member was found on this computer
    /// or the local network.
    NodeNote {
        /// What happened, for the operator.
        note: String,
    },
    /// The machine's network changed (ADR-012 N-52): which addresses came and went, which default
    /// routes moved, and what this node republished. Said once per change.
    NetworkChanged {
        /// The change and what was done about it, in one line.
        summary: String,
    },
    /// More peers dialled this node at once than it runs handshakes for, and the ones past the
    /// cap waited for a slot or were refused (V210-86): said once per burst, when none is left
    /// waiting, so an operator can see a burst was absorbed, or how many were turned away.
    HandshakesQueued {
        /// How many attempts waited for a slot.
        waited: usize,
        /// The most that waited at once.
        most_waiting: usize,
        /// The most handshakes that ran at once meanwhile: never more than the cap.
        most_running: usize,
        /// How many were refused: no place left to wait, or no slot in time.
        refused: usize,
        /// The longest any waited, in milliseconds.
        longest_ms: u64,
    },
    /// A join failed, with what each responder that was tried reported.
    ///
    /// `Outcome::Failed(Fault)` is a single token with no room for a reason, so this carries the
    /// one thing a person needs: which member was asked and what it said. "That member is
    /// offline", "the board has not caught up yet" and "the room does not want you" are three
    /// different problems that all render as `Unreachable`.
    JoinFailed {
        /// What each responder reported, as this node saw it.
        reason: String,
    },
    /// Where a join's time went, step by step — raised for every join this node starts, whether
    /// it got in or not, so a slow or failed join carries its own breakdown.
    JoinSteps {
        /// Whether the join got in.
        joined: bool,
        /// Each step and how long it took, in order.
        steps: String,
    },
    /// A join this node is running has begun a step: what it now waits for (V210-85).
    ///
    /// [`NodeEvent::JoinSteps`] arrives only once the join has ended, so a join that is stopped
    /// before then — Ctrl-C, a service manager's SIGTERM — had nothing to say about where it was.
    /// `vox connect` keeps the latest of these, and names it when it is stopped.
    JoinStep {
        /// The step, for the person: `dialling member 7r7pa7jfcfdo`.
        step: String,
    },
    /// An upgrade off a relayed path was tried and nothing better landed, with what each rung
    /// reported.
    ///
    /// Not an error. A peer behind a symmetric NAT stays relayed and that is ADR-012's
    /// documented limit. It is an event because "relayed because the NAT says no" and "relayed
    /// because a rung failed" look identical from outside, and only one of them is somebody's
    /// problem to fix.
    StillRelayed {
        /// The peer still reached over a relay.
        peer: Digest32,
        /// What each rung reported, as this node saw it.
        reason: String,
    },
    /// The proxy refused a CONNECT, or a forward refused or lost a connection, with the reason
    /// **this node** saw.
    ///
    /// What the application gets stays coarse — a SOCKS failure code, or a reset socket for a
    /// forward — and the host's refusal is uniform, so a peer learns nothing (ADR-013 dark
    /// services). This is
    /// the other side of that: the operator's own node telling them what happened, which is the
    /// difference between a diagnosable failure and `ssh` failing for no stated reason. Measured:
    /// a real SOCKS5 client got "SOCKS reply code 1" and the ladder's actual verdict — which
    /// `reach_host_with_patience` had deliberately kept — died in a dropped `Result`.
    ProxyRefused {
        /// What went wrong, as this node saw it.
        reason: String,
    },
    /// A tunnel this node carried was **closed on purpose** (V030-11): by a person here or at
    /// the other end (`vox tunnel close`, the TUI), or as stuck. Not [`NodeEvent::ProxyRefused`]:
    /// "refused or cut" read a deliberate close as a fault.
    TunnelClosed {
        /// Which session, by which end, and why.
        reason: String,
    },
    /// A dial this node started in the background failed, with what it reported.
    ///
    /// Connecting cannot run on the actor — it would stop the node answering anyone — so it runs
    /// off it, and the result came back through a channel that dropped the `Err`. A room then sits
    /// at an empty timeline having never said why: "the anchor refused", "the anchor is not
    /// listening" and "we never tried" are three different problems and all three looked like
    /// patience. This is the node reporting the one it actually hit.
    PeerUnreachable {
        /// The peer that could not be reached.
        peer: Digest32,
        /// What the attempt reported, as this node saw it.
        why: String,
    },
    /// A forward is live: the local port is accepting connections for a member's
    /// service (ADR-013).
    Forwarding {
        /// The channel the capability is claimed under.
        channel_id: Digest32,
        /// The member hosting the service.
        host: Digest32,
        /// The service tag.
        service_tag: String,
        /// The local address actually bound (a requested port 0 is resolved here).
        local: std::net::SocketAddr,
    },
    /// An address for a room was asked for and is **not** handed out (V210-96): it would name no
    /// route of this node's own (none discovered within the wait) and no anchor it names held the
    /// room, so it would lead nowhere. `reason` names each board and what kept the room off it; the
    /// verb itself fails with [`Fault::BoardUnreachable`].
    AddressWithheld {
        /// The room.
        channel_id: Digest32,
        /// Board by board, why none holds the room.
        reason: String,
    },
    /// What an address handed out for a room carries, in plain words (V210-96): the kinds of route
    /// to this node it names, and any anchor it names that has not taken the room yet; then, for
    /// each such anchor, whether it took it within the wait.
    AddressNote {
        /// The room.
        channel_id: Digest32,
        /// The note.
        note: String,
    },
    /// An invite link for a channel (public: it carries no secret).
    InviteLink {
        /// The channel.
        channel_id: Digest32,
        /// The `vox://` URL.
        url: String,
    },
    /// This node joined a channel.
    Joined {
        /// The channel joined.
        channel_id: Digest32,
        /// The member that answered the join.
        responder: Digest32,
    },
    /// This identity consented to `target`, which may now read its messages.
    Consented {
        /// The channel.
        channel_id: Digest32,
        /// The member consented to.
        target: Digest32,
    },
    /// This identity revoked `target`, rotating its sender key to a generation
    /// `target` cannot read. `rekeyed` counts the remaining consenters that were
    /// re-keyed immediately; the rest are re-keyed as they become reachable.
    Revoked {
        /// The channel.
        channel_id: Digest32,
        /// The member whose consent was withdrawn.
        target: Digest32,
        /// The new sender-key generation.
        generation: u64,
        /// How many remaining consenters were re-keyed at once.
        rekeyed: u64,
    },
    /// A member reached one of this node's services, and was authorized to.
    ///
    /// The host cannot learn this from the service's own logs: every Vox client reaches
    /// a local service from loopback, so `sshd` records `127.0.0.1` for all of them
    /// (ADR-017 decision 6). The identity is known at the gate — transport-authenticated
    /// and checked against the room's evaluator — so it is reported here.
    ///
    /// Grants only. A refused dial emits nothing, exactly as it tells the dialer
    /// nothing (dark services, ADR-013).
    TunnelServed {
        /// The room whose capability authorized it.
        channel_id: Digest32,
        /// The member that reached the service.
        client: Digest32,
        /// The service reached — for a port-named service (ADR-017), the port.
        service_tag: String,
    },
    /// The local entry point is up: a SOCKS5 proxy carrying one room's services.
    ProxyUp {
        /// The room it carries.
        channel_id: Digest32,
        /// The `.vox` hostname its services answer on.
        hostname: String,
        /// Where it is listening.
        bind: std::net::SocketAddr,
    },
    /// A sync session applied entries to a channel's log.
    Synced {
        /// The channel.
        channel_id: Digest32,
        /// Entries applied to the log.
        applied: u64,
        /// How many of those became readable.
        rendered: u64,
    },
    /// The actor has stopped.
    Shutdown,
}

impl NodeEvent {
    /// The event as a sentence a person can read, for a front end that shows events as text (the
    /// macOS app's notices): never the event's debug form, which is a struct dump (R36). Room and
    /// member ids are given as their first 12 characters, as the CLI shows them.
    #[must_use]
    pub fn words(&self) -> String {
        fn short(d: &Digest32) -> String {
            crate::node::link::b32_encode(d).chars().take(12).collect()
        }
        match self {
            NodeEvent::WaitingForProfile => {
                "waiting for another vox that is using this identity's files".into()
            }
            NodeEvent::NewEntry { channel_id, .. } => {
                format!("a new message in room {}", short(channel_id))
            }
            NodeEvent::ChannelOpened { channel_id } => {
                format!("room {} is open", short(channel_id))
            }
            NodeEvent::ChannelClosed { channel_id } => {
                format!("room {} is closed", short(channel_id))
            }
            NodeEvent::RoomEnded {
                channel_id,
                handed,
                members,
            } => format!(
                "room {} ended; {handed} of its {members} members were told directly, the rest \
                 learn it from them",
                short(channel_id)
            ),
            NodeEvent::RoomRemoved { channel_id } => {
                format!("room {} was removed from this device", short(channel_id))
            }
            NodeEvent::PeerJoined { channel_id, peer } => format!(
                "{} joined room {}; they read nothing until you trust them",
                short(peer),
                short(channel_id)
            ),
            NodeEvent::KeyNotTaken {
                channel_id,
                peer,
                why,
            } => format!(
                "{} did not take your key for room {} — {why}; it is sent again",
                short(peer),
                short(channel_id)
            ),
            NodeEvent::SenderKeyReceived {
                channel_id, peer, ..
            } => format!(
                "{}'s messages in room {} can be read now",
                short(peer),
                short(channel_id)
            ),
            NodeEvent::ReachWithdrawn { channel_id, port } => format!(
                "the host withdrew your reach to port {port} in room {}, so the tunnel was cut",
                short(channel_id)
            ),
            NodeEvent::SyncFailed {
                channel_id,
                peer,
                reason,
            } => format!(
                "sync of room {} with {} did not complete — {reason}",
                short(channel_id),
                short(peer)
            ),
            NodeEvent::RoomNotRemembered { channel_id, why } => format!(
                "room {} is open, but will not reopen by itself after a restart — {why}",
                short(channel_id)
            ),
            NodeEvent::Stalled { what, millis } => {
                format!("busy {millis} ms — {what} — nobody could be answered")
            }
            NodeEvent::PublishRefused {
                channel_id,
                what,
                why,
            } => format!(
                "a board would not take {what} for room {} — {why}",
                short(channel_id)
            ),
            NodeEvent::PublishCured { channel_id, what } => format!(
                "{what} for room {} was taken on a republish",
                short(channel_id)
            ),
            NodeEvent::RetentionAboveRoom {
                channel_id,
                node,
                room,
            } => format!(
                "this device asks to keep room {}'s messages for {node} s, but the room keeps \
                 them for {room} s, which is what applies",
                short(channel_id)
            ),
            NodeEvent::ConnectionNote { peer, note } => {
                format!("connection to {} — {note}", short(peer))
            }
            NodeEvent::NodeNote { note } => note.clone(),
            NodeEvent::NetworkChanged { summary } => summary.clone(),
            NodeEvent::HandshakesQueued {
                waited, refused, ..
            } => format!(
                "a burst of connections: {waited} waited for a handshake slot and {refused} were \
                 turned away"
            ),
            NodeEvent::JoinFailed { reason } => format!("a join did not complete — {reason}"),
            NodeEvent::JoinSteps { joined, steps } => {
                if *joined {
                    format!("the join got in — {steps}")
                } else {
                    format!("the join did not get in — {steps}")
                }
            }
            NodeEvent::JoinStep { step } => format!("joining: {step}"),
            NodeEvent::StillRelayed { peer, reason } => {
                format!("still relayed to {} — {reason}", short(peer))
            }
            NodeEvent::ProxyRefused { reason } => format!("tunnel refused or cut — {reason}"),
            NodeEvent::TunnelClosed { reason } => format!("tunnel closed — {reason}"),
            NodeEvent::PeerUnreachable { peer, why } => {
                format!("could not reach {} — {why}", short(peer))
            }
            NodeEvent::Forwarding {
                host,
                service_tag,
                local,
                ..
            } => format!("forwarding {local} to {service_tag} on {}", short(host)),
            NodeEvent::AddressWithheld { reason, .. } => {
                format!("the address was not handed out — {reason}")
            }
            NodeEvent::AddressNote { note, .. } => note.clone(),
            NodeEvent::InviteLink { channel_id, url } => {
                format!("room link for room {}: {url}", short(channel_id))
            }
            NodeEvent::Joined {
                channel_id,
                responder,
            } => format!(
                "joined room {}, let in by {}",
                short(channel_id),
                short(responder)
            ),
            NodeEvent::Consented { channel_id, target } => format!(
                "{} can now read your messages in room {}",
                short(target),
                short(channel_id)
            ),
            NodeEvent::Revoked {
                channel_id, target, ..
            } => format!(
                "{} can no longer read your new messages in room {}",
                short(target),
                short(channel_id)
            ),
            NodeEvent::TunnelServed {
                client,
                service_tag,
                ..
            } => format!("{} reached {service_tag}", short(client)),
            NodeEvent::ProxyUp { hostname, bind, .. } => {
                format!("{hostname} is reachable through {bind}")
            }
            NodeEvent::Synced {
                channel_id,
                applied,
                ..
            } => format!("room {} synced: {applied} new entries", short(channel_id)),
            NodeEvent::Shutdown => "the node stopped".into(),
        }
    }
}
