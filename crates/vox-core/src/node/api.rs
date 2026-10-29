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
    /// The room's shared name (ADR-028 R-1) — known only once the channel is **open** (it lives
    /// on the SEK-sealed log, ADR-010 double-lock), else `None`; `None` too for a room no admin
    /// has named.
    pub name: Option<String>,
    /// Whether the channel is open (SEK unlocked) in this session.
    pub open: bool,
    /// The room is recovering locally; its history is not yet available.
    pub preparing: bool,
    /// While preparing: what the room waits for, in words, and since when (unix ms), so a
    /// person can tell a stuck room from a slow one (ADR-038 FX-16, #991).
    pub waiting: Option<(String, u64)>,
    /// The rows this node shows of the room (0 while closed): every row `vox room read` pages
    /// through, as the room was last published, a body not received yet counting as the
    /// placeholder a person sees for it (ADR-038 FX-16, #995). A late joiner holds its rows
    /// below its contiguous feed, so this is not [`Self::log_entries`]: measured 2026-10-20, a
    /// member reading 115 rows was counted as holding 5.
    pub entries: u64,
    /// Accepted log entries in the contiguous feed (0 while closed): messages, and what no
    /// person is shown, such as read records (ADR-028 §6). What the room costs this node in
    /// storage and every sync in traffic, which a count of rows does not say.
    pub log_entries: u64,
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
    ends: Vec<usize>,
    len: usize,
}

/// A room's rendered timeline: [`Chunks`] of its rows.
pub type Timeline = Chunks<MessageRow>;

impl<T> Default for Chunks<T> {
    fn default() -> Self {
        Self {
            chunks: Vec::new(),
            ends: Vec::new(),
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
    pub fn get(&self, i: usize) -> Option<&T> {
        let chunk = self.ends.partition_point(|end| *end <= i);
        let start = chunk.checked_sub(1).map_or(0, |p| self.ends[p]);
        self.chunks.get(chunk)?.get(i - start)
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
        next.ends.push(next.len);
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
            next.ends.pop();
            next.ends.pop();
            next.ends.push(next.len);
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
                t.ends.push(t.len);
            }
        }
        if !chunk.is_empty() {
            t.len += chunk.len();
            t.chunks.push(chunk.into());
            t.ends.push(t.len);
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

/// The message domain selected before applying a bounded room-page limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoomView {
    /// General roots and currently unclassified owed placeholders.
    General,
    /// General's messages; clients add their separately bounded Session lifecycle notices.
    All,
    /// Every readable message carrying this exact tag, including thread replies.
    Tag(String),
}

/// A valid explicit thread reference, shared by indexed selection and message display.
#[must_use]
pub fn message_thread(text: &str) -> Option<Digest32> {
    vox_agentcomms::envelope::Envelope::parse(text)
        .ok()?
        .thread
        .and_then(|root| crate::node::link::b32_decode(root.trim(), "thread").ok())
}

/// The tags a message's text carries (#636): its envelope's `tags`, each a valid tag
/// ([`vox_agentcomms::envelope::is_valid_tag`]), none for prose or an envelope without them.
#[must_use]
pub fn message_tags(text: &str) -> Vec<String> {
    let trimmed = text.trim_start();
    if !trimmed.starts_with('{') {
        return Vec::new();
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return Vec::new();
    };
    let mut tags: Vec<String> = value
        .get("tags")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .filter(|t| vox_agentcomms::envelope::is_valid_tag(t))
        .take(vox_agentcomms::envelope::MAX_TAGS)
        .map(str::to_owned)
        .collect();
    tags.sort();
    tags.dedup();
    tags
}

/// Why a member is offered to this node's keyring (ADR-028 K-15, K-17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OfferWhy {
    /// It joined a room after this node did (K-15).
    Joined,
    /// It trusts this node: it granted it consent here (K-17, ADR-007 G-9).
    TrustsYou,
}

/// The log entry an offer of `member` rests on in one room: its join (its admission, or its
/// statement that it is back after leaving) or its consent grant to this node. An offer is derived
/// from these and never written as an entry of its own (K-15); a dismissal is kept against one
/// (K-18), so a new join or a new grant offers the member again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OfferBasis {
    /// The member offered.
    pub member: Digest32,
    /// What the entry is.
    pub why: OfferWhy,
    /// The entry's place in the member's feed.
    pub seq: u64,
}

/// A room an offer comes from, as the node names it here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferRoom {
    /// The room.
    pub id: Digest32,
    /// Its name as this node shows it ([`crate::node::resolver::room_shown_here`]).
    pub name: String,
}

/// A member offered to this node's keyring (ADR-028 K-15 – K-18): a node of a room it shares,
/// not in its keyring, that joined after it or trusts it, and that it has not dismissed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// The member offered.
    pub member: Digest32,
    /// The open rooms it is offered from, in channelID order.
    pub rooms: Vec<OfferRoom>,
    /// What a client says of it, word for word in the TUI and the app ([`vox_text::offer::said`]).
    pub said: String,
    /// Why, each reason once: joined, trusts you, or both.
    pub why: Vec<OfferWhy>,
    /// The members of this node's keyring that trust it (K-7), in fingerprint order.
    pub trusted_by: Vec<Digest32>,
}

/// A local arrival cursor bound to the saved room instance. Deleting and rejoining
/// a room resets this instance; an ordinary close/reopen preserves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryCursor {
    /// Opaque local store identity, never a room or trust identity.
    pub instance: [u8; 16],
    /// Strictly continue after this local arrival id.
    pub arrival: u64,
}

/// One bounded arrival-ordered history result. An explicit scan continuation may
/// accompany an empty filtered page; only its absence marks the end of this scan.
#[derive(Debug, Clone)]
pub struct MessagePage {
    /// Owned readable rows in this page.
    pub rows: Vec<MessageRow>,
    /// The saved room instance used by this page.
    pub instance: [u8; 16],
    /// Continue strictly after this cursor, even when there were no matching rows.
    pub next: Option<HistoryCursor>,
    /// The room's governance fold was behind its receipt frontier when this page was read
    /// (ADR-037 R3); see [`HistoryPage::provisional`].
    pub provisional: bool,
}

/// One reverse page of readable HELLO metadata for current room members. No historical
/// bodies or per-member history are retained by this reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberHelloPage {
    /// Saved room identity, checked on continuation.
    pub instance: [u8; 16],
    /// HELLO selection, current roster and read-policy equality token.
    pub revision: Digest32,
    /// True only for a completed caller's unchanged revision check.
    pub unchanged: bool,
    /// Newest first in canonical room order, at most 64 ordinary readable rows.
    pub rows: Vec<MessageRow>,
    /// Continue strictly before this examined canonical key, even on an empty page.
    pub next: Option<(u64, Digest32)>,
}

/// One bounded scan of readable files offered by private Session activity.
/// An empty page can still have a continuation after filtered records.
#[derive(Debug, Clone)]
pub struct SessionFilePage {
    /// Complete ordinary wire rows in this page, never assembled metadata bundles.
    pub rows: Vec<crate::node::drive::SessionRow>,
    /// The saved room instance used by this scan.
    pub instance: [u8; 16],
    /// Continue strictly after this private arrival; absent only at scan end.
    pub next: Option<HistoryCursor>,
}

/// Freshness of a bounded notice count. Ordinary append-only arrivals do not change it.
#[derive(Debug, Clone)]
pub struct NoticeRevision {
    pub(crate) incarnation: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub(crate) facts: [u64; 4],
}
impl PartialEq for NoticeRevision {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.incarnation, &other.incarnation) && self.facts == other.facts
    }
}
impl Eq for NoticeRevision {}

/// A notice scan's bounded freshness and arrival boundary from one actor read.
#[derive(Debug, Clone)]
pub struct NoticeState {
    /// Current saved room and newest readable arrival (zero for an empty room).
    pub head: HistoryCursor,
    /// Prefix/retention changes that require recounting.
    pub revision: NoticeRevision,
    /// The node's current wall clock, used for local retention deadlines.
    pub now_ms: u64,
}

/// One readable notice or reply parent, with its exact local retention deadline.
#[derive(Debug, Clone)]
pub struct NoticeRow {
    /// Owned authenticated row.
    pub row: MessageRow,
    /// A count using this row must be refreshed at this deadline; None means no expiry.
    pub expires: Option<u64>,
}

/// One bounded page of notice candidates, plus its exact freshness boundary.
#[derive(Debug, Clone)]
pub struct NoticePage {
    /// Readable, unexpired candidates only.
    pub rows: Vec<NoticeRow>,
    /// Continue after this cursor, including across an empty filtered page.
    pub next: Option<HistoryCursor>,
    /// State observed in the same short snapshot as the rows.
    pub state: NoticeState,
}

/// One bounded display page and the exact number of earlier visible rows.
#[derive(Debug, Clone)]
pub struct HistoryPage {
    /// Oldest first within this page, including owed placeholders.
    pub rows: Vec<MessageRow>,
    /// Rows strictly before the first returned row.
    pub older: u64,
    /// The room's governance fold was behind its receipt frontier when this page was read
    /// (ADR-037 R3): a control entry the node holds is not yet folded, so what this page shows
    /// may still be re-ordered or withdrawn. Never presented as final while true.
    pub provisional: bool,
}

/// A bounded governance selection carried by the existing room-page transport.
/// Continue a listing with its returned cursor and revision; a stale revision requires
/// reloading the selection. Authority queries refuse while their projection is refreshing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceQuery {
    /// Check one identity against current authority, including the genesis creator.
    Admin {
        /// Identity whose admin authority is requested.
        target: Digest32,
    },
    /// Page forward through notices between one visible message and the next.
    NoticesAfter {
        /// Visible message anchoring the range; none selects notices before the first message.
        entry: Option<Digest32>,
        /// Continue strictly after this canonical clock and entry hash within the range.
        after: Option<(u64, Digest32)>,
        /// Revision returned by the preceding page, or none for the first page.
        revision: Option<u64>,
    },
    /// Resolve one current service without scanning the room's shares.
    Service {
        /// Identity publishing the service.
        host: Digest32,
        /// Exact service name or base32 service fingerprint.
        selector: String,
    },
    /// Page backward through notices, returning each page in chronological order.
    Notices {
        /// Continue strictly before this canonical clock and entry hash; none selects newest.
        before: Option<(u64, Digest32)>,
        /// Revision returned by the preceding page, or none for the first page.
        revision: Option<u64>,
    },
    /// Page through current services whose hosts have not left the room.
    Shares {
        /// Continue strictly after this host and service-name hash; none starts the listing.
        after: Option<(Digest32, Digest32)>,
        /// Revision returned by the preceding page, or none for the first page.
        revision: Option<u64>,
    },
    /// Page through current admins other than the separately returned genesis creator.
    Admins {
        /// Continue strictly after this identity; none starts the listing.
        after: Option<Digest32>,
        /// Revision returned by the preceding page, or none for the first page.
        revision: Option<u64>,
    },
    /// Page through an author's current consent targets, including targets outside the roster.
    Consent {
        /// Consent author, or none for this node's identity.
        author: Option<Digest32>,
        /// Continue strictly after this target; none starts the listing.
        after: Option<Digest32>,
        /// Revision returned by the preceding page, or none for the first page.
        revision: Option<u64>,
    },
}

/// At most 64 inspected slots. Empty rows with a continuation are not exhaustion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernancePage {
    /// Current authority for one identity.
    Admin {
        /// Identity that was checked.
        target: Digest32,
        /// Whether that identity currently has admin authority.
        admin: bool,
        /// Governance revision used for this answer.
        revision: u64,
    },
    /// One exact service lookup.
    Service {
        /// Current share, or none when absent, withdrawn, or published by a departed host.
        share: Option<crate::node::channel::Share>,
        /// Governance revision used for this answer.
        revision: u64,
    },
    /// A chronological page within the requested visible-message range.
    NoticesAfter {
        /// Notices selected from this bounded page.
        rows: Vec<crate::node::channel::RoomNotice>,
        /// Continue strictly after this clock and hash; none exhausts the selected range.
        next: Option<(u64, Digest32)>,
        /// Revision to supply when continuing this selection.
        revision: u64,
    },
    /// A page selected backward through notices and returned in chronological order.
    Notices {
        /// Notices selected from this bounded page.
        rows: Vec<crate::node::channel::RoomNotice>,
        /// Continue strictly before this clock and hash; none exhausts older notices.
        before: Option<(u64, Digest32)>,
        /// Revision to supply when continuing this selection.
        revision: u64,
    },
    /// Current shares from one page, after filtering withdrawn shares and departed hosts.
    Shares {
        /// Current service announcements selected from this page.
        rows: Vec<crate::node::channel::Share>,
        /// Last inspected host and service-name hash; none exhausts the listing.
        next: Option<(Digest32, Digest32)>,
        /// Revision to supply when continuing this selection.
        revision: u64,
    },
    /// Current admin authority, with the creator separate from the paged identities.
    Admins {
        /// Genesis creator, whose authority is immutable.
        creator: Digest32,
        /// Active admin identities in fingerprint order, excluding the creator.
        members: Vec<Digest32>,
        /// Continue strictly after this identity; none exhausts the listing.
        next: Option<Digest32>,
        /// Revision to supply when continuing this selection.
        revision: u64,
    },
    /// One page of an author's current consent targets.
    Consent {
        /// Identity whose consent statements were selected.
        author: Digest32,
        /// Targets still covered by consent, including targets outside the roster.
        targets: Vec<Digest32>,
        /// Last inspected target; none exhausts the listing.
        next: Option<Digest32>,
        /// Revision to supply when continuing this selection.
        revision: u64,
    },
}

/// An open channel's full state for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelDetail {
    /// This node's durable room pause. It never gates direct operator input.
    pub pause: vox_agentcomms::drive::PauseState,
    /// Ordinary reply wakes at/below this saved readable-arrival boundary are held for a turn.
    /// Updated on resume; it is receiver-local and not a remote Session metadata cursor.
    pub pause_resume_after: u64,
    /// The channelID.
    pub channel_id: Digest32,
    /// The room's shared name (ADR-028 R-1); `None` for a room no admin has named.
    pub name: Option<String>,
    /// The current epoch.
    pub epoch: u64,
    /// Members, in fingerprint order.
    pub members: Vec<Digest32>,
    /// The newest readable local arrival; used to start bounded subscribers.
    pub last_arrival: Option<u64>,
    /// The saved instance that owns local arrival ids, preserved across reopen.
    pub history_instance: [u8; 16],
    /// Local reuse stamp for the already-built display; never serialized or sent to peers.
    pub(crate) display_stamp: crate::node::channel::DisplayStamp,
    /// Local indicator reuse token; never serialized or sent to peers.
    pub(crate) read_summary_stamp: crate::node::channel::ReadSummaryStamp,
    /// Node-local change token for the published timeline, unchanged on projection reuse.
    /// Scoped to this node actor; clients discard it when their node connection changes.
    pub display_revision: u64,
    /// The services this node offers in this channel: `(service_tag, local address)`
    /// in tag order (ADR-013 Bind config — host configuration, not authorization).
    pub services: Vec<(String, std::net::SocketAddr)>,
    /// Whether this node has completed the room's first sync since joining it (V210-164): until
    /// then its log may not yet hold what the room's members have written, shares included.
    pub synced: bool,
    /// Last contiguous authenticated position in this node's own room feed.
    pub own_feed_through: u64,
    /// The members this node holds back for equivocating in this room (V210-63): each
    /// `(author, seq)` at which two different messages signed by that author were seen.
    pub equivocations: Vec<(Digest32, u64)>,
    /// The room's genesis creator, its root admin (ADR-007).
    pub creator: Digest32,
    /// Current members this identity consents to, for roster indicators only.
    /// Arbitrary consent targets are read through GovernanceQuery::Consent.
    pub member_consent: Vec<Digest32>,
    /// Revision of the checked governance projection used by this display.
    pub governance_revision: u64,
    /// Whether retained ciphertext still has bounded rendering work queued. This is published
    /// with the room view so status can distinguish parked missing-fact state from active work.
    pub render_backfill_pending: bool,
    /// Members still owed any generation of this node's sender key, from the durable delivery
    /// ledger. The live actor may additionally have an admitted delivery in flight.
    pub key_delivery_pending: Vec<Digest32>,
    /// The other members that consent to this identity reading them here, in fingerprint order:
    /// the inbound half of `member_consent`, off the log the same way (V030-17).
    pub consenting: Vec<Digest32>,
    /// Who trusts each member here (ADR-028 K-7): `(member, the other members that consent to it
    /// reading them)`, in fingerprint order, a member no one trusts left out. `consenting` is this
    /// identity's own entry.
    pub trusted_by: Vec<(Digest32, Vec<Digest32>)>,
    /// What each other member could be offered to this node on here (ADR-028 K-15, K-17), off the
    /// log; whether it is offered is decided over every room, the keyring and the dismissals.
    pub offer_bases: Vec<OfferBasis>,
    /// The retention this node applies here, seconds (`0` forever): the shorter of the room's
    /// and the node's own (ADR-023 decision 2). What `vox status` reports. Carried in the view
    /// so a reader never has to take the room's lock, which a sync session holds while it runs.
    pub retention: u64,
    /// Configured room message retention, seconds; zero means forever.
    pub room_retention: u64,
    /// Configured room Session step retention, seconds; zero means forever.
    pub room_step_retention: u64,
    /// Effective Session retention, capped by room and node message policies.
    pub step_retention: u64,
    /// This node's explicit Session retention override, if any.
    pub local_step_retention: Option<u64>,
    /// `(what this node's own retention file asks, the room's)`, seconds, when the file asks to
    /// keep the room's messages longer than the room does (V030-32): ignored, the room's is in
    /// force, and the node says so. Carried in the view so a daemon says it from what the node
    /// holds, not only from the one-time event, which a subscriber started after it, or one that
    /// fell behind, never receives.
    pub retention_above_room: Option<(u64, u64)>,
    /// How many generations of this node's own sender key it still holds here (PRD-001 R14).
    pub key_generations: usize,
    /// How many generations of other members' sender keys it holds here (PRD-001 R14 on the
    /// receiving side).
    pub received_key_generations: usize,
    /// Whether a bounded scan or retained key-package replay still owes this room another turn.
    pub key_packages_pending: bool,
    /// Authors this node froze here for signing two entries at one position (ADR-008).
    pub frozen: Vec<Digest32>,
    /// Entries this node refused here as at or below their author's checkpoint since it opened
    /// the room (ADR-023 decision 3).
    pub refused_below_checkpoint: u64,
    /// Who has read this node's own recent messages, as the read records it can open say
    /// (ADR-028 RR-3, R-6): `(entry, readers)` for each of its newest
    /// [`crate::node::channel::READ_BY_SHOWN`] messages that any member is known to have read,
    /// oldest first. A member whose records this node cannot open is in none of them.
    pub read_by: Vec<(Digest32, Vec<Digest32>)>,
    /// Where this node's own recent messages are (ADR-028 R-6): `(entry, how many of the room's
    /// other members' nodes said they hold it)`, oldest first, for the same messages as
    /// [`Self::read_by`] looks at.
    pub held: Vec<(Digest32, u64)>,
    /// Last authenticated position each member said it holds in this node's feed.
    pub held_through: Vec<(Digest32, u64)>,
    /// Last authenticated, role-complete position this node holds in each member's feed.
    pub holds_through: Vec<(Digest32, u64)>,
    /// What this node's person has not read here, oldest first
    /// ([`crate::node::channel::ChannelState::unread`]): what a client counts at its start.
    pub unread: Vec<Digest32>,
    /// The nodes whose Sessions this node can read inside here (ADR-029 SC-2), sorted: itself, and
    /// each node whose drive key it holds. What a Session's `can_drive` is said from.
    pub drive_from: Vec<Digest32>,
    /// Opaque Session input/publication/drive token; no retained metadata strings.
    pub session_revision: Digest32,
}

/// The node's latest-wins view (published over a `watch`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NodeView {
    /// Exact actor-applied Computer policy of these trust rows. Internal publication metadata,
    /// copied with the rows; never inferred from a separately observed atomic revision.
    pub(crate) computer_policy: Option<(u64, bool)>,
    /// Display-only last-known anchors of every saved room, separate from dialing authority.
    pub room_anchors: Vec<RoomAnchorView>,
    /// Actual dial observations for anchors this running node uses, not saved provenance.
    pub anchor_reach: Vec<(Digest32, crate::node::daemonipc::AnchorReach)>,
    /// Why the saved-room inventory could not be read or kept. Never an empty-list success.
    pub anchor_inventory_error: Option<String>,
    /// The profile's identity, or `None` before one is created.
    pub identity: Option<IdentityInfo>,
    /// `(room, member, said)`: what is said of a member about this identity's key, after its name
    /// (ADR-030 D-5, W-4): that the key waits, and why, or that it runs an older Vox and reads
    /// without post-compromise protection. In room and member order.
    pub key_waits: Vec<(Digest32, Digest32, String)>,
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
    /// Authenticated remote self-names, held only in memory; never keyring or authority.
    pub presented: Vec<(Digest32, String)>,
    /// The keyring entries that carry drive (ADR-028 K-14), in fingerprint order; every other
    /// entry in [`NodeView::trusted`] grants read.
    pub drive: Vec<Digest32>,
    /// The members offered to the keyring (ADR-028 K-15 – K-18), in fingerprint order; empty while
    /// locked.
    pub offers: Vec<Offer>,
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

/// One saved room's last-known anchor provenance, for the daemon's shared list only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomAnchorView {
    /// The room identity.
    pub room: Digest32,
    /// Its last observed shared name, if it has one.
    pub name: Option<String>,
    /// The room's own anchors, excluding member addresses carried by a link.
    pub anchors: crate::nat::bootstrap::BootstrapSet,
    /// This observation could not be refreshed: the room is closed, locked or busy.
    pub stale: bool,
    /// When this node last observed a change to the displayed name or anchor set, in Unix ms.
    pub observed_at: u64,
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

/// An explicit local request for bounded peer history. Cache queries never construct this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoryDemandAction {
    /// Select a bounded missing interval near the newest accepted head.
    Newest,
    /// Select an older interval before this exact cached message.
    Older {
        /// Exact cached message before which the bounded interval is selected.
        before: Digest32,
    },
    /// Recover the next bounded sequential private interval from this exact donor.
    PrivateRecover {
        /// Exact donor whose next private interval is recovered.
        peer: Digest32,
    },
    /// Resume this exact retained operation, preserving its original bounds.
    Resume {
        /// Exact retained operation to resume.
        request: [u8; 16],
    },
    /// Cancel this exact retained operation, including provisional body storage.
    Cancel {
        /// Exact retained operation to cancel.
        request: [u8; 16],
    },
    /// Inspect saved progress; never starts or resumes traffic.
    Status,
}

/// Public progress for one explicit archive operation; partial progress is not synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryDemandPhase {
    /// No retained request exists.
    Idle,
    /// This bounded selection is already available locally.
    Cached,
    /// Local bounded selection or durable request preparation is running.
    Preparing,
    /// The explicit request is queued or running.
    Pending,
    /// This quantum ended with more within the original selection; explicit resume is required.
    More,
    /// Retained work is inactive, including after restart.
    Paused,
    /// The requested evidence or a suitable peer is presently unavailable.
    Unavailable,
    /// This bounded logical selection completed; older history may still exist.
    Complete,
    /// The request is cancelled; bounded provisional cleanup may remain.
    Cancelled,
    /// Another bounded operation owns the available reservation.
    Busy,
}

/// Redaction-safe, bounded progress returned to the CLI and app.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryDemandStatus {
    /// Private Drive scope; absent for public room history.
    #[serde(default)]
    pub private_peer: Option<Digest32>,
    /// Original donor-local private interval; unchanged by continuation.
    #[serde(default)]
    pub private_lo: Option<u64>,
    /// Inclusive high bound of the original donor-local private interval.
    #[serde(default)]
    pub private_hi: Option<u64>,
    /// Selected room.
    pub room: Digest32,
    /// Exact saved room incarnation.
    pub instance: [u8; 16],
    /// Current operation, when one was durably created.
    pub request: Option<[u8; 16]>,
    /// Public operation state.
    pub phase: HistoryDemandPhase,
    /// Author selected for this exact-head page.
    pub author: Option<Digest32>,
    /// Original accepted head, never widened by a peer continuation.
    pub head: Option<Digest32>,
    /// Remaining entries in the original authorized interval; this may exceed one quantum.
    pub remaining: usize,
    /// Persisted partial-body offset; ACK never precedes it.
    pub offset: u64,
    /// Maximum headers authorized for the logical page.
    pub headers: usize,
    /// Maximum total wire bytes per response quantum, including protocol traffic.
    pub wire_bytes: usize,
    /// Short operational explanation, never a body or secret.
    pub detail: String,
}

/// A command from a client to the node.
#[derive(Debug)]
pub enum NodeCommand {
    /// Explicit local archive demand, distinct from all cache/page/watch APIs.
    HistoryDemand {
        /// Selected room.
        channel_id: Digest32,
        /// Exact saved room incarnation from the caller's displayed selection.
        instance: [u8; 16],
        /// One explicit start, continuation, cancellation or status operation.
        action: HistoryDemandAction,
        /// Answer after bounded local preparation; no peer round trip blocks the actor.
        reply: tokio::sync::oneshot::Sender<Result<HistoryDemandStatus, String>>,
    },
    /// One private bounded attention operation, authenticated by the receiving transport.
    Attention {
        /// Exact room.
        channel_id: Digest32,
        /// Authenticated sender; mutations require this node's own identity.
        by: Digest32,
        /// Captured receiver-local room incarnation, when supplied by an owned caller.
        expected_instance: Option<[u8; 16]>,
        /// Selected query or local daemon mutation.
        operation: crate::node::attention::Operation,
        /// Answer after any mutation is sealed.
        reply: tokio::sync::oneshot::Sender<Result<crate::node::attention::Reply, String>>,
    },
    /// Read or change the local room pause. Only the authenticated drive receiver constructs
    /// a change; the actor rechecks current authority before sealing it.
    RoomPause {
        /// Exact room.
        channel_id: Digest32,
        /// Authenticated app-stream sender, or this node for its own socket.
        by: Digest32,
        /// Set pause/resume; `None` reads the saved state.
        paused: Option<bool>,
        /// Captured local room instance; checked with the mutation under the room lock.
        expected_instance: Option<[u8; 16]>,
        /// Existing receiver room incarnation/state when continuing an interrupt page.
        expected: Option<vox_agentcomms::drive::PauseSelection>,
        /// Already acquired outside the actor; kept through a queued mutation even if its
        /// caller is cancelled. The actor never waits for this hook-publication fence.
        publication_guard: Option<std::fs::File>,
        /// Answer only after durable state and its current view have been updated.
        reply: tokio::sync::oneshot::Sender<Result<vox_agentcomms::drive::PauseSelection, Fault>>,
    },
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
    /// Replace this node's manual anchors with the daemon's current machine set.
    ///
    /// The set is resolved when configuration is read, so a long-running node holds the
    /// addresses it got at startup. An anchor named by hostname — which is the point of
    /// naming one by hostname — moves when its ISP decides, and the node would keep
    /// redialling the old address for ever. This is how a re-resolved set reaches a node
    /// that is already running.
    SetAnchors {
        /// The complete freshly resolved machine set, including an empty set after removal.
        anchors: crate::nat::bootstrap::BootstrapSet,
    },
    /// Unlock the identity.
    Unlock {
        /// The identity passphrase.
        passphrase: Secret,
    },
    /// Internal bounded ownership for an accepted unlock while policy work is pending.
    #[doc(hidden)]
    UnlockAdmitted {
        passphrase: Secret,
        permit: tokio::sync::OwnedSemaphorePermit,
    },
    /// Create a channel (needs the unlocked identity).
    CreateChannel {
        /// The room's shared name, one DNS label (ADR-028 R-1, R-2).
        name: String,
        /// The channel passphrase (the second lock factor).
        passphrase: Secret,
        /// Explicitly chosen room anchors; never inherited from machine settings.
        anchors: crate::nat::bootstrap::BootstrapSet,
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
    /// Author a message only in the saved room incarnation captured by its composer.
    SendTextAt {
        /// The channelID.
        channel_id: Digest32,
        /// The text.
        text: String,
        /// The saved room incarnation observed before sending.
        instance: [u8; 16],
    },
    /// Capture the exact open room incarnation before a plain post may wait. Internal to node
    /// clients; the result crosses its own typed reply and is never accepted from IPC.
    PreparePost {
        /// The channel to post to.
        channel_id: Digest32,
        /// The incarnation observed under the room lock, or the exact refusal.
        reply: tokio::sync::oneshot::Sender<Result<[u8; 16], Fault>>,
    },
    /// Note that these entries of an open channel were shown to this node's person, or drained
    /// into its agent's turn (ADR-028 RR-1). Done means their local read marks are durably
    /// stored. The node later publishes a signed read record, at most one per room per
    /// 5 seconds (RR-2); a deferred publication does not lose the local marks.
    MarkRead {
        /// The channelID.
        channel_id: Digest32,
        /// The entries shown.
        entries: Vec<Digest32>,
        /// When supplied, admission must use this exact saved room incarnation.
        expected_instance: Option<[u8; 16]>,
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
        /// The channel passphrase.
        passphrase: Secret,
    },
    /// Authenticate a held room's supplied passphrase without admitting a member.
    CheckRoomPassphrase {
        /// The held room.
        channel_id: Digest32,
        /// Supplied by the operator over the local control socket.
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
        /// What the entry grants (ADR-028 K-14); `None` keeps what it grants now, and read for a
        /// new entry.
        capability: Option<crate::node::trust::Capability>,
    },
    /// Change what a trusted identity's keyring entry grants, read or read + drive (ADR-028
    /// K-14): a keyring change, behind the passphrase gate. Fails with [`Fault::NotConsented`]
    /// for an identity that is not trusted.
    SetCapability {
        /// The trusted identity.
        fingerprint: Digest32,
        /// What its entry grants from now on.
        capability: crate::node::trust::Capability,
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
    /// Dismiss the offer of `member` (ADR-028 K-18): on this node alone, and silently; the member
    /// is not told and stays out of the keyring. Kept against the entries the offer rests on, so a
    /// later join or grant offers it again.
    DismissOffer {
        /// The member offered.
        member: Digest32,
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
        /// The room's shared name, one DNS label (ADR-028 R-1, R-2).
        room: String,
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
        /// What the service is, as detected before it was offered (ADR-028 S-2,
        /// [`crate::node::probe::detect`]): said to the room with the share.
        kind: crate::governance::share::ServiceKind,
        /// Whether the offer outlives this node's run. `false` for an offer that lasts only as
        /// long as what made it: a client's connection (V210-72), or a file share.
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
    /// Set the room's Session retention, or this member's shorter local rule.
    SetStepRetention {
        /// The room to change.
        channel_id: Digest32,
        /// Seconds to retain Session entries; zero means forever.
        seconds: u64,
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
    /// Name a room for every member (ADR-028 R-1): a room-name statement on its log. Only its
    /// creator or an admin may.
    RenameRoom {
        /// The channel.
        channel_id: Digest32,
        /// The new name, one DNS label (ADR-028 R-2).
        name: String,
    },
    /// Add/remove room anchors by appending the resulting complete signed set (ADR-032 AN-5).
    ChangeRoomAnchors {
        /// The room.
        channel_id: Digest32,
        /// Anchors to add, replacing addresses for an identity already present.
        add: crate::nat::bootstrap::BootstrapSet,
        /// The anchor to remove, if any.
        remove: Option<Digest32>,
    },
    /// Append one entry of a Session (ADR-029 SC-1), sealed under this node's drive key so only
    /// members it trusts with drive read it (SC-2).
    AppendSession {
        /// The channel.
        channel_id: Digest32,
        /// The harness's own session id.
        session_id: String,
        /// The activity item.
        body: String,
    },
    /// Persist a complete Session activity batch before acknowledging it. Delivery is local,
    /// bounded work on the actor's tick, independently of the producer's lifetime.
    AcceptSessionBatch {
        /// Destination captured by the registered session at admission.
        channel_id: Digest32,
        /// The harness session.
        session_id: String,
        /// Unnumbered shared-format activity, within the ingress batch bound.
        bodies: Vec<String>,
        /// Exact committed range, or the saving/refusal error. Never a network receipt.
        reply: tokio::sync::oneshot::Sender<crate::node::session_ingress::AdmissionResult>,
    },
    /// Finish a hosted daemon's ordered cleanup after it retired this room's volatile tails
    /// and session bindings. Does not delete room history or reset persistent counters.
    RetireSessionRoom {
        /// The exact deletion whose saved bindings the owner cleared.
        retirement: crate::node::session_ingress::Retirement,
        /// Receipt for the final inbox cleanup.
        reply: tokio::sync::oneshot::Sender<crate::error::Result<()>>,
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
    /// Individual permissions cannot contradict an active computer policy.
    ComputerPolicy,
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
    /// Identity is Ready; this room is still preparing its saved state.
    RoomPreparing,
    /// The room's signed history format is no longer supported.
    UnsupportedRoomFormat,
    /// An input exceeded its bound (name or text length).
    TooLong,
    /// A trust add or remove needs the identity passphrase: it was not entered for a keyring
    /// change within [`KEYRING_WINDOW_MS`](crate::node::actor::KEYRING_WINDOW_MS) (V210-159,
    /// ADR-028 K-12). Not
    /// [`Fault::WrongPassphrase`]: none was given, and the client asks for it and tries again.
    PassphraseNeeded,
    /// An identity was to be made with an empty passphrase, refused by v0.4.0 to v0.4.2 (ADR-028
    /// K-11 before its amendment). No longer sent: an empty one is taken (ADR-005 J-2); kept so
    /// an older daemon's refusal still reads.
    PassphraseEmpty,
    /// The trust keyring already holds its maximum number of identities
    /// (`trust::MAX_TRUSTED`). Not [`Fault::TooLong`]: nothing the person typed was too
    /// long, and "longer than this field allows" sent them looking at the petname.
    KeyringFull,
    /// This node already offers the maximum services in this room, including file shares.
    /// A valid new offer name is not too long; an existing offer must be stopped first.
    ServiceOffersFull,
    /// The store failed; the channel may be poisoned until reopened.
    Storage,
    /// Another vox holds this profile's store open for writing, and only one at a time may.
    /// Not [`Fault::Internal`], which is how an unlock that met one was reported (V210-100):
    /// nothing was wrong with vox or the profile, and stopping the other one is the remedy.
    ProfileBusy,
    /// Local pairwise delivery capacity is occupied; no new key was sealed or grant recorded.
    DeliveryBusy,
    /// Stored governance is being brought current; no permission decision may use its old view.
    GovernanceRefreshing,
    /// The requested read marks no longer name the room's readable retained selection.
    ReadSelectionChanged,
    /// The composer selected a room incarnation that no longer exists; no text was appended.
    PostSelectionChanged,
    /// A prior local room change/open still owes its checked publication; no new write began.
    RoomChangePending,
    /// Trust was removed durably, but at least one room still needs its withdrawal completed.
    TrustRemovalIncomplete,
    /// This node already has its bounded number of posts waiting to enter the actor.
    PostBusy,
    /// One admin removal is already being applied over bounded actor turns.
    AdminChangePending,
    /// A previous hosted room deletion is still awaiting its bounded daemon handoff.
    SessionCleanupBusy,
    /// The hosted daemon's reliable Session cleanup handler has gone away.
    SessionCleanupUnavailable,
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
    /// The room's last place went to another newcomer joining at the same moment: a member asked
    /// had already promised it (V030-30, #366). Nobody was admitted on this joiner's account.
    SeatTaken,
    /// A member online did not agree to the newcomer within the bound, or does not yet count the
    /// answering member a member (V030-30, #366): every member online must agree before the room
    /// takes a newcomer. The reason names the member.
    SeatNotAgreed,
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
    /// A member holds entries of this node's own feed that this node does not (ADR-037 R5): a
    /// restored older profile. Nothing is written in that room until the person resolves it.
    OwnHistoryBehind,
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
    /// A room's name was not one DNS label (ADR-028 R-2).
    NotARoomName,
    /// A room was to be created or joined under a name a room this node holds already has
    /// (ADR-028 R-3).
    RoomNameTaken,
    /// A member who is not the room's creator or an admin asked to keep the room's messages
    /// **longer** than the room does (V030-32). A member may set a shorter retention, which
    /// governs only their own node; never a longer one.
    AboveRoomRetention,
    /// The room is over: its creator ended it, or its idle end ran out (V030-08). It takes no
    /// new message.
    RoomEnded,
    /// This identity has left the room (V210-164): nothing more of its is written there, not even
    /// a read record, which would undo the leave.
    RoomLeft,
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
    const _KEYRING_WINDOW_NAMED: () =
        assert!(crate::node::actor::KEYRING_WINDOW_MS == 30 * 60 * 1_000);

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
            Fault::IdentityExists => {
                "this node already has an identity\n       use it: `vox node unlock` unlocks it; for another node, vox node create and a name for it"
            }
            Fault::Locked => {
                "the identity is locked\n       unlock it: pipe the identity passphrase to `vox daemon`, or run `vox tui`"
            }
            Fault::WrongPassphrase => {
                "the passphrase is wrong\n       check it and type it again"
            }
            Fault::ComputerPolicy => "computer trust changed while this command was being applied\n       review the current policy and retry the command",
            Fault::PassphraseNeeded => {
                "changing who you trust needs your identity passphrase: it was not entered for a keyring change in the last 30 minutes\n       type it, and the change is made: `vox trust` asks for it at a terminal"
            }
            Fault::PassphraseEmpty => {
                "every node has an identity passphrase, and an empty one is refused; nothing was created\n       choose one, and run it again"
            }
            Fault::UnknownChannel => {
                "no such room on this node\n       `vox room list` shows the rooms it holds"
            }
            Fault::RoomPreparing => {
                "that room is preparing its saved history; the node is Ready, and the room will become available when preparation finishes — no passphrase is needed"
            }
            Fault::UnsupportedRoomFormat => crate::node::channel::UNSUPPORTED_ROOM_FORMAT,
            Fault::ChannelNotOpen => {
                "that room is not open on this node\n       open it with its passphrase: a line holding the room's id and its passphrase to `vox daemon`, or in `vox tui`"
            }
            Fault::TooLong => {
                "that is longer than this field allows\n       shorten it, and try again"
            }
            // The cap in force, read once (#85): a test build's lowered cap is never called 1,024.
            Fault::KeyringFull => {
                static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
                TEXT.get_or_init(|| {
                    format!(
                        "your trust keyring is full ({} identities)\n       remove one with \
                         vox trust remove and its fingerprint (`vox trust list` shows them), then \
                         add again",
                        crate::node::trust::trust_cap_words()
                    )
                })
            }
            Fault::ServiceOffersFull => {
                static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
                TEXT.get_or_init(|| {
                    format!(
                        "this node's room service offers are full ({} offers, including file shares)\n       stop an unused file share or remove an unused service offer from this room, then try again",
                        crate::node::channel::MAX_SERVICES
                    )
                })
            }
            Fault::Storage => {
                "the node's store could not be read or written\n       check free disk space, and that the data directory is writable and its files undamaged"
            }
            Fault::ProfileBusy => {
                "another vox holds this node open, and only one at a time may write it\n       run this again once that one is done; a `vox daemon` or `vox tui` holds it until stopped, and the `vox room …` verbs ask it instead"
            }
            Fault::DeliveryBusy => {
                "this node's key-delivery capacity is busy; the key waits locally\n       existing deliveries are retried; no new grant was recorded by this attempt"
            }
            Fault::GovernanceRefreshing => {
                "this room's permissions are still being read from local storage\n       try again once the room is ready"
            }
            Fault::ReadSelectionChanged => {
                "the selected messages changed before they could be marked as read\n       refresh the room and try again"
            }
            Fault::PostSelectionChanged => {
                "the room changed before sending; this message was not posted\n       refresh the room and try again"
            }
            Fault::RoomChangePending => {
                "a previous change to this room is still being applied; this request made no change\n       wait for its answer before changing the room again"
            }
            Fault::TrustRemovalIncomplete => {
                "trust was removed, but at least one room could not finish its withdrawal; its saved work remains pending\n       restart the node to finish narrowing before using that room"
            }
            Fault::PostBusy => {
                "this node already has too many posts waiting; this message was not posted\n       wait for those posts to finish, then try again"
            }
            Fault::AdminChangePending => {
                "an admin change is already being applied on this node\n       wait for its answer before making another admin change"
            }
            Fault::SessionCleanupBusy => {
                "an earlier room's Session cleanup is still pending; no deletion started for this request\n       try again after that cleanup finishes"
            }
            Fault::SessionCleanupUnavailable => {
                "the daemon's Session cleanup handler is unavailable; no deletion started for this request\n       restart the daemon before trying again"
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
                 or copied from another node's data directory"
            }
            Fault::ShuttingDown => {
                "the node is shutting down\n       make it Ready again (`vox node unlock`), then try again"
            }
            Fault::NotNetworked => {
                "this node is not on the network\n       make it Ready with `vox node unlock`, which unlocks it and puts it on the network"
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
            Fault::SeatTaken => {
                "another newcomer took the room's last place at the same moment, so you were not admitted\n       your passphrase was accepted; try again"
            }
            Fault::SeatNotAgreed => {
                "a member of the room did not agree to take you in, so you were not admitted\n       every member online must agree before the room takes a newcomer; the member is named below\n       your passphrase was accepted; try again"
            }
            Fault::NotAdmittedAfterJoin => {
                "a member accepted your passphrase, then could not admit you, so you were not admitted\n       the member may have been locking or closing; run the join again while it is running"
            }
            Fault::Refused => {
                "the other side refused, and said no more\n       ask the person who runs it; this node's log names the side that refused"
            }
            Fault::NotAdmitted => {
                "that member is not admitted to the room on this node yet\n       it is, once this node syncs their records; then try again"
            }
            Fault::NotConsented => {
                "that identity is not in your keyring\n       `vox trust list` shows who is; vox trust add and its fingerprint adds one"
            }
            Fault::NotTrusted => {
                "that identity is not in your trust keyring, so it is given no key to read you\n       run vox trust add with its fingerprint if you mean it to read you"
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
            Fault::BindFailed => {
                "a local address it was asked to use could not be listened on\n       another program may hold it: choose another port, or stop that program"
            }
            Fault::AlreadyMember => {
                "this node already holds that room — there is nothing to join\n       `vox room list` shows it; open it with its passphrase if it is closed"
            }
            Fault::RoomNotSynced => {
                "this room was joined and has not yet synced with another member, so nothing can be written to it\n       try again once a member is reachable"
            }
            Fault::OwnHistoryBehind => {
                "this node's record of its own history in this room is behind what a member holds, as after restoring an older backup; it writes nothing here until that is resolved\n       `vox status --node <name>` names the room; a profile restored from a backup must not write where a newer copy of it already has"
            }
            Fault::LeaveNotHeard => {
                "no other member of the room could be told within 30s, so this node still holds it\n       it leaves as soon as one can be told, and the members see it then"
            }
            Fault::LeaveUndone => {
                "something was written in the room from this node after the leave, so it is in the room again\n       run `vox room leave` again to leave"
            }
            Fault::NotAServiceRoom => {
                "that room offers no service by name, so it has no .vox name to resolve\n       reach a shared service with vox forward and its .vox address, which `vox service list` shows"
            }
            Fault::RoomNameTaken => {
                "a room this node holds already has that name, and a node holds one room of a name: nothing was made\n       it is the room part of every service address; rename the room it holds (`vox room rename`), or name the new one otherwise"
            }
            Fault::NotARoomName => {
                "a room name is one DNS label: 1 to 63 of a-z, 0-9 and `-`, not starting or ending with `-`\n       it is the room part of every service address"
            }
            Fault::AboveRoomRetention => {
                "a member may keep this room's data for less time than the room does, never longer\n       ask the room's creator or an admin (`vox room admin list`) to change the room's retention"
            }
            Fault::NotAdmin => {
                "only the room's admin may change that, and this identity is not its admin\n       the room's creator and the admins it named are; `vox room admin list` shows who"
            }
            Fault::RoomEnded => {
                "this room has ended — its creator or an admin ended it, or nothing was said in it for the idle end its creator chose — so it takes no new message\n       this node deletes it once it has passed the end on"
            }
            Fault::RoomLeft => {
                "you left this room, so nothing more of yours is written to it\n       join it again with its link to write to it"
            }
            Fault::NotCreator => {
                "only the room's creator, or an admin it delegated, may do that — and this identity is neither\n       ask the room's creator to do it, or to make you an admin"
            }
            Fault::JoinedRoomEnded => {
                "that room has ended — a member or its board said so — so it takes nobody in\n       your passphrase was never checked; the room is over, not your access to it"
            }
            Fault::ResponderLeft => {
                "the member that answered has left that room, so it lets nobody in\n       your passphrase was never checked; ask a member still in the room for an address"
            }
            Fault::NotRoomCreator => {
                "only the room's creator adds or removes an admin, and this identity did not create the room\n       ask the room's creator to do it"
            }
            Fault::NotAnAdmin => {
                "that member is not an admin of the room\n       `vox room admin list` shows who is"
            }
            Fault::NotOffered => {
                "that service is not offered in this room\n       check its name: it is the tag that was given to `vox service add`"
            }
            Fault::NameTaken => {
                "you already share a service under that name in this room\n       choose another name, or `vox service remove` the one you share first"
            }
            Fault::NoSuchForward => {
                "no forward is listening at that local address\n       `vox status` lists the forwards that are open"
            }
            Fault::TunnelLimit => {
                "16 tunnels are already open to this member\n       to free one: `vox tunnel close` it (`vox status` lists every tunnel, its number, and when it last moved), or close the program using it, or the `vox forward` carrying it; on the host, `vox service remove` the service, or `vox trust remove` the member"
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
    ComputerPolicy,
    NoIdentity,
    IdentityExists,
    Locked,
    WrongPassphrase,
    PassphraseNeeded,
    PassphraseEmpty,
    UnknownChannel,
    ChannelNotOpen,
    RoomPreparing,
    UnsupportedRoomFormat,
    TooLong,
    KeyringFull,
    ServiceOffersFull,
    Storage,
    ProfileBusy,
    DeliveryBusy,
    GovernanceRefreshing,
    ReadSelectionChanged,
    PostSelectionChanged,
    RoomChangePending,
    TrustRemovalIncomplete,
    PostBusy,
    AdminChangePending,
    SessionCleanupBusy,
    SessionCleanupUnavailable,
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
    SeatTaken,
    SeatNotAgreed,
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
    OwnHistoryBehind,
    LeaveNotHeard,
    LeaveUndone,
    NotAServiceRoom,
    NotOffered,
    NameTaken,
    NoSuchForward,
    NotAdmin,
    NotARoomName,
    RoomNameTaken,
    AboveRoomRetention,
    RoomEnded,
    RoomLeft,
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
    /// A Session entry was appended (ADR-029 SC-1): its entry hash, which a later entry's `re`
    /// names.
    Appended(Digest32),
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
            Outcome::Done | Outcome::Bound(_) | Outcome::OwnRetention { .. } | Outcome::Appended(_)
        )
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Outcome::Done => f.write_str("done"),
            Outcome::Bound(local) => write!(f, "bound at {local}"),
            Outcome::Appended(entry) => {
                write!(f, "appended {}", crate::node::link::b32_encode(entry))
            }
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
    /// Whether a keyring entry carries drive changed (ADR-028 K-14): granted, taken back, or gone
    /// with the entry. Raised once per change that moves it, so a node's Sessions can release
    /// their key to a member that gained drive and rotate it away from one that lost it (ADR-029
    /// SC-2a, SC-2b).
    CapabilityChanged {
        /// The identity whose entry changed.
        fingerprint: Digest32,
        /// Whether it now carries drive.
        drive: bool,
    },
    /// Creating the identity has waited more than a second for another vox that holds this
    /// profile's lock (it is creating the identity, or holds the profile, or is stopped while
    /// doing so). Sent once per wait; the command goes on when the lock is free. Each front end
    /// says it in its own place: the CLI on stderr, the TUI in its status line (V210-100). A wait
    /// to open an existing profile comes before the node exists, and is said through
    /// [`NodeConfig::on_profile_wait`](crate::node::actor::NodeConfig::on_profile_wait).
    WaitingForProfile,
    /// A Session entry was written here, or reached this node and opened (ADR-029 CL-2): the
    /// session `session_id` in the room `channel_id` has news. Its entries are not room messages,
    /// so no other event says so.
    SessionEntry {
        /// The room.
        channel_id: Digest32,
        /// The harness's session id.
        session_id: String,
    },
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
            NodeEvent::SessionEntry { session_id, .. } => {
                format!(
                    "new activity in Session {}",
                    session_id.chars().take(8).collect::<String>()
                )
            }
            NodeEvent::CapabilityChanged { fingerprint, drive } => {
                if *drive {
                    format!("{} can now drive this node's Sessions", short(fingerprint))
                } else {
                    format!(
                        "{} can no longer drive this node's Sessions",
                        short(fingerprint)
                    )
                }
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

/// Scalar unread facts under the existing newest-1,000-rows, until-first-read rule.
/// No retained message bodies or lifetime message IDs cross this boundary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnreadSummary {
    /// Unread messages addressed to this identity.
    pub addressed: u64,
    /// Urgent messages among those addressed to this identity.
    pub urgent: u64,
    /// Unread room conversation.
    pub new: u64,
    /// Unread coordination messages.
    pub coordination: u64,
    /// Oldest unread message in the examined range, in display order.
    pub first: Option<Digest32>,
    /// Older rows exist beyond the existing unread examination limit.
    pub scan_limited: bool,
}

/// Exact displayed-message footer selection. Recipient pages never imply a complete list
/// while their continuation is present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FooterSelection {
    /// Exact retained message.
    pub entry: Digest32,
    /// Continue signed/local readers strictly after this identity.
    pub read_after: Option<Digest32>,
    /// Continue completed fetches at this stable disk byte position.
    pub pulled_after: Option<u64>,
}
/// One bounded recipient page for one own message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageFooter {
    /// Selected entry, including when it is no longer visible.
    pub entry: Digest32,
    /// Still a readable own rendered message in this saved room.
    pub present: bool,
    /// Reader identities in this page.
    pub read_by: Vec<Digest32>,
    /// More readers remain when present.
    pub read_after: Option<Digest32>,
    /// Other members whose current highwater covers this message.
    pub held: u64,
    /// Current other-member count.
    pub others: u64,
    /// Completed fetch identities in this page.
    pub pulled_by: Vec<Digest32>,
    /// More receipt records remain when present; an empty page can still continue.
    pub pulled_after: Option<u64>,
}
