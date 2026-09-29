//! Per-channel state for the single-device node (ADR-016 M13.3): create a
//! channel, open it from the store, append and render messages, and persist
//! every step as sealed segments.
//!
//! ## What a channel is, at rest
//! Under the channel's SEK (ADR-010), sealed segments in the profile store:
//! - `KeyMaterial 0` — the **manifest**: `[1, genesis_wire, local_name, created,
//!   epoch]`. The genesis is the trust anchor (ADR-007); `local_name` is this
//!   device's label, never protocol state.
//! - `KeyMaterial 1` — this identity's **sender chain** state
//!   ([`SenderChain::to_state`]), advanced and re-sealed on every append.
//! - `LogDb n` (`n ≥ 1`, arrival order) — one ADR-008 log entry's wire bytes.
//! - `PlaintextCache n` — the rendered form of entry `n`: `[1, entry_hash,
//!   author_id, created_secs, text]` (ADR-010 permits a plaintext cache only
//!   inside a sealed segment; on open, each cache row is accepted only if its
//!   `entry_hash` is in the rebuilt DAG).
//!
//! The SEK wrap itself lives in the store's `sek_wraps` table.
//!
//! ## Invariants
//! - The DAG is rebuilt from the log segments on every open through the full
//!   ADR-008 acceptance predicate (`Dag::accept`): the store is a cache of
//!   *verified* entries, never trusted as such.
//! - An append is atomic: entry, plaintext cache and the advanced chain state
//!   commit in one [`crate::node::store::Batch`]. If the commit fails the channel
//!   is marked **poisoned** and refuses further appends until reopened — the
//!   in-memory chain has already advanced, and re-using a sender-key iteration for
//!   a different plaintext would be a key/nonce reuse (ADR-006), so the only safe
//!   continuation is the on-disk state.
//! - Double-lock (ADR-010): opening needs the unlocked identity (the identity
//!   factor) *and* the channel passphrase; there is no path to the SEK without both.
//!
//! M13 is single-device: the only author is this identity, membership is
//! `{self}`, and the channel's governance evaluator is built over the genesis
//! alone. M14 adds other authors' entries, SKDMs, consent and sync on top of the
//! same layout.

use std::collections::{BTreeMap, BTreeSet};

use zeroize::{Zeroize, Zeroizing};

use crate::atrest::idfactor::SignatureIdentityFactor;
use crate::atrest::sek::{Argon2Profile, Sek};
use crate::atrest::store::{open_segment, seal_segment, SealedSegment, SegmentKind};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::governance::capability::CapabilitySet;
use crate::governance::consent::{ConsentGrant, ConsentRevocation};
use crate::governance::entry::GovEntry;
use crate::governance::evaluator::Evaluator;
use crate::governance::genesis::{ChannelPolicy, DeniabilityMode, Genesis, HistoryMode};
use crate::governance::membership::{
    issue_consent_grant, issue_consent_revocation, MembershipView,
};
use crate::group::history::OriginKeyStore;
use crate::group::message::GroupMessage;
use crate::group::skdm::Skdm;
use crate::group::state::{ReceiverChain, SenderChain};
use crate::group::wire::GROUP_MSG_SIGN_DOMAIN;
use crate::hash::{sha256, Digest32};
use crate::identity::composite::{CompositePublicKey, RootSigner};
use crate::log::dag::{AdmissionPolicy, Dag, ForkProof};
use crate::log::entry::{Entry, EntryKind, EntrySkeleton, ZERO_HASH};
use crate::log::feed::lipmaa;
use crate::log::sync::{frontier_session_peer, AuthorResolver, Transport};
use crate::nat::bootstrap::BootstrapSet;
use crate::nat::record::Admission;
use crate::node::consent_order::Stamp;
use crate::node::content::Content;
use crate::node::profile::Profile;
use crate::node::store::Store;
use crate::suite::{algo, SuiteFloor};

/// Segment id of the manifest in `KeyMaterial`.
const SEG_MANIFEST: u64 = 0;
/// The admitted-authors segment id within [`SegmentKind::KeyMaterial`] (M14.5): the
/// composite keys of every identity whose entries this node accepts into the log.
const SEG_AUTHORS: u64 = 2;
/// The receiver-chains segment id within [`SegmentKind::KeyMaterial`] (M14.5b): the
/// sender keys other members have released to this identity.
const SEG_RECEIVERS: u64 = 3;
/// Segment id of this identity's sender chain in `KeyMaterial`.
const SEG_SENDER: u64 = 1;
/// The anchors segment id within [`SegmentKind::KeyMaterial`] (M15.1): the
/// bootstrap nodes this channel's records are published to and read from — the
/// configured set plus whatever the invite link that brought this node in named.
/// A node that forgot them after a restart could not republish its address and
/// would fall off the swarm.
const SEG_ANCHORS: u64 = 4;
/// The offered-services segment id within [`SegmentKind::KeyMaterial`] (ADR-013,
/// M16.1): the `service_tag → local address` map this node **binds** for this
/// channel. Host configuration, not authorization — what a peer may *reach* is the
/// `dial:` capability in the log, and the two are checked separately
/// ([`crate::tunnel::session::accept`]).
const SEG_SERVICES: u64 = 5;

/// The retained-origins segment id within [`SegmentKind::KeyMaterial`] (M18.1): the
/// iteration-0 chain key of each sender-key generation this identity has minted, so
/// a member who keeps consent across a rotation can be re-keyed at the new
/// generation's origin and reads it whole (ADR-006 §History, ADR-007 §Revocation).
const SEG_ORIGINS: u64 = 6;

/// The sender-key delivery ledger segment id within [`SegmentKind::KeyMaterial`]
/// (M18.1): target → the highest generation this identity has delivered to it. What
/// is *owed* is derived from this and the consent set, so it cannot go stale.
const SEG_DELIVERED: u64 = 7;

/// This node's **own admission** to the channel, within [`SegmentKind::KeyMaterial`]
/// (M17.6): whether it created the channel, or the [`JoinWitness`] a member signed
/// when it verified this node's ADR-005 passphrase proof.
///
/// Persisted because it is republished with every member bundle record, for as long
/// as this node is a member. A node that forgot it after a restart could publish no
/// bundle at all, and would fall off every board — the same reason `SEG_ANCHORS`
/// exists.
const SEG_ADMISSION: u64 = 8;

/// The history ledger segment id within [`SegmentKind::KeyMaterial`] (V210-45):
/// target → the oldest of this identity's generations it is still owed. Same encoding
/// as [`SEG_DELIVERED`]. A row exists only while some of that history is undelivered;
/// it is never the authority on what the target may read — `SEG_ENTITLED` is.
const SEG_HISTORY: u64 = 9;

/// The entitlement segment id within [`SegmentKind::KeyMaterial`] (V210-45): target →
/// the earliest `(chain_id, iteration)` of this identity's sender key the consent
/// released to it. Every later release to that target — a re-key, a refused key owed
/// again, history — starts there and never earlier, so a key taken at a position is
/// never re-released from its generation's origin.
const SEG_ENTITLED: u64 = 10;

/// The trust-mark segment id within [`SegmentKind::KeyMaterial`] (V210-45): identity →
/// `(decision, chain_id, iteration)`, the position this identity's sender key stood at
/// in this room when it decided to trust that identity. `decision` is the decision's
/// consent-order stamp, value and order id ([`crate::node::consent_order`], V210-49), so a
/// mark from a withdrawn decision, or from a deleted counter's, can never date a later one.
const SEG_TRUST_MARKS: u64 = 11;

/// The fork-proof segment id within [`SegmentKind::KeyMaterial`] (V210-63): every attributable
/// fork proof this room's DAG has recorded, as the pair of entries. The DAG is rebuilt from the
/// stored entries on open, and those hold only one side of a fork; without this a restart forgot
/// every freeze, and took the equivocator's messages again until a sync met the fork again.
const SEG_FORKS: u64 = 12;

/// Encoding version of [`SEG_FORKS`].
const FORKS_VERSION: u64 = 1;

pub(crate) fn forks_bytes(proofs: &[&ForkProof]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(2).uint(FORKS_VERSION).array(proofs.len());
    for p in proofs {
        e.array(2)
            .bytes(&p.existing.to_wire())
            .bytes(&p.conflicting.to_wire());
    }
    e.finish()
}

pub(crate) fn parse_forks(bytes: &[u8]) -> Result<Vec<(Entry, Entry)>> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 2 {
        return Err(Error::MalformedAtRest("fork proofs arity"));
    }
    if d.uint()? != FORKS_VERSION {
        return Err(Error::MalformedAtRest("fork proofs version"));
    }
    let n = d.array()?;
    // At most one proof per author: a frozen author's later entries are refused.
    if n > MAX_AUTHORS {
        return Err(Error::SizeLimitExceeded("fork proofs"));
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        if d.array()? != 2 {
            return Err(Error::MalformedAtRest("fork proof arity"));
        }
        let existing = Entry::from_wire(d.bytes()?)?;
        let conflicting = Entry::from_wire(d.bytes()?)?;
        out.push((existing, conflicting));
    }
    d.finish()?;
    Ok(out)
}

/// At-rest version of the entitlement segment.
const POSITIONS_VERSION: u64 = 1;
/// At-rest version of the trust-mark segment. Version 2 keeps the decision's order id
/// (V210-49); a version-1 segment is read as holding no marks (narrower, never wider).
const MARKS_VERSION: u64 = 2;

/// A trust mark: the decision's stamp, and where this identity's sender key stood at it.
type TrustMark = (Stamp, u64, u64);

/// At-rest version of the delivery-ledger segment.
const DELIVERED_VERSION: u64 = 1;
/// Services encoding version.
const SERVICES_VERSION: u64 = 1;
/// The most services one channel may offer — a sanity bound on host config.
pub const MAX_SERVICES: usize = 64;
/// Manifest encoding version.
const MANIFEST_VERSION: u64 = 1;
/// Plaintext-cache row encoding version.
/// Version of the plaintext rendering cache. **2 stores the timestamp in milliseconds; 1 stored
/// seconds.** Same arity, so the two differ only in the discriminant and the unit — see
/// `node::content` for why the unit changed and why the shape deliberately did not.
const CACHE_VERSION: u64 = 2;
/// Version 1 of the cache, whose timestamp is **seconds**. Still read: these rows are already on
/// disk, and a cache that refused them would silently blank every existing room's history.
const CACHE_VERSION_SECONDS: u64 = 1;

/// At-rest version of the admitted-authors segment.
const AUTHORS_VERSION: u64 = 1;

/// At-rest version of the receiver-chains segment.
const RECEIVERS_VERSION: u64 = 1;

/// Hard cap on retained receiver chains per channel (one per author generation).
pub const MAX_RECEIVER_CHAINS: usize = 4096;

/// Hard cap on admitted authors per channel, so a hostile or corrupt segment cannot
/// force an unbounded allocation on open.
pub const MAX_AUTHORS: usize = 1024;
/// Cap on a local channel name.
pub const MAX_LOCAL_NAME_LEN: usize = 128;

/// The ADR-005 join binding parameters for a channel, derived from its **genesis**
/// — which is what a joiner has (from the board) before it has any channel state at
/// all. Both ends derive these identically or CPace simply fails to agree.
pub fn join_context_from_genesis(
    genesis: &Genesis,
    epoch: u64,
) -> Result<crate::join::session::JoinContext> {
    let floor = genesis.body.policy.suite_floor()?;
    crate::join::session::JoinContext::new(
        genesis.channel_id(),
        epoch,
        crate::suite::VOX_SUITE_1.id,
        floor,
    )
}

/// Map an ADR-008 coded sync failure onto the error taxonomy, keeping the reason
/// (the ADR's rule is that a failure is never silently downgraded).
pub(crate) fn sync_failure(
    code: crate::wire::WireError,
    peer_refused: Option<crate::wire::WireError>,
) -> Error {
    // Its own variant, carrying the coded reason, never `MalformedGovernance` (#202), and naming
    // which end stopped the session: the peer's refusal, this node's rejection of what it was
    // sent, or a path that failed under both.
    use crate::wire::WireError;
    if peer_refused == Some(code) {
        Error::SyncRefused(code)
    } else if code == WireError::TransportFailed {
        Error::SyncFailed(code)
    } else {
        Error::SyncRejected(code)
    }
}

/// The channel's [`AuthorResolver`] for ADR-008 sync: the admitted authors' keys,
/// plus the entry classification the trait's `kind_for` previously had no
/// discriminator for (it defaulted everything to `Content`, so a governance entry
/// received via sync got the content fork remedy).
pub struct ChannelAuthors {
    authors: BTreeMap<Digest32, CompositePublicKey>,
}

impl ChannelAuthors {
    /// A resolver over exactly these authors.
    #[must_use]
    pub fn new(authors: BTreeMap<Digest32, CompositePublicKey>) -> Self {
        Self { authors }
    }
}

impl AuthorResolver for ChannelAuthors {
    fn key_for(&self, author: &Digest32) -> Option<CompositePublicKey> {
        self.authors.get(author).cloned()
    }

    fn kind_for(&self, entry: &Entry) -> EntryKind {
        // A governance payload is a struct-tagged frame, a sender-key message is
        // domain-prefixed. A payload that is neither, or a pruned one (which cannot
        // be classified at all), falls back to `Content` — the conservative choice,
        // since governance entries must retain their payload (ADR-008) and so are
        // never the pruned case.
        entry
            .payload
            .as_deref()
            .and_then(|p| classify_payload(p).ok())
            .unwrap_or(EntryKind::Content)
    }
}

/// What one [`ChannelState::sync_over`] session did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyncOutcome {
    /// Entries the ADR-008 session applied to the log.
    pub applied: usize,
    /// How many of those were governance entries folded into the evaluator.
    pub governance: usize,
    /// How many of those were decrypted and rendered into the timeline.
    pub rendered: usize,
    /// Whether every position this side asked for was filled (ADR-025 D3): `false` for a serve the
    /// peer bounded, which ends cleanly but leaves the rest owed.
    pub complete: bool,
    /// Whether any requested position was newly filled (ADR-025 D3's progress).
    pub filled_any: bool,
    /// Entries refused because their author is not admitted here (yet).
    pub unadmitted: usize,
    /// Entries refused because their author is frozen.
    pub frozen: usize,
    /// Authors the session's setup admitted from the peer's board (ADR-025 D3's progress).
    pub admitted_authors: usize,
    /// The room's generation read with this side's `HAVE` (ADR-025 D2).
    pub gen_have: Option<u64>,
    /// The room's generation when the session ended.
    pub gen_end: Option<u64>,
}

impl SyncOutcome {
    /// Whether the session made progress (ADR-025 D3): stored an entry, admitted an author, or
    /// filled a requested position.
    #[must_use]
    pub fn progress(&self) -> bool {
        self.applied > 0 || self.admitted_authors > 0 || self.filled_any
    }
}

/// Why a sync session did not complete (ADR-025 D5 maps each to a backoff kind).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncFailure {
    /// The session protocol failed: locally, by the peer's coded refusal, or by a protocol
    /// violation.
    Session(crate::log::sync::SessionError),
    /// The stream could not be opened, or the peer could not be reached.
    Unreachable(String),
    /// The room's persist failed: the room is poisoned until it is reopened.
    Poisoned(String),
    /// The session's worker panicked.
    Panicked,
}

impl std::fmt::Display for SyncFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::log::sync::SessionError;
        // Which end stopped the session, as #216 says it: the peer's refusal, this node's
        // rejection of what it was sent, or a path that failed under both.
        match self {
            Self::Session(SessionError::Peer(c)) => write!(f, "{}", Error::SyncRefused(*c)),
            Self::Session(SessionError::Local(c @ crate::wire::WireError::TransportFailed)) => {
                write!(f, "{}", Error::SyncFailed(*c))
            }
            Self::Session(SessionError::Local(c)) => write!(f, "{}", Error::SyncRejected(*c)),
            Self::Session(SessionError::ProtocolViolation) => {
                f.write_str("sync failed: the peer served an entry that was not asked for")
            }
            Self::Unreachable(why) | Self::Poisoned(why) => f.write_str(why),
            Self::Panicked => f.write_str("sync failed: the session panicked"),
        }
    }
}

/// What one sync session did, and why it stopped if it did not complete. The outcome is filled in
/// either way: a failure keeps what was persisted before it (ADR-025).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionReport {
    /// What the session did.
    pub out: SyncOutcome,
    /// Why it did not complete.
    pub fail: Option<SyncFailure>,
}

impl SessionReport {
    /// A session that failed before it did anything.
    #[must_use]
    pub fn failed(fail: SyncFailure) -> Self {
        Self {
            out: SyncOutcome::default(),
            fail: Some(fail),
        }
    }

    /// Fill in the room session's part of the outcome.
    pub(crate) fn from_room(
        mut out: SyncOutcome,
        s: crate::log::sync::RoomSession,
        fatal: Option<Error>,
    ) -> Self {
        out.applied = s.applied;
        out.complete = s.complete;
        out.filled_any = s.filled_any;
        out.unadmitted = s.unadmitted;
        out.frozen = s.frozen;
        out.gen_have = s.gen_have;
        out.gen_end = s.gen_end;
        let fail = match fatal {
            Some(e) => Some(SyncFailure::Poisoned(e.to_string())),
            None => s.fail.map(SyncFailure::Session),
        };
        Self { out, fail }
    }
}

/// What [`ChannelState::accept_entry`] did with a peer's entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accepted {
    /// A governance entry: verified, stored, and folded into the evaluator.
    Governance,
    /// A content entry: verified and stored, but not readable — this node holds no
    /// sender key for that author yet, or that author has not consented to this
    /// identity (ADR-007: consent, not credentials, grants reading).
    ContentNotReadable,
    /// A content entry that was decrypted and rendered into the timeline.
    Rendered,
}

/// A rendered (decrypted, render-gated) message in the timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// The ADR-008 entry hash this rendering belongs to.
    pub entry_hash: Digest32,
    /// The author's identity fingerprint.
    pub author: Digest32,
    /// The author's recorded send time, **milliseconds** since the Unix epoch.
    ///
    /// Carried at full precision from the content envelope to whatever orders it — the ADR-020
    /// work board sorts on this, and whole seconds put two racing agents in one bucket where a
    /// hash tie-break, not causality, picked the winner. Display divides by 1000.
    pub created_millis: u64,
    /// The text.
    pub text: String,
}

/// An open (SEK-unlocked) channel on this device.
pub struct ChannelState {
    channel_id: Digest32,
    genesis: Genesis,
    local_name: String,
    created: u64,
    epoch: u64,
    sek: Sek,
    /// Author fingerprint → composite root key (M13: the creator only).
    authors: BTreeMap<Digest32, CompositePublicKey>,
    admission: AdmissionPolicy,
    dag: Dag,
    /// How many of the DAG's fork proofs are kept in `SEG_FORKS` (V210-63). A sync that records
    /// another makes the DAG hold more than this, and the room keeps them all again.
    forks_kept: usize,
    /// The channel's ADR-007 authority. Shared, because a tunnel serving task must
    /// keep asking it after the actor has moved on (ADR-013, M16.1).
    evaluator: Arc<Evaluator>,
    sender: SenderChain,
    /// The next `LogDb` / `PlaintextCache` segment id.
    next_log_id: u64,
    timeline: Vec<Rendered>,
    /// Accepted governance entries (consent grants and the rest) in acceptance
    /// order — the evaluator's input, rebuilt from the log on open (M14.5).
    gov_entries: Vec<GovEntry>,
    /// Sender keys released to this identity, keyed by `(author, chain_id)`
    /// (M14.5b). Present only for authors that consented; its presence is what
    /// makes their content readable.
    receivers: BTreeMap<(Digest32, u64), ReceiverChain>,
    /// The anchors this channel is published to (M15.1), persisted in `SEG_ANCHORS`.
    anchors: BootstrapSet,
    /// The services this node offers in this channel (ADR-013 Bind config, M16.1),
    /// persisted in `SEG_SERVICES`.
    services: BTreeMap<String, SocketAddr>,
    /// How **this node** came to be a member here (M17.6), persisted in
    /// `SEG_ADMISSION`: it created the channel, or a member witnessed its join. Needed
    /// whenever this node publishes its own bundle record, which is every time it
    /// refreshes its board presence. Distinct from `admission`, which is the ADR-007
    /// policy governing *other* authors' entries.
    own_admission: Option<Admission>,
    /// The iteration-0 chain key of every sender-key generation this identity has
    /// minted here (M18.1), persisted in `SEG_ORIGINS`. Held so a rotation can
    /// re-key the members who keep consent *at the new generation's origin* — which
    /// is what makes a rotation invisible to them (ADR-006 §History).
    origins: OriginKeyStore,
    /// Target → the highest generation delivered to it (M18.1), persisted in
    /// `SEG_DELIVERED`. Combined with the consent set this yields
    /// [`ChannelState::owed_rekeys`]; it is never itself the authority on who may
    /// read (the log is).
    delivered: BTreeMap<Digest32, u64>,
    /// Target → the oldest generation it is still owed (V210-45), persisted in
    /// `SEG_HISTORY`. See [`ChannelState::owe_history`].
    history: BTreeMap<Digest32, u64>,
    /// Target → the earliest `(chain_id, iteration)` released to it (V210-45), persisted
    /// in `SEG_ENTITLED`. See [`ChannelState::entitled_from`].
    entitled: BTreeMap<Digest32, (u64, u64)>,
    /// Identity → `(decision, chain_id, iteration)` at the trust decision (V210-45),
    /// persisted in `SEG_TRUST_MARKS`. See [`ChannelState::mark_trust`].
    trust_marks: BTreeMap<Digest32, TrustMark>,
    /// The channel passphrase, retained **in memory only** for as long as the
    /// channel is open (M14.7c).
    ///
    /// ADR-005's CPace needs the passphrase live at each join handshake, so a node
    /// can only answer an inbound join while it holds one; the alternative is that
    /// nobody can ever join a channel unless its members are in a special mode.
    /// Retaining it is a deliberate, bounded decision (recorded in ADR-016): it is a
    /// **group** secret every member already holds, scoped to one channel and one
    /// epoch, and it sits beside the SEK it derives — an attacker who can read this
    /// memory already has the SEK and the decrypted timeline, which are strictly
    /// more valuable. It is wiped by [`ChannelState::lock_now`] with the SEK, never
    /// written to disk, and never crosses the client boundary (no view, event or
    /// `Debug` output carries it).
    passphrase: Zeroizing<Vec<u8>>,
    poisoned: bool,
    /// The room's **generation** (ADR-025 D1): bumped by every entry persisted, from any source.
    /// In memory; a restart resets it together with every sync port. Shared with the actor, which
    /// reads it without the room's lock; it only changes under the lock.
    gen: Arc<std::sync::atomic::AtomicU64>,
}

impl std::fmt::Debug for ChannelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelState")
            .field("channel_id", &crate::hash::Hex(&self.channel_id))
            .field("local_name", &self.local_name)
            .field("epoch", &self.epoch)
            .field("entries", &self.dag.len())
            .field("authors", &self.authors.len())
            .field("governance", &self.gov_entries.len())
            .field("receiver_chains", &self.receivers.len())
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

fn manifest_bytes(genesis: &Genesis, local_name: &str, created: u64, epoch: u64) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(5)
        .uint(MANIFEST_VERSION)
        .bytes(&genesis.to_wire())
        .text(local_name)
        .uint(created)
        .uint(epoch);
    e.finish()
}

fn parse_manifest(bytes: &[u8]) -> Result<(Genesis, String, u64, u64)> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 5 {
        return Err(Error::MalformedAtRest("channel manifest arity"));
    }
    if d.uint()? != MANIFEST_VERSION {
        return Err(Error::MalformedAtRest("channel manifest version"));
    }
    let genesis = Genesis::from_wire(d.bytes()?)?;
    let name = d.text()?;
    if name.len() > MAX_LOCAL_NAME_LEN {
        return Err(Error::SizeLimitExceeded("channel local name"));
    }
    let name = name.to_owned();
    let created = d.uint()?;
    let epoch = d.uint()?;
    d.finish()?;
    Ok((genesis, name, created, epoch))
}

/// The admitted-authors segment: `[version, [[fingerprint, composite_pubkey], …]]`
/// in fingerprint order (a `BTreeMap`, so the bytes are canonical).
/// The offered-services segment: `[version, [[tag, addr_text], …]]` in tag order (a
/// `BTreeMap`, so the bytes are canonical). Addresses are the standard `ip:port`
/// text, which round-trips exactly.
fn services_bytes(services: &BTreeMap<String, SocketAddr>) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(2).uint(SERVICES_VERSION).array(services.len());
    for (tag, addr) in services {
        e.array(2).text(tag).text(&addr.to_string());
    }
    e.finish()
}

/// Retain a freshly minted generation's origin (iteration-0) chain key (M18.1).
///
/// Valid **only** at the moment of minting: the origin is the live chain key exactly
/// while `next_iteration == 0`, and once the chain ratchets the origin is gone for
/// good (one-way). Storing a ratcheted key as an origin would make every later
/// release derive the wrong iteration, so a non-zero position is an error, not a
/// thing to paper over.
fn retain_generation(
    origins: &mut OriginKeyStore,
    channel_id: &Digest32,
    epoch: u64,
    author: &Digest32,
    sender: &SenderChain,
    created_at: u64,
    mint_seq: Stamp,
) -> Result<()> {
    let (iteration, origin_key) = sender.current_position();
    if iteration != 0 {
        return Err(Error::MalformedBundle("origin retention past iteration 0"));
    }
    origins.retain_origin(
        channel_id,
        epoch,
        author,
        sender.chain_id(),
        origin_key,
        sender.signing_pubkey().to_bytes(),
        created_at,
        Some(mint_seq),
    );
    Ok(())
}

/// The entitlement segment: `[version, [[target, chain_id, iteration], …]]`.
fn positions_bytes(rows: &BTreeMap<Digest32, (u64, u64)>) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(2).uint(POSITIONS_VERSION).array(rows.len());
    for (t, (c, i)) in rows {
        e.array(3).bytes(t).uint(*c).uint(*i);
    }
    e.finish()
}

fn parse_positions(bytes: &[u8]) -> Result<BTreeMap<Digest32, (u64, u64)>> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 2 {
        return Err(Error::MalformedAtRest("positions arity"));
    }
    if d.uint()? != POSITIONS_VERSION {
        return Err(Error::MalformedAtRest("positions version"));
    }
    let n = d.array()?;
    if n > MAX_AUTHORS {
        return Err(Error::SizeLimitExceeded("positions rows"));
    }
    let mut out = BTreeMap::new();
    for _ in 0..n {
        if d.array()? != 3 {
            return Err(Error::MalformedAtRest("positions row arity"));
        }
        let target: Digest32 = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("positions target"))?;
        let chain_id = d.uint()?;
        let iteration = d.uint()?;
        out.insert(target, (chain_id, iteration));
    }
    d.finish()?;
    Ok(out)
}

/// The trust-mark segment: `[version, [[target, decision, order_id, chain_id, iteration], …]]`.
fn marks_bytes(rows: &BTreeMap<Digest32, TrustMark>) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(2).uint(MARKS_VERSION).array(rows.len());
    for (t, (d, c, i)) in rows {
        e.array(5)
            .bytes(t)
            .uint(d.seq)
            .bytes(&d.order)
            .uint(*c)
            .uint(*i);
    }
    e.finish()
}

fn parse_marks(bytes: &[u8]) -> Result<BTreeMap<Digest32, TrustMark>> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 2 {
        return Err(Error::MalformedAtRest("trust marks arity"));
    }
    let version = d.uint()?;
    // A version-1 mark carries no order id, so it cannot be matched to any decision: it is
    // dropped, and a room opened later marks afresh at its position then (narrower).
    if version == POSITIONS_VERSION {
        return Ok(BTreeMap::new());
    }
    if version != MARKS_VERSION {
        return Err(Error::MalformedAtRest("trust marks version"));
    }
    let n = d.array()?;
    if n > MAX_AUTHORS {
        return Err(Error::SizeLimitExceeded("trust marks rows"));
    }
    let mut out = BTreeMap::new();
    for _ in 0..n {
        if d.array()? != 5 {
            return Err(Error::MalformedAtRest("trust marks row arity"));
        }
        let target: Digest32 = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("trust marks target"))?;
        let seq = d.uint()?;
        let order = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("trust marks order id"))?;
        let chain_id = d.uint()?;
        let iteration = d.uint()?;
        out.insert(target, (Stamp { order, seq }, chain_id, iteration));
    }
    d.finish()?;
    Ok(out)
}

/// The delivery ledger segment: `[version, [[target, chain_id], …]]`, targets in
/// canonical order.
fn delivered_bytes(delivered: &BTreeMap<Digest32, u64>) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(2).uint(DELIVERED_VERSION).array(delivered.len());
    for (target, chain_id) in delivered {
        e.array(2).bytes(target).uint(*chain_id);
    }
    e.finish()
}

fn parse_delivered(bytes: &[u8]) -> Result<BTreeMap<Digest32, u64>> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 2 {
        return Err(Error::MalformedAtRest("delivery ledger arity"));
    }
    if d.uint()? != DELIVERED_VERSION {
        return Err(Error::MalformedAtRest("delivery ledger version"));
    }
    let n = d.array()?;
    // One row per author this identity could ever consent to.
    if n > MAX_AUTHORS {
        return Err(Error::SizeLimitExceeded("delivery ledger rows"));
    }
    let mut out = BTreeMap::new();
    for _ in 0..n {
        if d.array()? != 2 {
            return Err(Error::MalformedAtRest("delivery ledger row arity"));
        }
        let target: Digest32 = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("delivery ledger target"))?;
        out.insert(target, d.uint()?);
    }
    d.finish()?;
    Ok(out)
}

fn parse_services(bytes: &[u8]) -> Result<BTreeMap<String, SocketAddr>> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 2 {
        return Err(Error::MalformedAtRest("channel services arity"));
    }
    if d.uint()? != SERVICES_VERSION {
        return Err(Error::MalformedAtRest("channel services version"));
    }
    let n = d.array()?;
    if n > MAX_SERVICES {
        return Err(Error::SizeLimitExceeded("channel services"));
    }
    let mut out = BTreeMap::new();
    for _ in 0..n {
        if d.array()? != 2 {
            return Err(Error::MalformedAtRest("channel service tuple arity"));
        }
        let tag = d.text()?.to_owned();
        let addr: SocketAddr = d
            .text()?
            .parse()
            .map_err(|_| Error::MalformedAtRest("channel service address"))?;
        if tag.is_empty() || tag.len() > crate::tunnel::session::MAX_SERVICE_TAG_LEN {
            return Err(Error::MalformedAtRest("channel service tag length"));
        }
        out.insert(tag, addr);
    }
    d.finish()?;
    Ok(out)
}

pub(crate) fn authors_bytes(authors: &BTreeMap<Digest32, CompositePublicKey>) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(2).uint(AUTHORS_VERSION).array(authors.len());
    for (fp, key) in authors {
        e.array(2).bytes(fp).bytes(&key.to_bytes());
    }
    e.finish()
}

pub(crate) fn parse_authors(bytes: &[u8]) -> Result<BTreeMap<Digest32, CompositePublicKey>> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 2 {
        return Err(Error::MalformedAtRest("channel authors arity"));
    }
    if d.uint()? != AUTHORS_VERSION {
        return Err(Error::MalformedAtRest("channel authors version"));
    }
    let n = d.array()?;
    if n > MAX_AUTHORS {
        return Err(Error::SizeLimitExceeded("channel authors"));
    }
    let mut out = BTreeMap::new();
    for _ in 0..n {
        if d.array()? != 2 {
            return Err(Error::MalformedAtRest("channel author tuple arity"));
        }
        let fp: Digest32 = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("channel author fingerprint"))?;
        let key_bytes: [u8; crate::hash::COMPOSITE_PUB_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("channel author key length"))?;
        let key = CompositePublicKey::from_bytes(&key_bytes)?;
        // The stored fingerprint must be the key's own: a swapped pair would admit
        // an identity under another's name.
        if key.fingerprint() != fp {
            return Err(Error::MalformedAtRest("channel author key/fingerprint"));
        }
        out.insert(fp, key);
    }
    d.finish()?;
    Ok(out)
}

/// The receiver-chains segment: `[version, [chain_state, …]]`, each element a
/// [`ReceiverChain::to_state`] blob (which carries its own author/chain binding).
/// Secret-bearing, so the assembled buffer zeroizes on drop.
fn receivers_bytes(receivers: &BTreeMap<(Digest32, u64), ReceiverChain>) -> Zeroizing<Vec<u8>> {
    let mut e = Encoder::new();
    e.array(2).uint(RECEIVERS_VERSION).array(receivers.len());
    for chain in receivers.values() {
        e.bytes(&chain.to_state());
    }
    Zeroizing::new(e.finish())
}

fn parse_receivers(bytes: &[u8]) -> Result<BTreeMap<(Digest32, u64), ReceiverChain>> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 2 {
        return Err(Error::MalformedAtRest("channel receivers arity"));
    }
    if d.uint()? != RECEIVERS_VERSION {
        return Err(Error::MalformedAtRest("channel receivers version"));
    }
    let n = d.array()?;
    if n > MAX_RECEIVER_CHAINS {
        return Err(Error::SizeLimitExceeded("channel receiver chains"));
    }
    let mut out = BTreeMap::new();
    for _ in 0..n {
        let chain = ReceiverChain::from_state(d.bytes()?)?;
        out.insert((chain.author_id(), chain.chain_id()), chain);
    }
    d.finish()?;
    Ok(out)
}

/// Classify a log entry by its payload — the discriminator ADR-008's `kind_for`
/// lacked (it defaulted every entry to `Content`).
///
/// The two payload families are self-describing and disjoint: a governance payload
/// is a struct-tagged ADR-008 frame, while a sender-key message is domain-prefixed
/// with `vox/group-msg/v1`. Anything else is neither, and is refused rather than
/// optimistically treated as content.
pub(crate) fn classify_payload(payload: &[u8]) -> Result<EntryKind> {
    if payload.starts_with(GROUP_MSG_SIGN_DOMAIN.as_bytes()) {
        return Ok(EntryKind::Content);
    }
    if crate::wire::parse_frame(payload).is_ok() {
        return Ok(EntryKind::Governance);
    }
    Err(Error::MalformedAtRest(
        "entry payload is neither a group message nor a governance struct",
    ))
}

fn cache_bytes(r: &Rendered) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(5)
        .uint(CACHE_VERSION)
        .bytes(&r.entry_hash)
        .bytes(&r.author)
        .uint(r.created_millis)
        .text(&r.text);
    e.finish()
}

fn parse_cache(bytes: &[u8]) -> Result<Rendered> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 5 {
        return Err(Error::MalformedAtRest("plaintext cache arity"));
    }
    // Both versions read, and the unit normalised here, so nothing above sees two units.
    let scale = match d.uint()? {
        CACHE_VERSION => 1,
        CACHE_VERSION_SECONDS => 1_000,
        _ => return Err(Error::MalformedAtRest("plaintext cache version")),
    };
    let entry_hash: Digest32 = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedAtRest("plaintext cache entry hash"))?;
    let author: Digest32 = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedAtRest("plaintext cache author"))?;
    let created_millis = d.uint()?.saturating_mul(scale);
    let text = d.text()?.to_owned();
    d.finish()?;
    Ok(Rendered {
        entry_hash,
        author,
        created_millis,
        text,
    })
}

impl ChannelState {
    /// Create a new channel on this device: genesis at the day-one suite floor
    /// with the default policy (forward-only history, attributable content, no
    /// TTL), a fresh SEK double-locked under (identity factor, `channel_passphrase`)
    /// with the production Argon2id profile, and this identity's first sender
    /// chain. Persists the wrap, manifest and chain atomically.
    pub fn create(
        profile: &Profile,
        local_name: &str,
        channel_passphrase: &[u8],
        now_secs: u64,
    ) -> Result<Self> {
        Self::create_with_profile(
            profile,
            local_name,
            channel_passphrase,
            now_secs,
            Argon2Profile::default(),
        )
    }

    /// [`ChannelState::create`] with an explicit Argon2id profile (tests).
    pub fn create_with_profile(
        profile: &Profile,
        local_name: &str,
        channel_passphrase: &[u8],
        now_secs: u64,
        argon2: Argon2Profile,
    ) -> Result<Self> {
        Self::create_with_grant(
            profile,
            local_name,
            channel_passphrase,
            CapabilitySet::new(),
            now_secs,
            argon2,
        )
    }

    /// Create a channel whose **genesis confers `service_grant` on every member**
    /// (ADR-017 decision 3) — the capability-bearing room `vox serve` makes.
    ///
    /// Joining such a room *is* the authorization: the joiner already proved it held
    /// the passphrase and paid the ADR-005 proof of work, and the room's purpose is
    /// the service, so "may this member dial it" and "is this person a member" are the
    /// same question. No certificate is issued to anyone, so the host never waits for
    /// the guest to appear in order to grant them something.
    ///
    /// The grant is immutable, being part of the genesis and therefore of the
    /// channelID — a room cannot silently *become* an access list, and one created as
    /// an access list cannot stop being one.
    pub fn create_with_grant(
        profile: &Profile,
        local_name: &str,
        channel_passphrase: &[u8],
        service_grant: CapabilitySet,
        now_secs: u64,
        argon2: Argon2Profile,
    ) -> Result<Self> {
        let (genesis, sek) = Self::create_genesis(profile, local_name, service_grant, now_secs)?;
        let signer = profile.signer()?;
        let factor = SignatureIdentityFactor::new(signer);
        let wrap = sek.seal(&factor, &genesis.channel_id(), channel_passphrase, argon2)?;
        Self::create_from_sealed(
            profile,
            local_name,
            channel_passphrase,
            genesis,
            sek,
            &wrap,
            now_secs,
        )
    }

    /// The fast first step of creating a room: its genesis and a fresh room key.
    ///
    /// Split from [`ChannelState::create_with_grant`] so the slow middle step — sealing the room
    /// key under the passphrase with production Argon2id, seconds of CPU — can run off the node's
    /// actor, which answers nothing while it works. [`ChannelState::create_from_sealed`] is the
    /// last step.
    ///
    /// # Errors
    /// A local name over the limit, no unlocked signer, or a genesis or key that cannot be made.
    pub fn create_genesis(
        profile: &Profile,
        local_name: &str,
        service_grant: CapabilitySet,
        now_secs: u64,
    ) -> Result<(Genesis, Sek)> {
        if local_name.len() > MAX_LOCAL_NAME_LEN {
            return Err(Error::SizeLimitExceeded("channel local name"));
        }
        let signer = profile.signer()?;
        let policy = ChannelPolicy {
            history_mode: HistoryMode::ForwardOnly,
            deniability_mode: DeniabilityMode::Attributable,
            ttl: 0,
            min_suite: SuiteFloor::DAY_ONE.id(),
        };
        let genesis = Genesis::create_with_grant(signer, now_secs, policy, service_grant)?;
        Ok((genesis, Sek::generate()?))
    }

    /// The last step of creating a room, from a genesis and a room key already sealed under the
    /// passphrase. See [`ChannelState::create_genesis`].
    ///
    /// # Errors
    /// No unlocked signer, a segment that cannot be sealed, or a store write that fails.
    pub fn create_from_sealed(
        profile: &Profile,
        local_name: &str,
        channel_passphrase: &[u8],
        genesis: Genesis,
        sek: Sek,
        wrap: &crate::atrest::SekWrap,
        now_secs: u64,
    ) -> Result<Self> {
        let signer = profile.signer()?;
        let channel_id = genesis.channel_id();
        let epoch = 0u64;
        let me = signer.fingerprint();
        let sender = SenderChain::new(&channel_id, epoch, &me, 0, now_secs)?;
        // Retain generation 0's origin at the moment it is minted: once the live
        // chain ratchets past iteration 0 the origin is unrecoverable, so it is kept
        // now or never (ADR-006 §History).
        let mut origins = OriginKeyStore::new();
        let mint_seq = crate::node::consent_order::stamp_mint(profile.store(), signer, 0)?;
        retain_generation(
            &mut origins,
            &channel_id,
            epoch,
            &me,
            &sender,
            now_secs,
            mint_seq,
        )?;

        let manifest = manifest_bytes(&genesis, local_name, now_secs, epoch);
        let manifest_seg = seal_segment(&sek, SegmentKind::KeyMaterial, SEG_MANIFEST, &manifest)?;
        let sender_seg = seal_segment(
            &sek,
            SegmentKind::KeyMaterial,
            SEG_SENDER,
            &sender.to_state(),
        )?;
        let origins_seg = seal_segment(
            &sek,
            SegmentKind::KeyMaterial,
            SEG_ORIGINS,
            &origins.to_state(),
        )?;
        let mut authors = BTreeMap::new();
        authors.insert(me, signer.public_key());
        let authors_seg = seal_segment(
            &sek,
            SegmentKind::KeyMaterial,
            SEG_AUTHORS,
            &authors_bytes(&authors),
        )?;

        let mut batch = profile.store().batch()?;
        batch.put_sek_wrap(&channel_id, wrap)?;
        batch.put_segment(
            &channel_id,
            SegmentKind::KeyMaterial,
            SEG_AUTHORS,
            &authors_seg,
        )?;
        batch.put_segment(
            &channel_id,
            SegmentKind::KeyMaterial,
            SEG_MANIFEST,
            &manifest_seg,
        )?;
        batch.put_segment(
            &channel_id,
            SegmentKind::KeyMaterial,
            SEG_SENDER,
            &sender_seg,
        )?;
        batch.put_segment(
            &channel_id,
            SegmentKind::KeyMaterial,
            SEG_ORIGINS,
            &origins_seg,
        )?;
        batch.commit()?;

        let mut admission = AdmissionPolicy::new();
        admission.admit(channel_id, epoch, me);
        let evaluator = Arc::new(Self::build_evaluator(&genesis, &authors, &[], now_secs)?);
        Ok(Self {
            channel_id,
            genesis,
            local_name: local_name.to_owned(),
            passphrase: Zeroizing::new(channel_passphrase.to_vec()),
            created: now_secs,
            epoch,
            sek,
            authors,
            admission,
            dag: Dag::new(),
            forks_kept: 0,
            evaluator,
            sender,
            next_log_id: 1,
            timeline: Vec::new(),
            gov_entries: Vec::new(),
            receivers: BTreeMap::new(),
            anchors: BootstrapSet::new(),
            services: BTreeMap::new(),
            // This node made the channel, so the genesis names it and nothing else needs
            // to (M17.6).
            own_admission: Some(Admission::Creator),
            origins,
            delivered: BTreeMap::new(),
            history: BTreeMap::new(),
            entitled: BTreeMap::new(),
            trust_marks: BTreeMap::new(),
            poisoned: false,
            gen: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// Open a channel from the store: double-lock unwrap of the SEK, then rebuild
    /// the DAG from the log segments through the full acceptance predicate, load
    /// the timeline from the plaintext cache (rows whose entry is not in the DAG
    /// are dropped), and restore the sender chain.
    pub fn open(
        profile: &Profile,
        channel_id: &Digest32,
        channel_passphrase: &[u8],
        now_secs: u64,
    ) -> Result<Self> {
        let signer = profile.signer()?;
        let store = profile.store();
        let wrap = store
            .get_sek_wrap(channel_id)?
            .ok_or(Error::Profile("no such channel in this profile"))?;
        let factor = SignatureIdentityFactor::new(signer);
        let sek = wrap.unwrap_sek(&factor, channel_id, channel_passphrase)?;
        Self::open_with_sek(store, channel_id, sek, channel_passphrase, now_secs)
    }

    /// Open a channel from the store with its SEK already in hand: the half of [`Self::open`]
    /// after the double-lock unwrap. A daemon reopening the rooms it held uses it (#208), with the
    /// SEK and passphrase kept sealed under its identity in [`crate::node::open_rooms`]. The
    /// passphrase is still needed: the room retains it to answer joins (ADR-005).
    ///
    /// It takes the store and not the profile, so that the reopening can run on a blocking task
    /// with a [`Profile::store_handle`] rather than on the actor.
    pub fn open_with_sek(
        store: &Store,
        channel_id: &Digest32,
        sek: Sek,
        channel_passphrase: &[u8],
        now_secs: u64,
    ) -> Result<Self> {
        let manifest_seg = store
            .get_segment(channel_id, SegmentKind::KeyMaterial, SEG_MANIFEST)?
            .ok_or(Error::MalformedAtRest("channel manifest missing"))?;
        let manifest = open_segment(&sek, SegmentKind::KeyMaterial, SEG_MANIFEST, &manifest_seg)?;
        let (genesis, local_name, created, epoch) = parse_manifest(&manifest)?;
        genesis.verify()?;
        if genesis.channel_id() != *channel_id {
            return Err(Error::MalformedAtRest("channel manifest genesis mismatch"));
        }

        // The admitted authors (M14.5). A channel created before this segment
        // existed has only its creator, which is exactly what it had.
        let mut authors =
            match store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_AUTHORS)? {
                Some(seg) => {
                    let bytes = open_segment(&sek, SegmentKind::KeyMaterial, SEG_AUTHORS, &seg)?;
                    parse_authors(&bytes)?
                }
                None => BTreeMap::new(),
            };
        // The creator is always an author: it signed the genesis whose hash is the
        // channelID, so it cannot be excluded by a tampered segment.
        authors.insert(
            genesis.body.creator_pubkey.fingerprint(),
            genesis.body.creator_pubkey.clone(),
        );
        let mut admission = AdmissionPolicy::new();
        for author in authors.keys() {
            admission.admit(*channel_id, epoch, *author);
        }

        // Rebuild the DAG: every stored entry re-passes the acceptance predicate,
        // classified by its payload so governance entries are not re-admitted as
        // content.
        let mut dag = Dag::new();
        let mut next_log_id = 1u64;
        let mut gov_entries = Vec::new();
        for (id, seg) in store.segments(channel_id, SegmentKind::LogDb)? {
            let wire = open_segment(&sek, SegmentKind::LogDb, id, &seg)?;
            let entry = Entry::from_wire(&wire)?;
            let key = authors
                .get(&entry.skeleton.author_id)
                .ok_or(Error::MalformedAtRest("stored entry from unknown author"))?
                .clone();
            let payload = entry
                .payload
                .as_deref()
                .ok_or(Error::MalformedAtRest("stored entry payload pruned"))?;
            let kind = classify_payload(payload)?;
            if kind == EntryKind::Governance {
                gov_entries.push(GovEntry::from_verified_log_entry(
                    &entry,
                    &key,
                    channel_id,
                    Default::default(),
                )?);
            }
            dag.accept(entry, kind, &key, &admission)
                .map_err(|_| Error::MalformedAtRest("stored entry failed acceptance"))?;
            next_log_id = id.saturating_add(1);
        }

        // The fork proofs this room kept (V210-63), each checked as a new one would be: a proof
        // that does not verify is a tampered store, as a stored entry that fails acceptance is.
        let mut forks_kept = 0usize;
        if let Some(seg) = store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_FORKS)? {
            let bytes = open_segment(&sek, SegmentKind::KeyMaterial, SEG_FORKS, &seg)?;
            for (existing, conflicting) in parse_forks(&bytes)? {
                let author_id = existing.skeleton.author_id;
                // An author no longer in the room has no key to check it with, and its entries
                // are refused anyway.
                let Some(key) = authors.get(&author_id) else {
                    continue;
                };
                let seq = existing.skeleton.seq;
                dag.restore_fork(
                    ForkProof {
                        author_id,
                        seq,
                        existing,
                        conflicting,
                    },
                    key,
                )
                .map_err(|_| Error::MalformedAtRest("stored fork proof failed verification"))?;
                forks_kept += 1;
            }
        }

        // Timeline from the sealed plaintext cache, render-gated by the DAG.
        let mut timeline = Vec::new();
        for (id, seg) in store.segments(channel_id, SegmentKind::PlaintextCache)? {
            let row = open_segment(&sek, SegmentKind::PlaintextCache, id, &seg)?;
            let rendered = parse_cache(&row)?;
            if dag.contains(&rendered.entry_hash) {
                timeline.push(rendered);
            }
        }

        let sender_seg = store
            .get_segment(channel_id, SegmentKind::KeyMaterial, SEG_SENDER)?
            .ok_or(Error::MalformedAtRest("sender chain missing"))?;
        let sender_state = open_segment(&sek, SegmentKind::KeyMaterial, SEG_SENDER, &sender_seg)?;
        let sender = SenderChain::from_state(&sender_state)?;
        drop(sender_state);

        // Sender keys other members released to us (M14.5b).
        let receivers =
            match store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_RECEIVERS)? {
                Some(seg) => {
                    let bytes = open_segment(&sek, SegmentKind::KeyMaterial, SEG_RECEIVERS, &seg)?;
                    parse_receivers(&bytes)?
                }
                None => BTreeMap::new(),
            };
        // The anchors this channel is published to (M15.1). A channel from before the
        // segment existed has none recorded, which is what it had.
        let anchors = match store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_ANCHORS)? {
            Some(seg) => {
                let bytes = open_segment(&sek, SegmentKind::KeyMaterial, SEG_ANCHORS, &seg)?;
                BootstrapSet::from_bytes(&bytes)?
            }
            None => BootstrapSet::new(),
        };
        // The services this node offers here (ADR-013 M16.1).
        let services =
            match store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_SERVICES)? {
                Some(seg) => {
                    let bytes = open_segment(&sek, SegmentKind::KeyMaterial, SEG_SERVICES, &seg)?;
                    parse_services(&bytes)?
                }
                None => BTreeMap::new(),
            };
        // How this node came to be a member here (M17.6). `None` for a channel that
        // predates the segment; such a node cannot publish a bundle record until it
        // has one, which is correct — its membership is exactly as unevidenced as any
        // other unwitnessed key's.
        let own_admission =
            match store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_ADMISSION)? {
                Some(seg) => {
                    let bytes = open_segment(&sek, SegmentKind::KeyMaterial, SEG_ADMISSION, &seg)?;
                    Some(Admission::from_body(&bytes)?)
                }
                None => None,
            };
        // The origins of this identity's own generations (M18.1). A channel from
        // before the segment existed retains none, and cannot: the live chain has
        // already ratcheted past iteration 0, so that generation is releasable only
        // from the author's current position (see `rekey_skdm`).
        let origins = match store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_ORIGINS)? {
            Some(seg) => {
                let bytes = open_segment(&sek, SegmentKind::KeyMaterial, SEG_ORIGINS, &seg)?;
                OriginKeyStore::from_state(&bytes)?
            }
            None => OriginKeyStore::new(),
        };
        let delivered =
            match store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_DELIVERED)? {
                Some(seg) => {
                    let bytes = open_segment(&sek, SegmentKind::KeyMaterial, SEG_DELIVERED, &seg)?;
                    parse_delivered(&bytes)?
                }
                None => BTreeMap::new(),
            };
        let history = match store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_HISTORY)? {
            Some(seg) => {
                let bytes = open_segment(&sek, SegmentKind::KeyMaterial, SEG_HISTORY, &seg)?;
                parse_delivered(&bytes)?
            }
            None => BTreeMap::new(),
        };
        let entitled =
            match store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_ENTITLED)? {
                Some(seg) => {
                    let bytes = open_segment(&sek, SegmentKind::KeyMaterial, SEG_ENTITLED, &seg)?;
                    parse_positions(&bytes)?
                }
                None => BTreeMap::new(),
            };
        let trust_marks =
            match store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_TRUST_MARKS)? {
                Some(seg) => {
                    let bytes =
                        open_segment(&sek, SegmentKind::KeyMaterial, SEG_TRUST_MARKS, &seg)?;
                    parse_marks(&bytes)?
                }
                None => BTreeMap::new(),
            };

        let evaluator = Arc::new(Self::build_evaluator(
            &genesis,
            &authors,
            &gov_entries,
            now_secs,
        )?);
        Ok(Self {
            channel_id: *channel_id,
            genesis,
            local_name,
            passphrase: Zeroizing::new(channel_passphrase.to_vec()),
            created,
            epoch,
            sek,
            authors,
            admission,
            dag,
            forks_kept,
            evaluator,
            sender,
            next_log_id,
            timeline,
            gov_entries,
            receivers,
            anchors,
            services,
            own_admission,
            origins,
            delivered,
            history,
            entitled,
            trust_marks,
            poisoned: false,
            gen: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    fn build_evaluator(
        genesis: &Genesis,
        authors: &BTreeMap<Digest32, CompositePublicKey>,
        gov_entries: &[GovEntry],
        now_secs: u64,
    ) -> Result<Evaluator> {
        // The admitted authors are this node's view of *who is a member*, which is
        // what a genesis service grant is conferred on (ADR-017 decision 3). It is
        // local state by ADR-007's design — membership is emergent, there is no
        // roster — and that is sound here because the decision it feeds is local too:
        // a host serving its own service consults the keys it verified itself.
        Evaluator::build_with_members(
            genesis,
            gov_entries,
            now_secs,
            |id| authors.get(id).cloned(),
            authors.keys().copied().collect(),
        )
    }

    /// Create the local state for a channel this identity **joined** (ADR-007
    /// §"Join and per-sender consent flow", step 1) rather than created.
    ///
    /// `genesis` comes from the rendezvous board and is accepted **only if its hash
    /// equals `channel_id`** (ADR-007: that check, not any roster, is what makes a
    /// cold-fetched genesis trustworthy). The joiner gets its own local SEK (the
    /// at-rest double-lock is per device, ADR-010) and its own sender chain at
    /// `chain_id` 0 — holding channel credentials releases **no** sender keys, so it
    /// can read nothing until members consent (step 3); its own messages are
    /// readable by others only once it distributes its SKDM (step 2).
    ///
    /// The creator is admitted as an author immediately (its key is in the verified
    /// genesis); every other member is admitted as its verified key arrives.
    pub fn join_channel(
        profile: &Profile,
        genesis: &Genesis,
        channel_id: &Digest32,
        local_name: &str,
        channel_passphrase: &[u8],
        now_secs: u64,
    ) -> Result<Self> {
        Self::join_channel_with_profile(
            profile,
            genesis,
            channel_id,
            local_name,
            channel_passphrase,
            now_secs,
            Argon2Profile::default(),
        )
    }

    /// [`ChannelState::join_channel`] with an explicit Argon2id profile (tests use
    /// the reduced one).
    pub fn join_channel_with_profile(
        profile: &Profile,
        genesis: &Genesis,
        channel_id: &Digest32,
        local_name: &str,
        channel_passphrase: &[u8],
        now_secs: u64,
        argon2: Argon2Profile,
    ) -> Result<Self> {
        Self::join_checks(profile, genesis, channel_id, local_name)?;
        let sek = Sek::generate()?;
        let signer = profile.signer()?;
        let factor = SignatureIdentityFactor::new(signer);
        let wrap = sek.seal(&factor, channel_id, channel_passphrase, argon2)?;
        Self::join_channel_from_sealed(
            profile,
            genesis,
            channel_id,
            local_name,
            channel_passphrase,
            now_secs,
            (sek, wrap),
        )
    }

    /// What must hold before a joined room is made: a name within the limit, an unlocked signer,
    /// a genesis that verifies and names this room, and no copy of the room already in the profile.
    ///
    /// # Errors
    /// The first of those that does not hold.
    pub fn join_checks(
        profile: &Profile,
        genesis: &Genesis,
        channel_id: &Digest32,
        local_name: &str,
    ) -> Result<()> {
        if local_name.len() > MAX_LOCAL_NAME_LEN {
            return Err(Error::SizeLimitExceeded("channel local name"));
        }
        profile.signer()?;
        genesis.verify()?;
        if genesis.channel_id() != *channel_id {
            return Err(Error::MalformedGovernance(
                "genesis hash is not the channelID joined with",
            ));
        }
        if profile.store().get_sek_wrap(channel_id)?.is_some() {
            return Err(Error::Profile("this channel is already in the profile"));
        }
        Ok(())
    }

    /// Make a joined room from a room key already sealed under the passphrase — the slow step,
    /// which the node runs off its actor. The checks of [`ChannelState::join_checks`] are repeated
    /// here, because time passed while the seal ran.
    ///
    /// # Errors
    /// A failed check, a segment that cannot be sealed, or a store write that fails.
    pub fn join_channel_from_sealed(
        profile: &Profile,
        genesis: &Genesis,
        channel_id: &Digest32,
        local_name: &str,
        channel_passphrase: &[u8],
        now_secs: u64,
        sealed: (Sek, crate::atrest::SekWrap),
    ) -> Result<Self> {
        Self::join_checks(profile, genesis, channel_id, local_name)?;
        let (sek, wrap) = sealed;
        let signer = profile.signer()?;
        let me = signer.fingerprint();
        let epoch = 0u64;
        let sender = SenderChain::new(channel_id, epoch, &me, 0, now_secs)?;
        let mut origins = OriginKeyStore::new();
        let mint_seq = crate::node::consent_order::stamp_mint(profile.store(), signer, 0)?;
        retain_generation(
            &mut origins,
            channel_id,
            epoch,
            &me,
            &sender,
            now_secs,
            mint_seq,
        )?;

        let creator = genesis.body.creator_pubkey.fingerprint();
        let mut authors = BTreeMap::new();
        authors.insert(creator, genesis.body.creator_pubkey.clone());
        authors.insert(me, signer.public_key());

        let manifest = manifest_bytes(genesis, local_name, now_secs, epoch);
        let manifest_seg = seal_segment(&sek, SegmentKind::KeyMaterial, SEG_MANIFEST, &manifest)?;
        let sender_seg = seal_segment(
            &sek,
            SegmentKind::KeyMaterial,
            SEG_SENDER,
            &sender.to_state(),
        )?;
        let authors_seg = seal_segment(
            &sek,
            SegmentKind::KeyMaterial,
            SEG_AUTHORS,
            &authors_bytes(&authors),
        )?;
        let origins_seg = seal_segment(
            &sek,
            SegmentKind::KeyMaterial,
            SEG_ORIGINS,
            &origins.to_state(),
        )?;
        let mut batch = profile.store().batch()?;
        batch.put_sek_wrap(channel_id, &wrap)?;
        batch.put_segment(
            channel_id,
            SegmentKind::KeyMaterial,
            SEG_MANIFEST,
            &manifest_seg,
        )?;
        batch.put_segment(
            channel_id,
            SegmentKind::KeyMaterial,
            SEG_SENDER,
            &sender_seg,
        )?;
        batch.put_segment(
            channel_id,
            SegmentKind::KeyMaterial,
            SEG_AUTHORS,
            &authors_seg,
        )?;
        batch.put_segment(
            channel_id,
            SegmentKind::KeyMaterial,
            SEG_ORIGINS,
            &origins_seg,
        )?;
        batch.commit()?;

        let mut admission = AdmissionPolicy::new();
        for author in authors.keys() {
            admission.admit(*channel_id, epoch, *author);
        }
        let evaluator = Arc::new(Self::build_evaluator(genesis, &authors, &[], now_secs)?);
        Ok(Self {
            channel_id: *channel_id,
            genesis: genesis.clone(),
            local_name: local_name.to_owned(),
            passphrase: Zeroizing::new(channel_passphrase.to_vec()),
            created: now_secs,
            epoch,
            sek,
            authors,
            admission,
            dag: Dag::new(),
            forks_kept: 0,
            evaluator,
            sender,
            next_log_id: 1,
            timeline: Vec::new(),
            gov_entries: Vec::new(),
            receivers: BTreeMap::new(),
            anchors: BootstrapSet::new(),
            services: BTreeMap::new(),
            // Set by the caller from the join witness the responder signed (M17.6).
            own_admission: None,
            origins,
            delivered: BTreeMap::new(),
            history: BTreeMap::new(),
            entitled: BTreeMap::new(),
            trust_marks: BTreeMap::new(),
            poisoned: false,
            gen: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// The most authors one peer's board may contribute in a single sweep (M17.6).
    ///
    /// A witness makes an admission **attributable**; it does not make it impossible.
    /// A member can sign witnesses for keys that never joined — nothing forces a
    /// signature to correspond to a real exchange — so without a bound, one compromised
    /// member could still mint [`MAX_AUTHORS`] of them and exhaust admission for every
    /// legitimate member thereafter, a denial of new membership that outlives the
    /// attacker and is repairable only by a passphrase rotation.
    ///
    /// The quota is per sweep rather than cumulative on purpose: it bounds the damage
    /// of any one exchange without keeping per-peer state that would itself need
    /// bounding, and a peer with genuinely more members to share will deliver them over
    /// several syncs, which is what the anti-entropy loop does anyway.
    pub const MAX_ADMISSIONS_PER_SWEEP: usize = 8;

    /// Admit a key **from a board**, on the ADR-016 M17.6 evidence that it belongs
    /// there — and on nothing else.
    ///
    /// A board record is self-signed: it proves its publisher holds that key and
    /// nothing more, so anyone can mint one for a key they hold. Admitting on the
    /// strength of *who relayed it* is trust-on-first-use, which ADR-020 decision 3
    /// forbids in as many words, and it let one compromised member inject arbitrary
    /// identities into every other member's author table.
    ///
    /// The two admissible answers to "why is this key here":
    ///
    /// - [`Admission::Creator`] — the genesis names it as the channel's creator, and
    ///   the genesis hash **is** the channelID, so this node checks it against data it
    ///   already holds, with nothing relayed and nobody to trust.
    /// - [`Admission::Witnessed`] — a member verified this key's ADR-005 passphrase
    ///   proof and signed that it did. The witness is accepted only if **this node
    ///   already admits the signer**, which roots every chain in the creator.
    ///
    /// Returns `Ok(true)` when the key was newly admitted, `Ok(false)` when it was
    /// already known, and an error when the evidence does not hold up.
    pub fn admit_from_board(
        &mut self,
        store: &Store,
        key: &CompositePublicKey,
        admission: &Admission,
        now_secs: u64,
    ) -> Result<bool> {
        let fingerprint = key.fingerprint();
        match admission {
            Admission::Creator => {
                if self.genesis.creator_pubkey().fingerprint() != fingerprint {
                    return Err(Error::MalformedGovernance(
                        "board record claims to be the creator and is not",
                    ));
                }
            }
            Admission::Witnessed(w) => {
                // The signer must already be an author *here*. That is the whole
                // mechanism: a stranger's signature convinces nobody, so a chain can
                // only start at the creator, whom the genesis names.
                let witness_key =
                    self.authors
                        .get(&w.witness_id)
                        .cloned()
                        .ok_or(Error::MalformedGovernance(
                            "join witness signed by an unadmitted key",
                        ))?;
                w.verify(&witness_key, &self.channel_id, self.epoch, &fingerprint)?;
            }
        }
        self.admit_author(store, key, now_secs)
    }

    /// Admit `key` as a log author for this channel: its entries are accepted into
    /// the DAG and its governance entries are evaluated (ADR-007 — admission is a
    /// *log* fact, not a read grant; reading still requires that author's SKDM and
    /// this node's consent view).
    ///
    /// The key must hash to `fingerprint` (ADR-016: author keys come from the
    /// verified genesis, admin certificates, or the board's records, each of which
    /// carries the full composite key). Idempotent: re-admitting the same key is a
    /// no-op that still succeeds.
    ///
    /// **This is the raw operation and it checks no evidence.** Admitting a key is what
    /// turns "entry from an unadmitted author" into "entry stored" (see
    /// [`ChannelState::accept_entry`]), and it occupies one of [`MAX_AUTHORS`] slots
    /// permanently within the epoch — so a caller that admits on no evidence hands any
    /// key the ability to write to this node's log, and enough of them exhaust
    /// admission for every legitimate member thereafter. Callers taking keys from a
    /// **board** MUST go through [`ChannelState::admit_from_board`], which requires the
    /// ADR-016 M17.6 evidence. This one is for keys whose right to be here this node
    /// established itself: the genesis creator, and a joiner whose proof it just
    /// verified.
    pub fn admit_author(
        &mut self,
        store: &Store,
        key: &CompositePublicKey,
        now_secs: u64,
    ) -> Result<bool> {
        let fingerprint = key.fingerprint();
        if let Some(existing) = self.authors.get(&fingerprint) {
            if existing.to_bytes() == key.to_bytes() {
                return Ok(false);
            }
            // Two different keys claiming one fingerprint is a SHA-256 collision or
            // a bug; either way, never silently replace an admitted author.
            return Err(Error::MalformedGovernance(
                "another key is already admitted for this fingerprint",
            ));
        }
        if self.authors.len() >= MAX_AUTHORS {
            return Err(Error::SizeLimitExceeded("channel authors"));
        }
        self.authors.insert(fingerprint, key.clone());
        self.admission
            .admit(self.channel_id, self.epoch, fingerprint);
        let seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_AUTHORS,
            &authors_bytes(&self.authors),
        )?;
        if let Err(e) = store.put_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_AUTHORS,
            &seg,
        ) {
            self.poisoned = true;
            return Err(e);
        }
        self.evaluator = Arc::new(Self::build_evaluator(
            &self.genesis,
            &self.authors,
            &self.gov_entries,
            now_secs,
        )?);
        Ok(true)
    }

    /// The anchors this channel is published to and read from (M15.1).
    #[must_use]
    pub fn anchors(&self) -> &BootstrapSet {
        &self.anchors
    }

    /// Add anchors for this channel — the set is persisted sealed under the SEK
    /// like every other per-channel segment, so a restart still knows where the
    /// swarm's board is. Returns how many were new.
    pub fn add_anchors(&mut self, store: &Store, more: &BootstrapSet) -> Result<usize> {
        let before = self.anchors.len();
        let before_addrs: usize = self.anchors.nodes().iter().map(|n| n.endpoints.len()).sum();
        // `merge_endpoints`, not `merge`: an anchor that moved is the same identity at a
        // new address, and `merge` keeps the first entry per identity and drops the rest.
        // A room would otherwise go on handing out the address its anchor had when the
        // room was made, in every invite link, for ever.
        self.anchors.merge_endpoints(more)?;
        let after_addrs: usize = self.anchors.nodes().iter().map(|n| n.endpoints.len()).sum();
        if self.anchors.len() == before && after_addrs == before_addrs {
            return Ok(0);
        }
        let seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_ANCHORS,
            &self.anchors.to_bytes(),
        )?;
        if let Err(e) = store.put_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_ANCHORS,
            &seg,
        ) {
            self.poisoned = true;
            return Err(e);
        }
        Ok(self.anchors.len().saturating_sub(before))
    }

    /// A shared handle to this channel's evaluator, for a task that must keep asking
    /// after the actor has moved on (ADR-013's tunnel serving).
    #[must_use]
    pub fn evaluator_handle(&self) -> Arc<Evaluator> {
        Arc::clone(&self.evaluator)
    }

    /// The services this node offers in this channel: `service_tag → local address`
    /// (ADR-013 Bind config).
    #[must_use]
    pub fn services(&self) -> &BTreeMap<String, SocketAddr> {
        &self.services
    }

    /// Where a service this node offers in this channel lives locally, or `None`.
    /// This is pure host configuration and carries **no** authorization: what a peer
    /// may reach is the `dial:` capability in the log, checked separately.
    #[must_use]
    pub fn service_endpoint(&self, service_tag: &str) -> Option<SocketAddr> {
        self.services.get(service_tag).copied()
    }

    /// Offer `service_tag` at `local`, persisted under the channel's SEK so a restart
    /// still serves it. Replacing an existing tag's address is allowed (that is how a
    /// service moves); the caller must hold `bind:<tag>` in this channel, which is
    /// checked here — a host cannot offer what the log does not let it offer.
    ///
    /// Returns whether this added a tag that was not offered before.
    pub fn add_service(
        &mut self,
        store: &Store,
        profile: &Profile,
        service_tag: &str,
        local: SocketAddr,
    ) -> Result<bool> {
        if service_tag.is_empty() || service_tag.len() > crate::tunnel::session::MAX_SERVICE_TAG_LEN
        {
            return Err(Error::MalformedTunnel("service tag length"));
        }
        // **No `bind:` check.** Withdrawn with the capability model it belonged to (ADR-017
        // decision 3 as revised, M17.7): offering a port of *this* machine is not the room's
        // business. What the room governs is *reach*, and that is the dial gate's job.
        //
        // Keeping it would have left the two halves gated by different models, only one of
        // which moved: reach became the host's own decision while offering still needed a
        // capability whose only sources were the genesis grant and `vox grant --may-bind`,
        // both withdrawn — so a plain member could be reachable and still unable to offer
        // anything. A non-creator simply could not serve. Found by the agent-comms session
        // hitting it from the file-exchange side, which is where it bit first.
        let _ = profile;
        let fresh = !self.services.contains_key(service_tag);
        if fresh && self.services.len() >= MAX_SERVICES {
            return Err(Error::SizeLimitExceeded("channel services"));
        }
        self.services.insert(service_tag.to_owned(), local);
        self.persist_services(store)?;
        Ok(fresh)
    }

    /// Stop offering `service_tag`. Returns whether it was offered.
    pub fn remove_service(&mut self, store: &Store, service_tag: &str) -> Result<bool> {
        if self.services.remove(service_tag).is_none() {
            return Ok(false);
        }
        self.persist_services(store)?;
        Ok(true)
    }

    /// How this node came to be a member here (M17.6) — `None` only for a channel
    /// opened from a store written before the segment existed.
    #[must_use]
    pub fn own_admission(&self) -> Option<&Admission> {
        self.own_admission.as_ref()
    }

    /// Record how this node came to be a member here, and persist it.
    ///
    /// Called once, by the join path, with the witness the responder signed. The
    /// creator sets it at creation and never calls this.
    pub fn set_own_admission(&mut self, store: &Store, admission: Admission) -> Result<()> {
        let seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_ADMISSION,
            &admission.body_bytes(),
        )?;
        if let Err(e) = store.put_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_ADMISSION,
            &seg,
        ) {
            self.poisoned = true;
            return Err(e);
        }
        self.own_admission = Some(admission);
        Ok(())
    }

    fn persist_services(&mut self, store: &Store) -> Result<()> {
        let seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_SERVICES,
            &services_bytes(&self.services),
        )?;
        if let Err(e) = store.put_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_SERVICES,
            &seg,
        ) {
            self.poisoned = true;
            return Err(e);
        }
        Ok(())
    }

    /// This identity's fingerprint in this channel — structurally the author of its
    /// own sender chain, so no signer is needed to know it.
    #[must_use]
    pub fn me(&self) -> Digest32 {
        self.sender.author_id()
    }

    /// Whether `fingerprint` is an admitted log author.
    #[must_use]
    pub fn is_author(&self, fingerprint: &Digest32) -> bool {
        self.authors.contains_key(fingerprint)
    }

    /// The admitted authors' keys, in fingerprint order.
    #[must_use]
    pub fn author_keys(&self) -> Vec<CompositePublicKey> {
        self.authors.values().cloned().collect()
    }

    /// Every admitted author's fingerprint, in deterministic order.
    #[must_use]
    pub fn author_fingerprints(&self) -> Vec<Digest32> {
        self.authors.keys().copied().collect()
    }

    /// Mint an SKDM releasing this identity's sender key at its **current
    /// position** — the forward-only release consent normally uses (ADR-006: the
    /// recipient reads from here on, never the history before it).
    ///
    /// Deliver it over a `pairwise` stream ([`crate::node::pairwise_stream`]) and
    /// record the consent with [`ChannelState::issue_consent`], passing the same
    /// SKDM so the grant carries its `skdm_ref`.
    pub fn skdm_for_consent(&self, profile: &Profile) -> Result<Skdm> {
        let signer = profile.signer()?;
        let (iteration, key) = self.sender.current_position();
        self.sender.skdm_for(signer, iteration, key)
    }

    /// Issue a **consent grant** to `target`: the ADR-007 log fact that this
    /// identity released its sender key to `target`, carrying the `skdm_ref` of the
    /// SKDM actually delivered over the pairwise session and the history mode in
    /// force. Appends it as a governance entry and folds it into the evaluator, so
    /// `target` immediately reads as consented in this node's view.
    ///
    /// The SKDM delivery itself is the caller's (M14.5b); this records the consent.
    ///
    /// `entitled_from` is the earliest `(chain_id, iteration)` this consent releases to
    /// `target` (V210-45): the delivered key's own position, or earlier when history
    /// is owed too. It is recorded, and no later release to `target` starts before it.
    pub fn issue_consent(
        &mut self,
        profile: &Profile,
        target: Digest32,
        delivered_skdm: &Skdm,
        entitled_from: (u64, u64),
        now_secs: u64,
    ) -> Result<ConsentGrant> {
        let signer = profile.signer()?;
        let grant = issue_consent_grant(
            signer,
            &self.channel_id,
            self.epoch,
            target,
            delivered_skdm,
            self.genesis.body.policy.history_mode,
        )?;
        self.append_governance(profile, &grant.to_wire(), now_secs)?;
        // The grant is the record that `target` holds the generation it was given; the ledger
        // is how a later rotation knows it has not yet been given the next one. The generation
        // is the delivered key's own, not the current one: a key taken when consent was decided
        // and delivered after a rotation is the older generation, and the rotation still owes
        // this member the new one (V210-30).
        self.delivered.insert(target, delivered_skdm.body.chain_id);
        self.persist_delivered(profile.store())?;
        // An entitlement already held (an earlier consent never revoked) stands: both were
        // decided, and the earlier one released what it released.
        let from = self
            .entitled
            .get(&target)
            .map_or(entitled_from, |e| (*e).min(entitled_from));
        if self.entitled.insert(target, from) != Some(from) {
            self.persist_entitled(profile.store())?;
        }
        Ok(grant)
    }

    /// Whether this identity's sender key has reached its scheduled-rotation bound
    /// (ADR-006: `N` messages or `T` elapsed). The caller rotates with
    /// [`ChannelState::rotate_sender`] and re-keys whoever is
    /// [`owed`](ChannelState::owed_rekeys).
    #[must_use]
    pub fn should_rotate_sender(&self, now_secs: u64) -> bool {
        self.sender.should_rotate(now_secs)
    }

    /// The generation this identity is currently sending under.
    #[must_use]
    pub fn sender_generation(&self) -> u64 {
        self.sender.chain_id()
    }

    /// Mint the next sender-key generation and persist it, returning its `chain_id`.
    ///
    /// Everything this identity sends from now on is sealed under keys nobody has
    /// yet: **the rotation itself is the forward-secrecy boundary**, and it takes
    /// effect whether or not any re-key is ever delivered. That is what makes
    /// revocation a cryptographic act rather than a request (ADR-007
    /// §"Enforcement honesty").
    ///
    /// The new generation's origin is retained, so members who keep consent can be
    /// re-keyed at iteration 0 and read the generation whole — a rotation must not
    /// silently narrow what an existing consenter can read (ADR-006 §History). The
    /// sender state and the retained origins are written in **one batch**: a
    /// rotation that persisted the chain but lost the origin would leave the members
    /// who kept consent permanently unable to read the messages sent before their
    /// re-key.
    pub fn rotate_sender(&mut self, profile: &Profile, now_secs: u64) -> Result<u64> {
        if self.poisoned {
            return Err(Error::Profile(
                "channel is poisoned after a failed persist; reopen it",
            ));
        }
        let store = profile.store();
        let next = self.sender.rotated(now_secs)?;
        let chain_id = next.chain_id();
        let me = self.me();
        // The mint's place in the consent order, persisted before the generation exists
        // (V210-45): a value is never handed out twice, so no later decision can tie it.
        let mint_seq = crate::node::consent_order::stamp_mint(
            store,
            profile.signer()?,
            self.newest_mint_seq(),
        )?;
        retain_generation(
            &mut self.origins,
            &self.channel_id,
            self.epoch,
            &me,
            &next,
            now_secs,
            mint_seq,
        )?;
        let sender_seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_SENDER,
            &next.to_state(),
        )?;
        let origins_seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_ORIGINS,
            &self.origins.to_state(),
        )?;
        let persisted = (|| -> Result<()> {
            let mut batch = store.batch()?;
            batch.put_segment(
                &self.channel_id,
                SegmentKind::KeyMaterial,
                SEG_SENDER,
                &sender_seg,
            )?;
            batch.put_segment(
                &self.channel_id,
                SegmentKind::KeyMaterial,
                SEG_ORIGINS,
                &origins_seg,
            )?;
            batch.commit()
        })();
        if let Err(e) = persisted {
            self.poisoned = true;
            return Err(e);
        }
        self.sender = next;
        Ok(chain_id)
    }

    /// Mint an SKDM releasing this identity's **current** generation at its
    /// origin — the re-key for a member who already had consent when the generation
    /// was minted.
    ///
    /// Releasing at iteration 0 rather than the author's current position is what
    /// closes the hole a rotation would otherwise open: a member who was merely
    /// offline while the author rotated reads every message of the new generation,
    /// not just the ones sent after they reconnected. It widens nothing, because a
    /// generation minted *after* someone consented contains, by construction, only
    /// messages sent after their consent.
    ///
    /// If the generation's origin is not retained — a channel created before M18.1,
    /// whose live chain has already ratcheted past iteration 0 — the origin is
    /// unrecoverable and the only honest release is the current position, exactly as
    /// [`ChannelState::skdm_for_consent`] does.
    pub fn rekey_skdm(&self, profile: &Profile) -> Result<Skdm> {
        let signer = profile.signer()?;
        let chain_id = self.sender.chain_id();
        if self.origins.has(&self.channel_id, self.epoch, chain_id) {
            self.origins
                .release_at(signer, &self.channel_id, self.epoch, chain_id, 0)
        } else {
            let (iteration, key) = self.sender.current_position();
            self.sender.skdm_for(signer, iteration, key)
        }
    }

    /// Record that `target` has been delivered generation `chain_id` of this
    /// identity's sender key, so it stops being [`owed`](ChannelState::owed_rekeys).
    pub fn note_undelivered(
        &mut self,
        store: &Store,
        target: Digest32,
        chain_id: u64,
    ) -> Result<()> {
        // Only the generation that was refused: a later one that did land stays recorded.
        if self.delivered.get(&target) != Some(&chain_id) {
            return Ok(());
        }
        match chain_id.checked_sub(1) {
            Some(before) => {
                self.delivered.insert(target, before);
            }
            None => {
                self.delivered.remove(&target);
            }
        }
        self.persist_delivered(store)
    }

    /// Record that `target` has been delivered generation `chain_id` of this
    /// identity's sender key, so it stops being [`owed`](ChannelState::owed_rekeys).
    pub fn note_delivered(&mut self, store: &Store, target: Digest32, chain_id: u64) -> Result<()> {
        let entry = self.delivered.entry(target).or_default();
        if *entry >= chain_id {
            return Ok(());
        }
        *entry = chain_id;
        self.persist_delivered(store)
    }

    /// Whether this identity has consented to `target` reading it here.
    ///
    /// Read off the log through the evaluator, never a cached flag: a revocation
    /// changes the answer because the log says so. This is what tells a keyring
    /// removal which rooms it actually has to change the lock in (ADR-020 §3) —
    /// rotating in a room where nothing was ever granted would be noise.
    #[must_use]
    pub fn has_consented(&self, target: &Digest32) -> bool {
        let me = self.me();
        MembershipView::new(&self.evaluator)
            .readers_of(&me)
            .contains(target)
    }

    /// The admitted authors in `trusted` this identity has **not yet consented
    /// to** — who auto-consent still owes a first key release (ADR-020 §3).
    ///
    /// Derived, never stored, exactly like [`owed_rekeys`](Self::owed_rekeys): the
    /// consent set comes off the log, so a member drops out the moment the log says
    /// it was consented to, and nothing has to be invalidated.
    ///
    /// `trusted` is the caller's keyring, and it is the whole point: membership of
    /// this channel is *not* sufficient. An author admitted by vouching — a bundle
    /// record published by a member, for an identity that never held the room
    /// passphrase — is an author here and still gets nothing unless the operator
    /// put its fingerprint in the keyring.
    #[must_use]
    pub fn owed_consents(&self, trusted: &BTreeSet<Digest32>) -> BTreeSet<Digest32> {
        let me = self.me();
        let already: BTreeSet<Digest32> = MembershipView::new(&self.evaluator).readers_of(&me);
        self.authors
            .keys()
            .copied()
            .filter(|a| *a != me)
            .filter(|a| trusted.contains(a))
            .filter(|a| !already.contains(a))
            .collect()
    }

    /// The members this identity has consented to that do not yet hold its current
    /// generation — who a rotation still owes a re-key.
    ///
    /// Derived from the consent set on the log and the delivery ledger, never stored:
    /// a revoked member drops out because the log says so, not because a cached list
    /// was updated. A consenter with no ledger row counts as owed; re-delivering a
    /// generation it already holds is ignored by
    /// [`ChannelState::accept_skdm`], so the safe direction is to send.
    #[must_use]
    pub fn owed_rekeys(&self) -> BTreeSet<Digest32> {
        let me = self.me();
        let current = self.sender.chain_id();
        MembershipView::new(&self.evaluator)
            .readers_of(&me)
            .into_iter()
            .filter(|t| *t != me)
            .filter(|t| self.delivered.get(t).is_none_or(|d| *d < current))
            .collect()
    }

    /// Revoke `target`'s consent to read this identity's messages (ADR-007
    /// §Revocation): rotate this identity's sender key and append the signed
    /// revocation naming the generation that excludes `target`.
    ///
    /// Revocation *is* rotation with one member left out. The forward guarantee is
    /// cryptographic and immediate — `target` holds no key for the new generation and
    /// no key it holds derives one. What `target` already received is not recalled
    /// and cannot be: ADR-007 §"Enforcement honesty" says so, and no protocol can
    /// say otherwise.
    ///
    /// The remaining consenters are re-keyed by the caller (the node's tick, from
    /// [`ChannelState::owed_rekeys`]); the rotation does not wait on that, because a
    /// revocation that took effect only once everyone else was reachable would be no
    /// revocation at all.
    pub fn revoke_consent(
        &mut self,
        profile: &Profile,
        target: Digest32,
        now_secs: u64,
    ) -> Result<ConsentRevocation> {
        let me = self.me();
        if target == me {
            return Err(Error::MalformedGovernance(
                "an identity cannot revoke its own consent",
            ));
        }
        if !MembershipView::new(&self.evaluator)
            .readers_of(&me)
            .contains(&target)
        {
            return Err(Error::MalformedGovernance("no consent to revoke"));
        }
        // Rotate first: the entry names the generation that excludes `target`, so
        // that generation has to exist before the fact is signed.
        let new_chain_id = self.rotate_sender(profile, now_secs)?;
        let signer = profile.signer()?;
        let revocation =
            issue_consent_revocation(signer, &self.channel_id, self.epoch, target, new_chain_id)?;
        self.append_governance(profile, &revocation.to_wire(), now_secs)?;
        // Nothing is owed to a revoked member; drop the row so a later re-consent
        // starts from "holds nothing".
        if self.delivered.remove(&target).is_some() {
            self.persist_delivered(profile.store())?;
        }
        // Nor any history: and none is owed again, because `history_floor` refuses a
        // member this identity has ever revoked here.
        if self.history.remove(&target).is_some() {
            self.persist_history(profile.store())?;
        }
        // And what the consent released is released no more: a later re-consent is
        // entitled from its own position only.
        if self.entitled.remove(&target).is_some() {
            self.persist_entitled(profile.store())?;
        }
        Ok(revocation)
    }

    /// Forget that `target` holds this identity's current sender key, so the next
    /// re-key round delivers it again (ADR-021 F12).
    ///
    /// For when the pairwise session a key was delivered over has been replaced by the
    /// one both ends keep: what was sealed under the dropped session cannot be opened.
    ///
    /// # Errors
    /// If the ledger cannot be persisted.
    pub fn forget_delivery(&mut self, store: &Store, target: &Digest32) -> Result<()> {
        if self.delivered.remove(target).is_some() {
            self.persist_delivered(store)?;
        }
        Ok(())
    }

    /// This identity's retained generations here, `(chain_id, mint_seq)` ascending.
    fn my_generations(&self) -> Vec<(u64, Option<Stamp>)> {
        self.origins
            .generations(&self.channel_id, self.epoch, &self.me())
    }

    /// The consent-order value of this identity's newest generation here, or 0 when none
    /// has one. A trust decision is stamped above it ([`crate::node::consent_order`]). Only a
    /// floor: a value under another counter's id raises a stamp and never orders anything.
    #[must_use]
    pub fn newest_mint_seq(&self) -> u64 {
        self.my_generations()
            .into_iter()
            .filter_map(|(_, s)| s.map(|s| s.seq))
            .max()
            .unwrap_or(0)
    }

    /// Record where this identity's sender key stands **now**, as the position at which it
    /// decided to trust `target` (decision value `decision`) — V210-45. Called at the
    /// decision for every open room, and on opening a room for a decision taken while it was
    /// closed (nothing is sealed in a closed room, so its position then is its position now).
    ///
    /// # Errors
    /// If the marks cannot be persisted.
    pub fn mark_trust(&mut self, store: &Store, target: Digest32, decision: Stamp) -> Result<()> {
        match self.mark_trust_sealed(target, decision)? {
            None => Ok(()),
            Some(seg) => {
                if let Err(e) = store.put_segment(
                    &self.channel_id,
                    SegmentKind::KeyMaterial,
                    SEG_TRUST_MARKS,
                    &seg,
                ) {
                    self.poisoned = true;
                    return Err(e);
                }
                Ok(())
            }
        }
    }

    /// [`Self::mark_trust`] without writing: the marks, sealed under this room's SEK, for the
    /// caller to write with every other room's in **one** commit ([`Self::queue_marks`]), or
    /// `None` when this room already holds the mark.
    ///
    /// A trust decision marks every open room, and one commit per room made `vox trust add` cost
    /// a durable commit for each: about 7 s on the node's actor at 1,600 rooms (#189). If the
    /// caller's commit fails, it must [`Self::poison`] each room it sealed for, as a failed
    /// write here always has.
    ///
    /// # Errors
    /// The room holds [`MAX_AUTHORS`] marks already, or the marks cannot be sealed.
    pub fn mark_trust_sealed(
        &mut self,
        target: Digest32,
        decision: Stamp,
    ) -> Result<Option<SealedSegment>> {
        if self
            .trust_marks
            .get(&target)
            .is_some_and(|m| m.0 == decision)
        {
            return Ok(None);
        }
        if !self.trust_marks.contains_key(&target) && self.trust_marks.len() >= MAX_AUTHORS {
            return Err(Error::SizeLimitExceeded("trust marks"));
        }
        let position = (
            decision,
            self.sender.chain_id(),
            self.sender.current_position().0,
        );
        self.trust_marks.insert(target, position);
        let bytes = marks_bytes(&self.trust_marks);
        seal_segment(&self.sek, SegmentKind::KeyMaterial, SEG_TRUST_MARKS, &bytes).map(Some)
    }

    /// Queue `channel_id`'s sealed marks ([`Self::mark_trust_sealed`]) into `batch`.
    ///
    /// # Errors
    /// The write cannot be queued.
    pub fn queue_marks(
        batch: &mut crate::node::store::Batch<'_>,
        channel_id: &Digest32,
        seg: &SealedSegment,
    ) -> Result<()> {
        batch.put_segment(channel_id, SegmentKind::KeyMaterial, SEG_TRUST_MARKS, seg)
    }

    /// Mark this room poisoned: its state in memory is ahead of what reached the store, so it
    /// must be reopened before it is used (a batched write of its state failed).
    pub fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Mark every decision in `order` taken while this room was closed (V210-45), with no
    /// mark of its own here yet: every decision not provably taken **before** the live
    /// generation was minted. A decision provably before it needs none: that generation, and
    /// every later one, is released whole.
    ///
    /// A live generation stamped by another counter (the blob was deleted and recreated,
    /// V210-49), or by none, cannot be ordered against any decision, so every decision is
    /// marked here. That mark is at or after the decision — nothing is sealed in a closed room,
    /// and a room open at a decision was marked then — so it releases nothing sealed before it.
    ///
    /// # Errors
    /// If the marks cannot be persisted.
    pub fn mark_decisions_on_open(
        &mut self,
        store: &Store,
        order: &crate::node::consent_order::ConsentOrder,
    ) -> Result<()> {
        let current = self.sender.chain_id();
        let live = self
            .my_generations()
            .into_iter()
            .find(|(c, _)| *c == current)
            .and_then(|(_, s)| s);
        for (target, decision) in order.decisions() {
            // `mark_trust` keeps a mark this decision already has.
            if !live.is_some_and(|l| l.after(&decision)) {
                self.mark_trust(store, target, decision)?;
            }
        }
        Ok(())
    }

    /// What of this identity's sender key a member it decided to trust at consent-order
    /// value `decision` may read here (V210-45), oldest first, as `(chain_id, iteration)`
    /// releases — or `None` when the decision entitles it to nothing before the ordinary
    /// forward-only release.
    ///
    /// Trust is the consent **decision** (ADR-020 §3); a room delivers it later, once the
    /// identity is a member there, which may be long after. Forward-only consent (ADR-006)
    /// is measured from the decision, and the order is logical, never a clock
    /// ([`crate::node::consent_order`]):
    /// - a generation minted **after** the decision (a greater value) holds only posts
    ///   sealed after it, so it is released **whole**, at its origin — the argument M18.1's
    ///   re-key at iteration 0 rests on;
    /// - the generation **live at** the decision is released from the position it had
    ///   then, which this room recorded at the decision ([`Self::mark_trust`]); with no
    ///   such mark it is not released here at all;
    /// - nothing older is released.
    ///
    /// Narrower, never wider:
    /// - no decision value (a keyring row from before the order was kept) → `None`;
    /// - a generation with no value (minted before the order was kept), or one stamped by
    ///   another counter than the decision's (a deleted and recreated one, V210-49), is not
    ///   provably after the decision: it is released only from this room's mark of the
    ///   decision, if the mark lies in it, and it ends the walk;
    /// - a hole in the retained generations ends the walk, and the live generation's origin
    ///   must be retained for anything to be released;
    /// - an identity this identity has **ever** revoked here → `None`: its re-consent is
    ///   dated by its own delivery, and what was sealed while it was excluded stays closed
    ///   to it (ADR-007).
    ///
    /// The work is bounded by what is held: at most [`MAX_RETAINED_ORIGINS`] generations,
    /// each at most `ROTATE_AFTER_MESSAGES` iterations long, so a receiver deriving a
    /// released generation never needs more than `MAX_SKIP` steps of it.
    ///
    /// [`MAX_RETAINED_ORIGINS`]: crate::group::history::MAX_RETAINED_ORIGINS
    #[must_use]
    pub fn history_plan(
        &self,
        target: &Digest32,
        decision: Option<Stamp>,
    ) -> Option<Vec<(u64, u64)>> {
        let decision = decision?;
        let me = self.me();
        let revoked_here = self.gov_entries.iter().any(|g| {
            matches!(
                &g.body,
                crate::governance::entry::GovBody::ConsentRevocation(r)
                    if r.body.author_id == me && r.body.target_id == *target
            )
        });
        if revoked_here {
            return None;
        }
        let current = self.sender.chain_id();
        let mut plan = Vec::new();
        let mut expect = current;
        for (chain_id, mint_seq) in self.my_generations().into_iter().rev() {
            if chain_id > current {
                continue;
            }
            // Contiguous from the live generation down: a hole ends what can be released.
            if chain_id != expect {
                break;
            }
            if mint_seq.is_some_and(|m| m.after(&decision)) {
                // Minted after the decision, in the decision's own counter: whole.
                plan.push((chain_id, 0));
            } else {
                // Live at the decision, or not provably after it (no stamp, or another
                // counter's): only from where this room marked the decision, and nothing before.
                if let Some(&(d, c, i)) = self.trust_marks.get(target) {
                    if d == decision && c == chain_id {
                        plan.push((chain_id, i));
                    }
                }
                break;
            }
            let Some(below) = chain_id.checked_sub(1) else {
                break;
            };
            expect = below;
        }
        plan.reverse();
        (!plan.is_empty()).then_some(plan)
    }

    /// Release this identity's generation `chain_id` at `iteration` (V210-45). The live
    /// generation whose origin is not retained can only be released at its current
    /// position, which is later: narrower, never wider.
    ///
    /// # Errors
    /// No signer, or a generation that cannot be released.
    pub fn release_generation(
        &self,
        profile: &Profile,
        chain_id: u64,
        iteration: u64,
    ) -> Result<Skdm> {
        let signer = profile.signer()?;
        if self.origins.has(&self.channel_id, self.epoch, chain_id) {
            return self.origins.release_at(
                signer,
                &self.channel_id,
                self.epoch,
                chain_id,
                iteration,
            );
        }
        if chain_id == self.sender.chain_id() {
            let (at, key) = self.sender.current_position();
            if at >= iteration {
                return self.sender.skdm_for(signer, at, key);
            }
        }
        Err(Error::MalformedBundle("no retained origin for generation"))
    }

    /// The earliest `(chain_id, iteration)` of this identity's sender key released to
    /// `target` here, if a consent recorded one (V210-45). Every later release to it
    /// starts there.
    #[must_use]
    pub fn entitled_from(&self, target: &Digest32) -> Option<(u64, u64)> {
        self.entitled.get(target).copied()
    }

    /// The re-key of the live generation for `target`: at its origin, unless `target`'s
    /// entitlement begins inside the live generation, and then from there (V210-45). A key
    /// released at a position, refused, and owed again is therefore owed at that position,
    /// never from the origin, which would reveal the posts sealed before the consent.
    ///
    /// # Errors
    /// No signer, or a generation that cannot be released.
    pub fn rekey_skdm_for(&self, profile: &Profile, target: &Digest32) -> Result<Skdm> {
        match self.entitled.get(target) {
            Some(&(c, i)) if c == self.sender.chain_id() => self.release_generation(profile, c, i),
            Some(&(c, _)) if c > self.sender.chain_id() => Err(Error::MalformedAtRest(
                "entitlement past the live generation",
            )),
            _ => self.rekey_skdm(profile),
        }
    }

    /// Record that `target` is owed this identity's generations from `floor` up to the
    /// current one **whole**, so the re-key round delivers them ([`Self::owed_history`],
    /// [`Self::history_skdms`]) and retries them until they are taken (V210-45).
    ///
    /// Only ever lowers an existing row: owing more of what the target is entitled to is
    /// harmless — a generation already held is ignored by [`Self::accept_skdm`] — and
    /// owing less could strand it. What it is entitled to is the caller's
    /// history floor, never this ledger.
    ///
    /// # Errors
    /// If the ledger cannot be persisted.
    pub fn owe_history(&mut self, store: &Store, target: Digest32, floor: u64) -> Result<()> {
        if floor >= self.sender.chain_id() {
            // Only the live generation: the ordinary re-key covers it.
            return Ok(());
        }
        let entry = self.history.entry(target).or_insert(floor);
        if *entry < floor {
            return Ok(());
        }
        *entry = floor;
        self.persist_history(store)
    }

    /// The consenters still owed history, with the oldest generation each is owed.
    /// Filtered by the consent set on the log, so a revoked member is never owed any.
    #[must_use]
    pub fn owed_history(&self) -> BTreeMap<Digest32, u64> {
        let me = self.me();
        let readers = MembershipView::new(&self.evaluator).readers_of(&me);
        self.history
            .iter()
            .filter(|(t, _)| **t != me && readers.contains(*t))
            .map(|(t, f)| (*t, *f))
            .collect()
    }

    /// The SKDMs releasing this identity's retained generations from `floor` to the
    /// current one, oldest first, each from where `target` is entitled
    /// ([`Self::entitled_from`]): the generation its entitlement begins in from that
    /// iteration, every later one at its origin, and none before it. A target with no
    /// recorded entitlement gets none. A generation whose origin is no longer retained is
    /// skipped: it cannot be released by anybody.
    pub fn history_skdms(
        &self,
        profile: &Profile,
        target: &Digest32,
        floor: u64,
    ) -> Result<Vec<Skdm>> {
        let Some((from_chain, from_iteration)) = self.entitled_from(target) else {
            return Ok(Vec::new());
        };
        let signer = profile.signer()?;
        let current = self.sender.chain_id();
        let mut out = Vec::new();
        for chain_id in floor.max(from_chain)..=current {
            if self.origins.has(&self.channel_id, self.epoch, chain_id) {
                let iteration = if chain_id == from_chain {
                    from_iteration
                } else {
                    0
                };
                out.push(self.origins.release_at(
                    signer,
                    &self.channel_id,
                    self.epoch,
                    chain_id,
                    iteration,
                )?);
            }
        }
        Ok(out)
    }

    /// Record that every generation `target` was owed from its history floor has gone
    /// out; a refusal of any of them owes it again ([`Self::owe_history`]).
    ///
    /// # Errors
    /// If the ledger cannot be persisted.
    pub fn note_history_delivered(&mut self, store: &Store, target: &Digest32) -> Result<()> {
        if self.history.remove(target).is_some() {
            self.persist_history(store)?;
        }
        Ok(())
    }

    fn persist_entitled(&mut self, store: &Store) -> Result<()> {
        let bytes = positions_bytes(&self.entitled);
        self.persist_positions(store, SEG_ENTITLED, &bytes)
    }

    fn persist_positions(&mut self, store: &Store, id: u64, bytes: &[u8]) -> Result<()> {
        let seg = seal_segment(&self.sek, SegmentKind::KeyMaterial, id, bytes)?;
        if let Err(e) = store.put_segment(&self.channel_id, SegmentKind::KeyMaterial, id, &seg) {
            self.poisoned = true;
            return Err(e);
        }
        Ok(())
    }

    /// Keep every fork proof the DAG holds in `SEG_FORKS`, if it holds more than are kept.
    fn keep_forks(&mut self, store: &Store) -> Result<()> {
        let proofs = self.dag.fork_proofs();
        if proofs.len() <= self.forks_kept {
            return Ok(());
        }
        let seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_FORKS,
            &forks_bytes(&proofs),
        )?;
        let kept = proofs.len();
        if let Err(e) =
            store.put_segment(&self.channel_id, SegmentKind::KeyMaterial, SEG_FORKS, &seg)
        {
            self.poisoned = true;
            return Err(e);
        }
        self.forks_kept = kept;
        Ok(())
    }

    /// The members this room holds back for equivocating (V210-63): each `(author, seq)` where
    /// two different messages signed by that author were seen, in author order.
    #[must_use]
    pub fn equivocations(&self) -> Vec<(Digest32, u64)> {
        self.dag
            .fork_proofs()
            .into_iter()
            .map(|p| (p.author_id, p.seq))
            .collect()
    }

    fn persist_history(&mut self, store: &Store) -> Result<()> {
        let seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_HISTORY,
            &delivered_bytes(&self.history),
        )?;
        if let Err(e) = store.put_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_HISTORY,
            &seg,
        ) {
            self.poisoned = true;
            return Err(e);
        }
        Ok(())
    }

    fn persist_delivered(&mut self, store: &Store) -> Result<()> {
        let seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_DELIVERED,
            &delivered_bytes(&self.delivered),
        )?;
        if let Err(e) = store.put_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_DELIVERED,
            &seg,
        ) {
            self.poisoned = true;
            return Err(e);
        }
        Ok(())
    }

    /// The capabilities this channel's genesis confers on every member (ADR-017).
    #[must_use]
    pub fn service_grant(&self) -> &CapabilitySet {
        &self.genesis.body.service_grant
    }

    /// Append an already-built governance struct as a signed log entry.
    fn append_governance(
        &mut self,
        profile: &Profile,
        payload: &[u8],
        now_secs: u64,
    ) -> Result<Digest32> {
        if self.poisoned {
            return Err(Error::Profile(
                "channel is poisoned after a failed persist; reopen it",
            ));
        }
        let signer = profile.signer()?;
        let me = signer.fingerprint();
        if !self.authors.contains_key(&me) {
            return Err(Error::Profile(
                "this identity is not an author of the channel",
            ));
        }
        let skeleton = self.next_skeleton(&me, payload);
        let entry = Entry::build_signed(signer, skeleton, payload.to_vec())?;
        let hash = entry.entry_hash();
        let wire = entry.to_wire();
        let id = self.next_log_id;
        let log_seg = seal_segment(&self.sek, SegmentKind::LogDb, id, &wire)?;
        let key = signer.public_key();
        let gov =
            GovEntry::from_verified_log_entry(&entry, &key, &self.channel_id, self.gov_heads())?;
        self.dag
            .accept(entry, EntryKind::Governance, &key, &self.admission)
            .map_err(|_| Error::Profile("authored entry failed the acceptance predicate"))?;
        if let Err(e) =
            profile
                .store()
                .put_segment(&self.channel_id, SegmentKind::LogDb, id, &log_seg)
        {
            self.poisoned = true;
            return Err(e);
        }
        self.next_log_id = id.saturating_add(1);
        self.gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.gov_entries.push(gov);
        self.evaluator = Arc::new(Self::build_evaluator(
            &self.genesis,
            &self.authors,
            &self.gov_entries,
            now_secs,
        )?);
        Ok(hash)
    }

    /// The governance entries a newly authored governance entry happens-after: the
    /// hashes accepted so far (ADR-007's causal relation is only ever *followed*,
    /// never trusted for authority).
    fn gov_heads(&self) -> std::collections::BTreeSet<Digest32> {
        self.gov_entries.iter().map(|g| g.entry_hash).collect()
    }

    /// The resolver ADR-008 sync needs: this channel's admitted authors and the
    /// entry classification for `kind_for`.
    #[must_use]
    pub fn resolver(&self) -> ChannelAuthors {
        ChannelAuthors {
            authors: self.authors.clone(),
        }
    }

    /// Run one ADR-008 **frontier sync** session over `transport` against a peer,
    /// then durably record and render whatever arrived (ADR-016 §"Sync
    /// scheduling").
    ///
    /// Sync is ADR-008's business and applies entries to the log itself; this method
    /// is the reconciliation the runtime owes afterwards. It snapshots each author's
    /// head, runs the session, and for every entry that appeared: seals it into a
    /// `LogDb` segment, folds a governance entry into the evaluator, and renders a
    /// content entry if this node holds the author's sender key **and** the author
    /// consented to it (ADR-007). An entry that arrives but cannot be persisted
    /// poisons the channel rather than living only in memory.
    ///
    /// **Whatever arrived is reconciled even when the session then fails**, so a
    /// session that dies part-way still makes durable progress instead of leaving
    /// entries in the in-memory DAG that the next open would silently drop.
    ///
    /// A session hard-fails on the first entry from an author this node has **not
    /// admitted** (it cannot verify it), so a member must admit the channel's current
    /// members — whose full composite keys are on the rendezvous board — before
    /// syncing. That is what makes ADR-016's "`AuthorResolver` built from the genesis,
    /// admin certificates and the stored records" load-bearing rather than incidental.
    ///
    /// The session is synchronous (ADR-008's engine is), so the caller runs it on a
    /// thread that may block — `tokio::task::spawn_blocking` in the node.
    pub fn sync_over<T: Transport>(
        &mut self,
        store: &Store,
        transport: &mut T,
        now_secs: u64,
    ) -> Result<SyncOutcome> {
        if self.poisoned {
            return Err(Error::Profile(
                "channel is poisoned after a failed persist; reopen it",
            ));
        }
        // Per-author heads before the session, so the new entries can be found after.
        let before: BTreeMap<Digest32, u64> = self
            .authors
            .keys()
            .map(|a| (*a, self.dag.feed(a).map_or(0, |f| f.max_seq())))
            .collect();
        let resolver = self.resolver();
        let session = frontier_session_peer(transport, &mut self.dag, &resolver, &self.admission);

        // Collect what arrived, in per-author sequence order, before touching the
        // store (the borrow of `self.dag` ends here).
        let mut out = self.absorb_arrived(store, &before, now_secs)?;
        if let Ok(n) = session {
            out.applied = n;
        }
        match session {
            Ok(_) => Ok(out),
            Err(code) => Err(sync_failure(code, transport.peer_refused())),
        }
    }

    /// Each author's head, for [`ChannelState::absorb_arrived`] to find what a sync added.
    fn heads(&self) -> BTreeMap<Digest32, u64> {
        self.authors
            .keys()
            .map(|a| (*a, self.dag.feed(a).map_or(0, |f| f.max_seq())))
            .collect()
    }

    /// Persist, fold and render every entry a sync added past `before`'s heads.
    fn absorb_arrived(
        &mut self,
        store: &Store,
        before: &BTreeMap<Digest32, u64>,
        now_secs: u64,
    ) -> Result<SyncOutcome> {
        // A fork this sync recorded is kept before anything else, so a restart does not forget it
        // (V210-63).
        self.keep_forks(store)?;
        let mut arrived: Vec<(Digest32, Digest32, Vec<u8>)> = Vec::new();
        for (author, head) in before {
            let Some(feed) = self.dag.feed(author) else {
                continue;
            };
            for seq in (head + 1)..=feed.max_seq() {
                if let Some(entry) = feed.get(seq) {
                    let Some(payload) = entry.payload.clone() else {
                        continue;
                    };
                    arrived.push((*author, entry.entry_hash(), payload));
                }
            }
        }

        let mut out = SyncOutcome {
            applied: arrived.len(),
            ..SyncOutcome::default()
        };
        if arrived.is_empty() {
            return Ok(out);
        }
        // **One durable commit for the whole batch** (see `render_content_into`).
        //
        // Two kinds of failure, kept apart as they were when each entry committed on its own:
        // - an entry this node refuses (an unadmitted author, bad governance) stops the pass
        //   **without** poisoning the room: what came before it is still committed and rendered,
        //   and the refusal is returned after that;
        // - a failed write poisons the room, because memory has advanced past what is on disk.
        let mut rendered_rows: Vec<Rendered> = Vec::new();
        let mut refused: Option<Error> = None;
        let mut batch = match store.batch() {
            Ok(b) => b,
            Err(e) => {
                self.poisoned = true;
                return Err(e);
            }
        };
        let mut write_failed: Option<Error> = None;
        // Log rows queued into `batch`: what the generation advances by once it commits (ADR-025
        // D1). Counted at the row, not per `arrived` entry — a refusal before the row is queued
        // stores nothing, one after it still stores the row.
        let mut logged: u64 = 0;
        for (author, entry_hash, payload) in arrived {
            let step =
                (|| -> Result<std::result::Result<Vec<Rendered>, Error>> {
                    // A refusal, not a write failure: `Ok(Err(..))`.
                    macro_rules! refuse {
                        ($e:expr) => {
                            match $e {
                                Ok(v) => v,
                                Err(e) => return Ok(Err(e)),
                            }
                        };
                    }
                    let key = refuse!(self.authors.get(&author).cloned().ok_or(
                        Error::MalformedGovernance("synced entry from an unadmitted author")
                    ));
                    let wire = refuse!(self
                        .dag
                        .get_by_hash(&entry_hash)
                        .ok_or(Error::MalformedGovernance("synced entry vanished")))
                    .to_wire();
                    // Written before the entry is classified, exactly as each entry was when it
                    // committed on its own: a refusal below still leaves its log row stored.
                    let id = self.next_log_id;
                    let log_seg = seal_segment(&self.sek, SegmentKind::LogDb, id, &wire)?;
                    batch.put_segment(&self.channel_id, SegmentKind::LogDb, id, &log_seg)?;
                    self.next_log_id = id.saturating_add(1);
                    logged += 1;
                    let kind = refuse!(classify_payload(&payload));
                    let gov = match kind {
                        EntryKind::Governance => {
                            let entry = refuse!(self
                                .dag
                                .get_by_hash(&entry_hash)
                                .ok_or(Error::MalformedGovernance("synced entry vanished")))
                            .clone();
                            Some(refuse!(GovEntry::from_verified_log_entry(
                                &entry,
                                &key,
                                &self.channel_id,
                                self.gov_heads(),
                            )))
                        }
                        EntryKind::Content => None,
                    };
                    if let Some(gov) = gov {
                        let could_read = self.readable_authors();
                        self.gov_entries.push(gov);
                        self.evaluator = Arc::new(refuse!(Self::build_evaluator(
                            &self.genesis,
                            &self.authors,
                            &self.gov_entries,
                            now_secs,
                        )));
                        out.governance += 1;
                        // Into this pass's batch, never a batch of its own: a second write
                        // transaction opened while this one is open blocks forever (redb).
                        let skip: BTreeSet<Digest32> =
                            rendered_rows.iter().map(|r| r.entry_hash).collect();
                        return Ok(Ok(self.backfill_newly_readable_into(
                            &mut batch,
                            &could_read,
                            &skip,
                        )?));
                    }
                    Ok(Ok(self
                        .render_content_into(&mut batch, author, entry_hash, &payload)?
                        .into_iter()
                        .collect()))
                })();
            match step {
                Ok(Ok(rows)) => rendered_rows.extend(rows),
                Ok(Err(refusal)) => {
                    refused = Some(refusal);
                    break;
                }
                Err(e) => {
                    write_failed = Some(e);
                    break;
                }
            }
        }
        let committed = match write_failed {
            Some(e) => Err(e),
            None => (|| -> Result<()> {
                if !rendered_rows.is_empty() {
                    self.queue_receivers(&mut batch)?;
                }
                batch.commit()
            })(),
        };
        if let Err(e) = committed {
            self.poisoned = true;
            return Err(e);
        }
        // Only now, after the commit: `SessionRoom::apply` reports `stored` from the generation,
        // and ADR-025 credits the peer from it, so it must count exactly the rows now durable —
        // none when the write failed (the room is poisoned above), and a refused pass's rows too.
        self.gen
            .fetch_add(logged, std::sync::atomic::Ordering::Relaxed);
        out.rendered += rendered_rows.len();
        self.timeline.extend(rendered_rows);
        if let Some(refusal) = refused {
            return Err(refusal);
        }
        // Reconciliation done; only now surface a session failure, with its coded
        // reason preserved (ADR-008 never downgrades a failure silently).
        Ok(out)
    }

    /// Reconcile the room with a peer over `transport`, holding `shared`'s lock only inside each
    /// protocol step — never across a send or a receive. See [`crate::log::sync::SessionRoom`].
    /// Every step fails once `fence` is retired (ADR-025 D1a).
    ///
    /// Never fails as a whole: the report says what was persisted and why the session stopped, if
    /// it did — the room poisoned, a persist that failed, or the session's own failure.
    pub fn sync_over_room<T: Transport>(
        shared: &tokio::sync::Mutex<Self>,
        store: &Store,
        transport: &mut T,
        now_secs: u64,
        fence: &crate::transport::stream_transport::Fence,
        on_stored: &dyn Fn(),
    ) -> SessionReport {
        let epoch = {
            let ch = shared.blocking_lock();
            if ch.poisoned {
                return SessionReport::failed(SyncFailure::Poisoned(
                    "channel is poisoned after a failed persist; reopen it".to_owned(),
                ));
            }
            ch.epoch
        };
        let room = ChannelSessionRoom {
            shared,
            store,
            now_secs,
            epoch,
            fence,
            on_stored,
            out: std::cell::RefCell::new(SyncOutcome::default()),
            fatal: std::cell::RefCell::new(None),
        };
        let session = crate::log::sync::frontier_session_room(transport, &room);
        let fatal = room.fatal.take();
        SessionReport::from_room(room.out.into_inner(), session, fatal)
    }

    /// Accept a **sender-key distribution message** from `author` (ADR-006/ADR-007
    /// step 2/3): the sender key that member released to this identity, delivered
    /// over the ADR-004 pairwise session (M14.5b `node::pairwise`).
    ///
    /// The SKDM is verified against the author's admitted key and bound to this
    /// channel and epoch. On acceptance the chain is persisted **and every content
    /// entry already stored from that author is retried**, so a message that arrived
    /// as ciphertext before consent renders as soon as the key arrives — the
    /// monotone per-sender fill-in ADR-007 describes. Returns how many entries that
    /// backfill rendered.
    pub fn accept_skdm(&mut self, store: &Store, skdm: &Skdm, now_secs: u64) -> Result<usize> {
        if self.poisoned {
            return Err(Error::Profile(
                "channel is poisoned after a failed persist; reopen it",
            ));
        }
        let author = skdm.body.author_id;
        let key = self
            .authors
            .get(&author)
            .ok_or(Error::MalformedGovernance("SKDM from an unadmitted author"))?
            .clone();
        let chain = ReceiverChain::from_skdm(skdm, &key, &self.channel_id, self.epoch)?;
        let slot = (author, chain.chain_id());
        // A second SKDM for a generation we already hold would rewind the chain
        // head and re-enable consumed iterations; keep the live one.
        if self.receivers.contains_key(&slot) {
            return Ok(0);
        }
        if self.receivers.len() >= MAX_RECEIVER_CHAINS {
            return Err(Error::SizeLimitExceeded("channel receiver chains"));
        }
        self.receivers.insert(slot, chain);
        self.persist_receivers(store)?;
        self.backfill(store, &author, now_secs)
    }

    /// Whether this node holds a sender key for `author`.
    #[must_use]
    pub fn has_sender_key(&self, author: &Digest32) -> bool {
        self.receivers.keys().any(|(a, _)| a == author)
    }

    /// Persist the receiver chains, poisoning the channel if the write fails.
    fn persist_receivers(&mut self, store: &Store) -> Result<()> {
        let seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_RECEIVERS,
            &receivers_bytes(&self.receivers),
        )?;
        if let Err(e) = store.put_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_RECEIVERS,
            &seg,
        ) {
            self.poisoned = true;
            return Err(e);
        }
        Ok(())
    }

    /// Retry every stored content entry from `author` against the sender keys now
    /// held, rendering those that open. Called when a key arrives.
    /// The authors whose messages this node may read now (see [`Self::may_read`]).
    fn readable_authors(&self) -> BTreeSet<Digest32> {
        let me = self.me();
        self.authors
            .keys()
            .copied()
            .filter(|a| *a != me && self.may_read(a, &me))
            .collect()
    }

    /// Render what a governance entry has just made readable (V210-30).
    ///
    /// Reading an author needs two things, its sender key and its consent on the log, and they
    /// arrive separately: the key over the pairwise session, the consent by sync. Rendering was
    /// attempted when the **key** arrived (`accept_skdm`'s backfill) and when an entry arrived,
    /// never when the consent did. So when the key came first, every message already held from
    /// that author stayed unrendered for good, and only messages arriving afterwards showed. The
    /// commonest way to get that order is a consent delivered late, whose key lands before its
    /// grant has synced. Now an author who has just become readable is backfilled.
    fn backfill_newly_readable(
        &mut self,
        store: &Store,
        could_read: &BTreeSet<Digest32>,
        now_secs: u64,
    ) -> Result<usize> {
        let _ = now_secs;
        let mut rows: Vec<Rendered> = Vec::new();
        let result = (|| -> Result<()> {
            let mut batch = store.batch()?;
            rows = self.backfill_newly_readable_into(&mut batch, could_read, &BTreeSet::new())?;
            if rows.is_empty() {
                return Ok(());
            }
            self.queue_receivers(&mut batch)?;
            batch.commit()
        })();
        if let Err(e) = result {
            self.poisoned = true;
            return Err(e);
        }
        let rendered = rows.len();
        self.timeline.extend(rows);
        Ok(rendered)
    }

    /// [`Self::backfill_newly_readable`] into a batch the caller commits, returning the rows for
    /// the caller to add to the timeline once it has. `skip` names rows already rendered in that
    /// batch and so not yet in the timeline.
    fn backfill_newly_readable_into(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        could_read: &BTreeSet<Digest32>,
        skip: &BTreeSet<Digest32>,
    ) -> Result<Vec<Rendered>> {
        let newly: Vec<Digest32> = self
            .readable_authors()
            .into_iter()
            .filter(|a| !could_read.contains(a))
            .collect();
        let mut rows = Vec::new();
        for author in newly {
            rows.extend(self.backfill_into(batch, &author, skip)?);
        }
        Ok(rows)
    }

    fn backfill(&mut self, store: &Store, author: &Digest32, now_secs: u64) -> Result<usize> {
        let _ = now_secs;
        // One durable commit for the whole backfill (see `render_content_into`).
        let mut rows: Vec<Rendered> = Vec::new();
        let result = (|| -> Result<()> {
            let mut batch = store.batch()?;
            rows = self.backfill_into(&mut batch, author, &BTreeSet::new())?;
            if rows.is_empty() {
                return Ok(());
            }
            self.queue_receivers(&mut batch)?;
            batch.commit()
        })();
        if let Err(e) = result {
            self.poisoned = true;
            return Err(e);
        }
        let rendered = rows.len();
        self.timeline.extend(rows);
        Ok(rendered)
    }

    /// Render every stored content entry from `author` not yet in the timeline (nor in `skip`)
    /// into `batch`, without committing it.
    fn backfill_into(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        author: &Digest32,
        skip: &BTreeSet<Digest32>,
    ) -> Result<Vec<Rendered>> {
        let already: BTreeSet<Digest32> = self.timeline.iter().map(|r| r.entry_hash).collect();
        let pending: Vec<(Digest32, Vec<u8>)> = match self.dag.feed(author) {
            None => Vec::new(),
            Some(feed) => (1..=feed.max_seq())
                .filter_map(|seq| feed.get(seq))
                .filter(|e| !already.contains(&e.entry_hash()) && !skip.contains(&e.entry_hash()))
                .filter_map(|e| e.payload.as_ref().map(|p| (e.entry_hash(), p.clone())))
                .collect(),
        };
        let mut rows = Vec::new();
        for (entry_hash, payload) in pending {
            if !matches!(classify_payload(&payload), Ok(EntryKind::Content)) {
                continue;
            }
            if let Some(r) = self.render_content_into(batch, *author, entry_hash, &payload)? {
                rows.push(r);
            }
        }
        Ok(rows)
    }

    /// Try to decrypt one stored content payload and, on success, render it into the
    /// timeline and persist the sealed plaintext cache row.
    ///
    /// Both gates apply: this node must hold the author's sender key for the
    /// message's generation **and** the author must have consented to this identity
    /// on the log (ADR-007). A message whose key is absent, whose consent is absent,
    /// or that fails to open is left stored as ciphertext.
    fn render_content(
        &mut self,
        store: &Store,
        author: Digest32,
        entry_hash: Digest32,
        payload: &[u8],
        now_secs: u64,
    ) -> Result<bool> {
        let _ = now_secs;
        let persisted = (|| -> Result<Option<Rendered>> {
            let mut batch = store.batch()?;
            let Some(rendered) =
                self.render_content_into(&mut batch, author, entry_hash, payload)?
            else {
                return Ok(None);
            };
            self.queue_receivers(&mut batch)?;
            batch.commit()?;
            Ok(Some(rendered))
        })();
        match persisted {
            Ok(Some(rendered)) => {
                self.timeline.push(rendered);
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(e) => {
                // The chain advanced in memory but the advance was not persisted: a
                // reopen would re-derive a consumed key. Poison instead.
                self.poisoned = true;
                Err(e)
            }
        }
    }

    /// Decrypt one content payload and queue its sealed plaintext-cache row into `batch`,
    /// returning the rendered row for the caller to add to the timeline **once the batch has
    /// committed** — or `None` when this node may not, or cannot, read it (see
    /// [`Self::render_content`]).
    ///
    /// **One transaction per pass, not two per entry.** Each entry used to commit its own cache
    /// row and its own copy of the receiver chains — two durable commits, about 17 ms apiece on
    /// macOS, taken while holding the room's lock. A sync delivering 133 of another member's
    /// messages held the room for 2.3 s, and every post made in that room waited behind it
    /// (V210-08, #179: `vox room post` p95 of seconds while a peer posts). The caller queues the
    /// receiver chains once, after its loop, and commits once.
    fn render_content_into(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        author: Digest32,
        entry_hash: Digest32,
        payload: &[u8],
    ) -> Result<Option<Rendered>> {
        let me = self.me();
        if author != me && !self.may_read(&author, &me) {
            return Ok(None);
        }
        let msg = match GroupMessage::from_wire(payload) {
            Ok(m) => m,
            Err(_) => return Ok(None),
        };
        let slot = (author, msg.header.chain_id);
        let Some(chain) = self.receivers.get_mut(&slot) else {
            return Ok(None);
        };
        let plaintext = match chain.decrypt(&msg) {
            Ok(p) => Zeroizing::new(p),
            Err(_) => return Ok(None),
        };
        // **Skipped, not propagated** — matching the three `Ok(false)` paths above it.
        //
        // An entry this node cannot render is one entry it cannot show, and every other reason for
        // that here already degrades: an unreadable group message, a missing receiver chain, a
        // failed decrypt. Only the content decode used `?`, which returns out of a function whose
        // three callers invoke it with `?` **inside a loop over pending entries** — so one
        // undecodable envelope did not hide one message, it aborted the render pass and took every
        // later entry in it along.
        //
        // That was unreachable while every envelope in existence was version 1. Bumping the
        // envelope to version 2 is exactly what makes it reachable, and reachable on nodes already
        // in the field that this change cannot fix. It cannot help those; it means the next format
        // change degrades to "that one message did not render" instead of "the room stopped
        // rendering". Found in review by the other session, not by me, and not by a test.
        let Ok(content) = Content::from_canonical_slice(&plaintext) else {
            return Ok(None);
        };
        let rendered = Rendered {
            entry_hash,
            author,
            created_millis: content.created_millis,
            text: content.text,
        };
        // The cache row shares the entry's log id space; use a fresh id so it never
        // collides with an authored row.
        let id = self.next_log_id;
        let cache_seg = seal_segment(
            &self.sek,
            SegmentKind::PlaintextCache,
            id,
            &cache_bytes(&rendered),
        )?;
        batch.put_segment(
            &self.channel_id,
            SegmentKind::PlaintextCache,
            id,
            &cache_seg,
        )?;
        // A cache row, not an entry: the generation counts entries only (ADR-025 D1).
        self.next_log_id = id.saturating_add(1);
        Ok(Some(rendered))
    }

    /// Queue the receiver chains, as they stand now, into `batch`.
    fn queue_receivers(&self, batch: &mut crate::node::store::Batch<'_>) -> Result<()> {
        let receivers_seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_RECEIVERS,
            &receivers_bytes(&self.receivers),
        )?;
        batch.put_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_RECEIVERS,
            &receivers_seg,
        )
    }

    /// Accept an entry authored by **another** member (M14.5; the bytes arrive from
    /// the join stream now and from ADR-008 sync in M14.6).
    ///
    /// The author must already be admitted ([`ChannelState::admit_author`]), the
    /// entry must pass the ADR-008 acceptance predicate under that author's key, and
    /// its payload decides its kind. A content entry is stored but **not rendered**:
    /// rendering needs that author's sender key, which only arrives with its SKDM,
    /// and this node's consent view (ADR-007 — the newcomer sees ciphertext until a
    /// member consents).
    pub fn accept_entry(&mut self, store: &Store, entry: Entry, now_secs: u64) -> Result<Accepted> {
        if self.poisoned {
            return Err(Error::Profile(
                "channel is poisoned after a failed persist; reopen it",
            ));
        }
        if entry.skeleton.channel_id != self.channel_id {
            return Err(Error::MalformedGovernance("entry binds another channel"));
        }
        if entry.skeleton.epoch != self.epoch {
            return Err(Error::MalformedGovernance("entry binds another epoch"));
        }
        let author = entry.skeleton.author_id;
        let key = self
            .authors
            .get(&author)
            .ok_or(Error::MalformedGovernance(
                "entry from an unadmitted author",
            ))?
            .clone();
        let payload = entry
            .payload
            .as_deref()
            .ok_or(Error::MalformedGovernance("entry payload pruned"))?;
        let kind = classify_payload(payload)?;
        let gov = if kind == EntryKind::Governance {
            Some(GovEntry::from_verified_log_entry(
                &entry,
                &key,
                &self.channel_id,
                self.gov_heads(),
            )?)
        } else {
            None
        };
        let entry_hash = entry.entry_hash();
        let wire = entry.to_wire();
        let id = self.next_log_id;
        let log_seg = seal_segment(&self.sek, SegmentKind::LogDb, id, &wire)?;
        self.dag
            .accept(entry, kind, &key, &self.admission)
            .map_err(|_| Error::MalformedGovernance("entry failed the acceptance predicate"))?;
        if let Err(e) = store.put_segment(&self.channel_id, SegmentKind::LogDb, id, &log_seg) {
            self.poisoned = true;
            return Err(e);
        }
        self.next_log_id = id.saturating_add(1);
        self.gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match gov {
            Some(g) => {
                let could_read = self.readable_authors();
                self.gov_entries.push(g);
                self.evaluator = Arc::new(Self::build_evaluator(
                    &self.genesis,
                    &self.authors,
                    &self.gov_entries,
                    now_secs,
                )?);
                self.backfill_newly_readable(store, &could_read, now_secs)?;
                Ok(Accepted::Governance)
            }
            // Content: render it if we hold the author's sender key and the author
            // has consented to us; otherwise it stays stored as ciphertext
            // (ADR-007 step 3) until an SKDM arrives and backfills it.
            None => {
                let payload = self
                    .dag
                    .get_by_hash(&entry_hash)
                    .and_then(|e| e.payload.clone())
                    .ok_or(Error::MalformedGovernance("accepted entry payload missing"))?;
                if self.render_content(store, author, entry_hash, &payload, now_secs)? {
                    Ok(Accepted::Rendered)
                } else {
                    Ok(Accepted::ContentNotReadable)
                }
            }
        }
    }

    /// Whether this node may read `author`'s messages: `author` has consented to
    /// this identity on the log (ADR-007 per-sender consent). Reading also needs the
    /// sender key itself (the SKDM).
    #[must_use]
    pub fn may_read(&self, author: &Digest32, me: &Digest32) -> bool {
        MembershipView::new(&self.evaluator).can_read(me, author)
    }

    /// Author a text message: encrypt under this identity's sender chain, wrap in
    /// a signed ADR-008 log entry, accept it into the DAG, and persist entry +
    /// rendering + advanced chain state atomically. Returns the rendered message.
    pub fn append_text(
        &mut self,
        profile: &Profile,
        text: &str,
        // **Milliseconds**, from one read of one clock. Renamed from `now_secs` rather than
        // converted at the call site: this value becomes half the ADR-020 claim ordering key, and a
        // caller still thinking in seconds should fail to compile rather than stamp 1970.
        now_millis: u64,
    ) -> Result<&Rendered> {
        if self.poisoned {
            return Err(Error::Profile(
                "channel is poisoned after a failed persist; reopen it",
            ));
        }
        let signer = profile.signer()?;
        let me = signer.fingerprint();
        if !self.authors.contains_key(&me) {
            return Err(Error::Profile(
                "this identity is not an author of the channel",
            ));
        }
        let content = Content::text(now_millis, text)?;
        let plaintext = Zeroizing::new(content.to_canonical_vec());
        let msg = self.sender.encrypt(&plaintext)?;
        let payload = msg.to_wire();

        let skeleton = self.next_skeleton(&me, &payload);
        let entry = Entry::build_signed(signer, skeleton, payload)?;
        let entry_hash = entry.entry_hash();
        let wire = entry.to_wire();
        let rendered = Rendered {
            entry_hash,
            author: me,
            created_millis: now_millis,
            text: content.text,
        };

        let id = self.next_log_id;
        let log_seg = seal_segment(&self.sek, SegmentKind::LogDb, id, &wire)?;
        let cache_seg = seal_segment(
            &self.sek,
            SegmentKind::PlaintextCache,
            id,
            &cache_bytes(&rendered),
        )?;
        let sender_seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_SENDER,
            &self.sender.to_state(),
        )?;

        // Validate against the DAG first (structural), then persist, then commit
        // to memory. A persist failure poisons the channel (see module docs).
        let key = signer.public_key();
        self.dag
            .accept(entry, EntryKind::Content, &key, &self.admission)
            .map_err(|_| Error::Profile("authored entry failed the acceptance predicate"))?;
        let persisted = (|| -> Result<()> {
            let mut batch = profile.store().batch()?;
            batch.put_segment(&self.channel_id, SegmentKind::LogDb, id, &log_seg)?;
            batch.put_segment(
                &self.channel_id,
                SegmentKind::PlaintextCache,
                id,
                &cache_seg,
            )?;
            batch.put_segment(
                &self.channel_id,
                SegmentKind::KeyMaterial,
                SEG_SENDER,
                &sender_seg,
            )?;
            batch.commit()
        })();
        if let Err(e) = persisted {
            self.poisoned = true;
            return Err(e);
        }
        self.next_log_id = id.saturating_add(1);
        self.gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.timeline.push(rendered);
        self.timeline
            .last()
            .ok_or(Error::Profile("timeline empty after push"))
    }

    /// The next entry skeleton for `author`'s feed in this DAG.
    fn next_skeleton(&self, author: &Digest32, payload: &[u8]) -> EntrySkeleton {
        let feed = self.dag.feed(author);
        let max = feed.map_or(0, |f| f.max_seq());
        let seq = max + 1;
        let hash_of = |s: u64| -> Digest32 {
            feed.and_then(|f| f.get(s))
                .map_or(ZERO_HASH, |e| e.entry_hash())
        };
        let prev_hash = if seq == 1 {
            ZERO_HASH
        } else {
            hash_of(seq - 1)
        };
        let lipmaa_backlink = if seq == 1 {
            ZERO_HASH
        } else {
            hash_of(lipmaa(seq))
        };
        EntrySkeleton {
            author_id: *author,
            seq,
            prev_hash,
            lipmaa_backlink,
            channel_id: self.channel_id,
            epoch: self.epoch,
            algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
            payload_hash: sha256(payload),
            payload_len: payload.len() as u64,
            end_of_feed: false,
        }
    }

    /// The channelID.
    #[must_use]
    pub fn channel_id(&self) -> Digest32 {
        self.channel_id
    }

    /// The local (device-only) channel name.
    #[must_use]
    pub fn local_name(&self) -> &str {
        &self.local_name
    }

    /// Creation time recorded in the manifest.
    #[must_use]
    pub fn created(&self) -> u64 {
        self.created
    }

    /// The current epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The genesis record.
    #[must_use]
    pub fn genesis(&self) -> &Genesis {
        &self.genesis
    }

    /// The render-gated timeline, oldest first.
    #[must_use]
    pub fn timeline(&self) -> &[Rendered] {
        &self.timeline
    }

    /// Known authors (M13: the creator), in fingerprint order.
    #[must_use]
    pub fn members(&self) -> Vec<Digest32> {
        self.authors.keys().copied().collect()
    }

    /// Number of accepted log entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.dag.len()
    }

    /// The governance evaluator over this channel's log.
    #[must_use]
    pub fn evaluator(&self) -> &Evaluator {
        &self.evaluator
    }

    /// The room's generation counter (ADR-025 D1), shared.
    #[must_use]
    pub fn generation(&self) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::clone(&self.gen)
    }

    /// Whether a failed persist has poisoned this channel (reopen to continue).
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Whether this channel's SEK is `mlock`ed (ADR-010 best-effort; surfaced to
    /// This channel's SEK, so a daemon can keep it sealed under its identity and reopen the room
    /// after a restart without the room passphrase (#208).
    pub fn sek_bytes(&self) -> Result<&[u8]> {
        self.sek.key_bytes()
    }

    /// the UI as the memory-protection honesty flag).
    #[must_use]
    pub fn mlock_active(&self) -> bool {
        self.sek.is_mlocked()
    }

    /// App-lock this channel: wipe the SEK now. The state should be dropped
    /// afterwards; any further seal/open fails with [`Error::AtRestLocked`].
    pub fn lock_now(&mut self) {
        self.sek.lock_now();
        // Wipe the retained passphrase with the SEK: after an app-lock this channel
        // can neither unseal nor answer a join until it is reopened (ADR-010/015).
        self.passphrase.zeroize();
        self.passphrase = Zeroizing::new(Vec::new());
    }

    /// The retained channel passphrase, for answering an ADR-005 join (the only
    /// thing that needs it). Fails once the channel has been app-locked.
    ///
    /// Stays crate-internal: it is a secret, and the only legitimate consumer is the
    /// node's own join-responder path.
    pub(crate) fn join_passphrase(&self) -> Result<&[u8]> {
        if self.passphrase.is_empty() {
            return Err(Error::AtRestLocked);
        }
        Ok(self.passphrase.as_slice())
    }

    /// The ADR-005 binding parameters for a join in this channel: its channelID,
    /// current epoch, the negotiated suite, and the genesis policy's floor.
    ///
    /// Both ends must derive identical values or CPace simply fails to agree, so
    /// deriving them from the shared genesis (rather than passing them around) is
    /// what keeps the two sides honest.
    pub fn join_context(&self) -> Result<crate::join::session::JoinContext> {
        join_context_from_genesis(&self.genesis, self.epoch)
    }

    /// Whether this channel can currently answer an inbound join.
    #[must_use]
    pub fn can_answer_join(&self) -> bool {
        !self.passphrase.is_empty()
    }
}

/// A channel as a [`crate::log::sync::SessionRoom`]: each step locks the room, does its work, and
/// lets go. See [`ChannelState::sync_over_room`].
struct ChannelSessionRoom<'a> {
    shared: &'a tokio::sync::Mutex<ChannelState>,
    store: &'a Store,
    now_secs: u64,
    /// The epoch the session began at; a room that has moved on refuses what was staged for it.
    epoch: u64,
    /// Retired sessions stop at their next step (ADR-025 D1a).
    fence: &'a crate::transport::stream_transport::Fence,
    /// Called after a batch persisted entries (ADR-025 D1a: stores report themselves).
    on_stored: &'a dyn Fn(),
    out: std::cell::RefCell<SyncOutcome>,
    /// A local failure (a persist that failed) that must reach the caller as itself, not as a code.
    fatal: std::cell::RefCell<Option<Error>>,
}

impl ChannelSessionRoom<'_> {
    fn room(
        &self,
    ) -> std::result::Result<tokio::sync::MutexGuard<'_, ChannelState>, crate::wire::WireError>
    {
        if self.fence.is_retired() {
            return Err(crate::wire::WireError::TransportFailed);
        }
        let ch = self.shared.blocking_lock();
        if ch.poisoned {
            return Err(crate::wire::WireError::TransportFailed);
        }
        if ch.epoch != self.epoch {
            return Err(crate::wire::WireError::EpochMismatch);
        }
        Ok(ch)
    }
}

impl crate::log::sync::SessionRoom for ChannelSessionRoom<'_> {
    fn frontiers(
        &self,
    ) -> std::result::Result<(Vec<crate::log::sync::FeedFrontier>, u64), crate::wire::WireError>
    {
        let ch = self.room()?;
        Ok((
            crate::log::sync::frontiers_of(&ch.dag),
            ch.gen.load(std::sync::atomic::Ordering::Relaxed),
        ))
    }

    fn wants(
        &self,
        remote: &[crate::log::sync::FeedFrontier],
    ) -> std::result::Result<Vec<crate::log::sync::WantRange>, crate::wire::WireError> {
        Ok(crate::log::sync::wants_for_unfrozen(
            &self.room()?.dag,
            remote,
        ))
    }

    fn entries(
        &self,
        wants: &[crate::log::sync::WantRange],
    ) -> std::result::Result<Vec<Vec<u8>>, crate::wire::WireError> {
        Ok(crate::log::sync::entries_for_wants(
            &self.room()?.dag,
            wants,
        ))
    }

    fn apply(&self, staged: Vec<Vec<u8>>) -> crate::log::sync::ApplyReport {
        let mut guard = match self.room() {
            Ok(g) => g,
            Err(code) => {
                return crate::log::sync::ApplyReport {
                    fail: Some(code),
                    ..crate::log::sync::ApplyReport::default()
                }
            }
        };
        let ch = &mut *guard;
        let before = ch.heads();
        let gen_before = ch.gen.load(std::sync::atomic::Ordering::Relaxed);
        // The resolver as it is *now*: an author revoked while this batch was on the wire is not
        // an author of this room any more, and its entries are refused.
        let resolver = ch.resolver();
        // **Absorb what was stored, then report the failure.** The DAG takes entries one at a time
        // and stops at the first hard failure; those before it are already in the log, so they are
        // persisted, rendered and counted before the failure is reported (one joiner once read
        // nothing from the host because the order was the other way round: tworooms.sh).
        let mut report = crate::log::sync::apply_staged_classified(
            &mut ch.dag,
            &resolver,
            &ch.admission,
            &staged,
        );
        match ch.absorb_arrived(self.store, &before, self.now_secs) {
            Ok(got) => {
                let mut out = self.out.borrow_mut();
                out.rendered += got.rendered;
                out.governance += got.governance;
            }
            Err(e) => {
                *self.fatal.borrow_mut() = Some(e);
                report.fail = Some(crate::wire::WireError::TransportFailed);
            }
        }
        // `stored` means persisted: the generation counts each entry the persist step committed.
        let gen_after = ch.gen.load(std::sync::atomic::Ordering::Relaxed);
        report.stored = usize::try_from(gen_after.saturating_sub(gen_before)).unwrap_or(usize::MAX);
        drop(guard);
        if report.stored > 0 {
            (self.on_stored)();
        }
        report
    }

    fn generation(&self) -> std::result::Result<u64, crate::wire::WireError> {
        Ok(self.room()?.gen.load(std::sync::atomic::Ordering::Relaxed))
    }
}
