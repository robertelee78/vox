//! Per-channel state for the single-device node (ADR-016 M13.3): create a
//! channel, open it from the store, append and render messages, and persist
//! every step as sealed segments.
//!
//! ## What a channel is, at rest
//! Under the channel's SEK (ADR-010), sealed segments in the profile store:
//! - `KeyMaterial 0` — the **manifest**: `[2, genesis_wire, name_hint, created,
//!   epoch]`. The genesis is the trust anchor (ADR-007); `name_hint` is the room's shared
//!   name as this node first heard it (its own at creation, the responder's at a join), shown
//!   only until the log, which decides the name, names the room (ADR-028 R-1). A version-1
//!   manifest held a per-member local name, which no longer exists, and is read without it.
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

fn key_package_for(entry: &Entry, recipient: &Digest32) -> bool {
    entry
        .payload
        .as_deref()
        .filter(|payload| crate::node::keypackage::KeyPackage::is_key_package(payload))
        .and_then(|payload| crate::node::keypackage::KeyPackage::from_wire(payload).ok())
        .is_some_and(|package| package.recipient == *recipient)
}

mod attention;
mod diagnostics;
pub(crate) mod entry_store;
pub(crate) mod governance;
pub(crate) mod history;
pub(crate) mod key_package_queue;
pub(crate) mod legacy_provisional;
mod legacy_session;
mod legacy_session_sender;
mod legacy_sync;
mod local_history;
pub(crate) use legacy_sync::LegacySync;
mod private_session;
pub(crate) use private_session::{SessionAdvance, SessionRefresh};
mod own_history;
pub(crate) mod session_floor;
pub(crate) mod session_projection;
mod sparse_history;
pub(crate) use own_history::OwnRecoveryPage;
pub(crate) use sparse_history::{
    HistoryDeclineResult, HistoryEffectCursor, HistoryEffectProgress, HistoryPayload,
    HistorySourceStart,
};

pub use diagnostics::SetAside;
pub use entry_store::OrderView;
use entry_store::Transaction;
pub use governance::{GovernanceNotices, GovernanceProgress, GovernanceShares, GovernanceTargets};
use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroizing;

use crate::atrest::idfactor::SignatureIdentityFactor;
use crate::atrest::sek::{Argon2Profile, Sek};
use crate::atrest::store::{open_segment, seal_segment, SealedSegment, SegmentKind};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::governance::consent::{ConsentGrant, ConsentRevocation};
use crate::governance::entry::{GovBody, GovEntry};
use crate::governance::genesis::{ChannelPolicy, Genesis, HistoryMode};
use crate::governance::membership::{issue_consent_grant, issue_consent_revocation};
use crate::governance::share::ServiceKind;
use crate::group::history::OriginKeyStore;
use crate::group::message::GroupMessage;
use crate::group::skdm::Skdm;
use crate::group::state::{ReceiverChain, SenderChain};
use crate::group::wire::GROUP_MSG_SIGN_DOMAIN;
use crate::hash::{sha256, Digest32};
use crate::identity::composite::{CompositePublicKey, RootSigner};
use crate::log::dag::{AdmissionPolicy, Dag, ForkProof};
use crate::log::entry::{Entry, EntryKind, EntryRead, EntrySkeleton, ZERO_HASH};
use crate::log::feed::lipmaa;
use crate::log::history::{
    ConsistentPrefix, Descriptor, LocalAppendBudget, LogScope, SignedHead, TreeBinding,
};
use crate::log::sync::{frontier_session_peer, AuthorResolver, Transport};
use crate::nat::bootstrap::BootstrapSet;
use crate::nat::record::Admission;
use crate::node::consent_order::Stamp;
use crate::node::content::{Content, Decoded};
use crate::node::drive::{drive_channel, DriveState, SessionRow};
use crate::node::profile::Profile;
use crate::node::retention::Tracked;
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
// KeyMaterial slot 4 held unsigned bootstrap hints. It is not room authority.
/// The offered-services segment id within [`SegmentKind::KeyMaterial`] (ADR-013,
/// M16.1): the `service_tag → local address` map this node **binds** for this
/// channel. Host configuration, not authorization — who may *reach* it is the host's
/// dial gate ([`crate::tunnel::session::accept`]).
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

/// Persist the canonical signed empty public head before a new sparse room becomes visible.
/// A joiner has no entry yet, but another member still needs an exact object to acknowledge
/// before this node may leave the unsettled state and author its first entry.
fn initialize_sparse_identity(
    index: &mut entry_store::Write<'_, '_>,
    signer: &dyn RootSigner,
    room: Digest32,
    epoch: u64,
) -> Result<()> {
    let binding = TreeBinding {
        author: signer.fingerprint(),
        room,
        scope: LogScope::Public,
    };
    let signed = SignedHead::sign(binding, epoch, Descriptor::empty(binding), signer)?;
    let mut budget = LocalAppendBudget::new();
    let verified = budget.verify_head(&signed, &signer.public_key())?;
    let prefix = ConsistentPrefix::empty(&verified)?;
    index.commit_history_head(&verified, &prefix)?;
    Ok(())
}

/// This node's **own admission** to the channel, within [`SegmentKind::KeyMaterial`]
/// (M17.6): whether it created the channel, or the [`crate::nat::record::JoinWitness`] a member signed
/// when it verified this node's ADR-005 passphrase proof.
///
/// Persisted because it is republished with every member bundle record, for as long
/// as this node is a member. A node that forgot it after a restart could publish no
/// bundle at all, and would fall off every board.
const SEG_ADMISSION: u64 = 8;

/// Version of an entry's retention record: the `Index` segment sharing its `LogDb` id,
/// `[version, first_seen]` (ADR-023 decision 2). Version 2 holds milliseconds; version 1, which
/// stores made before held, whole seconds.
const FIRST_SEEN_VERSION: u64 = 3;

fn first_seen_bytes(first_seen_ms: u64, steps: bool) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(3)
        .uint(FIRST_SEEN_VERSION)
        .uint(first_seen_ms)
        .uint(u64::from(steps));
    e.finish()
}

/// Old records keep their original age. Version 3 also remembers a pruned Session
/// body's kind, so restarting cannot turn expired activity into an owed message.
fn parse_first_seen(bytes: &[u8]) -> Result<(u64, bool)> {
    let mut d = Decoder::new(bytes);
    let arity = d.array()?;
    let version = d.uint()?;
    let t = match (version, arity) {
        (1, 2) => d.uint()?.saturating_mul(1_000),
        (2, 2) | (3, 3) => d.uint()?,
        _ => return Err(Error::MalformedAtRest("retention record")),
    };
    let steps = if version == FIRST_SEEN_VERSION {
        match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(Error::MalformedAtRest("retention kind")),
        }
    } else {
        false
    };
    d.finish()?;
    Ok((t, steps))
}

fn retained_control(body: &[u8]) -> bool {
    session_floor::is_session_floor(body)
        || private_session::is_support(body)
        || crate::governance::step_policy::is_step_policy(body)
}

fn is_step_body(room: &Digest32, body: &[u8]) -> bool {
    GroupMessage::from_wire(body)
        .is_ok_and(|message| message.header.channel_id == drive_channel(room))
}
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

/// The not-yet-synced marker within [`SegmentKind::KeyMaterial`] (V210-164): present from a
/// join until the room's first clean sync with another member, so a node that stops in between
/// still writes nothing when it reopens the room. See `ChannelState::settled`.
const SEG_UNSETTLED: u64 = 13;
/// Present while a member was seen holding entries of this node's own feed that this node does
/// not hold (ADR-037 R5): a restored older profile. The room refuses this node's writes.
const SEG_OWN_BEHIND: u64 = 18;

/// How far each member's node holds this identity's feed here, as that node last said in a sync
/// (ADR-028 R-6, #482), within [`SegmentKind::KeyMaterial`]: what "on N of M members' nodes" is
/// counted from, kept so a restart does not say "only on this machine" of what was delivered.
const SEG_HELD: u64 = 14;

/// Encoding version of [`SEG_HELD`].
const HELD_VERSION: u64 = 1;

/// The members this node knows to be members before their records are admitted (V030-51), within
/// [`SegmentKind::KeyMaterial`]: the member that answered this node's join. A room link names it
/// with an address, as it names the room's anchors; without this a joiner that admitted fewer
/// records than the room has members kept it as an anchor, dialled direct only and passed over by
/// the sync, until a sync admitted it — and again on every reopen before then.
const SEG_KNOWN_MEMBERS: u64 = 15;

/// Encoding version of [`SEG_KNOWN_MEMBERS`].
const KNOWN_MEMBERS_VERSION: u64 = 1;

/// This node's **drive key** material here (ADR-029 SC-2, #543) within
/// [`SegmentKind::KeyMaterial`]: its own drive chain, the drive keys others released to it, and its
/// release ledger ([`crate::node::drive::DriveState`]).
const SEG_DRIVE: u64 = 16;

/// What this node keeps of the room's board for good (#520), within [`SegmentKind::KeyMaterial`]:
/// the admission notice of every author it admitted on a witness, and every member's own withdraw
/// it has seen. A board forgets on a restart and a bundle record lapses; these are what let every
/// member learn of a newcomer that is offline, and never of one that left.
const SEG_BOARD_KEPT: u64 = 17;

/// One current local room pause; sealed independently of Session activity and retention.
/// Slots 18 and 19 belong to the legacy Session announcement cursor and drive generations.
const SEG_ROOM_PAUSE: u64 = 20;

/// Encoding version of [`SEG_BOARD_KEPT`]: `[1, [notice wire..], [withdraw wire..]]`.
const BOARD_KEPT_VERSION: u64 = 1;

/// The notices and withdraws a room keeps (#520), as their signed wire bytes.
#[derive(Debug, Clone, Default)]
struct BoardKept {
    /// `joiner` → `(witness time, notice)`, the newest witnessed.
    notices: BTreeMap<Digest32, (u64, Vec<u8>)>,
    /// `member` → `(withdraw time, withdraw)`, the newest.
    withdraws: BTreeMap<Digest32, (u64, Vec<u8>)>,
}

fn board_kept_bytes(kept: &BoardKept) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(3)
        .uint(BOARD_KEPT_VERSION)
        .array(kept.notices.len());
    for (_, wire) in kept.notices.values() {
        e.bytes(wire);
    }
    e.array(kept.withdraws.len());
    for (_, wire) in kept.withdraws.values() {
        e.bytes(wire);
    }
    e.finish()
}

fn parse_board_kept(bytes: &[u8], channel_id: &Digest32) -> Result<BoardKept> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 3 {
        return Err(Error::MalformedAtRest("board kept arity"));
    }
    if d.uint()? != BOARD_KEPT_VERSION {
        return Err(Error::MalformedAtRest("board kept version"));
    }
    let mut kept = BoardKept::default();
    let n = d.array()?;
    if n > AUTHORS_HARD_LIMIT {
        return Err(Error::SizeLimitExceeded("kept notices"));
    }
    for _ in 0..n {
        let wire = d.bytes()?.to_vec();
        let notice = crate::nat::notice::AdmissionNotice::from_wire(&wire)
            .map_err(|_| Error::MalformedAtRest("kept notice"))?;
        if notice.channel_id() != *channel_id {
            return Err(Error::MalformedAtRest("kept notice room"));
        }
        kept.notices
            .insert(notice.joiner(), (notice.witness.timestamp_ms, wire));
    }
    let n = d.array()?;
    if n > AUTHORS_HARD_LIMIT {
        return Err(Error::SizeLimitExceeded("kept withdraws"));
    }
    for _ in 0..n {
        let wire = d.bytes()?.to_vec();
        let w = crate::nat::withdraw::BoardWithdraw::from_wire(&wire)
            .map_err(|_| Error::MalformedAtRest("kept withdraw"))?;
        if w.channel_id != *channel_id || w.scope != crate::nat::withdraw::WithdrawScope::Member {
            return Err(Error::MalformedAtRest("kept withdraw scope"));
        }
        kept.withdraws.insert(w.author_id, (w.timestamp_ms, wire));
    }
    d.finish()?;
    Ok(kept)
}

fn known_members_bytes(known: &BTreeSet<Digest32>) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(2).uint(KNOWN_MEMBERS_VERSION).array(known.len());
    for id in known {
        e.bytes(id);
    }
    e.finish()
}

fn parse_known_members(bytes: &[u8]) -> Result<BTreeSet<Digest32>> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 2 {
        return Err(Error::MalformedAtRest("known members arity"));
    }
    if d.uint()? != KNOWN_MEMBERS_VERSION {
        return Err(Error::MalformedAtRest("known members version"));
    }
    let n = d.array()?;
    if n > AUTHORS_HARD_LIMIT {
        return Err(Error::SizeLimitExceeded("known members"));
    }
    let mut out = BTreeSet::new();
    for _ in 0..n {
        let id: Digest32 = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("known member"))?;
        out.insert(id);
    }
    d.finish()?;
    Ok(out)
}

fn held_bytes(held: &BTreeMap<Digest32, u64>) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(2).uint(HELD_VERSION).array(held.len());
    for (member, seq) in held {
        e.array(2).bytes(member).uint(*seq);
    }
    e.finish()
}

fn parse_held(bytes: &[u8]) -> Result<BTreeMap<Digest32, u64>> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 2 || d.uint()? != HELD_VERSION {
        return Err(Error::MalformedAtRest("room held-by record"));
    }
    let mut out = BTreeMap::new();
    for _ in 0..d.array()? {
        if d.array()? != 2 {
            return Err(Error::MalformedAtRest("room held-by entry"));
        }
        let member: Digest32 = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("room held-by member"))?;
        out.insert(member, d.uint()?);
    }
    d.finish()?;
    Ok(out)
}

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
    if n > AUTHORS_HARD_LIMIT {
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

/// One trust-mark segment prepared without changing the room's live projection. The caller writes
/// the sealed segment first, then installs the corresponding in-memory mark with
/// [`ChannelState::install_trust_mark`].
pub struct PreparedTrustMark {
    target: Digest32,
    position: TrustMark,
    sealed: SealedSegment,
}

/// How long a superseded generation of this identity's sender key is kept for a trusted
/// identity that has not joined, in a room kept forever (PRD-001 R14): 30 days. A room with a
/// retention keeps it for that instead ([`ChannelState::unjoined_hold_secs`]).
pub const UNJOINED_HOLD_SECS: u64 = 30 * 24 * 60 * 60;

/// At-rest version of the delivery-ledger segment.
const DELIVERED_VERSION: u64 = 1;
/// Services encoding version.
const SERVICES_VERSION: u64 = 2;
/// The most services one channel may offer — a sanity bound on host config.
pub const MAX_SERVICES: usize = 64;
/// Manifest encoding version. **2 holds the shared name's hint** where 1 held a per-member local
/// name (ADR-028 R-1 removed those); 1 is still read, without its name. **3 holds the creation time
/// in milliseconds**; 1 and 2 held it in seconds, and are read as milliseconds.
const MANIFEST_VERSION: u64 = 3;
/// Plaintext-cache row encoding version.
/// Version of the plaintext rendering cache. **2 stores the timestamp in milliseconds**, and is the
/// only version this build reads: version 1 (seconds) was an earlier release's (#423).
const CACHE_VERSION: u64 = 2;

/// At-rest version of the admitted-authors segment.
const AUTHORS_VERSION: u64 = 1;

/// At-rest version of the receiver-chains segment.
const RECEIVERS_VERSION: u64 = 1;

/// Hard cap on retained receiver chains per channel (one per author generation).
pub const MAX_RECEIVER_CHAINS: usize = 4096;

/// Hard cap on admitted authors per channel, so a hostile or corrupt segment cannot
/// force an unbounded allocation on open.
pub const MAX_AUTHORS: usize = 1024;

/// **The most authors this node holds for a room: a bound on memory only** (V210-128). A member
/// answering a join refuses it at the cap ([`MAX_AUTHORS`]), but a member another member admitted
/// is always admitted from the board, past the cap if it must be: joins answered at the same
/// moment by different members can each take the last place, and refusing the other's newcomer
/// would split the room, each told it joined and a member on one side only. The node says so when
/// that happens. This bound is not the cap; it only keeps a room's authors finite.
pub const AUTHORS_HARD_LIMIT: usize = 2 * MAX_AUTHORS;

/// Maximum retained rows the room projection examines in one backfill turn. Remaining work is
/// durable and another event-driven turn continues it.
pub const RENDER_BACKFILL_ROWS_PER_TURN: usize = governance::PAGE_ROWS;

/// **Test-only**: when set, `room admin add` gives the certificate this finite lifetime. The
/// optional FX-22 journey uses the real shipped command and this source-owned interval to prove
/// that an otherwise quiet room wakes exactly when its effective authority expires.
#[cfg(feature = "test-knobs")]
pub const TEST_EXPIRING_ADMIN_ENV: &str = "VOX_TEST_EXPIRING_ADMIN";

/// Lifetime of the expiring administrator certificate staged by [`TEST_EXPIRING_ADMIN_ENV`].
#[cfg(feature = "test-knobs")]
pub const TEST_EXPIRING_ADMIN_LIFETIME: std::time::Duration = std::time::Duration::from_secs(20);

/// **Test-only**: an empty named marker retains every already durable render continuation without
/// advancing it. A 96-byte marker names one room and two authors; that room remains held until it
/// has both exact sender keys, when the marker is renamed with `.ready` appended. A 64-byte marker
/// names one room and one author; the first bounded turn that commits a row by that author renames
/// it with `.engaged` appended, and later turns for that room park until the engaged marker is
/// removed. Proofs use shipped status/read commands at the causal boundary; marker states are
/// apparatus, never verdicts or test-only counts.
#[cfg(feature = "test-knobs")]
pub const TEST_HOLD_RENDER_ENV: &str = "VOX_TEST_HOLD_RENDER_FILE";

#[cfg(feature = "test-knobs")]
fn render_hold_path() -> Option<std::path::PathBuf> {
    std::env::var_os(TEST_HOLD_RENDER_ENV)
        .filter(|path| !path.is_empty())
        .map(std::path::PathBuf::from)
}

#[cfg(feature = "test-knobs")]
fn render_hold_suffixed_path(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
    let mut suffixed = path.as_os_str().to_owned();
    suffixed.push(suffix);
    suffixed.into()
}

#[cfg(feature = "test-knobs")]
fn engage_render_hold(room: &Digest32, rows: &[Rendered]) {
    let Some(path) = render_hold_path() else {
        return;
    };
    let Ok(marker) = std::fs::read(&path) else {
        return;
    };
    if marker.len() != 64 || marker[..32] != room[..] {
        return;
    }
    let author = &marker[32..];
    if rows.iter().any(|row| row.author[..] == author[..]) {
        let _ = std::fs::rename(&path, render_hold_suffixed_path(&path, ".engaged"));
    }
}

/// **Test-only**: a smaller room, so a proof fills one with a few members rather than 1,024. Its
/// value is the most authors a room admits, from 1 to [`MAX_AUTHORS`]. Unset, empty, unparsable or
/// out of range is [`MAX_AUTHORS`]: nothing in a real deployment sets it, and without the
/// `test-knobs` feature (V210-105) it is not compiled in.
#[cfg(feature = "test-knobs")]
pub const TEST_MAX_AUTHORS_ENV: &str = "VOX_TEST_MAX_AUTHORS";

/// **Test-only**: when set, this node never counts a room as synced since it joined, so a proof can
/// stand a forward in a room whose first sync has provably not happened, whatever the timing of
/// the join (a joiner's first sync otherwise races the end of `vox connect`). Unset, nothing
/// changes; nothing a person runs sets it, and without the `test-knobs` feature (V210-105) it is
/// not compiled in.
#[cfg(feature = "test-knobs")]
pub const TEST_NEVER_SETTLE_ENV: &str = "VOX_TEST_NEVER_SETTLE";

/// The most authors a room admits: [`MAX_AUTHORS`], or `TEST_MAX_AUTHORS_ENV`'s.
#[must_use]
pub fn max_authors() -> usize {
    #[cfg(feature = "test-knobs")]
    {
        static MAX: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        *MAX.get_or_init(|| {
            std::env::var(TEST_MAX_AUTHORS_ENV)
                .ok()
                .and_then(|v| v.trim().parse::<usize>().ok())
                .filter(|n| (1..=MAX_AUTHORS).contains(n))
                .unwrap_or(MAX_AUTHORS)
        })
    }
    #[cfg(not(feature = "test-knobs"))]
    MAX_AUTHORS
}
/// Cap on a room's name as a manifest or a request carries it: a version-1 manifest's local name
/// could be this long; a room name is at most [`crate::governance::name::MAX_ROOM_NAME`].
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

    fn unclassifiable(&self, entry: &Entry) -> Option<Error> {
        let payload = entry.payload.as_deref()?;
        match classify_payload(payload) {
            Err(e) => Some(e),
            Ok(EntryKind::Governance) => GovEntry::body_bound_to(entry).err(),
            // A checkpoint's claim about its own feed is checked where it is accepted.
            Ok(EntryKind::Content | EntryKind::Checkpoint) => None,
        }
    }
}

/// What one [`ChannelState::sync_over`] session did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SyncOutcome {
    /// A missing legacy prefix is recovered only through explicit history demand.
    pub(crate) legacy_required: Option<crate::log::sync::LegacyGap>,
    /// An exact explicit legacy interval reached a signed invalid/frozen feed boundary.
    /// This cancels recovery; it never credits the missing suffix as accepted history.
    pub(crate) legacy_invalid: bool,
    pub(crate) legacy_unavailable: bool,
    /// Received protocol bytes including transport length prefixes.
    pub(crate) wire_received: usize,
    /// Next exact legacy position retained by the explicit request, including sealed staging.
    pub(crate) legacy_next: Option<u64>,
    /// A signed witness still needs explicit bounded publication/cleanup work.
    pub(crate) legacy_pending: bool,
    /// Entries the ADR-008 session applied to the log.
    pub applied: usize,
    /// How many of those were governance entries accepted for the sealed projection.
    pub governance: usize,
    /// How many of those were decrypted and rendered into the timeline.
    pub rendered: usize,
    /// Entries refused rather than held (V210-74): by sync before they were held, or after.
    pub refused: usize,
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
    /// How far the peer said it holds this identity's feed here: the highest seq its frontier
    /// named, `0` for none (ADR-028 R-6). `None` when the session never read its frontier.
    pub mine_held: Option<u64>,
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
            Self::Session(SessionError::DrainBudget(secs)) => write!(
                f,
                "sync stopped: the peer's entries did not all arrive within {secs}s; what \
                 arrived was kept"
            ),
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
        out.refused += s.refused;
        out.gen_have = s.gen_have;
        out.gen_end = s.gen_end;
        out.wire_received = s.wire_received;
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
    /// A governance entry: verified and stored with its projection obligation.
    Governance,
    /// A content entry: verified and stored, but not readable — this node holds no
    /// sender key for that author yet, or that author has not consented to this
    /// identity (ADR-007: consent, not credentials, grants reading).
    ContentNotReadable,
    /// A content entry that was decrypted and rendered into the timeline.
    Rendered,
    /// An author's checkpoint on its own feed (ADR-023 decision 3): verified and stored.
    Checkpoint,
}

/// Result of taking a sender/drive key. `changed` is false for an unchanged duplicate: callers
/// acknowledge it but schedule no rendering or governance work.
#[derive(Debug, Clone, Copy)]
pub struct AcceptedSkdm {
    pub(crate) rendered: usize,
    pub(crate) changed: bool,
}

/// Why a room is over (V030-08).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomEnd {
    /// Its creator, or an admin the creator named, ended it for everyone.
    ByCreator,
    /// Nothing was said in it for the idle end its creator chose.
    Idle {
        /// The idle end, in seconds.
        idle_secs: u64,
    },
}

impl std::fmt::Display for RoomEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoomEnd::ByCreator => f.write_str("its creator or an admin ended it"),
            RoomEnd::Idle { idle_secs } => write!(
                f,
                "nothing was said in it for {}, the idle end its creator chose",
                crate::node::retention::describe(*idle_secs)
            ),
        }
    }
}

/// Inputs of an already-published timeline. The existing sync generation's allocation
/// identifies this open room, but its value is deliberately not used: durable log credit
/// does not cover body filling, classification, expiry or sender-key backfill.
#[derive(Debug, Clone)]
pub(crate) struct DisplayStamp {
    incarnation: Arc<std::sync::atomic::AtomicU64>,
    rewrite: u64,
    rendered_roots: [u64; 4],
    rendered_count: u64,
    order_revision: u64,
    body_revision: u64,
    session_revision: u64,
    retention: (u64, u64),
    expires_at: Option<u64>,
    /// How many of the rows shown stand for a body not received yet (V030-10).
    owed_count: u64,
    pub(crate) owed: bool,
}

impl DisplayStamp {
    /// The rows a person is shown of the room: every row `vox room read` pages through, a body
    /// not received yet counting as the placeholder shown for it. Read from the stamp, which is
    /// taken on every publication anyway: no store read is added for the count (ADR-038 FX-16,
    /// FX-22; #995).
    #[must_use]
    pub(crate) fn rows(&self) -> u64 {
        self.rendered_count.saturating_add(self.owed_count)
    }
}

impl PartialEq for DisplayStamp {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.incarnation, &other.incarnation)
            && self.rewrite == other.rewrite
            && self.rendered_roots == other.rendered_roots
            && self.rendered_count == other.rendered_count
            && self.order_revision == other.order_revision
            && self.body_revision == other.body_revision
            && self.session_revision == other.session_revision
            && self.retention == other.retention
            && self.expires_at == other.expires_at
            && self.owed_count == other.owed_count
            && self.owed == other.owed
    }
}

impl Eq for DisplayStamp {}

/// Inputs of the bounded read/held indicators, independent of unrelated actor events.
/// The timeline's DisplayStamp separately binds the open room and selected messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadSummaryStamp {
    reads: [u64; 2],
    members_held: Vec<(Digest32, Option<u64>)>,
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
    /// When **this node** rendered it: the id of its sealed plaintext cache row, which
    /// only grows. Local, never shared, and not part of the room's order. It is what
    /// "new since" means to a reader holding a cursor: a late arrival can land above
    /// the cursor in the order, and is still after it here.
    pub arrival: u64,
    /// When this node placed it in the timeline, ms on this node's clock; `0` for a row
    /// loaded from the store at open, which the reader saw before the restart. Local, never
    /// persisted, and only used to decide [`Rendered::late`].
    pub shown_at_ms: u64,
    /// This row took its place **above a row the reader had already been shown**: it
    /// arrived late, from a member who was offline or a sync that caught up (ADR-023
    /// decision 1). It is shown where it belongs, not at the bottom, and the flag is how a
    /// reader is told something appeared in history.
    ///
    /// "Already shown" means placed at least [`LATE_AFTER_MS`] earlier. Posts crossing in
    /// flight land within a second of each other and above one another in the order;
    /// that is ordinary concurrency, and flagging it would make the flag meaningless.
    pub late: bool,
    /// **Not received yet** (V030-10): a message whose signed envelope this node holds and whose
    /// body no peer has supplied yet, and which has not expired by this node's own reckoning. Its
    /// `text` is empty; it is asked for again on every sync, and replaced by the message when the
    /// body arrives. Selected history queries derive each placeholder from sealed owed facts.
    pub owed: bool,
}

/// The result of projecting one authenticated content body. `Deferred` means the body is valid
/// and retained, but a transient governance/receiver-chain dependency prevents a truthful
/// admission result yet. Callers that own an explicit history demand must not clear it in that
/// case.
enum ContentProjection {
    Visible(Rendered),
    Applied,
    Deferred,
    Unavailable,
}

impl ContentProjection {
    fn into_row(self) -> Option<Rendered> {
        match self {
            Self::Visible(row) => Some(row),
            Self::Applied | Self::Deferred | Self::Unavailable => None,
        }
    }
}

/// One line a person is told about the room, in its timeline but not a message (ADR-028 E-5):
/// `ann renamed the room to family`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomNotice {
    /// The log entry it comes from.
    pub entry_hash: Digest32,
    /// Who did it.
    pub author: Digest32,
    /// When, as its author's entry claims, milliseconds since the Unix epoch.
    pub created_millis: u64,
    /// What they did, without who: `renamed the room to family`.
    pub what: String,
    /// The newest timeline row before it in the room's order ([`Dag::order_key`]), where a
    /// client draws it: `None` before every row. Its time claims seconds only, so a client that
    /// placed it by time put it above a message sent earlier in the same second.
    pub after: Option<Digest32>,
}

/// How many more of an author's entries must have expired since its last checkpoint before it
/// posts another (ADR-023 decision 3): 32. A checkpoint is itself a signed entry of about the
/// size it saves on one skeleton, so one per 32 costs about 3% of what it frees, and a room
/// that expires slowly is not filled with checkpoints.
pub const CHECKPOINT_EVERY: usize = 32;
/// Maximum checkpoint-covered positions rewritten in one periodic maintenance turn. A peer can
/// arrive after many checkpoints, so the receiver must not walk that entire range on its actor.
const SIGNATURE_SWEEP_PAGE: usize = 64;

/// How many of this node's own newest messages in a room a client is told the readers of (ADR-028
/// R-6): more than a screen holds, and a bound on what every snapshot of the node carries.
pub const READ_BY_SHOWN: usize = 128;

/// How far back from a room's newest row its unread are looked for ([`ChannelState::unread`]):
/// a bound on what every view of the node walks, far more than a person reads at once.
pub const UNREAD_LOOKED: usize = 1_000;

/// How many owed bodies (V030-10) one sync session asks a peer for at most. The rest are asked of
/// the next session: a peer that stripped a long run is not asked for all of it at once.
pub const MAX_OWED_ASKED: usize = 256;

/// One entry a sync stored, for [`ChannelState::absorb_arrived`]: `(author, entry hash, body, the
/// log page it is already stored in)`. The page is set only for a body that arrived for a skeleton
/// held without one (V030-10).
type Arrived = (Digest32, Digest32, Option<Vec<u8>>, Option<u64>);

/// Whether an entry claimed at `claimed_ms` is past `ttl` seconds of retention at `now_ms`
/// (`ttl == 0` keeps everything), compared in milliseconds.
fn expired_at(claimed_ms: u64, now_ms: u64, ttl: u64) -> bool {
    ttl != 0 && claimed_ms <= now_ms.saturating_sub(ttl.saturating_mul(1_000))
}

/// How long nothing new must have expired before an author closes a backlog smaller than
/// [`CHECKPOINT_EVERY`] with a checkpoint anyway: ten minutes. Long enough that a room expiring
/// steadily batches its checkpoints; short enough that a quiet room's last few entries do not
/// keep their signatures indefinitely.
pub const CHECKPOINT_IDLE_SECS: u64 = 600;

/// How long a row must have been on screen before something landing above it counts as a
/// late arrival rather than ordinary concurrency: ten seconds. A push delivers a member's
/// post in about a second, so two people typing at once never trip it; a member returning
/// from offline, or a post that only arrived with the 30-second sync pass, does.
pub const LATE_AFTER_MS: u64 = 10_000;

/// How far ahead of this node's clock another member's post may be stamped and still push this
/// node's next stamp past it (see `ChannelState::stamp_after_held`): ten minutes covers clocks
/// that drift, and stops one far-off clock from dragging the room's stamps with it.
pub const STAMP_LEAD_LIMIT_MILLIS: u64 = 10 * 60 * 1000;

/// How many of this node's own posts `ChannelState::skipped_when_stamped` remembers.
const SKIPPED_KEPT: usize = 64;

/// Stable inputs to receipt eligibility. Routine directory seals do not wake a completed
/// pass; a changed pending set, rendered row or read policy does. Reopen starts a fresh pass.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ReadMarkEligibility {
    reader: Digest32,
    pending: u64,
    rendered: [u64; 4],
    governance: u64,
    retention: (u64, u64),
}

#[derive(Clone, Copy)]
struct ReadMarkScan {
    after: Option<Digest32>,
    through: Digest32,
    started: ReadMarkEligibility,
}

/// Restart rebuild of the admitted-member consent projection. One maintenance turn examines at
/// most [`governance::PAGE_ROWS`] author/target pairs; neither departed nor arbitrary
/// off-roster targets occupy this state.
struct ConsentFactsBuild {
    members: Vec<Digest32>,
    author: usize,
    target: usize,
    facts: governance::ConsentFacts,
}

impl ConsentFactsBuild {
    fn new(authors: &BTreeMap<Digest32, CompositePublicKey>) -> Self {
        Self {
            members: authors.keys().copied().collect(),
            author: 0,
            target: 0,
            facts: governance::ConsentFacts::empty(),
        }
    }
}

enum ConsentFactsState {
    Building(ConsentFactsBuild),
    Ready(std::sync::Arc<governance::ConsentFacts>),
}

/// An open (SEK-unlocked) channel on this device.
pub struct ChannelState {
    channel_id: Digest32,
    genesis: Genesis,
    /// The room's shared name as this node first heard it, shown only while the log names it not
    /// (ADR-028 R-1); empty for none.
    name_hint: String,
    /// When this node made or joined the room, milliseconds since the Unix epoch.
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
    /// Last published scalar display. Unchanged user-visible queries read this in memory;
    /// irreversible authority decisions still require the sealed checked view.
    governance_display: governance::Display,
    governance_ready: bool,
    /// This room's admitted-member consent facts in memory (ADR-038 FX-22). Unchanged questions
    /// never open storage; restart reconstruction advances in bounded governance turns.
    consent_facts: std::sync::Mutex<ConsentFactsState>,
    /// A member holds entries of this node's own feed here that this node does not (ADR-037
    /// R5): durable in `SEG_OWN_BEHIND`; every write here refuses with `OwnHistoryBehind`.
    own_behind: bool,
    own_recovery: own_history::Recovery,
    /// A completed authenticated current-head flow may settle after bounded maintenance.
    /// Current presence per admitted author, bounded by AUTHORS_HARD_LIMIT; no event history.
    presence: BTreeMap<Digest32, governance::Presence>,
    /// Highest semantically applied sparse entry per admitted author. Rebuilt from the
    /// sealed settled-tip index on open; signed/source-only heads never enter this map.
    sparse_applied_tips: BTreeMap<Digest32, u64>,
    /// Authors whose durable settled suffix still extends beyond the role-complete restart
    /// cursor. One bounded page is advanced per governance turn, fairly across authors.
    sparse_contiguous_pending: BTreeSet<Digest32>,
    sparse_contiguous_after: Option<Digest32>,
    sender: SenderChain,
    /// The next `LogDb` / `PlaintextCache` segment id.
    next_log_id: u64,
    /// Current fixed-tail pass and the unchanged eligibility it last finished examining.
    /// No mark set is resident, and skipped marks stay sealed while an idle pass is parked.
    read_mark_scan: Option<ReadMarkScan>,
    read_mark_complete: Option<ReadMarkEligibility>,
    /// Stored entries set aside when the room opened (V210-74): each as `author#seq: why`.
    set_aside: SetAside,
    /// A receiver chain advanced in memory since the chains were last written (V210-74): a decrypt
    /// uses its message key up even when what it opened does not render, so a pass that rendered
    /// nothing must write the chains too, or a restart could derive that key again.
    chains_advanced: bool,
    /// A render backfill was drained while the governance view was refreshing: nothing
    /// rendered, the queue kept; the next governance turn drains it (ADR-038 FX-22, #1007).
    backfill_refreshing: bool,
    /// Last author given one backfill row. The durable per-author cursors survive restart; this
    /// in-memory round-robin cursor only prevents one long author from starving the others.
    backfill_after: Option<Digest32>,
    /// Sealed exact-hash subtype evidence; never a permission or recovery eligibility decision.
    legacy_sessions: legacy_session::LegacySessions,
    /// Own-feed declaration cursor and the capable readers covered by that scan.
    legacy_announced: Option<legacy_session_sender::Announcements>,
    private_sessions: private_session::PrivateSessions,
    /// How far each other member's node holds this identity's feed here, by its own word in its
    /// last sync with this node (ADR-028 R-6): the highest seq of the feed its frontier named.
    /// Persisted as [`SEG_HELD`].
    held: BTreeMap<Digest32, u64>,
    /// Last missing-body position examined by `owed_wants`, including ineligible positions.
    /// The next session resumes after it and wraps, so unavailable bodies cannot starve others.
    owed_asked_to: Option<(Digest32, u64)>,
    /// The latest time this room was told (milliseconds): what "expired by now" is reckoned against
    /// where no clock is passed in (the view, the want-list).
    now_hint: u64,
    projection_state: history::State,
    /// Constant-size display watermarks; plaintext bodies live only in the sealed cache.
    /// A late insertion or canonical move invalidates a notice scan, but an end append does not.
    display_tail: Option<(u64, Digest32)>,
    display_order_revision: u64,
    /// Highest shown time in this open incarnation, to notice a backwards wall-clock step.
    display_shown_at: u64,
    /// Changes that cannot extend the previous rendered prefix.
    display_rewrite: u64,
    /// entry hash -> the `LogDb` page it is stored in, so a signature dropped under a
    /// checkpoint (ADR-023 decision 3) can be rewritten in place.
    entries: entry_store::EntryIndex,
    /// Startup cleanup is local bounded maintenance. `CleanupPending` keeps the room private;
    /// `ReadyWithCleanup` permits current traffic while detached retired roots are reclaimed.
    legacy_preparation: entry_store::Preparation,
    /// Current local trust used only to filter accepted-cache recovery reads.
    legacy_cache_trusted: Option<BTreeSet<Digest32>>,
    /// Bounded cursors over retained key-package log rows and admitted-author drive hints.
    /// The actor opens one returned package at a time using its prekey ring.
    key_packages: key_package_queue::Queue,
    /// Sender keys released to this identity, keyed by `(author, chain_id)`
    /// (M14.5b). Present only for authors that consented; its presence is what
    /// makes their content readable.
    receivers: BTreeMap<(Digest32, u64), ReceiverChain>,
    /// The services this node offers in this channel (ADR-013 Bind config, M16.1),
    /// persisted in `SEG_SERVICES` — except those in `transient`.
    services: BTreeMap<String, SocketAddr>,
    /// What each shared service in `services` was detected to be when it was shared (ADR-028
    /// S-2), persisted with it, so a share said only once the room settles says the same kind.
    kinds: BTreeMap<String, ServiceKind>,
    /// The tags in `services` that live only as long as whatever offered them (V210-72): a file
    /// share, which the node's shares offer again when they serve it again. Never persisted, so
    /// a node that stops while one runs does not come back offering a port nobody serves any
    /// more.
    transient: BTreeSet<String>,
    /// How **this node** came to be a member here (M17.6), persisted in
    /// `SEG_ADMISSION`: it created the channel, or a member witnessed its join. Needed
    /// whenever this node publishes its own bundle record, which is every time it
    /// refreshes its board presence. Distinct from `admission`, which is the ADR-007
    /// policy governing *other* authors' entries.
    own_admission: Admission,
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
    /// Members known before their records are admitted (V030-51), persisted in
    /// `SEG_KNOWN_MEMBERS`. See [`ChannelState::note_member`].
    known_members: BTreeSet<Digest32>,
    /// The drive key and the Session entries it opens (ADR-029 SC-2), persisted in `SEG_DRIVE`;
    /// the rows come from the plaintext cache.
    drive: DriveState,
    /// The room's admission notices and members' withdraws this node keeps (#520), persisted in
    /// `SEG_BOARD_KEPT`. See [`ChannelState::keep_notice`] and [`ChannelState::keep_withdraw`].
    board_kept: BoardKept,
    room_pause: vox_agentcomms::drive::PauseState,
    pause_resume_after: u64,
    /// The channel passphrase, retained **in memory only** for as long as the
    /// channel is open (M14.7c).
    ///
    /// ADR-005's CPace needs the passphrase live at each join handshake, so a node
    /// can only answer an inbound join while it holds one; the alternative is that
    /// nobody can ever join a channel unless its members are in a special mode.
    /// Retaining it is a deliberate, bounded decision (recorded in ADR-016): it is a
    /// **group** secret every member already holds, scoped to one channel and one
    /// epoch, and it sits beside the SEK it derives — an attacker who can read this
    /// memory already has the SEK and can decrypt its saved history, which are strictly
    /// more valuable. It is wiped by [`ChannelState::lock_now`] with the SEK, never
    /// written to disk, and never crosses the client boundary (no view, event or
    /// `Debug` output carries it).
    ///
    /// `None` once locked. An empty passphrase is a passphrase (V030-36, decider 2026-10-02:
    /// "technically optional"), so emptiness cannot mean "locked": a room made with none was
    /// read as locked and could never answer a join.
    passphrase: Option<Zeroizing<Vec<u8>>>,
    /// This node's own retention for the room, seconds; `0` is no node limit. Set by the
    /// actor from the node's config; the room's own lives in the checked governance display.
    node_retention: u64,
    node_step_retention: u64,
    /// When this node last pruned anything in the room (milliseconds), or opened it: what a closing
    /// checkpoint waits [`ChannelState::set_checkpoint_idle`] past (ADR-023 decision 3).
    last_pruned_at: u64,
    /// How long nothing new must have expired before an author closes a backlog smaller than
    /// [`CHECKPOINT_EVERY`] with a checkpoint anyway. [`CHECKPOINT_IDLE_SECS`] unless set.
    checkpoint_idle: u64,
    /// This node's latest posts that were stamped earlier than a post it already held (V210-168):
    /// each post's entry hash, and the authors of the held posts stamped more than
    /// [`STAMP_LEAD_LIMIT_MILLIS`] ahead of the clock, which `stamp_after_held` did not stamp it
    /// after. Memory only, the newest [`SKIPPED_KEPT`]: a claim asks about its own post at once.
    skipped: std::collections::VecDeque<(Digest32, Vec<Digest32>)>,
    poisoned: bool,
    save_error: Option<String>,
    /// Only one synchronous authored append may hold this bounded metadata. No value
    /// is an accepted head until the existing entry/sender transaction commits.
    local_pre_context: Option<crate::log::history::ControlContext>,
    local_append_budget: Option<crate::log::history::LocalAppendBudget>,
    local_content_header: Option<(crate::log::history::EntryV2, Vec<Digest32>)>,
    local_history: Option<local_history::Prepared>,
    /// Exact publication completion/key-erasure edge for cleanup blocked behind this room.
    history_publication_changed: std::sync::Arc<tokio::sync::Notify>,
    /// Whether this node holds its own feed in the room as the room does (V210-164). A room
    /// joined starts without: this identity may have been in it before — it left, or its
    /// profile is new — and its earlier entries are with the other members. Writing before they
    /// arrive would sign a second entry at a place it already signed, and every member would
    /// freeze it for that. So nothing is written until a sync with another member has ended
    /// cleanly. A room created or reopened here holds its own feed already.
    settled: bool,
    /// The room's **generation** (ADR-025 D1): bumped by every entry persisted, from any source.
    /// In memory; a restart resets it together with every sync port. Shared with the actor, which
    /// reads it without the room's lock; it only changes under the lock.
    gen: Arc<std::sync::atomic::AtomicU64>,
    /// Members that left and that this node let in again by answering their join (V030-08):
    /// members here until their signed return reaches it, which it then carries to the others.
    /// Each with the position in its feed of the departure the join undid: only that one. A
    /// departure it writes later, after it joined again, is a leave like any other; a member
    /// let in again kept its readmission for good, so a second leave was never applied (#564).
    /// In memory: a join is answered again after a restart.
    readmitted: BTreeMap<Digest32, u64>,
}

impl std::fmt::Debug for ChannelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelState")
            .field("channel_id", &crate::hash::Hex(&self.channel_id))
            .field("name", &self.name())
            .field("epoch", &self.epoch)
            .field("entries", &self.dag.len())
            .field("authors", &self.authors.len())
            .field("governance_ready", &self.governance_ready)
            .field("receiver_chains", &self.receivers.len())
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

fn manifest_bytes(genesis: &Genesis, name_hint: &str, created_ms: u64, epoch: u64) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(5)
        .uint(MANIFEST_VERSION)
        .bytes(&genesis.to_wire())
        .text(name_hint)
        .uint(created_ms)
        .uint(epoch);
    e.finish()
}

fn parse_manifest(bytes: &[u8]) -> Result<(Genesis, String, u64, u64)> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 5 {
        return Err(Error::MalformedAtRest("room manifest arity"));
    }
    let version = d.uint()?;
    if !(1..=MANIFEST_VERSION).contains(&version) {
        return Err(Error::MalformedAtRest("room manifest version"));
    }
    let genesis = Genesis::from_wire(d.bytes()?)?;
    let name = d.text()?;
    if name.len() > MAX_LOCAL_NAME_LEN {
        return Err(Error::SizeLimitExceeded("room local name"));
    }
    // Version 1's name was this member's own, which ADR-028 R-1 removed: never shown.
    let name = if version == 1 {
        String::new()
    } else {
        name.to_owned()
    };
    let created = d.uint()?;
    let created_ms = if version < MANIFEST_VERSION {
        created.saturating_mul(1_000)
    } else {
        created
    };
    let epoch = d.uint()?;
    d.finish()?;
    Ok((genesis, name, created_ms, epoch))
}

/// The admitted-authors segment: `[version, [[fingerprint, composite_pubkey], …]]`
/// in fingerprint order (a `BTreeMap`, so the bytes are canonical).
/// The offered-services segment: `[version, [[tag, addr_text, kind], …]]` in tag order (a
/// `BTreeMap`, so the bytes are canonical). Addresses are the standard `ip:port`
/// text, which round-trips exactly.
/// A service shared in a room (V030-25), as the log says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// The member sharing it: the `<node>` of its address.
    pub host: Digest32,
    /// Its name, as its sharer gave it: the `<service>` of its address.
    pub name: String,
    /// Whether it carries datagrams (ADR-022).
    pub udp: bool,
    /// What it is, as its sharer's node detected it (ADR-028 S-2).
    pub kind: ServiceKind,
}

/// A service's name from its tag: a UDP service's tag is `udp/<name>` (ADR-022 decision 6), and
/// the two transports share one namespace, as the address does.
#[must_use]
pub fn service_name(service_tag: &str) -> &str {
    service_tag.strip_prefix("udp/").unwrap_or(service_tag)
}

fn services_bytes(services: &BTreeMap<String, (SocketAddr, ServiceKind)>) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(2).uint(SERVICES_VERSION).array(services.len());
    for (tag, (addr, kind)) in services {
        e.array(3)
            .text(tag)
            .text(&addr.to_string())
            .text(kind.as_str());
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
    if n > AUTHORS_HARD_LIMIT {
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
    if n > AUTHORS_HARD_LIMIT {
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
    if n > AUTHORS_HARD_LIMIT {
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

type Services = (BTreeMap<String, SocketAddr>, BTreeMap<String, ServiceKind>);

fn parse_services(bytes: &[u8]) -> Result<Services> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 2 {
        return Err(Error::MalformedAtRest("room services arity"));
    }
    if d.uint()? != SERVICES_VERSION {
        return Err(Error::MalformedAtRest("room services version"));
    }
    let n = d.array()?;
    if n > MAX_SERVICES {
        return Err(Error::SizeLimitExceeded("room services"));
    }
    let mut out = BTreeMap::new();
    let mut kinds = BTreeMap::new();
    for _ in 0..n {
        if d.array()? != 3 {
            return Err(Error::MalformedAtRest("room service tuple arity"));
        }
        let tag = d.text()?.to_owned();
        let addr: SocketAddr = d
            .text()?
            .parse()
            .map_err(|_| Error::MalformedAtRest("room service address"))?;
        let kind =
            ServiceKind::from_word(d.text()?).ok_or(Error::MalformedAtRest("room service kind"))?;
        if tag.is_empty() || tag.len() > crate::tunnel::session::MAX_SERVICE_TAG_LEN {
            return Err(Error::MalformedAtRest("room service tag length"));
        }
        kinds.insert(tag.clone(), kind);
        out.insert(tag, addr);
    }
    d.finish()?;
    Ok((out, kinds))
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
        return Err(Error::MalformedAtRest("room authors arity"));
    }
    if d.uint()? != AUTHORS_VERSION {
        return Err(Error::MalformedAtRest("room authors version"));
    }
    let n = d.array()?;
    if n > AUTHORS_HARD_LIMIT {
        return Err(Error::SizeLimitExceeded("room authors"));
    }
    let mut out = BTreeMap::new();
    for _ in 0..n {
        if d.array()? != 2 {
            return Err(Error::MalformedAtRest("room author tuple arity"));
        }
        let fp: Digest32 = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("room author fingerprint"))?;
        let key_bytes: [u8; crate::hash::COMPOSITE_PUB_LEN] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("room author key length"))?;
        let key = CompositePublicKey::from_bytes(&key_bytes)?;
        // The stored fingerprint must be the key's own: a swapped pair would admit
        // an identity under another's name.
        if key.fingerprint() != fp {
            return Err(Error::MalformedAtRest("room author key/fingerprint"));
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
    receivers_bytes_with(receivers, None)
}

/// Serialize a candidate without publishing it in memory before the receiver/backfill commit.
fn receivers_bytes_with(
    receivers: &BTreeMap<(Digest32, u64), ReceiverChain>,
    replacement: Option<(&(Digest32, u64), &ReceiverChain)>,
) -> Zeroizing<Vec<u8>> {
    let count = receivers.len()
        + usize::from(replacement.is_some_and(|(slot, _)| !receivers.contains_key(slot)));
    let mut e = Encoder::for_secrets();
    e.array(2).uint(RECEIVERS_VERSION).array(count);
    let mut pending = replacement;
    for (slot, chain) in receivers {
        if let Some((new_slot, new_chain)) = pending.filter(|(new_slot, _)| *new_slot <= slot) {
            e.bytes(&new_chain.to_state());
            pending = None;
            if new_slot == slot {
                continue;
            }
        }
        e.bytes(&chain.to_state());
    }
    if let Some((_, chain)) = pending {
        e.bytes(&chain.to_state());
    }
    Zeroizing::new(e.finish())
}

fn parse_receivers(bytes: &[u8]) -> Result<BTreeMap<(Digest32, u64), ReceiverChain>> {
    let mut d = Decoder::new(bytes);
    if d.array()? != 2 {
        return Err(Error::MalformedAtRest("room receivers arity"));
    }
    if d.uint()? != RECEIVERS_VERSION {
        return Err(Error::MalformedAtRest("room receivers version"));
    }
    let n = d.array()?;
    if n > MAX_RECEIVER_CHAINS {
        return Err(Error::SizeLimitExceeded("room receiver chains"));
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
    // A key-package (ADR-023 decision 4) is framed like governance and carried like content:
    // any member may post one and it governs nothing. So the DAG sees content, and the channel
    // recognises it by its tag before trying to render it.
    if crate::node::keypackage::KeyPackage::is_key_package(payload) {
        return Ok(EntryKind::Content);
    }
    if let Ok(frame) = crate::wire::parse_frame(payload) {
        if frame.tag == crate::wire::StructTag::Checkpoint {
            return Ok(EntryKind::Checkpoint);
        }
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

/// A read record this node opened (ADR-028 §6): what its cache row holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRow {
    /// The record's own ADR-008 entry hash.
    pub entry_hash: Digest32,
    /// Who read: the record's author.
    pub reader: Digest32,
    /// The author's recorded send time, milliseconds since the Unix epoch.
    pub created_millis: u64,
    /// The entries it names as read.
    pub read: Vec<Digest32>,
}

/// A read record's cache row: a message's fields with the record's kind and its entries in place
/// of the text, `[CACHE_VERSION, entry hash, reader, created_millis, KIND_READ, [hash, …]]`. Six
/// fields where a message's row has five, so a row says which it is.
fn read_cache_bytes(r: &ReadRow) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(6)
        .uint(CACHE_VERSION)
        .bytes(&r.entry_hash)
        .bytes(&r.reader)
        .uint(r.created_millis)
        .uint(crate::node::content::KIND_READ)
        .array(r.read.len());
    for h in &r.read {
        e.bytes(h);
    }
    e.finish()
}

/// A Session entry's cache row: `[CACHE_VERSION, entry hash, author, created_millis,
/// KIND_SESSION, session id, body]`. Seven fields, so a row says which it is.
fn session_cache_bytes(r: &SessionRow) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(7)
        .uint(CACHE_VERSION)
        .bytes(&r.entry_hash)
        .bytes(&r.author)
        .uint(r.created_millis)
        .uint(crate::node::content::KIND_SESSION)
        .text(&r.session_id)
        .text(&r.body);
    e.finish()
}

/// One plaintext-cache row: a message, a read record or a Session entry.
enum CacheRow {
    Text(Rendered),
    Read(ReadRow),
    Session(SessionRow),
}

fn parse_cache(bytes: &[u8]) -> Result<CacheRow> {
    let mut d = Decoder::new(bytes);
    let arity = d.array()?;
    if !(5..=7).contains(&arity) {
        return Err(Error::MalformedAtRest("plaintext cache arity"));
    }
    if d.uint()? != CACHE_VERSION {
        return Err(Error::MalformedAtRest("plaintext cache version"));
    }
    let entry_hash: Digest32 = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedAtRest("plaintext cache entry hash"))?;
    let author: Digest32 = d
        .bytes()?
        .try_into()
        .map_err(|_| Error::MalformedAtRest("plaintext cache author"))?;
    let created_millis = d.uint()?;
    if arity == 7 {
        if d.uint()? != crate::node::content::KIND_SESSION {
            return Err(Error::MalformedAtRest("plaintext cache kind"));
        }
        let session_id = d.text()?.to_owned();
        let body = d.text()?.to_owned();
        d.finish()?;
        return Ok(CacheRow::Session(SessionRow {
            entry_hash,
            author,
            created_millis,
            session_id,
            body,
        }));
    }
    if arity == 6 {
        if d.uint()? != crate::node::content::KIND_READ {
            return Err(Error::MalformedAtRest("plaintext cache kind"));
        }
        let n = d.array()?;
        if n > crate::node::content::MAX_READ_HASHES {
            return Err(Error::MalformedAtRest("plaintext cache read record"));
        }
        let mut read = Vec::with_capacity(n);
        for _ in 0..n {
            read.push(
                d.bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedAtRest("plaintext cache read entry"))?,
            );
        }
        d.finish()?;
        return Ok(CacheRow::Read(ReadRow {
            entry_hash,
            reader: author,
            created_millis,
            read,
        }));
    }
    let text = d.text()?.to_owned();
    d.finish()?;
    Ok(CacheRow::Text(Rendered {
        entry_hash,
        author,
        created_millis,
        text,
        arrival: 0,
        shown_at_ms: 0,
        late: false,
        owed: false,
    }))
}

/// The wall-clock stamp stored with a rendering for this open incarnation.
fn shown_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl ChannelState {
    /// Create a new channel on this device: genesis at the day-one suite floor
    /// with the default policy (forward-only history, attributable content, no
    /// TTL), a fresh SEK double-locked under (identity factor, `channel_passphrase`)
    /// with the production Argon2id profile, and this identity's first sender
    /// chain. Persists the wrap, manifest and chain atomically.
    pub fn create(
        profile: &Profile,
        name: &str,
        channel_passphrase: &[u8],
        now: crate::time::Ms,
    ) -> Result<Self> {
        Self::create_with_profile(
            profile,
            name,
            channel_passphrase,
            now,
            Argon2Profile::default(),
        )
    }

    /// [`ChannelState::create`] with an explicit Argon2id profile (tests).
    pub fn create_with_profile(
        profile: &Profile,
        name: &str,
        channel_passphrase: &[u8],
        now: crate::time::Ms,
        argon2: Argon2Profile,
    ) -> Result<Self> {
        let (genesis, sek) = Self::create_genesis(profile, name, now)?;
        let signer = profile.signer()?;
        let factor = SignatureIdentityFactor::new(signer);
        let wrap = sek.seal(&factor, &genesis.channel_id(), channel_passphrase, argon2)?;
        Self::create_from_sealed(
            profile,
            name,
            channel_passphrase,
            genesis,
            sek,
            &wrap,
            now,
            &BootstrapSet::new(),
        )
    }

    /// The fast first step of creating a room: its genesis and a fresh room key.
    ///
    /// Split from [`ChannelState::create_with_profile`] so the slow middle step — sealing the room
    /// key under the passphrase with production Argon2id, seconds of CPU — can run off the node's
    /// actor, which answers nothing while it works. [`ChannelState::create_from_sealed`] is the
    /// last step.
    ///
    /// # Errors
    /// A name that is not a room name ([`crate::governance::name::room_name`]), no unlocked
    /// signer, or a genesis or key that cannot be made.
    pub fn create_genesis(
        profile: &Profile,
        name: &str,
        now: crate::time::Ms,
    ) -> Result<(Genesis, Sek)> {
        if crate::governance::name::room_name(name).as_deref() != Ok(name) {
            return Err(Error::MalformedGovernance("room name is not a DNS label"));
        }
        let signer = profile.signer()?;
        let policy = ChannelPolicy {
            history_mode: HistoryMode::ForwardOnly,
            ttl_ms: 0,
            min_suite: SuiteFloor::DAY_ONE.id(),
        };
        let genesis = Genesis::create(signer, now.get(), policy)?;
        Ok((genesis, Sek::generate()?))
    }

    /// The last step of creating a room, from a genesis and a room key already sealed under the
    /// passphrase. See [`ChannelState::create_genesis`].
    ///
    /// # Errors
    /// No unlocked signer, a segment that cannot be sealed, or a store write that fails.
    #[allow(clippy::too_many_arguments)]
    pub fn create_from_sealed(
        profile: &Profile,
        name: &str,
        channel_passphrase: &[u8],
        genesis: Genesis,
        sek: Sek,
        wrap: &crate::atrest::SekWrap,
        now: crate::time::Ms,
        anchors: &BootstrapSet,
    ) -> Result<Self> {
        let now_ms = now.get();
        let signer = profile.signer()?;
        let channel_id = genesis.channel_id();
        let epoch = 0u64;
        let me = signer.fingerprint();
        let sender = SenderChain::new(&channel_id, epoch, &me, 0, now_ms)?;
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
            now_ms,
            mint_seq,
        )?;

        let manifest = manifest_bytes(&genesis, name, now_ms, epoch);
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
        let entries = entry_store::EntryIndex::default();
        let mut index = entries.write(&mut batch, &sek, &channel_id)?;
        index.finish_rebuild()?;
        index.initialize_restart(epoch)?;
        if genesis.body.authenticated_history() {
            index.initialize_sparse_history()?;
            initialize_sparse_identity(&mut index, signer, channel_id, epoch)?;
        }
        index.empty_rendered()?;
        index.seal()?;
        session_projection::private_index::initialize(&mut batch, &sek, &channel_id)?;
        batch.commit()?;

        let mut admission = AdmissionPolicy::new();
        admission.admit(channel_id, epoch, me);
        let origin_ms = genesis.body.created_ms;
        governance::prepare(profile.store(), &sek, &channel_id)?;
        let governance_display = governance::Display::genesis(&genesis);
        let mut room = Self {
            channel_id,
            genesis,
            name_hint: name.to_owned(),
            passphrase: Some(Zeroizing::new(channel_passphrase.to_vec())),
            created: now_ms,
            epoch,
            sek,
            authors,
            admission,
            dag: Dag::for_room(origin_ms),
            forks_kept: 0,
            governance_display,
            governance_ready: false,
            consent_facts: std::sync::Mutex::new(ConsentFactsState::Ready(std::sync::Arc::new(
                governance::ConsentFacts::empty(),
            ))),
            own_behind: false,
            own_recovery: own_history::Recovery::UnknownBehind,
            presence: BTreeMap::new(),
            sparse_applied_tips: BTreeMap::new(),
            sparse_contiguous_pending: BTreeSet::new(),
            sparse_contiguous_after: None,
            sender,
            next_log_id: 1,
            read_mark_scan: None,
            read_mark_complete: None,
            set_aside: SetAside::default(),
            chains_advanced: false,
            backfill_refreshing: false,
            backfill_after: None,
            legacy_sessions: legacy_session::LegacySessions::default(),
            legacy_announced: None,
            private_sessions: private_session::PrivateSessions::default(),
            held: BTreeMap::new(),
            owed_asked_to: None,
            now_hint: now_ms,
            projection_state: history::State::default(),
            display_tail: None,
            display_order_revision: 0,
            display_shown_at: 0,
            display_rewrite: 0,
            entries,
            legacy_preparation: entry_store::Preparation::Ready,
            legacy_cache_trusted: None,
            key_packages: key_package_queue::Queue::new(1),
            receivers: BTreeMap::new(),
            services: BTreeMap::new(),
            kinds: BTreeMap::new(),
            transient: BTreeSet::new(),
            // This node made the channel, so the genesis names it and nothing else needs
            // to (M17.6).
            own_admission: Admission::Creator,
            origins,
            delivered: BTreeMap::new(),
            node_retention: 0,
            node_step_retention: 0,
            last_pruned_at: now_ms,
            checkpoint_idle: CHECKPOINT_IDLE_SECS,
            history: BTreeMap::new(),
            entitled: BTreeMap::new(),
            trust_marks: BTreeMap::new(),
            known_members: BTreeSet::new(),
            drive: DriveState::default(),
            board_kept: BoardKept::default(),
            room_pause: vox_agentcomms::drive::PauseState::default(),
            pause_resume_after: 0,
            skipped: std::collections::VecDeque::new(),
            poisoned: false,
            save_error: None,
            local_pre_context: None,
            local_append_budget: None,
            local_content_header: None,
            local_history: None,
            history_publication_changed: std::sync::Arc::new(tokio::sync::Notify::new()),
            settled: true,
            gen: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            readmitted: BTreeMap::new(),
        };
        // The room's name is stated on its log as its first entry after the genesis, so every
        // member that joins reads it there (ADR-028 R-1).
        let statement = crate::governance::name::RoomName::build(signer, &channel_id, epoch, name)?;
        room.append_governance(profile, &statement.to_wire(), now_ms)?;
        // Sign only the anchors its creator explicitly chose, including an empty set.
        // Machine configuration and join-link hints never supply room authority (AN-5/AN-9).
        room.set_anchors(profile, anchors, now)?;
        Ok(room)
    }

    /// Open a channel from its sealed accepted-prefix state and on-disk indexes. A store
    /// without that state performs one verified bootstrap; normal restarts do not replay
    /// message bodies or rewrite history. Restore the sender chain before any append.
    pub fn open(
        profile: &Profile,
        channel_id: &Digest32,
        channel_passphrase: &[u8],
        now: crate::time::Ms,
    ) -> Result<Self> {
        let signer = profile.signer()?;
        let store = profile.store();
        let wrap = store
            .get_sek_wrap(channel_id)?
            .ok_or(Error::Profile("no such room on this node"))?;
        let factor = SignatureIdentityFactor::new(signer);
        let sek = wrap.unwrap_sek(&factor, channel_id, channel_passphrase)?;
        let me = signer.fingerprint();
        let paused = crate::node::history_demand::retained_legacy_owner(profile)?
            .filter(|(room, _, _, _)| room == channel_id)
            .map(
                |(_, request, instance, author)| legacy_provisional::LegacyProvisionalOwner {
                    request,
                    instance,
                    author,
                },
            );
        Self::open_with_sek_owned(store, channel_id, sek, channel_passphrase, me, now, paused)
    }

    /// The post-unlock half of [`Self::open`]. The actor verifies paused legacy ownership before
    /// moving keys to its blocking opener, so restart cannot mistake retained work for an orphan.
    pub(crate) fn open_with_sek_owned(
        store: &Store,
        channel_id: &Digest32,
        sek: Sek,
        channel_passphrase: &[u8],
        me: Digest32,
        now: crate::time::Ms,
        paused_legacy_owner: Option<legacy_provisional::LegacyProvisionalOwner>,
    ) -> Result<Self> {
        let now_ms = now.get();
        let manifest_seg = store
            .get_segment(channel_id, SegmentKind::KeyMaterial, SEG_MANIFEST)?
            .ok_or(Error::MalformedAtRest("room manifest missing"))?;
        let manifest = open_segment(&sek, SegmentKind::KeyMaterial, SEG_MANIFEST, &manifest_seg)?;
        let (genesis, name_hint, created, epoch) = parse_manifest(&manifest)?;
        genesis.verify()?;
        if genesis.channel_id() != *channel_id {
            return Err(Error::MalformedAtRest("room manifest genesis mismatch"));
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
        //
        // **What a hostile peer got onto disk before V210-74 does not keep the room shut.** An entry
        // its author signed that cannot be classified, or whose governance body does not bind to
        // it, is set aside and reported, and still taken as a link in its author's feed so the
        // author's later entries link. An entry held without its predecessor is retried once the
        // rest is in, and set aside only if it still does not link: sync then fetches the missing
        // ones again. Anything else that fails acceptance is a tampered store, and the room does
        // not open. (A body-less entry is not set aside here, as it is in v0.2.10: in v0.3.0 it is
        // a pruned skeleton, kept on purpose — ADR-023 decision 2.)
        let mut dag = Dag::for_room(genesis.body.created_ms);
        let entries = entry_store::EntryIndex::default();
        // Recover unpublished work before reading authoritative LogDb; rebuild only derived
        // locators when absent. No unsigned suffix is replayed after a crash.
        let legacy_preparation =
            entries.prepare_owned(store, &sek, channel_id, genesis.body.created_ms, |owner| {
                Ok(Some(owner) == paused_legacy_owner)
            })?;
        let mut entry_read = entries.read(store, &sek, channel_id)?;

        let mut next_log_id = 1u64;
        let mut presence = BTreeMap::new();
        let mut retained_step_body = None;
        // Key-packages for this identity found on reload are offered again: installing one
        // twice is harmless (`accept_skdm` keeps the live chain), and one that arrived just
        // before a crash would otherwise never be installed.
        let mut key_packages = key_package_queue::Queue::new(1);
        let mut set_aside = SetAside::default();
        let restart = entry_read.restart_state().cloned();
        if let Some(state) = &restart {
            if state.room != *channel_id || state.epoch != epoch {
                return Err(Error::MalformedAtRest("restart room or epoch differs"));
            }
            if state.sparse != entry_read.sparse_enabled() {
                return Err(Error::MalformedAtRest(
                    "restart history format differs from published roots",
                ));
            }
            // Each compact head was sealed atomically with its accepted prefix. Verify its
            // bounded source binding, never infer acceptance from an arbitrary locator maximum.
            for (author, head) in &state.feeds {
                let key = authors
                    .get(author)
                    .ok_or(Error::MalformedAtRest("restart author missing"))?;
                let entry = entry_read
                    .get(author, head.seq)?
                    .ok_or(Error::MalformedAtRest("restart head missing"))?;
                if entry.skeleton.channel_id != *channel_id
                    || entry.skeleton.epoch != epoch
                    || entry.entry_hash() != head.hash
                    || entry.skeleton.end_of_feed != head.ended
                {
                    return Err(Error::MalformedAtRest("restart head source differs"));
                }
                entry.verify(key)?;
                let first = entry_read
                    .get(author, 1)?
                    .ok_or(Error::MalformedAtRest("restart first entry missing"))?;
                if first.skeleton.claimed_ms != head.first_claimed_ms {
                    return Err(Error::MalformedAtRest("restart first clock differs"));
                }
                if let Some((seq, hash)) = head.checkpoint {
                    if entry_read.get(author, seq)?.map(|entry| entry.entry_hash()) != Some(hash) {
                        return Err(Error::MalformedAtRest("restart checkpoint source differs"));
                    }
                }
            }
            dag = Dag::restore_published(&state.feeds)?;
            presence = state.presence.clone();
            retained_step_body = state.retained_step_body;
            set_aside = state.set_aside.clone();
            let snapshot = store.snapshot()?;
            next_log_id = snapshot
                .last_segment_id(channel_id, SegmentKind::LogDb)?
                .unwrap_or(0)
                .max(
                    snapshot
                        .last_segment_id(channel_id, SegmentKind::PlaintextCache)?
                        .unwrap_or(0),
                )
                .checked_add(1)
                .ok_or(Error::MalformedAtRest("log allocator exhausted"))?;
        } else {
            let mut unlinked = 0usize;
            store.visit_segments(channel_id, SegmentKind::LogDb, |id, seg| {
                next_log_id = id.saturating_add(1);
                let wire = open_segment(&sek, SegmentKind::LogDb, id, &seg)?;
                let entry = Entry::from_wire(&wire)?;
                let key = authors
                    .get(&entry.skeleton.author_id)
                    .ok_or(Error::MalformedAtRest("stored entry from unknown author"))?
                    .clone();
                let at = format!(
                    "{}#{}",
                    crate::node::link::b32_encode(&entry.skeleton.author_id)
                        .chars()
                        .take(12)
                        .collect::<String>(),
                    entry.skeleton.seq
                );
                // **A pruned entry is a kept entry** (ADR-023 decision 2). Retention drops a content
                // body and keeps the signed skeleton, which still verifies and still links the feed —
                // refusing it here made a room with one expired message impossible to open.
                // Governance is never pruned, so a body-less entry is content.
                let kind = match entry.payload.as_deref() {
                    None => EntryKind::Content,
                    Some(payload) => match classify_payload(payload) {
                        Ok(EntryKind::Governance) => {
                            match GovEntry::from_verified_log_entry(
                                &entry,
                                &key,
                                channel_id,
                                Default::default(),
                            ) {
                                Ok(gov) => {
                                    if gov.body.verify(&key).is_ok() {
                                        governance::remember_presence(&mut presence, &gov);
                                    }
                                    EntryKind::Governance
                                }
                                Err(e) => {
                                    set_aside.push(format!("{at}: {e}"));
                                    EntryKind::Content
                                }
                            }
                        }
                        Ok(kind) => kind,
                        Err(e) => {
                            set_aside.push(format!("{at}: {e}"));
                            EntryKind::Content
                        }
                    },
                };
                if entry
                    .payload
                    .as_deref()
                    .is_some_and(crate::governance::step_policy::is_step_policy)
                {
                    match GovEntry::from_verified_log_entry(
                        &entry,
                        &key,
                        channel_id,
                        Default::default(),
                    ) {
                        Ok(_) => {}
                        Err(e) => set_aside.push(format!("{at}: {e}")),
                    }
                }
                let saved_age = match store.get_segment(channel_id, SegmentKind::Index, id)? {
                    Some(seg) => {
                        parse_first_seen(&open_segment(&sek, SegmentKind::Index, id, &seg)?)?
                    }
                    None => (now_ms, false),
                };
                let steps = saved_age.1
                    || entry
                        .payload
                        .as_deref()
                        .is_some_and(|p| is_step_body(channel_id, p));
                if steps && entry.payload.is_some() {
                    retained_step_body.get_or_insert_with(|| entry.entry_hash());
                }
                let package = key_package_for(&entry, &me);
                let package_author = entry.skeleton.author_id;
                let package_seq = entry.skeleton.seq;
                match dag.accept(&mut entry_read, entry, kind, &key, &admission) {
                    Ok(_) => {
                        if package && package_seq <= dag.verified_head(&package_author) {
                            key_packages.note(package_author, id)?;
                        }
                    }
                    Err(crate::log::dag::Rejected::Feed(_)) => unlinked += 1,
                    Err(crate::log::dag::Rejected::Local(error)) => return Err(error),
                    Err(_) => return Err(Error::MalformedAtRest("stored entry failed acceptance")),
                }
                Ok(())
            })?;
            // Retry using the encrypted rows themselves, not a history-sized Vec<Entry>.
            // A pass that links nothing more leaves the same truthful set-aside diagnostics.
            while unlinked != 0 {
                let before = unlinked;
                unlinked = 0;
                store.visit_segments(channel_id, SegmentKind::LogDb, |id, seg| {
                    let wire = open_segment(&sek, SegmentKind::LogDb, id, &seg)?;
                    let entry = Entry::from_wire(&wire)?;
                    if dag
                        .feed(&entry.skeleton.author_id)
                        .is_some_and(|f| entry.skeleton.seq <= f.max_seq())
                    {
                        return Ok(());
                    }
                    let key = authors
                        .get(&entry.skeleton.author_id)
                        .ok_or(Error::MalformedAtRest("stored entry from unknown author"))?;
                    let kind = match entry
                        .payload
                        .as_deref()
                        .and_then(|p| classify_payload(p).ok())
                    {
                        Some(EntryKind::Governance)
                            if GovEntry::from_verified_log_entry(
                                &entry,
                                key,
                                channel_id,
                                Default::default(),
                            )
                            .is_err() =>
                        {
                            EntryKind::Content
                        }
                        Some(kind) => kind,
                        None => EntryKind::Content,
                    };
                    let package = key_package_for(&entry, &me);
                    let package_author = entry.skeleton.author_id;
                    let package_seq = entry.skeleton.seq;
                    match dag.accept(&mut entry_read, entry, kind, key, &admission) {
                        Ok(_) => {
                            if package && package_seq <= dag.verified_head(&package_author) {
                                key_packages.note(package_author, id)?;
                            }
                        }
                        Err(crate::log::dag::Rejected::Feed(_)) => unlinked += 1,
                        Err(crate::log::dag::Rejected::Local(error)) => return Err(error),
                        Err(_) => {
                            return Err(Error::MalformedAtRest("stored entry failed acceptance"))
                        }
                    }
                    Ok(())
                })?;
                if unlinked == before {
                    break;
                }
            }
            if unlinked != 0 {
                store.visit_segments(channel_id, SegmentKind::LogDb, |id, seg| {
                    let entry =
                        Entry::from_wire(&open_segment(&sek, SegmentKind::LogDb, id, &seg)?)?;
                    if dag
                        .feed(&entry.skeleton.author_id)
                        .is_none_or(|f| entry.skeleton.seq > f.max_seq())
                    {
                        let at = crate::node::link::b32_encode(&entry.skeleton.author_id)
                            .chars()
                            .take(12)
                            .collect::<String>();
                        set_aside.push(format!(
                            "{at}#{}: an earlier entry of its author is missing",
                            entry.skeleton.seq
                        ));
                    }
                    Ok(())
                })?;
            }
            // Replay's EntryWrite never deletes disk rows. Any unsigned tail is corrupt durable
            // history and returns the same refusal, rather than making it an authentic prefix.
            dag.discard_unverified(&mut entry_read)?;
        }
        drop(entry_read);
        entries.prepare_facts(store, &sek, channel_id, &dag, genesis.body.created_ms)?;
        entries.prepare_retention(store, &sek, channel_id, now_ms, |entry| {
            let Some(payload) = entry.payload.as_deref() else {
                return Ok(false);
            };
            if retained_control(payload) {
                return Ok(false);
            }
            let kind = classify_payload(payload).unwrap_or(EntryKind::Content);
            if kind == EntryKind::Checkpoint {
                return Ok(false);
            }
            if kind == EntryKind::Governance {
                let key = authors
                    .get(&entry.skeleton.author_id)
                    .ok_or(Error::MalformedAtRest("retention author missing"))?;
                if GovEntry::from_verified_log_entry(entry, key, channel_id, Default::default())
                    .is_ok()
                {
                    return Ok(false);
                }
            }
            Ok(true)
        })?;
        let entry_read = entries.read(store, &sek, channel_id)?;
        dag.set_order_revision(
            entry_read.order_revision(),
            entry_read.order_previous(None)?.map(|(clock, _)| clock),
        );

        // Sparse membership follows completed semantic effects, not a contiguous archive
        // prefix. Read at most one persistent, effect-checked tip per admitted author;
        // reopening never enumerates retained entries or promotes an observed/source head.
        let mut sparse_applied_tips = BTreeMap::new();
        let mut sparse_contiguous_pending = BTreeSet::new();
        if entry_read.sparse_enabled() {
            for (author, key) in &authors {
                if let Some(tip) = entry_read.history_settled_tip(author)? {
                    tip.verify(key)?;
                    sparse_applied_tips.insert(*author, tip.skeleton.seq);
                    let held = entry_read
                        .restart_state()
                        .and_then(|state| state.feeds.get(author))
                        .map_or(0, |feed| feed.seq);
                    if tip.skeleton.seq > held {
                        sparse_contiguous_pending.insert(*author);
                    }
                }
            }
            // This node applied its own authored operation in the same Batch that advanced
            // the restart feed. It needs no later source/effect settlement to be current.
            if let Some(seq) = entry_read
                .restart_state()
                .and_then(|state| state.feeds.get(&me))
                .map(|feed| feed.seq)
            {
                sparse_applied_tips
                    .entry(me)
                    .and_modify(|tip| *tip = (*tip).max(seq))
                    .or_insert(seq);
            }
        }

        // How far each member's node holds this identity's feed (ADR-028 R-6).
        let held = match store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_HELD)? {
            Some(seg) => parse_held(&open_segment(
                &sek,
                SegmentKind::KeyMaterial,
                SEG_HELD,
                &seg,
            )?)?,
            None => BTreeMap::new(),
        };
        // Joined, and not yet synced since (V210-164).
        let settled = store
            .get_segment(channel_id, SegmentKind::KeyMaterial, SEG_UNSETTLED)?
            .is_none();
        // A profile seen to be behind its own history here stays so across reopen (ADR-037 R5).
        let own_recovery = store
            .snapshot()?
            .get_segment_bounded(
                channel_id,
                SegmentKind::KeyMaterial,
                SEG_OWN_BEHIND,
                crate::log::history::MAX_HEADER_BYTES + 64,
            )?
            .map(|segment| {
                own_history::Recovery::parse(&open_segment(
                    &sek,
                    SegmentKind::KeyMaterial,
                    SEG_OWN_BEHIND,
                    &segment,
                )?)
            })
            .transpose()?;
        let own_behind = own_recovery.is_some();
        let own_recovery = own_recovery.unwrap_or(own_history::Recovery::UnknownBehind);
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

        // Cache and log ids share one allocator. Resume past both without retaining rows;
        // prepare_rendered validates and indexes the sealed cache one row at a time below.
        if restart.is_none() {
            store.visit_segments(channel_id, SegmentKind::PlaintextCache, |id, segment| {
                next_log_id = next_log_id.max(id.saturating_add(1));
                let row = open_segment(&sek, SegmentKind::PlaintextCache, id, &segment)?;
                let _ = parse_cache(&row)?;
                Ok(())
            })?;
        }
        key_packages.published(next_log_id);
        let display_order_revision = dag.reorder_generation();

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
        // The services this node offers here (ADR-013 M16.1).
        let (services, kinds) =
            match store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_SERVICES)? {
                Some(seg) => {
                    let bytes = open_segment(&sek, SegmentKind::KeyMaterial, SEG_SERVICES, &seg)?;
                    parse_services(&bytes)?
                }
                None => (BTreeMap::new(), BTreeMap::new()),
            };
        // How this node came to be a member here (M17.6). A joined room holds the witness to its
        // join (`SEG_ADMISSION`, written with the room). **A room this node created holds none:
        // its admission is the genesis, which names it**, so it is read from there. Left unset,
        // a reopened creator's room published no member bundle and no address record again, to
        // any board, and lapsed off its anchor's (a_restarted_creator_stays_on_its_board_proof).
        // A joined room without its witness is malformed (#423).
        let own_admission =
            match store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_ADMISSION)? {
                Some(seg) => {
                    let bytes = open_segment(&sek, SegmentKind::KeyMaterial, SEG_ADMISSION, &seg)?;
                    Admission::from_body(&bytes)?
                }
                None if genesis.body.creator_pubkey.fingerprint() == me => Admission::Creator,
                None => return Err(Error::MalformedAtRest("joined room has no admission")),
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
        let known_members =
            match store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_KNOWN_MEMBERS)? {
                Some(seg) => {
                    let bytes =
                        open_segment(&sek, SegmentKind::KeyMaterial, SEG_KNOWN_MEMBERS, &seg)?;
                    parse_known_members(&bytes)?
                }
                None => BTreeSet::new(),
            };
        let drive = match store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_DRIVE)? {
            Some(seg) => {
                let bytes = open_segment(&sek, SegmentKind::KeyMaterial, SEG_DRIVE, &seg)?;
                DriveState::from_state(&bytes)?
            }
            None => DriveState::default(),
        };
        let (room_pause, pause_resume_after) =
            match store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_ROOM_PAUSE)? {
                Some(seg) => {
                    let bytes = open_segment(&sek, SegmentKind::KeyMaterial, SEG_ROOM_PAUSE, &seg)?;
                    let mut d = crate::cbor::Decoder::new(&bytes);
                    if d.array()? != 5 || d.uint()? != 1 {
                        return Err(Error::MalformedAtRest("room pause format"));
                    }
                    let state = vox_agentcomms::drive::PauseState {
                        paused: match d.uint()? {
                            0 => false,
                            1 => true,
                            _ => return Err(Error::MalformedAtRest("room pause value")),
                        },
                        by: d
                            .bytes()?
                            .try_into()
                            .map_err(|_| Error::MalformedAtRest("room pause driver"))?,
                        at_millis: d.uint()?,
                    };
                    let resume_after = d.uint()?;
                    d.finish()?;
                    (state, resume_after)
                }
                None => (vox_agentcomms::drive::PauseState::default(), 0),
            };
        let board_kept =
            match store.get_segment(channel_id, SegmentKind::KeyMaterial, SEG_BOARD_KEPT)? {
                Some(seg) => {
                    let bytes = open_segment(&sek, SegmentKind::KeyMaterial, SEG_BOARD_KEPT, &seg)?;
                    parse_board_kept(&bytes, channel_id)?
                }
                None => BoardKept::default(),
            };

        drop(entry_read);
        if restart.is_none() {
            let state = entry_store::RestartState {
                room: *channel_id,
                epoch,
                feeds: dag.published_feeds()?,
                presence: presence.clone(),
                projection: None,
                retained_step_body,
                set_aside: set_aside.clone(),
                sparse: false,
            };
            let mut batch = store.batch()?;
            let mut writer = entries.write(&mut batch, &sek, channel_id)?;
            writer.bootstrap_restart(state)?;
            writer.seal()?;
            batch.commit()?;
            entries.committed();
        }
        entries.prepare_packages(store, &sek, channel_id, &dag)?;
        key_packages.restore(
            store,
            &sek,
            channel_id,
            entries.read(store, &sek, channel_id)?.key_package_tip()?,
        )?;
        governance::prepare(store, &sek, channel_id)?;
        // No destructive retention uses a partially rebuilt authority projection.
        let governance_display = governance::Display::genesis(&genesis);
        let consent_facts = std::sync::Mutex::new(ConsentFactsState::Building(
            ConsentFactsBuild::new(&authors),
        ));
        let mut room = Self {
            channel_id: *channel_id,
            genesis,
            name_hint,
            passphrase: Some(Zeroizing::new(channel_passphrase.to_vec())),
            created,
            epoch,
            sek,
            authors,
            admission,
            dag,
            forks_kept,
            governance_display,
            governance_ready: false,
            consent_facts,
            own_behind,
            own_recovery,
            presence,
            sparse_applied_tips,
            sparse_contiguous_pending,
            sparse_contiguous_after: None,
            sender,
            next_log_id,
            read_mark_scan: None,
            read_mark_complete: None,
            set_aside,
            chains_advanced: false,
            backfill_refreshing: false,
            backfill_after: None,
            legacy_sessions: legacy_session::LegacySessions::default(),
            legacy_announced: None,
            private_sessions: private_session::PrivateSessions::default(),
            held,
            owed_asked_to: None,
            now_hint: now_ms,
            projection_state: match restart
                .as_ref()
                .and_then(|state| state.projection.as_deref())
            {
                Some(bytes) => history::State::from_bytes(bytes)?,
                None => history::State::default(),
            },
            display_tail: None,
            display_order_revision,
            display_shown_at: 0,
            display_rewrite: 0,
            entries,
            legacy_preparation,
            legacy_cache_trusted: None,
            key_packages,
            receivers,
            services,
            kinds,
            transient: BTreeSet::new(),
            own_admission,
            origins,
            delivered,
            node_retention: 0,
            node_step_retention: 0,
            last_pruned_at: now_ms,
            checkpoint_idle: CHECKPOINT_IDLE_SECS,
            history,
            entitled,
            trust_marks,
            known_members,
            drive,
            board_kept,
            room_pause,
            pause_resume_after,
            skipped: std::collections::VecDeque::new(),
            poisoned: false,
            save_error: None,
            local_pre_context: None,
            local_append_budget: None,
            local_content_header: None,
            local_history: None,
            history_publication_changed: std::sync::Arc::new(tokio::sync::Notify::new()),
            settled,
            gen: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            readmitted: BTreeMap::new(),
        };
        room.entries
            .prepare_rendered(store, &room.sek, &room.channel_id, |batch, hash, id| {
                Ok(room
                    .retention_get_in(Transaction::Batch(batch), hash)?
                    .and_then(|r| r.cache_id)
                    == Some(id))
            })?;
        room.display_tail = room
            .entries
            .render_view(store, &room.sek, &room.channel_id)?
            .step(None, true, None, true)?
            .map(|(key, _)| key);
        // Apply the new default while upgrading an existing room, before publishing any
        // cached Session rows or permitting a sync to send its old encrypted bodies.
        room.restore_legacy_sessions(store, now.0)?;
        // Signed authorization facts catch up in bounded maintenance. Session permissions
        // refuse while that catalog is incomplete, without replaying whole feeds at open.
        room.restore_private_sessions(store)?;
        if let Some(hash) = retained_step_body {
            room.private_sessions.legacy_pending.insert(hash);
        }
        room.private_sessions.upgrading = !room.private_sessions.legacy_pending.is_empty();
        // The actor establishes current governance and this node's retention settings
        // before sweeping or refreshing. The constructor's placeholder policies must
        // never reset an already completed durable projection on an ordinary restart.
        Ok(room)
    }

    /// What must hold before a joined room is made: an unlocked signer, a genesis that verifies
    /// and names this room, and no copy of the room already in the profile.
    ///
    /// # Errors
    /// The first of those that does not hold.
    pub fn join_checks(profile: &Profile, genesis: &Genesis, channel_id: &Digest32) -> Result<()> {
        profile.signer()?;
        genesis.verify()?;
        if genesis.channel_id() != *channel_id {
            return Err(Error::MalformedGovernance(
                "genesis hash is not the room id joined with",
            ));
        }
        if profile.store().get_sek_wrap(channel_id)?.is_some() {
            return Err(Error::Profile("this room is already on this node"));
        }
        Ok(())
    }

    /// Make a joined room from a room key already sealed under the passphrase — the slow step,
    /// which the node runs off its actor. The checks of [`ChannelState::join_checks`] are repeated
    /// here, because time passed while the seal ran.
    ///
    /// `own_admission` is how this node was let in (the witness the responder signed, M17.6). It
    /// is written **in the same batch** as the room: a room held without it can publish nothing
    /// and falls off every board, and while it was a second write that could fail after the
    /// first, a failed join left exactly that room in the profile — which then refused every
    /// retry of the join as "already in the profile" (V210-80).
    ///
    /// # Errors
    /// A failed check, a segment that cannot be sealed, or a store write that fails. On an error
    /// nothing of the room is written.
    #[allow(clippy::too_many_arguments)]
    pub fn join_channel_from_sealed(
        profile: &Profile,
        genesis: &Genesis,
        channel_id: &Digest32,
        name_hint: Option<&str>,
        channel_passphrase: &[u8],
        now: crate::time::Ms,
        sealed: (Sek, crate::atrest::SekWrap),
        own_admission: Admission,
    ) -> Result<Self> {
        let now_ms = now.get();
        Self::join_checks(profile, genesis, channel_id)?;
        let name_hint = name_hint.unwrap_or_default();
        let (sek, wrap) = sealed;
        let signer = profile.signer()?;
        let me = signer.fingerprint();
        let epoch = 0u64;
        let sender = SenderChain::new(channel_id, epoch, &me, 0, now_ms)?;
        let mut origins = OriginKeyStore::new();
        let mint_seq = crate::node::consent_order::stamp_mint(profile.store(), signer, 0)?;
        retain_generation(
            &mut origins,
            channel_id,
            epoch,
            &me,
            &sender,
            now_ms,
            mint_seq,
        )?;

        let creator = genesis.body.creator_pubkey.fingerprint();
        let mut authors = BTreeMap::new();
        authors.insert(creator, genesis.body.creator_pubkey.clone());
        authors.insert(me, signer.public_key());

        let manifest = manifest_bytes(genesis, name_hint, now_ms, epoch);
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
        let admission_seg = seal_segment(
            &sek,
            SegmentKind::KeyMaterial,
            SEG_ADMISSION,
            &own_admission.body_bytes(),
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
        batch.put_segment(
            channel_id,
            SegmentKind::KeyMaterial,
            SEG_ADMISSION,
            &admission_seg,
        )?;
        batch.put_segment(
            channel_id,
            SegmentKind::KeyMaterial,
            SEG_UNSETTLED,
            &seal_segment(&sek, SegmentKind::KeyMaterial, SEG_UNSETTLED, &[1])?,
        )?;
        // **Remembered as open in the same batch** (#412). Written after it, a crash between the
        // two left a room in the profile that the restarted node did not reopen and every re-join
        // refused as already held: the member could not get back in. Now a crash leaves either no
        // room, which a re-join makes, or a room that reopens.
        let mut open = crate::node::open_rooms::OpenRooms::load(profile.store(), signer)?;
        open.remember(*channel_id, sek.key_bytes()?, channel_passphrase)?;
        batch.put_meta(
            crate::node::open_rooms::OPEN_ROOMS_META_KEY,
            &open.sealed(signer)?,
        )?;
        let entries = entry_store::EntryIndex::default();
        let mut index = entries.write(&mut batch, &sek, channel_id)?;
        index.finish_rebuild()?;
        index.initialize_restart(epoch)?;
        if genesis.body.authenticated_history() {
            index.initialize_sparse_history()?;
            initialize_sparse_identity(&mut index, signer, *channel_id, epoch)?;
        }
        index.empty_rendered()?;
        index.seal()?;
        session_projection::private_index::initialize(&mut batch, &sek, channel_id)?;
        batch.commit()?;

        let mut admission = AdmissionPolicy::new();
        for author in authors.keys() {
            admission.admit(*channel_id, epoch, *author);
        }
        governance::prepare(profile.store(), &sek, channel_id)?;
        let governance_display = governance::Display::genesis(genesis);
        Ok(Self {
            channel_id: *channel_id,
            genesis: genesis.clone(),
            name_hint: name_hint.to_owned(),
            passphrase: Some(Zeroizing::new(channel_passphrase.to_vec())),
            created: now_ms,
            epoch,
            sek,
            authors,
            admission,
            dag: Dag::for_room(genesis.body.created_ms),
            forks_kept: 0,
            governance_display,
            governance_ready: false,
            consent_facts: std::sync::Mutex::new(ConsentFactsState::Ready(std::sync::Arc::new(
                governance::ConsentFacts::empty(),
            ))),
            own_behind: false,
            own_recovery: own_history::Recovery::UnknownBehind,
            presence: BTreeMap::new(),
            sparse_applied_tips: BTreeMap::new(),
            sparse_contiguous_pending: BTreeSet::new(),
            sparse_contiguous_after: None,
            sender,
            next_log_id: 1,
            read_mark_scan: None,
            read_mark_complete: None,
            set_aside: SetAside::default(),
            chains_advanced: false,
            backfill_refreshing: false,
            backfill_after: None,
            legacy_sessions: legacy_session::LegacySessions::default(),
            legacy_announced: None,
            private_sessions: private_session::PrivateSessions::default(),
            held: BTreeMap::new(),
            owed_asked_to: None,
            now_hint: now_ms,
            projection_state: history::State::default(),
            display_tail: None,
            display_order_revision: 0,
            display_shown_at: 0,
            display_rewrite: 0,
            entries,
            legacy_preparation: entry_store::Preparation::Ready,
            legacy_cache_trusted: None,
            key_packages: key_package_queue::Queue::new(1),
            receivers: BTreeMap::new(),
            services: BTreeMap::new(),
            kinds: BTreeMap::new(),
            transient: BTreeSet::new(),
            // The join witness the responder signed (M17.6), written with the room above.
            own_admission,
            origins,
            delivered: BTreeMap::new(),
            node_retention: 0,
            node_step_retention: 0,
            last_pruned_at: now_ms,
            checkpoint_idle: CHECKPOINT_IDLE_SECS,
            history: BTreeMap::new(),
            entitled: BTreeMap::new(),
            trust_marks: BTreeMap::new(),
            known_members: BTreeSet::new(),
            drive: DriveState::default(),
            board_kept: BoardKept::default(),
            room_pause: vox_agentcomms::drive::PauseState::default(),
            pause_resume_after: 0,
            skipped: std::collections::VecDeque::new(),
            poisoned: false,
            save_error: None,
            local_pre_context: None,
            local_append_budget: None,
            local_content_header: None,
            local_history: None,
            history_publication_changed: std::sync::Arc::new(tokio::sync::Notify::new()),
            settled: false,
            gen: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            readmitted: BTreeMap::new(),
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
        now: crate::time::Ms,
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
                // **Never a member that left** (#520): its own withdraw, signed no earlier than
                // the witness, refuses it, wherever the record came from. A member that joins again
                // is witnessed again, later, and is taken.
                if !self.authors.contains_key(&fingerprint)
                    && self.withdrawn_since(&fingerprint, w.timestamp_ms)
                {
                    return Err(Error::MalformedGovernance(
                        "admission withdrawn: the member left the room",
                    ));
                }
                self.keep_notice(
                    store,
                    &crate::nat::notice::AdmissionNotice::new(key.clone(), (**w).clone())?,
                )?;
            }
        }
        // Past the cap if it must be: another member admitted it, on its own view that there was
        // room. Refusing it here would split the room (V210-128).
        self.admit_within(store, key, now, AUTHORS_HARD_LIMIT)
    }

    /// Admit a newcomer **from its admission notice** (#520): the evidence its bundle record would
    /// carry, the witness of a member this node already admits, without the bundle, so a newcomer
    /// that is offline is still learned of. The same rules as [`ChannelState::admit_from_board`]:
    /// the witness's signer must be an author here, the witness must bind this room, this epoch
    /// and the key's fingerprint, a withdraw of the newcomer no older than the witness refuses it,
    /// and the room's cap gives way only to what another member admitted. The notice is kept, to
    /// pass on.
    pub fn admit_from_notice(
        &mut self,
        store: &Store,
        notice: &crate::nat::notice::AdmissionNotice,
        now: crate::time::Ms,
    ) -> Result<bool> {
        if notice.channel_id() != self.channel_id {
            return Err(Error::MalformedGovernance(
                "admission notice of another room",
            ));
        }
        let w = &notice.witness;
        let witness_key =
            self.authors
                .get(&w.witness_id)
                .cloned()
                .ok_or(Error::MalformedGovernance(
                    "join witness signed by an unadmitted key",
                ))?;
        notice.verify(&witness_key, &self.channel_id, self.epoch)?;
        let fingerprint = notice.joiner();
        if !self.authors.contains_key(&fingerprint)
            && self.withdrawn_since(&fingerprint, w.timestamp_ms)
        {
            return Err(Error::MalformedGovernance(
                "admission withdrawn: the member left the room",
            ));
        }
        self.keep_notice(store, notice)?;
        self.admit_within(store, &notice.key, now, AUTHORS_HARD_LIMIT)
    }

    /// Whether this node holds a withdraw of `member` signed at or after `since` (#520).
    #[must_use]
    pub fn withdrawn_since(&self, member: &Digest32, since: u64) -> bool {
        self.board_kept
            .withdraws
            .get(member)
            .is_some_and(|(at, _)| *at >= since)
    }

    /// Keep `notice`, the newest witnessed for its joiner (#520), persisted so this node passes it
    /// on after a restart. A notice its joiner's kept withdraw refuses is not kept.
    pub fn keep_notice(
        &mut self,
        store: &Store,
        notice: &crate::nat::notice::AdmissionNotice,
    ) -> Result<()> {
        let (joiner, at) = (notice.joiner(), notice.witness.timestamp_ms);
        if self.withdrawn_since(&joiner, at)
            || self
                .board_kept
                .notices
                .get(&joiner)
                .is_some_and(|(held, _)| *held >= at)
        {
            return Ok(());
        }
        if !self.board_kept.notices.contains_key(&joiner)
            && self.board_kept.notices.len() >= AUTHORS_HARD_LIMIT
        {
            return Ok(());
        }
        self.board_kept
            .notices
            .insert(joiner, (at, notice.to_wire()));
        self.save_board_kept(store)
    }

    /// Keep a member's own withdraw (#520), checked by the caller against the member's key: the
    /// newest one, persisted, so this node refuses every admission of that member it witnessed
    /// before, and passes the withdraw on wherever it passes the member's notice.
    pub fn keep_withdraw(
        &mut self,
        store: &Store,
        withdraw: &crate::nat::withdraw::BoardWithdraw,
    ) -> Result<bool> {
        if withdraw.channel_id != self.channel_id
            || withdraw.scope != crate::nat::withdraw::WithdrawScope::Member
        {
            return Ok(false);
        }
        let member = withdraw.author_id;
        if self
            .board_kept
            .withdraws
            .get(&member)
            .is_some_and(|(at, _)| *at >= withdraw.timestamp_ms)
        {
            return Ok(false);
        }
        if !self.board_kept.withdraws.contains_key(&member)
            && self.board_kept.withdraws.len() >= AUTHORS_HARD_LIMIT
        {
            return Ok(false);
        }
        self.board_kept
            .withdraws
            .insert(member, (withdraw.timestamp_ms, withdraw.to_wire()));
        self.save_board_kept(store)?;
        Ok(true)
    }

    /// The kept withdraws then the kept notices, as wire bytes (#520): what this node files on its
    /// own board when it opens the room, and offers a peer's board that lacks them.
    #[must_use]
    pub fn board_kept(&self) -> Vec<Vec<u8>> {
        self.board_kept
            .withdraws
            .values()
            .chain(self.board_kept.notices.values())
            .map(|(_, w)| w.clone())
            .collect()
    }

    /// The key a kept notice gives `member` (#520): what checks a withdraw it signs where this
    /// node never admitted it.
    #[must_use]
    pub fn notice_key(&self, member: &Digest32) -> Option<CompositePublicKey> {
        let (_, wire) = self.board_kept.notices.get(member)?;
        crate::nat::notice::AdmissionNotice::from_wire(wire)
            .ok()
            .map(|n| n.key)
    }

    /// Current durable local pause. Session metadata publishers may copy this scalar state;
    /// no activity history or registration scan is needed to recover it after a restart.
    #[must_use]
    pub fn room_pause(&self) -> vox_agentcomms::drive::PauseState {
        self.room_pause
    }

    /// Ordinary replies already readable at the last resume wait for the next human turn.
    /// Addressed urgent news remains eligible for the existing wake policy.
    #[must_use]
    pub fn pause_resume_after(&self) -> u64 {
        self.pause_resume_after
    }

    /// Save a receiver-authorized change before exposing it to wake/news consumers.
    pub(crate) fn set_room_pause(
        &mut self,
        store: &Store,
        paused: bool,
        by: Digest32,
        now: u64,
    ) -> Result<()> {
        if self.is_poisoned() {
            return Err(self.save_failure());
        }
        if self.room_pause.paused == paused {
            return Ok(());
        }
        let resume_after = if paused {
            self.pause_resume_after
        } else {
            self.last_arrival(store)?.unwrap_or(0)
        };
        let state = vox_agentcomms::drive::PauseState {
            paused,
            by,
            at_millis: now.max(self.room_pause.at_millis.saturating_add(1)),
        };
        let mut e = crate::cbor::Encoder::new();
        e.array(5)
            .uint(1)
            .uint(u64::from(state.paused))
            .bytes(&state.by)
            .uint(state.at_millis)
            .uint(resume_after);
        let segment = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_ROOM_PAUSE,
            &e.finish(),
        )?;
        store.put_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_ROOM_PAUSE,
            &segment,
        )?;
        self.room_pause = state;
        self.pause_resume_after = resume_after;
        Ok(())
    }

    fn save_board_kept(&mut self, store: &Store) -> Result<()> {
        let seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_BOARD_KEPT,
            &board_kept_bytes(&self.board_kept),
        )?;
        if let Err(e) = store.put_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_BOARD_KEPT,
            &seg,
        ) {
            self.poisoned = true;
            self.save_error = Some(e.to_string());
            return Err(e);
        }
        Ok(())
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
    ///
    /// Refused past the room's cap ([`MAX_AUTHORS`]): this node is the one deciding whether there
    /// is room. [`ChannelState::admit_from_board`] admits what another member decided, past the
    /// cap if it must be.
    pub fn admit_author(
        &mut self,
        store: &Store,
        key: &CompositePublicKey,
        now: crate::time::Ms,
    ) -> Result<bool> {
        self.admit_within(store, key, now, max_authors())
    }

    /// Admit a joiner this node just authenticated and retain its witnessed admission in the
    /// same transaction. The caller verifies the witness and the live join authority first.
    /// A successful join must remain discoverable after this responder restarts while the
    /// joiner is offline; neither author membership nor its notice may be committed alone.
    /// Re-admitting the same key still succeeds at the room cap and returns `false`.
    pub(crate) fn admit_author_with_notice(
        &mut self,
        store: &Store,
        notice: &crate::nat::notice::AdmissionNotice,
        now: crate::time::Ms,
    ) -> Result<bool> {
        if self.is_poisoned() {
            return Err(self.save_failure());
        }
        let fingerprint = notice.key.fingerprint();
        if notice.channel_id() != self.channel_id
            || notice.witness.epoch != self.epoch
            || notice.joiner() != fingerprint
        {
            return Err(Error::MalformedGovernance(
                "admission notice does not name this room, epoch and joiner",
            ));
        }
        let added = match self.authors.get(&fingerprint) {
            Some(existing) if existing.to_bytes() == notice.key.to_bytes() => false,
            Some(_) => {
                return Err(Error::MalformedGovernance(
                    "another key is already admitted for this fingerprint",
                ));
            }
            None if self.authors.len() >= max_authors() => {
                return Err(Error::RoomFull {
                    members: self.authors.len() as u64,
                });
            }
            None => true,
        };
        let at = notice.witness.timestamp_ms;
        if self.withdrawn_since(&fingerprint, at) {
            return Err(Error::MalformedGovernance(
                "admission withdrawn: the member left the room",
            ));
        }
        let keep = self
            .board_kept
            .notices
            .get(&fingerprint)
            .is_none_or(|(held, _)| *held < at);
        if !self.board_kept.notices.contains_key(&fingerprint)
            && self.board_kept.notices.len() >= AUTHORS_HARD_LIMIT
        {
            return Err(Error::SizeLimitExceeded("kept notices"));
        }
        if !added && !keep {
            self.now_hint = self.now_hint.max(now.get());
            return Ok(false);
        }

        let mut authors = self.authors.clone();
        authors.insert(fingerprint, notice.key.clone());
        let mut board_kept = self.board_kept.clone();
        if keep {
            board_kept
                .notices
                .insert(fingerprint, (at, notice.to_wire()));
        }
        let authors_seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_AUTHORS,
            &authors_bytes(&authors),
        )?;
        let board_seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_BOARD_KEPT,
            &board_kept_bytes(&board_kept),
        )?;
        let committed = (|| {
            let mut batch = store.batch()?;
            batch.put_segment(
                &self.channel_id,
                SegmentKind::KeyMaterial,
                SEG_AUTHORS,
                &authors_seg,
            )?;
            batch.put_segment(
                &self.channel_id,
                SegmentKind::KeyMaterial,
                SEG_BOARD_KEPT,
                &board_seg,
            )?;
            batch.commit()
        })();
        if let Err(error) = committed {
            self.poisoned = true;
            self.save_error = Some(error.to_string());
            return Err(error);
        }
        self.authors = authors;
        self.board_kept = board_kept;
        self.now_hint = self.now_hint.max(now.get());
        if added {
            self.admission
                .admit(self.channel_id, self.epoch, fingerprint);
            self.owe_private_support();
            self.governance_ready = false;
        }
        Ok(added)
    }

    /// [`ChannelState::admit_author`], refused at `limit` authors. Keep the room's
    /// maintenance time in milliseconds, including after an admission (#562).
    fn admit_within(
        &mut self,
        store: &Store,
        key: &CompositePublicKey,
        now: crate::time::Ms,
        limit: usize,
    ) -> Result<bool> {
        let now_ms = now.get();
        self.now_hint = self.now_hint.max(now_ms);
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
        if self.authors.len() >= limit {
            return Err(Error::RoomFull {
                members: self.authors.len() as u64,
            });
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
            self.save_error = Some(e.to_string());
            return Err(e);
        }
        *self
            .consent_facts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            ConsentFactsState::Building(ConsentFactsBuild::new(&self.authors));
        // Capability announcements are live room traffic. A newly admitted member cannot read
        // the announcement that predates its admission, so the next bounded maintenance turn
        // republishes it. The obligation is recreated on open if the process stops here.
        self.owe_private_support();
        self.governance_ready = false;
        Ok(true)
    }

    /// Only the room's signed governance supplies its anchors. Until that history arrives,
    /// no room anchors are known; the current join uses its separate operation-scoped routes.
    #[must_use]
    pub fn anchors(&self) -> BootstrapSet {
        self.governance_display.anchors.clone().unwrap_or_default()
    }

    /// The services this node offers in this channel: `service_tag → local address`
    /// (ADR-013 Bind config).
    #[must_use]
    pub fn services(&self) -> &BTreeMap<String, SocketAddr> {
        &self.services
    }

    /// Where a service this node offers in this channel lives locally, or `None`.
    /// This is pure host configuration and carries **no** authorization: what a peer
    /// may reach is whether this host approved its key in this channel (its reachers,
    /// ADR-017 decision 3 as revised), checked separately.
    #[must_use]
    pub fn service_endpoint(&self, service_tag: &str) -> Option<SocketAddr> {
        self.services.get(service_tag).copied()
    }

    /// Offer `service_tag` at `local`, persisted under the channel's SEK so a restart
    /// still serves it — unless `persist` is false, when it lasts only until it is removed
    /// or this node stops. No capability is checked: offering a port of this machine is
    /// configuration, not authorization (see the body).
    ///
    /// **A name is shared once** (V030-25): the tag is the `<service>` of
    /// `<service>.<node>.<room>.vox`, so a second share under a name this node already shares
    /// here — over either transport (`udp/<name>` is the same name) — is refused, naming the one
    /// that holds it. A service moves by being removed and shared again.
    ///
    /// Returns whether this added a tag that was not offered before.
    pub fn add_service(
        &mut self,
        store: &Store,
        profile: &Profile,
        service_tag: &str,
        local: SocketAddr,
        kind: ServiceKind,
        persist: bool,
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
        let name = service_name(service_tag);
        if let Some((_, at)) = self
            .services
            .iter()
            .find(|(tag, _)| service_name(tag) == name)
        {
            return Err(Error::ServiceNameTaken(name.to_owned(), *at));
        }
        let fresh = true;
        if self.services.len() >= MAX_SERVICES {
            return Err(Error::SizeLimitExceeded("room services"));
        }
        self.services.insert(service_tag.to_owned(), local);
        self.kinds.insert(service_tag.to_owned(), kind);
        if persist {
            self.transient.remove(service_tag);
        } else {
            self.transient.insert(service_tag.to_owned());
        }
        self.persist_services(store)?;
        Ok(fresh)
    }

    /// Write this identity's statement that it shares `service_tag` in the room, or no longer
    /// does (V030-25), so every member can list it. A transient offer (a file being handed over)
    /// is not a share and is not announced.
    pub fn say_share(
        &mut self,
        profile: &Profile,
        service_tag: &str,
        shared: bool,
        now: crate::time::Ms,
    ) -> Result<()> {
        let now_ms = now.get();
        let statement = crate::governance::share::ServiceShare::build(
            profile.signer()?,
            &self.channel_id,
            self.epoch,
            service_name(service_tag),
            crate::tunnel::udp::is_udp(service_tag),
            shared,
            self.kind_of(service_tag),
        )?;
        self.append_governance(profile, &statement.to_wire(), now_ms)?;
        Ok(())
    }

    /// State every share this node offers here that the log does not yet say it shares, and
    /// return whether anything was written. A share made in a room joined and not yet synced is
    /// offered at once but can be said only once the room settles (V210-164); this says it then.
    pub fn say_unsaid_shares(&mut self, profile: &Profile, now: crate::time::Ms) -> Result<bool> {
        let me = profile.signer()?.fingerprint();
        let view = self.current_governance(profile.store())?;
        let mut unsaid = Vec::new();
        for tag in self
            .services
            .keys()
            .filter(|tag| !self.transient.contains(*tag))
        {
            if view.share(&me, service_name(tag))?.is_none() {
                unsaid.push(tag.clone());
            }
        }
        drop(view);
        for tag in &unsaid {
            self.say_share(profile, tag, true, now)?;
        }
        Ok(!unsaid.is_empty())
    }

    /// What `service_tag` was detected to be when it was offered (ADR-028 S-2); a tag offered
    /// with no detection, or no longer offered, is plain `tcp` or `udp`.
    fn kind_of(&self, service_tag: &str) -> ServiceKind {
        self.kinds
            .get(service_tag)
            .copied()
            .unwrap_or_else(|| ServiceKind::plain(crate::tunnel::udp::is_udp(service_tag)))
    }

    /// Whether `service_tag` is offered and persisted: a share, not a transient offer.
    #[must_use]
    pub fn is_shared(&self, service_tag: &str) -> bool {
        self.services.contains_key(service_tag) && !self.transient.contains(service_tag)
    }

    /// Stop offering `service_tag`. Returns whether it was offered.
    pub fn remove_service(&mut self, store: &Store, service_tag: &str) -> Result<bool> {
        if self.services.remove(service_tag).is_none() {
            return Ok(false);
        }
        self.kinds.remove(service_tag);
        self.transient.remove(service_tag);
        self.persist_services(store)?;
        Ok(true)
    }

    /// How this node came to be a member here (M17.6).
    #[must_use]
    pub fn own_admission(&self) -> &Admission {
        &self.own_admission
    }

    fn persist_services(&mut self, store: &Store) -> Result<()> {
        let seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_SERVICES,
            &services_bytes(
                &self
                    .services
                    .iter()
                    .filter(|(tag, _)| !self.transient.contains(*tag))
                    .map(|(tag, at)| {
                        let kind =
                            self.kinds.get(tag).copied().unwrap_or_else(|| {
                                ServiceKind::plain(crate::tunnel::udp::is_udp(tag))
                            });
                        (tag.clone(), (*at, kind))
                    })
                    .collect(),
            ),
        )?;
        if let Err(e) = store.put_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_SERVICES,
            &seg,
        ) {
            self.poisoned = true;
            self.save_error = Some(e.to_string());
            return Err(e);
        }
        Ok(())
    }

    /// Read at most 64 committed log positions and return at most one valid delivery.
    /// Unlinked rows kept for diagnostics never become key-delivery authority.
    pub(crate) fn next_key_package(
        &mut self,
        store: &Store,
        trust_digest: Digest32,
    ) -> Result<key_package_queue::Progress> {
        let room = self.channel_id;
        let epoch = self.epoch;
        let me = self.me();
        let dag = &self.dag;
        let read = self.entries.read(store, &self.sek, &room)?;
        self.key_packages
            .next(store, &self.sek, &room, &me, &read, trust_digest, |entry| {
                Ok(entry.skeleton.channel_id == room
                    && entry.skeleton.epoch == epoch
                    && entry.skeleton.seq != 0
                    && (entry.skeleton.seq <= dag.verified_head(&entry.skeleton.author_id)
                        || read.history_effect_finished(&entry.entry_hash())?))
            })
    }

    /// Whether a bounded forward scan or a requested retained-package replay needs a turn.
    pub(crate) fn key_packages_pending(&self) -> bool {
        self.key_packages.pending()
    }

    /// Release the attempted locator's drive hint even when opening or trust checks refused it.
    pub(crate) fn key_package_attempted(
        &mut self,
        store: &Store,
        author: &Digest32,
        log_id: u64,
    ) -> Result<()> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        let result =
            self.key_packages
                .attempted(store, &self.sek, &self.channel_id, author, log_id);
        if let Err(error) = &result {
            self.poison(error);
        }
        result
    }

    /// A trust or prekey change retries retained packages from disk without retaining bodies.
    pub fn release_held_packages(&mut self) {
        self.key_packages.retry_retained();
    }

    /// Validate and prepare unpublished entry/DAG roots before opening the effects Batch.
    /// A late parent may touch any number of descendants, so that work commits in bounded
    /// chunks while the previous active roots and authority remain intact.
    fn prepare_entry(
        &mut self,
        store: &Store,
        entry: &Entry,
        kind: EntryKind,
        key: &CompositePublicKey,
        now_ms: u64,
    ) -> Result<()> {
        use crate::log::dag::Rejected;
        let prepared = (|| -> Result<()> {
            let mut staging = self.entries.staging(store, &self.sek, &self.channel_id);
            self.dag
                .accept(&mut staging, entry.clone(), kind, key, &self.admission)
                .map_err(|why| match why {
                    Rejected::Local(error) => error,
                    Rejected::PreCheckpoint => {
                        Error::MalformedGovernance("entry is at or below its author's checkpoint")
                    }
                    _ => Error::MalformedGovernance("entry failed the acceptance predicate"),
                })?;
            self.entries.prepare_publication(
                store,
                &self.sek,
                &self.channel_id,
                entry_store::Publication {
                    witness: entry,
                    from: entry.skeleton.seq,
                    first_log: self.next_log_id,
                    received_ms: now_ms,
                    bodyless_prefix: false,
                    origin: self.genesis.body.created_ms,
                    local_contexts: self
                        .local_history
                        .as_ref()
                        .map(|prepared| (&prepared.pre, &prepared.post)),
                },
            )
        })();
        if let Err(ref error) = prepared {
            self.poison(error);
        }
        prepared
    }

    fn publish_entry_into(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        entry: &Entry,
    ) -> Result<Option<entry_store::sparse::LocalHistorySettlement>> {
        let mut index = self.entries.write(batch, &self.sek, &self.channel_id)?;
        index.publish_promotion()?;
        let settlement = if let Some(prepared) = &self.local_history {
            Some(
                index.publish_local_history(entry_store::sparse::LocalHistoryPublication {
                    entry,
                    header: &prepared.header,
                    head: &prepared.head,
                    consistency: &prepared.consistency,
                    included: &prepared.included,
                    pre_context: &prepared.pre,
                    post_context: &prepared.post,
                    ranges: &prepared.ranges,
                })?,
            )
        } else {
            None
        };
        index.seal()?;
        session_projection::private_index::observe_public(
            batch,
            &self.sek,
            &self.channel_id,
            entry,
            self.epoch,
        )?;
        Ok(settlement)
    }

    /// The local append's user-visible effects have been written into `batch`. Seal the exact
    /// sparse settlement token before the same commit, so neither side can survive alone.
    fn finish_local_history_effect_into(
        &self,
        batch: &mut crate::node::store::Batch<'_>,
        entry: &Entry,
        settlement: Option<entry_store::sparse::LocalHistorySettlement>,
    ) -> Result<()> {
        let settlement = match (entry.skeleton.v2.is_some(), settlement) {
            (true, Some(settlement)) => settlement,
            (false, None) => return Ok(()),
            (true, None) => return Err(Error::Profile("local history settlement missing")),
            (false, Some(_)) => {
                return Err(Error::Profile("legacy entry produced local settlement"))
            }
        };
        let mut index = self.entries.write(batch, &self.sek, &self.channel_id)?;
        index.finish_local_history_effect(entry, settlement)?;
        index.seal()
    }

    fn finish_entry_publication(&mut self, store: &Store) -> Result<()> {
        let local_applied = self.local_history.as_ref().map(|prepared| {
            let entry = prepared.header.entry();
            (entry.skeleton.author_id, entry.skeleton.seq)
        });
        self.local_history = None;
        self.local_pre_context = None;
        self.local_append_budget = None;
        self.local_content_header = None;
        self.key_packages.published(self.next_log_id);
        // The caller committed the local append and all of its effects before entering here.
        // Remote effects advance this cache in `advance_history_effect`; advance the authored
        // path from the exact verified header too, before optional cleanup can return early.
        if let Some((author, seq)) = local_applied {
            debug_assert_eq!(author, self.me());
            self.sparse_applied_tips
                .entry(author)
                .and_modify(|tip| *tip = (*tip).max(seq))
                .or_insert(seq);
        }
        // Explicit legacy history owns post-switch cleanup too. A large authenticated
        // unsigned prefix must not turn this one final witness into an unbounded cleanup.
        if self.legacy_provisional_state(store)?.is_some() {
            return Ok(());
        }
        let result = (|| -> Result<()> {
            loop {
                let mut batch = store.batch()?;
                let mut index = self
                    .entries
                    .write(&mut batch, &self.sek, &self.channel_id)?;
                let done = index.cleanup_chunk()?;
                index.seal()?;
                batch.commit()?;
                self.entries.committed();
                if done {
                    self.history_publication_changed.notify_waiters();
                    let read = self.entries.read(store, &self.sek, &self.channel_id)?;
                    self.dag.set_order_revision(
                        read.order_revision(),
                        read.order_previous(None)?.map(|(clock, _)| clock),
                    );
                    return Ok(());
                }
            }
        })();
        if let Err(ref error) = result {
            self.poison(error);
        }
        result
    }

    fn discard_unverified(&mut self, store: &Store) -> Result<usize> {
        let mut entries = self.entries.staging(store, &self.sek, &self.channel_id);
        self.dag.discard_unverified(&mut entries)
    }

    fn entry_at(&self, transaction: Transaction<'_, '_>, hash: &Digest32) -> Result<Option<Entry>> {
        self.dag.get_by_hash(
            &self
                .entries
                .view(transaction, &self.sek, &self.channel_id)?,
            hash,
        )
    }

    fn entry(&self, store: &Store, hash: &Digest32) -> Result<Option<Entry>> {
        self.dag.get_by_hash(
            &self.entries.read(store, &self.sek, &self.channel_id)?,
            hash,
        )
    }

    fn log_id_at(&self, transaction: Transaction<'_, '_>, hash: &Digest32) -> Result<Option<u64>> {
        self.entries
            .view(transaction, &self.sek, &self.channel_id)?
            .log_id(hash)
    }

    /// Every key-package this node holds in the room's log, with its author, whoever it is
    /// for — a diagnostic of what this node carries, not of what it can open.
    pub fn key_packages(
        &self,
        store: &Store,
    ) -> Result<Vec<(Digest32, crate::node::keypackage::KeyPackage)>> {
        let entries = self.entries.read(store, &self.sek, &self.channel_id)?;
        let mut out = Vec::new();
        for author in self.authors.keys() {
            let Some(feed) = self.dag.feed(author) else {
                continue;
            };
            for seq in 1..=feed.max_seq() {
                let Some(entry) = feed.get(&entries, seq)? else {
                    continue;
                };
                let Some(payload) = entry.payload.as_deref() else {
                    continue;
                };
                if let Ok(pkg) = crate::node::keypackage::KeyPackage::from_wire(payload) {
                    out.push((*author, pkg));
                }
            }
        }
        Ok(out)
    }

    /// Post a key-package to the room's log (ADR-023 decision 4): an entry every member
    /// replicates, carrying a sender key to one member who may never be online with its
    /// sender. Content-kind for the DAG; never rendered, never cached.
    ///
    /// # Errors
    /// If this identity is not an author, the channel is poisoned, or the persist fails.
    pub fn append_key_package(
        &mut self,
        profile: &Profile,
        package: &crate::node::keypackage::KeyPackage,
        now_millis: u64,
    ) -> Result<Digest32> {
        self.ensure_local_append_available(profile.store())?;
        if self.poisoned {
            return Err(self.save_failure());
        }
        if !self.settled {
            return Err(Error::RoomNotSynced);
        }
        self.require_own_history_current()?;
        let signer = profile.signer()?;
        let me = signer.fingerprint();
        if !self.authors.contains_key(&me) {
            return Err(Error::Profile("this identity is not an author of the room"));
        }
        let payload = package.to_wire();
        let skeleton = self.next_skeleton(profile, &me, &payload, now_millis)?;
        let entry = Entry::build_signed(signer, skeleton, payload)?;
        let entry_hash = entry.entry_hash();
        let id = self.next_log_id;
        let key = signer.public_key();

        let persisted = (|| -> Result<()> {
            self.prepare_local_entry(profile, &entry, EntryKind::Content, &key, now_millis)?;
            let mut batch = profile.store().batch()?;
            let settlement = self.publish_entry_into(&mut batch, &entry)?;
            self.observe_governance_into(profile.store(), &mut batch, &entry, id)?;
            self.finish_local_history_effect_into(&mut batch, &entry, settlement)?;
            batch.commit()
        })();
        if let Err(e) = persisted {
            self.poisoned = true;
            self.save_error = Some(e.to_string());
            return Err(e);
        }
        // As every other append: its page is found again when a checkpoint sheds its signature,
        // and its ports need a session at once (ADR-025 D2), not at the periodic sync.
        self.entries.committed();
        self.next_log_id = id.saturating_add(1);
        self.gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.finish_entry_publication(profile.store())?;
        Ok(entry_hash)
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

    /// Whether `fingerprint` is known to be a member here: an admitted author, or a member this
    /// node knows before its record is admitted ([`Self::note_member`]). What a room link names
    /// that passes this is a member at an address, never an anchor (V030-51).
    #[must_use]
    pub fn is_known_member(&self, fingerprint: &Digest32) -> bool {
        self.is_author(fingerprint) || self.known_members.contains(fingerprint)
    }

    /// Record `member` as a member of this room before its record is admitted: the member that
    /// answered this node's join, which proved it holds the room (V030-51). Persisted, so a reopen
    /// before the first sync still knows it. Admits nothing: it reads and writes as before.
    ///
    /// # Errors
    /// If the store cannot take the record.
    pub fn note_member(&mut self, store: &Store, member: Digest32) -> Result<()> {
        if self.is_author(&member) || !self.known_members.insert(member) {
            return Ok(());
        }
        let seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_KNOWN_MEMBERS,
            &known_members_bytes(&self.known_members),
        )?;
        if let Err(e) = store.put_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_KNOWN_MEMBERS,
            &seg,
        ) {
            self.poisoned = true;
            self.save_error = Some(e.to_string());
            return Err(e);
        }
        Ok(())
    }

    /// The admitted authors' keys, in fingerprint order.
    #[must_use]
    pub fn author_keys(&self) -> Vec<CompositePublicKey> {
        self.authors.values().cloned().collect()
    }

    /// Every admitted author's key by its fingerprint, as held: the fingerprints are not worked
    /// out again (V030-09).
    #[must_use]
    pub fn author_map(&self) -> BTreeMap<Digest32, CompositePublicKey> {
        self.authors.clone()
    }

    /// How many authors are admitted.
    #[must_use]
    pub fn author_count(&self) -> usize {
        self.authors.len()
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
        self.require_legacy_current(profile.store())?;
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.current_governance(profile.store())?;
        let signer = profile.signer()?;
        let (iteration, key) = self.sender.current_position();
        self.sender.skdm_for(signer, iteration, key)
    }

    /// Mint the SKDMs of a **full-history** grant (PRD-001 R12, ADR-023 decision 5):
    /// every generation of this identity's sender key still retained, each at its
    /// origin, oldest first, so the recipient reads this identity's messages from before
    /// the approval as well as after. The **last** is the live generation — the one a
    /// consent grant records.
    ///
    /// A live generation whose origin is not retained (a room from before M18.1) can
    /// only be released from its current position, as [`Self::skdm_for_consent`] does;
    /// that is the honest limit of "full", not a silent narrowing.
    pub fn skdms_for_full_history(&self, profile: &Profile) -> Result<Vec<Skdm>> {
        self.require_legacy_current(profile.store())?;
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.current_governance(profile.store())?;
        let signer = profile.signer()?;
        let live = self.sender.chain_id();
        let mut out = Vec::new();
        for (chain_id, _) in self
            .origins
            .generations(&self.channel_id, self.epoch, &self.me())
        {
            if chain_id != live {
                out.push(self.origins.release_at(
                    signer,
                    &self.channel_id,
                    self.epoch,
                    chain_id,
                    0,
                )?);
            }
        }
        out.push(self.rekey_skdm(profile)?);
        Ok(out)
    }

    /// How many generations of this identity's sender key this node still holds the
    /// origin of — what `vox status` reports, and what R14 keeps down to one.
    #[must_use]
    pub fn key_generations(&self) -> usize {
        self.origins
            .generations(&self.channel_id, self.epoch, &self.me())
            .len()
    }

    /// The oldest generation of this identity's sender key that a release still owes
    /// someone (V210-45): the generation a `trusted` identity's trust mark stands in, for
    /// one this identity has not consented to yet — whether or not it has joined — the first
    /// one for a trusted identity with no mark here (trusted before the room existed), and
    /// every history floor still owed. `None`: nothing older than the live one is needed.
    ///
    /// **What is kept for someone who has not joined is kept for a while, not forever** (PRD-001
    /// R14, decider 2026-09-28): for the room's retention when it has one, otherwise
    /// [`UNJOINED_HOLD_SECS`]. A generation created before `now_ms` less that hold goes even
    /// though a trusted identity never came to collect it; one that joins later reads what is
    /// still held. History floors owed to members who have joined are not bounded here.
    #[must_use]
    pub fn oldest_generation_needed(
        &self,
        trusted: &BTreeSet<Digest32>,
        now: crate::time::Ms,
    ) -> Option<u64> {
        let now_ms = now.get();
        let me = self.me();
        let unjoined = |id: &Digest32| *id != me && !self.entitled.contains_key(id);
        // A trusted identity with **no mark here** was trusted before this room existed, so every
        // generation of the room is after its decision and all of them are its (`history_plan`).
        let waiting = if trusted
            .iter()
            .any(|id| unjoined(id) && !self.trust_marks.contains_key(id))
        {
            Some(0)
        } else {
            self.trust_marks
                .iter()
                .filter(|(id, _)| trusted.contains(*id) && unjoined(id))
                .map(|(_, (_, chain_id, _))| *chain_id)
                .min()
        };
        // The hold: nothing older than it is kept for a waiting identity. No generation inside it
        // means none is kept for them at all.
        let waiting = waiting.map(|floor| {
            let cutoff = now_ms.saturating_sub(self.unjoined_hold_secs().saturating_mul(1_000));
            let young = self
                .origins
                .oldest_created_since(&self.channel_id, self.epoch, &me, cutoff)
                .unwrap_or(u64::MAX);
            floor.max(young)
        });
        waiting
            .into_iter()
            .chain(self.history.values().copied())
            .min()
    }

    /// How long a superseded generation is kept for a trusted identity that has not joined:
    /// the retention this node applies to the room, or [`UNJOINED_HOLD_SECS`] when that is
    /// forever. A message past retention is gone, so the key to it has nothing left to open.
    #[must_use]
    pub fn unjoined_hold_secs(&self) -> u64 {
        match self.effective_retention() {
            0 => UNJOINED_HOLD_SECS,
            secs => secs,
        }
    }

    /// Delete every superseded generation's origin key (ADR-023 decision 4, PRD-001
    /// R14) older than generation `keep_from`, and never the live one. The caller decides
    /// *when* and *from where*: nothing a release still owes somebody —
    /// [`Self::oldest_generation_needed`], or all of it while a full-history grant is owed
    /// — because "no longer needed" is what R14 deletes. Returns how many were deleted.
    pub fn prune_superseded_origins(&mut self, store: &Store, keep_from: u64) -> Result<usize> {
        match self.require_governance_ready(store, crate::time::Ms(self.now_hint)) {
            Ok(_) if self.governance_display_current(self.now_hint) => {}
            Ok(_) => return Ok(0),
            Err(error) if governance::refreshing(&error) => return Ok(0),
            Err(error) => return Err(error),
        }
        let live = self.sender.chain_id();
        let gone = self
            .origins
            .retain_from(&self.channel_id, self.epoch, keep_from.min(live));
        if gone == 0 {
            return Ok(0);
        }
        let seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_ORIGINS,
            &self.origins.to_state(),
        )?;
        if let Err(e) = store.put_segment(
            &self.channel_id,
            SegmentKind::KeyMaterial,
            SEG_ORIGINS,
            &seg,
        ) {
            self.poisoned = true;
            self.save_error = Some(e.to_string());
            return Err(e);
        }
        Ok(gone)
    }

    /// Issue a **consent grant** to `target`: the ADR-007 log fact that this
    /// identity released its sender key to `target`, carrying the `skdm_ref` of the
    /// SKDM actually delivered over the pairwise session and the history mode in
    /// force. Appends it with its current consent fact in the same transaction.
    /// An older source replay must finish before that checked view is available.
    ///
    /// The SKDM delivery itself is the caller's (M14.5b); this records the consent.
    ///
    /// `entitled_from` is the earliest `(chain_id, iteration)` this consent releases to
    /// `target` (V210-45): the delivered key's own position, or earlier when history
    /// is owed too. It is recorded, and no later release to `target` starts before it.
    /// `full_history` is the approver's per-grant choice (PRD-001 R12), which the grant
    /// records as its history mode.
    ///
    /// **It records nothing as delivered** (V210-88): the key is `delivered` only once `target`
    /// has taken it, which [`Self::note_delivered`] records when it says so. Returns the grant, and
    /// whether the consent owes `target` history, the generations before the key's own.
    pub fn issue_consent(
        &mut self,
        profile: &Profile,
        target: Digest32,
        delivered_skdm: &Skdm,
        full_history: bool,
        entitled_from: (u64, u64),
        now: crate::time::Ms,
    ) -> Result<(ConsentGrant, bool)> {
        let now_ms = now.get();
        let signer = profile.signer()?;
        // The grant records what this approval actually released (PRD-001 R12): the
        // approver's per-grant choice, not a room-wide default.
        let history_mode = if full_history {
            HistoryMode::FullHistory
        } else {
            HistoryMode::ForwardOnly
        };
        let grant = issue_consent_grant(
            signer,
            &self.channel_id,
            self.epoch,
            target,
            delivered_skdm,
            history_mode,
        )?;
        // **Not `delivered` yet** (V210-88). Recorded here, in the grant's transaction, a crash
        // after the commit and before `target` took the key left a node that believed it had
        // delivered a key the member never held: nothing owed it again, and the member read
        // nothing from this identity for good. Until it is taken, the consenter is owed a re-key
        // like any other, which releases from its entitlement, committed below with the grant.
        //
        // An entitlement already held (an earlier consent never revoked) stands: both were
        // decided, and the earlier one released what it released.
        let mut entitled = self.entitled.clone();
        let from = entitled
            .get(&target)
            .map_or(entitled_from, |e| (*e).min(entitled_from));
        entitled.insert(target, from);
        // The generations before the key's own that the decision covers (V210-45), owed as
        // history: in the same transaction, or a crash between the two lost them.
        // As `owe_history`: only generations before the live one, and the oldest floor stands.
        let floor = entitled_from.0;
        let history_owed = floor < delivered_skdm.body.chain_id && floor < self.sender.chain_id();
        let mut history = self.history.clone();
        let history_changed = history_owed && history.get(&target).is_none_or(|f| *f > floor);
        if history_changed {
            history.insert(target, floor);
        }
        // **One transaction** with the grant (V210-76). Written one after another, a crash after
        // the grant left no `entitled` row, so the re-key it was owed released the live
        // generation from its origin: the posts sealed before the consent.
        let mut rows = vec![(
            SEG_ENTITLED,
            seal_segment(
                &self.sek,
                SegmentKind::KeyMaterial,
                SEG_ENTITLED,
                &positions_bytes(&entitled),
            )?,
        )];
        if history_changed {
            rows.push((
                SEG_HISTORY,
                seal_segment(
                    &self.sek,
                    SegmentKind::KeyMaterial,
                    SEG_HISTORY,
                    &delivered_bytes(&history),
                )?,
            ));
        }
        self.append_governance_with(profile, &grant.to_wire(), now_ms, &rows)?;
        self.entitled = entitled;
        self.history = history;
        Ok((grant, history_owed))
    }

    /// Whether this identity's sender key has reached its scheduled-rotation bound
    /// (ADR-006: `N` messages or `T` elapsed). The caller rotates with
    /// [`ChannelState::rotate_sender`] and re-keys whoever is
    /// [`owed`](ChannelState::owed_rekeys).
    #[must_use]
    pub fn should_rotate_sender(&self, now: crate::time::Ms) -> bool {
        let now_ms = now.get();
        self.sender.should_rotate(now_ms)
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
    pub fn rotate_sender(&mut self, profile: &Profile, now: crate::time::Ms) -> Result<u64> {
        let now_ms = now.get();
        let next = self.sender.rotated(now_ms)?;
        self.rotate_sender_to(profile, next, now_ms)
    }

    /// Move this identity to a sender generation above every one its own feed shows it used here,
    /// if it is not above them already (V210-164). Returns whether it moved.
    ///
    /// A node that joins a room its identity was in before — it left, or the profile is new —
    /// starts at generation 0, and the other members still hold this identity's old key under
    /// that number. They refuse a second key for a generation they hold, so nothing it sent would
    /// ever read. Its feed, once synced, says what it used: each message's header names its
    /// generation, a revocation the one it moved to, and a presence statement the one it was on.
    pub fn catch_up_generation(&mut self, profile: &Profile, now: crate::time::Ms) -> Result<bool> {
        let now_ms = now.get();
        let me = self.me();
        let Some(feed) = self.dag.feed(&me).filter(|f| !f.is_empty()) else {
            return Ok(false);
        };
        // Sparse rotations publish their exact generation in the same Batch as a signed
        // Presence and key state. Initial generation is zero; each +1 rotation adds an
        // entry. Catch-up may jump to old seq+2, but adds its own entry atomically, so every
        // published generation remains <= its published sequence+1. Therefore seq+2 is
        // strictly fresh. A failed append cannot expose a silent new generation.
        if self.uses_sparse_history(profile.store())? {
            let used = feed.max_seq();
            if self.sender.chain_id() > used {
                return Ok(false);
            }
            let next_id = used
                .checked_add(2)
                .ok_or(Error::MalformedBundle("chain_id overflow"))?;
            let next = SenderChain::new(&self.channel_id, self.epoch, &me, next_id, now_ms)?;
            self.rotate_sender_to(profile, next, now_ms)?;
            return Ok(true);
        }
        // Generation 0 was this identity's first here whatever its feed shows.
        let mut used = 0u64;
        let entries = self
            .entries
            .read(profile.store(), &self.sek, &self.channel_id)?;
        for entry in feed.iter(&entries) {
            let entry = entry?;
            let Some(payload) = entry.payload.as_deref() else {
                continue;
            };
            let chain = match classify_payload(payload) {
                Ok(EntryKind::Content) => GroupMessage::from_wire(payload)
                    .ok()
                    .filter(|m| m.header.channel_id == self.channel_id)
                    .map(|m| m.header.chain_id),
                Ok(EntryKind::Governance) => match GovBody::parse_framed(payload) {
                    Ok(GovBody::Presence(p)) => Some(p.body.chain_id),
                    Ok(GovBody::ConsentRevocation(r)) => Some(r.body.new_chain_id),
                    _ => None,
                },
                Ok(EntryKind::Checkpoint) | Err(_) => None,
            };
            used = used.max(chain.unwrap_or(0));
        }
        drop(entries);
        if self.sender.chain_id() > used {
            return Ok(false);
        }
        let next_id = used
            .checked_add(1)
            .ok_or(Error::MalformedBundle("chain_id overflow"))?;
        let next = SenderChain::new(&self.channel_id, self.epoch, &me, next_id, now_ms)?;
        self.rotate_sender_to(profile, next, now_ms)?;
        Ok(true)
    }

    /// Make `next` this identity's sender generation: see [`Self::rotate_sender`].
    fn rotate_sender_to(
        &mut self,
        profile: &Profile,
        next: SenderChain,
        now_ms: u64,
    ) -> Result<u64> {
        self.rotate_sender_to_checked(profile, next, now_ms, false)
    }

    /// The narrowing path may retain extra history while consent replay is pending;
    /// it never authorizes a key release from that incomplete state.
    fn rotate_sender_to_checked(
        &mut self,
        profile: &Profile,
        next: SenderChain,
        now_ms: u64,
        narrowing: bool,
    ) -> Result<u64> {
        self.rotate_sender_with_presence(profile, next, now_ms, narrowing, false, false)
    }

    fn rotate_sender_with_presence(
        &mut self,
        profile: &Profile,
        next: SenderChain,
        now_ms: u64,
        narrowing: bool,
        settle_sparse: bool,
        recover_own: bool,
    ) -> Result<u64> {
        self.require_legacy_current(profile.store())?;
        if self.poisoned {
            return Err(self.save_failure());
        }
        let store = profile.store();
        let sparse = self.uses_sparse_history(store)?;
        if settle_sparse && (!sparse || self.settled) {
            return Err(Error::MalformedBundle("sender settlement state differs"));
        }
        let chain_id = next.chain_id();
        let me = self.me();
        let retired = self.sender.chain_id();
        // **A generation retired before a reader took it is owed to that reader as history.**
        // A member entitled to it that has not taken it — offline at the rotation, or refusing
        // keys from an owner it does not trust yet (V210-118) — was owed it only as the live
        // generation's re-key, which a rotation ends. Nothing owed it any more, so the next tick's
        // prune (R14) deleted its origin before the member's refusal of the new key could owe it
        // again, and the member never read what this identity wrote under it. Owed here, its
        // history floor keeps it (`oldest_generation_needed`) until it is taken.
        // Who may read this identity, from the room's facts in memory (FX-22); while they are
        // refreshing and the lock narrows, every entitled member is kept.
        let readers: Option<BTreeSet<Digest32>> = match self.with_consent_facts(|facts| {
            self.entitled
                .keys()
                .filter(|t| facts.can_read(t, &me))
                .copied()
                .collect()
        }) {
            Ok(readers) => Some(readers),
            Err(error) if narrowing && governance::refreshing(&error) => None,
            Err(error) => return Err(error),
        };
        let mut owed = Vec::new();
        for t in self.entitled.keys().copied() {
            if t == me
                || self.has_left(&t)
                || !readers.as_ref().is_none_or(|readers| readers.contains(&t))
            {
                continue;
            }
            let Some((from, _)) = self.entitled.get(&t) else {
                continue;
            };
            let floor = match self.delivered.get(&t) {
                None => *from,
                Some(d) if *d < retired => (*d + 1).max(*from),
                Some(_) => continue,
            };
            if floor <= retired {
                owed.push((t, floor));
            }
        }
        // The mint's place in the consent order, persisted before the generation exists
        // (V210-45): a value is never handed out twice, so no later decision can tie it.
        let mint_seq = crate::node::consent_order::stamp_mint(
            store,
            profile.signer()?,
            self.newest_mint_seq(),
        )?;
        let mut candidate_origins = if sparse {
            Some(OriginKeyStore::from_state(&self.origins.to_state())?)
        } else {
            None
        };
        retain_generation(
            candidate_origins.as_mut().unwrap_or(&mut self.origins),
            &self.channel_id,
            self.epoch,
            &me,
            &next,
            now_ms,
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
            &candidate_origins
                .as_ref()
                .unwrap_or(&self.origins)
                .to_state(),
        )?;
        if let Some(origins) = candidate_origins {
            // This is a public control, not encrypted content. It names `next` explicitly;
            // self.sender/origins remain unchanged until the ordinary effects Batch commits.
            let here = settle_sparse || !self.said_left(&me);
            let statement = crate::governance::presence::Presence::build(
                profile.signer()?,
                &self.channel_id,
                self.epoch,
                here,
                chain_id,
            )?;
            self.append_governance_with_sender(
                profile,
                &statement.to_wire(),
                now_ms,
                &[(SEG_SENDER, sender_seg), (SEG_ORIGINS, origins_seg)],
                settle_sparse,
                Some((next, origins)),
                settle_sparse,
                recover_own,
            )?;
        } else {
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
                self.save_error = Some(e.to_string());
                return Err(e);
            }
            self.sender = next;
        }
        for (target, floor) in owed {
            self.owe_history(store, target, floor)?;
        }
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
        self.require_legacy_current(profile.store())?;
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.current_governance(profile.store())?;
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

    /// Record that `target` refused generation `chain_id` of this identity's sender key, so it
    /// is [`owed`](ChannelState::owed_rekeys) again. A later generation it did take stays recorded.
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
        // **Generation 0 is recorded too** (V210-95). Defaulting a missing row to 0 and comparing
        // made a taken generation-0 key look recorded already: it was held in memory and never
        // written, so after a restart the member was owed the room's first key again.
        if self.delivered.get(&target).is_some_and(|d| *d >= chain_id) {
            return Ok(());
        }
        self.delivered.insert(target, chain_id);
        self.persist_delivered(store)
    }

    /// Whether this identity has consented to `target` reading it here.
    ///
    /// Read off the log through its sealed current facts: a revocation
    /// changes the answer because the log says so. This is what tells a keyring
    /// removal which rooms it actually has to change the lock in (ADR-020 §3) —
    /// rotating in a room where nothing was ever granted would be noise.
    pub fn has_consented(&self, _store: &Store, target: &Digest32) -> Result<bool> {
        let me = self.me();
        self.with_consent_facts(|facts| facts.can_read(target, &me))
    }

    /// Page through admitted members this identity currently consents to, from the same
    /// in-memory projection as [`Self::has_consented`]. Sender-key delivery uses this bounded
    /// page on its periodic retry; it must not reopen and decrypt the sealed governance index
    /// every second while that projection already stands current. Explicit governance queries
    /// and trust narrowing retain sealed pagination because they must include off-roster targets.
    pub(crate) fn consented_member_page(
        &self,
        after: Option<Digest32>,
        limit: usize,
    ) -> Result<GovernanceTargets> {
        use std::ops::Bound::{Excluded, Unbounded};

        let me = self.me();
        self.with_consent_facts(|facts| {
            let mut cursor = after;
            let mut targets = Vec::new();
            for _ in 0..limit.clamp(1, governance::PAGE_ROWS) {
                let Some(target) = self
                    .authors
                    .range((cursor.map_or(Unbounded, Excluded), Unbounded))
                    .next()
                    .map(|(target, _)| *target)
                else {
                    return GovernanceTargets {
                        targets,
                        next: None,
                    };
                };
                cursor = Some(target);
                if facts.can_read(&target, &me) {
                    targets.push(target);
                }
            }
            GovernanceTargets {
                targets,
                next: cursor,
            }
        })
    }

    /// **Who trusts each member here** (ADR-028 K-7): for every member some other member consents
    /// to reading it, those other members, off the log like [`Self::consent_page`]. This
    /// identity's own entry is who consents to it reading them, the inbound half of `consented`
    /// (V030-17). A consent grant is what a member's node writes once its owner trusts the other (ADR-007
    /// G-9), so this is what a client says of a newcomer: which members already trust it.
    pub fn trusted_by(&self, _store: &Store) -> Result<BTreeMap<Digest32, BTreeSet<Digest32>>> {
        let members = self.members();
        self.with_consent_facts(|facts| {
            let mut by: BTreeMap<Digest32, BTreeSet<Digest32>> = BTreeMap::new();
            for author in &members {
                for reader in &members {
                    if reader != author && facts.can_read(reader, author) {
                        by.entry(*reader).or_default().insert(*author);
                    }
                }
            }
            by
        })
    }

    /// The admitted-member consent projection. The common path is only this mutex and an Arc
    /// clone: it opens and decrypts no segment, including the governance header. A restart or a
    /// newly admitted member returns refreshing until bounded governance turns reconstruct it.
    fn consent_facts(&self) -> Result<std::sync::Arc<governance::ConsentFacts>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        if !self.governance_ready {
            return Err(Error::Profile(governance::REFRESHING));
        }
        let held = self
            .consent_facts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &*held {
            ConsentFactsState::Ready(facts) => Ok(std::sync::Arc::clone(facts)),
            ConsentFactsState::Building(_) => Err(Error::Profile(governance::REFRESHING)),
        }
    }

    /// Apply one newly indexed current-input fact to the in-memory projection. During a restart
    /// build, fold it into the partial result instead of resetting the cursor: pairs not yet
    /// inspected will read the committed slot later, while already-inspected pairs retain the
    /// newer authenticated sequence observed here.
    fn note_committed_consent(&self, entry: &Entry) -> Result<()> {
        let Ok(fact) = GovEntry::body_bound_to(entry) else {
            return Ok(());
        };
        let Some(author_key) = self.authors.get(&entry.skeleton.author_id) else {
            return Ok(());
        };
        // Keep this mirror on exactly the same authenticated input as the sealed current-input
        // index. `accepted_into` deliberately ignores malformed legacy statements; they must not
        // gain authority merely because their outer entry was publishable.
        if fact.verify(author_key).is_err() {
            return Ok(());
        }
        let relevant = match &fact {
            GovBody::ConsentGrant(grant) => {
                self.authors.contains_key(&entry.skeleton.author_id)
                    && self.authors.contains_key(&grant.body.target_id)
            }
            GovBody::ConsentRevocation(revoke) => {
                self.authors.contains_key(&entry.skeleton.author_id)
                    && self.authors.contains_key(&revoke.body.target_id)
            }
            GovBody::Presence(_) => self.authors.contains_key(&entry.skeleton.author_id),
            _ => false,
        };
        if !relevant {
            return Ok(());
        }
        let mut held = self
            .consent_facts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &mut *held {
            ConsentFactsState::Ready(facts) => {
                std::sync::Arc::make_mut(facts).observe(
                    entry.skeleton.author_id,
                    entry.skeleton.seq,
                    &fact,
                );
            }
            ConsentFactsState::Building(build) => {
                build
                    .facts
                    .observe(entry.skeleton.author_id, entry.skeleton.seq, &fact);
            }
        }
        Ok(())
    }

    /// Examine at most one production governance page of admitted author/target pairs. Returns
    /// true only when the restart/admission rebuild is complete.
    fn advance_consent_facts(&self, view: &governance::View<'_>) -> Result<bool> {
        let mut held = self
            .consent_facts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let ConsentFactsState::Building(build) = &mut *held else {
            return Ok(true);
        };
        let current_members: Vec<Digest32> = self.authors.keys().copied().collect();
        if build.members != current_members {
            *build = ConsentFactsBuild::new(&self.authors);
        }
        let mut examined = 0usize;
        while build.author < build.members.len() && examined < governance::PAGE_ROWS {
            let author = build.members[build.author];
            if build.target == 0 {
                build.facts.set_reset(author, view.consent_reset(&author)?);
            }
            let target = build.members[build.target];
            build
                .facts
                .set_consent(author, target, view.consent_state(&author, &target)?);
            build
                .facts
                .set_ever_revoked(author, target, view.ever_revoked(&author, &target)?);
            examined += 1;
            build.target += 1;
            if build.target == build.members.len() {
                build.author += 1;
                build.target = 0;
            }
        }
        if build.author != build.members.len() {
            return Ok(false);
        }
        let facts = std::mem::take(&mut build.facts);
        *held = ConsentFactsState::Ready(std::sync::Arc::new(facts));
        Ok(true)
    }

    /// One consent question answered from [`Self::consent_facts`].
    fn with_consent_facts<T>(&self, f: impl FnOnce(&governance::ConsentFacts) -> T) -> Result<T> {
        let facts = self.consent_facts()?;
        Ok(f(&facts))
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
    pub fn owed_consents(
        &self,
        _store: &Store,
        trusted: &BTreeSet<Digest32>,
    ) -> Result<BTreeSet<Digest32>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        if !self.settled {
            return Ok(BTreeSet::new());
        }
        let me = self.me();
        self.with_consent_facts(|facts| {
            let mut owed = BTreeSet::new();
            for author in self.authors.keys() {
                if *author != me
                    && !self.has_left(author)
                    && trusted.contains(author)
                    && !facts.can_read(author, &me)
                {
                    owed.insert(*author);
                }
            }
            owed
        })
    }

    /// The members this identity has consented to that do not yet hold its current
    /// generation — who a rotation still owes a re-key.
    ///
    /// Derived from the consent set on the log and the delivery ledger, never stored:
    /// a revoked member drops out because the log says so, not because a cached list
    /// was updated. A consenter with no ledger row counts as owed; re-delivering a
    /// generation it already holds is ignored by
    /// [`ChannelState::accept_skdm`], so the safe direction is to send.
    pub fn owed_rekeys(
        &self,
        _store: &Store,
        after: Option<Digest32>,
    ) -> Result<GovernanceTargets> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        if !self.settled {
            return Ok(GovernanceTargets {
                targets: Vec::new(),
                next: None,
            });
        }
        let me = self.me();
        let current = self.sender.chain_id();
        let mut page = self.consented_member_page(after, 64)?;
        page.targets.retain(|target| {
            *target != me
                && !self.has_left(target)
                && self
                    .delivered
                    .get(target)
                    .is_none_or(|held| *held < current)
        });
        Ok(page)
    }

    /// Check a single delivery target without collecting the room's consent page.
    pub fn owed_rekey(&self, store: &Store, target: &Digest32) -> Result<bool> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        if !self.settled || *target == self.me() || self.has_left(target) {
            return Ok(false);
        }
        Ok(self.has_consented(store, target)?
            && self
                .delivered
                .get(target)
                .is_none_or(|held| *held < self.sender.chain_id()))
    }

    /// Whether `target` is still owed this identity's current generation or any entitled
    /// historical generation. This is the durable half of the shipped delivery status; the node
    /// adds work currently admitted or in flight before reporting it.
    pub(crate) fn key_delivery_pending(&self, store: &Store, target: &Digest32) -> Result<bool> {
        Ok(self.owed_rekey(store, target)? || self.owed_history_for(store, target)?.is_some())
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
        now: crate::time::Ms,
    ) -> Result<ConsentRevocation> {
        let me = self.me();
        if target == me {
            return Err(Error::MalformedGovernance(
                "an identity cannot withdraw trust in itself",
            ));
        }
        if !self.has_consented(profile.store(), &target)? {
            return Err(Error::MalformedGovernance("no trust to withdraw"));
        }
        self.revoke_consent_checked(profile, target, now, false)
    }

    /// A local trust withdrawal narrows access even while old consent facts replay.
    /// A known absent consent is a no-op; unreadable/corrupt storage remains an error.
    pub fn withdraw_consent(
        &mut self,
        profile: &Profile,
        target: Digest32,
        now: crate::time::Ms,
    ) -> Result<Option<ConsentRevocation>> {
        if target == self.me() {
            return Err(Error::MalformedGovernance(
                "an identity cannot withdraw trust in itself",
            ));
        }
        match self.has_consented(profile.store(), &target) {
            Ok(false) => return Ok(None),
            Ok(true) => {}
            Err(error) if governance::refreshing(&error) => {}
            Err(error) => return Err(error),
        }
        self.revoke_consent_checked(profile, target, now, true)
            .map(Some)
    }

    fn revoke_consent_checked(
        &mut self,
        profile: &Profile,
        target: Digest32,
        now: crate::time::Ms,
        narrowing: bool,
    ) -> Result<ConsentRevocation> {
        let now_ms = now.get();
        // Rotate first: the entry names the generation that excludes `target`, so
        // that generation has to exist before the fact is signed.
        let next = self.sender.rotated(now_ms)?;
        let new_chain_id = self.rotate_sender_to_checked(profile, next, now_ms, narrowing)?;
        let signer = profile.signer()?;
        let revocation =
            issue_consent_revocation(signer, &self.channel_id, self.epoch, target, new_chain_id)?;
        self.append_governance(profile, &revocation.to_wire(), now_ms)?;
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
    /// re-key round delivers it again (ADR-004 O4).
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
            Some(prepared) => {
                if let Err(e) = store.put_segment(
                    &self.channel_id,
                    SegmentKind::KeyMaterial,
                    SEG_TRUST_MARKS,
                    &prepared.sealed,
                ) {
                    self.poisoned = true;
                    self.save_error = Some(e.to_string());
                    return Err(e);
                }
                self.install_trust_mark(prepared);
                Ok(())
            }
        }
    }

    /// [`Self::mark_trust`] without writing or changing this room's live marks: the next marks,
    /// sealed under this room's SEK, for the caller to write with every other room's in **one**
    /// commit ([`Self::queue_marks`]), or `None` when this room already holds the mark. The caller
    /// installs the prepared mark only after that commit succeeds.
    ///
    /// A trust decision marks every open room, and one commit per room made `vox trust add` cost
    /// a durable commit for each: about 7 s on the node's actor at 1,600 rooms (#189). A caller
    /// whose real storage commit fails must [`Self::poison`] each room it sealed for, as a failed
    /// write here always has. Refusal by an external policy fence writes nothing and is not room
    /// corruption.
    ///
    /// # Errors
    /// The room holds [`AUTHORS_HARD_LIMIT`] marks already, or the marks cannot be sealed.
    pub fn mark_trust_sealed(
        &self,
        target: Digest32,
        decision: Stamp,
    ) -> Result<Option<PreparedTrustMark>> {
        if self
            .trust_marks
            .get(&target)
            .is_some_and(|m| m.0 == decision)
        {
            return Ok(None);
        }
        if !self.trust_marks.contains_key(&target) && self.trust_marks.len() >= AUTHORS_HARD_LIMIT {
            return Err(Error::SizeLimitExceeded("trust marks"));
        }
        let position = (
            decision,
            self.sender.chain_id(),
            self.sender.current_position().0,
        );
        let mut next = self.trust_marks.clone();
        next.insert(target, position);
        let bytes = marks_bytes(&next);
        let sealed = seal_segment(&self.sek, SegmentKind::KeyMaterial, SEG_TRUST_MARKS, &bytes)?;
        Ok(Some(PreparedTrustMark {
            target,
            position,
            sealed,
        }))
    }

    /// Install exactly the mark whose sealed segment committed successfully. No other task writes
    /// trust marks: the node actor serializes their preparation and installation, while room work
    /// may hold the room lock without changing this projection.
    pub fn install_trust_mark(&mut self, prepared: PreparedTrustMark) {
        self.trust_marks.insert(prepared.target, prepared.position);
    }

    /// Queue `channel_id`'s sealed marks ([`Self::mark_trust_sealed`]) into `batch`.
    ///
    /// # Errors
    /// The write cannot be queued.
    pub fn queue_marks(
        batch: &mut crate::node::store::Batch<'_>,
        channel_id: &Digest32,
        prepared: &PreparedTrustMark,
    ) -> Result<()> {
        batch.put_segment(
            channel_id,
            SegmentKind::KeyMaterial,
            SEG_TRUST_MARKS,
            &prepared.sealed,
        )
    }

    /// Mark this room poisoned after a real storage or consistency failure.
    /// Pending governance or subtype replay is retryable and keeps the last good display.
    pub fn poison(&mut self, e: &Error) {
        // A refusal is not a storage fault: a room whose own history is behind (ADR-037 R5) or
        // that has not synced yet refuses writes and goes on serving. Poisoning it turned every
        // later command into "cannot save", wrapped the refusal once more per attempt ("store
        // save room: store save room: …") and said it on every refusal, where the detector had
        // already said it once. A history worker this node's actor cancelled (its ask was
        // replaced, paused or stopped) was stopped, not failed.
        if matches!(
            e,
            Error::Profile(legacy_provisional::LEGACY_HISTORY_REQUIRED)
                | Error::Profile(crate::node::history_demand::CANCELLED)
                | Error::OwnHistoryBehind
                | Error::RoomNotSynced
        ) || governance::refreshing(e)
            || Self::legacy_classification_refreshing(e)
            || Self::authorization_refreshing(e)
        {
            return;
        }
        self.poisoned = true;
        // The original cause survives every later refusal (`save_failure`); never wrap it in
        // itself.
        if self.save_error.is_none() {
            self.save_error = Some(e.to_string());
        }
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
    pub fn history_plan(
        &self,
        _store: &Store,
        target: &Digest32,
        decision: Option<Stamp>,
    ) -> Result<Option<Vec<(u64, u64)>>> {
        let Some(decision) = decision else {
            return Ok(None);
        };
        let me = self.me();
        if self.with_consent_facts(|facts| facts.ever_revoked(&me, target))? {
            return Ok(None);
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
        Ok((!plan.is_empty()).then_some(plan))
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
        self.require_legacy_current(profile.store())?;
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.current_governance(profile.store())?;
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
        self.require_legacy_current(profile.store())?;
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.current_governance(profile.store())?;
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

    /// The oldest generation this one current consenter is still owed.
    pub fn owed_history_for(&self, _store: &Store, target: &Digest32) -> Result<Option<u64>> {
        let me = self.me();
        if *target == me
            || self.has_left(target)
            || !self.with_consent_facts(|facts| facts.can_read(target, &me))?
        {
            return Ok(None);
        }
        Ok(self.history.get(target).copied())
    }

    /// Inspect at most 64 history-ledger slots. An empty result with a next cursor
    /// still has work; revoked and departed targets consume an inspected slot.
    pub fn owed_history_page(
        &self,
        _store: &Store,
        after: Option<Digest32>,
    ) -> Result<(BTreeMap<Digest32, u64>, Option<Digest32>)> {
        use std::ops::Bound::{Excluded, Unbounded};
        let me = self.me();
        let facts = self.consent_facts()?;
        let mut owed = BTreeMap::new();
        let mut slots = self
            .history
            .range((after.map_or(Unbounded, Excluded), Unbounded));
        let mut next = None;
        for _ in 0..64 {
            let Some((target, floor)) = slots.next() else {
                return Ok((owed, None));
            };
            next = Some(*target);
            if *target != me && !self.has_left(target) && facts.can_read(target, &me) {
                owed.insert(*target, *floor);
            }
        }
        Ok((owed, next))
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
        self.require_legacy_current(profile.store())?;
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.current_governance(profile.store())?;
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
            self.save_error = Some(e.to_string());
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
        let saved = (|| -> Result<()> {
            let mut batch = store.batch()?;
            batch.put_segment(&self.channel_id, SegmentKind::KeyMaterial, SEG_FORKS, &seg)?;
            let mut index = self
                .entries
                .write(&mut batch, &self.sek, &self.channel_id)?;
            for proof in &proofs {
                index.resolve_legacy_required_invalid(&proof.author_id, proof.seq);
            }
            index.seal()?;
            batch.commit()
        })();
        if let Err(e) = saved {
            self.poisoned = true;
            self.save_error = Some(e.to_string());
            return Err(e);
        }
        self.entries.committed();
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
            self.save_error = Some(e.to_string());
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
            self.save_error = Some(e.to_string());
            return Err(e);
        }
        Ok(())
    }

    /// The room's retention, seconds (`0` = forever): the ADR-007 policy-update `ttl` in
    /// force in the last completely published governance display.
    #[must_use]
    pub fn room_retention(&self) -> u64 {
        self.governance_display.policy.ttl_ms / 1_000
    }

    /// Whether `member` sets this room's retention: its creator, or an admin it named — a holder
    /// of the `policy` capability (V030-32). Anyone else sets only their own node's.
    pub fn governs_retention(
        &self,
        store: &Store,
        member: &Digest32,
        now: crate::time::Ms,
    ) -> Result<bool> {
        self.grants_policy(store, member, now.get())
    }

    /// What this node's log has caught in the room: the authors it froze for a fork, and how
    /// many entries it refused as at or below their author's checkpoint (ADR-008, ADR-023
    /// decision 3). What `vox status` reports.
    #[must_use]
    pub fn fork_watch(&self) -> (Vec<Digest32>, u64) {
        (
            self.dag.frozen_authors(),
            self.dag.refused_below_checkpoint(),
        )
    }

    /// The retention this node applies to the room: the shorter of the room's and its own
    /// (ADR-023 decision 2, PRD-001 R9). `0` is forever.
    #[must_use]
    pub fn effective_retention(&self) -> u64 {
        crate::node::retention::shortest(self.room_retention(), self.node_retention)
    }

    /// Configured room policy for Session activity; defaults to seven days.
    pub fn room_step_retention(&self) -> u64 {
        self.governance_display.step_ttl_ms / 1_000
    }

    /// Activity never outlives messages, including this node's shorter message rule.
    pub fn effective_step_retention(&self) -> u64 {
        crate::node::retention::shortest(
            self.effective_retention(),
            crate::node::retention::shortest(self.room_step_retention(), self.node_step_retention),
        )
    }

    /// Explicit local Session rule, or no local limit.
    pub fn local_step_retention(&self) -> Option<u64> {
        (self.node_step_retention != 0).then_some(self.node_step_retention)
    }

    /// Apply the node's Session rule before its next sync or sweep.
    pub fn set_node_step_retention(&mut self, store: &Store, seconds: u64) -> Result<()> {
        self.node_step_retention = seconds;
        if self.legacy_cache_only(store)? {
            return Ok(());
        }
        self.forget_settled_owed(store)
    }

    /// Floor controls carry durable authorization, like governance: neither message nor
    /// Session activity expiry may erase the evidence another reader needs after a restart.
    fn entry_retention(&self, transaction: Transaction<'_, '_>, entry: &Entry) -> Result<u64> {
        if entry.payload.as_deref().is_some_and(retained_control) {
            return Ok(0);
        }
        Ok(if self.entry_steps_in(transaction, entry)? {
            self.effective_step_retention()
        } else {
            self.effective_retention()
        })
    }

    /// Exact saved Session subtype, including the first-seen fact retained after pruning.
    pub(super) fn entry_steps_in(
        &self,
        transaction: Transaction<'_, '_>,
        entry: &Entry,
    ) -> Result<bool> {
        let hash = entry.entry_hash();
        let index = self
            .entries
            .view(transaction, &self.sek, &self.channel_id)?;
        Ok(if let Some(tracked) = index.retention(&hash)? {
            tracked.steps
        } else if let Some(body) = entry.payload.as_deref() {
            is_step_body(&self.channel_id, body)
        } else {
            // Retention removes its own row but keeps this sealed first-seen subtype fact
            // beside the log. A body never received has no log page and no such fact: it is
            // not a Session step this node knows of, and the message lifetime (the longer one)
            // applies; a disk error below is still an error. Measured 2026-10-20 on the
            // decider's node (ADR-038 FX-33): a sweep poisoned the room with "retention entry
            // missing" over an owed entry of a sparse room.
            let Some(log) = index.log_id(&hash)? else {
                return Ok(false);
            };
            let segment = match transaction {
                Transaction::Snapshot(snapshot) => {
                    snapshot.get_segment(&self.channel_id, SegmentKind::Index, log)?
                }
                Transaction::Batch(batch) => {
                    batch.get_segment(&self.channel_id, SegmentKind::Index, log)?
                }
            };
            match segment {
                Some(segment) => {
                    parse_first_seen(&open_segment(&self.sek, SegmentKind::Index, log, &segment)?)?
                        .1
                }
                None => false,
            }
        })
    }

    /// `(this node's own retention, the room's)` when the node's own asks to keep messages longer
    /// than the room does (V030-32): ignored, since a member may keep less than its room, never
    /// more. `None` otherwise.
    #[must_use]
    pub fn retention_above_room(&self) -> Option<(u64, u64)> {
        let (node, room) = (self.node_retention, self.room_retention());
        (node != 0 && room != 0 && node > room).then_some((node, room))
    }

    /// Set this node's own retention for the room (from its config; `0` = no node limit).
    /// Takes effect at the next [`ChannelState::sweep_retention`].
    pub fn set_node_retention(&mut self, store: &Store, secs: u64) -> Result<()> {
        self.node_retention = secs;
        if self.legacy_cache_only(store)? {
            return Ok(());
        }
        self.forget_settled_owed(store)
    }

    /// Whether an entry claimed at `claimed_ms` has expired here by `now_ms`: past this node's
    /// effective retention (the room's, or its own shorter one). **The receiver's own reckoning**
    /// (V030-10): from the author's signed claim, never from what a peer did or did not send.
    #[must_use]
    pub fn body_expired(&self, claimed_ms: u64, now: crate::time::Ms) -> bool {
        let now_ms = now.get();
        self.governance_display_current(now_ms)
            && expired_at(claimed_ms, now_ms, self.effective_retention())
    }

    /// Examine at most 64 missing positions per turn, removing settled recovery work in
    /// the same transaction as its placeholder. The cursor advances over retained positions too.
    fn forget_settled_owed(&mut self, store: &Store) -> Result<()> {
        let result = (|| -> Result<()> {
            let mut batch = store.batch()?;
            let mut writer = self
                .entries
                .write(&mut batch, &self.sek, &self.channel_id)?;
            let (positions, next) =
                writer.missing_page(self.projection_state.cleanup_cursor, 64)?;
            let mut changed = false;
            for (author, seq) in positions {
                let entry = writer.get(&author, seq)?;
                let keep = match entry.as_ref() {
                    Some(e) => {
                        e.payload.is_none()
                            && !self.private_contains_in(writer.batch(), &e.entry_hash())?
                            && !(self.governance_display_current(self.now_hint)
                                && expired_at(
                                    e.skeleton.claimed_ms,
                                    self.now_hint,
                                    self.entry_retention(Transaction::Batch(writer.batch()), e)?,
                                ))
                    }
                    None => false,
                };
                if !keep {
                    if let Some(entry) = entry {
                        writer.set_owed(entry.entry_hash(), None)?;
                    }
                    changed |= writer.set_missing(&author, seq, false)?;
                }
            }
            if changed {
                writer.seal()?;
                batch.commit()?;
                self.entries.committed();
                self.invalidate_display();
            }
            self.projection_state.cleanup_cursor = next;
            Ok(())
        })();
        if let Err(ref error) = result {
            self.poison(error);
        }
        result
    }

    /// Ask for at most MAX_OWED_ASKED bodies after examining at most 256 missing positions.
    /// Advance past every examined position, including frozen, expired and unreachable ones;
    /// wrap once to the start without revisiting positions from this same call.
    pub fn owed_wants(
        &mut self,
        store: &Store,
        remote: &[crate::log::sync::FeedFrontier],
        wants: &[crate::log::sync::WantRange],
    ) -> Result<Vec<crate::log::sync::WantRange>> {
        self.forget_settled_owed(store)?;
        let entries = self.entries.read(store, &self.sek, &self.channel_id)?;
        let mut out: Vec<crate::log::sync::WantRange> = Vec::new();
        let mut asked = 0usize;
        let mut examined = 0usize;
        let start = self.owed_asked_to;
        let mut after = start;
        let mut wrapped = false;
        'scan: while examined < 256 && asked < MAX_OWED_ASKED {
            let (positions, next) = entries.missing_page(after, 256 - examined)?;
            for (author, seq) in positions {
                if wrapped && start.is_some_and(|start| (author, seq) > start) {
                    break 'scan;
                }
                examined += 1;
                self.owed_asked_to = Some((author, seq));
                // Not of a frozen author, nor beyond a refused feed suffix (ADR-025 D3).
                if self.dag.is_frozen(&author)
                    || self
                        .dag
                        .refused_from(&author)
                        .is_some_and(|from| seq >= from)
                    || !remote
                        .iter()
                        .any(|f| f.author_id == author && f.max_seq >= seq)
                    || !wants
                        .iter()
                        .filter(|w| w.author_id == author)
                        .all(|w| seq < w.from_seq)
                {
                    continue;
                }
                let entry = entries
                    .get(&author, seq)?
                    .ok_or(Error::MalformedAtRest("missing-body entry missing"))?;
                // Cleanup has its own small budget. Recheck every requested position so a
                // settled position beyond that cleanup page is never asked for again.
                if entry.payload.is_some()
                    || self.private_id(store, &entry.entry_hash())?.is_some()
                    || (self.governance_display_current(self.now_hint)
                        && expired_at(
                            entry.skeleton.claimed_ms,
                            self.now_hint,
                            self.entry_retention(entries.transaction(), &entry)?,
                        ))
                {
                    continue;
                }
                asked += 1;
                match out.last_mut() {
                    Some(w) if w.author_id == author && w.to_seq.checked_add(1) == Some(seq) => {
                        w.to_seq = seq
                    }
                    _ => out.push(crate::log::sync::WantRange {
                        author_id: author,
                        from_seq: seq,
                        to_seq: seq,
                    }),
                }
                if asked == MAX_OWED_ASKED {
                    break 'scan;
                }
            }
            match next {
                Some(next) => after = Some(next),
                None if start.is_some() && !wrapped => {
                    after = None;
                    wrapped = true;
                }
                None => break,
            }
        }
        Ok(out)
    }

    fn invalidate_display(&mut self) {
        self.display_rewrite = self.display_rewrite.wrapping_add(1);
    }

    /// Compare the same sealed snapshot facts used to publish the candidate view. Expiry
    /// remains a wall-clock fence even when no entry or cache root changed meanwhile.
    pub(crate) fn display_is_current(&self, stamp: &DisplayStamp, current: &DisplayStamp) -> bool {
        stamp == current && stamp.expires_at.is_none_or(|at| self.now_hint < at)
    }

    /// Compact display invalidation facts, without collecting rendered rows or owed bodies.
    pub(crate) fn display_stamp(&self, store: &Store) -> Result<DisplayStamp> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        let rendered = self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?;
        let owed_count = rendered.owed_before(None)?;
        Ok(DisplayStamp {
            incarnation: self.gen.clone(),
            rewrite: self.display_rewrite,
            rendered_roots: rendered.display_roots(),
            rendered_count: rendered.count()?,
            order_revision: self.dag.reorder_generation(),
            body_revision: self.dag.body_generation(),
            session_revision: self.legacy_sessions.display_revision(),
            retention: (self.effective_retention(), self.effective_step_retention()),
            expires_at: rendered.next_owed_expiry()?,
            owed_count,
            owed: owed_count != 0,
        })
    }

    /// Set the **room's** retention (PRD-001 R7): append an ADR-007 policy-update carrying
    /// `ttl` seconds (`0` = forever). Only a holder of the `policy` capability may — the
    /// room's admin; anyone else is refused here rather than writing an entry every other
    /// node would ignore. It applies to what is already stored, at the next sweep (R8).
    /// Returns whether a different signed rule was appended; equal canonical rules are no-ops.
    pub fn set_retention(
        &mut self,
        profile: &Profile,
        ttl: u64,
        now: crate::time::Ms,
    ) -> Result<bool> {
        let now_ms = now.get();
        let signer = profile.signer()?;
        let me = signer.fingerprint();
        if !self.grants_policy(profile.store(), &me, now_ms)? {
            return Err(Error::MalformedGovernance(
                "only the room's admin may set its retention",
            ));
        }
        drop(self.local_append_eligible_for(profile.store(), false)?);
        self.ensure_governance_append_eligible(profile, false)?;
        let ttl_ms = ttl.saturating_mul(1_000);
        // Read the checked canonical rule, not the last display or a local TTL clamp.
        let current = self
            .checked_governance(profile.store(), now_ms)?
            .display(&self.genesis)?;
        if current.policy.ttl_ms == ttl_ms {
            return Ok(false);
        }
        let update = crate::governance::policy::PolicyUpdate::build(
            signer,
            &self.channel_id,
            self.epoch,
            ttl_ms,
        )?;
        self.append_governance(profile, &update.to_wire(), now_ms)?;
        Ok(true)
    }

    /// Set the shared Session retention without changing message retention.
    /// Returns whether a different signed rule was appended; equal canonical rules are no-ops.
    pub fn set_step_retention(
        &mut self,
        profile: &Profile,
        ttl: u64,
        now: crate::time::Ms,
    ) -> Result<bool> {
        let now_ms = now.get();
        let signer = profile.signer()?;
        let me = signer.fingerprint();
        if !self.grants_policy(profile.store(), &me, now_ms)? {
            return Err(Error::MalformedGovernance(
                "only the room's admin may set its Session retention",
            ));
        }
        drop(self.local_append_eligible_for(profile.store(), false)?);
        self.ensure_governance_append_eligible(profile, false)?;
        let ttl_ms = ttl.saturating_mul(1_000);
        // Read the checked canonical rule, not the last display or a local TTL clamp.
        let current = self
            .checked_governance(profile.store(), now_ms)?
            .display(&self.genesis)?;
        if current.step_ttl_ms == ttl_ms {
            return Ok(false);
        }
        let update = crate::governance::step_policy::StepPolicyUpdate::build(
            signer,
            &self.channel_id,
            self.epoch,
            ttl_ms,
        )?;
        self.append_governance(profile, &update.to_wire(), now_ms)?;
        Ok(true)
    }

    /// Prune one bounded due page, retaining signed skeletons. Repeated actor turns
    /// finish a backlog; unrelated rooms do not wait on a whole-history expiry sweep.
    pub fn sweep_retention(&mut self, store: &Store, now: crate::time::Ms) -> Result<usize> {
        let now_ms = now.get();
        self.now_hint = self.now_hint.max(now_ms);
        if self.legacy_cache_only(store)? {
            return Ok(0);
        }
        match self.require_governance_ready(store, now) {
            Ok(_) => {}
            Err(error) if governance::refreshing(&error) => return Ok(0),
            Err(error) => return Err(error),
        }
        if !self.governance_display_current(now_ms) {
            return Ok(0);
        }
        self.forget_settled_owed(store)?;
        self.refresh_projection(store)?;
        self.drain_backfill(store, now.get())?;
        if self.poisoned {
            return Ok(0);
        }
        let pruned =
            self.prune_retention_page(store)? + self.sweep_private_sessions(store, now.get())?;
        if pruned > 0 {
            self.last_pruned_at = now.get();
        }
        Ok(pruned)
    }

    fn retention_due(
        &self,
        store: &Store,
        limit: usize,
    ) -> Result<(Vec<(Digest32, Tracked)>, bool)> {
        self.entries
            .read(store, &self.sek, &self.channel_id)?
            .retention_due(
                self.now_hint,
                self.effective_retention(),
                self.effective_step_retention(),
                limit,
            )
    }
    fn prune_retention_page(&mut self, store: &Store) -> Result<usize> {
        let result = (|| -> Result<usize> {
            let (due, _) = self.retention_due(store, 64)?;
            if due.is_empty() {
                return Ok(0);
            }
            let pruned = self.prune(store, &due, false)?;
            if pruned != 0 {
                self.last_pruned_at = self.now_hint;
            }
            Ok(pruned)
        })();
        if let Err(ref error) = result {
            self.poison(error);
        }
        result
    }

    /// How long nothing new must have expired before a backlog smaller than
    /// [`CHECKPOINT_EVERY`] is checkpointed anyway (seconds). Set by the actor.
    pub fn set_checkpoint_idle(&mut self, secs: u64) {
        self.checkpoint_idle = secs;
    }

    /// Post a checkpoint on this identity's **own** feed when one is due (ADR-023 decision 3,
    /// [`crate::log::checkpoint`] for why only the author checkpoints its feed). Returns
    /// whether one was posted — a local append the caller pushes like any other.
    ///
    /// Due when the **room** keeps messages for a while (its retention is not forever; a
    /// node's own shorter limit does not make it the room's business), and either at least
    /// [`CHECKPOINT_EVERY`] more of this author's entries have expired here since its last
    /// checkpoint, or fewer have and nothing new has expired for the checkpoint idle time — a
    /// **closing** checkpoint, so no expired entry keeps its signature indefinitely.
    ///
    /// Cheap enough to ask on every tick: it looks only past the last checkpoint and stops at
    /// the first of this author's entries still holding a body. Asking every tick, not only
    /// after a prune, is what checkpoints a room opened with a backlog already expired (after a
    /// restart, or pruned while the room kept everything) without waiting for another prune. The position named is the highest one below which every content entry of
    /// this author has had its body pruned on this node; governance and earlier checkpoints
    /// keep their bodies and never hold it back.
    pub fn checkpoint_if_due(&mut self, profile: &Profile, now: crate::time::Ms) -> Result<bool> {
        let now_ms = now.get();
        if self.poisoned
            || !self.governance_display_current(now_ms)
            || (self.room_retention() == 0 && self.room_step_retention() == 0)
        {
            return Ok(false);
        }
        let me = profile.signer()?.fingerprint();
        let Some(feed) = self.dag.feed(&me) else {
            return Ok(false);
        };
        let mut below: Option<(u64, Digest32)> = None;
        let mut expired = 0usize;
        let already = self.dag.checkpoint(&me).map_or(0, |(s, _)| s);
        // Everything at or below the last checkpoint is already behind it.
        let entries = self
            .entries
            .read(profile.store(), &self.sek, &self.channel_id)?;
        for seq in already.saturating_add(1)..=feed.max_seq() {
            let Some(e) = feed.get(&entries, seq)? else {
                break;
            };
            match e.payload.as_deref() {
                None => {
                    below = Some((seq, e.entry_hash()));
                    expired += 1;
                }
                Some(p) if matches!(classify_payload(p), Ok(EntryKind::Content)) => break,
                Some(_) => {}
            }
        }
        drop(entries);
        let Some((seq, entry_hash)) = below else {
            return Ok(false);
        };
        let idle = now_ms.saturating_sub(self.last_pruned_at)
            >= self.checkpoint_idle.saturating_mul(1_000);
        if seq <= already || (expired < CHECKPOINT_EVERY && !idle) {
            return Ok(false);
        }
        let payload = crate::log::checkpoint::Checkpoint { seq, entry_hash }.to_wire();
        self.append_control(profile, &payload, now_ms)?;
        Ok(true)
    }

    /// Drop the signatures of every entry at or below its author's checkpoint whose body has
    /// expired here, and rewrite those pages (ADR-023 decision 3). Only in a room whose
    /// retention here is not forever: a room that keeps everything keeps its evidence too.
    /// Returns how many signatures were dropped.
    pub fn drop_checkpointed_signatures(&mut self, store: &Store) -> Result<usize> {
        if self.legacy_cache_only(store)? {
            return Ok(0);
        }
        match self.require_governance_ready(store, crate::time::Ms(self.now_hint)) {
            Ok(_) if self.governance_display_current(self.now_hint) => {}
            Ok(_) => return Ok(0),
            Err(error) if governance::refreshing(&error) => return Ok(0),
            Err(error) => return Err(error),
        }
        if self.poisoned
            || (self.effective_retention() == 0 && self.effective_step_retention() == 0)
        {
            return Ok(0);
        }
        // The actor asks every tick so a newly accepted checkpoint is handled promptly. Most
        // ticks have no new checkpoint range. Do not turn those no-ops into a durable database
        // commit: its synchronous fsync would park this room's actor and strand unrelated live
        // work (including a just-received key package).
        if !self.dag.checkpoint_signature_sweep_due() {
            return Ok(0);
        }
        let result = (|| -> Result<usize> {
            let mut batch = store.batch()?;
            let mut index = self
                .entries
                .write(&mut batch, &self.sek, &self.channel_id)?;
            index.committing(self.next_log_id);
            let dropped = self
                .dag
                .drop_checkpointed_signatures(&mut index, SIGNATURE_SWEEP_PAGE)?;
            index.note_swept(&self.dag)?;
            index.seal()?;
            batch.commit()?;
            self.entries.committed();
            Ok(dropped)
        })();
        if let Err(ref error) = result {
            self.poisoned = true;
            self.save_error = Some(error.to_string());
        }
        result
    }

    /// Append a control entry (a checkpoint) on this identity's own feed: signed and stored
    /// like governance, never folded into the ADR-007 evaluator, since it grants nothing.
    fn append_control(&mut self, profile: &Profile, payload: &[u8], now_ms: u64) -> Result<()> {
        self.append_control_kind(profile, payload, now_ms, EntryKind::Checkpoint, false)
    }

    fn append_control_kind(
        &mut self,
        profile: &Profile,
        payload: &[u8],
        now_ms: u64,
        kind: EntryKind,
        after_departure: bool,
    ) -> Result<()> {
        self.ensure_local_append_available_for(profile.store(), after_departure)?;
        if self.poisoned {
            return Err(self.save_failure());
        }
        if !self.settled {
            return Err(Error::RoomNotSynced);
        }
        self.require_own_history_current()?;
        let signer = profile.signer()?;
        let me = signer.fingerprint();
        let skeleton = self.next_skeleton(profile, &me, payload, now_ms)?;
        let entry = Entry::build_signed(signer, skeleton, payload.to_vec())?;
        let id = self.next_log_id;

        let persisted = (|| -> Result<()> {
            self.prepare_local_entry(profile, &entry, kind, &signer.public_key(), now_ms)?;
            let mut batch = profile.store().batch()?;
            let settlement = self.publish_entry_into(&mut batch, &entry)?;
            self.observe_governance_into(profile.store(), &mut batch, &entry, id)?;
            self.finish_local_history_effect_into(&mut batch, &entry, settlement)?;
            batch.commit()
        })();
        if let Err(e) = persisted {
            self.poisoned = true;
            self.save_error = Some(e.to_string());
            return Err(e);
        }
        self.entries.committed();
        self.next_log_id = id.saturating_add(1);
        // A new entry of this room: its ports need a session (ADR-025 D2), as after a post.
        // Without this a checkpoint waited for the periodic sync, so a member that pruned before
        // it arrived kept every signature below it (ADR-023 decision 3), and a conflicting entry
        // there was not refused as pre-checkpoint (R10).
        self.gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.finish_entry_publication(profile.store())?;
        Ok(())
    }

    /// Whether an entry this node is about to render has already outlived the effective
    /// retention — a late arrival of a message that is expired everywhere else.
    fn already_expired(
        &self,
        transaction: Transaction<'_, '_>,
        entry_hash: &Digest32,
        claimed_ms: u64,
        now_ms: u64,
    ) -> Result<bool> {
        if !self.governance_display_current(now_ms) {
            return Ok(false);
        }
        let entry = self
            .entry_at(transaction, entry_hash)?
            .ok_or(Error::MalformedAtRest("rendered entry missing"))?;
        self.already_expired_entry(transaction, &entry, claimed_ms, now_ms)
    }

    fn already_expired_entry(
        &self,
        transaction: Transaction<'_, '_>,
        entry: &Entry,
        claimed_ms: u64,
        now_ms: u64,
    ) -> Result<bool> {
        if !self.governance_display_current(now_ms) {
            return Ok(false);
        }
        let ttl = self.entry_retention(transaction, entry)?;
        if ttl == 0 {
            return Ok(false);
        }
        let entry_hash = entry.entry_hash();
        let first_seen = self
            .retention_get_in(transaction, &entry_hash)?
            .map_or(now_ms, |t| t.first_seen_ms);
        Ok(claimed_ms.min(first_seen) <= now_ms.saturating_sub(ttl.saturating_mul(1_000)))
    }

    /// Drop the bodies of `due`: rewrite each log page with the skeleton alone, delete its
    /// cache row and its retention record, in one batch. `with_receivers` also persists the
    /// receiver chains, for a caller that has just advanced one (a render that decrypted and
    /// then found the message expired must still record that the key was used).
    fn prune(
        &mut self,
        store: &Store,
        due: &[(Digest32, Tracked)],
        with_receivers: bool,
    ) -> Result<usize> {
        let selected = (|| -> Result<Vec<(Digest32, Tracked)>> {
            let read = self.entries.read(store, &self.sek, &self.channel_id)?;
            let mut selected = Vec::new();
            let mut bytes = 0usize;
            for (hash, tracked) in due.iter().take(64) {
                let entry = self
                    .dag
                    .get_by_hash(&read, hash)?
                    .ok_or(Error::MalformedAtRest("pruned entry missing"))?;
                let size = entry.payload.as_ref().map_or(0, Vec::len);
                if !selected.is_empty() && bytes.saturating_add(size) > 1024 * 1024 {
                    break;
                }
                bytes = bytes.saturating_add(size);
                if entry.payload.as_deref().is_some_and(retained_control) {
                    return Err(Error::MalformedAtRest(
                        "retained control indexed for expiry",
                    ));
                }
                selected.push((*hash, *tracked));
            }
            drop(read);
            self.reconcile_legacy_sessions(store, self.now_hint)?;
            Ok(selected)
        })();
        let due = match selected {
            Ok(due) => due,
            Err(error) => {
                self.poison(&error);
                return Err(error);
            }
        };
        if due.is_empty() && !with_receivers && !self.legacy_sessions.dirty() {
            return Ok(0);
        }
        let shed = self.effective_retention() != 0;
        let mut display_changed = false;
        let persisted = (|| -> Result<()> {
            let mut batch = store.batch()?;
            for (hash, tracked) in &due {
                let entry = self
                    .dag
                    .get_by_hash(
                        &self.entries.in_batch(&batch, &self.sek, &self.channel_id)?,
                        hash,
                    )?
                    .ok_or(Error::MalformedAtRest("pruned control entry missing"))?;
                session_projection::private_index::observe_public(
                    &mut batch,
                    &self.sek,
                    &self.channel_id,
                    &entry,
                    self.epoch,
                )?;
                self.inspect_legacy_body_into(&mut batch, &entry)?;
                {
                    let mut index = self
                        .entries
                        .write(&mut batch, &self.sek, &self.channel_id)?;
                    index.committing(self.next_log_id);
                    display_changed |= index.has_rendered(hash)?;
                    index.remove_rendered(hash)?;
                    index.remove_read_receipt(hash)?;
                    index.set_retention(*hash, None)?;
                    self.dag.prune_payload(&mut index, hash)?;
                    if shed {
                        self.dag.drop_signature_if_checkpointed(&mut index, hash)?;
                    }
                    index.seal()?;
                }
                let age = seal_segment(
                    &self.sek,
                    SegmentKind::Index,
                    tracked.log_id,
                    &first_seen_bytes(tracked.first_seen_ms, tracked.steps),
                )?;
                batch.put_segment(&self.channel_id, SegmentKind::Index, tracked.log_id, &age)?;
                if let Some(cache_id) = tracked.cache_id {
                    batch.delete_segment(
                        &self.channel_id,
                        SegmentKind::PlaintextCache,
                        cache_id,
                    )?;
                }
            }
            self.reconcile_legacy_sessions_in(&mut batch, self.now_hint)?;
            if with_receivers {
                self.queue_receivers(&mut batch)?;
            }
            batch.commit()
        })();
        if let Err(error) = persisted {
            self.poisoned = true;
            self.save_error = Some(error.to_string());
            return Err(error);
        }
        self.entries.committed();
        self.legacy_sessions.committed();
        if display_changed {
            self.invalidate_display();
            let tail = self
                .entries
                .render_view(store, &self.sek, &self.channel_id)
                .and_then(|view| view.step(None, true, None, true))
                .map(|row| row.map(|(key, _)| key));
            match tail {
                Ok(tail) => self.display_tail = tail,
                Err(error) => {
                    self.poison(&error);
                    return Err(error);
                }
            }
        }
        Ok(due.len())
    }

    /// Read fixed-size retention metadata from one saved snapshot.
    fn retention_get(&self, store: &Store, hash: &Digest32) -> Result<Option<Tracked>> {
        let snapshot = store.snapshot()?;
        self.retention_get_in(Transaction::Snapshot(&snapshot), hash)
    }
    fn retention_get_in(
        &self,
        transaction: Transaction<'_, '_>,
        hash: &Digest32,
    ) -> Result<Option<Tracked>> {
        self.entries
            .view(transaction, &self.sek, &self.channel_id)?
            .retention(hash)
    }
    fn queue_retention(
        &self,
        batch: &mut crate::node::store::Batch<'_>,
        hash: Digest32,
        value: Option<Tracked>,
    ) -> Result<()> {
        let mut index = self.entries.write(batch, &self.sek, &self.channel_id)?;
        index.set_retention(hash, value)?;
        index.seal()
    }
    fn queue_retention_rendered(
        &self,
        batch: &mut crate::node::store::Batch<'_>,
        hash: &Digest32,
        created: u64,
        cache: Option<u64>,
    ) -> Result<()> {
        let mut index = self.entries.write(batch, &self.sek, &self.channel_id)?;
        index.retention_rendered(hash, created, cache)?;
        index.seal()
    }

    /// Keep the authenticated carrier's age and public kind when permissions withhold its
    /// body. This is not a decrypted Session classification or a retained-body record.
    fn preserve_withheld_body_into(
        &self,
        batch: &mut crate::node::store::Batch<'_>,
        entry: &Entry,
    ) -> Result<()> {
        let hash = entry.entry_hash();
        let log = self
            .log_id_at(Transaction::Batch(batch), &hash)?
            .ok_or(Error::MalformedAtRest("withheld body has no log page"))?;
        let saved = batch
            .get_segment(&self.channel_id, SegmentKind::Index, log)?
            .map(|segment| {
                parse_first_seen(&open_segment(&self.sek, SegmentKind::Index, log, &segment)?)
            })
            .transpose()?;
        let tracked = self.retention_get_in(Transaction::Batch(batch), &hash)?;
        let first_seen = saved
            .map(|(at, _)| at)
            .into_iter()
            .chain(tracked.map(|value| value.first_seen_ms))
            .min()
            .unwrap_or(self.now_hint);
        let steps = entry
            .payload
            .as_deref()
            .is_some_and(|body| is_step_body(&self.channel_id, body))
            || saved.is_some_and(|(_, steps)| steps)
            || tracked.is_some_and(|value| value.steps);
        if saved != Some((first_seen, steps)) {
            let sealed = seal_segment(
                &self.sek,
                SegmentKind::Index,
                log,
                &first_seen_bytes(first_seen, steps),
            )?;
            batch.put_segment(&self.channel_id, SegmentKind::Index, log, &sealed)?;
        }
        if let Some(mut tracked) = tracked {
            if tracked.first_seen_ms != first_seen || tracked.steps != steps {
                tracked.first_seen_ms = first_seen;
                tracked.steps = steps;
                self.queue_retention(batch, hash, Some(tracked))?;
            }
        }
        Ok(())
    }

    /// Queue a body's age beside its authoritative log row, before the same commit.
    fn track_body_into(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        entry_hash: Digest32,
        log_id: u64,
        now_ms: u64,
    ) -> Result<()> {
        let entry = self
            .entry_at(Transaction::Batch(batch), &entry_hash)?
            .ok_or(Error::MalformedAtRest("tracked entry missing"))?;
        if entry.payload.as_deref().is_some_and(retained_control) {
            return Ok(());
        }
        let steps = entry
            .payload
            .as_deref()
            .is_some_and(|body| is_step_body(&self.channel_id, body));
        if steps {
            self.invalidate_display();
            self.private_sessions.legacy_pending.insert(entry_hash);
        }
        let claimed_ms = steps.then_some(entry.skeleton.claimed_ms);
        let seg = seal_segment(
            &self.sek,
            SegmentKind::Index,
            log_id,
            &first_seen_bytes(now_ms, steps),
        )?;
        batch.put_segment(&self.channel_id, SegmentKind::Index, log_id, &seg)?;
        self.queue_retention(
            batch,
            entry_hash,
            Some(Tracked {
                log_id,
                steps,
                first_seen_ms: now_ms,
                claimed_ms,
                cache_id: None,
            }),
        )
    }

    /// Queue the age of an exact, already-authenticated body while its sparse effect is still
    /// being published. Sparse Content cannot be marked settled merely to make the ordinary
    /// index lookup see it: settlement means its semantic projection completed. The caller's
    /// typed effect owns this entry and the same Batch owns both its source and this retention
    /// record, so the entry itself is the authoritative input until settlement is sealed.
    fn track_known_body_into(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        entry: &Entry,
        log_id: u64,
    ) -> Result<()> {
        let entry_hash = entry.entry_hash();
        if entry.payload.as_deref().is_some_and(retained_control) {
            return Ok(());
        }
        let body_steps = entry
            .payload
            .as_deref()
            .is_some_and(|body| is_step_body(&self.channel_id, body));
        let saved = batch
            .get_segment(&self.channel_id, SegmentKind::Index, log_id)?
            .ok_or(Error::MalformedAtRest("sparse Content age missing"))?;
        let (source_first_seen, source_steps) = parse_first_seen(&open_segment(
            &self.sek,
            SegmentKind::Index,
            log_id,
            &saved,
        )?)?;
        let previous = self.retention_get_in(Transaction::Batch(batch), &entry_hash)?;
        if previous.is_some_and(|tracked| tracked.log_id != log_id) {
            return Err(Error::MalformedAtRest(
                "sparse Content retention locator differs",
            ));
        }
        let first_seen_ms = previous
            .map(|tracked| tracked.first_seen_ms)
            .unwrap_or(source_first_seen)
            .min(source_first_seen);
        let steps = body_steps || source_steps || previous.is_some_and(|tracked| tracked.steps);
        if steps {
            self.invalidate_display();
            self.private_sessions.legacy_pending.insert(entry_hash);
        }
        let claimed_ms = previous
            .and_then(|tracked| tracked.claimed_ms)
            .or_else(|| steps.then_some(entry.skeleton.claimed_ms));
        let cache_id = previous.and_then(|tracked| tracked.cache_id);
        let seg = seal_segment(
            &self.sek,
            SegmentKind::Index,
            log_id,
            &first_seen_bytes(first_seen_ms, steps),
        )?;
        batch.put_segment(&self.channel_id, SegmentKind::Index, log_id, &seg)?;
        self.queue_retention(
            batch,
            entry_hash,
            Some(Tracked {
                log_id,
                steps,
                first_seen_ms,
                claimed_ms,
                cache_id,
            }),
        )
    }

    /// Append an already-built governance struct as a signed log entry.
    fn append_governance(
        &mut self,
        profile: &Profile,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<Digest32> {
        self.append_governance_with(profile, payload, now_ms, &[])
    }

    /// [`Self::append_governance`], committing `rows` — sealed `KeyMaterial` segments by id — in
    /// the same transaction as the entry, so neither is ever on disk without the other.
    fn append_governance_with(
        &mut self,
        profile: &Profile,
        payload: &[u8],
        now_ms: u64,
        rows: &[(u64, SealedSegment)],
    ) -> Result<Digest32> {
        self.append_governance_with_sender(
            profile, payload, now_ms, rows, false, None, false, false,
        )
    }

    /// Non-mutating command eligibility shared with same-policy no-op decisions.
    /// Physical publication/capacity admission remains specific to an actual append.
    fn ensure_governance_append_eligible(
        &self,
        profile: &Profile,
        settle_sparse: bool,
    ) -> Result<()> {
        self.ensure_governance_append_eligible_for(profile, settle_sparse, false)
    }

    fn ensure_governance_append_eligible_for(
        &self,
        profile: &Profile,
        settle_sparse: bool,
        recover_own: bool,
    ) -> Result<()> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        if !self.settled && !settle_sparse {
            return Err(Error::RoomNotSynced);
        }
        if recover_own {
            self.require_own_recovery_complete(profile.store())?;
        } else {
            self.require_own_history_current()?;
        }
        if settle_sparse && (!self.uses_sparse_history(profile.store())? || self.settled) {
            return Err(Error::MalformedBundle("sparse settlement state differs"));
        }
        let signer = profile.signer()?;
        let me = signer.fingerprint();
        if !self.authors.contains_key(&me) {
            return Err(Error::Profile("this identity is not an author of the room"));
        }
        Ok(())
    }

    /// The sparse settlement exception is local-only and publishes presence, sender state
    /// and removal of the unsettled marker in one effects Batch. No mutable state is exposed
    /// as settled before that commit; failed preflight keeps the original sender intact.
    // Sender advancement and the exact governance append share one transaction.
    #[allow(clippy::too_many_arguments)]
    fn append_governance_with_sender(
        &mut self,
        profile: &Profile,
        payload: &[u8],
        now_ms: u64,
        rows: &[(u64, SealedSegment)],
        settle_sparse: bool,
        sender: Option<(SenderChain, OriginKeyStore)>,
        after_departure: bool,
        recover_own: bool,
    ) -> Result<Digest32> {
        self.ensure_local_append_available_mode(profile.store(), after_departure, recover_own)?;
        self.ensure_governance_append_eligible_for(profile, settle_sparse, recover_own)?;
        let signer = profile.signer()?;
        let me = signer.fingerprint();
        let skeleton = self.next_skeleton(profile, &me, payload, now_ms)?;
        let entry = Entry::build_signed(signer, skeleton, payload.to_vec())?;
        let hash = entry.entry_hash();
        let wire = entry.to_wire();
        let id = self.next_log_id;
        let log_seg = seal_segment(&self.sek, SegmentKind::LogDb, id, &wire)?;
        let key = signer.public_key();
        GovEntry::from_verified_log_entry(&entry, &key, &self.channel_id, Default::default())?;
        // Step policy uses the existing content carrier so published readers retain the
        // signed entry and continue its author's feed while skipping the unknown subtype.
        let kind = classify_payload(payload)?;

        let written = (|| -> Result<()> {
            self.prepare_local_entry(profile, &entry, kind, &key, now_ms)?;
            let mut batch = profile.store().batch()?;
            if recover_own {
                self.check_own_recovery_marker_in(&batch)?;
            }
            let settlement = self.publish_entry_into(&mut batch, &entry)?;
            self.observe_governance_into(profile.store(), &mut batch, &entry, id)?;
            batch.put_segment(&self.channel_id, SegmentKind::LogDb, id, &log_seg)?;
            for (row, seg) in rows {
                batch.put_segment(&self.channel_id, SegmentKind::KeyMaterial, *row, seg)?;
            }
            if settle_sparse {
                batch.delete_segment(&self.channel_id, SegmentKind::KeyMaterial, SEG_UNSETTLED)?;
            }
            if recover_own {
                batch.delete_segment(&self.channel_id, SegmentKind::KeyMaterial, SEG_OWN_BEHIND)?;
            }
            self.finish_local_history_effect_into(&mut batch, &entry, settlement)?;
            batch.commit()
        })();
        if let Err(e) = written {
            if matches!(e, Error::OwnHistoryBehind) {
                return Err(e);
            }
            self.poisoned = true;
            self.save_error = Some(e.to_string());
            return Err(e);
        }
        if let Some((sender, origins)) = sender {
            self.sender = sender;
            self.origins = origins;
        }
        if settle_sparse {
            self.settled = true;
        }
        if recover_own {
            self.own_behind = false;
            self.own_recovery = own_history::Recovery::UnknownBehind;
        }
        self.entries.committed();
        self.next_log_id = id.saturating_add(1);
        self.gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.finish_entry_publication(profile.store())?;
        Ok(hash)
    }

    /// The stored entries set aside when this room opened (V210-74), each as `author#seq: why`.
    #[must_use]
    pub fn set_aside(&self) -> &SetAside {
        &self.set_aside
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
    /// `LogDb` segment, queues its bounded governance work, and renders a
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
        now: crate::time::Ms,
    ) -> Result<SyncOutcome> {
        let now_ms = now.get();
        if self.poisoned {
            return Err(self.save_failure());
        }
        // Per-author heads before the session, so the new entries can be found after.
        let before: BTreeMap<Digest32, u64> = self
            .authors
            .keys()
            .map(|a| (*a, self.dag.feed(a).map_or(0, |f| f.max_seq())))
            .collect();
        let resolver = self.resolver();
        let mut entries = self.entries.staging(store, &self.sek, &self.channel_id);
        let session = frontier_session_peer(
            transport,
            &mut self.dag,
            &mut entries,
            &resolver,
            &self.admission,
        );
        if let Err(crate::log::sync::ApplyError::Local(error)) = session {
            self.poisoned = true;
            self.save_error = Some(error.to_string());
            self.keep_forks(store)?;
            return Err(error);
        }

        // Collect what arrived, in per-author sequence order, before touching the
        // store (the borrow of `self.dag` ends here).
        let mut out = self.absorb_arrived(store, &before, now_ms)?;
        if let Ok(n) = session {
            out.applied = n;
        }
        match session {
            Ok(_) => Ok(out),
            Err(crate::log::sync::ApplyError::Wire(code)) => {
                Err(sync_failure(code, transport.peer_refused()))
            }
            Err(crate::log::sync::ApplyError::Local(error)) => Err(error),
        }
    }

    /// Each author's head, for [`ChannelState::absorb_arrived`] to find what a sync added.
    fn heads(&self) -> BTreeMap<Digest32, u64> {
        self.authors
            .keys()
            .map(|a| (*a, self.dag.verified_head(a)))
            .collect()
    }

    /// Persist, fold and render every entry a sync added past `before`'s heads.
    ///
    /// Only up to each author's **verified** head: a run of unsigned skeletons that no signed
    /// entry has chained to yet (ADR-023 decision 3) waits in the sealed provisional spool.
    /// It is discarded at session end if no witness comes, never exposed as accepted history.
    fn absorb_arrived(
        &mut self,
        store: &Store,
        before: &BTreeMap<Digest32, u64>,
        now_ms: u64,
    ) -> Result<SyncOutcome> {
        self.keep_forks(store)?;
        let result = (|| -> Result<SyncOutcome> {
            let mut out = SyncOutcome::default();
            self.now_hint = self.now_hint.max(now_ms);
            for (author, old_head) in before {
                let through = self.dag.verified_head(author);
                let mut from = old_head
                    .checked_add(1)
                    .ok_or(Error::MalformedAtRest("feed sequence exhausted"))?;
                while from <= through {
                    // Ordinary signed entries keep their bounded grouped governance fold.
                    // Their unpublished DAG work is prepared first: one late parent may lift
                    // arbitrarily many old descendants even when this input batch is tiny.
                    let first = self
                        .entries
                        .read(store, &self.sek, &self.channel_id)?
                        .get(author, from)?
                        .ok_or(Error::MalformedAtRest("verified suffix missing"))?;
                    if first.is_signed() {
                        let first_log = self.next_log_id;
                        let mut witness = None;
                        let mut arrived = Vec::new();
                        let mut bytes = 0usize;
                        let mut seq = from;
                        let mut next = Some(first);
                        while seq <= through && arrived.len() < 64 {
                            let entry = match next.take() {
                                Some(entry) => entry,
                                None => self
                                    .entries
                                    .read(store, &self.sek, &self.channel_id)?
                                    .get(author, seq)?
                                    .ok_or(Error::MalformedAtRest("verified suffix missing"))?,
                            };
                            if !entry.is_signed() {
                                break;
                            }
                            let size = entry.to_wire().len();
                            if !arrived.is_empty() && bytes.saturating_add(size) > 1024 * 1024 {
                                break;
                            }
                            let id = self.next_log_id;
                            self.next_log_id = id
                                .checked_add(1)
                                .ok_or(Error::MalformedAtRest("log allocator exhausted"))?;
                            witness = Some(entry.clone());
                            arrived.push((*author, entry.entry_hash(), entry.payload, Some(id)));
                            bytes = bytes.saturating_add(size);
                            seq = seq
                                .checked_add(1)
                                .ok_or(Error::MalformedAtRest("feed sequence exhausted"))?;
                        }
                        let witness = witness
                            .ok_or(Error::MalformedAtRest("signed batch witness missing"))?;
                        self.entries.prepare_publication(
                            store,
                            &self.sek,
                            &self.channel_id,
                            entry_store::Publication {
                                witness: &witness,
                                from,
                                first_log,
                                received_ms: now_ms,
                                bodyless_prefix: false,
                                origin: self.genesis.body.created_ms,
                                local_contexts: None,
                            },
                        )?;
                        let count = arrived.len() as u64;
                        let got = self.absorb_batch(store, arrived, now_ms, Some(count))?;
                        out.applied += got.applied;
                        out.rendered += got.rendered;
                        out.governance += got.governance;
                        out.refused += got.refused;
                        from = seq;
                        continue;
                    }
                    // Any signed successor authenticates the preceding bodyless suffix.
                    // Locate one witness at a time; never collect that suffix in RAM.
                    let mut seq = from;
                    let witness = loop {
                        let entry = self
                            .entries
                            .read(store, &self.sek, &self.channel_id)?
                            .get(author, seq)?
                            .ok_or(Error::MalformedAtRest("verified suffix missing"))?;
                        if entry.is_signed() {
                            break entry;
                        }
                        if entry.payload.is_some() || seq >= through {
                            return Err(Error::MalformedAtRest(
                                "verified suffix has no signed witness",
                            ));
                        }
                        seq = seq
                            .checked_add(1)
                            .ok_or(Error::MalformedAtRest("feed sequence exhausted"))?;
                    };
                    let count = seq - from + 1;
                    let witness_log = self
                        .next_log_id
                        .checked_add(count - 1)
                        .ok_or(Error::MalformedAtRest("log allocator exhausted"))?;
                    let after_log = witness_log
                        .checked_add(1)
                        .ok_or(Error::MalformedAtRest("log allocator exhausted"))?;
                    self.entries.prepare_publication(
                        store,
                        &self.sek,
                        &self.channel_id,
                        entry_store::Publication {
                            witness: &witness,
                            from,
                            first_log: self.next_log_id,
                            received_ms: now_ms,
                            bodyless_prefix: true,
                            origin: self.genesis.body.created_ms,
                            local_contexts: None,
                        },
                    )?;
                    // Reserve all log ids before rendering the witness can allocate a cache id.
                    self.next_log_id = after_log;
                    self.projection_state.owed_range(*author, from, seq);
                    let got = self.absorb_batch(
                        store,
                        vec![(
                            *author,
                            witness.entry_hash(),
                            witness.payload,
                            Some(witness_log),
                        )],
                        now_ms,
                        Some(count),
                    )?;
                    out.applied += count as usize;
                    out.rendered += got.rendered;
                    out.governance += got.governance;
                    out.refused += got.refused;
                    from = seq
                        .checked_add(1)
                        .ok_or(Error::MalformedAtRest("feed sequence exhausted"))?;
                }
            }
            for hash in self.dag.take_filled() {
                let read = self.entries.read(store, &self.sek, &self.channel_id)?;
                let Some(entry) = self.dag.get_by_hash(&read, &hash)? else {
                    continue;
                };
                // A new entry covered above was already published and removed from the spool.
                if !read.staged(&entry.skeleton.author_id, entry.skeleton.seq)? {
                    continue;
                }
                let id = read
                    .log_id(&hash)?
                    .ok_or(Error::MalformedAtRest("filled entry has no active log"))?;
                drop(read);
                let got = self.absorb_batch(
                    store,
                    vec![(entry.skeleton.author_id, hash, entry.payload, Some(id))],
                    now_ms,
                    None,
                )?;
                out.applied += got.applied;
                out.rendered += got.rendered;
                out.governance += got.governance;
                out.refused += got.refused;
            }
            // A repeated authenticated body may contradict a declaration without adding a row.
            self.reconcile_legacy_sessions(store, now_ms)?;
            Ok(out)
        })();
        if let Err(ref error) = result {
            self.poisoned = true;
            self.save_error = Some(error.to_string());
        }
        result
    }

    /// A bounded signed batch, one signed witness, or one body refill and its effects.
    /// An arbitrarily long unsigned prefix is written as unpublished chunks beforehand.
    fn absorb_batch(
        &mut self,
        store: &Store,
        arrived: Vec<Arrived>,
        now_ms: u64,
        promotion: Option<u64>,
    ) -> Result<SyncOutcome> {
        self.absorb_batch_authorized(store, arrived, now_ms, promotion, None)
    }

    fn absorb_batch_authorized(
        &mut self,
        store: &Store,
        arrived: Vec<Arrived>,
        now_ms: u64,
        promotion: Option<u64>,
        authorization: Option<LegacySync>,
    ) -> Result<SyncOutcome> {
        let mut out = SyncOutcome {
            applied: arrived.len(),
            ..SyncOutcome::default()
        };
        // **One durable commit for the whole batch** (see `render_content_into`).
        //
        // Two kinds of failure, kept apart as they were when each entry committed on its own:
        // - an entry this node refuses (bad governance) is counted and the pass goes on, **without**
        //   poisoning the room (V210-74): the entries after it are already held, so stopping left
        //   them in memory and not on disk, and a refusal reported as an error poisoned the room's
        //   sync. Sync refuses what cannot be classified before it is held, so this is what is left;
        // - a failed write poisons the room, because memory has advanced past what is on disk.
        //
        // Nothing below may write through `store` while `batch` is open: a second write
        // transaction blocks forever (redb). So a body's first-seen row goes into the batch
        // (`track_body_into`), and an expired late arrival is pruned only after the commit.
        let mut rendered_rows: Vec<Rendered> = Vec::new();
        let mut packages = Vec::new();
        let mut expired: Vec<(Digest32, Tracked)> = Vec::new();
        let mut chains_advanced = false;
        let mut batch = match store.batch() {
            Ok(b) => b,
            Err(e) => {
                self.poisoned = true;
                self.save_error = Some(e.to_string());
                return Err(e);
            }
        };
        if let Some(request) = authorization {
            request.check_in(self, &batch)?;
        }
        if promotion.is_some() {
            let mut index = self
                .entries
                .write(&mut batch, &self.sek, &self.channel_id)?;
            index.publish_promotion()?;
            index.seal()?;
        }
        let mut write_failed: Option<Error> = None;
        // Log rows queued into `batch`: what the generation advances by once it commits (ADR-025
        // D1). Counted at the row, not per `arrived` entry — a refusal before the row is queued
        // stores nothing, one after it still stores the row.
        let mut logged: u64 = promotion.unwrap_or(0);
        for (author, entry_hash, _, refill) in arrived {
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
                    let mut held = self
                        .dag
                        .get_by_hash(
                            &self.entries.in_batch(&batch, &self.sek, &self.channel_id)?,
                            &entry_hash,
                        )?
                        .ok_or(Error::MalformedAtRest("synced entry vanished"))?;
                    let seq = held.skeleton.seq;
                    // Written before the entry is classified, exactly as each entry was when it
                    // committed on its own: a refusal below still leaves its log row stored. A body
                    // that arrived for a held skeleton rewrites that skeleton's page.
                    let id = match refill {
                        Some(id) => id,
                        None => {
                            let id = self.next_log_id;
                            self.next_log_id = id.saturating_add(1);
                            id
                        }
                    };
                    if promotion.is_none() {
                        let mut index =
                            self.entries
                                .write(&mut batch, &self.sek, &self.channel_id)?;
                        index.put_committed(&held, id)?;
                        index.remove_staged(&author, seq)?;
                        index.seal()?;
                    }
                    session_projection::private_index::observe_public(
                        &mut batch,
                        &self.sek,
                        &self.channel_id,
                        &held,
                        self.epoch,
                    )?;
                    if promotion.is_none() {
                        logged += 1;
                    }
                    self.observe_governance_into(store, &mut batch, &held, id)?;
                    let key = refuse!(self.authors.get(&author).cloned().ok_or(
                        Error::MalformedGovernance("synced entry from an unadmitted author")
                    ));

                    // Save subtype evidence before withholding the body, beside the
                    // source locator in this same publication transaction.
                    self.filter_received_session_body_into(&mut batch, &mut held)?;
                    let Some(payload) = held.payload.as_deref() else {
                        // A skeleton: stored, never rendered. Its body is owed unless it has
                        // expired here (V030-10).
                        // Promotion already inserted the missing position atomically.
                        let missing = self
                            .entries
                            .write(&mut batch, &self.sek, &self.channel_id)?
                            .missing_contains(&author, seq)?;
                        let visibility = if missing {
                            self.owed_visibility(&batch, &held)?
                        } else {
                            None
                        };
                        let mut writer =
                            self.entries
                                .write(&mut batch, &self.sek, &self.channel_id)?;
                        writer.set_owed(entry_hash, visibility)?;
                        writer.seal()?;
                        return Ok(Ok(Vec::new()));
                    };
                    let wire_kind = refuse!(classify_payload(payload));
                    let gov = match wire_kind {
                        EntryKind::Governance | EntryKind::Content
                            if wire_kind == EntryKind::Governance
                                || crate::governance::step_policy::is_step_policy(payload) =>
                        {
                            let entry = held.clone();
                            Some(refuse!(GovEntry::from_verified_log_entry(
                                &entry,
                                &key,
                                &self.channel_id,
                                Default::default(),
                            )))
                        }
                        // A checkpoint is stored and read by the DAG; there is nothing to render.
                        EntryKind::Checkpoint => return Ok(Ok(Vec::new())),
                        EntryKind::Content | EntryKind::Governance => None,
                    };
                    if gov.is_some() {
                        // Every newly authenticated governance row is causal index work, even
                        // when its single-writer semantic effect is superseded. The projection
                        // observer separately declines to revise/invalidate/backfill for that
                        // no-op, while this one wake settles its durable frontier obligation.
                        out.governance += 1;
                        return Ok(Ok(Vec::new()));
                    }
                    let mut rows = Vec::new();
                    // A key-package is queued for the actor to install, never rendered or aged as
                    // a message.
                    if crate::node::keypackage::KeyPackage::is_key_package(payload) {
                        if key_package_for(&held, &self.me()) {
                            packages.push((author, id));
                        }
                        return Ok(Ok(rows));
                    }
                    self.track_body_into(&mut batch, entry_hash, id, now_ms)?;
                    let before_expired = expired.len();
                    let projection = self.render_content_into(
                        &mut batch,
                        author,
                        entry_hash,
                        payload,
                        None,
                        now_ms,
                        false,
                        &mut expired,
                    )?;
                    chains_advanced |= matches!(&projection, ContentProjection::Visible(_))
                        || expired.len() > before_expired;
                    rows.extend(projection.into_row());
                    Ok(Ok(rows))
                })();
            match step {
                Ok(Ok(rows)) => rendered_rows.extend(rows),
                Ok(Err(_refusal)) => out.refused += 1,
                Err(e) => {
                    write_failed = Some(e);
                    break;
                }
            }
        }
        let committed = match write_failed {
            Some(e) => Err(e),
            None => (|| -> Result<()> {
                self.reconcile_legacy_sessions_in(&mut batch, now_ms)?;
                if chains_advanced || self.chains_advanced {
                    self.queue_receivers(&mut batch)?;
                }
                self.queue_private_generations(&mut batch)?;
                let mut index = self
                    .entries
                    .write(&mut batch, &self.sek, &self.channel_id)?;
                index.note_projection(self.projection_state.to_bytes())?;
                index.seal()?;
                batch.commit()
            })(),
        };
        if let Err(e) = committed {
            self.poisoned = true;
            self.save_error = Some(e.to_string());
            return Err(e);
        }
        self.entries.committed();
        self.legacy_sessions.committed();
        self.key_packages.published(self.next_log_id);
        for (author, log_id) in packages {
            if let Err(error) = self.key_packages.note(author, log_id) {
                self.poison(&error);
                return Err(error);
            }
        }
        self.private_controls_committed(store)?;
        self.chains_advanced = false;
        // Only now, after the commit: `SessionRoom::apply` reports `stored` from the generation,
        // and ADR-025 credits the peer from it, so it must count exactly the rows now durable —
        // none when the write failed (the room is poisoned above), and a refused pass's rows too.
        self.gen
            .fetch_add(logged, std::sync::atomic::Ordering::Relaxed);
        if promotion.is_some() {
            self.finish_entry_publication(store)?;
        }
        out.rendered += rendered_rows.len();
        self.place_committed(store, rendered_rows, &expired)?;
        // An entry that arrived may be a parent others named before it: rows move.
        self.settle_display_order(store)?;
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
        peer: Digest32,
        transport: &mut T,
        now: crate::time::Ms,
        fence: &crate::transport::stream_transport::Fence,
        on_stored: &dyn Fn(),
    ) -> SessionReport {
        Self::sync_over_room_mode(shared, store, peer, transport, now, fence, on_stored, None)
    }

    // The explicit legacy owner stays bound to this one room transport session.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sync_over_room_mode<T: Transport>(
        shared: &tokio::sync::Mutex<Self>,
        store: &Store,
        peer: Digest32,
        transport: &mut T,
        now: crate::time::Ms,
        fence: &crate::transport::stream_transport::Fence,
        on_stored: &dyn Fn(),
        legacy: Option<LegacySync>,
    ) -> SessionReport {
        let now_ms = now.get();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let epoch = loop {
            if fence.is_retired() || std::time::Instant::now() >= deadline {
                return SessionReport::failed(SyncFailure::Session(
                    crate::log::sync::SessionError::Local(crate::wire::WireError::TransportFailed),
                ));
            }
            if let Ok(ch) = shared.try_lock() {
                if ch.poisoned {
                    return SessionReport::failed(SyncFailure::Poisoned(
                        ch.save_failure().to_string(),
                    ));
                }
                if ch.sek.key_bytes().is_err() {
                    return SessionReport::failed(SyncFailure::Session(
                        crate::log::sync::SessionError::Local(
                            crate::wire::WireError::TransportFailed,
                        ),
                    ));
                }
                break ch.epoch;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        };
        let room = ChannelSessionRoom {
            shared,
            store,
            peer,
            now_ms,
            epoch,
            fence,
            on_stored,
            legacy,
            observe_tip: std::cell::Cell::new(None),
            deadline,
            out: std::cell::RefCell::new(SyncOutcome::default()),
            fatal: std::cell::RefCell::new(None),
        };
        let session = crate::log::sync::frontier_session_room(transport, &room);
        // Whatever arrived without a signature and was never chained to a signed entry is not
        // authentic; it was never persisted, and it is taken back here on every path out of the
        // session (ADR-023 decision 3).
        {
            // Cancellation does not skip detaching volatile provisional heads. Wait only
            // for this bounded local cleanup; lock_now still wipes keys immediately.
            let cleanup_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let guard = loop {
                if let Ok(ch) = shared.try_lock() {
                    break Some(ch);
                }
                if std::time::Instant::now() >= cleanup_deadline {
                    break None;
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            };
            if let Some(mut ch) = guard.filter(|ch| ch.sek.key_bytes().is_ok()) {
                let cleanup = if let Some(request) = legacy {
                    if let Ok(Some(state)) = ch.legacy_provisional_state(store) {
                        room.out.borrow_mut().legacy_next = Some(state.tail_seq.saturating_add(1));
                        room.out.borrow_mut().legacy_pending = state.pending_witness != 0
                            || ch
                                .legacy_publication_progress(store, request.owner)
                                .ok()
                                .flatten()
                                .is_some();
                    }
                    ch.finish_legacy_sync(store, request).map(|()| 0)
                } else {
                    match ch.legacy_provisional_state(store) {
                        // A current session may finish between explicit recovery's lock
                        // slices. It never owns that attached suffix or its durable spool.
                        Ok(Some(_)) => Ok(0),
                        Ok(None) => ch.discard_unverified(store),
                        Err(error) => Err(error),
                    }
                };
                match cleanup {
                    Ok(_) => {}
                    Err(error) => {
                        ch.poisoned = true;
                        ch.save_error = Some(error.to_string());
                        *room.fatal.borrow_mut() = Some(error);
                    }
                }
            }
        }
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
    /// backfill rendered and whether key state actually changed.
    pub fn accept_skdm(
        &mut self,
        store: &Store,
        skdm: &Skdm,
        now: crate::time::Ms,
    ) -> Result<AcceptedSkdm> {
        self.require_legacy_current(store)?;
        let now_ms = now.get();
        if self.poisoned {
            return Err(self.save_failure());
        }
        let author = skdm.body.author_id;
        let key = self
            .authors
            .get(&author)
            .ok_or(Error::MalformedGovernance("SKDM from an unadmitted author"))?
            .clone();
        // A drive key (ADR-029 SC-2) comes by the same paths as a sender key and is told apart
        // by what it is bound to.
        if skdm.body.channel_id == drive_channel(&self.channel_id) {
            return self.accept_drive_skdm(store, skdm, &key, now_ms);
        }
        let chain = ReceiverChain::from_skdm(skdm, &key, &self.channel_id, self.epoch)?;
        let slot = (author, chain.chain_id());
        // A second SKDM for a generation we already hold would rewind the chain
        // head and re-enable consumed iterations; keep the live one. An earlier authenticated
        // history release widens only the separate history floor. Persist that floor with the
        // bounded rendering obligation so an upgraded v1 profile can recover old cache rows.
        if let Some(existing) = self.receivers.get_mut(&slot) {
            let widened = existing.retain_history_release(&chain)?;
            if !widened {
                return Ok(AcceptedSkdm {
                    rendered: 0,
                    changed: false,
                });
            }
            let saved = (|| -> Result<()> {
                let mut batch = store.batch()?;
                self.queue_receivers(&mut batch)?;
                let mut writer = self
                    .entries
                    .write(&mut batch, &self.sek, &self.channel_id)?;
                writer.queue_backfill(author, Some(1))?;
                writer.seal()?;
                batch.commit()
            })();
            if let Err(error) = saved {
                self.poison(&error);
                return Err(error);
            }
            self.entries.committed();
            return self
                .backfill(store, &author, now_ms)
                .map(|rendered| AcceptedSkdm {
                    rendered,
                    changed: true,
                });
        }
        if self.receivers.len() >= MAX_RECEIVER_CHAINS {
            return Err(Error::SizeLimitExceeded("room receiver chains"));
        }
        self.receivers.insert(slot, chain);
        // The key and the durable rendering cursor are one crash boundary. Startup already
        // drains this bounded cursor; it must never reopen with a held key and no obligation to
        // retry ciphertext accepted before the key arrived.
        let queued = (|| -> Result<()> {
            let mut batch = store.batch()?;
            self.queue_receivers(&mut batch)?;
            {
                let mut writer = self
                    .entries
                    .write(&mut batch, &self.sek, &self.channel_id)?;
                writer.queue_backfill(author, Some(1))?;
                writer.seal()?;
            }
            batch.commit()
        })();
        if let Err(error) = queued {
            self.poison(&error);
            return Err(error);
        }
        self.entries.committed();
        self.drain_backfill(store, now_ms)
            .map(|rendered| AcceptedSkdm {
                rendered,
                changed: true,
            })
    }

    /// Whether this node holds a sender key for `author`.
    #[must_use]
    pub fn has_sender_key(&self, author: &Digest32) -> bool {
        self.receivers.keys().any(|(a, _)| a == author)
    }

    /// Whether this node holds generation `chain_id` of `author`'s sender key.
    #[must_use]
    pub fn holds_generation(&self, author: &Digest32, chain_id: u64) -> bool {
        self.receivers.contains_key(&(*author, chain_id))
    }

    /// Drop every sender key held from an author not in `trusted` (V210-118): a node reads only
    /// the members its owner trusts. Messages already rendered stay rendered; nothing that
    /// arrives from such an author afterwards opens. Returns how many generations were dropped.
    pub fn forget_keys_except(
        &mut self,
        store: &Store,
        trusted: &BTreeSet<Digest32>,
    ) -> Result<usize> {
        self.legacy_cache_trusted = Some(trusted.clone());
        let before = self.receivers.len();
        let me = self.me();
        // Locally authenticated own-history receivers are not third-party trust grants.
        self.receivers
            .retain(|(a, _), _| *a == me || trusted.contains(a));
        let dropped = before - self.receivers.len();
        if dropped > 0 {
            self.persist_receivers(store)?;
        }
        // A drive key too (ADR-029 SC-2): a node reads no Session of a node it does not trust.
        let before = self.drive.receivers.len();
        self.drive.receivers.retain(|(a, _), _| trusted.contains(a));
        if self.drive.receivers.len() != before {
            self.persist_drive(store)?;
        }
        Ok(dropped)
    }

    // ---- Sessions: the drive key (ADR-029 SC-2, SC-2a, SC-2b; #543) ----------------------------

    /// Whether this node holds any drive key of `author`'s here: whether it can read inside
    /// `author`'s Sessions.
    #[must_use]
    pub fn holds_drive_key(&self, author: &Digest32) -> bool {
        self.drive.holds_from(author)
    }

    /// The nodes whose Sessions this node can read inside here, sorted: itself, and each node
    /// whose **live** drive key it holds (SC-2). The author's signed Session floors announce its
    /// generation even when this node is forbidden from receiving the new step bodies. For an
    /// older author without floors, the newest retained drive-sealed entry is the fallback.
    /// A member whose key was rotated away (SC-2b) drops out when the new generation arrives,
    /// unless a
    /// key-package from that author for this node waits to be opened (until the end of the sync
    /// session that brought it, when the node opens it): before that, nothing here can tell the key
    /// changed, and the session's node is the authority on whom it lets drive (DR-2).
    ///
    /// Refuses while any held author's Session control effects are still refreshing here; a
    /// read that can answer per author uses [`Self::drive_from_known`] instead.
    pub fn drive_from(&self, store: &Store) -> Result<Vec<Digest32>> {
        let (known, refreshing) = self.drive_from_known(store)?;
        if !refreshing.is_empty() {
            return Err(Error::StreamRefused("Session control facts are refreshing"));
        }
        Ok(known)
    }

    /// [`Self::drive_from`], answered from what this node knows now (ADR-037 R4): the nodes
    /// whose Sessions it can read inside here, sorted, and apart from them the held authors
    /// whose Session control effects are not yet current here, sorted. The second list lets a
    /// caller say per author that it is fetching that now instead of refusing the room; no
    /// author is dropped silently (ADR-036 H-1). This node itself is always known: its own
    /// Sessions are its own durable fact (R5).
    pub fn drive_from_known(&self, store: &Store) -> Result<(Vec<Digest32>, Vec<Digest32>)> {
        let me = self.me();
        let held: BTreeSet<Digest32> = self.drive.receivers.keys().map(|(a, _)| *a).collect();
        let snapshot = store.snapshot()?;
        let mut known = BTreeSet::new();
        let mut refreshing = BTreeSet::new();
        for author in held {
            if author == me {
                continue;
            }
            if !self.current_session_control_ready(store, &author)? {
                refreshing.insert(author);
                continue;
            }
            let announced = self
                .floor_author(Transaction::Snapshot(&snapshot), &author)?
                .announced;
            // A signed current floor is authoritative in sparse rooms. Only an older author
            // without floors needs the contiguous legacy encrypted-generation fallback, and
            // that fallback's own refusal is this author's gap, not the room's.
            let newest = match announced {
                Some(generation) => Some(generation),
                None => match self.legacy_drive_generation(store, &author) {
                    Ok(generation) => generation,
                    Err(Error::StreamRefused("Session control facts are refreshing")) => {
                        refreshing.insert(author);
                        continue;
                    }
                    Err(error) => return Err(error),
                },
            };
            if newest.is_none_or(|g| self.drive.receivers.contains_key(&(author, g)))
                || self.key_packages.pending_from(&author)
            {
                known.insert(author);
            }
        }
        known.insert(me);
        Ok((
            known.into_iter().collect(),
            refreshing.into_iter().collect(),
        ))
    }

    /// The members a drive key may be owed to: every member admitted here that has not left,
    /// this node excepted. Empty until this node holds its own feed (V210-164).
    #[must_use]
    pub fn drive_members(&self) -> BTreeSet<Digest32> {
        if self.poisoned || !self.settled {
            return BTreeSet::new();
        }
        let me = self.me();
        self.authors
            .keys()
            .copied()
            .filter(|a| *a != me && !self.has_left(a))
            .collect()
    }

    /// The highest drive generation this identity's own feed shows it used here, if any: a node
    /// in the room again must not reuse one the others still hold (as the sender key, V210-164).
    fn drive_used(&self, store: &Store) -> Result<Option<u64>> {
        let me = self.me();
        let ns = drive_channel(&self.channel_id);
        let mut used = self.private_drive_used(store)?;
        let entries = self.entries.read(store, &self.sek, &self.channel_id)?;
        if let Some(feed) = self.dag.feed(&me) {
            for entry in feed.iter(&entries) {
                let entry = entry?;
                if let Some(msg) = entry
                    .payload
                    .as_deref()
                    .and_then(|p| GroupMessage::from_wire(p).ok())
                    .filter(|m| m.header.channel_id == ns)
                {
                    used =
                        Some(used.map_or(msg.header.chain_id, |old| old.max(msg.header.chain_id)));
                }
            }
        }
        Ok(used)
    }

    /// A new drive generation for this node here: past every one it used, owed whole to
    /// `holders`.
    fn begin_drive(
        &mut self,
        store: &Store,
        holders: &BTreeSet<Digest32>,
        now_ms: u64,
        _current: governance::GovernanceCurrent,
    ) -> Result<()> {
        let me = self.me();
        // This author's own floor boundary waits only on this author's own control effects
        // through its committed head; another author's still-building receipt is not this
        // author's publication's to wait on.
        if !self.current_session_control_ready(store, &me)? {
            return Err(Error::StreamRefused(
                session_projection::floor_index::REFRESHING,
            ));
        }
        let published = self
            .floor_author(Transaction::Snapshot(&store.snapshot()?), &me)?
            .announced;
        let floor = self
            .drive
            .chain
            .as_ref()
            .map(SenderChain::chain_id)
            .into_iter()
            .chain(self.drive_used(store)?)
            .chain(published)
            .max();
        // A pre-upgrade departure has no public generation marker. Legacy generations began
        // at zero and incremented; start its replacement in the upper half of the namespace
        // rather than reusing the erased generation. Current departures use their signed floor.
        let first = if self.admission(&me).0 == 0 {
            0
        } else {
            1u64 << 63
        };
        let next = floor.map_or(Ok(first), |f| {
            f.checked_add(1)
                .ok_or(Error::MalformedBundle("drive chain_id overflow"))
        })?;
        let me = self.me();
        let chain = SenderChain::new(
            &drive_channel(&self.channel_id),
            self.epoch,
            &me,
            next,
            now_ms,
        )?;
        let members = self.drive_members();
        self.drive.begin(
            chain,
            holders.iter().filter(|m| members.contains(*m)).copied(),
        );
        Ok(())
    }

    /// Append one entry of Session `session_id` (ADR-029 SC-1), sealed under this node's drive
    /// key (SC-2): only members it trusts with drive (`holders`) open it. The drive key is begun
    /// here at its first use, owed whole to `holders`, and rotated on the sender key's schedule.
    /// Returns the entry's hash.
    pub fn append_session(
        &mut self,
        profile: &Profile,
        session_id: &str,
        body: &str,
        holders: &BTreeSet<Digest32>,
        now_millis: u64,
    ) -> Result<Digest32> {
        self.append_private_session(profile, session_id, body, holders, now_millis)
    }

    /// The sessions with an entry placed in this room since the last call, each once: what the
    /// node says as [`crate::node::api::NodeEvent::SessionEntry`] (ADR-029 CL-2).
    pub fn take_session_news(&mut self) -> Vec<String> {
        let mut news = std::mem::take(&mut self.drive.news);
        news.sort_unstable();
        news.dedup();
        news
    }

    /// Whether this node's drive key here changed and nothing is written under the new one yet
    /// ([`crate::node::drive::KEY_CHANGED`] is owed): a generation past the first with no entry of
    /// this node's under it. Worked out from the log once, then kept up to date.
    pub fn key_change_unsaid(&mut self, store: &Store) -> Result<bool> {
        if let Some(unsaid) = self.drive.change_unsaid {
            return Ok(unsaid);
        }
        let live = self.drive.chain.as_ref().map(SenderChain::chain_id);
        let used = self.drive_used(store)?;
        let unsaid = live.is_some_and(|g| g > 0 && used.is_none_or(|u| u < g));
        self.drive.change_unsaid = Some(unsaid);
        Ok(unsaid)
    }

    /// Begin this node's drive key here if it has none yet and a member of the room is in
    /// `holders` (SC-2a): a member given drive on a Session that has written nothing is owed the
    /// key at once, not at the Session's first entry. Whether a key was begun.
    pub fn ensure_drive(
        &mut self,
        store: &Store,
        holders: &BTreeSet<Digest32>,
        now: crate::time::Ms,
        current: governance::GovernanceCurrent,
    ) -> Result<bool> {
        if self.drive.chain.is_some() || self.poisoned {
            return Ok(false);
        }
        let members = self.drive_members();
        if !holders.iter().any(|h| members.contains(h)) {
            return Ok(false);
        }
        self.begin_drive(store, holders, now.get(), current)?;
        self.persist_drive(store)?;
        self.drive.change_unsaid = None;
        Ok(true)
    }

    /// Change this node's drive key if a member it was released to is no longer in `holders`
    /// (SC-2b): a new generation, owed whole to the members that still are. Returns the members
    /// that lost it; none, and nothing changes, when every holder still has drive.
    pub fn rotate_drive_if_lost(
        &mut self,
        store: &Store,
        holders: &BTreeSet<Digest32>,
        now: crate::time::Ms,
        current: governance::GovernanceCurrent,
    ) -> Result<Vec<Digest32>> {
        let now_ms = now.get();
        let lost = self.drive.lost(holders);
        if lost.is_empty() || self.drive.chain.is_none() {
            return Ok(lost);
        }
        self.drive.forget(&lost);
        self.begin_drive(store, holders, now_ms, current)?;
        self.persist_drive(store)?;
        self.drive.change_unsaid = Some(true);
        Ok(lost)
    }

    /// The members owed this node's live drive key (SC-2a), each now marked owed from where the
    /// key stands, if it was not before; the marks are kept, so a release made later is made
    /// from them.
    pub fn owed_drive(
        &mut self,
        profile: &Profile,
        holders: &BTreeSet<Digest32>,
        now: crate::time::Ms,
    ) -> Result<Vec<Digest32>> {
        self.ensure_session_floors(profile, holders, now.get())?;
        let members = self.drive_members();
        let owed = self.drive.take_owed(&members, holders);
        if !owed.is_empty() {
            self.persist_drive(profile.store())?;
        }
        Ok(owed)
    }

    /// The SKDM releasing this node's live drive key to `member` from its mark, and its
    /// generation, for [`Self::note_drive_delivered`] once sent.
    pub fn drive_skdm_for(
        &self,
        profile: &Profile,
        member: &Digest32,
        _current: governance::GovernanceCurrent,
    ) -> Result<(Skdm, u64)> {
        self.require_legacy_current(profile.store())?;
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.drive.release_for(profile.signer()?, member)
    }

    /// Record that `member` holds generation `generation` of this node's drive key.
    pub fn note_drive_delivered(
        &mut self,
        store: &Store,
        member: Digest32,
        generation: u64,
    ) -> Result<()> {
        self.drive.note_delivered(member, generation);
        self.persist_drive(store)
    }

    /// Take a drive key `author` released to this node (SC-2), verified against its admitted key
    /// and bound to this room's drive namespace, and open what it can of `author`'s Sessions.
    fn accept_drive_skdm(
        &mut self,
        store: &Store,
        skdm: &Skdm,
        key: &CompositePublicKey,
        now_ms: u64,
    ) -> Result<AcceptedSkdm> {
        let chain =
            ReceiverChain::from_skdm(skdm, key, &drive_channel(&self.channel_id), self.epoch)?;
        let slot = (skdm.body.author_id, chain.chain_id());
        if self.drive.receivers.contains_key(&slot) {
            return Ok(AcceptedSkdm {
                rendered: 0,
                changed: false,
            });
        }
        if self.drive.receivers.len() >= crate::node::drive::MAX_DRIVE_CHAINS {
            return Err(Error::SizeLimitExceeded("room drive keys"));
        }
        self.drive.receivers.insert(slot, chain);
        self.reset_private_pulls();
        self.persist_drive(store)?;
        self.drive.told_unheld.remove(&skdm.body.author_id);
        let before = self.drive.news.len();
        self.backfill(store, &skdm.body.author_id, now_ms)?;
        self.render_pending_private(store, now_ms)?;
        // What it opened of Sessions: a key-changed entry is none of theirs.
        Ok(AcceptedSkdm {
            rendered: self.drive.news[before..]
                .iter()
                .filter(|id| !crate::node::drive::is_key_changed(id))
                .count(),
            changed: true,
        })
    }

    /// Open one Session entry with the drive key it names, if this node holds it, queueing its
    /// cache row into `batch`; skipped quietly if it does not.
    fn render_session_into(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        author: Digest32,
        entry_hash: Digest32,
        msg: &GroupMessage,
        now_ms: u64,
        expired: &mut Vec<(Digest32, Tracked)>,
    ) -> Result<()> {
        let Some(chain) = self.drive.receivers.get_mut(&(author, msg.header.chain_id)) else {
            // An entry under a key of the author's this node does not hold, from an author whose
            // key it held: the author changed its key away from this node, and this node's drive
            // over the author's Sessions is gone (SC-2b). Said once as Session news for the room,
            // so a client that keeps the room's Sessions reads them again; there is no row.
            if self.drive.holds_from(&author) && self.drive.told_unheld.insert(author) {
                self.drive
                    .news
                    .push(crate::node::drive::KEY_CHANGED.to_owned());
            }
            return Ok(());
        };
        let Ok(plaintext) = chain.decrypt(msg).map(Zeroizing::new) else {
            return Ok(());
        };
        self.chains_advanced = true;
        // Only a Session entry opens under a drive key: a node's message to the room is sealed
        // under its sender key, for every reader.
        let Ok(Decoded::Session(entry)) = crate::node::content::decode(&plaintext) else {
            self.remember_legacy_kind(batch, entry_hash, author, false)?;
            return Ok(());
        };
        self.remember_legacy_kind(batch, entry_hash, author, true)?;
        if self.already_expired(
            Transaction::Batch(batch),
            &entry_hash,
            entry.created_millis,
            now_ms,
        )? {
            self.queue_retention_rendered(batch, &entry_hash, entry.created_millis, None)?;
            expired.extend(
                self.retention_get_in(Transaction::Batch(batch), &entry_hash)?
                    .map(|t| (entry_hash, t)),
            );
            return Ok(());
        }
        let id = self.next_log_id;
        let row = SessionRow {
            entry_hash,
            author,
            created_millis: entry.created_millis,
            session_id: entry.session_id,
            body: entry.body,
        };
        let cache_seg = seal_segment(
            &self.sek,
            SegmentKind::PlaintextCache,
            id,
            &session_cache_bytes(&row),
        )?;
        batch.put_segment(
            &self.channel_id,
            SegmentKind::PlaintextCache,
            id,
            &cache_seg,
        )?;
        self.queue_retention_rendered(batch, &entry_hash, row.created_millis, Some(id))?;
        self.next_log_id = id.saturating_add(1);
        self.drive.pending.push((row, id));
        Ok(())
    }

    fn persist_drive(&mut self, store: &Store) -> Result<()> {
        let saved = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_DRIVE,
            &self.drive.to_state(),
        )
        .and_then(|seg| {
            store.put_segment(&self.channel_id, SegmentKind::KeyMaterial, SEG_DRIVE, &seg)
        });
        if let Err(e) = saved {
            self.poisoned = true;
            self.save_error = Some(e.to_string());
            return Err(e);
        }
        Ok(())
    }

    /// Offer `target` again **every** generation it is entitled to, if it is consented to here
    /// (V210-118): the live one, and each retired one from where its entitlement began, as
    /// history. `target` may have refused them while its owner did not trust this identity, or
    /// dropped them when its owner stopped trusting it; a key it has just handed over says it may
    /// take ours now. Only the live generation was offered again, so the posts sealed under a
    /// generation retired in between stayed unreadable to it for good, although it was entitled
    /// to them. Sending a generation it already holds is harmless: [`Self::accept_skdm`] keeps the
    /// one it has.
    pub fn reoffer(&mut self, store: &Store, target: &Digest32) -> Result<()> {
        if !self.has_consented(store, target)? {
            return Ok(());
        }
        self.owe_entitled_history(store, target)?;
        if self.delivered.remove(target).is_some() {
            self.persist_delivered(store)?;
        }
        Ok(())
    }

    /// Owe `target`, as history, every retired generation from the one its entitlement begins
    /// in (V210-118). Nothing when it is entitled only to the live one, which the ordinary re-key
    /// covers.
    pub fn owe_entitled_history(&mut self, store: &Store, target: &Digest32) -> Result<()> {
        match self.entitled_from(target) {
            Some((from, _)) => self.owe_history(store, *target, from),
            None => Ok(()),
        }
    }

    /// Persist the receiver chains, poisoning the channel if sealing or writing fails.
    fn persist_receivers(&mut self, store: &Store) -> Result<()> {
        let saved = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_RECEIVERS,
            &receivers_bytes(&self.receivers),
        )
        .and_then(|seg| {
            store.put_segment(
                &self.channel_id,
                SegmentKind::KeyMaterial,
                SEG_RECEIVERS,
                &seg,
            )
        });
        if let Err(e) = saved {
            self.poisoned = true;
            self.save_error = Some(e.to_string());
            return Err(e);
        }
        Ok(())
    }

    /// How many generations of other members' sender keys this node holds here: what `vox
    /// status` reports beside [`Self::key_generations`], and what R14 keeps down to the ones
    /// still needed ([`Self::prune_superseded_receivers`]).
    #[must_use]
    pub fn received_key_generations(&self) -> usize {
        self.receivers.len()
    }

    /// Delete every received sender-key generation this node no longer needs (PRD-001 R14 on
    /// the receiving side): the sender prunes its own origins ([`Self::prune_superseded_origins`]),
    /// and a receiver that kept every generation it was ever given still opened all of them.
    ///
    /// A generation `c` of `author` is no longer needed once this node holds `author`'s feed
    /// without a gap up to an entry under a later generation, and every entry under `c` in that
    /// stretch is rendered. A sender only moves forward, so no entry under `c` can follow one
    /// under a later generation: none can still arrive. An entry whose body has expired here
    /// (PRD-001 R10) needs no key. **An entry whose body has not arrived and has not expired is
    /// not received yet** (V030-10): it fills in later, and which generation it is under is
    /// unknown until it does, so it counts as a gap. Kept: the newest generation held, and every
    /// generation with an entry not yet rendered — no consent on the log yet, say — or that may
    /// still be followed by one (a gap, a body still to come, or no later generation yet).
    /// Returns how many generations went.
    pub fn prune_superseded_receivers(&mut self, store: &Store) -> Result<usize> {
        if self.poisoned {
            return Ok(0);
        }
        let rendered = self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?;
        let authors: BTreeSet<Digest32> = self.receivers.keys().map(|(a, _)| *a).collect();
        let mut gone: Vec<(Digest32, u64)> = Vec::new();
        for author in authors {
            let held: Vec<u64> = self
                .receivers
                .range((author, 0)..=(author, u64::MAX))
                .map(|((_, c), _)| *c)
                .collect();
            if held.len() <= 1 {
                continue;
            }
            let Some(feed) = self.dag.feed(&author) else {
                continue;
            };
            let mut newest: Option<u64> = None;
            let mut unrendered: BTreeSet<u64> = BTreeSet::new();
            for seq in 1..=self.dag.verified_head(&author) {
                // A gap: what follows it is not known, so neither is what it still needs.
                let Some(entry) =
                    feed.get(&self.entries.read(store, &self.sek, &self.channel_id)?, seq)?
                else {
                    break;
                };
                let Some(payload) = entry.payload.as_deref() else {
                    // Expired: its key is needed by nothing. Not expired: a body still to come,
                    // under a generation not known yet — every generation from here on stays.
                    if self.body_expired(entry.skeleton.claimed_ms, crate::time::Ms(self.now_hint))
                    {
                        continue;
                    }
                    break;
                };
                if !matches!(classify_payload(payload), Ok(EntryKind::Content)) {
                    continue;
                }
                let Ok(msg) = GroupMessage::from_wire(payload) else {
                    continue;
                };
                let c = msg.header.chain_id;
                newest = Some(newest.map_or(c, |n| n.max(c)));
                if rendered.fact(&entry.entry_hash())?.is_none() {
                    unrendered.insert(c);
                }
            }
            let Some(newest) = newest else {
                continue;
            };
            let last_held = held.last().copied().unwrap_or(0);
            gone.extend(
                held.iter()
                    .filter(|c| **c < newest && **c < last_held && !unrendered.contains(c))
                    .map(|c| (author, *c)),
            );
        }
        if gone.is_empty() {
            return Ok(0);
        }
        for slot in &gone {
            // `ReceiverChain` holds its chain and skipped keys zeroized on drop.
            self.receivers.remove(slot);
        }
        self.persist_receivers(store)?;
        Ok(gone.len())
    }

    fn backfill(&mut self, store: &Store, author: &Digest32, now_ms: u64) -> Result<usize> {
        // Commit one bounded backfill chunk and its continuation together.
        let mut rows: Vec<Rendered> = Vec::new();
        let mut expired: Vec<(Digest32, Tracked)> = Vec::new();
        let result = (|| -> Result<()> {
            let mut batch = store.batch()?;
            rows =
                self.backfill_into(&mut batch, author, &BTreeSet::new(), now_ms, &mut expired)?;
            // Even an unrendered page advances the durable work cursor. Do not discard it
            // merely because this chunk did not hold a newly readable body.
            if self.chains_advanced {
                self.queue_receivers(&mut batch)?;
            }

            batch.commit()
        })();
        if let Err(e) = result {
            self.poisoned = true;
            self.save_error = Some(e.to_string());
            return Err(e);
        }
        // The cursor moves even when this page renders no plaintext row. Drop the entry-store
        // read cache at the commit boundary or the next maintenance turn sees the old queue root
        // and commits the same page forever.
        self.entries.committed();
        self.chains_advanced = false;
        let rendered = rows.len();
        self.place_committed(store, rows, &expired)?;
        Ok(rendered)
    }

    /// Render every stored content entry from `author` not yet in the timeline (nor in `skip`)
    /// into `batch`, without committing it.
    fn backfill_into(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        author: &Digest32,
        skip: &BTreeSet<Digest32>,
        now_ms: u64,
        expired: &mut Vec<(Digest32, Tracked)>,
    ) -> Result<Vec<Rendered>> {
        {
            let mut writer = self.entries.write(batch, &self.sek, &self.channel_id)?;
            writer.queue_backfill(*author, Some(1))?;
            writer.seal()?;
        }
        self.drain_backfill_into(batch, skip, now_ms, expired)
    }

    fn drain_backfill_into(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        skip: &BTreeSet<Digest32>,
        now_ms: u64,
        expired: &mut Vec<(Digest32, Tracked)>,
    ) -> Result<Vec<Rendered>> {
        #[cfg(feature = "test-knobs")]
        if self.render_backfill_held_for_proof() {
            return Ok(Vec::new());
        }
        let consent = match self.consent_facts() {
            Ok(facts) => {
                self.backfill_refreshing = false;
                facts
            }
            Err(error) if governance::refreshing(&error) => {
                // Nothing rendered, the queue kept: the governance turn after this refresh
                // drains it (ADR-038 FX-22, #1007), not the retention sweep.
                self.backfill_refreshing = true;
                return Ok(Vec::new());
            }
            Err(error) => return Err(error),
        };
        let mut rows = Vec::new();
        let mut bytes = 0usize;
        for _ in 0..RENDER_BACKFILL_ROWS_PER_TURN {
            let mut writer = self.entries.write(batch, &self.sek, &self.channel_id)?;
            let mut next = writer.next_backfill_after(self.backfill_after)?;
            if next.is_none() && self.backfill_after.is_some() {
                next = writer.next_backfill_after(None)?;
            }
            let Some((author, seq)) = next else {
                self.backfill_after = None;
                break;
            };
            self.backfill_after = Some(author);
            // Consent applies to every row by this author, and no row by the author can open
            // before this node holds at least one of its sender generations. Remove a blocked
            // author from runnable work instead of scanning or resetting it forever. Acceptance
            // of the missing consent/key is the durable event that queues it again. Removing only
            // this author leaves every other queued author eligible in this same bounded turn.
            let author_ready = if author == self.me() {
                true
            } else {
                consent.can_read(&self.me(), &author) && self.has_sender_key(&author)
            };
            if !author_ready {
                writer.queue_backfill(author, None)?;
                writer.seal()?;
                continue;
            }
            let sparse = writer.sparse_enabled();
            let (entry_seq, entry) = if sparse {
                let Some((accepted_seq, entry)) = writer.next_sparse_backfill(&author, seq)? else {
                    writer.queue_backfill(author, None)?;
                    writer.seal()?;
                    continue;
                };
                (accepted_seq, entry)
            } else {
                let head = self.dag.verified_head(&author);
                if seq > head {
                    writer.queue_backfill(author, None)?;
                    writer.seal()?;
                    continue;
                }
                (
                    seq,
                    Some(
                        writer
                            .get(&author, seq)?
                            .ok_or(Error::MalformedAtRest("backfill entry missing"))?,
                    ),
                )
            };
            let cost = entry
                .as_ref()
                .and_then(|entry| entry.payload.as_ref())
                .map_or(0, Vec::len);
            if bytes != 0 && bytes.saturating_add(cost) > 1024 * 1024 {
                break;
            }
            writer.queue_backfill(
                author,
                if sparse {
                    Some(
                        entry_seq
                            .checked_add(1)
                            .ok_or(Error::MalformedAtRest("backfill sequence exhausted"))?,
                    )
                } else if entry_seq == self.dag.verified_head(&author) {
                    None
                } else {
                    Some(
                        entry_seq
                            .checked_add(1)
                            .ok_or(Error::MalformedAtRest("backfill sequence exhausted"))?,
                    )
                },
            )?;
            writer.seal()?;
            let Some(entry) = entry else {
                // Its sparse effect has not settled yet. Once it does, that path renders with
                // the key now held; continue to the next actually accepted sparse position.
                continue;
            };
            let hash = entry.entry_hash();
            bytes = bytes.saturating_add(cost);
            let already = writer.has_rendered(&hash)?
                || writer.read_receipt_cache(&hash)?.is_some()
                || writer
                    .retention(&hash)?
                    .is_some_and(|r| r.cache_id.is_some())
                || self.private_contains_in(writer.batch(), &hash)?
                || self
                    .drive
                    .pending
                    .iter()
                    .any(|(row, _)| row.entry_hash == hash)
                || skip.contains(&hash);
            // The Batch owns all tree changes; release its short writer before decryption.
            let payload = entry.payload;
            if already {
                continue;
            }
            let Some(payload) = payload else {
                continue;
            };
            if !matches!(classify_payload(&payload), Ok(EntryKind::Content)) {
                continue;
            }
            if let Some(row) = self
                .render_content_into(batch, author, hash, &payload, None, now_ms, true, expired)?
                .into_row()
            {
                rows.push(row);
            }
        }
        Ok(rows)
    }

    /// Whether a render backfill waits on the governance view's refresh (ADR-038 FX-22,
    /// #1007): rows that arrived before their key, or before their author's consent folded,
    /// are rendered by the governance turn after the refresh, with no re-ask.
    #[must_use]
    pub fn backfill_awaits_refresh(&self) -> bool {
        self.backfill_refreshing
    }

    fn drain_backfill(&mut self, store: &Store, now_ms: u64) -> Result<usize> {
        // No durable cursor means no render work. Return before `place_committed`: that follow-up
        // also advances legacy/private-session migration and is not a harmless empty read. A
        // maintenance sweep with no backfill used to run it for every room on every unrelated
        // continuation, keeping the actor hot and starving commands even while shipped status
        // truthfully reported `render_backfill_pending: false`.
        if !self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?
            .has_backfill()
        {
            self.backfill_after = None;
            self.backfill_refreshing = false;
            return Ok(0);
        }
        let mut expired = Vec::new();
        let result = (|| -> Result<Vec<Rendered>> {
            let mut batch = store.batch()?;
            let rows =
                self.drain_backfill_into(&mut batch, &BTreeSet::new(), now_ms, &mut expired)?;
            if self.chains_advanced {
                self.queue_receivers(&mut batch)?;
            }

            batch.commit()?;
            Ok(rows)
        })();
        let rows = match result {
            Ok(rows) => rows,
            Err(error) => {
                self.poison(&error);
                return Err(error);
            }
        };
        // An unrendered page still advances or removes its durable cursor. `place_committed`
        // clears the cache only when it has a visible row to seal, so clear it here for every
        // successful queue commit.
        self.entries.committed();
        self.chains_advanced = false;
        let rendered = rows.len();
        #[cfg(feature = "test-knobs")]
        engage_render_hold(&self.channel_id, &rows);
        self.place_committed(store, rows, &expired)?;
        Ok(rendered)
    }

    /// Whether test apparatus has parked this room after a causally named render turn. The
    /// durable queue remains truthful through [`Self::governance_backfill_pending`]; the actor
    /// merely stops rescheduling until the proof removes the marker and supplies its next event.
    #[cfg(feature = "test-knobs")]
    #[must_use]
    pub fn render_backfill_held_for_proof(&self) -> bool {
        let Some(path) = render_hold_path() else {
            return false;
        };
        if let Ok(marker) = std::fs::read(&path) {
            if marker.is_empty() {
                return true;
            }
            if marker.len() == 96 && marker[..32] == self.channel_id[..] {
                let mut first = [0; 32];
                first.copy_from_slice(&marker[32..64]);
                let mut second = [0; 32];
                second.copy_from_slice(&marker[64..]);
                if self.has_sender_key(&first) && self.has_sender_key(&second) {
                    let _ = std::fs::rename(&path, render_hold_suffixed_path(&path, ".ready"));
                }
                return true;
            }
        }
        if std::fs::read(render_hold_suffixed_path(&path, ".ready"))
            .is_ok_and(|marker| marker.len() == 96 && marker[..32] == self.channel_id[..])
        {
            return true;
        }
        std::fs::read(render_hold_suffixed_path(&path, ".engaged"))
            .is_ok_and(|marker| marker.len() == 64 && marker[..32] == self.channel_id[..])
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
        now_ms: u64,
    ) -> Result<bool> {
        let mut expired: Vec<(Digest32, Tracked)> = Vec::new();
        let persisted = (|| -> Result<Option<Rendered>> {
            let mut batch = store.batch()?;
            let projection = self.render_content_into(
                &mut batch,
                author,
                entry_hash,
                payload,
                None,
                now_ms,
                false,
                &mut expired,
            )?;
            let deferred = matches!(&projection, ContentProjection::Deferred);
            let row = projection.into_row();
            if row.is_none()
                && expired.is_empty()
                && self.drive.pending.is_empty()
                && !self.chains_advanced
                && !self.legacy_sessions.dirty()
                && !deferred
            {
                return Ok(None);
            }
            self.queue_receivers(&mut batch)?;

            batch.commit()?;
            Ok(row)
        })();
        match persisted {
            Ok(row) => {
                let shown = row.is_some();
                self.place_committed(store, row.into_iter().collect(), &expired)?;
                Ok(shown)
            }
            Err(e) => {
                // The chain advanced in memory but the advance was not persisted: a
                // reopen would re-derive a consumed key. Poison instead.
                self.poisoned = true;
                self.save_error = Some(e.to_string());
                Err(e)
            }
        }
    }

    /// Decrypt one content payload and queue its sealed plaintext-cache row into `batch`.
    /// `Visible` carries the row the caller places after commit; `Applied` records an intentional
    /// non-row; `Deferred` preserves an explicit demand until transient projection state advances.
    ///
    /// **One transaction per pass, not two per entry.** Each entry used to commit its own cache
    /// row and its own copy of the receiver chains — two durable commits, about 17 ms apiece on
    /// macOS, taken while holding the room's lock. A sync delivering 133 of another member's
    /// messages held the room for 2.3 s, and every post made in that room waited behind it
    /// (V210-08, #179: `vox room post` p95 of seconds while a peer posts). The caller queues the
    /// receiver chains once, after its loop, and commits once.
    ///
    /// **A late arrival of an expired message never renders** (ADR-023 decision 2): its key has
    /// been used, so the caller still queues the chains, and the body is pushed onto `expired` to
    /// be pruned **after** the commit — pruning writes, and a write opened while `batch` is open
    /// blocks forever (redb).
    #[allow(clippy::too_many_arguments)]
    fn render_content_into(
        &mut self,
        batch: &mut crate::node::store::Batch<'_>,
        author: Digest32,
        entry_hash: Digest32,
        payload: &[u8],
        pending_sparse_entry: Option<&Entry>,
        now_ms: u64,
        historical: bool,
        expired: &mut Vec<(Digest32, Tracked)>,
    ) -> Result<ContentProjection> {
        let me = self.me();
        if author != me {
            let allowed = match self.consent_facts() {
                Ok(facts) => Some(facts.can_read(&me, &author)),
                Err(error) if governance::refreshing(&error) => None,
                Err(error) => return Err(error),
            };
            match allowed {
                Some(true) => {}
                Some(false) => {
                    // Park on the missing fact. The consent grant's acceptance queues this
                    // author in the same durable transaction as that grant; making every row
                    // queue itself here reset the cursor to one during historical backfill and
                    // kept an idle daemon turning forever.
                    return Ok(ContentProjection::Applied);
                }
                None => {
                    let mut writer = self.entries.write(batch, &self.sek, &self.channel_id)?;
                    writer.queue_backfill(author, Some(1))?;
                    writer.seal()?;
                    return Ok(ContentProjection::Deferred);
                }
            }
        }
        let msg = match GroupMessage::from_wire(payload) {
            Ok(m) => m,
            Err(_) => return Ok(ContentProjection::Applied),
        };
        // **A Session entry opens only with its node's drive key** (ADR-029 SC-2): a member
        // without it skips the entry, quietly; it is never owed, never a row.
        if msg.header.channel_id == drive_channel(&self.channel_id) {
            self.render_session_into(batch, author, entry_hash, &msg, now_ms, expired)?;
            return Ok(ContentProjection::Applied);
        }
        let slot = (author, msg.header.chain_id);
        if historical {
            let writer = self.entries.write(batch, &self.sek, &self.channel_id)?;
            let already = writer.has_rendered(&entry_hash)?
                || writer.read_receipt_cache(&entry_hash)?.is_some()
                || writer
                    .retention(&entry_hash)?
                    .is_some_and(|record| record.cache_id.is_some())
                || self.private_contains_in(writer.batch(), &entry_hash)?
                || self
                    .drive
                    .pending
                    .iter()
                    .any(|(row, _)| row.entry_hash == entry_hash);
            if already {
                return Ok(ContentProjection::Applied);
            }
        }
        let Some(chain) = self.receivers.get_mut(&slot) else {
            if author == me && self.own_behind {
                // Retaining ciphertext is not readable recovery. A generation minted after
                // the backup may have no local origin; never give it a role-complete receipt.
                return Ok(ContentProjection::Unavailable);
            }
            // Park on the missing fact. Installing or widening an SKDM queues this author in
            // the same durable transaction as the receiver chain. ChannelState is serialized,
            // so a key cannot commit and drain between this check and this row's acceptance.
            return Ok(ContentProjection::Applied);
        };
        let plaintext = match if historical {
            chain.decrypt_history(&msg)
        } else {
            chain.decrypt(&msg)
        } {
            Ok(p) => Zeroizing::new(p),
            Err(_) if historical => return Ok(ContentProjection::Unavailable),
            Err(_) => return Ok(ContentProjection::Applied),
        };
        self.chains_advanced = true;
        // **Skipped, not propagated** — matching the three `Ok(None)` paths above it.
        //
        // An entry this node cannot render is one entry it cannot show, and every other reason for
        // that here already degrades: an unreadable group message, a missing receiver chain, a
        // failed decrypt. Only the content decode used `?`, which returns out of a function whose
        // three callers invoke it with `?` **inside a loop over pending entries** — so one
        // undecodable envelope did not hide one message, it aborted the render pass and took every
        // later entry in it along.
        let content = match crate::node::content::decode(&plaintext) {
            Ok(Decoded::Text(content)) => content,
            // **A read record is never a row** (ADR-028 RR-4): it is cached like a message, so it
            // survives a restart (its key is used up), and ages like one (RR-2), and is indexed
            // for `read by` once the batch has committed.
            Ok(Decoded::Read(record)) => {
                let expired_now = match pending_sparse_entry {
                    Some(entry) => self.already_expired_entry(
                        Transaction::Batch(batch),
                        entry,
                        record.created_millis,
                        now_ms,
                    ),
                    None => self.already_expired(
                        Transaction::Batch(batch),
                        &entry_hash,
                        record.created_millis,
                        now_ms,
                    ),
                }?;
                if expired_now {
                    self.queue_retention_rendered(batch, &entry_hash, record.created_millis, None)?;
                    expired.extend(
                        self.retention_get_in(Transaction::Batch(batch), &entry_hash)?
                            .map(|t| (entry_hash, t)),
                    );
                    return Ok(ContentProjection::Applied);
                }
                let id = self.next_log_id;
                let row = ReadRow {
                    entry_hash,
                    reader: author,
                    created_millis: record.created_millis,
                    read: record.read,
                };
                let cache_seg = seal_segment(
                    &self.sek,
                    SegmentKind::PlaintextCache,
                    id,
                    &read_cache_bytes(&row),
                )?;
                batch.put_segment(
                    &self.channel_id,
                    SegmentKind::PlaintextCache,
                    id,
                    &cache_seg,
                )?;
                {
                    let mut index = self.entries.write(batch, &self.sek, &self.channel_id)?;
                    index.put_read_receipt(&row, id)?;
                    index.retention_rendered(&entry_hash, row.created_millis, Some(id))?;
                    index.seal()?;
                }
                self.next_log_id = id.saturating_add(1);
                return Ok(ContentProjection::Applied);
            }
            // A Session entry sealed under the sender key is not one: its node gave it to every
            // reader, and the Session is only for those with drive (SC-2). Not shown.
            Ok(Decoded::LegacySessionIndex(index)) => {
                self.accept_legacy_index(batch, entry_hash, author, index, now_ms)?;
                return Ok(ContentProjection::Applied);
            }
            Ok(Decoded::Session(_)) | Err(_) => return Ok(ContentProjection::Applied),
        };
        let expired_now = match pending_sparse_entry {
            Some(entry) => self.already_expired_entry(
                Transaction::Batch(batch),
                entry,
                content.created_millis,
                now_ms,
            ),
            None => self.already_expired(
                Transaction::Batch(batch),
                &entry_hash,
                content.created_millis,
                now_ms,
            ),
        }?;
        if expired_now {
            self.queue_retention_rendered(batch, &entry_hash, content.created_millis, None)?;
            expired.extend(
                self.retention_get_in(Transaction::Batch(batch), &entry_hash)?
                    .map(|t| (entry_hash, t)),
            );
            return Ok(ContentProjection::Applied);
        }
        // The cache row shares the entry's log id space; use a fresh id so it never
        // collides with an authored row. It is also the row's arrival (ADR-023 decision 1).
        let id = self.next_log_id;
        let rendered = Rendered {
            entry_hash,
            author,
            created_millis: content.created_millis,
            text: content.text,
            arrival: id,
            shown_at_ms: 0,
            late: false,
            owed: false,
        };
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
        {
            let mut index = self.entries.write(batch, &self.sek, &self.channel_id)?;
            index.put_rendered(&rendered, shown_now())?;
            index.retention_rendered(&entry_hash, rendered.created_millis, Some(id))?;
            index.seal()?;
        }
        // A cache row, not an entry: the generation counts entries only (ADR-025 D1).
        self.next_log_id = id.saturating_add(1);
        Ok(ContentProjection::Visible(rendered))
    }

    /// The data commit has completed. Give its bounded rows one visibility time before
    /// publishing their display facts, so time spent decrypting or committing this batch
    /// cannot make its own rows look late relative to each other.
    fn seal_render_visibility(&mut self, store: &Store, rows: &[Rendered]) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let shown = shown_now();
        let result = (|| -> Result<()> {
            let mut batch = store.batch()?;
            let mut index = self
                .entries
                .write(&mut batch, &self.sek, &self.channel_id)?;
            for row in rows {
                index.remove_rendered(&row.entry_hash)?;
            }
            for row in rows {
                index.put_rendered(row, shown)?;
            }
            index.seal()?;
            batch.commit()?;
            self.entries.committed();
            Ok(())
        })();
        if let Err(ref error) = result {
            self.poison(error);
        }
        result
    }

    /// After a committed render pass, retain only display watermarks.
    /// Bodies/order/late facts are already sealed. Prune expired late arrivals in their own
    /// transaction now that the rendering batch has committed.
    fn place_committed(
        &mut self,
        store: &Store,
        rows: Vec<Rendered>,
        expired: &[(Digest32, Tracked)],
    ) -> Result<()> {
        self.seal_render_visibility(store, &rows)?;
        self.legacy_sessions.committed();
        for (row, _) in std::mem::take(&mut self.drive.pending) {
            if !crate::node::drive::is_key_changed(&row.session_id) {
                self.drive.news.push(row.session_id.clone());
            }
        }
        for rendered in rows {
            self.note_rendered(store, &rendered.entry_hash)?;
        }
        let settled = (|| -> Result<()> {
            if !expired.is_empty() {
                self.prune(store, expired, true)?;
            }
            self.migrate_legacy_steps(store, self.now_hint)?;
            Ok(())
        })();
        if let Err(ref error) = settled {
            self.poison(error);
        }
        settled
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
        )?;
        // The drive keys advance in the same passes.
        self.queue_drive(batch)
    }

    fn queue_drive(&self, batch: &mut crate::node::store::Batch<'_>) -> Result<()> {
        let seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_DRIVE,
            &self.drive.to_state(),
        )?;
        batch.put_segment(&self.channel_id, SegmentKind::KeyMaterial, SEG_DRIVE, &seg)
    }

    /// Note only the committed row's sealed ordering and shown-time facts. No plaintext is
    /// retained, and late flags are derived by RenderView from ranked suffix metadata.
    fn note_rendered(&mut self, store: &Store, hash: &Digest32) -> Result<()> {
        let result = (|| -> Result<()> {
            self.settle_display_order(store)?;
            let rendered = self
                .entries
                .render_view(store, &self.sek, &self.channel_id)?;
            let key = rendered
                .order()
                .key(hash)?
                .ok_or(Error::MalformedAtRest("rendered entry not published"))?;
            let fact = rendered
                .fact(hash)?
                .ok_or(Error::MalformedAtRest("committed rendering missing"))?;
            drop(rendered);
            if self.display_tail.is_some_and(|tail| key <= tail)
                || fact.shown < self.display_shown_at
            {
                self.invalidate_display();
            }
            self.display_tail = Some(self.display_tail.map_or(key, |tail| tail.max(key)));
            self.display_shown_at = self.display_shown_at.max(fact.shown);
            Ok(())
        })();
        if let Err(ref error) = result {
            self.poison(error);
        }
        result
    }

    /// Canonical moves are already reflected in the sealed render tree. Refresh just the
    /// tail watermark and invalidate any notice scan that depended on the old prefix.
    fn settle_display_order(&mut self, store: &Store) -> Result<()> {
        let result = (|| -> Result<()> {
            if self.poisoned {
                return Err(self.save_failure());
            }
            let generation = self.dag.reorder_generation();
            if generation != self.display_order_revision {
                self.display_tail = self
                    .entries
                    .render_view(store, &self.sek, &self.channel_id)?
                    .step(None, true, None, true)?
                    .map(|(key, _)| key);
                self.display_order_revision = generation;
                self.invalidate_display();
            }
            Ok(())
        })();
        if let Err(ref error) = result {
            self.poison(error);
        }
        result
    }

    /// Whether `a` happened before `b` in this room: `a` is a causal ancestor of `b`
    /// through `b`'s author's feed and the `seen` edges this node holds
    /// ([`Dag::happened_before`]). `false` means concurrent or not yet known to be
    /// ordered. The seam claims are to be built on (PRD-001 R17).
    pub fn happened_before(&self, store: &Store, a: &Digest32, b: &Digest32) -> Result<bool> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.dag.happened_before(
            &self.entries.read(store, &self.sek, &self.channel_id)?,
            a,
            b,
        )
    }

    /// Every entry this node holds for the room — readable or not, body pruned or not —
    /// in the room's one order (PRD-001 R13). The timeline is this sequence restricted
    /// to the rows this node can render.
    pub fn causal_order(&self, store: &Store) -> Result<Vec<Digest32>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.dag
            .causal_order(&self.entries.read(store, &self.sek, &self.channel_id)?)
    }

    /// [`ChannelState::causal_order`] with each entry's clock. Transitional view consumer;
    /// bounded query callers use [`Self::order_view`] instead of collecting history.
    pub fn order_keys(&self, store: &Store) -> Result<Vec<(Digest32, u64)>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.dag
            .order_keys(&self.entries.read(store, &self.sek, &self.channel_id)?)
    }

    /// Pin published DAG roots for a bounded query. Drop the view before a client/network wait.
    pub fn order_view(&self, store: &Store) -> Result<OrderView<'_>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.entries.order_view(store, &self.sek, &self.channel_id)
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
    pub fn accept_entry(
        &mut self,
        store: &Store,
        entry: Entry,
        now: crate::time::Ms,
    ) -> Result<Accepted> {
        let now_ms = now.get();
        if self.poisoned {
            return Err(self.save_failure());
        }
        if entry.skeleton.channel_id != self.channel_id {
            return Err(Error::MalformedGovernance("entry binds another room"));
        }
        if entry.skeleton.epoch != self.epoch {
            return Err(Error::MalformedGovernance("entry binds another epoch"));
        }
        // A skeleton without its signature is authentic only through a signed successor,
        // which a single entry cannot bring; only a sync session, which brings the feed,
        // takes them (ADR-023 decision 3).
        if !entry.is_signed() {
            return Err(Error::MalformedGovernance(
                "an unsigned entry arrives only inside a sync session",
            ));
        }
        let author = entry.skeleton.author_id;
        let key = self
            .authors
            .get(&author)
            .ok_or(Error::MalformedGovernance(
                "entry from an unadmitted author",
            ))?
            .clone();
        // A pruned entry is a skeleton the peer no longer holds a body for: stored, so the
        // feed stays whole, and never rendered (ADR-023 decision 2).
        let kind = match entry.payload.as_deref() {
            Some(payload) => classify_payload(payload)?,
            None => EntryKind::Content,
        };
        let gov = if kind == EntryKind::Governance
            || entry
                .payload
                .as_deref()
                .is_some_and(crate::governance::step_policy::is_step_policy)
        {
            Some(GovEntry::from_verified_log_entry(
                &entry,
                &key,
                &self.channel_id,
                Default::default(),
            )?)
        } else {
            None
        };
        let entry_hash = entry.entry_hash();
        let id = self.next_log_id;

        let persisted = (|| -> Result<()> {
            self.prepare_entry(store, &entry, kind, &key, now_ms)?;
            let mut batch = store.batch()?;
            if self.publish_entry_into(&mut batch, &entry)?.is_some() {
                return Err(Error::Profile("remote entry produced local settlement"));
            }
            if kind == EntryKind::Content && gov.is_none() && entry.payload.is_some() {
                self.track_body_into(&mut batch, entry_hash, id, now_ms)?;
            }
            self.observe_governance_into(store, &mut batch, &entry, id)?;
            self.inspect_legacy_body_into(&mut batch, &entry)?;
            self.reconcile_legacy_sessions_in(&mut batch, now_ms)?;
            batch.commit()
        })();
        if let Err(e) = persisted {
            self.poisoned = true;
            self.save_error = Some(e.to_string());
            return Err(e);
        }
        self.entries.committed();
        self.legacy_sessions.committed();
        self.next_log_id = id.saturating_add(1);
        self.gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.finish_entry_publication(store)?;
        // It may be a parent rows already shown named before it arrived.
        self.settle_display_order(store)?;
        if kind == EntryKind::Checkpoint {
            return Ok(Accepted::Checkpoint);
        }
        let applied = (|| -> Result<Accepted> {
            match gov {
                Some(_) => Ok(Accepted::Governance),
                // Content: render it if we hold the author's sender key and the author
                // has consented to us; otherwise it stays stored as ciphertext
                // (ADR-007 step 3) until an SKDM arrives and backfills it.
                None => {
                    let Some((author, payload)) = self
                        .entry(store, &entry_hash)?
                        .and_then(|e| Some((e.skeleton.author_id, e.payload.clone()?)))
                    else {
                        return Ok(Accepted::ContentNotReadable);
                    };
                    if crate::node::keypackage::KeyPackage::is_key_package(&payload) {
                        if key_package_for(&entry, &self.me()) {
                            self.key_packages.note(author, id)?;
                        }
                        return Ok(Accepted::ContentNotReadable);
                    }
                    if self.render_content(store, author, entry_hash, &payload, now_ms)? {
                        Ok(Accepted::Rendered)
                    } else {
                        Ok(Accepted::ContentNotReadable)
                    }
                }
            }
        })();
        if let Err(ref error) = applied {
            self.poison(error);
        }
        applied
    }

    /// Whether this node may read `author`'s messages: `author` has consented to
    /// this identity on the log (ADR-007 per-sender consent). Reading also needs the
    /// sender key itself (the SKDM).
    pub fn may_read(&self, _store: &Store, author: &Digest32, me: &Digest32) -> Result<bool> {
        self.with_consent_facts(|facts| facts.can_read(me, author))
    }

    /// **The time to stamp a new post with**: the clock, or just past the latest post this node
    /// holds in the room if that is later (V210-168); and the authors of the held posts it is
    /// *not* stamped after.
    ///
    /// Posts are ordered by their stamps (the claim fold sorts on them), and each author's clock
    /// is its own. Without this, a node whose clock is behind could post *after* it held another
    /// member's post, and its post still sorted first: a member that had agreed another's claim
    /// came first then claimed the same item and won it, so two agents were told "you hold it".
    /// With it, a post made after another one was held sorts after it.
    ///
    /// A post stamped more than [`STAMP_LEAD_LIMIT_MILLIS`] ahead of this clock does not move it:
    /// one member's wrong clock must not carry every later post in the room into the future. Such
    /// a post is skipped, so the new post can sort before it although it was made after; its
    /// author is returned, and a claim made so is not called agreed.
    fn stamp_after_held(&self, store: &Store, now_millis: u64) -> Result<(u64, Vec<Digest32>)> {
        self.entries
            .render_view(store, &self.sek, &self.channel_id)?
            .stamp_info(
                now_millis,
                now_millis.saturating_add(STAMP_LEAD_LIMIT_MILLIS),
            )
    }

    /// The authors of the posts this node held, stamped later than its own post `entry`, when it
    /// stamped `entry` (see `stamp_after_held`). Empty when it skipped none, or when `entry` is
    /// not one of this node's latest posts.
    #[must_use]
    pub fn skipped_when_stamped(&self, entry: &Digest32) -> Vec<Digest32> {
        self.skipped
            .iter()
            .find(|(e, _)| e == entry)
            .map(|(_, a)| a.clone())
            .unwrap_or_default()
    }

    /// Author a text message: encrypt under this identity's sender chain, wrap in
    /// a signed ADR-008 log entry, accept it into the DAG, and persist entry +
    /// rendering + advanced chain state atomically. Returns the rendered message.
    pub fn append_text(
        &mut self,
        profile: &Profile,
        text: &str,
        // **Milliseconds**, from one read of one clock. Renamed from `now_ms` rather than
        // converted at the call site: this value becomes half the ADR-020 claim ordering key, and a
        // caller still thinking in seconds should fail to compile rather than stamp 1970.
        now_millis: u64,
    ) -> Result<Rendered> {
        // A person's post deliberately undoes a departure that no peer has acknowledged yet
        // (V210-164). Automatic key, receipt, session, and share work has no such exception.
        self.ensure_local_append_available_for(profile.store(), true)?;
        if self.poisoned {
            return Err(self.save_failure());
        }
        if !self.settled {
            return Err(Error::RoomNotSynced);
        }
        self.require_own_history_current()?;
        let signer = profile.signer()?;
        let me = signer.fingerprint();
        if !self.authors.contains_key(&me) {
            return Err(Error::Profile("this identity is not an author of the room"));
        }
        // An ended room takes no new message (V030-08). The actor says so to the person; this
        // is the backstop. A post while a leave waits to be heard is allowed, and undoes the
        // leave (V210-164).
        if self.ended(now_millis).is_some() {
            return Err(Error::Profile("this room has ended"));
        }
        let (now_millis, skipped) = self.stamp_after_held(profile.store(), now_millis)?;
        let content = Content::text(now_millis, text)?;
        self.prepare_content_context(profile, &me, now_millis, true)?;
        let plaintext = Zeroizing::new(content.to_canonical_vec());
        let msg = self.sender.encrypt(&plaintext)?;
        let payload = msg.to_wire();
        #[cfg(feature = "mutant-sender")]
        let payload = crate::log::sync::mutant::authored(payload);
        #[cfg(feature = "mutant-sender")]
        let payload = if crate::log::sync::mutant::misbound() {
            let skdm = self.skdm_for_consent(profile)?;
            crate::governance::membership::issue_consent_grant(
                signer,
                &self.channel_id,
                self.epoch + 7,
                me,
                &skdm,
                self.genesis.body.policy.history_mode,
            )?
            .to_wire()
        } else {
            payload
        };

        let skeleton = self.next_skeleton(profile, &me, &payload, now_millis)?;
        let entry = Entry::build_signed(signer, skeleton, payload)?;
        let entry_hash = entry.entry_hash();
        let wire = entry.to_wire();
        let rendered = Rendered {
            entry_hash,
            author: me,
            created_millis: now_millis,
            text: content.text,
            arrival: self.next_log_id,
            shown_at_ms: 0,
            late: false,
            owed: false,
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
        let seen_seg = seal_segment(
            &self.sek,
            SegmentKind::Index,
            id,
            &first_seen_bytes(now_millis, false),
        )?;

        // Validate against the DAG first (structural), then persist, then commit
        // to memory. A persist failure poisons the channel (see module docs).
        let key = signer.public_key();

        let persisted = (|| -> Result<()> {
            self.prepare_local_entry(profile, &entry, EntryKind::Content, &key, now_millis)?;
            let mut batch = profile.store().batch()?;
            let settlement = self.publish_entry_into(&mut batch, &entry)?;
            self.observe_governance_into(profile.store(), &mut batch, &entry, id)?;
            batch.put_segment(&self.channel_id, SegmentKind::LogDb, id, &log_seg)?;
            batch.put_segment(
                &self.channel_id,
                SegmentKind::PlaintextCache,
                id,
                &cache_seg,
            )?;
            {
                let mut index = self
                    .entries
                    .write(&mut batch, &self.sek, &self.channel_id)?;
                index.put_rendered(&rendered, shown_now())?;
                index.seal()?;
            }
            batch.put_segment(
                &self.channel_id,
                SegmentKind::KeyMaterial,
                SEG_SENDER,
                &sender_seg,
            )?;
            batch.put_segment(&self.channel_id, SegmentKind::Index, id, &seen_seg)?;
            self.queue_retention(
                &mut batch,
                entry_hash,
                Some(Tracked {
                    log_id: id,
                    first_seen_ms: now_millis,
                    steps: false,
                    claimed_ms: Some(now_millis),
                    cache_id: Some(id),
                }),
            )?;
            self.finish_local_history_effect_into(&mut batch, &entry, settlement)?;
            batch.commit()
        })();
        if let Err(e) = persisted {
            self.poisoned = true;
            self.save_error = Some(e.to_string());
            return Err(e);
        }
        self.entries.committed();
        // The send is already durable. A display-finalization error poisons future reads,
        // but must not tell the caller that this committed message was never sent.
        let _ = self.seal_render_visibility(profile.store(), std::slice::from_ref(&rendered));
        let _ = self.finish_entry_publication(profile.store());
        self.next_log_id = id.saturating_add(1);
        self.gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if !skipped.is_empty() {
            if self.skipped.len() >= SKIPPED_KEPT {
                self.skipped.pop_front();
            }
            self.skipped.push_back((entry_hash, skipped));
        }

        // Persistence succeeded; a later sealed-index read failure reports storage health,
        // not an unsent post. The returned receipt needs no retained plaintext copy.
        let _ = self.note_rendered(profile.store(), &rendered.entry_hash);
        Ok(rendered)
    }

    /// Read one message's readers from the same snapshot as its rendered row. Each index
    /// fetch is bounded; the returned identities are bounded by the admitted-author limit.
    fn read_by(rendered: &entry_store::RenderView<'_>, entry: &Digest32) -> Result<Vec<Digest32>> {
        let mut out = Vec::new();
        let mut after = None;
        loop {
            let (readers, next) = rendered.readers_page(entry, after, 64)?;
            out.extend(readers);
            match next {
                Some(next) => after = Some(next),
                None => return Ok(out),
            }
        }
    }

    /// This identity's own feed here: the contiguous verified head, the durable own fact
    /// (ADR-037 R5).
    pub fn own_verified_head(&self) -> u64 {
        self.dag.verified_head(&self.me())
    }

    /// How far `member`'s node last said it holds this identity's feed here (ADR-028 R-6).
    pub fn held_through(&self, member: &Digest32) -> Option<u64> {
        self.held.get(member).copied()
    }

    /// Last authenticated, role-complete contiguous position this node holds in `member`'s feed:
    /// the channel DAG's verified head. This is not the sparse-history receipt cursor returned by
    /// `history_held_through`, which separately records durable effect settlement before a receipt
    /// probe may be answered.
    pub fn holds_through(&self, member: &Digest32) -> Option<u64> {
        let through = self.dag.verified_head(member);
        (through != 0).then_some(through)
    }

    /// Record that `member`'s node said, in a sync, it holds this identity's feed here up to `seq`
    /// (ADR-028 R-6). Its last word stands. Kept on disk best effort: a write that fails costs a
    /// restart the count until the next sync, never the room.
    pub fn note_held(&mut self, store: &Store, member: Digest32, seq: u64) {
        if member == self.me() || self.held.get(&member) == Some(&seq) {
            return;
        }
        self.held.insert(member, seq);
        if let Ok(seg) = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_HELD,
            &held_bytes(&self.held),
        ) {
            let _ = store.put_segment(&self.channel_id, SegmentKind::KeyMaterial, SEG_HELD, &seg);
        }
    }

    /// Where this identity's own newest [`READ_BY_SHOWN`] messages here are, oldest first:
    /// `(entry, how many of the room's other members' nodes said they hold it)` (ADR-028 R-6,
    /// "on N of M members' nodes"). Only a node's own word counts: an entry sent to it is not
    /// held until it says so.
    pub fn held_own(&self, store: &Store) -> Result<Vec<(Digest32, u64)>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        let me = self.me();
        let others: Vec<_> = self.members().into_iter().filter(|m| *m != me).collect();
        let rendered = self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?;
        let mut cursor = None;
        let mut out = Vec::new();
        for _ in 0..READ_BY_SHOWN {
            let Some((key, _)) =
                rendered.step(Some(&entry_store::Filter::Author(me)), true, cursor, true)?
            else {
                break;
            };
            cursor = Some(key);
            let (_, seq) = rendered
                .order()
                .author_position(&key.1)?
                .ok_or(Error::MalformedAtRest("rendered entry missing"))?;
            let n = others
                .iter()
                .filter(|m| self.held.get(*m).is_some_and(|head| *head >= seq))
                .count();
            out.push((key.1, n as u64));
        }
        out.reverse();
        Ok(out)
    }

    /// What this node's person has not read here (ADR-028 R-8 at launch): the rows after the newest
    /// one this node recorded as read, oldest first — rendered, not owed, written by someone else,
    /// and covered by neither a signed receipt nor a durable local read mark of this node's.
    /// A room this node never recorded anything read
    /// in counts from its first row. At most [`UNREAD_LOOKED`] rows from the newest are looked at.
    pub fn unread(&self, store: &Store) -> Result<Vec<Digest32>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        let me = self.me();
        let mut out = Vec::new();
        let rendered = self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?;
        let mut cursor = None;
        for _ in 0..UNREAD_LOOKED {
            let Some((key, _)) = rendered.step(None, true, cursor, true)? else {
                break;
            };
            cursor = Some(key);
            if rendered.was_read(&key.1, &me)? {
                break;
            }
            let (author, _) = rendered
                .order()
                .author_position(&key.1)?
                .ok_or(Error::MalformedAtRest("rendered entry missing"))?;
            if author != me {
                out.push(key.1);
            }
        }
        out.reverse();
        Ok(out)
    }

    /// Exact sealed read roots and current members' held positions, without opening
    /// any message bodies. Reusing indicators requires an unchanged timeline too.
    pub(crate) fn read_summary_stamp(&self, store: &Store) -> Result<ReadSummaryStamp> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        let rendered = self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?;
        Ok(ReadSummaryStamp {
            reads: rendered.read_roots()?,
            members_held: self
                .members()
                .into_iter()
                .map(|member| (member, self.held.get(&member).copied()))
                .collect(),
        })
    }

    /// [`Self::read_by`] for this identity's own newest [`READ_BY_SHOWN`] messages here, those
    /// anyone is known to have read, oldest first: what a client shows under each message it sent
    /// (ADR-028 R-6).
    pub fn read_by_own(&self, store: &Store) -> Result<Vec<(Digest32, Vec<Digest32>)>> {
        if self.poisoned {
            return Err(self.save_failure());
        }
        let rendered = self
            .entries
            .render_view(store, &self.sek, &self.channel_id)?;
        let filter = entry_store::Filter::Author(self.me());
        let mut cursor = None;
        let mut out = Vec::new();
        for _ in 0..READ_BY_SHOWN {
            let Some((key, _)) = rendered.step(Some(&filter), true, cursor, true)? else {
                break;
            };
            cursor = Some(key);
            let readers = Self::read_by(&rendered, &key.1)?;
            if !readers.is_empty() {
                out.push((key.1, readers));
            }
        }
        out.reverse();
        Ok(out)
    }

    /// Durably mark one bounded request as locally read. Signed receipts are published
    /// later; an already recorded mark is idempotent, and invalidated selections fail whole.
    pub(crate) fn admit_read_marks(
        &mut self,
        profile: &Profile,
        shown: &[Digest32],
        now_ms: u64,
    ) -> Result<()> {
        self.require_legacy_current(profile.store())?;
        if shown.len() > crate::node::content::MAX_READ_HASHES {
            return Err(Error::SizeLimitExceeded("read marks"));
        }
        if self.poisoned {
            return Err(self.save_failure());
        }
        self.require_governance_display(profile.store(), crate::time::Ms(now_ms))?;
        let me = profile.fingerprint();
        if !self.authors.contains_key(&me) || self.has_left(&me) {
            return Err(Error::Profile("this identity has left the room"));
        }
        if self.ended(now_ms).is_some() {
            return Err(Error::Profile("this room has ended"));
        }
        let result = (|| -> Result<()> {
            let rendered =
                self.entries
                    .render_view(profile.store(), &self.sek, &self.channel_id)?;
            let facts = self.consent_facts()?;
            let mut marks = BTreeSet::new();
            for hash in shown {
                if rendered.was_read(hash, &me)? {
                    continue;
                }
                if rendered.fact(hash)?.is_none() {
                    return Err(Error::Profile("read selection changed; refresh and retry"));
                }
                let entry = rendered
                    .order()
                    .entry(hash)?
                    .ok_or(Error::MalformedAtRest("rendered read-mark entry missing"))?;
                let retained = rendered.retention(hash)?.ok_or(Error::MalformedAtRest(
                    "rendered read-mark retention missing",
                ))?;
                if expired_at(
                    retained.base(),
                    now_ms,
                    self.entry_retention(rendered.transaction(), &entry)?,
                ) {
                    return Err(Error::Profile("read selection changed; refresh and retry"));
                }
                if entry.skeleton.author_id == me {
                    continue;
                }
                if !facts.can_read(&me, &entry.skeleton.author_id) {
                    return Err(Error::Profile("read selection changed; refresh and retry"));
                }
                marks.insert(*hash);
            }
            drop(rendered);
            if marks.is_empty() {
                return Ok(());
            }
            let mut batch = profile.store().batch()?;
            let mut index = self
                .entries
                .write(&mut batch, &self.sek, &self.channel_id)?;
            let mut changed = false;
            for hash in marks {
                changed |= index.put_read_mark(&hash, &me)?;
            }
            if changed {
                index.seal()?;
                batch.commit()?;
                self.entries.committed();
            }
            Ok(())
        })();
        if let Err(ref error) = result {
            if !matches!(
                error,
                Error::Profile("read selection changed; refresh and retry")
            ) {
                self.poison(error);
            }
        }
        result
    }

    /// Examine one fixed-tail page of durable local marks and publish at most one receipt.
    /// Skipped marks remain sealed. An unavailable room or failed append loses no accepted work.
    pub(crate) fn flush_read_marks(
        &mut self,
        profile: &Profile,
        now_ms: u64,
        interval_ms: u64,
    ) -> Result<bool> {
        if self.legacy_cache_only(profile.store())? {
            return Ok(false);
        }
        if self.poisoned {
            return Err(self.save_failure());
        }
        if !self.settled {
            return Err(Error::RoomNotSynced);
        }
        self.require_own_history_current()?;
        self.require_governance_display(profile.store(), crate::time::Ms(now_ms))?;
        let me = profile.fingerprint();
        if self.has_left(&me) || self.ended(now_ms).is_some() {
            return Ok(false);
        }
        let selected = (|| -> Result<_> {
            let rendered =
                self.entries
                    .render_view(profile.store(), &self.sek, &self.channel_id)?;
            let last = rendered.read_sent_ms();
            if last != 0 && now_ms < last.saturating_add(interval_ms) {
                return Ok(None);
            }
            let facts = self.consent_facts()?;
            let eligibility = ReadMarkEligibility {
                reader: me,
                pending: rendered.pending_reads_root()?,
                rendered: rendered.display_roots(),
                governance: self.governance_revision(crate::time::Ms(now_ms))?,
                retention: (self.effective_retention(), self.effective_step_retention()),
            };
            if self.read_mark_scan.is_none() && self.read_mark_complete == Some(eligibility) {
                return Ok(None);
            }
            let scan = match self.read_mark_scan {
                Some(scan) => scan,
                None => match rendered.pending_reads_tail(&me)? {
                    Some(through) => ReadMarkScan {
                        after: None,
                        through,
                        started: eligibility,
                    },
                    None => return Ok(Some((Vec::new(), None, Some(eligibility)))),
                },
            };
            let (page, more) = rendered.pending_reads_page(&me, scan.after)?;
            let mut read = Vec::new();
            let mut cursor = scan.after;
            let mut complete = !more;
            for hash in page {
                if hash > scan.through {
                    complete = true;
                    break;
                }
                cursor = Some(hash);
                if hash == scan.through {
                    complete = true;
                }
                if rendered.fact(&hash)?.is_none() {
                    continue;
                }
                let entry = rendered
                    .order()
                    .entry(&hash)?
                    .ok_or(Error::MalformedAtRest("pending read-mark entry missing"))?;
                let retained = rendered.retention(&hash)?.ok_or(Error::MalformedAtRest(
                    "pending read-mark retention missing",
                ))?;
                if entry.skeleton.author_id == me
                    || expired_at(
                        retained.base(),
                        now_ms,
                        self.entry_retention(rendered.transaction(), &entry)?,
                    )
                    || !facts.can_read(&me, &entry.skeleton.author_id)
                {
                    continue;
                }
                read.push(hash);
            }
            let next = if complete {
                None
            } else {
                Some(ReadMarkScan {
                    after: cursor,
                    ..scan
                })
            };
            // Changes during a pass can make an already examined mark eligible or add a
            // mark behind its cursor. Finish the fixed tail fairly, then take another pass.
            // Own receipt commits also change the pending root; at most one unchanged pass
            // over the remaining skipped marks parks them without any postcommit read.
            let finished =
                (complete && read.is_empty() && scan.started == eligibility).then_some(eligibility);
            Ok(Some((read, next, finished)))
        })();
        let selected = match selected {
            Ok(selected) => selected,
            Err(error) => {
                self.poison(&error);
                return Err(error);
            }
        };
        let Some((read, next, finished)) = selected else {
            return Ok(false);
        };
        if read.is_empty() {
            self.read_mark_scan = next;
            self.read_mark_complete = finished;
            return Ok(false);
        }
        self.append_read(profile, read, now_ms)?;
        self.read_mark_scan = next;
        self.read_mark_complete = None;
        Ok(true)
    }

    /// Author a read record naming `read` (ADR-028 RR-2): sealed under this identity's sender key
    /// like a message, so only the members it trusts can open it, appended to its feed in this
    /// room, and kept as a cache row that ages with the room's retention. Never a row of the
    /// timeline. Returns the record's entry hash.
    ///
    /// Not in a room that has ended, nor one this identity has left: a record is an entry of its
    /// feed, and an entry after a leave undoes the leave (V210-164). Reading says nothing.
    pub fn append_read(
        &mut self,
        profile: &Profile,
        read: Vec<Digest32>,
        now_millis: u64,
    ) -> Result<Digest32> {
        self.ensure_local_append_available(profile.store())?;
        if self.poisoned {
            return Err(self.save_failure());
        }
        if !self.settled {
            return Err(Error::RoomNotSynced);
        }
        self.require_own_history_current()?;
        let signer = profile.signer()?;
        let me = signer.fingerprint();
        if !self.authors.contains_key(&me) || self.left().contains(&me) {
            return Err(Error::Profile("this identity is not an author of the room"));
        }
        if self.ended(now_millis).is_some() {
            return Err(Error::Profile("this room has ended"));
        }
        let sent_ms = now_millis;
        let (now_millis, _) = self.stamp_after_held(profile.store(), now_millis)?;
        let record = crate::node::content::ReadRecord::new(now_millis, read)?;
        self.prepare_content_context(profile, &me, now_millis, false)?;
        let plaintext = Zeroizing::new(record.to_canonical_vec());
        let msg = self.sender.encrypt(&plaintext)?;
        let payload = msg.to_wire();
        let skeleton = self.next_skeleton(profile, &me, &payload, now_millis)?;
        let entry = Entry::build_signed(signer, skeleton, payload)?;
        let entry_hash = entry.entry_hash();
        let wire = entry.to_wire();
        let row = ReadRow {
            entry_hash,
            reader: me,
            created_millis: now_millis,
            read: record.read,
        };
        let id = self.next_log_id;
        let log_seg = seal_segment(&self.sek, SegmentKind::LogDb, id, &wire)?;
        let cache_seg = seal_segment(
            &self.sek,
            SegmentKind::PlaintextCache,
            id,
            &read_cache_bytes(&row),
        )?;
        let sender_seg = seal_segment(
            &self.sek,
            SegmentKind::KeyMaterial,
            SEG_SENDER,
            &self.sender.to_state(),
        )?;
        let seen_seg = seal_segment(
            &self.sek,
            SegmentKind::Index,
            id,
            &first_seen_bytes(now_millis, false),
        )?;
        let key = signer.public_key();

        let persisted = (|| -> Result<()> {
            self.prepare_local_entry(profile, &entry, EntryKind::Content, &key, now_millis)?;
            let mut batch = profile.store().batch()?;
            let settlement = self.publish_entry_into(&mut batch, &entry)?;
            self.observe_governance_into(profile.store(), &mut batch, &entry, id)?;
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
            batch.put_segment(&self.channel_id, SegmentKind::Index, id, &seen_seg)?;
            self.queue_retention(
                &mut batch,
                entry_hash,
                Some(Tracked {
                    log_id: id,
                    first_seen_ms: now_millis,
                    steps: false,
                    claimed_ms: Some(now_millis),
                    cache_id: Some(id),
                }),
            )?;
            {
                let mut index = self
                    .entries
                    .write(&mut batch, &self.sek, &self.channel_id)?;
                index.put_read_receipt(&row, id)?;
                index.read_sent(sent_ms);
                index.seal()?;
            }
            self.finish_local_history_effect_into(&mut batch, &entry, settlement)?;
            batch.commit()
        })();
        if let Err(e) = persisted {
            self.poisoned = true;
            self.save_error = Some(e.to_string());
            return Err(e);
        }
        self.entries.committed();
        self.next_log_id = id.saturating_add(1);
        self.gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // The signed receipt and removal of its pending marks are already durable.
        // Cleanup failure poisons the room but cannot turn that success into a lost mark.
        let _ = self.finish_entry_publication(profile.store());

        Ok(entry_hash)
    }

    /// The next entry skeleton for `author`'s feed in this DAG, naming in `seen` the
    /// other authors' heads this node has applied (ADR-023 decision 1): that is what
    /// places the entry after everything its author could have read.
    fn next_skeleton(
        &mut self,
        profile: &Profile,
        author: &Digest32,
        payload: &[u8],
        claimed_ms: u64,
    ) -> Result<EntrySkeleton> {
        let typed = self.authored_v2(profile, author, payload, claimed_ms)?;
        let store = profile.store();
        let result = (|| -> Result<EntrySkeleton> {
            let feed = self.dag.feed(author);
            let max = feed.map_or(0, |f| f.max_seq());
            let seq = max
                .checked_add(1)
                .ok_or(Error::MalformedAtRest("feed sequence exhausted"))?;
            let entries = self.entries.read(store, &self.sek, &self.channel_id)?;
            let hash_of = |s: u64| -> Result<Digest32> {
                entries
                    .get(author, s)?
                    .map(|entry| entry.entry_hash())
                    .ok_or(Error::MalformedAtRest("local feed predecessor missing"))
            };
            Ok(EntrySkeleton {
                v2: typed.as_ref().map(|(v2, _)| v2.clone()),
                author_id: *author,
                seq,
                prev_hash: if seq == 1 {
                    ZERO_HASH
                } else {
                    hash_of(seq - 1)?
                },
                lipmaa_backlink: if seq == 1 {
                    ZERO_HASH
                } else {
                    hash_of(lipmaa(seq))?
                },
                channel_id: self.channel_id,
                epoch: self.epoch,
                algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
                payload_hash: sha256(payload),
                payload_len: payload.len() as u64,
                end_of_feed: false,
                claimed_ms,
                seen: match &typed {
                    Some((_, seen)) => seen.clone(),
                    None => self.dag.seen_for(
                        &self.entries.read(store, &self.sek, &self.channel_id)?,
                        author,
                    )?,
                },
            })
        })();
        if let Err(ref error) = result {
            self.poisoned = true;
            self.save_error = Some(error.to_string());
        }
        result
    }

    /// The channelID.
    #[must_use]
    pub fn channel_id(&self) -> Digest32 {
        self.channel_id
    }

    /// The room's shared name (ADR-028 R-1): what its log says, else the name this node heard
    /// when it made or joined the room, else `None` (a room made before rooms had names, until
    /// an admin names it).
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.governance_display
            .name
            .as_deref()
            .or_else(|| Some(self.name_hint.as_str()).filter(|n| !n.is_empty()))
    }

    /// Whether `who` may name the room: its creator or an admin (ADR-028 R-1).
    pub fn may_rename(&self, store: &Store, who: &Digest32, now: crate::time::Ms) -> Result<bool> {
        self.grants_policy(store, who, now.get())
    }

    /// Replace the room's complete anchor set with an authorized signed statement.
    pub fn set_anchors(
        &mut self,
        profile: &Profile,
        anchors: &BootstrapSet,
        now: crate::time::Ms,
    ) -> Result<()> {
        let signer = profile.signer()?;
        if !self.may_rename(profile.store(), &signer.fingerprint(), now)? {
            return Err(Error::MalformedGovernance(
                "only the room's creator or an admin may change its anchors",
            ));
        }
        let statement = crate::governance::anchors::RoomAnchors::build(
            signer,
            &self.channel_id,
            self.epoch,
            anchors,
        )?;
        self.append_governance(profile, &statement.to_wire(), now.get())?;
        Ok(())
    }

    /// Name the room `name` for every member (ADR-028 R-1): append a room-name statement. Only
    /// the creator or an admin may; anyone else is refused here rather than writing an entry
    /// every other node would ignore. `name` must already be a room name
    /// ([`crate::governance::name::room_name`]).
    ///
    /// # Errors
    /// Not an admin, not a room name, or an append that fails.
    pub fn set_name(
        &mut self,
        profile: &Profile,
        name: &str,
        now: crate::time::Ms,
    ) -> Result<Digest32> {
        let now_ms = now.get();
        let signer = profile.signer()?;
        if !self.may_rename(profile.store(), &signer.fingerprint(), now)? {
            return Err(Error::MalformedGovernance(
                "only the room's creator or an admin may rename it",
            ));
        }
        let statement =
            crate::governance::name::RoomName::build(signer, &self.channel_id, self.epoch, name)?;
        self.append_governance(profile, &statement.to_wire(), now_ms)
    }

    /// Creation time recorded in the manifest, milliseconds since the Unix epoch.
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

    /// The room's members, in fingerprint order: its admitted authors, less every one that has
    /// left (V210-164). A member that left stays an author — its entries are still the room's
    /// history — but it is nobody this node syncs with, delivers to or dials.
    #[must_use]
    pub fn members(&self) -> Vec<Digest32> {
        let left = self.left();
        self.authors
            .keys()
            .filter(|a| !left.contains(*a))
            .copied()
            .collect()
    }

    /// Where `author`'s current membership starts, and when: its statement that it is back after its
    /// last leave, else its admission, the start of its feed (`seq` 0). The time of an admission is
    /// what admitted it: the genesis for the creator, else the witness of the member that verified
    /// its join — this node's own, or the notice it keeps of another's — and only failing those the
    /// first of its entries this node holds. A member that has written nothing still joined when it
    /// was witnessed: taking its time from its writing made a node that never wrote offered no one
    /// who joined after it. `None` when nothing here says.
    fn admission(&self, author: &Digest32) -> (u64, Option<u64>) {
        let back = self.presence.get(author).and_then(|presence| presence.back);
        let feed = self.dag.feed(author);
        let witnessed = || {
            if *author == self.me() {
                match &self.own_admission {
                    Admission::Creator => Some(self.genesis.body.created_ms),
                    Admission::Witnessed(w) => Some(w.timestamp_ms),
                }
            } else if self.genesis.creator_pubkey().fingerprint() == *author {
                Some(self.genesis.body.created_ms)
            } else {
                self.board_kept.notices.get(author).map(|(at, _)| *at)
            }
        };
        match back {
            Some((seq, ms)) => (seq, Some(ms).or_else(witnessed)),
            None => (
                0,
                witnessed().or_else(|| feed.and_then(crate::log::feed::Feed::first_claimed_ms)),
            ),
        }
    }

    /// What each other member could be offered to this node on here (ADR-028 K-15, K-17), off the
    /// log: a member that joined after this node did, by its join, and a member that grants this
    /// node consent (ADR-007 G-9), by its latest grant. Nothing here knows the keyring or what was
    /// dismissed; [`crate::node::offers::offers`] decides over every room.
    pub fn offer_bases(&self, _store: &Store) -> Result<Vec<crate::node::api::OfferBasis>> {
        use crate::node::api::{OfferBasis, OfferWhy};
        let me = self.me();
        let (_, mine) = self.admission(&me);
        let members = self.members();
        let grants: BTreeMap<Digest32, u64> = self.with_consent_facts(|facts| {
            members
                .iter()
                .filter_map(|member| facts.grant_sequence(member, &me).map(|seq| (*member, seq)))
                .collect()
        })?;
        let mut out = Vec::new();
        for member in members {
            if member == me {
                continue;
            }
            let (seq, ms) = self.admission(&member);
            if ms.zip(mine).is_some_and(|(ms, mine)| ms > mine) {
                out.push(OfferBasis {
                    member,
                    why: OfferWhy::Joined,
                    seq,
                });
            }
            if let Some(seq) = grants.get(&member).copied() {
                out.push(OfferBasis {
                    member,
                    why: OfferWhy::TrustsYou,
                    seq,
                });
            }
        }
        Ok(out)
    }

    /// Whether `fingerprint` is a member: an admitted author that has not left.
    #[must_use]
    pub fn is_member(&self, fingerprint: &Digest32) -> bool {
        self.is_author(fingerprint) && !self.has_left(fingerprint)
    }

    /// The members' keys (see [`Self::members`]), in fingerprint order.
    #[must_use]
    pub fn member_keys(&self) -> Vec<CompositePublicKey> {
        let left = self.left();
        self.authors
            .iter()
            .filter(|(a, _)| !left.contains(*a))
            .map(|(_, k)| k.clone())
            .collect()
    }

    /// Whether `author` has left the room: the last entry this node holds of its feed is its
    /// own statement that it left (V210-164), and this node has not let it back in since
    /// ([`Self::readmit`]). Anything it authored after one — it joined again — puts it back.
    #[must_use]
    pub fn has_left(&self, author: &Digest32) -> bool {
        self.left_at(author)
            .is_some_and(|seq| self.readmitted.get(author) != Some(&seq))
    }

    /// Whether `author`'s feed, as this node holds it, ends in its statement that it left.
    fn said_left(&self, author: &Digest32) -> bool {
        self.left_at(author).is_some()
    }

    /// Where in `author`'s feed, as this node holds it, its statement that it left stands, when
    /// that statement is the feed's last entry.
    fn left_at(&self, author: &Digest32) -> Option<u64> {
        let head = self
            .dag
            .feed(author)
            .map_or(0, |feed| feed.max_seq())
            .max(self.sparse_applied_tips.get(author).copied().unwrap_or(0));
        self.presence
            .get(author)
            .filter(|presence| presence.last.0 == head && !presence.last.1)
            .map(|_| head)
    }

    fn left(&self) -> BTreeSet<Digest32> {
        self.authors
            .keys()
            .filter(|author| self.has_left(author))
            .copied()
            .collect()
    }

    /// Let `who`, which left, back in on this node: it just proved the room's passphrase in a
    /// join this node answered. It is a member here until its own statement that it is back
    /// reaches the others through this node.
    pub fn readmit(&mut self, who: Digest32) {
        if let Some(seq) = self.left_at(&who) {
            self.readmitted.insert(who, seq);
        }
    }

    /// Write that this identity has left the room (`here` = false) or is back in it, unless its
    /// feed already says so (V210-164). Returns whether an entry was written.
    pub fn say_presence(
        &mut self,
        profile: &Profile,
        here: bool,
        now: crate::time::Ms,
    ) -> Result<bool> {
        let now_ms = now.get();
        let me = profile.signer()?.fingerprint();
        if self.said_left(&me) != here {
            return Ok(false);
        }
        let statement = crate::governance::presence::Presence::build(
            profile.signer()?,
            &self.channel_id,
            self.epoch,
            here,
            self.sender.chain_id(),
        )?;
        self.append_governance_with_sender(
            profile,
            &statement.to_wire(),
            now_ms,
            &[],
            false,
            None,
            here,
            false,
        )?;
        Ok(true)
    }

    /// Record the exact sparse sender generation and mark settlement atomically. The
    /// caller has checked current head/control readiness under this same room lock.
    pub(crate) fn settle_sparse(
        &mut self,
        profile: &Profile,
        now: crate::time::Ms,
    ) -> Result<bool> {
        if self.settled {
            return Ok(false);
        }
        #[cfg(feature = "test-knobs")]
        if std::env::var_os(TEST_NEVER_SETTLE_ENV).is_some_and(|v| !v.is_empty()) {
            return Ok(false);
        }
        if !self.uses_sparse_history(profile.store())? {
            return Err(Error::MalformedBundle(
                "sparse settlement requires sparse room",
            ));
        }
        let me = self.me();
        let seq = self.dag.verified_head(&me);
        let previous_bound = seq
            .checked_add(1)
            .ok_or(Error::MalformedBundle("chain_id overflow"))?;
        if self.sender.chain_id() > previous_bound {
            return Err(Error::MalformedBundle(
                "sender generation exceeds authenticated sparse sequence bound",
            ));
        }
        // Even the initial generation may have been shared during join. Always choose
        // a fresh generation, including at seq zero, and record it before becoming ready.
        let next_id = previous_bound
            .checked_add(1)
            .ok_or(Error::MalformedBundle("chain_id overflow"))?;
        let next = SenderChain::new(&self.channel_id, self.epoch, &me, next_id, now.get())?;
        self.rotate_sender_with_presence(profile, next, now.get(), false, true, false)?;
        Ok(true)
    }

    /// Whether this node may write in the room: see `settled`.
    #[must_use]
    pub fn is_settled(&self) -> bool {
        self.settled
    }

    /// Whether a member was seen holding entries of this node's own feed here that this node
    /// does not hold (ADR-037 R5): a restored older profile, which must not write here.
    #[must_use]
    pub fn own_history_behind(&self) -> bool {
        self.own_behind
    }

    pub(crate) fn require_own_history_current(&self) -> Result<()> {
        if self.own_behind {
            return Err(Error::OwnHistoryBehind);
        }
        Ok(())
    }

    /// A sync with another member ended cleanly: this node holds its own feed as the room does,
    /// and may write. Returns whether that is new.
    pub fn settle(&mut self, store: &Store) -> Result<bool> {
        if self.settled {
            return Ok(false);
        }
        #[cfg(feature = "test-knobs")]
        if std::env::var_os(TEST_NEVER_SETTLE_ENV).is_some_and(|v| !v.is_empty()) {
            return Ok(false);
        }
        store.delete_segment(&self.channel_id, SegmentKind::KeyMaterial, SEG_UNSETTLED)?;
        self.settled = true;
        Ok(true)
    }

    /// Whether this room is over, and why (V030-08): its creator ended it, or the idle end its
    /// creator chose has run out — no entry for that long, by the room's own clock, at `now_ms`.
    #[must_use]
    pub fn ended(&self, now_ms: u64) -> Option<RoomEnd> {
        if !self.governance_display_current(now_ms) {
            return None;
        }
        let lifecycle = &self.governance_display.lifecycle;
        if lifecycle.ended_by.is_some() {
            return Some(RoomEnd::ByCreator);
        }
        let idle_ms = lifecycle.idle_end_ms?;
        let last = self.dag.newest_clock().unwrap_or_else(|| self.created());
        let at = last.saturating_add(idle_ms);
        (now_ms >= at).then_some(RoomEnd::Idle {
            idle_secs: idle_ms / 1_000,
        })
    }

    /// The idle end this room's creator chose, in seconds, if any (V030-08).
    #[must_use]
    pub fn idle_end(&self) -> Option<u64> {
        self.governance_display
            .lifecycle
            .idle_end_ms
            .map(|ms| ms / 1_000)
    }

    /// End the room for everyone (V030-08). Only its creator, or an admin the creator delegated,
    /// may: anyone else is refused here rather than writing an entry every other node would
    /// ignore.
    pub fn end(&mut self, profile: &Profile, now: crate::time::Ms) -> Result<Digest32> {
        let now_ms = now.get();
        let signer = profile.signer()?;
        let me = signer.fingerprint();
        if me != self.genesis.creator_pubkey().fingerprint()
            && !self
                .checked_governance(profile.store(), now_ms)?
                .can_end(&me)?
        {
            return Err(Error::Profile(
                "only the room's creator or an admin may end it",
            ));
        }
        let fact = crate::governance::lifecycle::RoomLifecycle::build(
            signer,
            &self.channel_id,
            self.epoch,
            crate::governance::lifecycle::LifecycleKind::End,
        )?;
        self.append_governance(profile, &fact.to_wire(), now_ms)
    }

    /// Make `member` an admin of the room (V030-08, the decider 2026-10-01): an admin
    /// certificate from the creator, carrying what a delegated admin holds and never `delegate`
    /// ([`Self::delegated_admin_caps`]). Only the creator may — not another admin —
    /// and only for a member of the room.
    pub fn add_admin(
        &mut self,
        profile: &Profile,
        member: &Digest32,
        now: crate::time::Ms,
    ) -> Result<Digest32> {
        let now_ms = now.get();
        let signer = profile.signer()?;
        // The client's own check. The room's is the certificate: it carries no `delegate`, so an
        // admin's certificate for anyone else verifies nowhere (#319).
        #[cfg(feature = "mutant-sender")]
        let entitled = signer.fingerprint() == self.genesis.creator_pubkey().fingerprint()
            || crate::log::sync::mutant::admins_unentitled();
        #[cfg(not(feature = "mutant-sender"))]
        let entitled = signer.fingerprint() == self.genesis.creator_pubkey().fingerprint();
        if !entitled {
            return Err(Error::Profile(
                "only the room's creator may add or remove an admin",
            ));
        }
        if *member == signer.fingerprint() {
            return Err(Error::Profile("the room's creator is its admin already"));
        }
        if !self.is_member(member) {
            return Err(Error::Profile("that identity is not a member of the room"));
        }
        if self.is_admin(profile.store(), member, now)? {
            return Err(Error::Profile("that identity is already a room admin"));
        }
        let mut after = None;
        let mut admins = 0_usize;
        loop {
            let page = self.admin_page(profile.store(), after, 64, now)?;
            admins = admins.saturating_add(page.targets.len());
            if admins >= crate::nat::withdraw::MAX_ROSTER {
                return Err(Error::Profile(
                    "this room already has its maximum 512 admins",
                ));
            }
            match page.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        let key = self
            .authors
            .get(member)
            .cloned()
            .ok_or(Error::Profile("that identity is not a member of the room"))?;
        #[cfg(feature = "test-knobs")]
        let expiry =
            if std::env::var_os(TEST_EXPIRING_ADMIN_ENV).is_some_and(|value| !value.is_empty()) {
                now_ms.saturating_add(
                    u64::try_from(TEST_EXPIRING_ADMIN_LIFETIME.as_millis()).unwrap_or(u64::MAX),
                )
            } else {
                0
            };
        #[cfg(not(feature = "test-knobs"))]
        let expiry = 0;
        let cert = crate::governance::cert::AdminCert::build(
            signer,
            &self.channel_id,
            self.epoch,
            key,
            Self::delegated_admin_caps(),
            expiry,
        )?;
        self.append_governance(profile, &cert.to_wire(), now_ms)
    }

    /// What a delegated admin holds (#319): the room's policy, which is its retention — the one
    /// thing room governance sets (V030-32) — and ending the room. **Not** `admin`: with `admin`,
    /// an admin could name or revoke further admins, every node would honour them, and "only the
    /// creator names admins" would be the client's word alone.
    #[must_use]
    pub fn delegated_admin_caps() -> crate::governance::capability::CapabilitySet {
        crate::governance::capability::CapabilitySet::from_iter_caps([
            crate::governance::capability::Capability::Policy,
        ])
    }

    /// Take `member`'s admin back (V030-08): revoke every admin certificate naming it, whoever
    /// issued it. Only the creator may.
    pub fn remove_admin(
        &mut self,
        profile: &Profile,
        member: &Digest32,
        after: Option<Digest32>,
        now: crate::time::Ms,
    ) -> Result<(usize, Option<Digest32>)> {
        let signer = profile.signer()?;
        if signer.fingerprint() != self.genesis.creator_pubkey().fingerprint() {
            return Err(Error::Profile(
                "only the room's creator may add or remove an admin",
            ));
        }
        // One inspected certificate and at most one signed append per actor turn.
        // The caller continues even through an empty, already-revoked slot.
        let page = self
            .current_governance(profile.store())?
            .certificates(member, after, 1)?;
        for hash in &page.rows {
            let rev = crate::governance::cert::AdminRevocation::build(
                signer,
                &self.channel_id,
                self.epoch,
                *hash,
                crate::governance::cert::RevocationReason::NoLongerNeeded,
            )?;
            self.append_governance(profile, &rev.to_wire(), now.get())?;
        }
        Ok((page.rows.len(), page.next))
    }

    /// When the room's admins last changed, on the room's own clock (V030-14): the newest admin
    /// certificate or revocation on the log. `None` when the room never had one.
    pub fn admin_change_clock(&self, store: &Store) -> Result<Option<u64>> {
        Ok(self.checked_governance(store, self.now_hint)?.admin_clock())
    }

    /// Choose the room's idle end (V030-08): it ends after `idle_secs` with nothing said in it.
    /// Only its creator may, and `vox room create` is where it does.
    pub fn choose_idle_end(
        &mut self,
        profile: &Profile,
        idle_secs: u64,
        now: crate::time::Ms,
    ) -> Result<Digest32> {
        let now_ms = now.get();
        let signer = profile.signer()?;
        if signer.fingerprint() != self.genesis.creator_pubkey().fingerprint() {
            return Err(Error::Profile(
                "only the room's creator may choose its idle end",
            ));
        }
        let fact = crate::governance::lifecycle::RoomLifecycle::build(
            signer,
            &self.channel_id,
            self.epoch,
            crate::governance::lifecycle::LifecycleKind::IdleEnd(idle_secs.saturating_mul(1_000)),
        )?;
        self.append_governance(profile, &fact.to_wire(), now_ms)
    }

    /// Number of accepted log entries.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.dag.len()
    }

    /// The room's generation counter (ADR-025 D1), shared.
    #[must_use]
    pub fn generation(&self) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::clone(&self.gen)
    }

    /// The original operating-system cause survives every later refusal while recovery retries.
    pub fn save_failure(&self) -> Error {
        Error::Storage {
            op: "save room",
            detail: self
                .save_error
                .clone()
                .unwrap_or_else(|| "a previous write failed".into()),
        }
    }

    /// Keys for reopening this same room after a failed store write; never leave the daemon.
    pub(crate) fn recovery_keys(&self) -> Result<crate::node::open_rooms::RoomKeys> {
        let key = <[u8; crate::atrest::sek::SEK_LEN]>::try_from(self.sek.key_bytes()?)
            .map_err(|_| Error::MalformedAtRest("room SEK length"))?;
        Ok(crate::node::open_rooms::RoomKeys {
            sek: Zeroizing::new(key),
            passphrase: self.passphrase.clone().ok_or(Error::AtRestLocked)?,
        })
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
        self.history_publication_changed.notify_waiters();
        // Wipe the retained passphrase with the SEK: after an app-lock this channel
        // can neither unseal nor answer a join until it is reopened (ADR-010/015).
        // `Zeroizing` wipes it as it drops.
        self.passphrase = None;
    }

    /// The retained channel passphrase, for answering an ADR-005 join (the only
    /// thing that needs it). Fails once the channel has been app-locked.
    ///
    /// Stays crate-internal: it is a secret, and the only legitimate consumer is the
    /// node's own join-responder path.
    pub(crate) fn join_passphrase(&self) -> Result<&[u8]> {
        self.passphrase
            .as_deref()
            .map(Vec::as_slice)
            .ok_or(Error::AtRestLocked)
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
        self.passphrase.is_some()
    }
}

/// A channel as a [`crate::log::sync::SessionRoom`]: each step locks the room, does its work, and
/// lets go. See [`ChannelState::sync_over_room`].
struct ChannelSessionRoom<'a> {
    peer: Digest32,
    shared: &'a tokio::sync::Mutex<ChannelState>,
    store: &'a Store,
    now_ms: u64,
    /// The epoch the session began at; a room that has moved on refuses what was staged for it.
    epoch: u64,
    /// Retired sessions stop at their next step (ADR-025 D1a).
    fence: &'a crate::transport::stream_transport::Fence,
    /// Called after a batch persisted entries (ADR-025 D1a: stores report themselves).
    on_stored: &'a dyn Fn(),
    legacy: Option<LegacySync>,
    observe_tip: std::cell::Cell<Option<crate::log::sync::LegacyGap>>,
    deadline: std::time::Instant,
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
        let ch = loop {
            if self.fence.is_retired() || std::time::Instant::now() >= self.deadline {
                return Err(crate::wire::WireError::TransportFailed);
            }
            if let Ok(ch) = self.shared.try_lock() {
                break ch;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        };
        if self.fence.is_retired() {
            return Err(crate::wire::WireError::TransportFailed);
        }

        if ch.poisoned {
            return Err(crate::wire::WireError::TransportFailed);
        }
        if ch.epoch != self.epoch {
            return Err(crate::wire::WireError::EpochMismatch);
        }
        if let Some(request) = self.legacy {
            request
                .check(&ch, self.store)
                .map_err(|_| crate::wire::WireError::TransportFailed)?;
        }
        Ok(ch)
    }
}

impl crate::log::sync::SessionRoom for ChannelSessionRoom<'_> {
    fn apply_entries_limit(&self) -> usize {
        if self.legacy.is_some() {
            crate::log::sync::LEGACY_QUANTUM_ENTRIES
        } else {
            1
        }
    }
    fn receive_entry_bytes_limit(&self) -> usize {
        1024 * 1024
    }
    fn receive_limits(&self) -> (usize, usize) {
        (
            crate::log::sync::LEGACY_QUANTUM_ENTRIES,
            crate::log::sync::LEGACY_QUANTUM_BYTES,
        )
    }
    fn frontiers(
        &self,
    ) -> std::result::Result<(Vec<crate::log::sync::FeedFrontier>, u64), crate::wire::WireError>
    {
        let ch = self.room()?;
        if self.legacy.is_some() {
            return Ok((
                Vec::new(),
                ch.gen.load(std::sync::atomic::Ordering::Relaxed),
            ));
        }
        let entries = ch
            .entries
            .read(self.store, &ch.sek, &ch.channel_id)
            .map_err(|_| crate::wire::WireError::TransportFailed)?;
        let mut frontiers = crate::log::sync::verified_frontiers_of(&ch.dag, &entries)
            .map_err(|_| crate::wire::WireError::TransportFailed)?;
        if let Some(state) = entries.legacy_provisional() {
            // A signed staged witness is not a published head. The sealed accepted base
            // remains the only automatic frontier even before final volatile detachment.
            frontiers.retain(|head| head.author_id != state.owner.author);
            if state.base_seq > 0 {
                frontiers.push(crate::log::sync::FeedFrontier {
                    author_id: state.owner.author,
                    max_seq: state.base_seq,
                    head_hash: state.base_hash,
                });
                frontiers.sort_unstable_by_key(|head| head.author_id);
            }
        }
        Ok((frontiers, ch.gen.load(std::sync::atomic::Ordering::Relaxed)))
    }

    fn wants(
        &self,
        remote: &[crate::log::sync::FeedFrontier],
    ) -> std::result::Result<Vec<crate::log::sync::WantRange>, crate::wire::WireError> {
        let mut room = self.room()?;
        // What the peer holds of this identity's feed, by its own frontier: nothing it was sent
        // counts until it says it holds it (ADR-028 R-6).
        let me = room.me();
        self.out.borrow_mut().mine_held = Some(
            remote
                .iter()
                .find(|f| f.author_id == me)
                .map_or(0, |f| f.max_seq),
        );
        let requested = (|| -> Result<_> {
            let entries = room.entries.read(self.store, &room.sek, &room.channel_id)?;
            if let Some(request) = self.legacy {
                let state = entries
                    .legacy_provisional()
                    .filter(|state| state.owner == request.owner)
                    .ok_or(Error::MalformedAtRest("legacy request owner changed"))?;
                let from = state.tail_seq.saturating_add(1);
                let through = remote
                    .iter()
                    .find(|f| f.author_id == request.owner.author)
                    .map_or(0, |f| f.max_seq)
                    .min(request.through)
                    .min(from.saturating_add(crate::log::sync::LEGACY_QUANTUM_ENTRIES as u64 - 1));
                let wants = if from <= through {
                    vec![crate::log::sync::WantRange {
                        author_id: request.owner.author,
                        from_seq: from,
                        to_seq: through,
                    }]
                } else {
                    Vec::new()
                };
                Ok((wants, None))
            } else {
                let (mut wants, mut gap) =
                    crate::log::sync::wants_for_current(&room.dag, &entries, remote)?;
                if let Some(state) = entries.legacy_provisional() {
                    gap = Some(crate::log::sync::LegacyGap {
                        author: state.owner.author,
                        from: state.base_seq.saturating_add(1),
                        through: state.tail_seq.max(state.base_seq.saturating_add(1)),
                        hash: state.tail_hash,
                    });
                    for want in &mut wants {
                        let verified = if want.author_id == state.owner.author {
                            state.base_seq
                        } else {
                            room.dag.verified_head(&want.author_id)
                        };
                        want.to_seq = want.to_seq.min(verified);
                    }
                    wants.retain(|want| want.from_seq <= want.to_seq);
                }
                if entries.legacy_required_any() {
                    for want in &mut wants {
                        want.to_seq = want.to_seq.min(room.dag.verified_head(&want.author_id));
                    }
                    wants.retain(|want| want.from_seq <= want.to_seq);
                }
                if let Some(tip) = gap.filter(|tip| {
                    entries.legacy_provisional().is_none()
                        && entries
                            .legacy_required(&tip.author)
                            .is_none_or(|known| known.through < tip.through)
                }) {
                    // Observe this signed tip alone: an older overlap may itself hold a
                    // whole legal record and consume the legacy envelope first. Once the
                    // scalar requirement is saved, the next metadata exchange retains the
                    // verified-position overlap and can discover a fork without backfill.
                    wants.clear();
                    wants.push(crate::log::sync::WantRange {
                        author_id: tip.author,
                        from_seq: tip.through,
                        to_seq: tip.through,
                    });
                    self.observe_tip.set(Some(tip));
                }
                Ok((wants, gap))
            }
        })();
        let wants = match requested {
            Ok((wants, gap)) => {
                self.out.borrow_mut().legacy_required = gap;
                wants
            }
            Err(error) => {
                room.poison(&error);
                *self.fatal.borrow_mut() = Some(error);
                return Err(crate::wire::WireError::TransportFailed);
            }
        };
        // Missing older bodies are explicit history demand, never a periodic refill pump.
        Ok(wants)
    }

    fn entries(
        &self,
        wants: &[crate::log::sync::WantRange],
    ) -> std::result::Result<Vec<Vec<u8>>, crate::wire::WireError> {
        let mut room = self.room()?;
        if self.legacy.is_some() {
            return Ok(Vec::new());
        }
        match room.session_entries_for_bounded(
            self.store,
            &self.peer,
            wants,
            self.now_ms,
            crate::log::sync::LEGACY_QUANTUM_ENTRIES,
            1024 * 1024,
        ) {
            Ok(entries) => Ok(entries),
            Err(error) if session_projection::floor_index::refreshing(&error) => {
                *self.fatal.borrow_mut() = Some(error);
                Err(crate::wire::WireError::TransportFailed)
            }
            Err(error) => {
                room.poisoned = true;
                room.save_error = Some(error.to_string());
                *self.fatal.borrow_mut() = Some(error);
                Err(crate::wire::WireError::TransportFailed)
            }
        }
    }

    fn apply(&self, mut staged: Vec<Vec<u8>>) -> crate::log::sync::ApplyReport {
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
        if self.legacy.is_none() && staged.len() == 1 {
            if let (Some(tip), Ok(mut entry)) =
                (self.observe_tip.get(), Entry::from_wire(&staged[0]))
            {
                if entry.skeleton.author_id == tip.author && entry.skeleton.seq == tip.through {
                    let verified = entry.entry_hash() == tip.hash
                        && entry.is_signed()
                        && ch
                            .authors
                            .get(&tip.author)
                            .is_some_and(|key| entry.verify(key).is_ok());
                    if !verified {
                        return crate::log::sync::ApplyReport {
                            fail: Some(crate::wire::WireError::AuthenticatorInvalid),
                            ..crate::log::sync::ApplyReport::default()
                        };
                    }
                    entry.payload = None;
                    match ch.note_legacy_required(self.store, &entry) {
                        Ok(_) => {
                            return crate::log::sync::ApplyReport {
                                classes: vec![crate::log::sync::EntryClass::Observed],
                                ..crate::log::sync::ApplyReport::default()
                            }
                        }
                        Err(
                            Error::MalformedBundle(_)
                            | Error::StreamRefused(_)
                            | Error::SizeLimitExceeded(_),
                        ) => {
                            return crate::log::sync::ApplyReport {
                                fail: Some(crate::wire::WireError::AuthenticatorInvalid),
                                ..crate::log::sync::ApplyReport::default()
                            }
                        }
                        Err(error) => {
                            ch.poison(&error);
                            *self.fatal.borrow_mut() = Some(error);
                            return crate::log::sync::ApplyReport {
                                fail: Some(crate::wire::WireError::TransportFailed),
                                ..crate::log::sync::ApplyReport::default()
                            };
                        }
                    }
                }
            }
        }
        let legacy_state = match ch.legacy_provisional_state(self.store) {
            Ok(state) => state,
            Err(error) => {
                *self.fatal.borrow_mut() = Some(error);
                return crate::log::sync::ApplyReport {
                    fail: Some(crate::wire::WireError::TransportFailed),
                    ..crate::log::sync::ApplyReport::default()
                };
            }
        };
        if self.legacy.is_none() && legacy_state.is_some() {
            let accepted = ch
                .entries
                .read(self.store, &ch.sek, &ch.channel_id)
                .and_then(|read| {
                    read.restart_state().cloned().ok_or(Error::MalformedAtRest(
                        "legacy accepted restart state missing",
                    ))
                });
            let accepted = match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    *self.fatal.borrow_mut() = Some(error);
                    return crate::log::sync::ApplyReport {
                        fail: Some(crate::wire::WireError::TransportFailed),
                        ..Default::default()
                    };
                }
            };
            if staged.iter().any(|wire| {
                Entry::from_wire(wire).is_ok_and(|entry| {
                    entry.skeleton.seq
                        > accepted
                            .feeds
                            .get(&entry.skeleton.author_id)
                            .map_or(0, |feed| feed.seq)
                })
            }) {
                // This WANT may have preceded acquisition of the exact legacy owner.
                return crate::log::sync::ApplyReport {
                    classes: vec![crate::log::sync::EntryClass::Unlinked; staged.len()],
                    ..Default::default()
                };
            }
        }
        if let Some(request) = self.legacy {
            if staged.iter().any(|wire| {
                Entry::from_wire(wire).is_ok_and(|entry| {
                    entry.skeleton.seq == request.through
                        && entry.entry_hash() != request.expected_head
                })
            }) {
                return crate::log::sync::ApplyReport {
                    fail: Some(crate::wire::WireError::AuthenticatorInvalid),
                    ..Default::default()
                };
            }
            if legacy_state.is_some_and(|state| state.pending_witness != 0) {
                return crate::log::sync::ApplyReport {
                    classes: vec![crate::log::sync::EntryClass::Unlinked; staged.len()],
                    ..crate::log::sync::ApplyReport::default()
                };
            }
            // A retained unsigned prefix needs its FIRST signed successor, not a bundle
            // containing later signed bodies that a bodyless-prefix promotion could discard.
            if let Some(at) = staged
                .iter()
                .position(|wire| Entry::from_wire(wire).is_ok_and(|entry| entry.is_signed()))
            {
                staged.truncate(at + 1);
            }
        } else if legacy_state.is_some() || self.out.borrow().legacy_required.is_some() {
            // Overlap comparison needs signed headers only. It must not refill old bodies
            // or mutate the paused request's spool as a side effect of periodic metadata.
            for wire in &mut staged {
                if let Ok(mut entry) = Entry::from_wire(wire) {
                    entry.payload = None;
                    *wire = entry.to_wire();
                }
            }
        }
        let before = ch.heads();
        let gen_before = ch.gen.load(std::sync::atomic::Ordering::Relaxed);
        // The resolver as it is *now*: an author revoked while this batch was on the wire is not
        // an author of this room any more, and its entries are refused.
        let resolver = ch.resolver();
        // **Absorb what was stored, then report the failure.** The DAG takes entries one at a time
        // and stops at the first hard failure; those before it are already in the log, so they are
        // persisted, rendered and counted before the failure is reported (one joiner once read
        // nothing from the host because the order was the other way round: tworooms.sh).
        let mut batch = match self.store.batch() {
            Ok(batch) => batch,
            Err(error) => {
                ch.poison(&error);
                *self.fatal.borrow_mut() = Some(error);
                return crate::log::sync::ApplyReport {
                    fail: Some(crate::wire::WireError::TransportFailed),
                    ..crate::log::sync::ApplyReport::default()
                };
            }
        };
        if let Some(request) = self.legacy {
            if request.check_in(ch, &batch).is_err() {
                // Expected cancellation before any DAG/index mutation is not room corruption.
                return crate::log::sync::ApplyReport {
                    fail: Some(crate::wire::WireError::TransportFailed),
                    ..crate::log::sync::ApplyReport::default()
                };
            }
        }
        let staged_result = (|| -> Result<(crate::log::sync::ApplyReport, Option<Error>)> {
            let mut index = ch.entries.write(&mut batch, &ch.sek, &ch.channel_id)?;
            let result = crate::log::sync::apply_staged_classified(
                &mut ch.dag,
                &mut index,
                &resolver,
                &ch.admission,
                &staged,
            );
            if result.1.is_some() {
                return Ok(result);
            }
            if let (Some(request), Some(state)) = (self.legacy, legacy_state) {
                if ch
                    .dag
                    .refused_from(&request.owner.author)
                    .is_some_and(|from| from <= request.through)
                {
                    // This refusal is volatile, unlike a retained fork or accepted End.
                    // Keep the sealed prerequisite and exact request; never claim that
                    // its missing suffix was accepted or durably proved impossible.
                    self.out.borrow_mut().legacy_unavailable = true;
                } else if ch.dag.is_frozen(&request.owner.author) {
                    // keep_forks persists the attributable proof before the explicit worker
                    // cancels its demand. Do not label this invalid interval completed.
                    self.out.borrow_mut().legacy_invalid = true;
                }
                if result.0.classes.last() == Some(&crate::log::sync::EntryClass::Stored) {
                    if let Some(witness) = staged
                        .last()
                        .map(|wire| Entry::from_wire(wire))
                        .transpose()?
                    {
                        if witness.is_signed() {
                            index.begin_promotion(entry_store::Publication {
                                witness: &witness,
                                from: state.base_seq.saturating_add(1),
                                first_log: ch.next_log_id,
                                received_ms: self.now_ms,
                                bodyless_prefix: true,
                                origin: ch.genesis.body.created_ms,
                                local_contexts: None,
                            })?;
                            debug_assert_eq!(request.owner, state.owner);
                        }
                    }
                }
            }
            index.seal()?;
            batch.commit()?;
            ch.entries.committed();
            Ok(result)
        })();
        let (mut report, local) = match staged_result {
            Ok(result) => result,
            Err(error) => (crate::log::sync::ApplyReport::default(), Some(error)),
        };
        if let Some(error) = local {
            ch.poisoned = true;
            ch.save_error = Some(error.to_string());
            *self.fatal.borrow_mut() = Some(error);
            report.stored = 0;
            report.fail = Some(crate::wire::WireError::TransportFailed);
            // Fork evidence remains independently durable even when unpublished log work fails.
            if let Err(error) = ch.keep_forks(self.store) {
                *self.fatal.borrow_mut() = Some(error);
            }
            return report;
        }
        if self.legacy.is_some() {
            if let Err(error) = ch.keep_forks(self.store) {
                *self.fatal.borrow_mut() = Some(error);
                report.fail = Some(crate::wire::WireError::TransportFailed);
            }
            // Exact staging and any witness cursor are durable. Publication/effects are
            // separate explicitly resumed quanta; no implicit full-prefix walk here.
            report.stored = 0;
            return report;
        }
        match ch.legacy_cache_only(self.store) {
            Ok(true) => {
                // Current overlap may discover a fork, but cannot refill or maintain the
                // mutable roots owned by an explicit legacy publication.
                if let Err(error) = ch.keep_forks(self.store) {
                    *self.fatal.borrow_mut() = Some(error);
                    report.fail = Some(crate::wire::WireError::TransportFailed);
                }
                report.stored = 0;
                return report;
            }
            Ok(false) => {}
            Err(error) => {
                ch.poison(&error);
                *self.fatal.borrow_mut() = Some(error);
                report.fail = Some(crate::wire::WireError::TransportFailed);
                return report;
            }
        }
        for author in ch.dag.authors() {
            let verified = ch.dag.verified_head(&author);
            let tail = ch.dag.feed(&author).map_or(0, |feed| feed.max_seq());
            if tail > verified {
                self.out
                    .borrow_mut()
                    .legacy_required
                    .get_or_insert(crate::log::sync::LegacyGap {
                        author,
                        from: verified.saturating_add(1),
                        through: tail,
                        hash: ch
                            .dag
                            .feed(&author)
                            .map_or(ZERO_HASH, |feed| feed.head_hash()),
                    });
            }
        }
        if let Err(error) = ch.filter_received_session_bodies(self.store, &staged, self.now_ms) {
            ch.poisoned = true;
            ch.save_error = Some(error.to_string());
            *self.fatal.borrow_mut() = Some(error);
            report.stored = 0;
            report.fail = Some(crate::wire::WireError::TransportFailed);
            return report;
        }
        match ch.absorb_arrived(self.store, &before, self.now_ms) {
            Ok(got) => {
                let mut out = self.out.borrow_mut();
                out.rendered += got.rendered;
                out.governance += got.governance;
                out.refused += got.refused;
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
