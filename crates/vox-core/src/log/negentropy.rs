//! Negentropy v1 range-based set reconciliation (Doug Hoyte; Nostr NIP-77),
//! the ADR-008 range-reconciliation sync mode.
//!
//! Negentropy reconciles two sets of items in logarithmic round-trips by
//! exchanging *fingerprints* over ranges and recursing only into ranges that
//! disagree. ADR-008 keys reconciliation by the **full 32-byte SHA-256 entry
//! hash** (no truncation); every item here is `(timestamp = 0, id = entry_hash)`,
//! so items sort purely by their 32-byte id — a valid Negentropy configuration
//! that satisfies "keyed by the full entry hash".
//!
//! ## Wire format (Negentropy v1, byte-exact)
//! A message is `protocol_version(0x61) ‖ Range*`. Each range is
//! `upper_bound ‖ mode ‖ payload`:
//! - **Bound** = `varint(encoded_timestamp) ‖ varint(id_prefix_len) ‖
//!   id_prefix_bytes`. The timestamp is delta-encoded: `0` means infinity
//!   (`u64::MAX`); otherwise `varint(1 + (timestamp − prev_timestamp))`, with
//!   `prev_timestamp` reset to 0 per message. Since all our timestamps are 0, a
//!   finite bound encodes timestamp as varint `1` and an infinity bound as `0`.
//! - **mode** = `varint`: `0` Skip, `1` Fingerprint, `2` IdList.
//! - Skip payload is empty; Fingerprint is 16 bytes; IdList is
//!   `varint(count) ‖ count × 32-byte id`.
//!
//! ## Fingerprint (the critical algebra)
//! `fingerprint = SHA-256( sum_le_256(ids) ‖ varint(count) )[0..16]`, where
//! `sum_le_256` adds every 32-byte id interpreted as a little-endian 256-bit
//! integer, modulo 2^256. See [`Fingerprint::of`].
//!
//! ## Engine
//! [`reconcile_initiate`] builds the opening message; [`reconcile`] processes an
//! incoming message and produces the response, collecting `have`/`need` ids from
//! `IdList` ranges. The split heuristic matches the reference: a range with
//! `< 2·BUCKETS` items is sent as an `IdList`; otherwise it is split into
//! [`BUCKETS`] fingerprint sub-ranges. Reconciliation terminates when the
//! initiator's response reduces to just the version byte.

use crate::cbor::CborError;
use crate::error::{Error, Result};
use crate::hash::{sha256, Digest32};

/// The Negentropy v1 protocol version byte.
pub const PROTOCOL_VERSION: u8 = 0x61;
/// The id size in bytes (full SHA-256 entry hash; no truncation, ADR-008).
pub const ID_SIZE: usize = 32;
/// The fingerprint size in bytes (first 16 of a SHA-256).
pub const FINGERPRINT_SIZE: usize = 16;
/// The number of fingerprint sub-ranges a disagreeing range is split into.
pub const BUCKETS: usize = 16;

/// Hard upper bound on a `NEG` message's wire length (bytes), checked **before**
/// decoding so a hostile frame cannot drive unbounded work/allocation (ADR-008
/// anti-abuse). 4 MiB comfortably holds any honest reconciliation round.
pub const MAX_MESSAGE_LEN: usize = 4 * 1024 * 1024;
/// Hard upper bound on the number of ranges in one message, checked incrementally
/// during decode (a range is at least a few bytes, so this is also bounded by
/// [`MAX_MESSAGE_LEN`], but the explicit cap documents the limit).
pub const MAX_RANGES_PER_MESSAGE: usize = 1 << 20;
/// Hard upper bound on the id count an `IdList` range may declare, checked
/// **before** the per-id loop so an attacker-declared count cannot drive a large
/// allocation/loop before the bytes are even present.
pub const MAX_IDS_PER_RANGE: usize = MAX_MESSAGE_LEN / ID_SIZE;

/// A reconciliation item: a `(timestamp, id)` pair. ADR-008 sets `timestamp = 0`
/// for every item and keys on the 32-byte `id` (the entry hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Item {
    /// The Negentropy timestamp (always 0 in Vox's hash-keyed configuration).
    pub timestamp: u64,
    /// The 32-byte id (the SHA-256 entry hash).
    pub id: Digest32,
}

impl Item {
    /// An item at timestamp 0 with the given id (the Vox configuration).
    #[must_use]
    pub fn new(id: Digest32) -> Self {
        Self { timestamp: 0, id }
    }
}

impl PartialOrd for Item {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Item {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.timestamp
            .cmp(&other.timestamp)
            .then_with(|| self.id.cmp(&other.id))
    }
}

/// A 16-byte Negentropy range fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint(pub [u8; FINGERPRINT_SIZE]);

impl Fingerprint {
    /// Compute the fingerprint of a set of items (their ids):
    /// `SHA-256( Σ_le256(id) mod 2^256 ‖ varint(count) )[0..16]`.
    #[must_use]
    pub fn of(items: &[Item]) -> Self {
        let mut sum = [0u8; ID_SIZE];
        for item in items {
            add_le_256(&mut sum, &item.id);
        }
        let mut input = Vec::with_capacity(ID_SIZE + 9);
        input.extend_from_slice(&sum);
        write_varint(&mut input, items.len() as u64);
        let digest = sha256(&input);
        let mut fp = [0u8; FINGERPRINT_SIZE];
        fp.copy_from_slice(&digest[..FINGERPRINT_SIZE]);
        Fingerprint(fp)
    }
}

/// Add `addend` into `acc` as little-endian 256-bit unsigned integers, mod 2^256
/// (natural wraparound). Limb 0 is the least-significant 64 bits (bytes 0..8).
fn add_le_256(acc: &mut [u8; ID_SIZE], addend: &Digest32) {
    let mut carry = 0u64;
    for limb in 0..4 {
        let base = limb * 8;
        let a = u64::from_le_bytes(slice8(acc, base));
        let b = u64::from_le_bytes(slice8(addend, base));
        // a + b + carry, tracking the new carry across the 64-bit limb.
        let (s1, c1) = a.overflowing_add(b);
        let (s2, c2) = s1.overflowing_add(carry);
        acc[base..base + 8].copy_from_slice(&s2.to_le_bytes());
        carry = u64::from(c1) + u64::from(c2);
    }
    // Final carry out of bit 255 is discarded (mod 2^256).
}

fn slice8(b: &[u8; ID_SIZE], base: usize) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&b[base..base + 8]);
    out
}

// ---------------------------------------------------------------------------
// Varint (base-128, MSB-first, minimal) — the Negentropy encoding.
// ---------------------------------------------------------------------------

/// Append a Negentropy varint (base-128, most-significant group first,
/// continuation bit `0x80` on all but the last byte).
pub fn write_varint(out: &mut Vec<u8>, mut n: u64) {
    let mut groups = [0u8; 10];
    let mut i = groups.len();
    loop {
        i -= 1;
        groups[i] = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            break;
        }
    }
    // groups[i..] holds the 7-bit digits MSB-first; set continuation on all but
    // the final one.
    let last = groups.len() - 1;
    for (idx, g) in groups.iter().enumerate().take(last).skip(i) {
        let _ = idx;
        out.push(g | 0x80);
    }
    out.push(groups[last]);
}

/// Read a Negentropy varint from `buf` at `*pos`, advancing `*pos`. Rejects an
/// over-long encoding that would overflow `u64`.
pub fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64> {
    let mut res: u64 = 0;
    let mut count = 0;
    loop {
        let byte = *buf.get(*pos).ok_or(Error::Cbor(CborError::UnexpectedEof))?;
        *pos += 1;
        count += 1;
        if count > 10 {
            return Err(Error::MalformedBundle("negentropy varint overflow"));
        }
        res = res
            .checked_shl(7)
            .ok_or(Error::MalformedBundle("negentropy varint overflow"))?
            | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            break;
        }
    }
    Ok(res)
}

// ---------------------------------------------------------------------------
// Bound
// ---------------------------------------------------------------------------

/// A range upper bound: a `(timestamp, id_prefix)` point in item space. The
/// id-prefix is the minimal prefix disambiguating adjacent ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    /// The bound timestamp (`u64::MAX` = infinity).
    pub timestamp: u64,
    /// The id-prefix bytes (0..=32).
    pub id_prefix: Vec<u8>,
}

impl Bound {
    /// The infinity upper bound (past every possible item).
    #[must_use]
    pub fn infinity() -> Self {
        Self {
            timestamp: u64::MAX,
            id_prefix: Vec::new(),
        }
    }

    /// A bound exactly at `item` (full id prefix). Used for the lower edge of a
    /// range when comparing item membership.
    #[must_use]
    pub fn at(item: &Item) -> Self {
        Self {
            timestamp: item.timestamp,
            id_prefix: item.id.to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// Message model
// ---------------------------------------------------------------------------

/// The reconciliation mode of a range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Skip: the sender asserts nothing about this range.
    Skip,
    /// Fingerprint: the 16-byte fingerprint of the sender's items in the range.
    Fingerprint(Fingerprint),
    /// IdList: the sender's full ids in the range.
    IdList(Vec<Digest32>),
}

/// A single range: its (exclusive) upper bound and its mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    /// The exclusive upper bound of the range.
    pub upper: Bound,
    /// The reconciliation mode + payload.
    pub mode: Mode,
}

/// A decoded Negentropy message: the ordered ranges (the version byte is handled
/// by [`encode_message`]/[`decode_message`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Message {
    /// The ranges, in ascending bound order, covering the whole item space.
    pub ranges: Vec<Range>,
}

impl Message {
    /// Whether this message has no ranges (the terminal/empty message — the
    /// initiator is done when its response reduces to this, ADR-008/NIP-77).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

/// Encode a message to wire bytes: `0x61 ‖ Range*`. Timestamps are delta-encoded
/// from a per-message running `prev` (reset to 0 here).
#[must_use]
pub fn encode_message(msg: &Message) -> Vec<u8> {
    let mut out = vec![PROTOCOL_VERSION];
    let mut prev_ts = 0u64;
    for range in &msg.ranges {
        encode_bound(&mut out, &range.upper, &mut prev_ts);
        match &range.mode {
            Mode::Skip => write_varint(&mut out, 0),
            Mode::Fingerprint(fp) => {
                write_varint(&mut out, 1);
                out.extend_from_slice(&fp.0);
            }
            Mode::IdList(ids) => {
                write_varint(&mut out, 2);
                write_varint(&mut out, ids.len() as u64);
                for id in ids {
                    out.extend_from_slice(id);
                }
            }
        }
    }
    out
}

/// Decode a wire message, validating the version byte and every range. Rejects a
/// message over [`MAX_MESSAGE_LEN`] (before any work), a wrong version, truncated
/// input, an out-of-range id-prefix length, more than [`MAX_RANGES_PER_MESSAGE`]
/// ranges, an `IdList` declaring more than [`MAX_IDS_PER_RANGE`] ids (before the
/// per-id loop/allocation), or an unknown mode (ADR-008 anti-abuse:
/// attacker-declared counts/lengths never drive allocation past a hard cap).
pub fn decode_message(buf: &[u8]) -> Result<Message> {
    if buf.len() > MAX_MESSAGE_LEN {
        return Err(Error::SizeLimitExceeded("negentropy message"));
    }
    let mut pos = 0usize;
    let version = *buf.get(pos).ok_or(Error::Cbor(CborError::UnexpectedEof))?;
    pos += 1;
    if version != PROTOCOL_VERSION {
        return Err(Error::UnsupportedVersion { tag: 0, version });
    }
    let mut prev_ts = 0u64;
    let mut ranges = Vec::new();
    while pos < buf.len() {
        if ranges.len() >= MAX_RANGES_PER_MESSAGE {
            return Err(Error::SizeLimitExceeded("negentropy range count"));
        }
        let upper = decode_bound(buf, &mut pos, &mut prev_ts)?;
        let mode_id = read_varint(buf, &mut pos)?;
        let mode = match mode_id {
            0 => Mode::Skip,
            1 => {
                let fp_bytes = buf
                    .get(pos..pos + FINGERPRINT_SIZE)
                    .ok_or(Error::Cbor(CborError::UnexpectedEof))?;
                pos += FINGERPRINT_SIZE;
                let mut fp = [0u8; FINGERPRINT_SIZE];
                fp.copy_from_slice(fp_bytes);
                Mode::Fingerprint(Fingerprint(fp))
            }
            2 => {
                let count = read_varint(buf, &mut pos)?;
                let count = usize::try_from(count)
                    .map_err(|_| Error::MalformedBundle("negentropy idlist count"))?;
                // Pre-allocation guard: reject an over-limit declared count before
                // the loop/allocation. (Each id also needs 32 real bytes, but the
                // explicit cap stops a huge count up front.)
                if count > MAX_IDS_PER_RANGE {
                    return Err(Error::SizeLimitExceeded("negentropy idlist count"));
                }
                let mut ids = Vec::with_capacity(count.min(1024));
                for _ in 0..count {
                    let id_bytes = buf
                        .get(pos..pos + ID_SIZE)
                        .ok_or(Error::Cbor(CborError::UnexpectedEof))?;
                    pos += ID_SIZE;
                    let mut id = [0u8; ID_SIZE];
                    id.copy_from_slice(id_bytes);
                    ids.push(id);
                }
                Mode::IdList(ids)
            }
            _ => return Err(Error::MalformedBundle("negentropy unknown mode")),
        };
        ranges.push(Range { upper, mode });
    }
    Ok(Message { ranges })
}

fn encode_bound(out: &mut Vec<u8>, bound: &Bound, prev_ts: &mut u64) {
    // Delta + offset timestamp encoding: infinity -> 0; else 1 + (ts - prev).
    if bound.timestamp == u64::MAX {
        write_varint(out, 0);
        *prev_ts = u64::MAX;
    } else {
        let delta = bound.timestamp.wrapping_sub(*prev_ts);
        write_varint(out, delta.wrapping_add(1));
        *prev_ts = bound.timestamp;
    }
    write_varint(out, bound.id_prefix.len() as u64);
    out.extend_from_slice(&bound.id_prefix);
}

fn decode_bound(buf: &[u8], pos: &mut usize, prev_ts: &mut u64) -> Result<Bound> {
    let v = read_varint(buf, pos)?;
    let timestamp = if v == 0 {
        *prev_ts = u64::MAX;
        u64::MAX
    } else {
        let ts = prev_ts.wrapping_add(v - 1);
        *prev_ts = ts;
        ts
    };
    let prefix_len = read_varint(buf, pos)?;
    let prefix_len = usize::try_from(prefix_len)
        .ok()
        .filter(|&l| l <= ID_SIZE)
        .ok_or(Error::MalformedBundle("negentropy id-prefix length"))?;
    let prefix = buf
        .get(*pos..*pos + prefix_len)
        .ok_or(Error::Cbor(CborError::UnexpectedEof))?
        .to_vec();
    *pos += prefix_len;
    Ok(Bound {
        timestamp,
        id_prefix: prefix,
    })
}

// ---------------------------------------------------------------------------
// Reconciliation engine
// ---------------------------------------------------------------------------

/// Compute the minimal bound separating the last item of one bucket from the
/// first item of the next (NIP-77 `getMinimalBound`): if the timestamps differ,
/// the prefix is empty; otherwise it is the shared id prefix plus one byte.
fn minimal_bound(prev: &Item, curr: &Item) -> Bound {
    if prev.timestamp != curr.timestamp {
        Bound {
            timestamp: curr.timestamp,
            id_prefix: Vec::new(),
        }
    } else {
        let mut shared = 0usize;
        for i in 0..ID_SIZE {
            if prev.id[i] != curr.id[i] {
                break;
            }
            shared += 1;
        }
        let take = (shared + 1).min(ID_SIZE);
        Bound {
            timestamp: curr.timestamp,
            id_prefix: curr.id[..take].to_vec(),
        }
    }
}

/// Whether `item` is strictly below the exclusive upper `bound`.
fn item_below(item: &Item, bound: &Bound) -> bool {
    use core::cmp::Ordering;
    match item.timestamp.cmp(&bound.timestamp) {
        Ordering::Less => true,
        Ordering::Greater => false,
        Ordering::Equal => {
            // Compare the id against the (possibly partial) prefix: the bound's
            // prefix is the smallest id at this timestamp that is >= the bound, so
            // the item is below iff its id sorts strictly before the prefix.
            let n = bound.id_prefix.len();
            item.id[..n.min(ID_SIZE)] < bound.id_prefix[..]
        }
    }
}

/// Split a sorted slice of items into ranges for transmission (the sender's
/// view), per the reference heuristic: a slice with `< 2·BUCKETS` items becomes a
/// single `IdList`; otherwise it is split into [`BUCKETS`] fingerprint ranges. The
/// final range inherits `upper` so it is consistent with the parent context.
fn split_range(items: &[Item], upper: Bound, out: &mut Vec<Range>) {
    if items.len() < 2 * BUCKETS {
        out.push(Range {
            upper,
            mode: Mode::IdList(items.iter().map(|i| i.id).collect()),
        });
        return;
    }
    let n = items.len();
    let per = n / BUCKETS;
    let extra = n % BUCKETS;
    let mut idx = 0usize;
    for b in 0..BUCKETS {
        let take = per + usize::from(b < extra);
        let bucket = &items[idx..idx + take];
        idx += take;
        let bound = if b == BUCKETS - 1 {
            upper.clone()
        } else {
            // Minimal bound between this bucket's last item and the next's first.
            let last = &items[idx - 1];
            let next = &items[idx];
            minimal_bound(last, next)
        };
        out.push(Range {
            upper: bound,
            mode: Mode::Fingerprint(Fingerprint::of(bucket)),
        });
    }
}

/// Build the initiator's opening message over all `items` (must be sorted): a
/// single full-universe range, split per the heuristic.
#[must_use]
pub fn reconcile_initiate(items: &[Item]) -> Message {
    let mut ranges = Vec::new();
    split_range(items, Bound::infinity(), &mut ranges);
    Message { ranges }
}

/// The outcome of processing an incoming message on one side.
#[derive(Debug, Default)]
pub struct ReconcileResult {
    /// The response message to send back (empty ⇒ this side has nothing more to
    /// say for the ranges it processed).
    pub response: Message,
    /// Ids the local side HAS that the remote lacked (learned from `IdList`
    /// ranges) — the local peer should offer these.
    pub have: Vec<Digest32>,
    /// Ids the remote HAS that the local side lacks — the local peer should
    /// request/accept these.
    pub need: Vec<Digest32>,
}

/// The role of the side calling [`reconcile`]. The roles are asymmetric (as in
/// the Negentropy reference): the **initiator** drives reconciliation, collects
/// the final `have`/`need`, and *resolves* `IdList` ranges (replying `Skip`); the
/// **responder** answers `Fingerprint` mismatches by splitting or sending
/// `IdList`. This asymmetry is what makes reconciliation terminate rather than
/// bounce `IdList`s forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The side that called [`reconcile_initiate`]; collects the final diff.
    Initiator,
    /// The side that answers the initiator's fingerprints.
    Responder,
}

/// Process an incoming reconciliation message against the local sorted `items`,
/// producing the response and (for the initiator) the `have`/`need` id sets.
///
/// For each incoming range, against the local items in the same bound:
/// - **Skip** → respond `Skip`.
/// - **Fingerprint** → equal to the local fingerprint ⇒ respond `Skip`; else
///   split the local items into fingerprint/idlist sub-ranges (recurse a level).
/// - **IdList** → diff against local items, recording `have` (only-local) and
///   `need` (only-remote). An **initiator** has now resolved the range and
///   replies `Skip`; a **responder** replies with its own `IdList` so the
///   initiator can compute its diff.
pub fn reconcile(role: Role, items: &[Item], incoming: &Message) -> ReconcileResult {
    let mut result = ReconcileResult::default();
    let mut lower = Bound {
        timestamp: 0,
        id_prefix: Vec::new(),
    };
    let mut out = Vec::new();
    for range in &incoming.ranges {
        let local: Vec<Item> = items
            .iter()
            .copied()
            .filter(|it| !item_below(it, &lower) && item_below(it, &range.upper))
            .collect();
        match &range.mode {
            Mode::Skip => {
                out.push(Range {
                    upper: range.upper.clone(),
                    mode: Mode::Skip,
                });
            }
            Mode::Fingerprint(remote_fp) => {
                let local_fp = Fingerprint::of(&local);
                if local_fp == *remote_fp {
                    out.push(Range {
                        upper: range.upper.clone(),
                        mode: Mode::Skip,
                    });
                } else {
                    split_range(&local, range.upper.clone(), &mut out);
                }
            }
            Mode::IdList(remote_ids) => {
                use std::collections::BTreeSet;
                let remote: BTreeSet<Digest32> = remote_ids.iter().copied().collect();
                let local_set: BTreeSet<Digest32> = local.iter().map(|i| i.id).collect();
                for id in &local_set {
                    if !remote.contains(id) {
                        result.have.push(*id);
                    }
                }
                for id in &remote {
                    if !local_set.contains(id) {
                        result.need.push(*id);
                    }
                }
                match role {
                    // The initiator has resolved this range: reply Skip.
                    Role::Initiator => out.push(Range {
                        upper: range.upper.clone(),
                        mode: Mode::Skip,
                    }),
                    // The responder replies with its own IdList so the initiator
                    // can diff against it.
                    Role::Responder => out.push(Range {
                        upper: range.upper.clone(),
                        mode: Mode::IdList(local_set.into_iter().collect()),
                    }),
                }
            }
        }
        lower = range.upper.clone();
    }
    // A response consisting solely of Skip ranges carries no new information, so
    // it is the terminal/empty message (the initiator stops, ADR-008/NIP-77).
    let all_skip = out.iter().all(|r| matches!(r.mode, Mode::Skip));
    result.response = if all_skip {
        Message::default()
    } else {
        Message { ranges: out }
    };
    result
}

/// Sort + dedup a list of ids into the canonical [`Item`] ordering used by the
/// engine. The single helper a caller uses to turn a feed/DAG's entry hashes into
/// reconciliation items.
#[must_use]
pub fn items_from_ids(ids: &[Digest32]) -> Vec<Item> {
    let mut items: Vec<Item> = ids.iter().map(|id| Item::new(*id)).collect();
    items.sort_unstable();
    items.dedup();
    items
}
