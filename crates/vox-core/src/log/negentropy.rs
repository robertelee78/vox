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

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Digest32 {
        let mut d = [0u8; 32];
        d[0] = n;
        d
    }

    #[test]
    fn varint_round_trip_and_known_vectors() {
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (127, &[0x7f]),
            (128, &[0x81, 0x00]),
            (300, &[0x82, 0x2c]),
        ];
        for &(n, expect) in cases {
            let mut v = Vec::new();
            write_varint(&mut v, n);
            assert_eq!(v, expect, "encode {n}");
            let mut pos = 0;
            assert_eq!(read_varint(&v, &mut pos).unwrap(), n, "decode {n}");
            assert_eq!(pos, v.len());
        }
    }

    #[test]
    fn fingerprint_sum_is_little_endian_mod_2_256() {
        // Two ids that are byte-reverses sum predictably; just assert determinism
        // and that order does not matter (addition is commutative).
        let a = id(1);
        let b = id(2);
        let f1 = Fingerprint::of(&[Item::new(a), Item::new(b)]);
        let f2 = Fingerprint::of(&[Item::new(b), Item::new(a)]);
        assert_eq!(f1, f2);
        // Different sets differ.
        let f3 = Fingerprint::of(&[Item::new(a)]);
        assert_ne!(f1, f3);
    }

    #[test]
    fn fingerprint_carry_propagates_across_limbs() {
        // 0xFF..FF (limb 0 all ones) + 1 should carry into limb 1.
        let mut all_ones_limb0 = [0u8; 32];
        for byte in all_ones_limb0.iter_mut().take(8) {
            *byte = 0xff;
        }
        let mut one = [0u8; 32];
        one[0] = 1;
        let mut acc = [0u8; 32];
        add_le_256(&mut acc, &all_ones_limb0);
        add_le_256(&mut acc, &one);
        // Result: limb0 == 0, limb1 (byte 8) == 1.
        assert_eq!(&acc[0..8], &[0u8; 8]);
        assert_eq!(acc[8], 1);
    }

    #[test]
    fn message_round_trip() {
        let msg = Message {
            ranges: vec![
                Range {
                    upper: Bound {
                        timestamp: 0,
                        id_prefix: vec![0xab, 0xcd],
                    },
                    mode: Mode::Fingerprint(Fingerprint([7u8; 16])),
                },
                Range {
                    upper: Bound::infinity(),
                    mode: Mode::IdList(vec![id(1), id(2)]),
                },
            ],
        };
        let bytes = encode_message(&msg);
        assert_eq!(bytes[0], PROTOCOL_VERSION);
        let back = decode_message(&bytes).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn decode_rejects_bad_version() {
        let bytes = [0x62u8, 0x00];
        assert!(matches!(
            decode_message(&bytes),
            Err(Error::UnsupportedVersion { version: 0x62, .. })
        ));
    }

    #[test]
    fn decode_rejects_oversize_message_and_idlist_count() {
        // Over-limit message length is rejected before any decoding work.
        let huge = vec![PROTOCOL_VERSION; MAX_MESSAGE_LEN + 1];
        assert!(matches!(
            decode_message(&huge),
            Err(Error::SizeLimitExceeded("negentropy message"))
        ));

        // An IdList range declaring more ids than MAX_IDS_PER_RANGE is rejected
        // BEFORE the per-id loop/allocation (no large alloc on a tiny frame).
        let mut frame = vec![PROTOCOL_VERSION];
        // Bound: infinity (ts varint 0), id-prefix len 0.
        write_varint(&mut frame, 0); // timestamp = infinity
        write_varint(&mut frame, 0); // id-prefix len
        write_varint(&mut frame, 2); // mode = IdList
        write_varint(&mut frame, (MAX_IDS_PER_RANGE as u64) + 1); // hostile count
                                                                  // No id bytes follow — the count cap must fire before reading them.
        assert!(matches!(
            decode_message(&frame),
            Err(Error::SizeLimitExceeded("negentropy idlist count"))
        ));
    }

    #[test]
    fn identical_sets_reconcile_in_one_step() {
        let ids: Vec<Digest32> = (0..50u8).map(id).collect();
        let items = items_from_ids(&ids);
        let opener = reconcile_initiate(&items);
        let res = reconcile(Role::Responder, &items, &opener);
        // Equal sets: nothing to exchange, the responder's message is empty.
        assert!(res.response.is_empty());
        assert!(res.have.is_empty());
        assert!(res.need.is_empty());
    }

    /// Drive a full Alice↔Bob reconciliation to convergence, returning Alice's
    /// learned (have, need) sets.
    fn drive(
        alice: &[Item],
        bob: &[Item],
    ) -> (
        std::collections::BTreeSet<Digest32>,
        std::collections::BTreeSet<Digest32>,
    ) {
        let mut msg = reconcile_initiate(alice);
        let mut have = std::collections::BTreeSet::new();
        let mut need = std::collections::BTreeSet::new();
        let mut rounds = 0;
        loop {
            rounds += 1;
            assert!(rounds < 30, "did not converge");
            let bob_res = reconcile(Role::Responder, bob, &msg);
            if bob_res.response.is_empty() {
                break;
            }
            let alice_res = reconcile(Role::Initiator, alice, &bob_res.response);
            have.extend(alice_res.have);
            need.extend(alice_res.need);
            if alice_res.response.is_empty() {
                break;
            }
            msg = alice_res.response;
        }
        (have, need)
    }

    #[test]
    fn divergent_sets_reconcile_to_full_diff() {
        // Alice has 0..60, Bob has 20..80.
        let alice = items_from_ids(&(0..60u8).map(id).collect::<Vec<_>>());
        let bob = items_from_ids(&(20..80u8).map(id).collect::<Vec<_>>());
        let (have, need) = drive(&alice, &bob);
        let expect_need: std::collections::BTreeSet<Digest32> = (60..80u8).map(id).collect();
        let expect_have: std::collections::BTreeSet<Digest32> = (0..20u8).map(id).collect();
        assert_eq!(need, expect_need, "need mismatch");
        assert_eq!(have, expect_have, "have mismatch");
    }

    #[test]
    fn large_divergent_sets_reconcile_via_recursion() {
        // 600 vs 600 items forces real fingerprint splitting (well above 2*BUCKETS).
        let mk = |lo: u32, hi: u32| -> Vec<Digest32> {
            (lo..hi).map(|n| sha256(&n.to_le_bytes())).collect()
        };
        let alice = items_from_ids(&mk(0, 600));
        let bob = items_from_ids(&mk(300, 900));
        let (have, need) = drive(&alice, &bob);
        let alice_set: std::collections::BTreeSet<Digest32> = mk(0, 600).into_iter().collect();
        let bob_set: std::collections::BTreeSet<Digest32> = mk(300, 900).into_iter().collect();
        let expect_have: std::collections::BTreeSet<Digest32> =
            alice_set.difference(&bob_set).copied().collect();
        let expect_need: std::collections::BTreeSet<Digest32> =
            bob_set.difference(&alice_set).copied().collect();
        assert_eq!(have, expect_have, "have mismatch");
        assert_eq!(need, expect_need, "need mismatch");
    }
}
