//! The Vox datagram frame and its reassembly (ADR-022 decisions 2 and 4).
//!
//! Every RFC 9221 datagram Vox sends names the **flow** it belongs to, so one
//! connection can carry many independent datagram flows — a relay circuit, a UDP
//! tunnel, an app's media — and a reader can hand each datagram to the one flow that
//! owns it ([`crate::transport::router`]).
//!
//! ## Frame layout
//! ```text
//! datagram   := varint flow_id ‖ varint context ‖ varint sent_us ‖ body
//! context 0  := body is one whole packet
//! context 1  := body is a fragment: varint packet_id ‖ u8 index ‖ u8 count ‖ bytes
//! context ≥2 := reserved; dropped and counted
//! ```
//! `sent_us` is when the sender framed it, in microseconds on the **sender's own**
//! monotonic clock ([`now_us`]). The receiver never compares it with its own clock
//! directly, only with the other send times of the same flow: arrival minus send time is
//! the one-way delay plus a constant clock offset, and its running minimum over a few
//! seconds is the path's base delay plus that offset. How far a datagram is above that
//! minimum is how late it is, which is how a receiver drops a datagram too late to be
//! worth delivering (ADR-022 decision 5, R27) with no clock synchronisation. A relay
//! forwards the field untouched.
//! Varints are QUIC's (RFC 9000 §16): the two high bits of the first byte give the
//! length, 1, 2, 4 or 8 bytes.
//!
//! ## Why there is no sequence number and no replay window
//! Until ADR-022 every datagram carried an 8-byte sequence behind a DTLS-style
//! 1024-packet replay window. It protected nothing. QUIC already refuses a replayed
//! or duplicated packet (RFC 9000 §12.3: packet protection plus packet-number
//! de-duplication), and a datagram is a frame inside such a packet, so an on-path
//! replay never reaches this layer. A relay carries inner QUIC packets that the inner
//! connection de-duplicates for itself. And the window could *wrongly* drop a
//! legitimate packet that arrived far out of order. It cost 8 bytes on every packet.
//!
//! ## Fragmentation (R26)
//! A packet that fits the connection's datagram limit after the header goes whole.
//! A larger one is split into at most [`MAX_FRAGMENTS`] fragments, and never more than
//! [`MAX_PACKET`] bytes in all, the largest UDP payload. The receiver reassembles per
//! `(flow, packet_id)` under three bounds — [`REASSEMBLY_TIMEOUT`],
//! [`MAX_PARTIALS_PER_FLOW`] and [`MAX_PARTIAL_BYTES`] — and a fragment is **never
//! retransmitted**: a lost fragment loses its packet, as a lost IP fragment does.
//! That is why fragmenting is the exception, not the norm.

use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Microseconds on this process's monotonic clock: the `sent_us` a datagram carries, and
/// what a receiver compares arrivals against. Only differences within one process mean
/// anything.
#[must_use]
pub fn now_us() -> u64 {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    u64::try_from(ORIGIN.get_or_init(Instant::now).elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// Context 0: the body is one whole packet.
pub const CONTEXT_PACKET: u64 = 0;

/// Context 1: the body is one fragment of a packet.
pub const CONTEXT_FRAGMENT: u64 = 1;

/// The most fragments one packet may be split into: the count is a `u8`.
pub const MAX_FRAGMENTS: usize = 255;

/// The largest packet Vox will fragment and reassemble: the largest UDP payload.
pub const MAX_PACKET: usize = 65_535;

/// A packet whose fragments are not all present this long after the first arrived is
/// dropped whole.
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_millis(500);

/// At most this many partly reassembled packets per flow; past it the flow's oldest is
/// dropped.
pub const MAX_PARTIALS_PER_FLOW: usize = 32;

/// At most this much partial-packet state per connection; past it the connection's
/// oldest partial packet is dropped.
pub const MAX_PARTIAL_BYTES: usize = 1024 * 1024;

/// The largest value a QUIC varint holds.
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// The encoded length of `v` as a QUIC varint.
#[must_use]
pub fn varint_len(v: u64) -> usize {
    match v {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

/// Append `v` as a QUIC varint. A value past [`VARINT_MAX`] is clamped to it: every
/// value Vox encodes — a stream ID, a context, a packet counter — is far below it.
pub fn put_varint(out: &mut Vec<u8>, v: u64) {
    let v = v.min(VARINT_MAX);
    match varint_len(v) {
        1 => out.push(v as u8),
        2 => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
        4 => out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes()),
    }
}

/// Read one QUIC varint off the front of `buf`, returning it and the rest.
#[must_use]
pub fn take_varint(buf: &[u8]) -> Option<(u64, &[u8])> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    let raw = buf.get(..len)?;
    let mut v = u64::from(first & 0x3F);
    for b in &raw[1..] {
        v = (v << 8) | u64::from(*b);
    }
    Some((v, &buf[len..]))
}

/// A whole packet framed for `flow`, sent at `sent_us` ([`now_us`]).
#[must_use]
pub fn frame_packet(flow: u64, sent_us: u64, packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(varint_len(flow) + 1 + varint_len(sent_us) + packet.len());
    put_varint(&mut out, flow);
    put_varint(&mut out, CONTEXT_PACKET);
    put_varint(&mut out, sent_us);
    out.extend_from_slice(packet);
    out
}

/// A datagram that carries `rest` — a context and its body, exactly as another flow
/// received them — on `flow` instead. This is all a relay does to a datagram: it
/// changes which flow it is on, and never looks at, reassembles or re-splits what it
/// carries.
#[must_use]
pub fn reframe(flow: u64, rest: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(varint_len(flow) + rest.len());
    put_varint(&mut out, flow);
    out.extend_from_slice(rest);
    out
}

/// Split `packet` into context-1 fragments for `flow`, each at most `max` bytes.
///
/// `None` if it cannot be done within the bounds: more than [`MAX_PACKET`] bytes, more
/// than [`MAX_FRAGMENTS`] fragments, or a limit too small to carry the fragment header
/// and one byte.
#[must_use]
pub fn fragment(
    flow: u64,
    sent_us: u64,
    packet_id: u64,
    packet: &[u8],
    max: usize,
) -> Option<Vec<Vec<u8>>> {
    if packet.len() > MAX_PACKET {
        return None;
    }
    let header = varint_len(flow) + 1 + varint_len(sent_us) + varint_len(packet_id) + 2;
    let chunk = max.checked_sub(header).filter(|c| *c > 0)?;
    let count = packet.len().div_ceil(chunk).max(1);
    let count = u8::try_from(count).ok()?;
    Some(
        packet
            .chunks(chunk)
            .enumerate()
            .map(|(index, bytes)| {
                let mut out = Vec::with_capacity(header + bytes.len());
                put_varint(&mut out, flow);
                put_varint(&mut out, CONTEXT_FRAGMENT);
                put_varint(&mut out, sent_us);
                put_varint(&mut out, packet_id);
                // `index < count <= 255`, so the cast cannot truncate.
                out.push(index as u8);
                out.push(count);
                out.extend_from_slice(bytes);
                out
            })
            .collect(),
    )
}

/// What one received datagram turned out to be, before any flow was consulted.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed<'a> {
    /// A whole packet.
    Packet(&'a [u8]),
    /// One fragment of a packet.
    Fragment(Fragment<'a>),
}

/// One fragment of a packet, as parsed off the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment<'a> {
    /// Which of the flow's packets it belongs to.
    pub packet_id: u64,
    /// Its place in the packet.
    pub index: u8,
    /// How many fragments the packet has.
    pub count: u8,
    /// Its bytes.
    pub bytes: &'a [u8],
}

/// Why a datagram could not be parsed.
#[derive(Debug, PartialEq, Eq)]
pub enum Unparsable {
    /// The header is cut short, or a fragment's index or count is impossible.
    Malformed,
    /// A context this version does not define (≥ 2).
    UnknownContext,
}

/// Parse the part of a datagram after its flow ID: `context ‖ sent_us ‖ body`. Returns the
/// sender's `sent_us` with what the body is.
pub fn parse_body(rest: &[u8]) -> std::result::Result<(u64, Parsed<'_>), Unparsable> {
    let (context, body) = take_varint(rest).ok_or(Unparsable::Malformed)?;
    if context > CONTEXT_FRAGMENT {
        return Err(Unparsable::UnknownContext);
    }
    let (sent_us, body) = take_varint(body).ok_or(Unparsable::Malformed)?;
    let parsed = match context {
        CONTEXT_PACKET => Parsed::Packet(body),
        _ => {
            let (packet_id, body) = take_varint(body).ok_or(Unparsable::Malformed)?;
            let (&index, body) = body.split_first().ok_or(Unparsable::Malformed)?;
            let (&count, bytes) = body.split_first().ok_or(Unparsable::Malformed)?;
            if count == 0 || index >= count {
                return Err(Unparsable::Malformed);
            }
            Parsed::Fragment(Fragment {
                packet_id,
                index,
                count,
                bytes,
            })
        }
    };
    Ok((sent_us, parsed))
}

/// What handing one fragment to the [`Reassembler`] produced.
#[derive(Debug, PartialEq, Eq)]
pub enum Reassembled {
    /// The packet is complete.
    Complete(Vec<u8>),
    /// More fragments are needed.
    Pending,
    /// The fragment contradicted the others of its packet (a different count, or a
    /// total past [`MAX_PACKET`]); the packet is dropped.
    Rejected,
}

/// What the reassembler threw away, for the connection's counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Discarded {
    /// Partial packets dropped because [`REASSEMBLY_TIMEOUT`] passed.
    pub expired: u64,
    /// Partial packets dropped to stay inside [`MAX_PARTIALS_PER_FLOW`] or
    /// [`MAX_PARTIAL_BYTES`].
    pub evicted: u64,
}

struct Partial {
    count: u8,
    have: usize,
    parts: Vec<Option<Vec<u8>>>,
    bytes: usize,
    started: Instant,
    /// Its place in the connection-wide age order.
    seq: u64,
}

impl Partial {
    /// What this partial costs against [`MAX_PARTIAL_BYTES`]: its bytes, and its slot
    /// table, so a flood of one-byte fragments of 255-fragment packets is bounded by the
    /// memory it really takes and not only by the bytes it carries.
    fn cost(&self) -> usize {
        self.bytes + self.parts.len() * std::mem::size_of::<Option<Vec<u8>>>()
    }
}

/// Per-connection reassembly of fragmented packets, under ADR-022's bounds.
///
/// Owned by the connection's one datagram reader, so it needs no lock.
#[derive(Default)]
pub struct Reassembler {
    partials: HashMap<(u64, u64), Partial>,
    /// Age order across the connection: sequence → key.
    order: BTreeMap<u64, (u64, u64)>,
    per_flow: HashMap<u64, usize>,
    cost: usize,
    next_seq: u64,
}

impl Reassembler {
    /// Take one fragment of `flow`'s packet `packet_id`, at `now`.
    pub fn accept(
        &mut self,
        flow: u64,
        fragment: &Fragment<'_>,
        now: Instant,
        discarded: &mut Discarded,
    ) -> Reassembled {
        let Fragment {
            packet_id,
            index,
            count,
            bytes,
        } = *fragment;
        self.expire(now, discarded);
        let key = (flow, packet_id);
        if !self.partials.contains_key(&key) {
            if self.per_flow.get(&flow).copied().unwrap_or(0) >= MAX_PARTIALS_PER_FLOW {
                if let Some(oldest) = self.oldest_of(flow) {
                    self.remove(oldest);
                    discarded.evicted += 1;
                }
            }
            let seq = self.next_seq;
            self.next_seq += 1;
            let partial = Partial {
                count,
                have: 0,
                parts: vec![None; usize::from(count)],
                bytes: 0,
                started: now,
                seq,
            };
            self.cost += partial.cost();
            self.partials.insert(key, partial);
            self.order.insert(seq, key);
            *self.per_flow.entry(flow).or_insert(0) += 1;
        }
        let Some(partial) = self.partials.get_mut(&key) else {
            return Reassembled::Pending;
        };
        let fits = partial.count == count && partial.bytes + bytes.len() <= MAX_PACKET;
        let Some(slot) = partial.parts.get_mut(usize::from(index)).filter(|_| fits) else {
            self.remove(key);
            return Reassembled::Rejected;
        };
        if slot.is_none() {
            *slot = Some(bytes.to_vec());
            partial.have += 1;
            partial.bytes += bytes.len();
            self.cost += bytes.len();
        }
        if partial.have == usize::from(partial.count) {
            let Some(done) = self.remove(key) else {
                return Reassembled::Pending;
            };
            return Reassembled::Complete(done.parts.into_iter().flatten().flatten().collect());
        }
        while self.cost > MAX_PARTIAL_BYTES {
            let Some((_, &oldest)) = self.order.iter().next() else {
                break;
            };
            self.remove(oldest);
            discarded.evicted += 1;
            if oldest == key {
                return Reassembled::Pending;
            }
        }
        Reassembled::Pending
    }

    /// How many packets are partly reassembled right now.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.partials.len()
    }

    fn expire(&mut self, now: Instant, discarded: &mut Discarded) {
        while let Some((_, &key)) = self.order.iter().next() {
            let expired = self
                .partials
                .get(&key)
                .is_none_or(|p| now.duration_since(p.started) >= REASSEMBLY_TIMEOUT);
            if !expired {
                break;
            }
            self.remove(key);
            discarded.expired += 1;
        }
    }

    fn oldest_of(&self, flow: u64) -> Option<(u64, u64)> {
        self.order.values().find(|(f, _)| *f == flow).copied()
    }

    fn remove(&mut self, key: (u64, u64)) -> Option<Partial> {
        let partial = self.partials.remove(&key)?;
        self.cost = self.cost.saturating_sub(partial.cost());
        self.order.remove(&partial.seq);
        match self.per_flow.get_mut(&key.0) {
            Some(n) if *n > 1 => *n -= 1,
            _ => {
                self.per_flow.remove(&key.0);
            }
        }
        Some(partial)
    }
}
