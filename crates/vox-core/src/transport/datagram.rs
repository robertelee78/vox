//! RFC 9221 unreliable-datagram framing with a Vox 64-bit sequence number and a
//! DTLS-style sliding anti-replay window (ADR-011 §"Datagram anti-replay").
//!
//! QUIC's reliable streams are ordered and de-duplicated by the transport, but the
//! RFC 9221 unreliable-DATAGRAM extension delivers each datagram at most once with
//! no ordering or replay protection at the Vox layer. Low-latency Vox flows that
//! ride datagrams therefore carry their own monotonically-increasing 64-bit
//! sequence number, and the receiver keeps a sliding bitmap window (default
//! [`DEFAULT_WINDOW`] = 1024) to drop duplicates and far-out-of-order datagrams —
//! the same anti-replay construction DTLS/IPsec use.
//!
//! ## Frame layout
//! A datagram is `seq(8, big-endian) ‖ payload`. The 8-byte fixed prefix keeps
//! parsing branch-free and the sequence outside the (separately AEAD-protected)
//! payload. The transport AEAD (the QUIC connection keys) protects confidentiality
//! and integrity; this layer adds only replay/order defence over that channel.
//!
//! ## Window semantics (matches RFC 6347 §4.1.2.6 / RFC 4303 anti-replay)
//! - A sequence above the current high-water mark advances the window and is
//!   accepted (the window slides, bits for newly-uncovered slots clear).
//! - A sequence within the window that has not been seen is accepted and marked.
//! - A sequence within the window already marked, or below the window's lower
//!   edge, is rejected as a replay/too-old.

/// The default sliding-window width in packets (ADR-011 default 1024).
pub const DEFAULT_WINDOW: u64 = 1024;

/// The fixed datagram sequence-prefix length in bytes.
pub const SEQ_PREFIX_LEN: usize = 8;

/// Frame a datagram payload with its 64-bit sequence: `seq(8 BE) ‖ payload`.
#[must_use]
pub fn frame_datagram(seq: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SEQ_PREFIX_LEN + payload.len());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Parse a datagram frame into `(seq, payload)`. Returns `None` if the frame is
/// shorter than the 8-byte sequence prefix.
#[must_use]
pub fn parse_datagram(frame: &[u8]) -> Option<(u64, &[u8])> {
    let seq_bytes: [u8; SEQ_PREFIX_LEN] = frame.get(..SEQ_PREFIX_LEN)?.try_into().ok()?;
    Some((u64::from_be_bytes(seq_bytes), &frame[SEQ_PREFIX_LEN..]))
}

/// A monotonic outbound datagram sequence counter.
///
/// Sequence numbers start at 0 and increase by one per datagram. A wrap of a
/// 64-bit counter is unreachable in any real deployment (it would require
/// ~10^19 datagrams on one connection); the counter saturates rather than wraps so
/// it can never silently reuse a sequence (a reused sequence would be dropped by
/// the peer's replay window — fail-closed, never a silent replay window hole).
#[derive(Debug, Default)]
pub struct DatagramSender {
    next: u64,
}

impl DatagramSender {
    /// A fresh sender starting at sequence 0.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate the next outbound sequence number.
    pub fn next_seq(&mut self) -> u64 {
        let seq = self.next;
        self.next = self.next.saturating_add(1);
        seq
    }

    /// Frame `payload` with the next sequence number.
    pub fn frame(&mut self, payload: &[u8]) -> Vec<u8> {
        frame_datagram(self.next_seq(), payload)
    }
}

/// A DTLS-style sliding anti-replay window over inbound datagram sequence numbers.
///
/// `highest` is the largest accepted sequence (the window's right edge). `bitmap`
/// bit `i` (counting from the LSB) tracks whether `highest - i` has been seen, for
/// `i` in `0..window`. The window covers `(highest - window, highest]`.
#[derive(Debug)]
pub struct ReplayWindow {
    window: u64,
    highest: u64,
    /// Bit `i` = sequence `highest - i` seen. Sized to `window` bits.
    bitmap: Vec<u64>,
    /// Whether any sequence has been accepted yet (so sequence 0 is acceptable on
    /// a fresh window without being mistaken for "already seen").
    seen_any: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW)
    }
}

impl ReplayWindow {
    /// Create a window of `window` packets (clamped to at least 1).
    #[must_use]
    pub fn new(window: u64) -> Self {
        let window = window.max(1);
        let words = window.div_ceil(64) as usize;
        Self {
            window,
            highest: 0,
            bitmap: vec![0u64; words],
            seen_any: false,
        }
    }

    /// The configured window width.
    #[must_use]
    pub fn width(&self) -> u64 {
        self.window
    }

    /// Test-and-set: accept `seq` if it is new and in range, marking it seen.
    /// Returns `true` if accepted, `false` if it is a replay or too old.
    ///
    /// This is the only mutator: a caller checks the return value and drops the
    /// datagram on `false` (ADR-011 — out-of-window or duplicate datagrams are
    /// dropped).
    pub fn accept(&mut self, seq: u64) -> bool {
        if !self.seen_any {
            // First datagram: accept any sequence and seed the window at it.
            self.seen_any = true;
            self.highest = seq;
            self.clear_all();
            self.set_bit(0);
            return true;
        }
        if seq > self.highest {
            // Advance: slide right by (seq - highest), clearing newly-uncovered
            // slots, then mark the new high-water bit.
            let shift = seq - self.highest;
            self.shift_left(shift);
            self.highest = seq;
            self.set_bit(0);
            true
        } else {
            // Within or below the window.
            let diff = self.highest - seq;
            if diff >= self.window {
                // Below the window's lower edge — too old.
                return false;
            }
            let i = diff; // bit index from the right edge
            if self.get_bit(i) {
                false // already seen → replay
            } else {
                self.set_bit(i);
                true
            }
        }
    }

    // --- bitmap helpers (bit i counts from the right edge / LSB) ---

    fn clear_all(&mut self) {
        for w in &mut self.bitmap {
            *w = 0;
        }
    }

    fn get_bit(&self, i: u64) -> bool {
        let (word, bit) = ((i / 64) as usize, i % 64);
        self.bitmap.get(word).is_some_and(|w| (w >> bit) & 1 == 1)
    }

    fn set_bit(&mut self, i: u64) {
        let (word, bit) = ((i / 64) as usize, i % 64);
        if let Some(w) = self.bitmap.get_mut(word) {
            *w |= 1u64 << bit;
        }
    }

    /// Shift the whole bitmap left by `shift` bit positions (the window slides
    /// toward newer sequences; vacated low bits become 0, i.e. "not yet seen").
    fn shift_left(&mut self, shift: u64) {
        if shift >= self.window {
            self.clear_all();
            return;
        }
        let word_shift = (shift / 64) as usize;
        let bit_shift = (shift % 64) as u32;
        let n = self.bitmap.len();
        if word_shift > 0 {
            for idx in (0..n).rev() {
                self.bitmap[idx] = if idx >= word_shift {
                    self.bitmap[idx - word_shift]
                } else {
                    0
                };
            }
        }
        if bit_shift > 0 {
            let mut carry = 0u64;
            for w in &mut self.bitmap {
                let new_carry = *w >> (64 - bit_shift);
                *w = (*w << bit_shift) | carry;
                carry = new_carry;
            }
        }
    }
}
