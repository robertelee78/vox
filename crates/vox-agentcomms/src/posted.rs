//! A message as the log holds it, and how its ids are written.
//!
//! The log supplies three facts the envelope does not carry: the entry hash, the signed
//! author and the author's recorded time. [`Posted`] keeps them with the envelope, so code
//! that reads a room (replies, op ids, wakes) never has to look them up again.

use crate::envelope::Envelope;

/// A message as the log holds it: the envelope plus the three facts the log
/// supplies and the envelope therefore does not carry.
#[derive(Debug, Clone, PartialEq)]
pub struct Posted {
    /// The entry hash — the message id, and the tie-break.
    pub entry_hash: [u8; 32],
    /// The signed author's fingerprint.
    pub author: [u8; 32],
    /// The author's recorded send time, **milliseconds** since the Unix epoch.
    ///
    /// Milliseconds, because whole seconds put two messages from different authors in one
    /// bucket, where only the entry hash orders them.
    pub created_millis: u64,
    /// The message.
    pub envelope: Envelope,
}

impl Posted {
    /// The send time in whole seconds, for display.
    #[must_use]
    pub const fn created_secs(&self) -> u64 {
        self.created_millis / 1_000
    }
}

/// The base32 alphabet Vox renders every id in (RFC 4648, lowercased, unpadded).
const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Render a 32-byte id as Vox renders fingerprints and entry hashes: 52 lowercase
/// base32 characters.
///
/// Duplicated from `vox-core`'s `link::b32_encode` on purpose: this crate does not
/// depend on the core (ADR-020 §1), and an id on the wire is text anyway.
#[must_use]
pub fn b32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(52);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32[((acc >> bits) & 0x1F) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(B32[((acc << (5 - bits)) & 0x1F) as usize]));
    }
    out
}

/// Parse a full 52-character base32 id, case-insensitively. `None` for anything else,
/// including a prefix: an id in a message is copied, never abbreviated.
#[must_use]
pub fn from_b32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 52 {
        return None;
    }
    let mut out = [0u8; 32];
    let (mut acc, mut bits, mut n) = (0u32, 0u32, 0usize);
    for c in text.bytes() {
        let lower = c.to_ascii_lowercase();
        let val = u32::try_from(B32.iter().position(|a| *a == lower)?).ok()?;
        acc = (acc << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if n == 32 {
                return None;
            }
            out[n] = u8::try_from((acc >> bits) & 0xFF).ok()?;
            n += 1;
        }
    }
    // Canonical encoding only: the trailing bits must be zero, so one id has one
    // spelling and two nodes cannot disagree about whether they name the same member.
    if n != 32 || (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}
