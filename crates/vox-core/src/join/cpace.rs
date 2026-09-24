//! CPace balanced PAKE — Ristretto255 + SHA-512 (ADR-005 factor 1, ADR-003 PAKE
//! id `0x0701`).
//!
//! This is the CFRG primary instantiation from `draft-irtf-cfrg-cpace`, group =
//! Ristretto255, hash = SHA-512. CPace is symmetric — no server, no fixed
//! initiator/responder roles — so Vox uses the draft's **symmetric / parallel**
//! transcript (`transcript_oc`, the ordered-concatenation `o_cat` variant): both
//! parties independently derive the same intermediate session key (ISK) regardless
//! of message order. It gives implicit mutual authentication and limits an attacker
//! to **one online guess per interaction** against the low-entropy passphrase.
//!
//! ## The exact construction (draft-irtf-cfrg-cpace)
//! Let `H = SHA-512` (`s_in_bytes = 128`, output 64), `G = Ristretto255`
//! (`DSI = "CPaceRistretto255"`).
//!
//! - **Generator.** `g = map_to_group(SHA-512(generator_string(DSI, PRS, CI, sid)))`
//!   where `generator_string = lv_cat(DSI, PRS, zpad, CI, sid)` and `zpad` is the
//!   zero padding that fixes PRS's position inside the first hash block:
//!   `len_zpad = max(0, s_in_bytes − 1 − len(prepend_len(PRS)) − len(prepend_len(DSI)))`.
//!   The 64-byte SHA-512 digest is mapped to a Ristretto point with the
//!   ristretto255 one-way map (`RistrettoPoint::from_uniform_bytes`).
//! - **Shares.** Each side samples a scalar `y` (32 random bytes with the top 4
//!   bits of the last byte cleared, then reduced — the draft's recommended
//!   `sample_scalar`) and sends `Y = (y · g)` as a 32-byte compressed Ristretto.
//! - **ISK.** `K = y · Y_peer`; **abort if K is the identity**
//!   (`scalar_mult_vfy` MUST-abort). Then
//!   `ISK = SHA-512( lv_cat("CPaceRistretto255_ISK", sid, K) ‖ transcript_oc(Ya,ADa,Yb,ADb) )`
//!   where `transcript_oc(...) = "oc" ‖ <larger lv-block> ‖ <smaller lv-block>`,
//!   the blocks being `lv_cat(Y, AD)` compared lexicographically. ISK is 64 bytes.
//!
//! Vox binds, per ADR-005:
//! - `CI = "vox/cpace/v1" ‖ channelID ‖ epoch_be` — channel identifier,
//! - `sid` — a fresh per-run nonce (the run identifier),
//! - `AD = suite_id_be` — the negotiated ciphersuite (ADR-003), identical on both
//!   sides so the symmetric ordering depends only on the shares.
//!
//! ## Validation against test vectors
//! The draft's Ristretto255+SHA-512 vector (Appendix B) is hardcoded in the tests
//! and is the **correctness gate**: `calculate_generator`, the scalar→share step,
//! `K`, and the symmetric `ISK_oc` must all reproduce the published bytes. The
//! `PRS`/`zpad`/`generator_string` intermediate is checked byte-for-byte too.
//!
//! ## What CPace does NOT prove
//! CPace proves "this party holds the passphrase", not *which identity* it is. The
//! identity is bound separately by the proof-of-possession run inside the
//! CPace-keyed channel ([`crate::join::pop`]). That separation is the whole point
//! of ADR-005's two-factor join.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::identity::rng::random_array;

/// Length of a CPace public share (compressed Ristretto255 point).
pub const CPACE_SHARE_LEN: usize = 32;

/// Length of the CPace intermediate session key (SHA-512 output).
pub const CPACE_ISK_LEN: usize = 64;

/// SHA-512 input block size (`s_in_bytes`), used for the generator-string padding.
const SHA512_BLOCK: usize = 128;

/// The Ristretto255 group domain-separation identifier (`G.DSI`).
const DSI: &[u8] = b"CPaceRistretto255";

/// The ISK domain-separation identifier (`G.DSI ‖ "_ISK"`).
const DSI_ISK: &[u8] = b"CPaceRistretto255_ISK";

/// The Vox channel-identifier label prefixed onto `CI` (ADR-005).
pub const CPACE_CI_LABEL: &str = "vox/cpace/v1";

/// LEB128 length prefix `prepend_len(data)` from the draft: the unsigned LEB128
/// encoding of `data.len()`, followed by `data`.
fn prepend_len(data: &[u8], out: &mut Vec<u8>) {
    let mut length = data.len();
    loop {
        if length < 0x80 {
            out.push(length as u8);
            break;
        }
        out.push(((length & 0x7f) | 0x80) as u8);
        length >>= 7;
    }
    out.extend_from_slice(data);
}

/// `lv_cat(*args)` from the draft: the length-prefixed concatenation of the args.
fn lv_cat(args: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for a in args {
        prepend_len(a, &mut out);
    }
    out
}

/// Length of `prepend_len(data)` (the LEB128 prefix plus the data) — used to size
/// the generator-string zero padding without materializing the prefix.
fn prepend_len_len(data_len: usize) -> usize {
    let mut n = data_len;
    let mut prefix = 1;
    while n >= 0x80 {
        prefix += 1;
        n >>= 7;
    }
    prefix + data_len
}

/// Build `generator_string(DSI, PRS, CI, sid, s_in_bytes)`:
/// `lv_cat(DSI, PRS, zpad, CI, sid)` with the zero padding that pins PRS inside
/// the first SHA-512 block (draft `generator_string`).
fn generator_string(prs: &[u8], ci: &[u8], sid: &[u8]) -> Vec<u8> {
    // len_zpad = max(0, s_in_bytes - 1 - len(prepend_len(PRS)) - len(prepend_len(DSI)))
    let len_zpad = SHA512_BLOCK
        .saturating_sub(1)
        .saturating_sub(prepend_len_len(prs.len()))
        .saturating_sub(prepend_len_len(DSI.len()));
    let zpad = vec![0u8; len_zpad];
    lv_cat(&[DSI, prs, &zpad, ci, sid])
}

/// `calculate_generator(H, PRS, CI, sid)` for Ristretto255: hash the
/// generator-string with SHA-512 and map the 64-byte digest to a Ristretto point
/// via the ristretto255 one-way map (`from_uniform_bytes`).
fn calculate_generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> RistrettoPoint {
    let gen_str = generator_string(prs, ci, sid);
    let mut h = Sha512::new();
    h.update(&gen_str);
    let digest: [u8; 64] = h.finalize().into();
    RistrettoPoint::from_uniform_bytes(&digest)
}

/// `sample_scalar()` for Ristretto255 (draft-recommended): 32 random bytes with
/// the top 4 bits of the last byte cleared (`group_size_bits = 252`), reduced mod
/// the group order. Zeroizes the random buffer.
fn sample_scalar() -> Result<Scalar> {
    let mut bytes = random_array::<32>()?;
    bytes[31] &= 0x0f; // clear bits 252..256
    let s = Scalar::from_bytes_mod_order(bytes);
    bytes.zeroize();
    Ok(s)
}

/// `o_cat(a, b)` — ordered concatenation: `"oc" ‖ max(a,b) ‖ min(a,b)` with `max`/
/// `min` by lexicographic byte comparison (a longer string with a shared prefix is
/// the larger). This is what makes the transcript symmetric: both sides order the
/// two `lv_cat(Y, AD)` blocks identically.
fn o_cat(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + a.len() + b.len());
    out.extend_from_slice(b"oc");
    // "lexicographically_larger(a, b)" in the draft: standard byte ordering.
    if a > b {
        out.extend_from_slice(a);
        out.extend_from_slice(b);
    } else {
        out.extend_from_slice(b);
        out.extend_from_slice(a);
    }
    out
}

/// `transcript_oc(Ya, ADa, Yb, ADb)` — the symmetric/parallel-mode transcript:
/// `o_cat(lv_cat(Ya, ADa), lv_cat(Yb, ADb))`.
fn transcript_oc(ya: &[u8], ad_a: &[u8], yb: &[u8], ad_b: &[u8]) -> Vec<u8> {
    let block_a = lv_cat(&[ya, ad_a]);
    let block_b = lv_cat(&[yb, ad_b]);
    o_cat(&block_a, &block_b)
}

/// Build the Vox CPace channel identifier `CI = "vox/cpace/v1" ‖ channelID ‖
/// epoch_be` (ADR-005).
#[must_use]
pub fn channel_identifier(channel_id: &[u8; 32], epoch: u64) -> Vec<u8> {
    let mut ci = Vec::with_capacity(CPACE_CI_LABEL.len() + 32 + 8);
    ci.extend_from_slice(CPACE_CI_LABEL.as_bytes());
    ci.extend_from_slice(channel_id);
    ci.extend_from_slice(&epoch.to_be_bytes());
    ci
}

/// One party's in-progress CPace run.
///
/// Created with [`CpaceState::start`], which samples the secret scalar and the
/// public share to send. The peer's share is consumed by [`CpaceState::finish`],
/// which yields the 64-byte ISK (or aborts on a degenerate share). The secret
/// scalar is held in a zeroizing wrapper and consumed on `finish`.
pub struct CpaceState {
    /// The secret scalar `y` for this run (zeroized on drop).
    scalar: SecretScalar,
    /// This party's public share `Y = y · g` (compressed Ristretto).
    own_share: [u8; CPACE_SHARE_LEN],
    /// The CPace channel identifier `CI` (ADR-005), held to bind into the ISK
    /// transcript via the recomputed generator on both sides (it is already mixed
    /// into `g`; the associated data carried in the transcript is `AD = suite_id`).
    associated_data: Vec<u8>,
    /// The fresh per-run session id `sid`.
    sid: Vec<u8>,
}

/// A CPace secret scalar that zeroizes its byte representation on drop. The dalek
/// `Scalar` does not zeroize by itself under our feature set, so we keep the
/// canonical bytes alongside and wipe them; the `Scalar` value is `Copy` and short
/// lived inside method bodies.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretScalar {
    bytes: [u8; 32],
}

impl SecretScalar {
    fn new(s: &Scalar) -> Self {
        Self {
            bytes: s.to_bytes(),
        }
    }

    fn scalar(&self) -> Scalar {
        // Canonical 32-byte little-endian encoding of a reduced scalar always
        // parses; `from_canonical_bytes` returns the same value we stored.
        Scalar::from_bytes_mod_order(self.bytes)
    }
}

impl core::fmt::Debug for CpaceState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never render the secret scalar; the public share is fine to show.
        f.debug_struct("CpaceState")
            .field("own_share", &crate::hash::Hex(&self.own_share))
            .finish_non_exhaustive()
    }
}

impl CpaceState {
    /// Begin a CPace run for `(passphrase, channel_id, epoch, suite_id, sid)`.
    ///
    /// - `passphrase` is `PRS` (the low-entropy shared secret) — its bytes feed
    ///   only the generator, never rendezvous (ADR-005).
    /// - `channel_id` + `epoch` form `CI = "vox/cpace/v1" ‖ channelID ‖ epoch`.
    /// - `suite_id` is the associated data `AD` (ADR-003 ciphersuite id).
    /// - `sid` is the fresh per-run nonce; both parties MUST use the same `sid`
    ///   (exchanged in the open before the run) — reuse across runs would let a
    ///   transcript be replayed, so callers generate it freshly with
    ///   [`fresh_sid`].
    ///
    /// Returns the state plus this party's public share to transmit.
    pub fn start(
        passphrase: &[u8],
        channel_id: &[u8; 32],
        epoch: u64,
        suite_id: u16,
        sid: &[u8],
    ) -> Result<(Self, [u8; CPACE_SHARE_LEN])> {
        let ci = channel_identifier(channel_id, epoch);
        let g = calculate_generator(passphrase, &ci, sid);
        let scalar = sample_scalar()?;
        let share_point = g * scalar;
        let own_share = share_point.compress().to_bytes();
        let state = Self {
            scalar: SecretScalar::new(&scalar),
            own_share,
            associated_data: suite_id.to_be_bytes().to_vec(),
            sid: sid.to_vec(),
        };
        Ok((state, own_share))
    }

    /// This party's public share (the value passed to the peer).
    #[must_use]
    pub fn own_share(&self) -> &[u8; CPACE_SHARE_LEN] {
        &self.own_share
    }

    /// Complete the run against the peer's share, returning the 64-byte ISK.
    ///
    /// Aborts with [`Error::CpaceInvalidShare`] if the peer's share does not decode
    /// as a Ristretto point, or if the derived `K = y · Y_peer` is the group
    /// identity (the `scalar_mult_vfy` MUST-abort: a degenerate share, or `y = 0`,
    /// would otherwise leak a trivially-known key).
    ///
    /// The ISK is returned in a [`Zeroizing`] buffer; the caller derives whatever
    /// keys it needs and lets it drop. `self` is consumed so the secret scalar is
    /// wiped exactly once.
    pub fn finish(
        self,
        peer_share: &[u8; CPACE_SHARE_LEN],
    ) -> Result<Zeroizing<[u8; CPACE_ISK_LEN]>> {
        let peer_point = CompressedRistretto(*peer_share)
            .decompress()
            .ok_or(Error::CpaceInvalidShare)?;
        let k_point = peer_point * self.scalar.scalar();
        // scalar_mult_vfy MUST abort if K = G.I (identity element).
        if k_point.is_identity() {
            return Err(Error::CpaceInvalidShare);
        }
        let k = Zeroizing::new(k_point.compress().to_bytes());

        // ISK = SHA-512( lv_cat(DSI_ISK, sid, K) ‖ transcript_oc(Ya,ADa,Yb,ADb) ).
        // AD is identical on both sides (suite_id), so the symmetric ordering
        // depends only on the two shares — exactly the draft's intent.
        let transcript = transcript_oc(
            &self.own_share,
            &self.associated_data,
            peer_share,
            &self.associated_data,
        );
        let prefix = lv_cat(&[DSI_ISK, &self.sid, &k[..]]);

        let mut h = Sha512::new();
        h.update(&prefix);
        h.update(&transcript);
        let isk: [u8; CPACE_ISK_LEN] = h.finalize().into();
        Ok(Zeroizing::new(isk))
    }
}

/// Generate a fresh 16-byte CPace session id `sid` from the OS CSPRNG.
///
/// `sid` MUST be fresh per run and shared by both parties (exchanged in the open
/// before the run). 128 bits is the draft's recommended size and matches the
/// channel/genesis nonce width used elsewhere in Vox.
pub fn fresh_sid() -> Result<[u8; 16]> {
    random_array::<16>()
}
