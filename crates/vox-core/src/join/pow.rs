//! Equihash join proof-of-work (ADR-005 anti-abuse layer 2).
//!
//! Each join attempt carries a PoW token bound to `(channelID, epoch,
//! responder_nonce)` so tokens cannot be precomputed or replayed across
//! channels/epochs. The function is **Equihash** (Biryukov–Khovratovich), at
//! Zcash's `n=200, k=9` by default — an *asymmetric memory-hard* PoW: hard to
//! **solve** (denies GPU/ASIC advantage via memory bandwidth) yet **cheap to
//! verify** (a few hashes + XOR checks, sub-millisecond), so verification is never
//! itself the DoS. The responder advertises a [`Difficulty`] (an
//! effective-difficulty filter on the solution hash) it can raise under load,
//! carried in the **signed** [`ResponderNonce`] so the prover cannot lie about it.
//!
//! ## Two layers, both required
//! 1. **Equihash validity** — the solution must be a real Equihash solution for
//!    the input `seed = "vox/join-pow/v1" ‖ channelID ‖ epoch_be ‖ responder_nonce`
//!    and a prover-chosen `nonce`. This is the memory-hard part. Verification uses
//!    the librustzcash [`equihash::is_valid_solution`] (runtime `(n,k)`), the
//!    canonical Zcash construction.
//! 2. **Difficulty filter** — `BLAKE2b("vox/join-pow-diff/v1" ‖ seed ‖ nonce ‖
//!    solution)` must have at least [`Difficulty::leading_zero_bits`] leading zero
//!    bits. Zcash itself layers difficulty on a hash of the header (not on Equihash
//!    directly); the same layering here makes the cost *tunable* without changing
//!    `(n,k)`, and an attacker cannot separate the layers (a solution that fails the
//!    filter forces restarting the memory-hard search).
//!
//! ## Difficulty policy (ADR-005) — calibrated, not prose
//! The cost model: an Equihash `(200,9)` solve yields ≈ 2 solutions per nonce by
//! design, and a solution passes a `d`-bit filter with probability `2^-d`, so a
//! join costs about `max(1, 2^d / 2)` **base solves** ([`Difficulty::expected_solves`]).
//! The base solve is the memory-hard unit of cost; the filter tunes it *upward*.
//! Measured on 2026-09-19 (release build, Apple-silicon laptop core, the
//! `spike_pow` example): a `(200,9)` base solve with this crate's Wagner solver is
//! **≈ 7.5 s and 1.65 GB peak RSS**, 2.0 solutions/nonce. That is already above
//! ADR-005's *target* of ≈ 1–2 s on a mobile CPU — the gap is the solver's memory
//! layout (a tromp-class bucket-sorted design runs the same algorithm in ≈ 144 MB
//! and well under a second per nonce), not the language; closing it is the next
//! PoW milestone (ADR-005 Implementation notes). The defaults below are therefore
//! expressed in base-solve multiples:
//! - [`Difficulty::DEFAULT_INVITE`] (1 bit, ≈ 1 solve): identity-bound / invite
//!   channels — the smallest *non-zero* filter, so a leaked channelID still costs a
//!   full memory-hard solve per attempt.
//! - [`Difficulty::DEFAULT_OPEN`] (2 bits, ≈ 2 solves): open passphrase channels.
//! - [`Difficulty::MAX`] (8 bits, ≈ 128 solves): the **accessibility cap**. A joiner
//!   refuses a challenge above it ([`crate::join::join_initiate`]), which also
//!   bounds the grind any attacker-signed challenge can extract.
//! - [`Difficulty::adapted_for_load`]: the responder-side adaptation rule (one extra
//!   bit per doubling of pending joins above a small threshold, capped at `MAX`; it
//!   falls back as load falls). It is a pure function the node runtime calls with
//!   its live queue depth.
//! - **Literal zero** ([`Difficulty::ZERO`]) is reserved for explicit LAN/closed
//!   mode — Equihash validity still applies; only the tunable filter is disabled.
//! - Difficulty is a parameter the responder sets and signs; it is not the security
//!   boundary (per-sender consent, ADR-007, is the real read-gate).
//!
//! ## Solve path — pure Rust, one backend
//! A pure-Rust generalized-Wagner solver ([`wagner`]) is the *only* prover, at
//! every parameter set. CI runs it at reduced `(n,k)` (the tests use `n=48,k=5`)
//! through the solve→verify round-trip; the real `(200,9)` solve is exercised by an
//! `#[ignore]`d test (seconds and GBs) and timed by the `spike_pow` example. Every
//! solution is cross-checked by the librustzcash verifier — that is the correctness
//! gate. The optional C++ `tromp` backend ADR-005 once carved out was **rejected by
//! the decider on 2026-09-19** ("Vox is Rust only"); it no longer exists in the
//! build, the manifest, or CI.

pub mod wagner;

use blake2b_simd::Params as Blake2bParams;

use crate::error::{Error, Result};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::identity::rng::random_array;

/// Default Equihash `n` (Zcash parameter): the hash output bit length.
pub const EQUIHASH_N: u32 = 200;
/// Default Equihash `k` (Zcash parameter): the collision-tree depth.
pub const EQUIHASH_K: u32 = 9;

/// Domain label for the Equihash PoW seed (the memory-hard input).
pub const POW_SEED_DOMAIN: &str = "vox/join-pow/v1";
/// Domain label for the difficulty-filter hash.
pub const POW_DIFF_DOMAIN: &str = "vox/join-pow-diff/v1";
/// Domain label for the signed responder-nonce body.
pub const RESPONDER_NONCE_DOMAIN: &str = "vox/join-rnonce/v1";

/// The Equihash parameters `(n, k)` for a PoW instance.
///
/// The defaults are `(200, 9)`; reduced parameters are used for fast CI solving.
/// `new` enforces the librustzcash validity constraints (`n % 8 == 0`, `k >= 3`,
/// `k < n`, `n % (k+1) == 0`, and the index width fits 32 bits) so an invalid
/// instance can never be constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowParams {
    /// Equihash `n` (hash output bit length).
    pub n: u32,
    /// Equihash `k` (collision-tree depth).
    pub k: u32,
}

impl PowParams {
    /// The production default: Zcash `(200, 9)`.
    pub const DEFAULT: Self = Self {
        n: EQUIHASH_N,
        k: EQUIHASH_K,
    };

    /// Construct and validate `(n, k)`. Returns [`Error::JoinPowInvalid`] if the
    /// pair violates Equihash's constraints.
    pub fn new(n: u32, k: u32) -> Result<Self> {
        // Mirror librustzcash `Params::new`: n%8==0, k in [3, n), n%(k+1)==0, and
        // ceil((n/(k+1)+1)/8) <= 4 (index fits a u32 in the minimal encoding).
        let ok = n.is_multiple_of(8) && k >= 3 && k < n && n.is_multiple_of(k + 1) && {
            let collision_bit_length = n / (k + 1);
            (collision_bit_length + 1).div_ceil(8) <= 4
        };
        if ok {
            Ok(Self { n, k })
        } else {
            Err(Error::JoinPowInvalid)
        }
    }

    /// The collision bit length `n / (k + 1)`.
    #[must_use]
    pub fn collision_bit_length(&self) -> u32 {
        self.n / (self.k + 1)
    }

    /// The number of indices in a solution `2^k`.
    #[must_use]
    pub fn solution_indices(&self) -> usize {
        1usize << self.k
    }

    /// The compressed (minimal) solution length in bytes:
    /// `2^k * (collision_bit_length + 1) / 8`.
    #[must_use]
    pub fn solution_len(&self) -> usize {
        (self.solution_indices() * (self.collision_bit_length() as usize + 1)) / 8
    }
}

/// The PoW difficulty: a minimum number of leading zero bits on the difficulty
/// hash. `0` means no filter (LAN/closed mode only — ADR-005). See the module
/// docs for the cost model and the measured calibration behind the defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Difficulty {
    /// Required leading zero bits on `BLAKE2b(diff_domain ‖ seed ‖ nonce ‖ soln)`.
    pub leading_zero_bits: u8,
}

impl Difficulty {
    /// No difficulty filter — explicit LAN/closed mode only (ADR-005). Equihash
    /// validity still applies; only the tunable filter is disabled.
    pub const ZERO: Self = Self::bits(0);

    /// Default for identity-bound / invite channels: the smallest **non-zero**
    /// filter (≈ 1 expected base solve). ADR-005: "low but non-zero — a leaked
    /// channelID cannot cheaply flood the swarm".
    pub const DEFAULT_INVITE: Self = Self::bits(1);

    /// Default for open passphrase channels (≈ 2 expected base solves).
    pub const DEFAULT_OPEN: Self = Self::bits(2);

    /// The accessibility cap (≈ 128 expected base solves). A responder never
    /// advertises above it ([`Difficulty::adapted_for_load`] saturates here) and a
    /// joiner refuses a challenge above it, which also bounds the grind an
    /// attacker-signed challenge can extract.
    pub const MAX: Self = Self::bits(8);

    /// Expected Equihash solutions per nonce at `(200,9)` (≈ 2 by construction of
    /// the generalized-birthday parameters; measured 2.0 on 2026-09-19).
    pub const SOLUTIONS_PER_NONCE: f64 = 2.0;

    /// Pending-join queue depth at which load adaptation starts adding bits.
    pub const ADAPT_THRESHOLD: u32 = 4;

    /// Build a difficulty of `bits` leading zero bits.
    #[must_use]
    pub const fn bits(bits: u8) -> Self {
        Self {
            leading_zero_bits: bits,
        }
    }

    /// Expected number of memory-hard base solves a joiner performs to satisfy
    /// this difficulty: `max(1, 2^bits / SOLUTIONS_PER_NONCE)`. This is the cost
    /// model the defaults are calibrated in (see module docs).
    #[must_use]
    pub fn expected_solves(self) -> f64 {
        let candidates = 2f64.powi(i32::from(self.leading_zero_bits));
        (candidates / Self::SOLUTIONS_PER_NONCE).max(1.0)
    }

    /// Whether this difficulty exceeds the accessibility cap ([`Difficulty::MAX`]).
    #[must_use]
    pub fn exceeds_cap(self) -> bool {
        self > Self::MAX
    }

    /// The responder's load-adaptation rule (ADR-005: "adapts upward under load and
    /// downward when idle"): from a base difficulty, add one bit per doubling of
    /// `pending_joins` at or above [`Difficulty::ADAPT_THRESHOLD`], saturating at
    /// [`Difficulty::MAX`]. Pure and monotone in `pending_joins`, so a node calls
    /// it with its live queue depth each time it mints a challenge; as the queue
    /// drains the result falls back to `self`.
    #[must_use]
    pub fn adapted_for_load(self, pending_joins: u32) -> Self {
        let extra = if pending_joins >= Self::ADAPT_THRESHOLD {
            (pending_joins / Self::ADAPT_THRESHOLD).ilog2()
        } else {
            0
        };
        let extra = u8::try_from(extra).unwrap_or(u8::MAX);
        let bits = self.leading_zero_bits.saturating_add(extra);
        Self::bits(bits.min(Self::MAX.leading_zero_bits))
    }

    /// Whether `hash` satisfies this difficulty (has at least `leading_zero_bits`
    /// leading zero bits, most-significant first).
    #[must_use]
    pub fn is_met_by(&self, hash: &[u8]) -> bool {
        let mut remaining = self.leading_zero_bits as usize;
        for &byte in hash {
            if remaining == 0 {
                return true;
            }
            if remaining >= 8 {
                if byte != 0 {
                    return false;
                }
                remaining -= 8;
            } else {
                // Check the top `remaining` bits of this byte are zero.
                let mask = 0xffu8 << (8 - remaining);
                return byte & mask == 0;
            }
        }
        remaining == 0
    }
}

/// The responder's signed nonce that binds a PoW challenge.
///
/// The responder generates a fresh `nonce` and an advertised [`Difficulty`], then
/// signs `"vox/join-rnonce/v1" ‖ channelID ‖ epoch_be ‖ difficulty ‖ nonce` with
/// its composite identity key. The prover cannot lie about the difficulty because
/// it is inside the responder's signature, and the verifier checks that signature
/// before accepting any token. This is what ADR-005 means by "carried in the signed
/// responder-nonce so the prover cannot lie about it".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponderNonce {
    /// The channel this challenge is for.
    pub channel_id: [u8; 32],
    /// The channel epoch (ADR-007) this challenge is for.
    pub epoch: u64,
    /// The advertised difficulty.
    pub difficulty: Difficulty,
    /// The fresh 32-byte responder nonce.
    pub nonce: [u8; 32],
}

impl ResponderNonce {
    /// Generate a fresh responder nonce for `(channel_id, epoch, difficulty)`.
    pub fn generate(channel_id: &[u8; 32], epoch: u64, difficulty: Difficulty) -> Result<Self> {
        Ok(Self {
            channel_id: *channel_id,
            epoch,
            difficulty,
            nonce: random_array::<32>()?,
        })
    }

    /// The signed body `"vox/join-rnonce/v1" ‖ channelID ‖ epoch_be ‖ difficulty ‖ nonce`.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RESPONDER_NONCE_DOMAIN.len() + 32 + 8 + 1 + 32);
        out.extend_from_slice(RESPONDER_NONCE_DOMAIN.as_bytes());
        out.extend_from_slice(&self.channel_id);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.push(self.difficulty.leading_zero_bits);
        out.extend_from_slice(&self.nonce);
        out
    }

    /// Sign this nonce with the responder's composite identity key.
    pub fn sign(&self, root: &dyn RootSigner) -> Result<CompositeSignature> {
        root.sign(&self.signing_input())
    }

    /// Verify the responder's signature over this nonce.
    pub fn verify(&self, root: &CompositePublicKey, sig: &CompositeSignature) -> Result<()> {
        root.verify(&self.signing_input(), sig)
            .map_err(|_| Error::JoinPowInvalid)
    }

    /// The Equihash seed bound to this challenge:
    /// `"vox/join-pow/v1" ‖ channelID ‖ epoch_be ‖ responder_nonce`.
    #[must_use]
    pub fn pow_seed(&self) -> Vec<u8> {
        let mut seed = Vec::with_capacity(POW_SEED_DOMAIN.len() + 32 + 8 + 32);
        seed.extend_from_slice(POW_SEED_DOMAIN.as_bytes());
        seed.extend_from_slice(&self.channel_id);
        seed.extend_from_slice(&self.epoch.to_be_bytes());
        seed.extend_from_slice(&self.nonce);
        seed
    }
}

/// A completed PoW token: the prover's Equihash nonce and the minimal solution
/// bytes for the responder-bound seed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PowToken {
    /// The prover-chosen Equihash nonce (the per-attempt counter).
    pub equihash_nonce: Vec<u8>,
    /// The compressed (minimal) Equihash solution bytes.
    pub solution: Vec<u8>,
}

/// Compute the difficulty-filter hash
/// `BLAKE2b("vox/join-pow-diff/v1" ‖ seed ‖ equihash_nonce ‖ solution)` (32 bytes).
fn difficulty_hash(seed: &[u8], equihash_nonce: &[u8], solution: &[u8]) -> [u8; 32] {
    let mut h = Blake2bParams::new().hash_length(32).to_state();
    h.update(POW_DIFF_DOMAIN.as_bytes());
    h.update(seed);
    h.update(equihash_nonce);
    h.update(solution);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

/// Verify a [`PowToken`] against a *signature-verified* [`ResponderNonce`].
///
/// The caller MUST first verify the responder's signature on `challenge`
/// ([`ResponderNonce::verify`]); this function trusts the difficulty in
/// `challenge`. It checks (1) the solution length matches `(n,k)`, (2) Equihash
/// validity for the responder-bound seed and the prover's nonce, and (3) the
/// difficulty filter. Any failure yields [`Error::JoinPowInvalid`]. Verification is
/// cheap (a few hashes + XOR checks) — never the DoS.
pub fn verify_token(params: PowParams, challenge: &ResponderNonce, token: &PowToken) -> Result<()> {
    if token.solution.len() != params.solution_len() {
        return Err(Error::JoinPowInvalid);
    }
    let seed = challenge.pow_seed();
    // (2) Equihash validity (the librustzcash canonical verifier).
    equihash::is_valid_solution(
        params.n,
        params.k,
        &seed,
        &token.equihash_nonce,
        &token.solution,
    )
    .map_err(|_| Error::JoinPowInvalid)?;
    // (3) Difficulty filter.
    let dh = difficulty_hash(&seed, &token.equihash_nonce, &token.solution);
    if !challenge.difficulty.is_met_by(&dh) {
        return Err(Error::JoinPowInvalid);
    }
    Ok(())
}

/// Solve a PoW challenge with the pure-Rust Wagner solver ([`wagner::solve`]),
/// returning a valid [`PowToken`]. One backend at every parameter set; the
/// nonce search is bounded at `2^24` nonces (a difficulty at [`Difficulty::MAX`]
/// needs ≈ 128 in expectation).
pub fn solve_token(params: PowParams, challenge: &ResponderNonce) -> Result<PowToken> {
    solve_token_bounded(params, challenge, 1 << 24)
}

/// [`solve_token`] with an explicit nonce-search bound (for tests).
pub fn solve_token_bounded(
    params: PowParams,
    challenge: &ResponderNonce,
    max_nonces: u32,
) -> Result<PowToken> {
    let seed = challenge.pow_seed();
    for counter in 0u32..max_nonces {
        let equihash_nonce = wagner::nonce_bytes(counter);
        for solution in wagner::solve(params, &seed, &equihash_nonce)? {
            let dh = difficulty_hash(&seed, &equihash_nonce, &solution);
            if challenge.difficulty.is_met_by(&dh) {
                // Cross-check with the canonical verifier before returning.
                if equihash::is_valid_solution(
                    params.n,
                    params.k,
                    &seed,
                    &equihash_nonce,
                    &solution,
                )
                .is_ok()
                {
                    return Ok(PowToken {
                        equihash_nonce,
                        solution,
                    });
                }
            }
        }
    }
    Err(Error::JoinPowInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;

    fn signer() -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[5; 32], &[6; 32]).unwrap()
    }

    /// Reduced params for fast CI solving: (48,5) — a 512-row initial list, so the
    /// pure-Rust solver finishes quickly. The librustzcash verifier accepts any
    /// `(n,k)`, so this still exercises the real verify path.
    fn reduced() -> PowParams {
        PowParams::new(48, 5).unwrap()
    }

    #[test]
    fn pow_params_validate() {
        assert_eq!(PowParams::DEFAULT, PowParams::new(200, 9).unwrap());
        assert_eq!(PowParams::new(96, 5).unwrap().solution_len(), 32 * 17 / 8); // 68
        assert_eq!(PowParams::DEFAULT.solution_len(), 1344);
        // Invalid pairs rejected.
        assert!(PowParams::new(200, 8).is_err()); // 200 % 9 != 0
        assert!(PowParams::new(7, 3).is_err()); // n % 8 != 0
        assert!(PowParams::new(96, 2).is_err()); // k < 3
    }

    #[test]
    fn difficulty_defaults_cap_and_cost_model() {
        // Ordering: ZERO < invite < open <= MAX; both defaults are non-zero.
        assert!(Difficulty::ZERO < Difficulty::DEFAULT_INVITE);
        assert!(Difficulty::DEFAULT_INVITE < Difficulty::DEFAULT_OPEN);
        assert!(Difficulty::DEFAULT_OPEN <= Difficulty::MAX);
        assert_ne!(Difficulty::DEFAULT_INVITE, Difficulty::ZERO);
        // Cost model in base solves: max(1, 2^d / 2).
        assert_eq!(Difficulty::ZERO.expected_solves(), 1.0);
        assert_eq!(Difficulty::DEFAULT_INVITE.expected_solves(), 1.0);
        assert_eq!(Difficulty::DEFAULT_OPEN.expected_solves(), 2.0);
        assert_eq!(Difficulty::bits(3).expected_solves(), 4.0);
        assert_eq!(Difficulty::MAX.expected_solves(), 128.0);
        // Cap.
        assert!(!Difficulty::MAX.exceeds_cap());
        assert!(Difficulty::bits(Difficulty::MAX.leading_zero_bits + 1).exceeds_cap());
    }

    #[test]
    fn difficulty_adapts_monotonically_and_saturates() {
        let base = Difficulty::DEFAULT_OPEN;
        // Below the threshold nothing changes (idle = base).
        for pending in 0..Difficulty::ADAPT_THRESHOLD {
            assert_eq!(base.adapted_for_load(pending), base);
        }
        // One extra bit per doubling at/above the threshold …
        assert_eq!(base.adapted_for_load(4), Difficulty::bits(2));
        assert_eq!(base.adapted_for_load(8), Difficulty::bits(3));
        assert_eq!(base.adapted_for_load(16), Difficulty::bits(4));
        assert_eq!(base.adapted_for_load(64), Difficulty::bits(6));
        // … monotone in load …
        let mut last = base;
        for pending in 0..2048u32 {
            let d = base.adapted_for_load(pending);
            assert!(d >= last, "difficulty must not fall as load rises");
            last = d;
        }
        // … and never above the cap, even under absurd load.
        assert_eq!(base.adapted_for_load(u32::MAX), Difficulty::MAX);
        assert_eq!(Difficulty::MAX.adapted_for_load(u32::MAX), Difficulty::MAX);
        // Falls back as load drains.
        assert_eq!(base.adapted_for_load(0), base);
    }

    #[test]
    fn difficulty_leading_zero_bits() {
        assert!(Difficulty::ZERO.is_met_by(&[0xff; 32]));
        assert!(Difficulty::bits(8).is_met_by(&[0x00, 0xff]));
        assert!(!Difficulty::bits(8).is_met_by(&[0x01, 0x00]));
        assert!(Difficulty::bits(12).is_met_by(&[0x00, 0x0f]));
        assert!(!Difficulty::bits(12).is_met_by(&[0x00, 0x10]));
        assert!(Difficulty::bits(1).is_met_by(&[0x7f]));
        assert!(!Difficulty::bits(1).is_met_by(&[0x80]));
    }

    #[test]
    fn responder_nonce_signature_round_trip() {
        let root = signer();
        let rn = ResponderNonce::generate(&[7; 32], 3, Difficulty::ZERO).unwrap();
        let sig = rn.sign(&root).unwrap();
        assert!(rn.verify(&root.public_key(), &sig).is_ok());
        // Tampering the difficulty (the thing the prover must not lie about) breaks
        // the signature.
        let mut rn2 = rn.clone();
        rn2.difficulty = Difficulty::bits(20);
        assert!(matches!(
            rn2.verify(&root.public_key(), &sig),
            Err(Error::JoinPowInvalid)
        ));
    }

    #[test]
    fn solve_then_verify_round_trip_reduced() {
        // Always-on correctness gate: pure-Rust Wagner solve at (96,5) produces a
        // token the canonical librustzcash verifier accepts.
        let params = reduced();
        let rn = ResponderNonce::generate(&[1; 32], 1, Difficulty::ZERO).unwrap();
        let token = solve_token_bounded(params, &rn, 64).unwrap();
        assert_eq!(token.solution.len(), params.solution_len());
        assert!(verify_token(params, &rn, &token).is_ok());
    }

    #[test]
    fn token_bound_to_channel_epoch_nonce() {
        // A token solved for one challenge must not verify under another channel,
        // epoch, or responder nonce (no precompute/replay).
        let params = reduced();
        let rn = ResponderNonce::generate(&[1; 32], 1, Difficulty::ZERO).unwrap();
        let token = solve_token_bounded(params, &rn, 64).unwrap();
        assert!(verify_token(params, &rn, &token).is_ok());

        let mut other_channel = rn.clone();
        other_channel.channel_id = [2; 32];
        assert!(matches!(
            verify_token(params, &other_channel, &token),
            Err(Error::JoinPowInvalid)
        ));
        let mut other_epoch = rn.clone();
        other_epoch.epoch = 2;
        assert!(matches!(
            verify_token(params, &other_epoch, &token),
            Err(Error::JoinPowInvalid)
        ));
        let mut other_nonce = rn.clone();
        other_nonce.nonce = [9; 32];
        assert!(matches!(
            verify_token(params, &other_nonce, &token),
            Err(Error::JoinPowInvalid)
        ));
    }

    #[test]
    fn difficulty_filter_enforced() {
        // A token that passes Equihash but not the difficulty filter is rejected.
        let params = reduced();
        let rn = ResponderNonce::generate(&[3; 32], 1, Difficulty::ZERO).unwrap();
        let token = solve_token_bounded(params, &rn, 64).unwrap();
        // Re-run verification under a difficulty that the token's hash will (almost
        // certainly) fail: require 32 leading zero bits.
        let mut hard = rn.clone();
        hard.difficulty = Difficulty::bits(32);
        // The token was solved for ZERO difficulty; under 32-bit difficulty it
        // fails unless its hash happens to start with 4 zero bytes (~2^-32).
        let dh = difficulty_hash(&hard.pow_seed(), &token.equihash_nonce, &token.solution);
        if !Difficulty::bits(32).is_met_by(&dh) {
            assert!(matches!(
                verify_token(params, &hard, &token),
                Err(Error::JoinPowInvalid)
            ));
        }
    }

    #[test]
    fn wrong_length_solution_rejected() {
        let params = reduced();
        let rn = ResponderNonce::generate(&[1; 32], 1, Difficulty::ZERO).unwrap();
        let token = PowToken {
            equihash_nonce: wagner::nonce_bytes(0),
            solution: vec![0u8; params.solution_len() - 1],
        };
        assert!(matches!(
            verify_token(params, &rn, &token),
            Err(Error::JoinPowInvalid)
        ));
    }

    #[test]
    fn verify_is_cheap() {
        // Sanity: verification of a valid token completes well under a tenth of a
        // second (it is a few hashes + XOR checks). Not a benchmark, just a guard
        // that verify is not accidentally doing solver-grade work.
        let params = reduced();
        let rn = ResponderNonce::generate(&[1; 32], 1, Difficulty::ZERO).unwrap();
        let token = solve_token_bounded(params, &rn, 64).unwrap();
        let start = std::time::Instant::now();
        for _ in 0..50 {
            verify_token(params, &rn, &token).unwrap();
        }
        assert!(start.elapsed().as_millis() < 500, "verify too slow");
    }

    /// The real (200,9) solve path EXISTS and is correct, but is slow with the
    /// pure-Rust Wagner solver, so it is ignored by default. Run with
    /// `cargo test -- --ignored` (allow several minutes / GBs of RAM).
    #[test]
    #[ignore = "real (200,9) Wagner solve is memory-hard and slow; on-demand only"]
    fn real_200_9_solve_then_verify() {
        let params = PowParams::DEFAULT;
        let rn = ResponderNonce::generate(&[1; 32], 1, Difficulty::ZERO).unwrap();
        let token = solve_token_bounded(params, &rn, 8).unwrap();
        assert_eq!(token.solution.len(), 1344);
        assert!(verify_token(params, &rn, &token).is_ok());
    }
}
