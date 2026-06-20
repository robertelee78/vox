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
//! ## Difficulty policy (ADR-005)
//! - **Identity-bound / invite channels** default to a *low but non-zero* PoW
//!   (`≈200–500 ms`) — a leaked channelID cannot cheaply flood the swarm.
//! - **Literal zero** is reserved for explicit LAN/closed mode
//!   ([`Difficulty::ZERO`]).
//! - Difficulty is modelled as a parameter the responder sets and signs; it is not
//!   the security boundary (per-sender consent, ADR-007, is the real read-gate).
//!
//! ## Solve paths
//! - **Always-on (CI):** a pure-Rust generalized-Wagner solver ([`wagner`])
//!   parameterised for *reduced* `(n,k)` (the tests use `n=48,k=5`), used by the
//!   always-on solve→verify round-trip test. It produces solutions the
//!   librustzcash verifier accepts — that cross-check is the correctness gate.
//! - **Real `(200,9)`:** the same Wagner solver runs at `(200,9)` correctly but is
//!   slow, so the real-parameter solve test is `#[ignore]`d. The librustzcash
//!   tromp C++ solver is also available under the `equihash-solver` crate feature
//!   (the `solve_real_200_9` function) for a fast real-parameter path. The
//!   `(200,9)` code path is real, not stubbed.

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
/// hash. `0` means no filter (LAN/closed mode only — ADR-005).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Difficulty {
    /// Required leading zero bits on `BLAKE2b(diff_domain ‖ seed ‖ nonce ‖ soln)`.
    pub leading_zero_bits: u8,
}

impl Difficulty {
    /// No difficulty filter — explicit LAN/closed mode only (ADR-005). Equihash
    /// validity still applies; only the tunable filter is disabled.
    pub const ZERO: Self = Self {
        leading_zero_bits: 0,
    };

    /// Build a difficulty of `bits` leading zero bits.
    #[must_use]
    pub fn bits(bits: u8) -> Self {
        Self {
            leading_zero_bits: bits,
        }
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

/// Which solver backend [`solve_token`] will use for a given parameter set.
///
/// This is the *decision*, separated from the *execution* so the selection logic is
/// unit-testable without running a (slow) real solve (ADR-005 §Implementation
/// notes, the Codex-review HIGH item).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolverStrategy {
    /// The pure-Rust generalized-Wagner solver ([`wagner::solve`]). Always used for
    /// reduced parameters; also the complete (slower) `(200,9)` fallback when the
    /// `equihash-solver` feature is **not** built.
    Wagner,
    /// The librustzcash C++ tromp solver ([`solve_real_200_9`]) — only selectable at
    /// the real `(200,9)` parameters and only when the `equihash-solver` feature is
    /// built. The fast production `(200,9)` prover.
    Tromp,
}

/// Choose the solver backend for `params` (ADR-005).
///
/// At the real `(200,9)` parameters the C++ tromp solver is preferred **iff** the
/// optional `equihash-solver` feature is compiled in (it meets the ~1–2 s mobile
/// join target; the pure-Rust solver is correct but takes seconds per nonce there).
/// Every other case — reduced parameters, or `(200,9)` without the feature — uses
/// the pure-Rust Wagner solver. Production `(200,9)` builds SHOULD enable
/// `equihash-solver`; without it the join still works, just slower.
#[must_use]
pub fn select_solver(params: PowParams) -> SolverStrategy {
    #[cfg(feature = "equihash-solver")]
    {
        if params == PowParams::DEFAULT {
            return SolverStrategy::Tromp;
        }
    }
    let _ = params;
    SolverStrategy::Wagner
}

/// Solve a PoW challenge, dispatching to the backend [`select_solver`] picks for
/// `params`, and returning a valid [`PowToken`].
///
/// - [`SolverStrategy::Tromp`] (real `(200,9)`, `equihash-solver` feature on) →
///   the fast C++ solver ([`solve_real_200_9`]).
/// - [`SolverStrategy::Wagner`] (reduced params, or `(200,9)` without the feature)
///   → the pure-Rust solver ([`solve_token_bounded`]). Correct at every parameter
///   set; at `(200,9)` it is the complete-but-slow fallback (production `(200,9)`
///   builds SHOULD enable `equihash-solver`).
pub fn solve_token(params: PowParams, challenge: &ResponderNonce) -> Result<PowToken> {
    match select_solver(params) {
        #[cfg(feature = "equihash-solver")]
        SolverStrategy::Tromp => solve_real_200_9(challenge),
        SolverStrategy::Wagner => solve_token_bounded(params, challenge, 1 << 24),
        // Without the feature, `Tromp` is never returned by `select_solver`, so this
        // arm is unreachable; it exists only to make the match exhaustive in both
        // cfg states without a feature-gated arm being the sole `Tromp` handler.
        #[cfg(not(feature = "equihash-solver"))]
        SolverStrategy::Tromp => solve_token_bounded(params, challenge, 1 << 24),
    }
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

/// Solve a real `(200, 9)` challenge with the librustzcash tromp C++ solver.
///
/// Available only with the `equihash-solver` crate feature (which builds the C++
/// backend). This is the fast real-parameter path; the always-on Wagner solver also
/// handles `(200,9)` correctly but slowly. Returns the first solution meeting the
/// difficulty.
///
/// Nonces are tried **one at a time** so the produced token's `equihash_nonce` is
/// exactly the nonce that generated the returned solution: the tromp helper's
/// `next_nonce` closure yields a single nonce, all its solutions for that nonce
/// come back, and each is re-checked through the canonical [`verify_token`] path
/// before being returned. There is therefore no nonce-binding ambiguity.
#[cfg(feature = "equihash-solver")]
pub fn solve_real_200_9(challenge: &ResponderNonce) -> Result<PowToken> {
    let params = PowParams::DEFAULT;
    let seed = challenge.pow_seed();
    for counter in 0u32..(1 << 20) {
        let mut equihash_nonce = [0u8; 32];
        equihash_nonce[..4].copy_from_slice(&counter.to_le_bytes());
        // Yield exactly this one nonce, then stop — so every returned solution is
        // for `equihash_nonce`.
        let mut yielded = false;
        let solutions = equihash::tromp::solve_200_9::<32>(&seed, || {
            if yielded {
                None
            } else {
                yielded = true;
                Some(equihash_nonce)
            }
        });
        for solution in solutions {
            let token = PowToken {
                equihash_nonce: equihash_nonce.to_vec(),
                solution,
            };
            // Canonical verify (Equihash validity + difficulty) — the single source
            // of truth, identical to what a remote verifier runs.
            if verify_token(params, challenge, &token).is_ok() {
                return Ok(token);
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
    fn solver_strategy_selects_correctly() {
        // Reduced parameters always use the pure-Rust Wagner solver, in either cfg.
        assert_eq!(
            select_solver(PowParams::new(48, 5).unwrap()),
            SolverStrategy::Wagner
        );
        assert_eq!(
            select_solver(PowParams::new(96, 5).unwrap()),
            SolverStrategy::Wagner
        );
        // The real (200,9) parameters pick the C++ tromp solver IFF the optional
        // feature is built; without it they fall back to the pure-Rust solver.
        // This tests the selection logic without running an actual (200,9) solve.
        let chosen = select_solver(PowParams::DEFAULT);
        #[cfg(feature = "equihash-solver")]
        assert_eq!(chosen, SolverStrategy::Tromp);
        #[cfg(not(feature = "equihash-solver"))]
        assert_eq!(chosen, SolverStrategy::Wagner);
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
