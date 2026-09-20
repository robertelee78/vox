//! Join orchestration (ADR-005 §Post-join): tie CPace + identity
//! proof-of-possession (+ a valid PoW) together and hand off to the M2 PQXDH
//! session that bootstraps the Double-Ratchet pairwise channel (ADR-004).
//!
//! ## The flow
//! A join is symmetric at the CPace layer but the PQXDH bootstrap has a natural
//! initiator (the joiner) and responder (the existing member whose prekey bundle
//! the joiner consumes). The orchestration:
//!
//! 1. **PoW (joiner → responder).** The responder issues a *signed*
//!    [`crate::join::pow::ResponderNonce`] (channel/epoch/difficulty bound). The
//!    joiner solves it; the responder verifies the token before doing CPace work,
//!    so passphrase-guessing is gated behind memory-hard work it cannot precompute.
//! 2. **CPace (both).** Both run [`crate::join::cpace`] keyed by the passphrase,
//!    `CI = "vox/cpace/v1" ‖ channelID ‖ epoch`, `AD = suite_id`, and a shared
//!    fresh `sid`. Equal passphrases ⇒ equal ISK; otherwise no agreement.
//! 3. **PoP (both, inside the CPace channel).** Each signs the run-bound
//!    `transcript_hash` with its composite identity key
//!    ([`crate::join::pop`]); each matches the peer's fingerprint to the expected
//!    one (ADR-014). This binds *which identity* is on each end.
//! 4. **PQXDH bootstrap.** On success the joiner runs [`Session::initiate`] against
//!    the responder's verified [`PrekeyBundlePublic`]; the responder runs
//!    [`Session::accept`] on the resulting [`InitialMessage`]. The established M2
//!    [`Session`] is the join's output.
//!
//! ## Boundary: joining yields NO readable content (ADR-005 / ADR-007)
//! The output of a successful join is a *pairwise* secure channel — nothing more.
//! Membership is emergent (join + per-sender consent, ADR-007/M6); a joined node
//! sees only ciphertext until individual members consent to it. There is **no
//! admin admission step and no membership certificate** here. This module
//! deliberately does not (and must not) grant read authority; that read-gate is
//! M6. The join proves "holds the passphrase" + "is this identity" + "did the
//! work" — it does not confer the right to *render* anything.
//!
//! ## What this module verifies vs. what the transport carries
//! This module computes and checks the cryptographic material. The *exchange* of
//! shares / PoP / PoW (and encrypting the PoP under a key derived from the CPace
//! ISK) is the transport's job (ADR-011/M9); the helpers here take and return the
//! values to put on / read off the wire, and a [`JoinContext`] bundles the binding
//! parameters so the two ends cannot silently disagree on channelID/epoch/suite.

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::identity::keyagreement::{PrekeyBundlePublic, X25519IdentityKey};
use crate::join::cpace::{CpaceState, CPACE_SHARE_LEN};
use crate::join::pop::{self, IdentityProof, JoinPeerIdentity};
use crate::join::pow::{self, PowParams, PowToken, ResponderNonce};
use crate::pairwise::session::Session;
use crate::pairwise::{InitialMessage, OtpReuseTracker, ResponderPrekeys};
use crate::suite::SuiteFloor;

/// The parameters that bind a join to a specific channel and suite. Both ends MUST
/// use identical values; a mismatch makes CPace fail to agree (the binding is into
/// `CI`/`AD`) and is the type-level guard against cross-channel confusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JoinContext {
    /// The channelID (ADR-005): `SHA-256(genesis)`.
    pub channel_id: [u8; 32],
    /// The channel epoch (ADR-007 rotation).
    pub epoch: u64,
    /// The negotiated ciphersuite id (ADR-003), bound as CPace `AD`. Must rank
    /// at or above [`JoinContext::floor`] (enforced by [`JoinContext::new`] and
    /// re-checked by [`join_initiate`] / [`join_accept`]).
    pub suite_id: u16,
    /// The channel's minimum ciphersuite (ADR-003 floor, from the genesis
    /// policy). Gates the CPace suite binding and the PQXDH bootstrap.
    pub floor: SuiteFloor,
    /// The Equihash PoW parameters in force for this channel.
    pub pow_params: PowParams,
}

impl JoinContext {
    /// Build a context with the production-default `(200,9)` PoW parameters.
    /// Fails with [`Error::SuiteBelowFloor`] if `suite_id` ranks below `floor`
    /// (a join can never negotiate under the channel's floor).
    pub fn new(channel_id: [u8; 32], epoch: u64, suite_id: u16, floor: SuiteFloor) -> Result<Self> {
        floor.check(suite_id)?;
        Ok(Self {
            channel_id,
            epoch,
            suite_id,
            floor,
            pow_params: PowParams::DEFAULT,
        })
    }
}

/// The joiner (PQXDH initiator) side of a join, after CPace start.
///
/// The borrowed signer is `Send + Sync` because this state is held across `await`
/// points when the exchange is driven over the network (ADR-016 §"Join over the
/// network"); the cryptography is unaffected.
///
/// Holds the in-progress CPace state and the joiner's X25519 identity key for the
/// subsequent PQXDH bootstrap. Produced by [`join_initiate`]; advanced by
/// [`JoinInitiator::complete_cpace`].
pub struct JoinInitiator<'a> {
    ctx: JoinContext,
    sid: Vec<u8>,
    cpace: CpaceState,
    own_share: [u8; CPACE_SHARE_LEN],
    root: &'a (dyn RootSigner + Send + Sync),
    ik: &'a X25519IdentityKey,
}

/// The responder (PQXDH responder) side of a join, after CPace start.
pub struct JoinResponder<'a> {
    ctx: JoinContext,
    sid: Vec<u8>,
    cpace: CpaceState,
    own_share: [u8; CPACE_SHARE_LEN],
    root: &'a (dyn RootSigner + Send + Sync),
}

/// Begin the joiner side: solve the PoW, start CPace, and produce the values to
/// send (PoW token, CPace share). The caller transmits these; the peer's share is
/// fed to [`JoinInitiator::complete_cpace`] and the peer's PoP to
/// [`JoinProofPending::verify_peer`].
///
/// `sid` is the fresh per-run CPace session id agreed in the open (both ends use
/// the same bytes). `challenge` is the responder's signed nonce; this function
/// verifies `challenge_sig` against `responder_pub` and that the challenge is for
/// **this** channel/epoch *before* doing any PoW work — so a prover cannot be made
/// to grind against an unsigned or cross-channel challenge (its difficulty is only
/// trustworthy because it is inside the responder's signature).
#[allow(clippy::too_many_arguments)] // each argument is a distinct, required binding input
pub fn join_initiate<'a>(
    ctx: JoinContext,
    passphrase: &[u8],
    sid: &[u8],
    challenge: &ResponderNonce,
    responder_pub: &CompositePublicKey,
    challenge_sig: &CompositeSignature,
    root: &'a (dyn RootSigner + Send + Sync),
    ik: &'a X25519IdentityKey,
) -> Result<(JoinInitiator<'a>, PowToken, [u8; CPACE_SHARE_LEN])> {
    // 0. The suite this join binds must sit at/above the channel floor
    //    (ADR-003) — a context built by hand cannot bypass the constructor check.
    ctx.floor.check(ctx.suite_id)?;
    //    Verify the responder's signature over the challenge, and that the
    //    challenge is bound to THIS channel/epoch, before grinding any PoW.
    challenge.verify(responder_pub, challenge_sig)?;
    if challenge.channel_id != ctx.channel_id || challenge.epoch != ctx.epoch {
        return Err(Error::JoinPowInvalid);
    }
    //    Accessibility cap (ADR-005): a challenge above `Difficulty::MAX` is
    //    refused outright — an honest responder never mints one, and it bounds the
    //    grind any attacker-signed challenge can extract from a joiner.
    if challenge.difficulty.exceeds_cap() {
        return Err(Error::JoinPowInvalid);
    }
    // 1. PoW — memory-hard work bound to (channelID, epoch, responder_nonce).
    let token = pow::solve_token(ctx.pow_params, challenge)?;
    // 2. CPace — keyed by the passphrase.
    let (cpace, own_share) =
        CpaceState::start(passphrase, &ctx.channel_id, ctx.epoch, ctx.suite_id, sid)?;
    Ok((
        JoinInitiator {
            ctx,
            sid: sid.to_vec(),
            cpace,
            own_share,
            root,
            ik,
        },
        token,
        own_share,
    ))
}

/// Begin the responder side: ENFORCE the joiner's PoW, then start CPace and produce
/// the CPace share to send. `challenge` is the responder's own signed nonce (issued
/// in the open) and `token` is the joiner's claimed solution; this function calls
/// [`pow::verify_token`] and aborts before any CPace work if it fails, so an
/// unauthenticated peer can never force PAKE computation (PoW-before-CPace is
/// structurally enforced, not left to the caller).
pub fn join_accept<'a>(
    ctx: JoinContext,
    passphrase: &[u8],
    sid: &[u8],
    challenge: &ResponderNonce,
    token: &PowToken,
    root: &'a (dyn RootSigner + Send + Sync),
) -> Result<(JoinResponder<'a>, [u8; CPACE_SHARE_LEN])> {
    // Gate: the suite this join binds must sit at/above the channel floor
    // (ADR-003), and the joiner's PoW must verify against our signed challenge —
    // both BEFORE any CPace work.
    ctx.floor.check(ctx.suite_id)?;
    pow::verify_token(ctx.pow_params, challenge, token)?;
    let (cpace, own_share) =
        CpaceState::start(passphrase, &ctx.channel_id, ctx.epoch, ctx.suite_id, sid)?;
    Ok((
        JoinResponder {
            ctx,
            sid: sid.to_vec(),
            cpace,
            own_share,
            root,
        },
        own_share,
    ))
}

/// Derive the CPace transcript hash and this side's identity proof for a completed
/// CPace run. Shared by both ends.
fn build_proof(
    root: &dyn RootSigner,
    sid: &[u8],
    isk: &[u8],
    own_share: &[u8; CPACE_SHARE_LEN],
    peer_share: &[u8; CPACE_SHARE_LEN],
) -> Result<(Digest32, IdentityProof)> {
    let th = pop::transcript_hash(sid, isk, own_share, peer_share);
    let proof = IdentityProof::create(root, sid, &th)?;
    Ok((th, proof))
}

/// A side that has completed CPace and produced its identity proof, awaiting the
/// peer's proof (and, for the joiner, the responder bundle).
///
/// Holding this between the two protocol phases is exactly the real exchange:
/// **both** parties finish CPace and emit their proof *before* either verifies the
/// other's — the proof is bound to the (now-known) shared ISK, so neither can be
/// produced earlier. The CPace secret scalar was consumed and wiped when this was
/// built ([`CpaceState::finish`] takes `self`).
pub struct JoinProofPending {
    sid: Vec<u8>,
    /// The run-bound transcript hash (same on both ends).
    transcript_hash: Digest32,
    /// This side's identity proof, to send to the peer.
    own_proof: IdentityProof,
    /// The PoP-sealing AEAD key, `K_pop = HKDF-SHA-256(ISK, "vox/cpace-pop/v1")`
    /// (ADR-005). Retained (instead of the whole ISK) so the PoP can be sealed/opened
    /// inside the CPace-derived channel; zeroized on drop.
    pop_key: Zeroizing<[u8; 32]>,
}

impl JoinProofPending {
    /// This side's identity proof to transmit to the peer.
    ///
    /// This is the **raw** proof; for confidentiality on the wire prefer
    /// [`own_proof_sealed`](Self::own_proof_sealed), which encrypts it under the
    /// CPace-derived `K_pop` so a passive observer never sees the identity public
    /// keys (ADR-005). `own_proof` remains available for callers that seal at a
    /// different layer.
    #[must_use]
    pub fn own_proof(&self) -> &IdentityProof {
        &self.own_proof
    }

    /// This side's identity proof, **sealed** for transmission inside the CPace
    /// channel: `nonce ‖ AES-256-GCM(K_pop, proof_bytes)` (ADR-005). The peer opens
    /// it with [`verify_peer_sealed`](Self::verify_peer_sealed).
    pub fn own_proof_sealed(&self) -> Result<Vec<u8>> {
        pop::seal_pop_with_key(&self.pop_key, &self.own_proof)
    }

    /// The run-bound transcript hash (for callers that key their own PoP-channel
    /// AEAD instead of using [`own_proof_sealed`](Self::own_proof_sealed)).
    #[must_use]
    pub fn transcript_hash(&self) -> &Digest32 {
        &self.transcript_hash
    }

    /// Verify the peer's **raw** proof against `expected_peer_fp`, returning the
    /// verified peer identity. A failed PoP yields
    /// [`crate::error::Error::JoinProofFailed`] and (because the caller has not yet
    /// bootstrapped PQXDH) leaves no session established.
    pub fn verify_peer(
        &self,
        peer_proof: &IdentityProof,
        expected_peer_fp: &Digest32,
    ) -> Result<JoinPeerIdentity> {
        pop::verify(
            peer_proof,
            &self.sid,
            &self.transcript_hash,
            expected_peer_fp,
        )
    }

    /// Open the peer's **sealed** proof (from
    /// [`own_proof_sealed`](Self::own_proof_sealed)) under the shared `K_pop`, then
    /// verify it against `expected_peer_fp`. A decryption failure (wrong key or
    /// tamper) and a verification failure both collapse to
    /// [`crate::error::Error::JoinProofFailed`], so a probe cannot distinguish them.
    pub fn verify_peer_sealed(
        &self,
        sealed_peer_proof: &[u8],
        expected_peer_fp: &Digest32,
    ) -> Result<JoinPeerIdentity> {
        let peer_proof = pop::open_pop_with_key(&self.pop_key, sealed_peer_proof)?;
        pop::verify(
            &peer_proof,
            &self.sid,
            &self.transcript_hash,
            expected_peer_fp,
        )
    }
}

impl<'a> JoinInitiator<'a> {
    /// This party's CPace public share.
    #[must_use]
    pub fn own_share(&self) -> &[u8; CPACE_SHARE_LEN] {
        &self.own_share
    }

    /// Phase 1 (joiner): finish CPace against the responder's share and produce
    /// this side's identity proof. Returns the pending state (carrying the proof to
    /// send) plus the joiner's X25519 key reference retained for phase 2.
    ///
    /// Returns [`crate::error::Error::CpaceInvalidShare`] on a degenerate CPace share.
    pub fn complete_cpace(
        self,
        peer_share: &[u8; CPACE_SHARE_LEN],
    ) -> Result<(JoinProofPending, JoinInitiatorBootstrap<'a>)> {
        let isk = self.cpace.finish(peer_share)?;
        let (transcript_hash, own_proof) =
            build_proof(self.root, &self.sid, &isk[..], &self.own_share, peer_share)?;
        let pop_key = pop::derive_pop_key(&isk[..])?;
        let pending = JoinProofPending {
            sid: self.sid,
            transcript_hash,
            own_proof,
            pop_key,
        };
        let bootstrap = JoinInitiatorBootstrap {
            ctx: self.ctx,
            ik: self.ik,
        };
        Ok((pending, bootstrap))
    }
}

/// The joiner's retained material for the PQXDH bootstrap (phase 2).
pub struct JoinInitiatorBootstrap<'a> {
    ctx: JoinContext,
    ik: &'a X25519IdentityKey,
}

impl JoinInitiatorBootstrap<'_> {
    /// Phase 2 (joiner): after the peer's proof has been verified
    /// ([`JoinProofPending::verify_peer`]), bootstrap the M2 PQXDH session against
    /// the responder's verified `bundle`. Returns the established [`Session`] and
    /// the [`InitialMessage`] to deliver. The bundle is verified inside
    /// [`Session::initiate`] (the M2 HIGH fix).
    pub fn bootstrap(&self, bundle: &PrekeyBundlePublic) -> Result<(Session, InitialMessage)> {
        let (init_msg, session) = Session::initiate(
            self.ik,
            bundle,
            &self.ctx.channel_id,
            self.ctx.epoch,
            self.ctx.suite_id,
            self.ctx.floor,
        )?;
        Ok((session, init_msg))
    }
}

impl JoinResponder<'_> {
    /// This party's CPace public share.
    #[must_use]
    pub fn own_share(&self) -> &[u8; CPACE_SHARE_LEN] {
        &self.own_share
    }

    /// Phase 1 (responder): finish CPace against the joiner's share and produce this
    /// side's identity proof. Returns the pending state plus the bootstrap handle.
    pub fn complete_cpace(
        self,
        peer_share: &[u8; CPACE_SHARE_LEN],
    ) -> Result<(JoinProofPending, JoinResponderBootstrap)> {
        let isk = self.cpace.finish(peer_share)?;
        let (transcript_hash, own_proof) =
            build_proof(self.root, &self.sid, &isk[..], &self.own_share, peer_share)?;
        let pop_key = pop::derive_pop_key(&isk[..])?;
        let pending = JoinProofPending {
            sid: self.sid,
            transcript_hash,
            own_proof,
            pop_key,
        };
        let bootstrap = JoinResponderBootstrap { ctx: self.ctx };
        Ok((pending, bootstrap))
    }
}

/// The responder's retained material for the PQXDH bootstrap (phase 2).
pub struct JoinResponderBootstrap {
    ctx: JoinContext,
}

impl JoinResponderBootstrap {
    /// Phase 2 (responder): after the peer's proof has been verified, accept the
    /// joiner's [`InitialMessage`] into an M2 [`Session`].
    ///
    /// `prekeys` are the responder's own private prekeys (the secrets matching the
    /// bundle the joiner consumed). `reuse` is the recipient-side one-time-prekey
    /// reuse tracker (ADR-004).
    pub fn bootstrap(
        &self,
        init_msg: &InitialMessage,
        prekeys: &ResponderPrekeys<'_>,
        reuse: &mut OtpReuseTracker,
    ) -> Result<Session> {
        Session::accept(
            init_msg,
            prekeys,
            &self.ctx.channel_id,
            self.ctx.epoch,
            reuse,
            self.ctx.floor,
        )
    }
}
