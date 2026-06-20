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

/// The parameters that bind a join to a specific channel and suite. Both ends MUST
/// use identical values; a mismatch makes CPace fail to agree (the binding is into
/// `CI`/`AD`) and is the type-level guard against cross-channel confusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JoinContext {
    /// The channelID (ADR-005): `SHA-256(genesis)`.
    pub channel_id: [u8; 32],
    /// The channel epoch (ADR-007 rotation).
    pub epoch: u64,
    /// The negotiated ciphersuite id (ADR-003), bound as CPace `AD`.
    pub suite_id: u16,
    /// The Equihash PoW parameters in force for this channel.
    pub pow_params: PowParams,
}

impl JoinContext {
    /// Build a context with the production-default `(200,9)` PoW parameters.
    #[must_use]
    pub fn new(channel_id: [u8; 32], epoch: u64, suite_id: u16) -> Self {
        Self {
            channel_id,
            epoch,
            suite_id,
            pow_params: PowParams::DEFAULT,
        }
    }
}

/// The joiner (PQXDH initiator) side of a join, after CPace start.
///
/// Holds the in-progress CPace state and the joiner's X25519 identity key for the
/// subsequent PQXDH bootstrap. Produced by [`join_initiate`]; advanced by
/// [`JoinInitiator::complete_cpace`].
pub struct JoinInitiator<'a> {
    ctx: JoinContext,
    sid: Vec<u8>,
    cpace: CpaceState,
    own_share: [u8; CPACE_SHARE_LEN],
    root: &'a dyn RootSigner,
    ik: &'a X25519IdentityKey,
}

/// The responder (PQXDH responder) side of a join, after CPace start.
pub struct JoinResponder<'a> {
    ctx: JoinContext,
    sid: Vec<u8>,
    cpace: CpaceState,
    own_share: [u8; CPACE_SHARE_LEN],
    root: &'a dyn RootSigner,
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
    root: &'a dyn RootSigner,
    ik: &'a X25519IdentityKey,
) -> Result<(JoinInitiator<'a>, PowToken, [u8; CPACE_SHARE_LEN])> {
    // 0. Verify the responder's signature over the challenge, and that the
    //    challenge is bound to THIS channel/epoch, before grinding any PoW.
    challenge.verify(responder_pub, challenge_sig)?;
    if challenge.channel_id != ctx.channel_id || challenge.epoch != ctx.epoch {
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
    root: &'a dyn RootSigner,
) -> Result<(JoinResponder<'a>, [u8; CPACE_SHARE_LEN])> {
    // Gate: the joiner's PoW must verify against our signed challenge BEFORE CPace.
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
        let pop_key = Zeroizing::new(pop::derive_pop_key(&isk[..]));
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
        let pop_key = Zeroizing::new(pop::derive_pop_key(&isk[..]));
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
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::identity::composite::SoftwareRootSigner;
    use crate::identity::keyagreement::{
        OneTimePrekey, OneTimePrekeyPool, SignedIdentityDhKey, SignedPrekey,
    };
    use crate::join::cpace::fresh_sid;
    use crate::join::pow::Difficulty;

    /// A member identity with the M1 prekey material needed to be a PQXDH responder.
    struct Member {
        root: SoftwareRootSigner,
        idk: SignedIdentityDhKey,
        spk: SignedPrekey,
        pool: OneTimePrekeyPool,
    }

    fn member(a: u8, b: u8) -> Member {
        let root = SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap();
        let idk = SignedIdentityDhKey::generate(&root, 1_700_000_000).unwrap();
        let spk = SignedPrekey::generate(&root, 1, 1_700_000_000).unwrap();
        let pool = OneTimePrekeyPool::generate(&root, 4, 1, 1_700_000_000).unwrap();
        Member {
            root,
            idk,
            spk,
            pool,
        }
    }

    fn bundle(m: &Member, otp: &OneTimePrekey) -> PrekeyBundlePublic {
        PrekeyBundlePublic {
            root_pub: m.root.public_key().to_bytes(),
            identity_dh_key: m.idk.public().clone(),
            identity_dh_key_sig: m.idk.signature().to_bytes(),
            signed_prekey: m.spk.public().clone(),
            signed_prekey_sig: m.spk.signature().to_bytes(),
            one_time_prekey: Some(otp.public().clone()),
            one_time_prekey_sig: Some(otp.signature().to_bytes()),
        }
    }

    fn responder_prekeys<'a>(
        m: &'a Member,
        idk: &'a X25519IdentityKey,
        otp: &'a OneTimePrekey,
    ) -> ResponderPrekeys<'a> {
        ResponderPrekeys {
            identity_dh_key: idk,
            signed_prekey: &m.spk,
            one_time_prekey: Some(otp),
        }
    }

    /// Reduced PoW params so the test's PoW solve is fast (512-row initial list).
    fn ctx(channel_id: [u8; 32], epoch: u64) -> JoinContext {
        JoinContext {
            channel_id,
            epoch,
            suite_id: 0x0001,
            pow_params: PowParams::new(48, 5).unwrap(),
        }
    }

    /// Drive a full, faithful two-phase join. Returns the two sessions plus the
    /// verified identities. This mirrors the real protocol: PoW → CPace → both
    /// emit proofs → exchange → verify → PQXDH bootstrap.
    #[allow(clippy::type_complexity)]
    fn run_join(
        pass_joiner: &[u8],
        pass_resp: &[u8],
        channel_id: [u8; 32],
        epoch: u64,
    ) -> Result<(Session, Session, JoinPeerIdentity, JoinPeerIdentity)> {
        let joiner = member(1, 2);
        let joiner_ik = X25519IdentityKey::generate().unwrap();
        let mut responder = member(3, 4);
        let otp = responder.pool.take().unwrap();
        let b = bundle(&responder, &otp);
        let resp_idk = X25519IdentityKey::from_secret_bytes(responder.idk.x25519_secret_bytes());
        let joiner_fp = joiner.root.public_key().fingerprint();
        let resp_fp = responder.root.public_key().fingerprint();

        let c = ctx(channel_id, epoch);
        let sid = fresh_sid().unwrap();

        // Responder issues + signs a challenge; joiner solves PoW + starts CPace.
        let challenge = ResponderNonce::generate(&channel_id, epoch, Difficulty::ZERO).unwrap();
        let challenge_sig = challenge.sign(&responder.root).unwrap();

        // join_initiate verifies the challenge signature + channel/epoch internally.
        let (ji, token, joiner_share) = join_initiate(
            c,
            pass_joiner,
            &sid,
            &challenge,
            &responder.root.public_key(),
            &challenge_sig,
            &joiner.root,
            &joiner_ik,
        )?;
        // join_accept enforces the PoW token before any CPace work.
        let (jr, resp_share) =
            join_accept(c, pass_resp, &sid, &challenge, &token, &responder.root)?;

        // Phase 1: BOTH complete CPace and emit their identity proof.
        let (ji_pending, ji_boot) = ji.complete_cpace(&resp_share)?;
        let (jr_pending, jr_boot) = jr.complete_cpace(&joiner_share)?;

        // Exchange proofs and verify peer identity against the out-of-band fingerprint.
        let verified_resp = ji_pending.verify_peer(jr_pending.own_proof(), &resp_fp)?;
        let verified_joiner = jr_pending.verify_peer(ji_pending.own_proof(), &joiner_fp)?;

        // Phase 2: bootstrap the M2 PQXDH session.
        let (joiner_session, init_msg) = ji_boot.bootstrap(&b)?;
        let responder_session = jr_boot.bootstrap(
            &init_msg,
            &responder_prekeys(&responder, &resp_idk, &otp),
            &mut OtpReuseTracker::new(),
        )?;

        Ok((
            joiner_session,
            responder_session,
            verified_resp,
            verified_joiner,
        ))
    }

    #[test]
    fn full_join_establishes_working_session_both_directions() {
        let (mut a, mut b, vr, vj) = run_join(b"team-pass", b"team-pass", [0x7a; 32], 5).unwrap();
        // The verified identities are the real peers.
        assert_eq!(vr.fingerprint.len(), 32);
        assert_eq!(vj.fingerprint.len(), 32);
        // Joiner (initiator) → responder.
        let m = a.encrypt(b"hello from joiner").unwrap();
        assert_eq!(b.decrypt(&m, 1_700_000_001).unwrap(), b"hello from joiner");
        // Responder → joiner.
        let r = b.encrypt(b"welcome").unwrap();
        assert_eq!(a.decrypt(&r, 1_700_000_002).unwrap(), b"welcome");
    }

    #[test]
    fn wrong_passphrase_fails_pop_no_session() {
        // Different passphrases ⇒ different ISK ⇒ different transcript hash ⇒ the
        // identity proofs do not verify ⇒ join fails, no session. Match rather than
        // `unwrap_err` (the Ok variant carries `Session`, which is not `Debug`).
        match run_join(b"right", b"wrong", [0x01; 32], 1) {
            Err(Error::JoinProofFailed) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("join must not establish a session on wrong passphrase"),
        }
    }

    #[test]
    fn wrong_expected_fingerprint_fails_no_session() {
        // The joiner expects an imposter's fingerprint, not the responder's: PoP
        // verification fails and no session is bootstrapped (the bootstrap step is
        // never reached).
        let joiner = member(1, 2);
        let mut responder = member(3, 4);
        let imposter = member(8, 8);
        let _otp = responder.pool.take().unwrap();
        let c = ctx([0x55; 32], 2);
        let sid = fresh_sid().unwrap();
        let challenge = ResponderNonce::generate(&c.channel_id, c.epoch, Difficulty::ZERO).unwrap();
        let challenge_sig = challenge.sign(&responder.root).unwrap();
        let joiner_ik = X25519IdentityKey::generate().unwrap();

        let (ji, token, joiner_share) = join_initiate(
            c,
            b"pw",
            &sid,
            &challenge,
            &responder.root.public_key(),
            &challenge_sig,
            &joiner.root,
            &joiner_ik,
        )
        .unwrap();
        let (jr, resp_share) =
            join_accept(c, b"pw", &sid, &challenge, &token, &responder.root).unwrap();

        let (ji_pending, _ji_boot) = ji.complete_cpace(&resp_share).unwrap();
        let (jr_pending, _jr_boot) = jr.complete_cpace(&joiner_share).unwrap();

        // The joiner verifies the responder's (genuine) proof but against the
        // IMPOSTER's expected fingerprint ⇒ rejected.
        assert!(matches!(
            ji_pending.verify_peer(
                jr_pending.own_proof(),
                &imposter.root.public_key().fingerprint()
            ),
            Err(Error::JoinProofFailed)
        ));
    }

    #[test]
    fn pow_token_required_and_bound() {
        // A token solved for one channel does not verify for another (the join
        // would reject before CPace). Exercised through the join context.
        let c1 = ctx([0xaa; 32], 1);
        let c2 = ctx([0xbb; 32], 1);
        let ch1 = ResponderNonce::generate(&c1.channel_id, c1.epoch, Difficulty::ZERO).unwrap();
        let token = pow::solve_token(c1.pow_params, &ch1).unwrap();
        assert!(pow::verify_token(c1.pow_params, &ch1, &token).is_ok());
        let ch2 = ResponderNonce::generate(&c2.channel_id, c2.epoch, Difficulty::ZERO).unwrap();
        assert!(pow::verify_token(c2.pow_params, &ch2, &token).is_err());
    }

    #[test]
    fn join_initiate_rejects_forged_challenge_signature() {
        // The challenge is signed by an imposter but presented with the responder's
        // public key ⇒ join_initiate must reject before any PoW work.
        let joiner = member(1, 2);
        let responder = member(3, 4);
        let imposter = member(9, 9);
        let c = ctx([0x33; 32], 1);
        let sid = fresh_sid().unwrap();
        let challenge = ResponderNonce::generate(&c.channel_id, c.epoch, Difficulty::ZERO).unwrap();
        let forged = challenge.sign(&imposter.root).unwrap();
        let ik = X25519IdentityKey::generate().unwrap();
        assert!(join_initiate(
            c,
            b"pw",
            &sid,
            &challenge,
            &responder.root.public_key(),
            &forged,
            &joiner.root,
            &ik,
        )
        .is_err());
    }

    #[test]
    fn join_initiate_rejects_channel_mismatch() {
        // A correctly-signed challenge but for a DIFFERENT channel than the context.
        let joiner = member(1, 2);
        let responder = member(3, 4);
        let c = ctx([0x33; 32], 1);
        let sid = fresh_sid().unwrap();
        let challenge = ResponderNonce::generate(&[0x99; 32], 1, Difficulty::ZERO).unwrap();
        let sig = challenge.sign(&responder.root).unwrap();
        let ik = X25519IdentityKey::generate().unwrap();
        assert!(matches!(
            join_initiate(
                c,
                b"pw",
                &sid,
                &challenge,
                &responder.root.public_key(),
                &sig,
                &joiner.root,
                &ik,
            ),
            Err(Error::JoinPowInvalid)
        ));
    }

    #[test]
    fn join_accept_rejects_bad_pow_token_before_cpace() {
        // join_accept must verify the PoW token and abort before any CPace work.
        let responder = member(3, 4);
        let c = ctx([0x44; 32], 1);
        let sid = fresh_sid().unwrap();
        let challenge = ResponderNonce::generate(&c.channel_id, c.epoch, Difficulty::ZERO).unwrap();
        // A token whose solution length cannot match (n,k) can never verify.
        let bad = PowToken {
            equihash_nonce: vec![0u8; 32],
            solution: vec![0u8; 3],
        };
        assert!(matches!(
            join_accept(c, b"pw", &sid, &challenge, &bad, &responder.root),
            Err(Error::JoinPowInvalid)
        ));
    }
}
