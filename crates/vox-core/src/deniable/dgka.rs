//! The 4-round Deniable Group Key Agreement + DSKE (ADR-009 §"Concrete protocol",
//! steps 1–4).
//!
//! Each member runs a [`DgkaMember`] state machine across four broadcast rounds.
//! Every round's broadcast rides the log as a `dgka-setup` **governance** entry
//! (tag `0x000B`, root-composite-signed *envelope* — participation attributable =
//! weak deniability; the key material *inside* carries no static signature). This
//! module produces and consumes the **bodies** of those broadcasts; framing them
//! into log entries is the caller's job (M5 [`crate::log::entry`]).
//!
//! ```text
//! 1. Commit   commit_i = SHA-256("vox/dgka-commit/v1" ‖ epk_i ‖ z_i ‖ n_i),  n_i 128-bit
//! 2. Reveal   (epk_i, z_i, n_i); verify each commit; everyone now knows all z_*
//! 3. DSKE     X_i = x_i·(z_{i+1} − z_{i-1})  (BD round 2, broadcast);
//!             sign T with esk_i  (T = SHA-256 transcript, ascending member order)
//! 4. Confirm  derive K = HKDF(BD-combine(z_*, X_*), info);  MAC_K(T)  (HMAC-SHA-256);
//!             session opens when all binds + confirmations verify
//! ```
//!
//! The Burmester–Desmedt round-2 value `X_i` rides the round-3 broadcast: it is a
//! *deterministic* function of the member's already-committed secret `x_i` and the
//! revealed neighbor shares, so it needs no separate commitment (it cannot be
//! chosen adaptively to control the key — `x_i` was fixed at round 1).
//!
//! `K` (the [`EpochKey`]) is used **only** for the step-4 key confirmation/binding
//! — never as a content key (content confidentiality is the PQ Sender Keys, M4),
//! so its classical Burmester–Desmedt origin is harmless (ADR-009).
//!
//! ## Commit binding
//! A member that has committed cannot change `epk_i`/`z_i` at reveal: the reveal is
//! checked against the stored commit ([`DgkaMember::recv_reveal`]). A mismatching
//! reveal is rejected — the standard commit-then-reveal defense against adaptive
//! key-choice (Ateniese–Steiner–Tsudik; Katz–Yung).

use std::collections::BTreeMap;

use subtle::ConstantTimeEq;

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::identity::rng::random_array;

use crate::deniable::epoch::{EphemeralSigningKey, EpochContext, MemberDescriptor};
use crate::deniable::key::EpochKey;
use crate::deniable::rounds::{commitment, Confirm, Reveal, NONCE_LEN};
use crate::deniable::share::{EphemeralShare, SHARE_LEN};

/// One member's run of the 4-round DGKA. Created at round 1, driven by feeding in
/// peers' broadcasts, and finalized into a [`DgkaSession`] once all four rounds
/// complete and every peer's bind + confirm verifies.
pub struct DgkaMember {
    channel_id: Digest32,
    epoch: u64,
    author_id: Digest32,
    /// This member's static identity composite public key (the ordering key and
    /// the key that signs this member's reveal envelope).
    author_pubkey: CompositePublicKey,
    /// This member's static identity signature over its own reveal body — the
    /// root-signed `dgka-setup` envelope that makes *participation* attributable
    /// (weak deniability) and binds `epk_i`/`z_i` to this static identity.
    reveal_sig: CompositeSignature,
    /// Ephemeral signing key `(esk_i, epk_i)` — content + DSKE bind key.
    esk: EphemeralSigningKey,
    /// Ephemeral DH key `(x_i, z_i)` — BD input.
    dh: EphemeralShare,
    /// This member's commitment nonce.
    nonce: [u8; NONCE_LEN],
    /// Recorded round-1 commits, by author.
    commits: BTreeMap<Digest32, Digest32>,
    /// Recorded round-2 reveals, by author.
    reveals: BTreeMap<Digest32, Reveal>,
}

impl core::fmt::Debug for DgkaMember {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DgkaMember")
            .field("author_id", &crate::hash::Hex(&self.author_id))
            .field("epoch", &self.epoch)
            .field("commits", &self.commits.len())
            .field("reveals", &self.reveals.len())
            .finish()
    }
}

impl DgkaMember {
    /// Start a member's DGKA run for `(channel_id, epoch)`, generating its
    /// ephemeral signing + DH keys and its commitment nonce. `static_signer` is the
    /// member's static identity (ADR-002); the member signs its own `dgka-setup`
    /// reveal body with it, so peers can bind `epk_i`/`z_i` to this identity.
    pub fn start(channel_id: Digest32, epoch: u64, static_signer: &dyn RootSigner) -> Result<Self> {
        let esk = EphemeralSigningKey::generate()?;
        let dh = EphemeralShare::generate()?;
        Self::from_parts(
            channel_id,
            epoch,
            static_signer,
            esk,
            dh,
            random_array::<NONCE_LEN>()?,
        )
    }

    /// Construct a member with explicit ephemeral material (deterministic tests and
    /// the re-key path, which supply fresh `(esk', x')`). Computes the static reveal
    /// signature over the canonical `dgka-setup` body.
    pub(crate) fn from_parts(
        channel_id: Digest32,
        epoch: u64,
        static_signer: &dyn RootSigner,
        esk: EphemeralSigningKey,
        dh: EphemeralShare,
        nonce: [u8; NONCE_LEN],
    ) -> Result<Self> {
        let author_pubkey = static_signer.public_key();
        let author_id = author_pubkey.fingerprint();
        // Sign the canonical dgka-setup reveal body with the STATIC identity.
        let body = MemberDescriptor {
            author_pubkey: author_pubkey.clone(),
            author_id,
            epk: esk.epk(),
            share: dh.public_bytes(),
        }
        .reveal_signing_input(channel_id, epoch);
        let reveal_sig = static_signer.sign(&body)?;
        Ok(Self {
            channel_id,
            epoch,
            author_id,
            author_pubkey,
            reveal_sig,
            esk,
            dh,
            nonce,
            commits: BTreeMap::new(),
            reveals: BTreeMap::new(),
        })
    }

    /// This member's static identity fingerprint.
    #[must_use]
    pub fn author_id(&self) -> Digest32 {
        self.author_id
    }

    /// This member's static identity composite public key (the ordering key).
    #[must_use]
    pub fn author_pubkey(&self) -> CompositePublicKey {
        self.author_pubkey.clone()
    }

    /// This member's public ephemeral verification key `epk_i`.
    #[must_use]
    pub fn epk(&self) -> CompositePublicKey {
        self.esk.epk()
    }

    /// This member's ephemeral DH share `z_i`.
    #[must_use]
    pub fn share(&self) -> [u8; SHARE_LEN] {
        self.dh.public_bytes()
    }

    /// Borrow this member's ephemeral signing key (to hand to content signing /
    /// epoch-end publication after the DGKA completes).
    #[must_use]
    pub fn signing_key(&self) -> &EphemeralSigningKey {
        &self.esk
    }

    // ---- Round 1: commit ----

    /// This member's round-1 commitment broadcast body.
    #[must_use]
    pub fn commit(&self) -> Digest32 {
        commitment(
            &self.author_pubkey,
            &self.esk.epk(),
            &self.dh.public_bytes(),
            &self.nonce,
        )
    }

    /// Record a peer's (or our own) round-1 commit. Idempotent for an identical
    /// re-broadcast; a *different* commit for an already-seen author is an
    /// equivocation and is rejected.
    pub fn recv_commit(&mut self, author_id: Digest32, commit: Digest32) -> Result<()> {
        match self.commits.get(&author_id) {
            Some(c) if *c == commit => Ok(()),
            Some(_) => Err(Error::MalformedBundle("dgka commit equivocation")),
            None => {
                self.commits.insert(author_id, commit);
                Ok(())
            }
        }
    }

    // ---- Round 2: reveal ----

    /// This member's round-2 reveal broadcast body.
    #[must_use]
    pub fn reveal(&self) -> Reveal {
        Reveal {
            author_id: self.author_id,
            author_pubkey: self.author_pubkey.clone(),
            epk: self.esk.epk(),
            share: self.dh.public_bytes(),
            nonce: self.nonce,
            reveal_sig: self.reveal_sig.clone(),
        }
    }

    /// Record a peer's (or our own) reveal. Checks, in order: (a) `author_id`
    /// equals `author_pubkey.fingerprint()` (the reveal cannot claim an identity it
    /// does not hold the key for); (b) the **static** reveal signature verifies over
    /// the canonical `dgka-setup` body (binds `epk`/`z` to the static identity —
    /// defeats `(victim_author_id, attacker_epk)` impersonation); (c) the reveal
    /// opens that author's stored round-1 commit (commit-binding); (d) it is not a
    /// conflicting second reveal.
    pub fn recv_reveal(&mut self, reveal: Reveal) -> Result<()> {
        // (a) identity binding: author_id is the fingerprint of author_pubkey.
        if reveal.author_pubkey.fingerprint() != reveal.author_id {
            return Err(Error::MalformedBundle("dgka reveal author_id != pubkey"));
        }
        // (b) static envelope signature binds epk/share to the static identity.
        let descriptor = MemberDescriptor {
            author_pubkey: reveal.author_pubkey.clone(),
            author_id: reveal.author_id,
            epk: reveal.epk.clone(),
            share: reveal.share,
        };
        let body = descriptor.reveal_signing_input(self.channel_id, self.epoch);
        reveal
            .author_pubkey
            .verify(&body, &reveal.reveal_sig)
            .map_err(|_| Error::SignatureInvalid)?;
        // (c) commit-binding.
        let stored_commit = self
            .commits
            .get(&reveal.author_id)
            .ok_or(Error::MalformedBundle("dgka reveal before commit"))?;
        let expect = commitment(
            &reveal.author_pubkey,
            &reveal.epk,
            &reveal.share,
            &reveal.nonce,
        );
        if &expect != stored_commit {
            return Err(Error::MalformedBundle("dgka reveal does not open commit"));
        }
        // (d) no conflicting second reveal.
        match self.reveals.get(&reveal.author_id) {
            Some(r) if r.share == reveal.share && r.epk == reveal.epk => Ok(()),
            Some(_) => Err(Error::MalformedBundle("dgka reveal equivocation")),
            None => {
                self.reveals.insert(reveal.author_id, reveal);
                Ok(())
            }
        }
    }

    /// Build the canonical [`EpochContext`] from all recorded reveals. Requires
    /// that every committed member has revealed.
    pub fn epoch_context(&self) -> Result<EpochContext> {
        if self.reveals.is_empty() || self.reveals.len() != self.commits.len() {
            return Err(Error::MalformedBundle("dgka not all members revealed"));
        }
        let members: Vec<MemberDescriptor> = self
            .reveals
            .values()
            .map(|r| MemberDescriptor {
                author_pubkey: r.author_pubkey.clone(),
                author_id: r.author_id,
                epk: r.epk.clone(),
                share: r.share,
            })
            .collect();
        EpochContext::new(self.channel_id, self.epoch, members)
    }

    // ---- Round 3: BD round-2 value + DSKE bind ----

    /// This member's Burmester–Desmedt round-2 value `X_i = x_i·(z_{i+1} − z_{i-1})`
    /// against its cyclic neighbors in the canonical ring. For `m == 2` BD
    /// degenerates and `X_i` is unused; this returns the (ignored) own share.
    ///
    /// Public so the driver can gather every member's `X_*` (round 3) before any
    /// member derives `K` (round 4) — the BD key needs the full `X` vector.
    pub fn own_round2(&self, ctx: &EpochContext) -> Result<[u8; SHARE_LEN]> {
        let n = ctx.member_count();
        let i = ctx
            .position_of(&self.author_id)
            .ok_or(Error::MalformedBundle("dgka self not in epoch"))?;
        if n == 2 {
            return Ok(self.dh.public_bytes());
        }
        let shares = ctx.shares();
        let left = shares[(i + n - 1) % n];
        let right = shares[(i + 1) % n];
        self.dh.round2_value(&left, &right)
    }

    /// Build this member's round-3+4 confirmation body once it holds every peer's
    /// `X_*`: derives `K`, signs the **bind transcript** `T_bind` (DSKE bind), and
    /// MACs `T_bind` (confirm). `round2` maps each member's `author_id` to its
    /// broadcast `X_j` (this member's own included). `T_bind = SHA-256(T ‖ X_1 ‖ …
    /// ‖ X_m)` in canonical member order, so the exact `X_*` used to derive `K` are
    /// bound by both the bind signature and the confirmation MAC — a substituted
    /// BD round-2 value (split view) is detected, not just silently divergent
    /// (ADR-009 step 3: the agreement material is bound to the transcript).
    /// Returns `(Confirm, EpochKey)`; the key is retained by the caller to verify
    /// peers' confirmations.
    pub fn finalize(
        &self,
        ctx: &EpochContext,
        round2: &BTreeMap<Digest32, [u8; SHARE_LEN]>,
    ) -> Result<(Confirm, EpochKey)> {
        let key = self.derive_key(ctx, round2)?;
        let t_bind = bind_transcript(ctx, round2)?;
        let bind_sig = self.esk.sign(&t_bind)?;
        let confirm_mac = key.confirm_mac_over(ctx, &t_bind)?;
        Ok((
            Confirm {
                author_id: self.author_id,
                round2: self.own_round2(ctx)?,
                bind_sig,
                confirm_mac,
            },
            key,
        ))
    }

    /// Derive this member's epoch key `K` (Burmester–Desmedt over all revealed
    /// shares + the broadcast `X_*`, in canonical order; ADR-009 step 2).
    fn derive_key(
        &self,
        ctx: &EpochContext,
        round2: &BTreeMap<Digest32, [u8; SHARE_LEN]>,
    ) -> Result<EpochKey> {
        let i = ctx
            .position_of(&self.author_id)
            .ok_or(Error::MalformedBundle("dgka self not in epoch"))?;
        let shares = ctx.shares();
        // Assemble the X_* vector in canonical (member) order from the broadcasts.
        let mut x_vec: Vec<[u8; SHARE_LEN]> = Vec::with_capacity(ctx.member_count());
        for m in ctx.members() {
            let x = round2
                .get(&m.author_id)
                .ok_or(Error::MalformedBundle("dgka missing round-2 value"))?;
            x_vec.push(*x);
        }
        let k_point = self.dh.group_key(i, &shares, &x_vec)?;
        EpochKey::derive(&k_point, ctx)
    }

    /// Verify a peer's round-3+4 confirmation against the **bind transcript**
    /// `T_bind = SHA-256(T ‖ X_1 ‖ … ‖ X_m)`: the DSKE bind signature over `T_bind`
    /// (against that peer's revealed `epk`) and the confirmation MAC over `T_bind`
    /// (against `our_key`, since every honest member derives the same `K`). The MAC
    /// compare is constant-time. `round2` is the full canonical `X_*` map this
    /// member used to derive `K`; binding it here detects a peer that signed/confirmed
    /// a *different* `X` vector (split view) rather than letting `K` silently diverge.
    /// The peer's own `confirm.round2` must match the `X` recorded for it in `round2`.
    pub fn verify_confirm(
        &self,
        ctx: &EpochContext,
        our_key: &EpochKey,
        round2: &BTreeMap<Digest32, [u8; SHARE_LEN]>,
        confirm: &Confirm,
    ) -> Result<()> {
        let reveal = self
            .reveals
            .get(&confirm.author_id)
            .ok_or(Error::MalformedBundle("dgka confirm from unknown member"))?;
        // The peer's broadcast X (carried on the Confirm) must equal the X this
        // member used for that peer when deriving K — no divergent BD round-2 value.
        match round2.get(&confirm.author_id) {
            Some(x) if *x == confirm.round2 => {}
            _ => return Err(Error::MalformedBundle("dgka round-2 value mismatch")),
        }
        let t_bind = bind_transcript(ctx, round2)?;
        // DSKE bind: composite signature by the peer's epk over the bind transcript.
        reveal
            .epk
            .verify(&t_bind, &confirm.bind_sig)
            .map_err(|_| Error::SignatureInvalid)?;
        // Key confirmation: the peer's MAC over T_bind must equal ours under K.
        let expect = our_key.confirm_mac_over(ctx, &t_bind)?;
        if expect.ct_eq(&confirm.confirm_mac).into() {
            Ok(())
        } else {
            Err(Error::SignatureInvalid)
        }
    }
}

/// The DSKE **bind transcript** `T_bind = SHA-256(T ‖ X_1 ‖ … ‖ X_m)`, with `T`
/// the epoch transcript ([`EpochContext::transcript`]) and `X_*` the BD round-2
/// values in canonical member order. Binds the exact agreement material into the
/// bind signature and confirmation MAC (ADR-009 step 3). Requires an `X` for every
/// member. For `m == 2` the `X_*` are the (unused) own shares — still bound, so the
/// transcript stays a total function of the broadcasts.
pub(crate) fn bind_transcript(
    ctx: &EpochContext,
    round2: &BTreeMap<Digest32, [u8; SHARE_LEN]>,
) -> Result<Digest32> {
    let t = ctx.transcript();
    let mut x_bytes: Vec<[u8; SHARE_LEN]> = Vec::with_capacity(ctx.member_count());
    for m in ctx.members() {
        let x = round2
            .get(&m.author_id)
            .ok_or(Error::MalformedBundle("dgka missing round-2 value"))?;
        x_bytes.push(*x);
    }
    let mut parts: Vec<&[u8]> = Vec::with_capacity(1 + x_bytes.len());
    parts.push(&t);
    for x in &x_bytes {
        parts.push(&x[..]);
    }
    Ok(crate::hash::sha256_concat(&parts))
}

/// A completed DGKA session for one member: the canonical [`EpochContext`] and the
/// agreed epoch key `K`.
pub struct DgkaSession {
    ctx: EpochContext,
    key: EpochKey,
}

impl core::fmt::Debug for DgkaSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DgkaSession")
            .field("ctx", &self.ctx)
            .finish_non_exhaustive()
    }
}

impl DgkaSession {
    /// Assemble a completed session from a finalized context + key (used by the
    /// driver once all peers' confirmations verify).
    #[must_use]
    pub fn new(ctx: EpochContext, key: EpochKey) -> Self {
        Self { ctx, key }
    }

    /// The epoch context (member set, transcript, shares, epks).
    #[must_use]
    pub fn context(&self) -> &EpochContext {
        &self.ctx
    }

    /// The agreed epoch key (confirmation-only).
    #[must_use]
    pub fn key(&self) -> &EpochKey {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;

    fn signer(seed: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[seed; 32], &[!seed; 32]).unwrap()
    }

    #[test]
    fn commit_binds_reveal() {
        let sa = signer(1);
        let a = DgkaMember::start([0xC1; 32], 1, &sa).unwrap();
        let mut b = DgkaMember::start([0xC1; 32], 1, &signer(2)).unwrap();
        b.recv_commit(a.author_id(), a.commit()).unwrap();
        b.recv_reveal(a.reveal()).unwrap();
        // A tampered reveal (different nonce) does NOT open the commit.
        let mut bad = a.reveal();
        bad.nonce[0] ^= 0xff;
        let mut b2 = DgkaMember::start([0xC1; 32], 1, &signer(3)).unwrap();
        b2.recv_commit(a.author_id(), a.commit()).unwrap();
        assert!(matches!(
            b2.recv_reveal(bad),
            Err(Error::MalformedBundle("dgka reveal does not open commit"))
        ));
    }

    #[test]
    fn reveal_before_commit_rejected() {
        let a = DgkaMember::start([0xC1; 32], 1, &signer(1)).unwrap();
        let mut b = DgkaMember::start([0xC1; 32], 1, &signer(2)).unwrap();
        assert!(matches!(
            b.recv_reveal(a.reveal()),
            Err(Error::MalformedBundle("dgka reveal before commit"))
        ));
    }

    #[test]
    fn commit_equivocation_rejected() {
        let mut b = DgkaMember::start([0xC1; 32], 1, &signer(2)).unwrap();
        b.recv_commit([9; 32], [0xAA; 32]).unwrap();
        assert!(matches!(
            b.recv_commit([9; 32], [0xBB; 32]),
            Err(Error::MalformedBundle("dgka commit equivocation"))
        ));
    }

    #[test]
    fn reveal_with_forged_identity_rejected() {
        // [HIGH] A reveal whose author_pubkey doesn't match its author_id, or whose
        // static signature doesn't verify, is rejected — defeating the
        // (victim_author_id, attacker_epk) impersonation.
        let sa = signer(1);
        let a = DgkaMember::start([0xC1; 32], 1, &sa).unwrap();
        let mut b = DgkaMember::start([0xC1; 32], 1, &signer(2)).unwrap();
        b.recv_commit(a.author_id(), a.commit()).unwrap();
        // Swap in a different author_id while keeping a's pubkey → fingerprint
        // mismatch.
        let mut forged = a.reveal();
        forged.author_id = [0xAB; 32];
        assert!(matches!(
            b.recv_reveal(forged),
            Err(Error::MalformedBundle("dgka reveal author_id != pubkey"))
        ));
        // Tamper the static signature → envelope verification fails.
        let mut bad_sig = a.reveal();
        let mut raw = bad_sig.reveal_sig.to_bytes();
        raw[0] ^= 0xff;
        bad_sig.reveal_sig =
            crate::identity::composite::CompositeSignature::from_bytes(&raw).unwrap();
        let mut b2 = DgkaMember::start([0xC1; 32], 1, &signer(4)).unwrap();
        b2.recv_commit(a.author_id(), a.commit()).unwrap();
        assert!(matches!(
            b2.recv_reveal(bad_sig),
            Err(Error::SignatureInvalid) | Err(Error::MalformedBundle(_))
        ));
    }
}
