//! Per-epoch ephemeral signing keys, canonical member ordering, and the DSKE
//! transcript (ADR-009 §"Concrete protocol").
//!
//! In a deniable channel, content is signed **only** by a member's per-epoch
//! ephemeral composite (Ed25519+ML-DSA-65) signing key `(esk_i, epk_i)` — never
//! the static identity key (signing content with a static key "destroys any chance
//! at retaining deniability", mpENC). The ephemeral keypair is just a fresh
//! composite keypair ([`crate::identity::composite::SoftwareRootSigner`]); M7 adds
//! the epoch lifecycle around it:
//! - it is bound to `(channelID, epoch)` through the transcript `T`;
//! - it authenticates this epoch's content live (PQ origin auth to peers);
//! - its **private** half is published at epoch end ([`crate::deniable::esk_publication`]),
//!   after which anyone can forge that epoch's content → repudiation.
//!
//! ## Canonical member ordering (ADR-009)
//! Members are ordered by **ascending composite-pubkey** (the
//! `SHA-256(Ed25519 ‖ ML-DSA)` fingerprint is the stable identity; ADR-009 pins
//! the ordering on the composite pubkey, and the fingerprint is its
//! collision-resistant stand-in used consistently across M5/M6 as the author id).
//! Both the Burmester–Desmedt ring and the transcript lists use this order, so
//! every member derives the same `K` and the same `T`.
//!
//! ## The transcript `T` (ADR-009 step 3)
//! ```text
//! T = SHA-256( "vox/dgka-transcript/v1" ‖ channelID ‖ epoch_le_u64
//!              ‖ epk_1 ‖ epk_2 ‖ … ‖ epk_m         (ascending member order)
//!              ‖ z_1   ‖ z_2   ‖ … ‖ z_m )         (ascending member order)
//! ```
//! Both lists are in ascending composite-pubkey order. Each member signs `T` with
//! its `esk_i` (the DSKE bind) and MACs `T` under `K` (the confirm). Binding `T`
//! to `(channelID, epoch)` prevents cross-epoch / cross-channel replay.

use crate::error::{Error, Result};
use crate::hash::{sha256_concat, Digest32};
use crate::identity::composite::{
    CompositePublicKey, CompositeSignature, RootSigner, SoftwareRootSigner,
};

use crate::deniable::share::SHARE_LEN;

/// Domain-separation label for the DSKE transcript `T` (ADR-009 step 3).
pub const TRANSCRIPT_LABEL: &[u8] = b"vox/dgka-transcript/v1";

/// A member's per-epoch ephemeral **signing** keypair `(esk_i, epk_i)`.
///
/// This is a freshly-generated composite (Ed25519+ML-DSA-65) signer; its public
/// half `epk_i` is broadcast in the DGKA setup, and its private half `esk_i` is
/// held secret **until epoch close**, when it is published to make this epoch's
/// content repudiable (see [`crate::deniable::esk_publication`]). The underlying
/// [`SoftwareRootSigner`] zeroizes its secret on drop.
pub struct EphemeralSigningKey {
    signer: SoftwareRootSigner,
}

impl core::fmt::Debug for EphemeralSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EphemeralSigningKey")
            .field("epk", &crate::hash::Hex(&self.epk().fingerprint()))
            .finish_non_exhaustive()
    }
}

impl EphemeralSigningKey {
    /// Generate a fresh per-epoch ephemeral signing keypair from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            signer: SoftwareRootSigner::generate()?,
        })
    }

    /// Construct from explicit component seeds (used by epoch-end publication
    /// round-trips and by deterministic tests).
    pub fn from_component_seeds(ed_seed: &[u8; 32], ml_dsa_seed: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            signer: SoftwareRootSigner::from_component_seeds(ed_seed, ml_dsa_seed)?,
        })
    }

    /// The public ephemeral verification key `epk_i`.
    #[must_use]
    pub fn epk(&self) -> CompositePublicKey {
        self.signer.public_key()
    }

    /// Sign `msg` with `esk_i`. Callers pass the already-prepared signing input
    /// (e.g. an entry's [`crate::log::entry::EntrySkeleton::signing_input`] or the
    /// DSKE transcript binder); no extra domain separation is added here.
    pub fn sign(&self, msg: &[u8]) -> Result<CompositeSignature> {
        self.signer.sign(msg)
    }

    /// The component seeds of `esk_i`, for the epoch-end publication body. Returns
    /// secret material — only [`crate::deniable::esk_publication`] calls this, and
    /// only **after** the epoch has closed (publishing earlier voids live auth).
    pub(crate) fn publishable_seeds(&self) -> ([u8; 32], [u8; 32]) {
        // The seed getters now return `Zeroizing<[u8; 32]>`; deref-copy them out.
        // Unlike the at-rest factors, these seeds are *deliberately* published here
        // (the ESK-publication mechanism, ADR-009): once the epoch has closed they
        // are no longer secret, so surfacing them by value is correct by design.
        (*self.signer.ed25519_seed(), *self.signer.ml_dsa_seed())
    }
}

/// A member's public contribution to an epoch: its static identity composite
/// **public key** (the canonical ordering key) and fingerprint (`author_id`, the
/// admitted-set key), its ephemeral verification key `epk_i`, and its ephemeral DH
/// share `z_i`.
///
/// This is the per-member record carried in the (root-signed) `dgka-setup`
/// reveal; the verifier and combiner both consume the sorted vector of these.
///
/// `author_pubkey` is the static composite identity key; `author_id ==
/// author_pubkey.fingerprint()` is enforced by the verified constructor
/// ([`Self::from_signed_reveal`]). The canonical ring/transcript order is
/// **ascending `author_pubkey` bytes** (ADR-009 "ascending author composite-pubkey
/// order"), so two independent implementations derive the same `K` — the
/// fingerprint hash is *not* the sort key (its order need not match the pubkey's).
#[derive(Clone)]
pub struct MemberDescriptor {
    /// The member's static identity composite public key (the ordering key).
    pub author_pubkey: CompositePublicKey,
    /// The member's static identity fingerprint (ADR-002), the admitted-set key.
    pub author_id: Digest32,
    /// The member's per-epoch ephemeral verification key `epk_i`.
    pub epk: CompositePublicKey,
    /// The member's ephemeral DH share `z_i` (compressed Ristretto255).
    pub share: [u8; SHARE_LEN],
}

impl core::fmt::Debug for MemberDescriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemberDescriptor")
            .field("author_id", &crate::hash::Hex(&self.author_id))
            .field("epk", &crate::hash::Hex(&self.epk.fingerprint()))
            .field("share", &crate::hash::Hex(&self.share))
            .finish()
    }
}

impl MemberDescriptor {
    /// Build a descriptor from a **root-signed** `dgka-setup` reveal envelope,
    /// binding the registered `epk`/`share` to the static identity that signed it.
    ///
    /// This is the **only** safe production path to a [`MemberDescriptor`] /
    /// [`EpochContext`] (and thence the verifier): it defeats the
    /// `(victim_author_id, attacker_epk)` impersonation that an unverified
    /// caller-supplied descriptor would allow (ADR-009 — the DGKA setup entries are
    /// governance-class, root-composite-signed; the registered `epk` MUST come from
    /// the member's own static key). `setup_root` is the static composite key that
    /// signed the `dgka-setup` reveal; `reveal_sig` is its composite signature over
    /// the canonical reveal body (`vox/dgka-setup/v1 ‖ body`). The resulting
    /// descriptor's `author_id` is fixed to `setup_root.fingerprint()` — a reveal
    /// cannot register an `epk` for any identity other than its own signer.
    pub fn from_signed_reveal(
        setup_root: &CompositePublicKey,
        channel_id: Digest32,
        epoch: u64,
        epk: CompositePublicKey,
        share: [u8; SHARE_LEN],
        reveal_sig: &CompositeSignature,
    ) -> Result<Self> {
        let author_id = setup_root.fingerprint();
        let body = dgka_setup_signing_input(channel_id, epoch, &author_id, &epk, &share);
        setup_root
            .verify(&body, reveal_sig)
            .map_err(|_| Error::SignatureInvalid)?;
        Ok(Self {
            author_pubkey: setup_root.clone(),
            author_id,
            epk,
            share,
        })
    }

    /// The canonical signing input for this descriptor's `dgka-setup` reveal:
    /// `vox/dgka-setup/v1 ‖ [channelID, epoch, author_id, epk, share]`. The static
    /// root signs this; [`Self::from_signed_reveal`] verifies it. The author signs
    /// its own descriptor, so the static signature attributes *participation* (weak
    /// deniability) without signing the per-epoch key-agreement material as content.
    #[must_use]
    pub fn reveal_signing_input(&self, channel_id: Digest32, epoch: u64) -> Vec<u8> {
        dgka_setup_signing_input(channel_id, epoch, &self.author_id, &self.epk, &self.share)
    }
}

/// Canonical `dgka-setup` reveal signing input:
/// `vox/dgka-setup/v1 ‖ CBOR[channelID, epoch, author_id, epk_bytes, share]`.
fn dgka_setup_signing_input(
    channel_id: Digest32,
    epoch: u64,
    author_id: &Digest32,
    epk: &CompositePublicKey,
    share: &[u8; SHARE_LEN],
) -> Vec<u8> {
    let mut e = crate::cbor::Encoder::new();
    e.array(5)
        .bytes(channel_id.as_slice())
        .uint(epoch)
        .bytes(author_id.as_slice())
        .bytes(&epk.to_bytes())
        .bytes(&share[..]);
    crate::wire::signing_input(crate::wire::StructTag::DgkaSetup, &e.finish())
}

/// The (author_id → epk) record a verifier registers for an epoch — the public
/// half of a [`MemberDescriptor`] needed only to verify content signatures.
#[derive(Clone)]
pub struct MemberEpk {
    /// The member's static identity fingerprint.
    pub author_id: Digest32,
    /// The member's per-epoch ephemeral verification key.
    pub epk: CompositePublicKey,
}

/// The immutable context of a deniable epoch: the channel id, the epoch number,
/// and the canonically-ordered member set. Owns the transcript construction so the
/// DGKA rounds, the verifier, and the re-key all bind to identical bytes.
#[derive(Clone)]
pub struct EpochContext {
    channel_id: Digest32,
    epoch: u64,
    /// Members sorted by ascending composite-pubkey (author_id). Pinned at
    /// construction so the ring order and the transcript order coincide.
    members: Vec<MemberDescriptor>,
}

impl core::fmt::Debug for EpochContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EpochContext")
            .field("channel_id", &crate::hash::Hex(&self.channel_id))
            .field("epoch", &self.epoch)
            .field("members", &self.members.len())
            .finish()
    }
}

impl EpochContext {
    /// Build an epoch context from the unsorted member descriptors. Sorts them by
    /// ascending `author_id` (the canonical order), rejecting an empty/singleton
    /// set (a deniable epoch needs ≥ 2 members to run a GKA) or duplicate authors.
    pub fn new(
        channel_id: Digest32,
        epoch: u64,
        mut members: Vec<MemberDescriptor>,
    ) -> Result<Self> {
        if members.len() < 2 {
            return Err(Error::MalformedBundle("dgka epoch needs >= 2 members"));
        }
        // Canonical ring/transcript order: ascending static composite-pubkey bytes
        // (ADR-009), so independent implementations derive the same K.
        members.sort_by(|a, b| a.author_pubkey.to_bytes().cmp(&b.author_pubkey.to_bytes()));
        // Reject duplicate authors (would corrupt the ring + transcript). After the
        // pubkey sort, equal author_ids are adjacent iff equal pubkeys are.
        for w in members.windows(2) {
            if w[0].author_pubkey.to_bytes() == w[1].author_pubkey.to_bytes()
                || w[0].author_id == w[1].author_id
            {
                return Err(Error::MalformedBundle("dgka duplicate member"));
            }
        }
        Ok(Self {
            channel_id,
            epoch,
            members,
        })
    }

    /// Build an epoch context from **verified** root-signed `dgka-setup` reveals,
    /// then check the member set equals the `expected` admitted/consenting author
    /// set exactly (no missing, no extra). This is the production constructor:
    /// every descriptor is bound to its static signer ([`MemberDescriptor::from_signed_reveal`]),
    /// and the split-view / subgroup risk is closed by pinning the expected set.
    ///
    /// `reveals` are `(setup_root, epk, share, reveal_sig)` tuples. `expected` is the
    /// set of static identity fingerprints admitted to `(channel_id, epoch)` (from
    /// M6 governance). Returns an error if any signature fails, any descriptor's
    /// signer is not in `expected`, or the verified set != `expected`.
    pub fn from_signed_reveals(
        channel_id: Digest32,
        epoch: u64,
        reveals: &[(
            CompositePublicKey,
            CompositePublicKey,
            [u8; SHARE_LEN],
            CompositeSignature,
        )],
        expected: &std::collections::HashSet<Digest32>,
    ) -> Result<Self> {
        let mut members = Vec::with_capacity(reveals.len());
        let mut seen: std::collections::HashSet<Digest32> = std::collections::HashSet::new();
        for (setup_root, epk, share, sig) in reveals {
            let d = MemberDescriptor::from_signed_reveal(
                setup_root,
                channel_id,
                epoch,
                epk.clone(),
                *share,
                sig,
            )?;
            if !expected.contains(&d.author_id) {
                return Err(Error::MalformedBundle("dgka reveal from non-member"));
            }
            if !seen.insert(d.author_id) {
                return Err(Error::MalformedBundle("dgka duplicate member"));
            }
            members.push(d);
        }
        // Exact match: every expected member contributed a verified reveal.
        if &seen != expected {
            return Err(Error::MalformedBundle("dgka member set != expected set"));
        }
        Self::new(channel_id, epoch, members)
    }

    /// The channel id.
    #[must_use]
    pub fn channel_id(&self) -> Digest32 {
        self.channel_id
    }

    /// The epoch number.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The number of members in this epoch (`m`).
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// The canonically-ordered member descriptors.
    #[must_use]
    pub fn members(&self) -> &[MemberDescriptor] {
        &self.members
    }

    /// The ring position (0-based, ascending composite-pubkey order) of `author`,
    /// or `None` if not a member of this epoch.
    #[must_use]
    pub fn position_of(&self, author: &Digest32) -> Option<usize> {
        self.members.iter().position(|m| &m.author_id == author)
    }

    /// All members' shares `z_*` in canonical (ascending) order.
    #[must_use]
    pub fn shares(&self) -> Vec<[u8; SHARE_LEN]> {
        self.members.iter().map(|m| m.share).collect()
    }

    /// The (author_id → epk) records in canonical order, for verifier registration.
    #[must_use]
    pub fn epks(&self) -> Vec<MemberEpk> {
        self.members
            .iter()
            .map(|m| MemberEpk {
                author_id: m.author_id,
                epk: m.epk.clone(),
            })
            .collect()
    }

    /// The DSKE transcript `T` for this epoch (ADR-009 step 3):
    /// `SHA-256(label ‖ channelID ‖ epoch_le ‖ epk_1..m ‖ z_1..m)`, all lists in
    /// ascending composite-pubkey order. This is the value bound by the DSKE
    /// signatures (step 3) and confirmed by the MACs (step 4).
    #[must_use]
    pub fn transcript(&self) -> Digest32 {
        let epoch_le = self.epoch.to_le_bytes();
        // Pre-collect epk encodings so they outlive the slice references.
        let epk_bytes: Vec<[u8; CompositePublicKey::LEN]> =
            self.members.iter().map(|m| m.epk.to_bytes()).collect();
        let mut parts: Vec<&[u8]> = Vec::with_capacity(3 + 2 * self.members.len());
        parts.push(TRANSCRIPT_LABEL);
        parts.push(&self.channel_id);
        parts.push(&epoch_le);
        for e in &epk_bytes {
            parts.push(&e[..]);
        }
        for m in &self.members {
            parts.push(&m.share);
        }
        sha256_concat(&parts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deniable::share::EphemeralShare;
    use crate::identity::composite::{RootSigner, SoftwareRootSigner};

    const CHANNEL: Digest32 = [0xC1; 32];

    /// A test descriptor with a real static identity, plus its static signer so a
    /// signed-reveal round-trip can be exercised.
    fn descriptor(seed: u8) -> (MemberDescriptor, SoftwareRootSigner) {
        let static_signer =
            SoftwareRootSigner::from_component_seeds(&[seed; 32], &[seed ^ 0xAA; 32]).unwrap();
        let esk = EphemeralSigningKey::from_component_seeds(&[seed ^ 0x11; 32], &[seed ^ 0xff; 32])
            .unwrap();
        let share = EphemeralShare::generate().unwrap();
        let d = MemberDescriptor {
            author_pubkey: static_signer.public_key(),
            author_id: static_signer.fingerprint(),
            epk: esk.epk(),
            share: share.public_bytes(),
        };
        (d, static_signer)
    }

    #[test]
    fn members_sorted_by_pubkey_ascending() {
        let (d1, _) = descriptor(3);
        let (d2, _) = descriptor(1);
        let (d3, _) = descriptor(2);
        let ctx = EpochContext::new(CHANNEL, 5, vec![d1, d2, d3]).unwrap();
        let keys: Vec<Vec<u8>> = ctx
            .members()
            .iter()
            .map(|m| m.author_pubkey.to_bytes().to_vec())
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(
            keys, sorted,
            "ring must be ascending composite-pubkey order"
        );
    }

    #[test]
    fn transcript_is_order_independent_of_input() {
        let (d1, _) = descriptor(3);
        let (d2, _) = descriptor(1);
        let a = EpochContext::new(CHANNEL, 5, vec![d1.clone(), d2.clone()]).unwrap();
        let b = EpochContext::new(CHANNEL, 5, vec![d2, d1]).unwrap();
        assert_eq!(a.transcript(), b.transcript());
    }

    #[test]
    fn transcript_binds_channel_and_epoch() {
        let (d1, _) = descriptor(1);
        let (d2, _) = descriptor(2);
        let base = EpochContext::new(CHANNEL, 5, vec![d1.clone(), d2.clone()]).unwrap();
        let other_epoch = EpochContext::new(CHANNEL, 6, vec![d1.clone(), d2.clone()]).unwrap();
        let other_chan = EpochContext::new([0xC2; 32], 5, vec![d1, d2]).unwrap();
        assert_ne!(base.transcript(), other_epoch.transcript());
        assert_ne!(base.transcript(), other_chan.transcript());
    }

    #[test]
    fn rejects_too_few_members() {
        let (d1, _) = descriptor(1);
        assert!(EpochContext::new([0; 32], 1, vec![d1]).is_err());
        assert!(EpochContext::new([0; 32], 1, vec![]).is_err());
    }

    #[test]
    fn rejects_duplicate_member() {
        let (d1, _) = descriptor(1);
        let (d2, _) = descriptor(2);
        assert!(matches!(
            EpochContext::new([0; 32], 1, vec![d1.clone(), d2, d1]),
            Err(Error::MalformedBundle("dgka duplicate member"))
        ));
    }

    #[test]
    fn position_of_finds_member() {
        let (d1, _) = descriptor(1);
        let (d2, _) = descriptor(2);
        let id1 = d1.author_id;
        let ctx = EpochContext::new([0; 32], 1, vec![d1, d2]).unwrap();
        assert!(ctx.position_of(&id1).is_some());
        assert!(ctx.position_of(&[0xAB; 32]).is_none());
    }

    #[test]
    fn ephemeral_key_signs_and_verifies() {
        let esk = EphemeralSigningKey::generate().unwrap();
        let sig = esk.sign(b"vox/test deniable content").unwrap();
        assert!(esk.epk().verify(b"vox/test deniable content", &sig).is_ok());
    }

    #[test]
    fn from_signed_reveal_binds_epk_to_signer() {
        // The verified path: a reveal signed by the static identity registers the
        // (author_id, epk) bound to that identity. A reveal NOT signed by the claimed
        // identity is rejected (impersonation defeated).
        let (d, signer) = descriptor(5);
        let body = d.reveal_signing_input(CHANNEL, 5);
        let sig = signer.sign(&body).unwrap();
        let rebuilt = MemberDescriptor::from_signed_reveal(
            &signer.public_key(),
            CHANNEL,
            5,
            d.epk.clone(),
            d.share,
            &sig,
        )
        .unwrap();
        assert_eq!(rebuilt.author_id, signer.fingerprint());
        assert_eq!(rebuilt.epk, d.epk);

        // An attacker signs with ITS key but claims the victim's epk: the descriptor
        // it produces is bound to the ATTACKER (author_id = attacker), never the
        // victim — so it cannot register an epk under the victim's identity.
        let attacker = SoftwareRootSigner::from_component_seeds(&[99; 32], &[1; 32]).unwrap();
        let abody = MemberDescriptor {
            author_pubkey: attacker.public_key(),
            author_id: attacker.fingerprint(),
            epk: d.epk.clone(),
            share: d.share,
        }
        .reveal_signing_input(CHANNEL, 5);
        let asig = attacker.sign(&abody).unwrap();
        let ad = MemberDescriptor::from_signed_reveal(
            &attacker.public_key(),
            CHANNEL,
            5,
            d.epk.clone(),
            d.share,
            &asig,
        )
        .unwrap();
        assert_eq!(ad.author_id, attacker.fingerprint());
        assert_ne!(ad.author_id, signer.fingerprint());

        // A reveal whose signature is from the wrong key is rejected.
        assert!(matches!(
            MemberDescriptor::from_signed_reveal(
                &signer.public_key(),
                CHANNEL,
                5,
                d.epk.clone(),
                d.share,
                &asig, // attacker's sig against the victim's pubkey
            ),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn from_signed_reveals_requires_expected_set() {
        use std::collections::HashSet;
        let (d1, s1) = descriptor(1);
        let (d2, s2) = descriptor(2);
        let mk = |d: &MemberDescriptor, s: &SoftwareRootSigner| {
            let sig = s.sign(&d.reveal_signing_input(CHANNEL, 5)).unwrap();
            (s.public_key(), d.epk.clone(), d.share, sig)
        };
        let reveals = vec![mk(&d1, &s1), mk(&d2, &s2)];
        let expected: HashSet<Digest32> = [d1.author_id, d2.author_id].into_iter().collect();
        // Exact match → ok.
        assert!(EpochContext::from_signed_reveals(CHANNEL, 5, &reveals, &expected).is_ok());
        // Missing a member → rejected (split view).
        let short: HashSet<Digest32> = [d1.author_id, d2.author_id, [0xEE; 32]]
            .into_iter()
            .collect();
        assert!(matches!(
            EpochContext::from_signed_reveals(CHANNEL, 5, &reveals, &short),
            Err(Error::MalformedBundle("dgka member set != expected set"))
        ));
        // A reveal from a non-expected member → rejected.
        let only1: HashSet<Digest32> = [d1.author_id].into_iter().collect();
        assert!(matches!(
            EpochContext::from_signed_reveals(CHANNEL, 5, &reveals, &only1),
            Err(Error::MalformedBundle("dgka reveal from non-member"))
        ));
    }
}
