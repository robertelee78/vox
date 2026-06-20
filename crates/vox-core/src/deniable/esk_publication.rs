//! Epoch-end ephemeral-signing-key publication (ADR-009; tag `0x0010`,
//! `vox/esk-publication/v1`) — the mechanism that makes content **repudiable**.
//!
//! During a deniable epoch, content is signed with the member's per-epoch
//! ephemeral key `esk_i`, giving peers genuine live PQ origin authentication. At
//! **epoch end** — and only after the epoch has closed (a passphrase-rotation /
//! epoch-increment is on the log) — each member publishes its `esk_i` as an
//! `esk-publication` log entry: a **root-composite-signed envelope** (governance
//! class, attributable participation) whose body is `{ epoch, esk_i }`. Once
//! `esk_i` is public, **anyone** can mint a valid composite signature under
//! `epk_i` over arbitrary content, so a recorded transcript no longer proves what
//! the member authored → offline content repudiation (mpENC weak deniability).
//!
//! ## Early-publication refusal (critical)
//! Publishing `esk_i` *before* the epoch closes would void live authentication for
//! the still-open epoch (peers could no longer trust `epk_i` signatures). M7 thus
//! **refuses** to build a publication for an epoch that is not yet closed:
//! [`EskPublication::build`] requires a witness that the publishing epoch is `<`
//! the current (closed-past) epoch on the log. The caller supplies the current
//! epoch from M5/M6 governance state (a passphrase-rotation increments it).
//!
//! ## Body layout
//! `vox/esk-publication/v1` body is a 3-element canonical-CBOR array
//! `[epoch, ed25519_seed(32), ml_dsa_seed(32)]`. The two component seeds are the
//! `esk_i` private material (the [`crate::identity::composite::SoftwareRootSigner`]
//! is reconstructible from them). This rides a log entry as the payload; the entry
//! envelope is root-composite-signed by the publisher (M5 `Entry::build_signed`).

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::identity::composite::CompositePublicKey;
use crate::wire::{frame, parse_frame, StructTag};

use crate::deniable::epoch::EphemeralSigningKey;

/// The published ephemeral private key for one closed epoch: the epoch number and
/// the two component seeds of `esk_i`. After this is on the log, that epoch's
/// content signatures are forgeable by anyone (the deniability property).
#[derive(Clone)]
pub struct EskPublication {
    /// The (closed) epoch whose ephemeral key is being published.
    pub epoch: u64,
    /// The Ed25519 component seed of `esk_i`.
    ed25519_seed: [u8; 32],
    /// The ML-DSA-65 component seed of `esk_i`.
    ml_dsa_seed: [u8; 32],
}

impl core::fmt::Debug for EskPublication {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The seeds are now public-by-design, but redact them anyway so a log dump
        // does not splatter key material into traces unintentionally.
        f.debug_struct("EskPublication")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl EskPublication {
    /// Build a publication for `esk`'s `publishing_epoch`, **refusing** if that
    /// epoch is not yet closed. `current_epoch` is the channel's current epoch from
    /// governance state (a passphrase-rotation increments it, ADR-006/ADR-007); the
    /// publishing epoch is closed iff `publishing_epoch < current_epoch`.
    pub fn build(
        esk: &EphemeralSigningKey,
        publishing_epoch: u64,
        current_epoch: u64,
    ) -> Result<Self> {
        if publishing_epoch >= current_epoch {
            // Epoch still open (or in the future): publishing now voids live auth.
            return Err(Error::MalformedBundle("esk publication before epoch close"));
        }
        let (ed25519_seed, ml_dsa_seed) = esk.publishable_seeds();
        Ok(Self {
            epoch: publishing_epoch,
            ed25519_seed,
            ml_dsa_seed,
        })
    }

    /// Reconstruct the (now-public) ephemeral signing key from the published seeds.
    /// This is what makes content forgeable: any party can rebuild `esk_i` and sign
    /// arbitrary content under `epk_i`. Used by the forge-after-publication
    /// demonstration and by an honest verifier that wishes to confirm an entry was
    /// authored under the (now-published) key.
    pub fn reconstruct(&self) -> Result<EphemeralSigningKey> {
        EphemeralSigningKey::from_component_seeds(&self.ed25519_seed, &self.ml_dsa_seed)
    }

    /// The canonical CBOR body `[epoch, ed25519_seed, ml_dsa_seed]`.
    #[must_use]
    pub fn canonical_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(3)
            .uint(self.epoch)
            .bytes(&self.ed25519_seed)
            .bytes(&self.ml_dsa_seed);
        e.finish()
    }

    /// Frame the publication for the wire/log payload:
    /// `tag(0x0010) ‖ version ‖ canonical_body`.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        frame(StructTag::EskPublication, &self.canonical_body())
    }

    /// Parse a framed `esk-publication`, validating the tag, version, arity, and
    /// seed lengths.
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::EskPublication {
            return Err(Error::MalformedBundle("esk-publication wrong struct tag"));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 3 {
            return Err(Error::MalformedBundle("esk-publication arity"));
        }
        let epoch = d.uint()?;
        let ed25519_seed: [u8; 32] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("esk-publication ed25519 seed length"))?;
        let ml_dsa_seed: [u8; 32] = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("esk-publication ml-dsa seed length"))?;
        d.finish()?;
        Ok(Self {
            epoch,
            ed25519_seed,
            ml_dsa_seed,
        })
    }
}

/// A reconstructed, now-public ephemeral key plus its epoch — the result of
/// ingesting an [`EskPublication`]. After holding this, a party can forge that
/// epoch's content signatures (the deniability demonstration).
pub struct PublishedEsk {
    /// The closed epoch this key belongs to.
    pub epoch: u64,
    /// The reconstructed (public) ephemeral signing key.
    pub esk: EphemeralSigningKey,
}

impl PublishedEsk {
    /// Ingest a publication, reconstructing the ephemeral key. **Unverified**: the
    /// caller has not checked the epoch is closed or that the seeds match a
    /// registered `epk`. Prefer [`Self::ingest_verified`] on the receive path.
    pub fn ingest(pubr: &EskPublication) -> Result<Self> {
        Ok(Self {
            epoch: pubr.epoch,
            esk: pubr.reconstruct()?,
        })
    }

    /// Ingest a received publication with the full receive-side guard (the
    /// receive-side mirror of [`EskPublication::build`]'s local refusal): require that
    /// (a) the published epoch is already **closed** (`pubr.epoch < current_epoch`)
    /// — accepting an open epoch's key would void its live authentication — and
    /// (b) the reconstructed key's `epk` equals `expected_epk`, the verification key
    /// registered for that epoch in the `dgka-setup` (so a publication cannot
    /// substitute an unrelated key). Rejects early/future/mismatched publications.
    pub fn ingest_verified(
        pubr: &EskPublication,
        current_epoch: u64,
        expected_epk: &CompositePublicKey,
    ) -> Result<Self> {
        if pubr.epoch >= current_epoch {
            return Err(Error::MalformedBundle("esk publication before epoch close"));
        }
        let esk = pubr.reconstruct()?;
        if &esk.epk() != expected_epk {
            return Err(Error::MalformedBundle("esk publication epk mismatch"));
        }
        Ok(Self {
            epoch: pubr.epoch,
            esk,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deniable::epoch::MemberEpk;
    use crate::deniable::verifier::{build_deniable_content, EpochVerifier};
    use crate::hash::sha256;
    use crate::log::entry::DeniableVerifier;
    use crate::log::entry::{Entry, EntrySkeleton, ZERO_HASH};
    use crate::suite::algo;

    #[test]
    fn rejects_publication_before_epoch_close() {
        let esk = EphemeralSigningKey::generate().unwrap();
        // Publishing epoch 5 while current epoch is still 5 (open) → refused.
        assert!(matches!(
            EskPublication::build(&esk, 5, 5),
            Err(Error::MalformedBundle("esk publication before epoch close"))
        ));
        // And a future epoch is refused too.
        assert!(EskPublication::build(&esk, 6, 5).is_err());
    }

    #[test]
    fn accepts_publication_after_epoch_close() {
        let esk = EphemeralSigningKey::generate().unwrap();
        // Epoch 5 closed (current epoch advanced to 6) → accepted.
        let p = EskPublication::build(&esk, 5, 6).unwrap();
        assert_eq!(p.epoch, 5);
        // Round-trips on the wire.
        let wire = p.to_wire();
        let back = EskPublication::from_wire(&wire).unwrap();
        assert_eq!(back.epoch, 5);
        // The reconstructed key matches the original epk.
        assert_eq!(back.reconstruct().unwrap().epk(), esk.epk());
    }

    #[test]
    fn reconstructed_key_equals_original() {
        let esk = EphemeralSigningKey::from_component_seeds(&[7; 32], &[8; 32]).unwrap();
        let p = EskPublication::build(&esk, 1, 2).unwrap();
        let rebuilt = p.reconstruct().unwrap();
        // Same epk, and it verifies a signature made by the original esk.
        let sig = esk.sign(b"vox/test").unwrap();
        assert!(rebuilt.epk().verify(b"vox/test", &sig).is_ok());
    }

    #[test]
    fn from_wire_rejects_wrong_tag() {
        let esk = EphemeralSigningKey::generate().unwrap();
        let p = EskPublication::build(&esk, 1, 2).unwrap();
        let reframed = frame(StructTag::LogEntry, &p.canonical_body());
        assert!(matches!(
            EskPublication::from_wire(&reframed),
            Err(Error::MalformedBundle("esk-publication wrong struct tag"))
        ));
    }

    /// THE DENIABILITY DEMONSTRATION (ADR-009): after `esk_i` is published, a third
    /// party who never held `esk_i` can forge a valid epoch content signature that
    /// the epoch verifier accepts — so a recorded entry no longer proves authorship.
    #[test]
    fn after_publication_a_third_party_forges_valid_content() {
        let epoch = 5u64;
        // The real author signs genuine content during the (open) epoch.
        let author = EphemeralSigningKey::from_component_seeds(&[1; 32], &[2; 32]).unwrap();
        let author_id = author.epk().fingerprint();
        let mepk = MemberEpk {
            author_id,
            epk: author.epk(),
        };
        let channel_id = [0xC1; 32];
        let mut verifier = EpochVerifier::new();
        verifier.release(channel_id, epoch, &mepk).unwrap();

        let genuine_sk = EntrySkeleton {
            author_id,
            seq: 1,
            prev_hash: ZERO_HASH,
            lipmaa_backlink: ZERO_HASH,
            channel_id,
            epoch,
            algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
            payload_hash: sha256(b"i said this"),
            payload_len: b"i said this".len() as u64,
            end_of_feed: false,
        };
        let genuine = build_deniable_content(&author, genuine_sk, b"i said this".to_vec()).unwrap();
        assert!(verifier
            .verify_deniable(&genuine.skeleton, &genuine.authenticator.to_bytes())
            .is_ok());

        // Epoch closes; the author publishes esk_i (epoch 5 closed, current 6).
        let publication = EskPublication::build(&author, epoch, 6).unwrap();

        // A THIRD PARTY ingests the publication WITH the receive-side guard (epoch
        // closed + epk matches the registered one) and forges DIFFERENT content under
        // the SAME epk — and the epoch verifier accepts it. Authorship is now
        // repudiable: the genuine entry is indistinguishable from this forgery.
        let forger = PublishedEsk::ingest_verified(&publication, 6, &author.epk()).unwrap();
        let forged_sk = EntrySkeleton {
            payload_hash: sha256(b"words i NEVER said"),
            payload_len: b"words i NEVER said".len() as u64,
            ..genuine.skeleton.clone()
        };
        let forged =
            build_deniable_content(&forger.esk, forged_sk, b"words i NEVER said".to_vec()).unwrap();
        assert!(verifier
            .verify_deniable(&forged.skeleton, &forged.authenticator.to_bytes())
            .is_ok());

        // The forged signature verifies even though `forger` is not the author —
        // the very definition of content-authorship repudiation. (Compile-time
        // proof that `Entry` is the carrier; the forged entry stands on its own.)
        let _ = Entry::from_wire(&forged.to_wire()).unwrap();
    }

    #[test]
    fn ingest_verified_guards_epoch_and_epk() {
        // [MED] receive-side guard: reject ingesting a publication whose epoch is
        // still open, or whose reconstructed epk does not match the registered one.
        let esk = EphemeralSigningKey::from_component_seeds(&[3; 32], &[4; 32]).unwrap();
        let p = EskPublication::build(&esk, 5, 6).unwrap();
        // Epoch 5 still open (current == 5) → rejected on receive too.
        assert!(matches!(
            PublishedEsk::ingest_verified(&p, 5, &esk.epk()),
            Err(Error::MalformedBundle("esk publication before epoch close"))
        ));
        // Wrong expected epk → rejected.
        let other = EphemeralSigningKey::from_component_seeds(&[9; 32], &[9; 32]).unwrap();
        assert!(matches!(
            PublishedEsk::ingest_verified(&p, 6, &other.epk()),
            Err(Error::MalformedBundle("esk publication epk mismatch"))
        ));
        // Closed epoch + matching epk → accepted.
        assert!(PublishedEsk::ingest_verified(&p, 6, &esk.epk()).is_ok());
    }
}
