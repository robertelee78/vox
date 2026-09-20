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
