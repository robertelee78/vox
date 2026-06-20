//! The local content store: content-addressed dedup (layer 1 adjacency) and the
//! per-channel SEK-encrypted **segment** store (layer 2) (ADR-010 §"Two distinct
//! encryption layers", §"Local at-rest encryption").
//!
//! ## Layer separation (do not conflate)
//! - **Content encryption is layer 1 (shared), already done by M4/M6.** Each
//!   payload is encrypted *once, by its author* under a Sender-Key-derived content
//!   key with a fresh random nonce (ADR-006). M8 does **not** re-encrypt content.
//!   What M8 adds at this layer is only the **content-addressed object store**:
//!   the author's exact `(nonce ‖ ciphertext)` object is content-addressed by
//!   `CID = SHA-256(object)` and de-duplicated **by identical bytes** — never by
//!   deterministic/convergent encryption (which ADR-010 explicitly rejects because
//!   it leaks plaintext equality). Two members storing the byte-identical author
//!   object share one CID; a different author nonce yields a different object and a
//!   different CID.
//! - **Local at-rest encryption is layer 2 (the double-lock).** The per-channel
//!   local store — log DB, decrypted plaintext/index caches, and per-channel key
//!   material — is encrypted at rest under the channel SEK
//!   ([`crate::atrest::sek::Sek`]), AEAD per **segment** with a fresh random nonce.
//!   This is strictly local; it does not touch the wire/log format, so it cannot
//!   break dedup or replication. Plaintext caches live *inside* a sealed segment,
//!   never written unencrypted (ADR-010 §"App-lock and memory hygiene").
//!
//! ## Why segments, not whole-store
//! AEAD per segment lets the store seal/open independent units (a key-material
//! blob, an index page, a plaintext cache page) without rewriting the whole DB,
//! and gives each its own nonce so no `(SEK, nonce)` pair repeats. The store does
//! not impose a record schema on a segment — callers put their own canonical bytes
//! in — but every segment is bound by AEAD AAD to its `kind` and `segment_id`, so a
//! sealed key-material segment can never be opened as if it were a cache page, and
//! a segment cannot be moved to another slot.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use zeroize::Zeroize;

use crate::atrest::sek::{Sek, NONCE_LEN, TAG_LEN};
use crate::error::{Error, Result};
use crate::hash::{sha256, Digest32};
use crate::identity::rng::random_array;

/// A content identifier: `SHA-256` of the exact author object
/// `(nonce ‖ ciphertext)` (ADR-010 §"content-addressing"). Dedup is by equality
/// of this digest, i.e. by identical bytes.
pub type Cid = Digest32;

/// Compute the CID of an author content object: `SHA-256(nonce ‖ ciphertext)`.
///
/// The argument is the **exact byte object the author produced and replicated**
/// (ADR-006/008) — Vox does not re-encrypt it. Identical objects hash to the same
/// CID (dedup); any difference (including a different author nonce) changes it.
#[must_use]
pub fn content_id(object: &[u8]) -> Cid {
    sha256(object)
}

/// The kind of a SEK-encrypted store segment. Bound into the AEAD AAD so kinds are
/// not interchangeable at rest (a key-material blob cannot be opened as a cache).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SegmentKind {
    /// A page of the log database (skeletons + retained payloads).
    LogDb,
    /// A decrypted **plaintext** cache page — must only ever exist inside a sealed
    /// segment (ADR-010 forbids unencrypted plaintext caches at rest).
    PlaintextCache,
    /// An index page (search / by-author / by-time indexes).
    Index,
    /// Per-channel key material at rest: sender keys, received SKDMs, and the SEK
    /// *wrap* itself (ADR-010 §"per-channel key material ... the SEK wrap itself").
    KeyMaterial,
}

impl SegmentKind {
    /// The stable AAD tag for this kind.
    const fn aad_tag(self) -> &'static [u8] {
        match self {
            SegmentKind::LogDb => b"vox/seg/log-db/v1",
            SegmentKind::PlaintextCache => b"vox/seg/plaintext-cache/v1",
            SegmentKind::Index => b"vox/seg/index/v1",
            SegmentKind::KeyMaterial => b"vox/seg/key-material/v1",
        }
    }
}

/// A sealed store segment: `nonce ‖ AES-256-GCM(SEK, nonce, plaintext)` with AAD
/// binding the segment's `kind` and `segment_id`. Only sealed segments are written
/// to disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedSegment {
    /// The AES-256-GCM nonce.
    pub nonce: [u8; NONCE_LEN],
    /// `AES-256-GCM(SEK, nonce, plaintext)` (ciphertext + 16-byte tag).
    pub ciphertext: Vec<u8>,
}

/// Build the AEAD AAD for a segment: `kind_tag ‖ segment_id(8 BE)`. Binding the id
/// pins a sealed segment to its slot (it cannot be relocated/replayed into another
/// id), and binding the kind keeps kinds non-interchangeable.
fn segment_aad(kind: SegmentKind, segment_id: u64) -> Vec<u8> {
    let tag = kind.aad_tag();
    let mut aad = Vec::with_capacity(tag.len() + 8);
    aad.extend_from_slice(tag);
    aad.extend_from_slice(&segment_id.to_be_bytes());
    aad
}

/// **Seal** a plaintext segment under the SEK (ADR-010 layer 2). A fresh random
/// nonce is sampled; the segment is bound to `(kind, segment_id)` via AAD.
///
/// Callers pass already-canonical plaintext bytes (e.g. a serialized cache page or
/// a serialized key-material blob). The returned [`SealedSegment`] is the only form
/// written at rest.
pub fn seal_segment(
    sek: &Sek,
    kind: SegmentKind,
    segment_id: u64,
    plaintext: &[u8],
) -> Result<SealedSegment> {
    // `key_bytes()` returns `Err(AtRestLocked)` if the app has been locked, so a
    // seal cannot proceed under an invalidated SEK (ADR-010 app-lock enforcement).
    let cipher =
        Aes256Gcm::new_from_slice(sek.key_bytes()?).map_err(|_| Error::AtRestUnlockFailed)?;
    let nonce = random_array::<NONCE_LEN>()?;
    let aad = segment_aad(kind, segment_id);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::AtRestUnlockFailed)?;
    Ok(SealedSegment {
        nonce,
        ciphertext: ct,
    })
}

/// **Open** a segment sealed by [`seal_segment`]. The same `(kind, segment_id)`
/// must be supplied; a mismatch (or a wrong SEK, or tamper) fails with
/// [`Error::AtRestUnlockFailed`] — so a segment cannot be opened as the wrong kind
/// or in the wrong slot.
pub fn open_segment(
    sek: &Sek,
    kind: SegmentKind,
    segment_id: u64,
    sealed: &SealedSegment,
) -> Result<Vec<u8>> {
    if sealed.ciphertext.len() < TAG_LEN {
        return Err(Error::MalformedAtRest("segment ciphertext too short"));
    }
    // Post-lock open fails with `AtRestLocked` until re-auth (ADR-010).
    let cipher =
        Aes256Gcm::new_from_slice(sek.key_bytes()?).map_err(|_| Error::AtRestUnlockFailed)?;
    let aad = segment_aad(kind, segment_id);
    cipher
        .decrypt(
            Nonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::AtRestUnlockFailed)
}

/// Serialize a [`SealedSegment`] to canonical CBOR (array of 3:
/// `[version, nonce, ciphertext]`).
#[must_use]
pub fn sealed_segment_to_vec(seg: &SealedSegment) -> Vec<u8> {
    use crate::cbor::Encoder;
    let mut e = Encoder::new();
    e.array(3).uint(1).bytes(&seg.nonce).bytes(&seg.ciphertext);
    e.finish()
}

/// Parse a [`SealedSegment`] from canonical CBOR produced by
/// [`sealed_segment_to_vec`].
pub fn sealed_segment_from_slice(buf: &[u8]) -> Result<SealedSegment> {
    use crate::cbor::Decoder;
    let mut d = Decoder::new(buf);
    if d.array().map_err(Error::from)? != 3 {
        return Err(Error::MalformedAtRest("sealed segment arity"));
    }
    if d.uint().map_err(Error::from)? != 1 {
        return Err(Error::MalformedAtRest("sealed segment version"));
    }
    let nonce: [u8; NONCE_LEN] = d
        .bytes()
        .map_err(Error::from)?
        .try_into()
        .map_err(|_| Error::MalformedAtRest("sealed segment nonce length"))?;
    let ciphertext = d.bytes().map_err(Error::from)?.to_vec();
    d.finish().map_err(Error::from)?;
    Ok(SealedSegment { nonce, ciphertext })
}

/// A stored content object together with its CID (ADR-010 layer-1 adjacency). The
/// `object` is the author's exact `(nonce ‖ ciphertext)` bytes — already encrypted
/// by M4/M6; M8 only addresses and dedups it.
#[derive(Clone)]
pub struct ContentObject {
    cid: Cid,
    object: Vec<u8>,
}

impl ContentObject {
    /// Wrap an author content object, computing its CID.
    #[must_use]
    pub fn new(object: Vec<u8>) -> Self {
        let cid = content_id(&object);
        Self { cid, object }
    }

    /// The content id.
    #[must_use]
    pub fn cid(&self) -> &Cid {
        &self.cid
    }

    /// The exact author object bytes.
    #[must_use]
    pub fn object(&self) -> &[u8] {
        &self.object
    }

    /// Whether two objects de-duplicate (identical bytes ⇒ identical CID).
    #[must_use]
    pub fn dedups_with(&self, other: &ContentObject) -> bool {
        self.cid == other.cid
    }
}

impl Drop for ContentObject {
    fn drop(&mut self) {
        // The object is ciphertext (already encrypted by M4/M6), not a raw secret,
        // but wiping local copies is cheap defense-in-depth and matches the
        // crate's "leave nothing in freed memory" posture.
        self.object.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cid_dedups_identical_objects() {
        // Identical author objects (same nonce + ciphertext) => same CID (dedup).
        let mut obj = vec![0u8; NONCE_LEN];
        obj.extend_from_slice(b"author-ciphertext-bytes");
        let a = ContentObject::new(obj.clone());
        let b = ContentObject::new(obj);
        assert!(a.dedups_with(&b));
        assert_eq!(a.cid(), b.cid());
    }

    #[test]
    fn different_nonce_gives_different_cid() {
        let body = b"same-plaintext-different-nonce";
        let mut obj1 = vec![1u8; NONCE_LEN];
        obj1.extend_from_slice(body);
        let mut obj2 = vec![2u8; NONCE_LEN]; // only the nonce differs
        obj2.extend_from_slice(body);
        let a = ContentObject::new(obj1);
        let b = ContentObject::new(obj2);
        assert!(!a.dedups_with(&b));
        assert_ne!(a.cid(), b.cid());
    }

    #[test]
    fn segment_seal_open_round_trip() {
        let sek = Sek::generate().unwrap();
        let pt = b"a decrypted plaintext cache page (must stay sealed at rest)";
        let sealed = seal_segment(&sek, SegmentKind::PlaintextCache, 7, pt).unwrap();
        let got = open_segment(&sek, SegmentKind::PlaintextCache, 7, &sealed).unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn segment_kind_is_bound() {
        // A segment sealed as KeyMaterial cannot be opened as PlaintextCache.
        let sek = Sek::generate().unwrap();
        let sealed = seal_segment(&sek, SegmentKind::KeyMaterial, 1, b"sender-keys").unwrap();
        assert!(matches!(
            open_segment(&sek, SegmentKind::PlaintextCache, 1, &sealed),
            Err(Error::AtRestUnlockFailed)
        ));
    }

    #[test]
    fn segment_id_is_bound() {
        // A segment sealed at slot 1 cannot be opened at slot 2 (no relocation).
        let sek = Sek::generate().unwrap();
        let sealed = seal_segment(&sek, SegmentKind::Index, 1, b"index-page").unwrap();
        assert!(matches!(
            open_segment(&sek, SegmentKind::Index, 2, &sealed),
            Err(Error::AtRestUnlockFailed)
        ));
    }

    #[test]
    fn wrong_sek_fails() {
        let sek = Sek::generate().unwrap();
        let other = Sek::generate().unwrap();
        let sealed = seal_segment(&sek, SegmentKind::LogDb, 0, b"db").unwrap();
        assert!(matches!(
            open_segment(&other, SegmentKind::LogDb, 0, &sealed),
            Err(Error::AtRestUnlockFailed)
        ));
    }

    #[test]
    fn tampered_segment_fails() {
        let sek = Sek::generate().unwrap();
        let mut sealed = seal_segment(&sek, SegmentKind::LogDb, 0, b"db").unwrap();
        sealed.ciphertext[0] ^= 0x01;
        assert!(matches!(
            open_segment(&sek, SegmentKind::LogDb, 0, &sealed),
            Err(Error::AtRestUnlockFailed)
        ));
    }

    #[test]
    fn sealed_segment_round_trips_through_cbor() {
        let sek = Sek::generate().unwrap();
        let sealed = seal_segment(&sek, SegmentKind::Index, 3, b"payload").unwrap();
        let bytes = sealed_segment_to_vec(&sealed);
        let back = sealed_segment_from_slice(&bytes).unwrap();
        assert_eq!(sealed, back);
        assert_eq!(
            open_segment(&sek, SegmentKind::Index, 3, &back).unwrap(),
            b"payload"
        );
    }
}
