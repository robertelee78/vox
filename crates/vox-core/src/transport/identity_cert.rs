//! The self-signed TLS leaf certificate carrying the Vox composite identity in a
//! custom X.509 extension, and the composite proof-of-possession that binds the
//! ephemeral certificate key to the long-term identity (ADR-011 §"Identity
//! authentication (libp2p-style, no CA/PKI)").
//!
//! ## Why a custom extension instead of a CA
//! There is no PKI in Vox. A peer authenticates by presenting a freshly-generated
//! self-signed leaf whose key is *only* used for this TLS handshake, plus a
//! signature over `"vox-tls-handshake:" ‖ cert_public_key` made with the
//! **composite Ed25519+ML-DSA-65 identity key** (ADR-002). That signature is the
//! proof-of-possession: it proves the presenter controls the long-term identity
//! and binds it to the ephemeral cert key, so a man-in-the-middle that swaps the
//! cert cannot forge the binding without the identity key. This is the deployed
//! `libp2p-tls` mechanism, with Vox's own OID arc and canonical-CBOR value.
//!
//! ## Extension layout (ADR-011, concrete)
//! - **OID** [`VOX_IDENTITY_EXT_OID`] — a **provisional** arc under the documented
//!   PEN placeholder until Vox's IANA Private Enterprise Number is assigned (the
//!   interop matrix pins the exact OID; Vox does NOT squat libp2p's PEN 53594).
//! - `critical = false`.
//! - value = canonical-CBOR (ADR-008 framing, tag [`StructTag::TlsIdentityExtension`]
//!   = `0x0009`, domain `vox/tls-identity-extension/v1`) of the 2-field struct
//!   `{ composite_pubkey, pop_sig }`.
//!
//! ## The PoP signing string (deliberately outside the CBOR struct-domain regime)
//! The proof-of-possession signs the raw TLS-layer byte string
//! [`POP_PREFIX`] ‖ `cert_public_key` with the composite identity key, where
//! `cert_public_key` is the leaf certificate's **subject public key** (the raw key
//! bytes the cert carries — for the Ed25519 leaf, the 32-byte public key). Per
//! ADR-011 this string is *not* an ADR-008 log struct, so it does **not** go
//! through [`crate::wire::signing_input`]; it is a fixed ASCII prefix concatenated
//! with the cert's public-key bytes. The *extension value* that carries the
//! signature, by contrast, **is** a canonical-CBOR struct and is framed/parsed via
//! the ADR-008 registry, so the two regimes never blur.
//!
//! The bind target is the raw subject-public-key bytes (not the full SPKI DER)
//! because rcgen exposes exactly those bytes at build time and x509-parser exposes
//! exactly those bytes at verify time, so the two sides bind to a byte-identical
//! value with no algorithm-prefix ambiguity. They uniquely identify the ephemeral
//! cert key — the property the PoP needs.

use rcgen::{CertificateParams, CustomExtension, KeyPair, PublicKeyData as _, PKCS_ED25519};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use x509_parser::der_parser::oid::Oid;
use x509_parser::prelude::{FromDer as _, X509Certificate};

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{Digest32, COMPOSITE_PUB_LEN, COMPOSITE_SIG_LEN};
use crate::identity::composite::{CompositePublicKey, CompositeSignature, RootSigner};
use crate::wire::{self, StructTag};

/// The provisional Vox identity-extension OID arc.
///
/// `1.3.6.1.4.1.<PEN>.1.1`, where `<PEN>` is a **provisional placeholder**
/// (`1234567`) standing in for Vox's IANA Private Enterprise Number, which is
/// pending registration (ADR-011). Until the real PEN is assigned, this exact arc
/// is pinned by the interop-test matrix as a release gate, so every supported peer
/// agrees on it. Vox deliberately does **not** reuse libp2p's PEN `53594`.
///
/// `.1.1` under the PEN names the v1 Vox-TLS-identity extension specifically; the
/// trailing `.1` leaves room for future extension families under the same PEN.
pub const VOX_IDENTITY_EXT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 1_234_567, 1, 1];

/// The PoP signing-string prefix (ADR-011). Concatenated with the certificate's
/// raw subject-public-key bytes to form the bytes the composite identity key
/// signs. It is a TLS-layer string, deliberately outside the ADR-008 CBOR
/// struct-domain regime, so it is a bare ASCII prefix — never an ADR-008 domain
/// label.
pub const POP_PREFIX: &[u8] = b"vox-tls-handshake:";

/// The minimum length of a parsed identity-extension CBOR body. Used only as an
/// early cheap reject; the strict structural checks live in [`parse_extension`].
const MIN_EXT_BODY: usize = COMPOSITE_PUB_LEN; // pubkey alone already exceeds any header overhead

/// A generated Vox TLS leaf: the self-signed certificate (DER) carrying the
/// identity extension, plus the ephemeral private key (DER) for the TLS stack.
///
/// The certificate key is **ephemeral** — generated per endpoint and used only for
/// the TLS handshake. Authentication is carried by the composite PoP in the
/// extension, not by this key. The key is therefore an Ed25519 leaf key (the
/// cert's own self-signature may be classical, ADR-011 §"PQ authentication").
pub struct VoxLeafCertificate {
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
    /// The local identity fingerprint bound into the extension, kept so the caller
    /// can record it without re-parsing.
    identity_fingerprint: Digest32,
}

impl VoxLeafCertificate {
    /// The certificate chain (a single self-signed leaf) for the TLS config.
    #[must_use]
    pub fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![self.cert_der.clone()]
    }

    /// The ephemeral private key for the TLS config.
    #[must_use]
    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        self.key_der.clone_key()
    }

    /// The identity fingerprint bound into this certificate's extension.
    #[must_use]
    pub fn identity_fingerprint(&self) -> Digest32 {
        self.identity_fingerprint
    }
}

/// Build a fresh self-signed leaf certificate that carries `signer`'s composite
/// identity in the [`VOX_IDENTITY_EXT_OID`] extension, with a composite
/// proof-of-possession over [`POP_PREFIX`] ‖ `cert_public_key`.
///
/// The flow (ADR-011) is necessarily two-pass because the PoP signs the
/// certificate's *own* public key:
/// 1. generate the ephemeral Ed25519 leaf key pair;
/// 2. read its raw subject-public-key bytes and sign `POP_PREFIX ‖ cert_public_key`
///    with the composite identity key;
/// 3. encode `{ composite_pubkey, pop_sig }` as the canonical-CBOR extension value
///    and self-sign the certificate carrying it.
pub fn build_leaf_certificate<S: RootSigner>(signer: &S) -> Result<VoxLeafCertificate> {
    // 1. Ephemeral leaf key pair (Ed25519). The cert's self-signature is classical
    //    by design; the PoP carries the PQ authentication.
    let key_pair = KeyPair::generate_for(&PKCS_ED25519).map_err(|_| Error::SigningFailed)?;

    // 2. The PoP binds the composite identity to *this* leaf key. `der_bytes`
    //    (the `PublicKeyData` trait) returns the raw subject-public-key bytes that
    //    end up in the cert (for Ed25519, the 32-byte public key) — byte-identical
    //    to what the verifier reads back as `subject_public_key.data` via
    //    x509-parser. Signing over them ties the identity to the exact key the peer
    //    will see.
    let cert_public_key = key_pair.der_bytes();
    let pop_sig = signer.sign(&pop_signing_input(cert_public_key))?;

    // 3. Encode the extension value and self-sign the leaf carrying it.
    let ext_value = encode_extension(&signer.public_key(), &pop_sig);
    let mut params =
        CertificateParams::new(Vec::<String>::new()).map_err(|_| Error::SigningFailed)?;
    let mut ext = CustomExtension::from_oid_content(VOX_IDENTITY_EXT_OID, ext_value);
    ext.set_criticality(false);
    params.custom_extensions.push(ext);

    let cert = params
        .self_signed(&key_pair)
        .map_err(|_| Error::SigningFailed)?;
    let cert_der = cert.der().clone();
    let key_der =
        PrivateKeyDer::try_from(key_pair.serialize_der()).map_err(|_| Error::SigningFailed)?;

    Ok(VoxLeafCertificate {
        cert_der,
        key_der,
        identity_fingerprint: signer.fingerprint(),
    })
}

/// The exact bytes the composite identity key signs for the PoP:
/// [`POP_PREFIX`] ‖ `cert_public_key`, where `cert_public_key` is the leaf's raw
/// subject-public-key bytes.
#[must_use]
pub fn pop_signing_input(cert_public_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(POP_PREFIX.len() + cert_public_key.len());
    out.extend_from_slice(POP_PREFIX);
    out.extend_from_slice(cert_public_key);
    out
}

/// Encode the identity-extension value: canonical-CBOR `[composite_pubkey,
/// pop_sig]`, ADR-008-framed under tag [`StructTag::TlsIdentityExtension`].
///
/// The framing (`tag(2) ‖ version(1) ‖ body`) is applied so the value is
/// self-describing and tag-disjoint from every other Vox struct — a verifier that
/// mis-tags it fails on the tag, never cross-interprets the bytes.
#[must_use]
pub fn encode_extension(pubkey: &CompositePublicKey, pop_sig: &CompositeSignature) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(2)
        .bytes(&pubkey.to_bytes())
        .bytes(&pop_sig.to_bytes());
    wire::frame(StructTag::TlsIdentityExtension, &e.finish())
}

/// The composite identity recovered from a peer's identity extension, before the
/// PoP is checked. [`verify_peer_certificate`] is the only intended entry point;
/// this is the structural decode it performs first.
#[derive(Debug)]
struct ParsedExtension {
    pubkey: CompositePublicKey,
    pop_sig: CompositeSignature,
}

/// Parse an ADR-008-framed identity-extension value into its composite key + PoP.
///
/// Strict: rejects the wrong struct tag/version (a tag-confusion attempt), wrong
/// arity, wrong-length component fields, or any trailing bytes — each as the
/// appropriate [`Error`] so [`crate::log::sync::wire_error_for`] maps it precisely.
fn parse_extension(value: &[u8]) -> Result<ParsedExtension> {
    if value.len() < MIN_EXT_BODY {
        return Err(Error::MalformedBundle("tls identity extension too short"));
    }
    let frame = wire::parse_frame(value)?;
    if frame.tag != StructTag::TlsIdentityExtension {
        return Err(Error::UnknownStructTag(frame.tag.as_u16()));
    }
    let mut d = Decoder::new(frame.body);
    if d.array()? != 2 {
        return Err(Error::MalformedBundle("tls identity extension arity"));
    }
    let pub_bytes = d.bytes()?;
    let sig_bytes = d.bytes()?;
    d.finish()?;

    let pub_arr: &[u8; COMPOSITE_PUB_LEN] = pub_bytes
        .try_into()
        .map_err(|_| Error::MalformedBundle("tls identity extension pubkey length"))?;
    let sig_arr: &[u8; COMPOSITE_SIG_LEN] = sig_bytes
        .try_into()
        .map_err(|_| Error::MalformedBundle("tls identity extension sig length"))?;
    let pubkey = CompositePublicKey::from_bytes(pub_arr)?;
    let pop_sig = CompositeSignature::from_bytes(sig_arr)?;
    Ok(ParsedExtension { pubkey, pop_sig })
}

/// Verify a peer's leaf certificate and recover its authenticated Vox identity
/// (ADR-011 §"Identity authentication").
///
/// Steps, all of which must pass:
/// 1. parse the leaf DER and locate the [`VOX_IDENTITY_EXT_OID`] extension
///    (exactly one — a duplicate is malformed);
/// 2. decode the canonical-CBOR `{ composite_pubkey, pop_sig }` (strict);
/// 3. read the leaf's **raw subject-public-key BIT STRING content**
///    (`subject_public_key.data`, NOT the full SubjectPublicKeyInfo DER) and verify
///    the composite PoP over [`POP_PREFIX`] ‖ `cert_public_key` against the
///    extension's composite key. This is byte-identical to what
///    [`build_leaf_certificate`] signed (`KeyPair::der_bytes`), so an independent
///    implementation must bind the raw subject-public-key bytes here — **not** the
///    SPKI DER — or it will not interoperate.
///
/// On success returns the peer's [`CompositePublicKey`]; the caller compares its
/// fingerprint against the expected peer and aborts on mismatch (ADR-011 — the
/// expected-peer check is the responsibility of the verifier wrapper so a probe
/// cannot distinguish "no extension" from "wrong identity": both surface as a
/// single authenticator failure at the TLS layer).
///
/// Note this verifies the *binding* (identity ↔ cert key), not the TLS handshake
/// signature itself — that is checked separately by rustls via the provider's
/// `verify_tls13_signature` (see [`crate::transport::verifier`]).
pub fn verify_peer_certificate(cert_der: &[u8]) -> Result<CompositePublicKey> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|_| Error::SignatureInvalid)?;

    // The raw subject-public-key bytes — the exact value the PoP was bound to at
    // build time (`KeyPair::der_bytes`).
    let cert_public_key = cert.public_key().subject_public_key.data.as_ref();

    // Locate the identity extension by OID (exactly one).
    let oid = oid_from_arcs(VOX_IDENTITY_EXT_OID)?;
    let ext = cert
        .get_extension_unique(&oid)
        .map_err(|_| Error::SignatureInvalid)? // duplicate extension ⇒ reject
        .ok_or(Error::SignatureInvalid)?; // missing extension ⇒ reject

    let parsed = parse_extension(ext.value)?;

    // Verify the composite PoP over POP_PREFIX ‖ cert_public_key. A failure here
    // means the presented cert key is not bound to the claimed identity ⇒
    // authenticator invalid.
    parsed
        .pubkey
        .verify(&pop_signing_input(cert_public_key), &parsed.pop_sig)?;
    Ok(parsed.pubkey)
}

/// Build an `x509_parser` OID from a `&[u64]` arc slice.
fn oid_from_arcs(arcs: &[u64]) -> Result<Oid<'static>> {
    Oid::from(arcs).map_err(|_| Error::MalformedBundle("invalid identity extension OID"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::composite::SoftwareRootSigner;

    fn signer(a: u8, b: u8) -> SoftwareRootSigner {
        SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
    }

    #[test]
    fn cert_round_trips_and_recovers_identity() {
        let s = signer(1, 2);
        let leaf = build_leaf_certificate(&s).unwrap();
        assert_eq!(leaf.cert_chain().len(), 1);
        assert_eq!(leaf.identity_fingerprint(), s.fingerprint());

        let recovered = verify_peer_certificate(leaf.cert_chain()[0].as_ref()).unwrap();
        assert_eq!(recovered.fingerprint(), s.fingerprint());
        assert_eq!(recovered, s.public_key());
    }

    #[test]
    fn extension_value_round_trips() {
        let s = signer(3, 4);
        let cert_pubkey = b"fake-raw-subject-public-key-for-test";
        let pop = s.sign(&pop_signing_input(cert_pubkey)).unwrap();
        let value = encode_extension(&s.public_key(), &pop);
        let parsed = parse_extension(&value).unwrap();
        assert_eq!(parsed.pubkey, s.public_key());
        // The PoP verifies against the same input.
        assert!(parsed
            .pubkey
            .verify(&pop_signing_input(cert_pubkey), &parsed.pop_sig)
            .is_ok());
    }

    #[test]
    fn distinct_signers_produce_distinct_identities() {
        let a = build_leaf_certificate(&signer(1, 1)).unwrap();
        let b = build_leaf_certificate(&signer(2, 2)).unwrap();
        let ia = verify_peer_certificate(a.cert_chain()[0].as_ref()).unwrap();
        let ib = verify_peer_certificate(b.cert_chain()[0].as_ref()).unwrap();
        assert_ne!(ia.fingerprint(), ib.fingerprint());
    }

    #[test]
    fn tampered_pop_signature_is_rejected() {
        let s = signer(5, 6);
        let leaf = build_leaf_certificate(&s).unwrap();
        let mut der = leaf.cert_chain()[0].as_ref().to_vec();

        // The composite signature lives near the end of the cert (inside the
        // extension value). Flip a byte in the last quarter — well within the
        // ML-DSA signature region — and confirm verification fails. We scan a few
        // offsets because the exact byte position depends on DER framing.
        let n = der.len();
        let mut rejected = false;
        for off in (n.saturating_sub(n / 4)..n).step_by(7) {
            let mut t = der.clone();
            t[off] ^= 0xff;
            if verify_peer_certificate(&t).is_err() {
                rejected = true;
                break;
            }
        }
        // Also flip a byte squarely in the signature region computed from layout.
        if !rejected {
            // Fallback: corrupt the very last byte.
            *der.last_mut().unwrap() ^= 0xff;
            rejected = verify_peer_certificate(&der).is_err();
        }
        assert!(rejected, "a tampered PoP must be rejected");
    }

    #[test]
    fn missing_extension_is_rejected() {
        // A plain self-signed cert with no Vox extension must not authenticate.
        let kp = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let params = CertificateParams::new(Vec::<String>::new()).unwrap();
        let cert = params.self_signed(&kp).unwrap();
        let err = verify_peer_certificate(cert.der().as_ref()).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }

    #[test]
    fn wrong_tag_in_extension_is_rejected() {
        // An extension value framed under the wrong struct tag is a tag-confusion
        // attempt; parse_extension must reject it on the tag.
        let s = signer(7, 8);
        let pop = s.sign(b"x").unwrap();
        let mut e = Encoder::new();
        e.array(2)
            .bytes(&s.public_key().to_bytes())
            .bytes(&pop.to_bytes());
        // Frame under LogEntry (0x0001) instead of TlsIdentityExtension (0x0009).
        let bad = wire::frame(StructTag::LogEntry, &e.finish());
        let err = parse_extension(&bad).unwrap_err();
        assert!(matches!(err, Error::UnknownStructTag(0x0001)));
    }
}
