//! The **neutral daemon leaf** (ADR-011 requirements 27 and 37, ADR-026): the TLS certificate a
//! Vox daemon presents on every connection of one run, for every node it hosts.
//!
//! It carries no Vox identity. Until v0.3.0 each node's leaf carried its composite identity in a
//! custom X.509 extension with a proof of possession, so the TLS handshake said which node
//! answered; one endpoint serving several nodes cannot do that without showing on the path which
//! node a dialler wants. The node is now proved inside the connection by the identity exchange
//! ([`crate::transport::identity`]), bound to this TLS session by its exporter, and no
//! certificate names anyone. The extension, its OID arc and its tag (`0x0009`) apply to nothing.

use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use x509_parser::prelude::{FromDer as _, X509Certificate};

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// The neutral daemon leaf (ADR-011 requirements 27 and 37, ADR-026).
// ---------------------------------------------------------------------------

/// The ASN.1 OID of Ed25519 (RFC 8410), dotted: the only key a neutral leaf may carry.
const ED25519_OID_DOTTED: &str = "1.3.101.112";

/// A **neutral** TLS leaf: self-signed Ed25519, no extension, no name, no Vox identity
/// (ADR-011 requirement 27). One daemon run generates one and offers it on every connection of
/// that run, for every node it hosts: the TLS handshake authenticates only the daemon, and which
/// node a connection is to is proved afterwards by the identity exchange
/// ([`crate::transport::identity`]), bound to this TLS session by its exporter.
///
/// Nothing in it names anyone, so a path observer who reads it (it travels encrypted under TLS
/// 1.3's handshake keys, but a peer sees it) learns only that a daemon answered. Its digest
/// still matters: a peer's remote-process identity is `sha256(leaf ‖ instance)` (ADR-026 I-3).
pub struct NeutralLeaf {
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
}

impl NeutralLeaf {
    /// The certificate chain (a single self-signed leaf) for the TLS config.
    #[must_use]
    pub fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![self.cert_der.clone()]
    }

    /// The leaf's private key for the TLS config.
    #[must_use]
    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        self.key_der.clone_key()
    }

    /// The leaf's DER bytes, which a peer hashes into this daemon's process identity.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        self.cert_der.as_ref()
    }
}

/// Build a fresh neutral leaf: an Ed25519 key, a self-signature, an empty subject, and no
/// extension of any kind (ADR-011 requirement 27).
///
/// # Errors
/// [`Error::SigningFailed`] if the key cannot be generated or the certificate cannot be signed.
pub fn build_neutral_leaf() -> Result<NeutralLeaf> {
    let key_pair = KeyPair::generate_for(&PKCS_ED25519).map_err(|_| Error::SigningFailed)?;
    let mut params =
        CertificateParams::new(Vec::<String>::new()).map_err(|_| Error::SigningFailed)?;
    // rcgen names a default subject ("rcgen self signed cert"); a neutral leaf names nothing.
    params.distinguished_name = rcgen::DistinguishedName::new();
    let cert = params
        .self_signed(&key_pair)
        .map_err(|_| Error::SigningFailed)?;
    let key_der =
        PrivateKeyDer::try_from(key_pair.serialize_der()).map_err(|_| Error::SigningFailed)?;
    Ok(NeutralLeaf {
        cert_der: CertificateDer::from(cert.der().to_vec()),
        key_der,
    })
}

/// Check that `cert_der` is a leaf a neutral verifier accepts: one well-formed certificate
/// whose key is Ed25519 and whose self-signature verifies under that key.
///
/// It proves nothing about who the peer is — the TLS handshake's own signature (checked by
/// rustls) proves the peer holds this key, and the identity exchange says which node it is. The
/// checks keep the leaf to the one shape every Vox daemon makes, so a parser downstream (the
/// process-identity digest) never meets anything else.
///
/// # Errors
/// [`Error::SignatureInvalid`] for anything else.
pub fn check_neutral_leaf(cert_der: &[u8]) -> Result<()> {
    let (rest, cert) = X509Certificate::from_der(cert_der).map_err(|_| Error::SignatureInvalid)?;
    if !rest.is_empty() {
        return Err(Error::SignatureInvalid);
    }
    let spki = cert.public_key();
    if spki.algorithm.algorithm.to_id_string() != ED25519_OID_DOTTED
        || cert.signature_algorithm.algorithm.to_id_string() != ED25519_OID_DOTTED
    {
        return Err(Error::SignatureInvalid);
    }
    let key: [u8; 32] = spki
        .subject_public_key
        .data
        .as_ref()
        .try_into()
        .map_err(|_| Error::SignatureInvalid)?;
    let sig: [u8; 64] = cert
        .signature_value
        .data
        .as_ref()
        .try_into()
        .map_err(|_| Error::SignatureInvalid)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| Error::SignatureInvalid)?;
    key.verify_strict(
        cert.tbs_certificate.as_ref(),
        &ed25519_dalek::Signature::from_bytes(&sig),
    )
    .map_err(|_| Error::SignatureInvalid)
}
