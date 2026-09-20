//! Custom rustls certificate verifiers that authenticate a peer by its Vox
//! composite identity instead of a CA chain (ADR-011 §"Identity authentication
//! (libp2p-style, no CA/PKI)").
//!
//! rustls always performs the TLS-level handshake-signature check via the crypto
//! provider; these verifiers add the Vox layer on top:
//! 1. They do **not** consult any CA root store (there is none).
//! 2. They run [`super::identity_cert::verify_peer_certificate`] to recover the
//!    peer's authenticated [`CompositePublicKey`] from the leaf's identity
//!    extension + composite PoP.
//! 3. They require the recovered identity's fingerprint to equal the
//!    **expected peer** (when one is pinned), aborting on mismatch — the
//!    [`crate::wire::WireError::AuthenticatorInvalid`] (`0x05`) case of ADR-011.
//! 4. They still delegate the TLS 1.3 handshake-signature verification to
//!    `rustls::crypto::verify_tls13_signature` with the provider's supported
//!    algorithms, so the cert key actually owns the handshake.
//!
//! The recovered fingerprint of a *completed* handshake is published through a
//! shared cell ([`VerifiedPeer`]) so the connecting code can read who it talked
//! to and record the session-establishment entry (tag `0x0011`).
//!
//! ## Why all failures collapse to one TLS error
//! A missing extension, a malformed extension, a bad PoP, and a wrong-but-valid
//! identity all surface to rustls as `CertificateError::ApplicationVerificationFailure`.
//! That deliberate flattening means a network probe cannot distinguish "this peer
//! has no Vox identity" from "this peer is the wrong Vox identity" — the same
//! single-error discipline ADR-005's join PoP and ADR-010's at-rest unlock use.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};

use crate::hash::Digest32;
use crate::identity::composite::CompositePublicKey;
use crate::transport::identity_cert::verify_peer_certificate;

/// A shared, write-once slot that records the peer identity a verifier
/// authenticated, so the connecting side can read it after the handshake.
///
/// Each connection gets its own [`VerifiedPeer`]; the verifier writes the
/// recovered fingerprint on success and the connecting code reads it to build the
/// session-establishment record and to confirm the expected peer at the
/// application layer too.
#[derive(Clone, Debug, Default)]
pub struct VerifiedPeer {
    inner: Arc<Mutex<Option<Digest32>>>,
}

impl VerifiedPeer {
    /// A fresh, empty slot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The authenticated peer fingerprint, if the handshake completed and the
    /// verifier accepted it.
    #[must_use]
    pub fn fingerprint(&self) -> Option<Digest32> {
        // A poisoned lock can only happen if a verifier panicked while holding it;
        // our verifiers never panic, so recover the inner value rather than
        // propagating (this is read-only observation).
        self.inner.lock().map_or(None, |g| *g)
    }

    fn set(&self, fp: Digest32) {
        if let Ok(mut g) = self.inner.lock() {
            *g = Some(fp);
        }
    }
}

/// Who a verifier requires the peer to be.
#[derive(Clone, Debug)]
enum Expectation {
    /// The peer must present this exact identity fingerprint (initiator dialing a
    /// known peer).
    Pinned(Digest32),
    /// Any well-formed Vox identity is accepted (a responder that does not yet know
    /// who is dialing); the authenticated fingerprint is still recorded.
    AnyVoxIdentity,
}

/// Authenticate `cert` as a Vox peer: recover the identity from the extension +
/// PoP, enforce the expectation, and publish the fingerprint. Returns the rustls
/// flattened error on any failure.
fn authenticate(
    cert: &CertificateDer<'_>,
    expect: &Expectation,
    out: &VerifiedPeer,
) -> Result<Digest32, Error> {
    let identity: CompositePublicKey = verify_peer_certificate(cert.as_ref())
        .map_err(|_| Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))?;
    let fp = identity.fingerprint();
    match expect {
        Expectation::Pinned(expected) if &fp != expected => {
            // Wrong identity: collapse to the same error as "no identity".
            return Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        _ => {}
    }
    out.set(fp);
    Ok(fp)
}

// ---------------------------------------------------------------------------
// Client-side: verify the *server's* certificate.
// ---------------------------------------------------------------------------

/// The client-side verifier (authenticates the server we dialed).
#[derive(Debug)]
pub struct VoxServerCertVerifier {
    supported: WebPkiSupportedAlgorithms,
    expect: Expectation,
    verified: VerifiedPeer,
}

impl VoxServerCertVerifier {
    /// A verifier pinning the server to `expected_peer` (the dialer knows whom it
    /// wants to reach). `verified` receives the authenticated fingerprint.
    #[must_use]
    pub fn pinned(
        supported: WebPkiSupportedAlgorithms,
        expected_peer: Digest32,
        verified: VerifiedPeer,
    ) -> Self {
        Self {
            supported,
            expect: Expectation::Pinned(expected_peer),
            verified,
        }
    }
}

impl ServerCertVerifier for VoxServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        authenticate(end_entity, &self.expect, &self.verified)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // Vox transport is TLS 1.3 only (the configs pin TLS13). A 1.2 signature
        // request should never arrive; refuse rather than accept.
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Server-side: verify the *client's* certificate.
// ---------------------------------------------------------------------------

/// The server-side verifier (authenticates a client that dialed us). Mutual TLS
/// is mandatory in Vox: both directions present and prove a Vox identity.
#[derive(Debug)]
pub struct VoxClientCertVerifier {
    supported: WebPkiSupportedAlgorithms,
    expect: Expectation,
    verified: VerifiedPeer,
}

impl VoxClientCertVerifier {
    /// A verifier that accepts any well-formed Vox identity (the listener does not
    /// pin who may connect; the application layer applies admission/consent after
    /// authentication). `verified` receives the authenticated fingerprint.
    #[must_use]
    pub fn any_identity(supported: WebPkiSupportedAlgorithms, verified: VerifiedPeer) -> Self {
        Self {
            supported,
            expect: Expectation::AnyVoxIdentity,
            verified,
        }
    }

    /// A verifier that pins the connecting client to `expected_peer`.
    #[must_use]
    pub fn pinned(
        supported: WebPkiSupportedAlgorithms,
        expected_peer: Digest32,
        verified: VerifiedPeer,
    ) -> Self {
        Self {
            supported,
            expect: Expectation::Pinned(expected_peer),
            verified,
        }
    }
}

impl ClientCertVerifier for VoxClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No CA roots — authentication is by the Vox identity extension.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        authenticate(end_entity, &self.expect, &self.verified)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}
