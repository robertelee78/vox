//! The rustls certificate verifiers of the **neutral handshake** (ADR-011 requirement 27): each
//! side holds the other only to a neutral daemon leaf
//! ([`crate::transport::identity_cert::check_neutral_leaf`]), and rustls checks, through the
//! provider's `verify_tls13_signature`, that the peer holds that leaf's key. Which node is behind
//! it is not a TLS question: the identity exchange ([`crate::transport::identity`]) proves it.
//!
//! Every failure is the same flattened `ApplicationVerificationFailure`, so a probe learns nothing
//! from which check failed.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};

// ---------------------------------------------------------------------------
// Neutral verifiers (ADR-011 requirement 27): the TLS handshake authenticates only the daemon.
// ---------------------------------------------------------------------------

/// Accept `end_entity` as a neutral daemon leaf (see
/// [`crate::transport::identity_cert::check_neutral_leaf`]): one self-signed Ed25519 leaf, no
/// chain. Every failure is the same flattened TLS error.
fn neutral(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
) -> Result<(), Error> {
    if !intermediates.is_empty() {
        return Err(Error::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ));
    }
    crate::transport::identity_cert::check_neutral_leaf(end_entity.as_ref())
        .map_err(|_| Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure))
}

/// The client-side verifier of a **neutral** handshake: the server proves it holds a neutral
/// daemon leaf and nothing more. Which node answered is proved by the identity exchange
/// ([`crate::transport::identity::dial`]), never here (ADR-011 requirements 27 and 37).
#[derive(Debug)]
pub struct NeutralServerVerifier {
    supported: WebPkiSupportedAlgorithms,
}

impl NeutralServerVerifier {
    /// A verifier over the provider's signature algorithms.
    #[must_use]
    pub fn new(supported: WebPkiSupportedAlgorithms) -> Self {
        Self { supported }
    }
}

impl ServerCertVerifier for NeutralServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        neutral(end_entity, intermediates)?;
        Ok(ServerCertVerified::assertion())
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

/// The server-side verifier of a **neutral** handshake. A client certificate stays mandatory:
/// the listener needs the dialler's daemon leaf for the dialler's process identity,
/// `sha256(leaf ‖ instance)` (ADR-011 requirement 35).
#[derive(Debug)]
pub struct NeutralClientVerifier {
    supported: WebPkiSupportedAlgorithms,
}

impl NeutralClientVerifier {
    /// A verifier over the provider's signature algorithms.
    #[must_use]
    pub fn new(supported: WebPkiSupportedAlgorithms) -> Self {
        Self { supported }
    }
}

impl ClientCertVerifier for NeutralClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        neutral(end_entity, intermediates)?;
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
