//! The post-quantum-only rustls crypto provider and the quinn client/server
//! config builders (ADR-011 §"Transport security (concrete)").
//!
//! ## The single Rust-maximal exception (ADR-001 #10)
//! Vox is a Rust-maximal codebase and the *application* crypto is RustCrypto.
//! The TLS crypto **provider** here is the one unavoidable exception: rustls's
//! `aws-lc-rs` provider (a C/asm AWS-LC backend) is what currently supplies the
//! X25519MLKEM768 hybrid group named by ADR-011, and a Rust-pure provider for that
//! group does not exist in the ecosystem. This is the universal Rust-TLS reality,
//! it is scoped to the transport handshake only, and `#![forbid(unsafe_code)]`
//! still holds in *our* crate (the unsafe lives in the dependency). No application
//! key, message key, or log authenticator ever touches this provider.
//!
//! ## No downgrade target
//! The provider's `kx_groups` is pinned to exactly `[X25519MLKEM768]` (TLS code
//! point `0x11EC`). A classical-only peer offers no group we accept and the
//! handshake fails with a clear error — there is no silent fallback (ADR-011
//! §"Interop is a release criterion, and failure is hard").
//!
//! ## 0-RTT disabled
//! rustls defaults to no early data on both sides (`enable_early_data = false`,
//! `max_early_data_size = 0`); the builders here additionally set
//! `max_early_data_size = 0` and disable session tickets explicitly, so 0-RTT is
//! never offered or accepted (ADR-011 §"0-RTT is disabled").

use std::sync::Arc;

use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::aws_lc_rs;
use rustls::crypto::CryptoProvider;
use rustls::server::danger::ClientCertVerifier;
use rustls::{ClientConfig, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::{Error, Result};

/// The TLS named group Vox negotiates (and the only one it offers): the
/// X25519+ML-KEM-768 hybrid, TLS code point `0x11EC` (ADR-011 / ADR-003
/// `TLS_X25519MLKEM768`). Recorded in every session-establishment entry.
pub const X25519MLKEM768_CODE_POINT: u16 = 0x11EC;

/// The ALPN protocol identifier for the Vox transport. Pinning an ALPN ensures a
/// Vox endpoint never completes a handshake with a non-Vox QUIC service that
/// happened to share the port.
pub const VOX_ALPN: &[u8] = b"vox/1";

/// Build the Vox crypto provider: the `aws-lc-rs` provider with `kx_groups`
/// restricted to exactly the X25519MLKEM768 hybrid group, so there is no classical
/// downgrade target.
#[must_use]
pub fn vox_crypto_provider() -> CryptoProvider {
    CryptoProvider {
        kx_groups: vec![rustls_post_quantum::X25519MLKEM768],
        ..aws_lc_rs::default_provider()
    }
}

/// Assert the single-group invariant on a provider before it is wired into a TLS
/// config: its `kx_groups` MUST be exactly `[X25519MLKEM768]`.
///
/// Because quinn/rustls does not surface the *negotiated* named group to the
/// application, the audit record cannot independently observe which group a session
/// used (see [`crate::transport::session`]); the security guarantee instead rests
/// on (a) offering only the hybrid group — checked here — and (b) TLS 1.3's
/// Finished MAC binding the negotiated group. Calling this at **every** config
/// construction boundary means a future regression that widened the offered groups
/// (e.g. dropping the explicit `kx_groups` override) fails loudly here rather than
/// silently shipping a classical downgrade target. A non-panicking hard error
/// keeps the crate's no-panic discipline.
fn assert_pq_only(provider: &CryptoProvider) -> Result<()> {
    let only_hybrid = provider.kx_groups.len() == 1
        && u16::from(provider.kx_groups[0].name()) == X25519MLKEM768_CODE_POINT;
    if only_hybrid {
        Ok(())
    } else {
        Err(Error::MalformedBundle(
            "tls provider offers a non-hybrid kx group (downgrade target)",
        ))
    }
}

/// Build a rustls [`ClientConfig`] over the PQ-only provider: TLS 1.3 only, the
/// supplied Vox server-cert verifier, our own client leaf for mutual auth, ALPN
/// pinned, and 0-RTT off.
///
/// The single-group invariant is asserted (`assert_pq_only`) before the provider
/// is used, so there is no classical downgrade target.
pub fn client_config(
    verifier: Arc<dyn ServerCertVerifier>,
    client_cert_chain: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
) -> Result<ClientConfig> {
    let provider = vox_crypto_provider();
    assert_pq_only(&provider)?;
    let provider = Arc::new(provider);
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::MalformedBundle("tls client provider/version setup"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(single_cert_resolver(client_cert_chain, client_key)?);
    cfg.alpn_protocols = vec![VOX_ALPN.to_vec()];
    // Never offer 0-RTT early data (ADR-011).
    cfg.enable_early_data = false;
    Ok(cfg)
}

/// Build a rustls [`ServerConfig`] over the PQ-only provider: TLS 1.3 only, the
/// supplied Vox client-cert verifier (mutual auth mandatory), our own server leaf,
/// ALPN pinned, and 0-RTT off (no early data, no session tickets).
///
/// The single-group invariant is asserted (`assert_pq_only`) before the provider
/// is used, so there is no classical downgrade target.
pub fn server_config(
    verifier: Arc<dyn ClientCertVerifier>,
    server_cert_chain: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
) -> Result<ServerConfig> {
    let provider = vox_crypto_provider();
    assert_pq_only(&provider)?;
    let provider = Arc::new(provider);
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::MalformedBundle("tls server provider/version setup"))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_cert_chain, server_key)
        .map_err(|_| Error::MalformedBundle("tls server certificate setup"))?;
    cfg.alpn_protocols = vec![VOX_ALPN.to_vec()];
    // Belt-and-suspenders 0-RTT disable: no early data, and issue no resumption
    // tickets at all (a ticket is a prerequisite for 0-RTT) — ADR-011.
    cfg.max_early_data_size = 0;
    cfg.send_tls13_tickets = 0;
    Ok(cfg)
}

/// A `ResolvesClientCert` that always presents the single Vox leaf. Vox always
/// performs mutual auth, so the client unconditionally offers its identity cert.
fn single_cert_resolver(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<dyn rustls::client::ResolvesClientCert>> {
    let signing_key = vox_crypto_provider()
        .key_provider
        .load_private_key(key)
        .map_err(|_| Error::MalformedBundle("tls client key load"))?;
    let certified = Arc::new(rustls::sign::CertifiedKey::new(chain, signing_key));
    Ok(Arc::new(AlwaysResolvesClientCert(certified)))
}

/// Presents a fixed client certificate on every request (mutual auth always on).
#[derive(Debug)]
struct AlwaysResolvesClientCert(Arc<rustls::sign::CertifiedKey>);

impl rustls::client::ResolvesClientCert for AlwaysResolvesClientCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_offers_only_the_hybrid_group() {
        let p = vox_crypto_provider();
        assert_eq!(p.kx_groups.len(), 1, "exactly one kx group");
        let only = p.kx_groups[0];
        let code: u16 = u16::from(only.name());
        assert_eq!(
            code, X25519MLKEM768_CODE_POINT,
            "the single offered group must be X25519MLKEM768 (0x11EC)"
        );
    }

    #[test]
    fn code_point_matches_adr003_registry() {
        // ADR-003's TLS group constant is the same 0x11EC wire code point.
        assert_eq!(X25519MLKEM768_CODE_POINT, 0x11EC);
    }

    #[test]
    fn assert_pq_only_accepts_the_vox_provider() {
        assert!(assert_pq_only(&vox_crypto_provider()).is_ok());
    }

    #[test]
    fn assert_pq_only_rejects_a_widened_provider() {
        // A provider that still offers a classical group is a downgrade target and
        // must be rejected at the config boundary (catches a future regression).
        let widened = aws_lc_rs::default_provider(); // includes classical groups
        assert!(widened.kx_groups.len() > 1);
        assert!(matches!(
            assert_pq_only(&widened),
            Err(Error::MalformedBundle(_))
        ));
    }

    #[test]
    fn assert_pq_only_rejects_a_classical_only_provider() {
        let classical = aws_lc_rs::default_provider()
            .kx_groups
            .into_iter()
            .find(|g| u16::from(g.name()) == 0x001D)
            .map(|g| CryptoProvider {
                kx_groups: vec![g],
                ..aws_lc_rs::default_provider()
            })
            .expect("classical X25519 available");
        assert!(matches!(
            assert_pq_only(&classical),
            Err(Error::MalformedBundle(_))
        ));
    }
}
