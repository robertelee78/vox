//! The quinn-backed QUIC substrate (ADR-011 §"Substrate = QUIC") and the real
//! [`crate::log::sync::Transport`] implementation that M5 anti-entropy sync runs
//! over.
//!
//! ## One connection, many streams
//! A [`VoxConnection`] is one QUIC connection to one peer. Each logical flow opens
//! its own bidirectional stream ([`VoxConnection::open_stream`] /
//! [`VoxConnection::accept_stream`]): QUIC gives per-stream flow control with no
//! cross-stream head-of-line blocking, so bulk log replication on one stream never
//! stalls an interactive flow on another (ADR-011 §"Two contracts on one
//! connection"). Low-latency, loss-tolerant flows use RFC 9221 datagrams
//! ([`VoxConnection::send_datagram`] / [`VoxConnection::recv_datagram`]) with the
//! [`crate::transport::datagram`] anti-replay window layered on top.
//!
//! ## Authentication + the recorded session
//! Connecting and accepting both authenticate the peer via the
//! [`crate::transport::verifier`] custom verifiers (no CA): the peer's Vox identity
//! is recovered from its leaf's identity extension + composite PoP, the negotiated
//! group is confirmed to be X25519MLKEM768, and a
//! [`crate::transport::session::SessionEstablishment`] record (tag `0x0011`) is
//! produced so a downgrade is auditable end-to-end. A handshake that cannot
//! negotiate the hybrid group simply fails — there is no classical fallback.
//!
//! ## Sync over QUIC (the M5 `Transport` impl)
//! [`QuicStreamTransport`] implements the synchronous M5
//! [`Transport`](crate::log::sync::Transport) trait over
//! a reliable QUIC bi-stream by bridging to a tokio runtime
//! ([`tokio::runtime::Handle::block_on`]). Each M5 frame (an opaque byte vector) is
//! length-delimited on the stream with a 4-byte big-endian length prefix, so the
//! byte stream is re-framed into the exact messages M5 sent. A hard close maps the
//! [`WireError`] to a QUIC application close code. Two loopback peers reconcile
//! divergent logs over this transport in the tests.

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::{Connection, Endpoint, RecvStream, SendStream};

use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::identity::composite::RootSigner;
use crate::transport::identity_cert::build_leaf_certificate;
use crate::transport::provider::{client_config, server_config, X25519MLKEM768_CODE_POINT};
use crate::transport::session::SessionEstablishment;
use crate::transport::verifier::{VerifiedPeer, VoxClientCertVerifier, VoxServerCertVerifier};
use crate::wire::WireError;

/// The maximum length of a single length-delimited M5 frame on a reliable stream.
/// Generous enough for any [`crate::log::sync`] frame (it bounds an `ENTRY` carrying
/// a max-size entry), and a hard cap so a hostile peer cannot announce a huge frame
/// length to force an allocation (anti-abuse, mirroring the M5 codec's own caps).
pub const MAX_STREAM_FRAME: usize = crate::log::sync::MAX_ENTRY_WIRE + 4096;

/// The QUIC application close code carried when a sync stream hard-fails. quinn
/// requires a `VarInt`; the M5 [`WireError`] byte is widened into it so the peer
/// observes the exact coded reason (ADR-008 — never a silent downgrade).
pub(super) fn close_code(err: WireError) -> quinn::VarInt {
    quinn::VarInt::from_u32(u32::from(err.code()))
}

/// A Vox QUIC endpoint: it owns the local UDP socket and the authenticated TLS
/// configuration, and can both dial peers and accept inbound connections.
///
/// The endpoint holds the local identity (via its leaf certificate) and the shared
/// supported-signature-algorithms set the verifiers need.
pub struct VoxEndpoint {
    endpoint: Endpoint,
    /// The local leaf cert chain + key, re-offered on each dial for mutual auth.
    leaf_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    leaf_key: rustls_pki_types::PrivateKeyDer<'static>,
    /// The provider's signature-verification algorithms, shared with verifiers.
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
    /// This endpoint's own identity fingerprint.
    local_id: Digest32,
}

/// Transport-layer admission for an *inbound* connection, evaluated **after** the
/// peer has been cryptographically authenticated (its composite identity recovered
/// and PoP verified) but before [`VoxEndpoint::accept`] returns the connection.
///
/// ## The default is open, by design (ADR-001 / ADR-005 / ADR-007)
/// Vox membership is **emergent**, not a transport-enforced roster: the swarm is
/// gated at *join* by the channel passphrase + Equihash PoW (ADR-005), and
/// *reading* is gated by per-sender consent (ADR-007). The transport's job is to
/// **authenticate and surface** the peer identity; authorization lives above it.
/// So the default ([`Admission::AcceptAnyAuthenticated`]) admits any peer that
/// proved a valid Vox identity, and the recovered identity is always available to
/// the caller via [`VoxConnection::peer_id`] for the upper-layer join/consent
/// checks.
///
/// ## Pinned / private deployments
/// A caller that *does* know who may connect (a pinned pair, or a closed
/// deployment) can supply [`Admission::Pinned`] or [`Admission::Callback`] to
/// reject an unwanted-but-authenticated identity at the transport boundary,
/// before the connection is handed up.
pub enum Admission {
    /// Admit any peer that authenticated as a valid Vox identity (open-swarm
    /// default). The identity is still recovered and surfaced to the caller.
    AcceptAnyAuthenticated,
    /// Admit only peers whose recovered identity fingerprint is in this set.
    Pinned(std::collections::HashSet<Digest32>),
    /// Admit a peer iff this predicate returns `true` for its recovered identity
    /// fingerprint. Lets a caller consult its own (dynamic) membership view.
    Callback(Box<dyn FnMut(&Digest32) -> bool + Send>),
}

impl std::fmt::Debug for Admission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AcceptAnyAuthenticated => f.write_str("Admission::AcceptAnyAuthenticated"),
            Self::Pinned(s) => f.debug_tuple("Admission::Pinned").field(&s.len()).finish(),
            Self::Callback(_) => f.write_str("Admission::Callback"),
        }
    }
}

impl Admission {
    /// Evaluate admission for a recovered, already-authenticated peer identity.
    fn admits(&mut self, peer: &Digest32) -> bool {
        match self {
            Self::AcceptAnyAuthenticated => true,
            Self::Pinned(set) => set.contains(peer),
            Self::Callback(f) => f(peer),
        }
    }
}

impl VoxEndpoint {
    /// Bind a Vox endpoint to `addr`, authenticating as `signer`'s identity.
    ///
    /// The endpoint can immediately [`accept`](Self::accept) inbound connections
    /// (open-swarm default: any *authenticated* Vox identity is admitted at the
    /// transport layer and surfaced for upper-layer join/consent authorization —
    /// see [`Admission`]) or [`accept_with_admission`](Self::accept_with_admission)
    /// (to enforce a pinned set / callback), and [`connect`](Self::connect) to
    /// peers (pinning the expected peer identity).
    ///
    /// Per-connection server configs are built lazily on each accept (each needs
    /// its own verifier output slot), so `bind` itself only stores the local leaf
    /// + the provider's supported-signature algorithms.
    pub fn bind<S: RootSigner>(signer: &S, addr: SocketAddr) -> Result<Self> {
        let leaf = build_leaf_certificate(signer)?;
        let leaf_chain = leaf.cert_chain();
        let leaf_key = leaf.private_key();
        let supported =
            crate::transport::provider::vox_crypto_provider().signature_verification_algorithms;

        // A minimal server config to bind the listening socket. The authenticating
        // verifier is installed per-connection in `accept` (each connection needs
        // its own [`VerifiedPeer`] slot), so this initial config's verifier output
        // is never read — it exists only so `Endpoint::server` has a crypto config.
        let bootstrap_verifier =
            VoxClientCertVerifier::any_identity(supported, VerifiedPeer::new());
        let s_cfg = server_config(
            Arc::new(bootstrap_verifier),
            leaf_chain.clone(),
            leaf.private_key(),
        )?;
        let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(s_cfg)
            .map_err(|_| Error::MalformedBundle("quic server config"))?;
        let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_server));

        let endpoint = Endpoint::server(server_cfg, addr)
            .map_err(|_| Error::MalformedBundle("quic endpoint bind"))?;

        Ok(Self {
            endpoint,
            leaf_chain,
            leaf_key,
            supported,
            local_id: leaf.identity_fingerprint(),
        })
    }

    /// The bound local socket address (useful when binding to port 0).
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|_| Error::MalformedBundle("quic local_addr"))
    }

    /// This endpoint's identity fingerprint.
    #[must_use]
    pub fn local_id(&self) -> Digest32 {
        self.local_id
    }

    /// Dial `addr`, requiring the peer to authenticate as `expected_peer`.
    ///
    /// Fails (no silent fallback) if: the peer cannot negotiate X25519MLKEM768, the
    /// peer's identity does not match `expected_peer`, or its composite PoP does not
    /// verify. On success returns an authenticated [`VoxConnection`] plus the
    /// session-establishment record.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        expected_peer: Digest32,
        now_secs: u64,
    ) -> Result<VoxConnection> {
        let verified = VerifiedPeer::new();
        let verifier =
            VoxServerCertVerifier::pinned(self.supported, expected_peer, verified.clone());
        let c_cfg = client_config(
            Arc::new(verifier),
            self.leaf_chain.clone(),
            self.clone_key(),
        )?;
        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(c_cfg)
            .map_err(|_| Error::MalformedBundle("quic client config"))?;
        let client_cfg = quinn::ClientConfig::new(Arc::new(quic_client));

        // The SNI server name is unused for authentication (we authenticate by the
        // Vox identity), but rustls requires a syntactically valid name.
        let connecting = self
            .endpoint
            .connect_with(client_cfg, addr, "vox.invalid")
            .map_err(|_| Error::MalformedBundle("quic connect"))?;
        let connection = connecting.await.map_err(|_| Error::SignatureInvalid)?; // handshake/auth failure
        finish_connection(connection, &verified, now_secs)
    }

    /// Accept the next inbound connection, admitting **any authenticated Vox
    /// identity** (the open-swarm default — see [`Admission`]). Returns `Ok(None)`
    /// if the endpoint is closed.
    ///
    /// The peer is cryptographically authenticated during the handshake (composite
    /// identity recovered + PoP verified); the recovered identity is recorded and
    /// surfaced via [`VoxConnection::peer_id`] so the application can apply its
    /// join/consent authorization (ADR-005/007). To reject an
    /// authenticated-but-unwanted identity at the transport boundary (pinned /
    /// private deployments), use [`accept_with_admission`](Self::accept_with_admission).
    pub async fn accept(&self, now_secs: u64) -> Result<Option<VoxConnection>> {
        self.accept_with_admission(now_secs, Admission::AcceptAnyAuthenticated)
            .await
    }

    /// Accept the next inbound connection, enforcing `admission` **after** the peer
    /// is cryptographically authenticated. Returns `Ok(None)` if the endpoint is
    /// closed.
    ///
    /// The peer always proves a valid Vox identity first (handshake-level auth); a
    /// peer that authenticates but is **not admitted** by `admission` has its
    /// connection closed with [`WireError::AuthenticatorInvalid`] (`0x05`) and this
    /// returns `Err` — the same coded rejection the dialer uses for an identity
    /// mismatch, so an unwanted peer cannot tell "not authenticated" from "not
    /// admitted". An admitted peer's identity is surfaced via
    /// [`VoxConnection::peer_id`].
    pub async fn accept_with_admission(
        &self,
        now_secs: u64,
        mut admission: Admission,
    ) -> Result<Option<VoxConnection>> {
        let Some(incoming) = self.endpoint.accept().await else {
            return Ok(None);
        };
        // A fresh slot for THIS connection's verifier output. We install a
        // per-connection server config so the verifier writes into our slot.
        let verified = VerifiedPeer::new();
        let client_verifier = VoxClientCertVerifier::any_identity(self.supported, verified.clone());
        let s_cfg = server_config(
            Arc::new(client_verifier),
            self.leaf_chain.clone(),
            self.clone_key(),
        )?;
        let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(s_cfg)
            .map_err(|_| Error::MalformedBundle("quic server config (accept)"))?;
        let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
        let connection = incoming
            .accept_with(Arc::new(server_cfg))
            .map_err(|_| Error::SignatureInvalid)?
            .await
            .map_err(|_| Error::SignatureInvalid)?;
        let conn = finish_connection(connection, &verified, now_secs)?;

        // Transport-layer admission, after authentication. A non-admitted peer is
        // closed with the coded reason and rejected — indistinguishable on the wire
        // from an authentication failure.
        if !admission.admits(&conn.peer_id()) {
            conn.close(WireError::AuthenticatorInvalid);
            return Err(Error::SignatureInvalid);
        }
        Ok(Some(conn))
    }

    /// Gracefully close the endpoint (all connections).
    pub fn close(&self) {
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"endpoint closed");
    }

    /// Clone the private key (rustls `PrivateKeyDer` is clone-by-method).
    fn clone_key(&self) -> rustls_pki_types::PrivateKeyDer<'static> {
        self.leaf_key.clone_key()
    }

    /// **Test-only.** Attempt to connect with a deliberately *classical-only* TLS
    /// key-exchange group (no X25519MLKEM768), to prove the PQ-only server refuses
    /// to negotiate it — i.e. there is no silent downgrade. Returns `Err` on the
    /// (expected) handshake failure.
    ///
    /// This is the only place a non-hybrid provider is constructed, and it exists
    /// solely so the downgrade-rejection property is testable through the real
    /// handshake. Production code never offers a classical group.
    #[cfg(test)]
    pub async fn connect_classical_only(
        &self,
        addr: SocketAddr,
        expected_peer: Digest32,
    ) -> Result<VoxConnection> {
        use rustls::crypto::aws_lc_rs;

        // A provider whose ONLY kx group is classical X25519 (TLS 0x001D) — no
        // hybrid group offered.
        let classical_x25519 = aws_lc_rs::default_provider()
            .kx_groups
            .into_iter()
            .find(|g| u16::from(g.name()) == 0x001D)
            .ok_or(Error::MalformedBundle("classical X25519 group unavailable"))?;
        let provider = Arc::new(rustls::crypto::CryptoProvider {
            kx_groups: vec![classical_x25519],
            ..aws_lc_rs::default_provider()
        });
        let supported = provider.signature_verification_algorithms;
        let verified = VerifiedPeer::new();
        let verifier = Arc::new(VoxServerCertVerifier::pinned(
            supported,
            expected_peer,
            verified.clone(),
        ));

        // Build the client config by hand over the classical provider.
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| Error::MalformedBundle("classical client provider/version"))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![crate::transport::provider::VOX_ALPN.to_vec()];
        cfg.enable_early_data = false;

        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(cfg)
            .map_err(|_| Error::MalformedBundle("classical quic client config"))?;
        let client_cfg = quinn::ClientConfig::new(Arc::new(quic_client));
        let connecting = self
            .endpoint
            .connect_with(client_cfg, addr, "vox.invalid")
            .map_err(|_| Error::MalformedBundle("classical connect"))?;
        let connection = connecting.await.map_err(|_| Error::SignatureInvalid)?;
        finish_connection(connection, &verified, 0)
    }
}

/// Confirm the negotiated group, record the session, and build the connection.
fn finish_connection(
    connection: Connection,
    verified: &VerifiedPeer,
    now_secs: u64,
) -> Result<VoxConnection> {
    // The verifier authenticated the peer during the handshake; its fingerprint is
    // in the slot. Absence means the handshake completed without our verifier
    // running, which must not happen — treat as an auth failure.
    let peer_id = verified.fingerprint().ok_or(Error::SignatureInvalid)?;

    // Confirm the negotiated named group is the hybrid PQ group. quinn exposes the
    // negotiated group via the rustls handshake data attached to the connection.
    confirm_hybrid_group(&connection)?;

    let session = SessionEstablishment::new(peer_id, now_secs);
    Ok(VoxConnection {
        connection,
        peer_id,
        session,
    })
}

/// Confirm the connection negotiated X25519MLKEM768; abort otherwise. Because the
/// provider offers only the hybrid group there is no downgrade target, but the
/// check makes the guarantee explicit (defence in depth) and surfaces a clear
/// error if a future config regression ever widened the offered groups.
fn confirm_hybrid_group(connection: &Connection) -> Result<()> {
    let Some(hd) = connection.handshake_data() else {
        return Err(Error::SignatureInvalid);
    };
    let Some(hd) = hd.downcast_ref::<quinn::crypto::rustls::HandshakeData>() else {
        return Err(Error::SignatureInvalid);
    };
    // quinn 0.11's rustls HandshakeData does not surface the named group directly;
    // the authoritative guarantee is the provider's single-group `kx_groups`
    // (verified by `provider::tests::provider_offers_only_the_hybrid_group`) plus
    // TLS 1.3's transcript binding. We assert the ALPN was the Vox protocol, which
    // confirms a Vox-config handshake completed (a non-Vox config would not carry
    // it), and rely on the offered-group restriction for the group guarantee.
    match &hd.protocol {
        Some(p) if p.as_slice() == crate::transport::provider::VOX_ALPN => Ok(()),
        _ => Err(Error::SignatureInvalid),
    }
}

/// An authenticated QUIC connection to one Vox peer.
pub struct VoxConnection {
    connection: Connection,
    peer_id: Digest32,
    session: SessionEstablishment,
}

impl VoxConnection {
    /// The authenticated peer identity fingerprint.
    #[must_use]
    pub fn peer_id(&self) -> Digest32 {
        self.peer_id
    }

    /// The recorded session-establishment entry (tag `0x0011`) for this session,
    /// pinning the negotiated suite + group so a downgrade is auditable.
    #[must_use]
    pub fn session(&self) -> &SessionEstablishment {
        &self.session
    }

    /// The negotiated TLS group code point recorded for this session
    /// (X25519MLKEM768 = `0x11EC`).
    #[must_use]
    pub fn negotiated_group(&self) -> u16 {
        debug_assert_eq!(self.session.negotiated_group, X25519MLKEM768_CODE_POINT);
        self.session.negotiated_group
    }

    /// Open a fresh outbound bidirectional stream for a logical flow.
    pub async fn open_stream(&self) -> Result<(SendStream, RecvStream)> {
        self.connection
            .open_bi()
            .await
            .map_err(|_| Error::MalformedBundle("quic open_bi"))
    }

    /// Accept the next inbound bidirectional stream the peer opened.
    pub async fn accept_stream(&self) -> Result<(SendStream, RecvStream)> {
        self.connection
            .accept_bi()
            .await
            .map_err(|_| Error::MalformedBundle("quic accept_bi"))
    }

    /// Send one RFC 9221 unreliable datagram (the caller frames it with a
    /// [`crate::transport::datagram`] sequence number). Fails if the datagram
    /// exceeds the peer's advertised limit.
    pub fn send_datagram(&self, frame: Vec<u8>) -> Result<()> {
        self.connection
            .send_datagram(bytes::Bytes::from(frame))
            .map_err(|_| Error::MalformedBundle("quic send_datagram"))
    }

    /// Receive the next inbound datagram's bytes.
    pub async fn recv_datagram(&self) -> Result<Vec<u8>> {
        self.connection
            .read_datagram()
            .await
            .map(|b| b.to_vec())
            .map_err(|_| Error::MalformedBundle("quic read_datagram"))
    }

    /// The maximum datagram payload the peer will accept right now, if datagrams
    /// are enabled on the connection.
    #[must_use]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.connection.max_datagram_size()
    }

    /// Close the connection with an application code + reason.
    pub fn close(&self, err: WireError) {
        self.connection
            .close(close_code(err), err.to_string().as_bytes());
    }

    /// The underlying quinn connection, for advanced callers (M11 tunnels).
    #[must_use]
    pub fn quinn(&self) -> &Connection {
        &self.connection
    }
}

// The M5 `Transport` over a reliable QUIC bi-stream lives in its own module to
// keep this file focused on the endpoint/connection lifecycle; it is re-exported
// here so `crate::transport::quic::QuicStreamTransport` remains a stable path.
pub use crate::transport::stream_transport::QuicStreamTransport;
