//! **The identity certificate and the session record state only true values** — V030-33 (#382),
//! driven against the shipped `vox` binary.
//!
//! **The staging.** A `vox daemon` on `127.0.0.1`, and a TLS client of this proof's own (quinn
//! and rustls, as any implementation would be) with a Vox identity of its own: no `vox` command
//! shows the certificate a node presents, or offers a group the build does not, so the client is
//! the person's instrument here; everything it talks to is the shipped binary.
//!
//! **What is asserted.**
//! 1. **The certificate the node presents carries the Vox identity extension under
//!    `2.25.<UUID>.1.1`**, the UUID arc Vox generated once (`14b7e534-e0b1-494d-8cb6-b81f37787c27`,
//!    derived here from the UUID itself, not read from the product), and **not** the old
//!    `1.3.6.1.4.1.1234567.1.1`, a placeholder for a Private Enterprise Number Vox never held.
//! 2. **The session record names the group actually negotiated.** A client offering only the
//!    post-quantum hybrid is admitted; the group it saw its own handshake negotiate is the group
//!    the node's `vox status --json` names for it (`tls_group`).
//! 3. **A session under a classical group is refused.** A client with a valid Vox identity that
//!    offers only X25519 never becomes a peer of the node.
//!
//! **Mutations that must turn it red, as PRODUCT:** the OID put back to the PEN placeholder (1);
//! the node's provider widened to offer X25519 too, with the observed-group refusal in
//! `SessionEstablishment::observed` removed (3) — and with the record's group written from the
//! constant, the node names `X25519MLKEM768` for a session that negotiated X25519 (2).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/hostile.rs"]
mod hostile;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use vox_core::identity::composite::RootSigner as _;
use world::{args, vox_once, VoxProc};

/// The UUID Vox's identity-extension arc is made from.
const UUID: &str = "14b7e534-e0b1-494d-8cb6-b81f37787c27";
/// X25519MLKEM768's TLS code point.
const HYBRID: u16 = 0x11EC;

/// The DER of an OBJECT IDENTIFIER (tag, length, value) for `arcs`.
fn oid_der(arcs: &[u128]) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    let mut push = |mut n: u128| {
        let mut b = vec![(n & 0x7f) as u8];
        n >>= 7;
        while n > 0 {
            b.push(0x80 | (n & 0x7f) as u8);
            n >>= 7;
        }
        v.extend(b.iter().rev());
    };
    push(arcs[0] * 40 + arcs[1]);
    for a in &arcs[2..] {
        push(*a);
    }
    let mut der = vec![0x06, u8::try_from(v.len()).unwrap_or(0)];
    der.extend(v);
    der
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Takes whatever certificate the node presents and keeps it; checks no signature. The client is
/// an instrument, not a node: what it is talking to is not its question.
#[derive(Debug)]
struct Keeps {
    cert: Arc<Mutex<Option<Vec<u8>>>>,
    schemes: Vec<rustls::SignatureScheme>,
}

impl rustls::client::danger::ServerCertVerifier for Keeps {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        *self
            .cert
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(end_entity.to_vec());
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.clone()
    }
}

/// What one handshake with the node came to.
struct Handshake {
    /// The certificate the node presented, if it got that far.
    cert: Option<Vec<u8>>,
    /// The group this client's own handshake negotiated, or why it did not complete.
    outcome: Result<u16, String>,
    /// Held so the connection stays up while the node is asked about it.
    _held: Option<(quinn::Endpoint, quinn::Connection)>,
}

/// A handshake with the node at `node`, under the Vox ALPN, presenting `seed`'s Vox identity,
/// offering only `groups`.
fn handshake(
    rt: &hostile::Rt,
    node: SocketAddr,
    seed: u8,
    groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
) -> Handshake {
    let signer = hostile::stranger(seed);
    let leaf = vox_core::transport::identity_cert::build_leaf_certificate(&signer)
        .unwrap_or_else(|e| panic!("APPARATUS: the client's own Vox leaf: {e:?}"));
    let cert = Arc::new(Mutex::new(None));
    let provider = Arc::new(rustls::crypto::CryptoProvider {
        kx_groups: groups,
        ..vox_core::transport::provider::vox_crypto_provider()
    });
    let schemes = provider
        .signature_verification_algorithms
        .supported_schemes();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|e| panic!("APPARATUS: the client's TLS 1.3: {e}"))
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Keeps {
            cert: Arc::clone(&cert),
            schemes,
        }))
        .with_client_auth_cert(leaf.cert_chain(), leaf.private_key())
        .unwrap_or_else(|e| panic!("APPARATUS: the client's own certificate: {e}"));
    tls.alpn_protocols = vec![vox_core::transport::provider::VOX_ALPN.to_vec()];
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .unwrap_or_else(|e| panic!("APPARATUS: the client's QUIC TLS: {e}"));
    let (outcome, held) = rt.block_on(async {
        let endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
            .unwrap_or_else(|e| panic!("APPARATUS: the client's socket: {e}"));
        let connecting = endpoint
            .connect_with(
                quinn::ClientConfig::new(Arc::new(quic)),
                node,
                "vox.invalid",
            )
            .unwrap_or_else(|e| panic!("APPARATUS: the client's connect: {e}"));
        match tokio::time::timeout(Duration::from_secs(20), connecting).await {
            Err(_) => (Err("no answer in 20 s".to_owned()), None),
            Ok(Err(e)) => (Err(e.to_string()), None),
            Ok(Ok(conn)) => {
                let group = conn
                    .handshake_data()
                    .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                    .map(|d| u16::from(d.negotiated_key_exchange_group));
                match group {
                    Some(g) => (Ok(g), Some((endpoint, conn))),
                    None => (Err("no handshake data".to_owned()), None),
                }
            }
        }
    });
    let cert = cert
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    Handshake {
        cert,
        outcome,
        _held: held,
    }
}

/// The `tls_group` the node's `vox status --json` names for `peer`, waiting up to 10 s for the
/// peer to be listed. `None`: never listed.
fn named_group(dir: &std::path::Path, peer: &str) -> Option<String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (ok, out, err) = vox_once(dir, &args(&["status", "--json"]));
        assert!(
            ok,
            "PRODUCT: the node's `vox status --json` did not answer.\n{out}\n{err}"
        );
        let v: Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` is not JSON ({e}):\n{out}"));
        let found = v
            .get("peers")
            .and_then(Value::as_array)
            .and_then(|ps| {
                ps.iter()
                    .find(|p| p.get("id").and_then(Value::as_str) == Some(peer))
            })
            .map(|p| {
                p.get("tls_group")
                    .and_then(Value::as_str)
                    .unwrap_or("(none)")
                    .to_owned()
            });
        if found.is_some() || Instant::now() >= deadline {
            return found;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// A rustls group name as `vox status` writes it: rustls's own name for the code point.
fn group_name(code: u16) -> String {
    format!("{:?}", rustls::NamedGroup::from(code))
}

#[test]
#[ignore = "a real vox daemon with production Argon2id; run in release"]
fn the_certificate_and_the_session_record_state_only_true_values() {
    watchdog::arm();
    let tmp = world::tempdir();
    let dir = tmp.path().join("node");
    world::mkdir(&dir.join("cfg"));
    let _ = world::fingerprint(&dir, "the node");
    let pass = tmp.path().join("node.pass");
    std::fs::write(&pass, world::IDENTITY)
        .unwrap_or_else(|e| panic!("APPARATUS: write the passphrase file: {e}"));
    let mut daemon = VoxProc::spawn(
        "node",
        &dir,
        &args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--passphrase-file",
            &world::utf8(&pass),
        ]),
    );
    // Where it listens, from its own status.
    let deadline = Instant::now() + Duration::from_secs(60);
    let node = loop {
        let (ok, out, _) = vox_once(&dir, &args(&["status", "--json"]));
        let at = ok
            .then(|| serde_json::from_str::<Value>(&out).ok())
            .flatten()
            .and_then(|v| {
                v.get("listening")?
                    .as_array()?
                    .iter()
                    .filter_map(Value::as_str)
                    .find_map(|l| {
                        let port: u16 = l.rsplit([':', '/']).next()?.parse().ok()?;
                        (l.contains("127.0.0.1")).then_some(port)
                    })
            });
        if let Some(port) = at {
            break SocketAddr::from(([127, 0, 0, 1], port));
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): the daemon never said where it listens.\n{out}\n{}",
            daemon.transcript()
        );
        std::thread::sleep(Duration::from_millis(250));
    };
    let rt = hostile::Rt::new();

    // ---- 2: a client offering only the hybrid is admitted, and the record names its group ----
    let hybrid = handshake(&rt, node, 0x61, vec![rustls_post_quantum::X25519MLKEM768]);
    let seen = hybrid.outcome.clone().unwrap_or_else(|e| {
        panic!(
            "PRODUCT (staging): a client with a valid Vox identity offering the post-quantum hybrid \
             was refused: {e}\n{}",
            daemon.transcript()
        )
    });
    let hybrid_fp = vox_core::node::link::b32_encode(&hostile::stranger(0x61).fingerprint());
    let named = named_group(&dir, &hybrid_fp);
    eprintln!(
        "[proof] the hybrid client negotiated {} (0x{seen:04x}); the node names {named:?} for it",
        group_name(seen)
    );
    assert!(
        seen == HYBRID,
        "PRODUCT: a client offering only X25519MLKEM768 negotiated 0x{seen:04x}"
    );
    assert!(
        named.as_deref() == Some(group_name(seen).as_str()),
        "PRODUCT: the session negotiated {}, yet the node's `vox status --json` names {named:?} \
         for it",
        group_name(seen)
    );

    // ---- 1: the certificate the node presented ----
    let cert = hybrid
        .cert
        .clone()
        .unwrap_or_else(|| panic!("CANNOT MEASURE: the node presented no certificate"));
    let uuid = u128::from_str_radix(&UUID.replace('-', ""), 16)
        .unwrap_or_else(|e| panic!("APPARATUS: the UUID {UUID}: {e}"));
    let new_oid = oid_der(&[2, 25, uuid, 1, 1]);
    let old_oid = oid_der(&[1, 3, 6, 1, 4, 1, 1_234_567, 1, 1]);
    eprintln!(
        "[proof] the node's certificate: {} bytes; 2.25.<UUID>.1.1 present: {}; the PEN placeholder \
         present: {}",
        cert.len(),
        contains(&cert, &new_oid),
        contains(&cert, &old_oid)
    );
    assert!(
        contains(&cert, &new_oid) && !contains(&cert, &old_oid),
        "PRODUCT: the certificate the node presents must carry its identity under \
         2.25.{uuid}.1.1 and never under 1.3.6.1.4.1.1234567.1.1: new {}, old {}",
        contains(&cert, &new_oid),
        contains(&cert, &old_oid)
    );
    drop(hybrid);

    // ---- 3: a client offering only X25519 never becomes a peer ----
    let classical = handshake(
        &rt,
        node,
        0x62,
        vec![rustls::crypto::aws_lc_rs::kx_group::X25519],
    );
    let classical_fp = vox_core::node::link::b32_encode(&hostile::stranger(0x62).fingerprint());
    let listed = match &classical.outcome {
        Ok(_) => named_group(&dir, &classical_fp),
        Err(_) => None,
    };
    eprintln!(
        "[proof] the classical client: {}; the node lists it as {listed:?}",
        match &classical.outcome {
            Ok(g) => format!("negotiated {}", group_name(*g)),
            Err(e) => format!("refused ({e})"),
        }
    );
    assert!(
        listed.is_none(),
        "PRODUCT: a session under a classical group must be refused, yet the node holds the \
         X25519-only client as a peer and names its group {listed:?} (the client saw {:?})",
        classical.outcome.as_ref().map(|g| group_name(*g))
    );
    drop(classical);
    drop(daemon);
}
