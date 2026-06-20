//! Integration tests for the M9 QUIC transport (ADR-011): real loopback
//! handshakes over 127.0.0.1 with bounded timeouts, never the public network.
//!
//! These exercise the *whole* transport: the PQ-hybrid handshake, the libp2p-style
//! identity authentication, the expected-peer enforcement, 0-RTT being off, the
//! session-establishment record, and — the headline — M5 anti-entropy sync running
//! over a real quinn connection to reconcile two divergent logs.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::runtime::Runtime;

use crate::hash::{sha256, Digest32};
use crate::identity::composite::{CompositePublicKey, RootSigner, SoftwareRootSigner};
use crate::log::dag::{AdmissionPolicy, Dag};
use crate::log::entry::{Entry, EntryKind, EntrySkeleton, ZERO_HASH};
use crate::log::feed::{lipmaa, Feed};
use crate::log::sync::{frontier_session_peer, AuthorResolver};
use crate::suite::algo;
use crate::transport::quic::{QuicStreamTransport, VoxConnection, VoxEndpoint};

const CHANNEL: Digest32 = [0xD0; 32];
const EPOCH: u64 = 1;
/// Generous loopback bound; a healthy handshake/sync completes in milliseconds.
const TIMEOUT: Duration = Duration::from_secs(10);

fn signer(a: u8, b: u8) -> SoftwareRootSigner {
    SoftwareRootSigner::from_component_seeds(&[a; 32], &[b; 32]).unwrap()
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// A resolver backed by a fixed set of author keys (mirrors the M5 sync tests).
struct MapResolver {
    keys: Vec<(Digest32, CompositePublicKey)>,
}
impl AuthorResolver for MapResolver {
    fn key_for(&self, author: &Digest32) -> Option<CompositePublicKey> {
        self.keys
            .iter()
            .find(|(a, _)| a == author)
            .map(|(_, k)| k.clone())
    }
}

fn next_entry(dag: &Dag, r: &SoftwareRootSigner, payload: &[u8]) -> Entry {
    let author = r.fingerprint();
    let feed = dag.feed(&author);
    let max = feed.map_or(0, Feed::max_seq);
    let seq = max + 1;
    let prev_hash = if seq == 1 {
        ZERO_HASH
    } else {
        feed.unwrap().get(seq - 1).unwrap().entry_hash()
    };
    let lipmaa_backlink = if seq == 1 {
        ZERO_HASH
    } else {
        feed.unwrap().get(lipmaa(seq)).unwrap().entry_hash()
    };
    let sk = EntrySkeleton {
        author_id: author,
        seq,
        prev_hash,
        lipmaa_backlink,
        channel_id: CHANNEL,
        epoch: EPOCH,
        algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
        payload_hash: sha256(payload),
        payload_len: payload.len() as u64,
        end_of_feed: false,
    };
    Entry::build_signed(r, sk, payload.to_vec()).unwrap()
}

fn admit_all(rs: &[&SoftwareRootSigner]) -> AdmissionPolicy {
    let mut a = AdmissionPolicy::new();
    for r in rs {
        a.admit(CHANNEL, EPOCH, r.fingerprint());
    }
    a
}

fn fill(dag: &mut Dag, r: &SoftwareRootSigner, n: usize, adm: &AdmissionPolicy) {
    for i in 0..n {
        let p = format!("e{i}");
        let e = next_entry(dag, r, p.as_bytes());
        dag.accept(e, EntryKind::Content, &r.public_key(), adm, 0)
            .unwrap();
    }
}

/// A multi-thread runtime so two peers' blocking stream I/O make concurrent
/// progress on the worker pool.
fn runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn loopback_handshake_authenticates_each_peer() {
    let rt = runtime();
    let server = signer(1, 2);
    let client = signer(3, 4);
    let server_id = server.fingerprint();
    let client_id = client.fingerprint();

    rt.block_on(async move {
        let server_ep = VoxEndpoint::bind(&server, loopback()).unwrap();
        let server_addr = server_ep.local_addr().unwrap();
        let client_ep = VoxEndpoint::bind(&client, loopback()).unwrap();

        // Server accepts; client dials pinning the server identity.
        let accept = tokio::spawn(async move {
            tokio::time::timeout(TIMEOUT, server_ep.accept(1000))
                .await
                .unwrap()
                .unwrap()
                .unwrap()
        });
        let conn = tokio::time::timeout(TIMEOUT, client_ep.connect(server_addr, server_id, 1000))
            .await
            .unwrap()
            .unwrap();

        // Client authenticated the server as the expected identity.
        assert_eq!(conn.peer_id(), server_id);
        // The session record pins the hybrid group + default suite.
        assert_eq!(conn.negotiated_group(), 0x11EC);
        assert_eq!(conn.session().suite_id, crate::suite::VOX_SUITE_1.id);

        // Server side recovered the client's identity (no pinning, any Vox id).
        let server_conn = accept.await.unwrap();
        assert_eq!(server_conn.peer_id(), client_id);
    });
}

#[test]
fn identity_mismatch_aborts_connection() {
    let rt = runtime();
    let server = signer(1, 2);
    let client = signer(3, 4);
    let wrong = signer(9, 9).fingerprint(); // not the server's identity

    rt.block_on(async move {
        let server_ep = VoxEndpoint::bind(&server, loopback()).unwrap();
        let server_addr = server_ep.local_addr().unwrap();
        let client_ep = VoxEndpoint::bind(&client, loopback()).unwrap();

        // Server keeps accepting (its accept will error when the client aborts).
        let _accept = tokio::spawn(async move { server_ep.accept(1000).await });

        // Client pins the WRONG identity → the verifier rejects the server cert →
        // the handshake fails. No silent acceptance.
        let res = tokio::time::timeout(TIMEOUT, client_ep.connect(server_addr, wrong, 1000))
            .await
            .unwrap();
        assert!(
            res.is_err(),
            "a wrong expected-peer must abort the handshake"
        );
    });
}

#[test]
fn admission_callback_rejects_unwanted_but_authenticated_peer() {
    // A peer that authenticates correctly but is NOT admitted by the callback is
    // rejected at the transport boundary (pinned/private deployment), even though
    // it was cryptographically authenticated first.
    let rt = runtime();
    let server = signer(50, 51);
    let client = signer(52, 53);
    let server_fp = server.fingerprint();
    let client_fp = client.fingerprint();

    rt.block_on(async move {
        let server_ep = VoxEndpoint::bind(&server, loopback()).unwrap();
        let server_addr = server_ep.local_addr().unwrap();
        let client_ep = VoxEndpoint::bind(&client, loopback()).unwrap();

        // Admission rejects the dialer (callback returns false) — but only AFTER
        // confirming the recovered identity is the authenticated client.
        let accept = tokio::spawn(async move {
            server_ep
                .accept_with_admission(
                    0,
                    crate::transport::quic::Admission::Callback(Box::new(move |peer| {
                        assert_eq!(*peer, client_fp);
                        false
                    })),
                )
                .await
        });

        let _ = tokio::time::timeout(TIMEOUT, client_ep.connect(server_addr, server_fp, 0)).await;
        let server_res = accept.await.unwrap();
        assert!(
            server_res.is_err(),
            "a non-admitted (but authenticated) peer must be rejected"
        );
    });
}

#[test]
fn admission_pinned_set_admits_listed_identity_and_surfaces_it() {
    // A Pinned set that contains the dialer admits it and surfaces the recovered
    // identity to the caller.
    let rt = runtime();
    let server = signer(54, 55);
    let client = signer(56, 57);
    let server_fp = server.fingerprint();
    let client_fp = client.fingerprint();

    rt.block_on(async move {
        let server_ep = VoxEndpoint::bind(&server, loopback()).unwrap();
        let server_addr = server_ep.local_addr().unwrap();
        let client_ep = VoxEndpoint::bind(&client, loopback()).unwrap();

        let mut allowed = std::collections::HashSet::new();
        allowed.insert(client_fp);
        let accept = tokio::spawn(async move {
            server_ep
                .accept_with_admission(0, crate::transport::quic::Admission::Pinned(allowed))
                .await
                .unwrap()
                .unwrap()
        });
        let conn = tokio::time::timeout(TIMEOUT, client_ep.connect(server_addr, server_fp, 0))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(conn.peer_id(), server_fp);
        let server_conn = accept.await.unwrap();
        assert_eq!(server_conn.peer_id(), client_fp);
    });
}

#[test]
fn classical_only_peer_fails_to_connect_no_silent_downgrade() {
    // A peer that offers only a classical key-exchange group (no X25519MLKEM768)
    // must FAIL to connect to the PQ-only server — never silently downgrade.
    let rt = runtime();
    let server = signer(30, 31);
    let client = signer(32, 33);
    let server_fp = server.fingerprint();

    rt.block_on(async move {
        let server_ep = VoxEndpoint::bind(&server, loopback()).unwrap();
        let server_addr = server_ep.local_addr().unwrap();
        let client_ep = VoxEndpoint::bind(&client, loopback()).unwrap();
        // Server keeps accepting; its accept will error as the handshake fails.
        let _accept = tokio::spawn(async move { server_ep.accept(0).await });

        let res = tokio::time::timeout(
            TIMEOUT,
            client_ep.connect_classical_only(server_addr, server_fp),
        )
        .await
        .unwrap();
        assert!(
            res.is_err(),
            "a classical-only peer must fail to connect (no downgrade target)"
        );

        // Sanity: the SAME endpoints DO connect over the hybrid group, proving the
        // failure above is the group restriction, not a broken fixture.
        let server2 = signer(34, 35);
        let client2 = signer(36, 37);
        let server2_fp = server2.fingerprint();
        let sep = VoxEndpoint::bind(&server2, loopback()).unwrap();
        let saddr = sep.local_addr().unwrap();
        let cep = VoxEndpoint::bind(&client2, loopback()).unwrap();
        let acc = tokio::spawn(async move { sep.accept(0).await.unwrap().unwrap() });
        let ok = tokio::time::timeout(TIMEOUT, cep.connect(saddr, server2_fp, 0))
            .await
            .unwrap();
        assert!(ok.is_ok(), "the hybrid-group path must succeed");
        let _ = acc.await.unwrap();
    });
}

#[test]
fn zero_rtt_is_never_offered() {
    // The client config disables early data; the server issues no tickets and sets
    // max early data to 0. Assert these directly on the built rustls configs so a
    // regression that re-enables 0-RTT is caught.
    let server = signer(40, 41);
    let leaf = crate::transport::identity_cert::build_leaf_certificate(&server).unwrap();
    let supported =
        crate::transport::provider::vox_crypto_provider().signature_verification_algorithms;
    let verified = crate::transport::verifier::VerifiedPeer::new();

    let client_verifier = crate::transport::verifier::VoxServerCertVerifier::pinned(
        supported,
        server.fingerprint(),
        verified.clone(),
    );
    let client_cfg = crate::transport::provider::client_config(
        Arc::new(client_verifier),
        leaf.cert_chain(),
        leaf.private_key(),
    )
    .unwrap();
    assert!(!client_cfg.enable_early_data, "0-RTT must be off on client");

    let server_verifier =
        crate::transport::verifier::VoxClientCertVerifier::any_identity(supported, verified);
    let server_cfg = crate::transport::provider::server_config(
        Arc::new(server_verifier),
        leaf.cert_chain(),
        leaf.private_key(),
    )
    .unwrap();
    assert_eq!(server_cfg.max_early_data_size, 0, "no early data on server");
    assert_eq!(server_cfg.send_tls13_tickets, 0, "no resumption tickets");
}

#[test]
fn session_record_round_trips_over_the_wire_codec() {
    // The session-establishment record a live connection produces re-parses, and
    // records the hybrid group — the same struct the log layer would persist.
    let rt = runtime();
    let server = signer(5, 6);
    let client = signer(7, 8);
    let server_id = server.fingerprint();

    rt.block_on(async move {
        let server_ep = VoxEndpoint::bind(&server, loopback()).unwrap();
        let server_addr = server_ep.local_addr().unwrap();
        let client_ep = VoxEndpoint::bind(&client, loopback()).unwrap();
        let _accept = tokio::spawn(async move { server_ep.accept(1234).await });
        let conn = tokio::time::timeout(TIMEOUT, client_ep.connect(server_addr, server_id, 1234))
            .await
            .unwrap()
            .unwrap();

        let wire = conn.session().to_wire();
        let back = crate::transport::session::SessionEstablishment::from_wire(&wire).unwrap();
        assert_eq!(&back, conn.session());
        assert_eq!(back.peer_id, server_id);
        assert_eq!(back.negotiated_group, 0x11EC);
    });
}

#[test]
fn m5_sync_reconciles_divergent_logs_over_real_quic() {
    let rt = runtime();
    let handle = rt.handle().clone();

    // Two authors; each peer holds one feed the other lacks.
    let ra = signer(1, 2);
    let rb = signer(3, 4);
    let adm = admit_all(&[&ra, &rb]);
    let resolver = Arc::new(MapResolver {
        keys: vec![
            (ra.fingerprint(), ra.public_key()),
            (rb.fingerprint(), rb.public_key()),
        ],
    });

    let mut dag_a = Dag::new();
    let mut dag_b = Dag::new();
    fill(&mut dag_a, &ra, 5, &adm);
    fill(&mut dag_b, &rb, 4, &adm);

    // Transport endpoints (distinct identities for the two peers).
    let id_server = signer(10, 11);
    let id_client = signer(12, 13);
    let server_fp = id_server.fingerprint();

    let (server_conn, client_conn) = rt.block_on(async {
        let server_ep = VoxEndpoint::bind(&id_server, loopback()).unwrap();
        let server_addr = server_ep.local_addr().unwrap();
        let client_ep = VoxEndpoint::bind(&id_client, loopback()).unwrap();
        let accept = tokio::spawn(async move { server_ep.accept(0).await.unwrap().unwrap() });
        let client_conn =
            tokio::time::timeout(TIMEOUT, client_ep.connect(server_addr, server_fp, 0))
                .await
                .unwrap()
                .unwrap();
        let server_conn = accept.await.unwrap();
        (server_conn, client_conn)
    });

    // Run each peer's sync half on its own OS thread, bridging blocking stream I/O
    // onto the shared multi-thread runtime. The CLIENT opens the bi-stream; the
    // SERVER accepts it (deterministic stream pairing).
    let h1 = handle.clone();
    let res1 = resolver.clone();
    let adm1 = adm.clone();
    let client_t = std::thread::spawn(move || {
        let mut t = h1
            .block_on(QuicStreamTransport::open(h1.clone(), &client_conn))
            .unwrap();
        let applied = frontier_session_peer(&mut t, &mut dag_a, &*res1, &adm1, 0).unwrap();
        (applied, dag_a)
    });

    let h2 = handle.clone();
    let res2 = resolver.clone();
    let adm2 = adm.clone();
    let server_t = std::thread::spawn(move || {
        let mut t = h2
            .block_on(QuicStreamTransport::accept(h2.clone(), &server_conn))
            .unwrap();
        let applied = frontier_session_peer(&mut t, &mut dag_b, &*res2, &adm2, 0).unwrap();
        (applied, dag_b)
    });

    let (applied_a, dag_a) = client_t.join().unwrap();
    let (applied_b, dag_b) = server_t.join().unwrap();

    // A learned B's 4; B learned A's 5.
    assert_eq!(applied_a, 4);
    assert_eq!(applied_b, 5);
    // Both logs are now identical.
    assert_eq!(dag_a.causal_order(), dag_b.causal_order());
    assert_eq!(dag_a.len(), 9);
    assert_eq!(dag_b.len(), 9);
}

#[test]
fn datagram_round_trips_over_real_quic_with_replay_window() {
    use crate::transport::datagram::{DatagramSender, ReplayWindow};
    let rt = runtime();
    let server = signer(20, 21);
    let client = signer(22, 23);
    let server_fp = server.fingerprint();

    rt.block_on(async move {
        let server_ep = VoxEndpoint::bind(&server, loopback()).unwrap();
        let server_addr = server_ep.local_addr().unwrap();
        let client_ep = VoxEndpoint::bind(&client, loopback()).unwrap();
        let accept: tokio::task::JoinHandle<VoxConnection> =
            tokio::spawn(async move { server_ep.accept(0).await.unwrap().unwrap() });
        let client_conn =
            tokio::time::timeout(TIMEOUT, client_ep.connect(server_addr, server_fp, 0))
                .await
                .unwrap()
                .unwrap();
        let server_conn = accept.await.unwrap();

        // Client frames three datagrams with sequence numbers; server applies the
        // anti-replay window. (Datagrams may be reordered/dropped by QUIC, but on
        // loopback they arrive; we assert the window accepts each new seq once.)
        let mut sender = DatagramSender::new();
        let mut window = ReplayWindow::default();
        for i in 0..3u8 {
            let frame = sender.frame(&[i]);
            client_conn.send_datagram(frame).unwrap();
        }
        for _ in 0..3 {
            let got = tokio::time::timeout(TIMEOUT, server_conn.recv_datagram())
                .await
                .unwrap()
                .unwrap();
            let (seq, _payload) = crate::transport::datagram::parse_datagram(&got).unwrap();
            assert!(window.accept(seq), "new datagram seq {seq} accepted once");
            assert!(!window.accept(seq), "duplicate seq {seq} dropped");
        }
    });
}
