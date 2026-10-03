//! In-process proofs of the identity exchange (ADR-011 requirements 28–34, 38a; #401 / D3) over
//! a real loopback quinn pair: two endpoints on 127.0.0.1, the neutral daemon leaf on both, the
//! pre-identity transport parameters, real composite keys.
//!
//! Each claim names the mutant that turns it red; a red names its side (`PRODUCT:` — the exchange
//! did the wrong thing; `APPARATUS:` — the pair could not be set up). The real-binary forms
//! (a recording UDP proxy, a fake listener at a real node's address) need the shared endpoint
//! wired in (D5) and come with the proofs story (D12).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use quinn::{Connection, Endpoint, RecvStream, SendStream};
use tokio::time::Instant;

use super::*;
use crate::identity::composite::SoftwareRootSigner;
use crate::transport::identity_cert::build_neutral_leaf;
use crate::transport::provider::{neutral_client_config, neutral_server_config};
use crate::transport::quic::{pre_identity_transport_config, DEFAULT_UDP_PAYLOAD};

// ---------------------------------------------------------------------------
// The apparatus.
// ---------------------------------------------------------------------------

/// An endpoint on 127.0.0.1 with its own neutral leaf, both roles configured as a daemon's are
/// before the exchange.
fn endpoint() -> Endpoint {
    let leaf = build_neutral_leaf().expect("APPARATUS: neutral leaf");
    let server = quinn::crypto::rustls::QuicServerConfig::try_from(
        neutral_server_config(&leaf).expect("APPARATUS: server config"),
    )
    .expect("APPARATUS: quic server config");
    let client = quinn::crypto::rustls::QuicClientConfig::try_from(
        neutral_client_config(&leaf).expect("APPARATUS: client config"),
    )
    .expect("APPARATUS: quic client config");
    let mut s = quinn::ServerConfig::with_crypto(Arc::new(server));
    s.transport_config(pre_identity_transport_config(DEFAULT_UDP_PAYLOAD));
    let mut c = quinn::ClientConfig::new(Arc::new(client));
    c.transport_config(pre_identity_transport_config(DEFAULT_UDP_PAYLOAD));
    let mut e = Endpoint::server(s, "127.0.0.1:0".parse().expect("addr"))
        .expect("APPARATUS: bind 127.0.0.1:0");
    e.set_default_client_config(c);
    e
}

/// One connection from `dialler` to `listener`: (the dialling side, the listening side).
async fn pair(dialler: &Endpoint, listener: &Endpoint) -> (Connection, Connection) {
    let to = listener.local_addr().expect("APPARATUS: local addr");
    let (c, s) = tokio::join!(
        async {
            dialler
                .connect(to, "vox.invalid")
                .expect("APPARATUS: connect")
                .await
                .expect("APPARATUS: the neutral handshake failed")
        },
        async {
            listener
                .accept()
                .await
                .expect("APPARATUS: no incoming")
                .await
                .expect("APPARATUS: the neutral handshake failed (listening side)")
        },
    );
    (c, s)
}

struct Node {
    signer: Arc<SoftwareRootSigner>,
    instance: Instance,
}

impl Node {
    fn new() -> Self {
        Self {
            signer: Arc::new(SoftwareRootSigner::generate().expect("APPARATUS: keygen")),
            instance: new_instance().expect("APPARATUS: instance"),
        }
    }
    fn id(&self) -> Digest32 {
        self.signer.fingerprint()
    }
    fn hosted(&self) -> Hosted {
        Hosted {
            id: self.id(),
            instance: self.instance,
            signer: Arc::clone(&self.signer) as Arc<dyn RootSigner + Send + Sync>,
        }
    }
}

struct Table(HashMap<Digest32, Hosted>);

impl Table {
    fn of(nodes: &[&Node]) -> Arc<Self> {
        Arc::new(Self(nodes.iter().map(|n| (n.id(), n.hosted())).collect()))
    }
}

impl Hosts for Table {
    fn host(&self, target: &Digest32) -> Option<Hosted> {
        self.0.get(target).cloned()
    }
}

type Listened = std::result::Result<(Hosted, Proven), Refused>;

/// Run the listener's side on `s` in the background.
fn listen_on(
    s: &Connection,
    hosts: Arc<Table>,
    limiter: Arc<AskLimiter>,
    owner: Option<Digest32>,
) -> tokio::task::JoinHandle<Listened> {
    let s = s.clone();
    tokio::spawn(async move {
        listen(
            &s,
            SourceKey::of_addr(s.remote_address()),
            owner,
            &*hosts,
            &limiter,
        )
        .await
    })
}

async fn listened(h: tokio::task::JoinHandle<Listened>) -> Listened {
    tokio::time::timeout(EXCHANGE_TIMEOUT + Duration::from_secs(2), h)
        .await
        .expect("PRODUCT: the listener's exchange outlived its 5 s bound")
        .expect("APPARATUS: listener task")
}

/// A raw dialler's flights 1: the identity stream's kind, then `ASK { target }`.
async fn raw_ask(c: &Connection, target: Digest32) -> (SendStream, RecvStream) {
    let (mut send, recv) = c
        .open_bi()
        .await
        .expect("APPARATUS: open the identity stream");
    write_frame(&mut send, &StreamKind::Identity.frame())
        .await
        .expect("APPARATUS: write kind");
    write_frame(&mut send, &Ask { target }.encode())
        .await
        .expect("APPARATUS: write ASK");
    (send, recv)
}

async fn read_prove(recv: &mut RecvStream) -> Vec<u8> {
    read_frame_within(recv, MAX_FLIGHT, Duration::from_secs(3))
        .await
        .expect("PRODUCT: no PROVE for a hosted node")
        .expect("PRODUCT: the identity stream ended with no PROVE")
}

/// How a connection ended, as its dialling side saw it.
async fn close_seen(c: &Connection) -> (u64, Vec<u8>) {
    match tokio::time::timeout(Duration::from_secs(7), c.closed())
        .await
        .expect("PRODUCT: the connection was not closed")
    {
        quinn::ConnectionError::ApplicationClosed(a) => {
            (a.error_code.into_inner(), a.reason.to_vec())
        }
        other => {
            panic!("PRODUCT: the connection ended otherwise than by an application close: {other}")
        }
    }
}

fn refusal_code() -> u64 {
    u64::from(REFUSAL.code())
}

// ---------------------------------------------------------------------------
// The proofs.
// ---------------------------------------------------------------------------

/// The happy path: each end learns exactly who the other is, the listener answers no earlier than
/// the floor, and once the exchange is done the connection takes more streams than the
/// pre-identity two.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over a loopback quinn pair; run on demand"]
async fn an_exchange_proves_both_ends_to_each_other() {
    let (l, d) = (endpoint(), endpoint());
    let (target, me) = (Node::new(), Node::new());
    let (c, s) = pair(&d, &l).await;
    let h = listen_on(
        &s,
        Table::of(&[&target]),
        Arc::new(AskLimiter::standard()),
        None,
    );
    let started = Instant::now();
    let dialled = dial(&c, &*me.signer, me.instance, target.id())
        .await
        .unwrap_or_else(|e| panic!("PRODUCT: an honest dial was refused: {e:?}"));
    let took = started.elapsed();
    let (hosted, proven) = listened(h)
        .await
        .unwrap_or_else(|r| panic!("PRODUCT: the listener refused an honest dialler: {r}"));

    assert_eq!(
        dialled.peer,
        target.id(),
        "PRODUCT: the dialler proved the wrong node"
    );
    assert_eq!(
        dialled.instance, target.instance,
        "PRODUCT: the dialler got the wrong instance"
    );
    assert_eq!(
        hosted.id,
        target.id(),
        "PRODUCT: the listener answered for the wrong node"
    );
    assert_eq!(
        proven.peer,
        me.id(),
        "PRODUCT: the listener proved the wrong dialler"
    );
    assert_eq!(
        proven.instance, me.instance,
        "PRODUCT: the listener got the wrong instance"
    );
    assert!(
        took >= ANSWER_FLOOR,
        "PRODUCT: PROVE came {took:?} after the ASK, under the {ANSWER_FLOOR:?} floor"
    );

    // After the exchange the limits are the normal ones: four streams at once.
    let srv = s.clone();
    let accepted = tokio::spawn(async move {
        let mut n = 0;
        while n < 4 {
            let Ok((_s, mut r)) = srv.accept_bi().await else {
                break;
            };
            let _ = r.read_to_end(64).await;
            n += 1;
        }
        n
    });
    let mut open = Vec::new();
    for i in 0..4u8 {
        let (mut send, recv) = tokio::time::timeout(Duration::from_secs(2), c.open_bi())
            .await
            .unwrap_or_else(|_| panic!("PRODUCT: stream {i} after the exchange did not open: the pre-identity limit was not raised"))
            .expect("PRODUCT: open a stream after the exchange");
        send.write_all(&[i])
            .await
            .expect("PRODUCT: write after the exchange");
        open.push((send, recv));
    }
    for (send, _) in &mut open {
        let _ = send.finish();
    }
    let n = tokio::time::timeout(Duration::from_secs(3), accepted)
        .await
        .expect("PRODUCT: the listener did not take four streams after the exchange")
        .expect("APPARATUS: accept task");
    assert_eq!(
        n, 4,
        "PRODUCT: the listener took {n} streams after the exchange, not 4"
    );
    eprintln!("[identity] honest exchange: PROVE after {took:?}");
}

/// Exporter binding (requirement 30): a `CLAIM` that verified on one connection is refused on
/// another. Mutant: `init_input` without `E` — the replay then verifies.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over a loopback quinn pair; run on demand"]
async fn a_claim_replayed_on_another_connection_is_refused() {
    let (l, d) = (endpoint(), endpoint());
    let (target, me) = (Node::new(), Node::new());
    let table = Table::of(&[&target]);

    // Connection 1: an honest exchange, whose CLAIM an observer of this end could have kept.
    let (c1, s1) = pair(&d, &l).await;
    let h1 = listen_on(
        &s1,
        Arc::clone(&table),
        Arc::new(AskLimiter::standard()),
        None,
    );
    dial(&c1, &*me.signer, me.instance, target.id())
        .await
        .expect("PRODUCT: an honest dial was refused");
    listened(h1)
        .await
        .expect("PRODUCT: the honest CLAIM was refused");
    let e1 = exporter(&c1).expect("APPARATUS: exporter");
    let kept = Claim {
        dialler: me.signer.public_key(),
        instance: me.instance,
        sig: me
            .signer
            .sign(&init_input(&e1, &target.id(), &me.id(), &me.instance))
            .expect("APPARATUS: sign"),
    };

    // Connection 2: someone without the dialler's key replays it.
    let (c2, s2) = pair(&d, &l).await;
    let h2 = listen_on(&s2, table, Arc::new(AskLimiter::standard()), None);
    let (mut send, mut recv) = raw_ask(&c2, target.id()).await;
    let _ = read_prove(&mut recv).await;
    write_frame(&mut send, &kept.encode())
        .await
        .expect("APPARATUS: write CLAIM");
    let _ = send.finish();
    match listened(h2).await {
        Err(Refused::BadClaim) => {}
        Ok(_) => panic!("PRODUCT: a CLAIM replayed from another connection was accepted"),
        Err(other) => {
            panic!("PRODUCT: a replayed CLAIM was refused as {other}, not as a bad CLAIM")
        }
    }
    let (code, reason) = close_seen(&c2).await;
    assert_eq!(
        code,
        refusal_code(),
        "PRODUCT: a replayed CLAIM was closed with code {code}"
    );
    assert!(reason.is_empty(), "PRODUCT: the refusal carried a reason");
}

/// Reflection (requirement 31): a `PROVE` fed back as a `CLAIM` is refused — both re-tagged as a
/// `CLAIM` and sent as it came. Mutant (requirement 40): one shared label **and** `dialler_fp`
/// dropped from what `CLAIM` signs — the two signed inputs are then the same bytes, and the
/// re-tagged `PROVE` verifies. Either change alone leaves them different.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over a loopback quinn pair; run on demand"]
async fn a_prove_fed_back_as_a_claim_is_refused() {
    let (l, d) = (endpoint(), endpoint());
    let target = Node::new();
    let table = Table::of(&[&target]);
    for retag in [true, false] {
        let (c, s) = pair(&d, &l).await;
        let h = listen_on(
            &s,
            Arc::clone(&table),
            Arc::new(AskLimiter::standard()),
            None,
        );
        let (mut send, mut recv) = raw_ask(&c, target.id()).await;
        let prove = read_prove(&mut recv).await;
        let back = if retag {
            let p = Prove::decode(&prove).expect("PRODUCT: the PROVE does not parse");
            Claim {
                dialler: p.target,
                instance: p.instance,
                sig: p.sig,
            }
            .encode()
        } else {
            prove
        };
        write_frame(&mut send, &back)
            .await
            .expect("APPARATUS: write");
        let _ = send.finish();
        match listened(h).await {
            Ok(_) => {
                panic!("PRODUCT: a PROVE fed back as a CLAIM (retagged: {retag}) was accepted")
            }
            Err(Refused::BadClaim | Refused::Malformed(_)) => {}
            Err(other) => panic!("PRODUCT: a reflected PROVE was refused as {other}"),
        }
        let (code, _) = close_seen(&c).await;
        assert_eq!(
            code,
            refusal_code(),
            "PRODUCT: a reflected PROVE was closed with code {code}"
        );
    }
}

/// What a fake listener sends as flight 2.
#[derive(Debug, Clone, Copy)]
enum Fake {
    /// Its own key's PROVE.
    OwnKey,
    /// The pinned node's public key, with its own signature.
    PinnedKeyOwnSig,
    /// A real PROVE of the pinned node, taken from another connection to the real node.
    Relayed,
    /// Bytes that are no flight.
    Garbage,
}

/// Responder first (requirement 29): a party at the address that does not prove the pinned node
/// on this session never receives the dialler's `CLAIM`. Mutant: `CLAIM` sent before `PROVE` is
/// checked; also exporter left out (the relayed `PROVE` then verifies).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over a loopback quinn pair; run on demand"]
async fn a_prove_that_does_not_verify_gets_no_claim() {
    let (real, fake, d) = (endpoint(), endpoint(), endpoint());
    let (target, impostor, me) = (Node::new(), Node::new(), Node::new());
    let table = Table::of(&[&target]);
    for how in [
        Fake::OwnKey,
        Fake::PinnedKeyOwnSig,
        Fake::Relayed,
        Fake::Garbage,
    ] {
        let (c, s) = pair(&d, &fake).await;
        let flight2 = match how {
            Fake::OwnKey | Fake::PinnedKeyOwnSig => {
                let e = exporter(&s).expect("APPARATUS: exporter");
                let sig = impostor
                    .signer
                    .sign(&resp_input(&e, &target.id(), &impostor.instance))
                    .expect("APPARATUS: sign");
                let key = if matches!(how, Fake::OwnKey) {
                    impostor.signer.public_key()
                } else {
                    target.signer.public_key()
                };
                Prove {
                    target: key,
                    instance: impostor.instance,
                    sig,
                }
                .encode()
            }
            Fake::Relayed => {
                let (rc, rs) = pair(&fake, &real).await;
                let _h = listen_on(
                    &rs,
                    Arc::clone(&table),
                    Arc::new(AskLimiter::standard()),
                    None,
                );
                let (_send, mut recv) = raw_ask(&rc, target.id()).await;
                read_prove(&mut recv).await
            }
            Fake::Garbage => vec![0xa0, 0x01, 0x02],
        };
        let fake_side = tokio::spawn(async move {
            let (mut send, mut recv) = s.accept_bi().await.expect("APPARATUS: fake accept");
            let deadline = Instant::now() + Duration::from_secs(3);
            let _kind = flight(&mut recv, deadline).await.expect("APPARATUS: kind");
            let _ask = flight(&mut recv, deadline).await.expect("APPARATUS: ASK");
            write_frame(&mut send, &flight2)
                .await
                .expect("APPARATUS: write the fake PROVE");
            // Whatever the dialler sends next, if anything.
            read_frame_within(&mut recv, MAX_FLIGHT, Duration::from_secs(2)).await
        });
        let dialled = dial(&c, &*me.signer, me.instance, target.id()).await;
        let next = fake_side.await.expect("APPARATUS: fake task");
        if let Ok(Some(f)) = &next {
            panic!(
                "PRODUCT: the dialler sent a flight 3 ({} bytes) to a fake listener ({how:?}) that \
                 did not prove the pinned node",
                f.len()
            );
        }
        assert!(
            matches!(dialled, Err(DialFailed::BadProve(_))),
            "PRODUCT: a dial to a fake listener ({how:?}) ended {dialled:?}, not as a bad PROVE"
        );
        let err = dialled
            .unwrap_err()
            .into_error(c.remote_address(), &target.id())
            .to_string();
        assert!(
            err.contains("nothing at") && err.contains("answers as"),
            "PRODUCT: the dial said {err:?}, not \"nothing at <address> answers as <node>\""
        );
    }
}

/// What a probing dialler did, and how it was answered.
#[derive(Debug)]
struct Probe {
    case: &'static str,
    code: u64,
    reason: Vec<u8>,
    flight_bytes: usize,
    after_ask: Duration,
}

/// No further oracle (requirement 32): an unknown target, a detached one, a malformed and an
/// oversize flight, a rate-limited source, a circuit asking for another node and a failing
/// exporter all get one close — the same code, no reason, no flight — no earlier than the answer
/// floor after the `ASK` and within its window. Mutant: a distinct refusal for one case.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over a loopback quinn pair; run on demand"]
async fn every_refusal_is_one_close_at_one_time() {
    let (l, d) = (endpoint(), endpoint());
    let (target, detached, other) = (Node::new(), Node::new(), Node::new());
    let table = Table::of(&[&target]);
    let mut probes = Vec::new();
    let cases: [&'static str; 8] = [
        "unknown target",
        "detached target",
        "malformed ASK",
        "oversize flight",
        "not an identity stream",
        "rate-limited source",
        "circuit for another node",
        "exporter fails",
    ];
    for case in cases {
        let (c, s) = pair(&d, &l).await;
        let limiter = Arc::new(if case == "rate-limited source" {
            AskLimiter::new(0, 0)
        } else {
            AskLimiter::standard()
        });
        let owner = (case == "circuit for another node").then(|| other.id());
        let h = if case == "exporter fails" {
            let (s, table) = (s.clone(), Arc::clone(&table));
            tokio::spawn(async move {
                let fail = |_: &Connection| -> Result<Zeroizing<[u8; EXPORTER_LEN]>> {
                    Err(Error::SignatureInvalid)
                };
                listen_with(
                    &s,
                    SourceKey::of_addr(s.remote_address()),
                    None,
                    &*table,
                    &limiter,
                    &fail,
                )
                .await
            })
        } else {
            listen_on(&s, Arc::clone(&table), limiter, owner)
        };
        let (mut send, mut recv) = c.open_bi().await.expect("APPARATUS: open");
        let kind = if case == "not an identity stream" {
            StreamKind::Sync.frame()
        } else {
            StreamKind::Identity.frame()
        };
        write_frame(&mut send, &kind)
            .await
            .expect("APPARATUS: kind");
        match case {
            "malformed ASK" => {
                let mut e = Encoder::new();
                e.array(3)
                    .uint(u64::from(StructTag::IdentityAsk.as_u16()))
                    .uint(1)
                    .bytes(&target.id());
                write_frame(&mut send, &e.finish())
                    .await
                    .expect("APPARATUS: write");
            }
            "oversize flight" => {
                let len = u32::try_from(MAX_FLIGHT + 1).expect("len");
                send.write_all(&len.to_be_bytes())
                    .await
                    .expect("APPARATUS: write");
            }
            "not an identity stream" => {}
            "detached target" => write_frame(
                &mut send,
                &Ask {
                    target: detached.id(),
                }
                .encode(),
            )
            .await
            .expect("APPARATUS: write"),
            _ => write_frame(
                &mut send,
                &Ask {
                    target: if case == "unknown target" {
                        other.id()
                    } else {
                        target.id()
                    },
                }
                .encode(),
            )
            .await
            .expect("APPARATUS: write"),
        }
        let asked = Instant::now();
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(7), async {
            let mut buf = [0u8; 4096];
            while let Ok(Some(n)) = recv.read(&mut buf).await {
                got.extend_from_slice(&buf[..n]);
            }
        })
        .await;
        let (code, reason) = close_seen(&c).await;
        let after_ask = asked.elapsed();
        let refused = listened(h).await;
        assert!(
            refused.is_err(),
            "PRODUCT: the {case} case was answered, not refused"
        );
        probes.push(Probe {
            case,
            code,
            reason,
            flight_bytes: got.len(),
            after_ask,
        });
    }
    for p in &probes {
        eprintln!("[identity] refusal: {p:?}");
        assert_eq!(
            p.code,
            refusal_code(),
            "PRODUCT: the {} case closed with code {}, not the one refusal",
            p.case,
            p.code
        );
        assert!(
            p.reason.is_empty(),
            "PRODUCT: the {} case's close carried a reason",
            p.case
        );
        assert_eq!(
            p.flight_bytes, 0,
            "PRODUCT: the {} case sent {} bytes of flight",
            p.case, p.flight_bytes
        );
        assert!(
            p.after_ask >= ANSWER_FLOOR - Duration::from_millis(2),
            "PRODUCT: the {} case was refused {:?} after its ASK, under the {ANSWER_FLOOR:?} floor",
            p.case,
            p.after_ask
        );
        // The window's top, with room for a loaded machine.
        let top = ANSWER_FLOOR + ANSWER_JITTER + Duration::from_millis(150);
        assert!(
            p.after_ask <= top,
            "PRODUCT: the {} case was refused {:?} after its ASK, past the answer window",
            p.case,
            p.after_ask
        );
    }
}

/// The exporter is mandatory (requirement 30), on both sides: a listener that cannot read it
/// refuses (proved in [`every_refusal_is_one_close_at_one_time`]); a dialler that cannot read it
/// sends nothing at all, not even its `ASK`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over a loopback quinn pair; run on demand"]
async fn a_dialler_whose_exporter_fails_sends_nothing() {
    let (l, d) = (endpoint(), endpoint());
    let (target, me) = (Node::new(), Node::new());
    let (c, s) = pair(&d, &l).await;
    let h = listen_on(
        &s,
        Table::of(&[&target]),
        Arc::new(AskLimiter::standard()),
        None,
    );
    let fail =
        |_: &Connection| -> Result<Zeroizing<[u8; EXPORTER_LEN]>> { Err(Error::SignatureInvalid) };
    let dialled = dial_with(&c, &*me.signer, me.instance, target.id(), &fail).await;
    assert_eq!(
        dialled.err(),
        Some(DialFailed::Exporter),
        "PRODUCT: a dial without an exporter went on"
    );
    match listened(h).await {
        Err(Refused::Closed) => {}
        other => {
            panic!("PRODUCT: the listener saw {other:?}, not a connection closed before any ASK")
        }
    }
}

/// Requirement 33: a datagram before `PROVE` closes the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over a loopback quinn pair; run on demand"]
async fn a_datagram_before_prove_closes_the_connection() {
    let (l, d) = (endpoint(), endpoint());
    let target = Node::new();
    let (c, s) = pair(&d, &l).await;
    let h = listen_on(
        &s,
        Table::of(&[&target]),
        Arc::new(AskLimiter::standard()),
        None,
    );
    c.send_datagram(bytes::Bytes::from_static(b"too early"))
        .expect("APPARATUS: send a datagram");
    // The listener may close before these leave: the datagram alone is enough.
    if let Ok((mut send, _recv)) = c.open_bi().await {
        let _ = write_frame(&mut send, &StreamKind::Identity.frame()).await;
        let _ = write_frame(
            &mut send,
            &Ask {
                target: target.id(),
            }
            .encode(),
        )
        .await;
    }
    assert_eq!(
        listened(h).await.err(),
        Some(Refused::Datagram),
        "PRODUCT: a datagram before PROVE did not close the connection"
    );
    let (code, _) = close_seen(&c).await;
    assert_eq!(
        code,
        refusal_code(),
        "PRODUCT: a datagram before PROVE closed with code {code}"
    );
}

/// Requirement 33: QUIC's limits hold a connection to the exchange — a third bidirectional
/// stream, any unidirectional stream and more than 64 KiB of data wait until `CLAIM` verifies.
/// Mutant: the pre-identity parameters left at the normal values.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over a loopback quinn pair; run on demand"]
async fn the_pre_identity_limits_hold_a_connection_to_the_exchange() {
    let (l, d) = (endpoint(), endpoint());
    let (c, _s) = pair(&d, &l).await;
    let wait = Duration::from_millis(300);
    let (mut s0, _r0) = c
        .open_bi()
        .await
        .expect("PRODUCT: the identity stream did not open");
    s0.write_all(&[0]).await.expect("APPARATUS: write");
    let (mut s1, _r1) = c
        .open_bi()
        .await
        .expect("PRODUCT: the second stream did not open");
    s1.write_all(&[0]).await.expect("APPARATUS: write");
    assert!(
        tokio::time::timeout(wait, c.open_bi()).await.is_err(),
        "PRODUCT: a third bidirectional stream opened before the exchange"
    );
    assert!(
        tokio::time::timeout(wait, c.open_uni()).await.is_err(),
        "PRODUCT: a unidirectional stream opened before the exchange"
    );
    let big = vec![0u8; 4 * PRE_IDENTITY_WINDOW as usize];
    assert!(
        tokio::time::timeout(wait, s1.write_all(&big)).await.is_err(),
        "PRODUCT: {} bytes went through before the exchange, past the {PRE_IDENTITY_WINDOW}-byte window",
        big.len()
    );
}

/// One exchange per connection (requirement 33): a flight after `CLAIM` on the identity stream
/// closes the connection. Mutant: no check for a second flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over a loopback quinn pair; run on demand"]
async fn a_second_flight_after_claim_closes_the_connection() {
    let (l, d) = (endpoint(), endpoint());
    let (target, me) = (Node::new(), Node::new());
    let (c, s) = pair(&d, &l).await;
    let h = listen_on(
        &s,
        Table::of(&[&target]),
        Arc::new(AskLimiter::standard()),
        None,
    );
    let (mut send, mut recv) = raw_ask(&c, target.id()).await;
    let _ = read_prove(&mut recv).await;
    let e = exporter(&c).expect("APPARATUS: exporter");
    let claim = Claim {
        dialler: me.signer.public_key(),
        instance: me.instance,
        sig: me
            .signer
            .sign(&init_input(&e, &target.id(), &me.id(), &me.instance))
            .expect("APPARATUS: sign"),
    };
    write_frame(&mut send, &claim.encode())
        .await
        .expect("APPARATUS: CLAIM");
    write_frame(
        &mut send,
        &Ask {
            target: target.id(),
        }
        .encode(),
    )
    .await
    .expect("APPARATUS: second ASK");
    let _ = send.finish();
    match listened(h).await {
        Err(Refused::Malformed(_)) => {}
        Ok(_) => panic!("PRODUCT: a second flight after CLAIM was let through"),
        Err(other) => panic!("PRODUCT: a second flight was refused as {other}"),
    }
    let (code, _) = close_seen(&c).await;
    assert_eq!(
        code,
        refusal_code(),
        "PRODUCT: a second flight closed with code {code}"
    );
}

/// Requirement 33: a dialler that says nothing is closed with the refusal at 5 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over a loopback quinn pair; run on demand"]
async fn a_silent_dialler_is_closed_at_five_seconds() {
    let (l, d) = (endpoint(), endpoint());
    let target = Node::new();
    let (c, s) = pair(&d, &l).await;
    let started = Instant::now();
    let h = listen_on(
        &s,
        Table::of(&[&target]),
        Arc::new(AskLimiter::standard()),
        None,
    );
    assert_eq!(
        listened(h).await.err(),
        Some(Refused::TimedOut),
        "PRODUCT: a silent dialler was not timed out"
    );
    let took = started.elapsed();
    assert!(
        took >= EXCHANGE_TIMEOUT && took < EXCHANGE_TIMEOUT + Duration::from_millis(500),
        "PRODUCT: a silent dialler was closed after {took:?}, not at {EXCHANGE_TIMEOUT:?}"
    );
    let (code, _) = close_seen(&c).await;
    assert_eq!(
        code,
        refusal_code(),
        "PRODUCT: the timeout closed with code {code}"
    );
}

/// The rate limit: a burst of 16, then 8 a second, per source; sources are separate, and an
/// IPv4-mapped address counts as its IPv4.
#[test]
#[ignore = "in-process proof over a loopback quinn pair; run on demand"]
fn the_rate_limit_is_eight_a_second_burst_sixteen_per_source() {
    let lim = AskLimiter::standard();
    let a = SourceKey::of_addr("192.0.2.1:1".parse().expect("addr"));
    let a6 = SourceKey::of_addr("[::ffff:192.0.2.1]:2".parse().expect("addr"));
    let b = SourceKey::of_addr("192.0.2.2:1".parse().expect("addr"));
    assert_eq!(
        a, a6,
        "PRODUCT: an IPv4-mapped source is counted apart from its IPv4"
    );
    let burst = (0..20).filter(|_| lim.admit(a)).count();
    assert_eq!(
        burst, 16,
        "PRODUCT: a source got {burst} ASKs at once, not a burst of 16"
    );
    assert!(lim.admit(b), "PRODUCT: one source's limit refused another");
    std::thread::sleep(Duration::from_millis(1000));
    let next = (0..20).filter(|_| lim.admit(a)).count();
    assert_eq!(
        next, 8,
        "PRODUCT: a source got {next} ASKs a second later, not 8"
    );
}

/// A [`Table`] that counts its lookups.
struct Counting(Arc<Table>, std::sync::atomic::AtomicUsize);

impl Hosts for Counting {
    fn host(&self, target: &Digest32) -> Option<Hosted> {
        self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.0.host(target)
    }
}

/// Requirement 34's order: a rate-limited `ASK` is refused **before its target is looked up**, so
/// a flood costs the listener no lookup (and no signature); an admitted one is looked up once.
/// Mutant: the limiter checked after the lookup — the refused `ASK` then counts one lookup.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over a loopback quinn pair; run on demand"]
async fn a_rate_limited_ask_is_refused_before_its_target_is_looked_up() {
    let (l, d) = (endpoint(), endpoint());
    let target = Node::new();
    let mut lookups = Vec::new();
    for (case, limiter) in [
        ("rate-limited", AskLimiter::new(0, 0)),
        ("admitted", AskLimiter::standard()),
    ] {
        let (c, s) = pair(&d, &l).await;
        let hosts = Arc::new(Counting(Table::of(&[&target]), Default::default()));
        let h = {
            let (s, hosts) = (s.clone(), Arc::clone(&hosts));
            tokio::spawn(async move {
                listen(
                    &s,
                    SourceKey::of_addr(s.remote_address()),
                    None,
                    &*hosts,
                    &limiter,
                )
                .await
                .map(|_| ())
            })
        };
        let (_send, _recv) = raw_ask(&c, target.id()).await;
        let _ = tokio::time::timeout(EXCHANGE_TIMEOUT + Duration::from_secs(2), h).await;
        let n = hosts.1.load(std::sync::atomic::Ordering::SeqCst);
        eprintln!("[identity] {case} ASK: {n} lookup(s) of its target");
        lookups.push((case, n));
        c.close(0u32.into(), b"");
    }
    assert_eq!(
        lookups[1].1, 1,
        "APPARATUS: an admitted ASK's lookup was not counted, so a zero for the refused one would \
         mean nothing: {lookups:?}"
    );
    assert_eq!(
        lookups[0].1, 0,
        "PRODUCT: a rate-limited ASK looked up its target before it was refused (requirement 34): \
         {lookups:?}"
    );
}

/// Requirement 32's timing: a `PROVE` leaves no earlier than the 50 ms floor after its `ASK`, plus
/// a **uniformly random** delay up to 50 ms — so its timing is not a constant a prober could learn
/// a refusal's from. 24 exchanges: each at or past the floor and within the window, and
/// the draws spread over it (some in its lower half, some in its upper). Mutant: the jitter left
/// out (`answer_at` = the floor) — every answer lands at the floor plus the signing time, red on the
/// spread.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-process proof over a loopback quinn pair; run on demand"]
async fn every_answer_waits_the_floor_and_a_random_jitter() {
    const SAMPLES: usize = 24;
    let (l, d) = (endpoint(), endpoint());
    let target = Node::new();
    let table = Table::of(&[&target]);
    let limiter = Arc::new(AskLimiter::new(1000, 1000));
    let mut took = Vec::new();
    for _ in 0..SAMPLES {
        let (c, s) = pair(&d, &l).await;
        let h = listen_on(&s, Arc::clone(&table), Arc::clone(&limiter), None);
        let (_send, mut recv) = raw_ask(&c, target.id()).await;
        let asked = Instant::now();
        let _ = read_prove(&mut recv).await;
        took.push(asked.elapsed());
        c.close(0u32.into(), b"");
        let _ = tokio::time::timeout(EXCHANGE_TIMEOUT + Duration::from_secs(2), h).await;
    }
    took.sort();
    let (min, max) = (took[0], took[SAMPLES - 1]);
    let mid = ANSWER_FLOOR + ANSWER_JITTER / 2;
    let (low, high) = (
        took.iter().filter(|t| **t < mid).count(),
        took.iter().filter(|t| **t >= mid).count(),
    );
    eprintln!(
        "[identity] {SAMPLES} PROVEs after their ASK: min {min:?}, median {:?}, max {max:?}; {low} \
         in the window's lower half, {high} in its upper",
        took[SAMPLES / 2]
    );
    assert!(
        min >= ANSWER_FLOOR - Duration::from_millis(2),
        "PRODUCT: a PROVE left {min:?} after its ASK, under the {ANSWER_FLOOR:?} floor"
    );
    assert!(
        max <= ANSWER_FLOOR + ANSWER_JITTER + Duration::from_millis(150),
        "PRODUCT: a PROVE left {max:?} after its ASK, past the answer window"
    );
    assert!(
        low >= 2 && high >= 2 && max - min >= Duration::from_millis(20),
        "PRODUCT: the answers do not spread over the {ANSWER_JITTER:?} jitter (requirement 32): \
         {low} in the lower half, {high} in the upper, spread {:?}: {took:?}",
        max - min
    );
}
