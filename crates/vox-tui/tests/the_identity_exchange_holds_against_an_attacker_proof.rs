//! ADR-011 requirements 29–34 — **the identity exchange holds against an attacker**, at a running
//! `vox daemon`.
//!
//! **Staging.** Every node here is the shipped `vox`: `vox daemon` with its node attached, on
//! 127.0.0.1, beside a `vox node` anchor. The attacker is not a person using vox, so it is not a
//! `vox` process (AGENTS.md: a test-side attacker is apparatus): it is a QUIC endpoint of this
//! test's own, built from vox-core's transport (the neutral leaf, the flights, the signed inputs),
//! that speaks the exchange's wire to the daemon and does what no honest node does. Each test
//! starts its own daemon, so each has the per-source rate limit to itself, and the tests run one
//! at a time, so a loaded machine does not blur the answer window. Times are in ms.
//!
//! **Claims** (each with the mutant that turns it red, as `PRODUCT:`):
//! 1. **Replay** (requirement 30): a `CLAIM` that verified on one connection is refused on
//!    another, with the one refusal. Mutant: `init_input` without `E`.
//! 2. **Reflection** (requirement 31): the daemon's own `PROVE` fed back as a `CLAIM`, retagged
//!    or as it came, is refused. Mutant: one shared label, and `dialler_fp` dropped from what
//!    `CLAIM` signs.
//! 3. **Responder first** (requirement 29): a daemon dialling a party that does not prove the
//!    pinned node on that session sends no `CLAIM` and closes with the bad-`PROVE` code. The party
//!    sends its own key's `PROVE`, the pinned key with its own signature, a real `PROVE` of the
//!    pinned node relayed from another connection to it, and bytes that are no flight. Mutant:
//!    `CLAIM` sent before `PROVE` is checked.
//! 4. **No further oracle** (requirement 32): an unknown target, a detached one, a malformed and
//!    an oversize flight, and a first stream that is not the identity stream each get one close:
//!    the refusal's code, no reason, no flight bytes, no earlier than the 50 ms answer floor after
//!    the `ASK` and inside the answer window. Mutant: a detached target refused with its own code.
//! 5. **The rate limit** (requirement 34): from one source, a burst of 16 `ASK`s is answered and
//!    the rest refused with the same close; a second later 8 more are. Mutant: a burst of 32.
//! 6. **Pre-identity limits** (requirement 33): before `CLAIM`, a third bidirectional stream, any
//!    unidirectional stream and more than 64 KiB of data wait, and a datagram before `PROVE`
//!    closes the connection with the refusal. Mutants: the pre-identity transport parameters left
//!    at the normal values; the datagram check removed.
//! 7. **One exchange per connection** (requirement 33): a flight after `CLAIM` on the identity
//!    stream closes the connection with the refusal. Mutant: no check for a second flight.
//! 8. **A silent dialler** (requirement 33): a connection that never asks is closed with the
//!    refusal 5000 ms after its handshake. Mutant: no bound on the wait for the `ASK`.
//!
//! **Not measurable from outside, so not claimed here:** that a rate-limited `ASK` is refused
//! *before* its target is looked up (requirement 34's order: the lookup leaves no trace on the
//! wire); a circuit's `ASK` for another node, and a listener whose exporter fails (internal
//! failures no attacker can cause); the answer jitter's distribution.
//!
//! **Which side a red is on.** The daemon doing what an attack wanted (answering, accepting,
//! leaking a reason, a code, a flight or a time) is `PRODUCT:`; a daemon that would not start, an
//! endpoint that would not bind, or a connection that would not finish its neutral handshake is
//! `APPARATUS:`.

#![cfg(unix)]

#[path = "support/hostile.rs"]
mod hostile;
#[path = "support/ports.rs"]
mod ports;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quinn::{Connection, Endpoint, RecvStream, SendStream};
use vox_core::hash::Digest32;
use vox_core::identity::composite::{RootSigner, SoftwareRootSigner};
use vox_core::node::link::{b32_decode, b32_encode};
use vox_core::transport::framing::{read_frame_within, write_frame};
use vox_core::transport::identity::{
    dial, exporter, init_input, new_instance, resp_input, Ask, Claim, Prove, ANSWER_FLOOR,
    ANSWER_JITTER, ASKS_PER_SECOND, ASK_BURST, BAD_PROVE, EXCHANGE_TIMEOUT, MAX_FLIGHT,
    PRE_IDENTITY_WINDOW, REFUSAL,
};
use vox_core::transport::identity_cert::build_neutral_leaf;
use vox_core::transport::provider::{neutral_client_config, neutral_server_config};
use vox_core::transport::quic::{pre_identity_transport_config, DEFAULT_UDP_PAYLOAD};
use vox_core::transport::streams::StreamKind;
use world::{args, vox_once_plain, VoxProc, IDENTITY};

/// One test at a time: each runs its own daemon, and the answer window is measured in ms.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn ms(d: Duration) -> u128 {
    d.as_millis()
}

fn refusal() -> u64 {
    u64::from(REFUSAL.code())
}

// ---- the real side ------------------------------------------------------------------------------

/// A running `vox daemon` with its node attached: its data root, fingerprint and address.
struct Daemon {
    _proc: VoxProc,
    data: PathBuf,
    fp: Digest32,
    addr: SocketAddr,
}

/// `vox daemon` for a fresh identity named `name` under `root`, with `--anchor spec`.
fn daemon(root: &Path, name: &str, spec: &str) -> Daemon {
    let data = hostile::profile_dir(root, name);
    let pass = root.join(format!("{name}.pass"));
    std::fs::write(&pass, IDENTITY).expect("APPARATUS: write the passphrase file");
    let fp = hostile::fingerprint(&data);
    let proc = hostile::daemon_on(name, &data, "127.0.0.1:0", spec, &pass);
    let port = hostile::listening_port(&data);
    Daemon {
        _proc: proc,
        data,
        fp,
        addr: SocketAddr::from(([127, 0, 0, 1], port)),
    }
}

/// An anchor and one daemon beside it.
struct World {
    _tmp: tempfile::TempDir,
    _anchor: VoxProc,
    host: Daemon,
}

fn world() -> World {
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let (anchor, spec) =
        hostile::anchor(&hostile::profile_dir(tmp.path(), "anchor"), "127.0.0.1:0");
    let host = daemon(tmp.path(), "host", &spec);
    World {
        _tmp: tmp,
        _anchor: anchor,
        host,
    }
}

// ---- the attacker ------------------------------------------------------------------------------

/// The attacker's QUIC endpoint on 127.0.0.1: a neutral leaf and the pre-identity parameters, as a
/// node's own endpoint has before its exchange; it listens too when `listens`.
fn endpoint(listens: bool) -> Endpoint {
    let leaf = build_neutral_leaf().expect("APPARATUS: a neutral leaf");
    let client = quinn::crypto::rustls::QuicClientConfig::try_from(
        neutral_client_config(&leaf).expect("APPARATUS: the client config"),
    )
    .expect("APPARATUS: the QUIC client config");
    let mut c = quinn::ClientConfig::new(Arc::new(client));
    c.transport_config(pre_identity_transport_config(DEFAULT_UDP_PAYLOAD));
    let at: SocketAddr = "127.0.0.1:0".parse().expect("APPARATUS: an address");
    let mut e = if listens {
        let server = quinn::crypto::rustls::QuicServerConfig::try_from(
            neutral_server_config(&leaf).expect("APPARATUS: the server config"),
        )
        .expect("APPARATUS: the QUIC server config");
        let mut s = quinn::ServerConfig::with_crypto(Arc::new(server));
        s.transport_config(pre_identity_transport_config(DEFAULT_UDP_PAYLOAD));
        Endpoint::server(s, at).expect("APPARATUS: bind the attacker's endpoint")
    } else {
        Endpoint::client(at).expect("APPARATUS: bind the attacker's endpoint")
    };
    e.set_default_client_config(c);
    e
}

/// A connection to `to` through its neutral handshake.
async fn connect(e: &Endpoint, to: SocketAddr) -> Connection {
    tokio::time::timeout(
        Duration::from_secs(10),
        e.connect(to, "vox.invalid")
            .expect("APPARATUS: start a connection"),
    )
    .await
    .expect("APPARATUS: the neutral handshake did not finish in 10000 ms")
    .expect("APPARATUS: the neutral handshake failed")
}

/// The identity stream opened and `ASK { target }` written; when the `ASK` left.
async fn raw_ask(c: &Connection, target: Digest32) -> (SendStream, RecvStream, Instant) {
    let (mut send, recv) = c.open_bi().await.expect("APPARATUS: open a stream");
    write_frame(&mut send, &StreamKind::Identity.frame())
        .await
        .expect("APPARATUS: write the stream's kind");
    write_frame(&mut send, &Ask { target }.encode())
        .await
        .expect("APPARATUS: write the ASK");
    (send, recv, Instant::now())
}

/// The daemon's `PROVE`, which a hosted node must send.
async fn read_prove(recv: &mut RecvStream) -> Vec<u8> {
    read_frame_within(recv, MAX_FLIGHT, Duration::from_secs(3))
        .await
        .unwrap_or_else(|e| panic!("PRODUCT: no PROVE for the hosted node: {e:?}"))
        .expect("PRODUCT: the identity stream ended with no PROVE")
}

/// How a connection ended, as this end saw it.
#[derive(Debug)]
struct Closed {
    code: u64,
    reason: Vec<u8>,
    at: Instant,
}

/// Wait up to `within` for the connection to be closed by the other end with an application
/// close; `None` if it was still open.
async fn closed(c: &Connection, within: Duration) -> Option<Closed> {
    let err = tokio::time::timeout(within, c.closed()).await.ok()?;
    let at = Instant::now();
    match err {
        quinn::ConnectionError::ApplicationClosed(a) => Some(Closed {
            code: a.error_code.into_inner(),
            reason: a.reason.to_vec(),
            at,
        }),
        other => panic!("PRODUCT: the connection ended otherwise than by a close: {other}"),
    }
}

/// The one refusal (requirement 32): the refusal's code and no reason, within `within`. A bad flight
/// is refused at once, so its `within` is under the 5000 ms bound that closes any exchange: a
/// refusal only at that bound would be the timeout's, not the check's.
async fn refused(c: &Connection, what: &str, within: Duration) -> Closed {
    let Some(seen) = closed(c, within).await else {
        panic!(
            "PRODUCT: {what} was not refused: the connection was still open {} ms later",
            ms(within)
        )
    };
    assert_eq!(
        seen.code,
        refusal(),
        "PRODUCT: {what} was closed with code {}, not the one refusal ({})",
        seen.code,
        refusal()
    );
    assert!(
        seen.reason.is_empty(),
        "PRODUCT: {what} was closed with a reason: {:?}",
        String::from_utf8_lossy(&seen.reason)
    );
    seen
}

fn runtime() -> hostile::Rt {
    hostile::Rt::new()
}

/// A dialler's identity of the attacker's own.
fn stranger() -> SoftwareRootSigner {
    SoftwareRootSigner::generate().expect("APPARATUS: a key pair")
}

// ---- the claims ---------------------------------------------------------------------------------

/// Claim 1. An honest exchange is accepted (the connection then takes the normal stream limit);
/// its `CLAIM`, replayed on a second connection by someone without the dialler's key, is refused.
#[test]
#[ignore = "real daemons and a test-side attacker; run in release"]
fn a_claim_replayed_on_another_connection_is_refused() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    watchdog::arm();
    let w = world();
    let rt = runtime();
    rt.block_on(async {
        let e = endpoint(false);
        let me = stranger();
        let instance = new_instance().expect("APPARATUS: an instance");
        let c1 = connect(&e, w.host.addr).await;
        let started = Instant::now();
        let proven = dial(&c1, &me, instance, w.host.fp)
            .await
            .unwrap_or_else(|f| panic!("PRODUCT: an honest dial was refused: {f:?}"));
        let took = started.elapsed();
        assert_eq!(
            proven.peer, w.host.fp,
            "PRODUCT: the daemon proved another node"
        );
        assert!(
            took >= ANSWER_FLOOR,
            "PRODUCT: an honest exchange took {} ms, under the {} ms answer floor",
            ms(took),
            ms(ANSWER_FLOOR)
        );
        // Accepted: the limits are the normal ones now, three more streams at once.
        let mut held = Vec::new();
        for i in 0..3 {
            let opened = tokio::time::timeout(Duration::from_millis(2000), c1.open_bi()).await;
            let Ok(Ok(pair)) = opened else {
                panic!("PRODUCT: stream {i} after an honest CLAIM did not open in 2000 ms")
            };
            held.push(pair);
        }
        println!(
            "[proof] honest exchange: PROVE after {} ms; 3 more streams opened",
            ms(took)
        );

        let e1 = exporter(&c1).expect("APPARATUS: the exporter");
        let kept = Claim {
            dialler: me.public_key(),
            instance,
            sig: me
                .sign(&init_input(&e1, &w.host.fp, &me.fingerprint(), &instance))
                .expect("APPARATUS: sign"),
        };
        let c2 = connect(&e, w.host.addr).await;
        let (mut send, mut recv, _) = raw_ask(&c2, w.host.fp).await;
        let _ = read_prove(&mut recv).await;
        write_frame(&mut send, &kept.encode())
            .await
            .expect("APPARATUS: write the replayed CLAIM");
        let _ = send.finish();
        refused(
            &c2,
            "a CLAIM replayed from another connection",
            Duration::from_millis(2000),
        )
        .await;
        println!("[proof] a CLAIM replayed on another connection: refused");
    });
}

/// Claim 2. The daemon's own `PROVE`, fed back to it as a `CLAIM`, is refused.
#[test]
#[ignore = "real daemons and a test-side attacker; run in release"]
fn a_prove_fed_back_as_a_claim_is_refused() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    watchdog::arm();
    let w = world();
    let rt = runtime();
    rt.block_on(async {
        let e = endpoint(false);
        for retag in [true, false] {
            let c = connect(&e, w.host.addr).await;
            let (mut send, mut recv, _) = raw_ask(&c, w.host.fp).await;
            let prove = read_prove(&mut recv).await;
            let back = if retag {
                let p = Prove::decode(&prove).expect("PRODUCT: the daemon's PROVE does not parse");
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
                .expect("APPARATUS: write the reflected PROVE");
            let _ = send.finish();
            refused(
                &c,
                &format!("the daemon's PROVE fed back as a CLAIM (retagged: {retag})"),
                Duration::from_millis(2000),
            )
            .await;
            println!("[proof] PROVE fed back as a CLAIM (retagged: {retag}): refused");
        }
    });
}

/// What the party at a pinned node's address sends as flight 2.
#[derive(Debug, Clone, Copy)]
enum Fake {
    OwnKey,
    PinnedKeyOwnSig,
    Relayed,
    Garbage,
}

/// Claim 3. A daemon told its anchor is node B at the attacker's address dials it there. Whatever
/// the attacker answers that does not prove B on that session, the daemon sends no `CLAIM` and
/// closes with the bad-`PROVE` code.
#[test]
#[ignore = "real daemons and a test-side attacker; run in release"]
fn a_daemon_sends_no_claim_to_a_party_that_does_not_prove_the_pinned_node() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    watchdog::arm();
    let w = world();
    let rt = runtime();
    let fake = rt.block_on(async { endpoint(true) });
    let fake_addr = fake.local_addr().expect("APPARATUS: the fake's address");
    // Node B, real, is the one pinned; a real PROVE of it is what the attacker can relay.
    let b = &w.host;
    let (pinned_key, relayed) = rt.block_on(async {
        let c = connect(&fake, b.addr).await;
        let (_send, mut recv, _) = raw_ask(&c, b.fp).await;
        let prove = read_prove(&mut recv).await;
        let key = Prove::decode(&prove)
            .expect("PRODUCT: B's PROVE does not parse")
            .target;
        (key, prove)
    });
    // Daemon A: its anchor is "B" at the attacker's address.
    let spec = format!(
        "{}@/ip4/127.0.0.1/udp/{}",
        b32_encode(&b.fp),
        fake_addr.port()
    );
    let _a = daemon(w._tmp.path(), "dialler", &spec);
    let impostor = stranger();
    let instance = new_instance().expect("APPARATUS: an instance");
    for how in [
        Fake::OwnKey,
        Fake::PinnedKeyOwnSig,
        Fake::Relayed,
        Fake::Garbage,
    ] {
        let (next, close) = rt.block_on(async {
            let incoming = tokio::time::timeout(Duration::from_secs(60), fake.accept())
                .await
                .unwrap_or_else(|_| {
                    panic!("APPARATUS: the daemon did not dial its anchor in 60000 ms ({how:?})")
                })
                .expect("APPARATUS: the fake endpoint closed");
            let s = incoming
                .await
                .expect("APPARATUS: the daemon's neutral handshake with the fake failed");
            let (mut send, mut recv) = tokio::time::timeout(Duration::from_secs(10), s.accept_bi())
                .await
                .expect("APPARATUS: the daemon opened no identity stream in 10000 ms")
                .expect("APPARATUS: accept the identity stream");
            let wait = Duration::from_secs(3);
            let _kind = read_frame_within(&mut recv, MAX_FLIGHT, wait)
                .await
                .expect("APPARATUS: read the stream's kind");
            let ask = read_frame_within(&mut recv, MAX_FLIGHT, wait)
                .await
                .expect("APPARATUS: read the ASK")
                .expect("APPARATUS: no ASK");
            let asked = Ask::decode(&ask).expect("PRODUCT: the daemon's ASK does not parse");
            assert_eq!(
                asked.target, b.fp,
                "PRODUCT: the daemon asked for another node"
            );
            let flight2 = match how {
                Fake::OwnKey | Fake::PinnedKeyOwnSig => {
                    let e = exporter(&s).expect("APPARATUS: the exporter");
                    let sig = impostor
                        .sign(&resp_input(&e, &b.fp, &instance))
                        .expect("APPARATUS: sign");
                    let key = if matches!(how, Fake::OwnKey) {
                        impostor.public_key()
                    } else {
                        pinned_key.clone()
                    };
                    Prove {
                        target: key,
                        instance,
                        sig,
                    }
                    .encode()
                }
                Fake::Relayed => relayed.clone(),
                Fake::Garbage => vec![0xa0, 0x01, 0x02],
            };
            write_frame(&mut send, &flight2)
                .await
                .expect("APPARATUS: write the fake PROVE");
            let next = read_frame_within(&mut recv, MAX_FLIGHT, Duration::from_secs(2)).await;
            let close = closed(&s, Duration::from_secs(5)).await;
            (next, close)
        });
        if let Ok(Some(f)) = &next {
            panic!(
                "PRODUCT: the daemon sent a flight 3 ({} bytes) to a party that did not prove the \
                 pinned node ({how:?})",
                f.len()
            );
        }
        let Some(close) = close else {
            panic!("PRODUCT: the daemon left open a connection whose PROVE failed ({how:?})")
        };
        assert_eq!(
            close.code,
            u64::from(BAD_PROVE.code()),
            "PRODUCT: the daemon closed a bad PROVE ({how:?}) with code {}, not {}",
            close.code,
            BAD_PROVE.code()
        );
        println!("[proof] a fake listener ({how:?}): no CLAIM, closed as a bad PROVE");
    }
}

/// Claim 4. Every refusal is one close at one time.
#[test]
#[ignore = "real daemons and a test-side attacker; run in release"]
fn every_refusal_is_one_close_at_one_time() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    watchdog::arm();
    let w = world();
    // A node of this daemon that was attached and is detached now: its fingerprint is what
    // `vox node create` prints.
    let pass = w._tmp.path().join("host.pass");
    let pass = pass.to_str().expect("APPARATUS: a UTF-8 path");
    let mut spare = None;
    for argv in [
        vec!["node", "create", "spare", "--passphrase-file", pass],
        vec!["node", "attach", "spare", "--passphrase-file", pass],
        vec!["node", "detach", "spare"],
    ] {
        let (ok, out, err) = vox_once_plain(&w.host.data, &args(&argv));
        assert!(
            ok,
            "APPARATUS: staging `vox {}`: {out}{err}",
            argv.join(" ")
        );
        if argv[1] == "create" {
            spare = out
                .split_whitespace()
                .find_map(|t| b32_decode(t, "fingerprint").ok());
        }
    }
    let spare = spare
        .unwrap_or_else(|| panic!("APPARATUS: `vox node create spare` printed no fingerprint"));
    let (_, listed, _) = vox_once_plain(&w.host.data, &args(&["node", "list"]));
    println!("[proof] staging: `vox node list` after the spare node's detach: {listed:?}");
    let unknown = stranger().fingerprint();
    let rt = runtime();
    let probes = rt.block_on(async {
        let e = endpoint(false);
        let mut probes = Vec::new();
        for case in [
            "unknown target",
            "detached target",
            "malformed ASK",
            "oversize flight",
            "not an identity stream",
        ] {
            let c = connect(&e, w.host.addr).await;
            let (mut send, mut recv) = c.open_bi().await.expect("APPARATUS: open a stream");
            let kind = if case == "not an identity stream" {
                StreamKind::Sync.frame()
            } else {
                StreamKind::Identity.frame()
            };
            write_frame(&mut send, &kind)
                .await
                .expect("APPARATUS: write the stream's kind");
            match case {
                "unknown target" | "detached target" => {
                    let target = if case == "unknown target" {
                        unknown
                    } else {
                        spare
                    };
                    write_frame(&mut send, &Ask { target }.encode())
                        .await
                        .expect("APPARATUS: write the ASK");
                }
                "malformed ASK" => {
                    let mut ask = Ask { target: w.host.fp }.encode();
                    ask.truncate(ask.len() - 1);
                    write_frame(&mut send, &ask)
                        .await
                        .expect("APPARATUS: write the ASK");
                }
                "oversize flight" => {
                    let len = u32::try_from(MAX_FLIGHT + 1).expect("APPARATUS: a length");
                    send.write_all(&len.to_be_bytes())
                        .await
                        .expect("APPARATUS: write the length");
                }
                _ => {}
            }
            let asked = Instant::now();
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(Ok(Some(n))) =
                tokio::time::timeout(Duration::from_secs(7), recv.read(&mut buf)).await
            {
                got.extend_from_slice(&buf[..n]);
            }
            let seen = refused(&c, &format!("the {case} case"), Duration::from_millis(7000)).await;
            probes.push((case, seen.at.duration_since(asked), got.len()));
        }
        probes
    });
    let top = ANSWER_FLOOR + ANSWER_JITTER + Duration::from_millis(150);
    for (case, after, bytes) in &probes {
        println!(
            "[proof] {case}: the one refusal, {} ms after the ASK, {bytes} flight bytes",
            ms(*after)
        );
        assert_eq!(
            *bytes, 0,
            "PRODUCT: the {case} case sent {bytes} bytes of flight"
        );
        assert!(
            *after >= ANSWER_FLOOR - Duration::from_millis(2),
            "PRODUCT: the {case} case was refused {} ms after its ASK, under the {} ms floor",
            ms(*after),
            ms(ANSWER_FLOOR)
        );
        assert!(
            *after <= top,
            "PRODUCT: the {case} case was refused {} ms after its ASK, past the {} ms window",
            ms(*after),
            ms(top)
        );
    }
}

/// What one `ASK` of a burst got.
enum Answered {
    Proved,
    Refused(Duration),
}

/// `n` connections, each through its handshake, then each one's `ASK` sent at once; what each got,
/// and how long the `ASK`s took to leave, first to last.
async fn burst(
    e: &Endpoint,
    to: SocketAddr,
    target: Digest32,
    n: usize,
) -> (Vec<Answered>, Duration) {
    let mut conns = Vec::new();
    for _ in 0..n {
        conns.push(connect(e, to).await);
    }
    let first = Instant::now();
    let tasks: Vec<_> = conns
        .into_iter()
        .map(|c| {
            tokio::spawn(async move {
                let (_send, mut recv, asked) = raw_ask(&c, target).await;
                let left = asked;
                let got = read_frame_within(&mut recv, MAX_FLIGHT, Duration::from_secs(3)).await;
                let answer = if matches!(got, Ok(Some(_))) {
                    Answered::Proved
                } else {
                    let seen = refused(&c, "a rate-limited ASK", Duration::from_millis(7000)).await;
                    Answered::Refused(seen.at.duration_since(asked))
                };
                (answer, left, c)
            })
        })
        .collect();
    let mut answers = Vec::new();
    let mut last = first;
    let mut keep = Vec::new();
    for t in tasks {
        let (a, left, c) = t.await.expect("APPARATUS: an ASK task");
        last = last.max(left);
        answers.push(a);
        keep.push(c);
    }
    (answers, last.duration_since(first))
}

/// Claim 5. 16 at once, then 8 a second, from one source.
#[test]
#[ignore = "real daemons and a test-side attacker; run in release"]
fn the_rate_limit_is_sixteen_at_once_then_eight_a_second() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    watchdog::arm();
    let w = world();
    let rt = runtime();
    rt.block_on(async {
        let e = endpoint(false);
        let top = ANSWER_FLOOR + ANSWER_JITTER + Duration::from_millis(150);
        let check = |round: &str, answers: &[Answered], span: Duration, base: u32| {
            let proved = answers
                .iter()
                .filter(|a| matches!(a, Answered::Proved))
                .count();
            let refill = (f64::from(ASKS_PER_SECOND) * span.as_secs_f64()).ceil() as usize;
            let (low, high) = (base as usize, base as usize + 1 + refill);
            println!(
                "[proof] {round}: {} ASKs over {} ms, {proved} answered, {} refused (allowed \
                 {low}..={high})",
                answers.len(),
                ms(span),
                answers.len() - proved
            );
            assert!(
                (low..=high).contains(&proved),
                "PRODUCT: {round}: {proved} of {} ASKs from one source were answered; the limit \
                 allows {low} to {high}",
                answers.len()
            );
            for a in answers {
                if let Answered::Refused(after) = a {
                    assert!(
                        *after >= ANSWER_FLOOR - Duration::from_millis(2) && *after <= top,
                        "PRODUCT: {round}: a rate-limited ASK was refused {} ms after it, outside \
                         the {}..={} ms window",
                        ms(*after),
                        ms(ANSWER_FLOOR),
                        ms(top)
                    );
                }
            }
        };
        let (first, span) = burst(&e, w.host.addr, w.host.fp, 24).await;
        check("a burst of 24", &first, span, ASK_BURST);
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let (second, span) = burst(&e, w.host.addr, w.host.fp, 12).await;
        check("12 more, 1000 ms later", &second, span, ASKS_PER_SECOND);
    });
}

/// Claim 6. QUIC's own limits hold a connection to the exchange, and a datagram before `PROVE`
/// closes it.
#[test]
#[ignore = "real daemons and a test-side attacker; run in release"]
fn the_pre_identity_limits_hold_a_connection_to_the_exchange() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    watchdog::arm();
    let w = world();
    let rt = runtime();
    rt.block_on(async {
        let e = endpoint(false);
        let c = connect(&e, w.host.addr).await;
        let wait = Duration::from_millis(300);
        let (_s0, _r0) = c.open_bi().await.expect("PRODUCT: the first stream did not open");
        let (mut s1, _r1) = c.open_bi().await.expect("PRODUCT: the second stream did not open");
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
            "PRODUCT: {} bytes went through before the exchange, past the {PRE_IDENTITY_WINDOW}-byte \
             window",
            big.len()
        );
        println!(
            "[proof] before the exchange: a third stream, a unidirectional one and {} bytes all \
             wait {} ms",
            big.len(),
            ms(wait)
        );
        drop(c);

        // Closed for the datagram, at once: not answered, and not left to the 5000 ms bound.
        let c = connect(&e, w.host.addr).await;
        let sent = Instant::now();
        c.send_datagram(b"too early".to_vec().into())
            .expect("APPARATUS: send a datagram");
        if let Ok((mut send, mut recv)) = c.open_bi().await {
            let _ = write_frame(&mut send, &StreamKind::Identity.frame()).await;
            let _ = write_frame(&mut send, &Ask { target: w.host.fp }.encode()).await;
            if let Ok(Some(_)) =
                read_frame_within(&mut recv, MAX_FLIGHT, Duration::from_millis(1000)).await
            {
                panic!("PRODUCT: the daemon answered an ASK with PROVE after a datagram");
            }
        }
        let seen = refused(&c, "a datagram before PROVE", Duration::from_millis(1500)).await;
        println!(
            "[proof] a datagram before PROVE: refused {} ms after it",
            ms(seen.at.duration_since(sent))
        );
    });
}

/// Claim 7. One exchange per connection.
#[test]
#[ignore = "real daemons and a test-side attacker; run in release"]
fn a_second_flight_after_claim_closes_the_connection() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    watchdog::arm();
    let w = world();
    let rt = runtime();
    rt.block_on(async {
        let e = endpoint(false);
        let me = stranger();
        let instance = new_instance().expect("APPARATUS: an instance");
        let c = connect(&e, w.host.addr).await;
        let (mut send, mut recv, _) = raw_ask(&c, w.host.fp).await;
        let _ = read_prove(&mut recv).await;
        let ex = exporter(&c).expect("APPARATUS: the exporter");
        let claim = Claim {
            dialler: me.public_key(),
            instance,
            sig: me
                .sign(&init_input(&ex, &w.host.fp, &me.fingerprint(), &instance))
                .expect("APPARATUS: sign"),
        };
        write_frame(&mut send, &claim.encode())
            .await
            .expect("APPARATUS: write the CLAIM");
        write_frame(&mut send, &Ask { target: w.host.fp }.encode())
            .await
            .expect("APPARATUS: write the second flight");
        let _ = send.finish();
        refused(
            &c,
            "a second flight after CLAIM",
            Duration::from_millis(2000),
        )
        .await;
        println!("[proof] a second flight after CLAIM: refused");
    });
}

/// Claim 8. A dialler that says nothing is closed at 5000 ms.
#[test]
#[ignore = "real daemons and a test-side attacker; run in release"]
fn a_silent_dialler_is_closed_at_five_seconds() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    watchdog::arm();
    let w = world();
    let rt = runtime();
    rt.block_on(async {
        let e = endpoint(false);
        let c = connect(&e, w.host.addr).await;
        let started = Instant::now();
        let seen = refused(&c, "a silent dialler", Duration::from_millis(9000)).await;
        let took = seen.at.duration_since(started);
        println!(
            "[proof] a silent dialler: closed {} ms after its handshake",
            ms(took)
        );
        assert!(
            took >= EXCHANGE_TIMEOUT - Duration::from_millis(50)
                && took <= EXCHANGE_TIMEOUT + Duration::from_millis(500),
            "PRODUCT: a silent dialler was closed {} ms after its handshake, not at {} ms",
            ms(took),
            ms(EXCHANGE_TIMEOUT)
        );
    });
}
