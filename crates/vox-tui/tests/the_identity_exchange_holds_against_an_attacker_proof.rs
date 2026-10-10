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
//! 9. **No second exchange after the first** (requirement 33): a stream of the identity kind
//!    after the exchange closes the connection with the refusal's code, a member's and a
//!    stranger's alike (same code and reason, at once). Mutant: the gate's stream refusal kept for
//!    a stranger.
//! 10. **The answer's random delay** (requirement 32): of 16 `PROVE`s, some leave in the first
//!     half of the 50–100 ms window and some in the second. Mutant: no random delay.
//! 11. **A node that comes back is a new process** (requirement 40, ADR-026 I-3): the host's
//!     instance is the same while it stays attached and new after a detach and attach; and the
//!     host closes an identity's connection as superseded when that identity connects with a new
//!     instance, four rounds running. Mutants: the instance fixed; the instance left out of the
//!     process identity.
//! 12. **A flood of pre-identity connections is capped** (requirements 33–34): 64 that never ask
//!     hold every handshake slot, so the next waits about 5000 ms for one; and with every slot
//!     held, 1124 attempts at once have 100 refused at once (1024 wait). Mutants: no cap of 64; no
//!     cap of 1024.
//!
//! 13. **The previous published release and this build** (requirement 14): the newest published
//!     release's `vox daemon` (downloaded, digest-checked) and this build's join each other's
//!     rooms, both dial directions, and read each other's posts; this build's flights and labels
//!     complete an exchange with the published daemon. Mutant: one exchange label changed.
//! 14. **A circuit for one node cannot ask for another** (requirement 32, ADR-026 P-1): over a
//!     circuit the anchor carries for node A, an exchange asking for A completes and one asking
//!     for B, attached to the same daemon, is refused. Mutant: `serves_on` answering for any node.
//!
//! **Not measurable from outside, so not claimed here:** that a rate-limited `ASK` is refused
//! *before* its target is looked up (requirement 34's order: the lookup leaves no trace on the
//! wire), and a listener whose exporter fails (an internal failure no attacker can cause).
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
#[path = "support/previous_release.rs"]
mod previous_release;
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
    spec: String,
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
        spec,
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

/// Claim 9 (requirement 33's last rule). Once the exchange is done, a stream that opens with the
/// identity kind is a second exchange, and closes the connection with the refusal, **whoever opens
/// it**: a member of the host's room (whose key the attacker holds, its own daemon stopped) and a
/// stranger alike, with the same code and reason text, at once. A stranger's used to be refused as
/// a stream, like any kind it may not open, and its connection stayed.
#[test]
#[ignore = "real daemons and a test-side attacker; run in release"]
fn an_identity_stream_after_the_exchange_closes_the_connection() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    watchdog::arm();
    let w = world();
    let (_room, link) = hostile::create_room(&w.host.data, "team", "room pass");
    let member = {
        let m = daemon(w._tmp.path(), "member", &w.spec);
        let (ok, out, err) = hostile::vox_in(
            &m.data,
            &["room", "join", "--passphrase-file", "-", &link],
            "room pass",
        );
        assert!(
            ok,
            "APPARATUS: staging: the member could not join: {out}{err}"
        );
        // Let the host file the new member before its daemon goes.
        std::thread::sleep(Duration::from_secs(3));
        m.data.clone()
    };
    let signer = hostile::member_signer(&member);
    let stranger = stranger();
    let rt = runtime();
    let (as_member, as_stranger) = rt.block_on(async {
        let e = endpoint(false);
        let member = second_exchange(&e, w.host.addr, w.host.fp, &*signer).await;
        let stranger = second_exchange(&e, w.host.addr, w.host.fp, &stranger).await;
        (member, stranger)
    });
    let mut red = Vec::new();
    for (who, seen) in [("a member", &as_member), ("a stranger", &as_stranger)] {
        let Some((code, reason, after)) = seen else {
            red.push(format!(
                "{who}'s identity stream after the exchange left the connection open 2000 ms later"
            ));
            continue;
        };
        println!(
            "[proof] {who}'s identity stream after the exchange: closed {} ms after it opened, code \
             {code}, reason {reason:?}",
            ms(*after)
        );
        if *code != refusal() {
            red.push(format!(
                "{who}'s identity stream closed the connection with code {code}, not the \
                 refusal's ({})",
                refusal()
            ));
        }
    }
    // **A stranger learns nothing a member does not**: the same code and reason text, and both at
    // once (the timing class of a stream refusal, which was also at once).
    if let (Some(m), Some(s)) = (&as_member, &as_stranger) {
        if m.1 != s.1 || m.0 != s.0 {
            red.push(format!(
                "a stranger's close ({}, {:?}) differs from a member's ({}, {:?})",
                s.0, s.1, m.0, m.1
            ));
        }
        for (who, after) in [("member", m.2), ("stranger", s.2)] {
            if after > Duration::from_millis(500) {
                red.push(format!(
                    "the {who}'s close came {} ms after the stream opened, not at once",
                    ms(after)
                ));
            }
        }
    }
    assert!(red.is_empty(), "PRODUCT: {red:#?}");
}

/// After an honest exchange as `who`, open a stream of the identity kind: how the connection was
/// closed (code, reason, ms after the stream opened), or `None` if it was still open 2000 ms later.
async fn second_exchange(
    e: &Endpoint,
    to: SocketAddr,
    target: Digest32,
    who: &(dyn RootSigner + Send + Sync),
) -> Option<(u64, String, Duration)> {
    let c = connect(e, to).await;
    dial(
        &c,
        who,
        new_instance().expect("APPARATUS: an instance"),
        target,
    )
    .await
    .unwrap_or_else(|f| panic!("PRODUCT: an honest dial was refused: {f:?}"));
    let (mut send, _recv) = c
        .open_bi()
        .await
        .expect("PRODUCT: a stream after the exchange did not open");
    let opened = Instant::now();
    write_frame(&mut send, &StreamKind::Identity.frame())
        .await
        .expect("APPARATUS: write the stream's kind");
    write_frame(&mut send, &Ask { target }.encode())
        .await
        .expect("APPARATUS: write the ASK");
    // After the exchange the peer is known, so the close may say why ("not available").
    closed(&c, Duration::from_millis(2000)).await.map(|seen| {
        (
            seen.code,
            String::from_utf8_lossy(&seen.reason).into_owned(),
            seen.at.duration_since(opened),
        )
    })
}

/// Claim 10 (requirement 32's timing). Each `PROVE` leaves no earlier than the 50 ms floor after
/// its `ASK`, plus a random delay up to 50 ms, so a prober cannot learn a refusal's timing from a
/// constant: of 16 answers, some come in the window's first half and some in its second.
#[test]
#[ignore = "real daemons and a test-side attacker; run in release"]
fn every_answer_waits_the_floor_and_a_random_delay() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    watchdog::arm();
    let w = world();
    let rt = runtime();
    let fp = w.host.fp;
    let delays = rt.block_on(async {
        let e = endpoint(false);
        let mut conns = Vec::new();
        for _ in 0..ASK_BURST {
            conns.push(connect(&e, w.host.addr).await);
        }
        let tasks: Vec<_> = conns
            .into_iter()
            .map(|c| {
                tokio::spawn(async move {
                    let (_send, mut recv, asked) = raw_ask(&c, fp).await;
                    let _ = read_prove(&mut recv).await;
                    let took = asked.elapsed();
                    drop(c);
                    took
                })
            })
            .collect();
        let mut delays = Vec::new();
        for t in tasks {
            delays.push(t.await.expect("APPARATUS: an ASK task"));
        }
        delays
    });
    let mid = ANSWER_FLOOR + ANSWER_JITTER / 2;
    let top = ANSWER_FLOOR + ANSWER_JITTER + Duration::from_millis(150);
    let mut ms_list: Vec<u128> = delays.iter().map(|d| ms(*d)).collect();
    ms_list.sort_unstable();
    let early = delays.iter().filter(|d| **d < mid).count();
    let late = delays.len() - early;
    println!(
        "[proof] {} PROVEs after their ASKs, ms: {ms_list:?}; {early} before {} ms, {late} at or \
         after",
        delays.len(),
        ms(mid)
    );
    for d in &delays {
        assert!(
            *d >= ANSWER_FLOOR - Duration::from_millis(2) && *d <= top,
            "PRODUCT: a PROVE left {} ms after its ASK, outside {}..={} ms",
            ms(*d),
            ms(ANSWER_FLOOR),
            ms(top)
        );
    }
    assert!(
        early >= 3 && late >= 3,
        "PRODUCT: of {} PROVEs, {early} left in the first half of the window and {late} in the \
         second: the delay is not spread over the window ({ms_list:?} ms)",
        delays.len()
    );
}

/// Claim 11 (requirement 40, ADR-026 I-3). **A node that comes back is a new process to its
/// peers.** Its instance is drawn fresh at every attach: two `ASK`s while the host's node stays
/// attached get one instance in their `PROVE`s, and one after `vox node detach` and `vox node
/// attach` gets another. And a peer takes a connection of a new instance for a new process of
/// that identity: an identity that connects again with a new instance has its connection before
/// closed by the host (`Unresponsive`, ADR-011 V210-57), while the new one stays, every time.
#[test]
#[ignore = "real daemons and a test-side attacker; run in release"]
fn a_node_that_comes_back_is_a_new_process() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    watchdog::arm();
    let w = world();
    let rt = runtime();
    let fp = w.host.fp;
    let instance_of = |rt: &hostile::Rt| {
        rt.block_on(async {
            let e = endpoint(false);
            let c = connect(&e, w.host.addr).await;
            let (_send, mut recv, _) = raw_ask(&c, fp).await;
            let prove = read_prove(&mut recv).await;
            Prove::decode(&prove)
                .expect("PRODUCT: the daemon's PROVE does not parse")
                .instance
        })
    };
    let (first, again) = (instance_of(&rt), instance_of(&rt));
    let pass = w._tmp.path().join("host.pass");
    let pass = pass.to_str().expect("APPARATUS: a UTF-8 path");
    for argv in [
        vec!["node", "detach", "default"],
        vec![
            "node",
            "attach",
            "default",
            "--keep",
            "--passphrase-file",
            pass,
        ],
    ] {
        let (ok, out, err) = vox_once_plain(&w.host.data, &args(&argv));
        assert!(
            ok,
            "APPARATUS: staging `vox {}`: {out}{err}",
            argv.join(" ")
        );
    }
    let back = instance_of(&rt);
    println!(
        "[proof] the host's instance: {} twice while attached ({}), {} after detach and attach",
        b32_encode_16(&first),
        first == again,
        b32_encode_16(&back)
    );
    assert_eq!(
        first, again,
        "PRODUCT: the host's instance changed while its node stayed attached"
    );
    assert_ne!(
        first, back,
        "PRODUCT: the host's node came back with the instance it had: its peers would take it for \
         the process before"
    );

    // The peer's side: one identity, a new instance each round.
    let me = stranger();
    rt.block_on(async {
        let e = endpoint(false);
        let held = connect(&e, w.host.addr).await;
        dial(
            &held,
            &me,
            new_instance().expect("APPARATUS: an instance"),
            fp,
        )
        .await
        .unwrap_or_else(|f| panic!("PRODUCT: an honest dial was refused: {f:?}"));
        let mut held = held;
        let unresponsive = u64::from(vox_core::wire::WireError::Unresponsive.code());
        for round in 1..=4 {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let next = connect(&e, w.host.addr).await;
            dial(
                &next,
                &me,
                new_instance().expect("APPARATUS: an instance"),
                fp,
            )
            .await
            .unwrap_or_else(|f| {
                panic!("PRODUCT: round {round}: an honest dial was refused: {f:?}")
            });
            let Some(old) = closed(&held, Duration::from_millis(1000)).await else {
                panic!(
                    "PRODUCT: round {round}: the connection of the process before was still open \
                     1000 ms after a new process of its identity connected"
                )
            };
            assert_eq!(
                old.code, unresponsive,
                "PRODUCT: round {round}: the connection of the process before was closed with \
                 code {}, not as superseded by a new process ({unresponsive})",
                old.code
            );
            assert!(
                closed(&next, Duration::from_millis(1000)).await.is_none(),
                "PRODUCT: round {round}: the new process's connection was closed"
            );
            held = next;
        }
        println!("[proof] 4 rounds: each new instance's connection closed the one before");
    });
}

/// A 16-byte instance, shown in base32.
fn b32_encode_16(i: &[u8; 16]) -> String {
    let mut d = [0u8; 32];
    d[..16].copy_from_slice(i);
    b32_encode(&d)[..26].to_owned()
}

/// Claim 12 (requirements 33, 34; ADR-026). **A flood of pre-identity connections is capped.**
/// 64 connections that finish their handshake and never ask hold every handshake slot until the
/// 5000 ms exchange bound closes them; the next attempt waits for a slot, so its handshake
/// finishes only once one frees. With every slot held, at most 1024 more attempts wait: a burst of
/// 1124 has its last 100 refused at once.
#[test]
#[ignore = "real daemons and a test-side attacker; run in release"]
fn a_flood_of_pre_identity_connections_is_capped() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    watchdog::arm();
    let w = world();
    let rt = runtime();
    let addr = w.host.addr;
    rt.block_on(async {
        let e = endpoint(false);
        // Every slot held, by connections that never ask.
        let started = Instant::now();
        let mut silent = Vec::new();
        for _ in 0..64 {
            silent.push(connect(&e, addr).await);
        }
        let held_by = started.elapsed();
        // The next attempt waits for a slot.
        let asked = Instant::now();
        let next = tokio::time::timeout(Duration::from_secs(15), async {
            e.connect(addr, "vox.invalid")
                .expect("APPARATUS: start a connection")
                .await
        })
        .await
        .expect("PRODUCT: the 65th attempt neither finished nor was refused in 15000 ms");
        let waited = asked.elapsed();
        println!(
            "[proof] 64 silent connections took the slots in {} ms; the 65th attempt's handshake \
             finished {} ms after it began ({})",
            ms(held_by),
            ms(waited),
            if next.is_ok() { "admitted" } else { "refused" }
        );
        assert!(
            waited >= Duration::from_millis(3000),
            "PRODUCT: with every handshake slot held, the 65th attempt finished its handshake {} ms \
             after it began: the cap of 64 did not hold it",
            ms(waited)
        );
        drop(next);
        drop(silent);
        // Wait for the slots to come back before the next part.
        tokio::time::sleep(Duration::from_millis(6000)).await;

        // Every slot held again; then 1124 attempts at once.
        let mut silent = Vec::new();
        for _ in 0..64 {
            silent.push(connect(&e, addr).await);
        }
        let fired = Instant::now();
        let attempts: Vec<_> = (0..1124)
            .map(|_| {
                let connecting = e
                    .connect(addr, "vox.invalid")
                    .expect("APPARATUS: start a connection");
                tokio::spawn(async move {
                    let r = tokio::time::timeout(Duration::from_secs(15), connecting).await;
                    (r, Instant::now())
                })
            })
            .collect();
        // A slot freed while the burst arrived (one of the 64 closing early) lets an attempt run at
        // once, so it never queues: the queue's bound shows as the refusals at once plus those.
        let (mut refused_at_once, mut admitted_at_once, mut other) = (0usize, 0usize, 0usize);
        for a in attempts {
            let (r, at) = a.await.expect("APPARATUS: an attempt task");
            let at_once = at.duration_since(fired) < Duration::from_millis(2000);
            match r {
                Ok(Err(quinn::ConnectionError::ConnectionClosed(_))) if at_once => {
                    refused_at_once += 1;
                }
                Ok(Ok(_)) if at_once => admitted_at_once += 1,
                _ => other += 1,
            }
        }
        println!(
            "[proof] with every slot held, 1124 attempts at once: {refused_at_once} refused within \
             2000 ms, {admitted_at_once} admitted within 2000 ms (a slot came free), {other} \
             waited longer"
        );
        assert!(
            refused_at_once + admitted_at_once >= 1124 - 1024,
            "PRODUCT: with every slot held, {refused_at_once} of 1124 attempts were refused at \
             once and {admitted_at_once} admitted at once: the 1024 waiting places did not bound \
             the queue"
        );
        drop(silent);
    });
}

/// `exe` (a `vox`) run once on the data root `data`, as `vox_once_plain` runs this build: the
/// identity passphrase in its environment, a keyring change typed at a terminal, `stdin` given.
fn run_as(exe: &Path, data: &Path, argv: &[&str], stdin: Option<&str>) -> (bool, String) {
    use std::io::Write as _;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(argv)
        .env("VOX_PROXY", world::proxy())
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE");
    if world::typed::is_keyring_change(argv) {
        return world::typed::keyring(&cmd);
    }
    let mut child = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: could not run {}: {e}", exe.display()));
    if let Some(input) = stdin {
        let _ = child
            .stdin
            .take()
            .expect("APPARATUS: a piped stdin")
            .write_all(input.as_bytes());
    }
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("APPARATUS: wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

/// A `vox daemon` of `exe` for a fresh identity named `name` under `root`, with `--anchor spec`.
fn daemon_of(exe: &Path, root: &Path, name: &str, spec: &str) -> Daemon {
    let data = hostile::profile_dir(root, name);
    let pass = root.join(format!("{name}.pass"));
    std::fs::write(&pass, IDENTITY).expect("APPARATUS: write the passphrase file");
    let (ok, said) = run_as(exe, &data, &["id"], None);
    assert!(ok, "APPARATUS: staging {name}'s `vox id`: {said}");
    let fp = said
        .split_whitespace()
        .find_map(|t| b32_decode(t, "fingerprint").ok())
        .unwrap_or_else(|| panic!("APPARATUS: {name}'s `vox id` printed no fingerprint: {said}"));
    let proc = VoxProc::spawn_exe(
        exe,
        name,
        &data,
        &args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--anchor",
            spec,
            "--passphrase-file",
            pass.to_str().expect("APPARATUS: a UTF-8 path"),
        ]),
        &[],
    );
    let deadline = Instant::now() + Duration::from_secs(120);
    while !run_as(exe, &data, &["room", "list"], None).0 {
        assert!(
            Instant::now() < deadline,
            "APPARATUS: {name}'s daemon ({}) never answered `vox room list`",
            exe.display()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let port = hostile::listening_port(&data);
    Daemon {
        _proc: proc,
        data,
        fp,
        addr: SocketAddr::from(([127, 0, 0, 1], port)),
    }
}

/// Claim 13 (requirement 14). **The previous published release and this build complete the
/// exchange, both ways.** The previous release's `vox daemon` (downloaded, its digest checked)
/// and this build's are members of each other's rooms: the old one joins a room the new one made
/// (old dials new) and the new one joins a room the old one made (new dials old); each trusts the
/// other, and this build reads the old one's post in both rooms. And this build's flights and
/// labels are the previous release's: a `PROVE` from the old daemon verifies under this build's
/// `resp_input` and exporter label, and a `CLAIM` this build signs is accepted by the old daemon.
///
/// **Key delivery is lockstep** (ADR-030 W-4, D-5). This build delivers every key in a session of
/// its own (`OP_ROTATION_HELLO`), which the old release cannot read, so the old one reads nothing
/// new from this build, in either room: its key is never sealed where the old node could open it,
/// in the pair's long-lived session. This build's daemon says why, in plain words, and resends the
/// same delivery after a backoff, never every second. Mutants: sealing the key in the long-lived
/// session again (the old one reads this build); a stream ended without an answer counted as lost
/// (no plain reason, and a resend each second).
#[test]
#[ignore = "downloads the previous release; real daemons of each; run in release"]
fn the_previous_release_and_this_build_complete_the_exchange_both_ways() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    watchdog::arm_for(Duration::from_secs(900));
    let mut w = world();
    let (version, old) = previous_release::previous_release(w._tmp.path());
    let new = Path::new(world::VOX);
    let old_d = daemon_of(&old, w._tmp.path(), "old", &w.spec);
    let new_d = &w.host;

    // Labels and flights: this build's library against the old daemon.
    let rt = runtime();
    rt.block_on(async {
        let e = endpoint(false);
        let me = stranger();
        let c = connect(&e, old_d.addr).await;
        dial(&c, &me, new_instance().expect("APPARATUS: an instance"), old_d.fp)
            .await
            .unwrap_or_else(|f| {
                panic!(
                    "PRODUCT: this build's exchange with v{version}'s daemon failed: {f:?} (its PROVE \
                     did not verify under this build's labels, or it refused this build's CLAIM)"
                )
            });
        // Taken: the limits are raised, three more streams at once, and the connection stays.
        let mut held = Vec::new();
        for i in 0..3 {
            let opened = tokio::time::timeout(Duration::from_millis(2000), c.open_bi()).await;
            let Ok(Ok(pair)) = opened else {
                panic!(
                    "PRODUCT: v{version}'s daemon did not take this build's CLAIM: stream {i} after \
                     it did not open in 2000 ms"
                )
            };
            held.push(pair);
        }
        assert!(
            closed(&c, Duration::from_millis(1000)).await.is_none(),
            "PRODUCT: v{version}'s daemon closed the connection after this build's CLAIM"
        );
        println!("[proof] this build's flights and labels against v{version}'s daemon: exchanged");
    });

    // Real use, both ways.
    let room_pass = "room pass";
    let make_room = |exe: &Path, d: &Daemon, name: &str| -> String {
        let (ok, said) = run_as(
            exe,
            &d.data,
            &["room", "create", "--passphrase-file", "-", "--name", name],
            Some(room_pass),
        );
        assert!(ok, "APPARATUS: staging `vox room create {name}`: {said}");
        let (ok, list) = run_as(exe, &d.data, &["room", "list"], None);
        assert!(ok, "APPARATUS: staging `vox room list`: {list}");
        let short = list
            .split_whitespace()
            .next()
            .unwrap_or_else(|| panic!("APPARATUS: no room listed: {list}"))
            .to_owned();
        let (ok, link) = run_as(exe, &d.data, &["room", "link", &short], None);
        assert!(ok, "APPARATUS: staging `vox room link`: {link}");
        link.split_whitespace()
            .find(|t| t.starts_with("vox://"))
            .unwrap_or_else(|| panic!("APPARATUS: no room link in {link:?}"))
            .to_owned()
    };
    let to_new = make_room(new, new_d, "made-by-new");
    let to_old = make_room(&old, &old_d, "made-by-old");
    let mut red = Vec::new();
    let mut joined = Vec::new();
    for (who, exe, d, link) in [
        (
            format!("v{version} (old dials new)"),
            old.as_path(),
            &old_d,
            &to_new,
        ),
        ("this build (new dials old)".to_owned(), new, new_d, &to_old),
    ] {
        let (ok, said) = run_as(
            exe,
            &d.data,
            &["room", "join", "--passphrase-file", "-", link],
            Some(room_pass),
        );
        println!("[proof] {who} joined: {ok}");
        joined.push(ok);
        if !ok {
            red.push(format!("{who} could not join: {said}"));
        }
    }
    for (exe, d, other, name) in [
        (old.as_path(), &old_d, new_d, "new"),
        (new, new_d, &old_d, "old"),
    ] {
        let fp = b32_encode(&other.fp);
        let (ok, said) = run_as(exe, &d.data, &["trust", "add", &fp, "--name", name], None);
        assert!(ok, "APPARATUS: staging `vox trust add {name}`: {said}");
    }
    let trusted_at = Instant::now();
    // The room made by new is the one old joined, and the other way round.
    for (room_of, was_joined) in [("new", joined[0]), ("old", joined[1])] {
        if !was_joined {
            continue;
        }
        let marker_old = format!("from-old-in-{room_of}");
        let marker_new = format!("from-new-in-{room_of}");
        let room = |exe: &Path, d: &Daemon| -> String {
            let (_, list) = run_as(exe, &d.data, &["room", "list"], None);
            list.lines()
                .find(|l| l.contains(&format!("made-by-{room_of}")))
                .and_then(|l| l.split_whitespace().next())
                .unwrap_or_else(|| panic!("APPARATUS: room made-by-{room_of} not listed: {list}"))
                .to_owned()
        };
        let (r_old, r_new) = (room(&old, &old_d), room(new, new_d));
        let deadline = Instant::now() + Duration::from_secs(90);
        // Long enough for the old one to read this build if its key had reached it: before ADR-030
        // both read each other within a few seconds.
        let fair = Instant::now() + Duration::from_secs(30);
        let (mut new_reads_old, mut old_reads_new) = (false, false);
        while Instant::now() < deadline && !(new_reads_old && Instant::now() >= fair) {
            let _ = run_as(
                &old,
                &old_d.data,
                &["room", "post", &r_old, &marker_old],
                None,
            );
            let _ = run_as(
                new,
                &new_d.data,
                &["room", "post", &r_new, &marker_new],
                None,
            );
            std::thread::sleep(Duration::from_secs(1));
            new_reads_old |= run_as(
                new,
                &new_d.data,
                &["room", "read", &r_new, "--limit", "500"],
                None,
            )
            .1
            .contains(&marker_old);
            old_reads_new |= run_as(
                &old,
                &old_d.data,
                &["room", "read", &r_old, "--limit", "500"],
                None,
            )
            .1
            .contains(&marker_new);
        }
        println!(
            "[proof] in the room made by {room_of}: this build read v{version}: {new_reads_old}; \
             v{version} read this build: {old_reads_new}"
        );
        if !new_reads_old {
            red.push(format!(
                "this build never read v{version}'s post in the room made by {room_of}"
            ));
        }
        if old_reads_new {
            red.push(format!(
                "v{version} read this build's post in the room made by {room_of}: this build's key \
                 reached a node that cannot read a key delivered in a session of its own, so it was \
                 sealed where that node opens it, in the long-lived session (ADR-030 W-4)"
            ));
        }
    }
    // What this build's daemon told its person about the old one's keys.
    let since = trusted_at.elapsed();
    let said = w.host._proc.transcript();
    let old_id: String = b32_encode(&old_d.fp).chars().take(20).collect();
    let refusals: Vec<&str> = said
        .lines()
        .filter(|l| l.contains(&old_id) && l.contains("did not take our key"))
        .collect();
    let plain = refusals
        .iter()
        .filter(|l| {
            l.contains(
                "it closed the stream without an answer, as a node running a Vox older than key \
                 delivery in a session of its own does; it reads nothing new from you until it is \
                 updated",
            )
        })
        .count();
    println!(
        "[proof] this build's daemon on v{version}'s keys, over {}s: {} refusal(s), {plain} saying \
         why plainly; first: {:?}",
        since.as_secs(),
        refusals.len(),
        refusals.first()
    );
    if joined.iter().any(|j| *j) && plain == 0 {
        red.push(format!(
            "this build never said plainly why v{version} took no key of its; it said, first: {:#?}",
            &refusals[..refusals.len().min(3)]
        ));
    }
    // A backoff from 2 s doubling: a handful per room a minute. A resend each second is two a
    // second over the two rooms.
    if refusals.len() as u64 > since.as_secs() / 2 {
        red.push(format!(
            "this build resent its key to v{version} {} times in {}s, about every second, though \
             that node had answered by closing the stream",
            refusals.len(),
            since.as_secs()
        ));
    }
    assert!(red.is_empty(), "PRODUCT: {red:#?}");
}

/// Claim 14 (requirement 32, ADR-026 P-1). **A relayed connection for node A cannot ask for node
/// B on the same daemon.** The host's daemon holds two nodes, A (its own) and B. The attacker, a
/// member of A's room whose key it holds (its own daemon stopped), asks the room's anchor for a
/// circuit to A, which the anchor carries; over it, an exchange asking for A completes, and one
/// asking for B is refused, though B is attached to the same daemon: a relay cannot use one node's
/// circuit to learn whether another is hosted there.
#[test]
#[ignore = "real daemons and a test-side attacker; run in release"]
fn a_circuit_for_one_node_cannot_ask_for_another() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    watchdog::arm();
    let w = world();
    let a_fp = w.host.fp;
    // A member of A's room, known to the anchor, whose key the attacker then holds.
    let (_room, link) = hostile::create_room(&w.host.data, "team", "room pass");
    let member = {
        let m = daemon(w._tmp.path(), "member", &w.spec);
        let (ok, out, err) = hostile::vox_in(
            &m.data,
            &["room", "join", "--passphrase-file", "-", &link],
            "room pass",
        );
        assert!(
            ok,
            "APPARATUS: staging: the member could not join: {out}{err}"
        );
        std::thread::sleep(Duration::from_secs(3));
        m.data.clone()
    };
    // Node B, attached to the same daemon (after the room: a data root of several nodes asks
    // which one a verb is for).
    let pass = w._tmp.path().join("host.pass");
    let pass = pass.to_str().expect("APPARATUS: a UTF-8 path");
    let (ok, out, err) = vox_once_plain(
        &w.host.data,
        &args(&["node", "create", "b", "--passphrase-file", pass]),
    );
    assert!(ok, "APPARATUS: staging `vox node create b`: {out}{err}");
    let b_fp = out
        .split_whitespace()
        .find_map(|t| b32_decode(t, "fingerprint").ok())
        .unwrap_or_else(|| panic!("APPARATUS: `vox node create b` printed no fingerprint: {out}"));
    let (ok, out, err) = vox_once_plain(
        &w.host.data,
        &args(&["node", "attach", "b", "--passphrase-file", pass]),
    );
    assert!(ok, "APPARATUS: staging `vox node attach b`: {out}{err}");
    let signer = hostile::member_signer(&member);
    let anchor_addr = world::spec_addr(&w.spec);
    let anchor_fp = b32_decode(
        w.spec.split('@').next().expect("APPARATUS: a spec"),
        "anchor fingerprint",
    )
    .expect("APPARATUS: the anchor's spec carries its fingerprint");
    let rt = runtime();
    let (to_a, to_b) = rt.block_on(async {
        let (endpoint, relay) = hostile::connect(&signer, anchor_addr, anchor_fp).await;
        let endpoint = Arc::new(endpoint);
        let to_a = over_circuit_for(&endpoint, &relay, a_fp, a_fp).await;
        let to_b = over_circuit_for(&endpoint, &relay, a_fp, b_fp).await;
        (to_a, to_b)
    });
    println!(
        "[proof] over a circuit for A: asking for A {}; asking for B (same daemon) {}",
        to_a.as_ref()
            .map_or_else(|e| format!("failed: {e}"), |()| "completed".to_owned()),
        to_b.as_ref()
            .map_or_else(|e| format!("failed: {e}"), |()| "completed".to_owned()),
    );
    assert!(
        to_a.is_ok(),
        "APPARATUS: the circuit for A did not carry an exchange with A: {to_a:?}"
    );
    assert!(
        to_b.is_err(),
        "PRODUCT: over a circuit attached for node A, an exchange asking for node B completed: the \
         daemon answered for another node than the circuit's"
    );
}

/// Ask `relay` for a circuit to `circuit_for`, then dial over it expecting `ask_for`: `Ok` if the
/// exchange completed. The circuit's datagrams are moved by a loop of this test's own, as
/// `circuitstream::connect_through` moves them.
async fn over_circuit_for(
    endpoint: &Arc<vox_core::transport::quic::VoxEndpoint>,
    relay: &Arc<vox_core::transport::quic::VoxConnection>,
    circuit_for: Digest32,
    ask_for: Digest32,
) -> Result<(), String> {
    use vox_core::node::circuitstream::{CircuitFrame, CIRCUIT_DATAGRAM_MAX};
    use vox_core::transport::framing::read_frame;
    use vox_core::transport::streams::open_typed;
    let (mut send, mut recv) = open_typed(relay, StreamKind::Circuit)
        .await
        .map_err(|e| format!("circuit stream: {e:?}"))?;
    write_frame(
        &mut send,
        &CircuitFrame::Open { peer: circuit_for }.to_bytes(),
    )
    .await
    .map_err(|e| format!("OPEN: {e:?}"))?;
    let answer = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut recv, 64 * 1024))
        .await
        .map_err(|_| "the relay did not answer the OPEN in 10000 ms".to_owned())?
        .map_err(|e| format!("the relay's answer: {e:?}"))?
        .ok_or("the relay closed the circuit stream")?;
    match CircuitFrame::from_bytes(&answer) {
        Ok(CircuitFrame::Opened) => {}
        other => panic!("APPARATUS: the anchor did not open a circuit to A: {other:?}"),
    }
    let mut flow = relay
        .bind_flow(send, recv)
        .map_err(|e| format!("bind the flow: {e:?}"))?;
    flow.cap_datagrams(CIRCUIT_DATAGRAM_MAX);
    let mut port = endpoint
        .attach_circuit_via(&circuit_for, &relay.peer_id(), Some(relay.as_carrier()))
        .map_err(|e| format!("attach the circuit: {e:?}"))?;
    let target = port.addr();
    let mut outbound = port
        .take_outbound()
        .expect("APPARATUS: the port's outbound");
    let inlet = port.inlet();
    let mover = tokio::spawn(async move {
        let _port = port;
        loop {
            tokio::select! {
                out = outbound.recv() => {
                    let Some(packet) = out else { break };
                    if flow.send(&packet).is_err() { break; }
                }
                inbound = flow.recv() => {
                    let Some(packet) = inbound else { break };
                    inlet.deliver(packet);
                }
            }
        }
    });
    let dialled = tokio::time::timeout(
        Duration::from_secs(15),
        vox_core::nat::reachability::connect_direct(
            Arc::clone(endpoint),
            &[target],
            ask_for,
            hostile::now_ms(),
        ),
    )
    .await;
    mover.abort();
    match dialled {
        Ok(Ok(_conn)) => Ok(()),
        Ok(Err(e)) => Err(format!("{e}")),
        Err(_) => Err("no answer in 15000 ms".to_owned()),
    }
}
