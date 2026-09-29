//! **A host answers the next joiner straight after the last one** (PRD-001 R42's
//! prerequisite, defect D8; ADR-017 "Open proof gap", ADR-018 "Root cause of
//! `service_rehearsal_proof:490`").
//!
//! The node's accept loop awaited each TLS handshake inline, so it served one at a time for
//! up to 30 seconds each. `vox connect` is a one-shot — it exits the moment it has joined —
//! and that left the host mid-handshake on something and deaf to everybody for the next half
//! minute. Measured on the serialised loop: a lone joiner gets in in about 2 s; a second one
//! **immediately** after the first is locked out with `direct attempt timed out` against the
//! host's real, still-bound port; a second one 40 s later gets in.
//!
//! This is that reproduction as a proof: one host, then two `vox connect`s back to back, with
//! no trust, no malice and no waiting in between. Both must get in, and **the host must answer
//! them promptly**: the time each joiner spent waiting on others — every step of its own
//! `join got in — …` line but its `solve` and `seal` (V210-65) — is bounded, not the whole join.
//!
//! **Not the whole join** (V210-62). The whole join includes the joiner's own proof of work,
//! which is its own CPU and random in length by design (ADR-005), and its own Argon2id. Bounded
//! whole, the proof measured the machine it ran on: on CI it went red at 12.2 s and 13.3 s while
//! the joiner's own line said most of the time was its `exchange (incl. solve)`, and a local run
//! under load spent 20.75 s there. The defect this proves gone made the joiner wait on the
//! **host** — `direct attempt timed out` against a deaf accept loop — and that wait is what is
//! bounded now.
//!
//! **A handshake left open in front of them** (V210-62). Back to back alone no longer stages
//! D8: each joiner's handshake finishes before the next arrives, so a host that serves one
//! handshake at a time answered both promptly, and the inline-accept mutant was green. So a peer
//! opens a handshake with the host and then holds it — its client stops in its own certificate
//! check, past the host's reply, for longer than `HANDSHAKE_TIMEOUT` — and the second joiner
//! arrives while the host waits on it. The proof waits until the host has answered that peer
//! before sending the second joiner, so the stall is in place, not assumed.
//!
//! ## Why it is `#[ignore]`d
//!
//! Production Argon2id on four profiles plus a real ADR-005 proof of work per join. CI runs
//! it in release with the other real-parameter proofs.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use world::{echo_service, VoxProc, World};

/// How long a joiner may wait on **everything but its own work**: every step of its join except
/// its proof-of-work `solve` and its local `seal` (V210-65). An answering host keeps that to tens
/// of milliseconds (measured 10–40 ms, under load too); a deaf one holds a dial for its whole 10 s
/// attempt. At 5 s the bound itself goes red on a host that is slow but under the dial attempt,
/// where 12 s never could (V210-62's verifier).
const PROMPT: Duration = Duration::from_secs(5);

/// The time a joiner spent waiting on others, from its own `join got in — …` line: every step but
/// its `solve` and `seal`. **Every step, not only `dial` and `exchange`** (V210-65): the host
/// serves the room's board too, so a host slow to take handshakes delayed the joiner's `board`
/// step, which the sum left out — a mutant that held each inbound handshake 6 s waited
/// `board 6.01s` and passed. `None` when the line is missing or lacks its `board`, `dial` or
/// `exchange` step, which is a proof that cannot measure, not a pass.
fn waited_on_others(stderr: &str) -> Option<Duration> {
    let line = stderr.lines().find(|l| l.contains("join got in — "))?;
    let steps = line.split("join got in — ").nth(1)?;
    let mut total = Duration::ZERO;
    let (mut board, mut dial, mut exchange) = (false, false, false);
    for step in steps.split(", ") {
        let Some((name, secs)) = step.rsplit_once(' ') else {
            continue;
        };
        if name.ends_with(": solve") || name == "seal" {
            continue;
        }
        board |= name == "board";
        dial |= name.ends_with(": dial");
        exchange |= name.ends_with(": exchange");
        let secs: f64 = secs.strip_suffix('s')?.parse().ok()?;
        total += Duration::from_secs_f64(secs);
    }
    (board && dial && exchange).then_some(total)
}

#[test]
#[ignore = "production Argon2id profiles + real PoW joins, driving the real binary; CI runs it in release"]
fn two_joiners_back_to_back_both_get_in_promptly() {
    watchdog::arm();
    // The world's own guest is the first joiner; `World::new` asserts it got in.
    let mut w = World::new(echo_service(), false);
    let second = w.tmp.path().join("second");
    let third = w.tmp.path().join("third");
    for d in [&second, &third] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    // A peer holds a handshake open with the host; the joiners arrive while it does.
    let answered = Arc::new(AtomicBool::new(false));
    let _held = hold_a_handshake(host_endpoint(&w), Arc::clone(&answered));
    let deadline = Instant::now() + Duration::from_secs(10);
    while !answered.load(Ordering::SeqCst) {
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE: the host never answered the held handshake, so nothing was waiting \
             on it"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // The first joiner's `vox connect` has already exited. Nothing is awaited between these.
    let (ok2, t2, out2, err2) = w.join(&second);
    eprintln!("[test] second joiner: joined={ok2} after {t2:?}");
    let (ok3, t3, out3, err3) = w.join(&third);
    eprintln!("[test] third joiner:  joined={ok3} after {t3:?}");
    assert!(
        ok2,
        "a second joiner straight after the first must get in (PRD-001 D8); after {t2:?}:\n\
         stdout:\n{out2}\nstderr:\n{err2}"
    );
    assert!(
        ok3,
        "a third joiner straight after the second must get in; after {t3:?}:\n\
         stdout:\n{out3}\nstderr:\n{err3}"
    );
    let (Some(h2), Some(h3)) = (waited_on_others(&err2), waited_on_others(&err3)) else {
        panic!(
            "CANNOT MEASURE: a joiner did not say its board, dial and exchange steps\n---- the second \
             joiner ----\n{err2}\n---- the third joiner ----\n{err3}"
        );
    };
    eprintln!("[test] waited on others: second {h2:?}, third {h3:?} (bound {PROMPT:?})");
    for (who, err) in [("second", &err2), ("third", &err3)] {
        if let Some(l) = err.lines().find(|l| l.contains("join got in — ")) {
            eprintln!("[test] {who} joiner's steps: {l}");
        }
    }
    // A slow join says what it waited on: the joiners' own step lines, and what the host noticed.
    let host_said = w.host.as_mut().map(VoxProc::transcript).unwrap_or_default();
    assert!(
        h2 < PROMPT && h3 < PROMPT,
        "back-to-back joiners must each wait under {PROMPT:?} on others; they waited {h2:?} and \
         {h3:?} (whole joins {t2:?} and {t3:?})\n---- the second joiner ----\n{err2}\n---- the \
         third joiner ----\n{err3}\n---- the host ----\n{host_said}"
    );
}

/// The host's own UDP endpoint, from the room's address: the `b=` that follows `a=<host>`.
fn host_endpoint(w: &World) -> SocketAddr {
    let at = format!("a={}&b=/ip4/127.0.0.1/udp/", w.host_fp);
    let tail = w
        .address
        .split(&at)
        .nth(1)
        .unwrap_or_else(|| panic!("no host endpoint in the room address {}", w.address));
    let port: u16 = tail
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .expect("the host's port");
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// A certificate check that does not return for [`HOLD`]: the client has the host's reply and
/// sends nothing more, so the host is left waiting on a handshake that never finishes.
#[derive(Debug)]
struct Holds {
    answered: Arc<AtomicBool>,
    schemes: Vec<rustls::SignatureScheme>,
}

/// Longer than the host's 30 s `HANDSHAKE_TIMEOUT`, so a host that waits on it waits in full.
const HOLD: Duration = Duration::from_secs(40);

impl rustls::client::danger::ServerCertVerifier for Holds {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.answered.store(true, Ordering::SeqCst);
        std::thread::sleep(HOLD);
        Err(rustls::Error::General("held".into()))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("held".into()))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("held".into()))
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.clone()
    }
}

/// Open a handshake with `host` under the Vox TLS configuration (its provider and ALPN, so the
/// host takes it as a real one) and hold it: see [`Holds`]. `answered` is set once the host's
/// reply has arrived.
fn hold_a_handshake(host: SocketAddr, answered: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async move {
            let provider = Arc::new(vox_core::transport::provider::vox_crypto_provider());
            let schemes = provider
                .signature_verification_algorithms
                .supported_schemes();
            let mut tls = rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("TLS 1.3")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(Holds { answered, schemes }))
                .with_no_client_auth();
            tls.alpn_protocols = vec![vox_core::transport::provider::VOX_ALPN.to_vec()];
            let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QUIC TLS");
            let endpoint =
                quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).expect("client");
            let connecting = endpoint
                .connect_with(quinn::ClientConfig::new(Arc::new(quic)), host, "vox")
                .expect("connect");
            let _ = connecting.await;
        });
    })
}
