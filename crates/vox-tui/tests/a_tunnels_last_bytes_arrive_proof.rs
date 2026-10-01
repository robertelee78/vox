//! V210-81 (#272) — **a tunnel's last bytes arrive even when its host stops right after sending
//! them**, through the shipped binary.
//!
//! A tunnel's splice used to `finish()` its QUIC send half and return at once. The bytes it had
//! written were then only in quinn's send buffer, and a close of the connection that followed —
//! a node shutting down (`stop_network`), or a retired connection closed because nothing held it
//! any more — threw away whatever the peer had not yet acknowledged. The application at the far
//! end saw its connection reset part-way through a reply whose sender had finished it.
//!
//! Staging, all real processes: a `vox node` anchor, a host running `vox serve` in front of a
//! backend this test runs, and a guest that `vox connect`s and `vox forward`s. The host listens on
//! `127.0.0.1` and the guest on `[::1]`, so neither can send the other a datagram
//! (`support/relay.rs`); their direct path is a userspace UDP relay on `[::1]` in front of the
//! host that delays every packet by [`ONE_WAY`] each way and carries the host's at [`RATE`] (the
//! host advertises it, `VOX_TEST_ADVERTISE`), so that a reply is still leaving the host for a
//! while after its sender finished it. The application sends a request and half-closes; the
//! backend answers [`REPLY`] bytes and closes; [`AFTER_CLOSE`] later the host's `vox serve` is
//! interrupted (SIGINT), exactly as a person stops it.
//!
//! Asserted: the application reads all [`REPLY`] bytes, in order, and then a clean end of stream.
//! A warm-up exchange that reads a truncated reply with nothing stopped is the same data loss,
//! and is a PRODUCT red too, as is a `vox connect` that fails.
//!
//! ## Preconditions (else CANNOT MEASURE)
//! The tunnel crossed the relay, and when the host was interrupted the relay had not yet carried
//! the whole reply toward the guest (else the close came too late to test anything).
//!
//! ## Mutation
//! Return from the splice right after `finish()`, without waiting for the peer to acknowledge,
//! and let the node close its connections without waiting for finished tunnels: the reply is cut
//! short and the application's connection is reset.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use world::{after_label, args, vox_once, VoxProc};

/// The reply: more than the relay's delay lets arrive before the host is stopped.
const REPLY: usize = 8 << 20;
/// Each way, on the relay between guest and host.
const ONE_WAY: Duration = Duration::from_millis(40);
/// The relay's rate toward the guest, in bytes per second: the reply takes about 1.7 s to cross,
/// so most of it has not left the host when the host is interrupted.
const RATE: f64 = 5e6;
/// How long after the backend closed that the host is interrupted: long enough for the host to
/// have read the whole reply and finished its stream, short of the reply having arrived.
const AFTER_CLOSE: Duration = Duration::from_millis(100);
/// How long the application waits for the end of the reply.
const READ_BOUND: Duration = Duration::from_secs(60);

fn byte(i: usize) -> u8 {
    (i % 251) as u8
}

/// A UDP relay in front of `upstream` that delays every datagram by [`ONE_WAY`] in each
/// direction, and carries the host's datagrams toward the client at [`RATE`]. Returns its address and the bytes it has carried toward the client.
fn delaying_relay(upstream: SocketAddr) -> (SocketAddr, Arc<AtomicU64>) {
    let front = UdpSocket::bind("[::1]:0").expect("APPARATUS: bind the relay");
    let back = UdpSocket::bind("127.0.0.1:0").expect("APPARATUS: bind the relay's upstream side");
    back.connect(upstream)
        .expect("APPARATUS: connect the relay upstream");
    let addr = front.local_addr().expect("APPARATUS: the relay's address");
    let to_client = Arc::new(AtomicU64::new(0));
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // Toward the host.
    let (rx, tx) = (
        front
            .try_clone()
            .expect("APPARATUS: clone the relay socket"),
        back.try_clone().expect("APPARATUS: clone the relay socket"),
    );
    let learn = Arc::clone(&client);
    let (q_tx, q_rx) = mpsc::channel::<(Instant, Vec<u8>)>();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = rx.recv_from(&mut buf) {
            *learn.lock().expect("APPARATUS: the relay's client lock") = Some(from);
            if q_tx
                .send((Instant::now() + ONE_WAY, buf[..n].to_vec()))
                .is_err()
            {
                return;
            }
        }
    });
    std::thread::spawn(move || {
        for (due, pkt) in q_rx {
            std::thread::sleep(due.saturating_duration_since(Instant::now()));
            let _ = tx.send(&pkt);
        }
    });

    // Toward the client, paced at [`RATE`]: the reply takes a while to leave the host.
    let (q_tx, q_rx) = mpsc::channel::<(Instant, Vec<u8>)>();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        let mut next_free = Instant::now();
        while let Ok(n) = back.recv(&mut buf) {
            next_free = next_free.max(Instant::now()) + Duration::from_secs_f64(n as f64 / RATE);
            if q_tx.send((next_free + ONE_WAY, buf[..n].to_vec())).is_err() {
                return;
            }
        }
    });
    let carried = Arc::clone(&to_client);
    std::thread::spawn(move || {
        for (due, pkt) in q_rx {
            std::thread::sleep(due.saturating_duration_since(Instant::now()));
            if let Some(to) = *client.lock().expect("APPARATUS: the relay's client lock") {
                carried.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                let _ = front.send_to(&pkt, to);
            }
        }
    });
    (addr, to_client)
}

/// A backend that reads a request to its end, answers [`REPLY`] bytes and closes, then says when
/// it closed. Returns its port.
fn replying_backend(closed: mpsc::Sender<Instant>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("APPARATUS: bind the backend");
    let port = listener
        .local_addr()
        .expect("APPARATUS: the backend's address")
        .port();
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            let mut req = Vec::new();
            if s.read_to_end(&mut req).is_err() {
                continue;
            }
            let reply: Vec<u8> = (0..REPLY).map(byte).collect();
            if s.write_all(&reply).is_err() {
                continue;
            }
            drop(s);
            let _ = closed.send(Instant::now());
        }
    });
    port
}

/// The application: connect to the forward, send a request, half-close, and read the whole
/// reply on a thread. Joins to what it read and how the stream ended.
fn exchange(at: SocketAddr) -> std::thread::JoinHandle<(Vec<u8>, String)> {
    let mut app = TcpStream::connect(at).unwrap_or_else(|e| {
        panic!("PRODUCT: `vox forward` printed {at} but refuses a connection there: {e}")
    });
    app.write_all(b"send me the reply")
        .unwrap_or_else(|e| panic!("PRODUCT: the forward at {at} failed the request's write: {e}"));
    app.shutdown(Shutdown::Write)
        .unwrap_or_else(|e| panic!("PRODUCT: the forward at {at} failed the half-close: {e}"));
    std::thread::spawn(move || {
        app.set_read_timeout(Some(READ_BOUND))
            .expect("APPARATUS: set the application's read timeout");
        let mut got = Vec::with_capacity(REPLY);
        let mut buf = vec![0u8; 64 * 1024];
        let ending = loop {
            match app.read(&mut buf) {
                Ok(0) => break "a clean end of stream".to_owned(),
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) => break format!("{:?}: {e}", e.kind()),
            }
        };
        (got, ending)
    })
}

#[test]
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; CI runs it in release"]
fn a_tunnels_last_bytes_arrive_when_its_host_stops() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let (anchor_dir, host_dir, guest_dir) = (
        tmp.path().join("anchor"),
        tmp.path().join("host"),
        tmp.path().join("guest"),
    );
    for d in [&anchor_dir, &host_dir, &guest_dir] {
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a profile directory");
    }
    // Split by address family (`support/relay.rs`): the host on 127.0.0.1 and the guest on [::1]
    // cannot send each other a datagram, so the delaying relay — on [::1], in front of the host —
    // is the only direct path between them, and the only other is the anchor's circuit.
    let anchor = relay::Anchor::start(&anchor_dir);
    let (ok, host_fp, err) = vox_once(&host_dir, &args(&["id"]));
    assert!(
        ok,
        "CANNOT MEASURE: staging: the host's `vox id` failed: {err}"
    );
    let (ok, guest_fp, err) = vox_once(&guest_dir, &args(&["id"]));
    assert!(
        ok,
        "CANNOT MEASURE: staging: the guest's `vox id` failed: {err}"
    );
    let (ok, out, err) = vox_once(
        &host_dir,
        &args(&["trust", "add", guest_fp.trim(), "--name", "the guest"]),
    );
    assert!(
        ok,
        "CANNOT MEASURE: staging: the host's `vox trust add` of the guest failed: {out}{err}"
    );

    let (closed_tx, closed_rx) = mpsc::channel();
    let backend = replying_backend(closed_tx);
    let host_port = UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("APPARATUS: find a free port for the host")
        .port();
    let host_listen = format!("127.0.0.1:{host_port}");
    let (relay, to_guest) = delaying_relay(
        host_listen
            .parse()
            .expect("APPARATUS: the host's listen address parses"),
    );
    let relay_s = relay.to_string();
    let mut host = VoxProc::spawn_env(
        "host",
        &host_dir,
        &args(&[
            "serve",
            &backend.to_string(),
            "--anchor",
            &anchor.v4_spec,
            "--listen",
            &host_listen,
        ]),
        &[("VOX_TEST_ADVERTISE", relay_s.as_str())],
    );
    let room = after_label(
        &host.expect_line("room", |l| l.starts_with("room ")),
        "room",
    );
    let address = after_label(
        &host.expect_line("address", |l| l.starts_with("address ")),
        "address",
    );
    let passphrase = after_label(
        &host.expect_line("passphrase", |l| l.starts_with("passphrase ")),
        "passphrase",
    );
    assert!(
        address.contains(&format!("/udp/{}", relay.port())),
        "CANNOT MEASURE: the host did not advertise the relay: {address}"
    );

    // In a file, as a person passes it: a command line is world-readable, so `--passphrase` is
    // refused.
    let pass_file = world::room_pass_file(&guest_dir, &passphrase);
    let mut connect = VoxProc::spawn_env(
        "connect",
        &guest_dir,
        &args(&[
            "connect",
            &address,
            "--passphrase-file",
            &pass_file,
            "--anchor",
            &anchor.v6_spec,
            "--listen",
            "[::1]:0",
        ]),
        &[],
    );
    let status = connect
        .child
        .wait()
        .expect("APPARATUS: wait for vox connect");
    assert!(
        status.success(),
        "PRODUCT: `vox connect` to the host's printed address failed ({status}):\n{}",
        connect.transcript()
    );
    let mut fwd = VoxProc::spawn_env(
        "forward",
        &guest_dir,
        &args(&[
            "forward",
            &room,
            host_fp.trim(),
            &backend.to_string(),
            "127.0.0.1:0",
            "--passphrase-file",
            &pass_file,
            "--anchor",
            &anchor.v6_spec,
            "--listen",
            "[::1]:0",
        ]),
        &[],
    );
    let line = fwd.expect_line("the forward's bound address", |l| {
        l.starts_with("vox: 127.0.0.1:") && l.contains('→')
    });
    let at: SocketAddr = line
        .split_whitespace()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| {
            panic!("PRODUCT: `vox forward`'s bound-address line names no socket address: {line:?}")
        });

    // Unmeasured exchanges first, until one rides the relay: the forward's first tunnels ride
    // the anchor's circuit while the direct path through the relay is found, and the measured
    // one must not. A relayed pair retries for a direct path every 60 s.
    let warm_start = Instant::now();
    let mut warm = 0;
    loop {
        warm += 1;
        let b0 = to_guest.load(Ordering::Relaxed);
        let (got, ending) = exchange(at)
            .join()
            .expect("APPARATUS: the warm-up reader thread panicked");
        assert!(
            got.len() == REPLY,
            "PRODUCT: with nothing stopped, warm-up exchange {warm} read {} of {REPLY} bytes, then \
             {ending}: the tunnel truncated a reply\nhost:\n{}\nforward:\n{}",
            got.len(),
            host.transcript(),
            fwd.transcript()
        );
        let _ = closed_rx.recv_timeout(Duration::from_secs(10));
        if to_guest.load(Ordering::Relaxed) - b0 >= REPLY as u64 {
            break;
        }
        assert!(
            warm_start.elapsed() < Duration::from_secs(100),
            "CANNOT MEASURE: after {warm} exchanges in {:?} the tunnel still did not ride the relay",
            warm_start.elapsed()
        );
        std::thread::sleep(Duration::from_secs(2));
    }
    eprintln!(
        "[proof] the tunnel rode the relay from warm-up exchange {warm}, {:?} in",
        warm_start.elapsed()
    );
    let before = to_guest.load(Ordering::Relaxed);

    // The measured exchange.
    let reader = exchange(at);
    let closed_at = closed_rx
        .recv_timeout(Duration::from_secs(120))
        .expect("CANNOT MEASURE: the backend never finished its reply");
    std::thread::sleep(AFTER_CLOSE.saturating_sub(closed_at.elapsed()));
    let crossed = to_guest.load(Ordering::Relaxed) - before;
    let pid = host.child.id();
    let t0 = Instant::now();
    let ok = Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(ok, "APPARATUS: kill -INT {pid} (the host) did not take");
    eprintln!(
        "[proof] host interrupted {:?} after the backend closed; the relay had carried {crossed} \
         bytes toward the guest",
        closed_at.elapsed()
    );
    let (got, ending) = reader
        .join()
        .expect("APPARATUS: the application's reader thread panicked");
    let exited = host
        .child
        .wait()
        .expect("APPARATUS: wait for vox serve to exit");
    let total = to_guest.load(Ordering::Relaxed) - before;
    eprintln!(
        "[proof] the application read {} of {REPLY} bytes, then {ending}; the host exited {exited} \
         {:?} after SIGINT; the relay carried {total} bytes toward the guest",
        got.len(),
        t0.elapsed()
    );
    assert!(
        total > 0 && total >= got.len() as u64,
        "CANNOT MEASURE: the measured reply did not ride the relay ({total} bytes carried, {} \
         read)",
        got.len()
    );
    assert!(
        crossed < REPLY as u64,
        "CANNOT MEASURE: the whole reply had crossed the relay ({crossed} bytes) before the host \
         was interrupted, so the close came too late to test anything"
    );
    let first_wrong = got.iter().enumerate().position(|(i, b)| *b != byte(i));
    assert!(
        got.len() == REPLY && first_wrong.is_none() && ending == "a clean end of stream",
        "PRODUCT: the host stopped right after its backend finished a {REPLY}-byte reply, and the \
         application read {} bytes (first wrong byte at {first_wrong:?}) and then {ending}: a \
         tunnel's last bytes must be acknowledged before its connection closes.\nhost:\n{}\n\
         forward:\n{}",
        got.len(),
        host.transcript(),
        fwd.transcript()
    );
}
