//! **A tunnel tells the truth about how it ended**, proved by running the product
//! (PRD-001 R22, R23, R24; defects D6, D7 and D11).
//!
//! Every property here is about what an *application* sees on the far side of a tunnel —
//! a socket that succeeds, fails, resets or keeps working — so every one is measured with a
//! real TCP socket against real `vox` processes, and nothing reaches into `vox_core`:
//!
//! - **A forward survives its host restarting** (R24, D7). `vox forward` used to pin the
//!   one QUIC connection it started with, so once the host restarted every later connection
//!   was opened on a connection that went nowhere and the forward was dead while still
//!   bound. Here the host's `vox serve` is killed and the same room brought back by
//!   `vox daemon` on a **different port**, and the *same* forward must carry a new
//!   connection.
//! - **A refused SOCKS CONNECT is refused in the reply, and says why** (R23, D6). `vox up`
//!   replied "succeeded" before it had asked the host, so a refusal looked like a
//!   connection that died.
//! - **A refused forward resets the application's connection and says why** (R23). The
//!   application's `connect` succeeded before the host was asked, so a quiet close read as
//!   "connected, then the server hung up"; and the reason died in a dropped `Result`.
//! - **A backend's reset reaches the far client as a reset** (R22/R23, D11). The splice
//!   dropped its QUIC send half on the error path, and quinn *finishes* a dropped stream, so
//!   a backend that crashed mid-reply reached the client as an orderly EOF after a truncated
//!   reply — a lie a client cannot detect.
//! - **Removing a service cuts the sessions it is carrying** (R22). Only untrusting a
//!   member used to; removing the service changed the stored offer and nothing else.
//! - **A quiet session is not dropped** (RP-09). quinn's defaults are a 30 s idle timeout and
//!   no keep-alive, so on defaults an `ssh` session through a forward dies while its person
//!   reads. Three things keep the guest's connection to the host up, and any one of them is
//!   enough on its own:
//!   - the transport's keep-alive (`KEEP_ALIVE`, 20 s);
//!   - the members' periodic sync over the same connection (`SYNC_INTERVAL_SECS`, 30 s);
//!   - V210-93's liveness probe of a quiet anchor connection (`close_if_unanswering`): the
//!     invite names the host itself as one of the places to reach the room, so the guest keeps
//!     it as an anchor and probes it once it falls quiet.
//!
//!   So this proves what a person sees: a quiet forwarded session survives with the product as
//!   it is. It goes red only when all three are gone, so it guards against losing every one of
//!   them, not against losing any single one; removing the keep-alive alone, or using quinn's
//!   defaults, stays green while the other two hold.
//! - **Withdrawing trust cuts a live session and refuses the next request** (ADR-017 M17.11,
//!   RP-10). An `ssh` session opened while the guest was trusted is reset the moment the host's
//!   operator runs `vox trust remove`, and `vox up` says the host withdrew access. A new CONNECT
//!   through the **same** proxy — whose connection to the host was made while trusted — is
//!   refused in the SOCKS reply, and the service behind it never accepts a connection.
//!
//!   *A stream parked open across the withdrawal* (opened while trusted, its request sent only
//!   after) cannot be produced by the shipped binary: no honest `vox` delays its request. It is
//!   judged by the same gate this proof reaches — the request is read first and the reacher set
//!   consulted after it, live (`tunnel::session::accept_reporting`) — so the refusal here and a
//!   parked refusal are one line of code; that the set is a live handle rather than a copy rests
//!   on review (ADR-017 M17.11).
//! - **A `.vox` name for a room this machine never joined is refused at the proxy, and nothing
//!   is dialled** (ADR-017, RP-44). The room is real: its host runs on the same anchor, trusts
//!   this guest and offers a service that counts connections. The guest only never joined it.
//!   The CONNECT is refused in the reply with the proxy's own reason ("no room on this machine
//!   answers to …", not a host's refusal), and neither room's service is ever dialled.
//!
//! Every red in those two proofs says which kind it is: **PRODUCT** (what the product did, as a
//! person sees it), **PRODUCT (staging)** (a step vox itself performs before the claim failed),
//! or **APPARATUS** / **CANNOT MEASURE** (the proof's own fault, or a case the shared harness never
//! staged, so the run says nothing).
//!
//! ## Why it is `#[ignore]`d
//!
//! Production Argon2id on several profiles plus a real ADR-005 proof of work per test, and a
//! wait on QUIC's idle timeout in the restart proof. CI runs these in release with the other
//! real-parameter proofs.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use world::{
    args, counting_echo_service, echo_service, read_to_end_within, resetting_service, round_trip,
    socks5_connect, vox_once, Ending, VoxProc, World, PARTIAL,
};

/// How long the idle session says nothing: past quinn's 30 s default idle timeout and past
/// Vox's own 60 s one, so the session survives only if something keeps its connection alive.
const QUIET: Duration = Duration::from_secs(75);

#[test]
#[ignore = "production Argon2id profiles + a real PoW + a QUIC idle timeout, driving the real binary; CI runs it in release"]
fn a_forward_carries_a_new_connection_after_its_host_restarts() {
    watchdog::arm();
    let mut w = World::new(echo_service(), true);
    let guest_dir = w.guest_dir.clone();
    let (mut fwd, at) = w.forward("forward", &guest_dir);

    // Step 1: the forward works at all — otherwise the restart proves nothing.
    let before = round_trip(at, b"before the restart", Duration::from_secs(120))
        .expect("the forward must carry a connection before the host restarts");
    assert_eq!(before, b"before the restart", "bytes must cross unchanged");
    eprintln!(
        "[test] step 1: {} bytes echoed before the restart",
        before.len()
    );

    // Step 2: the host goes away and comes back on a different port.
    w.restart_host_as_daemon();

    // Step 3: the SAME forward — same process, same local port — carries a NEW connection.
    // One attempt, not a retry loop: the forward's own patience must absorb the restart,
    // because an application does not know to retry.
    let t0 = Instant::now();
    let after = round_trip(
        at,
        b"after the restart",
        vox_core::node::up::HOST_PATIENCE + Duration::from_secs(30),
    );
    let waited = t0.elapsed();
    let after = after.unwrap_or_else(|e| {
        let host_said = w.host.as_mut().map(|h| h.transcript()).unwrap_or_default();
        panic!(
            "the same forward must carry a new connection after its host restarted \
             (PRD-001 R24); after {waited:?} it failed with {e}. The forward said:\n{}\n\
             The restarted host said:\n{host_said}",
            fwd.transcript()
        )
    });
    assert_eq!(after, b"after the restart", "bytes must cross unchanged");
    eprintln!(
        "[test] step 3: {} bytes echoed through the same forward {waited:?} after the host \
         restarted on a new port",
        after.len()
    );
    // The forward process never restarted: it is the same child throughout.
    assert!(
        fwd.child.try_wait().unwrap().is_none(),
        "the forward process must still be the one that started"
    );
    drop(fwd);
    drop(w);
}

#[test]
#[ignore = "production Argon2id profiles + a real PoW + 75 s of quiet, driving the real binary; CI runs it in release"]
fn a_quiet_session_still_carries_bytes() {
    watchdog::arm();
    let w = World::new(echo_service(), true);
    let guest_dir = w.guest_dir.clone();
    let (mut fwd, at) = w.forward("forward", &guest_dir);

    // Step 1: the session carries bytes, so what follows measures the quiet and not a path
    // that never worked.
    let mut s = TcpStream::connect(at).expect("APPARATUS: connect to the forward's own port");
    s.set_read_timeout(Some(
        vox_core::node::up::HOST_PATIENCE + Duration::from_secs(30),
    ))
    .expect("APPARATUS: set a read timeout");
    s.write_all(b"before the quiet")
        .expect("CANNOT MEASURE: the session never took a first write");
    let mut back = [0u8; 16];
    if let Err(e) = s.read_exact(&mut back) {
        panic!(
            "CANNOT MEASURE: the session never carried bytes ({e}), so whether it survives a \
             quiet cannot be measured. The forward said:\n{}",
            fwd.transcript()
        );
    }
    assert_eq!(
        &back, b"before the quiet",
        "PRODUCT: bytes must cross unchanged"
    );
    eprintln!("[test] step 1: the session echoed {} bytes", back.len());

    // Step 2: nobody types.
    std::thread::sleep(QUIET);

    // Step 3: the same session, on the same socket, still carries bytes.
    let t0 = Instant::now();
    let wrote = s.write_all(b"after the quiet");
    // An echo on a live connection takes milliseconds; a dead session ends sooner than this.
    let (got, ending) = read_to_end_within(&mut s, Duration::from_secs(10));
    let waited = t0.elapsed();
    eprintln!(
        "[test] step 3: after {QUIET:?} of quiet the session took the write ({wrote:?}), gave {} \
         bytes, then {ending:?} after {waited:?}",
        got.len()
    );
    assert!(
        got == b"after the quiet" && ending == Ending::StillOpen,
        "PRODUCT: a session quiet for {QUIET:?} must still carry bytes and stay open (RP-09): \
         an idle ssh session must not drop while its person reads. The write gave {wrote:?}; \
         the session gave {:?} and ended {ending:?} after {waited:?}. The forward said:\n{}",
        String::from_utf8_lossy(&got),
        fwd.transcript()
    );
    drop(fwd);
    drop(w);
}

#[test]
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; CI runs it in release"]
fn removing_a_service_cuts_its_live_sessions_within_a_second() {
    watchdog::arm();
    let mut w = World::new(echo_service(), true);
    // The host has to be a running node that `vox service remove` can ask, which `vox serve`
    // is not (it serves no control socket). A daemon holding the same room is.
    w.restart_host_as_daemon();
    let guest_dir = w.guest_dir.clone();
    let (_fwd, at) = w.forward("forward", &guest_dir);

    // Step 1: a live session carrying bytes both ways.
    let mut s = TcpStream::connect(at).expect("connect to the forward");
    s.set_read_timeout(Some(
        vox_core::node::up::HOST_PATIENCE + Duration::from_secs(30),
    ))
    .unwrap();
    s.write_all(b"are you there").unwrap();
    let mut back = [0u8; 13];
    s.read_exact(&mut back)
        .expect("the session must be live before the removal");
    assert_eq!(&back, b"are you there");
    eprintln!("[test] step 1: live session echoed {} bytes", back.len());

    // Step 2: the host's operator removes the service, from the command line.
    let (ok, out, err) = vox_once(
        &w.host_dir,
        &args(&["service", "remove", &w.room, &w.service_port.to_string()]),
    );
    let removed_at = Instant::now();
    assert!(
        ok,
        "`vox service remove` must reach the running host.\nstdout:\n{out}\nstderr:\n{err}"
    );
    eprintln!("[test] step 2: {}", out.trim());

    // Step 3: the live session is cut, within a second, and not by a quiet EOF.
    let (tail, ending) = read_to_end_within(&mut s, Duration::from_secs(1));
    let elapsed = removed_at.elapsed();
    eprintln!(
        "[test] step 3: session ended {ending:?} after {elapsed:?}, {} stray bytes",
        tail.len()
    );
    assert_eq!(
        ending,
        Ending::Reset,
        "removing a service must cut its live sessions immediately (PRD-001 R22), and say so \
         with a reset; it ended {ending:?} within {elapsed:?}"
    );
    assert!(
        tail.is_empty(),
        "nothing should arrive after the cut: {tail:?}"
    );
    drop(w);
}

#[test]
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; CI runs it in release"]
fn a_backend_reset_reaches_the_far_client_as_a_reset() {
    watchdog::arm();
    let w = World::new(resetting_service(), true);
    let guest_dir = w.guest_dir.clone();
    let (_fwd, at) = w.forward("forward", &guest_dir);

    let mut s = TcpStream::connect(at).expect("connect to the forward");
    s.write_all(b"GET /").unwrap();
    // The first read may wait for the forward to reach its host.
    let (got, ending) = read_to_end_within(
        &mut s,
        vox_core::node::up::HOST_PATIENCE + Duration::from_secs(30),
    );
    eprintln!(
        "[test] client read {} of {} bytes, then {ending:?}",
        got.len(),
        PARTIAL.len()
    );
    // Step 1: the path works — the partial reply crossed — so the ending is the backend's.
    assert_eq!(
        got, PARTIAL,
        "the partial reply must cross before the reset, or this measures a broken path"
    );
    // Step 2: the backend's reset is a reset at the far end, not a clean EOF.
    assert_eq!(
        ending,
        Ending::Reset,
        "a backend that reset its connection must reach the client as a reset, not as a clean \
         EOF after a truncated reply (PRD-001 D11)"
    );
    drop(w);
}

#[test]
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; CI runs it in release"]
fn a_refused_forward_resets_the_application_and_says_why() {
    watchdog::arm();
    // The guest joined with the address and the passphrase and was never trusted.
    let w = World::new(echo_service(), false);
    let guest_dir = w.guest_dir.clone();
    let (mut fwd, at) = w.forward("stranger-forward", &guest_dir);

    let t0 = Instant::now();
    let mut s = TcpStream::connect(at).expect("connect to the forward");
    // **Nothing is written.** A socket closed with unread data in its receive buffer is
    // reset by the kernel whatever the closer intended, so writing first made a quiet close
    // look like a reset and this proof pass against the defect — its first mutation check
    // stayed green for exactly that reason. A server-speaks-first client (`ssh`) is the case
    // that matters anyway: it reads before it writes.
    let (got, ending) = read_to_end_within(
        &mut s,
        vox_core::node::up::HOST_PATIENCE + Duration::from_secs(30),
    );
    let waited = t0.elapsed();
    eprintln!(
        "[test] the untrusted forward's application saw {ending:?} after {waited:?}, {} bytes",
        got.len()
    );
    assert!(
        got.is_empty(),
        "an untrusted joiner must carry no bytes: {got:?}"
    );
    assert_eq!(
        ending,
        Ending::Reset,
        "a refused forward must fail the application's connection as a reset — a quiet close \
         reads as `connected, then the server hung up` (PRD-001 R23)"
    );
    // And this node, which is the operator's own, says why.
    let why = fwd.expect_within(Duration::from_secs(10), "the reason, on stderr", |l| {
        l.starts_with("! ") && l.contains("the host refused")
    });
    eprintln!("[test] the forward said: {why}");
    drop(fwd);
    drop(w);
}

#[test]
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; CI runs it in release"]
fn a_refused_socks_connect_is_refused_in_the_reply_and_says_why() {
    watchdog::arm();
    // The guest joined with the address and the passphrase and was never trusted.
    let w = World::new(echo_service(), false);
    let guest_dir = w.guest_dir.clone();
    let (mut up, at) = w.up("stranger-up", &guest_dir);
    let hostname = format!("{}.vox", w.room);

    // **The reply is the host's answer** (PRD-001 R23, D6). The proxy used to say
    // "succeeded" before it had asked, so a refusal looked like a connection that died.
    let t0 = Instant::now();
    let (code, mut s) = socks5_connect(at, &hostname, w.service_port);
    let waited = t0.elapsed();
    eprintln!("[test] the untrusted CONNECT got SOCKS reply code {code} after {waited:?}");
    assert_eq!(
        code, 0x02,
        "an untrusted joiner's CONNECT must be refused in the SOCKS reply itself — code 2, \
         not allowed — not told it succeeded"
    );
    let (got, ending) = read_to_end_within(&mut s, Duration::from_secs(5));
    assert!(
        got.is_empty(),
        "a refused CONNECT must carry nothing: {got:?}"
    );
    eprintln!("[test] and the socket then ended {ending:?}");
    // And this node, the operator's own, says why.
    let why = up.expect_within(Duration::from_secs(10), "the reason, on stderr", |l| {
        l.starts_with("! ") && l.contains("the host refused")
    });
    eprintln!("[test] vox up said: {why}");
}

/// A trusted session through `vox up`, carrying bytes: the staging both trust proofs start
/// from. Every failure here is vox's own, so it is `PRODUCT (staging)`; a proxy that breaks the
/// SOCKS exchange is `socks5_connect`'s PRODUCT red.
fn live_session(up: &mut VoxProc, at: std::net::SocketAddr, name: &str, port: u16) -> TcpStream {
    let (code, mut s) = socks5_connect(at, name, port);
    assert_eq!(
        code,
        0,
        "PRODUCT (staging): vox up refused a trusted member's CONNECT to {name}:{port} \
         (reply {code}); vox up said:\n{}",
        up.transcript()
    );
    s.set_read_timeout(Some(Duration::from_secs(30)))
        .expect("APPARATUS: setting a read timeout on the proof's own socket");
    let echoed = s
        .write_all(b"are you there")
        .and_then(|()| {
            let mut back = [0u8; 13];
            s.read_exact(&mut back).map(|()| back)
        })
        .unwrap_or_else(|e| {
            panic!("PRODUCT (staging): the trusted session through vox up carried no echo: {e}")
        });
    assert_eq!(
        &echoed, b"are you there",
        "PRODUCT (staging): the trusted session through vox up altered the echo"
    );
    s
}

#[test]
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; CI runs it in release"]
fn withdrawing_trust_cuts_a_live_session_and_refuses_the_next_request() {
    watchdog::arm();
    let (port, accepted) = counting_echo_service();
    let mut w = World::new(port, true);
    // `vox trust remove` asks the running node, which `vox serve` does not answer (it serves
    // no control socket); a daemon holding the same room does.
    w.restart_host_as_daemon();
    let guest_dir = w.guest_dir.clone();
    let (mut up, at) = w.up("guest-up", &guest_dir);
    let name = format!("{}.vox", w.room);

    // Step 1: a live session, as `ssh user@<room>.vox` holds one.
    let mut s = live_session(&mut up, at, &name, port);
    let dialled = accepted.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        dialled, 1,
        "PRODUCT (staging): the service counted {dialled} connections for one session, so it cannot \
         say whether a later one was dialled"
    );
    eprintln!("[test] step 1: a trusted session through vox up echoed; the service counted 1");

    // Step 2: the host's operator withdraws trust, from the command line.
    let (ok, out, err) = vox_once(&w.host_dir, &args(&["trust", "remove", &w.guest_fp]));
    let removed_at = Instant::now();
    assert!(
        ok,
        "PRODUCT: `vox trust remove` did not take effect on the running host.\nstdout:\n{out}\n\
         stderr:\n{err}"
    );
    eprintln!("[test] step 2: {}", out.trim());

    // Step 3: the live session is cut — a reset, not a quiet EOF — within a second.
    let (tail, ending) = read_to_end_within(&mut s, Duration::from_secs(1));
    let elapsed = removed_at.elapsed();
    eprintln!(
        "[test] step 3: the live session ended {ending:?} {elapsed:?} after the removal, {} \
         stray bytes",
        tail.len()
    );
    assert_eq!(
        ending,
        Ending::Reset,
        "PRODUCT: withdrawing trust must cut the live session at once, with a reset (ADR-017 \
         M17.11); it ended {ending:?} within {elapsed:?}"
    );
    assert!(
        tail.is_empty(),
        "PRODUCT: bytes arrived after trust was withdrawn: {tail:?}"
    );
    let said = up.try_expect_within(
        Duration::from_secs(10),
        "that the host withdrew access",
        |l| l.contains("the host withdrew access") && l.contains(&port.to_string()),
    );
    assert!(
        said.is_ok(),
        "PRODUCT: vox up must tell its person the host withdrew access, so they do not retry a \
         thing that cannot work; it said:\n{}",
        up.transcript()
    );

    // Step 4: the next request, through the same proxy and the same connection to the host —
    // made while the guest was trusted — is refused, and the service is never dialled.
    let (code, mut s2) = socks5_connect(at, &name, port);
    eprintln!("[test] step 4: the CONNECT after the withdrawal got SOCKS reply {code}");
    assert_eq!(
        code, 0x02,
        "PRODUCT: a CONNECT after `vox trust remove` must be refused in the reply — code 2, not \
         allowed; it got {code}"
    );
    let (got, _) = read_to_end_within(&mut s2, Duration::from_secs(2));
    assert!(
        got.is_empty(),
        "PRODUCT: a refused CONNECT carried bytes: {got:?}"
    );
    let why = up.try_expect_within(Duration::from_secs(10), "that the host refused", |l| {
        l.starts_with("! ") && l.contains("the host refused")
    });
    assert!(
        why.is_ok(),
        "PRODUCT: vox up must say the host refused the CONNECT; it said:\n{}",
        up.transcript()
    );
    let dialled = accepted.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        dialled, 1,
        "PRODUCT: the host dialled its service for a guest it no longer trusts — the service \
         counted {dialled} connections, one more than the session before the withdrawal"
    );
    eprintln!("[test] step 4: refused, said why, and the service still counted 1");
}

#[test]
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; CI runs it in release"]
fn a_vox_name_for_a_room_never_joined_is_refused_at_the_proxy_and_nothing_is_dialled() {
    watchdog::arm();
    let (port, accepted) = counting_echo_service();
    let w = World::new(port, true);

    // A second, real room on the same anchor, hosted by someone who trusts this guest and
    // offers a service that counts connections. The guest never joins it: that is the only
    // reason left for a refusal.
    let (other_port, other_accepted) = counting_echo_service();
    let other_dir = w.tmp.path().join("other-host");
    std::fs::create_dir_all(other_dir.join("cfg"))
        .expect("APPARATUS: creating the other host's profile directory");
    let (ok, _, err) = vox_once(&other_dir, &args(&["id"]));
    assert!(ok, "PRODUCT (staging): `vox id` (other host) failed: {err}");
    let (ok, out, err) = vox_once(
        &other_dir,
        &args(&["trust", "add", &w.guest_fp, "--name", "the guest"]),
    );
    assert!(
        ok,
        "PRODUCT (staging): the other host's `vox trust add` failed: {out}\n{err}"
    );
    let mut other = VoxProc::spawn(
        "other-host",
        &other_dir,
        &args(&[
            "serve",
            &other_port.to_string(),
            "--anchor",
            &w.anchor_spec,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    let other_room = world::after_label(
        &other.expect_staging("the other room", |l| l.starts_with("room ")),
        "room",
    );
    assert_ne!(
        other_room, w.room,
        "PRODUCT (staging): the other host's `vox serve` printed this world's room"
    );
    let other_name = format!("{other_room}.vox");

    let guest_dir = w.guest_dir.clone();
    let (mut up, at) = w.up("guest-up", &guest_dir);

    // Control: the proxy dials a room this machine did join — otherwise a refusal below could
    // be a proxy that reaches nothing.
    let s = live_session(&mut up, at, &format!("{}.vox", w.room), port);
    let _ = s.shutdown(std::net::Shutdown::Both);
    let joined = accepted.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        joined, 1,
        "PRODUCT (staging): the joined room's service counted {joined} connections for one session"
    );
    eprintln!("[test] control: the joined room's name was carried; its service counted 1");

    // The unjoined room's name, at its own service's port and at the joined room's: a proxy
    // that resolved the name anywhere — the other room's host, or the room it does hold —
    // would dial one of the two services.
    for p in [other_port, port] {
        let t0 = Instant::now();
        let (code, mut s) = socks5_connect(at, &other_name, p);
        eprintln!(
            "[test] CONNECT {other_name}:{p} got SOCKS reply {code} after {:?}",
            t0.elapsed()
        );
        assert_eq!(
            code, 0x02,
            "PRODUCT: a CONNECT to the .vox name of a room this machine never joined must be \
             refused in the reply — code 2, not allowed; {other_name}:{p} got {code}"
        );
        let (got, _) = read_to_end_within(&mut s, Duration::from_secs(2));
        assert!(
            got.is_empty(),
            "PRODUCT: a refused CONNECT carried bytes: {got:?}"
        );
    }
    // Refused **at the proxy**: its own reason, not a host's refusal relayed back.
    let why = up.try_expect_within(Duration::from_secs(10), "the proxy's own refusal", |l| {
        l.starts_with("! ")
            && l.contains("no room on this machine answers to")
            && l.contains(&other_room)
    });
    assert!(
        why.is_ok(),
        "PRODUCT: vox up must refuse an unjoined room's name itself, saying no room on this \
         machine answers to it; it said:\n{}",
        up.transcript()
    );
    assert!(
        !up.transcript().contains("the host refused"),
        "PRODUCT: a host was asked about a room this machine never joined (the refusal came \
         from a host, not the proxy); vox up said:\n{}",
        up.transcript()
    );
    let (mine, theirs) = (
        accepted.load(std::sync::atomic::Ordering::SeqCst),
        other_accepted.load(std::sync::atomic::Ordering::SeqCst),
    );
    assert_eq!(
        (mine, theirs),
        (1, 0),
        "PRODUCT: an unjoined room's name was dialled — the joined room's service counted {mine} \
         (1 is the control), the unjoined room's {theirs}"
    );
    eprintln!("[test] both refused at the proxy; the services counted 1 (the control) and 0");
    drop(other);
}
