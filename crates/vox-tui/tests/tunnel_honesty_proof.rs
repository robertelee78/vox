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
//!
//! Every red names its side: `PRODUCT:` quotes what the tunnel's application saw and what
//! `vox` said; `PRODUCT (staging):` is a step `vox` performs that failed before the event under
//! test (a forward that never carried a byte, a session never live); `CANNOT MEASURE:` is only a
//! runner that stalled through a timed window, which [`StallClock`] measures on the same
//! timeline as the bound.
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use world::{
    args, echo_service, read_to_end_within, resetting_service, round_trip, socks5_connect,
    vox_once, Ending, World, PARTIAL,
};

/// How long the idle session says nothing: past quinn's 30 s default idle timeout and past
/// Vox's own 60 s one, so the session survives only if something keeps its connection alive.
const QUIET: Duration = Duration::from_secs(75);

/// The runner's own stalls, on the proof's timeline: a thread that asks to sleep [`Self::TICK`]
/// and records how much longer than that it was away. A bound missed while the runner itself
/// stalled for a good part of it measured the runner, not `vox`.
struct StallClock {
    stop: Arc<AtomicBool>,
    worst_us: Arc<AtomicU64>,
    thread: std::thread::JoinHandle<()>,
}

impl StallClock {
    const TICK: Duration = Duration::from_millis(10);

    fn start() -> Self {
        let (stop, worst_us) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
        );
        let (s, w) = (stop.clone(), worst_us.clone());
        let thread = std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                let t = Instant::now();
                std::thread::sleep(Self::TICK);
                let late = t.elapsed().saturating_sub(Self::TICK);
                w.fetch_max(late.as_micros() as u64, Ordering::Relaxed);
            }
        });
        Self {
            stop,
            worst_us,
            thread,
        }
    }

    /// The longest the runner was away past one tick.
    fn stop(self) -> Duration {
        self.stop.store(true, Ordering::Relaxed);
        self.thread
            .join()
            .expect("APPARATUS: the stall clock's thread panicked");
        Duration::from_micros(self.worst_us.load(Ordering::Relaxed))
    }
}

#[test]
#[ignore = "production Argon2id profiles + a real PoW + a QUIC idle timeout, driving the real binary; CI runs it in release"]
fn a_forward_carries_a_new_connection_after_its_host_restarts() {
    watchdog::arm();
    let mut w = World::new(echo_service(), true);
    let guest_dir = w.guest_dir.clone();
    let (mut fwd, at) = w.forward("forward", &guest_dir);

    // Step 1: the forward works at all — otherwise the restart proves nothing.
    let before =
        round_trip(at, b"before the restart", Duration::from_secs(120)).unwrap_or_else(|e| {
            let host_said = w.host.as_mut().map(|h| h.transcript()).unwrap_or_default();
            panic!(
                "PRODUCT (staging): the forward carried no connection before \
                 the restart ({e}), so a restart proves nothing. The forward said:\n{}\nThe host \
                 said:\n{host_said}",
                fwd.transcript()
            )
        });
    assert_eq!(
        before, b"before the restart",
        "PRODUCT: bytes changed crossing the forward"
    );
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
            "PRODUCT: the same forward must carry a new connection after its host restarted \
             (PRD-001 R24); after {waited:?} it failed with {e}. The forward said:\n{}\n\
             The restarted host said:\n{host_said}",
            fwd.transcript()
        )
    });
    assert_eq!(
        after, b"after the restart",
        "PRODUCT: bytes changed crossing the forward after the restart"
    );
    eprintln!(
        "[test] step 3: {} bytes echoed through the same forward {waited:?} after the host \
         restarted on a new port",
        after.len()
    );
    // The forward process never restarted: it is the same child throughout.
    let exited = fwd
        .child
        .try_wait()
        .expect("APPARATUS: could not ask whether the forward process is alive");
    assert!(
        exited.is_none(),
        "PRODUCT: the forward process exited ({exited:?}) — it must be the one that started. It \
         said:\n{}",
        fwd.transcript()
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
    let mut s = TcpStream::connect(at)
        .expect("PRODUCT (staging): the forward's own port refused a connection");
    s.set_read_timeout(Some(
        vox_core::node::up::HOST_PATIENCE + Duration::from_secs(30),
    ))
    .expect("APPARATUS: set a read timeout");
    s.write_all(b"before the quiet")
        .expect("PRODUCT (staging): the forward never took the session's first write");
    let mut back = [0u8; 16];
    if let Err(e) = s.read_exact(&mut back) {
        panic!(
            "PRODUCT (staging): the session never carried bytes ({e}), so whether it survives a \
             quiet was never reached. The forward said:\n{}",
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
    let (mut fwd, at) = w.forward("forward", &guest_dir);

    // Step 1: a live session carrying bytes both ways. Staging: without it there is nothing
    // for the removal to cut.
    let mut s = TcpStream::connect(at).unwrap_or_else(|e| {
        panic!(
            "PRODUCT (staging): the forward's listener {at} refused a \
             connection: {e}. It said:\n{}",
            fwd.transcript()
        )
    });
    s.set_read_timeout(Some(
        vox_core::node::up::HOST_PATIENCE + Duration::from_secs(30),
    ))
    .expect("APPARATUS: set the session's read timeout");
    let mut back = [0u8; 13];
    if let Err(e) = s
        .write_all(b"are you there")
        .and_then(|()| s.read_exact(&mut back))
    {
        panic!(
            "PRODUCT (staging): the session was never live before the \
             removal ({e}). The forward said:\n{}",
            fwd.transcript()
        );
    }
    assert_eq!(
        &back, b"are you there",
        "PRODUCT: bytes changed crossing the forward"
    );
    eprintln!("[test] step 1: live session echoed {} bytes", back.len());

    // Step 2: the host's operator removes the service, from the command line.
    let (ok, out, err) = vox_once(
        &w.host_dir,
        &args(&["service", "remove", &w.room, &w.service_port.to_string()]),
    );
    let removed_at = Instant::now();
    assert!(
        ok,
        "PRODUCT: `vox service remove` did not reach the running host.\nstdout:\n{out}\n\
         stderr:\n{err}"
    );
    eprintln!("[test] step 2: {}", out.trim());

    // Step 3: the live session is cut, within a second, and not by a quiet EOF. The read goes
    // on past the bound, so a late cut reads "cut late at X" and a missing one "never cut";
    // the runner's own stalls are timed alongside, so a stalled runner reads CANNOT MEASURE.
    let bound = Duration::from_secs(1);
    let clock = StallClock::start();
    let (tail, ending) = read_to_end_within(&mut s, Duration::from_secs(30));
    let elapsed = removed_at.elapsed();
    let stall = clock.stop();
    eprintln!(
        "[test] step 3: session ended {ending:?} after {elapsed:?}, {} stray bytes; the runner's \
         longest stall was {stall:?}",
        tail.len()
    );
    let transcript = fwd.transcript();
    match ending {
        Ending::Reset => {}
        Ending::StillOpen => panic!(
            "PRODUCT: removing a service never cut its live session (PRD-001 R22): still open \
             {elapsed:?} after `vox service remove` returned. The forward said:\n{transcript}"
        ),
        other => panic!(
            "PRODUCT: removing a service ended its live session as {other:?} after {elapsed:?}, \
             not a reset (PRD-001 R22). The forward said:\n{transcript}"
        ),
    }
    if elapsed > bound {
        // Half the bound away from the clock: the runner, not `vox`, may have spent the second.
        assert!(
            stall <= bound / 2,
            "CANNOT MEASURE: the runner stalled {stall:?} on the proof's timeline while a \
             {bound:?} bound was timed (the cut came at {elapsed:?})"
        );
        panic!(
            "PRODUCT: removing a service cut its live session late, at {elapsed:?} (bound \
             {bound:?}; the runner's longest stall {stall:?}) (PRD-001 R22). The forward \
             said:\n{transcript}"
        );
    }
    assert!(
        tail.is_empty(),
        "PRODUCT: {} bytes arrived after the service was removed: {tail:?}",
        tail.len()
    );
    drop(w);
}

#[test]
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; CI runs it in release"]
fn a_backend_reset_reaches_the_far_client_as_a_reset() {
    watchdog::arm();
    let w = World::new(resetting_service(), true);
    let guest_dir = w.guest_dir.clone();
    let (mut fwd, at) = w.forward("forward", &guest_dir);

    let mut s = TcpStream::connect(at).unwrap_or_else(|e| {
        panic!(
            "PRODUCT (staging): the forward's listener {at} refused a \
             connection: {e}. It said:\n{}",
            fwd.transcript()
        )
    });
    s.write_all(b"GET /").unwrap_or_else(|e| {
        panic!(
            "PRODUCT (staging): the request could not be written to the \
             forward: {e}. It said:\n{}",
            fwd.transcript()
        )
    });
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
    // Nothing at all crossing is staging that did not happen (the far side never carried the
    // request, or the test's backend never answered); any byte that crossed makes the rest
    // the tunnel's.
    let transcript = fwd.transcript();
    assert!(
        !got.is_empty(),
        "PRODUCT (staging): not one byte of the backend's reply crossed \
         (the read ended {ending:?}), so no reset was ever relayed. The forward said:\n\
         {transcript}"
    );
    assert!(
        PARTIAL.starts_with(&got),
        "PRODUCT: the backend's reply changed crossing the tunnel: {:?}",
        String::from_utf8_lossy(&got)
    );
    assert_eq!(
        got.len(),
        PARTIAL.len(),
        "PRODUCT: the client got {} of the {} bytes the backend sent before its reset, then \
         {ending:?}. The forward said:\n{transcript}",
        got.len(),
        PARTIAL.len()
    );
    // Step 2: the backend's reset is a reset at the far end, not a clean EOF.
    assert_eq!(
        ending,
        Ending::Reset,
        "PRODUCT: a backend that reset its connection reached the client as {ending:?}, not as \
         a reset (PRD-001 D11). The forward said:\n{transcript}"
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
    let mut s = TcpStream::connect(at).unwrap_or_else(|e| {
        panic!(
            "PRODUCT (staging): the forward's listener {at} refused a \
             connection: {e}. It said:\n{}",
            fwd.transcript()
        )
    });
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
        "PRODUCT: an untrusted joiner's forward carried {} bytes: {got:?}. It said:\n{}",
        got.len(),
        fwd.transcript()
    );
    assert_eq!(
        ending,
        Ending::Reset,
        "PRODUCT: a refused forward ended the application's connection as {ending:?} after \
         {waited:?}, not as a reset — a quiet close reads as `connected, then the server hung \
         up` (PRD-001 R23). It said:\n{}",
        fwd.transcript()
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
        code,
        0x02,
        "PRODUCT: an untrusted joiner's CONNECT got SOCKS reply code {code}, not 2 (not \
         allowed): it must be refused in the reply itself. `vox up` said:\n{}",
        up.transcript()
    );
    let (got, ending) = read_to_end_within(&mut s, Duration::from_secs(5));
    assert!(
        got.is_empty(),
        "PRODUCT: a refused CONNECT carried {} bytes: {got:?}",
        got.len()
    );
    eprintln!("[test] and the socket then ended {ending:?}");
    // And this node, the operator's own, says why.
    let why = up.expect_within(Duration::from_secs(10), "the reason, on stderr", |l| {
        l.starts_with("! ") && l.contains("the host refused")
    });
    eprintln!("[test] vox up said: {why}");
}
