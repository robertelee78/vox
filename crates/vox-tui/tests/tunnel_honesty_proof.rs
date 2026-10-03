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
//! - **A restarted host is reached again promptly, by a forward and by a proxy** (V210-141). The
//!   host's process is killed and the room brought back by `vox daemon`, on a new port and on the
//!   same port, and the first connection a running `vox forward` or `vox up` makes afterwards
//!   must reach the new process within V210-57's host-restart bound, [`HOST_BACK_WITHIN`], one
//!   attempt and no retry. A dialer that kept its stale connection to the dead process would wait
//!   out the silence rule (30 s) or QUIC's idle timeout (about 60 s) instead.
//! - **A forward survives its path changing while the host stays up** (R24's "or the path
//!   changing"). The host and guest are split by address family, so the anchor's circuit is
//!   their only path, and the host advertises a port forward this proof owns
//!   (`support/port_forward.rs`), closed at first. A running `vox forward` carries a connection
//!   over the relay; then the port forward opens, a direct path exists, and with the host and the
//!   forward still running, a later connection through the **same** forward must ride the direct
//!   path (its bytes cross the port forward). A forward pinned to the connection it started with
//!   keeps riding the relay and goes red.
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
//! - **A refusal is immediate** (R23): once the path to the host is up, a refused connection
//!   fails for the application within [`IMMEDIATE`], through `vox forward` and through `vox up`.
//!   Each is read for at most a few times that, so a refusal that is slow or never comes is
//!   red on the proof's own line, not on the watchdog's.
//! - **A refusal tells the refused side nothing new** (R23, ADR-013 dark services): to a
//!   stranger, a port the host offers and one it does not are refused the same way — the same
//!   ending, no bytes, the same SOCKS reply and the same words on its own terminal.
//! - **A refusal this node makes itself sends the host nothing** (R23, "the remote side learns
//!   nothing new", read the other way): a CONNECT that `vox up` refuses on its own — a name that
//!   is not `.vox`, a room this machine does not have, a node it has not trusted — is refused
//!   with the reason on this node's terminal, and the host logs no attempt. The host is first
//!   shown to log a refusal it made, so its silence afterwards is a measurement.
//! - **A tunnel can be closed by itself, from either end, and nothing else changes** (V030-11).
//!   On the host, `vox tunnel close <member> <service>` closes that member's session to the
//!   service; on the guest, `vox tunnel close --id N` closes one session its `vox forward`
//!   carries. Each closed session reaches its application as a reset, the other end says the
//!   tunnel was closed, both ends' `vox status` lists it with why, and a new session through
//!   the same forward works at once: the member is still trusted and the service still served.
//! - **A stuck tunnel is closed on its own, and an idle one never is** (V030-11). With the host's
//!   `tunnel-stuck-after` set to [`STUCK_AFTER`] (the guest's far longer), a session whose
//!   application writes and never reads the echo is closed as stuck by the host, not before that
//!   time, saying it; the guest, the far end, says "closed as stuck at the other end" in its
//!   `vox status` and its forward's line; a session left idle past twice that time still echoes.
//! - **The TUI lists tunnels and closes the one selected** (V030-11). The guest runs `vox tui`
//!   (driven in a pty, `tests/pty/tui_tunnel_close.py`); two sessions run through a forward of
//!   the TUI's node; the TUI's tunnel list shows both, Down moves the selection to the other one,
//!   and `x` closes it: that session is reset, the other still echoes and is still listed, the
//!   host says it was closed by a person at the other end, and a new session works.
//! - **A member prefix that matches two members closes nothing** (V030-11). A second guest is
//!   made whose id starts with the same character as the first's; both hold a session. The host's
//!   `vox tunnel close <that character>` is refused, naming both members, and both sessions still
//!   echo; then the second's own longer prefix closes only the second's.
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
//!   The name is the full address, `<service>.<node>.<room>.vox` (V030-25), with the unjoined
//!   room's id and its host's fingerprint. The CONNECT is refused in the reply with the proxy's
//!   own reason ("no room on this machine is called …", not a host's refusal), and neither
//!   room's service is ever dialled.
//!
//! Every red in those two proofs says which kind it is: **PRODUCT** (what the product did, as a
//! person sees it), **PRODUCT (staging)** (a step vox itself performs before the claim failed),
//! or **APPARATUS** / **CANNOT MEASURE** (the proof's own fault, or a case the shared harness never
//! staged, so the run says nothing).
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
//! wait on QUIC's idle timeout in the restart proof. They run on demand, in release, by name:
//! CI runs no tests.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/pty_driver.rs"]
mod pty_driver;

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[path = "support/relay.rs"]
mod relay;

#[path = "support/port_forward.rs"]
mod port_forward;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use world::{
    args, counting_echo_service, echo_service, read_to_end_within, resetting_service, round_trip,
    socks5_connect, socks5_connect_within, vox_once, Ending, VoxProc, World, PARTIAL,
};

/// How soon a refused connection must fail for its application once the path to the host is
/// up (PRD-001 R23, "immediately"): one round trip to the host and its answer. ADR-013 measured
/// 1.6–18 ms on loopback; this is a bound under ordinary load, not a measurement.
const IMMEDIATE: Duration = Duration::from_secs(2);

/// How long the first connection may wait for the forward or proxy to reach its host at all,
/// before the refusal can be timed.
fn first_reach() -> Duration {
    vox_core::node::up::HOST_PATIENCE + Duration::from_secs(30)
}

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
#[ignore = "production Argon2id profiles + a real PoW + a QUIC idle timeout, driving the real binary; run on demand"]
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

/// R24's "or the path changing": the product retries a relayed pair's direct path every 60 s
/// (`UPGRADE_RETRY`), so a direct path that opens is found within that and some margin. A
/// number, not the product constant.
const PATH_CHANGED_WITHIN: Duration = Duration::from_secs(75);

#[test]
#[ignore = "production Argon2id + a real PoW, a relayed pair held until its direct path is found; run on demand"]
fn a_forward_keeps_carrying_when_its_path_changes_from_relayed_to_direct() {
    watchdog::arm();
    let mut w = port_forward::ForwardedWorld::new(false);
    let pass = world::room_pass_file(&w.guest_dir, &w.passphrase);
    let mut fwd = world::VoxProc::spawn(
        "forward",
        &w.guest_dir,
        &args(&[
            "forward",
            &w.room,
            &w.host_fp,
            &w.service_port.to_string(),
            "127.0.0.1:0",
            "--passphrase-file",
            &pass,
            "--anchor",
            &w.anchor.v6_spec,
            "--listen",
            "[::1]:0",
        ]),
    );
    let line = fwd.expect_line("the forward's bound address", |l| {
        l.starts_with("vox: 127.0.0.1:") && l.contains('→')
    });
    let at = world::address_in(&mut fwd, &line, 1);
    let payload: Vec<u8> = (0..16 * 1024).map(|i| (i % 251) as u8).collect();

    // Staging: relayed, observed. The connection rides the anchor's circuit, and none of its
    // bytes cross the port forward, which is closed.
    let sent = w.forward.to_host();
    let mut s = TcpStream::connect(at)
        .unwrap_or_else(|e| panic!("PRODUCT: the bound forward at {at} refused a connection: {e}"));
    assert!(
        port_forward::echo_over(&mut s, &payload, Duration::from_secs(120)),
        "CANNOT MEASURE: no echo through the forward over the relayed path, so there is no \
         relayed forward to watch change path.\nThe forward said:\n{}",
        fwd.transcript()
    );
    drop(s);
    let crossed = w.forward.to_host() - sent;
    assert!(
        crossed == 0,
        "CANNOT MEASURE: the first connection crossed the port forward ({crossed} B) while it was \
         closed, so the path was never relayed"
    );
    w.anchor.assert_relayed("before the path changes");

    // The path changes, live: a direct path becomes possible while the host and the forward
    // keep running.
    w.forward.open();
    let opened = Instant::now();
    let (mut tried, mut carried, mut direct) = (0usize, 0usize, None);
    let mut last_failure = String::new();
    while opened.elapsed() < PATH_CHANGED_WITHIN {
        std::thread::sleep(Duration::from_millis(500));
        tried += 1;
        let sent = w.forward.to_host();
        let echoed = TcpStream::connect(at)
            .map_err(|e| e.to_string())
            .and_then(|mut s| {
                port_forward::echo_over(&mut s, &payload, Duration::from_secs(10))
                    .then_some(())
                    .ok_or_else(|| "no echo within 10 s".to_owned())
            });
        match echoed {
            Ok(()) => {
                carried += 1;
                if w.forward.to_host() - sent >= payload.len() as u64 {
                    direct = Some(opened.elapsed());
                    break;
                }
            }
            Err(e) => last_failure = e,
        }
    }
    eprintln!(
        "[test] path change: {tried} connections through the same forward after a direct path \
         opened, {carried} echoed; the port forward carried {} B to the host",
        w.forward.to_host()
    );
    let Some(took) = direct else {
        panic!(
            "PRODUCT: {PATH_CHANGED_WITHIN:?} after a direct path to its running host became \
             possible, the same forward still carried no connection over it ({carried} of {tried} \
             echoed, every one over the relay; last failure: {last_failure:?}) — the forward is \
             pinned to the path it started with (PRD-001 R24).\nThe forward said:\n{}",
            fwd.transcript()
        );
    };
    match fwd.child.try_wait() {
        Ok(None) => {}
        Ok(Some(status)) => panic!(
            "PRODUCT: the forward exited ({status}) while its path changed.\nIt said:\n{}",
            fwd.transcript()
        ),
        Err(e) => panic!("APPARATUS: could not ask whether the forward still runs: {e}"),
    }
    eprintln!(
        "[test] the same forward carried a connection over the direct path {took:?} after it \
         became possible"
    );
    drop(fwd);
}

#[test]
#[ignore = "production Argon2id profiles + a real PoW + 75 s of quiet, driving the real binary; run on demand"]
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
        .expect("PRODUCT (staging): the forward's session never took a first write");
    let mut back = [0u8; 16];
    if let Err(e) = s.read_exact(&mut back) {
        panic!(
            "PRODUCT (staging): the forward's session never carried bytes ({e}), before any quiet: \
             vox failed to carry a fresh session. The forward said:\n{}",
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
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; run on demand"]
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
            "APPARATUS, CANNOT MEASURE: the runner stalled {stall:?} on the proof's timeline while a \
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
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; run on demand"]
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
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; run on demand"]
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
    let (got, ending) = read_to_end_within(&mut s, first_reach());
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
    let why = refusal_line(&mut fwd, "the forward");
    eprintln!("[test] the forward said: {why}");

    // **Immediately** (R23): the path to the host is up now, so the next refusal is one round
    // trip, not a wait.
    let (ending, took) = refused_within(at);
    eprintln!("[test] a second connection was refused ({ending:?}) after {took:?}");
    assert!(
        ending == Ending::Reset && took <= IMMEDIATE,
        "PRODUCT: a refused connection must fail for the application immediately (PRD-001 R23): \
         the second one, with the path to the host already up, ended {ending:?} after {took:?} \
         (at most {IMMEDIATE:?})"
    );
    drop(fwd);
    drop(w);
}

#[test]
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; run on demand"]
fn a_refused_socks_connect_is_refused_in_the_reply_and_says_why() {
    watchdog::arm();
    // The guest joined with the address and the passphrase and was never trusted.
    let w = World::new(echo_service(), false);
    let guest_dir = w.guest_dir.clone();
    let (mut up, at) = w.up("stranger-up", &guest_dir);
    let hostname = w.service_host();

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
    let why = refusal_line(&mut up, "vox up");
    eprintln!("[test] vox up said: {why}");

    // **Immediately** (R23): with the path to the host up, the next CONNECT's refusal is one
    // round trip. Its reply is read for at most a few times the bound, so a proxy that does not
    // answer is red here, on this claim, not at the watchdog.
    let t1 = Instant::now();
    let (code, _s) = socks5_connect_within(
        at,
        &hostname,
        w.service_port,
        IMMEDIATE * 5,
        Some(
            "PRODUCT: a refused CONNECT must be answered immediately (PRD-001 R23): the second \
             one, with the path to the host already up, got",
        ),
    );
    let took = t1.elapsed();
    eprintln!("[test] a second CONNECT got SOCKS reply code {code} after {took:?}");
    assert!(
        code == 0x02 && took <= IMMEDIATE,
        "PRODUCT: a refused CONNECT must be answered immediately (PRD-001 R23): the second one, \
         with the path to the host already up, got reply {code} after {took:?} (code 2 within \
         {IMMEDIATE:?}). `vox up` said:\n{}",
        up.transcript()
    );
}

#[test]
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; run on demand"]
fn a_refusal_tells_the_refused_side_nothing_new() {
    watchdog::arm();
    // A stranger: joined with the address and the passphrase, never trusted. It asks for the
    // port the host offers and for one it does not. If the answers differ, the refusal has told
    // it which ports the host serves (ADR-013 dark services; PRD-001 R23, "the remote side
    // learns nothing new").
    let w = World::new(echo_service(), false);
    let guest_dir = w.guest_dir.clone();
    let unoffered = unoffered_port(w.service_port);
    let mut seen = Vec::new();
    for (label, port) in [("offered", w.service_port), ("unoffered", unoffered)] {
        let (mut fwd, at) = w.forward_port(&format!("{label}-forward"), &guest_dir, port);
        let mut s = TcpStream::connect(at).unwrap_or_else(|e| {
            panic!("PRODUCT (staging): the forward at {at} refused a connection: {e}")
        });
        let (got, ending) = read_to_end_within(&mut s, first_reach());
        // Whatever it says on its terminal about this connection, compared below; not only the
        // words this build says, or a different answer would stop the run before the comparison
        // could name it.
        let said = fwd
            .line_within(Duration::from_secs(10), |l| {
                l.starts_with("! ") && l.contains("tunnel refused or cut")
            })
            .unwrap_or_else(|| "(nothing within 10 s)".to_owned())
            .replace(&port.to_string(), "<port>");
        eprintln!(
            "[test] {label} port {port}: the application saw {ending:?}, {} bytes; the forward \
             said: {said}",
            got.len()
        );
        seen.push((label, got.len(), ending, said));
    }
    let mut codes = Vec::new();
    let (_up, proxy) = w.up("stranger-up", &guest_dir);
    let hostname = format!("{}.vox", w.room);
    for (label, port) in [("offered", w.service_port), ("unoffered", unoffered)] {
        let (code, _s) = socks5_connect(proxy, &hostname, port);
        eprintln!("[test] {label} port {port}: SOCKS reply code {code}");
        codes.push((label, code));
    }
    let (a, b) = (&seen[0], &seen[1]);
    assert!(
        a.1 == 0 && b.1 == 0,
        "PRODUCT: a refused stranger was carried bytes: {} from the offered port, {} from the \
         unoffered",
        a.1,
        b.1
    );
    assert_eq!(
        (a.2, &a.3),
        (b.2, &b.3),
        "PRODUCT: the refusal told a stranger which port the host offers: the offered port \
         ended {:?} and said {:?}; the unoffered ended {:?} and said {:?}",
        a.2,
        a.3,
        b.2,
        b.3
    );
    assert_eq!(
        codes[0].1, codes[1].1,
        "PRODUCT: the SOCKS reply told a stranger which port the host offers: {codes:?}"
    );
}

#[test]
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; run on demand"]
fn a_local_refusal_sends_the_host_nothing() {
    watchdog::arm();
    // A stranger, so that anything that does reach the host is refused there and logged.
    let mut w = World::new(echo_service(), false);
    let guest_dir = w.guest_dir.clone();
    let (mut up, proxy) = w.up("stranger-up", &guest_dir);
    let room = w.room.clone();
    let host_heard = |w: &World, since: Instant| -> Vec<String> {
        let host = w.host.as_ref().expect("APPARATUS: the world has no host");
        host.timed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(at, l)| *at >= since && l.contains("a tunnel"))
            .map(|(_, l)| l.clone())
            .collect()
    };

    // The control: a CONNECT the host refuses is one the host logs. Without it, the host's
    // silence below would prove nothing.
    let t0 = Instant::now();
    let (code, _s) = socks5_connect(proxy, &format!("{room}.vox"), w.service_port);
    let mut logged = Vec::new();
    while logged.is_empty() && t0.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(100));
        logged = host_heard(&w, t0);
    }
    eprintln!("[test] control: SOCKS reply {code}; the host logged {logged:?}");
    assert!(
        code == 0x02 && !logged.is_empty(),
        "CANNOT MEASURE: the host did not log the refusal it made itself (reply {code}, logged \
         {logged:?}), so its silence for a local refusal would prove nothing"
    );
    let host_line = refusal_line(&mut up, "vox up");
    eprintln!("[test] control: vox up said: {host_line}");

    // Each refusal this node makes on its own: the name, what it is, and the reason it says.
    let stranger = format!("stranger.{room}.vox");
    let cases = [
        (
            "printer.example.com",
            "not a .vox name",
            "is not a .vox name",
        ),
        (
            "nosuchroom.vox",
            "a room this machine does not have",
            "neither a room id nor a node",
        ),
        (
            "nas.nosuchroom.vox",
            "a room name this machine does not have",
            "no room on this machine is called",
        ),
        (
            stranger.as_str(),
            "a node this machine has not trusted",
            "no node you trust is called",
        ),
    ];
    for (name, what, reason) in cases {
        let t = Instant::now();
        let (code, _s) = socks5_connect(proxy, name, w.service_port);
        let said = up.expect_within(
            Duration::from_secs(10),
            &format!("vox up to say why it refused {what}"),
            |l| l.starts_with("! ") && l.contains(reason),
        );
        // Long enough for anything sent to reach the host and be logged: the control was
        // logged within its first round trip.
        std::thread::sleep(Duration::from_secs(3));
        let heard = host_heard(&w, t);
        eprintln!(
            "[test] {what} ({name}): SOCKS reply {code}; vox up said: {said}; the host logged \
             {heard:?}"
        );
        assert_ne!(
            code, 0x00,
            "PRODUCT: vox up told the application that a CONNECT to {what} ({name}) succeeded"
        );
        assert!(
            heard.is_empty(),
            "PRODUCT: vox up refused {what} ({name}) on its own, and the host still heard of it: \
             {heard:?}"
        );
    }
    drop(up);
    drop(w.host.take());
}

/// A port the host does not offer: `offered`'s neighbour.
fn unoffered_port(offered: u16) -> u16 {
    offered.checked_add(1).unwrap_or(offered - 1)
}

/// The refusal `p` said for this node's operator: a `! … the host refused …` line.
fn refusal_line(p: &mut VoxProc, who: &str) -> String {
    p.expect_within(
        Duration::from_secs(10),
        &format!("{who} to say, on its own terminal, that the host refused"),
        |l| l.starts_with("! ") && l.contains("the host refused"),
    )
}

/// Connect to the forward at `at`, write nothing, and see how and how soon the connection ends:
/// read for at most a few times [`IMMEDIATE`], so a refusal that never comes is red on the
/// caller's own line.
fn refused_within(at: std::net::SocketAddr) -> (Ending, Duration) {
    let t = Instant::now();
    let mut s = TcpStream::connect(at).unwrap_or_else(|e| {
        panic!("PRODUCT (staging): the forward at {at} refused a connection: {e}")
    });
    let (_, ending) = read_to_end_within(&mut s, IMMEDIATE * 5);
    (ending, t.elapsed())
}

/// What `vox status --json` on the node holding `dir`'s profile says, parsed.
fn status_of(dir: &std::path::Path, who: &str) -> serde_json::Value {
    let (ok, out, err) = vox_once(dir, &args(&["status", "--json"]));
    assert!(ok, "PRODUCT: {who}'s `vox status --json` failed: {err}");
    serde_json::from_str(out.trim()).unwrap_or_else(|e| {
        panic!("PRODUCT: {who}'s `vox status --json` printed what is not JSON, {out:?}: {e}")
    })
}

/// The rows of `section` (`tunnels` or `closed_tunnels`) for `service`, going `direction`.
fn rows<'a>(
    status: &'a serde_json::Value,
    section: &str,
    service: &str,
    direction: &str,
) -> Vec<&'a serde_json::Value> {
    status[section]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter(|t| {
                    t["service"].as_str() == Some(service)
                        && t["direction"].as_str() == Some(direction)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// How long a closed tunnel may take to appear on a node's closed list: its splice resets the
/// local socket once its queue drains (`DRAIN_BOUND`, 2 s) before the tunnel ends, and the far
/// end's after the reset reaches it.
const CLOSE_LISTED_WITHIN: Duration = Duration::from_secs(8);

/// Whether the node holding `dir`'s profile lists, within [`CLOSE_LISTED_WITHIN`], an inbound
/// tunnel to `port` that ended for `why`; and its last `vox status --json`.
fn closed_listed(dir: &std::path::Path, port: &str, why: &str) -> (bool, serde_json::Value) {
    let t0 = Instant::now();
    loop {
        let status = status_of(dir, "the host");
        let listed = rows(&status, "closed_tunnels", port, "in")
            .iter()
            .any(|t| t["why"].as_str() == Some(why));
        if listed || t0.elapsed() > CLOSE_LISTED_WITHIN {
            return (listed, status);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// An echo through a fresh session to `at`, or why it failed.
fn echoes(at: std::net::SocketAddr, what: &[u8]) -> Result<TcpStream, String> {
    let mut s = TcpStream::connect(at).map_err(|e| format!("connect: {e}"))?;
    s.set_read_timeout(Some(
        vox_core::node::up::HOST_PATIENCE + Duration::from_secs(30),
    ))
    .map_err(|e| format!("set a read timeout: {e}"))?;
    s.write_all(what).map_err(|e| format!("write: {e}"))?;
    let mut back = vec![0u8; what.len()];
    s.read_exact(&mut back).map_err(|e| format!("read: {e}"))?;
    if back != what {
        return Err(format!("echoed {back:?}, not {what:?}"));
    }
    Ok(s)
}

#[test]
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; CI runs it in release"]
fn a_tunnel_is_closed_from_either_end_and_nothing_else_changes() {
    watchdog::arm();
    let mut w = World::new(echo_service(), true);
    // `vox tunnel close` asks the running node over its control socket, which a daemon serves
    // and `vox serve` does not; `vox forward` serves one for the guest.
    w.restart_host_as_daemon();
    let guest_dir = w.guest_dir.clone();
    let (mut fwd, at) = w.forward("forward", &guest_dir);
    let port = w.service_port.to_string();

    // Step 1: a live session, and the host's `vox status` names its member.
    let mut first = echoes(at, b"before the close").unwrap_or_else(|e| {
        panic!("PRODUCT (staging): the forward never carried a first session: {e}")
    });
    let host_status = status_of(&w.host_dir, "the host");
    let live = rows(&host_status, "tunnels", &port, "in");
    let member: String = match live.as_slice() {
        [one] => one["peer"]
            .as_str()
            .unwrap_or_else(|| panic!("PRODUCT: a tunnel row with no member: {one}"))
            .chars()
            .take(12)
            .collect(),
        other => panic!(
            "PRODUCT: with one session open, the host's `vox status` lists {} tunnel(s) from the \
             guest to {port}: {host_status}",
            other.len()
        ),
    };

    // Step 2: the host's operator closes the member's tunnels to the service.
    let (ok, out, err) = vox_once(&w.host_dir, &args(&["tunnel", "close", &member, &port]));
    let closed_at = Instant::now();
    eprintln!("[test] step 2: {}{}", out.trim(), err.trim());
    assert!(
        ok && out.contains("closed 1 tunnel"),
        "PRODUCT: `vox tunnel close {member} {port}` on the host did not close the one live \
         tunnel.\nstdout:\n{out}\nstderr:\n{err}"
    );

    // Step 3: the session ends as a reset, and the guest says the tunnel was closed.
    let (tail, ending) = read_to_end_within(&mut first, Duration::from_secs(3));
    eprintln!(
        "[test] step 3: the closed session ended {ending:?} after {:?}, {} stray bytes",
        closed_at.elapsed(),
        tail.len()
    );
    assert_eq!(
        ending,
        Ending::Reset,
        "PRODUCT: a tunnel closed by the host must end its session with a reset; it ended \
         {ending:?}"
    );
    let told = fwd.try_expect_within(Duration::from_secs(10), "word the tunnel was closed", |l| {
        l.contains("was closed by a person at the other end")
    });
    let told = told.unwrap_or_else(|e| {
        panic!(
            "PRODUCT: the guest's `vox forward` did not say its session's tunnel was closed by a \
             person at the other end: {e}"
        )
    });
    // Said as a close, never as a refusal or a fault (the transcript marks stderr lines `! `).
    assert!(
        told.contains("vox: tunnel closed — ") && !told.contains("refused or cut"),
        "PRODUCT: the guest's `vox forward` said the close as {told:?}, not as a close"
    );

    // Step 4: nothing else changed. A new session through the same forward works at once.
    let second = echoes(at, b"after the close").unwrap_or_else(|e| {
        panic!(
            "PRODUCT: after one tunnel was closed, a new session to the same service failed — \
             the member must stay trusted and the service served: {e}"
        )
    });
    let host_status = closed_listed(&w.host_dir, &port, "closed by a person on this side");
    assert!(
        host_status.0,
        "PRODUCT: the host's `vox status` does not list the tunnel it closed, with why, within \
         {CLOSE_LISTED_WITHIN:?}: {}",
        host_status.1
    );

    // Step 5: the guest closes its own session, by the number its `vox status` gives it.
    let guest_status = status_of(&guest_dir, "the guest");
    let id = match rows(&guest_status, "tunnels", &port, "out").as_slice() {
        [one] => one["id"]
            .as_u64()
            .unwrap_or_else(|| panic!("PRODUCT: a tunnel row with no number: {one}")),
        other => panic!(
            "PRODUCT: with one session open, the guest's `vox status` lists {} tunnel(s) to \
             {port}: {guest_status}",
            other.len()
        ),
    };
    let (ok, out, err) = vox_once(
        &guest_dir,
        &args(&["tunnel", "close", "--id", &id.to_string()]),
    );
    eprintln!("[test] step 5: {}{}", out.trim(), err.trim());
    assert!(
        ok && out.contains("closed 1 tunnel"),
        "PRODUCT: `vox tunnel close --id {id}` on the guest did not close its session.\nstdout:\
         \n{out}\nstderr:\n{err}"
    );
    let mut second = second;
    let (_, ending) = read_to_end_within(&mut second, Duration::from_secs(3));
    assert_eq!(
        ending,
        Ending::Reset,
        "PRODUCT: a session the guest closed must end with a reset; it ended {ending:?}"
    );
    let host_status = closed_listed(&w.host_dir, &port, "closed by a person at the other end");
    assert!(
        host_status.0,
        "PRODUCT: the host's `vox status` does not say the guest closed its tunnel within \
         {CLOSE_LISTED_WITHIN:?}: {}",
        host_status.1
    );
    eprintln!("[test] step 5: the guest's close reached the host as `closed by a person at the other end`");
    drop(fwd);
    drop(w);
}

/// The stuck time both profiles are given in the stuck proof: long enough that a session
/// carrying bytes is not mistaken for stuck, short enough to wait out.
const STUCK_AFTER: Duration = Duration::from_secs(15);
/// The guest's stuck time in the stuck proof: past the proof's whole wait, so the host is the end
/// that finds the tunnel stuck, and the guest learns it only from the other end.
const GUEST_STUCK_AFTER: Duration = Duration::from_secs(120);

#[test]
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; CI runs it in release"]
fn a_stuck_tunnel_is_closed_and_an_idle_one_is_not() {
    watchdog::arm();
    let mut w = World::new(echo_service(), true);
    // The host is given the stuck time and the guest far longer, so the host is the end that
    // finds the tunnel stuck and the guest the far end, told so by the tunnel's reset.
    for (dir, after) in [
        (&w.host_dir, STUCK_AFTER),
        (&w.guest_dir, GUEST_STUCK_AFTER),
    ] {
        std::fs::write(
            dir.join("cfg").join("tunnel-stuck-after"),
            format!("{}s\n", after.as_secs()),
        )
        .expect("APPARATUS: write the profile's tunnel-stuck-after");
    }
    // Restarted so the host's node reads the setting; `vox forward` reads it as it starts.
    w.restart_host_as_daemon();
    let guest_dir = w.guest_dir.clone();
    let (mut fwd, at) = w.forward("forward", &guest_dir);
    let port = w.service_port.to_string();

    // An idle session: it echoes once, then nothing moves on it.
    let mut idle = echoes(at, b"idle from here on").unwrap_or_else(|e| {
        panic!("PRODUCT (staging): the forward never carried the idle session: {e}")
    });
    let idle_since = Instant::now();
    let reported = [
        status_of(&w.host_dir, "the host")["tunnel_stuck_after"].as_u64(),
        status_of(&guest_dir, "the guest")["tunnel_stuck_after"].as_u64(),
    ];
    eprintln!("[test] stuck setting as each node reports it: host, guest {reported:?}");
    assert!(
        reported
            == [
                Some(STUCK_AFTER.as_secs()),
                Some(GUEST_STUCK_AFTER.as_secs())
            ],
        "PRODUCT: the profiles' `tunnel-stuck-after` say {STUCK_AFTER:?} (host) and \
         {GUEST_STUCK_AFTER:?} (guest), but `vox status` reports {reported:?} (host, guest)"
    );

    // A stuck session: its application writes and never reads what the service echoes back,
    // so the echo waits, and then everything behind it.
    let stuck = TcpStream::connect(at)
        .unwrap_or_else(|e| panic!("PRODUCT: the forward refused the stuck session: {e}"));
    let mut writer = stuck
        .try_clone()
        .expect("APPARATUS: clone the stuck session's socket");
    let wrote = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counted = std::sync::Arc::clone(&wrote);
    let writing = std::thread::spawn(move || {
        let chunk = vec![0x5a_u8; 64 * 1024];
        loop {
            match writer.write(&chunk) {
                Ok(n) => {
                    counted.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                }
                Err(e) => return e.kind(),
            }
        }
    });
    let stuck_from = Instant::now();

    // Closed as stuck, and said, within the stuck time and some slack for the bytes to back up.
    let within = STUCK_AFTER * 2 + Duration::from_secs(20);
    // When each of the host's tunnels last moved a byte, as its `vox status` says, so the wait
    // before its close can be measured from when its bytes began to wait: the host is the end
    // that finds the tunnel stuck, and its blocked write begins right after its last move.
    let mut last_moved: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
    let mut host_closed: Vec<(u64, u64)> = Vec::new();
    let mut guest_closed: Vec<(u64, u64)>;
    let mut far_why: Vec<String> = Vec::new();
    let said = loop {
        let host = status_of(&w.host_dir, "the host");
        let guest = status_of(&guest_dir, "the guest");
        for t in rows(&host, "tunnels", &port, "in") {
            if let (Some(id), Some(at)) = (t["id"].as_u64(), t["last_moved"].as_u64()) {
                last_moved.insert(id, at);
            }
        }
        guest_closed = rows(&guest, "closed_tunnels", &port, "out")
            .iter()
            .filter_map(|t| Some((t["id"].as_u64()?, t["closed"].as_u64()?)))
            .collect();
        // The host's own word, and the guest's row once it has one: the far end's reset lands
        // just after the host's close.
        let stuck_rows: Vec<String> = rows(&host, "closed_tunnels", &port, "in")
            .into_iter()
            .filter_map(|t| t["why"].as_str())
            .filter(|why| why.starts_with("closed as stuck:"))
            .map(str::to_owned)
            .collect();
        if !stuck_rows.is_empty() && !guest_closed.is_empty() {
            host_closed = rows(&host, "closed_tunnels", &port, "in")
                .iter()
                .filter(|t| {
                    t["why"]
                        .as_str()
                        .is_some_and(|w| w.starts_with("closed as stuck:"))
                })
                .filter_map(|t| Some((t["id"].as_u64()?, t["closed"].as_u64()?)))
                .collect();
            far_why = rows(&guest, "closed_tunnels", &port, "out")
                .iter()
                .filter_map(|t| t["why"].as_str().map(str::to_owned))
                .collect();
            break Some(stuck_rows);
        }
        if stuck_from.elapsed() > within {
            // The host closed it as stuck and the guest, the far end, never listed it: the
            // far end's failure, said as such, not "neither end says so" (c5 verdict).
            if !stuck_rows.is_empty() {
                panic!(
                    "PRODUCT: the host closed the tunnel as stuck ({stuck_rows:?}), but the guest, \
                     the far end, lists no closed tunnel for it within {within:?}.\nhost \
                     closed_tunnels: {}\nguest closed_tunnels: {}",
                    host["closed_tunnels"], guest["closed_tunnels"]
                );
            }
            break None;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let ended = stuck_from.elapsed();
    let _ = stuck.shutdown(std::net::Shutdown::Both);
    let write_ended = writing
        .join()
        .expect("APPARATUS: the stuck session's writer panicked");
    eprintln!(
        "[test] stuck session: wrote {} bytes; closed as stuck after {ended:?}: {said:?}; its \
         writer ended {write_ended:?}",
        wrote.load(std::sync::atomic::Ordering::Relaxed)
    );
    assert!(
        said.is_some(),
        "PRODUCT: a session whose application read nothing, with data waiting, was not closed \
         as stuck within {within:?} (stuck time {STUCK_AFTER:?}); neither end's `vox status` \
         says so"
    );
    // Not before the configured time: the bytes began waiting after the session started, so a
    // close seen sooner than that came early (V030-11 c1 verdict).
    assert!(
        ended >= STUCK_AFTER,
        "PRODUCT: the stuck session was closed {ended:?} after it started, before the configured \
         {STUCK_AFTER:?}: {said:?}"
    );
    // A tunnel's last move covers both its directions, and the other direction keeps moving for
    // a few seconds after the stuck one blocks, so it cannot time the stuck write: measured from
    // it, a close 15 s after the block read as 12 s (c5 run). The wait is held instead by what the
    // node measured from the blocked write itself, stated in the reason, below; this record is
    // printed for the reader.
    let waited: Vec<(u64, Option<u64>)> = host_closed
        .iter()
        .map(|(id, closed)| (*id, last_moved.get(id).map(|m| closed.saturating_sub(*m))))
        .collect();
    eprintln!("[test] the host's stuck tunnel(s), and seconds from last move to close: {waited:?}");
    // And the reason says how long the bytes really waited, which is at least the stuck time: a
    // close that came early must not say the configured time (c4 verdict).
    let stated: Vec<Option<u64>> = said
        .iter()
        .flatten()
        .map(|why| {
            why.split(" for ")
                .nth(1)?
                .split(" s with data waiting")
                .next()?
                .parse()
                .ok()
        })
        .collect();
    assert!(
        !stated.is_empty()
            && stated
                .iter()
                .all(|s| s.is_some_and(|s| s >= STUCK_AFTER.as_secs())),
        "PRODUCT: the stuck reason does not say a wait of at least {STUCK_AFTER:?} (seconds \
         stated: {stated:?}): {said:?}"
    );
    // The far end, which did not find it stuck, is told why it was closed: in its `vox status`
    // and in its forward's own line (c4 pre-read).
    let far_line = fwd.try_expect_within(Duration::from_secs(10), "word of a stuck close", |l| {
        l.contains("vox: tunnel closed — ") && l.contains("was closed as stuck at the other end")
    });
    eprintln!("[test] the far end (the guest) says: status {far_why:?}; forward {far_line:?}");
    assert!(
        far_why == ["closed as stuck at the other end"] && far_line.is_ok(),
        "PRODUCT: the guest, the far end of a tunnel the host closed as stuck, does not say it was \
         closed as stuck at the other end: its `vox status` says {far_why:?}, its forward \
         {far_line:?}"
    );

    // The idle session, now idle past twice the stuck time, still carries bytes.
    let idle_for = STUCK_AFTER * 2 + Duration::from_secs(1);
    std::thread::sleep(idle_for.saturating_sub(idle_since.elapsed()));
    let idle_was = idle_since.elapsed();
    let echoed = (|| -> Result<(), String> {
        idle.write_all(b"still here")
            .map_err(|e| format!("write: {e}"))?;
        let mut back = [0u8; 10];
        idle.read_exact(&mut back)
            .map_err(|e| format!("read: {e}"))?;
        (back == *b"still here")
            .then_some(())
            .ok_or_else(|| format!("echoed {back:?}"))
    })();
    eprintln!("[test] idle session after {idle_was:?} idle: {echoed:?}");
    assert!(
        echoed.is_ok(),
        "PRODUCT: a session idle for {idle_was:?}, with nothing waiting either way, was closed: \
         {echoed:?}. An idle tunnel must never be closed as stuck"
    );
    drop(w);
}

/// Whether `path` appears within `within`.
fn cue(path: &std::path::Path, within: Duration) -> bool {
    let t0 = Instant::now();
    while t0.elapsed() < within {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
#[ignore = "production Argon2id profiles + a real PoW + the real TUI in a pty; CI runs it in release"]
fn the_tui_lists_tunnels_and_closes_the_one_selected() {
    watchdog::arm();
    let mut w = World::new(echo_service(), true);
    w.restart_host_as_daemon();
    let guest_dir = w.guest_dir.clone();
    let port = w.service_port.to_string();
    let cues = w.tmp.path().join("cues");
    std::fs::create_dir_all(&cues).expect("APPARATUS: create the cue directory");

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_tunnel_close.py");
    let driver = {
        let (dir, pass, cues) = (guest_dir.clone(), w.passphrase.clone(), cues.clone());
        std::thread::spawn(move || {
            pty_driver::run(
                script,
                &[
                    world::VOX,
                    dir.to_str().expect("APPARATUS: a UTF-8 path"),
                    dir.join("cfg").to_str().expect("APPARATUS: a UTF-8 path"),
                    world::IDENTITY,
                    &pass,
                    cues.to_str().expect("APPARATUS: a UTF-8 path"),
                    "guest",
                ],
            )
        })
    };
    let said_by = |driver: std::thread::JoinHandle<pty_driver::Driven>| {
        driver.join().map_or_else(
            |_| "the TUI driver thread panicked".to_owned(),
            |d| format!("the driver exited {:?} saying:\n{}", d.code, d.stdout),
        )
    };
    if !cue(&cues.join("open"), Duration::from_secs(240)) {
        let said = if driver.is_finished() {
            said_by(driver)
        } else {
            "the driver is still running".to_owned()
        };
        panic!("PRODUCT (staging): the guest's TUI never opened its room; {said}");
    }

    // A session through a forward of the TUI's own node, as `vox room get` makes one.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: a tokio runtime");
    let paths = vox_core::node::paths::Paths::resolve(
        "default",
        Some(&guest_dir),
        Some(&guest_dir.join("cfg")),
    )
    .expect("APPARATUS: resolve the guest's paths");
    let mut client = rt
        .block_on(vox_core::node::ipc::IpcClient::open(&paths.socket_file()))
        .unwrap_or_else(|e| panic!("PRODUCT: the guest's TUI serves no control socket: {e}"));
    let room = match rt.block_on(client.rooms()) {
        Ok(vox_core::node::ipc::Frame::Rooms { rooms }) => rooms
            .iter()
            .map(|(id, _, _)| *id)
            .find(|id| vox_core::node::link::b32_encode(id).starts_with(&w.room))
            .unwrap_or_else(|| {
                panic!(
                    "PRODUCT (staging): room {} is not on the guest's node",
                    w.room
                )
            }),
        other => panic!("PRODUCT: the guest's TUI did not list its rooms: {other:?}"),
    };
    let host = vox_core::node::link::b32_decode(&w.host_fp, "host")
        .expect("APPARATUS: the host's fingerprint as `vox id` printed it");
    let at: std::net::SocketAddr =
        match rt.block_on(client.request(&vox_core::node::ipc::Request::Forward {
            channel_id: room,
            host,
            service_tag: port.clone(),
            local: "127.0.0.1:0".into(),
        })) {
            Ok(vox_core::node::ipc::Frame::Bound { local }) => local
                .parse()
                .unwrap_or_else(|e| panic!("PRODUCT: the forward bound {local:?}: {e}")),
            other => panic!("PRODUCT: the guest's TUI refused a forward to {port}: {other:?}"),
        };
    // Two sessions, each a tunnel of the TUI's node; which number each is, from its `vox status`.
    let ids_now = || -> Vec<u64> {
        rows(
            &status_of(&guest_dir, "the guest's TUI"),
            "tunnels",
            &port,
            "out",
        )
        .iter()
        .filter_map(|t| t["id"].as_u64())
        .collect()
    };
    let mut first = echoes(at, b"the first session").unwrap_or_else(|e| {
        panic!("PRODUCT (staging): the first session never carried bytes: {e}")
    });
    let first_id = match ids_now().as_slice() {
        [one] => *one,
        other => panic!("PRODUCT: with one session open, the TUI's node lists tunnels {other:?}"),
    };
    let mut second = echoes(at, b"the second session").unwrap_or_else(|e| {
        panic!("PRODUCT (staging): the second session never carried bytes: {e}")
    });
    let second_id = match ids_now()
        .iter()
        .copied()
        .filter(|i| *i != first_id)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [one] => *one,
        other => panic!(
            "PRODUCT: with two sessions open, the TUI's node lists tunnels {other:?} besides \
             {first_id}"
        ),
    };
    std::fs::write(cues.join("tunnel"), &port).expect("APPARATUS: write the tunnel cue");

    // The driver writes `closed` when the selected tunnel was said closed, or `red` when the TUI
    // got something wrong; then it has exited, with the TUI's node, so nothing more is asked of it.
    let t0 = Instant::now();
    let (closed, red) = loop {
        let (c, r) = (cues.join("closed").exists(), cues.join("red").exists());
        if c || r || t0.elapsed() > Duration::from_secs(90) {
            break (c, r);
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let listed = cues.join("listed").exists();
    let screen = |name: &str| std::fs::read_to_string(cues.join(name)).unwrap_or_default();
    if !closed {
        std::fs::write(cues.join("stop"), b"").expect("APPARATUS: write the stop cue");
        let said = said_by(driver);
        if red {
            panic!(
                "PRODUCT: the TUI did not close the one selected with Down; {said}\n[the screen]\n{}",
                screen("red")
            );
        }
        panic!("PRODUCT: the TUI closed no tunnel within 90 s and its driver saw no red; {said}");
    }
    eprintln!(
        "[test] tunnels {first_id} and {second_id}; the TUI's tunnel list:\n{}\n[test] after Down \
         and `x`:\n{}",
        screen("listed"),
        screen("closed")
    );
    let chosen: Option<u64> = screen("closed")
        .lines()
        .next()
        .and_then(|l| l.trim().parse().ok());
    // The session whose tunnel the TUI closed, and the one it was to leave alone.
    let (closed_session, kept_session, kept_id) = match chosen {
        Some(id) if id == first_id => (&mut first, &mut second, second_id),
        Some(id) if id == second_id => (&mut second, &mut first, first_id),
        other => {
            std::fs::write(cues.join("stop"), b"").expect("APPARATUS: write the stop cue");
            panic!(
                "APPARATUS: the driver names no closed tunnel among {first_id} and \
                 {second_id} ({other:?}); {}",
                said_by(driver)
            )
        }
    };
    let (_, ending) = read_to_end_within(closed_session, Duration::from_secs(3));
    let kept = (|| -> Result<(), String> {
        kept_session
            .write_all(b"still here")
            .map_err(|e| format!("write: {e}"))?;
        let mut back = [0u8; 10];
        kept_session
            .read_exact(&mut back)
            .map_err(|e| format!("read: {e}"))?;
        (back == *b"still here")
            .then_some(())
            .ok_or_else(|| format!("echoed {back:?}"))
    })();
    let still_listed = ids_now();
    let after = echoes(at, b"after the TUI closed one");
    let host_status = closed_listed(&w.host_dir, &port, "closed by a person at the other end");
    std::fs::write(cues.join("stop"), b"").expect("APPARATUS: write the stop cue");
    let driven = driver
        .join()
        .expect("APPARATUS: the TUI driver thread panicked");
    eprintln!(
        "[test] the TUI driver exited {:?} after {:?}: {}; the closed session ended {ending:?}; \
         the other ({kept_id}) echoed {kept:?}; the TUI's node lists {still_listed:?}",
        driven.code,
        driven.took,
        driven.stdout.trim()
    );
    assert!(
        driven.stdout.contains("guest RED") || driven.has_verdict("guest"),
        "APPARATUS: the TUI driver gave no verdict (stage {:?}):\n{}",
        driven.stage,
        driven.stdout
    );
    assert!(
        listed && closed && driven.code == Some(0),
        "PRODUCT: the TUI did not list both tunnels and close the one selected with Down:\n{}",
        driven.stdout
    );
    assert_eq!(
        ending,
        Ending::Reset,
        "PRODUCT: the session whose tunnel the TUI closed must end with a reset; it ended \
         {ending:?}"
    );
    assert!(
        kept.is_ok() && still_listed.contains(&kept_id),
        "PRODUCT: closing tunnel {chosen:?} in the TUI also ended the other one ({kept_id}): it \
         echoed {kept:?}, and the TUI's node lists {still_listed:?}"
    );
    assert!(
        host_status.0,
        "PRODUCT: the host's `vox status` does not say the guest closed its tunnel within \
         {CLOSE_LISTED_WITHIN:?}: {}",
        host_status.1
    );
    assert!(
        after.is_ok(),
        "PRODUCT: after the TUI closed one tunnel, a new session through the same forward \
         failed — nothing else may change: {:?}",
        after.err()
    );
    drop(w);
}

#[test]
#[ignore = "production Argon2id profiles (several, for a shared prefix) + real PoWs; CI runs it in release"]
fn an_ambiguous_member_prefix_closes_nothing() {
    /// How many identities may be made for the second guest before one shares the first's
    /// opening character: 1 in 32 each, so this many fail to only with odds of about 1 in 10⁵.
    const TRIES: usize = 360;
    // About 32 production-Argon2id identities on average, each tens of seconds in a debug build:
    // run there only on request, like the other proofs that take most of an hour in debug.
    if cfg!(debug_assertions) && !cfg!(feature = "optional-proofs") {
        eprintln!(
            "OPTIONAL PROOF NOT RUN: the ambiguous-prefix case in a debug build, whose search for \
             two identities sharing a first character takes most of an hour there; it runs in \
             every release build, or here with --features optional-proofs; it blocks nothing"
        );
        return;
    }
    watchdog::arm();
    let mut w = World::new(echo_service(), true);
    w.restart_host_as_daemon();
    let guest_dir = w.guest_dir.clone();
    let (ok, first_fp, err) = vox_once(&guest_dir, &args(&["id"]));
    assert!(
        ok,
        "PRODUCT (staging): the first guest's `vox id` failed: {err}"
    );
    let first_fp = first_fp.trim().to_ascii_lowercase();

    // A second guest whose id opens with the same character.
    let second_dir = w.tmp.path().join("second");
    let mut second_fp = None;
    for _ in 0..TRIES {
        let _ = std::fs::remove_dir_all(&second_dir);
        std::fs::create_dir_all(second_dir.join("cfg"))
            .expect("APPARATUS: make the second guest's profile directory");
        let (ok, fp, err) = vox_once(&second_dir, &args(&["id"]));
        assert!(
            ok,
            "PRODUCT (staging): the second guest's `vox id` failed: {err}"
        );
        let fp = fp.trim().to_ascii_lowercase();
        if fp[..1] == first_fp[..1] {
            second_fp = Some(fp);
            break;
        }
    }
    let second_fp = second_fp.unwrap_or_else(|| {
        panic!(
            "APPARATUS, CANNOT MEASURE: no identity in {TRIES} shared the first guest's opening \
             character"
        )
    });
    let shared = &first_fp[..1];
    let (ok, out, err) = vox_once(
        &w.host_dir,
        &args(&["trust", "add", &second_fp, "--name", "the second guest"]),
    );
    assert!(
        ok,
        "PRODUCT (staging): the host could not trust the second guest: {out}{err}"
    );
    let (ok, _, out, err) = w.join(&second_dir);
    assert!(
        ok,
        "PRODUCT (staging): the second guest could not join: {out}{err}"
    );

    let (_fwd1, at1) = w.forward("forward-1", &guest_dir);
    let (_fwd2, at2) = w.forward("forward-2", &second_dir);
    let mut one = echoes(at1, b"the first guest").unwrap_or_else(|e| {
        panic!("PRODUCT (staging): the first guest's session never echoed: {e}")
    });
    let mut two = echoes(at2, b"the second guest").unwrap_or_else(|e| {
        panic!("PRODUCT (staging): the second guest's session never echoed: {e}")
    });
    eprintln!("[test] two guests, {first_fp} and {second_fp}, share the prefix {shared:?}");

    // The shared prefix names two members: refused, naming both, and nothing closed.
    let (ok, out, err) = vox_once(&w.host_dir, &args(&["tunnel", "close", shared]));
    eprintln!("[test] `vox tunnel close {shared}`: ok {ok}\n{out}{err}");
    let still = |s: &mut TcpStream, what: &[u8]| -> Result<(), String> {
        s.write_all(what).map_err(|e| format!("write: {e}"))?;
        let mut back = vec![0u8; what.len()];
        s.read_exact(&mut back).map_err(|e| format!("read: {e}"))?;
        (back == what)
            .then_some(())
            .ok_or_else(|| format!("echoed {back:?}"))
    };
    let (kept1, kept2) = (still(&mut one, b"still one"), still(&mut two, b"still two"));
    assert!(
        !ok && err.contains(&first_fp) && err.contains(&second_fp),
        "PRODUCT: `vox tunnel close {shared}`, a prefix of two members' ids, was not refused \
         naming both.\nstdout:\n{out}\nstderr:\n{err}"
    );
    assert!(
        kept1.is_ok() && kept2.is_ok(),
        "PRODUCT: a refused, ambiguous `vox tunnel close {shared}` still closed a session: first \
         {kept1:?}, second {kept2:?}"
    );

    // The control: the second guest's own longer prefix closes the second guest's alone.
    let (ok, out, err) = vox_once(&w.host_dir, &args(&["tunnel", "close", &second_fp[..12]]));
    eprintln!(
        "[test] `vox tunnel close {}`: ok {ok}\n{out}{err}",
        &second_fp[..12]
    );
    let (_, ending) = read_to_end_within(&mut two, Duration::from_secs(3));
    let kept1 = still(&mut one, b"one remains");
    assert!(
        ok && out.contains("closed 1 tunnel") && ending == Ending::Reset && kept1.is_ok(),
        "PRODUCT: `vox tunnel close {}` did not close the second guest's session alone: ok \
         {ok}, its session ended {ending:?}, the first's echoed {kept1:?}\nstdout:\n{out}\n\
         stderr:\n{err}",
        &second_fp[..12]
    );
    drop(w);
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
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; run on demand"]
fn withdrawing_trust_cuts_a_live_session_and_refuses_the_next_request() {
    watchdog::arm();
    let (port, accepted) = counting_echo_service();
    let mut w = World::new(port, true);
    // `vox trust remove` asks the running node, which `vox serve` does not answer (it serves
    // no control socket); a daemon holding the same room does.
    w.restart_host_as_daemon();
    let guest_dir = w.guest_dir.clone();
    let (mut up, at) = w.up("guest-up", &guest_dir);
    let name = w.service_host();

    // Step 1: a live session, as `ssh user@<service>.<node>.<room>.vox` holds one.
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
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; run on demand"]
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
    let (ok, other_fp, err) = vox_once(&other_dir, &args(&["id"]));
    assert!(ok, "PRODUCT (staging): `vox id` (other host) failed: {err}");
    let other_fp = other_fp.trim().to_owned();
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
            &format!("{other_port}={other_port}"),
            "--anchor",
            &w.host_anchor,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    let other_room = world::after_label(
        &other.expect_line("the other room", |l| l.starts_with("room ")),
        "room",
    );
    assert_ne!(
        other_room, w.room,
        "PRODUCT (staging): the other host's `vox serve` printed this world's room"
    );
    // The unjoined room's service by its full address: the only `.vox` form that resolves
    // anywhere (V030-25), so a refusal is about the room, not the shape of the name.
    let other_name = format!("{other_port}.{other_fp}.{other_room}.vox");

    let guest_dir = w.guest_dir.clone();
    let (mut up, at) = w.up("guest-up", &guest_dir);

    // Control: the proxy dials a room this machine did join — otherwise a refusal below could
    // be a proxy that reaches nothing.
    let s = live_session(&mut up, at, &w.service_host(), port);
    let _ = s.shutdown(std::net::Shutdown::Both);
    let joined = accepted.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        joined, 1,
        "PRODUCT (staging): the joined room's service counted {joined} connections for one session"
    );
    eprintln!("[test] control: the joined room's name was carried; its service counted 1");

    // The unjoined room's name, at its own service's port and at the joined room's (the port
    // selects nothing now, but a proxy that let it would show here): a proxy that resolved the
    // name anywhere — the other room's host, or the room it does hold — would dial one of the
    // two services.
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
            && l.contains("no room on this machine is called")
            && l.contains(&other_room)
    });
    assert!(
        why.is_ok(),
        "PRODUCT: vox up must refuse an unjoined room's name itself, saying no room on this \
         machine is called that; it said:\n{}",
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

/// V210-57's bound for a host restart (`BACK_WITHIN` in `an_anchor_that_restarts_is_redialled_
/// promptly_proof`): the first connection after the host is back reaches it within this.
const HOST_BACK_WITHIN: Duration = Duration::from_secs(10);

/// How a restarted host comes back.
#[derive(Clone, Copy, Debug)]
enum Back {
    /// On a different port: what `World::restart_host_as_daemon` does.
    NewPort,
    /// On the port it had, so the dialer's stale connection still names a live address.
    SamePort,
}

/// The UDP port the host's process listens on, read from the system (`lsof` on its PID).
fn host_udp_port(w: &World) -> u16 {
    let pid = w
        .host
        .as_ref()
        .expect("APPARATUS: a running host")
        .child
        .id();
    let out = std::process::Command::new("lsof")
        .args(["-a", "-p", &pid.to_string(), "-iUDP", "-Fn", "-P", "-n"])
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not run lsof to read the host's port: {e}"));
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .filter_map(|l| l.strip_prefix('n'))
        .find_map(|a| a.rsplit(':').next()?.parse().ok())
        .unwrap_or_else(|| {
            panic!("CANNOT MEASURE: lsof found no UDP port for the host's pid {pid}: {text:?}")
        })
}

/// Kill the host and bring the same identity and room back as `vox daemon`, as `back` says.
/// Returns when the daemon holds the room.
fn restart_host(w: &mut World, back: Back) {
    match back {
        Back::NewPort => w.restart_host_as_daemon(),
        Back::SamePort => {
            let port = host_udp_port(w);
            drop(w.host.take());
            let pass_file = w.tmp.path().join("daemon-passphrases");
            std::fs::write(
                &pass_file,
                format!("{}\n{}\n", world::IDENTITY, w.passphrase),
            )
            .unwrap_or_else(|e| panic!("APPARATUS: could not write {}: {e}", pass_file.display()));
            let listen = format!("127.0.0.1:{port}");
            let mut daemon = world::VoxProc::spawn(
                "host-daemon",
                &w.host_dir,
                &args(&[
                    "daemon",
                    "--passphrase-file",
                    &world::utf8(&pass_file),
                    "--anchor",
                    &w.host_anchor,
                    "--listen",
                    &listen,
                ]),
            );
            let room = w.room.clone();
            daemon.expect_within(
                Duration::from_secs(60),
                &format!("the restarted daemon to hold the room open on port {port}"),
                |l| l.starts_with("vox daemon: holding room") && l.contains(&room),
            );
            w.host = Some(daemon);
        }
    }
}

/// One world, one dialer, one restart: the first connection after it reaches the new process
/// within [`HOST_BACK_WITHIN`]. `proxy` says whether the dialer is `vox up` (else `vox forward`).
fn reached_again(proxy: bool, back: Back) -> Duration {
    let mut w = World::new(echo_service(), true);
    let guest_dir = w.guest_dir.clone();
    let what = if proxy { "vox up" } else { "vox forward" };
    let hostname = w.service_host();
    let port = w.service_port;
    let (mut dialer, at) = if proxy {
        w.up("up", &guest_dir)
    } else {
        w.forward("forward", &guest_dir)
    };
    // One connection through the dialer, echoed; `Err` says how it failed.
    let once = |payload: &[u8], patience: Duration| -> Result<Vec<u8>, String> {
        if proxy {
            let (code, mut s) = socks5_connect(at, &hostname, port);
            if code != 0 {
                return Err(format!("SOCKS reply {code}"));
            }
            s.set_read_timeout(Some(patience))
                .map_err(|e| format!("APPARATUS: {e}"))?;
            s.write_all(payload).map_err(|e| e.to_string())?;
            let mut back = vec![0u8; payload.len()];
            s.read_exact(&mut back).map_err(|e| e.to_string())?;
            Ok(back)
        } else {
            round_trip(at, payload, patience).map_err(|e| e.to_string())
        }
    };
    let before = once(b"before the restart", Duration::from_secs(120)).unwrap_or_else(|e| {
        panic!(
            "PRODUCT (staging): {what} carried nothing before the host restarted ({e}): vox \
             failed to carry a fresh connection.\nIt said:\n{}",
            dialer.transcript()
        )
    });
    assert!(
        before == b"before the restart",
        "PRODUCT: the bytes changed crossing {what} before the restart: {:?}",
        String::from_utf8_lossy(&before)
    );
    restart_host(&mut w, back);
    // Timed from the restarted daemon holding its room: one attempt, as an application makes.
    let t0 = Instant::now();
    let after = once(
        b"after the restart",
        HOST_BACK_WITHIN + Duration::from_secs(60),
    );
    let took = t0.elapsed();
    eprintln!(
        "[test] {what}, host back on {back:?}: first connection {took:?} after the restart ({})",
        match &after {
            Ok(b) => format!("echoed {:?}", String::from_utf8_lossy(b)),
            Err(e) => format!("failed: {e}"),
        }
    );
    // How the dialer let go of the dead process, as it said it (times from the daemon holding
    // its room): the record of the mechanism ADR-013 names, green or red.
    for l in dialer.said_since(t0) {
        if l.contains("vox: connection to") {
            eprintln!("[test] {what} said: {l}");
        }
    }
    let host_said = w.host.as_mut().map(|h| h.transcript()).unwrap_or_default();
    match after {
        Ok(b) if b == b"after the restart" => {}
        Ok(b) => panic!(
            "PRODUCT: the bytes changed crossing {what} after the restart: {:?}",
            String::from_utf8_lossy(&b)
        ),
        Err(e) => panic!(
            "PRODUCT: {what}'s first connection after its host restarted on {back:?} failed after \
             {took:?}: {e}.\nIt said:\n{}\nThe restarted host said:\n{host_said}",
            dialer.transcript()
        ),
    }
    assert!(
        took <= HOST_BACK_WITHIN,
        "PRODUCT: {what}'s first connection after its host restarted on {back:?} took {took:?}, \
         past V210-57's {HOST_BACK_WITHIN:?}: it waited on its stale connection to the dead \
         process (V210-141).\nIt said:\n{}\nThe restarted host said:\n{host_said}",
        dialer.transcript()
    );
    took
}

#[test]
#[ignore = "four worlds with production Argon2id profiles + a real PoW each, driving the real binary; run on demand"]
fn a_restarted_host_is_reached_again_promptly_by_a_forward_and_by_a_proxy() {
    watchdog::arm();
    let mut took = Vec::new();
    for proxy in [false, true] {
        for back in [Back::NewPort, Back::SamePort] {
            took.push((proxy, back, reached_again(proxy, back)));
        }
    }
    eprintln!(
        "[test] V210-141: first connection after a host restart, each within {HOST_BACK_WITHIN:?}: {}",
        took.iter()
            .map(|(p, b, t)| format!(
                "{} {b:?} {:.2}s",
                if *p { "up" } else { "forward" },
                t.as_secs_f64()
            ))
            .collect::<Vec<_>>()
            .join(", ")
    );
}
