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
    args, echo_service, read_to_end_within, resetting_service, round_trip, socks5_connect,
    vox_once, Ending, World, PARTIAL,
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
                    &w.anchor_spec,
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
    let hostname = format!("{}.vox", w.room);
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
            "CANNOT MEASURE: {what} carried nothing before the host restarted ({e}), so the \
             restart proves nothing.\nIt said:\n{}",
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
#[ignore = "four worlds with production Argon2id profiles + a real PoW each, driving the real binary; CI runs it in release"]
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
