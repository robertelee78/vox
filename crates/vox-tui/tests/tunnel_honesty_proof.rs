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

#[path = "support/pty_driver.rs"]
mod pty_driver;

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
        panic!("CANNOT MEASURE: the forward never carried a first session: {e}")
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
        panic!("CANNOT MEASURE: the forward never carried the idle session: {e}")
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
        panic!("CANNOT MEASURE: the guest's TUI never opened its room; {said}");
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
                panic!("CANNOT MEASURE: room {} is not on the guest's node", w.room)
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
    let mut first = echoes(at, b"the first session")
        .unwrap_or_else(|e| panic!("CANNOT MEASURE: the first session never carried bytes: {e}"));
    let first_id = match ids_now().as_slice() {
        [one] => *one,
        other => panic!("PRODUCT: with one session open, the TUI's node lists tunnels {other:?}"),
    };
    let mut second = echoes(at, b"the second session")
        .unwrap_or_else(|e| panic!("CANNOT MEASURE: the second session never carried bytes: {e}"));
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
        panic!(
            "CANNOT MEASURE: the TUI driver neither closed a tunnel nor said why in 90 s; {said}"
        );
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
                "CANNOT MEASURE: the driver names no closed tunnel among {first_id} and \
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
        "CANNOT MEASURE: the TUI driver gave no verdict (stage {:?}):\n{}",
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
        "CANNOT MEASURE: the first guest's `vox id` failed: {err}"
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
            "CANNOT MEASURE: the second guest's `vox id` failed: {err}"
        );
        let fp = fp.trim().to_ascii_lowercase();
        if fp[..1] == first_fp[..1] {
            second_fp = Some(fp);
            break;
        }
    }
    let second_fp = second_fp.unwrap_or_else(|| {
        panic!("CANNOT MEASURE: no identity in {TRIES} shared the first guest's opening character")
    });
    let shared = &first_fp[..1];
    let (ok, out, err) = vox_once(
        &w.host_dir,
        &args(&["trust", "add", &second_fp, "--name", "the second guest"]),
    );
    assert!(
        ok,
        "CANNOT MEASURE: the host could not trust the second guest: {out}{err}"
    );
    let (ok, _, out, err) = w.join(&second_dir);
    assert!(
        ok,
        "CANNOT MEASURE: the second guest could not join: {out}{err}"
    );

    let (_fwd1, at1) = w.forward("forward-1", &guest_dir);
    let (_fwd2, at2) = w.forward("forward-2", &second_dir);
    let mut one = echoes(at1, b"the first guest")
        .unwrap_or_else(|e| panic!("CANNOT MEASURE: the first guest's session never echoed: {e}"));
    let mut two = echoes(at2, b"the second guest")
        .unwrap_or_else(|e| panic!("CANNOT MEASURE: the second guest's session never echoed: {e}"));
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
