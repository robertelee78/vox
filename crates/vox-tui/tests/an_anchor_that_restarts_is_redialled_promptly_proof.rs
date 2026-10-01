//! V210-57 (#243) — **an anchor that goes away is redialled at once, not on a 30-second tick**,
//! through the shipped binary.
//!
//! A node's anchor is its board and its relay: without it, a node reaches nobody it cannot dial
//! directly. The only redial used to run once every `ANCHOR_REDIAL_SECS` (30 s), so a node that lost
//! its anchor stayed without one for up to 30 s. CI run 36418572653 had a relayed first connection
//! take 30065 ms that way. A lost anchor is now dialled on the next tick, and only one that keeps
//! failing is backed off.
//!
//! **The scene** (`support/relay.rs`, `Split::Families`, so the only path is a circuit through the
//! anchor): the host serves an echo and the guest's `vox forward` carries it. A few seconds after
//! the forward started, the anchor is **stopped** (SIGINT, as a person stops it: it closes every
//! connection, so its peers learn at once that it is gone, which is the shape of CI's red, where the
//! anchor *closed* a connection) and brought back [`DOWN`] later **on the same port**. It is a new
//! process, so every connection to the old one is gone. The forward must carry an echo again within
//! [`BACK_WITHIN`] of the anchor's return, and say it saw the anchor go.
//!
//! **V210-93 (#287): the loss is noticed and said, however the anchor went, in every build.** In a
//! debug build the forward never said it: the arm above was red there. Two more arms stop the
//! anchor for good and time the forward's "gone" line from the moment the anchor was stopped:
//! - **SIGKILL** (a crash, as far as anyone can tell): no close is sent, so only the node's own
//!   probing of a quiet anchor connection can notice. It must say so within [`KILLED_WITHIN`]; the
//!   node used to learn it from the connection's silence (`SILENCE_IS_DEATH`, 30 s): 28 s measured.
//! - **SIGTERM** (how a service manager stops an anchor): a clean stop, whose close must reach the
//!   forward, so it says so within [`CLOSED_WITHIN`], well short of what silence alone can do
//!   ([`KILLED_WITHIN`]'s probe needs at least 8 s of it). The forward is then sent SIGTERM too,
//!   and must stop the way Ctrl-C stops it: say it is stopping and exit 0.
//!
//! Mutations: the probe disabled (a quiet anchor connection is never judged) → the SIGKILL arm red;
//! `vox node` without its SIGTERM handler, or its closes not waited for → the SIGTERM arm red.
//!
//! **Why the bound separates the two:** the old redial ran at the node's start and then every 30 s,
//! so a forward started at `t` redialled at `t + 30`. The anchor returns at about `t + 9`, so the
//! old code comes back about 20 s later, well past [`BACK_WITHIN`].
//!
//! Mutation: the 30 s gate restored (a lost anchor waits for the next half-minute) → red.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::time::{Duration, Instant};

use relay::{RelayWorld, Split};
use world::round_trip;

/// How long after the forward starts the anchor is killed: long enough that the forward has its
/// anchor connection and its circuit, and short of the old 30 s tick.
const KILL_AFTER: Duration = Duration::from_secs(4);
/// How long the anchor stays down.
const DOWN: Duration = Duration::from_secs(3);
/// How soon after the anchor is back the forward must carry an echo again. The new code needs a
/// tick, a dial, and the host's own redial; the old code needed about 20 s more.
const BACK_WITHIN: Duration = Duration::from_secs(10);
/// What a node says when its anchor connection goes.
const GONE: &str = "the connection to this anchor is gone";
/// Why, when the anchor was stopped cleanly (V210-93): it closed with "the peer stopped".
const STOPPED: &str = "the anchor stopped";
/// What a clean stop must never be reported as: it is not an authentication failure.
const NOT_AUTH: &str = "authenticator invalid";
/// What a node says when its anchor connection is made.
const CONNECTED: &str = "connected to this anchor";
/// How many times the anchor is stopped the moment the forward has reached it.
const STOPS_AT_ONCE: usize = 3;
/// How soon after a SIGKILL the forward must say its anchor is gone: 8 s of unanswered probes, a
/// 1 s tick, and 2 s for a loaded box. Silence alone took 28 s.
const KILLED_WITHIN: Duration = Duration::from_secs(11);
/// How soon after a SIGTERM the forward must say it: the close arrives at once and the next 1 s
/// tick reads it. Short of the 8 s any inference from silence needs.
const CLOSED_WITHIN: Duration = Duration::from_secs(3);

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn an_anchor_that_restarts_is_redialled_promptly() {
    watchdog::arm();
    let mut w = RelayWorld::new(Split::Families);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "CANNOT PROVE: the guest could not join over the relay ({took:?}).\n{out}\n{err}"
    );
    let started = Instant::now();
    let at = w.forward();
    let first = round_trip(at, b"before", Duration::from_secs(30));
    assert!(
        first.as_deref().is_ok_and(|b| b == b"before"),
        "CANNOT PROVE: no echo through the forward before the anchor went: {first:?}\n{}",
        w.fwd.as_mut().unwrap().transcript()
    );
    w.expect_still_relayed();
    std::thread::sleep(KILL_AFTER.saturating_sub(started.elapsed()));

    // ---- the anchor is stopped, and comes back on the same port --------------------------------
    let anchor_dir = w.tmp.path().join("anchor");
    let killed = Instant::now();
    let _ = std::process::Command::new("kill")
        .args(["-INT", &w.anchor.proc.child.id().to_string()])
        .status();
    let stopping = Instant::now();
    while w.anchor.proc.child.try_wait().ok().flatten().is_none() {
        assert!(
            stopping.elapsed() < Duration::from_secs(10),
            "CANNOT MEASURE: the anchor did not stop within 10 s of SIGINT"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(DOWN);
    w.anchor.restart(&anchor_dir);
    let back = Instant::now();
    eprintln!(
        "[proof] the anchor was stopped {:?} after the forward started, and is back {:?} later",
        killed.duration_since(started),
        back.duration_since(killed)
    );

    // ---- the forward carries again within BACK_WITHIN -----------------------------------------
    let mut carried = None;
    while back.elapsed() < BACK_WITHIN + Duration::from_secs(20) {
        if round_trip(at, b"after", Duration::from_secs(2)).is_ok_and(|b| b == b"after") {
            carried = Some(back.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let said = w.fwd.as_mut().unwrap().transcript();
    let saw_it_go = said.lines().any(|l| l.contains(GONE));
    eprintln!(
        "[proof] the forward carried again {carried:?} after the anchor was back (bound \
         {BACK_WITHIN:?}); it said its anchor went: {saw_it_go}"
    );
    let carried = carried.unwrap_or_else(|| {
        panic!(
            "the forward never carried again within {:?} of the anchor's return\n---- the forward \
             ----\n{said}\n---- the anchor ----\n{}\n---- the host ----\n{}",
            BACK_WITHIN + Duration::from_secs(20),
            w.anchor.proc.transcript(),
            w.host.as_mut().map(|h| h.transcript()).unwrap_or_default()
        )
    });
    assert!(
        carried < BACK_WITHIN,
        "the forward carried again only {carried:?} after its anchor was back, over {BACK_WITHIN:?}: \
         a lost anchor waited for a periodic redial\n---- the forward ----\n{said}"
    );
    assert!(
        saw_it_go,
        "the forward did not say its anchor connection went ({GONE:?})\n{said}"
    );
    assert_says_stopped("the forward", &said);
    let host = w.host.as_mut().map(|h| h.transcript()).unwrap_or_default();
    assert_says_stopped("the host", &host);
}

/// A clean stop is said as one (V210-93): every "gone" line in `said` gives "the anchor stopped"
/// as the reason, at least one does, and none calls it an authentication failure.
fn assert_says_stopped(who: &str, said: &str) {
    let gone: Vec<&str> = said.lines().filter(|l| l.contains(GONE)).collect();
    let auth = said.lines().filter(|l| l.contains(NOT_AUTH)).count();
    eprintln!(
        "[proof] {who}: {} \"gone\" line(s), {} saying {STOPPED:?}, {auth} saying {NOT_AUTH:?}",
        gone.len(),
        gone.iter().filter(|l| l.contains(STOPPED)).count()
    );
    assert!(
        auth == 0,
        "{who} reported a cleanly stopped anchor as {NOT_AUTH:?}\n{said}"
    );
    assert!(
        !gone.is_empty() && gone.iter().all(|l| l.contains(STOPPED)),
        "{who} did not say its anchor stopped ({STOPPED:?}) when it was stopped cleanly\n{said}"
    );
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn a_killed_anchor_is_noticed_promptly() {
    let _ = stopped_for_good("KILL", KILLED_WITHIN, false);
}

/// **A clean stop is said as one even when the anchor was busy carrying for the node** (V210-93).
/// The forward is moving a bulk echo through its circuit, and is held still for a moment
/// ([`FROZEN_BEFORE_STOP`], SIGSTOP: a node descheduled on a busy machine, or still in a debug
/// build's proof of work), so it acknowledges nothing and the anchor's congestion window toward it
/// fills with the echo. The anchor is stopped (SIGINT) then, and the forward let go
/// [`FROZEN_AFTER_STOP`] later. The anchor's CONNECTION_CLOSE waits behind its queued data: quinn
/// (0.11.19 and earlier, quinn-rs/quinn#2785) holds a close back with the data, the connection's
/// closing period (three probe timeouts, under 100 ms here) ends first, and the close never leaves.
/// That is the debug red's cause, measured: the anchor made the close for the forward's connection
/// and no datagram for it reached the socket. The forward must still say, within
/// [`CLOSED_WITHIN`], that its anchor **stopped**: not that it answered nothing, 8 s or more later,
/// or that it reset. That is what a stopping node's goodbye, said on a stream while the connection
/// still runs and waited for, is for.
///
/// Mutation: the goodbye not said (the close left to carry the news alone) → red.
#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn an_anchor_stopped_while_it_carries_a_transfer_is_said_to_have_stopped() {
    let mut w = stopped_for_good("INT", CLOSED_WITHIN, true);
    let said = w.fwd.as_mut().unwrap().transcript();
    assert_says_stopped("the forward", &said);
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn an_anchor_stopped_by_sigterm_is_noticed_at_once() {
    let mut w = stopped_for_good("TERM", CLOSED_WITHIN, false);
    let said = w.fwd.as_mut().unwrap().transcript();
    assert_says_stopped("the forward", &said);
    // ---- and a forward stops on SIGTERM as it does on Ctrl-C -----------------------------------
    let fwd = w.fwd.as_mut().unwrap();
    let signalled = Instant::now();
    let _ = std::process::Command::new("kill")
        .args(["-TERM", &fwd.child.id().to_string()])
        .status();
    let status = loop {
        if let Some(status) = fwd.child.try_wait().ok().flatten() {
            break Some(status);
        }
        if signalled.elapsed() > Duration::from_secs(10) {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let said = fwd.transcript();
    let stopping = said
        .lines()
        .any(|l| l.contains("vox: stopping the forward"));
    eprintln!(
        "[proof] SIGTERM to the forward: exited {status:?} after {:?}, said it was stopping: \
         {stopping}",
        signalled.elapsed()
    );
    assert!(
        status.is_some_and(|s| s.success()) && stopping,
        "the forward did not stop cleanly on SIGTERM (exit {status:?}, said it was stopping: \
         {stopping})\n{said}"
    );
}

/// Stop the anchor with `signal` and leave it down; the forward must say its anchor connection is
/// gone within `within` of the signal. With `carrying`, a bulk echo runs through the forward, and
/// so through the anchor's circuit, from before the stop until after it.
fn stopped_for_good(signal: &str, within: Duration, carrying: bool) -> RelayWorld {
    watchdog::arm();
    let mut w = RelayWorld::new(Split::Families);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "CANNOT MEASURE: the guest could not join over the relay ({took:?}).\n{out}\n{err}"
    );
    let started = Instant::now();
    let at = w.forward();
    let first = round_trip(at, b"before", Duration::from_secs(30));
    assert!(
        first.as_deref().is_ok_and(|b| b == b"before"),
        "CANNOT MEASURE: no echo through the forward before the anchor went: {first:?}\n{}",
        w.fwd.as_mut().unwrap().transcript()
    );
    std::thread::sleep(KILL_AFTER.saturating_sub(started.elapsed()));
    let fwd = w.fwd.as_mut().unwrap();
    let before = fwd
        .transcript()
        .lines()
        .filter(|l| l.contains(GONE))
        .count();
    assert_eq!(
        before,
        0,
        "CANNOT MEASURE: the forward said its anchor went before it was stopped\n{}",
        fwd.transcript()
    );

    // ---- a transfer in flight through the anchor, if asked for -----------------------------------
    let transfer = carrying.then(|| Transfer::start(at));
    if let Some(t) = &transfer {
        let flowing = t.echoed_at_least(TRANSFER_FLOWING, Duration::from_secs(30));
        eprintln!(
            "[proof] a transfer through the anchor: {} bytes echoed before the stop",
            t.echoed()
        );
        assert!(
            flowing,
            "CANNOT MEASURE: the transfer through the forward never echoed {TRANSFER_FLOWING} bytes \
             ({} did)\n{}",
            t.echoed(),
            w.fwd.as_mut().unwrap().transcript()
        );
    }

    // ---- the anchor is stopped, and stays down --------------------------------------------------
    let fwd_pid = w.fwd.as_mut().unwrap().child.id().to_string();
    if carrying {
        let _ = std::process::Command::new("kill")
            .args(["-STOP", &fwd_pid])
            .status();
        std::thread::sleep(FROZEN_BEFORE_STOP);
    }
    let at_stop = transfer.as_ref().map(Transfer::echoed);
    let stopped = Instant::now();
    let _ = std::process::Command::new("kill")
        .args([&format!("-{signal}"), &w.anchor.proc.child.id().to_string()])
        .status();
    if carrying {
        std::thread::sleep(FROZEN_AFTER_STOP);
        let _ = std::process::Command::new("kill")
            .args(["-CONT", &fwd_pid])
            .status();
    }
    while w.anchor.proc.child.try_wait().ok().flatten().is_none() {
        assert!(
            stopped.elapsed() < Duration::from_secs(10),
            "CANNOT MEASURE: the anchor did not exit within 10 s of SIG{signal}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let exited = stopped.elapsed();
    if let (Some(t), Some(before)) = (&transfer, at_stop) {
        eprintln!(
            "[proof] the forward was held {FROZEN_BEFORE_STOP:?} before the stop and \
             {FROZEN_AFTER_STOP:?} after it; the transfer echoed {} more bytes between the signal \
             and the anchor's exit",
            t.echoed().saturating_sub(before)
        );
    }

    // ---- the forward says so ---------------------------------------------------------------------
    // Watched well past the bound, so a red prints how long it did take.
    let fwd = w.fwd.as_mut().unwrap();
    let mut said = None;
    while stopped.elapsed() < within + Duration::from_secs(30) {
        let _ = fwd.transcript();
        said = fwd
            .said_since(stopped)
            .into_iter()
            .find(|l| l.starts_with("[+") && l.contains(GONE));
        if said.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let after = said.as_deref().and_then(|l| {
        l.strip_prefix("[+")?
            .split_once("s]")?
            .0
            .parse::<f64>()
            .ok()
            .map(Duration::from_secs_f64)
    });
    eprintln!(
        "[proof] SIG{signal}: the anchor exited {exited:?} after the signal; the forward said its \
         anchor connection went {after:?} after it (bound {within:?}): {said:?}"
    );
    let transcript = fwd.transcript();
    let after = after.unwrap_or_else(|| {
        panic!(
            "the forward never said its anchor connection went ({GONE:?}) within {:?} of \
             SIG{signal}\n---- the forward ----\n{transcript}\n---- the anchor ----\n{}",
            within + Duration::from_secs(30),
            w.anchor.proc.transcript()
        )
    });
    assert!(
        after < within,
        "the forward said its anchor connection went only {after:?} after SIG{signal}, over \
         {within:?}\n---- the forward ----\n{transcript}"
    );
    drop(transfer);
    w
}

/// How many bytes a transfer must have echoed before the anchor is stopped, so it is known to be
/// moving through the circuit.
const TRANSFER_FLOWING: u64 = 1 << 20;
/// How long the forward is held still before the anchor is stopped: long enough for the anchor's
/// congestion window toward it to fill, since nothing it sends is acknowledged.
const FROZEN_BEFORE_STOP: Duration = Duration::from_millis(500);
/// How long the forward stays held after the stop: past the anchor's closing period (three probe
/// timeouts, under 100 ms on loopback), so a close held back by its queued data is never sent, and
/// well short of how long a stopping node waits for its goodbye to be heard (500 ms).
const FROZEN_AFTER_STOP: Duration = Duration::from_millis(150);

/// A bulk echo through the forward: one thread writes as fast as the path takes it, another reads
/// the echo back and counts it. Stopped when dropped.
struct Transfer {
    echoed: std::sync::Arc<std::sync::atomic::AtomicU64>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Transfer {
    fn start(at: std::net::SocketAddr) -> Self {
        use std::io::{Read, Write};
        use std::sync::atomic::Ordering;
        let echoed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut out = std::net::TcpStream::connect(at).expect("connect to the forward");
        let mut back = out.try_clone().expect("clone the stream");
        let _ = out.set_write_timeout(Some(Duration::from_millis(200)));
        let _ = back.set_read_timeout(Some(Duration::from_millis(200)));
        let idle = |e: &std::io::Error| {
            matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            )
        };
        let writer = {
            let stop = std::sync::Arc::clone(&stop);
            std::thread::spawn(move || {
                let chunk = vec![0x5a_u8; 64 * 1024];
                while !stop.load(Ordering::Relaxed) {
                    match out.write(&chunk) {
                        Ok(_) => {}
                        Err(e) if idle(&e) => {}
                        Err(_) => break,
                    }
                }
            })
        };
        let reader = {
            let (stop, echoed) = (std::sync::Arc::clone(&stop), std::sync::Arc::clone(&echoed));
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 64 * 1024];
                while !stop.load(Ordering::Relaxed) {
                    match back.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            echoed.fetch_add(n as u64, Ordering::Relaxed);
                        }
                        Err(e) if idle(&e) => {}
                        Err(_) => break,
                    }
                }
            })
        };
        Self {
            echoed,
            stop,
            threads: vec![writer, reader],
        }
    }

    fn echoed(&self) -> u64 {
        self.echoed.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn echoed_at_least(&self, bytes: u64, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while self.echoed() < bytes {
            if Instant::now() > deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        true
    }
}

impl Drop for Transfer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

/// **A connection lost the moment it is made is still said to be gone** (V210-93), however soon
/// after the forward reached its anchor the anchor goes. This is the proven cause, staged every
/// time rather than by luck: the anchor is stopped (SIGINT) the instant the forward prints that it
/// reached it, which is before the forward's 1 s tick can have looked at the new connection, and
/// brought back on the same port. That is done [`STOPS_AT_ONCE`] times, and every stop must be
/// said, as a clean stop.
///
/// Mutation: the connection watched only from a tick's look, not from when it is made (as before
/// V210-93) → the stops are not said → red.
#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn an_anchor_lost_the_moment_it_is_reached_is_noticed() {
    watchdog::arm();
    let mut w = RelayWorld::new(Split::Families);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "CANNOT MEASURE: the guest could not join over the relay ({took:?}).\n{out}\n{err}"
    );
    let _ = w.forward();
    let anchor_dir = w.tmp.path().join("anchor");
    let mut stops = 0;
    for round in 1..=STOPS_AT_ONCE {
        // The next "connected" line, read as it arrives: the stop follows it at once. The first
        // may already have been read while the forward started.
        let fwd = w.fwd.as_mut().unwrap();
        let reached = if round == 1 && fwd.seen.iter().any(|l| l.contains(CONNECTED)) {
            Some(Instant::now())
        } else {
            next_line(fwd, CONNECTED, Duration::from_secs(60))
        };
        assert!(
            reached.is_some(),
            "CANNOT MEASURE: round {round}: the forward never said it reached its anchor\n{}",
            w.fwd.as_mut().unwrap().transcript()
        );
        let _ = std::process::Command::new("kill")
            .args(["-INT", &w.anchor.proc.child.id().to_string()])
            .status();
        let stopping = Instant::now();
        while w.anchor.proc.child.try_wait().ok().flatten().is_none() {
            assert!(
                stopping.elapsed() < Duration::from_secs(10),
                "CANNOT MEASURE: the anchor did not stop within 10 s of SIGINT"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        stops += 1;
        eprintln!(
            "[proof] round {round}: the anchor was stopped {:?} after the forward said it reached it",
            reached.map(|at| stopping.duration_since(at))
        );
        std::thread::sleep(Duration::from_millis(500));
        w.anchor.restart(&anchor_dir);
    }
    // Every stop is said within a few ticks of it: the last one is waited for.
    let deadline = Instant::now() + Duration::from_secs(10);
    let fwd = w.fwd.as_mut().unwrap();
    let mut said = fwd.transcript();
    while said.lines().filter(|l| l.contains(GONE)).count() < stops && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
        said = fwd.transcript();
    }
    let gone = said.lines().filter(|l| l.contains(GONE)).count();
    eprintln!(
        "[proof] the anchor was stopped {stops} times; the forward said it went {gone} times"
    );
    assert!(
        gone >= stops,
        "the anchor was stopped {stops} times, each the moment the forward reached it, and the \
         forward said it went only {gone} times\n{said}"
    );
    assert_says_stopped("the forward", &said);
}

/// Read `proc`'s output as it arrives until a line containing `what`, and say when it came.
fn next_line(proc: &mut world::VoxProc, what: &str, within: Duration) -> Option<Instant> {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if let Ok(line) = proc.lines.recv_timeout(Duration::from_millis(10)) {
            let hit = line.contains(what);
            proc.seen.push(line);
            if hit {
                return Some(Instant::now());
            }
        }
    }
    None
}
