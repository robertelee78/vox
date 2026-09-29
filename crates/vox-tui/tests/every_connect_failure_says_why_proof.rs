//! V210-85 / #277 — **every way `vox connect` ends without joining says why**, driven through the
//! shipped binary over a relay circuit.
//!
//! Found in the relayed-restart proof: a guest's `vox connect` ended non-zero after 92.5 s with an
//! empty stdout and an empty stderr. The transcript shows what that was: the test's watchdog had
//! reached its 600 s budget and SIGKILLed every `vox` it started, the connect mid-join among them,
//! and the harness kept only `status.success()`, so a kill read exactly like a verb that failed and
//! said nothing. That connect was not stuck — its sibling trials joined in 36.8–61.0 s, and the
//! same join measured here spent **108.7 s in its own proof-of-work solve** in a debug build on a
//! loaded machine (`join got in — … solve 108.73s …`). But it could not have said so: a `vox
//! connect` stopped by Ctrl-C or a SIGTERM died on the signal's default action, silently, and one
//! whose `Joined` event was lost from the lossy event stream waited for it for good.
//!
//! What must hold, each through the anchor's circuit (the host on IPv4, the guest on `[::1]`, so
//! the circuit is the only path — see `support/relay.rs`):
//!
//! 1. **Stopped mid-join by SIGTERM**: exit status 143 — not death by the signal — and stderr says
//!    `stopped by SIGTERM after …s`, that the room was not joined, and the step it was waiting in,
//!    naming the host as the member it waited for. The host is SIGSTOPped the moment the guest's
//!    pre-join record reaches the board, so the join is left waiting on it: for its dial, or for
//!    its answer to the proof of work. A join that ended before it could be stopped is CANNOT
//!    MEASURE, never a pass. **And it ends when it says so**, within [`STOPS_WITHIN`] of the
//!    signal: the first version printed its reason at once and then lived on in a debug build until
//!    the proof of work it had abandoned finished, past 15 s.
//! 2. **Stopped mid-join by SIGINT** (Ctrl-C): the same, with 130.
//! 3. **The host gone** (SIGKILLed): exit status 1, `cannot join: …`, and the join's steps with the
//!    one that failed — the host's dial — and how long each took.
//! 4. **Refused** (a wrong room passphrase, checked by the live host): exit status 1, `cannot join:
//!    …`, the refusal, and the steps. The refusal is the host's own answer over the circuit, so it
//!    is also the control: this world's joins reach the host and are answered.
//!
//! In every one, stderr is non-empty and the exit is a status, never a signal. Cases 1 and 4 share
//! one world and 2 and 3 another, as two tests that run side by side. Each prints its counts.
//!
//! **Mutations that must turn it red:** the verb runner printing nothing for an error; `vox
//! connect` not taking SIGINT/SIGTERM (cases 1 and 2 die by the signal); the joiner not announcing
//! its steps (cases 1 and 2 name no member); a stop that waits for the runtime's blocking work
//! (cases 1 and 2 outlive [`STOPS_WITHIN`] in a debug build, where the solve is long).
//!
//! `#[ignore]`d: production Argon2id and a real PoW. Run it in release.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use relay::{RelayWorld, Split};
use world::{args, VoxProc};

/// A `vox connect` that fails on its own must have ended by then: past the board's 30 s patience,
/// a dial's timeout and a proof of work, with room for a loaded machine.
const FAILS_WITHIN: Duration = Duration::from_secs(300);

/// A `vox connect` sent SIGINT or SIGTERM must have ended, and said so, by then — whatever it was
/// doing, a proof of work included.
const STOPS_WITHIN: Duration = Duration::from_secs(10);

/// How long the join is left waiting on the stopped host before it is stopped itself: well inside
/// the 10 s its dial to the host takes to give up (measured: `dial 10.00s`) and the 30 s it waits
/// for a frame, so the stop lands mid-join and not after a failure of its own.
const LEFT_WAITING: Duration = Duration::from_secs(2);

/// The build profile, named in every count line.
const PROFILE: &str = if cfg!(debug_assertions) {
    "debug"
} else {
    "release"
};

/// How a `vox connect` ended.
struct Ended {
    status: ExitStatus,
    took: Duration,
    stdout: String,
    stderr: String,
}

impl Ended {
    fn describe(&self) -> String {
        format!(
            "status: {} after {:.1}s\n--- stdout:\n{}\n--- stderr:\n{}",
            self.status,
            self.took.as_secs_f64(),
            self.stdout,
            self.stderr
        )
    }
}

/// Start the guest's `vox connect` with `passphrase`, on `[::1]` through the anchor's IPv6 name.
fn start_connect(w: &RelayWorld, passphrase: &str) -> (VoxProc, Instant) {
    let file = w.tmp.path().join("connect-passphrase");
    std::fs::write(&file, passphrase).unwrap();
    let proc = VoxProc::spawn(
        "connect",
        &w.guest_dir,
        &args(&[
            "connect",
            &w.address,
            "--passphrase-file",
            file.to_str().unwrap(),
            "--anchor",
            &w.anchor.v6_spec,
            "--listen",
            "[::1]:0",
        ]),
    );
    (proc, Instant::now())
}

/// Read everything `proc` says until both its pipes close, then reap it. Panics — a hang, not a
/// verdict — if that takes longer than `within`.
fn finish(mut proc: VoxProc, t0: Instant, within: Duration) -> Ended {
    let deadline = Instant::now() + within;
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(
            !left.is_zero(),
            "`vox connect` had not ended {within:?} after it was due to. It said:\n{}\n{}",
            stdout.join("\n"),
            stderr.join("\n")
        );
        match proc.lines.recv_timeout(left.min(Duration::from_secs(1))) {
            Ok(line) => match line.strip_prefix("! ") {
                Some(err) => stderr.push(err.to_owned()),
                None => stdout.push(line),
            },
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    let status = proc.child.wait().expect("reap vox connect");
    let ended = Ended {
        status,
        took: t0.elapsed(),
        stdout: stdout.join("\n"),
        stderr: stderr.join("\n"),
    };
    eprintln!(
        "[connect] {}",
        ended.describe().replace('\n', "\n[connect] ")
    );
    ended
}

/// Send `sig` to `pid`.
fn signal(pid: u32, sig: &str) {
    let ok = std::process::Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "kill {sig} {pid}");
}

/// Wait until the anchor's board holds the host's room with its one member. The host prints its
/// address before it has published there, and a host stopped before that leaves a board with
/// nothing for the room: a join then fails on its own, before it ever waits on the host.
fn until_published(w: &mut RelayWorld) {
    let held = format!("board — {} 1m", &w.room[..12]);
    w.anchor.proc.expect_within(
        Duration::from_secs(240),
        "the host's room, with its member, on the anchor's board",
        |l| l.contains(&held),
    );
}

/// Wait until the anchor's board holds the guest's pre-join record: the guest has unlocked, reached
/// the board and announced itself, so its join is past its own machine and waiting on the host.
fn until_announced(w: &mut RelayWorld) {
    w.anchor.proc.expect_within(
        Duration::from_secs(240),
        "the guest's pre-join record on the anchor's board",
        |l| l.contains("board — ") && l.contains("/1p"),
    );
}

/// Every case: a status, never a signal, and something on stderr.
fn assert_said_why(e: &Ended, case: &str, code: i32) {
    assert_eq!(
        e.status.signal(),
        None,
        "{case}: `vox connect` died by a signal instead of ending with a reason.\n{}",
        e.describe()
    );
    assert_eq!(
        e.status.code(),
        Some(code),
        "{case}: exit status\n{}",
        e.describe()
    );
    assert!(
        !e.stderr.trim().is_empty(),
        "{case}: `vox connect` ended with status {code} and SAID NOTHING on stderr.\n{}",
        e.describe()
    );
}

/// Cases 1 and 2: stopped by `sig` while the join waits on the host, SIGSTOPped once the guest has
/// announced itself. The host is left stopped.
fn stopped_mid_join(w: &mut RelayWorld, host: u32, sig: &str, name: &str, code: i32) -> Ended {
    until_published(w);
    let (mut connect, t0) = start_connect(w, &w.passphrase.clone());
    until_announced(w);
    signal(host, "-STOP");
    std::thread::sleep(LEFT_WAITING);
    if let Ok(Some(status)) = connect.child.try_wait() {
        panic!(
            "CANNOT MEASURE ({name}): the join ended ({status}) before it could be stopped mid-way.\n{}",
            connect.transcript()
        );
    }
    signal(connect.child.id(), sig);
    let sent = Instant::now();
    let e = finish(connect, t0, STOPS_WITHIN);
    eprintln!(
        "[proof] ({PROFILE}) {name}: status {} {:.1}s after the signal, {:.1}s after the start",
        e.status,
        sent.elapsed().as_secs_f64(),
        e.took.as_secs_f64()
    );
    let case = format!("stopped by {name}");
    assert_said_why(&e, &case, code);
    let host12 = &w.host_fp[..12];
    for want in [
        format!("stopped by {name} after "),
        "the room was not joined".to_owned(),
        "it had waited ".to_owned(),
        format!("member {host12}"),
    ] {
        assert!(
            e.stderr.contains(&want),
            "{case}: stderr does not say {want:?} — it must say how long it ran, that the room \
             was not joined, and the step it was waiting in (for the host, {host12}).\n{}",
            e.describe()
        );
    }
    e
}

/// Cases 3 and 4: a join that fails on its own.
fn failed_join(e: &Ended, case: &str, also: &[&str]) {
    assert_said_why(e, case, 1);
    for want in ["cannot join: ", "join did not get in — "]
        .iter()
        .chain(also)
    {
        assert!(
            e.stderr.contains(want),
            "{case}: stderr does not say {want:?}.\n{}",
            e.describe()
        );
    }
}

#[test]
#[ignore = "production Argon2id + a real PoW, a relayed world of real `vox` processes; run in release"]
fn a_connect_stopped_by_sigterm_or_refused_says_why() {
    watchdog::arm();
    // SIGTERM mid-join, then a refusal.
    let mut w = RelayWorld::new(Split::Families);
    let host = w.host.as_ref().expect("a host").child.id();
    stopped_mid_join(&mut w, host, "-TERM", "SIGTERM", 143);
    signal(host, "-CONT");

    let (c, t0) = start_connect(&w, "not-the-room-passphrase");
    let e = finish(c, t0, FAILS_WITHIN);
    failed_join(&e, "refused (a wrong passphrase)", &["refused"]);
    eprintln!(
        "[proof] ({PROFILE}) refused: status {} in {:.1}s",
        e.status,
        e.took.as_secs_f64()
    );
    eprintln!("[proof] ({PROFILE}) 2/2 failures said why (SIGTERM, refused)");
}

#[test]
#[ignore = "production Argon2id + a real PoW, a relayed world of real `vox` processes; run in release"]
fn a_connect_stopped_by_sigint_or_left_without_its_host_says_why() {
    watchdog::arm();
    // SIGINT mid-join, then the host gone.
    let mut w = RelayWorld::new(Split::Families);
    let host = w.host.as_ref().expect("a host").child.id();
    let host12 = w.host_fp[..12].to_owned();
    stopped_mid_join(&mut w, host, "-INT", "SIGINT", 130);
    drop(w.host.take());
    eprintln!("[test] host pid {host} killed and reaped");

    let (c, t0) = start_connect(&w, &w.passphrase.clone());
    let e = finish(c, t0, FAILS_WITHIN);
    let dial = format!("{host12}: dial");
    failed_join(&e, "the host gone", &[&dial]);
    eprintln!(
        "[proof] ({PROFILE}) host gone: status {} in {:.1}s",
        e.status,
        e.took.as_secs_f64()
    );
    eprintln!("[proof] ({PROFILE}) 2/2 failures said why (SIGINT, the host gone)");
}
