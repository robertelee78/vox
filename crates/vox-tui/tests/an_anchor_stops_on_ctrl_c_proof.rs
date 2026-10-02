//! **A `vox node` stops on Ctrl-C even when the signal lands in the same turn as its tick**, and
//! **every long-running verb stops cleanly on every stop signal**, through the shipped binary.
//!
//! **1. The anchor and its tick.** The anchor's loop made a new Ctrl-C listener on every turn of
//! its `select!`. A listener sees only signals that arrive after it starts listening, so a SIGINT
//! that became ready in the same turn as the 500 ms status tick went to a listener the tick's win
//! then dropped, and the anchor served on, deaf to Ctrl-C. CI's macOS runner met it as "CANNOT
//! MEASURE: the anchor did not stop within 10 s of SIGINT" in
//! `an_anchor_that_restarts_is_redialled_promptly_proof`.
//!
//! **And on every stop signal, not only Ctrl-C** (V210-85, #277): SIGTERM (a service manager,
//! `kill`), SIGHUP (its terminal closed, its ssh session gone) and SIGQUIT (`Ctrl-\`) stop it the
//! same way. Left to their defaults they killed it on the spot — SIGQUIT with a core dump — its
//! closes unsent.
//!
//! **The scene:** an anchor is started and settles; it is then stopped (SIGSTOP) for longer than
//! one tick, which is what a loaded box does to a process it does not schedule, sent a stop signal,
//! and resumed. On waking the tick and the signal are ready together. The [`TRIALS`] anchors take
//! SIGINT, SIGTERM, SIGHUP and SIGQUIT in turn. Each must exit within [`STOP_WITHIN`] with status 0,
//! not by the signal, and say which signal stopped it and that it is shutting down.
//!
//! **A red names its side.** An anchor that never wrote its anchors file, or a `kill` that failed,
//! is CANNOT MEASURE (the scene was not staged). Anything after the signal is the product's: it
//! did not exit, died by the signal, or exited without saying why. The wait for each exit is
//! polled every 50 ms, and the proof measures its own clock on the same timeline: how far the
//! deschedule's sleep overshot, and the longest gap between two polls. An anchor still running
//! while that apparatus stalled past [`APPARATUS_BUDGET`] cannot be told from a runner that
//! stalled, and reads `CANNOT MEASURE: apparatus took X`; otherwise it reads `PRODUCT: … (apparatus
//! Y)`.
//!
//! Mutations: the listener made inside the `select!` again → red (13 of 20 anchors never exited);
//! SIGHUP or SIGQUIT not taken → those trials die by the signal → red.
//!
//! **2. Every verb, every stop signal (V210-108, #303).** SIGINT, SIGTERM, SIGHUP and SIGQUIT are
//! each a clean stop: people run these verbs in tmux, over ssh and under systemd, whose stop and
//! whose closed window send SIGTERM and SIGHUP. `vox serve` died silently on SIGHUP and SIGTERM,
//! `vox daemon` ignored SIGHUP, `vox up` and `vox forward` heard only Ctrl-C, and `vox room tail`
//! and `vox room send` heard nothing or Ctrl-C alone.
//!
//! The scene: one anchor, one `vox serve` host and a trusted guest that has joined (the shared
//! `World`). Each of `vox up`, `vox forward`, `vox daemon` (holding the room), `vox room tail` and
//! `vox room send` (through that daemon) on the guest, and `vox serve` on the host, is started,
//! brought to where it is serving, and sent one signal — each verb once per signal, 24 stops. And
//! `vox up` and `vox forward` are each stopped once per signal while they wait at their identity
//! passphrase prompt on a terminal of their own (a pty), 8 stops more, 32 in all. Each
//! must be gone within [`STOP_BOUND`], not killed by the signal's default action, and, as the
//! person sees it:
//! - a **server** (`vox daemon`, `vox serve`) says `stopped by <SIGNAL>` and exits 0: being stopped
//!   is how a server ends, and a service manager counts a non-zero exit on its stop as a failure;
//! - a **client** (`vox up`, `vox forward`, `vox room tail`, `vox room send`) says on stderr
//!   `vox: stopped by <SIGNAL>` and exits 128 + the signal's number, as a shell reports it.
//! - stopped at its prompt, a client also hands its terminal back with echo on: the prompt's raw
//!   mode left behind is a shell where nothing typed shows.
//!
//! **A red names its side.** A verb that never reached serving, or a `kill` that failed, is
//! APPARATUS (staging not achieved). Anything after the signal is the product's, quoting what it
//! said: it did not stop, died by the signal, exited with the wrong code, or did not say why.
//!
//! Mutations, one per claim: `vox serve`'s runner listening for Ctrl-C alone; `with_room`
//! (`vox up`, `vox forward`) listening for Ctrl-C alone; `vox daemon` ignoring SIGHUP again; a
//! stopped `vox serve` exiting 128+n as a client does; `vox up` and `vox forward` asking for their
//! passphrases before the stop is taken. Each goes red on the stops it gets wrong.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use world::{after_label, args, echo_service, vox_once, VoxProc, World, IDENTITY};

/// How many anchors are signalled. On the unfixed code 13 of 20 missed the signal, so ten that all
/// stop is not luck.
const TRIALS: usize = 10;
/// The stop signals, taken in turn, with the name `vox node` gives each.
const SIGNALS: [(&str, &str); 4] = [
    ("-INT", "SIGINT"),
    ("-TERM", "SIGTERM"),
    ("-HUP", "SIGHUP"),
    ("-QUIT", "SIGQUIT"),
];
/// Longer than the anchor's 500 ms tick, so a tick is due when it wakes.
const DESCHEDULED: Duration = Duration::from_millis(1200);
/// A clean stop takes well under a second.
const STOP_WITHIN: Duration = Duration::from_secs(10);
/// How long an anchor may take to start and write its anchors file.
const LINE_PATIENCE: Duration = Duration::from_secs(60);
/// The most the proof's own clock may stall (the deschedule's sleep overshooting, or the longest
/// gap between two 50 ms polls) before an anchor still running is the runner's, not the anchor's.
const APPARATUS_BUDGET: Duration = Duration::from_secs(2);

fn signal(pid: u32, sig: &str) {
    let sent = std::process::Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(sent, "CANNOT MEASURE: `kill {sig} {pid}` failed");
}

#[test]
#[ignore = "real binaries; CI runs it in release"]
fn an_anchor_stops_on_ctrl_c_when_a_tick_is_due() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let mut stuck = Vec::new();
    let mut stalled = Vec::new();
    for trial in 0..TRIALS {
        let (sig, name) = SIGNALS[trial % SIGNALS.len()];
        let dir = tmp.path().join(format!("anchor{trial}"));
        std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: cannot make a directory");
        let mut anchor =
            VoxProc::spawn("anchor", &dir, &args(&["node", "--listen", "127.0.0.1:0"]));
        if let Err(why) = anchor.try_expect_within(LINE_PATIENCE, "the anchors file written", |l| {
            l.starts_with("vox node: wrote ")
        }) {
            panic!("CANNOT MEASURE: anchor {trial} never settled: {why}");
        }
        let pid = anchor.child.id();
        signal(pid, "-STOP");
        let slept = Instant::now();
        std::thread::sleep(DESCHEDULED);
        let overshoot = slept.elapsed().saturating_sub(DESCHEDULED);
        signal(pid, sig);
        signal(pid, "-CONT");
        let signalled = Instant::now();
        let (mut last_poll, mut longest_gap) = (signalled, Duration::ZERO);
        while anchor.child.try_wait().ok().flatten().is_none() && signalled.elapsed() < STOP_WITHIN
        {
            std::thread::sleep(Duration::from_millis(50));
            longest_gap = longest_gap.max(last_poll.elapsed());
            last_poll = Instant::now();
        }
        let apparatus = overshoot.max(longest_gap);
        let status = anchor.child.try_wait().ok().flatten();
        let said = anchor.transcript();
        let shut = said.lines().any(|l| l == "vox node: shutting down");
        let named = said
            .lines()
            .any(|l| l == format!("vox node: stopped by {name}"));
        eprintln!(
            "[proof] anchor {trial}, {name}: exited {status:?} after {:?}, said it was stopped by \
             {name}: {named}, shutting down: {shut} (apparatus {apparatus:?})",
            signalled.elapsed()
        );
        let Some(status) = status else {
            let _ = anchor.child.kill();
            let _ = anchor.child.wait();
            let what = format!("anchor {trial} ({name}, apparatus {apparatus:?}):\n{said}");
            if apparatus > APPARATUS_BUDGET {
                stalled.push(what);
            } else {
                stuck.push(what);
            }
            continue;
        };
        assert_eq!(
            status.signal(),
            None,
            "PRODUCT: anchor {trial}: `vox node` died by {name} instead of stopping:\n{said}"
        );
        assert_eq!(
            status.code(),
            Some(0),
            "PRODUCT: anchor {trial}: `vox node` stopped by {name} ended with {status}:\n{said}"
        );
        assert!(
            named && shut,
            "PRODUCT: anchor {trial} exited on {name} without saying it was stopped by {name} and is \
             shutting down:\n{said}"
        );
    }
    eprintln!(
        "[proof] {} of {TRIALS} anchors stopped (SIGINT, SIGTERM, SIGHUP and SIGQUIT in turn)",
        TRIALS - stuck.len()
    );
    assert!(
        stuck.is_empty(),
        "PRODUCT: {} of {TRIALS} anchors did not stop within {STOP_WITHIN:?} of a stop signal that landed \
         with a tick:\n{}",
        stuck.len(),
        stuck.join("\n")
    );
    assert!(
        stalled.is_empty(),
        "CANNOT MEASURE: {} of {TRIALS} anchors were still running {STOP_WITHIN:?} after the \
         signal, but the apparatus stalled past {APPARATUS_BUDGET:?} meanwhile, so a slow anchor \
         cannot be told from a stalled runner:\n{}",
        stalled.len(),
        stalled.join("\n")
    );
}

/// The four stop signals: name, `kill` flag, and the exit code a clean stop ends with (128 + its
/// number, as a shell reports a process the signal killed).
const STOP_SIGNALS: [(&str, &str, i32); 4] = [
    ("SIGINT", "-INT", 130),
    ("SIGTERM", "-TERM", 143),
    ("SIGHUP", "-HUP", 129),
    ("SIGQUIT", "-QUIT", 131),
];
/// A clean stop takes well under a second; a node's shutdown is bounded at 5 s and a daemon's
/// runtime at 5 s more. Anything still running after this has not stopped.
const STOP_BOUND: Duration = Duration::from_secs(20);
/// The servers, and the prefix each says it was stopped with.
const DAEMON: Kind = Kind::Server("vox daemon");
const SERVE: Kind = Kind::Server("vox");

/// Run a staging step. A panic in it is the staging's, not the product's verdict, and says so.
fn staged<T>(what: &str, step: impl FnOnce() -> T) -> T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(step)).unwrap_or_else(|e| {
        let why = e
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_default();
        panic!("APPARATUS: staging not achieved — {what}: {why}")
    })
}

/// How a verb says it was stopped: a server on stdout, as `<prefix>: stopped by <SIGNAL>`, exiting
/// 0; a client on stderr, as `vox: stopped by <SIGNAL>`, exiting 128 + the signal's number.
#[derive(Clone, Copy)]
enum Kind {
    Server(&'static str),
    Client,
}

/// Send `verb`'s process the stop signal `(name, flag, client_code)` and assert, as the person sees
/// it, that it stops cleanly: gone within [`STOP_BOUND`], not by the signal's default action, saying
/// it was stopped by `name`, with the exit code its [`Kind`] has.
fn stops_cleanly(
    p: &mut VoxProc,
    verb: &str,
    kind: Kind,
    (name, flag, client_code): (&str, &str, i32),
) {
    let (code, told) = match kind {
        Kind::Server(prefix) => (0, format!("{prefix}: stopped by {name}")),
        Kind::Client => (client_code, format!("! vox: stopped by {name}")),
    };
    let pid = p.child.id();
    let sent = std::process::Command::new("kill")
        .args([flag, &pid.to_string()])
        .status();
    assert!(
        sent.as_ref().is_ok_and(std::process::ExitStatus::success),
        "APPARATUS: `kill {flag} {pid}` could not signal {verb}: {sent:?}"
    );
    let signalled = Instant::now();
    let status = loop {
        if let Some(st) = p.child.try_wait().ok().flatten() {
            break Some(st);
        }
        if signalled.elapsed() > STOP_BOUND {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // Everything it said, to the end of its output.
    let drained = Instant::now() + Duration::from_secs(5);
    loop {
        let left = drained.saturating_duration_since(Instant::now());
        match p.lines.recv_timeout(left.max(Duration::from_millis(1))) {
            Ok(line) => p.seen.push(line),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) if left.is_zero() => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    let said = p.seen.join("\n");
    let Some(status) = status else {
        let _ = p.child.kill();
        let _ = p.child.wait();
        panic!("PRODUCT: {verb} did not stop within {STOP_BOUND:?} of {name}. It said:\n{said}");
    };
    assert!(
        status.signal().is_none(),
        "PRODUCT: {verb} died on {name}'s default action ({status:?}) — no clean stop, nothing \
         said. It said:\n{said}"
    );
    assert_eq!(
        status.code(),
        Some(code),
        "PRODUCT: {verb} stopped by {name} exited {status:?}, not {code}. It said:\n{said}"
    );
    assert!(
        p.seen.iter().any(|l| l.trim_end() == told),
        "PRODUCT: {verb} did not say it was stopped by {name}. It said:\n{said}"
    );
    println!(
        "[proof] {verb}: {name} -> said so, exit {code}, gone in {:?}",
        signalled.elapsed()
    );
}

/// `verb` (`up` or `forward`) started on a terminal of its own — stdin and stdout on a pty, stderr
/// on a pipe — with no identity passphrase to hand, so it asks for one; sent `sig` while it waits
/// at that prompt. As the person sees it, it must stop as any client does (said so, 128 + n), and
/// hand back a terminal that echoes and edits lines again: the prompt's raw mode left behind is a
/// shell where nothing typed shows.
fn stops_cleanly_at_its_prompt(w: &World, verb: &str, (name, flag, code): (&str, &str, i32)) {
    use rustix::pty::{grantpt, openpt, ptsname, unlockpt, OpenptFlags};
    use rustix::termios::LocalModes;
    use std::io::{BufRead as _, Read as _};
    let who = format!("`vox {verb}` at its passphrase prompt");
    let pty = staged("a pty of its own", || {
        let controller = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("openpt");
        grantpt(&controller).expect("grantpt");
        unlockpt(&controller).expect("unlockpt");
        let name = ptsname(&controller, Vec::new()).expect("ptsname");
        (
            controller,
            name.to_str().expect("the pty's name").to_owned(),
        )
    });
    let (controller, pty_name) = pty;
    let open = || {
        staged("open the pty", || {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&pty_name)
                .expect("open")
        })
    };
    let terminal = open();
    let mut a = vec![verb.to_owned(), w.room.clone()];
    if verb == "forward" {
        a.extend([
            w.host_fp.clone(),
            w.service_port.to_string(),
            "127.0.0.1:0".into(),
        ]);
    }
    a.extend([
        "--anchor".into(),
        w.anchor_spec.clone(),
        "--listen".into(),
        "127.0.0.1:0".into(),
    ]);
    let mut child = staged("start it on the pty", || {
        std::process::Command::new(world::VOX)
            .args(&a)
            .env("VOX_DATA_DIR", &w.guest_dir)
            .env("VOX_CONFIG_DIR", w.guest_dir.join("cfg"))
            .env_remove("VOX_IDENTITY_PASSPHRASE")
            .env_remove("VOX_ROOM_PASSPHRASE")
            .stdin(std::process::Stdio::from(open()))
            .stdout(std::process::Stdio::from(open()))
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn")
    });
    // What it draws on its terminal, read as it arrives: a process whose output nobody reads
    // cannot finish exiting on macOS.
    let shown = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let (mut screen, into) = (std::fs::File::from(controller), shown.clone());
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = screen.read(&mut buf) {
                if n == 0 {
                    break;
                }
                into.lock()
                    .expect("APPARATUS: the screen buffer's lock")
                    .extend_from_slice(&buf[..n]);
            }
        });
    }
    let (tx, stderr) = mpsc::channel();
    let err = child.stderr.take().expect("APPARATUS: its stderr");
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(err).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let screen = || {
        String::from_utf8_lossy(&shown.lock().expect("APPARATUS: the screen buffer's lock"))
            .into_owned()
    };
    let echo = |t: &std::fs::File| {
        rustix::termios::tcgetattr(t)
            .map(|m| m.local_modes.contains(LocalModes::ECHO))
            .unwrap_or_else(|e| panic!("APPARATUS: reading the terminal's modes: {e}"))
    };
    // At the prompt once it shows it and has turned echo off, so a passphrase is not shown.
    let deadline = Instant::now() + Duration::from_secs(30);
    while !screen().contains("identity passphrase") || echo(&terminal) {
        if let Ok(Some(st)) = child.try_wait() {
            panic!(
                "APPARATUS: staging not achieved — {who} ended ({st}) before its prompt:\n{}",
                screen()
            );
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("APPARATUS: staging not achieved — {who} never waited at a prompt with echo off:\n{}", screen());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let pid = child.id();
    let sent = std::process::Command::new("kill")
        .args([flag, &pid.to_string()])
        .status();
    assert!(
        sent.as_ref().is_ok_and(std::process::ExitStatus::success),
        "APPARATUS: `kill {flag} {pid}` could not signal {who}: {sent:?}"
    );
    let signalled = Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait().ok().flatten() {
            break Some(st);
        }
        if signalled.elapsed() > STOP_BOUND {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // Everything it said, to the end of its stderr.
    let mut said = Vec::new();
    let drained = Instant::now() + Duration::from_secs(5);
    loop {
        let left = drained.saturating_duration_since(Instant::now());
        match stderr.recv_timeout(left.max(Duration::from_millis(1))) {
            Ok(line) => said.push(line),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) if left.is_zero() => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    let said = said.join("\n");
    let Some(status) = status else {
        let _ = child.kill();
        let _ = child.wait();
        panic!("PRODUCT: {who} did not stop within {STOP_BOUND:?} of {name}. It said:\n{said}");
    };
    assert!(
        status.signal().is_none(),
        "PRODUCT: {who} died on {name}'s default action ({status:?}) — no clean stop, nothing said."
    );
    assert_eq!(
        status.code(),
        Some(code),
        "PRODUCT: {who} stopped by {name} exited {status:?}, not {code}. It said:\n{said}"
    );
    assert!(
        said.lines()
            .any(|l| l.trim_end() == format!("vox: stopped by {name}")),
        "PRODUCT: {who} did not say it was stopped by {name}. It said:\n{said}"
    );
    assert!(
        echo(&terminal),
        "PRODUCT: {who}, stopped by {name}, left its terminal without echo — a shell where nothing \
         typed shows. It said:\n{said}"
    );
    println!(
        "[proof] {who}: {name} -> said so, exit {code}, echo back on, gone in {:?}",
        signalled.elapsed()
    );
}

/// `vox daemon` on the profile at `dir`, holding the world's room; returns once it says so.
fn daemon(w: &World, dir: &Path, pass_file: &Path) -> VoxProc {
    let mut d = VoxProc::spawn(
        "daemon",
        dir,
        &args(&[
            "daemon",
            "--passphrase-file",
            pass_file
                .to_str()
                .expect("APPARATUS: a temp path is not UTF-8"),
            "--anchor",
            &w.anchor_spec,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    let room = w.room.clone();
    staged("`vox daemon` holding the room", || {
        d.expect_line("the daemon to hold the room open", |l| {
            l.starts_with("vox daemon: holding room") && l.contains(&room)
        })
    });
    d
}

#[test]
#[ignore = "real binaries; CI runs it in release"]
fn every_long_running_verb_stops_cleanly_on_every_stop_signal() {
    // 24 starts in a row, each unlocking an identity with production Argon2id: a debug build took
    // 298 s on a quiet box and passed the 600 s default under load with 8 of 24 done.
    watchdog::arm_for(Duration::from_secs(if cfg!(debug_assertions) {
        1800
    } else {
        600
    }));
    let mut w = staged("an anchor, a `vox serve` host and a joined guest", || {
        World::new(echo_service(), true)
    });
    let guest = w.guest_dir.clone();
    let mut stops = 0;

    // ---- vox up, vox forward at their passphrase prompt, on a terminal --------------------------
    for verb in ["up", "forward"] {
        for sig in STOP_SIGNALS {
            stops_cleanly_at_its_prompt(&w, verb, sig);
            stops += 1;
        }
    }

    // ---- vox up, vox forward: the guest, while the host serves ---------------------------------
    for sig in STOP_SIGNALS {
        let (mut up, _) = staged("`vox up` serving", || w.up("up", &guest));
        stops_cleanly(&mut up, "`vox up`", Kind::Client, sig);
        stops += 1;
    }
    for sig in STOP_SIGNALS {
        let (mut fwd, _) = staged("`vox forward` forwarding", || w.forward("forward", &guest));
        stops_cleanly(&mut fwd, "`vox forward`", Kind::Client, sig);
        stops += 1;
    }

    // ---- vox room tail, vox room send: through a daemon on the guest ---------------------------
    let pass_file = w.tmp.path().join("daemon-passphrases");
    std::fs::write(&pass_file, format!("{IDENTITY}\n{}\n", w.passphrase))
        .expect("APPARATUS: write the daemon's passphrase file");
    let offered = w.tmp.path().join("offered.txt");
    std::fs::write(&offered, "a file offered in the room\n")
        .expect("APPARATUS: write the file to offer");
    let mut held = daemon(&w, &guest, &pass_file);
    for (i, sig) in STOP_SIGNALS.into_iter().enumerate() {
        let mut tail = VoxProc::spawn("tail", &guest, &args(&["room", "tail", &w.room]));
        // In its loop once it shows a post made after it started: posted every 2 s until it does,
        // since a post made before it subscribed is not one it shows.
        let text = format!("tail check {i}");
        let shown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let poster = {
            let (shown, guest, room, text) =
                (shown.clone(), guest.clone(), w.room.clone(), text.clone());
            std::thread::spawn(move || {
                for _ in 0..30 {
                    if shown.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    let _ = vox_once(&guest, &args(&["room", "post", &room, &text]));
                    std::thread::sleep(Duration::from_secs(2));
                }
            })
        };
        staged("`vox room tail` showing a new post", || {
            tail.expect_within(Duration::from_secs(60), "the post", |l| l.contains(&text))
        });
        shown.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = poster.join();
        stops_cleanly(&mut tail, "`vox room tail`", Kind::Client, sig);
        stops += 1;
    }
    for sig in STOP_SIGNALS {
        let mut send = VoxProc::spawn(
            "send",
            &guest,
            &args(&[
                "room",
                "send",
                &w.room,
                offered
                    .to_str()
                    .expect("APPARATUS: a temp path is not UTF-8"),
            ]),
        );
        staged("`vox room send` offering", || {
            send.expect_line("the offer", |l| l.starts_with("vox: offering "))
        });
        stops_cleanly(&mut send, "`vox room send`", Kind::Client, sig);
        stops += 1;
    }

    // ---- vox daemon: the one above, then one per remaining signal -------------------------------
    stops_cleanly(&mut held, "`vox daemon`", DAEMON, STOP_SIGNALS[0]);
    stops += 1;
    for sig in &STOP_SIGNALS[1..] {
        let mut d = daemon(&w, &guest, &pass_file);
        stops_cleanly(&mut d, "`vox daemon`", DAEMON, *sig);
        stops += 1;
    }

    // ---- vox serve: the world's host, then a new one per remaining signal -----------------------
    let mut host = w.host.take().expect("APPARATUS: the world's host");
    stops_cleanly(&mut host, "`vox serve`", SERVE, STOP_SIGNALS[0]);
    stops += 1;
    for sig in &STOP_SIGNALS[1..] {
        let mut serve = VoxProc::spawn(
            "serve",
            &w.host_dir,
            &args(&[
                "serve",
                &w.service_port.to_string(),
                "--anchor",
                &w.anchor_spec,
                "--listen",
                "127.0.0.1:0",
            ]),
        );
        staged("`vox serve` serving", || {
            after_label(
                &serve.expect_line("its address", |l| l.starts_with("address ")),
                "address",
            )
        });
        stops_cleanly(&mut serve, "`vox serve`", SERVE, *sig);
        stops += 1;
    }
    println!("[proof] {stops} of 32 stops were clean");
}
