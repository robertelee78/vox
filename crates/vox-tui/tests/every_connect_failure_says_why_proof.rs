//! V210-85 / #277 — **every way `vox connect` ends without joining says why**, driven through the
//! shipped binary.
//!
//! Found in the relayed-restart proof: a guest's `vox connect` ended non-zero after 92.5 s with an
//! empty stdout and an empty stderr. The transcript shows what that was: the test's watchdog had
//! reached its 600 s budget and SIGKILLed every `vox` it started, the connect mid-join among them,
//! and the harness kept only `status.success()`, so a kill read exactly like a verb that failed and
//! said nothing. That connect was not stuck — its sibling trials joined in 36.8–61.0 s, and the
//! same join measured here spent **108.7 s in its own proof-of-work solve** in a debug build on a
//! loaded machine (`join got in — … solve 108.73s …`). But it could not have said so: a `vox
//! connect` stopped by Ctrl-C, a SIGTERM or a hangup died on the signal's default action, silently,
//! and one whose `Joined` event was lost from the lossy event stream waited for it for good.
//!
//! What must hold. The joins go through the anchor's circuit (the host on IPv4, the guest on
//! `[::1]`, so the circuit is the only path — see `support/relay.rs`):
//!
//! 1. **Stopped mid-join by SIGTERM, SIGINT, SIGHUP or SIGQUIT**: exit status 143, 130, 129 or
//!    131 — not death by the signal — and stderr says `stopped by <SIGNAL> after …s`, that the room
//!    was not joined, and the join step it was waiting in, which names the host it waited on. **And
//!    it ends when it says so**, within [`STOPS_WITHIN`] of the signal: the first version printed
//!    its reason at once and then lived on in a debug build until the proof of work it had
//!    abandoned finished, past 15 s. SIGHUP is what a closed terminal or a dropped ssh session
//!    sends; with stderr kept in a log it was the original symptom exactly. **And its peers are
//!    told**: the connect closes its connections before it exits, so the anchor counts it gone
//!    within [`CLOSED_WITHIN`] of the signal — a stop that just exited left the anchor and the host
//!    counting it until their idle timeout.
//! 2. **A join its host never answers** (left to run out): exit status 1, and the reason names the
//!    host and the step that did not complete — the join exchange. The exchange's timeout used to
//!    name nobody: the join ended on advice about members that could not be reached, for one that
//!    had been reached and then went quiet.
//! 3. **Refused** (a wrong room passphrase, checked by the live host): exit status 1, `cannot join:
//!    …`, the refusal, and the steps. The refusal is the host's own answer over the circuit, so it
//!    is also the control: this world's joins reach the host and are answered.
//! 4. **The host gone** (SIGKILLed): exit status 1, `cannot join: …`, and the join's steps with the
//!    one that failed — the host's dial — and how long each took.
//! 5. **Stopped at a passphrase prompt** — the room passphrase's, or the identity's — on a
//!    terminal: SIGTERM gives 143 and SIGHUP 129, each naming the prompt it waited at, and the
//!    terminal is handed back with echo and line editing on, not in the prompt's raw mode. Ctrl-C
//!    typed at the prompt ends with a status and `cancelled`. The prompts ran before the signal
//!    handler was taken, so a stop there died on the signal and said nothing.
//!
//! 6. **An anchor stopped by SIGQUIT** (`Ctrl-\`): the stop helper `vox connect` shares with the
//!    long-running verbs takes SIGQUIT as a clean stop for all of them, so `vox node` must end with
//!    status 0, not a core dump, say `stopped by SIGQUIT` and that it is shutting down, and a forward
//!    through it must say its anchor connection is gone within [`CLOSED_WITHIN`] — its close, not
//!    the seconds of silence a vanished anchor takes to be noticed.
//! 7. **An anchor stopped by SIGHUP** (its terminal closed, its ssh session gone): `vox node` ends
//!    with status 0, not death by the signal, and says `stopped by SIGHUP` and that it is shutting
//!    down.
//!
//! In every one, stderr is non-empty and the exit is a status, never a signal. Each prints its
//! counts.
//!
//! **Staging without a race.** Cases 1 and 2 need a join that is still waiting on its host when it
//! is stopped. The first version SIGSTOPped the host once the guest's pre-join record reached the
//! board — and the anchor shows that on a 500 ms tick, so under load the join had sometimes been
//! answered before the host stopped, the join succeeded, and the proof called it a product red.
//! Here the host runs with `VOX_TEST_JOIN_UNANSWERED` (inert unset): it takes every join exchange
//! and never answers, so no join into it can get in, however late the stop lands. Each stop uses a
//! guest of its own, so each announce shows on the board as one more pending joiner (`1m/<k>p`),
//! and the stop is sent after that. Case 5 waits for the prompt itself on the pty: the handlers are
//! taken before the prompt is shown, so nothing about when the signal lands is left to timing.
//!
//! **Mutations that must turn it red:** the verb runner printing nothing for an error; `vox
//! connect` not taking one of the four signals (that case dies by the signal); the prompts run
//! before the handler is taken (case 5 dies by the signal); SIGQUIT or SIGHUP not taken (cases 1,
//! 6 and 7 die by it); a stop that exits without closing (case 1's anchor counts the connect until
//! its idle timeout); the terminal not handed back (case 5, still raw); the joiner not announcing
//! its steps (case 1 names no join step); the exchange's timeout naming nobody (case 2); a stop
//! that waits for the runtime's blocking work (case 1 outlives [`STOPS_WITHIN`] in a debug build,
//! where the solve is long).
//!
//! `#[ignore]`d: production Argon2id and a real PoW. Run it in release.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use relay::{RelayWorld, Split};
use world::{args, round_trip, vox_once, VoxProc, VOX};

/// A `vox connect` that fails on its own must have ended by then: past the board's 30 s patience,
/// a dial's timeout and a proof of work, with room for a loaded machine.
const FAILS_WITHIN: Duration = Duration::from_secs(300);

/// A `vox connect` sent a signal must have ended, and said so, by then — whatever it was doing, a
/// proof of work included.
const STOPS_WITHIN: Duration = Duration::from_secs(10);

/// How long the join is left waiting on its host before it is stopped: past its announce, into
/// the dial and the exchange with a host that never answers, and well inside the 30 s the exchange
/// waits for a frame, so the stop lands mid-join and not after a failure of its own.
const LEFT_WAITING: Duration = Duration::from_secs(2);

/// How long a `vox connect` may take to show a passphrase prompt on its terminal.
const PROMPTS_WITHIN: Duration = Duration::from_secs(60);

/// How soon after a stop signal its peers must count a stopped process gone: a forward through a
/// stopped anchor says so on its next 1 s tick, an anchor whose joiner stopped on its next 500 ms
/// status tick. The close arrives at once; short of the 8 s any inference from silence needs.
const CLOSED_WITHIN: Duration = Duration::from_secs(3);

/// What a node says when its anchor connection goes.
const GONE: &str = "the connection to this anchor is gone";

/// The build profile, named in every count line.
const PROFILE: &str = if cfg!(debug_assertions) {
    "debug"
} else {
    "release"
};

/// The steps a join announces as it begins them, as `vox connect` names them when it is stopped.
const JOIN_STEPS: [&str; 8] = [
    "reaching a board",
    "reading the room from board ",
    "announcing this joiner to board ",
    "waiting for member ",
    "dialling member ",
    "the join exchange with member ",
    "sealing the room key",
    "making the room here",
];

/// The join's steps that wait on one member, and name it.
const MEMBER_STEPS: [&str; 3] = [
    "waiting for member ",
    "dialling member ",
    "the join exchange with member ",
];

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

    /// The step stderr says it had waited in: what follows `it had waited <n>s for `.
    fn waited(&self) -> &str {
        self.stderr
            .split("it had waited ")
            .nth(1)
            .and_then(|l| l.lines().next())
            .and_then(|l| l.split_once(" for "))
            .map(|(_, step)| step)
            .unwrap_or_default()
    }
}

/// A new guest profile under `w`'s temp dir, with an identity of its own.
fn new_guest(w: &RelayWorld, k: usize) -> PathBuf {
    let dir = w.tmp.path().join(format!("guest-{k}"));
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    let (ok, _, err) = vox_once(&dir, &args(&["id"]));
    assert!(ok, "vox id (guest {k}): {err}");
    dir
}

/// Start `guest`'s `vox connect` with `passphrase`, on `[::1]` through the anchor's IPv6 name.
fn start_connect(w: &RelayWorld, guest: &Path, passphrase: &str) -> (VoxProc, Instant) {
    let file = guest.join("connect-passphrase");
    std::fs::write(&file, passphrase).unwrap();
    let proc = VoxProc::spawn(
        "connect",
        guest,
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
    let ok = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "kill {sig} {pid}");
}

/// Wait until the anchor's board holds the host's room with its one member. The host prints its
/// address before it has published there, and a join before that fails on its own, before it ever
/// waits on the host.
fn until_published(w: &mut RelayWorld) {
    let held = format!("board — {} 1m", &w.room[..12]);
    w.anchor.proc.expect_within(
        Duration::from_secs(240),
        "the host's room, with its member, on the anchor's board",
        |l| l.contains(&held),
    );
}

/// Wait until the anchor's board holds `k` pre-join records for the room: the `k`-th guest has
/// unlocked, reached the board and announced itself, so its join is past its own machine and
/// waiting on the host. Every guest is a new identity, so each announce is one more.
fn until_announced(w: &mut RelayWorld, k: usize) {
    let pending = format!("board — {} 1m/{k}p", &w.room[..12]);
    w.anchor.proc.expect_within(
        Duration::from_secs(240),
        &format!("guest {k}'s pre-join record on the anchor's board"),
        |l| l.contains(&pending),
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

/// What every stop must say: how long it ran, that the room was not joined, and what it waited for.
fn assert_says_stopped(e: &Ended, case: &str, name: &str) {
    for want in [
        format!("stopped by {name} after "),
        "the room was not joined".to_owned(),
        "it had waited ".to_owned(),
    ] {
        assert!(
            e.stderr.contains(&want),
            "{case}: stderr does not say {want:?} — it must say how long it ran, that the room \
             was not joined, and the step it was waiting in.\n{}",
            e.describe()
        );
    }
}

/// Case 1: guest `k` stopped by `sig` while its join waits on a host that never answers.
fn stopped_mid_join(w: &mut RelayWorld, k: usize, sig: &str, name: &str, code: i32) {
    let guest = new_guest(w, k);
    let (mut connect, t0) = start_connect(w, &guest, &w.passphrase.clone());
    until_announced(w, k);
    std::thread::sleep(LEFT_WAITING);
    if let Ok(Some(status)) = connect.child.try_wait() {
        panic!(
            "CANNOT MEASURE ({name}): the join ended ({status}) before it could be stopped mid-way.\n{}",
            connect.transcript()
        );
    }
    let case = format!("stopped by {name}");
    let before = w.anchor.proc.transcript();
    let peers = before
        .lines()
        .rev()
        .find_map(peers_connected)
        .unwrap_or_else(|| {
            panic!(
                "CANNOT MEASURE ({name}): the anchor never said how many peers it has.\n{before}"
            )
        });
    signal(connect.child.id(), sig);
    let sent = Instant::now();
    // Timed as it happens, both of them: when the connect exits, and when the anchor's count of
    // connected peers drops by the one that went. Watched well past the bound, so a red says how
    // long it did take.
    let (mut exited, mut gone) = (None, None);
    while sent.elapsed() < CLOSED_WITHIN + Duration::from_secs(30) && gone.is_none() {
        if exited.is_none() && connect.child.try_wait().ok().flatten().is_some() {
            exited = Some(sent.elapsed());
        }
        if let Ok(line) = w.anchor.proc.lines.recv_timeout(Duration::from_millis(20)) {
            if peers_connected(&line).is_some_and(|n| n < peers) {
                gone = Some(sent.elapsed());
            }
            w.anchor.proc.seen.push(line);
        }
    }
    let e = finish(connect, t0, STOPS_WITHIN);
    eprintln!(
        "[proof] ({PROFILE}) {name}: status {} {:.1}s after the signal, {:.1}s after the start; \
         the anchor counted it gone {gone:?} after the signal",
        e.status,
        exited.unwrap_or_else(|| sent.elapsed()).as_secs_f64(),
        e.took.as_secs_f64()
    );
    assert_said_why(&e, &case, code);
    assert_says_stopped(&e, &case, name);
    // Past its announce the join waits on the host — to be dialled, or to answer the exchange —
    // and the host never answers, so the step is one of the join's own that waits on a member,
    // never the verb's fallback ("the node to take the join"), and the member is the host.
    let waited = e.waited();
    let step = JOIN_STEPS
        .iter()
        .find(|s| waited.starts_with(*s))
        .unwrap_or_else(|| {
            panic!(
                "{case}: the step it waited in, {waited:?}, is not one of the join's own steps.\n{}",
                e.describe()
            )
        });
    assert!(
        MEMBER_STEPS.contains(step),
        "{case}: it waited in {waited:?}, but a join past its announce into a host that never \
         answers waits on that host.\n{}",
        e.describe()
    );
    let host12 = &w.host_fp[..12];
    assert!(
        waited.starts_with(&format!("{step}{host12}")),
        "{case}: it waited on a member, but not the host {host12}.\n{}",
        e.describe()
    );
    eprintln!("[proof] ({PROFILE}) {name}: stopped in the step {step:?} on the host");
    let gone = gone.unwrap_or_else(|| {
        panic!(
            "{case}: the anchor still counted {peers} peers {:?} after the signal — the connect \
             did not close its connection to it.\n---- the anchor ----\n{}",
            CLOSED_WITHIN + Duration::from_secs(30),
            w.anchor.proc.transcript()
        )
    });
    assert!(
        gone < CLOSED_WITHIN,
        "{case}: the anchor counted the connect gone only {gone:?} after the signal, over \
         {CLOSED_WITHIN:?} — not a close, the silence of one that never came.\n---- the anchor \
         ----\n{}",
        w.anchor.proc.transcript()
    );
}

/// The number of peers `vox node` says it has connected, from its status line.
fn peers_connected(line: &str) -> Option<usize> {
    line.strip_prefix("vox node: ")?
        .split_once(" peer(s) connected")?
        .0
        .parse()
        .ok()
}

/// Cases 2–4: a join that fails on its own.
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
fn a_connect_stopped_by_a_signal_or_never_answered_says_why() {
    watchdog::arm();
    let mut w = RelayWorld::with_host_env(Split::Families, &[("VOX_TEST_JOIN_UNANSWERED", "1")]);
    until_published(&mut w);
    let stops = [
        ("-TERM", "SIGTERM", 143),
        ("-INT", "SIGINT", 130),
        ("-HUP", "SIGHUP", 129),
        ("-QUIT", "SIGQUIT", 131),
    ];
    for (k, (sig, name, code)) in stops.iter().enumerate() {
        stopped_mid_join(&mut w, k + 1, sig, name, *code);
    }

    // Left to run out on the host that never answers.
    let host12 = w.host_fp[..12].to_owned();
    let guest = new_guest(&w, stops.len() + 1);
    let (connect, t0) = start_connect(&w, &guest, &w.passphrase.clone());
    let e = finish(connect, t0, FAILS_WITHIN);
    let exchange = format!("{host12}: exchange (incl. solve) ");
    failed_join(&e, "never answered", &[&exchange]);
    let reason = e
        .stderr
        .lines()
        .find(|l| l.starts_with("vox: cannot join: "))
        .unwrap_or_default();
    assert!(
        reason.contains(&host12),
        "never answered: the reason does not name the host {host12}, the member the join waited \
         on.\n{}",
        e.describe()
    );
    eprintln!(
        "[proof] ({PROFILE}) never answered: status {} in {:.1}s, the reason names the host",
        e.status,
        e.took.as_secs_f64()
    );
    eprintln!(
        "[proof] ({PROFILE}) {}/{} failures said why (SIGTERM, SIGINT, SIGHUP, SIGQUIT, never \
         answered)",
        stops.len() + 1,
        stops.len() + 1
    );
}

#[test]
#[ignore = "production Argon2id + a real PoW, a relayed world of real `vox` processes; run in release"]
fn a_refused_connect_and_one_without_its_host_say_why() {
    watchdog::arm();
    let mut w = RelayWorld::new(Split::Families);
    let host12 = w.host_fp[..12].to_owned();
    until_published(&mut w);

    let guest = w.guest_dir.clone();
    let (c, t0) = start_connect(&w, &guest, "not-the-room-passphrase");
    let e = finish(c, t0, FAILS_WITHIN);
    // The host checks the passphrase only after the joiner's proof of work, and gives up on a solve
    // that outlasts its patience: in a debug build on a loaded machine the solve alone has taken
    // 185 s. Then the passphrase was never checked, and the refusal cannot be measured — the
    // product still said why, which `failed_join` holds it to either way.
    if !e.stderr.contains("refused") && e.stderr.contains(": the join exchange: ") {
        failed_join(
            &e,
            "refused (a wrong passphrase)",
            &[": exchange (incl. solve) "],
        );
        panic!(
            "CANNOT MEASURE (refused): the host gave up on the join exchange before it checked the \
             passphrase — the proof of work outlasted its patience.\n{}",
            e.describe()
        );
    }
    failed_join(&e, "refused (a wrong passphrase)", &["refused"]);
    eprintln!(
        "[proof] ({PROFILE}) refused: status {} in {:.1}s",
        e.status,
        e.took.as_secs_f64()
    );

    let host = w.host.take().expect("a host");
    let pid = host.child.id();
    drop(host);
    eprintln!("[test] host pid {pid} killed and reaped");
    let (c, t0) = start_connect(&w, &guest, &w.passphrase.clone());
    let e = finish(c, t0, FAILS_WITHIN);
    let dial = format!("{host12}: dial");
    failed_join(&e, "the host gone", &[&dial]);
    eprintln!(
        "[proof] ({PROFILE}) host gone: status {} in {:.1}s",
        e.status,
        e.took.as_secs_f64()
    );
    eprintln!("[proof] ({PROFILE}) 2/2 failures said why (refused, the host gone)");
}

/// A `vox connect` on a terminal of its own: stdin and stdout on a pty, stderr on a pipe.
struct OnTerminal {
    child: Child,
    /// The pty's other end, kept to read the terminal's modes after the connect has ended.
    terminal: std::os::fd::OwnedFd,
    /// Everything the connect drew on its terminal, read as it arrives: a process that exits with
    /// output nobody has read cannot finish exiting on macOS.
    shown: Arc<Mutex<Vec<u8>>>,
    /// The pty's controlling side, to type on.
    keys: std::fs::File,
    stderr: mpsc::Receiver<String>,
    t0: Instant,
}

impl OnTerminal {
    /// `vox connect` for `profile`, with no identity passphrase in its environment, and the room
    /// passphrase from `room_file` or else prompted for.
    fn start(profile: &Path, room_file: Option<&Path>) -> Self {
        use rustix::pty::{grantpt, openpt, ptsname, unlockpt, OpenptFlags};
        let controller = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("openpt");
        grantpt(&controller).expect("grantpt");
        unlockpt(&controller).expect("unlockpt");
        let name = ptsname(&controller, Vec::new()).expect("ptsname");
        let open = || {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(name.to_str().expect("a pty name"))
                .expect("open the pty")
        };
        let terminal: std::os::fd::OwnedFd = open().into();
        // Nothing reads this address before both prompts are answered: the stop lands first.
        let mut a = vec![
            "connect".to_owned(),
            "vox://not-read-before-the-prompts".to_owned(),
        ];
        if let Some(f) = room_file {
            a.push("--passphrase-file".to_owned());
            a.push(f.to_str().unwrap().to_owned());
        }
        let mut child = Command::new(VOX)
            .args(&a)
            .env("VOX_DATA_DIR", profile)
            .env("VOX_CONFIG_DIR", profile.join("cfg"))
            .env_remove("VOX_IDENTITY_PASSPHRASE")
            .env_remove("VOX_ROOM_PASSPHRASE")
            .stdin(Stdio::from(open()))
            .stdout(Stdio::from(open()))
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn vox connect on a pty");
        let t0 = Instant::now();
        let mut screen = std::fs::File::from(controller);
        let keys = screen.try_clone().expect("the pty, to type on");
        let shown = Arc::new(Mutex::new(Vec::new()));
        let into = Arc::clone(&shown);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = screen.read(&mut buf) {
                if n == 0 {
                    break;
                }
                into.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        let (tx, stderr) = mpsc::channel();
        let err = child.stderr.take().expect("stderr");
        std::thread::spawn(move || {
            use std::io::BufRead;
            for line in std::io::BufReader::new(err).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            terminal,
            shown,
            keys,
            stderr,
            t0,
        }
    }

    /// Wait until the connect shows `prompt` on its terminal.
    fn until_prompted(&mut self, prompt: &str) {
        let deadline = Instant::now() + PROMPTS_WITHIN;
        loop {
            let shown = String::from_utf8_lossy(&self.shown.lock().unwrap()).into_owned();
            if shown.contains(prompt) {
                return;
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!(
                    "CANNOT MEASURE: `vox connect` ended ({status}) before it showed {prompt:?}. \
                     Its terminal:\n{shown}\n--- stderr:\n{}",
                    self.stderr.try_iter().collect::<Vec<_>>().join("\n")
                );
            }
            assert!(
                Instant::now() < deadline,
                "`vox connect` did not show {prompt:?} within {PROMPTS_WITHIN:?}. Its terminal:\n{shown}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Read what it says on stderr until the pipe closes, and reap it; panics past [`STOPS_WITHIN`].
    fn finish(mut self) -> (Ended, rustix::termios::Termios) {
        let deadline = Instant::now() + STOPS_WITHIN;
        let mut stderr = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "`vox connect` had not ended {STOPS_WITHIN:?} after it was due to. It said:\n{}",
                stderr.join("\n")
            );
            match self.stderr.recv_timeout(left.min(Duration::from_secs(1))) {
                Ok(line) => stderr.push(line),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        let status = self.child.wait().expect("reap vox connect");
        let modes = rustix::termios::tcgetattr(&self.terminal).expect("the terminal's modes");
        let ended = Ended {
            status,
            took: self.t0.elapsed(),
            stdout: String::from_utf8_lossy(&self.shown.lock().unwrap()).into_owned(),
            stderr: stderr.join("\n"),
        };
        eprintln!(
            "[connect] {}",
            ended.describe().replace('\n', "\n[connect] ")
        );
        (ended, modes)
    }
}

impl Drop for OnTerminal {
    fn drop(&mut self) {
        // By its own PID, and reaped.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The terminal a stopped prompt hands back must echo and edit lines again.
fn assert_terminal_handed_back(modes: &rustix::termios::Termios, case: &str, e: &Ended) {
    use rustix::termios::LocalModes;
    assert!(
        modes
            .local_modes
            .contains(LocalModes::ECHO | LocalModes::ICANON),
        "{case}: the terminal was left without echo or line editing (local modes {:?}) — the \
         prompt's raw mode, handed back to the shell.\n{}",
        modes.local_modes,
        e.describe()
    );
}

/// Case 5: stopped at a prompt by `sig`, it says so, names the prompt, and hands the terminal back.
fn stopped_at_prompt(
    profile: &Path,
    room_file: Option<&Path>,
    prompt: &str,
    stop: (&str, &str, i32),
    waited_for: &str,
) {
    let (sig, name, code) = stop;
    let mut c = OnTerminal::start(profile, room_file);
    c.until_prompted(prompt);
    signal(c.child.id(), sig);
    let (e, modes) = c.finish();
    let case = format!("{name} at the {prompt:?} prompt");
    assert_said_why(&e, &case, code);
    assert_says_stopped(&e, &case, name);
    assert_eq!(
        e.waited(),
        waited_for,
        "{case}: it does not say it had waited for {waited_for:?}.\n{}",
        e.describe()
    );
    assert_terminal_handed_back(&modes, &case, &e);
    eprintln!(
        "[proof] ({PROFILE}) {case}: status {}, waited for {waited_for:?}, terminal handed back",
        e.status
    );
}

#[test]
#[ignore = "production Argon2id for the profile's identity; run in release"]
fn a_connect_stopped_at_a_passphrase_prompt_says_why() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let profile = tmp.path().join("guest");
    std::fs::create_dir_all(profile.join("cfg")).unwrap();
    let (ok, _, err) = vox_once(&profile, &args(&["id"]));
    assert!(ok, "vox id: {err}");
    let room_file = tmp.path().join("room-passphrase");
    std::fs::write(&room_file, "a room passphrase").unwrap();

    stopped_at_prompt(
        &profile,
        None,
        "room passphrase: ",
        ("-TERM", "SIGTERM", 143),
        "the room passphrase",
    );
    stopped_at_prompt(
        &profile,
        Some(&room_file),
        "identity passphrase: ",
        ("-HUP", "SIGHUP", 129),
        "this profile's identity passphrase",
    );

    // Ctrl-C typed at the prompt is a key on a raw terminal, not a signal: the prompt's own "no".
    let mut c = OnTerminal::start(&profile, Some(&room_file));
    c.until_prompted("identity passphrase: ");
    std::io::Write::write_all(&mut c.keys, b"\x03").expect("type Ctrl-C");
    let (e, modes) = c.finish();
    let case = "Ctrl-C at the identity passphrase prompt";
    assert_said_why(&e, case, 1);
    assert!(
        e.stderr.contains("cancelled"),
        "{case}: stderr does not say it was cancelled.\n{}",
        e.describe()
    );
    assert_terminal_handed_back(&modes, case, &e);
    eprintln!(
        "[proof] ({PROFILE}) {case}: status {}, said it was cancelled",
        e.status
    );
    eprintln!("[proof] ({PROFILE}) 3/3 stops at a prompt said why (SIGTERM, SIGHUP, Ctrl-C)");
}

#[test]
#[ignore = "production Argon2id + a real PoW, a relayed world of real `vox` processes; run in release"]
fn an_anchor_stopped_by_sigquit_stops_cleanly_and_is_noticed() {
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
        "CANNOT MEASURE: no echo through the forward before the anchor was stopped: {first:?}\n{}",
        w.fwd.as_mut().unwrap().transcript()
    );
    // Long enough that the forward holds its anchor connection and its circuit.
    std::thread::sleep(Duration::from_secs(4).saturating_sub(started.elapsed()));
    let fwd = w.fwd.as_mut().unwrap();
    assert!(
        !fwd.transcript().contains(GONE),
        "CANNOT MEASURE: the forward said its anchor went before it was stopped\n{}",
        fwd.transcript()
    );

    let stopped = Instant::now();
    signal(w.anchor.proc.child.id(), "-QUIT");
    let status = loop {
        if let Some(status) = w.anchor.proc.child.try_wait().ok().flatten() {
            break status;
        }
        assert!(
            stopped.elapsed() < STOPS_WITHIN,
            "`vox node` had not ended {STOPS_WITHIN:?} after SIGQUIT.\n{}",
            w.anchor.proc.transcript()
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let exited = stopped.elapsed();
    let said = w.anchor.proc.transcript();
    eprintln!("[proof] ({PROFILE}) SIGQUIT to the anchor: {status} after {exited:?}");
    assert_eq!(
        status.signal(),
        None,
        "`vox node` died by SIGQUIT (a core dump) instead of stopping.\n{said}"
    );
    assert_eq!(
        status.code(),
        Some(0),
        "`vox node` stopped by SIGQUIT: exit status\n{said}"
    );
    for want in ["vox node: stopped by SIGQUIT", "vox node: shutting down"] {
        assert!(
            said.lines().any(|l| l == want),
            "`vox node` stopped by SIGQUIT does not say {want:?}.\n{said}"
        );
    }

    // Watched well past the bound, so a red prints how long it did take.
    let fwd = w.fwd.as_mut().unwrap();
    let mut gone = None;
    while stopped.elapsed() < CLOSED_WITHIN + Duration::from_secs(30) {
        let _ = fwd.transcript();
        gone = fwd
            .said_since(stopped)
            .into_iter()
            .find(|l| l.starts_with("[+") && l.contains(GONE));
        if gone.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let after = gone.as_deref().and_then(|l| {
        l.strip_prefix("[+")?
            .split_once("s]")?
            .0
            .parse::<f64>()
            .ok()
            .map(Duration::from_secs_f64)
    });
    eprintln!(
        "[proof] ({PROFILE}) SIGQUIT: the forward said its anchor connection went {after:?} after \
         the signal (bound {CLOSED_WITHIN:?}): {gone:?}"
    );
    let transcript = fwd.transcript();
    let after = after.unwrap_or_else(|| {
        panic!(
            "the forward never said its anchor connection went ({GONE:?}) within {:?} of \
             SIGQUIT\n---- the forward ----\n{transcript}",
            CLOSED_WITHIN + Duration::from_secs(30)
        )
    });
    assert!(
        after < CLOSED_WITHIN,
        "the forward said its anchor connection went only {after:?} after SIGQUIT, over \
         {CLOSED_WITHIN:?}\n---- the forward ----\n{transcript}"
    );
}

#[test]
#[ignore = "real `vox` processes; run in release"]
fn an_anchor_stopped_by_sighup_stops_cleanly() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("anchor");
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    let mut anchor = VoxProc::spawn("anchor", &dir, &args(&["node", "--listen", "127.0.0.1:0"]));
    anchor.expect_line("an --anchor spec", |l| {
        !l.starts_with("! ")
            && l.trim_start().contains('@')
            && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
    });
    let stopped = Instant::now();
    signal(anchor.child.id(), "-HUP");
    let status = loop {
        if let Some(status) = anchor.child.try_wait().ok().flatten() {
            break status;
        }
        assert!(
            stopped.elapsed() < STOPS_WITHIN,
            "`vox node` had not ended {STOPS_WITHIN:?} after SIGHUP.\n{}",
            anchor.transcript()
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let said = anchor.transcript();
    eprintln!(
        "[proof] ({PROFILE}) SIGHUP to the anchor: {status} after {:?}",
        stopped.elapsed()
    );
    assert_eq!(
        status.signal(),
        None,
        "`vox node` died by SIGHUP instead of stopping.\n{said}"
    );
    assert_eq!(
        status.code(),
        Some(0),
        "`vox node` stopped by SIGHUP: exit status\n{said}"
    );
    for want in ["vox node: stopped by SIGHUP", "vox node: shutting down"] {
        assert!(
            said.lines().any(|l| l == want),
            "`vox node` stopped by SIGHUP does not say {want:?}.\n{said}"
        );
    }
}
