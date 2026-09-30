//! A stranger holding every one of a member's join slots must not keep a real joiner out
//! (V210-92, #286).
//!
//! **The defect.** A member answers joins in 16 slots, first come first served, and a join past
//! them is refused. A slot is taken before the joiner has done any work, and held while the member
//! waits for the joiner's proof of work — 480s and more since V210-87, so that a slow device gets
//! in. A stranger who opens 16 joins and never finishes them therefore kept everybody else from
//! joining through that member for as long as it cared to: every real join was refused
//! `already answering 16 joins`.
//!
//! **What this drives, with real binaries.** An anchor (`vox node`); alice (`vox id`,
//! `vox daemon`, `vox room create`, `vox room invite`), the member; carol (`vox id`, `vox daemon`,
//! `vox room join`), the real joiner; and the stranger's own `vox daemon`s, which run
//! `vox room join` against alice's rooms with `VOX_TEST_SOLVE_AT_LEAST_MS` set to an hour — the
//! product's test-only floor on a joiner's own grind (V210-87), inert when unset. A join that
//! grinds for an hour is a join that never finishes, which is what a stranger's join is, and it
//! is staged with nothing but the shipped binary. One daemon holds many slots by joining many rooms
//! at once. Everything is on 127.0.0.1, so every join here comes from **one address**: the
//! stranger's and carol's alike.
//!
//! 1. `one_identity_holding_every_slot_does_not_keep_a_joiner_out`: one stranger identity joins 16
//!    of alice's rooms at once, then keeps joining a 17th, over and over, for as long as carol's
//!    join runs.
//! 2. `a_handful_of_identities_holding_every_slot_do_not_keep_a_joiner_out`: four stranger
//!    identities join 4 rooms each, and one of them keeps joining a 5th.
//!
//! **The precondition**, before carol joins, read from alice's own stderr: the cap was reached
//! with only the stranger's joins in flight — alice refused one of them (`already answering 16
//! joins`) or ended one for another (`ended …`). Not seen within [`FILL_PATIENCE`] is CANNOT
//! MEASURE, never green.
//!
//! **What is asserted.** Carol's one `vox room join` of a room the stranger is also joining, while
//! every slot is held and the stranger keeps arriving, succeeds within [`JOIN_BOUND`] — hard-coded,
//! 90s in release. The member demands more work while 16 joins are in flight (two more bits, four
//! times the solves), so this is the time of a join through a member under a flood, not through an
//! idle one; measured 3–20s. The unoptimized build grinds far slower (V210-87 measured 22–194s at
//! the base difficulty), so in debug the bound is the proof's watchdog, and what is asserted is
//! that carol gets in at all.
//!
//! **The mutation that must turn it red.** `JoinSlots::take` refusing every newcomer once the cap
//! is reached (first come, first served, as before): carol is refused `already answering 16 joins`
//! and her join fails, in both cases.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "identity passphrase";
const ROOM_PASS: &str = "channel passphrase";

/// A member's join slots, as this proof expects them.
const SLOTS: usize = 16;
/// The stranger's grind: an hour, far past anything this proof waits for.
const NEVER_MS: u64 = 3_600_000;
/// How long the stranger's joins may take to fill every slot of alice's.
const FILL_PATIENCE: Duration = Duration::from_secs(120);
/// Carol's whole `vox room join` while every slot is held; see the header for debug.
const JOIN_BOUND: Duration = if cfg!(debug_assertions) {
    Duration::from_secs(420)
} else {
    Duration::from_secs(90)
};
/// How long a stranger's churning join may take to be turned away before it counts as holding.
const ARRIVAL: Duration = Duration::from_secs(10);
/// How long a daemon may take to answer after it starts (production Argon2id unlock).
const START_PATIENCE: Duration = Duration::from_secs(240);

fn profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

/// A child process killed and reaped when dropped, by its own handle.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Who {
    data: PathBuf,
    cfg: PathBuf,
    pass: PathBuf,
}

impl Who {
    fn new(tmp: &Path, name: &str) -> Self {
        let w = Who {
            data: tmp.join(name).join("data"),
            cfg: tmp.join(name).join("cfg"),
            pass: tmp.join(format!("{name}.pass")),
        };
        std::fs::create_dir_all(&w.cfg).unwrap();
        std::fs::write(&w.pass, IDENTITY).unwrap();
        w
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(VOX);
        cmd.args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
            .env_remove("VOX_ROOM")
            .env_remove("VOX_SESSION");
        cmd
    }

    /// `vox …` as this profile, with `input` on stdin; `(ok, stdout, stderr)`.
    fn vox(&self, args: &[&str], input: Option<&str>) -> (bool, String, String) {
        let mut child = self
            .command(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn vox");
        if let Some(text) = input {
            let mut pipe = child.stdin.take().unwrap();
            pipe.write_all(text.as_bytes()).unwrap();
        }
        let out = child.wait_with_output().expect("vox ran");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// `vox room join <link>` left running: a stranger's join, which never finishes.
    fn join_in_background(&self, link: &str, name: &str) -> Proc {
        let mut child = self
            .command(&["room", "join", link, "--name", name])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vox room join");
        let mut pipe = child.stdin.take().unwrap();
        pipe.write_all(ROOM_PASS.as_bytes()).unwrap();
        drop(pipe);
        Proc(child)
    }

    /// `vox daemon` for this profile, stderr to `err`, answering on its socket before this returns.
    fn daemon(&self, anchor: &str, err: &Path, env: &[(&str, String)]) -> Proc {
        let mut cmd = Command::new(VOX);
        cmd.args(["daemon", "--listen", "127.0.0.1:0", "--anchor", anchor])
            .arg("--passphrase-file")
            .arg(&self.pass)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(err).unwrap()));
        for (k, v) in env {
            cmd.env(k, v);
        }
        let proc = Proc(cmd.spawn().expect("spawn vox daemon"));
        let started = Instant::now();
        while !self.vox(&["room", "list"], None).0 {
            assert!(
                started.elapsed() < START_PATIENCE,
                "CANNOT MEASURE: a daemon never answered; its stderr:\n{}",
                std::fs::read_to_string(err).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(500));
        }
        proc
    }
}

struct Staged {
    _anchor: Proc,
    _daemons: Vec<Proc>,
    carol: Who,
    strangers: Vec<Who>,
    alice_err: PathBuf,
    /// One invite link per room of alice's.
    links: Vec<String>,
}

/// An anchor; alice's daemon with `rooms` rooms; carol's daemon; and `strangers` stranger daemons,
/// each grinding for an hour on any join.
fn stage(tmp: &Path, rooms: usize, strangers: usize) -> Staged {
    let anchor_who = Who::new(tmp, "anchor");
    let out = tmp.join("anchor.out");
    let anchor = Proc(
        Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &anchor_who.data)
            .env("VOX_CONFIG_DIR", &anchor_who.cfg)
            .stdout(Stdio::from(std::fs::File::create(&out).unwrap()))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vox node"),
    );
    let started = Instant::now();
    let spec = loop {
        let text = std::fs::read_to_string(&out).unwrap_or_default();
        if let Some(s) = text
            .split_whitespace()
            .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        {
            break s.to_owned();
        }
        assert!(
            started.elapsed() < START_PATIENCE,
            "CANNOT MEASURE: the anchor never printed its spec"
        );
        std::thread::sleep(Duration::from_millis(250));
    };

    let alice = Who::new(tmp, "alice");
    let carol = Who::new(tmp, "carol");
    let strangers: Vec<Who> = (0..strangers)
        .map(|i| Who::new(tmp, &format!("stranger{i}")))
        .collect();
    let alice_err = tmp.join("alice.daemon.err");
    // Every identity, then every daemon, at once: each unlock is production Argon2id.
    let everyone: Vec<&Who> = [&alice, &carol].into_iter().chain(&strangers).collect();
    let daemons = std::thread::scope(|sc| {
        let ids: Vec<_> = everyone
            .iter()
            .map(|&w| sc.spawn(move || w.vox(&["id"], None)))
            .collect();
        for id in ids {
            let (ok, out, err) = id.join().unwrap();
            assert!(ok, "CANNOT MEASURE: vox id failed: {out}{err}");
        }
        let (spec, alice_err) = (&spec, &alice_err);
        let (alice, carol) = (&alice, &carol);
        let mut running = vec![
            sc.spawn(move || alice.daemon(spec, alice_err, &[])),
            sc.spawn(move || carol.daemon(spec, &tmp.join("carol.daemon.err"), &[])),
        ];
        for (i, s) in strangers.iter().enumerate() {
            running.push(sc.spawn(move || {
                s.daemon(
                    spec,
                    &tmp.join(format!("stranger{i}.daemon.err")),
                    &[("VOX_TEST_SOLVE_AT_LEAST_MS", NEVER_MS.to_string())],
                )
            }));
        }
        running
            .into_iter()
            .map(|d| d.join().unwrap())
            .collect::<Vec<_>>()
    });
    drop(everyone);

    let mut links = Vec::new();
    for r in 0..rooms {
        let name = format!("r{r}");
        let (ok, out, err) = alice.vox(&["room", "create", "--name", &name], Some(ROOM_PASS));
        assert!(ok, "CANNOT MEASURE: room create failed: {out}{err}");
        let list = alice.vox(&["room", "list"], None).1;
        let id = list
            .lines()
            .find(|l| l.split_whitespace().any(|w| w == name))
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or_else(|| panic!("CANNOT MEASURE: room {name} not in `vox room list`: {list}"))
            .to_owned();
        let link = alice
            .vox(&["room", "invite", &id], None)
            .1
            .trim()
            .to_owned();
        assert!(
            !link.is_empty(),
            "CANNOT MEASURE: no invite link for room {name}"
        );
        links.push(link);
    }
    eprintln!(
        "[proof] {} staged: {rooms} rooms on alice, {} stranger identities, in {:.1}s",
        profile(),
        strangers.len(),
        started.elapsed().as_secs_f64()
    );
    Staged {
        _anchor: anchor,
        _daemons: daemons,
        carol,
        strangers,
        alice_err,
        links,
    }
}

/// Alice's stderr: `(joins refused at the cap, joins ended for another)`.
fn alice_counts(s: &Staged) -> (usize, usize, String) {
    let text = std::fs::read_to_string(&s.alice_err).unwrap_or_default();
    let refused = text
        .matches(&format!("already answering {SLOTS} joins"))
        .count();
    let ended = text.lines().filter(|l| l.contains("— ended ")).count();
    (refused, ended, text)
}

/// Fill alice's slots with `holds` (stranger, room) joins, then keep `churner` joining `churn_room`
/// until carol's join is done; assert carol gets in.
fn run(s: &Staged, holds: &[(usize, usize)], churner: usize, churn_room: usize, case: &str) {
    let mut held: Vec<Proc> = holds
        .iter()
        .map(|&(who, room)| {
            s.strangers[who].join_in_background(&s.links[room], &format!("s{room}"))
        })
        .collect();

    let done = AtomicBool::new(false);
    let churned = AtomicUsize::new(0);
    // A churning join that did not come back within `ARRIVAL` is holding a slot: kept, and killed
    // with the rest at the end.
    let kept = std::sync::Mutex::new(Vec::<Proc>::new());
    let rooms: Vec<usize> = holds
        .iter()
        .filter(|&&(who, _)| who == churner)
        .map(|&(_, room)| room)
        .chain([churn_room])
        .collect();
    std::thread::scope(|sc| {
        // The stranger keeps arriving, before and during carol's join: each of its joins is one
        // more that wants a slot. It goes round its rooms, so a room whose join alice ended or
        // refused is joined again.
        sc.spawn(|| {
            for &room in rooms.iter().cycle() {
                if done.load(Ordering::SeqCst) {
                    break;
                }
                let mut join = s.strangers[churner].join_in_background(&s.links[room], "churn");
                let sent = Instant::now();
                while join.0.try_wait().ok().flatten().is_none() && sent.elapsed() < ARRIVAL {
                    std::thread::sleep(Duration::from_millis(100));
                }
                if join.0.try_wait().ok().flatten().is_none() {
                    kept.lock().unwrap().push(join);
                }
                churned.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(200));
            }
        });

        let filling = Instant::now();
        let (refused, ended) = loop {
            let (refused, ended, _) = alice_counts(s);
            if refused + ended > 0 {
                break (refused, ended);
            }
            if filling.elapsed() >= FILL_PATIENCE {
                done.store(true, Ordering::SeqCst);
                let (_, _, text) = alice_counts(s);
                panic!(
                    "CANNOT MEASURE: the stranger's {} joins never filled alice's {SLOTS} slots \
                     in {}s; alice's stderr:\n{text}",
                    holds.len(),
                    FILL_PATIENCE.as_secs()
                );
            }
            std::thread::sleep(Duration::from_millis(250));
        };
        eprintln!(
            "[proof] {} {case}: every slot held by the stranger after {:.1}s ({} joins, {refused} \
             refused at the cap, {ended} ended)",
            profile(),
            filling.elapsed().as_secs_f64(),
            holds.len()
        );

        let t = Instant::now();
        let (ok, out, err) = s.carol.vox(
            &["room", "join", &s.links[0], "--name", "real"],
            Some(ROOM_PASS),
        );
        let took = t.elapsed();
        done.store(true, Ordering::SeqCst);
        let (refused, ended, text) = alice_counts(s);
        let alice_ended: Vec<&str> = text.lines().filter(|l| l.contains("— ended ")).collect();
        eprintln!(
            "[proof] {} {case}: carol's join {} in {:.1}s (bound {}s); the stranger joined {} more \
             times; alice refused {refused} at the cap and ended {ended}: {alice_ended:?}",
            profile(),
            if ok { "got in" } else { "was refused" },
            took.as_secs_f64(),
            JOIN_BOUND.as_secs(),
            churned.load(Ordering::SeqCst)
        );
        assert!(
            ok,
            "{case}: carol was kept out while a stranger held every join slot, after {:.1}s\n  \
             carol: {out}{err}\n  alice's stderr:\n{text}",
            took.as_secs_f64()
        );
        assert!(
            took < JOIN_BOUND,
            "{case}: carol got in, but only after {:.1}s, past {}s\n  alice's stderr:\n{text}",
            took.as_secs_f64(),
            JOIN_BOUND.as_secs()
        );
    });
    held.clear();
    kept.lock().unwrap().clear();
    eprintln!("[proof] {} {case}: 1/1 got in", profile());
}

#[test]
#[ignore = "sixteen joins that never finish, production Argon2id and a real anchor; CI runs it in release"]
fn one_identity_holding_every_slot_does_not_keep_a_joiner_out() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    // Rooms 0–15 are held; room 16 is the one the stranger keeps arriving for.
    let s = stage(tmp.path(), SLOTS + 1, 1);
    let holds: Vec<(usize, usize)> = (0..SLOTS).map(|room| (0, room)).collect();
    run(&s, &holds, 0, SLOTS, "one identity");
}

#[test]
#[ignore = "sixteen joins that never finish, production Argon2id and a real anchor; CI runs it in release"]
fn a_handful_of_identities_holding_every_slot_do_not_keep_a_joiner_out() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    // Four identities hold four rooms each; room 4 is the one the first keeps arriving for.
    let s = stage(tmp.path(), 5, 4);
    let holds: Vec<(usize, usize)> = (0..4)
        .flat_map(|who| (0..4).map(move |room| (who, room)))
        .collect();
    run(&s, &holds, 0, 4, "four identities");
}
