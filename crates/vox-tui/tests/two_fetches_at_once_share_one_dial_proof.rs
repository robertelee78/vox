//! **Two reaches to one peer at once share one dial**, through the shipped binaries.
//!
//! **The defect.** `NodeNet::reach` races every rung, a circuit through each connected helper among
//! them. Two reaches to the same peer at once raced two circuits through the same relay, and the far
//! end keeps one circuit per peer: attaching the second closed the first, and whichever handshake
//! lost waited out its whole attempt, 10 s. Found on the v0.3.0 merge (#226), where RP-24's cold
//! relayed connections took 10.8 s instead of about 260 ms.
//!
//! **The scene, as people would make it.** A real `vox node` anchor; alice, a `vox daemon` on IPv4,
//! and bob, a `vox daemon` on IPv6, so the only path between them is a circuit through the anchor.
//! They trust each other and share a room, and alice offers a file (`vox room send`). Then, [`CYCLES`]
//! times: bob's daemon is restarted, and the moment it answers, **two `vox room get`s of that file
//! are started together**. Each asks bob's daemon for a forward to alice, and the daemon's own sync
//! reaches for her too: three reaches to one peer, none with a connection to reuse.
//!
//! What must hold, every cycle:
//! - **one dial**: bob's daemon ran exactly one reachability ladder to alice, read from its own
//!   `vox status --json` (`reach`, counted where a ladder starts dialling). Timing alone could not
//!   say it: a verifier's mutant that let a woken reach dial again after the first one finished
//!   kept every fetch fast and was green (#232);
//! - every fetch succeeds, each within [`FETCH_WITHIN`] — well under the 10 s a lost circuit
//!   handshake costs — and the anchor carried the circuits (the path was relayed).
//!
//! - **one circuit**: bob's daemon asked a relay for exactly one circuit to alice, counted in
//!   `circuitstream::connect_through`, which every outbound circuit goes through (`reach.circuits`).
//!   A ladder count alone missed a verifier's mutant that opened a second circuit outside the ladder
//!   (#232, mutant C).
//!
//! Each cycle's counts are read [`SETTLE`] after the fetches return and before the next restart
//! zeroes them, so a circuit opened late is counted too.
//!
//! A fetch past [`FETCH_WITHIN`] is **PRODUCT** only when it is still past the bound after taking
//! off what the runner itself stalled during it, measured on the same timeline by a thread that
//! sleeps 10 ms at a time; otherwise it is **CANNOT MEASURE**.
//!
//! Mutations: every reach runs its own ladder (the coalescing removed) — red, more than one ladder
//! and circuit; a woken reach dials again instead of taking the connection the first made — red,
//! two ladders; a woken reach opens a second circuit outside the ladder — red, two circuits; and
//! a woken reach opens that second circuit 1.5 s later — red, two circuits.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const ID_PASS: &str = "identity passphrase";
const ROOM_PASS: &str = "channel passphrase";
/// Restart-and-fetch cycles.
const CYCLES: usize = 5;
/// How long one fetch may take: a relayed fetch of the file, cold, is well under a second here; a
/// circuit handshake lost to a second circuit costs 10 s.
const FETCH_WITHIN: Duration = Duration::from_secs(5);
/// How long after both fetches return each cycle's counts are read: past any circuit a woken
/// reach might still open (the verifier's mutant D opened one 1.5 s on), and well before the next
/// restart.
const SETTLE: Duration = Duration::from_secs(4);

/// The runner's own stalls, on the proof's timeline: a thread that sleeps [`TICK`] at a time and
/// records how late each wake was. Time the runner lost is time no `vox` could have used either.
struct Stalls {
    late: Arc<Mutex<Vec<(Instant, Duration)>>>,
    stop: Arc<AtomicBool>,
}

const TICK: Duration = Duration::from_millis(10);

impl Stalls {
    fn start() -> Self {
        let late = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (l, s) = (Arc::clone(&late), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                let before = Instant::now();
                std::thread::sleep(TICK);
                let woke = Instant::now();
                let over = woke.duration_since(before).saturating_sub(TICK);
                if over > Duration::from_millis(2) {
                    if let Ok(mut v) = l.lock() {
                        v.push((woke, over));
                    }
                }
            }
        });
        Self { late, stop }
    }

    /// How long the runner stalled between `from` and `to`.
    fn within(&self, from: Instant, to: Instant) -> Duration {
        self.late
            .lock()
            .map(|v| {
                v.iter()
                    .filter(|(at, _)| *at >= from && *at <= to)
                    .map(|(_, d)| *d)
                    .sum()
            })
            .unwrap_or_default()
    }
}

impl Drop for Stalls {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

struct Running(Child, Arc<Mutex<String>>);

impl Running {
    fn said(&self) -> String {
        self.1.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn drain(stream: Option<impl std::io::Read + Send + 'static>, into: &Arc<Mutex<String>>) {
    let Some(mut stream) = stream else { return };
    let sink = Arc::clone(into);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if let Ok(mut s) = sink.lock() {
                        s.push_str(&String::from_utf8_lossy(&buf[..n]));
                    }
                }
            }
        }
    });
}

struct Agent {
    name: String,
    data: PathBuf,
    cfg: PathBuf,
    pass: PathBuf,
    listen: String,
    spec: String,
    daemon: Option<Running>,
}

impl Agent {
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(VOX);
        c.args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env_remove("VOX_ROOM");
        c
    }

    fn vox(&self, args: &[&str]) -> (bool, String, String) {
        let out = self
            .cmd(args)
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: could not run {VOX}: {e}"));
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn vox_with(&self, args: &[&str], stdin: &str) -> (bool, String, String) {
        let mut child = self
            .cmd(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: could not spawn {VOX}: {e}"));
        child
            .stdin
            .take()
            .expect("APPARATUS: the child's stdin was not piped")
            .write_all(stdin.as_bytes())
            .unwrap_or_else(|e| panic!("APPARATUS: could not write vox's stdin: {e}"));
        let out = child
            .wait_with_output()
            .unwrap_or_else(|e| panic!("APPARATUS: could not wait for vox: {e}"));
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn spawn(&self, args: &[&str]) -> Running {
        let mut child = self
            .cmd(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: could not spawn {VOX}: {e}"));
        let said = Arc::new(Mutex::new(String::new()));
        drain(child.stdout.take(), &said);
        drain(child.stderr.take(), &said);
        Running(child, said)
    }

    /// Start (or restart) this member's `vox daemon`, and return once it answers.
    fn start_daemon(&mut self) -> Instant {
        self.daemon = Some(
            self.spawn(&[
                "daemon",
                "--listen",
                &self.listen,
                "--anchor",
                &self.spec,
                "--passphrase-file",
                self.pass
                    .to_str()
                    .expect("APPARATUS: a non-UTF-8 temp path"),
            ]),
        );
        let started = Instant::now();
        while !self.vox(&["room", "list"]).0 {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "PRODUCT (staging): {}'s daemon never answered `vox room list` \
                 in {:?}; it said:\n{}",
                self.name,
                started.elapsed(),
                self.daemon.as_ref().map(Running::said).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        Instant::now()
    }
}

fn agent(tmp: &tempfile::TempDir, name: &str, listen: &str, spec: &str) -> Agent {
    let data = tmp.path().join(name).join("data");
    let cfg = tmp.path().join(name).join("cfg");
    std::fs::create_dir_all(&cfg)
        .unwrap_or_else(|e| panic!("APPARATUS: could not make {}: {e}", cfg.display()));
    let pass = tmp.path().join(format!("{name}.pass"));
    std::fs::write(&pass, ID_PASS)
        .unwrap_or_else(|e| panic!("APPARATUS: could not write {}: {e}", pass.display()));
    let mut a = Agent {
        name: name.to_owned(),
        data,
        cfg,
        pass,
        listen: listen.to_owned(),
        spec: spec.to_owned(),
        daemon: None,
    };
    let (ok, _, err) = a.vox(&[
        "id",
        "--identity-passphrase-file",
        &a.pass.to_string_lossy(),
    ]);
    assert!(ok, "PRODUCT (staging): {name}'s `vox id` failed: {err}");
    a.start_daemon();
    a
}

/// A real `vox node` anchor on the dual-stack wildcard, and its spec for an IPv4 and an IPv6 node.
fn anchor(tmp: &tempfile::TempDir) -> (Running, String, String) {
    let dir = tmp.path().join("anchor");
    std::fs::create_dir_all(dir.join("cfg"))
        .unwrap_or_else(|e| panic!("APPARATUS: could not make {}: {e}", dir.display()));
    let a = Agent {
        name: "anchor".into(),
        data: dir.join("data"),
        cfg: dir.join("cfg"),
        pass: PathBuf::new(),
        listen: String::new(),
        spec: String::new(),
        daemon: None,
    };
    let node = a.spawn(&["node", "--listen", "[::]:0"]);
    let deadline = Instant::now() + Duration::from_secs(60);
    let spec = loop {
        let said = node.said();
        if let Some(l) = said.lines().find(|l| {
            let t = l.trim_start();
            t.contains('@') && t.starts_with(|c: char| c.is_alphanumeric())
        }) {
            break l.trim().to_owned();
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): the anchor never printed its spec in 60 s:\n\
             {said}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let Some((fp, addr)) = spec.split_once('@') else {
        panic!("PRODUCT (staging): the anchor's spec is not `fingerprint@address`: {spec}");
    };
    let port = addr.rsplit('/').next().unwrap_or_default();
    (
        node,
        format!("{fp}@/ip4/127.0.0.1/udp/{port}"),
        format!("{fp}@/ip6/::1/udp/{port}"),
    )
}

/// The latest circuit count the anchor printed, or `None` if it printed no status line to read
/// one from — which is not zero circuits.
fn circuits(anchor: &Running) -> Option<usize> {
    anchor.said().lines().rev().find_map(|l| {
        let rest = l.split("vox node: ").nth(1)?;
        let (_, after) = rest.split_once(" peer(s) connected, ")?;
        after.split_whitespace().next()?.parse().ok()
    })
}

fn until(who: &Agent, what: &str, args: &[&str], ok: impl Fn(&str) -> bool) {
    let started = Instant::now();
    loop {
        let (_, out, err) = who.vox(args);
        if ok(&out) {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(90),
            "PRODUCT (staging): no {what} in {:?}; `vox {}` last said:\n\
             {out}{err}",
            started.elapsed(),
            args.join(" ")
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// One `vox room get`, into its own home so two at once do not write the same file.
fn fetch(
    bob: &Agent,
    room: &str,
    home: PathBuf,
) -> std::thread::JoinHandle<(bool, Instant, Duration, String)> {
    let mut c = bob.cmd(&["room", "get", room, "artifact.bin"]);
    std::fs::create_dir_all(&home)
        .unwrap_or_else(|e| panic!("APPARATUS: could not make {}: {e}", home.display()));
    c.env("HOME", &home).stdin(Stdio::null());
    std::thread::spawn(move || {
        let started = Instant::now();
        let out = c
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: could not run {VOX} room get: {e}"));
        (
            out.status.success(),
            started,
            started.elapsed(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    })
}

#[test]
#[ignore = "real binaries, production Argon2id and a PoW; CI runs it in release"]
fn two_fetches_at_once_share_one_dial() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: could not make a temporary directory");
    let source = tmp.path().join("artifact.bin");
    std::fs::write(&source, vec![7u8; 100_000])
        .unwrap_or_else(|e| panic!("APPARATUS: could not write {}: {e}", source.display()));

    let (anchor, v4, v6) = anchor(&tmp);
    let alice = agent(&tmp, "alice", "127.0.0.1:0", &v4);
    let mut bob = agent(&tmp, "bob", "[::1]:0", &v6);
    let fp = |a: &Agent| {
        let (ok, out, err) = a.vox(&["id"]);
        assert!(ok, "PRODUCT (staging): `vox id` failed: {err}");
        out.trim().to_owned()
    };
    let (alice_fp, bob_fp) = (fp(&alice), fp(&bob));
    for (who, peer, name) in [(&alice, &bob_fp, "bob"), (&bob, &alice_fp, "alice")] {
        let (ok, _, err) = who.vox(&[
            "trust",
            "add",
            peer,
            "--name",
            name,
            "--identity-passphrase-file",
            &who.pass.to_string_lossy(),
        ]);
        assert!(ok, "PRODUCT (staging): trusting {name} failed: {err}");
    }
    let (ok, _, err) = alice.vox_with(&["room", "create", "--name", "mission"], ROOM_PASS);
    assert!(ok, "PRODUCT (staging): `vox room create` failed: {err}");
    let (_, list, err) = alice.vox(&["room", "list"]);
    let Some(label) = list.split_whitespace().next().map(str::to_owned) else {
        panic!("PRODUCT (staging): `vox room list` names no room: {list}{err}");
    };
    let (ok, link, err) = alice.vox(&["room", "invite", &label]);
    assert!(ok, "PRODUCT (staging): `vox room invite` failed: {err}");
    let link = link.trim().to_owned();
    let Some(room) = link
        .strip_prefix("vox://")
        .and_then(|l| l.split('?').next())
        .map(str::to_owned)
    else {
        panic!("PRODUCT (staging): `vox room invite` printed no `vox://` link: {link}");
    };
    // One join, no retry: a join that fails is a defect in joining, which is not what this proves,
    // and retrying would hide it.
    let (ok, out, err) = bob.vox_with(&["room", "join", &link, "--name", "mission"], ROOM_PASS);
    assert!(
        ok,
        "PRODUCT (staging): bob's `vox room join` over the relay failed: \
         {out}{err}"
    );

    let _offer = alice.spawn(&["room", "send", &room, &source.to_string_lossy()]);
    until(
        &bob,
        "the offer to reach bob",
        &["room", "read", &room],
        |o| o.contains("artifact.bin"),
    );

    let mut slow: Vec<String> = Vec::new();
    let mut extra: Vec<String> = Vec::new();
    let mut extra_circuits: Vec<String> = Vec::new();
    let mut failed: Vec<String> = Vec::new();
    let mut left_listening: Vec<String> = Vec::new();
    let mut unmeasured: Vec<String> = Vec::new();
    let stalls = Stalls::start();
    for cycle in 0..CYCLES {
        // A fresh daemon for bob: no connection to alice to reuse.
        drop(bob.daemon.take());
        bob.start_daemon();
        let a = fetch(&bob, &room, tmp.path().join(format!("home-{cycle}-a")));
        let b = fetch(&bob, &room, tmp.path().join(format!("home-{cycle}-b")));
        for (which, h) in [("a", a), ("b", b)] {
            let (ok, started, took, said) = h
                .join()
                .unwrap_or_else(|_| panic!("APPARATUS: fetch {which}'s thread panicked"));
            let stalled = stalls.within(started, started + took);
            eprintln!(
                "[proof] cycle {cycle} fetch {which}: ok={ok} in {took:?} (runner stalled \
                 {stalled:?})"
            );
            // A fetch that fails is the claim failing, not the scene: a reach whose circuit another
            // reach closed waits out its attempt and gives up (red on the uncoalesced mutant, 10.24 s).
            if !ok {
                failed.push(format!(
                    "cycle {cycle} fetch {which} failed after {took:?}:\n{said}\n---- bob's daemon ----\n{}",
                    bob.daemon.as_ref().map(Running::said).unwrap_or_default()
                ));
            }
            // Past the bound even without the runner's own stalls: the product was slow.
            if took.saturating_sub(stalled) > FETCH_WITHIN {
                slow.push(format!(
                    "cycle {cycle} fetch {which}: {took:?} (runner stalled {stalled:?})"
                ));
            } else if took > FETCH_WITHIN {
                unmeasured.push(format!(
                    "cycle {cycle} fetch {which}: {took:?}, of which the runner stalled {stalled:?}"
                ));
            }
        }
        // Read after the dust settles and before the next restart zeroes the count: a second
        // circuit opened late — 1.5 s after the fetches, in the verifier's mutant D — was missed
        // by a read the moment they returned.
        std::thread::sleep(SETTLE);
        let (ok, json, err) = bob.vox(&["status", "--json"]);
        assert!(ok, "PRODUCT: bob's `vox status --json` failed: {err}");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_else(|e| {
            panic!("PRODUCT: bob's `vox status --json` is not JSON ({e}): {json}")
        });
        let row = v["reach"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|r| r["peer"].as_str() == Some(alice_fp.as_str()));
        // **Each get gets its own forward, and stops it** (#249). Two gets at once were each
        // answered with whichever forward bound first, so both used one and the other was never
        // stopped: bob's daemon went on listening on a port nothing would ever connect to (and,
        // when the first get stopped the shared one while the second was still connecting, the
        // second was refused). With both gets done, bob's daemon listens on no TCP port.
        let listening = tcp_listeners(
            bob.daemon
                .as_ref()
                .expect("APPARATUS: bob's daemon handle is gone")
                .0
                .id(),
        );
        eprintln!("[proof] cycle {cycle}: bob's daemon listens on {listening:?} after both gets");
        if !listening.is_empty() {
            left_listening.push(format!("cycle {cycle}: {listening:?}"));
        }
        // No row, or a row without the field, cannot say how many: it is not zero.
        let count = |field: &str| {
            row.and_then(|r| r[field].as_u64()).unwrap_or_else(|| {
                panic!(
                    "PRODUCT (staging): cycle {cycle}: bob's `vox status --json` has no `reach` \
                     `{field}` for alice, so nothing dialled her or the field is gone: {json}"
                )
            })
        };
        let (ladders, circuits) = (count("ladders"), count("circuits"));
        eprintln!(
            "[proof] cycle {cycle}: bob's daemon ran {ladders} ladder(s) and asked for {circuits} \
             circuit(s) to alice"
        );
        if circuits != 1 {
            extra_circuits.push(format!("cycle {cycle}: {circuits} circuits"));
        }
        assert!(
            ladders >= 1,
            "CANNOT MEASURE: cycle {cycle} ran no ladder to alice, so nothing dialled her: {json}"
        );
        if ladders != 1 {
            extra.push(format!("cycle {cycle}: {ladders} ladders"));
        }
    }
    let Some(carried) = circuits(&anchor) else {
        panic!(
            "PRODUCT (staging): the anchor printed no status line to read its circuits from:\n{}",
            anchor.said()
        );
    };
    eprintln!("[proof] the anchor reports {carried} circuit(s) carried");
    assert!(
        carried > 0,
        "CANNOT MEASURE: the anchor carried no circuit, so the path was not relayed"
    );
    assert!(
        left_listening.is_empty(),
        "PRODUCT: each get must be given its own forward and stop it — bob's daemon was left listening \
         after both gets were done:\n{}",
        left_listening.join("\n")
    );
    assert!(
        failed.is_empty(),
        "PRODUCT: fetches started together must all succeed — a reach lost its circuit to another reach to \
         the same peer:\n{}",
        failed.join("\n")
    );
    assert!(
        extra_circuits.is_empty(),
        "PRODUCT: reaches to alice started together must open one circuit to her, not one each: \
         {extra_circuits:?}"
    );
    assert!(
        extra.is_empty(),
        "PRODUCT: reaches to alice started together must share one dial, one ladder a cycle: {extra:?}"
    );
    assert!(
        slow.is_empty(),
        "PRODUCT: fetches started together took longer than {FETCH_WITHIN:?}, past the runner's \
         own stalls — a reach lost its circuit to another reach to the same peer: {slow:?}"
    );
    assert!(
        unmeasured.is_empty(),
        "CANNOT MEASURE: a fetch passed {FETCH_WITHIN:?} only by what the runner stalled during \
         it: {unmeasured:?}"
    );
}

/// The TCP ports `pid` is listening on, as `lsof` reports them: what a forward leaves behind.
///
/// `lsof` exits 1 both when the process has no such socket and when it cannot see the process at
/// all, so the process is first confirmed visible: an empty list from an `lsof` that could not look
/// would read as "nothing left listening".
fn tcp_listeners(pid: u32) -> Vec<String> {
    let seen = Command::new("lsof")
        .args(["-a", "-p", &pid.to_string(), "-d", "cwd", "-F", "p"])
        .output()
        .unwrap_or_else(|e| panic!("CANNOT MEASURE: could not run lsof: {e}"));
    assert!(
        String::from_utf8_lossy(&seen.stdout)
            .lines()
            .any(|l| l == format!("p{pid}")),
        "CANNOT MEASURE: lsof cannot see bob's daemon (pid {pid}), so it cannot say what it \
         listens on: exit {:?}: {}",
        seen.status.code(),
        String::from_utf8_lossy(&seen.stderr)
    );
    let out = Command::new("lsof")
        .args([
            "-a",
            "-p",
            &pid.to_string(),
            "-iTCP",
            "-sTCP:LISTEN",
            "-P",
            "-n",
            "-F",
            "n",
        ])
        .output()
        .unwrap_or_else(|e| panic!("CANNOT MEASURE: could not run lsof: {e}"));
    // 0: listeners listed; 1 with nothing on stderr: none. Anything else is lsof failing.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.code() == Some(0) || (out.status.code() == Some(1) && stderr.trim().is_empty()),
        "CANNOT MEASURE: lsof failed listing bob's daemon's TCP listeners: exit {:?}: {stderr}",
        out.status.code()
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.strip_prefix('n').map(str::to_owned))
        .collect()
}
