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
//! Mutations: every reach runs its own ladder (the coalescing removed) — red, more than one ladder
//! and circuit; a woken reach dials again instead of taking the connection the first made — red,
//! two ladders; a woken reach opens a second circuit outside the ladder — red, two circuits.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
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
            .expect("spawn vox");
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
            .expect("spawn vox");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
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
            .expect("spawn vox");
        let said = Arc::new(Mutex::new(String::new()));
        drain(child.stdout.take(), &said);
        drain(child.stderr.take(), &said);
        Running(child, said)
    }

    /// Start (or restart) this member's `vox daemon`, and return once it answers.
    fn start_daemon(&mut self) -> Instant {
        self.daemon = Some(self.spawn(&[
            "daemon",
            "--listen",
            &self.listen,
            "--anchor",
            &self.spec,
            "--passphrase-file",
            self.pass.to_str().unwrap(),
        ]));
        let deadline = Instant::now() + Duration::from_secs(60);
        while !self.vox(&["room", "list"]).0 {
            assert!(
                Instant::now() < deadline,
                "{}'s daemon never answered:\n{}",
                self.name,
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
    std::fs::create_dir_all(&cfg).unwrap();
    let pass = tmp.path().join(format!("{name}.pass"));
    std::fs::write(&pass, ID_PASS).unwrap();
    let mut a = Agent {
        name: name.to_owned(),
        data,
        cfg,
        pass,
        listen: listen.to_owned(),
        spec: spec.to_owned(),
        daemon: None,
    };
    let (ok, _, err) = a.vox(&["id", "--identity-passphrase-file", a.pass.to_str().unwrap()]);
    assert!(ok, "{name}: vox id: {err}");
    a.start_daemon();
    a
}

/// A real `vox node` anchor on the dual-stack wildcard, and its spec for an IPv4 and an IPv6 node.
fn anchor(tmp: &tempfile::TempDir) -> (Running, String, String) {
    let dir = tmp.path().join("anchor");
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
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
            "the anchor never printed its spec:\n{said}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let (fp, addr) = spec.split_once('@').expect("fp@addr");
    let port = addr.rsplit('/').next().expect("a port");
    (
        node,
        format!("{fp}@/ip4/127.0.0.1/udp/{port}"),
        format!("{fp}@/ip6/::1/udp/{port}"),
    )
}

/// The latest circuit count the anchor printed.
fn circuits(anchor: &Running) -> usize {
    anchor
        .said()
        .lines()
        .rev()
        .find_map(|l| {
            let rest = l.split("vox node: ").nth(1)?;
            let (_, after) = rest.split_once(" peer(s) connected, ")?;
            after.split_whitespace().next()?.parse().ok()
        })
        .unwrap_or(0)
}

fn until(who: &Agent, what: &str, args: &[&str], ok: impl Fn(&str) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let (_, out, _) = who.vox(args);
        if ok(&out) {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// One `vox room get`, into its own home so two at once do not write the same file.
fn fetch(
    bob: &Agent,
    room: &str,
    home: PathBuf,
) -> std::thread::JoinHandle<(bool, Duration, String)> {
    let mut c = bob.cmd(&["room", "get", room, "artifact.bin"]);
    std::fs::create_dir_all(&home).unwrap();
    c.env("HOME", &home).stdin(Stdio::null());
    std::thread::spawn(move || {
        let started = Instant::now();
        let out = c.output().expect("spawn vox room get");
        (
            out.status.success(),
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
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("artifact.bin");
    std::fs::write(&source, vec![7u8; 100_000]).unwrap();

    let (anchor, v4, v6) = anchor(&tmp);
    let alice = agent(&tmp, "alice", "127.0.0.1:0", &v4);
    let mut bob = agent(&tmp, "bob", "[::1]:0", &v6);
    let fp = |a: &Agent| {
        let (ok, out, err) = a.vox(&["id"]);
        assert!(ok, "vox id: {err}");
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
            who.pass.to_str().unwrap(),
        ]);
        assert!(ok, "trust {name}: {err}");
    }
    let (ok, _, err) = alice.vox_with(&["room", "create", "--name", "mission"], ROOM_PASS);
    assert!(ok, "vox room create: {err}");
    let label = alice
        .vox(&["room", "list"])
        .1
        .split_whitespace()
        .next()
        .expect("a room")
        .to_owned();
    let (ok, link, err) = alice.vox(&["room", "invite", &label]);
    assert!(ok, "vox room invite: {err}");
    let link = link.trim().to_owned();
    let room = link
        .strip_prefix("vox://")
        .and_then(|l| l.split('?').next())
        .expect("an invite link naming the room")
        .to_owned();
    let mut joined = false;
    for _ in 0..6 {
        if bob
            .vox_with(&["room", "join", &link, "--name", "mission"], ROOM_PASS)
            .0
        {
            joined = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(5));
    }
    assert!(joined, "CANNOT PROVE: bob never joined over the relay");

    let _offer = alice.spawn(&["room", "send", &room, source.to_str().unwrap()]);
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
    for cycle in 0..CYCLES {
        // A fresh daemon for bob: no connection to alice to reuse.
        drop(bob.daemon.take());
        bob.start_daemon();
        let a = fetch(&bob, &room, tmp.path().join(format!("home-{cycle}-a")));
        let b = fetch(&bob, &room, tmp.path().join(format!("home-{cycle}-b")));
        for (which, h) in [("a", a), ("b", b)] {
            let (ok, took, said) = h.join().unwrap();
            eprintln!("[proof] cycle {cycle} fetch {which}: ok={ok} in {took:?}");
            // A fetch that fails is the claim failing, not the scene: a reach whose circuit another
            // reach closed waits out its attempt and gives up (red on the uncoalesced mutant, 10.24 s).
            if !ok {
                failed.push(format!(
                    "cycle {cycle} fetch {which} failed after {took:?}:\n{said}\n---- bob's daemon ----\n{}",
                    bob.daemon.as_ref().map(Running::said).unwrap_or_default()
                ));
            }
            if took > FETCH_WITHIN {
                slow.push(format!("cycle {cycle} fetch {which}: {took:?}"));
            }
        }
        let (ok, json, err) = bob.vox(&["status", "--json"]);
        assert!(ok, "vox status --json: {err}");
        let v: serde_json::Value = serde_json::from_str(&json).expect("status JSON");
        let row = v["reach"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|r| r["peer"].as_str() == Some(alice_fp.as_str()));
        let ladders = row.and_then(|r| r["ladders"].as_u64()).unwrap_or(0);
        let circuits = row.and_then(|r| r["circuits"].as_u64()).unwrap_or(0);
        eprintln!(
            "[proof] cycle {cycle}: bob's daemon ran {ladders} ladder(s) and asked for {circuits} \
             circuit(s) to alice"
        );
        if circuits != 1 {
            extra_circuits.push(format!("cycle {cycle}: {circuits} circuits"));
        }
        assert!(
            ladders >= 1,
            "CANNOT PROVE: cycle {cycle} ran no ladder to alice, so nothing dialled her: {json}"
        );
        if ladders != 1 {
            extra.push(format!("cycle {cycle}: {ladders} ladders"));
        }
    }
    let carried = circuits(&anchor);
    eprintln!("[proof] the anchor reports {carried} circuit(s) carried");
    assert!(
        carried > 0,
        "CANNOT PROVE: the anchor carried no circuit, so the path was not relayed"
    );
    assert!(
        failed.is_empty(),
        "fetches started together must all succeed — a reach lost its circuit to another reach to \
         the same peer:\n{}",
        failed.join("\n")
    );
    assert!(
        extra_circuits.is_empty(),
        "reaches to alice started together must open one circuit to her, not one each: \
         {extra_circuits:?}"
    );
    assert!(
        extra.is_empty(),
        "reaches to alice started together must share one dial, one ladder a cycle: {extra:?}"
    );
    assert!(
        slow.is_empty(),
        "fetches started together took longer than {FETCH_WITHIN:?} — a reach lost its circuit to \
         another reach to the same peer: {slow:?}"
    );
}
