//! **A relay circuit carries a node that listens on an IPv6 socket**, driven through the shipped
//! binary.
//!
//! A circuit's address is a synthetic IPv4 address in the mux's table. On an IPv6 socket quinn
//! dials it as the IPv4-mapped `::ffff:a.b.c.d`, and records that as the connection's remote; the
//! mux handed the circuit's inbound datagrams up from the plain IPv4 address. A QUIC client
//! discards packets from any address but its recorded remote, so every handshake over a circuit
//! from a node bound to `[::1]` — or to the dual-stack `[::]` — timed out, and the relay rung was
//! dead for it: `circuit via <anchor>: … 251.x.y.z:1: direct attempt timed out`.
//!
//! **The only path is the circuit.** On loopback, split by address family with the product's own
//! `--listen`: the anchor on `[::]` (dual-stack), the host on `127.0.0.1` (an IPv4 socket), the
//! guest on `[::1]`. Each reaches the anchor; neither can send a datagram to the other — an IPv4
//! socket cannot address `::1`, and a socket bound to `::1` cannot send to `127.0.0.1` — so no
//! direct dial and no hole punch connects them. The gate asserts the product itself says the path
//! is relayed, so a split that stopped splitting cannot pass it.
//!
//! What must hold: the guest joins the host's room, and bytes cross a `vox forward` both ways; and
//! two members who reach each other only through the circuit, dialling each other at once, both
//! get through (`two_members_dialling_each_other_…`).
//!
//! `#[ignore]`d: production Argon2id and a real PoW. Run it in release.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use relay::{Anchor, RelayWorld, Split};
use world::round_trip;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";
const ROOMPASS: &str = "room passphrase";

#[test]
#[ignore = "production Argon2id + a real PoW, three real `vox` processes; run in release"]
fn a_guest_on_an_ipv6_socket_reaches_its_host_through_a_relay_circuit() {
    watchdog::arm();
    let mut w = RelayWorld::new(Split::Families);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "the guest on [::1] could not join its host through the relay (after {took:?}).\n\
         stdout:\n{out}\nstderr:\n{err}"
    );
    eprintln!(
        "[test] joined through the relay in {:.1}s",
        took.as_secs_f64()
    );
    let at = w.forward();
    let back =
        round_trip(at, b"across the circuit", Duration::from_secs(120)).unwrap_or_else(|e| {
            panic!(
                "no echo through the forward ({e}).\nforward:\n{}",
                w.fwd.as_mut().unwrap().transcript()
            )
        });
    assert_eq!(back, b"across the circuit", "bytes must cross unchanged");
    w.assert_relayed("after the echo");
    w.expect_still_relayed();
    eprintln!("[test] echo crossed the circuit, and the forward reports the path relayed");
}

/// **The control**: the same anchor, verbs and service with the split removed — host and guest
/// both on `127.0.0.1`. The pair goes direct: the anchor carries no circuit and the guest never
/// reports `still relayed`. Without this, the relayed proofs on this harness could be relayed for
/// some reason other than the split.
#[test]
#[ignore = "production Argon2id + a real PoW, three real `vox` processes; run in release"]
fn without_the_split_the_same_pair_goes_direct() {
    watchdog::arm();
    let mut w = RelayWorld::new(Split::None);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "the control guest could not join ({took:?}).\n{out}\n{err}"
    );
    let at = w.forward();
    let back = round_trip(at, b"direct", Duration::from_secs(120)).expect("echo in the control");
    assert_eq!(back, b"direct");
    let circuits = w.anchor_circuits(Duration::from_secs(10));
    let fwd = w.fwd.as_mut().unwrap().transcript();
    eprintln!("[test] control: the anchor reports {circuits} circuit(s) carried after the echo");
    assert_eq!(
        circuits, 0,
        "the control is relayed too, so the split is not what forces the relay"
    );
    assert!(
        !fwd.contains("still relayed"),
        "the control guest reports a relayed path:\n{fwd}"
    );
}

// ---- two members who dial each other through one relay at once (V210-80, #271) ----------------

/// How long each frozen stage of the crossing is held, so the process let run in it is done with
/// the one thing it has to do: the anchor sending each member the other's circuit, then each member
/// taking it.
const STAGE: Duration = Duration::from_millis(1500);
/// Each reads the other within this of the release.
const BOUND: Duration = Duration::from_secs(8);
/// How long after the release the reads are watched for, past the 10 s a lost dial waits out, so a
/// red says how late each read was, or that it never came.
const WATCH: Duration = Duration::from_secs(16);

fn vox(dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .env_remove("VOX_ROOM")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("CANNOT MEASURE: the harness could not spawn vox");
    if let Some(text) = stdin {
        let mut pipe = child
            .stdin
            .take()
            .expect("CANNOT MEASURE: the harness has no stdin pipe");
        pipe.write_all(text.as_bytes())
            .expect("CANNOT MEASURE: the harness could not write to stdin");
    }
    let out = child
        .wait_with_output()
        .expect("CANNOT MEASURE: the harness could not wait for vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn reads(dir: &std::path::Path, room: &str, text: &str) -> bool {
    vox(dir, &["room", "read", room], None).1.contains(text)
}

fn until(what: &str, secs: u64, ok: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    eprintln!("[proof] {what}: not within {secs} s");
    false
}

/// A daemon, killed by its own PID however the test ends, its output kept.
struct Daemon(Child, Arc<Mutex<String>>);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Daemon {
    fn said(&self) -> String {
        self.1.lock().unwrap().clone()
    }
}

fn daemon(dir: &std::path::Path, listen: &str, anchor: &str) -> Daemon {
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", listen, "--anchor", anchor])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("CANNOT MEASURE: the harness could not spawn a daemon");
    let mut pipe = child
        .stdin
        .take()
        .expect("CANNOT MEASURE: the harness has no stdin pipe");
    pipe.write_all(format!("{IDPASS}\n").as_bytes()).unwrap();
    drop(pipe);
    let said = Arc::new(Mutex::new(String::new()));
    for stream in [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let sink = Arc::clone(&said);
        let mut stream = stream;
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => sink
                        .lock()
                        .unwrap()
                        .push_str(&String::from_utf8_lossy(&buf[..n])),
                }
            }
        });
    }
    let d = Daemon(child, said);
    let deadline = Instant::now() + Duration::from_secs(90);
    while !d.1.lock().unwrap().contains("control socket") {
        assert!(
            Instant::now() < deadline,
            "PRODUCT: a `vox daemon` never served its control socket:\n{}",
            d.1.lock().unwrap()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    d
}

fn signal(pids: &[u32], sig: &str) {
    for pid in pids {
        let ok = Command::new("kill")
            .args([sig, &pid.to_string()])
            .status()
            .is_ok_and(|s| s.success());
        assert!(
            ok,
            "CANNOT MEASURE: the harness could not send {sig} to process {pid}"
        );
    }
}

/// Circuits `dir`'s node has asked a relay for to `peer` (`vox status --json` `reach.circuits`).
fn circuits_to(dir: &std::path::Path, peer: &str) -> u64 {
    let (ok, out, err) = vox(dir, &["status", "--json"], None);
    assert!(ok, "CANNOT MEASURE: vox status --json: {err}");
    let v: serde_json::Value = serde_json::from_str(out.trim())
        .unwrap_or_else(|e| panic!("CANNOT MEASURE: vox status --json is not JSON ({e}): {out}"));
    v["reach"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["peer"].as_str() == Some(peer))
        .and_then(|r| r["circuits"].as_u64())
        .unwrap_or(0)
}

/// What `d` said about `peer` from its `mark`th line on: every line naming the peer's short id.
fn about(d: &Daemon, mark: usize, peer: &str) -> Vec<String> {
    d.said()
        .lines()
        .skip(mark)
        .filter(|l| l.contains(&peer[..26]))
        .map(str::to_owned)
        .collect()
}

/// **Two members who dial each other through one relay at the same moment both get through**
/// (V210-80, #271): the same family split, between two members of a room.
///
/// A node's mux kept one circuit per peer, and attaching a circuit unmapped the one attached before
/// it to the same peer. Two live circuits to one peer are ordinary: a member dialling a peer through
/// a relay while that peer dials it back through the same relay, each end attaching one circuit for
/// the other's dial and one for its own. The second attach took the first one's address out of the
/// table, its packets went to the real socket and were lost, and a dial over it waited out its whole
/// 10 s: a first relayed connection took 10558 ms on CI (R42, run 36601388611), and the two members
/// did not read each other until then.
///
/// **Staging, forced on every run with no switch in the product.** bob listens on `127.0.0.1` and
/// carol on `[::1]`, so the anchor's circuit is their only path to each other. Both daemons are
/// restarted, so neither holds a connection to the other; `vox status --json` naming no circuit
/// between them is checked. Then the crossing is ordered with SIGSTOP/SIGCONT, so it does not rest
/// on which of two tasks the anchor happens to run first:
///
/// 1. The anchor is frozen, and bob and carol trust each other at once, which makes each dial the
///    other. The run waits until each has asked the relay for a circuit to the other (`vox status
///    --json`), or it is `CANNOT MEASURE`.
/// 2. bob and carol are frozen and the anchor runs: it hands each the other's circuit request,
///    which waits in the frozen member, and then waits for their answers.
/// 3. The anchor is frozen again and bob and carol run: each takes the other's circuit (one attach
///    each) and answers into the frozen anchor. Neither can yet hear that its own circuit is open.
/// 4. The anchor runs: each hears its own circuit is open and attaches it second.
///
/// So on both ends the far end's circuit is attached first and the member's own second, which is
/// the order in which unmapping the earlier circuit loses **both** dials. Left to the anchor, one
/// order in two lost only one dial, the other connected, and the members read each other anyway.
///
/// **Asserted, as the members see it:** each reads a post of the other's within [`BOUND`] of the
/// release. A `PRODUCT:` red is the product's verdict; `CANNOT MEASURE` is the staging not achieved.
///
/// **Mutation that must turn it red:** in `MuxSocket::attach`, remove the earlier circuit to the
/// same peer when a new one is attached (the code before V210-80).
#[test]
#[ignore = "three daemons and a relay anchor with production Argon2id; CI runs it in release"]
fn two_members_dialling_each_other_through_one_relay_both_get_through() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dirs: Vec<std::path::PathBuf> = ["alice", "bob", "carol"]
        .iter()
        .map(|n| tmp.path().join(n))
        .collect();
    for d in &dirs {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let (alice_dir, bob_dir, carol_dir) = (&dirs[0], &dirs[1], &dirs[2]);
    let anchor = Anchor::start(&tmp.path().join("anchor"));
    let mut fps = Vec::new();
    for d in &dirs {
        let (ok, out, err) = vox(d, &["id"], None);
        assert!(ok, "PRODUCT: vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    // alice and bob on IPv4, carol on IPv6: bob and carol reach each other only through the
    // anchor's relay.
    let carol_spec = Split::Families.guest_spec(&anchor).to_owned();
    let _alice = daemon(alice_dir, "127.0.0.1:0", &anchor.v4_spec);
    let bob = daemon(bob_dir, "127.0.0.1:0", &anchor.v4_spec);
    let carol = daemon(carol_dir, Split::Families.guest_listen(), &carol_spec);

    // alice's room; alice and each joiner trust each other. bob and carol do NOT, yet.
    for (i, name) in [(1usize, "bob"), (2, "carol")] {
        let (ok, _, err) = vox(alice_dir, &["trust", "add", &fps[i], "--name", name], None);
        assert!(ok, "PRODUCT: alice trusts {name}: {err}");
        let (ok, _, err) = vox(
            &dirs[i],
            &["trust", "add", &fps[0], "--name", "alice"],
            None,
        );
        assert!(ok, "PRODUCT: {name} trusts alice: {err}");
    }
    let (ok, _, err) = vox(
        alice_dir,
        &["room", "create", "--name", "crossed"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT: room create: {err}");
    let listed = vox(alice_dir, &["room", "list"], None).1;
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .expect("PRODUCT: no room id in `vox room list` after `room create`")
        .to_owned();
    let (ok, link, err) = vox(alice_dir, &["room", "invite", &room], None);
    assert!(ok, "PRODUCT: room invite: {err}");
    for d in [bob_dir, carol_dir] {
        let (ok, _, err) = vox(
            d,
            &["room", "join", link.trim(), "--name", "crossed"],
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(ok, "CANNOT MEASURE: a join failed: {err}");
    }

    // Fresh processes, so neither holds a connection to the other from the joins.
    drop(bob);
    drop(carol);
    let bob = daemon(bob_dir, "127.0.0.1:0", &anchor.v4_spec);
    let carol = daemon(carol_dir, Split::Families.guest_listen(), &carol_spec);
    assert!(
        until("bob and carol hold their room", 60, || {
            vox(bob_dir, &["room", "list"], None).1.contains(&room)
                && vox(carol_dir, &["room", "list"], None).1.contains(&room)
        }),
        "CANNOT MEASURE: a restarted daemon never listed the room"
    );

    // ---- precondition: neither has dialled the other ----
    let (bob_fp, carol_fp) = (fps[1].as_str(), fps[2].as_str());
    let before = (
        circuits_to(bob_dir, carol_fp),
        circuits_to(carol_dir, bob_fp),
    );
    assert!(
        before == (0, 0),
        "CANNOT MEASURE: bob and carol already asked for circuits to each other before the \
         freeze: {before:?}"
    );
    let marks = (bob.said().lines().count(), carol.said().lines().count());

    // ---- the crossing, in the order that loses both dials to the defect ----
    let anchor_pid = [anchor.proc.child.id()];
    let members = [bob.0.id(), carol.0.id()];
    signal(&anchor_pid, "-STOP");
    let frozen = Instant::now();
    let (asked, released, b, c) = std::thread::scope(|s| {
        // 1. Both dial; each request waits in the frozen anchor.
        let b = s.spawn(|| {
            vox(
                bob_dir,
                &["trust", "add", carol_fp, "--name", "carol"],
                None,
            )
        });
        let c = s.spawn(|| vox(carol_dir, &["trust", "add", bob_fp, "--name", "bob"], None));
        let asked = until(
            "bob and carol ask the frozen relay for each other",
            5,
            || {
                circuits_to(bob_dir, carol_fp) > before.0
                    && circuits_to(carol_dir, bob_fp) > before.1
            },
        );
        if asked {
            // 2. The anchor hands each member the other's circuit; both wait in the members.
            signal(&members, "-STOP");
            signal(&anchor_pid, "-CONT");
            std::thread::sleep(STAGE);
            // 3. Each member takes the other's circuit; its answer waits in the anchor.
            signal(&anchor_pid, "-STOP");
            signal(&members, "-CONT");
            std::thread::sleep(STAGE);
        }
        // 4. Each member hears its own circuit is open.
        signal(&anchor_pid, "-CONT");
        let released = Instant::now();
        (asked, released, b.join().unwrap(), c.join().unwrap())
    });
    assert!(
        asked,
        "CANNOT MEASURE: bob and carol did not both ask the frozen relay for a circuit to each \
         other within 5 s, so the crossing was not staged"
    );
    assert!(b.0, "PRODUCT: bob trusts carol: {}", b.2);
    assert!(c.0, "PRODUCT: carol trusts bob: {}", c.2);

    // ---- each reads the other ----
    let (mut bob_reads_carol, mut carol_reads_bob) = (None, None);
    let mut n = 0;
    while (bob_reads_carol.is_none() || carol_reads_bob.is_none()) && released.elapsed() < WATCH {
        let (ok, _, _) = vox(
            bob_dir,
            &["room", "post", &room, &format!("BOB-PROBE-{n:02}")],
            None,
        );
        assert!(ok, "PRODUCT: bob could not post to the room");
        let (ok, _, _) = vox(
            carol_dir,
            &["room", "post", &room, &format!("CAROL-PROBE-{n:02}")],
            None,
        );
        assert!(ok, "PRODUCT: carol could not post to the room");
        std::thread::sleep(Duration::from_millis(500));
        if carol_reads_bob.is_none() && reads(carol_dir, &room, "BOB-PROBE-") {
            carol_reads_bob = Some(released.elapsed());
        }
        if bob_reads_carol.is_none() && reads(bob_dir, &room, "CAROL-PROBE-") {
            bob_reads_carol = Some(released.elapsed());
        }
        n += 1;
    }
    let after = (
        circuits_to(bob_dir, carol_fp),
        circuits_to(carol_dir, bob_fp),
    );
    let (bob_said, carol_said) = (
        about(&bob, marks.0, carol_fp),
        about(&carol, marks.1, bob_fp),
    );
    eprintln!(
        "[proof] crossing staged over {:?}; circuits asked bob->carol {} carol->bob {}; bob reads \
         carol at {bob_reads_carol:?}, carol reads bob at {carol_reads_bob:?} after the release",
        released - frozen,
        after.0,
        after.1
    );
    for l in &bob_said {
        eprintln!("[proof] bob said: {l}");
    }
    for l in &carol_said {
        eprintln!("[proof] carol said: {l}");
    }

    // 1. The escalation: both dials went through the relay.
    assert!(
        after.0 > before.0 && after.1 > before.1,
        "CANNOT MEASURE: the dials did not cross: bob asked for {} circuit(s) to carol, carol {} \
         to bob",
        after.0,
        after.1
    );
    // 2. Each reads the other promptly.
    for (who, at) in [
        ("bob reads carol", bob_reads_carol),
        ("carol reads bob", carol_reads_bob),
    ] {
        assert!(
            at.is_some_and(|t| t < BOUND),
            "PRODUCT: {who} at {at:?} after the release, over {BOUND:?}: a dial between two members \
             crossing through one relay waited out its timeout\nbob said:\n{}\ncarol said:\n{}",
            bob_said.join("\n"),
            carol_said.join("\n")
        );
    }
}
