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
//! direct dial and no hole punch connects them. That is checked first, as a precondition
//! (`support/family_split.rs`), and the gate asserts the product itself says the path is relayed,
//! so a split that stopped splitting cannot pass it.
//!
//! What must hold: the guest joins the host's room, and bytes cross a `vox forward` both ways; and
//! two members who reach each other only through the circuit, dialling each other at once, both
//! get through (`two_members_dialling_each_other_…`).
//!
//! **RP-15 — two hosts behind symmetric NATs talk through the anchor**
//! (`two_hosts_behind_symmetric_nats_reach_a_service_through_the_anchor`). This is what an anchor
//! is for: bridging two hosts that cannot otherwise find each other. `support/nat.rs` puts a
//! **symmetric** NAT in userspace in front of each `vox` process (a new public port for every
//! destination, and an unsolicited datagram dropped), so the address the anchor observes is
//! useless to the peer and no hole punch can work: the only path is the anchor's relay. With the
//! shipped binary as a person runs it — `vox node`, `vox serve` on the host, `vox id`,
//! `vox trust add`, `vox connect` and `vox up` on the guest — the guest must join the host's room
//! and reach its service over SOCKS5 (`<room>.vox`), [`SYM_REQUESTS`] times, every byte through the
//! anchor and none peer to peer.
//! - A process that never used its NAT, or a single payload byte peer to peer, is `CANNOT
//!   MEASURE`: the emulator would not be what is being measured.
//! - The join failing is a PRODUCT red naming the relay path: behind symmetric NATs the relay is the
//!   only path, so a failed join is that path not being established.
//! - A request not answered, once the join has proved the relay up, is a PRODUCT red that names the
//!   failing side from what the request showed — a refused tunnel (the host or its tunnel), a broken
//!   SOCKS exchange (the guest's proxy) or a lost echo — and does not blame the anchor for it.
//! - **The mutation that must turn it red:** the anchor refuses to carry any circuit
//!   (`serve_circuit`'s open arm refuses). The guest cannot reach its host, and the join fails.
//!
//! **V210-143 — a guest that asks before the anchor holds the room still joins**
//! (`a_guest_that_arrives_before_the_anchor_holds_the_room_still_joins_through_the_relay`): with
//! the host's room kept off the anchor for its first seconds (the test-only
//! `VOX_TEST_HOLD_ROOM_FROM_ANCHORS_MS`), the guest says it is waiting for the room and joins
//! through the relay within the join's patience. **The mutation that must turn it red:** the join's
//! repeated search removed (`run_steps` gives up on the first search that finds the room on no
//! board).
//!
//! `#[ignore]`d: production Argon2id and a real PoW. Run it in release.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/relay.rs"]
mod relay;

#[path = "support/nat.rs"]
mod nat;

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[path = "support/family_split.rs"]
mod family_split;

use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nat::{Kind, TwoNats};
use relay::{Anchor, RelayWorld, Split};
use world::{after_label, args, echo_service, round_trip, vox_once, VoxProc};

/// How many requests the guest makes to the host's service behind the symmetric NATs.
const SYM_REQUESTS: usize = 3;
/// A request's echo payload.
const SYM_PAYLOAD: usize = 16 * 1024;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";
const ROOMPASS: &str = "room passphrase";

#[test]
#[ignore = "production Argon2id + a real PoW, three real `vox` processes; run in release"]
fn a_guest_on_an_ipv6_socket_reaches_its_host_through_a_relay_circuit() {
    watchdog::arm();
    family_split::assert_the_families_are_split();
    let mut w = RelayWorld::new(Split::Families);
    let (ok, took, out, err) = w.join_guest();
    assert!(
        ok,
        "PRODUCT: the guest on [::1] could not join its host through the relay (after {took:?}); \
         the joiner said:\n{err}\nstdout:\n{out}"
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

// ---- a guest that arrives before the anchor holds the room (V210-143) ----------------------------

/// How long the host keeps its room off the anchor: past the guest's arrival, and well inside the
/// join's 30 s patience once the host's publish backoff (1, 2, 4 s) has run.
const HOST_HOLD_MS: &str = "3000";

/// **A guest that asks before the anchor holds the room still joins** (V210-143).
///
/// A host publishes its room to its anchor moments after it starts; one whose first dial to the
/// anchor fails publishes a second or more later. A guest that arrived first found the anchor's
/// board empty, and its circuit to the host refused — an anchor carries circuits for a room's
/// pending joiners, which it knows only once it holds the room, and it refuses anyone else
/// uninformatively (`0x05`, "authenticator invalid"), as it must. `vox connect` then said "cannot
/// join" after half a second: red 1 of 2 on integrate e7194d02, where the host's first dial to the
/// anchor had failed.
///
/// Staged with the test-only `VOX_TEST_HOLD_ROOM_FROM_ANCHORS_MS`: the host's publish rounds to the
/// anchor fail for [`HOST_HOLD_MS`] and are retried on their backoff. The guest asks at once.
/// - The guest must say it is waiting for the room (`vox: waiting: …`), or the staging was not
///   achieved: CANNOT MEASURE.
/// - It must then join through the relay, within the join's patience: PRODUCT, quoting it.
///
/// **The mutation that must turn it red:** the join's repeated search removed, so a search that
/// finds the room on no board ends the join at once (the code before V210-143).
#[test]
#[ignore = "production Argon2id + a real PoW, three real `vox` processes; run in release"]
fn a_guest_that_arrives_before_the_anchor_holds_the_room_still_joins_through_the_relay() {
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_HOLD_ROOM_FROM_ANCHORS_MS"]);
    family_split::assert_the_families_are_split();
    let w = RelayWorld::new_with_host_env(
        Split::Families,
        &[("VOX_TEST_HOLD_ROOM_FROM_ANCHORS_MS", HOST_HOLD_MS)],
    );
    let (ok, took, out, err) = w.join_guest();
    let waited = err.lines().any(|l| l.starts_with("vox: waiting:"));
    eprintln!(
        "[test] the guest {} after {:.1}s; it said it was waiting for the room: {waited}",
        if ok { "joined" } else { "did not join" },
        took.as_secs_f64()
    );
    assert!(
        ok,
        "PRODUCT: a guest that asked before the anchor held the room could not join its host through \
         the relay (after {took:?}): the join must wait for the host to publish, within its \
         patience; the joiner said:\n{err}\nstdout:\n{out}"
    );
    assert!(
        waited,
        "CANNOT MEASURE (precondition unmet): the guest joined without saying it waited for the \
         room, so the anchor already held it and the moment V210-143 is about was not staged; the \
         joiner said:\n{err}"
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

/// What one request through `vox up` to the host's echo service came to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    /// The whole payload came back.
    Echoed,
    /// `vox up` answered the CONNECT with this non-zero SOCKS reply.
    Refused(u8),
    /// The tunnel opened (reply 0), but the payload did not come back whole.
    EchoLost,
    /// The SOCKS exchange with `vox up` did not complete: it closed, ran past the 90 s read
    /// timeout, or answered something that is not SOCKS5.
    ProxyBroke(String),
}

/// One request through `vox up` (`socks5h`, CONNECT by name) to the host's echo service. A local
/// socket that cannot even be opened is the harness's fault; anything `vox up` does once the
/// connection is up is reported as an [`Outcome`].
fn sym_request(proxy: SocketAddr, host: &str, port: u16, payload: &[u8]) -> Outcome {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(proxy).unwrap_or_else(|e| {
        panic!("CANNOT MEASURE (harness error): could not open a TCP connection to vox up at {proxy}: {e}")
    });
    let _ = s.set_read_timeout(Some(Duration::from_secs(90)));
    let io = |what: &str, e: std::io::Error| Outcome::ProxyBroke(format!("{what}: {e}"));
    if let Err(e) = s.write_all(&[0x05, 0x01, 0x00]) {
        return io("sending the SOCKS greeting", e);
    }
    let mut hello = [0u8; 2];
    if let Err(e) = s.read_exact(&mut hello) {
        return io("reading the SOCKS method", e);
    }
    if hello != [0x05, 0x00] {
        return Outcome::ProxyBroke(format!("method reply {hello:?}, not no-auth"));
    }
    let Ok(len) = u8::try_from(host.len()) else {
        panic!("CANNOT MEASURE (harness error): host name {host:?} is too long for SOCKS5");
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x03, len];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    if let Err(e) = s.write_all(&req) {
        return io("sending the CONNECT", e);
    }
    let mut head = [0u8; 4];
    if let Err(e) = s.read_exact(&mut head) {
        return io("reading the CONNECT reply", e);
    }
    if head[0] != 0x05 {
        return Outcome::ProxyBroke(format!("reply version {}", head[0]));
    }
    let skip = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        other => return Outcome::ProxyBroke(format!("reply address type {other}")),
    };
    let mut sink = vec![0u8; skip];
    if let Err(e) = s.read_exact(&mut sink) {
        return io("reading the bound address", e);
    }
    if head[1] != 0 {
        return Outcome::Refused(head[1]);
    }
    if s.write_all(payload).is_err() {
        return Outcome::EchoLost;
    }
    let mut back = vec![0u8; payload.len()];
    if s.read_exact(&mut back).is_ok() && back == payload {
        Outcome::Echoed
    } else {
        Outcome::EchoLost
    }
}

#[test]
#[ignore = "production Argon2id + a real PoW, two userspace NATs and four real `vox` processes; run in release"]
fn two_hosts_behind_symmetric_nats_reach_a_service_through_the_anchor() {
    test_knobs::require(&["VOX_TEST_ADVERTISE"]);
    watchdog::arm();
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("CANNOT MEASURE (harness error): no temp dir: {e}"));
    let (anchor_dir, host_dir, guest_dir) = (
        tmp.path().join("anchor"),
        tmp.path().join("host"),
        tmp.path().join("guest"),
    );
    for d in [&anchor_dir, &host_dir, &guest_dir] {
        std::fs::create_dir_all(d.join("cfg")).unwrap_or_else(|e| {
            panic!(
                "CANNOT MEASURE (harness error): could not make {}: {e}",
                d.display()
            )
        });
    }
    let anchor_port = UdpSocket::bind("[::]:0")
        .and_then(|s| s.local_addr())
        .unwrap_or_else(|e| panic!("CANNOT MEASURE (harness error): no free UDP port: {e}"))
        .port();
    let nats = TwoNats::start(Kind::Symmetric, anchor_port);
    let advertise = format!("{},{}", nats.anchor_for_host, nats.anchor_for_guest);
    let mut anchor = VoxProc::spawn_env(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", &format!("[::]:{anchor_port}")]),
        &[("VOX_TEST_ADVERTISE", advertise.as_str())],
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            !l.starts_with("! ")
                && l.trim_start().contains('@')
                && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
        })
        .trim()
        .to_owned();
    let Some((fp, _)) = spec.split_once('@') else {
        panic!("PRODUCT: vox node printed an --anchor spec with no fingerprint: {spec:?}");
    };
    let host_spec = format!("{fp}@/ip4/127.0.0.1/udp/{}", nats.anchor_for_host.port());
    let guest_spec = format!("{fp}@/ip6/::1/udp/{}", nats.anchor_for_guest.port());

    let (ok, guest_fp, err) = vox_once(&guest_dir, &args(&["id"]));
    assert!(ok, "CANNOT MEASURE: vox id (guest): {err}");
    let (ok, _, err) = vox_once(&host_dir, &args(&["id"]));
    assert!(ok, "CANNOT MEASURE: vox id (host): {err}");
    let (ok, out, err) = vox_once(
        &host_dir,
        &args(&["trust", "add", guest_fp.trim(), "--name", "the guest"]),
    );
    assert!(ok, "CANNOT MEASURE: trust add: {out}\n{err}");
    let service_port = echo_service();
    let mut host = VoxProc::spawn(
        "host",
        &host_dir,
        &args(&[
            "serve",
            &service_port.to_string(),
            "--anchor",
            &host_spec,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    let room = after_label(
        &host.expect_line("room", |l| l.starts_with("room ")),
        "room",
    );
    let address = after_label(
        &host.expect_line("address", |l| l.starts_with("address ")),
        "address",
    );
    let passphrase = after_label(
        &host.expect_line("passphrase", |l| l.starts_with("passphrase ")),
        "passphrase",
    );
    let pass_file = world::room_pass_file(&guest_dir, &passphrase);
    let (joined, out, err) = vox_once(
        &guest_dir,
        &args(&[
            "connect",
            &address,
            "--passphrase-file",
            &pass_file,
            "--anchor",
            &guest_spec,
            "--listen",
            "[::1]:0",
        ]),
    );
    let (host_maps, guest_maps) = nats.mappings();
    eprintln!(
        "[proof] symmetric NATs: guest joined {joined}; NAT mappings host {host_maps}, guest \
         {guest_maps}; unsolicited peer datagrams dropped {}",
        nats.p2p_filtered()
    );
    assert!(
        host_maps > 0 && guest_maps > 0,
        "CANNOT MEASURE: a process never sent through its NAT (host {host_maps}, guest \
         {guest_maps} mappings), so the NATs are not in the path"
    );
    // Behind symmetric NATs the anchor's relay is the only path, so a join that fails is the
    // relay path not being established between them.
    assert!(
        joined,
        "PRODUCT: behind symmetric NATs the guest could not join its host's room — the anchor's \
         relay, the only path between them, was not established.\nstdout:\n{out}\nstderr:\n\
         {err}\nhost:\n{}",
        host.transcript()
    );

    let mut up = VoxProc::spawn(
        "up",
        &guest_dir,
        &args(&[
            "up",
            &room,
            "--passphrase-file",
            &pass_file,
            "--bind",
            "127.0.0.1:0",
            "--anchor",
            &guest_spec,
            "--listen",
            "[::1]:0",
        ]),
    );
    let line = up.expect_line("the proxy's bound address", |l| l.starts_with("vox up on "));
    let proxy: SocketAddr = line
        .split_whitespace()
        .nth(3)
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| panic!("PRODUCT: vox up printed no bound address: {line:?}"));
    let payload: Vec<u8> = (0..SYM_PAYLOAD).map(|i| (i % 251) as u8).collect();
    let hostname = format!("{room}.vox");
    let outcomes: Vec<Outcome> = (0..SYM_REQUESTS)
        .map(|_| sym_request(proxy, &hostname, service_port, &payload))
        .collect();
    let answered = outcomes.iter().filter(|o| **o == Outcome::Echoed).count();
    let p2p = nats.p2p_to_host() + nats.p2p_to_guest();
    eprintln!(
        "[proof] symmetric NATs: {answered}/{SYM_REQUESTS} requests to the host's service \
         answered ({outcomes:?}); peer to peer {p2p} B; unsolicited peer datagrams dropped {}",
        nats.p2p_filtered()
    );
    assert!(
        p2p == 0,
        "CANNOT MEASURE: behind symmetric NATs the pair moved {p2p} B peer to peer — a path leaks \
         around the emulator, so the anchor was not the only path"
    );
    // A shortfall says only what the requests showed. The join ran over its own circuit, so it
    // says nothing about vox up's path; the reason for a failure is in vox up's own transcript.
    let mut seen: Vec<String> = Vec::new();
    for o in &outcomes {
        let what = match o {
            Outcome::Echoed => continue,
            Outcome::Refused(2) => "vox up answered SOCKS reply 2 (not allowed): the host refused \
                                   the tunnel, or vox up knows no room by that name"
                .to_string(),
            Outcome::Refused(n) => format!("vox up answered SOCKS reply {n}"),
            Outcome::EchoLost => {
                "the CONNECT succeeded, but the echo did not come back whole".into()
            }
            Outcome::ProxyBroke(why) => format!("the SOCKS exchange did not complete ({why})"),
        };
        if !seen.contains(&what) {
            seen.push(what);
        }
    }
    assert_eq!(
        answered,
        SYM_REQUESTS,
        "PRODUCT: behind symmetric NATs {answered} of {SYM_REQUESTS} requests reached the host's \
         service — {}. vox up's transcript below names the reason ({outcomes:?}).\nup:\n{}",
        seen.join("; "),
        up.transcript()
    );
}
