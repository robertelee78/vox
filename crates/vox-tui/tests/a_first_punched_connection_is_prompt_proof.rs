//! PRD-001 **R42, punch** (RP-23) — **a first hole-punched connection completes in under 2 s**,
//! driven through the shipped `vox` binary.
//!
//! **The claim.** Host and guest are each behind a port-restricted-cone NAT: an unsolicited datagram
//! is dropped, so a direct dial alone never lands, and only a coordinated simultaneous open (ADR-012
//! rung 3, coordinated by the anchor) gets through. The guest has joined the host's room and is
//! trusted; nothing runs on its side. It starts `vox up` and asks for the host's service over SOCKS5
//! (what `ssh user@<room>.vox` does). The wait until the request is answered by any path, and the
//! wait until the pair is **on the punched path**, must both be under 2 s.
//!
//! **The staging — real processes only, NATs in userspace.** A `vox node` anchor on `[::]`, a
//! `vox serve` host on `127.0.0.1`, the guest on `[::1]`, set up with `vox id`, `vox trust add` and
//! `vox connect`. `support/nat.rs` puts a NAT in front of each: split by address family, neither
//! process can reach the other or the anchor except through sockets the emulator owns, and each is
//! given the anchor by an alias in its own family, so every datagram — process to process and
//! process to anchor — crosses its NAT. The anchor therefore observes each process at its **NAT's
//! public mapping**, and that reflexive address is what the punch trades. Nothing in the product is
//! switched: it runs its own ladder against NATs it cannot see.
//!
//! **Cold, each sample**, as in RP-22: a new `vox up` on a new port behind a new NAT mapping, the
//! last one stopped with Ctrl-C by PID; the two Argon2id unlocks before `vox up` is up are outside
//! the clock. The clock starts when `vox up` says it is up — or at its first datagram towards the
//! host, if its node began that on its own before then. (In that case the relayed connection and
//! the punch coordination that preceded that datagram, a few loopback round trips through the
//! anchor, are not on the clock: the emulator sees only ciphertext and cannot tell when the node
//! first *wanted* the host.)
//!
//! **What is asserted**, on every one of [`SAMPLES`] samples, against hard-coded numbers:
//! - the first request is answered in under 2000 ms, and a request rides the **peer-to-peer path**
//!   (its echo payload counted crossing both NATs, not via the anchor) in under 2000 ms;
//! - at least one unsolicited peer datagram was **dropped** by a NAT in that sample — the path was
//!   punched through a filter that was really there, not an open one.
//!
//! **Control, same run:** both NATs made **symmetric** (a new mapping per destination, so the
//! observed address is useless to the peer and no punch can work). The pair must stay relayed —
//! answered, but not one payload byte peer to peer — or the emulator leaks and this proof reports
//! CANNOT MEASURE.
//!
//! **The mutation that must turn it red:** drop the punch rung from `NodeNet::upgrade` (no
//! coordinator is asked). The pair is answered over the circuit and never reaches a direct path.
//!
//! **What it found.** On integrate/v0.2.10 39c3884 no sample ever punched: the anchor, on a
//! dual-stack socket, reports the host's view of the guest as `::ffff:127.0.0.1:…`, and the host's
//! IPv4 socket filtered that out as the wrong family and fired nothing (0/10; the guest's datagrams
//! went unanswered at 1, 2, 4 and 7 s). Fixed on this branch in `connect_direct_within` by reading an
//! IPv4-mapped candidate as IPv4 (`fix/punch-v4-mapped-observed`).
//!
//! Replaces `crates/vox-core/tests/perf_r42_first_connect_punch_gate.rs`, which ran every node in
//! process on a NAT simulator.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[path = "support/world.rs"]
mod world;

#[path = "support/nat.rs"]
mod nat;

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use nat::{Kind, TwoNats};
use world::{after_label, args, echo_service, socks5_connect, vox_once, VoxProc};

/// PRD-001 R42. A number, not a product constant.
const TARGET: Duration = Duration::from_millis(2000);
/// Cold first connections through the port-restricted-cone NATs.
const SAMPLES: usize = 10;
/// How long a sample may take to reach the punched path before it is recorded at this bound
/// (five times the target) and the proof is red.
const GIVE_UP: Duration = Duration::from_secs(10);
/// How long the symmetric control is watched for a direct path that must not come.
const CONTROL_WATCH: Duration = Duration::from_secs(15);
const PAYLOAD: usize = 16 * 1024;

struct NatWorld {
    _tmp: tempfile::TempDir,
    /// When the world began: the zero the host's and anchor's notes are timed from.
    started: Instant,
    nats: TwoNats,
    _anchor: VoxProc,
    _host: VoxProc,
    guest_dir: std::path::PathBuf,
    guest_spec: String,
    room: String,
    passphrase: String,
    service_port: u16,
}

impl NatWorld {
    fn new(kind: Kind) -> Self {
        let started = Instant::now();
        let tmp = tempfile::tempdir()
            .unwrap_or_else(|e| panic!("APPARATUS: no temporary directory: {e}"));
        let (anchor_dir, host_dir, guest_dir) = (
            tmp.path().join("anchor"),
            tmp.path().join("host"),
            tmp.path().join("guest"),
        );
        for d in [&anchor_dir, &host_dir, &guest_dir] {
            std::fs::create_dir_all(d.join("cfg"))
                .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", d.display()));
        }
        let anchor_port = UdpSocket::bind("[::]:0")
            .and_then(|s| s.local_addr())
            .unwrap_or_else(|e| panic!("APPARATUS: no free UDP port for the anchor: {e}"))
            .port();
        let nats = TwoNats::start(kind, anchor_port);
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
        let (fp, _) = spec
            .split_once('@')
            .unwrap_or_else(|| panic!("PRODUCT: the anchor's spec {spec:?} is not fp@address"));
        let host_spec = format!("{fp}@/ip4/127.0.0.1/udp/{}", nats.anchor_for_host.port());
        let guest_spec = format!("{fp}@/ip6/::1/udp/{}", nats.anchor_for_guest.port());

        let (ok, guest_fp, err) = vox_once(&guest_dir, &args(&["id"]));
        assert!(ok, "PRODUCT (staging): vox id (guest): {err}");
        let (ok, _host_fp, err) = vox_once(&host_dir, &args(&["id"]));
        assert!(ok, "PRODUCT (staging): vox id (host): {err}");
        let (ok, out, err) = vox_once(
            &host_dir,
            &args(&["trust", "add", guest_fp.trim(), "--name", "the guest"]),
        );
        assert!(ok, "PRODUCT (staging): trust add: {out}\n{err}");
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
        let t0 = Instant::now();
        let (ok, out, err) = vox_once(
            &guest_dir,
            &args(&[
                "connect",
                &address,
                "--passphrase-file",
                &world::room_pass_file(&guest_dir, &passphrase),
                "--anchor",
                &guest_spec,
                "--listen",
                "[::1]:0",
            ]),
        );
        assert!(
            ok,
            "CANNOT MEASURE ({kind:?}): the guest could not join through its NAT (after {:?}).\n\
             stdout:\n{out}\nstderr:\n{err}\nhost:\n{}",
            t0.elapsed(),
            host.transcript()
        );
        eprintln!("[proof] {kind:?}: the guest joined in {:?}", t0.elapsed());
        Self {
            _tmp: tmp,
            started,
            nats,
            _anchor: anchor,
            _host: host,
            guest_dir,
            guest_spec,
            room,
            passphrase,
            service_port,
        }
    }

    fn up(&self, name: &str) -> (VoxProc, SocketAddr, Instant) {
        let mut up = VoxProc::spawn(
            name,
            &self.guest_dir,
            &args(&[
                "up",
                &self.room,
                "--passphrase-file",
                &world::room_pass_file(&self.guest_dir, &self.passphrase),
                "--bind",
                "127.0.0.1:0",
                "--anchor",
                &self.guest_spec,
                "--listen",
                "[::1]:0",
            ]),
        );
        let line = up.expect_line("the proxy's bound address", |l| l.starts_with("vox up on "));
        let ready = Instant::now();
        let bound = line
            .split_whitespace()
            .nth(3)
            .and_then(|a| a.parse().ok())
            .unwrap_or_else(|| panic!("PRODUCT: no proxy address in `vox up`'s line {line:?}"));
        (up, bound, ready)
    }

    fn hostname(&self) -> String {
        format!("{}.vox", self.room)
    }
}

fn interrupt(p: &mut VoxProc) {
    let _ = std::process::Command::new("kill")
        .args(["-INT", &p.child.id().to_string()])
        .status();
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(Some(_)) = p.child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn echo_over(s: &mut std::net::TcpStream, payload: &[u8]) -> bool {
    use std::io::{Read, Write};
    let _ = s.set_read_timeout(Some(GIVE_UP));
    if s.write_all(payload).is_err() {
        return false;
    }
    let mut back = vec![0u8; payload.len()];
    s.read_exact(&mut back).is_ok() && back == payload
}

/// One request: CONNECT and a whole echo. `Some(true)` if its payload crossed peer to peer.
fn request(w: &NatWorld, proxy: SocketAddr, payload: &[u8]) -> Option<bool> {
    let (code, mut s) = socks5_connect(proxy, &w.hostname(), w.service_port);
    if code != 0 {
        return None;
    }
    let sent = w.nats.p2p_to_host();
    echo_over(&mut s, payload).then(|| w.nats.p2p_to_host() - sent >= payload.len() as u64)
}

fn stats(label: &str, samples: &[Duration]) -> Duration {
    let mut s = samples.to_vec();
    s.sort();
    let at = |q: f64| s[((q * s.len() as f64).ceil() as usize).clamp(1, s.len()) - 1];
    eprintln!(
        "[proof] {label}: n={} min={:?} median={:?} p95={:?} max={:?}",
        s.len(),
        s[0],
        at(0.5),
        at(0.95),
        s[s.len() - 1]
    );
    s[s.len() - 1]
}

#[test]
#[ignore = "production Argon2id + a real PoW, two NAT worlds and a dozen cold `vox up`; run in release"]
fn a_first_hole_punched_connection_completes_in_under_two_seconds() {
    test_knobs::require(&["VOX_TEST_ADVERTISE"]);
    watchdog::arm();
    let payload: Vec<u8> = (0..PAYLOAD).map(|i| (i % 251) as u8).collect();

    // The control first: symmetric NATs, where no punch can work, must leave the pair relayed.
    {
        let w = NatWorld::new(Kind::Symmetric);
        let (mut up, proxy, _) = w.up("control-up");
        let first = request(&w, proxy, &payload);
        assert!(
            first.is_some(),
            "CANNOT MEASURE: behind symmetric NATs the guest's request was not answered at all — \
             the anchor's circuit, the one path that must exist, did not carry it.\nup:\n{}",
            up.transcript()
        );
        let t0 = Instant::now();
        let mut n = 0usize;
        while t0.elapsed() < CONTROL_WATCH {
            if request(&w, proxy, &payload).is_some() {
                n += 1;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        eprintln!(
            "[proof] control (symmetric): {} requests answered over {CONTROL_WATCH:?}; peer to peer \
             {} B to the host, {} B back; {} unsolicited peer datagrams dropped",
            n + 1,
            w.nats.p2p_to_host(),
            w.nats.p2p_to_guest(),
            w.nats.p2p_filtered()
        );
        assert!(
            w.nats.p2p_to_host() == 0 && w.nats.p2p_to_guest() == 0,
            "CANNOT MEASURE: behind symmetric NATs the pair still moved {} B peer to peer — a path \
             leaks around the emulator, so a direct path behind the cone NATs would prove nothing",
            w.nats.p2p_to_host() + w.nats.p2p_to_guest()
        );
        interrupt(&mut up);
        drop(up);
    }

    let mut w = NatWorld::new(Kind::PortRestrictedCone);
    let mut any = Vec::new();
    let mut punched = Vec::new();
    let mut first_over_circuit = 0usize;
    let mut began_before_ready = 0usize;
    for i in 0..SAMPLES {
        let before = w.nats.first_p2p();
        let filtered_before = w.nats.p2p_filtered();
        let (mut up, proxy, ready) = w.up(&format!("up-{i}"));
        let first = request(&w, proxy, &payload);
        let answered = Instant::now();
        let Some(first_direct) = first else {
            panic!(
                "PRODUCT: sample {i}: the first request to the host was not answered.\nup:\n{}",
                up.transcript()
            );
        };
        if !first_direct {
            first_over_circuit += 1;
        }
        let mut direct_at = first_direct.then_some(answered);
        // Every request that took longer than the target, and what it came back with: a late
        // sample then says whether it was one request that hung or many that went the long way.
        let mut slow = Vec::new();
        while direct_at.is_none() && answered.duration_since(ready) < GIVE_UP * 2 {
            std::thread::sleep(Duration::from_millis(20));
            let asked = Instant::now();
            let got = request(&w, proxy, &payload);
            if asked.elapsed() >= TARGET {
                slow.push(format!(
                    "a request asked at +{:.3}s took {:?} and came back {got:?}",
                    asked.duration_since(ready).as_secs_f64(),
                    asked.elapsed()
                ));
            }
            if got == Some(true) {
                direct_at = Some(Instant::now());
            } else if Instant::now().duration_since(ready) >= GIVE_UP {
                break;
            }
        }
        let began = w
            .nats
            .first_p2p()
            .into_iter()
            .filter(|(src, _)| src.is_ipv6() && !before.contains_key(src))
            .map(|(_, at)| at)
            .min();
        let t0 = match began {
            Some(b) if b < ready => {
                began_before_ready += 1;
                b
            }
            _ => ready,
        };
        let filtered = w.nats.p2p_filtered() - filtered_before;
        let a = answered.duration_since(t0);
        let d = direct_at.map_or(GIVE_UP + a, |at| at.duration_since(t0));
        eprintln!(
            "[proof] sample {i}: answered {a:?} ({}), punched {}, {filtered} unsolicited peer \
             datagrams dropped",
            if first_direct {
                "punched"
            } else {
                "over the circuit"
            },
            direct_at.map_or_else(|| "NEVER".to_owned(), |_| format!("{d:?}"))
        );
        if direct_at.is_none() {
            // Say which side sent what, so a red names its cause rather than a timeout.
            let ev: Vec<_> = w
                .nats
                .events()
                .into_iter()
                .filter(|e| e.at >= ready)
                .collect();
            let count = |g: bool, d: bool| {
                ev.iter()
                    .filter(|e| e.to_guest == g && e.delivered == d)
                    .count()
            };
            eprintln!(
                "[proof] sample {i} never punched: host → guest {} delivered / {} dropped; guest → \
                 host {} delivered / {} dropped",
                count(true, true),
                count(true, false),
                count(false, true),
                count(false, false)
            );
            for e in ev.iter().take(12) {
                eprintln!(
                    "[proof]   +{:?} {} {} → {} {} ({} B)",
                    e.at.duration_since(ready),
                    if e.to_guest {
                        "host→guest"
                    } else {
                        "guest→host"
                    },
                    e.from_inside,
                    e.to_public,
                    if e.delivered { "delivered" } else { "DROPPED" },
                    e.len
                );
            }
        }
        // A sample that never punched, or punched late, says what its `vox up` noticed (#243's
        // CI red on dd78874: sample 0 punched after 61.9 s, and nothing said why).
        if d >= TARGET {
            eprintln!(
                "[proof]   sample {i} was ready at +{:.3}s (times below: from its ready)",
                ready.duration_since(w.started).as_secs_f64()
            );
            for l in &slow {
                eprintln!("[proof]   {l}");
            }
            for l in up.said_since(ready) {
                eprintln!("[proof]   up-{i} said: {l}");
            }
        }
        if direct_at.is_some() {
            assert!(
                filtered >= 1,
                "CANNOT MEASURE (sample {i}): the pair went direct and no NAT dropped a single \
                 unsolicited datagram — the filter this proof depends on was not in the way"
            );
        }
        any.push(a);
        punched.push(d);
        interrupt(&mut up);
        drop(up);
    }
    let never = punched.iter().filter(|d| **d > GIVE_UP).count();
    let (hm, gm) = w.nats.mappings();
    eprintln!(
        "[proof] {SAMPLES} cold first connections behind port-restricted-cone NATs; \
         {first_over_circuit} first answers over the circuit; {began_before_ready} began before \
         `vox up` was up; {never} never punched; peer to peer {} B to the host, {} B back; {} \
         unsolicited dropped; NAT mappings host {hm}, guest {gm}; anchor datagrams dropped {}",
        w.nats.p2p_to_host(),
        w.nats.p2p_to_guest(),
        w.nats.p2p_filtered(),
        w.nats.anchor_filtered()
    );
    let any_max = stats("first request answered, any path", &any);
    let punched_max = stats("on the punched path", &punched);
    let over_any = any.iter().filter(|d| **d >= TARGET).count();
    let over_punched = punched.iter().filter(|d| **d >= TARGET).count();
    if never > 0 || over_any > 0 || over_punched > 0 {
        for (who, p) in [("host", &mut w._host), ("anchor", &mut w._anchor)] {
            eprintln!("[proof]   times below: from the proof's start");
            for l in p.said_since(w.started) {
                eprintln!("[proof]   {who} said: {l}");
            }
        }
    }
    assert!(
        never == 0 && over_any == 0 && over_punched == 0,
        "PRODUCT: R42 punch: a first connection must complete in under {TARGET:?}. {over_any} of {SAMPLES} \
         first answers took longer (slowest {any_max:?}); {over_punched} of {SAMPLES} reached the \
         punched path at or past it (slowest {punched_max:?}), {never} never within {GIVE_UP:?}"
    );
}
