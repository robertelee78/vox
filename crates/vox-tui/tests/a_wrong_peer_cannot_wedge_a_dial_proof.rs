//! A dial whose first address answers **as somebody else** must go on to the next address, not
//! spin. ADR-018 §6's 21-hour hang, found and reproduced (v0.2.10 V210-17).
//!
//! **What hung.** On 2026-09-20 two `node_m15_anchor_gate` processes ran 21 hours at ~1.5 cores
//! each. Rebuilt on 2026-09-26 with `connect_direct` as it was before M15.1 (`3037525^`), that gate
//! hangs the same way, every time: sampled, two tokio workers spend **every** sample inside
//! `connect_direct` — one under bob's `Node::dial`, one under alice's `Node::answer_punch` — and no
//! worker is left driving the timer, so the gate's own 120-second `tokio::time::timeout`s never fire.
//! The loop raced "launch the next candidate after 250 ms" against "an attempt finished", and when
//! the only attempt in flight failed **faster than 250 ms**, the set of attempts was empty: waiting on
//! an empty `JoinSet` returns at once, the loop went round, armed a fresh 250 ms timer, and found the
//! set empty again — forever, without once returning `Pending`. Nothing else on that worker ever ran
//! again, and a task that never yields cannot be cancelled or shut down, so the process could not
//! even exit. M15.1 fixed the loop (an empty set launches the next candidate at once) the same
//! morning; the fix was never pinned by a proof of the product, so nothing stops it coming back.
//!
//! **The trigger is ordinary.** M15.1's was an IPv6 address offered to an IPv4 socket, now filtered
//! out before the loop. This proof uses the other way an attempt fails in milliseconds: the address
//! is live, and **a different node** answers there — a peer's old address now held by somebody else,
//! or a stale record. The handshake completes and the identity check refuses it, in well under the
//! 250 ms stagger.
//!
//! Driven through the shipped binary: `vox node` (the anchor), a second `vox node` (the decoy that
//! holds the stale address), `vox serve` (the host), and `vox connect` (the guest joining). The host
//! advertises the decoy's address **first** and its own second (`VOX_TEST_ADVERTISE`); the guest
//! advertises nothing reachable, so the host cannot reach it instead. The decoy sits behind a
//! counting UDP relay, which is how the proof knows the guest really dialled it and really got an
//! answer — without that, a guest that skipped the decoy would pass for the wrong reason.
//!
//! Mutation-checked by restoring the pre-M15.1 loop in `nat/reachability.rs`: see ADR-018 §6a.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::net::{SocketAddr, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use world::{after_label, args, echo_service, VoxProc, IDENTITY, VOX};

/// How long `vox connect` may take. It joins in seconds (two production Argon2id steps and a
/// PoW); a dial that spins never finishes at all, so this is generous rather than tight.
const CONNECT_PATIENCE: Duration = Duration::from_secs(120);

/// A UDP relay in front of the decoy, counting what crosses it each way.
struct CountingRelay {
    front: SocketAddr,
    to_decoy: Arc<AtomicU64>,
    from_decoy: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl CountingRelay {
    fn new(decoy: SocketAddr) -> Self {
        let front = UdpSocket::bind("127.0.0.1:0").expect("bind the relay's front");
        let back = UdpSocket::bind("127.0.0.1:0").expect("bind the relay's back");
        for s in [&front, &back] {
            s.set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
        }
        let front_addr = front.local_addr().unwrap();
        let (to_decoy, from_decoy) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let stop = Arc::new(AtomicBool::new(false));
        let client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        {
            let (front, back) = (front.try_clone().unwrap(), back.try_clone().unwrap());
            let (count, stop, client) = (
                Arc::clone(&to_decoy),
                Arc::clone(&stop),
                Arc::clone(&client),
            );
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65_536];
                while !stop.load(Ordering::Relaxed) {
                    if let Ok((n, from)) = front.recv_from(&mut buf) {
                        *client.lock().unwrap() = Some(from);
                        if back.send_to(&buf[..n], decoy).is_ok() {
                            count.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            });
        }
        {
            let (count, stop) = (Arc::clone(&from_decoy), Arc::clone(&stop));
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65_536];
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(n) = back.recv(&mut buf) {
                        let to = *client.lock().unwrap();
                        if let Some(to) = to {
                            if front.send_to(&buf[..n], to).is_ok() {
                                count.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            });
        }
        Self {
            front: front_addr,
            to_decoy,
            from_decoy,
            stop,
        }
    }

    fn counts(&self) -> (u64, u64) {
        (
            self.to_decoy.load(Ordering::Relaxed),
            self.from_decoy.load(Ordering::Relaxed),
        )
    }
}

impl Drop for CountingRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// The socket address in an `--anchor` spec, `<fingerprint>@/ip4/<ip>/udp/<port>`.
fn spec_addr(spec: &str) -> SocketAddr {
    let addr = spec.split('@').nth(1).expect("a spec has an @");
    let parts: Vec<&str> = addr.split('/').collect();
    match parts.as_slice() {
        ["", "ip4", ip, "udp", port] => format!("{ip}:{port}").parse().expect("an ip4 address"),
        _ => panic!("an --anchor spec this proof cannot read: {spec}"),
    }
}

fn spawn_node(name: &str, dir: &std::path::Path) -> (VoxProc, String) {
    let mut node = VoxProc::spawn(name, dir, &args(&["node", "--listen", "127.0.0.1:0"]));
    let spec = node
        .expect_line("an --anchor spec", |l| {
            !l.starts_with("! ")
                && l.trim_start().contains('@')
                && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
        })
        .trim()
        .to_owned();
    (node, spec)
}

/// CPU seconds a live process has used, from `ps`.
fn cpu_secs(pid: u32) -> f64 {
    let out = Command::new("ps")
        .args(["-o", "time=", "-p", &pid.to_string()])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    // `[[dd-]hh:]mm:ss[.ss]`
    out.replace('-', ":")
        .split(':')
        .filter_map(|p| p.parse::<f64>().ok())
        .fold(0.0, |acc, p| acc * 60.0 + p)
}

#[test]
#[ignore = "four real vox processes and production Argon2id; CI runs it in release"]
fn a_dial_whose_first_address_answers_as_somebody_else_goes_on_to_the_next() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, decoy_dir, host_dir, guest_dir) =
        (dir("anchor"), dir("decoy"), dir("host"), dir("guest"));

    let (_anchor, anchor_spec) = spawn_node("anchor", &anchor_dir);
    let (_decoy, decoy_spec) = spawn_node("decoy", &decoy_dir);
    let relay = CountingRelay::new(spec_addr(&decoy_spec));

    let (ok, guest_fp, err) = world::vox_once(&guest_dir, &args(&["id"]));
    assert!(ok, "vox id (guest): {err}");
    let (ok, out, err) = world::vox_once(
        &host_dir,
        &args(&["trust", "add", guest_fp.trim(), "--name", "the guest"]),
    );
    assert!(ok, "trust add: {out}\n{err}");

    // The host's own address second, the decoy's (through the relay) first.
    let host_listen = {
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap()
    };
    let advertise = format!("{},{host_listen}", relay.front);
    let service = echo_service().to_string();
    let mut host = VoxProc::spawn_env(
        "host",
        &host_dir,
        &args(&[
            "serve",
            &service,
            "--anchor",
            &anchor_spec,
            "--listen",
            &host_listen.to_string(),
        ]),
        &[("VOX_TEST_ADVERTISE", &advertise)],
    );
    let address = after_label(
        &host.expect_line("address", |l| l.starts_with("address ")),
        "address",
    );
    let passphrase = after_label(
        &host.expect_line("passphrase", |l| l.starts_with("passphrase ")),
        "passphrase",
    );
    let decoy_port = format!("/udp/{}", relay.front.port());
    let host_port = format!("/udp/{}", host_listen.port());
    assert!(
        address.contains(&decoy_port) && address.contains(&host_port),
        "CANNOT MEASURE: the host's address does not carry both the decoy's and its own: {address}"
    );
    assert!(
        address.find(&decoy_port) < address.find(&host_port),
        "CANNOT MEASURE: the decoy's address is not offered first: {address}"
    );

    // The guest joins. Bounded here, by its PID: a spinning dial never returns.
    let started = Instant::now();
    let mut guest = Command::new(VOX)
        .args([
            "connect",
            &address,
            "--passphrase",
            &passphrase,
            "--anchor",
            &anchor_spec,
            "--listen",
            "127.0.0.1:0",
        ])
        .env("VOX_DATA_DIR", &guest_dir)
        .env("VOX_CONFIG_DIR", guest_dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        // Nothing reachable, so the host cannot dial the guest instead.
        .env("VOX_TEST_ADVERTISE", "127.0.0.1:9")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vox connect");
    let pid = guest.id();
    let status = loop {
        if let Some(status) = guest.try_wait().expect("poll vox connect") {
            break Some(status);
        }
        if started.elapsed() > CONNECT_PATIENCE {
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let took = started.elapsed();
    let (to_decoy, from_decoy) = relay.counts();
    let Some(status) = status else {
        let cpu = cpu_secs(pid);
        let _ = guest.kill();
        let out = guest.wait_with_output().expect("reap vox connect");
        panic!(
            "vox connect did not finish in {CONNECT_PATIENCE:?}: {cpu:.1} CPU-seconds used in that \
             time (a spinning dial burns a core; a waiting one burns next to none). The decoy was \
             sent {to_decoy} datagram(s) and answered {from_decoy}.\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    };
    let out = guest.wait_with_output().expect("collect vox connect");
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // The escalation step: the guest really dialled the decoy and the decoy really answered, so
    // the attempt that failed was the fast failure this proof exists for.
    assert!(
        to_decoy > 0 && from_decoy > 0,
        "CANNOT MEASURE: the guest never completed an exchange with the decoy \
         ({to_decoy} datagram(s) to it, {from_decoy} back), so no attempt failed fast.\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        status.success(),
        "vox connect failed after dialling the decoy ({to_decoy} datagram(s) to it, {from_decoy} \
         back) in {took:?}.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    println!(
        "joined in {took:?} after the first address answered as somebody else \
         ({to_decoy} datagram(s) to the decoy, {from_decoy} back)"
    );
    drop(host);
}
