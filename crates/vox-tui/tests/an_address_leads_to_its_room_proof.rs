//! V210-96 (#292) — **an address is printed only once its room can be joined through it**, and **a
//! join asks every board the address names** before it says the room is not there. Driven through
//! the shipped `vox` binary.
//!
//! **The defect.** `vox serve` printed its address the moment the room was made. The room's first
//! publish round ran on its own task, and went only to an anchor the node already held a connection
//! to — which a node `vox serve` has just started often does not. A guest who joined at once
//! reached the anchor and was told "board … has nothing for room …": CI macOS at 1a648c9, the R42
//! proof's setup (`a_first_direct_connection_is_prompt_proof`), and 1 of 77 local probes; in 11 of
//! 18 ordered runs the host said it had connected to its anchor *after* printing the address. And
//! the join stopped at that first board, although the address named others — the host's own last,
//! which always holds its room.
//!
//! **Arm 1, the address waits for its board.** One anchor on `[::]`, **stopped** before the host
//! starts; a `vox serve` host on `127.0.0.1` naming it. The anchor stays stopped until the host's
//! room exists (`vox room list`, asked of the host's own control socket, names one) and [`HOLD`]
//! after, then is started again (same identity, same port). Tied to the room rather than a clock,
//! so a slow (debug) host cannot pass merely by not having reached its address yet. The guest is on
//! `[::1]`, so the anchor is the only board it can reach (the host's own addresses are IPv4). Every
//! line the host prints is read as it comes, so **when** the address was printed is known. The
//! instant it is, the guest runs `vox connect`. Asserted: the address was not printed while the
//! anchor was stopped, and the guest's join got in.
//!
//! **Arm 2, the join asks the other boards.** Two anchors: `A4` on `127.0.0.1` only, `A6` on `[::1]`
//! only. The host on `127.0.0.1` names both and reaches only `A4`, so only `A4` holds the room. It
//! advertises a port forward on `[::1]` (`support/port_forward.rs`), its only address a guest on
//! `[::1]` can reach, and the forward starts **closed**. The guest on `[::1]`, with `A6` as its own
//! anchor, cannot reach `A4` and cannot yet reach the host, so the board its search takes is `A6` —
//! which has nothing for the room. The forward opens [`FORWARD_OPENS`] after the guest's first
//! datagram reaches it, long after `A6` (a loopback handshake) was taken, and well inside the 30 s a
//! dial is given. Asserted: the join got in (through the host's own board), and its steps say
//! another board was asked.
//!
//! **Arm 3, an address that would lead nowhere is not handed out.** The anchor is stopped for the
//! whole run. Asserted: the host prints no address, exits failing, and says why, naming the anchor.
//!
//! **Every red names which it is** (the decider's rule: a test that cannot tell a broken product
//! from a broken test is not a valid test). `PRODUCT:` — `vox` did the wrong thing, and what it
//! said is quoted. `APPARATUS:` — the staging was not achieved or a precondition is unmet (a setup
//! verb failed, an anchor printed no spec, the guest never reached the closed forward), so nothing
//! about the claim was measured. The watchdog (`support/watchdog.rs`) names itself when it fires.
//!
//! **Mutations that must turn it red:** answering `Invite` at once (arms 1 and 3: the address is
//! printed while the anchor is stopped), and stopping the join at the first board's "nothing for
//! room" (arm 2: the join fails naming only `A6`).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

// `port_forward.rs` names its helpers' anchor type.
#[path = "support/relay.rs"]
mod relay;

#[path = "support/port_forward.rs"]
mod port_forward;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use world::{after_label, args, room_pass_file, vox_once, VoxProc};

/// How long the anchor stays stopped once the host's room exists. An address answered at once is
/// printed within milliseconds of the room existing; this is the host's chance to do that.
const HOLD: Duration = Duration::from_secs(3);
/// How long the host may take to make its room: production Argon2id, in either profile.
const ROOM_WITHIN: Duration = Duration::from_secs(300);
/// How long the host may take to print its address once the anchor is back: its redial, the
/// connection and the first publish round.
const PRINT_WITHIN: Duration = Duration::from_secs(120);
/// How long after the guest's first datagram reaches the closed forward it opens (arm 2).
const FORWARD_OPENS: Duration = Duration::from_secs(3);
/// How long the host may take to give up on an address no board holds (arm 3): its 30 s wait,
/// after making its room, with headroom.
const WITHHELD_WITHIN: Duration = Duration::from_secs(400);

/// A `vox node` anchor on `listen`, and the `fp@/ip…/udp/port` spec that names it on `family`.
fn anchor_on(dir: &Path, listen: &str, v6: bool) -> (VoxProc, String) {
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    let mut a = VoxProc::spawn("anchor", dir, &args(&["node", "--listen", listen]));
    let spec = line_within(&mut a, Duration::from_secs(180), |l| {
        !l.starts_with("! ")
            && l.trim_start().contains('@')
            && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
    });
    let spec = spec
        .unwrap_or_else(|| {
            panic!(
                "APPARATUS: the anchor on {listen} printed no --anchor spec, so there is no world \
                 to measure in.\nanchor:\n{}",
                a.transcript()
            )
        })
        .trim()
        .to_owned();
    let (fp, addr) = spec
        .split_once('@')
        .unwrap_or_else(|| panic!("APPARATUS: the anchor's spec {spec:?} has no fp@addr"));
    let port = addr
        .rsplit('/')
        .next()
        .unwrap_or_else(|| panic!("APPARATUS: the anchor's spec {spec:?} has no port"));
    let spec = if v6 {
        format!("{fp}@/ip6/::1/udp/{port}")
    } else {
        format!("{fp}@/ip4/127.0.0.1/udp/{port}")
    };
    (a, spec)
}

/// A `vox node` anchor on `[::]:port` (dual-stack; `0` for any), and the specs naming it from an
/// IPv4 socket and from an IPv6 one.
struct DualAnchor {
    proc: VoxProc,
    v4_spec: String,
    v6_spec: String,
}

impl DualAnchor {
    fn start(dir: &Path, port: u16) -> Self {
        let (proc, v4_spec) = anchor_on(dir, &format!("[::]:{port}"), false);
        let v6_spec = v4_spec.replace("/ip4/127.0.0.1/", "/ip6/::1/");
        Self {
            proc,
            v4_spec,
            v6_spec,
        }
    }

    fn port(&self) -> u16 {
        self.v4_spec
            .rsplit('/')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| panic!("APPARATUS: no port in the anchor spec {:?}", self.v4_spec))
    }

    /// Stop it, by its own PID.
    fn stop(&mut self) {
        let _ = self.proc.child.kill();
        let _ = self.proc.child.wait();
    }

    /// Start it again from `dir` on the same port: the same identity, so every spec still names it.
    fn restart(&mut self, dir: &Path) {
        let port = self.port();
        self.stop();
        let again = Self::start(dir, port);
        assert_eq!(
            again.v4_spec, self.v4_spec,
            "APPARATUS: the restarted anchor is not the same anchor on the same port"
        );
        *self = again;
    }
}

/// A guest and a host with identities, the host trusting the guest.
fn two_identities(guest: &Path, host: &Path) {
    for d in [guest, host] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let (ok, guest_fp, err) = vox_once(guest, &args(&["id"]));
    assert!(ok, "APPARATUS: setup verb `vox id` (guest) failed: {err}");
    let (ok, _, err) = vox_once(host, &args(&["id"]));
    assert!(ok, "APPARATUS: setup verb `vox id` (host) failed: {err}");
    let (ok, out, err) = vox_once(
        host,
        &args(&["trust", "add", guest_fp.trim(), "--name", "the guest"]),
    );
    assert!(
        ok,
        "APPARATUS: setup verb `vox trust add` failed: {out}\n{err}"
    );
}

/// Read what `host` prints, as it comes, until `until` says stop or `within` passes; record when an
/// `address ` line was first seen. Returns that, and whether `until` was met.
fn watch_host(
    host: &mut VoxProc,
    started: Instant,
    within: Duration,
    mut until: impl FnMut() -> bool,
) -> (Option<Duration>, bool) {
    let deadline = Instant::now() + within;
    let mut address_at = None;
    let mut poll_at = Instant::now();
    while Instant::now() < deadline {
        match host.lines.recv_timeout(Duration::from_millis(50)) {
            Ok(line) => {
                eprintln!("[host] {line}");
                if line.starts_with("address ") && address_at.is_none() {
                    address_at = Some(started.elapsed());
                }
                host.seen.push(line);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return (address_at, false),
        }
        if Instant::now() >= poll_at {
            if until() {
                return (address_at, true);
            }
            poll_at = Instant::now() + Duration::from_millis(250);
        }
    }
    (address_at, false)
}

/// The first line `p` prints (or has printed) that matches `pred`, within `within`; `None` if it
/// exits or the time passes first. Every line is kept, for the transcript a red quotes.
fn line_within(p: &mut VoxProc, within: Duration, pred: impl Fn(&str) -> bool) -> Option<String> {
    if let Some(line) = p.seen.iter().find(|l| pred(l)) {
        return Some(line.clone());
    }
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        match p.lines.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                eprintln!("[{}] {line}", p.name);
                let hit = pred(&line);
                p.seen.push(line.clone());
                if hit {
                    return Some(line);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return None,
        }
    }
    None
}

/// The passphrase `vox serve` prints right after its address.
fn passphrase_of(host: &mut VoxProc) -> String {
    let line = line_within(host, Duration::from_secs(10), |l| {
        l.starts_with("passphrase ")
    });
    after_label(
        &line.unwrap_or_else(|| {
            panic!(
                "PRODUCT: `vox serve` printed its address and no passphrase after it. It said:\n{}",
                host.transcript()
            )
        }),
        "passphrase",
    )
}

/// Whether the host's running node holds a room yet, asked of its own control socket.
fn host_has_a_room(host_dir: &Path) -> bool {
    let (ok, out, _) = vox_once(host_dir, &args(&["room", "list"]));
    ok && !out.trim().is_empty() && !out.contains("no rooms")
}

#[test]
#[ignore = "real anchors, host and guest, production Argon2id and a real PoW; CI runs it in release"]
fn an_address_is_printed_only_once_a_board_it_names_holds_the_room() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (anchor_dir, host_dir, guest_dir) = (
        tmp.path().join("anchor"),
        tmp.path().join("host"),
        tmp.path().join("guest"),
    );
    let mut anchor = DualAnchor::start(&anchor_dir, 0);
    two_identities(&guest_dir, &host_dir);

    // The anchor stops before the host starts, by its own handle.
    anchor.stop();
    let started = Instant::now();
    let mut host = VoxProc::spawn(
        "host",
        &host_dir,
        &args(&[
            "serve",
            "22",
            "--anchor",
            &anchor.v4_spec,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    // Until the host's room exists, then HOLD more, the anchor stays stopped.
    let (early, has_room) = watch_host(&mut host, started, ROOM_WITHIN, || {
        host_has_a_room(&host_dir)
    });
    assert!(
        has_room || early.is_some(),
        "PRODUCT: `vox serve` made no room within {ROOM_WITHIN:?} (its own control socket listed \
         none, and it printed no address). It said:\n{}",
        host.transcript()
    );
    let room_at = started.elapsed();
    let (held, _) = watch_host(&mut host, started, HOLD, || false);
    let printed_while_down = early.or(held);
    anchor.restart(&anchor_dir);
    let back = started.elapsed();
    let address = line_within(&mut host, PRINT_WITHIN, |l| l.starts_with("address "));
    let printed = started.elapsed();
    let address = after_label(
        &address.unwrap_or_else(|| {
            panic!(
                "PRODUCT: the anchor came back at +{:.2}s and `vox serve` printed no address within \
                 {PRINT_WITHIN:?} of it. It said:\n{}",
                back.as_secs_f64(),
                host.transcript()
            )
        }),
        "address",
    );
    let passphrase = passphrase_of(&mut host);
    // At once, as a person pasting it (or an agent handed it) would.
    let t = Instant::now();
    let (joined, out, err) = vox_once(
        &guest_dir,
        &args(&[
            "connect",
            &address,
            "--passphrase-file",
            &room_pass_file(&guest_dir, &passphrase),
            "--anchor",
            &anchor.v6_spec,
            "--listen",
            "[::1]:0",
        ]),
    );
    eprintln!(
        "[proof] arm 1: the room existed at +{:.2}s; the anchor was stopped from +0s to +{:.2}s; \
         the address was printed at +{:.2}s{}; the guest's join {} after {:.2}s",
        room_at.as_secs_f64(),
        back.as_secs_f64(),
        printed.as_secs_f64(),
        printed_while_down.map_or(String::new(), |d| format!(
            " (first seen at +{:.2}s, while the anchor was stopped)",
            d.as_secs_f64()
        )),
        if joined { "got in" } else { "failed" },
        t.elapsed().as_secs_f64()
    );
    assert!(
        printed_while_down.is_none(),
        "PRODUCT: `vox serve` printed its address at +{:.2}s, while the only board a guest on [::1] can reach \
         was stopped (until +{:.2}s): an address must be printed only once a board it names holds \
         the room.\nhost:\n{}",
        printed_while_down.unwrap_or_default().as_secs_f64(),
        back.as_secs_f64(),
        host.transcript()
    );
    assert!(
        joined,
        "PRODUCT: a guest that ran `vox connect` the instant the address was printed was refused: \
         the address must lead to its room when it is printed. `vox connect` said:\n{out}\n{err}\n\
         host:\n{}",
        host.transcript()
    );
}

#[test]
#[ignore = "real anchors, host and guest, production Argon2id and a real PoW; CI runs it in release"]
fn a_join_asks_every_board_the_address_names() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (a4_dir, a6_dir, host_dir, guest_dir) = (
        tmp.path().join("a4"),
        tmp.path().join("a6"),
        tmp.path().join("host"),
        tmp.path().join("guest"),
    );
    let (_a4, a4_spec) = anchor_on(&a4_dir, "127.0.0.1:0", false);
    let (_a6, a6_spec) = anchor_on(&a6_dir, "[::1]:0", true);
    two_identities(&guest_dir, &host_dir);

    let host_port = port_forward::free_v4_udp_port();
    let host_addr: SocketAddr = format!("127.0.0.1:{host_port}").parse().unwrap();
    let forward = port_forward::PortForward::start(host_addr, false);
    let advertise = forward.public.to_string();
    let mut host = VoxProc::spawn_env(
        "host",
        &host_dir,
        &args(&[
            "serve",
            "22",
            "--anchor",
            &a4_spec,
            "--anchor",
            &a6_spec,
            "--listen",
            &host_addr.to_string(),
        ]),
        &[("VOX_TEST_ADVERTISE", advertise.as_str())],
    );
    // A4 is up and reachable by the host, so the address is due as soon as the room is on it.
    let address = line_within(&mut host, ROOM_WITHIN, |l| l.starts_with("address "));
    let address = after_label(
        &address.unwrap_or_else(|| {
            panic!(
                "PRODUCT: `vox serve` printed no address within {ROOM_WITHIN:?}, with its anchor A4 \
                 up the whole time. It said:\n{}",
                host.transcript()
            )
        }),
        "address",
    );
    let passphrase = passphrase_of(&mut host);
    let a6_fp = a6_spec.split_once('@').map_or("", |(fp, _)| fp).to_owned();
    assert!(
        !a6_fp.is_empty() && address.contains(&a6_fp),
        "PRODUCT: the address `vox serve` printed does not name A6 ({a6_fp}), one of the two \
         anchors it was given: {address}"
    );

    let t = Instant::now();
    let join_args = args(&[
        "connect",
        &address,
        "--passphrase-file",
        &room_pass_file(&guest_dir, &passphrase),
        "--anchor",
        &a6_spec,
        "--listen",
        "[::1]:0",
    ]);
    let guest = guest_dir.clone();
    let join = std::thread::spawn(move || vox_once(&guest, &join_args));
    // The forward opens FORWARD_OPENS after the guest first knocks on it: its board search has
    // long since taken A6, and a dial to the host is still inside its 30 s.
    let knocked = loop {
        if !forward.sources().is_empty() {
            break Some(Instant::now());
        }
        if join.is_finished() {
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if knocked.is_some() {
        std::thread::sleep(FORWARD_OPENS);
    }
    forward.open();
    let (joined, out, err) = join
        .join()
        .unwrap_or_else(|_| panic!("APPARATUS: the thread running `vox connect` panicked"));
    let steps: Vec<&str> = err.lines().filter(|l| l.contains("join ")).collect();
    eprintln!(
        "[proof] arm 2: the guest {} the closed forward; the guest's join {} after {:.2}s; its \
         steps: {steps:?}; the forward carried {} bytes to the host",
        if knocked.is_some() {
            "knocked on"
        } else {
            "never knocked on"
        },
        if joined { "got in" } else { "failed" },
        t.elapsed().as_secs_f64(),
        forward.to_host()
    );
    assert!(
        knocked.is_some(),
        "APPARATUS: staging not achieved — the guest's join never sent the host's (closed) forward a \
         datagram, so its board search never had the host as a route and the fallback was not \
         staged. `vox connect` said:\n{out}\n{err}"
    );
    assert!(
        joined,
        "PRODUCT: the guest's join stopped at a board without the room, while the address names the \
         host's own board, which holds it: a join must ask every board the address names. `vox \
         connect` said:\n{out}\n{err}\nhost:\n{}",
        host.transcript()
    );
    assert!(
        err.contains("another board"),
        "APPARATUS: staging not achieved — the join got in, but its steps do not say another board \
         was asked, so the first board it took held the room and the fallback was never needed \
         (the forward was closed for {FORWARD_OPENS:?} after the guest first knocked). `vox \
         connect` said:\n{err}"
    );
}

#[test]
#[ignore = "a real anchor and host, production Argon2id; CI runs it in release"]
fn an_address_no_board_holds_the_room_for_is_not_handed_out() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (anchor_dir, host_dir, guest_dir) = (
        tmp.path().join("anchor"),
        tmp.path().join("host"),
        tmp.path().join("guest"),
    );
    let mut stopped = DualAnchor::start(&anchor_dir, 0);
    two_identities(&guest_dir, &host_dir);
    stopped.stop();
    let anchor_fp = stopped
        .v4_spec
        .split_once('@')
        .map_or("", |(fp, _)| fp)
        .to_owned();
    assert!(
        !anchor_fp.is_empty(),
        "APPARATUS: the anchor's spec {:?} has no fp@addr",
        stopped.v4_spec
    );

    let started = Instant::now();
    let mut host = VoxProc::spawn(
        "host",
        &host_dir,
        &args(&[
            "serve",
            "22",
            "--anchor",
            &stopped.v4_spec,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    let (printed, _) = watch_host(&mut host, started, WITHHELD_WITHIN, || false);
    let ended = started.elapsed();
    // Its output closed or the wait ran out: give an exiting process a moment to be reaped.
    let status = (0..100).find_map(|_| {
        let s = host.child.try_wait().ok().flatten();
        if s.is_none() {
            std::thread::sleep(Duration::from_millis(100));
        }
        s
    });
    let said = host.transcript();
    eprintln!(
        "[proof] arm 3: the host {} at +{:.2}s{}",
        match status {
            Some(s) => format!("exited ({s})"),
            None => "was still running".to_owned(),
        },
        ended.as_secs_f64(),
        printed.map_or(String::new(), |d| format!(
            ", having printed an address at +{:.2}s",
            d.as_secs_f64()
        ))
    );
    assert!(
        printed.is_none(),
        "PRODUCT: `vox serve` printed an address while its only anchor was stopped for the whole \
         run: an address no board holds the room for must not be handed out. It said:\n{said}"
    );
    assert!(
        status.is_some_and(|s| !s.success()),
        "PRODUCT: `vox serve` neither printed an address nor failed within {WITHHELD_WITHIN:?} \
         ({status:?}); it must give up on an address no board holds, and say so. It said:\n{said}"
    );
    let short: String = anchor_fp.chars().take(8).collect();
    assert!(
        said.contains("would lead nowhere") && said.contains(&short),
        "PRODUCT: `vox serve` withheld the address but did not say why, naming the anchor \
         {short}. It said:\n{said}"
    );
}
