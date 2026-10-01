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
//! **Mutations that must turn it red:** answering `Invite` at once (arms 1 and 3: the address is
//! printed while the anchor is stopped), and stopping the join at the first board's "nothing for
//! room" (arm 2: the join fails naming only `A6`).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

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
    let spec = a
        .expect_line("an --anchor spec", |l| {
            !l.starts_with("! ")
                && l.trim_start().contains('@')
                && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
        })
        .trim()
        .to_owned();
    let (fp, addr) = spec.split_once('@').expect("fp@addr");
    let port = addr.rsplit('/').next().expect("a port");
    let spec = if v6 {
        format!("{fp}@/ip6/::1/udp/{port}")
    } else {
        format!("{fp}@/ip4/127.0.0.1/udp/{port}")
    };
    (a, spec)
}

/// A guest and a host with identities, the host trusting the guest.
fn two_identities(guest: &Path, host: &Path) {
    for d in [guest, host] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }
    let (ok, guest_fp, err) = vox_once(guest, &args(&["id"]));
    assert!(ok, "vox id (guest) failed: {err}");
    let (ok, _, err) = vox_once(host, &args(&["id"]));
    assert!(ok, "vox id (host) failed: {err}");
    let (ok, out, err) = vox_once(
        host,
        &args(&["trust", "add", guest_fp.trim(), "--name", "the guest"]),
    );
    assert!(ok, "trust add failed: {out}\n{err}");
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
    let mut anchor = relay::Anchor::start(&anchor_dir);
    two_identities(&guest_dir, &host_dir);

    // The anchor stops before the host starts, by its own handle.
    let _ = anchor.proc.child.kill();
    let _ = anchor.proc.child.wait();
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
        "the host made no room within {ROOM_WITHIN:?}.\nhost:\n{}",
        host.transcript()
    );
    let room_at = started.elapsed();
    let (held, _) = watch_host(&mut host, started, HOLD, || false);
    let printed_while_down = early.or(held);
    anchor.restart(&anchor_dir);
    let back = started.elapsed();
    let address = after_label(
        &host.expect_within(PRINT_WITHIN, "the address", |l| l.starts_with("address ")),
        "address",
    );
    let printed = started.elapsed();
    let passphrase = after_label(
        &host.expect_line("the passphrase", |l| l.starts_with("passphrase ")),
        "passphrase",
    );
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
        "the host printed its address at +{:.2}s, while the only board a guest on [::1] can reach \
         was stopped (until +{:.2}s): an address must be printed only once a board it names holds \
         the room.\nhost:\n{}",
        printed_while_down.unwrap_or_default().as_secs_f64(),
        back.as_secs_f64(),
        host.transcript()
    );
    assert!(
        joined,
        "a guest that joined the instant the address was printed was refused: the address must \
         lead to its room when it is printed.\nstdout:\n{out}\nstderr:\n{err}\nhost:\n{}",
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
    let address = after_label(
        &host.expect_within(ROOM_WITHIN, "the address", |l| l.starts_with("address ")),
        "address",
    );
    let passphrase = after_label(
        &host.expect_line("the passphrase", |l| l.starts_with("passphrase ")),
        "passphrase",
    );
    let a6_fp = a6_spec.split_once('@').expect("fp@addr").0.to_owned();
    assert!(
        address.contains(&a6_fp),
        "the address does not name A6, one of the two anchors the host was given: {address}"
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
    let (joined, out, err) = join.join().expect("the guest's join thread");
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
        joined,
        "the guest's join stopped at a board without the room, while the address names the host's \
         own board, which holds it: a join must ask every board the address names.\nstdout:\n{out}\
         \nstderr:\n{err}\nhost:\n{}",
        host.transcript()
    );
    assert!(
        err.contains("another board"),
        "the join got in, but its steps do not say another board was asked: the first board it \
         took must have been A6, which does not hold the room, so the fallback is what got it \
         in.\nstderr:\n{err}"
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
    let anchor = relay::Anchor::start(&anchor_dir);
    two_identities(&guest_dir, &host_dir);
    let mut stopped = anchor;
    let _ = stopped.proc.child.kill();
    let _ = stopped.proc.child.wait();
    let anchor_fp = stopped
        .v4_spec
        .split_once('@')
        .expect("fp@addr")
        .0
        .to_owned();

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
        "the host printed an address while its only anchor was stopped for the whole run: an \
         address no board holds the room for must not be handed out.\nhost:\n{said}"
    );
    assert!(
        status.is_some_and(|s| !s.success()),
        "the host neither printed an address nor failed within {WITHHELD_WITHIN:?}.\nhost:\n{said}"
    );
    let short: String = anchor_fp.chars().take(8).collect();
    assert!(
        said.contains("would lead nowhere") && said.contains(&short),
        "the host withheld the address but did not say why, naming the anchor {short}.\nhost:\n\
         {said}"
    );
}
