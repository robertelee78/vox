//! V210-96 (#292) — **an address leads to its room the moment it is printed**, and **a join asks
//! every route the address names** before it says the room is not there. Driven through the shipped
//! `vox` binary, as a person runs it.
//!
//! **The defect.** `vox serve` printed its address while the room's first publish round to its
//! anchor had not landed, and a guest who reached the anchor was told "board … has nothing for room
//! …" — CI macOS at 1a648c9 (`a_first_direct_connection_is_prompt_proof`'s setup), 1 of 77 local
//! probes — and the join stopped there, although the address named the host itself, whose own
//! board always holds its room.
//!
//! **The rule** (the decider, 2026-10-01; ADR-012): an anchor bridges hosts that cannot otherwise
//! find each other, and nothing else needs one. So the address is printed at once whenever it names
//! a route of the host's own, with a note saying which anchors have not taken the room yet (and,
//! later, that they have); a guest who can reach the host goes direct; a guest who cannot waits for
//! the anchor, which the host says when it has.
//!
//! **Arms**, each the way a person meets it:
//! - **A, no anchor at all.** `vox serve` and `vox connect` with no anchor and the default
//!   `--listen`: the host prints an address naming itself, and the guest gets in.
//! - **B, the anchors are down.** Four anchors, all stopped, given to a host on `127.0.0.1`: the
//!   address is printed anyway, names the host (a link holds four boards, and the host must not be
//!   the one dropped), the host says which of the anchors it names have not taken the room, and a
//!   guest on `127.0.0.1` with no anchor gets in.
//! - **C, a guest who can reach only the anchor.** The anchor is stopped; the host on `127.0.0.1`
//!   prints its address at once and says the anchor has not taken the room. While the anchor stays
//!   stopped the host must not say it has. The anchor comes back; the instant the host says it took
//!   the room, a guest on `[::1]` — which can reach the anchor and not the host — joins, and gets in.
//! - **D, a join asks the other routes.** Two anchors: `A4` on `127.0.0.1` only, `A6` on `[::1]`
//!   only. The host on `127.0.0.1` names both, reaches only `A4`, and advertises a port forward on
//!   `[::1]` (`support/port_forward.rs`) that starts **closed**. The guest on `[::1]`, with `A6` as
//!   its anchor, can reach `A6` but not `A4`, and not yet the host, so its board search takes `A6`,
//!   which has nothing for the room. The forward opens [`FORWARD_OPENS`] after the guest first
//!   knocks on it, inside the 30 s a dial is given. Asserted: the join gets in, and its steps say
//!   another board was asked.
//! - **E, an address that would lead nowhere.** No anchor, and a host that knows no address of its
//!   own (`VOX_TEST_ADVERTISE` holds its discovery empty — what a person meets while discovery
//!   waits on a gateway that does not answer, C5). Asserted: no address is printed, the host says
//!   it knows no address of its own, and it stops with a failure.
//!
//! - **F, a board that holds the room but not the host's address** (C7). The host's records are
//!   given a short life (`VOX_TEST_RECORD_TTL_SECS`, 8 s) and the host is frozen (SIGSTOP) until
//!   its address record on the anchor lapses, as a host that slept would leave it; the anchor still
//!   holds the room's genesis and the host's bundle. The guest joins, and the host is resumed
//!   (SIGCONT) a moment later. Asserted: the join gets in, and its steps say it dialled the host at
//!   the link's address rather than polling the board for one.
//!
//! **Every red names which it is** (the decider: a test that cannot tell a broken product from a
//! broken test is not a valid test). `PRODUCT:` — `vox` did the wrong thing, and what it said is
//! quoted; `PRODUCT (staging):` — a `vox` verb the staging runs failed (`vox id`, `vox trust add`,
//! `vox node`), or vox did not reach the state the claim needs (the guest never reached the closed
//! forward, the board still held the host's address). `APPARATUS:` — this proof's own machinery
//! failed. The watchdog (`support/watchdog.rs`) names itself when it fires.
//!
//! **Mutations that must turn it red:** `vox serve` refusing without an anchor or public address
//! (A); minting the address before the host knows an address of its own (E); not counting the
//! host's own board, so a down anchor holds the address back (B, C); capping the link's boards
//! after adding the host (B); saying an anchor took the room before it did (C); stopping the join
//! at the first board's "nothing for room" (D); polling the board for the host's address when the link
//! gives it (F).
//!
//! **Why a file of its own:** no existing proof starts `vox serve` without an anchor or with its
//! anchor down — the old refusal made that impossible — and the join journeys
//! (`a_room_not_on_the_board_is_named_proof`) stage a board without the room only where no other
//! route can hold it, which is the failure this fix keeps.

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

#[path = "support/test_knobs.rs"]
mod test_knobs;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use world::{after_label, args, room_pass_file, vox_once, VoxProc};

/// How long the anchor stays stopped after the host has said it has not taken the room (arm C): the
/// host's chance to claim otherwise.
const HOLD: Duration = Duration::from_secs(3);
/// How long the host may take to make its room and print the address: production Argon2id, in
/// either profile, and address discovery on a wildcard bind.
const ROOM_WITHIN: Duration = Duration::from_secs(300);
/// How long the host may take to say it printed which anchors have not taken the room.
const NOTE_WITHIN: Duration = Duration::from_secs(20);
/// How long the host may take to say the anchor took the room once it is back (arm C): its redial,
/// the connection and the first publish round.
const TAKEN_WITHIN: Duration = Duration::from_secs(120);
/// The watchdog's bound on the whole binary: its four arms took 623 s in debug on 2026-10-01, which
/// is past the default 600 s, so twice that, rounded up.
const BUDGET: Duration = Duration::from_secs(1300);
/// How long the host may take, past making its room, to withhold an address that would lead
/// nowhere and say why (arm E): the node's `ADDRESS_PATIENCE` (30 s), and margin.
const WITHHELD_WITHIN: Duration = Duration::from_secs(60);
/// How long after the guest's first datagram reaches the closed forward it opens (arm D).
const FORWARD_OPENS: Duration = Duration::from_secs(3);

/// An anchor's short id as `vox` prints it: the first 12 characters of its fingerprint.
fn short(spec: &str) -> String {
    spec.split_once('@')
        .map_or("", |(fp, _)| fp)
        .chars()
        .take(12)
        .collect()
}

/// A `vox node` anchor on `listen`, and the `fp@/ip…/udp/port` spec that names it on `family`.
fn anchor_on(dir: &Path, listen: &str, v6: bool) -> (VoxProc, String) {
    std::fs::create_dir_all(dir.join("cfg"))
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a profile directory: {e}"));
    let mut a = VoxProc::spawn("anchor", dir, &args(&["node", "--listen", listen]));
    let spec = line_within(&mut a, Duration::from_secs(180), |l| {
        !l.starts_with("! ")
            && l.trim_start().contains('@')
            && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
    });
    let spec = spec
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT (staging): `vox node` on {listen} printed no --anchor spec, so there is no \
                 world to measure in.\nanchor:\n{}",
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
            "PRODUCT (staging): `vox node`, restarted in the same profile on the same port, printed another spec"
        );
        *self = again;
    }
}

/// A guest and a host with identities, the host trusting the guest. Returns the host's fingerprint.
fn two_identities(guest: &Path, host: &Path) -> String {
    for d in [guest, host] {
        std::fs::create_dir_all(d.join("cfg"))
            .unwrap_or_else(|e| panic!("APPARATUS: could not make a profile directory: {e}"));
    }
    let (ok, guest_fp, err) = vox_once(guest, &args(&["id"]));
    assert!(ok, "PRODUCT (staging): `vox id` (guest) failed: {err}");
    let (ok, host_fp, err) = vox_once(host, &args(&["id"]));
    assert!(ok, "PRODUCT (staging): `vox id` (host) failed: {err}");
    let (ok, out, err) = vox_once(
        host,
        &args(&["trust", "add", guest_fp.trim(), "--name", "the guest"]),
    );
    assert!(
        ok,
        "PRODUCT (staging): `vox trust add` failed: {out}\n{err}"
    );
    host_fp.trim().to_owned()
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

/// Which a red about `host` is: `PRODUCT`, unless the host was killed by a signal — which no
/// proof sends it, so it is the watchdog, past its budget, and nothing about the claim was measured.
fn host_verdict(host: &mut VoxProc) -> String {
    use std::os::unix::process::ExitStatusExt as _;
    match host.child.try_wait() {
        Ok(Some(status)) if status.signal().is_some() => format!(
            "APPARATUS: `vox serve` was killed by signal {:?} (the watchdog, past its budget), so \
             nothing was measured —",
            status.signal()
        ),
        _ => "PRODUCT".to_owned(),
    }
}

/// `vox` run to completion, as [`vox_once`] does, but a run killed by a signal — which no proof
/// sends it, so the watchdog — is an apparatus red, never read as the product refusing.
fn vox_joined(data: &Path, args: &[String]) -> (bool, String, String) {
    use std::os::unix::process::ExitStatusExt as _;
    let out = std::process::Command::new(world::VOX)
        .args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", world::IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not run `vox`: {e}"));
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    );
    assert!(
        out.status.signal().is_none(),
        "APPARATUS: `vox {}` was killed by signal {:?} (the watchdog, past its budget), so its \
         outcome measures nothing.\nstdout:\n{stdout}\nstderr:\n{stderr}",
        args.first().map_or("", String::as_str),
        out.status.signal()
    );
    (out.status.success(), stdout, stderr)
}

/// The passphrase `vox serve` prints right after its address.
fn passphrase_of(host: &mut VoxProc) -> String {
    let line = line_within(host, Duration::from_secs(10), |l| {
        l.starts_with("passphrase ")
    });
    after_label(
        &line.unwrap_or_else(|| {
            panic!(
                "{}: `vox serve` printed its address and no passphrase after it. It said:\n{}",
                host_verdict(host),
                host.transcript()
            )
        }),
        "passphrase",
    )
}

#[test]
#[ignore = "real host and guest, production Argon2id and a real PoW; CI runs it in release"]
fn a_a_host_with_no_anchor_prints_its_address_and_a_guest_joins() {
    watchdog::arm_for(BUDGET);
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a temporary directory: {e}"));
    let (host_dir, guest_dir) = (tmp.path().join("host"), tmp.path().join("guest"));
    let host_fp = two_identities(&guest_dir, &host_dir);
    // No --anchor, no --listen: as a person on a LAN runs it. (`r=` always names the host as the
    // responder; `a=` is the host named as a place to reach the room.)
    let mut host = VoxProc::spawn("host", &host_dir, &args(&["serve", "22"]));
    let address = line_within(&mut host, ROOM_WITHIN, |l| l.starts_with("address "));
    let address = after_label(
        &address.unwrap_or_else(|| {
            panic!(
                "{}: `vox serve` with no anchor printed no address within {ROOM_WITHIN:?}; a \
                 host a guest can reach directly needs none. It said:\n{}",
                host_verdict(&mut host),
                host.transcript()
            )
        }),
        "address",
    );
    let passphrase = passphrase_of(&mut host);
    assert!(
        address.contains(&format!("a={host_fp}")),
        "PRODUCT: the address `vox serve` printed with no anchor does not name the host \
         ({host_fp}), so it names nowhere at all: {address}\nIt said:\n{}",
        host.transcript()
    );
    let t = Instant::now();
    let (joined, out, err) = vox_joined(
        &guest_dir,
        &args(&[
            "connect",
            &address,
            "--passphrase-file",
            &room_pass_file(&guest_dir, &passphrase),
        ]),
    );
    eprintln!(
        "[proof] arm A: no anchor; the guest's join {} after {:.2}s",
        if joined { "got in" } else { "failed" },
        t.elapsed().as_secs_f64()
    );
    assert!(
        joined,
        "PRODUCT: a guest on the host's machine, with no anchor, was refused the address `vox \
         serve` printed. `vox connect` said:\n{out}\n{err}\nhost:\n{}",
        host.transcript()
    );
}

#[test]
#[ignore = "real anchors, host and guest, production Argon2id and a real PoW; CI runs it in release"]
fn b_anchors_that_are_down_do_not_hold_back_the_address() {
    watchdog::arm_for(BUDGET);
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a temporary directory: {e}"));
    let (host_dir, guest_dir) = (tmp.path().join("host"), tmp.path().join("guest"));
    // Four anchors — a link's whole capacity — each started for its identity, then stopped by PID.
    let mut specs = Vec::new();
    for i in 0..4 {
        let (mut a, spec) = anchor_on(&tmp.path().join(format!("a{i}")), "127.0.0.1:0", false);
        let _ = a.child.kill();
        let _ = a.child.wait();
        specs.push(spec);
    }
    let host_fp = two_identities(&guest_dir, &host_dir);
    let mut serve = vec!["serve", "22", "--listen", "127.0.0.1:0"];
    for spec in &specs {
        serve.extend(["--anchor", spec.as_str()]);
    }
    let started = Instant::now();
    let mut host = VoxProc::spawn("host", &host_dir, &args(&serve));
    let address = line_within(&mut host, ROOM_WITHIN, |l| l.starts_with("address "));
    let printed = started.elapsed();
    let address = after_label(
        &address.unwrap_or_else(|| {
            panic!(
                "{}: `vox serve` printed no address while its four anchors were down, \
                 although the address names the host itself, which a guest can reach. It \
                 said:\n{}",
                host_verdict(&mut host),
                host.transcript()
            )
        }),
        "address",
    );
    let passphrase = passphrase_of(&mut host);
    assert!(
        address.contains(&format!("a={host_fp}")),
        "PRODUCT: with four anchors, the address `vox serve` printed does not name the host \
         ({host_fp}) — only anchors, all down: {address}"
    );
    // The host says, of each anchor the address names, that it has not taken the room. (A link
    // holds four boards, and the host is one, so one of the four anchors is left out of it.)
    let shorts: Vec<String> = specs
        .iter()
        .filter(|s| address.contains(s.split_once('@').map_or("-", |(fp, _)| fp)))
        .map(|s| short(s))
        .collect();
    assert!(
        !shorts.is_empty(),
        "PRODUCT: the address `vox serve` printed names none of the four anchors it was given: \
         {address}"
    );
    let _ = line_within(&mut host, NOTE_WITHIN, |l| {
        l.contains("not taken") && shorts.iter().all(|s| l.contains(s.as_str()))
    });
    let verdict = host_verdict(&mut host);
    let said = host.transcript();
    let unnamed: Vec<&String> = shorts
        .iter()
        .filter(|s| {
            !said
                .lines()
                .any(|l| l.contains("not taken") && l.contains(s.as_str()))
        })
        .collect();
    assert!(
        unnamed.is_empty(),
        "{verdict}: `vox serve` printed its address without saying that anchor(s) {unnamed:?} have \
         not taken the room; a guest who cannot reach the host directly must be told. It \
         said:\n{said}"
    );
    let t = Instant::now();
    let (joined, out, err) = vox_joined(
        &guest_dir,
        &args(&[
            "connect",
            &address,
            "--passphrase-file",
            &room_pass_file(&guest_dir, &passphrase),
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    eprintln!(
        "[proof] arm B: four anchors down; the address was printed at +{:.2}s; the guest's join {} \
         after {:.2}s",
        printed.as_secs_f64(),
        if joined { "got in" } else { "failed" },
        t.elapsed().as_secs_f64()
    );
    assert!(
        joined,
        "PRODUCT: a guest who can reach the host directly was refused while the host's anchors \
         were down. `vox connect` said:\n{out}\n{err}\nhost:\n{said}"
    );
}

#[test]
#[ignore = "a real anchor, host and guest, production Argon2id and a real PoW; CI runs it in release"]
fn c_a_guest_who_needs_the_anchor_joins_once_the_host_says_it_took_the_room() {
    watchdog::arm_for(BUDGET);
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a temporary directory: {e}"));
    let (anchor_dir, host_dir, guest_dir) = (
        tmp.path().join("anchor"),
        tmp.path().join("host"),
        tmp.path().join("guest"),
    );
    let mut anchor = DualAnchor::start(&anchor_dir, 0);
    two_identities(&guest_dir, &host_dir);
    let a = short(&anchor.v4_spec);
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
    let address = line_within(&mut host, ROOM_WITHIN, |l| l.starts_with("address "));
    let address = after_label(
        &address.unwrap_or_else(|| {
            panic!(
                "{}: `vox serve` printed no address while its anchor was down, although the \
                 address names the host itself. It said:\n{}",
                host_verdict(&mut host),
                host.transcript()
            )
        }),
        "address",
    );
    let passphrase = passphrase_of(&mut host);
    let taken = |l: &str| l.contains(a.as_str()) && l.contains("has taken");
    let not_yet = line_within(&mut host, NOTE_WITHIN, |l| {
        l.contains(a.as_str()) && l.contains("not taken")
    });
    assert!(
        not_yet.is_some(),
        "{}: `vox serve` printed its address without saying that anchor {a}, which was \
         down, has not taken the room. It said:\n{}",
        host_verdict(&mut host),
        host.transcript()
    );
    // While the anchor stays stopped, the host must not say it took the room.
    let early = line_within(&mut host, HOLD, taken);
    let back_from = started.elapsed();
    assert!(
        early.is_none(),
        "PRODUCT: `vox serve` said anchor {a} took the room while it was stopped (until +{:.2}s): \
         {early:?}. It said:\n{}",
        back_from.as_secs_f64(),
        host.transcript()
    );
    anchor.restart(&anchor_dir);
    let back = started.elapsed();
    let said_taken = line_within(&mut host, TAKEN_WITHIN, taken);
    let told = started.elapsed();
    assert!(
        said_taken.is_some(),
        "{}: anchor {a} came back at +{:.2}s and `vox serve` never said it took the room \
         within {TAKEN_WITHIN:?}. It said:\n{}",
        host_verdict(&mut host),
        back.as_secs_f64(),
        host.transcript()
    );
    // At once, as a person told "it can be joined through the anchor now" would.
    let t = Instant::now();
    let (joined, out, err) = vox_joined(
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
        "[proof] arm C: the anchor was stopped until +{:.2}s; the host said it took the room at \
         +{:.2}s; the guest's join {} after {:.2}s",
        back.as_secs_f64(),
        told.as_secs_f64(),
        if joined { "got in" } else { "failed" },
        t.elapsed().as_secs_f64()
    );
    assert!(
        joined,
        "PRODUCT: a guest who can reach only the anchor was refused the instant the host said the \
         anchor took the room. `vox connect` said:\n{out}\n{err}\nhost:\n{}",
        host.transcript()
    );
}

#[test]
#[ignore = "real anchors, host and guest, production Argon2id and a real PoW; CI runs it in release"]
fn d_a_join_asks_every_board_the_address_names() {
    test_knobs::require(&["VOX_TEST_ADVERTISE"]);
    watchdog::arm_for(BUDGET);
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a temporary directory: {e}"));
    let (a4_dir, a6_dir, host_dir, guest_dir) = (
        tmp.path().join("a4"),
        tmp.path().join("a6"),
        tmp.path().join("host"),
        tmp.path().join("guest"),
    );
    let (_a4, a4_spec) = anchor_on(&a4_dir, "127.0.0.1:0", false);
    let (_a6, a6_spec) = anchor_on(&a6_dir, "[::1]:0", true);
    two_identities(&guest_dir, &host_dir);
    // A guest on [::1] can reach A6 and the forward; A4 and the host's own addresses are IPv4.
    let host_port = port_forward::free_v4_udp_port();
    let host_addr: SocketAddr = format!("127.0.0.1:{host_port}")
        .parse()
        .expect("APPARATUS: a socket address the proof wrote");
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
    // The host's own route (the forward) is in the address, so it is printed at once.
    let address = line_within(&mut host, ROOM_WITHIN, |l| l.starts_with("address "));
    let address = after_label(
        &address.unwrap_or_else(|| {
            panic!(
                "{}: `vox serve` printed no address within {ROOM_WITHIN:?}, with its anchor A4 \
                 up the whole time. It said:\n{}",
                host_verdict(&mut host),
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
    let join = std::thread::spawn(move || vox_joined(&guest, &join_args));
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
    let (joined, out, err) = join.join().unwrap_or_else(|e| {
        let said = e
            .downcast_ref::<String>()
            .cloned()
            .unwrap_or_else(|| "APPARATUS: the thread running `vox connect` panicked".to_owned());
        panic!("{said}")
    });
    let steps: Vec<&str> = err.lines().filter(|l| l.contains("join ")).collect();
    eprintln!(
        "[proof] arm D: the guest {} the closed forward; the guest's join {} after {:.2}s; its \
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
        "PRODUCT (staging): the guest's join never sent the host's (closed) forward a \
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
        "PRODUCT (staging): the join got in, but its steps do not say another board \
         was asked, so the first board it took held the room and the fallback was never needed \
         (the forward was closed for {FORWARD_OPENS:?} after the guest first knocked). `vox \
         connect` said:\n{err}"
    );
}

#[test]
#[ignore = "a real host, production Argon2id; CI runs it in release"]
fn e_an_address_that_would_lead_nowhere_is_withheld_and_why_is_said() {
    test_knobs::require(&["VOX_TEST_ADVERTISE"]);
    watchdog::arm_for(BUDGET);
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a temporary directory: {e}"));
    let (host_dir, guest_dir) = (tmp.path().join("host"), tmp.path().join("guest"));
    let host_fp = two_identities(&guest_dir, &host_dir);
    // No anchor, and an address discovery that never finds an address of the host's own. A person
    // meets this while discovery is still waiting on a gateway that does not answer (C5); that
    // cannot be staged here without root, so `VOX_TEST_ADVERTISE` (which no address parses from)
    // stands in for it, holding the host to no address of its own for the whole run.
    let mut host = VoxProc::spawn_env(
        "host",
        &host_dir,
        &args(&["serve", "22"]),
        &[("VOX_TEST_ADVERTISE", "none")],
    );
    let said = line_within(&mut host, ROOM_WITHIN + WITHHELD_WITHIN, |l| {
        l.starts_with("address ") || l.contains("knows no address of its own")
    });
    let Some(said) = said else {
        panic!(
            "{}: `vox serve`, knowing no address of its own and given no anchor, neither printed \
             an address nor said why it withheld one within {:?}. It said:\n{}",
            host_verdict(&mut host),
            ROOM_WITHIN + WITHHELD_WITHIN,
            host.transcript()
        );
    };
    if said.starts_with("address ") {
        let address = after_label(&said, "address");
        assert!(
            !address.contains(&format!("a={host_fp}")),
            "PRODUCT (staging): the address names the host as a route, so it knew \
             an address of its own (`VOX_TEST_ADVERTISE` had no effect): {address}"
        );
        panic!(
            "PRODUCT: `vox serve` printed an address that names no route at all — no address of \
             the host's own and no anchor — which a guest cannot use: {address}\nIt said:\n{}",
            host.transcript()
        );
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Ok(Some(status)) = host.child.try_wait() {
            break Some(status);
        }
        if Instant::now() > deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    eprintln!("[proof] arm E: the host withheld its address and exited {status:?}");
    let said_all = host.transcript();
    assert!(
        said_all.contains("names no anchor") && !said_all.contains("the anchor could not be reached"),
        "PRODUCT: `vox serve` was given no anchor, and its reason for withholding the address must \
         say it names none rather than blame an anchor (an anchor bridges hosts that cannot \
         otherwise find each other; nothing else needs one). It said:\n{said_all}"
    );
    assert!(
        status.is_some_and(|s| !s.success()),
        "PRODUCT: `vox serve` said it withheld the address ({said}) but did not stop with a \
         failure ({status:?}): a host that hands out nothing must not look like it serves.\nIt \
         said:\n{}",
        host.transcript()
    );
}

/// Send `signal` (`STOP` or `CONT`) to `pid`, as `kill -<signal>` does.
fn signal(pid: u32, signal: &str) {
    let ok = std::process::Command::new("kill")
        .args([format!("-{signal}"), pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(
        ok,
        "APPARATUS: could not send SIG{signal} to the host ({pid})"
    );
}

#[test]
#[ignore = "a real anchor, host and guest, production Argon2id and a real PoW; CI runs it in release"]
fn f_a_join_dials_the_host_at_the_links_address_when_the_board_has_none() {
    test_knobs::require(&["VOX_TEST_RECORD_TTL_SECS"]);
    watchdog::arm_for(BUDGET);
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a temporary directory: {e}"));
    let (anchor_dir, host_dir, guest_dir) = (
        tmp.path().join("anchor"),
        tmp.path().join("host"),
        tmp.path().join("guest"),
    );
    let (_anchor, anchor_spec) = anchor_on(&anchor_dir, "127.0.0.1:0", false);
    two_identities(&guest_dir, &host_dir);
    let mut host = VoxProc::spawn_env(
        "host",
        &host_dir,
        &args(&[
            "serve",
            "22",
            "--anchor",
            &anchor_spec,
            "--listen",
            "127.0.0.1:0",
        ]),
        &[("VOX_TEST_RECORD_TTL_SECS", "8")],
    );
    let address = line_within(&mut host, ROOM_WITHIN, |l| l.starts_with("address "));
    let address = after_label(
        &address.unwrap_or_else(|| {
            panic!(
                "{}: `vox serve` printed no address within {ROOM_WITHIN:?}. It said:\n{}",
                host_verdict(&mut host),
                host.transcript()
            )
        }),
        "address",
    );
    let passphrase = passphrase_of(&mut host);
    // The anchor takes the room — genesis, the host's bundle and its address record.
    std::thread::sleep(Duration::from_secs(3));
    let t_unlock = Instant::now();
    let (ok, _, err) = vox_once(&guest_dir, &args(&["id"]));
    assert!(ok, "PRODUCT (staging): `vox id` (guest) failed: {err}");
    let unlock = t_unlock.elapsed();
    let pid = host.child.id();
    signal(pid, "STOP");
    // Past the record's 8 s life from its last renewal: the anchor's board holds no address for
    // the host, and still holds the room.
    std::thread::sleep(Duration::from_secs(11));
    let guest = {
        let (dir, address, pass) = (
            guest_dir.clone(),
            address.clone(),
            room_pass_file(&guest_dir, &passphrase),
        );
        std::thread::spawn(move || {
            vox_joined(
                &dir,
                &args(&[
                    "connect",
                    &address,
                    "--passphrase-file",
                    &pass,
                    "--listen",
                    "127.0.0.1:0",
                ]),
            )
        })
    };
    // Resumed once the guest has read the board: after its identity unlock (production Argon2id,
    // timed on the guest's own `vox id` below, which unlocks the same way) and a margin. Resumed
    // earlier, the host republishes its address before the guest reads the board, and the staging
    // is lost (seen in debug, where the unlock takes 10 s and more). Its dial to the frozen host
    // waits up to the 30 s a dial is given, so a later resume costs nothing but time.
    std::thread::sleep(unlock.mul_f64(1.5) + Duration::from_millis(2500));
    signal(pid, "CONT");
    let t = Instant::now();
    let (joined, out, err) = guest
        .join()
        .unwrap_or_else(|_| panic!("APPARATUS: the guest's `vox connect` thread panicked"));
    let steps: Vec<&str> = err.lines().filter(|l| l.contains("join got in")).collect();
    eprintln!(
        "[proof] arm F: the host was frozen {:.1}s (the guest's unlock takes {:.1}s); the guest's \
         join {} {:.2}s after it resumed; its steps: {steps:?}",
        11.0 + unlock.mul_f64(1.5).as_secs_f64() + 2.5,
        unlock.as_secs_f64(),
        if joined { "got in" } else { "failed" },
        t.elapsed().as_secs_f64()
    );
    assert!(
        joined,
        "PRODUCT: the guest was refused although the link names the host's address and the host \
         was back. `vox connect` said:\n{out}\n{err}\nhost:\n{}",
        host.transcript()
    );
    assert!(
        !err.contains("address poll"),
        "PRODUCT: the join polled the board for the host's address although the link gives it, \
         and dialled the host only once the board had one again. `vox connect` said:\n{err}"
    );
    assert!(
        err.contains("the link's address"),
        "PRODUCT (staging): the join neither polled the board nor dialled the \
         link's address, so the board it used still held the host's address (or was the host). \
         `vox connect` said:\n{err}"
    );
}
