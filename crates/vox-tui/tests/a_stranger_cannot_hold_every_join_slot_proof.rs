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
//! at once. The strangers are all on 127.0.0.1, **one address**.
//!
//! 1. `one_identity_holding_every_slot_does_not_keep_a_joiner_out`: one stranger identity joins 16
//!    of alice's rooms at once, then keeps joining a 17th, over and over, for as long as carol's
//!    join runs.
//! 2. `a_handful_of_identities_holding_every_slot_do_not_keep_a_joiner_out`: four stranger
//!    identities join 4 rooms each, and one of them keeps joining a 5th.
//!
//!    In these two, carol is on 127.0.0.1 too, so what sets her apart is her identity.
//! 3. `one_address_holding_every_slot_does_not_keep_a_joiner_from_another_out`: sixteen stranger
//!    identities join one room once each, so by identity every hold weighs what carol's does; and
//!    carol joins from **::1**, a second source address on the same machine, no sudo needed. Alice
//!    and the anchor listen on both families (`[::]`), and alice advertises exactly `[::1]` and
//!    `127.0.0.1` (`VOX_TEST_ADVERTISE`, inert when unset), so no third address of this machine's
//!    comes into it. Only the address tells carol from the flood. The product keys an IPv4 source
//!    by its address (an IPv4-mapped one canonicalised first) and an IPv6 one by its /64, so
//!    `127.0.0.1` and `::1` are two sources.
//!
//!
//!    No joiner may have asked for a circuit (each one's own `vox status --json`), so no join
//!    measured here rode a relay; otherwise CANNOT MEASURE.
//! 4. `a_relayed_flood_from_one_host_does_not_keep_a_relayed_joiner_from_another_out`: as 3, but
//!    **every join relayed** by the one anchor (see `Layout::Relayed`: alice listens on the LAN
//!    address and the joiners on loopback, so neither a dial nor a hole punch reaches her). The
//!    sixteen stranger identities are relayed from 127.0.0.1, carol from ::1. Each joiner's own
//!    `vox status --json` must show it asked for a circuit, else CANNOT MEASURE.
//!    Only the origin the relay says tells carol from the flood: a relayed join's circuit address
//!    is made up per circuit and says nothing.
//!
//!    **What no proof here can show, and no fix could:** a joiner on the attacker's own host, under
//!    its address, cannot be told apart from the attacker's joins. Sixteen identities and carol all
//!    relayed from one host weigh the same, and carol is refused as one more of them would be.
//! 5. `a_join_ended_for_another_is_told_the_member_is_busy`: one stranger identity holds all
//!    sixteen slots with joins that grind for 45s; carol's join makes alice end one of them
//!    (`ended …` on alice's stderr, else CANNOT MEASURE). Every join of the stranger's that alice
//!    ended must say the member is busy answering other joins, and none may say the passphrase is
//!    wrong. An ended joiner reads that once its own grind is done, which is why the grind is
//!    bounded here and not an hour.
//! 6. `joins_that_did_their_work_and_went_quiet_give_their_slots_back`: the stranger's sixteen
//!    joins each **do their proof of work** and then go quiet (`VOX_TEST_STALL_AFTER_SOLVE_MS`, the
//!    product's test-only knob beside `VOX_TEST_SOLVE_AT_LEAST_MS`, inert when unset; its daemon
//!    says `solved, now silent` for each, and all sixteen must, else CANNOT MEASURE). A hold that
//!    has done its work is never ended for a newcomer, so carol's first try is turned away as
//!    busy and alice ends nothing; carol tries again every 3s, as a person told to would, and
//!    must be in within the member's 60s admission patience plus the join bound, once those holds
//!    have been given up on.
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
//! **And a joiner turned away at the cap is told so.** Every one of the stranger's joins that alice
//! turns away while its slots are held (it is the heaviest source, so it is refused) must say the
//! member is busy answering other joins, and none may say the room passphrase is wrong: that is
//! what a bare refusal said, and it sent a person looking for a typo. So that some certainly are,
//! the stranger goes on joining after carol's join until alice has turned it away three more
//! times; not within 120s is CANNOT MEASURE.
//!
//! **The mutations that must turn it red.**
//! - `JoinSlots::take` refusing every newcomer once the cap is reached (first come, first served,
//!   as before): carol is refused and her join fails, in every case.
//! - The cap's refusal sent as the bare `JoinReject::Refused` again: carol still gets in, and the
//!   stranger's refused joins are told `usually the room passphrase is wrong`, in every case.
//! - Holds weighed by identity alone, the address dropped: case 3 red, carol ties with every hold
//!   and is refused; cases 1 and 2 stay green, since they turn on the identity.
//! - A relayed join's origin ignored, every circuit one source: case 4 red.
//! - The identity ignored: cases 1 and 2 red.
//! - An ended join stopped without a word, or told the bare refusal: case 5 red.
//! - A hold that has done its work ended like any other: case 6 red, alice ends one for carol.
//! - No admission patience, so a join that did its work may stay quiet for ever: case 6 red,
//!   carol is still kept out at the bound.

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
/// Between the stranger's arrivals. Each is a `vox room join` process; at 0.2s the unoptimized
/// build spent more on the stranger's processes than on carol's grind (one debug run: 288 arrivals,
/// carol in 412s).
const CHURN_PAUSE: Duration = Duration::from_secs(1);
/// How long after carol's join the stranger's refused joins are given to have said so.
const TOLD_GRACE: Duration = Duration::from_secs(5);
/// How many more times the stranger is to be turned away after carol's join.
const PROBES: usize = 3;
/// How long that may take.
const PROBE_PATIENCE: Duration = Duration::from_secs(120);
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

    /// `vox room join <link>` left running: a stranger's join, which never finishes. What it says,
    /// if it does end, goes to `said`.
    fn join_in_background(&self, link: &str, name: &str, said: Option<&Path>) -> Proc {
        let to = || match said {
            Some(p) => Stdio::from(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .unwrap(),
            ),
            None => Stdio::null(),
        };
        let mut child = self
            .command(&["room", "join", link, "--name", name])
            .stdin(Stdio::piped())
            .stdout(to())
            .stderr(to())
            .spawn()
            .expect("spawn vox room join");
        let mut pipe = child.stdin.take().unwrap();
        pipe.write_all(ROOM_PASS.as_bytes()).unwrap();
        drop(pipe);
        Proc(child)
    }

    /// `vox daemon` for this profile, stderr to `err`, answering on its socket before this returns.
    fn daemon(&self, anchor: &str, listen: &str, err: &Path, env: &[(&str, String)]) -> Proc {
        let mut cmd = Command::new(VOX);
        cmd.args(["daemon", "--listen", listen, "--anchor", anchor])
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

/// Where everyone listens, so what source each join reaches alice from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layout {
    /// Everyone on 127.0.0.1: one address, so only identity tells carol from the stranger.
    OneAddress,
    /// Alice and the anchor on both families (`[::]`), alice advertising exactly `[::1]` and
    /// `127.0.0.1` (`VOX_TEST_ADVERTISE`, inert when unset); the strangers on 127.0.0.1 and carol on
    /// ::1. Two sources, every join direct: the anchor must carry no circuit.
    TwoAddresses,
    /// Every join **relayed** by the one anchor, from two origins. Alice listens on this machine's
    /// LAN address (the one it would send off-machine from), which reaches the anchor on `[::]`; the
    /// strangers listen on 127.0.0.1 and carol on `[::1]`. A loopback-bound node can neither dial
    /// nor punch to a LAN address, so every join reaches alice over the anchor's circuit, and the
    /// anchor sees the strangers at 127.0.0.1 and carol at ::1. No sudo; no LAN address is
    /// CANNOT MEASURE. (A link-local `fe80::1%lo0` would be a third loopback source, but the
    /// transport does not keep an IPv6 scope, so an anchor cannot answer it.)
    Relayed,
}

struct Staged {
    dir: PathBuf,
    layout: Layout,
    anchor_out: PathBuf,
    _anchor: Proc,
    _daemons: Vec<Proc>,
    carol: Who,
    strangers: Vec<Who>,
    stranger_errs: Vec<PathBuf>,
    alice_err: PathBuf,
    /// One invite link per room of alice's.
    links: Vec<String>,
}

/// An anchor; alice's daemon with `rooms` rooms; carol's daemon; and `strangers` stranger daemons,
/// each with `stranger_env` (by default a grind of an hour on any join), placed as `layout` says.
fn stage(
    tmp: &Path,
    rooms: usize,
    strangers: usize,
    layout: Layout,
    stranger_env: &[(&'static str, String)],
) -> Staged {
    let anchor_who = Who::new(tmp, "anchor");
    let out = tmp.join("anchor.out");
    let anchor = Proc(
        Command::new(VOX)
            .args([
                "node",
                "--listen",
                if layout == Layout::OneAddress {
                    "127.0.0.1:0"
                } else {
                    "[::]:0"
                },
            ])
            .env("VOX_DATA_DIR", &anchor_who.data)
            .env("VOX_CONFIG_DIR", &anchor_who.cfg)
            .stdout(Stdio::from(std::fs::File::create(&out).unwrap()))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vox node"),
    );
    let started = Instant::now();
    let (fp, port) = loop {
        let text = std::fs::read_to_string(&out).unwrap_or_default();
        if let Some((fp, port)) = text
            .split_whitespace()
            .find(|w| w.contains("@/ip") && w.contains("/udp/"))
            .and_then(|w| w.split_once('@'))
            .and_then(|(fp, addr)| Some((fp.to_owned(), addr.rsplit('/').next()?.to_owned())))
        {
            break (fp, port);
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
    let v4_spec = format!("{fp}@/ip4/127.0.0.1/udp/{port}");
    let v6_spec = format!("{fp}@/ip6/::1/udp/{port}");
    // Alice on both families, advertising exactly her two loopback addresses: what the ladder
    // would add (this machine's LAN addresses) would be a third source nobody here chose.
    let lan = lan_v4();
    let lan_spec = lan.map(|ip| format!("{fp}@/ip4/{ip}/udp/{port}"));
    let (alice_listen, alice_spec, alice_env) = match layout {
        Layout::OneAddress => ("127.0.0.1:0".to_owned(), &v4_spec, Vec::new()),
        Layout::TwoAddresses => {
            let port = std::net::UdpSocket::bind("[::]:0")
                .and_then(|s| s.local_addr())
                .expect("a free port")
                .port();
            (
                format!("[::]:{port}"),
                &v4_spec,
                vec![(
                    "VOX_TEST_ADVERTISE",
                    format!("[::1]:{port},127.0.0.1:{port}"),
                )],
            )
        }
        Layout::Relayed => match (lan, &lan_spec) {
            (Some(ip), Some(spec)) => (format!("{ip}:0"), spec, Vec::new()),
            _ => panic!("CANNOT MEASURE: this machine has no LAN IPv4 address to put alice on"),
        },
    };
    let (carol_listen, carol_spec) = match layout {
        Layout::OneAddress => ("127.0.0.1:0", &v4_spec),
        Layout::TwoAddresses => ("[::1]:0", &v6_spec),
        Layout::Relayed => ("[::1]:0", &v6_spec),
    };
    let (stranger_listen, stranger_spec) = ("127.0.0.1:0", &v4_spec);
    let alice_err = tmp.join("alice.daemon.err");
    // Identities and daemons four at a time: each is production Argon2id at 256 MiB or more.
    let everyone: Vec<&Who> = [&alice, &carol].into_iter().chain(&strangers).collect();
    for batch in everyone.chunks(4) {
        std::thread::scope(|sc| {
            let ids: Vec<_> = batch
                .iter()
                .map(|&w| sc.spawn(move || w.vox(&["id"], None)))
                .collect();
            for id in ids {
                let (ok, out, err) = id.join().unwrap();
                assert!(ok, "CANNOT MEASURE: vox id failed: {out}{err}");
            }
        });
    }
    let mut daemons = vec![
        alice.daemon(alice_spec, &alice_listen, &alice_err, &alice_env),
        carol.daemon(carol_spec, carol_listen, &tmp.join("carol.daemon.err"), &[]),
    ];
    let numbered: Vec<(usize, &Who)> = strangers.iter().enumerate().collect();
    for batch in numbered.chunks(4) {
        let started: Vec<Proc> = std::thread::scope(|sc| {
            let running: Vec<_> = batch
                .iter()
                .map(|&(i, s)| {
                    let spec = stranger_spec;
                    sc.spawn(move || {
                        s.daemon(
                            spec,
                            stranger_listen,
                            &tmp.join(format!("stranger{i}.daemon.err")),
                            stranger_env,
                        )
                    })
                })
                .collect();
            running.into_iter().map(|d| d.join().unwrap()).collect()
        });
        daemons.extend(started);
    }
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
    let stranger_errs = (0..strangers.len())
        .map(|i| tmp.join(format!("stranger{i}.daemon.err")))
        .collect();
    Staged {
        dir: tmp.to_path_buf(),
        layout,
        anchor_out: out,
        _anchor: anchor,
        _daemons: daemons,
        carol,
        strangers,
        stranger_errs,
        alice_err,
        links,
    }
}

/// This machine's LAN IPv4 address: the one a socket would send off-machine from. Connecting a UDP
/// socket sends nothing; 192.0.2.1 is a documentation address, never reached.
fn lan_v4() -> Option<std::net::Ipv4Addr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    match s.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => Some(ip),
        _ => None,
    }
}

/// The stranger's default: every join grinds for an hour.
fn never() -> Vec<(&'static str, String)> {
    vec![("VOX_TEST_SOLVE_AT_LEAST_MS", NEVER_MS.to_string())]
}

/// The most circuits the anchor ever reported carrying at once, and how many reports it printed.
/// It reports on every change (`vox node: … N circuit(s) carried …`).
fn anchor_circuits(s: &Staged) -> (usize, usize) {
    let text = std::fs::read_to_string(&s.anchor_out).unwrap_or_default();
    let mut max = 0;
    let mut reports = 0;
    for l in text.lines() {
        if let Some((_, after)) = l
            .strip_prefix("vox node: ")
            .and_then(|r| r.split_once(" peer(s) connected, "))
        {
            if let Some(n) = after.split_whitespace().next().and_then(|n| n.parse().ok()) {
                reports += 1;
                max = max.max(n);
            }
        }
    }
    (max, reports)
}

/// How many circuits `who`'s node has asked a relay for, to any peer (`vox status --json`,
/// `reach[].circuits`).
fn circuits_asked(who: &Who) -> u64 {
    let (ok, out, err) = who.vox(&["status", "--json"], None);
    assert!(ok, "CANNOT MEASURE: vox status --json failed: {err}");
    let v: serde_json::Value = serde_json::from_str(out.trim())
        .unwrap_or_else(|e| panic!("CANNOT MEASURE: status is not JSON ({e}): {out}"));
    v["reach"]
        .as_array()
        .unwrap_or_else(|| panic!("CANNOT MEASURE: status has no reach: {out}"))
        .iter()
        .map(|r| r["circuits"].as_u64().unwrap_or(0))
        .sum()
}

/// What the path every join took says about the case, read from each joiner's own node: none
/// relayed in [`Layout::TwoAddresses`] (else the address dimension is not what was measured), every
/// one relayed in [`Layout::Relayed`]. `Err` is CANNOT MEASURE, returned rather than raised so the
/// caller can stop the stranger first.
fn paths(s: &Staged, case: &str) -> Result<(), String> {
    let carol = circuits_asked(&s.carol);
    let strangers: Vec<u64> = s.strangers.iter().map(circuits_asked).collect();
    let (max, reports) = anchor_circuits(s);
    eprintln!(
        "[proof] {} {case}: circuits asked for — carol {carol}, the strangers {strangers:?}; the \
         anchor carried at most {max} at once ({reports} reports)",
        profile()
    );
    match s.layout {
        Layout::TwoAddresses if carol > 0 || strangers.iter().any(|&n| n > 0) => Err(format!(
            "CANNOT MEASURE: {case}: some join was relayed (carol {carol}, strangers \
             {strangers:?}), not from the address measured"
        )),
        Layout::Relayed if carol == 0 || strangers.iter().any(|&n| n == 0) => Err(format!(
            "CANNOT MEASURE: {case}: not every join was relayed (carol {carol}, strangers \
             {strangers:?})"
        )),
        _ => Ok(()),
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

/// Fill alice's slots with `holds` (stranger, room) joins, then keep `churner` joining its rooms,
/// `churn_room` and the last room until carol's join is done and it has been turned away
/// [`PROBES`] more times; assert carol gets in, and that each time it was turned away it was told
/// why.
fn run(s: &Staged, holds: &[(usize, usize)], churner: usize, churn_room: usize, case: &str) {
    let mut held: Vec<Proc> = holds
        .iter()
        .map(|&(who, room)| {
            s.strangers[who].join_in_background(&s.links[room], &format!("s{room}"), None)
        })
        .collect();

    let done = AtomicBool::new(false);
    let churned = AtomicUsize::new(0);
    // A churning join that did not come back within `ARRIVAL` is holding a slot: kept, and killed
    // with the rest at the end.
    let kept = std::sync::Mutex::new(Vec::<Proc>::new());
    // Where each of the stranger's churning joins wrote what it was told.
    let said_to = std::sync::Mutex::new(Vec::<PathBuf>::new());
    let rooms: Vec<usize> = holds
        .iter()
        .filter(|&&(who, _)| who == churner)
        .map(|&(_, room)| room)
        .chain([churn_room, s.links.len() - 1])
        .collect();
    // Set once carol's join has ended; from then on the joins alice turns away are counted, and
    // the stranger goes on until it has been turned away `PROBES` times more.
    let carol_done = AtomicBool::new(false);
    let turned_after = AtomicUsize::new(0);
    std::thread::scope(|sc| {
        // The stranger keeps arriving, before and during carol's join: each of its joins is one
        // more that wants a slot. It goes round its rooms, so a room whose join alice ended or
        // refused is joined again.
        sc.spawn(|| {
            for &room in rooms.iter().cycle() {
                if done.load(Ordering::SeqCst) {
                    break;
                }
                let n = churned.fetch_add(1, Ordering::SeqCst);
                let said = s.dir.join(format!("churn-{case}-{n}.out"));
                let mut join =
                    s.strangers[churner].join_in_background(&s.links[room], "churn", Some(&said));
                let sent = Instant::now();
                while join.0.try_wait().ok().flatten().is_none() && sent.elapsed() < ARRIVAL {
                    std::thread::sleep(Duration::from_millis(100));
                }
                // Still running: holding a slot, or still being turned away. Either way it is
                // kept, and what it said is read at the end.
                if join.0.try_wait().ok().flatten().is_none() {
                    kept.lock().unwrap().push(join);
                } else if carol_done.load(Ordering::SeqCst)
                    && std::fs::read_to_string(&said)
                        .unwrap_or_default()
                        .contains("a member answered")
                {
                    turned_after.fetch_add(1, Ordering::SeqCst);
                }
                said_to.lock().unwrap().push(said);
                std::thread::sleep(CHURN_PAUSE);
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
        eprintln!(
            "[proof] {} {case}: carol's join ok={ok} in {:.1}s: {}",
            profile(),
            took.as_secs_f64(),
            format!("{out}{err}").replace('\n', " / ")
        );
        if let Err(cannot) = paths(s, case) {
            done.store(true, Ordering::SeqCst);
            panic!("{cannot}");
        }
        // So the claim below does not rest on how often the stranger happened to arrive while
        // carol joined, it goes on until alice has turned it away `PROBES` more times.
        carol_done.store(true, Ordering::SeqCst);
        let probing = Instant::now();
        while turned_after.load(Ordering::SeqCst) < PROBES {
            if probing.elapsed() >= PROBE_PATIENCE {
                done.store(true, Ordering::SeqCst);
                panic!(
                    "CANNOT MEASURE: {case}: alice turned the stranger away {} times in {}s after \
                     carol's join, not {PROBES}",
                    turned_after.load(Ordering::SeqCst),
                    PROBE_PATIENCE.as_secs()
                );
            }
            std::thread::sleep(Duration::from_millis(250));
        }
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
    // A joiner turned away at the cap is told that, and not that its passphrase is wrong. Read
    // after a grace, so a refusal that took longer than `ARRIVAL` to be reported is counted too;
    // a join that is still holding a slot has said nothing. Only a refusal by alice herself is
    // counted: a join this daemon would not start (the room already being joined) never reached her.
    let said_to = said_to.into_inner().unwrap();
    std::thread::sleep(TOLD_GRACE);
    let turned_away: Vec<String> = said_to
        .iter()
        .map(|p| std::fs::read_to_string(p).unwrap_or_default())
        .filter(|t| t.contains("a member answered"))
        .collect();
    let blamed = turned_away
        .iter()
        .filter(|t| t.contains("passphrase is wrong"))
        .count();
    let busy = turned_away
        .iter()
        .filter(|t| t.contains("busy answering other joins") && !t.contains("passphrase is wrong"))
        .count();
    eprintln!(
        "[proof] {} {case}: the stranger was turned away {} times: {busy} told the member was busy, \
         {blamed} told the passphrase was wrong",
        profile(),
        turned_away.len()
    );
    assert!(
        !turned_away.is_empty(),
        "CANNOT MEASURE: {case}: none of the stranger's joins was turned away by alice"
    );
    assert!(
        busy == turned_away.len(),
        "{case}: a joiner turned away at the join-slot cap was not told the member was busy \
         ({busy} of {}), {blamed} were told the passphrase was wrong:\n{}",
        turned_away.len(),
        turned_away.join("\n---\n")
    );
    held.clear();
    kept.lock().unwrap().clear();
    eprintln!(
        "[proof] {} {case}: 1/1 got in; {busy}/{} turned away at the cap were told why",
        profile(),
        turned_away.len()
    );
}

#[test]
#[ignore = "sixteen joins that never finish, production Argon2id and a real anchor; CI runs it in release"]
fn one_identity_holding_every_slot_does_not_keep_a_joiner_out() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    // Rooms 0–15 are held; 16 and 17 are two more the stranger keeps arriving for.
    let s = stage(tmp.path(), SLOTS + 2, 1, Layout::OneAddress, &never());
    let holds: Vec<(usize, usize)> = (0..SLOTS).map(|room| (0, room)).collect();
    run(&s, &holds, 0, SLOTS, "one identity");
}

#[test]
#[ignore = "sixteen joins that never finish, production Argon2id and a real anchor; CI runs it in release"]
fn a_handful_of_identities_holding_every_slot_do_not_keep_a_joiner_out() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    // Four identities hold four rooms each; rooms 4 and 5 are two more the first keeps arriving
    // for.
    let s = stage(tmp.path(), 6, 4, Layout::OneAddress, &never());
    let holds: Vec<(usize, usize)> = (0..4)
        .flat_map(|who| (0..4).map(move |room| (who, room)))
        .collect();
    run(&s, &holds, 0, 4, "four identities");
}

#[test]
#[ignore = "sixteen joins that never finish, production Argon2id and a real anchor; CI runs it in release"]
fn one_address_holding_every_slot_does_not_keep_a_joiner_from_another_out() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    // Sixteen identities on 127.0.0.1 hold one slot each, of room 0, so by identity every hold
    // weighs what carol's does: only the address tells them apart. Carol joins from ::1. Rooms 1
    // and 2 are the ones the first stranger keeps arriving for.
    let s = stage(tmp.path(), 3, SLOTS, Layout::TwoAddresses, &never());
    let holds: Vec<(usize, usize)> = (0..SLOTS).map(|who| (who, 0)).collect();
    run(&s, &holds, 0, 1, "one address");
}

#[test]
#[ignore = "sixteen joins that never finish, production Argon2id and a real anchor; CI runs it in release"]
fn a_relayed_flood_from_one_host_does_not_keep_a_relayed_joiner_from_another_out() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    // Sixteen stranger identities, every one of their joins relayed by the anchor from one host,
    // hold one slot each of room 0; carol's join is relayed by the same anchor from another
    // origin. Only the origin the relay says tells her from the flood.
    let s = stage(tmp.path(), 3, SLOTS, Layout::Relayed, &never());
    let holds: Vec<(usize, usize)> = (0..SLOTS).map(|who| (who, 0)).collect();
    run(&s, &holds, 0, 1, "relayed");
}

/// The stranger's grind in [`a_join_ended_for_another_is_told_the_member_is_busy`]: long enough that
/// every one of its joins is still holding a slot when carol arrives, and short enough that the one
/// alice ends hears why within the proof — an ended joiner reads the member's answer once its own
/// grind is done.
const ENDED_GRIND_MS: u64 = 45_000;
/// How long the stranger's joins have to be in flight before carol arrives.
const HOLD_SETTLE: Duration = Duration::from_secs(10);
/// How long after carol's join the stranger's joins have to say how they ended.
const ENDED_TELL_PATIENCE: Duration = Duration::from_secs(180);

#[test]
#[ignore = "sixteen slow joins, production Argon2id and a real anchor; CI runs it in release"]
fn a_join_ended_for_another_is_told_the_member_is_busy() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let s = stage(
        tmp.path(),
        SLOTS + 1,
        1,
        Layout::OneAddress,
        &[("VOX_TEST_SOLVE_AT_LEAST_MS", ENDED_GRIND_MS.to_string())],
    );
    let said: Vec<PathBuf> = (0..SLOTS)
        .map(|room| s.dir.join(format!("held-{room}.out")))
        .collect();
    let mut held: Vec<Proc> = (0..SLOTS)
        .map(|room| {
            s.strangers[0].join_in_background(
                &s.links[room],
                &format!("s{room}"),
                Some(&said[room]),
            )
        })
        .collect();
    std::thread::sleep(HOLD_SETTLE);
    let t = Instant::now();
    let (ok, out, err) = s.carol.vox(
        &["room", "join", &s.links[SLOTS], "--name", "real"],
        Some(ROOM_PASS),
    );
    let took = t.elapsed();
    let (refused, ended, text) = alice_counts(&s);
    eprintln!(
        "[proof] {} ended: carol's join {} in {:.1}s; alice refused {refused} at the cap and ended \
         {ended}",
        profile(),
        if ok { "got in" } else { "was refused" },
        took.as_secs_f64()
    );
    assert!(
        ended >= 1,
        "CANNOT MEASURE: carol's join ended none of the stranger's joins (refused {refused}), so \
         its {SLOTS} were not all in flight; alice's stderr:\n{text}"
    );
    assert!(
        ok,
        "carol was kept out: {out}{err}\n  alice's stderr:\n{text}"
    );
    // Every one of the stranger's joins ends: the ones alice ended hear it once their grind is done;
    // the rest finish their join, since the stranger knows the passphrase.
    let waiting = Instant::now();
    while held
        .iter_mut()
        .any(|p| p.0.try_wait().ok().flatten().is_none())
    {
        assert!(
            waiting.elapsed() < ENDED_TELL_PATIENCE,
            "CANNOT MEASURE: the stranger's joins had not all ended {}s after carol's",
            ENDED_TELL_PATIENCE.as_secs()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    let outs: Vec<String> = said
        .iter()
        .map(|p| std::fs::read_to_string(p).unwrap_or_default())
        .collect();
    let busy = outs
        .iter()
        .filter(|t| t.contains("busy answering other joins"))
        .count();
    let blamed = outs
        .iter()
        .filter(|t| t.contains("passphrase is wrong"))
        .count();
    let failed: Vec<&String> = outs.iter().filter(|t| t.contains("cannot join")).collect();
    eprintln!(
        "[proof] {} ended: of the stranger's {SLOTS} joins, {} failed: {busy} told the member was \
         busy, {blamed} told the passphrase was wrong; alice ended {ended}",
        profile(),
        failed.len()
    );
    assert!(
        busy >= ended && blamed == 0,
        "a join alice ended to answer carol was not told the member was busy: {busy} were, {blamed} \
         were told the passphrase was wrong, and alice ended {ended}:\n{}",
        failed
            .iter()
            .map(|t| t.as_str())
            .collect::<Vec<_>>()
            .join("\n---\n")
    );
    held.clear();
}

/// The member's `ADMISSION_PATIENCE` (`node::joinstream`): how long a join may take once its proof
/// of work has verified. Hard-coded, as the product's is.
const ADMISSION_PATIENCE: Duration = Duration::from_secs(60);
/// The stranger's grind in the stalled case, so its sixteen joins do their work at nearly once.
const STALL_GRIND_MS: u64 = 15_000;
/// Between carol's tries, as a person told "try the join again shortly" would.
const RETRY_PAUSE: Duration = Duration::from_secs(3);

#[test]
#[ignore = "sixteen stalled joins, production Argon2id and a real anchor; CI runs it in release"]
fn joins_that_did_their_work_and_went_quiet_give_their_slots_back() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let s = stage(
        tmp.path(),
        SLOTS + 1,
        1,
        Layout::OneAddress,
        &[
            ("VOX_TEST_SOLVE_AT_LEAST_MS", STALL_GRIND_MS.to_string()),
            ("VOX_TEST_STALL_AFTER_SOLVE_MS", NEVER_MS.to_string()),
        ],
    );
    let mut held: Vec<Proc> = (0..SLOTS)
        .map(|room| s.strangers[0].join_in_background(&s.links[room], &format!("s{room}"), None))
        .collect();
    // The precondition, from the stranger's own daemon: all sixteen joins sent a solution and
    // went quiet. Alice verified each solution before answering, so all sixteen holds have done
    // their work.
    let stalled = || {
        std::fs::read_to_string(&s.stranger_errs[0])
            .unwrap_or_default()
            .matches("solved, now silent")
            .count()
    };
    let filling = Instant::now();
    while stalled() < SLOTS {
        assert!(
            filling.elapsed() < FILL_PATIENCE,
            "CANNOT MEASURE: only {} of the stranger's {SLOTS} joins did their work in {}s",
            stalled(),
            FILL_PATIENCE.as_secs()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let all_worked = Instant::now();
    eprintln!(
        "[proof] {} stalled: all {SLOTS} of the stranger's joins did their work and went quiet \
         after {:.1}s",
        profile(),
        filling.elapsed().as_secs_f64()
    );
    // Carol tries, and tries again, as a person told the member is busy would.
    let mut tries: Vec<(bool, f64, String)> = Vec::new();
    let deadline = ADMISSION_PATIENCE + JOIN_BOUND;
    let got_in = loop {
        let at = all_worked.elapsed().as_secs_f64();
        let (ok, out, err) = s.carol.vox(
            &["room", "join", &s.links[SLOTS], "--name", "real"],
            Some(ROOM_PASS),
        );
        let said = format!("{out}{err}");
        // The first try lands while every slot is held by a join that has done its work: alice
        // must not end one of them for carol, however heavy their source.
        if tries.is_empty() {
            let (refused, ended, text) = alice_counts(&s);
            assert!(
                at < ADMISSION_PATIENCE.as_secs_f64(),
                "CANNOT MEASURE: carol's first try came {at:.1}s after the holds did their work, \
                 past the admission patience"
            );
            assert!(
                ended == 0,
                "alice ended a join that had done its work to answer carol ({ended} ended, \
                 {refused} refused):\n{text}"
            );
        }
        tries.push((ok, at, said.clone()));
        if ok {
            break true;
        }
        assert!(
            said.contains("busy answering other joins") && !said.contains("passphrase is wrong"),
            "carol, turned away while the slots were held, was not told the member was busy: \
             {said}"
        );
        if all_worked.elapsed() >= deadline {
            break false;
        }
        std::thread::sleep(RETRY_PAUSE);
    };
    let took = all_worked.elapsed();
    let (refused, ended, text) = alice_counts(&s);
    let quiet = text.matches("went quiet after its proof of work").count();
    eprintln!(
        "[proof] {} stalled: carol {} {:.1}s after the holds did their work, on try {} of {} \
         (bound {}s); alice refused {refused} at the cap, ended {ended}, and gave up on {quiet} \
         joins that went quiet",
        profile(),
        if got_in {
            "got in"
        } else {
            "was still kept out"
        },
        took.as_secs_f64(),
        tries.len(),
        tries.len(),
        deadline.as_secs()
    );
    assert!(
        got_in,
        "sixteen joins that did their work and went quiet kept carol out for {:.1}s, past {}s: \
         their slots were never given back\n  alice's stderr:\n{text}",
        took.as_secs_f64(),
        deadline.as_secs()
    );
    held.clear();
}
