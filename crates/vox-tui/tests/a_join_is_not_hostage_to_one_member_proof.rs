//! **RP-02 — a room is joinable when one of its members is offline**, through the shipped
//! `vox` binary only: a `vox node` anchor and three `vox daemon`s, every step typed as an
//! operator types it (`vox id`, `vox trust add`, `vox room create|invite|join|post|read`).
//!
//! Replaces `crates/vox-core/tests/a_join_is_not_hostage_to_one_member.rs`, which ran every
//! node in-process (V29-17).
//!
//! ## The claim
//! A join is not hostage to one member. The joiner reaches the anchor's board, and walks the
//! room's members — the link's pinned responder first, then the others — until one admits it.
//! One member being away is not the room being gone.
//!
//! ## The staging
//! 1. Alice creates the room and mints the link with `vox room invite`. A link minted by a
//!    node **pins that node** (`r=<alice>`), so Alice is, by the product's own rule, the first
//!    member any joiner reaches for. The proof asserts the pin is there rather than hoping.
//! 2. Bob joins, and Alice and Bob trust each other; the room is ready when each has rendered
//!    a post by the other (precondition — `PRODUCT (staging)` if not).
//! 3. Alice's and Bob's daemons trust Carol (and she them) before she joins.
//! 4. **Alice's daemon is killed by its PID** and reaped: the member the join tries first is
//!    offline.
//! 5. Carol runs `vox room join` with the link Alice minted — **one attempt, no retry**.
//!
//! ## What is asserted
//! - Carol's join succeeds, and **the join's own work** — her `vox room join` end to end, less
//!   that attempt's proof-of-work `solve` and its Argon2 `seal`, as her daemon names them in its
//!   `join got in — …` line — is within [`WORK_BOUND`] (hard-coded: 40 s, in both profiles).
//!   The wait this proof exists for, on the offline member, is a **dial** to it, and the step line
//!   puts it there (`<alice>: dial 10.00s`): never in the solve or the seal, which are the joiner's
//!   own CPU once a live member has answered. So excluding them cannot hide the defect. Measured:
//!   the work is the 10 s dial to the dead member and about 2 s more, in release and in debug.
//! - In **release** the whole join is also within [`JOIN_BOUND`] (hard-coded: 60 s; measured
//!   ~12 s), as before. Not in debug: the unoptimized build's solve alone takes 22–194 s on this
//!   machine, varying with the nonces it happens to need — 128 s on the base build once — so an
//!   end-to-end bound there measured the solve, and the work bound is what that profile asserts.
//!   The solve and the work are printed apart, in both.
//! - Carol then renders a post Bob made after her join, within [`READ_BOUND`] (60 s) — she is
//!   really in the room, through the member that stayed online.
//!
//! ## The mutations that must turn it red
//! - `MAX_JOIN_RESPONDERS = 1` in `crates/vox-core/src/node/actor.rs`: the join stops after the
//!   first candidate, which is the pinned, dead Alice, so Carol's single join attempt fails with
//!   `cannot join: …`.
//! - The join **waiting on the offline member**: `PER_ATTEMPT_TIMEOUT` (`nat::reachability`)
//!   raised from 10 s to 90 s, so the dial to dead Alice holds the join for 90 s before it walks
//!   on to Bob. Carol still gets in; the wait shows in her step line as `<alice>: dial 90…s`, in
//!   the work, and the work bound turns it red in both profiles.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

/// **Every red names its kind** (decider rule 1). A verdict on the product says `PRODUCT:` and
/// quotes what the product said; a staging, precondition or harness failure says `APPARATUS`.
/// Anything else that panics — an `unwrap` or `expect` on spawning a process, a file, a thread — is
/// this proof's own failure, and this hook says so before its message.
fn label_reds() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let payload = info.payload();
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("");
            if !(message.starts_with("PRODUCT") || message.starts_with("APPARATUS")) {
                eprintln!(
                    "APPARATUS (harness error): the panic below is this proof's own, not a \
                     verdict on the product"
                );
            }
            previous(info);
        }));
    });
}

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const ID_PASS: &str = "identity passphrase";
const ROOM_PASS: &str = "channel passphrase";
/// Carol's whole `vox room join`, with the first member tried dead, in release. Hard-coded on
/// purpose. See the header for why debug does not assert it.
const JOIN_BOUND: Duration = Duration::from_secs(60);
/// Carol's join less its proof-of-work solve and Argon2 seal, in both profiles. The 10 s dial to the
/// dead member and about 2 s more, measured; the 90 s dial of a join that waits on it is far past.
const WORK_BOUND: Duration = Duration::from_secs(40);
/// From her join to rendering a post Bob made after it.
const READ_BOUND: Duration = Duration::from_secs(60);

/// A child killed and reaped by its own PID when dropped — never by pattern.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Member {
    name: &'static str,
    data: PathBuf,
    /// Its daemon's stderr, which names each step of a join (`vox: join got in — …`).
    err: PathBuf,
    pass: PathBuf,
    fp: String,
    daemon: Option<Proc>,
}

impl Member {
    fn vox(&self, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
        let mut child = Command::new(VOX)
            .args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", self.data.join("cfg"))
            .env_remove("VOX_ROOM")
            .env_remove("VOX_SESSION")
            .env_remove("VOX_ROOM_PASSPHRASE")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("APPARATUS: spawn vox");
        if let Some(text) = stdin {
            child
                .stdin
                .take()
                .expect("APPARATUS: a piped stdio handle")
                .write_all(text.as_bytes())
                .expect("PRODUCT (staging): vox exited without reading its stdin");
        }
        let out = child.wait_with_output().expect("APPARATUS: vox ran");
        let r = (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        );
        eprintln!(
            "[receipt] <{}> vox {} -> {}\n  stdout: {}\n  stderr: {}",
            self.name,
            args.join(" "),
            r.0,
            r.1.trim(),
            r.2.trim()
        );
        r
    }

    fn reads(&self, room: &str, text: &str) -> bool {
        self.vox(&["room", "read", room], None).1.contains(text)
    }

    fn trust(&self, other: &Member) {
        let (ok, o, e) = self.vox(
            &[
                "trust",
                "add",
                &other.fp,
                "--name",
                other.name,
                "--identity-passphrase-file",
                self.pass
                    .to_str()
                    .expect("APPARATUS: a path that is not UTF-8"),
            ],
            None,
        );
        assert!(
            ok,
            "PRODUCT (staging): {} trusts {}: {o}{e}",
            self.name, other.name
        );
    }
}

fn member(tmp: &Path, name: &'static str, anchor: &str) -> Member {
    let data = tmp.join(name);
    std::fs::create_dir_all(data.join("cfg")).expect("APPARATUS: create a staging directory");
    let pass = tmp.join(format!("{name}.pass"));
    std::fs::write(&pass, ID_PASS).expect("APPARATUS: write a staging file");
    let mut m = Member {
        name,
        data,
        err: tmp.join(format!("{name}.daemon.err")),
        pass,
        fp: String::new(),
        daemon: None,
    };
    let (ok, out, err) = m.vox(
        &[
            "id",
            "--identity-passphrase-file",
            m.pass
                .to_str()
                .expect("APPARATUS: a path that is not UTF-8"),
        ],
        None,
    );
    assert!(ok, "PRODUCT (staging): {name}: vox id: {err}");
    m.fp = out.trim().to_owned();
    assert_eq!(
        m.fp.len(),
        52,
        "PRODUCT (staging): {name}: a fingerprint from vox id"
    );
    let err = std::fs::File::create(&m.err).expect("APPARATUS: create a staging file");
    let child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0", "--anchor", anchor])
        .arg("--passphrase-file")
        .arg(&m.pass)
        .env("VOX_DATA_DIR", &m.data)
        .env("VOX_CONFIG_DIR", m.data.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(err))
        .spawn()
        .expect("APPARATUS: spawn vox daemon");
    m.daemon = Some(Proc(child));
    let deadline = Instant::now() + Duration::from_secs(90);
    while !m.vox(&["room", "list"], None).0 {
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): {name}'s daemon never answered"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    m
}

fn anchor(tmp: &Path) -> (Proc, String) {
    let dir = tmp.join("anchor");
    std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: create a staging directory");
    let out = tmp.join("anchor.out");
    let p = Proc(
        Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .stdout(Stdio::from(
                std::fs::File::create(&out).expect("APPARATUS: create a staging file"),
            ))
            .stderr(Stdio::null())
            .spawn()
            .expect("APPARATUS: spawn vox node"),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let text = std::fs::read_to_string(&out).unwrap_or_default();
        if let Some(spec) = text
            .split_whitespace()
            .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        {
            return (p, spec.to_owned());
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): the anchor never printed its spec"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Keep `author` posting fresh `tag n` lines until `reader` renders one — rooms are
/// forward-only, so an early post may stay unreadable for good. Returns how many were posted.
fn posts_until_read(
    author: &Member,
    reader: &Member,
    room: &str,
    tag: &str,
    within: Duration,
) -> Option<u32> {
    let deadline = Instant::now() + within;
    let mut n = 0u32;
    while Instant::now() < deadline {
        n += 1;
        let (ok, _, e) = author.vox(&["room", "post", room, &format!("{tag} {n}")], None);
        assert!(ok, "PRODUCT (staging): {} posts: {e}", author.name);
        std::thread::sleep(Duration::from_secs(1));
        if reader.reads(room, &format!("{tag} ")) {
            return Some(n);
        }
    }
    None
}

#[test]
#[ignore = "an anchor and three daemons with production Argon2id; CI runs it in release"]
fn a_room_is_still_joinable_when_the_first_member_tried_is_offline() {
    watchdog::arm();
    label_reds();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let (_anchor, spec) = anchor(tmp.path());
    let mut alice = member(tmp.path(), "alice", &spec);
    let bob = member(tmp.path(), "bob", &spec);
    let carol = member(tmp.path(), "carol", &spec);

    // ---- alice makes the room; the link she mints pins her ----
    let (ok, _, e) = alice.vox(
        &["room", "create", "--passphrase-file", "-", "--name", "team"],
        Some(&format!("{ROOM_PASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): room create: {e}");
    let room = alice
        .vox(&["room", "list"], None)
        .1
        .split_whitespace()
        .next()
        .expect("PRODUCT: the new room in `vox room list`")
        .to_owned();
    let (ok, link, e) = alice.vox(&["room", "invite", &room], None);
    assert!(ok, "PRODUCT (staging): invite: {e}");
    let link = link.trim().to_owned();
    let pinned = link
        .split(['?', '&'])
        .find_map(|p| p.strip_prefix("r="))
        .map(str::to_owned);
    assert_eq!(
        pinned.as_deref(),
        Some(alice.fp.as_str()),
        "PRODUCT (staging): the link `vox room invite` printed does not pin alice, so alice is not \
         provably the first member a join reaches for: {link}"
    );

    // ---- bob joins; alice and bob read each other ----
    let (ok, o, e) = bob.vox(
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            &link,
            "--name",
            "team",
        ],
        Some(&format!("{ROOM_PASS}\n")),
    );
    assert!(
        ok,
        "PRODUCT (staging): bob's join, with every member up, failed (if this names \
         `authenticator invalid` it is #217): {o}{e}"
    );
    alice.trust(&bob);
    bob.trust(&alice);
    let ab = posts_until_read(&alice, &bob, &room, "ALICE-READY", Duration::from_secs(120));
    let ba = posts_until_read(&bob, &alice, &room, "BOB-READY", Duration::from_secs(120));
    eprintln!("[proof] ready: alice->bob after {ab:?} posts, bob->alice after {ba:?} posts");
    assert!(
        ab.is_some() && ba.is_some(),
        "PRODUCT (staging): alice and bob never read each other (alice->bob {ab:?}, bob->alice {ba:?})"
    );

    // ---- everyone trusts carol before she joins, so what she reads is only the join's doing ----
    alice.trust(&carol);
    bob.trust(&carol);
    carol.trust(&alice);
    carol.trust(&bob);

    // ---- alice goes away: killed by PID and reaped ----
    let alice_pid = alice
        .daemon
        .as_ref()
        .expect("APPARATUS: a process the proof started")
        .0
        .id();
    drop(alice.daemon.take());
    let still = Command::new("kill")
        .args(["-0", &alice_pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    assert!(
        !still,
        "APPARATUS: the proof's kill did not stop alice's daemon (pid {alice_pid})"
    );
    eprintln!("[proof] alice's daemon pid {alice_pid} killed and reaped");

    // ---- carol joins with alice's own link: one attempt ----
    let t0 = Instant::now();
    let (ok, o, e) = carol.vox(
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            &link,
            "--name",
            "team",
        ],
        Some(&format!("{ROOM_PASS}\n")),
    );
    let took = t0.elapsed();
    eprintln!(
        "[proof] carol's join with the pinned member offline: ok={ok} in {:.1}s (release bound \
         {}s)",
        took.as_secs_f64(),
        JOIN_BOUND.as_secs()
    );
    if !ok && format!("{o}{e}").contains("authenticator invalid") {
        panic!("PRODUCT: carol's join hit #217 (`authenticator invalid`): {o}{e}");
    }
    assert!(
        ok,
        "PRODUCT: carol could not join a room with a live member in it: alice (the link's pinned \
         responder) is offline, and the join must fall through to bob. It said: {o}{e}"
    );
    // Her daemon names each step of the join that got in: `… <peer>: solve 3.68s, … seal 0.56s`.
    let steps = std::fs::read_to_string(&carol.err)
        .unwrap_or_default()
        .lines()
        .rfind(|l| l.contains("join got in"))
        .map(str::to_owned)
        .unwrap_or_else(|| {
            panic!("PRODUCT: carol's join got in but her daemon printed no `join got in` line")
        });
    let step_secs = |name: &str| -> f64 {
        steps
            .split(", ")
            .filter_map(|part| {
                let (_, rest) = part.split_once(&format!("{name} "))?;
                rest.trim_end_matches('s').parse::<f64>().ok()
            })
            .sum()
    };
    let (solve, seal) = (step_secs("solve"), step_secs("seal"));
    assert!(
        solve > 0.0 && seal > 0.0,
        "PRODUCT: carol's daemon did not name her join's solve and seal: {steps}"
    );
    let work = took.saturating_sub(Duration::from_secs_f64(solve + seal));
    eprintln!(
        "[proof] carol's join: {:.1}s in all, of which solve {solve:.2}s and seal {seal:.2}s; the \
         join's work {:.1}s (bound {}s); steps: {steps}",
        took.as_secs_f64(),
        work.as_secs_f64(),
        WORK_BOUND.as_secs()
    );
    assert!(
        work <= WORK_BOUND,
        "PRODUCT: carol's join took {:.1}s of its own work (less solve {solve:.2}s and seal {seal:.2}s), \
         over the {}s bound: a join waited on the offline member. Steps: {steps}",
        work.as_secs_f64(),
        WORK_BOUND.as_secs()
    );
    if !cfg!(debug_assertions) {
        assert!(
            took <= JOIN_BOUND,
            "PRODUCT: carol's join took {:.1}s, over the {}s bound: a join waited on the offline member",
            took.as_secs_f64(),
            JOIN_BOUND.as_secs()
        );
    }

    // ---- and she is really in: she renders what bob says next ----
    let t1 = Instant::now();
    let bc = posts_until_read(&bob, &carol, &room, "BOB-TO-CAROL", READ_BOUND);
    eprintln!(
        "[proof] carol renders bob after {bc:?} posts, {:.1}s after her join (bound {}s)",
        t1.elapsed().as_secs_f64(),
        READ_BOUND.as_secs()
    );
    assert!(
        bc.is_some(),
        "PRODUCT: carol joined but never rendered a post bob made after her join, within {}s",
        READ_BOUND.as_secs()
    );
}
