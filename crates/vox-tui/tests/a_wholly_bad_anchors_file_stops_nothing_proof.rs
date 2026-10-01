//! V210-107 (#302) — **an anchors file that names no usable anchor stops nothing**, through the
//! shipped binary, between two people who can reach each other directly and run no anchor at all.
//!
//! An anchor bridges hosts that cannot otherwise find each other; "for all other use cases, direct
//! is fine, sans anchor" (ADR-012, restated 2026-10-01). V210-75 (#266) made an anchors file whose
//! every line is unusable a refusal for every verb that starts a node — `vox daemon`, `serve`,
//! `connect`, `up`, `forward`, `service add/remove` and the TUI — so a person whose file named a
//! host that no longer resolves could not `vox connect` to a host one hop away. Now each bad line is
//! named, then that the file names no usable anchor, and the verb carries on with none.
//!
//! **Staging.** Two profiles, alice (the host) and bob (the guest), made by `vox id`, each with an
//! anchors file of two lines that cannot be used (a host that does not resolve, and a malformed
//! fingerprint). No `--anchor`, no `vox node` running, both on `127.0.0.1`. Then, each a real `vox`:
//! - `vox id` prints alice's fingerprint and exits 0; `vox trust add` (each trusts the other) exits
//!   0. Each says the file and both lines were skipped and that it carries on.
//! - alice's `vox daemon` **starts** (answers `vox room list`) and says it carries on; she
//!   `vox room create`s a room, posts in it, and `vox room invite`s.
//! - bob **`vox connect`s** with that address and the room passphrase, and exits 0.
//! - bob's `vox daemon` starts, and bob **reads alice's post** with `vox room read` — the room
//!   reached him directly, with no anchor anywhere.
//! - bob's **`vox tui`** unlocks, opens the room and closes it (`tests/pty/tui_close_room.py`).
//! - `vox node` with the same file keeps running and says it runs with no anchor of its own.
//!
//! `vox serve` is not driven here: on a host whose only address is loopback it refuses for want
//! of a routable address or an anchor (anchor sweep C1, owned by V210-96), whatever the anchors
//! file says. Every verb above, and `serve`, `up`, `forward` and `service`, read the anchors file
//! through the one function, `ProfileArgs::anchor_set`.
//!
//! **Every red names its side.** A verb that exits, refuses, or says something other than what
//! is asserted is a **product** red, quoting what it said. A step this proof needs that is not
//! the claim (a fingerprint to write into the file, a room id to read back, the TUI driver's own
//! apparatus) is `CANNOT MEASURE`.
//!
//! **The mutation that must turn it red:** `ProfileArgs::anchor_set` returns the
//! `AnchorsFileUnusable` error again instead of saying it and carrying on (the V210-75 refusal).
//! `vox id` exits 1 and prints no fingerprint: red, on the product, at the first arm.

#![cfg(unix)]

#[path = "support/pty_driver.rs"]
mod pty_driver;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::io::Write as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use world::{args, vox_once, IDENTITY, VOX};

/// How long a daemon may take to answer its socket: one production Argon2id unlock.
const STARTS_WITHIN: Duration = Duration::from_secs(90);
/// How long `vox connect` may take: two Argon2id derivations, a real PoW, and the join.
const CONNECT_WITHIN: Duration = Duration::from_secs(240);
/// How long bob may take to read alice's post once his daemon holds the room.
const READS_WITHIN: Duration = Duration::from_secs(90);
/// How long `vox node` must stay up with no anchor of its own.
const STAYS_UP: Duration = Duration::from_secs(5);
/// The room's passphrase.
const ROOMPASS: &str = "a room passphrase";
/// What alice posts before bob joins, and bob must read.
const POST: &str = "hello from alice, no anchor between us";

/// A `vox` child with its output in files, killed by its own PID on drop.
struct Proc {
    child: Child,
    out: std::path::PathBuf,
    err: std::path::PathBuf,
}

impl Proc {
    fn spawn(data: &Path, argv: &[&str], tag: &str) -> Self {
        let out = data.join(format!("{tag}.out"));
        let err = data.join(format!("{tag}.err"));
        let child = Command::new(VOX)
            .args(argv)
            .env("VOX_DATA_DIR", data)
            .env("VOX_CONFIG_DIR", data.join("cfg"))
            .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
            .env_remove("VOX_ANCHORS")
            .stdin(Stdio::null())
            .stdout(Stdio::from(std::fs::File::create(&out).unwrap()))
            .stderr(Stdio::from(std::fs::File::create(&err).unwrap()))
            .spawn()
            .expect("spawn vox");
        Self { child, out, err }
    }

    /// Its exit within `within`, if it exited.
    fn exited_within(&mut self, within: Duration) -> Option<std::process::ExitStatus> {
        let t0 = Instant::now();
        while t0.elapsed() < within {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        None
    }

    fn said(&self) -> String {
        format!(
            "{}{}",
            std::fs::read_to_string(&self.out).unwrap_or_default(),
            std::fs::read_to_string(&self.err).unwrap_or_default()
        )
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A one-shot `vox` verb with `stdin` written to it, for the verbs that read a room passphrase.
fn vox_in(data: &Path, argv: &[&str], stdin: &str) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ANCHORS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vox");
    let mut pipe = child.stdin.take().expect("stdin");
    pipe.write_all(stdin.as_bytes()).unwrap();
    drop(pipe);
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Whether `said` names the anchors file at `path`, both of its skipped lines, and that the verb
/// carries on with no anchor.
fn carries_on(said: &str, path: &str) -> bool {
    said.contains("names no usable anchor")
        && said.contains(path)
        && said.contains("line 1 is skipped")
        && said.contains("line 2 is skipped")
        && said.contains("carrying on with no anchor")
}

/// `vox daemon` on the profile at `dir`, once it answers `vox room list`; a red naming the
/// product if it exits first.
fn daemon(dir: &Path, pass: &str, tag: &str) -> Proc {
    let mut d = Proc::spawn(
        dir,
        &[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--passphrase-file",
            pass,
        ],
        tag,
    );
    let t0 = Instant::now();
    loop {
        if vox_once(dir, &args(&["room", "list"])).0 {
            return d;
        }
        if let Ok(Some(status)) = d.child.try_wait() {
            panic!(
                "PRODUCT: `vox daemon` ({tag}) with an anchors file that names no usable anchor, \
                 and no anchor needed, exited ({status}) instead of starting. It said:\n{}",
                d.said()
            );
        }
        assert!(
            t0.elapsed() < STARTS_WITHIN,
            "PRODUCT: `vox daemon` ({tag}) did not answer `vox room list` within \
             {STARTS_WITHIN:?}. It said:\n{}",
            d.said()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[test]
#[ignore = "real vox processes, a TUI in a pty and production Argon2id; CI runs it in release"]
fn an_anchors_file_with_no_usable_anchor_stops_nothing() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (alice, bob) = (tmp.path().join("alice"), tmp.path().join("bob"));
    let mut fps = Vec::new();
    for dir in [&alice, &bob] {
        std::fs::create_dir_all(dir.join("cfg")).unwrap();
        let (ok, fp, err) = vox_once(dir, &args(&["id"]));
        let fp = fp.trim().to_owned();
        assert!(
            ok && fp.len() == 52,
            "CANNOT MEASURE: the first `vox id` (no anchors file yet) printed {fp:?}: {err}"
        );
        fps.push(fp);
    }
    let (alice_fp, bob_fp) = (fps[0].clone(), fps[1].clone());
    let bad = format!("{alice_fp}@no-such-anchor.invalid:4433\nnot-a-fingerprint@127.0.0.1:4433\n");
    for dir in [&alice, &bob] {
        std::fs::write(dir.join("cfg").join("anchors"), &bad).unwrap();
    }
    let alice_file = alice.join("cfg").join("anchors").display().to_string();
    let bob_file = bob.join("cfg").join("anchors").display().to_string();
    let pass = tmp.path().join("identity.pass");
    std::fs::write(&pass, format!("{IDENTITY}\n")).unwrap();
    let pass = pass.to_str().unwrap().to_owned();
    // A daemon opens a closed room from a passphrase on a line of its own (bob's, after his
    // `vox connect` closed it).
    let bob_pass = tmp.path().join("bob.pass");
    std::fs::write(&bob_pass, format!("{IDENTITY}\n{ROOMPASS}\n")).unwrap();
    let bob_pass = bob_pass.to_str().unwrap().to_owned();
    let room_pass = tmp.path().join("room.pass");
    std::fs::write(&room_pass, format!("{ROOMPASS}\n")).unwrap();
    let room_pass = room_pass.to_str().unwrap().to_owned();

    // ---- vox id and vox trust: said, skipped, done ---------------------------------------------
    let (ok, out, err) = vox_once(&alice, &args(&["id"]));
    println!(
        "[proof] vox id: exit ok {ok}; printed the fingerprint: {}; said it carries on: {}",
        out.trim() == alice_fp,
        carries_on(&err, &alice_file)
    );
    assert!(
        ok && out.trim() == alice_fp && carries_on(&err, &alice_file),
        "PRODUCT: `vox id` with an anchors file that names no usable anchor must print its \
         fingerprint ({alice_fp}), exit 0, and name the file, both lines and that it carries on; \
         it exited ok={ok}, printed {out:?} and said:\n{err}"
    );
    for (dir, file, fp, name) in [
        (&alice, &alice_file, &bob_fp, "bob"),
        (&bob, &bob_file, &alice_fp, "alice"),
    ] {
        let (ok, out, err) = vox_once(dir, &args(&["trust", "add", fp, "--name", name]));
        println!("[proof] vox trust add {name}: exit ok {ok}");
        assert!(
            ok && carries_on(&err, file),
            "PRODUCT: `vox trust add {name}` with an anchors file that names no usable anchor \
             must work and say it carries on; it exited ok={ok} and said:\n{out}{err}"
        );
    }

    // ---- alice hosts a room from her daemon ------------------------------------------------------
    let alice_daemon = daemon(&alice, &pass, "alice-daemon");
    let said = alice_daemon.said();
    println!(
        "[proof] alice's vox daemon started; said it carries on: {}",
        carries_on(&said, &alice_file)
    );
    assert!(
        carries_on(&said, &alice_file),
        "PRODUCT: alice's `vox daemon` started, but did not name the anchors file, both lines and \
         that it carries on with no anchor. It said:\n{said}"
    );
    let (ok, _, err) = vox_in(
        &alice,
        &["room", "create", "--name", "shared"],
        &format!("{ROOMPASS}\n"),
    );
    assert!(
        ok,
        "PRODUCT: `vox room create` over alice's anchorless daemon: {err}"
    );
    let (ok, listed, err) = vox_once(&alice, &args(&["room", "list"]));
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(str::to_owned);
    let Some(room) = room.filter(|_| ok) else {
        panic!("CANNOT MEASURE: no room id in alice's `vox room list`: {listed}{err}");
    };
    let (ok, _, err) = vox_once(&alice, &args(&["room", "post", &room, POST]));
    assert!(ok, "PRODUCT: alice's post in her own room: {err}");
    let (ok, link, err) = vox_once(&alice, &args(&["room", "invite", &room]));
    let link = link.trim().to_owned();
    println!("[proof] alice's room {room}; invite {link}");
    assert!(
        ok && link.starts_with("vox://"),
        "PRODUCT: `vox room invite` from alice's anchorless daemon gave no address: {link:?} {err}"
    );

    // ---- bob connects, with no anchor anywhere ---------------------------------------------------
    let t0 = Instant::now();
    let mut connect = Proc::spawn(
        &bob,
        &[
            "connect",
            &link,
            "--passphrase-file",
            &room_pass,
            "--listen",
            "127.0.0.1:0",
        ],
        "bob-connect",
    );
    let status = connect.exited_within(CONNECT_WITHIN);
    let said = connect.said();
    println!(
        "[proof] bob's vox connect: exited {status:?} after {:?}; said it carries on: {}",
        t0.elapsed(),
        carries_on(&said, &bob_file)
    );
    assert!(
        status.is_some_and(|s| s.success()) && carries_on(&said, &bob_file),
        "PRODUCT: bob's `vox connect` to alice, who is directly reachable, with an anchors file \
         that names no usable anchor, must join (exit 0) and say it carries on; it exited \
         {status:?} within {CONNECT_WITHIN:?} and said:\n{said}"
    );
    drop(connect);

    // ---- bob reads alice's post ------------------------------------------------------------------
    let bob_daemon = daemon(&bob, &bob_pass, "bob-daemon");
    let t0 = Instant::now();
    let read = loop {
        let (ok, out, err) = vox_once(&bob, &args(&["room", "read", &room]));
        if ok && out.contains(POST) {
            break Ok(out);
        }
        if t0.elapsed() > READS_WITHIN {
            break Err(format!("{out}{err}"));
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    println!(
        "[proof] bob reads alice's post: {} after {:?}",
        read.is_ok(),
        t0.elapsed()
    );
    if let Err(last) = read {
        panic!(
            "PRODUCT: bob joined, but did not read alice's post {POST:?} within {READS_WITHIN:?}. \
             His last `vox room read`:\n{last}\nhis daemon said:\n{}\nalice's daemon said:\n{}",
            bob_daemon.said(),
            alice_daemon.said()
        );
    }
    drop(bob_daemon);

    // ---- bob's TUI opens the room ----------------------------------------------------------------
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pty/tui_close_room.py");
    let out = pty_driver::run(
        script,
        &[
            VOX,
            &bob.to_string_lossy(),
            &bob.join("cfg").to_string_lossy(),
            IDENTITY,
            ROOMPASS,
            "bob",
        ],
    );
    let said = out.stdout.clone();
    println!(
        "[proof] bob's vox tui: driver exit {:?} after {:?}, last stage {:?}: {}",
        out.code,
        out.took,
        out.stage,
        said.trim()
    );
    assert!(
        !said.contains("bob RED"),
        "PRODUCT: bob's `vox tui` with an anchors file that names no usable anchor exited before \
         it asked to unlock:\n{said}"
    );
    assert!(
        out.has_verdict("bob"),
        "CANNOT MEASURE: the TUI driver was stopped before it gave a verdict, at stage {:?} \
         (exit {:?}): {said}",
        out.stage.as_deref().unwrap_or("(before its first stage)"),
        out.code
    );
    assert!(
        out.code == Some(0) && said.contains("bob the TUI said done to :close"),
        "CANNOT MEASURE: bob's TUI started, but the driver did not see it open and close the \
         room: {said}"
    );

    // ---- `vox node` runs anchorless, and says so -------------------------------------------------
    let node_dir = tmp.path().join("n");
    std::fs::create_dir_all(node_dir.join("cfg")).unwrap();
    std::fs::write(node_dir.join("cfg").join("anchors"), &bad).unwrap();
    let mut node = Proc::spawn(&node_dir, &["node", "--listen", "127.0.0.1:0"], "node");
    let exited = node.exited_within(STAYS_UP);
    let said = node.said();
    let says = said.contains("names no usable anchor")
        && said.contains("running with no anchor of its own");
    println!(
        "[proof] vox node: exited {exited:?} in {STAYS_UP:?}; said it runs anchorless: {says}"
    );
    assert!(
        exited.is_none() && says,
        "PRODUCT: `vox node` with the same file must run with no anchor of its own and say so; it \
         exited {exited:?} and said:\n{said}"
    );
    drop(node);
    drop(alice_daemon);
}
