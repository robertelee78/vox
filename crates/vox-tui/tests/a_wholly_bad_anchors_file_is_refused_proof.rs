//! V210-75 (#266) — **an anchors file that names no usable anchor is refused**, through the
//! shipped binary.
//!
//! A bad line of the anchors file is skipped and named, and the others still count. But when
//! *every* line is bad and no `--anchor` is given, skipping them all left a node with no anchor
//! at all: `vox daemon` started and reached nobody it could not dial directly, and nothing but
//! the skipped-line notes said why. A verb that needs an anchor now refuses to start, naming the
//! file; `vox node`, an anchor itself, may run with no anchor of its own, and says so.
//!
//! **Staging.** One profile made by `vox id`, whose anchors file holds two lines that cannot be
//! used (a host that does not resolve, and a malformed fingerprint). Then, each a real `vox`:
//! - `vox daemon`, `vox serve` and `vox connect` must each **exit with failure** within
//!   [`EXIT_WITHIN`], saying the file names no usable anchor, with the file's path, and naming
//!   both skipped lines.
//! - `vox node` must **keep running** for [`STAYS_UP`] and say it runs with no anchor of its own.
//! - The verbs that dial no anchor must **work**, saying they carry on: `vox id` prints the
//!   profile's fingerprint and exits 0, and `vox trust add`, `vox trust list` and
//!   `vox trust remove` (no node running) add, show and remove a second profile's fingerprint.
//!   Printing a fingerprint or editing a keyring needs no anchor, and a broken anchors file
//!   withheld both.
//! - The control: `vox daemon` with the same file and an `--anchor` it can use **starts** (it
//!   answers `vox room list`), so the refusal is the file, not the verb.
//!
//! **Mutations that must turn it red:**
//! - `ProfileArgs::anchor_set` returns the empty set instead of the refusal (the candidate
//!   before this change): `vox daemon` keeps running.
//! - `vox id` loads its anchors strictly again (`AnchorUse::Needed`, candidate 2): it refuses,
//!   exit 1, and prints no fingerprint.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use world::{args, vox_once, IDENTITY, VOX};

/// How long a refusing verb may take to exit: it refuses before unlocking anything.
const EXIT_WITHIN: Duration = Duration::from_secs(30);
/// How long `vox node` must stay up with no anchor of its own.
const STAYS_UP: Duration = Duration::from_secs(5);
/// What the refusal says.
const REFUSED: &str = "names no usable anchor";

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

#[test]
#[ignore = "real vox processes and production Argon2id; CI runs it in release"]
fn an_anchors_file_with_no_usable_anchor_is_refused() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("p");
    std::fs::create_dir_all(data.join("cfg")).unwrap();
    let (ok, fp, err) = vox_once(&data, &args(&["id"]));
    assert!(ok, "CANNOT MEASURE: vox id: {err}");
    let fp = fp.trim().to_owned();
    assert_eq!(
        fp.len(),
        52,
        "CANNOT MEASURE: `vox id` prints a fingerprint: {fp:?}"
    );
    let anchors = data.join("cfg").join("anchors");
    std::fs::write(
        &anchors,
        format!("{fp}@no-such-anchor.invalid:4433\nnot-a-fingerprint@127.0.0.1:4433\n"),
    )
    .unwrap();
    let pass = tmp.path().join("identity.pass");
    std::fs::write(&pass, format!("{IDENTITY}\n")).unwrap();
    let pass = pass.to_str().unwrap().to_owned();
    let room_pass = tmp.path().join("room.pass");
    std::fs::write(&room_pass, "a room passphrase\n").unwrap();
    let room_pass = room_pass.to_str().unwrap().to_owned();
    let path = anchors.display().to_string();

    // ---- the verbs that need an anchor refuse, naming the file --------------------------------
    let verbs: [(&str, Vec<&str>); 3] = [
        (
            "daemon",
            vec![
                "daemon",
                "--listen",
                "127.0.0.1:0",
                "--passphrase-file",
                &pass,
            ],
        ),
        ("serve", vec!["serve", "9", "--listen", "127.0.0.1:0"]),
        (
            "connect",
            vec![
                "connect",
                "vox://example",
                "--passphrase-file",
                &room_pass,
                "--listen",
                "127.0.0.1:0",
            ],
        ),
    ];
    let mut refused = 0;
    for (tag, argv) in &verbs {
        let mut p = Proc::spawn(&data, argv, tag);
        let status = p.exited_within(EXIT_WITHIN);
        let said = p.said();
        let names_all = said.contains(REFUSED)
            && said.contains(&path)
            && said.contains("line 1 is skipped")
            && said.contains("line 2 is skipped");
        println!(
            "[proof] vox {tag}: exited {status:?}; refused naming the file and both lines: {names_all}"
        );
        assert!(
            status.is_some_and(|s| !s.success()) && names_all,
            "`vox {tag}` with an anchors file of two unusable lines and no --anchor must exit with \
             failure within {EXIT_WITHIN:?}, saying the file ({path}) {REFUSED:?} and naming both \
             lines; it exited {status:?} and said:\n{said}"
        );
        refused += 1;
    }

    // ---- the verbs that dial no anchor work, and say they carry on -----------------------------
    const CARRIES_ON: &str = "this command dials no anchor, so it carries on";
    let (ok, out, err) = vox_once(&data, &args(&["id"]));
    let printed = out.trim() == fp;
    println!(
        "[proof] vox id: exit ok {ok}; printed the fingerprint: {printed}; said it carries on: {}",
        err.contains(CARRIES_ON)
    );
    assert!(
        ok && printed && err.contains(CARRIES_ON) && err.contains("line 1 is skipped"),
        "`vox id` dials no anchor: with an anchors file that names none it must print its \
         fingerprint ({fp}), exit 0, and say it carries on; it exited ok={ok}, printed \
         {out:?} and said:\n{err}"
    );
    let friend_dir = tmp.path().join("q");
    std::fs::create_dir_all(friend_dir.join("cfg")).unwrap();
    let (ok, friend, err) = vox_once(&friend_dir, &args(&["id"]));
    let friend = friend.trim().to_owned();
    assert!(
        ok && friend.len() == 52,
        "CANNOT MEASURE: a second profile's `vox id`: {friend:?} {err}"
    );
    let trust = |argv: &[&str]| {
        let (ok, out, err) = vox_once(&data, &args(argv));
        (ok && err.contains(CARRIES_ON), out, err)
    };
    let (added, _, add_err) = trust(&["trust", "add", &friend, "--name", "friend"]);
    let (listed, list_out, list_err) = trust(&["trust", "list"]);
    let listed = listed && list_out.contains(&friend);
    let (removed, _, rm_err) = trust(&["trust", "remove", &friend]);
    let (relisted, relist_out, relist_err) = trust(&["trust", "list"]);
    let gone = relisted && !relist_out.contains(&friend);
    println!(
        "[proof] vox trust with the same file: add {added}, list shows it {listed}, remove \
         {removed}, list no longer shows it {gone}"
    );
    assert!(
        added && listed && removed && gone,
        "`vox trust` dials no anchor: with an anchors file that names none, add, list and \
         remove must work and say they carry on.\nadd: {add_err}\nlist: {list_out}{list_err}\n\
         remove: {rm_err}\nlist again: {relist_out}{relist_err}"
    );

    // ---- `vox node` runs anchorless, and says so ----------------------------------------------
    let node_dir = tmp.path().join("n");
    std::fs::create_dir_all(node_dir.join("cfg")).unwrap();
    std::fs::copy(&anchors, node_dir.join("cfg").join("anchors")).unwrap();
    let mut node = Proc::spawn(&node_dir, &["node", "--listen", "127.0.0.1:0"], "node");
    let exited = node.exited_within(STAYS_UP);
    let said = node.said();
    let says = said.contains(REFUSED) && said.contains("running with no anchor of its own");
    println!(
        "[proof] vox node: exited {exited:?} in {STAYS_UP:?}; said it runs anchorless: {says}"
    );
    assert!(
        exited.is_none() && says,
        "`vox node` with the same file must run with no anchor of its own and say so; it exited \
         {exited:?} and said:\n{said}"
    );
    drop(node);

    // ---- the control: the same file with a usable --anchor starts -----------------------------
    let anchor_spec = {
        // Any well-formed spec will do: the daemon starts whether or not the anchor answers.
        format!("{fp}@/ip4/127.0.0.1/udp/9")
    };
    let mut daemon = Proc::spawn(
        &data,
        &[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--passphrase-file",
            &pass,
            "--anchor",
            &anchor_spec,
        ],
        "control",
    );
    let t0 = Instant::now();
    let started = loop {
        if vox_once(&data, &args(&["room", "list"])).0 {
            break true;
        }
        if daemon.child.try_wait().ok().flatten().is_some()
            || t0.elapsed() > Duration::from_secs(90)
        {
            break false;
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    println!("[proof] control: vox daemon with a usable --anchor started: {started}; {refused}/3 verbs refused");
    assert!(
        started,
        "CANNOT MEASURE: the control daemon, given a usable --anchor, did not start, so the \
         refusals above may not be the file's doing:\n{}",
        daemon.said()
    );
}
