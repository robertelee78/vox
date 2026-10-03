//! PRD-001 R45, ADR-023 decision 6 — **an anchor upgraded from a release that kept room pages
//! deletes its store file**, through the shipped binaries.
//!
//! Before ADR-023 an anchor kept a ciphertext log of every room whose members synced with it, in
//! its store file. This build keeps nothing on disk for a room it is not a member of, and the
//! decider ruled (2026-10-02, #95): "Delete the store file." An upgraded anchor removes it whole;
//! it has no use for one.
//!
//! **The scene.** [`PREVIOUS`] (`support/previous_release.rs`, its published binary checked
//! against its SHA-256) runs everything first: an anchor (`vox node`) and two member daemons, A and
//! B, both naming it. A makes a room, B joins, they trust each other, A posts and B reads every
//! post. Everything stops, and the anchor's data directory must hold a store file — else the old
//! release did not stage what this proof is about (CANNOT MEASURE). Then **this build's**
//! `vox node` starts on the same data directory, as an upgrade leaves it, says its `--anchor` spec,
//! and is stopped.
//!
//! **What is asserted.** What a person sees in the anchor's data directory: no store file remains
//! (`PRODUCT:` otherwise), and this build's anchor starting there and saying its spec
//! (`PRODUCT (staging):` otherwise). The previous release failing to stage the scene is
//! `CANNOT MEASURE`. Nothing is opened in this process.
//!
//! **Not driven here:** a data directory a member's vault shares with the anchor. There the store
//! is the member's rooms, so only the anchor's retired pages go, never the file.
//!
//! **Why a file of its own.** It needs the previous release's binary, which no anchor proof uses.
//!
//! **Mutation.** The headless start keeping the file: it stays, and the proof goes red.

#![cfg(unix)]

#[path = "support/previous_release.rs"]
mod previous_release;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use previous_release::{previous_release, PREVIOUS};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "identity passphrase";
const ROOMPASS: &str = "the room passphrase";
/// How long B may take to read what A posts.
const READ_WITHIN: Duration = Duration::from_secs(90);

/// A process of `exe` in `dir`'s profile, killed and reaped by its own PID however the proof ends,
/// with its stdout collected.
struct Proc {
    name: String,
    child: Child,
    out: Arc<Mutex<Vec<String>>>,
}

impl Proc {
    fn start(exe: &Path, name: &str, dir: &Path, argv: &[&str]) -> Self {
        let mut child = Command::new(exe)
            .args(argv)
            .env("VOX_DATA_DIR", dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
            .env_remove("VOX_ROOM")
            .env_remove("VOX_ROOM_PASSPHRASE")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: spawn {name} ({}): {e}", exe.display()));
        let out = Arc::new(Mutex::new(Vec::new()));
        let lines = Arc::clone(&out);
        let stdout = child.stdout.take().expect("APPARATUS: a piped stdout");
        std::thread::spawn(move || {
            for l in BufReader::new(stdout).lines().map_while(Result::ok) {
                lines.lock().unwrap().push(l);
            }
        });
        Self {
            name: name.to_owned(),
            child,
            out,
        }
    }

    /// The first stdout line matching `pred` within a minute; a red labelled `side` otherwise
    /// (`CANNOT MEASURE` for the previous release, `PRODUCT` for this build).
    fn wait_for(&self, side: &str, what: &str, pred: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(l) = self.out.lock().unwrap().iter().find(|l| pred(l)) {
                return l.clone();
            }
            assert!(
                Instant::now() < deadline,
                "{side} (staging): {} never printed {what}; it said:\n{}",
                self.name,
                self.out.lock().unwrap().join("\n")
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Stop it with SIGINT, as a person does, and wait until it is gone, so its store is released.
    fn stop(mut self) {
        let _ = Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(20);
        while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A one-shot verb of `exe` in `dir`'s profile that must succeed: anything else is CANNOT MEASURE.
fn ok(exe: &Path, dir: &Path, argv: &[&str], stdin: &str) -> String {
    let mut child = Command::new(exe)
        .args(argv)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: run vox {argv:?}: {e}"));
    child
        .stdin
        .take()
        .expect("APPARATUS: a piped stdin")
        .write_all(stdin.as_bytes())
        .expect("APPARATUS: write stdin");
    let out = child.wait_with_output().expect("APPARATUS: vox ran");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "CANNOT MEASURE (staging): {} {argv:?} failed: {said}",
        exe.display()
    );
    said
}

/// A member daemon of `exe` for `dir`, naming `anchor`.
fn daemon(exe: &Path, name: &str, dir: &Path, anchor: &str) -> Proc {
    let pass = dir.join("pass");
    std::fs::write(&pass, format!("{IDPASS}\n{ROOMPASS}\n"))
        .expect("APPARATUS: write the passphrase file");
    let pass = pass.to_str().expect("APPARATUS: a UTF-8 path").to_owned();
    let d = Proc::start(
        exe,
        name,
        dir,
        &[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--passphrase-file",
            &pass,
            "--anchor",
            anchor,
        ],
    );
    d.wait_for("CANNOT MEASURE", "its control socket", |l| {
        l.contains("control socket")
    });
    d
}

/// A `vox node` of `exe` for `dir`, once it has said its `--anchor` spec.
fn anchor(exe: &Path, name: &str, dir: &Path, side: &str) -> (Proc, String) {
    let a = Proc::start(exe, name, dir, &["node", "--listen", "127.0.0.1:0"]);
    let spec = a
        .wait_for(side, "its --anchor spec", |l| {
            let l = l.trim();
            l.contains('@') && l.starts_with(|c: char| c.is_alphanumeric())
        })
        .trim()
        .to_owned();
    (a, spec)
}

fn mk(root: &Path, name: &str) -> PathBuf {
    let d = root.join(name);
    std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: make a profile directory");
    d
}

#[test]
#[ignore = "fetches the previous release and runs real daemons with production Argon2id; CI runs it in release"]
fn an_anchor_upgraded_from_a_release_that_kept_room_pages_deletes_them() {
    watchdog::arm();
    let old = previous_release();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let (n, a, b) = (
        mk(tmp.path(), "anchor"),
        mk(tmp.path(), "a"),
        mk(tmp.path(), "b"),
    );
    let fp = |d: &Path| {
        ok(&old, d, &["id"], "")
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned()
    };
    let (a_fp, b_fp) = (fp(&a), fp(&b));

    // ---- the previous release: an anchor and two members, a room, posts read through it ----
    let (old_anchor, spec) = anchor(&old, "the old anchor", &n, "CANNOT MEASURE");
    let da = daemon(&old, "a", &a, &spec);
    ok(
        &old,
        &a,
        // v0.2.9 reads a piped passphrase unasked and has no `--passphrase-file` here.
        &["room", "create", "--name", "r"],
        &format!("{ROOMPASS}\n"),
    );
    let room = ok(&old, &a, &["room", "list"], "")
        .split_whitespace()
        .find(|w| w.len() >= 12 && w.chars().all(|ch| ch.is_ascii_alphanumeric()))
        .unwrap_or_else(|| panic!("CANNOT MEASURE (staging): A lists no room"))
        .to_owned();
    let link = ok(&old, &a, &["room", "invite", &room], "")
        .lines()
        .find(|l| l.starts_with("vox://"))
        .unwrap_or_else(|| panic!("CANNOT MEASURE (staging): no invitation"))
        .trim()
        .to_owned();
    let db = daemon(&old, "b", &b, &spec);
    ok(
        &old,
        &b,
        &["room", "join", &link, "--name", "r"],
        &format!("{ROOMPASS}\n"),
    );
    ok(&old, &a, &["trust", "add", &b_fp, "--name", "b"], "");
    ok(&old, &b, &["trust", "add", &a_fp, "--name", "a"], "");
    let posts: Vec<String> = (0..4).map(|i| format!("r34-upgrade-{i}")).collect();
    for p in &posts {
        ok(&old, &a, &["room", "post", &room, p], "");
    }
    let deadline = Instant::now() + READ_WITHIN;
    loop {
        let said = ok(&old, &b, &["room", "read", &room], "");
        if posts.iter().all(|p| said.contains(p.as_str())) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE (staging): under {PREVIOUS}, B never read A's posts: {said}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    // A moment for the members' last sync with the anchor, then everything stops.
    std::thread::sleep(Duration::from_secs(5));
    da.stop();
    db.stop();
    old_anchor.stop();
    // The store file, where an anchor kept what it kept; the path a person would look in.
    let store = n.join("default").join("store.redb");
    println!(
        "[proof] under {PREVIOUS}, the anchor's store file {} exists: {}",
        store.display(),
        store.is_file()
    );
    assert!(
        store.is_file(),
        "CANNOT MEASURE (staging): {PREVIOUS}'s anchor kept no store file, so there is nothing for \
         an upgrade to delete"
    );

    // ---- this build's anchor on the same data directory ----
    let (new_anchor, _) = anchor(Path::new(VOX), "the upgraded anchor", &n, "PRODUCT");
    new_anchor.stop();
    println!(
        "[proof] after this build's `vox node` ran on it, the store file exists: {}",
        store.exists()
    );
    assert!(
        !store.exists(),
        "PRODUCT: an anchor upgraded from {PREVIOUS} must delete its store file (ADR-023 decision \
         6; the decider, #95): {} is still there",
        store.display()
    );
}
