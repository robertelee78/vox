//! ADR-028 F-1, F-2 (PRD-001 R18) — `vox share`: a file handed to a room as one addressed
//! message, served by the daemon over a room-bound HTTP service, announced with its name, size and
//! SHA-256, pulled with curl through `vox up` or with `vox room get`. Proved with the shipped
//! binary only: every member is a `vox daemon`, and everything they do is a `vox` verb (`vox trust
//! add`, `vox room create/link/join/post/read/get/leave`, `vox share`, `vox share list/stop`, `vox
//! up`).
//!
//! alice shares a file `--to bob --urgent -m <note>`, and `vox share` returns. bob reads **one**
//! announcement carrying the note, his whole fingerprint and the urgent flag, and no message of its
//! own carries the note. Then bob, whom she trusts, pulls it twice — once with `curl` through his
//! own `vox up`, once with `vox room get`, which lands it in his downloads directory — from her
//! daemon, the command that shared it long gone. mallory is in the same room and is not trusted:
//! she can neither read the announcement nor open the service, and her attempts are not fetches.
//! After two fetches (`--count 2`) the daemon stops serving it by itself, and a late pull is told
//! the offer is gone. A folder is shared as one tar, arrives as a valid one, and after `vox share
//! stop` a pull is told it is gone. A share alice leaves behind when she leaves the room ends.
//!
//! Mutants: post the note as a message of its own (red: two rows carry the note); serve only while
//! `vox share` runs (red: bob's curl gets nothing after it exits).

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};
use world::{args, VoxProc, IDENTITY, VOX};

const TIMEOUT: Duration = Duration::from_secs(60);
const SETUP: Duration = Duration::from_secs(90);
const ROOM_PASS: &str = "room passphrase";

/// A one-shot `vox` verb in `dir`'s profile, `stdin` piped in when given.
/// A verb as a person runs it since ADR-026 L-2: one that needs its node attached, run while no
/// daemon holds the data root, runs with the node attached by `vox node attach` and let go after.
fn vox(dir: &std::path::Path, argv: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let verb: Vec<&str> = argv.to_vec();
    match world::attach::needs(dir, &verb) {
        Some(node) => {
            world::attach::Root::at(dir, IDENTITY).attached(&node, || vox_plain(dir, argv, stdin))
        }
        None => vox_plain(dir, argv, stdin),
    }
}

fn vox_plain(dir: &Path, argv: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_ANCHORS")
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: run vox");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("APPARATUS: vox's piped stdin");
        pipe.write_all(text.as_bytes())
            .expect("APPARATUS: write vox's stdin");
    }
    let out = child
        .wait_with_output()
        .expect("APPARATUS: collect vox's output");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// One member: a profile directory, its fingerprint, and its `vox daemon` once started.
struct Member {
    name: &'static str,
    dir: PathBuf,
    fp: String,
    daemon: Option<VoxProc>,
}

fn member(tmp: &Path, name: &'static str) -> Member {
    let dir = tmp.join(name);
    std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: make the profile dir");
    let (ok, out, err) = vox(&dir, &["id", "--listen", "127.0.0.1:0"], None);
    assert!(ok, "PRODUCT (staging): vox id ({name}): {err}");
    let fp = out.trim().to_owned();
    assert_eq!(
        fp.len(),
        52,
        "PRODUCT (staging): {name}'s fingerprint: {out:?}"
    );
    Member {
        name,
        dir,
        fp,
        daemon: None,
    }
}

impl Member {
    fn trust(&self, peer: &Member, as_name: &str) {
        let (ok, out, err) = vox(
            &self.dir,
            &[
                "trust",
                "add",
                &peer.fp,
                "--name",
                as_name,
                "--listen",
                "127.0.0.1:0",
            ],
            None,
        );
        assert!(
            ok,
            "PRODUCT (staging): {} trusts {} as {as_name}: {out}{err}",
            self.name, peer.name
        );
    }

    /// `vox daemon` with the identity passphrase from a file; returns once it answers
    /// `vox room list`.
    fn start(&mut self, anchor: &str) {
        let pass_file = self.dir.join("passphrases");
        std::fs::write(&pass_file, format!("{IDENTITY}\n"))
            .expect("APPARATUS: write the passphrase file");
        let mut p = VoxProc::spawn(
            self.name,
            &self.dir,
            &args(&[
                "daemon",
                "--listen",
                "127.0.0.1:0",
                "--anchor",
                anchor,
                "--passphrase-file",
                pass_file.to_str().expect("APPARATUS: a UTF-8 path"),
            ]),
        );
        let deadline = Instant::now() + SETUP;
        while !vox(&self.dir, &["room", "list"], None).0 {
            if Instant::now() >= deadline {
                panic!(
                    "PRODUCT (staging): {}'s daemon never answered `vox room list`. It said:\n{}",
                    self.name,
                    p.transcript()
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        self.daemon = Some(p);
    }

    fn run(&self, argv: &[&str]) -> (bool, String) {
        let (ok, out, err) = vox(&self.dir, argv, None);
        (ok, format!("{out}{err}"))
    }

    /// Wait until `vox room read` shows `what`: it has synced here, and this member can
    /// read its author.
    fn sees(&self, room: &str, what: &str) {
        let until = Instant::now() + TIMEOUT;
        while Instant::now() < until {
            if self.run(&["room", "read", room]).1.contains(what) {
                return;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!("PRODUCT: {what} never reached {}", self.name);
    }

    /// How often this member's daemon says `tag` was fetched (`vox share list`), or `None` if it
    /// does not list it.
    fn fetched(&self, room: &str, tag: &str) -> Option<u64> {
        let (ok, out) = self.run(&["share", "list", room]);
        assert!(
            ok,
            "PRODUCT (staging): {} lists its shares: {out}",
            self.name
        );
        out.lines()
            .find(|l| l.starts_with(tag))
            .and_then(|l| l.split("fetched ").nth(1))
            .and_then(|n| n.split_whitespace().next())
            .and_then(|n| n.parse().ok())
    }

    /// Whether this member's daemon stops listing `tag` within `within`.
    fn stops_sharing(&self, room: &str, tag: &str, within: Duration) -> bool {
        let until = Instant::now() + within;
        while Instant::now() < until {
            let (ok, out) = self.run(&["share", "list", room]);
            if !ok || !out.contains(tag) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        false
    }

    /// A `vox up` with no room, carried by this member's daemon, and where it listens.
    fn up(&self) -> (VoxProc, SocketAddr) {
        let mut p = VoxProc::spawn(
            &format!("{} up", self.name),
            &self.dir,
            &args(&["up", "--bind", "127.0.0.1:0"]),
        );
        let line = p.expect_within(TIMEOUT, "vox up's address", |l| l.starts_with("vox up on "));
        let addr = line
            .split_whitespace()
            .nth(3)
            .and_then(|a| a.parse().ok())
            .unwrap_or_else(|| panic!("PRODUCT (staging): no address in {line:?}"));
        (p, addr)
    }
}

/// The tag `vox share` said it serves the share as: `vox: sharing <name> (<n> bytes) as <tag>`.
fn tag_of(said: &str) -> String {
    said.lines()
        .find(|l| l.starts_with("vox: sharing "))
        .and_then(|l| l.rsplit(" as ").next())
        .map(|t| t.trim().to_owned())
        .unwrap_or_else(|| panic!("PRODUCT: `vox share` did not say what it serves: {said}"))
}

/// Every row `vox room read --json` shows `who`.
fn rows_of(who: &Member, room: &str) -> Vec<serde_json::Value> {
    let (ok, out) = who.run(&["room", "read", room, "--json"]);
    assert!(ok, "PRODUCT (staging): {} reads the room: {out}", who.name);
    out.lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// `curl` through `proxy`: whether it succeeded, and the bytes.
fn curl(proxy: SocketAddr, url: &str) -> (bool, Vec<u8>) {
    let out = Command::new("curl")
        .args([
            "-s",
            "--fail",
            "--max-time",
            "60",
            "--socks5-hostname",
            &proxy.to_string(),
            url,
        ])
        .output()
        .unwrap();
    (out.status.success(), out.stdout)
}

fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}

#[test]
#[ignore = "an anchor, three vox daemons and real child processes; CI runs it in release"]
fn a_share_is_pulled_by_the_trusted_and_by_nobody_else() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let payload: Vec<u8> = (0..700_000u32)
        .map(|i| (i.wrapping_mul(97) >> 3) as u8)
        .collect();
    let file = tmp.path().join("report.bin");
    std::fs::write(&file, &payload).unwrap();
    let folder = tmp.path().join("photos");
    std::fs::create_dir_all(folder.join("2026")).unwrap();
    std::fs::write(folder.join("a.txt"), b"first").unwrap();
    std::fs::write(folder.join("2026").join("b.txt"), b"second").unwrap();

    let anchor_dir = tmp.path().join("anchor");
    std::fs::create_dir_all(anchor_dir.join("cfg")).unwrap();
    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();

    let mut alice = member(tmp.path(), "alice");
    let mut bob = member(tmp.path(), "bob");
    let mut mallory = member(tmp.path(), "mallory");
    alice.trust(&bob, "bob");
    bob.trust(&alice, "alice");
    // mallory trusts alice — she would like what alice shares — but alice has not
    // trusted her.
    mallory.trust(&alice, "alice");
    for m in [&mut alice, &mut bob, &mut mallory] {
        m.start(&spec);
    }

    let (ok, out, err) = vox(
        &alice.dir,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "files",
        ],
        Some(&format!("{ROOM_PASS}\n")),
    );
    assert!(ok, "vox room create: {out}{err}");
    let (ok, list, err) = vox(&alice.dir, &["room", "list"], None);
    assert!(ok, "vox room list: {err}");
    let room = list
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some("files"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("files is not listed: {list}"))
        .to_owned();
    let (ok, link, err) = vox(&alice.dir, &["room", "link", &room], None);
    assert!(ok, "vox room link: {err}");
    for who in [&bob, &mallory] {
        let (ok, out, err) = vox(
            &who.dir,
            &[
                "room",
                "join",
                "--passphrase-file",
                "-",
                link.trim(),
                "--name",
                "files",
            ],
            Some(&format!("{ROOM_PASS}\n")),
        );
        assert!(ok, "{} joins files: {out}{err}", who.name);
    }
    // **Precondition: bob reads alice.** Until alice's key reaches him he can read none of
    // what she posts, the announcement included; that is key distribution, not sharing, so
    // it is waited for here rather than measured below.
    let (ok, said) = alice.run(&["room", "post", &room, "hello from alice"]);
    assert!(ok, "alice posts: {said}");
    bob.sees(&room, "hello from alice");

    let bob_dl = tmp.path().join("bob-downloads");
    std::fs::write(
        bob.dir.join("cfg").join("config"),
        format!("downloads = {}\n", bob_dl.display()),
    )
    .unwrap();

    // **One message, addressed** (ADR-028 F-1): the note, who it is for and the urgent flag ride
    // in the share itself. And **the daemon serves it** (F-2): `vox share` returns once it does.
    let note = "the quarterly numbers, for your review";
    let posted_before = rows_of(&bob, &room).len();
    let (shared_ok, shared_said) = alice.run(&[
        "share",
        &room,
        file.to_str().unwrap(),
        "--count",
        "2",
        "--to",
        "bob",
        "--urgent",
        "-m",
        note,
    ]);
    assert!(
        shared_ok,
        "PRODUCT: `vox share` must return once the daemon serves the file; it said: {shared_said}"
    );
    let tag = tag_of(&shared_said);
    let (_bob_up, bob_proxy) = bob.up();
    let (_mal_up, mal_proxy) = mallory.up();
    // `<service>.<node>.<room>.vox` (V030-25): the share's service is its tag, `alice` is what bob
    // and mallory each call her, and `files` what each calls the room.
    let url = format!("http://{tag}.alice.files.vox/report.bin");

    // Fetch 1: bob, with curl through his own `vox up` — after `vox share` has exited.
    let (curl_ok, curled) = curl(bob_proxy, &url);
    // mallory: the same URL through her own proxy, and `vox room get`. Neither is a fetch.
    let (mal_curl_ok, mal_curled) = curl(mal_proxy, &url);
    let (mal_get_ok, mal_get_said) = mallory.run(&["room", "get", &room, "report.bin"]);
    let fetches_before_get = alice.fetched(&room, &tag);
    // What bob reads: the share's one announcement.
    bob.sees(&room, "report.bin");
    let after: Vec<serde_json::Value> = rows_of(&bob, &room).split_off(posted_before);
    let announcements: Vec<&serde_json::Value> = after
        .iter()
        .filter(|r| {
            r["envelope"]["type"] == "file" && r["envelope"]["data"]["name"] == "report.bin"
        })
        .collect();
    let carrying_note = after
        .iter()
        .filter(|r| r["text"].as_str().is_some_and(|t| t.contains(note)))
        .count();
    // Fetch 2: bob, with `vox room get`, into his downloads directory.
    let (get_ok, get_said) = bob.run(&["room", "get", &room, "report.bin"]);
    let landed = bob_dl.join("report.bin");
    let got = std::fs::read(&landed).unwrap_or_default();
    // Two fetches: the daemon stops serving it by itself.
    let ended = alice.stops_sharing(&room, &tag, Duration::from_secs(20));

    // **A late collector is told the offer is gone** (ADR-020 11.8): the announcement stays on the
    // log, the bytes were live. The share has ended (above: after `--count 2`), and bob, who reads
    // the announcement, asks again.
    let (late_ok, late_said) = bob.run(&["room", "get", &room, "report.bin"]);
    eprintln!("[proof] bob's get after the share ended (ok {late_ok}): {late_said}");

    // A folder, as one tar; then stopped by hand (`vox share stop`).
    let (folder_ok, folder_said) =
        alice.run(&["share", &room, folder.to_str().unwrap(), "--for", "120s"]);
    assert!(
        folder_ok,
        "PRODUCT (staging): vox share of a folder: {folder_said}"
    );
    bob.sees(&room, "photos.tar");
    let (tar_ok, tar_said) = bob.run(&["room", "get", &room, "photos.tar"]);
    let listing = Command::new("tar")
        .args(["-tf", bob_dl.join("photos.tar").to_str().unwrap()])
        .output()
        .unwrap();
    let listing = String::from_utf8_lossy(&listing.stdout).into_owned();
    let (stop_ok, stop_said) = alice.run(&["share", "stop", &room, "photos.tar"]);
    let (stopped_get_ok, stopped_get_said) = bob.run(&["room", "get", &room, "photos.tar"]);

    // And one left behind when alice leaves the room: leaving ends it (F-2).
    let left_file = tmp.path().join("notes.txt");
    std::fs::write(&left_file, b"what alice left behind").unwrap();
    let (left_ok, left_said) = alice.run(&["share", &room, left_file.to_str().unwrap()]);
    assert!(
        left_ok,
        "PRODUCT (staging): vox share before leaving: {left_said}"
    );
    let left_tag = tag_of(&left_said);
    bob.sees(&room, "notes.txt");
    let (leave_ok, leave_said) = alice.run(&["room", "leave", &room]);
    assert!(leave_ok, "PRODUCT (staging): alice leaves: {leave_said}");
    let left_ended = alice.stops_sharing(&room, &left_tag, Duration::from_secs(20));
    let (after_leave_ok, after_leave_said) = bob.run(&["room", "get", &room, "notes.txt"]);

    eprintln!(
        "share said: {shared_said}\ncurl by bob: ok {curl_ok}, {} bytes, sha {}\nsent {} bytes, sha \
         {}\nmallory curl: ok {mal_curl_ok}, {} bytes; mallory get: ok {mal_get_ok}: \
         {mal_get_said}fetches counted before bob's get: {fetches_before_get:?}\nbob reads: \
         {announcements:?} ({carrying_note} row(s) carry the note)\nbob's get: ok {get_ok}: \
         {get_said}landed {} ({} bytes, sha {})\nshare ended {ended}\nfolder get: ok {tar_ok}: \
         {tar_said}tar lists:\n{listing}\nstop: ok {stop_ok}: {stop_said}get after stop: ok \
         {stopped_get_ok}: {stopped_get_said}\nafter leave (ended {left_ended}): ok \
         {after_leave_ok}: {after_leave_said}",
        curled.len(),
        sha(&curled),
        payload.len(),
        sha(&payload),
        mal_curled.len(),
        landed.display(),
        got.len(),
        sha(&got),
    );
    // #493: one announcement, carrying the note, the addressee and the urgent flag.
    assert_eq!(
        announcements.len(),
        1,
        "PRODUCT: bob must read exactly one announcement of report.bin; he read: {after:?}"
    );
    let a = announcements[0];
    assert!(
        a["envelope"]["data"]["note"] == note
            && a["envelope"]["to"] == serde_json::json!([bob.fp])
            && a["envelope"]["urgent"] == true,
        "PRODUCT: the announcement must carry the note, bob's whole fingerprint as its addressee \
         and the urgent flag; bob read: {a}"
    );
    assert_eq!(
        carrying_note, 1,
        "PRODUCT: the note must travel in the share, never as a message of its own; bob read: \
         {after:?}"
    );
    // #494: served by the daemon once `vox share` has exited.
    assert!(
        curl_ok && sha(&curled) == sha(&payload),
        "PRODUCT: curl through vox up must get the same bytes after `vox share` has exited"
    );
    assert!(
        !mal_curl_ok && mal_curled.is_empty(),
        "PRODUCT: an untrusted member's curl must get nothing"
    );
    assert!(
        !mal_get_ok,
        "PRODUCT: an untrusted member's `vox room get` must get nothing; it said: {mal_get_said}"
    );
    assert_eq!(
        fetches_before_get,
        Some(1),
        "PRODUCT: only bob's curl was a fetch (`vox share list`)"
    );
    assert!(
        get_ok,
        "PRODUCT: bob's `vox room get` must succeed: {get_said}"
    );
    assert_eq!(
        sha(&got),
        sha(&payload),
        "PRODUCT: and land the same bytes in his downloads directory"
    );
    assert!(
        ended,
        "PRODUCT: the daemon must stop serving the share by itself after --count 2"
    );
    let gone = |ok: bool, said: &str, name: &str| {
        !ok && said.contains(&format!("the offer of {name} is gone"))
            && said.contains("no longer serves it")
            && !said.contains("reset by peer")
    };
    assert!(
        gone(late_ok, &late_said, "report.bin"),
        "PRODUCT: a collector of an offer whose share has ended must be told the offer is gone \
         (ADR-020 11.8), not a transport error; bob's `vox room get` said (ok {late_ok}): \
         {late_said}"
    );
    assert!(
        tar_ok,
        "PRODUCT: the folder share must be collectable: {tar_said}"
    );
    for entry in [
        "photos/",
        "photos/a.txt",
        "photos/2026/",
        "photos/2026/b.txt",
    ] {
        assert!(
            listing.lines().any(|l| l == entry),
            "PRODUCT: the tar must hold {entry}"
        );
    }
    assert!(
        stop_ok && stop_said.contains("no longer sharing photos.tar"),
        "PRODUCT: `vox share stop` must stop the folder share; it said: {stop_said}"
    );
    assert!(
        gone(stopped_get_ok, &stopped_get_said, "photos.tar"),
        "PRODUCT: a pull after `vox share stop` must be told the offer is gone; bob's `vox room \
         get` said (ok {stopped_get_ok}): {stopped_get_said}"
    );
    assert!(
        left_ended && !after_leave_ok,
        "PRODUCT: leaving the room must end the share (ended {left_ended}); bob's `vox room get` \
         after alice left said (ok {after_leave_ok}): {after_leave_said}"
    );
    drop((alice, bob, mallory, anchor));
}

/// The last fetch reaches its receiver whole, however slowly it reads.
///
/// A share used to count a fetch when its last byte entered the local socket, and ending on
/// that count removed the service — which cuts every session carried on it (PRD-001 R22),
/// the one still delivering those bytes included. A fast `vox room get` usually outran the
/// cut. Here it cannot: the file is larger than a stream's flow-control window (16 MiB), and
/// the receiver reads at 2 MB/s, so when the last byte leaves the share megabytes are still
/// waiting on the host for the receiver to make room — and the red does not depend on timing.
#[test]
#[ignore = "an anchor, two vox daemons and real child processes; CI runs it in release"]
fn the_last_fetch_is_delivered_before_the_share_ends() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let payload: Vec<u8> = (0..24_000_000u32)
        .map(|i| (i.wrapping_mul(131) >> 5) as u8)
        .collect();
    let file = tmp.path().join("big.bin");
    std::fs::write(&file, &payload).expect("APPARATUS: write the shared file");

    let anchor_dir = tmp.path().join("anchor");
    std::fs::create_dir_all(anchor_dir.join("cfg")).expect("APPARATUS: the anchor's dir");
    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();
    let mut alice = member(tmp.path(), "alice");
    let mut bob = member(tmp.path(), "bob");
    alice.trust(&bob, "bob");
    bob.trust(&alice, "alice");
    for m in [&mut alice, &mut bob] {
        m.start(&spec);
    }
    let (ok, out, err) = vox(
        &alice.dir,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "files",
        ],
        Some(&format!("{ROOM_PASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room create: {out}{err}");
    let (_, list, _) = vox(&alice.dir, &["room", "list"], None);
    let room = list
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some("files"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("PRODUCT (staging): files is not listed: {list}"))
        .to_owned();
    let (ok, link, err) = vox(&alice.dir, &["room", "link", &room], None);
    assert!(ok, "PRODUCT (staging): vox room link: {err}");
    let (ok, out, err) = vox(
        &bob.dir,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            link.trim(),
            "--name",
            "files",
        ],
        Some(&format!("{ROOM_PASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): bob joins files: {out}{err}");

    let (shared_ok, shared_said) = alice.run(&[
        "share",
        &room,
        file.to_str().expect("APPARATUS: a UTF-8 path"),
        "--count",
        "1",
    ]);
    assert!(shared_ok, "PRODUCT (staging): vox share: {shared_said}");
    let tag = tag_of(&shared_said);
    let (_bob_up, bob_proxy) = bob.up();
    let out = Command::new("curl")
        .args([
            "-s",
            "--fail",
            "--max-time",
            "60",
            "--limit-rate",
            "2M",
            "--socks5-hostname",
            &bob_proxy.to_string(),
            // `<service>.<node>.<room>.vox`: a node's name alone resolves to nothing (PRD-001
            // R20), and the share's service is its tag.
            &format!("http://{tag}.alice.files.vox/big.bin"),
        ])
        .output()
        .expect("APPARATUS: run curl");
    let ended = alice.stops_sharing(&room, &tag, Duration::from_secs(20));
    eprintln!(
        "slow curl: exit {:?}, {} of {} bytes, sha {} (sent {})\nshare ended {ended}",
        out.status.code(),
        out.stdout.len(),
        payload.len(),
        sha(&out.stdout),
        sha(&payload),
    );
    assert!(
        out.status.success() && sha(&out.stdout) == sha(&payload),
        "PRODUCT: the last fetch must arrive whole before the share ends"
    );
    assert!(
        ended,
        "PRODUCT: the daemon must still stop serving the share by itself after --count 1"
    );
    drop((alice, bob, anchor));
}
