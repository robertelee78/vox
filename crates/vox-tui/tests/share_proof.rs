//! PRD-001 R18 — `vox share`: a file offered to a room over a room-bound HTTP service,
//! announced with its name, size and SHA-256, pulled with curl through `vox up` or with
//! `vox room get`. Proved with the shipped binary only: every member is a `vox daemon`, and
//! everything they do is a `vox` verb (`vox trust add`, `vox room create/invite/join/post/
//! read/get`, `vox share`, `vox up`).
//!
//! alice shares; bob, whom she trusts, pulls it twice — once with `curl` through his own
//! `vox up`, once with `vox room get`, which lands it in his downloads directory. mallory
//! is in the same room and is not trusted: she can neither read the announcement nor open
//! the service, and her attempts are not fetches. After two fetches (`--count 2`) the share
//! stops by itself. A folder is shared as one tar, and arrives as a valid one.

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
fn vox(dir: &Path, argv: &[&str], stdin: Option<&str>) -> (bool, String, String) {
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
        .expect("run vox");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("stdin");
        pipe.write_all(text.as_bytes()).unwrap();
    }
    let out = child.wait_with_output().expect("vox finished");
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
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    let (ok, out, err) = vox(&dir, &["id", "--listen", "127.0.0.1:0"], None);
    assert!(ok, "vox id ({name}): {err}");
    let fp = out.trim().to_owned();
    assert_eq!(fp.len(), 52, "{name}'s fingerprint: {out:?}");
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
            "{} trusts {} as {as_name}: {out}{err}",
            self.name, peer.name
        );
    }

    /// `vox daemon` with the identity passphrase from a file; returns once it answers
    /// `vox room list`.
    fn start(&mut self, anchor: &str) {
        let pass_file = self.dir.join("passphrases");
        std::fs::write(&pass_file, format!("{IDENTITY}\n")).unwrap();
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
                pass_file.to_str().unwrap(),
            ]),
        );
        let deadline = Instant::now() + SETUP;
        while !vox(&self.dir, &["room", "list"], None).0 {
            if Instant::now() >= deadline {
                panic!(
                    "{}'s daemon never answered `vox room list`. It said:\n{}",
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
        panic!("{what} never reached {}", self.name);
    }

    /// A `vox up` with no room, carried by this member's daemon, and where it listens.
    fn up(&self) -> (VoxProc, SocketAddr) {
        let mut p = VoxProc::spawn(
            &format!("{} up", self.name),
            &self.dir,
            &args(&["up", "--bind", "127.0.0.1:0"]),
        );
        let line = p.expect_within(TIMEOUT, "vox up's address", |l| l.starts_with("vox up on "));
        let addr = line.split_whitespace().nth(3).unwrap().parse().unwrap();
        (p, addr)
    }
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
    let (ok, link, err) = vox(&alice.dir, &["room", "invite", &room], None);
    assert!(ok, "vox room invite: {err}");
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

    let mut share = VoxProc::spawn(
        "alice share",
        &alice.dir,
        &args(&["share", &room, file.to_str().unwrap(), "--count", "2"]),
    );
    let line = share.expect_within(TIMEOUT, "the share's port", |l| {
        l.starts_with("vox: sharing ")
    });
    let port: u16 = line
        .split("on port ")
        .nth(1)
        .and_then(|p| p.trim().parse().ok())
        .unwrap_or_else(|| panic!("no port in {line:?}"));
    let (_bob_up, bob_proxy) = bob.up();
    let (_mal_up, mal_proxy) = mallory.up();
    // `<service>.<node>.<room>.vox` (V030-25): the share's service is named for its port, `alice`
    // is what bob and mallory each call her, and `files` what each calls the room.
    let url = format!("http://{port}.alice.files.vox:{port}/report.bin");

    // Fetch 1: bob, with curl through his own `vox up`.
    let (curl_ok, curled) = curl(bob_proxy, &url);
    // mallory: the same URL through her own proxy, and `vox room get`. Neither is a fetch.
    let (mal_curl_ok, mal_curled) = curl(mal_proxy, &url);
    let (mal_get_ok, mal_get_said) = mallory.run(&["room", "get", &room, "report.bin"]);
    let fetches_before_get = share.transcript().matches("vox: fetched ").count();
    // Fetch 2: bob, with `vox room get`, into his downloads directory, once the
    // announcement has reached him.
    bob.sees(&room, "report.bin");
    let (get_ok, get_said) = bob.run(&["room", "get", &room, "report.bin"]);
    let landed = bob_dl.join("report.bin");
    let got = std::fs::read(&landed).unwrap_or_default();
    // Two fetches: the share stops by itself.
    let until = Instant::now() + Duration::from_secs(20);
    let mut ended = None;
    while Instant::now() < until {
        if let Ok(Some(s)) = share.child.try_wait() {
            ended = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Its last words, drained after it has exited.
    std::thread::sleep(Duration::from_millis(200));
    let share_said = share.transcript();

    // A folder, as one tar.
    let mut folder_share = VoxProc::spawn(
        "alice share folder",
        &alice.dir,
        &args(&["share", &room, folder.to_str().unwrap(), "--for", "120s"]),
    );
    folder_share.expect_within(TIMEOUT, "the folder share", |l| {
        l.starts_with("vox: sharing ")
    });
    bob.sees(&room, "photos.tar");
    let (tar_ok, tar_said) = bob.run(&["room", "get", &room, "photos.tar"]);
    let listing = Command::new("tar")
        .args(["-tf", bob_dl.join("photos.tar").to_str().unwrap()])
        .output()
        .unwrap();
    let listing = String::from_utf8_lossy(&listing.stdout).into_owned();

    eprintln!(
        "curl by bob: ok {curl_ok}, {} bytes, sha {}\nsent {} bytes, sha {}\n\
         mallory curl: ok {mal_curl_ok}, {} bytes; mallory get: ok {mal_get_ok}: {mal_get_said}\
         fetches counted before bob's get: {fetches_before_get}\nbob's get: ok {get_ok}: \
         {get_said}landed {} ({} bytes, sha {})\nshare ended {ended:?}; it said:\n{share_said}\n\
         folder get: ok {tar_ok}: {tar_said}tar lists:\n{listing}",
        curled.len(),
        sha(&curled),
        payload.len(),
        sha(&payload),
        mal_curled.len(),
        landed.display(),
        got.len(),
        sha(&got),
    );
    assert!(
        curl_ok && sha(&curled) == sha(&payload),
        "curl through vox up must get the same bytes"
    );
    assert!(
        !mal_curl_ok && mal_curled.is_empty(),
        "an untrusted member's curl must get nothing"
    );
    assert!(
        !mal_get_ok,
        "an untrusted member's `vox room get` must get nothing"
    );
    assert_eq!(fetches_before_get, 1, "only bob's curl was a fetch");
    assert!(get_ok, "bob's `vox room get` must succeed");
    assert_eq!(
        sha(&got),
        sha(&payload),
        "and land the same bytes in his downloads directory"
    );
    assert!(
        ended.is_some_and(|s| s.success()) && share_said.contains("fetched 2 time(s)"),
        "the share must stop by itself after --count 2"
    );
    assert!(tar_ok, "the folder share must be collectable");
    for entry in [
        "photos/",
        "photos/a.txt",
        "photos/2026/",
        "photos/2026/b.txt",
    ] {
        assert!(
            listing.lines().any(|l| l == entry),
            "the tar must hold {entry}"
        );
    }
    drop((folder_share, share, alice, bob, mallory, anchor));
}
