//! ADR-028 F-1, F-2 (PRD-001 R18) — `vox share`: a file handed to a room as one addressed
//! message, served by the daemon over a room-bound HTTP service, announced with its name, size and
//! SHA-256, pulled with curl through `vox up` or with `vox room get`. Proved with the shipped
//! binary only: every member is a `vox daemon`, and everything they do is a `vox` verb (`vox trust
//! add`, `vox room create/link/join/post/read/get/leave`, `vox share`, `vox share list/stop`, `vox
//! up`).
//!
//! alice shares a file `--to bob --urgent -m <note>`, and `vox share` returns. bob reads **one**
//! announcement carrying the note, his whole fingerprint and the urgent flag, and no message of its
//! own carries the note. bob's node, which trusts her, pulls it by itself, verified, into
//! `nodes/<node>/files/<room>/` (F-3, F-4); then bob pulls it twice more — once with `curl` through
//! his own `vox up`, once with `vox room get`, which lands it beside his node's copy — all from
//! her daemon, the command that shared it long gone. mallory is in the same room and is not
//! trusted: she can neither read the announcement nor open the service, and her attempts are not
//! fetches. A share alice addresses to carol is pulled by carol's node, and shows on bob as a card
//! naming carol until bob pulls it with `vox room get`. After three fetches (`--count 3`) the daemon stops serving it by itself, and a late pull is told
//! the offer is gone. A folder of ten files is shared listed, not packed (ADR-028 F-8): bob's first
//! get fetches all ten; after one changes and alice shares it again, his get fetches that one
//! alone; a file he changed in his copy is kept and said to be; a get cut short with two of six
//! large files landed resumes with the other four; a folder of more than 100,000 files is refused.
//! After `vox share
//! stop` a pull is told it is gone. A share alice leaves behind when she leaves the room ends.
//!
//! The folder is shared as a reply to the report's announcement (`--re`): it carries that entry
//! and spends a hop of its budget, as a `vox room post` reply does (ADR-020 §9).
//!
//! Mutants: post the note as a message of its own (red: two rows carry the note); serve only while
//! `vox share` runs (red: bob's curl gets nothing after it exits); a share keeps a fresh hop budget
//! (red: the folder's announcement carries the default, not its parent's less one); pull a share
//! addressed to another node (red: bob's node pulls carol's); pull whatever the disk has free (red:
//! bob's node and `vox room get` try a 2^60-byte share); count a fetch cut short as pulled (red:
//! alice's card says carol pulled report.bin); refetch every file of a folder (red: the re-pull
//! says 10 fetched).

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::collections::BTreeMap;
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
            &args(&["up", "--watch"]),
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

/// Whether a file with SHA-256 `want` appears at `path` within `within`: only a verified pull is
/// ever put there, under its own name.
fn arrives(path: &Path, want: &str, within: Duration) -> bool {
    let until = Instant::now() + within;
    while Instant::now() < until {
        if std::fs::read(path).is_ok_and(|b| sha(&b) == want) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Where `who`'s node puts what it pulls from `room` (ADR-028 F-4): `nodes/<node>/files/<room>/`,
/// named by the room's whole id, of which `room` (as `vox room list` prints it) is the start.
fn files_of(who: &Member, room: &str) -> PathBuf {
    let (ok, out) = who.run(&["room", "link", room]);
    assert!(ok, "PRODUCT (staging): {}'s room link: {out}", who.name);
    let id = out
        .trim()
        .strip_prefix("vox://")
        .and_then(|l| l.split(['?', '/', '@']).next())
        .filter(|id| id.starts_with(room))
        .unwrap_or_else(|| panic!("PRODUCT (staging): no room id in {out:?}"))
        .to_owned();
    who.dir.join("nodes").join("default").join("files").join(id)
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
    // Ten files, one in a folder of its own.
    let folder = tmp.path().join("photos");
    std::fs::create_dir_all(folder.join("2026")).unwrap();
    for i in 0..9 {
        std::fs::write(folder.join(format!("f{i}.txt")), format!("file {i}")).unwrap();
    }
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
    let mut carol = member(tmp.path(), "carol");
    alice.trust(&bob, "bob");
    bob.trust(&alice, "alice");
    alice.trust(&carol, "carol");
    carol.trust(&alice, "alice");
    // bob names carol, so a card addressed to her says so.
    bob.trust(&carol, "carol");
    // mallory trusts alice — she would like what alice shares — but alice has not
    // trusted her.
    mallory.trust(&alice, "alice");
    for m in [&mut alice, &mut bob, &mut mallory, &mut carol] {
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
    for who in [&bob, &mallory, &carol] {
        let (ok, out, err) = vox(
            &who.dir,
            &["room", "join", "--passphrase-file", "-", link.trim()],
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
    carol.sees(&room, "hello from alice");

    // Where each node's pulls land (ADR-028 F-4): `<data root>/nodes/<node>/files/<room>/`.
    let bob_dl = files_of(&bob, &room);
    let carol_dl = files_of(&carol, &room);

    // **One message, addressed** (ADR-028 F-1): the note, who it is for and the urgent flag ride
    // in the share itself. And **the daemon serves it** (F-2): `vox share` returns once it does.
    let note = "the quarterly numbers, for your review";
    let posted_before = rows_of(&bob, &room).len();
    let (shared_ok, shared_said) = alice.run(&[
        "share",
        &room,
        file.to_str().unwrap(),
        "--count",
        "3",
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

    // Fetch 1: **bob's node pulls it by itself** (F-3): it is addressed to him, from a member he
    // trusts. Nothing is asked of bob, and it lands verified in his node's files directory.
    let auto = arrives(&bob_dl.join("report.bin"), &sha(&payload), TIMEOUT);
    // Fetch 2: bob, with curl through his own `vox up` — after `vox share` has exited.
    let (curl_ok, curled) = curl(bob_proxy, &url);
    // carol, whom alice trusts, starts a fetch and gives up on it two seconds in: not a pull.
    let (_carol_up, carol_proxy) = carol.up();
    let carol_cut = Command::new("curl")
        .args([
            "-s",
            "--limit-rate",
            "20k",
            "--max-time",
            "2",
            "--socks5-hostname",
            &carol_proxy.to_string(),
            &url,
            "-o",
            "/dev/null",
        ])
        .status()
        .map(|s| s.code())
        .unwrap_or_default();
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
    // Fetch 3: bob, with `vox room get`, into his node's files directory beside the copy his node
    // pulled — never over it.
    let (get_ok, get_said) = bob.run(&["room", "get", &room, "report.bin"]);
    let landed = bob_dl.join("report (1).bin");
    let got = std::fs::read(&landed).unwrap_or_default();
    // Three fetches: the daemon stops serving it by itself.
    let ended = alice.stops_sharing(&room, &tag, Duration::from_secs(20));

    // **A late collector is told the offer is gone** (ADR-020 11.8): the announcement stays on the
    // log, the bytes were live. The share has ended (above: after `--count 2`), and bob, who reads
    // the announcement, asks again.
    let (late_ok, late_said) = bob.run(&["room", "get", &room, "report.bin"]);
    eprintln!("[proof] bob's get after the share ended (ok {late_ok}): {late_said}");

    // **The sharer's card says who pulled it** (ADR-028 F-7): bob, whose three fetches were whole;
    // not carol, who gave up on hers, nor mallory, who could not open it. Read on alice's own
    // `vox room read`, the line under the share's row.
    let (_, alice_reads) = alice.run(&["room", "read", &room]);
    // The row's own lines: the row, then its indented continuations (who it is to, who pulled it).
    let pulled_line = alice_reads
        .lines()
        .skip_while(|l| !l.contains("file offered: report.bin"))
        .skip(1)
        .take_while(|l| l.starts_with("  "))
        .map(str::trim)
        .find(|l| l.starts_with("pulled by"))
        .unwrap_or_default()
        .to_owned();
    // And it is the daemon's record, kept across restarts: alice's daemon stops and starts again,
    // twice, so what one start reads from disk is what the next one reads too.
    for _ in 0..2 {
        alice.daemon = None;
        alice.start(&spec);
    }
    let restarted_until = Instant::now() + TIMEOUT;
    let pulled_after_restart = loop {
        let (_, reads) = alice.run(&["room", "read", &room]);
        let line = reads
            .lines()
            .skip_while(|l| !l.contains("file offered: report.bin"))
            .skip(1)
            .take_while(|l| l.starts_with("  "))
            .map(str::trim)
            .find(|l| l.starts_with("pulled by"))
            .unwrap_or_default()
            .to_owned();
        if !line.is_empty() || Instant::now() >= restarted_until {
            break line;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    eprintln!(
        "[proof] carol's cut-short curl exited {carol_cut:?}; alice reads under report.bin: \
         {pulled_line:?}; after her daemon restarted: {pulled_after_restart:?}"
    );

    // **A share for someone else is a card, not a pull** (F-3): carol's node pulls what alice
    // shares with her; bob's node, which reads it too, leaves it — and shows it naming carol —
    // until bob asks for it with `vox room get`.
    let for_carol = tmp.path().join("for-carol.txt");
    std::fs::write(&for_carol, b"carol's eyes only, by address").unwrap();
    let (carol_ok, carol_said) = alice.run(&[
        "share",
        &room,
        for_carol.to_str().unwrap(),
        "--to",
        "carol",
        "-m",
        "for carol",
    ]);
    assert!(
        carol_ok,
        "PRODUCT (staging): vox share --to carol: {carol_said}"
    );
    let carol_got = arrives(
        &carol_dl.join("for-carol.txt"),
        &sha(b"carol's eyes only, by address"),
        TIMEOUT,
    );
    bob.sees(&room, "for-carol.txt");
    // bob's node looks over the room every second: three seconds after it reads the card, a pull
    // it was going to make has had its time to land.
    std::thread::sleep(Duration::from_secs(3));
    let bob_pulled_carols = bob_dl.join("for-carol.txt").exists();
    let (_, bob_reads) = bob.run(&["room", "read", &room]);
    let card: Vec<&str> = bob_reads
        .lines()
        .skip_while(|l| !l.contains("file offered: for-carol.txt"))
        .take(2)
        .collect();
    let (carols_get_ok, carols_get_said) = bob.run(&["room", "get", &room, "for-carol.txt"]);
    let bob_got_carols = std::fs::read(bob_dl.join("for-carol.txt")).unwrap_or_default();

    // **A pull never fills the disk** (#495): alice, as a test-side attacker, announces a share of
    // 2^60 bytes, more than any disk has free. bob's node must not pull it, must say why once, and
    // `vox room get` must refuse it before dialling, saying why.
    let huge = format!(
        r#"{{"v":1,"type":"file","body":"a share no disk can hold","data":{{"name":"huge.bin","size":{},"sha256":"{}","tag":"file-0000000000000000-0000000000000000","http":true}}}}"#,
        1u64 << 60,
        "0".repeat(64)
    );
    let (huge_ok, huge_said) = alice.run(&["room", "post", &room, &huge]);
    assert!(
        huge_ok,
        "PRODUCT (staging): alice posts the oversized announcement: {huge_said}"
    );
    bob.sees(&room, "huge.bin");
    let short_note = bob
        .daemon
        .as_mut()
        .expect("APPARATUS: bob's daemon")
        .line_within(Duration::from_secs(10), |l| {
            l.contains("not pulled: huge.bin")
        });
    let huge_landed: Vec<String> = std::fs::read_dir(&bob_dl)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("huge.bin"))
        .collect();
    let (huge_get_ok, huge_get_said) = bob.run(&["room", "get", &room, "huge.bin"]);

    // **A folder is listed, not packed** (ADR-028 F-8), shared as a reply to the report's
    // announcement and addressed to carol, so bob pulls it by hand. **A share follows a post's hop
    // rule** (ADR-020 §9): a reply carries its `re` and spends a hop of its parent's budget, so
    // agents sharing back and forth cannot wake each other for ever.
    let report_entry = announcements
        .first()
        .and_then(|a| a["entry_hash"].as_str())
        .unwrap_or_default()
        .to_owned();
    let report_hops = announcements
        .first()
        .and_then(|a| a["envelope"]["hops"].as_u64());
    let photos_rows = |who: &Member| {
        rows_of(who, &room)
            .into_iter()
            .filter(|r| {
                r["envelope"]["type"] == "file" && r["envelope"]["data"]["name"] == "photos"
            })
            .collect::<Vec<_>>()
    };
    // alice shares the folder (again), and bob reads that announcement: the `n`th of the folder.
    let share_photos = |extra: &[&str], n: usize| {
        let mut argv = vec!["share", &room, folder.to_str().unwrap(), "--to", "carol"];
        argv.extend_from_slice(extra);
        let (ok, said) = alice.run(&argv);
        assert!(ok, "PRODUCT (staging): vox share of a folder: {said}");
        let until = Instant::now() + TIMEOUT;
        while photos_rows(&bob).len() < n {
            assert!(
                Instant::now() < until,
                "PRODUCT (staging): bob never read the folder's announcement number {n}"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        said
    };
    let stat = |dir: &Path| -> BTreeMap<String, (u64, std::time::SystemTime, Vec<u8>)> {
        use std::os::unix::fs::MetadataExt as _;
        let mut out = BTreeMap::new();
        for name in (0..9)
            .map(|i| format!("f{i}.txt"))
            .chain(std::iter::once("2026/b.txt".to_owned()))
        {
            if let Ok(m) = std::fs::metadata(dir.join(&name)) {
                let bytes = std::fs::read(dir.join(&name)).unwrap_or_default();
                out.insert(name, (m.ino(), m.modified().unwrap(), bytes));
            }
        }
        out
    };
    let folder_said = share_photos(&["--re", &report_entry], 1);
    let folder_row = photos_rows(&bob).into_iter().next();
    let bob_photos = bob_dl.join("photos");
    let (pull1_ok, pull1) = bob.run(&["room", "get", &room, "photos"]);
    let first = stat(&bob_photos);
    // One file of ten changes, alice shares the folder again, and bob pulls it again.
    std::fs::write(folder.join("f3.txt"), b"file 3, revised").unwrap();
    share_photos(&[], 2);
    let (pull2_ok, pull2) = bob.run(&["room", "get", &room, "photos"]);
    let second = stat(&bob_photos);
    // bob edits his copy of f5; alice shares the folder once more, unchanged: bob's edit is his.
    std::fs::write(bob_photos.join("f5.txt"), b"bob's own edit").unwrap();
    share_photos(&[], 3);
    let (pull3_ok, pull3) = bob.run(&["room", "get", &room, "photos"]);
    let bob_f5 = std::fs::read_to_string(bob_photos.join("f5.txt")).unwrap_or_default();
    let (stop_ok, stop_said) = alice.run(&["share", "stop", &room, "photos"]);
    let (stopped_get_ok, stopped_get_said) = bob.run(&["room", "get", &room, "photos"]);

    // **A pull cut short resumes**: bob's get of a folder of six large files is stopped once two
    // have landed, and his next get fetches only the rest.
    let big = tmp.path().join("big");
    std::fs::create_dir_all(&big).unwrap();
    for i in 0..6u8 {
        let bytes: Vec<u8> = (0..24 * 1024 * 1024u32)
            .map(|b| (b.wrapping_mul(31) >> 5) as u8 ^ i)
            .collect();
        std::fs::write(big.join(format!("part{i}.bin")), bytes).unwrap();
    }
    let (big_ok, big_said) = alice.run(&["share", &room, big.to_str().unwrap(), "--to", "carol"]);
    assert!(
        big_ok,
        "PRODUCT (staging): vox share of the large folder: {big_said}"
    );
    bob.sees(&room, "big/");
    let bob_big = bob_dl.join("big");
    let landed_in = |dir: &Path| -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with('.'))
            .collect();
        names.sort();
        names
    };
    let mut cut_get = Command::new(VOX)
        .args(["room", "get", &room, "big"])
        .env("VOX_DATA_DIR", &bob.dir)
        .env("VOX_CONFIG_DIR", bob.dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("APPARATUS: start bob's get of the large folder");
    let cut_until = Instant::now() + TIMEOUT;
    let cut = loop {
        if landed_in(&bob_big).len() >= 2 {
            let _ = cut_get.kill();
            let _ = cut_get.wait();
            break true;
        }
        if cut_get.try_wait().ok().flatten().is_some() || Instant::now() >= cut_until {
            let _ = cut_get.kill();
            let _ = cut_get.wait();
            break false;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let before_resume = landed_in(&bob_big);
    let (resume_ok, resume_said) = bob.run(&["room", "get", &room, "big"]);
    let resumed = landed_in(&bob_big);

    // **A folder holds at most 100,000 files**: one more is refused, saying so. (Its list is
    // served, not carried in the message, so an ordinary folder of any size passes.)
    let many = tmp.path().join("many");
    for chunk in 0..101 {
        let d = many.join(format!("{chunk:03}"));
        std::fs::create_dir_all(&d).unwrap();
        for i in 0..1000 {
            if chunk * 1000 + i > 100_000 {
                break;
            }
            std::fs::write(d.join(format!("{i:03}")), b"").unwrap();
        }
    }
    let (many_ok, many_said) = alice.run(&["share", &room, many.to_str().unwrap()]);

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
         {get_said}landed {} ({} bytes, sha {})\nshare ended {ended}\nfolder shared: {folder_said}\
         pulls: (ok {pull1_ok}) {pull1}(ok {pull2_ok}) {pull2}(ok {pull3_ok}) {pull3}\
         cut after {before_resume:?} (cut {cut}); resume (ok {resume_ok}): {resume_said}100001 \
         files (ok {many_ok}): {many_said}\nstop: ok {stop_ok}: {stop_said}get after stop: ok \
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
    // #495: pulled by bob's node by itself, verified, into its files directory.
    assert!(
        auto,
        "PRODUCT: a share addressed to bob from a member he trusts must appear, verified, in {} \
         without any command",
        bob_dl.display()
    );
    assert!(
        carol_got,
        "PRODUCT: a share addressed to carol must appear, verified, in her node's files directory"
    );
    assert!(
        !bob_pulled_carols,
        "PRODUCT: bob's node must not pull a share addressed to carol; it landed {} before he \
         asked for it",
        bob_dl.join("for-carol.txt").display()
    );
    assert!(
        card.len() == 2 && card[1].contains("to carol"),
        "PRODUCT: bob must see the share for carol as a card naming her; he read: {card:?}"
    );
    assert!(
        carols_get_ok && bob_got_carols == b"carol's eyes only, by address",
        "PRODUCT: bob may still pull the share for carol with `vox room get`; it said (ok \
         {carols_get_ok}): {carols_get_said}"
    );
    assert!(
        short_note.as_deref().is_some_and(|l| l.contains(
            "it would leave less than 1.0 GB free \
            on the disk holding"
        ) && l.contains("it is pulled when there is room")),
        "PRODUCT: bob's node must say once why it does not pull a share larger than its disk's \
         free space; his daemon said: {short_note:?}"
    );
    assert!(
        huge_landed.is_empty(),
        "PRODUCT: bob's node must write nothing of a share larger than its disk's free space; \
         his files directory holds {huge_landed:?}"
    );
    assert!(
        !huge_get_ok
            && huge_get_said.contains("refusing to pull huge.bin (")
            && huge_get_said.contains("free on the disk holding"),
        "PRODUCT: `vox room get` must refuse a share larger than the disk's free space before \
         dialling, saying why; it said (ok {huge_get_ok}): {huge_get_said}"
    );
    assert!(
        pulled_line == "pulled by bob",
        "PRODUCT: alice's card for report.bin must say it was pulled by bob alone (carol gave up on \
         her fetch, curl exit {carol_cut:?}; mallory could not open it); alice read: \
         {alice_reads}"
    );
    assert!(
        pulled_after_restart == "pulled by bob",
        "PRODUCT: who pulled report.bin is alice's daemon's record and must outlive restarts; \
         after two, under report.bin alice read {pulled_after_restart:?}"
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
        Some(2),
        "PRODUCT: only bob's node's pull and bob's curl were fetches (`vox share list`)"
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
        "PRODUCT: the daemon must stop serving the share by itself after --count 3"
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
    let folder_env = folder_row.map(|r| r["envelope"].clone());
    assert!(
        folder_env
            .as_ref()
            .is_some_and(|e| e["re"] == report_entry.as_str()
                && e["hops"].as_u64().is_some()
                && e["hops"].as_u64() == report_hops.map(|h| h.saturating_sub(1))),
        "PRODUCT: a share replying to an entry must carry it as `re` and its parent's hop budget \
         less one ({report_hops:?} - 1, as `vox room post` does); bob read the folder's \
         announcement as: {folder_env:?}"
    );
    // F-8: the first pull fetches all ten; a re-pull after one changed fetches that one alone,
    // leaving the nine as they were; a file bob changed is his; a cut pull resumes.
    assert!(
        pull1_ok && pull1.contains("(10 files: 10 fetched, 0 already here)") && first.len() == 10,
        "PRODUCT: bob's first get of the folder must fetch its ten files; it said (ok \
         {pull1_ok}): {pull1}"
    );
    let untouched = first
        .iter()
        .filter(|(name, _)| name.as_str() != "f3.txt")
        .all(|(name, was)| second.get(name) == Some(was));
    assert!(
        pull2_ok && pull2.contains("(10 files: 1 fetched, 9 already here)") && untouched,
        "PRODUCT: after one file of ten changed, bob's get must fetch that file alone and leave \
         the nine as they were (untouched: {untouched}); it said (ok {pull2_ok}): {pull2}"
    );
    assert_eq!(
        second.get("f3.txt").map(|(_, _, b)| b.as_slice()),
        Some(&b"file 3, revised"[..]),
        "PRODUCT: bob's copy of the changed file must hold its new bytes"
    );
    assert!(
        pull3_ok
            && pull3.contains("photos/f5.txt was changed here; not replaced")
            && pull3.contains("(10 files: 0 fetched, 9 already here)")
            && bob_f5 == "bob's own edit",
        "PRODUCT: a file bob changed in his copy must be kept and said to be; his get said (ok \
         {pull3_ok}): {pull3}; f5.txt holds {bob_f5:?}"
    );
    assert!(
        cut,
        "APPARATUS (staging not achieved): bob's get of the large folder was not cut with two \
         files landed (it finished, or none landed within {TIMEOUT:?}); landed: {before_resume:?}"
    );
    let resumed_said = format!(
        "(6 files: {} fetched, {} already here)",
        6 - before_resume.len(),
        before_resume.len()
    );
    assert!(
        resume_ok && resume_said.contains(&resumed_said) && resumed.len() == 6,
        "PRODUCT: bob's get after one cut short with {before_resume:?} in place must fetch only \
         the rest, {resumed_said}; it said (ok {resume_ok}): {resume_said}"
    );
    assert!(
        !many_ok && many_said.contains("the most a shared folder may hold"),
        "PRODUCT: a folder of more than 100,000 files must be refused, saying so; `vox share` \
         said (ok {many_ok}): {many_said}"
    );
    assert!(
        stop_ok && stop_said.contains("no longer sharing photos"),
        "PRODUCT: `vox share stop` must stop the folder share; it said: {stop_said}"
    );
    assert!(
        gone(stopped_get_ok, &stopped_get_said, "photos"),
        "PRODUCT: a pull after `vox share stop` must be told the offer is gone; bob's `vox room \
         get` said (ok {stopped_get_ok}): {stopped_get_said}"
    );
    assert!(
        left_ended && gone(after_leave_ok, &after_leave_said, "notes.txt"),
        "PRODUCT: leaving the room must end the share (ended {left_ended}); bob's `vox room get` \
         after alice left said (ok {after_leave_ok}): {after_leave_said}"
    );
    drop((alice, bob, mallory, carol, anchor));
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
        &["room", "join", "--passphrase-file", "-", link.trim()],
        Some(&format!("{ROOM_PASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): bob joins files: {out}{err}");

    let (shared_ok, shared_said) = alice.run(&[
        "share",
        &room,
        file.to_str().expect("APPARATUS: a UTF-8 path"),
        "--count",
        "2",
    ]);
    assert!(shared_ok, "PRODUCT (staging): vox share: {shared_said}");
    let tag = tag_of(&shared_said);
    // bob's node pulls it by itself first (ADR-028 F-3): that is the first fetch, so the slow curl
    // below is the last.
    let bob_files = files_of(&bob, &room);
    assert!(
        arrives(&bob_files.join("big.bin"), &sha(&payload), SETUP),
        "PRODUCT (staging): bob's node never pulled the share by itself, so the slow fetch would \
         not be the last"
    );
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
        "PRODUCT: the daemon must still stop serving the share by itself after --count 2"
    );
    drop((alice, bob, anchor));
}
