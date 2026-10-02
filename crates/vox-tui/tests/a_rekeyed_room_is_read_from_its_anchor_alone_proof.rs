//! V210-137 (#356) — **after a re-key, a member who can reach only the anchor still reads the
//! room**, through the shipped `vox` binary only: a `vox node` anchor and three `vox daemon`s, every
//! step typed as an operator types it (`vox id`, `vox trust add|remove`,
//! `vox room create|invite|join|post|read`).
//!
//! ## Why
//! An anchor keeps a ciphertext copy of each room's log and admits its authors at **epoch 0
//! only** (`node/anchor.rs`). No shipped path moves a room off epoch 0: the re-key a person can
//! make, `vox trust remove`, rotates sender chains inside the epoch. So the anchor's copy must keep
//! taking and serving a room's entries across a re-key. This proof is the user's view of that: the
//! only re-key there is, then the one member left reading **from the anchor alone**.
//!
//! ## The staging
//! 1. Alice creates a room; Bob and Carol join with the link; all three trust each other. Carol
//!    reads Alice (precondition).
//! 2. **Control, before any re-key.** Carol's daemon stops. Alice posts [`CONTROL`] and Bob reads
//!    it. Alice's and Bob's daemons stop, Carol's starts: the anchor is the only node holding the
//!    room. Carol must read it within [`FROM_ANCHOR`], or the staging cannot show anything
//!    (`CANNOT MEASURE`).
//! 3. Alice's and Bob's daemons start again, and Carol's stops once Alice reads a post of hers.
//! 4. **The re-key.** Alice runs `vox trust remove <bob>`, which rotates her sender key and re-keys
//!    everyone still trusted, then posts [`AFTER`] messages, and Bob's node takes them in its log.
//!    Alice's and Bob's daemons stop, Carol's starts.
//!
//! ## What is asserted
//! Carol, reaching only the anchor, reads **all** of Alice's post-removal messages within
//! [`FROM_ANCHOR`] (`PRODUCT` otherwise).
//!
//! ## What would turn it red
//! The anchor refusing a re-keyed room's entries (an epoch or admission it does not follow), or
//! refusing to serve them, or a re-key whose new key reaches a member only from its author.
#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const ID_PASS: &str = "identity passphrase";
const ROOM_PASS: &str = "channel passphrase";

/// What Alice posts before any re-key, with Carol offline.
const CONTROL: &str = "BEFORE-REKEY-CONTROL";
/// How many messages Alice posts after removing Bob, with Carol offline.
const AFTER: u32 = 3;
/// How long Carol, reaching only the anchor, may take to read what it holds.
const FROM_ANCHOR: Duration = Duration::from_secs(90);

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
    pass: PathBuf,
    fp: String,
    log: PathBuf,
    anchor: String,
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
            .expect("spawn vox");
        if let Some(text) = stdin {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
        }
        let out = child.wait_with_output().expect("vox ran");
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
                self.pass.to_str().unwrap(),
            ],
            None,
        );
        assert!(
            ok,
            "CANNOT MEASURE (staging): {} trusts {}: {o}{e}",
            self.name, other.name
        );
    }

    /// Start this member's daemon, pointed at the anchor, and wait until it answers.
    fn start(&mut self) {
        let err = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .unwrap();
        let child = Command::new(VOX)
            .args([
                "daemon",
                "--listen",
                "127.0.0.1:0",
                "--anchor",
                &self.anchor,
            ])
            .arg("--passphrase-file")
            .arg(&self.pass)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", self.data.join("cfg"))
            .env_remove("VOX_ROOM")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(err))
            .spawn()
            .expect("spawn vox daemon");
        self.daemon = Some(Proc(child));
        let deadline = Instant::now() + Duration::from_secs(90);
        while !self.vox(&["room", "list"], None).0 {
            assert!(
                Instant::now() < deadline,
                "CANNOT MEASURE: {}'s daemon never answered",
                self.name
            );
            std::thread::sleep(Duration::from_millis(500));
        }
        eprintln!("[proof] {}'s daemon is up", self.name);
    }

    /// Stop this member's daemon, by its PID, and reap it.
    fn stop(&mut self) {
        drop(self.daemon.take());
        eprintln!("[proof] {}'s daemon is stopped", self.name);
    }
}

fn member(tmp: &Path, name: &'static str, anchor: &str) -> Member {
    let data = tmp.join(name);
    std::fs::create_dir_all(data.join("cfg")).unwrap();
    let pass = tmp.join(format!("{name}.pass"));
    std::fs::write(&pass, ID_PASS).unwrap();
    let mut m = Member {
        name,
        data,
        pass,
        fp: String::new(),
        log: tmp.join(format!("{name}.daemon.err")),
        anchor: anchor.to_owned(),
        daemon: None,
    };
    let (ok, out, err) = m.vox(
        &["id", "--identity-passphrase-file", m.pass.to_str().unwrap()],
        None,
    );
    assert!(ok, "{name}: vox id: {err}");
    m.fp = out.trim().to_owned();
    assert_eq!(m.fp.len(), 52, "{name}: a fingerprint from vox id");
    m.start();
    m
}

fn anchor(tmp: &Path) -> (Proc, String) {
    let dir = tmp.join("anchor");
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    let out = tmp.join("anchor.out");
    let p = Proc(
        Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .stdout(Stdio::from(std::fs::File::create(&out).unwrap()))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vox node"),
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
            "CANNOT MEASURE: the anchor never printed its spec"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn join(m: &Member, link: &str, name: &str) {
    let joined = (1..=6).any(|attempt| {
        let (ok, o, e) = m.vox(
            &["room", "join", link, "--name", name],
            Some(&format!("{ROOM_PASS}\n")),
        );
        if !ok {
            eprintln!(
                "[harness] {} join of {name} attempt {attempt} refused: {o}{e}",
                m.name
            );
            std::thread::sleep(Duration::from_secs(5));
        }
        ok
    });
    assert!(
        joined,
        "CANNOT MEASURE (staging): {} could not join {name} after 6 attempts",
        m.name
    );
}

/// The id `vox room list` prints for the room named `name`.
fn room_id(m: &Member, name: &str) -> String {
    let (ok, list, e) = m.vox(&["room", "list"], None);
    assert!(ok, "CANNOT MEASURE: {}'s room list: {e}", m.name);
    list.lines()
        .find(|l| l.split_whitespace().any(|w| w == name))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| {
            panic!(
                "CANNOT MEASURE: {name} is not in {}'s room list: {list}",
                m.name
            )
        })
        .to_owned()
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
        assert!(ok, "{} posts: {e}", author.name);
        std::thread::sleep(Duration::from_secs(1));
        if reader.reads(room, &format!("{tag} ")) {
            return Some(n);
        }
    }
    None
}

/// How long `ok` took to hold, polled every half second, or `None` past `within`.
fn until(within: Duration, ok: impl Fn() -> bool) -> Option<Duration> {
    let t0 = Instant::now();
    while t0.elapsed() < within {
        if ok() {
            return Some(t0.elapsed());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    None
}

#[test]
#[ignore = "an anchor and three daemons with production Argon2id; CI runs it in release"]
fn a_rekeyed_room_is_read_from_its_anchor_alone() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (_anchor, spec) = anchor(tmp.path());
    let mut alice = member(tmp.path(), "alice", &spec);
    let mut bob = member(tmp.path(), "bob", &spec);
    let mut carol = member(tmp.path(), "carol", &spec);

    // ---- 1. one room, all three in it, everyone trusting everyone ----
    let (ok, _, e) = alice.vox(
        &["room", "create", "--name", "team"],
        Some(&format!("{ROOM_PASS}\n")),
    );
    assert!(ok, "CANNOT MEASURE (staging): vox room create failed: {e}");
    let room = room_id(&alice, "team");
    let (ok, link, e) = alice.vox(&["room", "invite", &room], None);
    assert!(ok, "CANNOT MEASURE (staging): vox room invite failed: {e}");
    join(&bob, link.trim(), "team");
    join(&carol, link.trim(), "team");
    for a in [&alice, &bob, &carol] {
        for b in [&alice, &bob, &carol] {
            if a.fp != b.fp {
                a.trust(b);
            }
        }
    }
    let ab = posts_until_read(&alice, &bob, &room, "READY-BOB", Duration::from_secs(120));
    let ac = until(Duration::from_secs(60), || carol.reads(&room, "READY-BOB "));
    let cb = posts_until_read(&carol, &bob, &room, "READY-CAROL", Duration::from_secs(120));
    let ca = until(Duration::from_secs(60), || {
        alice.reads(&room, "READY-CAROL ")
    });
    eprintln!("[proof] ready: alice->bob {ab:?}, alice->carol {ac:?}, carol->bob {cb:?}, carol->alice {ca:?}");
    assert!(
        ab.is_some() && ac.is_some() && cb.is_some() && ca.is_some(),
        "CANNOT MEASURE: the room never became readable both ways (alice->bob {ab:?}, \
         alice->carol {ac:?}, carol->bob {cb:?}, carol->alice {ca:?})"
    );

    // ---- 2. control: before any re-key, carol reads from the anchor alone ----
    carol.stop();
    let (ok, _, e) = alice.vox(&["room", "post", &room, CONTROL], None);
    assert!(
        ok,
        "CANNOT MEASURE (staging): alice's control post failed: {e}"
    );
    assert!(
        until(Duration::from_secs(60), || bob.reads(&room, CONTROL)).is_some(),
        "CANNOT MEASURE: bob never read alice's control post, so it may not have left her node"
    );
    alice.stop();
    bob.stop();
    carol.start();
    let control = until(FROM_ANCHOR, || carol.reads(&room, CONTROL));
    eprintln!("[proof] control: carol, reaching only the anchor, read it after {control:?}");
    assert!(
        control.is_some(),
        "CANNOT MEASURE: before any re-key, carol reaching only the anchor did not read alice's \
         post within {FROM_ANCHOR:?}: the anchor does not carry this room here, so the re-key arm \
         would show nothing"
    );

    // ---- 3. everyone back, then carol away again ----
    alice.start();
    bob.start();
    let back = posts_until_read(&carol, &alice, &room, "BACK", Duration::from_secs(120));
    let back_bob = until(Duration::from_secs(60), || bob.reads(&room, "BACK "));
    assert!(
        back.is_some() && back_bob.is_some(),
        "CANNOT MEASURE: after the restart alice ({back:?}) and bob ({back_bob:?}) never read \
         carol again"
    );
    carol.stop();

    // ---- 4. the re-key: alice removes bob, posts, and only the anchor is left for carol ----
    let (ok, o, e) = alice.vox(
        &[
            "trust",
            "remove",
            &bob.fp,
            "--identity-passphrase-file",
            alice.pass.to_str().unwrap(),
        ],
        None,
    );
    assert!(
        ok,
        "CANNOT MEASURE (staging): vox trust remove bob failed: {o}{e}"
    );
    let after: Vec<String> = (1..=AFTER).map(|n| format!("AFTER-REKEY {n}")).collect();
    for text in &after {
        let (ok, _, e) = alice.vox(&["room", "post", &room, text], None);
        assert!(
            ok,
            "CANNOT MEASURE (staging): alice's post-removal post failed: {e}"
        );
    }
    // Bob can no longer read alice, but his node still syncs the room; give her posts the same
    // time to leave her node that the control had.
    std::thread::sleep(Duration::from_secs(10));
    alice.stop();
    bob.stop();
    carol.start();
    let t0 = Instant::now();
    let read = until(FROM_ANCHOR, || {
        let (_, out, _) = carol.vox(&["room", "read", &room], None);
        after.iter().all(|t| out.contains(t.as_str()))
    });
    let (_, seen, _) = carol.vox(&["room", "read", &room], None);
    let got = after.iter().filter(|t| seen.contains(t.as_str())).count();
    eprintln!(
        "[proof] after the re-key: carol, reaching only the anchor, read {got} of {AFTER} after \
         {:?} ({read:?})",
        t0.elapsed()
    );
    assert!(
        read.is_some(),
        "PRODUCT: after alice's `vox trust remove` re-keyed the room, carol, reaching only the \
         anchor, read {got} of alice's {AFTER} later posts within {FROM_ANCHOR:?}; the control \
         before the re-key took {control:?}.\ncarol's room read:\n{seen}"
    );
}
