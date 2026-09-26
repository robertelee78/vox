//! **RP-17 — revocation rotates the key with one member left out**, through the shipped `vox`
//! binary only: a `vox node` anchor and three `vox daemon`s, every step typed as an operator
//! types it (`vox id`, `vox trust add|remove`, `vox room create|invite|join|post|read`).
//!
//! Replaces `crates/vox-core/tests/node_m18_revocation_gate.rs`, which ran every node
//! in-process (V29-17).
//!
//! ## The claim
//! `vox trust remove <bob>` on Alice's node removes the ring entry **and changes the lock**:
//! Alice's sender key is rotated and everyone still trusted is re-keyed, in every room shared
//! with Bob. So Bob, who holds Alice's old key, reads nothing Alice posts afterwards, while
//! Carol, still trusted, reads all of it — the rotation costs her nothing. What Bob already
//! read stays read (it cannot be recalled).
//!
//! `a_retrust_does_not_inherit_a_withdrawn_key_proof.rs` covers a key that was never
//! delivered; this covers a key that **was** delivered and is in use.
//!
//! ## The staging
//! 1. Alice creates the room; Bob and Carol join with the link (a set-up join is retried, as
//!    `support/room.rs` does, for the separate known host-busy refusal); all three trust each
//!    other after the joins.
//! 2. Precondition: Bob and Carol each render a post by Alice, and Bob renders one by Carol
//!    (`CANNOT MEASURE` otherwise) — Bob really holds Alice's key before she removes him.
//! 3. Alice runs `vox trust remove <bob>`, then posts [`AFTER`] fresh messages.
//! 4. Carol must render all of them. Then Carol posts until Bob renders one of hers — a
//!    **positive control** that Bob's node is still syncing the room (and Carol's post comes
//!    after she already held Alice's), so Bob's silence below is the lock, not the plumbing.
//!
//! ## What is asserted
//! - Carol renders **3 of 3** of Alice's post-removal messages, within 90 s.
//! - Bob, with the control proved and 10 s more to settle, renders **0 of 3**.
//! - Bob still renders what Alice said before the removal.
//!
//! ## The mutation that must turn it red
//! Drop `self.change_the_lock_against(fingerprint).await;` from `untrust_identity` in
//! `crates/vox-core/src/node/actor.rs`: the ring entry goes but the key is not rotated, so Bob
//! keeps opening Alice's new posts with the key he already holds.
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
        assert!(ok, "{} trusts {}: {o}{e}", self.name, other.name);
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
        daemon: None,
    };
    let (ok, out, err) = m.vox(
        &["id", "--identity-passphrase-file", m.pass.to_str().unwrap()],
        None,
    );
    assert!(ok, "{name}: vox id: {err}");
    m.fp = out.trim().to_owned();
    assert_eq!(m.fp.len(), 52, "{name}: a fingerprint from vox id");
    let err = std::fs::File::create(tmp.join(format!("{name}.daemon.err"))).unwrap();
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
        .expect("spawn vox daemon");
    m.daemon = Some(Proc(child));
    let deadline = Instant::now() + Duration::from_secs(90);
    while !m.vox(&["room", "list"], None).0 {
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE: {name}'s daemon never answered"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
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

/// How many messages Alice posts after removing Bob.
const AFTER: u32 = 3;

fn join(m: &Member, link: &str) {
    let joined = (1..=6).any(|attempt| {
        let (ok, o, e) = m.vox(
            &["room", "join", link, "--name", "team"],
            Some(&format!("{ROOM_PASS}\n")),
        );
        if !ok {
            eprintln!(
                "[harness] {} join attempt {attempt} refused: {o}{e}",
                m.name
            );
            std::thread::sleep(Duration::from_secs(5));
        }
        ok
    });
    assert!(joined, "CANNOT MEASURE: {} could not join the room", m.name);
}

fn until(what: &str, within: Duration, ok: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    eprintln!("[proof] {what}: not within {}s", within.as_secs());
    false
}

#[test]
#[ignore = "an anchor and three daemons with production Argon2id; CI runs it in release"]
fn removing_one_member_rotates_the_key_and_keeps_the_others_whole() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (_anchor, spec) = anchor(tmp.path());
    let alice = member(tmp.path(), "alice", &spec);
    let bob = member(tmp.path(), "bob", &spec);
    let carol = member(tmp.path(), "carol", &spec);

    // ---- one room, all three in it, everyone trusting everyone ----
    let (ok, _, e) = alice.vox(
        &["room", "create", "--name", "team"],
        Some(&format!("{ROOM_PASS}\n")),
    );
    assert!(ok, "room create: {e}");
    let room = alice
        .vox(&["room", "list"], None)
        .1
        .split_whitespace()
        .next()
        .expect("the new room in `vox room list`")
        .to_owned();
    let (ok, link, e) = alice.vox(&["room", "invite", &room], None);
    assert!(ok, "invite: {e}");
    join(&bob, link.trim());
    join(&carol, link.trim());
    for a in [&alice, &bob, &carol] {
        for b in [&alice, &bob, &carol] {
            if a.fp != b.fp {
                a.trust(b);
            }
        }
    }

    // ---- precondition: bob holds alice's key and reads her, as does carol ----
    let ab = posts_until_read(
        &alice,
        &bob,
        &room,
        "EVERYONE-READS-THIS",
        Duration::from_secs(120),
    );
    let ac = until("carol reads alice before", Duration::from_secs(60), || {
        carol.reads(&room, "EVERYONE-READS-THIS ")
    });
    let cb = posts_until_read(&carol, &bob, &room, "CAROL-READY", Duration::from_secs(120));
    eprintln!("[proof] ready: alice->bob after {ab:?} posts, alice->carol {ac}, carol->bob after {cb:?} posts");
    assert!(
        ab.is_some() && ac && cb.is_some(),
        "CANNOT MEASURE: the room never became readable (alice->bob {ab:?}, alice->carol {ac}, \
         carol->bob {cb:?})"
    );

    // ---- alice removes bob, then keeps talking ----
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
    assert!(ok, "alice removes bob: {o}{e}");
    for n in 1..=AFTER {
        let (ok, _, e) = alice.vox(
            &["room", "post", &room, &format!("ONLY-CAROL-READS-THIS {n}")],
            None,
        );
        assert!(ok, "alice posts: {e}");
    }

    // ---- carol reads every one of them ----
    let carol_all = until(
        "carol reads all of alice's post-removal messages",
        Duration::from_secs(90),
        || {
            let seen = carol.vox(&["room", "read", &room], None).1;
            (1..=AFTER).all(|n| seen.contains(&format!("ONLY-CAROL-READS-THIS {n}")))
        },
    );
    let carol_seen = carol.vox(&["room", "read", &room], None).1;
    let carol_count = (1..=AFTER)
        .filter(|n| carol_seen.contains(&format!("ONLY-CAROL-READS-THIS {n}")))
        .count();

    // ---- positive control: bob is still receiving the room ----
    let control = posts_until_read(
        &carol,
        &bob,
        &room,
        "CAROL-AFTER-REMOVAL",
        Duration::from_secs(90),
    );
    std::thread::sleep(Duration::from_secs(10));
    let bob_seen = bob.vox(&["room", "read", &room], None).1;
    let bob_count = (1..=AFTER)
        .filter(|n| bob_seen.contains(&format!("ONLY-CAROL-READS-THIS {n}")))
        .count();
    let bob_before = bob_seen.contains("EVERYONE-READS-THIS ");
    eprintln!(
        "[proof] after the removal: carol read {carol_count}/{AFTER}, bob read {bob_count}/{AFTER}; \
         control (bob reads carol) after {control:?} posts; bob still reads the pre-removal post: {bob_before}"
    );
    assert!(
        carol_all && carol_count == 3,
        "carol, still trusted, must read all of alice's messages across the rotation: read {carol_count}/3"
    );
    assert!(
        control.is_some(),
        "CANNOT MEASURE: bob never rendered carol's post after the removal, so his not reading \
         alice would prove nothing"
    );
    assert_eq!(
        bob_count, 0,
        "bob, removed from alice's ring, still reads {bob_count}/3 of what she posted afterwards: \
         `vox trust remove` did not change the lock"
    );
    assert!(
        bob_before,
        "what bob read before the removal is not recalled"
    );
}
