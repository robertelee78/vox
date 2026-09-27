//! **RP-28 — no consent without a ring entry: joining grants nothing**, through the shipped
//! `vox` binary only: a `vox node` anchor and three `vox daemon`s, every step typed as an
//! operator types it (`vox id`, `vox trust add`, `vox room create|invite|join|post|read`).
//!
//! Replaces the networked half of `crates/vox-core/tests/sec_no_consent_without_a_ring_entry.rs`,
//! which ran every node in-process (V29-17). Its other half — a forged board record is refused
//! admission ("no author without evidence") — is **not** covered here: no `vox` command can
//! publish a forged member-bundle record, and no test-side hostile wire client exists yet (see
//! the item's report).
//!
//! ## The claim
//! A sender key — the thing that lets someone read you — is released **only** to identities in
//! this node's trust keyring. Joining a room does not release the joiner's key to the member
//! that answered the join (M17.6), and being a room member is not a ring entry. And it holds in
//! **every** room the two share, not just the first.
//!
//! `a_room_admits_the_passphrase_and_authors_decide_readers.rs` shows the creator's key is not
//! released to an untrusted joiner; this is the other direction — the joiner's key and the
//! responder — across two rooms.
//!
//! ## The staging
//! 1. Alice creates **two** rooms; her `vox room invite` links pin her, so she is the member
//!    that answers every join. Bob and Carol join both (a set-up join is retried, as
//!    `support/room.rs` does, for the separate known host-busy refusal).
//! 2. After the joins: **Bob trusts Carol only — never Alice.** Alice trusts Bob and Carol;
//!    Carol trusts Alice and Bob.
//! 3. Positive controls, per room: Bob posts until Carol renders one (Bob's node does release
//!    his key, to whom his ring names); Bob posts a final line and Carol renders it; then Carol
//!    posts until Alice renders one of hers — Alice's node is receiving the room, past Bob's
//!    final post (Carol held it before she posted). Any control failing is `CANNOT MEASURE`.
//!
//! ## What is asserted
//! After the controls and 10 s more to settle, Alice renders **0** of Bob's posts in room one
//! and **0** in room two. Each final `vox room read` must itself succeed **and** show Alice's
//! earlier `CAROL-TO-ALICE-IN-{room}` line, otherwise `CANNOT MEASURE`: a dead or wedged daemon
//! reads as 0 bytes, which must never count as 0 of Bob's posts.
//!
//! ## The mutations that must turn it red
//! - M1: the join releases the joiner's key to its responder — `self.consent(&parsed.channel_id,
//!   responder, false).await` restored before `NodeEvent::Joined` in `crates/vox-core/src/node/actor.rs`.
//! - M2: consent without a keyring check — `.filter(|a| trusted.contains(a))` removed from
//!   `ChannelState::owed_consents` in `crates/vox-core/src/node/channel.rs`.
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

fn join(m: &Member, link: &str, name: &str) {
    let joined = (1..=6).any(|attempt| {
        let (ok, o, e) = m.vox(
            &["room", "join", link, "--name", name],
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
    assert!(joined, "CANNOT MEASURE: {} could not join {name}", m.name);
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

/// Alice's room, by the name she gave it, and the link she mints for it (which pins her).
fn make_room(alice: &Member, name: &str) -> (String, String) {
    let (ok, _, e) = alice.vox(
        &["room", "create", "--name", name],
        Some(&format!("{ROOM_PASS}\n")),
    );
    assert!(ok, "room create {name}: {e}");
    let listed = alice.vox(&["room", "list"], None).1;
    let room = listed
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some(name))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("{name} in `vox room list`: {listed}"))
        .to_owned();
    let (ok, link, e) = alice.vox(&["room", "invite", &room], None);
    assert!(ok, "invite {name}: {e}");
    let link = link.trim().to_owned();
    assert!(
        link.contains(&format!("r={}", alice.fp)),
        "CANNOT MEASURE: the link for {name} does not pin alice, so she is not provably the \
         member that answers the joins: {link}"
    );
    (room, link)
}

fn count(text: &str, tag: &str) -> usize {
    text.lines().filter(|l| l.contains(tag)).count()
}

#[test]
#[ignore = "an anchor and three daemons with production Argon2id; CI runs it in release"]
fn joining_grants_nothing_and_only_the_ring_releases_a_key() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (_anchor, spec) = anchor(tmp.path());
    let alice = member(tmp.path(), "alice", &spec);
    let bob = member(tmp.path(), "bob", &spec);
    let carol = member(tmp.path(), "carol", &spec);

    let rooms = [make_room(&alice, "one"), make_room(&alice, "two")];
    for ((_, link), name) in rooms.iter().zip(["one", "two"]) {
        join(&bob, link, name);
        join(&carol, link, name);
    }

    // ---- the decisions: bob's ring names carol, never alice ----
    bob.trust(&carol);
    alice.trust(&bob);
    alice.trust(&carol);
    carol.trust(&alice);
    carol.trust(&bob);

    let mut alice_read_bob = Vec::new();
    for ((room, _), name) in rooms.iter().zip(["one", "two"]) {
        let tag = format!("BOB-IN-{name}");
        let bc = posts_until_read(&bob, &carol, room, &tag, Duration::from_secs(120));
        assert!(
            bc.is_some(),
            "CANNOT MEASURE: in room {name}, carol (in bob's ring) never rendered bob, so bob's \
             node releasing nothing to alice would prove nothing"
        );
        let final_line = format!("BOB-FINAL-IN-{name}");
        let (ok, _, e) = bob.vox(&["room", "post", room, &final_line], None);
        assert!(ok, "bob posts: {e}");
        assert!(
            until(
                &format!("carol renders {final_line}"),
                Duration::from_secs(60),
                || { carol.reads(room, &final_line) }
            ),
            "CANNOT MEASURE: carol never rendered bob's final post in room {name}"
        );
        let ca = posts_until_read(
            &carol,
            &alice,
            room,
            &format!("CAROL-TO-ALICE-IN-{name}"),
            Duration::from_secs(120),
        );
        assert!(
            ca.is_some(),
            "CANNOT MEASURE: alice never rendered carol in room {name}, so alice is not provably \
             receiving the room"
        );
        eprintln!(
            "[proof] room {name}: carol rendered bob after {bc:?} posts; alice rendered carol after {ca:?} posts"
        );
        alice_read_bob.push((name, room.clone(), bc.unwrap() + 1));
    }

    std::thread::sleep(Duration::from_secs(10));
    let mut leaked = 0;
    for (name, room, posted) in &alice_read_bob {
        // The same read must succeed and still show what alice rendered in the control:
        // a daemon that died or wedged reads as 0 bytes, which would count as 0 of bob's.
        let (ok, seen, e) = alice.vox(&["room", "read", room], None);
        let control = format!("CAROL-TO-ALICE-IN-{name}");
        assert!(
            ok && seen.contains(&control),
            "CANNOT MEASURE: alice's final read of room {name} did not succeed with her earlier \
             {control} in it (ok={ok}), so 0 of bob's posts would prove nothing: {e}"
        );
        let n = count(&seen, "BOB-");
        leaked += n;
        eprintln!("[proof] room {name}: alice renders {n} of bob's {posted} posts");
    }
    assert_eq!(
        leaked, 0,
        "alice renders {leaked} of bob's posts, but bob never put her in his ring: joining (she \
         answered both joins) or room membership released his key"
    );
}
