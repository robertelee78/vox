//! **RP-20 (with RP-17) — revocation rotates the key in every shared room, with one member left
//! out**, through the shipped `vox` binary only: a `vox node` anchor and three `vox daemon`s, every
//! step typed as an operator types it (`vox id`, `vox trust add|remove`,
//! `vox room create|invite|join|post|read`).
//!
//! Replaces `crates/vox-core/tests/node_m18_revocation_gate.rs` and
//! `node_m19_untrust_lock_gate.rs`, which ran every node in-process (V29-17).
//!
//! ## The claim
//! `vox trust remove <bob>` on Alice's node removes the ring entry **and changes the lock**:
//! Alice's sender key is rotated and everyone still trusted is re-keyed, **in every room shared
//! with Bob**. So Bob, who holds Alice's old key, reads nothing Alice posts afterwards, in any of
//! those rooms, while Carol — still trusted, and still trusting Alice — reads all of it, the
//! rotation costing her nothing. What Bob already read stays read.
//!
//! Trust is per direction (V210-118): Carol reads Alice because Carol trusts Alice and holds the
//! key Alice released to her; this proof trusts everyone to everyone before it begins, so no
//! assertion here depends on reading a member one has not trusted.
//!
//! `a_retrust_does_not_inherit_a_withdrawn_key_proof.rs` covers a key that was never delivered;
//! this covers a key that **was** delivered and is in use.
//!
//! ## The staging
//! 1. Alice creates **two** rooms, `team` and `side` — each with its own sender keys, so the
//!    removal has to change the lock in each of them (RP-20's quantifier); Bob and Carol join both
//!    with the links, once each (a join that fails is `PRODUCT`); all three trust each other after
//!    the joins.
//! 2. Precondition, in every room: Bob and Carol each render a post by Alice, and Bob renders one
//!    by Carol (`PRODUCT (staging)` otherwise) — Bob really holds Alice's key before she removes him.
//! 3. In every room Alice posts a `BEFORE-REMOVAL-CONTROL` and Bob renders it.
//! 4. Alice runs `vox trust remove <bob>`, then posts [`AFTER`] fresh messages in each room.
//! 5. In each room Carol posts until Bob renders one of hers — a **positive control** that Bob's
//!    node is still syncing that room, so Bob's silence on Alice's posts below is the lock, not the
//!    plumbing.
//!
//! ## What is asserted, in each of the 2 rooms
//! - Carol renders **3 of 3** of Alice's post-removal messages, within 90 s.
//! - Bob, with the control proved and 10 s more to settle, renders **0 of 3**.
//! - Bob still renders what Alice said before the removal.
//!
//! **What this does not prove by real use.** That Bob reads 0/3 is the shipped binary refusing;
//! it does not, on its own, tell "his node declines" from "no key he holds opens it". Showing the
//! latter needs a **modified** node that ignores the revocation and reads Bob's own store, which
//! AGENTS.md forbids in a committed proof (no in-process `vox-core`, no assertion on an internal
//! value). So RP-17's sharper "can't, not won't" half rests on review of the rotation code plus a
//! **reported spike** (`~/vox-coord/logs/ac-fix70/spike/rp17_attacker_arm_spike.rs`, run and
//! reported in the candidate post), not on this gate.
//!
//! It also asserts what `vox trust remove` says (ADR-028 E-5): before it acts, a "vox: about to
//! stop trusting" line, then a line naming both rooms bob is to read nothing new in; after, "vox: no
//! longer trusting".
//!
//! ## The mutations that must turn it red
//! - **Change the lock in one shared room only** (RP-20): `change_the_lock_against` in
//!   `crates/vox-core/src/node/actor.rs` stops after the first room it revokes in. The other room
//!   keeps its old key, so Bob renders Alice's post-removal posts there.
//! - Drop `self.change_the_lock_against(fingerprint).await;` from `untrust_identity` in
//!   `crates/vox-core/src/node/actor.rs`: the ring entry goes but the key is not rotated, so Bob
//!   keeps opening Alice's new posts with the key he already holds.
#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/layout.rs"]
mod layout;
#[path = "support/typed.rs"]
mod typed;

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
        let mut cmd = Command::new(VOX);
        cmd.args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", self.data.join("cfg"))
            .env_remove("VOX_ROOM")
            .env_remove("VOX_SESSION")
            .env_remove("VOX_ROOM_PASSPHRASE");
        // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028
        // K-13).
        if typed::is_keyring_change(args) {
            let (ok, shown) = typed::keyring(&cmd);
            return (ok, shown.clone(), shown);
        }
        let mut child = cmd
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
                .expect("APPARATUS: vox's stdin")
                .write_all(text.as_bytes())
                .expect("PRODUCT (staging): vox exited without reading its stdin");
        }
        let out = child.wait_with_output().expect("APPARATUS: wait for vox");
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
                self.pass.to_str().expect("APPARATUS: a UTF-8 temp path"),
            ],
            None,
        );
        assert!(
            ok,
            "PRODUCT (staging): {} could not trust {}: {o}{e}",
            self.name, other.name
        );
    }
}

fn member(tmp: &Path, name: &'static str, anchor: &str) -> Member {
    let data = tmp.join(name);
    std::fs::create_dir_all(data.join("cfg")).expect("APPARATUS: create a staging dir");
    let pass = tmp.join(format!("{name}.pass"));
    std::fs::write(&pass, ID_PASS).expect("APPARATUS: write a staging file");
    let mut m = Member {
        name,
        data,
        pass,
        fp: String::new(),
        daemon: None,
    };
    let (ok, out, err) = m.vox(
        &[
            "id",
            "--identity-passphrase-file",
            m.pass.to_str().expect("APPARATUS: a UTF-8 temp path"),
        ],
        None,
    );
    assert!(ok, "PRODUCT (staging): {name}: vox id: {err}");
    m.fp = out.trim().to_owned();
    assert_eq!(
        m.fp.len(),
        52,
        "PRODUCT: `vox id` printed no 52-character fingerprint for {name}: {:?}",
        m.fp
    );
    let err = std::fs::File::create(tmp.join(format!("{name}.daemon.err")))
        .expect("APPARATUS: create a log file");
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
    std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: create a staging dir");
    let out = tmp.join("anchor.out");
    let p = Proc(
        Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .stdout(Stdio::from(
                std::fs::File::create(&out).expect("APPARATUS: create a log file"),
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
        assert!(
            ok,
            "PRODUCT: `vox room post` failed for {}: {e}",
            author.name
        );
        std::thread::sleep(Duration::from_secs(1));
        if reader.reads(room, &format!("{tag} ")) {
            return Some(n);
        }
    }
    None
}

/// How many messages Alice posts after removing Bob.
const AFTER: u32 = 3;

fn join(m: &Member, link: &str, name: &str) {
    // One join, no retry: a join that fails is the product's failure, and #217's busy-host
    // refusal is fixed (V210-43), so nothing known excuses one.
    let (ok, o, e) = m.vox(
        &["room", "join", "--passphrase-file", "-", link],
        Some(&format!("{ROOM_PASS}\n")),
    );
    assert!(
        ok,
        "PRODUCT: `vox room join` of {name} failed for {}.\nstdout: {o}\nstderr: {e}",
        m.name
    );
}

/// The rooms every member shares: each one is a separate room with its own sender keys, so the
/// removal must change the lock in each of them, not just in one.
const ROOMS: [&str; 2] = ["team", "side"];

/// The id `vox room list` prints for the room named `name`.
fn room_id(m: &Member, name: &str) -> String {
    let (ok, list, e) = m.vox(&["room", "list"], None);
    assert!(ok, "PRODUCT (staging): {}'s room list: {e}", m.name);
    list.lines()
        .find(|l| l.split_whitespace().any(|w| w == name))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT (staging): {name} is not in {}'s room list: {list}",
                m.name
            )
        })
        .to_owned()
}

/// Send `sig` to `pid` with `kill(1)` — by PID, never by pattern.
fn signal(pid: u32, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .expect("APPARATUS: run kill")
        .success();
    assert!(ok, "APPARATUS: `kill {sig} {pid}` failed");
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
fn removing_one_member_rotates_the_key_in_every_shared_room_and_keeps_the_others_whole() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a tempdir");
    let (_anchor, spec) = anchor(tmp.path());
    let alice = member(tmp.path(), "alice", &spec);
    let bob = member(tmp.path(), "bob", &spec);
    let carol = member(tmp.path(), "carol", &spec);

    // ---- two rooms, all three in each, everyone trusting everyone ----
    let mut rooms = Vec::new();
    for name in ROOMS {
        let (ok, _, e) = alice.vox(
            &["room", "create", "--passphrase-file", "-", "--name", name],
            Some(&format!("{ROOM_PASS}\n")),
        );
        assert!(ok, "PRODUCT (staging): vox room create {name} failed: {e}");
        let room = room_id(&alice, name);
        let (ok, link, e) = alice.vox(&["room", "link", &room], None);
        assert!(ok, "PRODUCT (staging): vox room link {name} failed: {e}");
        join(&bob, link.trim(), name);
        join(&carol, link.trim(), name);
        rooms.push((name, room));
    }
    for a in [&alice, &bob, &carol] {
        for b in [&alice, &bob, &carol] {
            if a.fp != b.fp {
                a.trust(b);
            }
        }
    }
    // Each member's own id for each room (the ids are the room's, the same on every node).
    let ids: Vec<(&str, String)> = rooms.iter().map(|(n, r)| (*n, r.clone())).collect();

    // ---- precondition, in every room: bob holds alice's key and reads her, as does carol ----
    for (name, room) in &ids {
        let ab = posts_until_read(
            &alice,
            &bob,
            room,
            &format!("EVERYONE-READS-THIS-{name}"),
            Duration::from_secs(120),
        );
        let ac = until(
            &format!("carol reads alice before, in {name}"),
            Duration::from_secs(60),
            || carol.reads(room, &format!("EVERYONE-READS-THIS-{name} ")),
        );
        let cb = posts_until_read(
            &carol,
            &bob,
            room,
            &format!("CAROL-READY-{name}"),
            Duration::from_secs(120),
        );
        eprintln!(
            "[proof] {name} ready: alice->bob after {ab:?} posts, alice->carol {ac}, carol->bob \
             after {cb:?} posts"
        );
        assert!(
            ab.is_some() && ac && cb.is_some(),
            "PRODUCT (staging): room {name} never became readable (alice->bob {ab:?}, alice->carol \
             {ac}, carol->bob {cb:?})"
        );
    }

    // ---- the attacker's snapshot of bob's own key state, then a post in each room it must be
    // able to open ----
    // Wherever `vox id` put bob's one node: it is named for the machine, not `default`.
    let bob_store = match layout::find_named(&bob.data.join("nodes"), "store.redb").as_slice() {
        [one] => one.clone(),
        found => panic!(
            "APPARATUS: bob's data root holds {} stores, not one: {found:?}",
            found.len()
        ),
    };
    let snapshot = tmp.path().join("bob-snapshot.redb");
    let bob_pid = bob
        .daemon
        .as_ref()
        .expect("APPARATUS: bob's daemon handle")
        .0
        .id();
    signal(bob_pid, "-STOP");
    let copied = std::fs::copy(&bob_store, &snapshot);
    signal(bob_pid, "-CONT");
    copied.expect("APPARATUS: copy bob's store.redb");
    for (name, room) in &ids {
        let control = format!("BEFORE-REMOVAL-CONTROL-{name}");
        let (ok, _, e) = alice.vox(&["room", "post", room, &control], None);
        assert!(ok, "PRODUCT (staging): vox room post in {name} failed: {e}");
        assert!(
            until(
                &format!("bob renders {control}"),
                Duration::from_secs(60),
                || bob.reads(room, &control)
            ),
            "PRODUCT (staging): bob never rendered alice's last pre-removal post in {name}, so it is \
             not provably in his log for the attacker to open"
        );
    }

    // ---- alice removes bob, then keeps talking in every room ----
    let (ok, o, e) = alice.vox(
        &[
            "trust",
            "remove",
            &bob.fp,
            "--identity-passphrase-file",
            alice.pass.to_str().expect("APPARATUS: a UTF-8 temp path"),
        ],
        None,
    );
    assert!(ok, "PRODUCT: `vox trust remove` of bob failed: {o}{e}");
    // It says what it is to stop before it acts, naming every room shared with bob, and what it
    // did after (ADR-028 E-5).
    eprintln!("[proof] `vox trust remove` said:\n{o}");
    let lines: Vec<&str> = o.lines().collect();
    let about = lines
        .iter()
        .position(|l| l.starts_with("vox: about to remove "));
    let rooms_named = about.and_then(|b| {
        lines[b..]
            .iter()
            .position(|l| ROOMS.iter().all(|r| l.contains(&format!("{r:?}"))))
            .map(|i| b + i)
    });
    let done = lines.iter().position(|l| l.starts_with("vox: removed "));
    assert!(
        matches!((rooms_named, done), (Some(r), Some(d)) if r < d),
        "PRODUCT: `vox trust remove` must say, before it acts, that bob is to read nothing new in \
         {ROOMS:?}, and then what it did: {o}"
    );
    let after_text = |name: &str, n: u32| format!("ONLY-CAROL-READS-THIS-{name} {n}");
    for (name, room) in &ids {
        for n in 1..=AFTER {
            let (ok, _, e) = alice.vox(&["room", "post", room, &after_text(name, n)], None);
            assert!(ok, "PRODUCT (staging): vox room post in {name} failed: {e}");
        }
    }

    // ---- in every room: carol reads every one; bob, still receiving, reads none ----
    let mut verdicts = Vec::new();
    for (name, room) in &ids {
        let carol_all = until(
            &format!("carol reads all of alice's post-removal messages in {name}"),
            Duration::from_secs(90),
            || {
                let seen = carol.vox(&["room", "read", room], None).1;
                (1..=AFTER).all(|n| seen.contains(&after_text(name, n)))
            },
        );
        let carol_seen = carol.vox(&["room", "read", room], None).1;
        let carol_count = (1..=AFTER)
            .filter(|n| carol_seen.contains(&after_text(name, *n)))
            .count();
        // Positive control: bob is still receiving this room.
        let control = posts_until_read(
            &carol,
            &bob,
            room,
            &format!("CAROL-AFTER-REMOVAL-{name}"),
            Duration::from_secs(90),
        );
        std::thread::sleep(Duration::from_secs(10));
        let (bob_read_ok, bob_seen, bob_read_err) = bob.vox(&["room", "read", room], None);
        assert!(
            bob_read_ok,
            "PRODUCT (staging): bob's final read of {name} failed: {bob_read_err}"
        );
        let bob_count = (1..=AFTER)
            .filter(|n| bob_seen.contains(&after_text(name, *n)))
            .count();
        let bob_before = bob_seen.contains(&format!("EVERYONE-READS-THIS-{name} "));
        eprintln!(
            "[proof] {name} after the removal: carol read {carol_count}/{AFTER}, bob read \
             {bob_count}/{AFTER}; control (bob reads carol) after {control:?} posts; bob still \
             reads the pre-removal post: {bob_before}"
        );
        assert!(
            control.is_some(),
            "PRODUCT (staging): bob never rendered carol's post in {name} after the removal, so his \
             not reading alice there would prove nothing"
        );
        verdicts.push((*name, carol_all, carol_count, bob_count, bob_before));
    }
    eprintln!(
        "[proof] rooms checked: {} of {}",
        verdicts.len(),
        ROOMS.len()
    );
    for (name, carol_all, carol_count, bob_count, bob_before) in &verdicts {
        assert!(
            *carol_all && *carol_count == 3,
            "PRODUCT: carol, still trusted, read only {carol_count}/3 of alice's messages in \
             {name} across the rotation"
        );
        assert_eq!(
            *bob_count, 0,
            "PRODUCT: bob, removed from alice's ring, still reads {bob_count}/3 of what she \
             posted afterwards in {name} — `vox trust remove` did not change the lock in every \
             shared room"
        );
        assert!(
            *bob_before,
            "PRODUCT: what bob read before the removal in {name} is no longer readable — the rotation recalled it"
        );
    }
}
