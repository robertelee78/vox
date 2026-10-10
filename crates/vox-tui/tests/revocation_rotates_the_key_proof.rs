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
//! 1. Alice creates **three** rooms, `team`, `side` and `third` — each with its own sender keys, so
//!    the removal has to change the lock in each of them (RP-20's quantifier); Bob, Carol and Dave
//!    join each with the links, once each (a join that fails is `PRODUCT`); all four trust each
//!    other after the joins.
//! 2. Precondition, in every room: Bob and Carol each render a post by Alice, and Bob renders one
//!    by Carol (`PRODUCT (staging)` otherwise) — Bob really holds Alice's key before she removes him.
//! 3. In every room Alice posts a `BEFORE-REMOVAL-CONTROL` and Bob renders it.
//! 4. Alice runs `vox trust remove <bob>`, then posts [`AFTER`] fresh messages in each room.
//! 5. In each room Carol posts until Bob renders one of hers — a **positive control** that Bob's
//!    node is still syncing that room, so Bob's silence on Alice's posts below is the lock, not the
//!    plumbing.
//!
//! ## What is asserted, in each of the 3 rooms
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
//! ## ADR-030 T-1: the rotated key travels in a session of its own
//! Dave, made and joined by the shipped binary, has his daemon stopped once he reads alice in
//! every room, and the proof takes his place with his own profile (the attacker apparatus, below):
//! it connects to alice as dave, opens his long-lived session with her in each room (a `Hello`,
//! then an `Open`) and **freezes** it. That frozen session is the attacker's pre-rotation pairwise
//! state. It answers each delivery as dave's node does, from his prekey ring, and republishes his
//! bundle on alice's board after each one it takes. When alice removes bob, in every room:
//! - (a) the rotated key reaches dave in an `OP_ROTATION_HELLO`, never in the long-lived session;
//! - (b) the frozen session does not open it;
//! - (c) the fresh session its own opening names, built from dave's ring, does, and it is alice's
//!   key (the positive control);
//! - and each of those deliveries names a one-time prekey of its own, none his signed prekey alone
//!   (ADR-030 P-3: a key waits for the next bundle rather than reuse a one-time prekey).
//!
//! Then twice, alice removes and re-trusts dave with a bad bundle of his on her board. One time
//! its one-time prekey is signed by his root as made eight days ago; the other time, an hour
//! ahead of her clock. Each time:
//! - (d) she sends him nothing, and her daemon says why, in every room: "its prekey bundle is
//!   stale: its one-time prekey is 8 days old", or "… was made 60 minutes from now" (P-2, D-5);
//! - (e) once dave publishes a good bundle, the retrust reaches him in every room, each key in an
//!   `OP_ROTATION_HELLO` of its own (D-3).
//!
//! ## The mutations that must turn it red
//! - **Change the lock in one shared room only** (RP-20): `change_the_lock_against` in
//!   `crates/vox-core/src/node/actor.rs` stops after the first room it revokes in. The other room
//!   keeps its old key, so Bob renders Alice's post-removal posts there.
//! - Drop `self.change_the_lock_against(fingerprint).await;` from `untrust_identity` in
//!   `crates/vox-core/src/node/actor.rs`: the ring entry goes but the key is not rotated, so Bob
//!   keeps opening Alice's new posts with the key he already holds.
//! - ADR-030 T-2: `deliver_rekeys_for` seals the rotated key in the long-lived session → (a) and
//!   (b) red; `release_key_to` seals in the long-lived session → (e) red; `delivery_bundle` without
//!   its cadence check (P-1, P-2 skipped) → (d) red on the backdated bundle; without its check of
//!   a date ahead → (d) red on the bundle dated ahead; a one-time prekey already named reused (no
//!   wait for the next bundle) → red: a delivery on the signed prekey alone, or one prekey named
//!   twice.
#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/layout.rs"]
mod layout;
#[path = "support/ports.rs"]
mod ports;
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
const ROOMS: [&str; 3] = ["team", "side", "third"];

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
    let mut dave = member(tmp.path(), "dave", &spec);

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
        join(&dave, link.trim(), name);
        rooms.push((name, room));
    }
    for a in [&alice, &bob, &carol, &dave] {
        for b in [&alice, &bob, &carol, &dave] {
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
        let ad = until(
            &format!("dave reads alice before, in {name}"),
            Duration::from_secs(60),
            || dave.reads(room, &format!("EVERYONE-READS-THIS-{name} ")),
        );
        eprintln!(
            "[proof] {name} ready: alice->bob after {ab:?} posts, alice->carol {ac}, carol->bob \
             after {cb:?} posts, alice->dave {ad}"
        );
        assert!(
            ab.is_some() && ac && cb.is_some() && ad,
            "PRODUCT (staging): room {name} never became readable (alice->bob {ab:?}, alice->carol \
             {ac}, carol->bob {cb:?}, alice->dave {ad})"
        );
    }

    // ---- ADR-030 T-1: dave's place taken by the apparatus, his pairwise state frozen ----
    let dave_c = Dave::take_over(&mut dave, &alice, &ids);
    dave_c.open_and_freeze();
    std::thread::sleep(Duration::from_secs(2));
    let seen_before = dave_c.got().len();

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
    adr030_rotation_to_dave(&dave_c, &ids, seen_before);
    adr030_refused_bundles_and_retrust(&dave_c, &alice, &dave, &ids, tmp.path());
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

// ---- the attacker apparatus (ADR-030 T-1) ----------------------------------------------------
//
// **Dave, played by the proof.** Dave is a real member, made, joined and trusted by the shipped
// binary. Then his daemon is stopped, and test-side code holding his profile takes his place. It
// connects to alice as dave and takes her pairwise streams. It opens his long-lived session with
// her in every room, and freezes it: that frozen session is the attacker's pre-rotation pairwise
// state. It answers a delivery the way dave's node does: it opens it from his own prekey ring,
// answers `KEY_TAKEN`, and republishes his bundle on alice's board. Nothing asserted below is
// read from alice: every verdict is what alice's shipped binary sent, or what it said.
//
// This is apparatus, as AGENTS.md allows: a test-side client sending to and reading from a real
// running `vox`. It asserts nothing about alice's internals.

use vox_core::hash::Digest32;
use vox_core::nat::record::MemberBundleRecord;
use vox_core::nat::service::{RecordKinds, RendezvousClient};
use vox_core::node::pairwise_stream::{self as pw, PairwiseFrame};
use vox_core::node::prekeys::{self, OneTimeUse, PrekeyRing};
use vox_core::pairwise::session::Session;
use vox_core::pairwise::{InitialMessage, OtpReuseTracker};
use vox_core::transport::quic::{VoxConnection, VoxEndpoint};
use vox_core::transport::streams::{accept_typed, open_typed, StreamKind};

fn wall_ms() -> u64 {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("APPARATUS: the clock")
        .as_millis();
    u64::try_from(ms).expect("APPARATUS: the clock")
}

fn digest(b32: &str) -> Digest32 {
    vox_core::node::link::b32_decode(b32.trim(), "fingerprint")
        .unwrap_or_else(|e| panic!("APPARATUS: {b32:?} is no fingerprint: {e:?}"))
}

/// One frame alice sent dave, as received, and what dave could do with it.
#[derive(Clone)]
struct Got {
    /// The frame's kind: `rotation-hello`, `skdm`, `hello` or `open`.
    kind: &'static str,
    room: Digest32,
    /// The one-time prekey a delivery's opening named, if any.
    one_time: Option<u64>,
    /// Whether dave's frozen, pre-rotation session with alice opened it.
    frozen_opened: bool,
    /// The author and generation of the key a fresh session opened from dave's ring, if it did.
    fresh_opened: Option<(Digest32, u64)>,
}

impl std::fmt::Debug for Got {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let short = |d: &Digest32| -> String {
            vox_core::node::link::b32_encode(d)
                .chars()
                .take(12)
                .collect()
        };
        write!(
            f,
            "{} in {}: one-time prekey {:?}; opened under the frozen session {}; opened fresh {}",
            self.kind,
            short(&self.room),
            self.one_time,
            self.frozen_opened,
            self.fresh_opened.map_or_else(
                || "no".to_owned(),
                |(a, c)| format!("as {}'s key, generation {c}", short(&a))
            )
        )
    }
}

/// A room as dave's apparatus needs it.
#[derive(Clone)]
struct DaveRoom {
    id: Digest32,
    ctx: vox_core::join::session::JoinContext,
}

struct Dave {
    rt: tokio::runtime::Runtime,
    signer: Arc<vox_core::atrest::vault::VaultRootSigner>,
    ring: Arc<tokio::sync::Mutex<PrekeyRing>>,
    _profile: vox_core::node::profile::Profile,
    _endpoint: VoxEndpoint,
    conn: Arc<VoxConnection>,
    rooms: Vec<DaveRoom>,
    /// Dave's long-lived session with alice in each room, opened before the rotation and never
    /// advanced after: the attacker's frozen state.
    frozen: Arc<std::sync::Mutex<std::collections::BTreeMap<Digest32, Session>>>,
    got: Arc<std::sync::Mutex<Vec<Got>>>,
    /// Republish dave's bundle after each delivery he takes, as his node does.
    republish: Arc<std::sync::atomic::AtomicBool>,
    seq: Arc<std::sync::atomic::AtomicU64>,
    alice: Digest32,
}

use std::sync::Arc;

impl Dave {
    /// Take dave's place: his daemon at `data` is stopped first, by its PID.
    fn take_over(dave: &mut Member, alice: &Member, rooms: &[(&str, String)]) -> Self {
        let pid = dave
            .daemon
            .as_ref()
            .expect("APPARATUS: dave's daemon handle")
            .0
            .id();
        signal(pid, "-TERM");
        if let Some(mut p) = dave.daemon.take() {
            let _ = p.0.wait();
            std::mem::forget(p);
        }
        let node = match layout::find_named(&dave.data.join("nodes"), "store.redb").as_slice() {
            [one] => one
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .expect("APPARATUS: dave's node name")
                .to_owned(),
            found => panic!(
                "APPARATUS: dave's data root holds {} stores: {found:?}",
                found.len()
            ),
        };
        let paths = vox_core::node::paths::Paths::resolve(
            &node,
            Some(&dave.data),
            Some(&dave.data.join("cfg")),
        )
        .expect("APPARATUS: dave's paths");
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut profile = loop {
            match vox_core::node::profile::Profile::open(paths.clone()) {
                Ok(p) => break p,
                Err(e) if Instant::now() < deadline => {
                    let _ = e;
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(e) => panic!("APPARATUS: dave's profile did not open: {e:?}"),
            }
        };
        profile
            .unlock(ID_PASS.as_bytes())
            .expect("APPARATUS: dave's identity unlocks");
        let signer = profile.signer_arc().expect("APPARATUS: dave's signer");
        let ring = prekeys::load(profile.store(), signer.as_ref())
            .expect("APPARATUS: dave's prekey ring opens")
            .expect("APPARATUS: dave has a prekey ring");
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("APPARATUS: a runtime");
        let alice_id = digest(&alice.fp);
        let status = alice.vox(&["status", "--json"], None).1;
        let addr = ports::loopback_listen(&status).unwrap_or_else(|| {
            panic!("APPARATUS: alice's status names no loopback address: {status}")
        });
        let (endpoint, conn) = rt.block_on(connect_as(&signer, addr, alice_id));
        // Each room's context, from the genesis on alice's board and the epoch alice reports.
        let v: serde_json::Value =
            serde_json::from_str(status.trim()).expect("APPARATUS: alice's status is JSON");
        let mut out = Vec::new();
        for (name, room) in rooms {
            let r = v["rooms"]
                .as_array()
                .and_then(|rs| {
                    rs.iter().find(|r| {
                        r["id"]
                            .as_str()
                            .is_some_and(|i| i.starts_with(room.as_str()))
                    })
                })
                .unwrap_or_else(|| {
                    panic!("APPARATUS: alice's status lists no room {name}: {status}")
                });
            let full = r["id"].as_str().unwrap_or_default().to_owned();
            let epoch = r["epoch"].as_u64().unwrap_or(0);
            let id = rt.block_on(full_room_id(&conn, &full, epoch)).unwrap_or_else(|| {
                panic!("APPARATUS: room {name} ({full}) has no genesis on alice's board at epoch {epoch}")
            });
            out.push(id);
        }
        let ring = Arc::new(tokio::sync::Mutex::new(ring));
        let d = Self {
            rt,
            signer,
            ring,
            _profile: profile,
            _endpoint: endpoint,
            conn,
            rooms: out,
            frozen: Arc::default(),
            got: Arc::default(),
            republish: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            alice: alice_id,
        };
        d.serve();
        d
    }

    /// Take every pairwise stream alice opens to dave, on a task of its own.
    fn serve(&self) {
        let conn = Arc::clone(&self.conn);
        let ring = Arc::clone(&self.ring);
        let frozen = Arc::clone(&self.frozen);
        let got = Arc::clone(&self.got);
        let rooms = self.rooms.clone();
        let signer = Arc::clone(&self.signer);
        let republish = Arc::clone(&self.republish);
        let seq = Arc::clone(&self.seq);
        let alice = self.alice;
        self.rt.spawn(async move {
            while let Ok((kind, mut send, mut recv)) = accept_typed(&conn).await {
                if kind != StreamKind::Pairwise {
                    // Sync and the rest are not what this proof is about: refused.
                    let _ = send.reset(quinn::VarInt::from_u32(0x05));
                    let _ = recv.stop(quinn::VarInt::from_u32(0x05));
                    continue;
                }
                let (ring, frozen, got, rooms, signer, republish, seq, conn) = (
                    Arc::clone(&ring),
                    Arc::clone(&frozen),
                    Arc::clone(&got),
                    rooms.clone(),
                    Arc::clone(&signer),
                    Arc::clone(&republish),
                    Arc::clone(&seq),
                    Arc::clone(&conn),
                );
                tokio::spawn(async move {
                    let mut took = false;
                    while let Ok(Some(frame)) = pw::recv_pairwise(&mut recv).await {
                        let now = wall_ms();
                        let mut g = match &frame {
                            PairwiseFrame::RotationHello { channel_id, .. } => Got {
                                kind: "rotation-hello",
                                room: *channel_id,
                                one_time: None,
                                frozen_opened: false,
                                fresh_opened: None,
                            },
                            PairwiseFrame::Skdm { channel_id, .. } => Got {
                                kind: "skdm",
                                room: *channel_id,
                                one_time: None,
                                frozen_opened: false,
                                fresh_opened: None,
                            },
                            PairwiseFrame::Hello { channel_id, .. } => Got {
                                kind: "hello",
                                room: *channel_id,
                                one_time: None,
                                frozen_opened: false,
                                fresh_opened: None,
                            },
                            PairwiseFrame::Open { channel_id, .. } => Got {
                                kind: "open",
                                room: *channel_id,
                                one_time: None,
                                frozen_opened: false,
                                fresh_opened: None,
                            },
                        };
                        let sealed = match &frame {
                            PairwiseFrame::RotationHello { sealed, .. }
                            | PairwiseFrame::Skdm { sealed, .. } => Some(sealed.clone()),
                            _ => None,
                        };
                        // (b) The attacker's frozen state, tried on every sealed key.
                        if let Some(sealed) = &sealed {
                            if let Some(s) = frozen.lock().expect("frozen").get_mut(&g.room) {
                                g.frozen_opened = pw::open_skdm(s, sealed, now).is_ok();
                            }
                        }
                        // (c) A fresh session from dave's own ring, as his node opens a delivery.
                        if let PairwiseFrame::RotationHello {
                            initial, sealed, ..
                        } = &frame
                        {
                            if let (Ok(init), Some(room)) = (
                                InitialMessage::from_wire(initial),
                                rooms.iter().find(|r| r.id == g.room),
                            ) {
                                g.one_time = init.one_time_prekey_id;
                                let mut ring = ring.lock().await;
                                let usable = match init.one_time_prekey_id {
                                    Some(id) => ring.use_one_time(id, now) == OneTimeUse::Fresh,
                                    None => true,
                                };
                                if usable {
                                    if let Some(spk) = ring.signed_prekey_for(init.signed_prekey_id)
                                    {
                                        let prekeys = vox_core::pairwise::pqxdh::ResponderPrekeys {
                                            identity_dh_key: ring.identity_dh(),
                                            signed_prekey: spk,
                                            one_time_prekey: init
                                                .one_time_prekey_id
                                                .and_then(|id| ring.consumed_one_time(id)),
                                        };
                                        let mut reuse = OtpReuseTracker::new();
                                        if let Ok(mut s) = Session::accept(
                                            &init,
                                            &prekeys,
                                            &room.ctx.channel_id,
                                            room.ctx.epoch,
                                            &mut reuse,
                                            room.ctx.floor,
                                        ) {
                                            if let Ok(skdm) = pw::open_skdm(&mut s, sealed, now) {
                                                g.fresh_opened =
                                                    Some((skdm.body.author_id, skdm.body.chain_id));
                                                took = skdm.body.author_id == alice;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        got.lock().expect("got").push(g);
                    }
                    if took {
                        let _ = send.write_all(&[pw::KEY_TAKEN]).await;
                        let _ = send.finish();
                        if republish.load(std::sync::atomic::Ordering::SeqCst) {
                            publish_bundle(&conn, &signer, &ring, &rooms, &seq, None).await;
                        }
                    } else {
                        let _ = send.reset(pw::KeyRefusal::CannotOpen.code());
                    }
                });
            }
        });
    }

    /// Open dave's long-lived session with alice in every room, from her bundle on her board, and
    /// freeze it: a `Hello`, then an `Open` so alice can send in it too.
    fn open_and_freeze(&self) {
        self.rt.block_on(async {
            for room in &self.rooms {
                let bundle = board_bundle(&self.conn, room, &self.alice)
                    .await
                    .unwrap_or_else(|| panic!("APPARATUS: alice's bundle is not on her board"));
                let ring = self.ring.lock().await;
                let (initial, mut session) = Session::initiate(
                    ring.identity_dh(),
                    &bundle.prekey_bundle,
                    &room.ctx.channel_id,
                    room.ctx.epoch,
                    room.ctx.suite_id,
                    room.ctx.floor,
                )
                .expect("APPARATUS: a session with alice opens from her bundle");
                drop(ring);
                let open = pw::open_frame(&room.id, &mut session)
                    .expect("APPARATUS: the session's opening message");
                let frames = vec![pw::hello_frame(&room.id, &initial), open];
                let (mut send, recv) = open_typed(&self.conn, StreamKind::Pairwise)
                    .await
                    .expect("APPARATUS: a pairwise stream to alice");
                for f in &frames {
                    vox_core::transport::framing::write_frame(&mut send, f)
                        .await
                        .expect("APPARATUS: write to alice");
                }
                let _ = send.finish();
                // Whatever alice answers, the session is now the one she holds for dave.
                let _ = pw::refused(recv, Duration::from_secs(10)).await;
                self.frozen.lock().expect("frozen").insert(room.id, session);
            }
        });
    }

    /// Publish dave's bundle on alice's board in every room: his ring's, or `bundle` as given.
    fn publish(&self, bundle: Option<vox_core::identity::keyagreement::PrekeyBundlePublic>) {
        self.rt.block_on(publish_bundle(
            &self.conn,
            &self.signer,
            &self.ring,
            &self.rooms,
            &self.seq,
            bundle,
        ));
    }

    /// Dave's current bundle with its one-time prekey replaced by a fresh one, signed by his root,
    /// made at `created_ms`, which the proof backdates or dates ahead.
    fn bundle_dated(
        &self,
        created_ms: u64,
    ) -> vox_core::identity::keyagreement::PrekeyBundlePublic {
        self.rt.block_on(async {
            let ring = self.ring.lock().await;
            let mut bundle = ring
                .bundle(&vox_core::identity::composite::RootSigner::public_key(
                    self.signer.as_ref(),
                ))
                .expect("APPARATUS: dave's bundle");
            let mut pool = vox_core::identity::keyagreement::OneTimePrekeyPool::new(1 << 40);
            pool.refill_to(self.signer.as_ref(), 0, 1, created_ms)
                .expect("APPARATUS: a dated one-time prekey");
            let otp = pool.first().expect("APPARATUS: the dated one-time prekey");
            bundle.one_time_prekey = Some(otp.public().clone());
            bundle.one_time_prekey_sig = Some(otp.signature().to_bytes());
            bundle
        })
    }

    fn got(&self) -> Vec<Got> {
        self.got.lock().expect("got").clone()
    }
}

async fn connect_as(
    signer: &Arc<vox_core::atrest::vault::VaultRootSigner>,
    addr: std::net::SocketAddr,
    id: Digest32,
) -> (VoxEndpoint, Arc<VoxConnection>) {
    let endpoint = VoxEndpoint::bind(
        Arc::clone(signer) as Arc<_>,
        "127.0.0.1:0".parse().expect("APPARATUS: an address"),
    )
    .expect("APPARATUS: bind dave's endpoint");
    let deadline = Instant::now() + Duration::from_secs(60);
    let conn = loop {
        match endpoint.connect(addr, id, wall_ms()).await {
            Ok(c) => break c,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => panic!("APPARATUS: dave could not connect to alice: {e:?}"),
        }
    };
    (endpoint, Arc::new(conn))
}

/// The full id and context of the room whose id begins with `short`, from its genesis on the board
/// `conn` reaches. Tried as the full id first.
async fn full_room_id(conn: &VoxConnection, room: &str, epoch: u64) -> Option<DaveRoom> {
    let id = vox_core::node::link::b32_decode(room, "room").ok()?;
    let mut c = RendezvousClient::open(conn).await.ok()?;
    let set = c.get(&id, epoch, RecordKinds::GENESIS).await.ok()?;
    c.finish();
    let genesis = set.genesis?;
    let ctx = vox_core::node::channel::join_context_from_genesis(&genesis, epoch).ok()?;
    Some(DaveRoom { id, ctx })
}

async fn board_bundle(
    conn: &VoxConnection,
    room: &DaveRoom,
    who: &Digest32,
) -> Option<MemberBundleRecord> {
    let mut c = RendezvousClient::open(conn).await.ok()?;
    let set = c
        .get(&room.id, room.ctx.epoch, RecordKinds::BUNDLES)
        .await
        .ok()?;
    c.finish();
    set.bundles.into_iter().find(|b| b.author_id == *who)
}

async fn publish_bundle(
    conn: &VoxConnection,
    signer: &Arc<vox_core::atrest::vault::VaultRootSigner>,
    ring: &tokio::sync::Mutex<PrekeyRing>,
    rooms: &[DaveRoom],
    seq: &std::sync::atomic::AtomicU64,
    bundle: Option<vox_core::identity::keyagreement::PrekeyBundlePublic>,
) {
    use vox_core::identity::composite::RootSigner as _;
    let me = signer.fingerprint();
    let bundle = match bundle {
        Some(b) => b,
        None => ring
            .lock()
            .await
            .bundle(&signer.public_key())
            .expect("APPARATUS: dave's bundle"),
    };
    for room in rooms {
        let Some(held) = board_bundle(conn, room, &me).await else {
            panic!("APPARATUS: dave's own bundle record is not on alice's board");
        };
        // A changed claim is taken once it is a second newer than the one held.
        let ts = wall_ms().max(held.timestamp_ms + 1_001);
        let n = seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let record = MemberBundleRecord::build(
            signer.as_ref(),
            &room.id,
            room.ctx.epoch,
            bundle.clone(),
            held.seq + 1 + n,
            ts,
            held.ttl_ms,
            held.admission.clone(),
        )
        .expect("APPARATUS: dave's bundle record");
        let mut c = RendezvousClient::open(conn)
            .await
            .expect("APPARATUS: a rendezvous stream to alice");
        let put = c.put(&record.to_wire()).await;
        c.finish();
        if let Err(e) = put {
            eprintln!("[apparatus] alice's board refused dave's bundle record: {e:?}");
        }
    }
}

/// T-1 (a)–(c), and every rotated key on a one-time prekey of its own: what alice sent dave when
/// she removed bob, in each room.
fn adr030_rotation_to_dave(dave: &Dave, ids: &[(&str, String)], seen_before: usize) {
    let in_room = |g: &Got, room: &DaveRoom| g.room == room.id;
    let ok = until(
        "alice's rotated key reaches dave in every room",
        Duration::from_secs(90),
        || {
            let got = dave.got();
            dave.rooms.iter().all(|r| {
                got[seen_before..]
                    .iter()
                    .any(|g| in_room(g, r) && matches!(g.kind, "rotation-hello" | "skdm"))
            })
        },
    );
    let got = dave.got();
    let after: Vec<&Got> = got[seen_before..].iter().collect();
    eprintln!("[proof] what alice sent dave after removing bob: {after:#?}");
    assert!(
        ok,
        "PRODUCT: alice removed bob, and in 90 s her node sent dave, still trusted, no new key in \
         every room: {after:#?}"
    );
    let mut one_times = Vec::new();
    for ((name, _), room) in ids.iter().zip(&dave.rooms) {
        let keys: Vec<&&Got> = after
            .iter()
            .filter(|g| in_room(g, room) && matches!(g.kind, "rotation-hello" | "skdm"))
            .collect();
        // (a) In a delivery of its own.
        assert!(
            keys.iter().all(|g| g.kind == "rotation-hello"),
            "PRODUCT: in {name}, alice's rotated key reached dave as {:?}, not in an \
             OP_ROTATION_HELLO of its own (ADR-030 D-1, W-1)",
            keys.iter().map(|g| g.kind).collect::<Vec<_>>()
        );
        // (b) Never under the attacker's frozen, pre-rotation state.
        assert!(
            keys.iter().all(|g| !g.frozen_opened),
            "PRODUCT: in {name}, the rotated key alice sent dave opened under dave's pre-rotation \
             session with her, which the attacker holds (ADR-030 D-1)"
        );
        // (c) Positive control: the fresh session from dave's own ring opens it, and it is alice's.
        let opened: Vec<(Digest32, u64)> = keys.iter().filter_map(|g| g.fresh_opened).collect();
        assert!(
            !opened.is_empty() && opened.iter().all(|(a, _)| *a == dave.alice),
            "PRODUCT: in {name}, no key alice delivered to dave opened in the fresh session its \
             own opening names, from dave's ring: {keys:#?}"
        );
        one_times.extend(keys.iter().map(|g| g.one_time));
    }
    // Each on a one-time prekey of its own, none on the signed prekey alone (ADR-030 P-3, S-2).
    let named: std::collections::BTreeSet<u64> = one_times.iter().flatten().copied().collect();
    eprintln!("[proof] one-time prekeys alice's deliveries to dave named: {one_times:?}");
    assert!(
        one_times.iter().all(Option::is_some) && named.len() == one_times.len(),
        "PRODUCT: alice's {} rotated keys to dave, one per shared room, must each name a one-time \
         prekey of its own; they named {one_times:?} (None is his signed prekey alone, which heals \
         only when it rotates)",
        one_times.len()
    );
}

/// What alice's daemon said about dave since `from` bytes into its log.
fn alice_said_of_dave(tmp: &Path, from: usize, dave_fp: &str) -> Vec<String> {
    let log = std::fs::read_to_string(tmp.join("alice.daemon.err")).unwrap_or_default();
    let short = &dave_fp[..12.min(dave_fp.len())];
    log.get(from..)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains("waits:") && l.to_lowercase().contains(&short.to_lowercase()))
        .map(str::to_owned)
        .collect()
}

/// T-1 (d) and (e): a bundle of dave's with a backdated one-time prekey, then one dated ahead of
/// alice's clock, is refused with its reason, and each time the retrust, once dave publishes a
/// good bundle, comes in an `OP_ROTATION_HELLO`.
fn adr030_refused_bundles_and_retrust(
    dave: &Dave,
    alice: &Member,
    dave_m: &Member,
    ids: &[(&str, String)],
    tmp: &Path,
) {
    const DAY_MS: u64 = 24 * 60 * 60 * 1000;
    let pass = alice
        .pass
        .to_str()
        .expect("APPARATUS: a UTF-8 temp path")
        .to_owned();
    let cases: [(&str, u64, &str); 2] = [
        (
            "a one-time prekey made eight days ago",
            wall_ms() - 8 * DAY_MS,
            "waits: its prekey bundle is stale: its one-time prekey is 8 days old",
        ),
        (
            "a one-time prekey dated an hour ahead",
            wall_ms() + 60 * 60 * 1000,
            "waits: its prekey bundle says its one-time prekey was made",
        ),
    ];
    for (what, created, reason) in cases {
        dave.publish(Some(dave.bundle_dated(created)));
        std::thread::sleep(Duration::from_secs(2));
        let log_at = std::fs::read_to_string(tmp.join("alice.daemon.err"))
            .unwrap_or_default()
            .len();
        let (ok, o, e) = alice.vox(
            &[
                "trust",
                "remove",
                &dave_m.fp,
                "--identity-passphrase-file",
                &pass,
            ],
            None,
        );
        assert!(
            ok,
            "PRODUCT (staging): alice's `vox trust remove` of dave failed: {o}{e}"
        );
        let seen = dave.got().len();
        alice.trust(dave_m);
        // (d) Refused, with its reason, in every room; nothing delivered meanwhile.
        let said = until(
            &format!("alice says why her key to dave waits ({what})"),
            Duration::from_secs(45),
            || {
                let lines = alice_said_of_dave(tmp, log_at, &dave_m.fp);
                ids.iter().all(|_| lines.iter().any(|l| l.contains(reason)))
            },
        );
        let lines = alice_said_of_dave(tmp, log_at, &dave_m.fp);
        let sent: Vec<Got> = dave.got()[seen..]
            .iter()
            .filter(|g| matches!(g.kind, "rotation-hello" | "skdm"))
            .cloned()
            .collect();
        eprintln!("[proof] dave's bundle with {what}: alice said {lines:#?}; sent {sent:#?}");
        assert!(
            said && sent.is_empty(),
            "PRODUCT: dave's bundle on alice's board names {what}; on retrust her node must not \
             seal his key to it, and must say \"{reason}\" (ADR-030 P-2, D-5). It said \
             {lines:#?} and sent {sent:#?}"
        );
        // (e) A good bundle: the retrust delivers, in a delivery of its own, in every room.
        dave.publish(None);
        let ok = until(
            &format!("alice's retrust reaches dave after {what}"),
            Duration::from_secs(60),
            || {
                let got = dave.got();
                dave.rooms.iter().all(|r| {
                    got[seen..]
                        .iter()
                        .any(|g| g.room == r.id && g.fresh_opened.is_some())
                })
            },
        );
        let after: Vec<Got> = dave.got()[seen..].to_vec();
        assert!(
            ok && after
                .iter()
                .filter(|g| matches!(g.kind, "rotation-hello" | "skdm"))
                .all(|g| g.kind == "rotation-hello" && !g.frozen_opened),
            "PRODUCT: once dave published a good bundle, alice's retrust must deliver his key in \
             every room, each in an OP_ROTATION_HELLO of its own (ADR-030 D-3): {after:#?}"
        );
    }
}
