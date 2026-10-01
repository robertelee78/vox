//! **RP-17 — revocation rotates the key with one member left out**, through the shipped `vox`
//! binary only: a `vox node` anchor and three `vox daemon`s, every step typed as an operator
//! types it (`vox id`, `vox trust add|remove`, `vox room create|invite|join|post|read`).
//!
//! Replaces `crates/vox-core/tests/node_m18_revocation_gate.rs`, which ran every node
//! in-process (V29-17).
//!
//! **One arm is test code, not a `vox` command: the attacker.** It models a **removed member
//! running a modified node** — Bob himself, with his own passphrases, reading his own profile
//! as his `vox` binary wrote it to disk, and ignoring the log's revocation. No `vox` command can
//! play that node (the shipped one declines to render a revoked author before it decrypts), so
//! the test opens Bob's store with `vox-core`'s own at-rest, log and sender-key functions used
//! as a library — exactly what a modified node would do. It starts no in-process `vox` node.
//!
//! ## The claim
//! `vox trust remove <bob>` on Alice's node removes the ring entry **and changes the lock**:
//! Alice's sender key is rotated and everyone still trusted is re-keyed, in every room shared
//! with Bob. So Bob, who holds Alice's old key, reads nothing Alice posts afterwards — not
//! because his node politely declines, but because **no key he holds opens it** — while
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
//! 3. Bob's daemon is frozen (SIGSTOP) for as long as it takes to copy his `store.redb`, then
//!    thawed: the attacker's **snapshot** of Bob's own key state. Alice then posts
//!    `BEFORE-REMOVAL-CONTROL` and Bob renders it (`CANNOT MEASURE` otherwise), so it is in his
//!    log and his snapshot key sits before it.
//! 4. Alice runs `vox trust remove <bob>`, then posts [`AFTER`] fresh messages.
//! 5. Carol must render all of them. Then Carol posts until Bob renders one of hers — a
//!    **positive control** that Bob's node is still syncing the room (and Carol's post comes
//!    after she already held Alice's), so Bob's silence below is the lock, not the plumbing.
//!
//! ## What is asserted
//! - Carol renders **3 of 3** of Alice's post-removal messages, within 90 s.
//! - Bob, with the control proved and 10 s more to settle, renders **0 of 3**.
//! - Bob still renders what Alice said before the removal.
//! - **The attacker arm.** Bob's daemon is stopped (SIGTERM, by PID). The attacker unlocks Bob's
//!   profile with his identity passphrase, unwraps the room's SEK with the room passphrase, and
//!   reads the receiver chains (the sender keys released to Bob) from both his final store and
//!   the snapshot, and Alice's log entries from his final store. Then:
//!   - **the escalation works:** the snapshot's key opens `BEFORE-REMOVAL-CONTROL` from Bob's
//!     log (`CANNOT MEASURE` otherwise — an attacker that opens nothing proves nothing);
//!   - Bob's log holds **exactly 3** content entries by Alice after that one (`CANNOT MEASURE`
//!     otherwise);
//!   - **no key Bob holds, in either store, opens any of the 3** — the key rotated.
//!
//! ## The mutations that must turn it red
//! - Drop `self.change_the_lock_against(fingerprint).await;` from `untrust_identity` in
//!   `crates/vox-core/src/node/actor.rs`: the ring entry goes but the key is not rotated, so Bob
//!   keeps opening Alice's new posts with the key he already holds.
//! - **Revoke without rotating**: in `ChannelState::revoke_consent`
//!   (`crates/vox-core/src/node/channel.rs`), `let new_chain_id = self.rotate_sender(..)?;`
//!   becomes `let new_chain_id = self.sender.chain_id();`. The revocation is still written, so
//!   Bob's cooperative node still shows 0/3 — only the attacker arm sees that it opens 3/3.
#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use vox_core::atrest::store::{open_segment, SegmentKind};
use vox_core::atrest::{Sek, SignatureIdentityFactor};
use vox_core::cbor::Decoder;
use vox_core::group::{GroupMessage, ReceiverChain};
use vox_core::log::entry::Entry;
use vox_core::node::content::Content;
use vox_core::node::paths::Paths;
use vox_core::node::profile::Profile;
use vox_core::node::store::Store;

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
            .expect("APPARATUS: spawn vox");
        if let Some(text) = stdin {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(text.as_bytes())
                .expect("APPARATUS: write vox's stdin");
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
                self.pass.to_str().unwrap(),
            ],
            None,
        );
        assert!(
            ok,
            "CANNOT MEASURE: {} could not trust {}: {o}{e}",
            self.name, other.name
        );
    }
}

fn member(tmp: &Path, name: &'static str, anchor: &str) -> Member {
    let data = tmp.join(name);
    std::fs::create_dir_all(data.join("cfg")).expect("APPARATUS: a profile dir");
    let pass = tmp.join(format!("{name}.pass"));
    std::fs::write(&pass, ID_PASS).expect("APPARATUS: the passphrase file");
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
    assert!(ok, "CANNOT MEASURE: {name}: vox id: {err}");
    m.fp = out.trim().to_owned();
    assert_eq!(
        m.fp.len(),
        52,
        "PRODUCT: {name}: `vox id` printed {:?}, not a fingerprint",
        m.fp
    );
    let err_path = tmp.join(format!("{name}.daemon.err"));
    let err = std::fs::File::create(&err_path).expect("APPARATUS: the daemon's stderr file");
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
            "CANNOT MEASURE: {name}'s daemon never answered `vox room list` within 90 s; it \
             said:\n{}",
            std::fs::read_to_string(&err_path).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    m
}

fn anchor(tmp: &Path) -> (Proc, String) {
    let dir = tmp.join("anchor");
    std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: the anchor's dir");
    let out = tmp.join("anchor.out");
    let p = Proc(
        Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .stdout(Stdio::from(
                std::fs::File::create(&out).expect("APPARATUS: the anchor's stdout file"),
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
            "CANNOT MEASURE: the anchor never printed its spec within 60 s; it printed: {text}"
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
        assert!(ok, "PRODUCT: {} could not post: {e}", author.name);
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
    let mut last = String::new();
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
            last = format!("{o}{e}");
            std::thread::sleep(Duration::from_secs(5));
        }
        ok
    });
    assert!(
        joined,
        "PRODUCT: {} could not join the room in 6 attempts (if this is a refusal as a pending \
         joiner, it is the open defect #217, V210-43); the last refusal: {last}",
        m.name
    );
}

/// Send `sig` to `pid` with `kill(1)` — by PID, never by pattern.
fn signal(pid: u32, sig: &str) {
    let ok = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .expect("APPARATUS: run kill")
        .success();
    assert!(ok, "APPARATUS: `kill {sig} {pid}` did not take");
}

/// Stop a daemon the way a service manager does and wait for it to leave, so its store is
/// closed and the profile is free to open.
fn stop(mut daemon: Proc) {
    signal(daemon.0.id(), "-TERM");
    let deadline = Instant::now() + Duration::from_secs(30);
    while daemon
        .0
        .try_wait()
        .expect("APPARATUS: try_wait on bob's daemon")
        .is_none()
    {
        assert!(
            Instant::now() < deadline,
            "CANNOT MEASURE: bob's daemon did not leave within 30s of SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

// ---- the attacker: a removed member on a modified node (test code, vox-core as a library) ----

/// The receiver-chain segment's slot in `KeyMaterial`, and its at-rest version — as bob's binary
/// writes them (`SEG_RECEIVERS`, `RECEIVERS_VERSION` in `node/channel.rs`).
const SEG_RECEIVERS: u64 = 3;
const RECEIVERS_VERSION: u64 = 1;

/// Every sender key released to bob, as the state blobs his node sealed into `store`.
fn stored_receivers(store: &Store, channel: &[u8; 32], sek: &Sek) -> Vec<Vec<u8>> {
    let Some(seg) = store
        .get_segment(channel, SegmentKind::KeyMaterial, SEG_RECEIVERS)
        .expect("CANNOT MEASURE: the attacker could not read bob's receiver segment")
    else {
        return Vec::new();
    };
    let bytes = open_segment(sek, SegmentKind::KeyMaterial, SEG_RECEIVERS, &seg)
        .expect("CANNOT MEASURE: the receiver segment does not open under bob's SEK");
    // The attacker's reader of bob's own format: a mismatch means it cannot read what it means
    // to attack, so nothing below would be measured.
    let unreadable = |what: &str| {
        format!("CANNOT MEASURE: the attacker cannot read the receiver segment's {what}")
    };
    let mut d = Decoder::new(&bytes);
    assert_eq!(
        d.array()
            .unwrap_or_else(|e| panic!("{}: {e}", unreadable("arity"))),
        2,
        "{}",
        unreadable("arity")
    );
    assert_eq!(
        d.uint()
            .unwrap_or_else(|e| panic!("{}: {e}", unreadable("version"))),
        RECEIVERS_VERSION,
        "{}",
        unreadable("version")
    );
    let n = d
        .array()
        .unwrap_or_else(|e| panic!("{}: {e}", unreadable("key list")));
    (0..n)
        .map(|_| {
            d.bytes()
                .unwrap_or_else(|e| panic!("{}: {e}", unreadable("keys")))
                .to_vec()
        })
        .collect()
}

/// Try every held key for the message's (author, generation), each from its stored state,
/// ignoring any consent or revocation. `Some(text)` if one opens it.
fn attacker_opens(keys: &[Vec<u8>], msg: &GroupMessage) -> Option<String> {
    keys.iter().find_map(|state| {
        let mut chain = ReceiverChain::from_state(state).ok()?;
        if chain.author_id() != msg.header.author_id || chain.chain_id() != msg.header.chain_id {
            return None;
        }
        let plain = chain.decrypt(msg).ok()?;
        Content::from_canonical_slice(&plain).ok().map(|c| c.text)
    })
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
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let (_anchor, spec) = anchor(tmp.path());
    let alice = member(tmp.path(), "alice", &spec);
    let bob = member(tmp.path(), "bob", &spec);
    let carol = member(tmp.path(), "carol", &spec);

    // ---- one room, all three in it, everyone trusting everyone ----
    let (ok, _, e) = alice.vox(
        &["room", "create", "--name", "team"],
        Some(&format!("{ROOM_PASS}\n")),
    );
    assert!(ok, "CANNOT MEASURE: room create: {e}");
    let (_, listed, list_err) = alice.vox(&["room", "list"], None);
    let room = listed
        .split_whitespace()
        .next()
        .unwrap_or_else(|| {
            panic!("PRODUCT: `vox room list` names no room after a create: {listed}{list_err}")
        })
        .to_owned();
    let (ok, link, e) = alice.vox(&["room", "invite", &room], None);
    assert!(ok, "CANNOT MEASURE: invite: {e}");
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

    // ---- the attacker's snapshot of bob's own key state, then a post it must be able to open ----
    let bob_store = bob.data.join("default").join("store.redb");
    let snapshot = tmp.path().join("bob-snapshot.redb");
    let bob_pid = bob.daemon.as_ref().unwrap().0.id();
    signal(bob_pid, "-STOP");
    let copied = std::fs::copy(&bob_store, &snapshot);
    signal(bob_pid, "-CONT");
    copied.expect("CANNOT MEASURE: copy bob's store.redb");
    let (ok, _, e) = alice.vox(&["room", "post", &room, "BEFORE-REMOVAL-CONTROL"], None);
    assert!(ok, "PRODUCT: alice could not post: {e}");
    assert!(
        until(
            "bob renders BEFORE-REMOVAL-CONTROL",
            Duration::from_secs(60),
            || { bob.reads(&room, "BEFORE-REMOVAL-CONTROL") }
        ),
        "CANNOT MEASURE: bob never rendered alice's last pre-removal post, so it is not provably \
         in his log for the attacker to open"
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
    assert!(ok, "PRODUCT: `vox trust remove` on alice refused: {o}{e}");
    for n in 1..=AFTER {
        let (ok, _, e) = alice.vox(
            &["room", "post", &room, &format!("ONLY-CAROL-READS-THIS {n}")],
            None,
        );
        assert!(ok, "PRODUCT: alice could not post: {e}");
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
    let (_, carol_seen, carol_err) = carol.vox(&["room", "read", &room], None);
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
    let (bob_read_ok, bob_seen, bob_read_err) = bob.vox(&["room", "read", &room], None);
    assert!(
        bob_read_ok,
        "CANNOT MEASURE: bob's final read failed: {bob_read_err}"
    );
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
        "PRODUCT: carol, still trusted, read {carol_count}/3 of alice's messages across the \
         rotation; her `vox room read` said:\n{carol_seen}{carol_err}"
    );
    assert!(
        control.is_some(),
        "CANNOT MEASURE: bob never rendered carol's post after the removal, so his not reading \
         alice would prove nothing"
    );
    assert_eq!(
        bob_count, 0,
        "PRODUCT: bob, removed from alice's ring, still reads {bob_count}/3 of what she posted \
         afterwards: `vox trust remove` did not change the lock"
    );
    assert!(
        bob_before,
        "PRODUCT: what bob read before the removal is no longer rendered to him: {bob_seen}"
    );

    // ---- the attacker arm: bob, on a modified node, reads his own disk ----
    let mut bob = bob;
    stop(bob.daemon.take().expect("APPARATUS: bob's daemon handle"));
    let mut profile = Profile::open(Paths {
        config_dir: bob.data.join("cfg"),
        profile_dir: bob.data.join("default"),
    })
    .expect("CANNOT MEASURE: open bob's profile offline");
    profile
        .unlock(ID_PASS.as_bytes())
        .expect("CANNOT MEASURE: unlock bob's profile with his passphrase");
    let store = profile.store();
    let channels = store
        .channels()
        .expect("CANNOT MEASURE: the attacker could not list bob's rooms");
    assert_eq!(
        channels.len(),
        1,
        "CANNOT MEASURE: bob's store holds {} rooms, not the one",
        channels.len()
    );
    let channel = channels[0];
    let sek = store
        .get_sek_wrap(&channel)
        .expect("CANNOT MEASURE: the attacker could not read the SEK wrap")
        .expect("CANNOT MEASURE: bob's store has no SEK wrap for the room")
        .unwrap_sek(
            &SignatureIdentityFactor::new(
                profile
                    .signer()
                    .expect("CANNOT MEASURE: bob's unlocked profile has no signer"),
            ),
            &channel,
            ROOM_PASS.as_bytes(),
        )
        .expect(
            "CANNOT MEASURE: unwrap the room's SEK with bob's identity and the room passphrase",
        );
    let final_keys = stored_receivers(store, &channel, &sek);
    let snapshot_store =
        Store::open(&snapshot).expect("CANNOT MEASURE: open the snapshot of bob's store");
    let snapshot_keys = stored_receivers(&snapshot_store, &channel, &sek);
    let mut every_key = final_keys.clone();
    every_key.extend(snapshot_keys.iter().cloned());

    // Every content entry in bob's log, as (author, seq, message), in log order.
    let mut content = Vec::new();
    for (id, seg) in store
        .segments(&channel, SegmentKind::LogDb)
        .expect("CANNOT MEASURE: the attacker could not read bob's log")
    {
        let wire = open_segment(&sek, SegmentKind::LogDb, id, &seg)
            .expect("CANNOT MEASURE: a log segment does not open under bob's SEK");
        let entry = Entry::from_wire(&wire)
            .expect("CANNOT MEASURE: the attacker cannot decode a stored log entry");
        if let Some(msg) = entry
            .payload
            .as_deref()
            .and_then(|p| GroupMessage::from_wire(p).ok())
        {
            content.push((entry.skeleton.author_id, entry.skeleton.seq, msg));
        }
    }

    // The escalation works: bob's own earlier key opens alice's last pre-removal post.
    let control = content.iter().find(|(_, _, msg)| {
        attacker_opens(&snapshot_keys, msg).as_deref() == Some("BEFORE-REMOVAL-CONTROL")
    });
    let Some((alice_id, control_seq, control_msg)) = control else {
        panic!(
            "CANNOT MEASURE: the attacker could not open BEFORE-REMOVAL-CONTROL with bob's own \
             stored key ({} content entries in his log, {} keys in the snapshot, {} in his final \
             store): its escalation does not work, so its failing below would prove nothing",
            content.len(),
            snapshot_keys.len(),
            final_keys.len()
        )
    };
    let after: Vec<&GroupMessage> = content
        .iter()
        .filter(|(author, seq, _)| author == alice_id && seq > control_seq)
        .map(|(_, _, msg)| msg)
        .collect();
    let opened: Vec<String> = after
        .iter()
        .filter_map(|msg| attacker_opens(&every_key, msg))
        .collect();
    eprintln!(
        "[proof] attacker: opened the pre-removal control (generation {}); alice's post-removal \
         entries in bob's log: {} (generations {:?}); bob's keys: {} final + {} snapshot; opened \
         {}/{}: {opened:?}",
        control_msg.header.chain_id,
        after.len(),
        after.iter().map(|m| m.header.chain_id).collect::<Vec<_>>(),
        final_keys.len(),
        snapshot_keys.len(),
        opened.len(),
        after.len()
    );
    assert_eq!(
        after.len(),
        3,
        "CANNOT MEASURE: bob's log holds {} of alice's post-removal posts, not 3, so what the \
         attacker fails to open is not what she said",
        after.len()
    );
    assert_eq!(
        opened.len(),
        0,
        "PRODUCT: a removed member on a modified node opens {}/3 of alice's post-removal posts with a key \
         he already held ({opened:?}): `vox trust remove` wrote the revocation but did not rotate \
         the key",
        opened.len()
    );
}
