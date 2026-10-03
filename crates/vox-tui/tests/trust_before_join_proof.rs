//! **Trust is decided once, not per room**: a real `vox node` anchor and two real `vox daemon`s.
//!
//! ## 1. ADR-021 F12 — a joiner reads what the room's host posts the moment the join returns,
//! when the host already trusted it
//!
//! A room is ForwardOnly (ADR-006): a newcomer reads only what is sealed after a key
//! is released to it. With the joiner already in the host's trust ring, the host's
//! release used to wait for its next tick, so a post made right after the join was
//! sealed before the key and was unreadable to the joiner for good — "bob never sees
//! alice's warmup", every time. With trust added AFTER the join it crossed in 2 s,
//! because trusting consents at once. Found by `peer.sh`, narrowed with instrumented
//! daemons: the entry synced, the key arrived, and decryption refused "group
//! iteration before chain head". The host now releases the key at admission.
//!
//! Every trust edge is added before either daemon starts, and alice posts the moment
//! bob's `vox room join` returns — the shape that failed.
//!
//! ## 2. V210-156 — two people who share a room join a second one with no new trust step
//!
//! The decider's join journey (2026-10-02): the first room two people share takes six steps —
//! swap fingerprints, create, invite, send the link and passphrase, join, trust each other — and
//! any later room they share takes only create, invite, send and join, because trust is a
//! node's decision about a person, not about a room. So, staged as people do it:
//! 1. alice and bob each run `vox id`; alice creates `first`, invites, bob joins; **then** each
//!    runs `vox trust add` on the other, and each reads the other in `first`
//!    (`PRODUCT (staging)` otherwise: the first room never worked, so the second proves nothing);
//! 2. alice creates `second` and invites, bob joins — and **neither runs any trust command**;
//! 3. each posts the moment bob's join returns, and each must read the other in `second` within
//!    [`ROOM_BOUND`].
//!
//! **The mutation that must turn (2) red:** a key released only into the rooms that were open when
//! trust was decided (`release_key_to` refusing any other room). The first room still works; the
//! second does not, and the red says `PRODUCT`.
//!
//! **Every red names its side:** what the shipped binary does wrong is `PRODUCT:`, a step of the
//! staging the shipped binary fails is `PRODUCT (staging):`, and a fault of this harness is
//! `CANNOT MEASURE (harness error):`.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const ID_PASS: &str = "an identity passphrase";
const ROOM_PASS: &str = "the room passphrase";
/// How long a member may take to read another's post in a room they share: the bound both
/// journeys hold a room's first read to.
const ROOM_BOUND: u64 = 60;

/// A harness step that must not fail, or the proof cannot measure anything.
fn harness<T, E: std::fmt::Debug>(r: Result<T, E>, what: &str) -> T {
    r.unwrap_or_else(|e| panic!("CANNOT MEASURE (harness error): {what}: {e:?}"))
}

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
    cfg: PathBuf,
    pass: PathBuf,
}

impl Member {
    fn new(root: &Path, name: &'static str) -> Self {
        let (data, cfg) = (root.join(name).join("data"), root.join(name).join("cfg"));
        harness(std::fs::create_dir_all(&cfg), "make the config directory");
        let pass = root.join(format!("{name}.pass"));
        harness(std::fs::write(&pass, ID_PASS), "write the passphrase file");
        Self {
            name,
            data,
            cfg,
            pass,
        }
    }

    fn pass_file(&self) -> &str {
        self.pass
            .to_str()
            .unwrap_or_else(|| panic!("CANNOT MEASURE (harness error): a non-UTF-8 temp path"))
    }

    fn vox(&self, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
        let mut cmd = Command::new(VOX);
        cmd.args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env_remove("VOX_ROOM")
            .env_remove("VOX_SESSION")
            .env_remove("CLAUDE_CODE_SESSION_ID")
            .env_remove("CODEX_THREAD_ID")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = harness(cmd.spawn(), "spawn vox");
        if let Some(s) = stdin {
            let mut pipe = child
                .stdin
                .take()
                .unwrap_or_else(|| panic!("CANNOT MEASURE (harness error): no stdin pipe"));
            harness(pipe.write_all(s.as_bytes()), "write vox's stdin");
        }
        let out = harness(child.wait_with_output(), "wait for vox");
        let r = (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        );
        eprintln!(
            "[receipt] {} vox {} -> {} {}",
            self.name,
            args.join(" "),
            r.0,
            r.2.trim()
        );
        r
    }

    fn fingerprint(&self) -> String {
        let (ok, out, err) = self.vox(
            &["id", "--identity-passphrase-file", self.pass_file()],
            None,
        );
        assert!(ok, "PRODUCT (staging): {} `vox id`: {err}", self.name);
        out.trim().to_owned()
    }

    fn trust(&self, other: &Member, fingerprint: &str) {
        let (ok, _, err) = self.vox(
            &[
                "trust",
                "add",
                fingerprint,
                "--name",
                other.name,
                "--identity-passphrase-file",
                self.pass_file(),
            ],
            None,
        );
        assert!(
            ok,
            "PRODUCT (staging): {} `vox trust add` {}: {err}",
            self.name, other.name
        );
    }

    fn daemon(&self, anchor: &str, err: &Path) -> Proc {
        let child = harness(
            Command::new(VOX)
                .args([
                    "daemon",
                    "--listen",
                    "127.0.0.1:0",
                    "--anchor",
                    anchor,
                    "--passphrase-file",
                ])
                .arg(&self.pass)
                .env("VOX_DATA_DIR", &self.data)
                .env("VOX_CONFIG_DIR", &self.cfg)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::from(harness(
                    std::fs::File::create(err),
                    "create the daemon's log",
                )))
                .spawn(),
            "spawn vox daemon",
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        while !self.vox(&["room", "list"], None).0 {
            assert!(
                Instant::now() < deadline,
                "PRODUCT (staging): {}'s daemon never answered",
                self.name
            );
            std::thread::sleep(Duration::from_millis(500));
        }
        Proc(child)
    }

    /// The id (as `vox room list` prints it) of the room this member calls `name`.
    fn room_id(&self, name: &str) -> String {
        let (ok, list, err) = self.vox(&["room", "list"], None);
        assert!(
            ok,
            "PRODUCT (staging): {} `vox room list`: {err}",
            self.name
        );
        list.lines()
            .find(|l| l.split_whitespace().nth(1) == Some(name))
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or_else(|| {
                panic!(
                    "PRODUCT (staging): {} has no room named {name}: {list}",
                    self.name
                )
            })
            .to_owned()
    }

    /// Create the room `name` on this member's node, and the link to it.
    fn create(&self, name: &str) -> (String, String) {
        let (ok, _, err) = self.vox(&["room", "create", "--name", name], Some(ROOM_PASS));
        assert!(
            ok,
            "PRODUCT (staging): {} `vox room create` {name}: {err}",
            self.name
        );
        let room = self.room_id(name);
        let (ok, link, err) = self.vox(&["room", "invite", &room], None);
        assert!(
            ok && link.trim().starts_with("vox://"),
            "PRODUCT (staging): {} `vox room invite` {name}: {link}{err}",
            self.name
        );
        (room, link.trim().to_owned())
    }

    /// Join `link` as the room `name`. A set-up join is retried, as `support/room.rs` does, for
    /// the separate known host-busy refusal.
    fn join(&self, link: &str, name: &str) {
        let mut last = String::new();
        for attempt in 1..=6 {
            let (ok, _, err) = self.vox(&["room", "join", link, "--name", name], Some(ROOM_PASS));
            if ok {
                eprintln!("[receipt] {} joined {name} on attempt {attempt}", self.name);
                return;
            }
            last = err;
            std::thread::sleep(Duration::from_secs(5));
        }
        panic!(
            "PRODUCT (staging): {} never joined {name} — the join itself failed, which is not \
             what this proves: {last}",
            self.name
        );
    }

    fn post(&self, room: &str, text: &str) {
        let (ok, _, err) = self.vox(&["room", "post", room, text], None);
        assert!(
            ok,
            "PRODUCT (staging): {} `vox room post`: {err}",
            self.name
        );
    }

    fn reads(&self, room: &str, text: &str, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            let (_, out, _) = self.vox(&["room", "read", room], None);
            if out.contains(text) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        false
    }
}

/// An anchor (`vox node`) and its `--anchor` spec.
fn anchor(root: &Path) -> (Proc, String) {
    let (a_data, a_cfg) = (root.join("anchor/data"), root.join("anchor/cfg"));
    harness(std::fs::create_dir_all(&a_cfg), "make the anchor's config");
    let anchor_out = root.join("anchor.out");
    let proc = Proc(harness(
        Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &a_data)
            .env("VOX_CONFIG_DIR", &a_cfg)
            .stdout(Stdio::from(harness(
                std::fs::File::create(&anchor_out),
                "create the anchor's log",
            )))
            .stderr(Stdio::null())
            .spawn(),
        "spawn vox node",
    ));
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let text = std::fs::read_to_string(&anchor_out).unwrap_or_default();
        if let Some(s) = text
            .split_whitespace()
            .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        {
            return (proc, s.to_owned());
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): the anchor never printed its spec"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Both daemons' logs, for a red.
fn logs(root: &Path, members: &[Member]) -> String {
    members
        .iter()
        .map(|m| {
            format!(
                "--- {} ---\n{}",
                m.name,
                std::fs::read_to_string(root.join(format!("{}.err", m.name))).unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
#[ignore = "a real anchor and two real daemons with production Argon2id; run by hand, on demand, in release"]
fn a_trusted_joiner_reads_what_the_host_posts_right_after_the_join() {
    watchdog::arm();
    let tmp = harness(tempfile::tempdir(), "a temp dir");
    let root = tmp.path();
    let (_anchor, spec) = anchor(root);

    let members = [Member::new(root, "alice"), Member::new(root, "bob")];
    let fps: Vec<String> = members.iter().map(Member::fingerprint).collect();
    for (i, m) in members.iter().enumerate() {
        let j = 1 - i;
        m.trust(&members[j], &fps[j]);
    }
    let _daemons: Vec<Proc> = members
        .iter()
        .map(|m| m.daemon(&spec, &root.join(format!("{}.err", m.name))))
        .collect();
    let [alice, bob] = &members;

    let (room, link) = alice.create("mission");
    bob.join(&link, "mission");

    // The moment the join returns: this is the post that used to be lost for good.
    alice.post(&room, "warmup from alice");
    bob.post(&room, "warmup from bob");
    let bob_reads_alice = bob.reads(&room, "warmup from alice", ROOM_BOUND);
    let alice_reads_bob = alice.reads(&room, "warmup from bob", ROOM_BOUND);
    assert!(
        bob_reads_alice && alice_reads_bob,
        "PRODUCT: F12: a joiner trusted before the join must read what the host posts the moment \
         the join returns, and the host the joiner, within {ROOM_BOUND} s: bob reads alice = \
         {bob_reads_alice}, alice reads bob = {alice_reads_bob}; daemon logs:\n{}",
        logs(root, &members)
    );
}

#[test]
#[ignore = "a real anchor and two real daemons with production Argon2id; run by hand, on demand, in release"]
fn two_people_who_share_a_room_read_each_other_in_a_second_one_with_no_new_trust_step() {
    watchdog::arm();
    let tmp = harness(tempfile::tempdir(), "a temp dir");
    let root = tmp.path();
    let (_anchor, spec) = anchor(root);

    // ---- the first room: all six steps ----
    let members = [Member::new(root, "alice"), Member::new(root, "bob")];
    // 1. Each has an identity, and they swap fingerprints.
    let fps: Vec<String> = members.iter().map(Member::fingerprint).collect();
    let _daemons: Vec<Proc> = members
        .iter()
        .map(|m| m.daemon(&spec, &root.join(format!("{}.err", m.name))))
        .collect();
    let [alice, bob] = &members;
    // 2.–5. Alice creates and invites; the link and passphrase are sent; bob joins.
    let (first, link) = alice.create("first");
    bob.join(&link, "first");
    // 6. Each trusts the other.
    alice.trust(bob, &fps[1]);
    bob.trust(alice, &fps[0]);
    alice.post(&first, "alice in the first room");
    bob.post(&first, "bob in the first room");
    let first_ab = bob.reads(&first, "alice in the first room", ROOM_BOUND);
    let first_ba = alice.reads(&first, "bob in the first room", ROOM_BOUND);
    eprintln!("[proof] first room: bob reads alice {first_ab}, alice reads bob {first_ba}");
    assert!(
        first_ab && first_ba,
        "PRODUCT (staging): in the first room, after both trusted each other, bob reads alice = \
         {first_ab}, alice reads bob = {first_ba}: the first room never worked, so the second \
         proves nothing; daemon logs:\n{}",
        logs(root, &members)
    );

    // ---- the second room: create, invite, send, join — no fingerprint swap, no trust ----
    let (second, link) = alice.create("second");
    bob.join(&link, "second");
    let joined = Instant::now();
    // The moment the join returns, as people would.
    alice.post(&second, "alice in the second room");
    bob.post(&second, "bob in the second room");
    let second_ab = bob.reads(&second, "alice in the second room", ROOM_BOUND);
    let second_ba = alice.reads(&second, "bob in the second room", ROOM_BOUND);
    eprintln!(
        "[proof] second room, no trust step: bob reads alice {second_ab}, alice reads bob \
         {second_ba}, {} ms after the join returned",
        joined.elapsed().as_millis()
    );
    assert!(
        second_ab && second_ba,
        "PRODUCT: two people who trust each other from their first room must read each other in a \
         second one with no new trust step, each within {ROOM_BOUND} s: bob reads alice = \
         {second_ab}, alice reads bob = {second_ba}; daemon logs:\n{}",
        logs(root, &members)
    );
}
