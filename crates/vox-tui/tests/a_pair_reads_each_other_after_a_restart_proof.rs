//! **V210-78 — two members whose pairwise session the join opened still read each other after
//! the member that answered the join restarts**, through the shipped `vox` binary only: a
//! `vox node` anchor and three `vox daemon`s, every step typed as an operator types it (`vox id`,
//! `vox trust add|remove`, `vox room create|invite|join|post|read`).
//!
//! ## The defect
//! A join opens the joiner's pairwise session with the member that answered it, and the join
//! itself delivers that session's hello — so the joiner holds no hello it could offer again.
//! Sessions live only in memory. When the responder restarted (or locked) it held none, and:
//! - **joiner → responder:** the joiner's next key went under the dead session; the responder
//!   answered "no pairwise session", and the joiner resent it under the same dead session, for
//!   good;
//! - **responder → joiner:** the responder opened a fresh session and sent its hello; when the
//!   joiner's fingerprint is the lower, the rule kept the joiner's own (the join's) and asked for
//!   it to be offered again — which a join session cannot be. The hello was refused, for good.
//!
//! Neither read the other's next key until the joiner restarted. A key goes pairwise only when a
//! sender key rotates, so the split shows at the first rotation after the restart.
//!
//! ## The staging
//! 1. Two identities are made first and ordered by fingerprint: the **higher** creates the room
//!    (alice, the responder), the **lower** joins it (bob, the joiner), so the responder → joiner
//!    arm hits the rule's losing side on every run. carol joins third; she is only the lever.
//! 2. All three trust each other after the joins; each renders a post by each other
//!    (`CANNOT MEASURE` otherwise).
//! 3. alice's daemon is killed (SIGKILL, by PID) and started again with its identity passphrase
//!    alone; it reopens the room by itself (#208). Control: alice then renders a fresh post by
//!    bob and bob one by alice, both under the keys already held (`CANNOT MEASURE` otherwise), so
//!    what follows measures the sessions and nothing else.
//! 4. One of them rotates **alone**: it runs `vox trust remove <carol>`, which rotates its sender
//!    key and re-keys everyone still trusted — the other, pairwise — and posts once under it.
//!    Two tests, one per direction, each in a world of its own: were both to rotate, the first
//!    fresh session either sends would heal the pair on its own, and one direction's defect would
//!    hide the other's (measured: with both rotating, removing the joiner's half of the fix left
//!    it green).
//!
//! ## What is asserted
//! - bob rotates: alice renders his post within 90 s (joiner → responder);
//! - alice rotates: bob renders her post within 90 s (responder → joiner).
//!
//! The 90 s are an upper wait for a functional claim, not a latency claim: without the fix the
//! pair never reads each other again. Joiner → responder took about 31 s: bob's first key went
//! out on his connection to alice's old process, and the refusal that makes him open a fresh
//! session came only after that key's 30 s patience. V210-80 (#271) probes a connection whose key
//! answer is late and closes a dead one, and `the_joiner_is_read_again_promptly_…` holds that arm
//! to [`JOINER_PROMPTLY`], a latency claim, run in the timing lock.
//!
//! ## The mutations that must turn it red
//! - In `NetEvent::SkdmRefused` (`crates/vox-core/src/node/actor.rs`), never forget a session
//!   the member said it does not hold: the joiner → responder test goes red.
//! - In `accept_hello`, keep a join session that won the rule instead of replacing it with one
//!   that can be offered: the responder → joiner test goes red.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
/// How long the other member has to read the rotating member's post.
const AFTER_ROTATION: Duration = Duration::from_secs(90);

/// Everything a harness might have put in this process's environment (see `support/room.rs`).
const HARNESS_VARS: [&str; 10] = [
    "VOX_SESSION",
    "CLAUDE_CODE_SESSION_ID",
    "CODEX_THREAD_ID",
    "CODEX_SESSION_ID",
    "VOX_ROOM",
    "VOX_AGENT_NAME",
    "CLAUDE_CODE_MESSAGING_SOCKET",
    "CLAUDE_CODE_MESSAGING_TOKEN",
    "OPENCODE_SERVER_URL",
    "VOX_HARNESS",
];

/// A child process killed and reaped when dropped, by its own handle.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Member {
    name: &'static str,
    dir: PathBuf,
    pass: PathBuf,
    fp: String,
    daemon: Option<Proc>,
}

fn vox(dir: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    use std::io::Write as _;
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for v in HARNESS_VARS {
        cmd.env_remove(v);
    }
    let mut child = cmd.spawn().expect("spawn vox");
    if let Some(text) = stdin {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(text.as_bytes())
            .expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn member(tmp: &Path, name: &'static str) -> Member {
    let dir = tmp.join(name);
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    let pass = tmp.join(format!("{name}.pass"));
    std::fs::write(&pass, IDPASS).unwrap();
    let (ok, out, err) = vox(&dir, &["id"], None);
    assert!(ok, "{name}: vox id: {err}");
    Member {
        name,
        dir,
        pass,
        fp: out.trim().to_owned(),
        daemon: None,
    }
}

fn spawn_anchor(tmp: &Path) -> (Proc, String) {
    let dir = tmp.join("anchor");
    std::fs::create_dir_all(dir.join("cfg")).unwrap();
    let out = tmp.join("anchor.out");
    let mut cmd = Command::new(VOX);
    cmd.args(["node", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", &dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .stdout(Stdio::from(std::fs::File::create(&out).unwrap()))
        .stderr(Stdio::null());
    for v in HARNESS_VARS {
        cmd.env_remove(v);
    }
    let anchor = Proc(cmd.spawn().expect("spawn vox node"));
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let text = std::fs::read_to_string(&out).unwrap_or_default();
        if let Some(spec) = text
            .split_whitespace()
            .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        {
            return (anchor, spec.to_owned());
        }
        assert!(
            Instant::now() < deadline,
            "the anchor never printed its spec"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn start_daemon(m: &mut Member, anchor: &str, tag: &str) {
    let err = m.dir.join(format!("daemon-{tag}.err"));
    let mut cmd = Command::new(VOX);
    cmd.args([
        "daemon",
        "--listen",
        "127.0.0.1:0",
        "--anchor",
        anchor,
        "--passphrase-file",
    ])
    .arg(&m.pass)
    .env("VOX_DATA_DIR", &m.dir)
    .env("VOX_CONFIG_DIR", m.dir.join("cfg"))
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::from(std::fs::File::create(&err).unwrap()));
    for v in HARNESS_VARS {
        cmd.env_remove(v);
    }
    m.daemon = Some(Proc(cmd.spawn().expect("spawn vox daemon")));
    let deadline = Instant::now() + Duration::from_secs(60);
    while !vox(&m.dir, &["room", "list"], None).0 {
        assert!(
            Instant::now() < deadline,
            "{}'s daemon never answered",
            m.name
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn post(m: &Member, room: &str, text: &str) {
    let (ok, _, err) = vox(&m.dir, &["room", "post", room, text], None);
    assert!(ok, "{} posts {text:?}: {err}", m.name);
}

fn renders(m: &Member, room: &str, text: &str) -> bool {
    let (_, out, _) = vox(&m.dir, &["room", "read", room], None);
    out.lines().any(|l| l.ends_with(text))
}

/// Keep `author` posting fresh probes tagged `tag` until `reader` renders one, or `within` ends.
/// Returns how long it took.
fn until_read(
    author: &Member,
    reader: &Member,
    room: &str,
    tag: &str,
    within: Duration,
) -> Option<Duration> {
    let t0 = Instant::now();
    let mut n = 0u32;
    while t0.elapsed() < within {
        n += 1;
        post(author, room, &format!("{tag} {n}"));
        std::thread::sleep(Duration::from_millis(1500));
        let (_, out, _) = vox(&reader.dir, &["room", "read", room], None);
        if out.lines().any(|l| l.contains(&format!("{tag} "))) {
            return Some(t0.elapsed());
        }
    }
    None
}

/// Everything both tests share: the room, its three members, and the responder restarted.
struct World {
    _tmp: tempfile::TempDir,
    _anchor: Proc,
    alice: Member,
    bob: Member,
    carol: Member,
    room: String,
}

/// Steps 1–3 of the staging (see the module docs).
fn restarted_responder() -> World {
    let tmp = tempfile::tempdir().unwrap();

    // ---- the responder is the higher fingerprint, the joiner the lower ------------------
    let x = member(tmp.path(), "alice");
    let y = member(tmp.path(), "bob");
    let key = |m: &Member| vox_core::node::link::b32_decode(&m.fp, "fingerprint").unwrap();
    let (mut alice, mut bob) = if key(&x) > key(&y) { (x, y) } else { (y, x) };
    // The names follow the roles, whichever identity drew which.
    alice.name = "alice";
    bob.name = "bob";
    let mut carol = member(tmp.path(), "carol");
    assert!(
        key(&bob) < key(&alice),
        "CANNOT MEASURE: the joiner's fingerprint is not the lower"
    );

    let (anchor, spec) = spawn_anchor(tmp.path());
    for m in [&mut alice, &mut bob, &mut carol] {
        start_daemon(m, &spec, "start");
    }

    // ---- alice creates the room; bob joins through her, then carol ---------------------
    let (ok, _, err) = vox(
        &alice.dir,
        &["room", "create", "--name", "pair"],
        Some(ROOMPASS),
    );
    assert!(ok, "room create: {err}");
    let (_, listed, _) = vox(&alice.dir, &["room", "list"], None);
    let room = listed
        .split_whitespace()
        .next()
        .expect("the room in `vox room list`")
        .to_owned();
    let (ok, link, err) = vox(&alice.dir, &["room", "invite", &room], None);
    assert!(ok, "room invite: {err}");
    for m in [&bob, &carol] {
        // A join can be turned away while the host admits another joiner (a known, separate
        // defect): retried, bounded, as `support/room.rs` does.
        let joined = (1..=6).any(|attempt| {
            let (ok, _, err) = vox(
                &m.dir,
                &["room", "join", link.trim(), "--name", "pair"],
                Some(ROOMPASS),
            );
            if !ok {
                eprintln!("[harness] {} join attempt {attempt} refused: {err}", m.name);
                std::thread::sleep(Duration::from_secs(5));
            }
            ok
        });
        assert!(joined, "CANNOT MEASURE: {} could not join the room", m.name);
    }

    // ---- everyone trusts everyone, after the joins -------------------------------------
    for a in [&alice, &bob, &carol] {
        for b in [&alice, &bob, &carol] {
            if a.fp != b.fp {
                let (ok, _, err) = vox(
                    &a.dir,
                    &[
                        "trust",
                        "add",
                        &b.fp,
                        "--name",
                        b.name,
                        "--identity-passphrase-file",
                        a.pass.to_str().unwrap(),
                    ],
                    None,
                );
                assert!(ok, "{} trusts {}: {err}", a.name, b.name);
            }
        }
    }
    let members = [&alice, &bob, &carol];
    for a in members {
        for r in members {
            if a.fp != r.fp {
                let took = until_read(
                    a,
                    r,
                    &room,
                    &format!("ready {} for {}", a.name, r.name),
                    Duration::from_secs(120),
                );
                assert!(
                    took.is_some(),
                    "CANNOT MEASURE: {} never read {} before the restart",
                    r.name,
                    a.name
                );
            }
        }
    }

    // ---- the responder restarts: SIGKILL, then its identity passphrase alone -----------
    drop(alice.daemon.take());
    let t_restart = Instant::now();
    start_daemon(&mut alice, &spec, "restart");
    let reopened = Instant::now() + Duration::from_secs(60);
    while !vox(&alice.dir, &["room", "read", &room], None).0 {
        assert!(
            Instant::now() < reopened,
            "CANNOT MEASURE: alice's restarted daemon never reopened the room (#208)"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    // Control: the keys already held still work both ways, so the room syncs again.
    let control_ab = until_read(&bob, &alice, &room, "control bob", Duration::from_secs(90));
    let control_ba = until_read(
        &alice,
        &bob,
        &room,
        "control alice",
        Duration::from_secs(90),
    );
    eprintln!(
        "[proof] after the restart ({:.1}s): alice read bob's control in {control_ab:?}, bob \
         read alice's in {control_ba:?}",
        t_restart.elapsed().as_secs_f64()
    );
    assert!(
        control_ab.is_some() && control_ba.is_some(),
        "CANNOT MEASURE: the restarted room does not sync (control alice<-bob {control_ab:?}, \
         bob<-alice {control_ba:?})"
    );

    World {
        _tmp: tmp,
        _anchor: anchor,
        alice,
        bob,
        carol,
        room,
    }
}

/// Step 4: `rotator` alone removes carol and posts; `reader` must render that post.
fn one_rotates(
    w: &World,
    rotator: &Member,
    reader: &Member,
    arm: &str,
    why: &str,
    bound: Duration,
) {
    let (ok, _, err) = vox(
        &rotator.dir,
        &[
            "trust",
            "remove",
            &w.carol.fp,
            "--identity-passphrase-file",
            rotator.pass.to_str().unwrap(),
        ],
        None,
    );
    assert!(ok, "{} removes carol: {err}", rotator.name);
    let text = format!("rotated: {} says", rotator.name);
    post(rotator, &w.room, &text);
    let t0 = Instant::now();
    let mut took = None;
    while t0.elapsed() < bound {
        if renders(reader, &w.room, &text) {
            took = Some(t0.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    eprintln!(
        "[proof] {arm}, {} rotated alone: {} reads the post in {took:?} (bound {}s)",
        rotator.name,
        reader.name,
        bound.as_secs()
    );
    // What each node said about its keys and its connections to the other, on every run: a
    // key not taken says why, and a dead connection closed says so (V210-80).
    for (m, tag) in [(&w.bob, "start"), (&w.alice, "restart")] {
        let log =
            std::fs::read_to_string(m.dir.join(format!("daemon-{tag}.err"))).unwrap_or_default();
        for l in log.lines().filter(|l| {
            l.contains("not take") || l.contains("unanswered") || l.contains("new process")
        }) {
            eprintln!("[proof] {} said: {l}", m.name);
        }
    }
    let tail = |m: &Member, tag: &str| {
        std::fs::read_to_string(m.dir.join(format!("daemon-{tag}.err")))
            .unwrap_or_default()
            .lines()
            .rev()
            .take(15)
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert!(
        took.is_some(),
        "{arm}: {} never read {}'s post under the rotated key within {}s — {why}\nalice's log \
         tail:\n{}\nbob's log tail:\n{}",
        reader.name,
        rotator.name,
        bound.as_secs(),
        tail(&w.alice, "restart"),
        tail(&w.bob, "start")
    );
}

#[test]
#[ignore = "real vox daemons and production Argon2id; CI runs it in release"]
fn the_joiner_is_read_again_after_the_responder_restarts() {
    watchdog::arm();
    let w = restarted_responder();
    one_rotates(
        &w,
        &w.bob,
        &w.alice,
        "joiner -> responder",
        "bob's key went under the session alice lost when she restarted",
        AFTER_ROTATION,
    );
}

/// **V210-80 (#271): and promptly.** The joiner's re-key used to go out on his connection to the
/// responder's dead process, which counts as live until it has been silent 30 s; the key waited
/// out that 30 s before it was counted not taken, then its backoff (31.1–79.1 s measured on this
/// staging). A key whose answer is late now has its connection probed, and a dead one is closed at
/// once. Mutation: never probe (`close_if_unanswered` answering `false`) → red past this bound.
const JOINER_PROMPTLY: Duration = Duration::from_secs(15);

#[test]
#[ignore = "real vox daemons and production Argon2id; CI runs it in release"]
fn the_joiner_is_read_again_promptly_after_the_responder_restarts() {
    watchdog::arm();
    let w = restarted_responder();
    one_rotates(
        &w,
        &w.bob,
        &w.alice,
        "joiner -> responder, promptly",
        "bob's key waited on his connection to alice's dead process",
        JOINER_PROMPTLY,
    );
}

#[test]
#[ignore = "real vox daemons and production Argon2id; CI runs it in release"]
fn the_responder_is_read_again_after_it_restarts() {
    watchdog::arm();
    let w = restarted_responder();
    one_rotates(
        &w,
        &w.alice,
        &w.bob,
        "responder -> joiner",
        "bob kept the join's session, which cannot be offered again",
        AFTER_ROTATION,
    );
}
