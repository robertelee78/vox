//! PRD-001 R1/R3 — a room with a long history reopens, and a newcomer's log catches up with all of it,
//! driven through the **shipped `vox` binary**.
//!
//! **The defect (PRD-001 D1).** Every log entry passed `Dag::accept`, which charged it to a
//! per-author quota of 1,000 entries per rolling hour: an entry authored here, an entry arriving
//! by sync, and — the part that made it a defect rather than a policy — every **stored** entry
//! replayed when a room is opened. Replay is one burst, so the 1,001st stored entry from one
//! author was "over quota" at open time and the room could not be opened: a room was lost for good
//! once one member had posted a thousand times in an hour, and restarting the node was what
//! triggered it. The same charge refused the 1,001st post outright and throttled a newcomer's
//! catch-up. The decider removed the quota (R3): invitees are trusted, agents are not throttled.
//!
//! What this drives, as an operator would type it:
//!
//! ```text
//! vox id; vox trust add …          # two identities that consent to each other
//! vox daemon                       # alice's node, no terminal
//! vox room create; vox room post   # POSTS posts from one author, every one must succeed
//! (kill the daemon) vox daemon     # restart: the room must open, and read back every row
//! vox room invite / vox room join  # bob, cold: his log must hold every entry alice's does
//! ```
//!
//! Mutation: put the 1,000/hour check back in `Dag::accept` and this goes red at post 1,001;
//! exempt local appends from it and it goes red at the reopen.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
/// Half again past the old 1,000-per-hour cap, from one author, inside a minute or two.
const POSTS: usize = 1_500;

/// A `vox daemon`, killed by its own PID when dropped.
struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn vox(dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        // In the environment, not argv: a command line is world-readable (ADR-015).
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn vox");
    if let Some(text) = stdin {
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(text.as_bytes())
            .expect("write stdin");
        drop(child.stdin.take());
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Start `vox daemon` with `stdin_lines` piped in, its output to files next to the profile.
fn daemon(dir: &std::path::Path, tag: &str, stdin_lines: &str) -> Daemon {
    let out = std::fs::File::create(dir.join(format!("daemon-{tag}.out"))).unwrap();
    let err = std::fs::File::create(dir.join(format!("daemon-{tag}.err"))).unwrap();
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .expect("spawn vox daemon");
    // Write, then close: the daemon reads stdin to EOF before it binds its socket.
    let mut pipe = child.stdin.take().expect("daemon stdin");
    pipe.write_all(stdin_lines.as_bytes()).unwrap();
    drop(pipe);
    Daemon(child)
}

/// `vox room list` once the daemon's socket answers.
fn attached(dir: &std::path::Path, tag: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last = String::new();
    while Instant::now() < deadline {
        let (ok, out, err) = vox(dir, &["room", "list"], None);
        if ok {
            return out;
        }
        last = err;
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!(
        "{tag}'s daemon never answered: {last}\nits stderr: {}",
        std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default()
    );
}

/// How many of the posts `vox room read` returns.
fn rows(dir: &std::path::Path, room: &str) -> (usize, String) {
    let (ok, out, err) = vox(dir, &["room", "read", room], None);
    if !ok {
        return (0, err);
    }
    (
        out.lines().filter(|l| l.contains(" post ")).count(),
        String::new(),
    )
}

#[test]
#[ignore = "real vox daemons, 1,500 CLI posts and production Argon2id; CI runs it in release"]
fn a_room_past_a_thousand_posts_from_one_author_reopens_and_a_newcomer_holds_them_all() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let alice = tmp.path().join("alice");
    let bob = tmp.path().join("bob");
    for d in [&alice, &bob] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }

    // ---- two identities that consent to each other, decided before any daemon runs ----
    let mut fps = Vec::new();
    for dir in [&alice, &bob] {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "vox id: {err}");
        fps.push(out.trim().to_owned());
    }
    for (dir, fp, name) in [(&alice, &fps[1], "bob"), (&bob, &fps[0], "alice")] {
        let (ok, _, err) = vox(dir, &["trust", "add", fp, "--name", name], None);
        assert!(ok, "vox trust add {name}: {err}");
    }

    // ---- alice: a room, and POSTS posts from one author --------------------------------
    let first = daemon(&alice, "first", &format!("{IDENTITY}\n"));
    attached(&alice, "alice");
    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--name", "long"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room create: {err}");
    let listed = attached(&alice, "alice");
    let room = listed
        .split_whitespace()
        .find(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .expect("a room id in `room list`")
        .to_owned();

    let started = Instant::now();
    for i in 1..=POSTS {
        let (ok, _, err) = vox(&alice, &["room", "post", &room, &format!("post {i}")], None);
        assert!(
            ok,
            "post {i} of {POSTS} was refused after {} succeeded: {err} — one author may post \
             without limit (PRD-001 R1/R3)",
            i - 1
        );
    }
    let (before, why) = rows(&alice, &room);
    println!(
        "alice posted {POSTS} through `vox room post` in {:?}; `vox room read` returns {before} {why}",
        started.elapsed()
    );
    assert_eq!(before, POSTS, "every post reads back before the restart");

    // ---- restart: the room must open, with every row --------------------------------------
    drop(first); // killed by PID
    let second = daemon(&alice, "second", &format!("{IDENTITY}\n{ROOMPASS}\n"));
    let listed = attached(&alice, "alice");
    let (after, why) = rows(&alice, &room);
    println!(
        "after the restart: `room list` says {listed:?}; `vox room read` returns {after} {why}"
    );
    assert!(
        listed.contains("long") && !listed.contains("[closed]"),
        "the room with {POSTS} posts from one author did not reopen after a restart: \
         {listed:?} — PRD-001 D1\nalice's daemon said: {}",
        std::fs::read_to_string(alice.join("daemon-second.err")).unwrap_or_default()
    );
    assert_eq!(after, POSTS, "every post reads back after the restart");

    // ---- bob joins cold and must read every row ------------------------------------------
    let (ok, link, err) = vox(&alice, &["room", "invite", &room], None);
    assert!(ok, "vox room invite: {err}");
    let link = link.trim().to_owned();
    let bob_daemon = daemon(&bob, "bob", &format!("{IDENTITY}\n"));
    attached(&bob, "bob");
    let (ok, _, err) = vox(
        &bob,
        &["room", "join", &link, "--name", "long"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "vox room join: {err}");
    // Bob's catch-up is measured on his **log**, not on what he can render. Rendering history is
    // a key question, not a sync one — and on this tree a newcomer given its key at the origin
    // cannot open a live message more than `MAX_SKIP` (1,000) iterations ahead of it, so "bob
    // reads the next post" is not a usable signal past a thousand posts (recorded as a separate
    // finding). So bob's daemon runs for a round, is stopped by PID, and his store is opened by
    // the same node code the daemon runs, to count what it holds; then it runs again.
    let held = |dir: &std::path::Path| -> u64 {
        let paths =
            vox_core::node::paths::Paths::resolve("default", Some(dir), Some(&dir.join("cfg")))
                .unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let node = loop {
                match vox_core::node::actor::Node::spawn(paths.clone()) {
                    Ok(n) => break n,
                    Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
                }
            };
            let secret = |s: &str| vox_core::node::api::Secret::new(s.as_bytes().to_vec());
            assert!(node
                .apply(vox_core::node::api::NodeCommand::Unlock {
                    passphrase: secret(IDENTITY)
                })
                .await
                .is_done());
            let cid = node.view().channels[0].channel_id;
            assert!(node
                .apply(vox_core::node::api::NodeCommand::OpenChannel {
                    channel_id: cid,
                    passphrase: secret(ROOMPASS),
                })
                .await
                .is_done());
            let n = node.view().channels[0].entries;
            let _ = node.apply(vox_core::node::api::NodeCommand::Shutdown).await;
            n
        })
    };
    let joined = Instant::now();
    let mut bob_held = 0;
    let mut last = u64::MAX;
    let mut bob_daemon = Some(bob_daemon);
    for round in 1..=8 {
        std::thread::sleep(Duration::from_secs(15));
        drop(bob_daemon.take()); // stopped by PID
        bob_held = held(&bob);
        println!(
            "round {round}: bob's log holds {bob_held} entries after {:?}",
            joined.elapsed()
        );
        // Past the posts and unchanged since the last round: the governance entries (the two
        // consents) travel too, so the count is settled rather than guessed.
        if bob_held >= POSTS as u64 && bob_held == last {
            break;
        }
        last = bob_held;
        bob_daemon = Some(daemon(
            &bob,
            &format!("bob-{round}"),
            &format!("{IDENTITY}\n{ROOMPASS}\n"),
        ));
        attached(&bob, "bob");
    }
    drop(bob_daemon);
    drop(second);
    let alice_held = held(&alice);
    println!("entries held: alice {alice_held}, bob {bob_held}");
    assert!(
        alice_held >= POSTS as u64,
        "alice's log holds her posts: {alice_held}"
    );
    assert_eq!(
        bob_held,
        alice_held,
        "a newcomer's log must reach the whole history, of any size (PRD-001 R1)\nbob's daemon \
         said: {}",
        std::fs::read_to_string(bob.join("daemon-bob.err")).unwrap_or_default()
    );
}
