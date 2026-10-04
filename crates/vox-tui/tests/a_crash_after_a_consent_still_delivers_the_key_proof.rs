//! V210-88 (#280) — **a crash right after a consent never costs the member the room**: after a kill at
//! any point between the consent's record and the member taking the key, the restarted node
//! delivers the key, and the member reads what the node posts next. Driven through the shipped
//! `vox` binary.
//!
//! **The defect.** A consent recorded the key as `delivered` in the grant's own transaction, the
//! moment the bytes were written, before the member had taken it. A SIGKILL right after that
//! commit cut the key off unread, and the watcher that would have re-owed it died with the process.
//! After the restart nothing owed the member anything: the log said consented, the ledger said
//! delivered. The member never read another post from that node. Found in V210-76's kill-point
//! proof, where it was counted apart as "left bob with no key" at kill point 4 in 3 of 3 runs.
//!
//! **The staging** is V210-76's (#267), kill point by kill point: an anchor, and alice's `vox
//! daemon` under the syscall interposer (`crates/vox-test-interpose`) with a kill point armed. For
//! each kill point `k` from 1: a new member `bob<k>` (who trusts alice) runs a daemon and joins;
//! alice posts `pre <k>`; once her store has gone [`QUIET`], the kill point is armed at `k` and
//! alice runs `vox trust add bob<k>`. Her daemon SIGKILLs itself right after the `k`-th flush of
//! its store that follows, which is a boundary between two of its transactions. Bob's daemon is
//! stopped, alice's is restarted, then bob's (V210-78's F-B2 otherwise splits the pair).
//!
//! **Nothing is decided again after the crash.** The #267 proof re-ran `vox trust add` in every
//! trial. Here alice re-trusts `bob<k>` only if the crash lost the trust itself, i.e. `vox trust
//! list` no longer names him (a decision that never reached the disk is a person's to make
//! again). Otherwise the restarted node has to act on what it recorded. Then alice posts `post
//! <k>`.
//!
//! **Asserted,** with hard-coded bounds: in every trial, killed or not, `bob<k>` reads `post <k>`
//! within [`BOUND`], and still reads no post made before alice trusted him [`HOLD`] later.
//! Preconditions (a vox step that misses one is `PRODUCT (staging)`; too few kill points is `APPARATUS`): every `bob<k>` is on alice's roster before she decides;
//! alice reads every post she made; at least [`MIN_KILLS`] kill points fell inside a consent; the
//! sweep ended inside [`MAX_POINTS`]. Every trial prints whether the trust survived the crash.
//!
//! **Two arms, because a member's own key can hide a lost one** (V210-118). When alice takes a
//! sender-key generation of bob's she did not hold, she offers him hers again, which owes it
//! whatever her ledger says. In the trust arm she cannot hold bob's key before the crash (she
//! refuses a key from a member she has not trusted, and trusting him is the decision under the
//! kill), so his key always reaches her after the restart and covers a ledger that lied.
//! - **The trust arm** (`a_crash_at_any_point_of_a_consent_still_delivers_the_key`): the decision
//!   is `vox trust add bob<k>`, as above. It measures what the trust decision records.
//! - **The held-key arm** (`a_crash_in_a_consent_whose_member_key_is_held_still_delivers_it`):
//!   alice trusts `host<k>` first; `host<k>` creates a room; once alice's store is quiet, the kill
//!   point is armed and alice runs `vox room join`. The host admits her and hands her its key in
//!   the join, before her copy of the room has synced; her consent to the host is issued only once
//!   it has (V210-164). So at every kill point inside that consent she already holds the host's
//!   key, and nothing re-offers hers: her ledger alone says whether it is owed. A join the crash
//!   lost is joined again, as a person would; then alice posts `post <k>` and the host must read it.
//!
//! **Mutations that must turn it red:**
//! - the key recorded as `delivered` when the consent is recorded, not when it is taken (V210-88):
//!   red in the held-key arm, `host<k>` reading nothing alice posts after the restart;
//! - a trust decision's place in the consent order drawn after the trust is saved, not before
//!   (V210-45): red in the trust arm at kill point 1, the restarted node releasing the key from
//!   after the post it then makes.
//!
//! **The one step that is not a `vox` command** is the crash: the interposer is test apparatus,
//! loaded into the unmodified binary with `DYLD_INSERT_LIBRARIES` (macOS), as the durable-write
//! proofs load it. Everything else is the shipped binary, killed by its PID when dropped.

#![cfg(target_os = "macos")]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/attach.rs"]
mod attach;

#[path = "support/syscalls.rs"]
mod syscalls;

use std::collections::BTreeSet;
use std::io::Write;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";
/// How long a member has to read the post made after it was trusted.
const BOUND: Duration = Duration::from_secs(90);
/// How long it keeps reading after that post arrived, to catch a late release from the origin.
const HOLD: Duration = Duration::from_secs(10);
/// How long a trust decision's consent has to reach the kill point before the sweep is over.
const PAST_THE_END: Duration = Duration::from_secs(8);
/// How long alice's store must go unflushed before a kill point is armed.
const QUIET: Duration = Duration::from_secs(3);
/// A consent is a handful of transactions; a sweep longer than this measures something else.
const MAX_POINTS: u64 = 16;
/// Fewer kill points than this inside a consent cannot have visited every boundary in it.
const MIN_KILLS: u64 = 3;
/// The held-key arm's sweep: a join and the consent after it are many more transactions than a
/// trust decision's consent.
const MAX_HELD_POINTS: u64 = 48;

/// A child process, killed by its own PID when dropped.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn command(dir: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        // In the environment, not argv: a command line is world-readable (ADR-015).
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_SESSION");
    cmd
}

/// A verb as a person runs it since ADR-026 L-2: one that needs its node attached, run while no
/// daemon holds the data root, runs with the node attached by `vox node attach` and let go after.
fn vox(dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let verb: Vec<&str> = args.to_vec();
    match attach::needs(dir, &verb) {
        Some(node) => {
            attach::Root::at(dir, IDENTITY).attached(&node, || vox_plain(dir, args, stdin))
        }
        None => vox_plain(dir, args, stdin),
    }
}

fn vox_plain(dir: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut child = command(dir, args)
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
        let mut pipe = child.stdin.take().expect("APPARATUS: stdin");
        pipe.write_all(text.as_bytes())
            .expect("PRODUCT (staging): vox exited without reading its stdin");
    }
    let out = child.wait_with_output().expect("APPARATUS: wait");
    let mut err = String::from_utf8_lossy(&out.stderr).into_owned();
    // A process ended by a signal says nothing on stderr: say how it ended, so a verb killed by
    // the watchdog's abort is not read as a verb that failed without a cause (#295).
    if !out.status.success() {
        err.push_str(&format!(" [vox {}: {}]", args.join(" "), out.status));
    }
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        err,
    )
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .map(|a| a.port())
        .expect("APPARATUS: a free port")
}

/// Start `vox daemon` on `port` with the identity passphrase piped in; `extra` is its environment.
fn daemon(dir: &Path, port: u16, anchor: &str, tag: &str, extra: &[(&str, &Path)]) -> Proc {
    let err = std::fs::File::options()
        .create(true)
        .append(true)
        .open(dir.join(format!("daemon-{tag}.err")))
        .expect("APPARATUS: open a log file");
    let listen = format!("127.0.0.1:{port}");
    let mut cmd = command(dir, &["daemon", "--listen", &listen, "--anchor", anchor]);
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(err))
        .spawn()
        .expect("APPARATUS: spawn vox daemon");
    let mut pipe = child.stdin.take().expect("APPARATUS: daemon stdin");
    pipe.write_all(format!("{IDENTITY}\n").as_bytes())
        .expect("PRODUCT (staging): vox exited without reading its stdin");
    drop(pipe);
    Proc(child)
}

/// `vox room list` once the daemon answers.
fn attached(dir: &Path, tag: &str) -> String {
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
    panic!("PRODUCT (staging): {tag}'s daemon never answered: {last}");
}

/// Every `pre <k>` and `post <k>` this profile reads in `room`. A row it cannot open carries a
/// marker, not a post, and is not counted.
fn texts(dir: &Path, room: &str) -> BTreeSet<String> {
    let (ok, out, err) = vox(
        dir,
        &["room", "read", room, "--json", "--limit", "500"],
        None,
    );
    assert!(ok, "PRODUCT (staging): vox room read --json refused: {err}");
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|row| row["text"].as_str().map(str::to_owned))
        .filter(|t| t.starts_with("pre ") || t.starts_with("post "))
        .collect()
}

fn post(dir: &Path, room: &str, text: &str) {
    let (ok, _, err) = vox(dir, &["room", "post", room, text], None);
    assert!(
        ok,
        "PRODUCT (staging): alice's post {text:?} was refused: {err}"
    );
}

fn alive(p: &mut Proc) -> bool {
    p.0.try_wait().ok().flatten().is_none()
}

#[test]
#[ignore = "real vox daemons under the syscall interposer, production Argon2id; CI runs it in release"]
fn a_crash_at_any_point_of_a_consent_still_delivers_the_key() {
    // Sized on the whole debug run (#295): its up to 16 joins and 131 unlocks, each at twice its
    // most measured, would ask for 8,838 s, past what any run is given. Two debug runs of this
    // proof took 1,041.7 s and 1,270.0 s.
    watchdog::arm_for_debug_total(Duration::from_millis(1_270_000), 2);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let root = tmp.path();
    let alice = root.join("alice");
    std::fs::create_dir_all(alice.join("cfg")).expect("APPARATUS: create a staging directory");
    let arm = root.join("kill-arm");
    let log = root.join("alice-interpose.tsv");
    let interposer = syscalls::interposer().to_path_buf();
    let env: Vec<(&str, &Path)> = vec![
        ("DYLD_INSERT_LIBRARIES", &interposer),
        ("VOX_INTERPOSE_LOG", &log),
        ("VOX_INTERPOSE_KILL_ARM", &arm),
    ];

    // ---- the anchor, and alice with a room --------------------------------------------------
    let anchor_dir = root.join("anchor");
    std::fs::create_dir_all(anchor_dir.join("cfg")).expect("APPARATUS: create a staging directory");
    let anchor_port = free_udp_port();
    let anchor_out = anchor_dir.join("node.out");
    let _anchor = Proc(
        command(
            &anchor_dir,
            &["node", "--listen", &format!("127.0.0.1:{anchor_port}")],
        )
        .stdout(Stdio::from(
            std::fs::File::create(&anchor_out).expect("APPARATUS: create a staging file"),
        ))
        .stderr(Stdio::null())
        .spawn()
        .expect("APPARATUS: spawn the anchor"),
    );
    let t0 = Instant::now();
    let spec = loop {
        let out = std::fs::read_to_string(&anchor_out).unwrap_or_default();
        if let Some(l) = out.lines().find(|l| l.contains("@/ip4/127.0.0.1/udp/")) {
            break l.trim().to_owned();
        }
        assert!(
            t0.elapsed() < Duration::from_secs(60),
            "PRODUCT (staging): the anchor printed no spec:\n{out}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let (ok, alice_fp, err) = vox(&alice, &["id"], None);
    assert!(ok, "PRODUCT (staging): vox id: {err}");
    let alice_fp = alice_fp.trim().to_owned();
    let alice_port = free_udp_port();
    let mut alice_daemon = daemon(&alice, alice_port, &spec, "alice", &env);
    let before: BTreeSet<String> = attached(&alice, "alice")
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--passphrase-file", "-", "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room create: {err}");
    let room = attached(&alice, "alice")
        .split_whitespace()
        .filter(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(str::to_owned)
        .find(|w| !before.contains(w))
        .expect("PRODUCT (staging): no new room id in alice's `room list`");
    let (ok, link, err) = vox(&alice, &["room", "invite", &room], None);
    assert!(ok, "PRODUCT (staging): vox room invite: {err}");
    let link = link.trim().to_owned();

    // The recorder's positive control: alice's daemon has opened its store by now, so a log with
    // no `open` is a recorder that records nothing, and every kill point below would be unarmed.
    let opens = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.split('\t').nth(2) == Some("open"))
        .count();
    assert!(
        opens > 0,
        "APPARATUS: the syscall recorder (vox-test-interpose under DYLD_INSERT_LIBRARIES) \
         recorded no `open` by alice's daemon in {}: it is not recording",
        log.display()
    );

    // ---- one trial per kill point ----------------------------------------------------------
    let mut made: Vec<String> = Vec::new();
    let mut kills = 0u64;
    let mut leaks: Vec<String> = Vec::new();
    let mut keyless: Vec<u64> = Vec::new();
    let mut retrusted: Vec<u64> = Vec::new();
    let mut ended_at = None;
    for k in 1..=MAX_POINTS {
        let bob: PathBuf = root.join(format!("bob{k}"));
        std::fs::create_dir_all(bob.join("cfg")).expect("APPARATUS: create a staging directory");
        let (ok, bob_fp, err) = vox(&bob, &["id"], None);
        assert!(ok, "PRODUCT (staging): vox id: {err}");
        let bob_fp = bob_fp.trim().to_owned();
        let (ok, _, err) = vox(&bob, &["trust", "add", &alice_fp, "--name", "alice"], None);
        assert!(ok, "PRODUCT (staging): bob{k} trusts alice: {err}");
        let bob_port = free_udp_port();
        let mut bob_daemon = daemon(&bob, bob_port, &spec, "bob", &[]);
        attached(&bob, "bob");
        let (ok, _, err) = vox(
            &bob,
            &[
                "room",
                "join",
                "--passphrase-file",
                "-",
                &link,
                "--name",
                "r",
            ],
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(ok, "PRODUCT (staging): bob{k} could not join: {err}");
        let t = Instant::now();
        loop {
            let (_, roster, _) = vox(&alice, &["room", "roster", &room], None);
            if roster.lines().any(|l| l.trim().starts_with(&bob_fp[..26])) {
                break;
            }
            assert!(
                t.elapsed() < Duration::from_secs(60),
                "PRODUCT (staging): bob{k} is not on alice's roster"
            );
            std::thread::sleep(Duration::from_millis(250));
        }
        let pre = format!("pre {k}");
        post(&alice, &room, &pre);
        made.push(pre);

        // **A quiet store first.** Bob's join goes on writing to alice's store for a few seconds
        // (his records, his key), and a flush of that landing inside the sweep would shift which
        // commit of the consent each kill point falls after. So the kill point is armed only once
        // alice's store has not been flushed for QUIET.
        let flushes = || {
            std::fs::read_to_string(&log)
                .unwrap_or_default()
                .lines()
                .filter(|l| l.contains("\tsync\t") && l.contains("store.redb"))
                .count()
        };
        let t = Instant::now();
        let (mut seen, mut since) = (flushes(), Instant::now());
        while since.elapsed() < QUIET {
            assert!(
                t.elapsed() < Duration::from_secs(60),
                "PRODUCT (staging): alice's daemon kept flushing its store; it never went quiet before kill point {k}"
            );
            std::thread::sleep(Duration::from_millis(200));
            let now = flushes();
            if now != seen {
                (seen, since) = (now, Instant::now());
            }
        }

        // The decision, with the kill point armed.
        std::fs::write(&arm, k.to_string()).expect("APPARATUS: write a staging file");
        let _ = vox(
            &alice,
            &["trust", "add", &bob_fp, "--name", &format!("bob{k}")],
            None,
        );
        let t = Instant::now();
        while alive(&mut alice_daemon) && t.elapsed() < PAST_THE_END {
            std::thread::sleep(Duration::from_millis(50));
        }
        std::fs::remove_file(&arm).expect("APPARATUS: remove a staging file");
        let killed = !alive(&mut alice_daemon);
        if killed {
            kills += 1;
            // Bob's daemon restarts too, and is down while alice's comes back. The session bob's
            // join made is not offered again once the responder restarts: alice's new process
            // offers a hello bob's old one refuses, and after that the pair stays split (measured:
            // "its hello was not accepted", then "no pairwise session for that room" for good).
            // That is V210-78's defect (F-B2), not this one, and it would hide what this reads.
            drop(bob_daemon);
            drop(alice_daemon);
            alice_daemon = daemon(&alice, alice_port, &spec, "alice", &env);
            attached(&alice, "alice");
            bob_daemon = daemon(&bob, bob_port, &spec, "bob", &[]);
            attached(&bob, "bob");
            // Decided again only if the crash lost the decision itself; otherwise the restarted
            // node must act on what it recorded.
            let (ok, list, err) = vox(&alice, &["trust", "list"], None);
            assert!(ok, "PRODUCT (staging): alice's trust list: {err}");
            if !list.lines().any(|l| l.trim_start().starts_with(&bob_fp)) {
                retrusted.push(k);
                let (ok, _, err) = vox(
                    &alice,
                    &["trust", "add", &bob_fp, "--name", &format!("bob{k}")],
                    None,
                );
                assert!(ok, "PRODUCT (staging): alice re-trusts bob{k}: {err}");
            }
        }
        let after = format!("post {k}");
        post(&alice, &room, &after);
        made.push(after.clone());

        // What bob<k> reads: `post <k>` only, and still only that HOLD later.
        let t = Instant::now();
        let mut read: BTreeSet<String> = BTreeSet::new();
        let mut got = None;
        while t.elapsed() < BOUND && got.is_none_or(|g: Instant| g.elapsed() < HOLD) {
            read.extend(texts(&bob, &room));
            if got.is_none() && read.contains(&after) {
                got = Some(Instant::now());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        let before_trust: Vec<&String> = read.iter().filter(|t| **t != after).collect();
        println!(
            "[proof] kill point {k}: alice's daemon {}{}; bob{k} reads {} post(s) made before \
             alice trusted him {before_trust:?}, and `{after}`: {}",
            if killed { "killed" } else { "not reached" },
            if retrusted.contains(&k) {
                ", the trust lost and decided again"
            } else if killed {
                ", the trust kept"
            } else {
                ""
            },
            before_trust.len(),
            got.is_some()
        );
        if !before_trust.is_empty() {
            leaks.push(format!("kill point {k}: bob{k} reads {before_trust:?}"));
        }
        // **The claim**: a crash anywhere in the consent never leaves bob without the key.
        if got.is_none() && killed {
            keyless.push(k);
        }
        assert!(
            got.is_some(),
            "PRODUCT: kill point {k}: bob{k} never read `{after}`, made after alice's restart {}— the \
             restarted node did not deliver the key it had decided to release (alice's daemon {}). \
             His daemon said:\n{}\nalice's said:\n{}\nalice's status:\n{}\nhis status:\n{}",
            if retrusted.contains(&k) {
                "and her re-trust "
            } else {
                "with nothing decided again "
            },
            if killed { "killed" } else { "not killed" },
            std::fs::read_to_string(bob.join("daemon-bob.err")).unwrap_or_default(),
            std::fs::read_to_string(alice.join("daemon-alice.err")).unwrap_or_default(),
            vox(&alice, &["status"], None).1,
            vox(&bob, &["status"], None).1
        );
        drop(bob_daemon);
        if !killed {
            ended_at = Some(k);
            break;
        }
    }
    let mine = texts(&alice, &room);
    let missing: Vec<&String> = made.iter().filter(|t| !mine.contains(*t)).collect();
    let recorded_kills = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.split('\t').nth(2) == Some("kill"))
        .count();
    println!(
        "[proof] {kills} kill point(s) inside a consent, {recorded_kills} recorded kill(s), the sweep \
         ended at {ended_at:?}; the key delivered after {} of {kills}, re-trusted after \
         {retrusted:?}, {} left bob with no key {keyless:?}; {} trial(s) leaked",
        kills - keyless.len() as u64,
        keyless.len(),
        leaks.len()
    );
    assert!(
        missing.is_empty(),
        "PRODUCT: alice does not read her own posts {missing:?}"
    );
    assert!(
        leaks.is_empty(),
        "PRODUCT: a consent cut short released posts sealed before it:\n{}",
        leaks.join("\n")
    );
    assert!(
        ended_at.is_some(),
        "APPARATUS (precondition not met): every one of {MAX_POINTS} kill points fell inside a consent, and bob read the key after each, so the sweep is too short to reach the consent's end"
    );
    assert!(
        kills >= MIN_KILLS,
        "APPARATUS (precondition not met): only {kills} kill point(s) fell inside a consent, and bob read the key after each: too few crashes to measure"
    );
    drop(alice_daemon);
}

/// The held-key arm (see the module doc): a consent to a member whose own key alice already
/// holds, so no key of the member's can arrive after the restart and owe hers again (V210-118).
#[test]
#[ignore = "real vox daemons under the syscall interposer, production Argon2id; CI runs it in release"]
fn a_crash_in_a_consent_whose_member_key_is_held_still_delivers_it() {
    watchdog::arm_for_debug_total(Duration::from_millis(1_270_000), 2);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let root = tmp.path();
    let alice = root.join("alice");
    std::fs::create_dir_all(alice.join("cfg")).expect("APPARATUS: create a staging directory");
    let arm = root.join("kill-arm");
    let log = root.join("alice-interpose.tsv");
    let interposer = syscalls::interposer().to_path_buf();
    let env: Vec<(&str, &Path)> = vec![
        ("DYLD_INSERT_LIBRARIES", &interposer),
        ("VOX_INTERPOSE_LOG", &log),
        ("VOX_INTERPOSE_KILL_ARM", &arm),
    ];

    // ---- the anchor, and alice ---------------------------------------------------------------
    let anchor_dir = root.join("anchor");
    std::fs::create_dir_all(anchor_dir.join("cfg")).expect("APPARATUS: create a staging directory");
    let anchor_port = free_udp_port();
    let anchor_out = anchor_dir.join("node.out");
    let _anchor = Proc(
        command(
            &anchor_dir,
            &["node", "--listen", &format!("127.0.0.1:{anchor_port}")],
        )
        .stdout(Stdio::from(
            std::fs::File::create(&anchor_out).expect("APPARATUS: create a staging file"),
        ))
        .stderr(Stdio::null())
        .spawn()
        .expect("APPARATUS: spawn the anchor"),
    );
    let t0 = Instant::now();
    let spec = loop {
        let out = std::fs::read_to_string(&anchor_out).unwrap_or_default();
        if let Some(l) = out.lines().find(|l| l.contains("@/ip4/127.0.0.1/udp/")) {
            break l.trim().to_owned();
        }
        assert!(
            t0.elapsed() < Duration::from_secs(60),
            "PRODUCT (staging): the anchor printed no spec:\n{out}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let (ok, alice_fp, err) = vox(&alice, &["id"], None);
    assert!(ok, "PRODUCT (staging): vox id: {err}");
    let alice_fp = alice_fp.trim().to_owned();
    let alice_port = free_udp_port();
    let mut alice_daemon = daemon(&alice, alice_port, &spec, "alice", &env);
    attached(&alice, "alice");
    let flushes = || {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .filter(|l| l.contains("\tsync\t") && l.contains("store.redb"))
            .count()
    };
    assert!(
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .any(|l| l.split('\t').nth(2) == Some("open")),
        "APPARATUS: the syscall recorder recorded no `open` by alice's daemon in {}: it is not \
         recording",
        log.display()
    );

    // ---- one trial per kill point ----------------------------------------------------------
    let mut kills = 0u64;
    let mut rejoined: Vec<u64> = Vec::new();
    let mut ended_at = None;
    for k in 1..=MAX_HELD_POINTS {
        // The host: trusts alice, is trusted by her, and makes a room of its own.
        let host: PathBuf = root.join(format!("host{k}"));
        std::fs::create_dir_all(host.join("cfg")).expect("APPARATUS: create a staging directory");
        let (ok, host_fp, err) = vox(&host, &["id"], None);
        assert!(ok, "PRODUCT (staging): vox id: {err}");
        let host_fp = host_fp.trim().to_owned();
        let host_port = free_udp_port();
        let mut host_daemon = daemon(&host, host_port, &spec, "host", &[]);
        attached(&host, "host");
        let (ok, _, err) = vox(&host, &["trust", "add", &alice_fp, "--name", "alice"], None);
        assert!(ok, "PRODUCT (staging): host{k} trusts alice: {err}");
        let (ok, _, err) = vox(
            &alice,
            &["trust", "add", &host_fp, "--name", &format!("host{k}")],
            None,
        );
        assert!(ok, "PRODUCT (staging): alice trusts host{k}: {err}");
        let before: BTreeSet<String> = attached(&host, "host")
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        let (ok, _, err) = vox(
            &host,
            &["room", "create", "--passphrase-file", "-", "--name", "h"],
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(ok, "PRODUCT (staging): host{k}'s room create: {err}");
        let room = attached(&host, "host")
            .split_whitespace()
            .filter(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
            .map(str::to_owned)
            .find(|w| !before.contains(w))
            .expect("PRODUCT (staging): no new room id in the host's `room list`");
        let (ok, link, err) = vox(&host, &["room", "invite", &room], None);
        assert!(ok, "PRODUCT (staging): host{k}'s room invite: {err}");
        let link = link.trim().to_owned();
        let join = |dir: &Path| {
            vox(
                dir,
                &[
                    "room",
                    "join",
                    "--passphrase-file",
                    "-",
                    &link,
                    "--name",
                    &format!("h{k}"),
                ],
                Some(&format!("{ROOMPASS}\n")),
            )
        };

        // A quiet store, then the join with the kill point armed: the host hands alice its key in
        // the join, and her consent to it follows once her copy of the room has synced.
        let t = Instant::now();
        let (mut seen, mut since) = (flushes(), Instant::now());
        while since.elapsed() < QUIET {
            assert!(
                t.elapsed() < Duration::from_secs(60),
                "PRODUCT (staging): alice's daemon kept flushing its store; it never went quiet \
                 before kill point {k}"
            );
            std::thread::sleep(Duration::from_millis(200));
            let now = flushes();
            if now != seen {
                (seen, since) = (now, Instant::now());
            }
        }
        std::fs::write(&arm, k.to_string()).expect("APPARATUS: write a staging file");
        let _ = join(&alice);
        let t = Instant::now();
        while alive(&mut alice_daemon) && t.elapsed() < PAST_THE_END {
            std::thread::sleep(Duration::from_millis(50));
        }
        std::fs::remove_file(&arm).expect("APPARATUS: remove a staging file");
        let killed = !alive(&mut alice_daemon);
        if killed {
            kills += 1;
            // As in the trust arm: the host's daemon is down while alice's comes back (F-B2).
            drop(host_daemon);
            drop(alice_daemon);
            alice_daemon = daemon(&alice, alice_port, &spec, "alice", &env);
            attached(&alice, "alice");
            host_daemon = daemon(&host, host_port, &spec, "host", &[]);
            attached(&host, "host");
            // A join the crash lost is a person's to make again; one that landed stands.
            if !attached(&alice, "alice").contains(&room[..8]) {
                rejoined.push(k);
                let (ok, _, err) = join(&alice);
                assert!(
                    ok,
                    "PRODUCT (staging): alice joins host{k}'s room again: {err}"
                );
            }
        }
        // Posted once her copy of the room may be written to (V210-164).
        let after = format!("post {k}");
        let t = Instant::now();
        loop {
            let (ok, _, err) = vox(&alice, &["room", "post", &room, &after], None);
            if ok {
                break;
            }
            assert!(
                t.elapsed() < Duration::from_secs(60),
                "PRODUCT (staging): alice could not post in host{k}'s room: {err}"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
        let t = Instant::now();
        let mut read = false;
        while t.elapsed() < BOUND && !read {
            read = texts(&host, &room).contains(&after);
            if !read {
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        println!(
            "[proof] held-key kill point {k}: alice's daemon {}{}; host{k} reads `{after}`: {read}",
            if killed { "killed" } else { "not reached" },
            if rejoined.contains(&k) {
                ", the join lost and made again"
            } else if killed {
                ", the join kept"
            } else {
                ""
            }
        );
        assert!(
            read,
            "PRODUCT: held-key kill point {k}: host{k} never read `{after}`, made after alice's \
             restart — the restarted node did not deliver the key it had decided to release, to a \
             member whose own key it already held (alice's daemon {}). Its daemon said:\n{}\n\
             alice's said:\n{}\nalice's status:\n{}\nits status:\n{}",
            if killed { "killed" } else { "not killed" },
            std::fs::read_to_string(host.join("daemon-host.err")).unwrap_or_default(),
            std::fs::read_to_string(alice.join("daemon-alice.err")).unwrap_or_default(),
            vox(&alice, &["status"], None).1,
            vox(&host, &["status"], None).1
        );
        drop(host_daemon);
        if !killed {
            ended_at = Some(k);
            break;
        }
    }
    println!(
        "[proof] held-key arm: {kills} kill point(s) inside the join and its consent, the sweep \
         ended at {ended_at:?}, the join made again after {rejoined:?}"
    );
    assert!(
        ended_at.is_some(),
        "APPARATUS (precondition not met): every one of {MAX_HELD_POINTS} kill points fell inside \
         the join and its consent, so the sweep is too short to reach the consent's end"
    );
    assert!(
        kills >= MIN_KILLS,
        "APPARATUS (precondition not met): only {kills} kill point(s) fell inside the join and its \
         consent: too few crashes to measure"
    );
    drop(alice_daemon);
}
