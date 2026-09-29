//! V210-71 (#262) — **a room with a long governance history is joined promptly**, through the
//! shipped binary.
//!
//! Every consent and every revocation is a governance entry, and a node folds them into its
//! evaluator: who is an admin, which epoch is in force, who may read whom. A joiner's first sync
//! brings the whole governance history at once, and each synced governance entry rebuilt the
//! evaluator from scratch — an O(N^3) causal closure plus a signature check of every entry —
//! under the room's lock. So the joiner's first sync of a room with a few hundred consents took
//! minutes, and its own posts and reads waited behind it. The fix folds a run of governance
//! entries in once, verifies each signature once, and computes the closure in O(N^2).
//!
//! **Staging.** Every node is the real `vox` binary, set up as a person sets it up: an anchor
//! (`vox node`), a host `vox daemon` that creates a room, a member that joins it, and the two
//! trusting each other with `vox trust add`. The host then changes its mind [`CYCLES`] times —
//! `vox trust remove` and `vox trust add` — each of which puts a consent revocation or a consent
//! grant on the room's log. Only then does a newcomer, already trusted by the host, join with
//! `vox room join`.
//!
//! **Asserted.**
//! 1. The history exists: at least [`MIN_ENTRIES`] of the host's trust changes succeeded (each is
//!    one governance entry). Fewer is `CANNOT MEASURE`.
//! 2. After its join returns, the newcomer's `vox room read` shows a post the host made after the
//!    join **within [`READ_BOUND`]** — which needs the newcomer to have synced and folded the
//!    whole governance history (the host's consent to it is the last of it).
//! 3. Meanwhile the newcomer's own `vox room post`, once a second, **each return within
//!    [`POST_BOUND`]**: the room's lock is not held for the fold.
//!
//! **Mutation that must turn it red.** Rebuild the evaluator from scratch for every synced
//! governance entry, with the cubic closure and every signature checked again (revert this fix's
//! `evaluator.rs` and `channel.rs`): the newcomer's first sync then takes tens of seconds to
//! minutes, and its read and its posts wait behind it.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use world::{args, vox_once, VoxProc, IDENTITY, VOX};

/// How many times the host withdraws and restores its trust in the member: two governance
/// entries each.
const CYCLES: usize = 150;
/// Governance entries the history must hold for the measurement to mean anything.
const MIN_ENTRIES: usize = 280;
/// From the newcomer's `vox room join` returning to its read showing the host's post. Measured:
/// 0.25 s with the fix, 8.3 s with the evaluator rebuilt per entry, on a history of 300.
const READ_BOUND: Duration = Duration::from_secs(4);
/// Any one of the newcomer's posts while it catches up. Measured: 68 ms with the fix, 8.3 s with
/// the evaluator rebuilt per entry.
const POST_BOUND: Duration = Duration::from_secs(2);
/// The cap on any one verb, so a stopped node is reported rather than waited on.
const VERB_CAP: Duration = Duration::from_secs(120);
/// How long the read is polled for before the verdict, so a red says how slow it was.
const READ_CAP: Duration = Duration::from_secs(240);
const SETUP: Duration = Duration::from_secs(120);
const ROOM_PASS: &str = "room passphrase";

fn vox_in(data: &Path, argv: &[&str], stdin: &str) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run vox");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("vox finished");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Run a one-shot `vox` verb, killing it (by PID) if it has not finished in `cap`. Returns
/// whether it succeeded, how long it ran, and what it printed.
fn vox_timed(data: &Path, argv: &[&str], cap: Duration) -> (bool, Duration, String) {
    let out_file = data.join(format!("timed-{}.out", std::process::id()));
    let t0 = Instant::now();
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::null())
        .stdout(Stdio::from(std::fs::File::create(&out_file).unwrap()))
        .stderr(Stdio::from(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&out_file)
                .unwrap(),
        ))
        .spawn()
        .expect("run vox");
    let ok = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.success();
        }
        if t0.elapsed() >= cap {
            let _ = child.kill();
            let _ = child.wait();
            break false;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let took = t0.elapsed();
    (
        ok,
        took,
        std::fs::read_to_string(&out_file).unwrap_or_default(),
    )
}

fn daemon(name: &str, data: &Path, spec: &str, pass_file: &Path) -> VoxProc {
    let p = VoxProc::spawn(
        name,
        data,
        &args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--anchor",
            spec,
            "--passphrase-file",
            pass_file.to_str().unwrap(),
        ]),
    );
    let deadline = Instant::now() + SETUP;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("CANNOT MEASURE: {name}'s daemon never answered `vox room list`");
}

fn fingerprint(data: &Path) -> String {
    let (ok, out, err) = vox_once(data, &args(&["id"]));
    assert!(ok, "CANNOT MEASURE: vox id: {err}");
    out.trim().to_owned()
}

fn trust(data: &Path, verb: &str, fp: &str, name: &str) -> bool {
    let mut argv = vec!["trust", verb, fp];
    if verb == "add" {
        argv.extend(["--name", name]);
    }
    vox_once(data, &args(&argv)).0
}

#[test]
#[ignore = "real vox processes, production Argon2id and hundreds of trust changes; run in release"]
fn a_room_with_hundreds_of_consents_is_joined_promptly() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, host_dir, member_dir, newcomer_dir) =
        (dir("anchor"), dir("host"), dir("member"), dir("newcomer"));
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).unwrap();

    // ---- staging, all through the shipped binary ----------------------------------------
    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("the anchor's spec", |l| l.contains("@/ip4/127.0.0.1/udp/"))
        .split_whitespace()
        .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        .unwrap()
        .to_owned();
    let host_fp = fingerprint(&host_dir);
    let member_fp = fingerprint(&member_dir);
    let newcomer_fp = fingerprint(&newcomer_dir);
    let _host = daemon("host", &host_dir, &spec, &pass_file);
    let _member = daemon("member", &member_dir, &spec, &pass_file);

    let (ok, out, err) = vox_in(&host_dir, &["room", "create", "--name", "team"], ROOM_PASS);
    assert!(ok, "CANNOT MEASURE: room create: {out}\n{err}");
    let (_, list, _) = vox_once(&host_dir, &args(&["room", "list"]));
    let prefix = list
        .split_whitespace()
        .next()
        .expect("CANNOT MEASURE: the new room in `vox room list`")
        .to_owned();
    let (ok, link, err) = vox_once(&host_dir, &args(&["room", "invite", &prefix]));
    assert!(ok, "CANNOT MEASURE: room invite: {err}");
    let link = link.trim().to_owned();
    let join = |data: &Path, who: &str| {
        (1..=6).any(|attempt| {
            let (ok, out, err) =
                vox_in(data, &["room", "join", &link, "--name", "team"], ROOM_PASS);
            if !ok {
                eprintln!("[proof] {who}'s join attempt {attempt} refused: {out} {err}");
                std::thread::sleep(Duration::from_secs(5));
            }
            ok
        })
    };
    assert!(
        join(&member_dir, "member"),
        "CANNOT MEASURE: the member could not join"
    );
    assert!(
        trust(&member_dir, "add", &host_fp, "host"),
        "CANNOT MEASURE: the member could not trust the host"
    );
    assert!(
        trust(&host_dir, "add", &member_fp, "member"),
        "CANNOT MEASURE: the host could not trust the member"
    );
    let (ok, _, err) = vox_once(&host_dir, &args(&["room", "post", &prefix, "hello"]));
    assert!(ok, "CANNOT MEASURE: first post: {err}");
    let (_, rows, _) = vox_once(&host_dir, &args(&["room", "read", &prefix, "--json"]));
    let room = rows
        .lines()
        .find_map(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .ok()?
                .get("room")?
                .as_str()
                .map(str::to_owned)
        })
        .expect("CANNOT MEASURE: the host's read names its room");

    // ---- the governance history: the host changes its mind, again and again -------------
    let t_hist = Instant::now();
    let mut entries = 0usize;
    for i in 1..=CYCLES {
        if trust(&host_dir, "remove", &member_fp, "member") {
            entries += 1;
        } else {
            eprintln!("[proof] cycle {i}: trust remove refused");
        }
        if trust(&host_dir, "add", &member_fp, "member") {
            entries += 1;
        } else {
            eprintln!("[proof] cycle {i}: trust add refused");
        }
    }
    println!(
        "[proof] history: {entries} trust changes by the host in {:?}",
        t_hist.elapsed()
    );
    assert!(
        entries >= MIN_ENTRIES,
        "CANNOT MEASURE: only {entries} of {} trust changes succeeded (need {MIN_ENTRIES})",
        CYCLES * 2
    );

    // ---- the newcomer, trusted by the host before it joins ------------------------------
    assert!(
        trust(&host_dir, "add", &newcomer_fp, "newcomer"),
        "CANNOT MEASURE: the host could not trust the newcomer"
    );
    let _newcomer = daemon("newcomer", &newcomer_dir, &spec, &pass_file);
    let t_join = Instant::now();
    assert!(
        join(&newcomer_dir, "newcomer"),
        "CANNOT MEASURE: the newcomer could not join"
    );
    let joined = Instant::now();
    println!(
        "[proof] the newcomer's join returned in {:?}",
        t_join.elapsed()
    );
    let marker = "posted by the host after the newcomer joined";
    let (ok, _, err) = vox_once(&host_dir, &args(&["room", "post", &room, marker]));
    assert!(ok, "CANNOT MEASURE: the host's post after the join: {err}");

    let mut posts: Vec<Duration> = Vec::new();
    let mut last_post = Instant::now() - Duration::from_secs(1);
    let read_at = loop {
        if last_post.elapsed() >= Duration::from_secs(1) {
            last_post = Instant::now();
            let text = format!("the newcomer catching up {}", posts.len() + 1);
            let (ok, t, said) = vox_timed(&newcomer_dir, &["room", "post", &room, &text], VERB_CAP);
            println!(
                "[proof] newcomer post {}: ok={ok} in {t:?} at +{:?}",
                posts.len() + 1,
                joined.elapsed()
            );
            assert!(ok, "the newcomer's post failed after {t:?}: {said}");
            posts.push(t);
        }
        let (ok, _, read) = vox_timed(&newcomer_dir, &["room", "read", &room], VERB_CAP);
        if ok && read.contains(marker) {
            break joined.elapsed();
        }
        assert!(
            t_join.elapsed() < READ_CAP,
            "the newcomer never read the host's post in {READ_CAP:?} after joining a room of \
             {entries} consents and revocations"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let slowest = posts.iter().max().copied().unwrap_or_default();
    println!(
        "[proof] {entries} governance entries: the newcomer read the host {read_at:?} after \
         its join returned; {} posts meanwhile, slowest {slowest:?}",
        posts.len()
    );
    assert!(
        read_at < READ_BOUND,
        "the newcomer read the host's post {read_at:?} after its join returned (bound {READ_BOUND:?}) in a room \
         of {entries} consents and revocations: its first sync folds the governance too slowly"
    );
    assert!(
        slowest < POST_BOUND,
        "a newcomer post took {slowest:?} (bound {POST_BOUND:?}) while it caught up on {entries} \
         governance entries: the room's lock is held for the fold"
    );
}
