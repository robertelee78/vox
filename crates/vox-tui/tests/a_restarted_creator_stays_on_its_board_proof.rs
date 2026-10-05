//! **A room's creator stays on its anchor's board after its daemon restarts** (v0.3.0), through
//! the shipped binary.
//!
//! A room this node created keeps no admission segment: its admission is the genesis, which names
//! it. A reopened room loaded its admission from that segment alone, so after a restart the
//! creator's room had none, and every publish round for it returned before it sent anything: no
//! member bundle and no address record, to any board, ever again. Once the records it had put up
//! before the restart lapsed, nobody could find the creator through its anchor.
//!
//! Every process runs with `VOX_TEST_RECORD_TTL_SECS` = [`TTL`] (test-only, lower-only), so a
//! record lapses in seconds:
//!
//! 1. Alice creates a room behind a real `vox node` anchor. She is its only member.
//! 2. Her daemon is stopped (SIGINT, by its pid) and started again with the identity passphrase
//!    alone, which reopens the room (#208).
//! 3. [`LIFETIMES`] record lifetimes pass, so what she published before the restart has lapsed.
//! 4. Carol joins with an address that names **only the anchor** (Alice's own endpoint taken out),
//!    so the only way to Alice is the records the anchor's board holds now. She must get in, and
//!    her daemon's account of the join must show no `address poll` (no waiting for an address).
//!
//! **Which side a red is on.** Carol not getting in, or getting in only after polling for an
//! address, is `PRODUCT:`; a staging step that fails is `PRODUCT (staging)`; the proof's own I/O is
//! `APPARATUS:`.
//!
//! Mutation: the reopened creator's admission left unset (the defect) -> red, Carol cannot find
//! Alice.

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/test_knobs.rs"]
mod test_knobs;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use world::{args, vox_once, VoxProc, IDENTITY, VOX};

/// The record lifetime every process runs with, in seconds.
const TTL: u64 = 16;
/// How many lifetimes pass after the restart before Carol joins.
const LIFETIMES: u64 = 2;
const TIMEOUT: Duration = Duration::from_secs(90);

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
        .expect("APPARATUS: run vox");
    child
        .stdin
        .take()
        .expect("APPARATUS: a piped stdio handle")
        .write_all(stdin.as_bytes())
        .expect("PRODUCT (staging): vox exited without reading its stdin");
    let out = child.wait_with_output().expect("APPARATUS: vox finished");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A `vox daemon` whose records live `ttl` seconds (given to this process alone, never through the
/// test's own environment, which both arms share).
fn daemon(name: &str, data: &Path, spec: &str, pass_file: &Path, ttl: &str) -> VoxProc {
    let p = VoxProc::spawn_env(
        name,
        data,
        &args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--anchor",
            spec,
            "--passphrase-file",
            pass_file
                .to_str()
                .expect("APPARATUS: a path that is not UTF-8"),
        ]),
        &[("VOX_TEST_RECORD_TTL_SECS", ttl)],
    );
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("PRODUCT (staging): {name}'s daemon never answered `vox room list`");
}

/// `address` without the `a=<who>&b=<endpoint>` pair naming `who`: what is left names the anchor.
fn without_endpoint_of(address: &str, who: &str) -> String {
    let (head, query) = address
        .split_once('?')
        .expect("PRODUCT: an address with a query");
    let parts: Vec<&str> = query.split('&').collect();
    let mut kept = Vec::new();
    let mut i = 0;
    while i < parts.len() {
        if parts[i] == format!("a={who}") && parts.get(i + 1).is_some_and(|p| p.starts_with("b=")) {
            i += 2;
            continue;
        }
        kept.push(parts[i]);
        i += 1;
    }
    format!("{head}?{}", kept.join("&"))
}

/// A `vox node` anchor listening on `port` (0: its own choice, read back from its spec — #410), and
/// its `--anchor` spec. A restart on a port another program took meanwhile reads as APPARATUS
/// (`VoxProc::expect_line`).
fn anchor_on(name: &str, data: &Path, port: u16, ttl: &str) -> (VoxProc, String) {
    let mut p = VoxProc::spawn_env(
        name,
        data,
        &args(&["node", "--listen", &format!("127.0.0.1:{port}")]),
        &[("VOX_TEST_RECORD_TTL_SECS", ttl)],
    );
    let spec = p
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();
    (p, spec)
}

/// Stop `p` as a person does (SIGINT: it closes its connections, so its peers learn at once).
fn stop(mut p: VoxProc) {
    let pid = p.child.id().to_string();
    let _ = Command::new("kill").args(["-INT", &pid]).status();
    let deadline = Instant::now() + Duration::from_secs(10);
    while p.child.try_wait().ok().flatten().is_none() {
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): anchor {pid} did not stop within 10 s of SIGINT"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
#[ignore = "real vox processes with production Argon2id, idle past a record lifetime; run in release"]
fn a_restarted_creator_stays_findable_on_its_board() {
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_RECORD_TTL_SECS"]);
    let ttl_s = TTL.to_string();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a staging directory");
        d
    };
    let (anchor_dir, alice_dir, carol_dir) = (dir("anchor"), dir("alice"), dir("carol"));
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).expect("APPARATUS: write a staging file");
    let (anchor, spec) = anchor_on("anchor", &anchor_dir, 0, &ttl_s);
    let fp = |d: &Path| {
        let (ok, out, err) = vox_once(d, &args(&["id"]));
        assert!(ok, "PRODUCT (staging): vox id: {err}");
        out.trim().to_owned()
    };
    let alice_fp = fp(&alice_dir);
    fp(&carol_dir);

    // ---- 1. alice creates the room -----------------------------------------------------------
    let alice = daemon("alice", &alice_dir, &spec, &idpass, &ttl_s);
    let (ok, out, err) = vox_in(
        &alice_dir,
        &["room", "create", "--passphrase-file", "-", "--name", "kept"],
        "room pass",
    );
    assert!(ok, "PRODUCT (staging): vox room create: {out}{err}");
    let (ok, list, err) = vox_once(&alice_dir, &args(&["room", "list"]));
    assert!(ok, "PRODUCT (staging): vox room list: {err}");
    let room = list
        .lines()
        .find(|l| l.contains("kept"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("PRODUCT: room not listed: {list}"))
        .to_owned();
    let (ok, link, err) = vox_once(&alice_dir, &args(&["room", "link", &room]));
    assert!(ok, "PRODUCT (staging): vox room link: {err}");
    let link = link.trim().to_owned();

    // ---- 2. alice's daemon restarts; the room reopens -----------------------------------------
    stop(alice);
    let _alice = daemon("alice (restarted)", &alice_dir, &spec, &idpass, &ttl_s);
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let (ok, out, _) = vox_once(&alice_dir, &args(&["room", "read", &room]));
        if ok {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): alice's restarted daemon never reopened the room: {out}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let restarted = Instant::now();

    // ---- 3. what she published before the restart lapses --------------------------------------
    std::thread::sleep(Duration::from_secs(TTL * LIFETIMES));

    // ---- 4. carol, who has only the anchor -----------------------------------------------------
    let anchor_only = without_endpoint_of(&link, &alice_fp);
    assert!(
        !anchor_only.contains(&format!("a={alice_fp}&b=")),
        "APPARATUS: Alice's endpoint is still in the address: {anchor_only}"
    );
    let carol = daemon("carol", &carol_dir, &spec, &idpass, &ttl_s);
    let t = Instant::now();
    let (joined, out, err) = vox_in(
        &carol_dir,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            &anchor_only,
            "--name",
            "kept",
        ],
        "room pass",
    );
    let took = t.elapsed();
    let said = carol.said_since(t);
    for l in &said {
        println!("[carol] {l}");
    }
    let steps = said
        .iter()
        .find_map(|l| l.split("vox: join got in — ").nth(1))
        .map(str::to_owned);
    println!(
        "[proof] {}s after alice's restart ({LIFETIMES} lifetimes of {TTL}s): carol, with only \
         the anchor's address, joined = {joined} in {took:.1?}; steps: {steps:?}",
        restarted.elapsed().as_secs() - took.as_secs()
    );
    assert!(
        joined,
        "PRODUCT: the room's creator was not findable on its anchor's board {LIFETIMES} record \
         lifetimes after its daemon restarted: {out}{err}"
    );
    let steps = steps.unwrap_or_else(|| {
        panic!("PRODUCT (staging): carol's daemon printed no `join got in` line: {said:#?}")
    });
    assert!(
        !steps.contains("address poll"),
        "PRODUCT: after the creator's restart the anchor's board held no address of hers: \
         carol's join had to wait for one — {steps}"
    );
    drop(carol);
    drop(anchor);
}
