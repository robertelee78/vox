//! V210-68 (#258) — **a node that goes quiet stays findable on its anchor's board**, through the
//! shipped binary.
//!
//! A node's address record lives two hours on a board, and nothing renewed it on a schedule: a
//! publish round went out only when something happened. Until #179 one also went out after every
//! sync that brought messages, which renewed the record by accident; an idle room lost it after
//! two hours either way, and after #179 so did a room that only carried messages. Then a joiner,
//! or a member restarting, that finds this node through the board found nothing.
//!
//! Every process here runs with `VOX_TEST_RECORD_TTL_SECS` = [`TTL`] (test-only, lower-only: a
//! shorter record lifetime, and the board's refresh floor scaled with it), so several lifetimes
//! pass in under a minute:
//!
//! 1. Alice creates a room behind a real `vox node` anchor; Bob joins.
//! 2. Nobody does anything for [`LIFETIMES`] lifetimes.
//! 3. Carol joins with an address that names **only the anchor**: Alice's own endpoint is taken
//!    out of it, so the only way to reach anyone in the room is the records the anchor's board
//!    still holds. She must get in.
//!
//! And while everyone was idle, Alice's node renewed, and not in a storm: its publish rounds
//! (`vox status --json`) are at least one per lifetime and at most two per half-lifetime.
//!
//! Carol's daemon names each step of her join; the board must have held a member's address when
//! she asked (no `address poll`: she did not have to wait for anyone to publish again).
//!
//! Mutation: no scheduled renewal. The records lapse; Carol's join polls the board for about
//! twenty seconds until a member's own traffic brings one back, and Alice's rounds fall to 0–1.

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use world::{args, vox_once, VoxProc, IDENTITY, VOX};

/// The record lifetime every process runs with, in seconds.
const TTL: u64 = 16;
/// How many lifetimes everyone stays idle before Carol joins.
const LIFETIMES: u64 = 3;
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
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("{name}'s daemon never answered `vox room list`");
}

/// A node's publish rounds so far (`vox status --json`).
fn rounds(data: &Path) -> u64 {
    let (ok, out, err) = vox_once(data, &args(&["status", "--json"]));
    assert!(ok, "vox status --json: {err}");
    let v: serde_json::Value = serde_json::from_str(out.trim()).expect("status is JSON");
    v["publish"]["rounds"]
        .as_u64()
        .unwrap_or_else(|| panic!("CANNOT MEASURE: status has no publish.rounds: {out}"))
}

/// `address` without the `a=<who>&b=<endpoint>` pair naming `who`: what is left names the anchor.
fn without_endpoint_of(address: &str, who: &str) -> String {
    let (head, query) = address.split_once('?').expect("an address with a query");
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

#[test]
#[ignore = "real vox processes with production Argon2id, idle for several record lifetimes; CI runs it in release"]
fn an_idle_node_stays_findable_on_its_board() {
    watchdog::arm();
    // Every process this proof starts inherits it: the nodes give their records this lifetime,
    // and the anchor's board scales its refresh floor with it.
    std::env::set_var(vox_core::nat::store::TEST_RECORD_TTL_ENV, TTL.to_string());
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, alice_dir, bob_dir, carol_dir) =
        (dir("anchor"), dir("alice"), dir("bob"), dir("carol"));
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).unwrap();

    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("an --anchor spec", |l| {
            l.trim_start().contains("@/ip4/127.0.0.1/udp/")
        })
        .trim()
        .to_owned();
    let fp = |d: &Path| {
        let (ok, out, err) = vox_once(d, &args(&["id"]));
        assert!(ok, "vox id: {err}");
        out.trim().to_owned()
    };
    let alice_fp = fp(&alice_dir);
    fp(&bob_dir);
    fp(&carol_dir);

    let _alice = daemon("alice", &alice_dir, &spec, &idpass);
    let _bob = daemon("bob", &bob_dir, &spec, &idpass);
    let (ok, out, err) = vox_in(
        &alice_dir,
        &["room", "create", "--name", "quiet"],
        "room pass",
    );
    assert!(ok, "vox room create: {out}{err}");
    let (ok, list, err) = vox_once(&alice_dir, &args(&["room", "list"]));
    assert!(ok, "vox room list: {err}");
    let room = list
        .lines()
        .find(|l| l.contains("quiet"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("room not listed: {list}"))
        .to_owned();
    let (ok, link, err) = vox_once(&alice_dir, &args(&["room", "invite", &room]));
    assert!(ok, "vox room invite: {err}");
    let link = link.trim().to_owned();
    let (ok, out, err) = vox_in(
        &bob_dir,
        &["room", "join", &link, "--name", "quiet"],
        "room pass",
    );
    assert!(ok, "bob joins: {out}{err}");

    // ---- nobody does anything for several lifetimes -----------------------------------------
    let before = rounds(&alice_dir);
    let idle = Duration::from_secs(TTL * LIFETIMES);
    std::thread::sleep(idle);
    let renewed = rounds(&alice_dir).saturating_sub(before);

    // ---- Carol, who has only the anchor ----------------------------------------------------
    let anchor_only = without_endpoint_of(&link, &alice_fp);
    assert!(
        !anchor_only.contains(&format!("a={alice_fp}&b=")),
        "CANNOT MEASURE: Alice's endpoint is still in the address: {anchor_only}"
    );
    let carol = daemon("carol", &carol_dir, &spec, &idpass);
    let t = Instant::now();
    let (joined, out, err) = vox_in(
        &carol_dir,
        &["room", "join", &anchor_only, "--name", "quiet"],
        "room pass",
    );
    let took = t.elapsed();
    // Her daemon's own account of the join: `vox: join got in — board …, fetch …, <responder>:
    // …`. A responder whose address the board no longer holds shows up as `address poll ×N`: the
    // join waited for the responder to publish again, which is the lapse, however it ended.
    let said = carol.said_since(t);
    for l in &said {
        println!("[carol] {l}");
    }
    let steps = said
        .iter()
        .find_map(|l| l.split("vox: join got in — ").nth(1))
        .map(str::to_owned);
    println!(
        "[proof] idle {}s ({LIFETIMES} lifetimes of {TTL}s): alice's node renewed with {renewed} \
         publish round(s); carol, with only the anchor's address, joined = {joined} in {:.1?}",
        idle.as_secs(),
        took
    );
    assert!(
        joined,
        "a node idle for {LIFETIMES} record lifetimes was not findable on its anchor's board: \
         {out}{err}"
    );
    let steps = steps.unwrap_or_else(|| {
        panic!("CANNOT MEASURE: carol's daemon printed no `join got in` line: {said:#?}")
    });
    assert!(
        !steps.contains("address poll"),
        "after {LIFETIMES} idle lifetimes the anchor's board no longer held a member's address: \
         carol's join had to wait for one — {steps}"
    );
    // At half the lifetime to one anchor: about two rounds a lifetime. At least one a lifetime,
    // or the records would have lapsed; at most twice the schedule, or it is a storm.
    let (least, most) = (LIFETIMES, 4 * LIFETIMES);
    assert!(
        (least..=most).contains(&renewed),
        "alice's node renewed with {renewed} publish rounds over {LIFETIMES} idle lifetimes; \
         expected {least}..={most}"
    );
    drop(anchor);
}
