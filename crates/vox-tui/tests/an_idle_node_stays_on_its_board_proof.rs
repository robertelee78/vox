//! V210-68 (#258) — **a node that goes quiet stays findable on its anchor's board**, through the
//! shipped binary.
//!
//! A node's address record lives two hours on a board, and nothing renewed it on a schedule: a
//! publish round went out only when something happened. Until #179 one also went out after every
//! sync that brought messages, which renewed the record by accident; an idle room lost it after
//! two hours either way, and after #179 so did a room that only carried messages. Then a joiner,
//! or a member restarting, that finds this node through the board found nothing.
//!
//! Every process here runs with `VOX_TEST_RECORD_TTL_SECS` = [`TTL`] ([`CHURN_TTL`] in the second
//! arm) (test-only, lower-only: a
//! shorter record lifetime, and the board's refresh floor scaled with it), so several lifetimes
//! pass in under a minute:
//!
//! 1. Alice creates a room behind a real `vox node` anchor; Bob joins.
//! 2. Nobody does anything for [`LIFETIMES`] lifetimes.
//! 3. Carol joins with an address that names **only the anchor**: Alice's own endpoint is taken
//!    out of it, so the only way to reach anyone in the room is the records the anchor's board
//!    still holds. She must get in.
//!
//! And while everyone was idle, Alice's node renewed, and not in a storm: its scheduled renewals
//! (`publish.renewals` in `vox status --json`, one per room per half-lifetime, whatever the number
//! of boards each reaches) are at least one per lifetime and at most two per half-lifetime. Its
//! publish rounds, one per board reached, are printed too: with two anchors, one of them coming
//! back every few seconds, they count every renewal twice and every return of B once more, so
//! they are not what the design bounds.
//!
//! Carol's daemon names each step of her join; the board must have held a member's address when
//! she asked (no `address poll`: she did not have to wait for anyone to publish again).
//!
//! Mutation: no scheduled renewal. The records lapse; Carol's join polls the board for about
//! twenty seconds until a member's own traffic brings one back, and Alice's rounds fall to 0–1.
//!
//! **A round to one anchor does not put off the others'** ([`a_round_to_one_anchor_does_not_put_off_the_others`]).
//! The renewal is one deadline per room. A round to a single anchor (it reconnected, it asked
//! again, it learned news) signs the records too, and it used to re-arm that deadline, so an anchor
//! that reconnected more often than every half-lifetime kept the room's renewal from ever coming
//! due: its own board and every other anchor lapsed. The second arm runs the same scene with a
//! second anchor, B, which is stopped and started again every few seconds while everyone is idle,
//! and Carol joins through the first, A, alone.
//!
//! Mutation: the renewal re-armed by a round to one anchor, and the second arm's Carol polls A's
//! board; the first arm stays green, which is why the second exists.

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
/// The record lifetime in the second arm: a returning anchor is reached again only every few
/// seconds (up to 10 s apart, measured), and the rounds to it must come closer than half of this.
const CHURN_TTL: u64 = 32;
/// How many lifetimes everyone stays idle before Carol joins.
const LIFETIMES: u64 = 3;
const TIMEOUT: Duration = Duration::from_secs(90);
/// How often anchor B restarts in the second arm: well inside half of [`CHURN_TTL`]. Faster than
/// this, the node backs off its redial and reaches B less often, not more.
const CHURN: Duration = Duration::from_secs(4);

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
            pass_file.to_str().unwrap(),
        ]),
        &[(vox_core::nat::store::TEST_RECORD_TTL_ENV, ttl)],
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

/// A node's publish counters at one instant (`vox status --json`): its renewals, its rounds, and
/// its rounds by cause. **One read for all three**: read apart, a round landing between two reads
/// is in one count and not the other.
struct Publish {
    renewals: u64,
    rounds: u64,
    by_cause: std::collections::BTreeMap<String, u64>,
}

fn publish(data: &Path) -> Publish {
    let (ok, out, err) = vox_once(data, &args(&["status", "--json"]));
    assert!(ok, "vox status --json: {err}");
    let v: serde_json::Value = serde_json::from_str(out.trim()).expect("status is JSON");
    let p = &v["publish"];
    let n = |what: &str| {
        p[what]
            .as_u64()
            .unwrap_or_else(|| panic!("CANNOT MEASURE: status has no publish.{what}: {out}"))
    };
    Publish {
        renewals: n("renewals"),
        rounds: n("rounds"),
        by_cause: p["by_cause"]
            .as_object()
            .unwrap_or_else(|| panic!("CANNOT MEASURE: status has no publish.by_cause: {out}"))
            .iter()
            .map(|(k, n)| (k.clone(), n.as_u64().unwrap_or(0)))
            .collect(),
    }
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
    idle_then_join(false);
}

#[test]
#[ignore = "real vox processes with production Argon2id, idle for several record lifetimes; CI runs it in release"]
fn a_round_to_one_anchor_does_not_put_off_the_others() {
    idle_then_join(true);
}

/// A free loopback UDP port, for an anchor that must come back where it was.
fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A `vox node` anchor listening on `port`, and its `--anchor` spec.
fn anchor_on(name: &str, data: &Path, port: u16, ttl: &str) -> (VoxProc, String) {
    let mut p = VoxProc::spawn_env(
        name,
        data,
        &args(&["node", "--listen", &format!("127.0.0.1:{port}")]),
        &[(vox_core::nat::store::TEST_RECORD_TTL_ENV, ttl)],
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
            "CANNOT MEASURE: anchor {pid} did not stop within 10 s of SIGINT"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The scene in the header; with `churn`, anchor B restarts all through the idle time.
fn idle_then_join(churn: bool) {
    watchdog::arm();
    // Every node this arm starts is given it: the nodes give their records this lifetime, and the
    // anchor's board scales its refresh floor with it. **Per process, never `set_var`**: both
    // arms run in one test process, and a process-wide variable let one arm's lifetime decide the
    // other's (found by V210-68's verifier).
    let ttl = if churn { CHURN_TTL } else { TTL };
    let ttl_s = ttl.to_string();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, second_dir, alice_dir, bob_dir, carol_dir) = (
        dir("anchor"),
        dir("second"),
        dir("alice"),
        dir("bob"),
        dir("carol"),
    );
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).unwrap();

    let (anchor, spec) = anchor_on("anchor", &anchor_dir, free_port(), &ttl_s);
    // Anchor B, only with `churn`: on a port it can come back to.
    let second_port = free_port();
    let mut second = churn.then(|| anchor_on("second", &second_dir, second_port, &ttl_s));
    let anchors = match &second {
        Some((_, b)) => format!("{spec},{}", b),
        None => spec.clone(),
    };
    let fp = |d: &Path| {
        let (ok, out, err) = vox_once(d, &args(&["id"]));
        assert!(ok, "vox id: {err}");
        out.trim().to_owned()
    };
    let alice_fp = fp(&alice_dir);
    fp(&bob_dir);
    fp(&carol_dir);

    let alice = daemon("alice", &alice_dir, &anchors, &idpass, &ttl_s);
    let _bob = daemon("bob", &bob_dir, &anchors, &idpass, &ttl_s);
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
    let alice_before = publish(&alice_dir);
    // Bob's renewals too: a board passes on another member's record only when it changed.
    let bob_before = publish(&bob_dir).renewals;
    let idle = Duration::from_secs(ttl * LIFETIMES);
    let idle_from = Instant::now();
    let mut restarts = 0u32;
    match second.take() {
        // B goes away and comes back every few seconds, well inside a half-lifetime: each return
        // is a round to B alone.
        Some((mut b, b_spec)) => {
            while idle_from.elapsed() + CHURN < idle {
                std::thread::sleep(CHURN);
                stop(b);
                b = anchor_on("second", &second_dir, second_port, &ttl_s).0;
                restarts += 1;
            }
            std::thread::sleep(idle.saturating_sub(idle_from.elapsed()));
            second = Some((b, b_spec));
        }
        None => std::thread::sleep(idle),
    }
    let alice_after = publish(&alice_dir);
    let renewed = alice_after.renewals.saturating_sub(alice_before.renewals);
    let rounds = alice_after.rounds.saturating_sub(alice_before.rounds);
    // What asked for each round while everyone was idle.
    let causes: std::collections::BTreeMap<String, u64> = alice_after
        .by_cause
        .into_iter()
        .map(|(k, n)| {
            let was = alice_before.by_cause.get(&k).copied().unwrap_or(0);
            (k, n.saturating_sub(was))
        })
        .filter(|(_, n)| *n > 0)
        .collect();
    let bob_renewed = publish(&bob_dir).renewals.saturating_sub(bob_before);
    println!(
        "[proof] alice's publish rounds while idle, by cause: {causes:?}; bob renewed \
         {bob_renewed} time(s)"
    );
    assert_eq!(
        causes.values().sum::<u64>(),
        rounds,
        "CANNOT MEASURE: alice's rounds by cause {causes:?} do not add up to her {rounds} rounds"
    );

    // ---- Carol, who has only the anchor ----------------------------------------------------
    let mut anchor_only = without_endpoint_of(&link, &alice_fp);
    // Rounds to B alone, one per return: printed beside the rounds they add to.
    let mut reconnects = 0u64;
    if let Some((_, b_spec)) = &second {
        // Through A alone: B's pair goes too.
        let b_fp = b_spec.split('@').next().unwrap();
        anchor_only = without_endpoint_of(&anchor_only, b_fp);
        assert!(
            !anchor_only.contains(b_fp),
            "CANNOT MEASURE: anchor B is still in the address: {anchor_only}"
        );
        // B came back as often as asked, and Alice reached it again each time: otherwise there
        // were no rounds to B alone to put anything off.
        // Each return's time, from the `[+12.345s]` alice's own line carries.
        let back: Vec<f64> = alice
            .said_since(idle_from)
            .iter()
            .filter(|l| {
                // A daemon names a peer by the first 26 characters of its id.
                l.contains(&format!("connection to {}", &b_fp[..26]))
                    && l.contains("connected to this anchor")
            })
            .filter_map(|l| l.strip_prefix("[+")?.split('s').next()?.parse().ok())
            .collect();
        let reached = back.len();
        reconnects = reached as u64;
        // Rounds to B alone put the renewal off only if none is more than half a lifetime after
        // the last (or after the idle time began): past that, the renewal was due and went out.
        let widest = std::iter::once(0.0)
            .chain(back.iter().copied())
            .collect::<Vec<f64>>()
            .windows(2)
            .map(|w| w[1] - w[0])
            .fold(0.0_f64, f64::max);
        println!(
            "[proof] anchor B restarted {restarts} time(s); alice reconnected to it {reached} \
             time(s), at most {widest:.1}s apart"
        );
        assert!(
            reached >= 8 && widest < (ttl / 2) as f64,
            "CANNOT MEASURE: alice reached anchor B {reached} time(s) while idle, at most \
             {widest:.1}s apart; the arm needs rounds to B alone closer than half a lifetime"
        );
    }
    assert!(
        !anchor_only.contains(&format!("a={alice_fp}&b=")),
        "CANNOT MEASURE: Alice's endpoint is still in the address: {anchor_only}"
    );
    let carol = daemon("carol", &carol_dir, &spec, &idpass, &ttl_s);
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
        "[proof] idle {}s ({LIFETIMES} lifetimes of {ttl}s): alice's node renewed {renewed} \
         time(s), in {rounds} publish round(s) to boards ({reconnects} return(s) of anchor B); \
         carol, with only the anchor's address, joined = {joined} in {:.1?}",
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
    // One renewal per room per half-lifetime, however many boards it reaches: two a lifetime,
    // give or take one for where the idle window falls against the schedule. Fewer is a node
    // renewing late (or at a longer lifetime than it was given); more is a storm.
    let (least, most) = (2 * LIFETIMES - 1, 2 * LIFETIMES + 1);
    assert!(
        (least..=most).contains(&renewed),
        "alice's node renewed its records {renewed} times over {LIFETIMES} idle lifetimes; \
         expected {least}..={most}"
    );
    // **Every round has a cause, and each cause is bounded by the design** (V210-68). While
    // everyone is idle a round goes out only for one of three reasons:
    // - a renewal, to each anchor connected at that moment: between one and `anchors` per renewal;
    // - an anchor that came back empty (`anchor_returned`): at most one per return of B;
    // - news a board passed on (`board_news`): another member's record that changed, which only
    //   bob's renewals can bring here, to each anchor.
    // Anything else (a retry, a round queued behind one in flight, governance, a join) is work
    // the idle room did not ask for.
    let anchors_n: u64 = if churn { 2 } else { 1 };
    let count = |cause: &str| causes.get(cause).copied().unwrap_or(0);
    let unasked: Vec<(&String, &u64)> = causes
        .iter()
        .filter(|(c, _)| !["renewal", "anchor_returned", "board_news"].contains(&c.as_str()))
        .collect();
    assert!(
        unasked.is_empty(),
        "alice's node published while idle for causes the idle room did not ask for: \
         {unasked:?} (all: {causes:?})"
    );
    assert!(
        (renewed..=renewed * anchors_n).contains(&count("renewal")),
        "alice's renewal rounds {} are not one to {anchors_n} per renewal ({renewed} renewals)",
        count("renewal")
    );
    assert!(
        count("anchor_returned") <= reconnects,
        "alice's rounds to a returned anchor {} exceed anchor B's {reconnects} return(s)",
        count("anchor_returned")
    );
    assert!(
        count("board_news") <= bob_renewed * anchors_n,
        "alice passed on {} rounds of news while bob renewed only {bob_renewed} time(s) \
         ({anchors_n} anchor(s))",
        count("board_news")
    );
    drop(second);
    drop(anchor);
}
