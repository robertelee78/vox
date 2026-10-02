//! V210-43 (#217) — **a member that has just joined is never refused by its anchor as a stranger**,
//! through the shipped binary.
//!
//! **The defect.** A member that had just joined synced with the room's anchor before the anchor
//! knew it as a member. The anchor held only its pre-join record — the bundle that admits it, which
//! the joiner publishes and the member that let it in mirrors, had not landed — so the gate classed
//! it a pending joiner, which may not open a sync, and refused with the uninformative code. The
//! member then reported **"sync failed: authenticator invalid"**: an integrity failure, for a record
//! still in flight. Seen as 1 report in 42, and 3 runs in 8 under load, in #202's proof; the
//! anchor's own dump showed the refusal two seconds after the joiner's pre-join record was written.
//!
//! What this drives, as people would: an anchor, alice's `vox daemon` with a room, and eight
//! more daemons ([`JOINERS`]) that each join it and **post straight away**, one after another, while the machine
//! is busy. What it asserts:
//! 1. no joiner reports a failed sync as a governance, malformed-data or authenticator failure;
//! 2. alice reads each joiner's first post within [`READ_WITHIN`] of it being posted.
//!
//! 3. **the window was reached**: at least one joiner was told "not a member of the room yet"
//!    (`NotYetMember`), the honest name for it, which the push retry resolves. A run in which none
//!    was is `CANNOT MEASURE: staging not achieved`, never a pass: it would have passed with the
//!    defect present (V210-106).
//!
//! **How the window is forced.** It is a race between the joiner's first session with its anchor
//! and its address record landing there, and the record usually wins: with #261 on the tree, runs
//! met the window in 0 of 4. So each joiner's daemon runs with the test-only
//! `VOX_TEST_HOLD_ADDRESS_MS` = [`HOLD_ADDRESS_MS`] (the `test-knobs` feature, V210-105), which keeps
//! its address record off every board for that long after it joins, while its bundle goes as usual
//! and is mirrored by alice. Its first syncs with the anchor then meet an anchor that knows it only
//! by its pre-join record and that bundle — every joiner, every run. The proof refuses as CANNOT
//! MEASURE a `vox` built without the knob.
//!
//! **Why it still makes load.** The other three refusals below are races of their own, so the proof
//! runs one `yes` per core while the joiners join — started here, killed here by PID, and checked
//! gone — and each joiner is a fresh chance. Run it alone (the timing lock), as every
//! timing-sensitive proof is.
//!
//! **Mutation that must turn it red:** a joiner's pre-join record dropped when the bundle that
//! admits it lands (#297 c1, which ac-ver286c2 caught): the anchor then knows the joiner as neither
//! member nor pending joiner, refuses its sync uninformatively, and it reports "authenticator
//! invalid" — a PRODUCT red.
//!
//! What it guards is four refusals of a member at join, each once sent as `0x05`: the anchor's gate
//! refusing a pending joiner (now `NotYetMember`), the joiner's gate and actor refusing the member
//! letting it in (now `EpochMismatch`, "not held here yet"), and a joiner rejecting an entry from a
//! member who joined after it (now `NotAdmitted`'s code). Its base — all four restored — is red in 3
//! runs of 5. Each path alone is rare: a mutant restoring one of them was green in 2 runs of 2 with
//! four joiners, which is why there are eight.

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/test_knobs.rs"]
mod test_knobs;

use std::io::Write as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use world::{args, vox_once, VoxProc, IDENTITY, VOX};

/// Members that join alice's room, one after another. Each is a fresh chance at the window — and
/// each of the four paths this guards is rare on its own, so eight (measured: with four, a mutant
/// restoring any single path could stay green two runs in a row).
const JOINERS: [&str; 8] = [
    "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan",
];
/// A joiner's first post must reach alice within this, measured from the moment it was posted.
const READ_WITHIN: Duration = Duration::from_secs(60);
const TIMEOUT: Duration = Duration::from_secs(120);
const ROOM_PASS: &str = "room pass";
/// What a joiner is told when its anchor does not know it yet (`WireError::NotYetMember`).
const NOT_YET: &str = "not know this node as a member";
/// How long each joiner keeps its address record off the boards after it joins
/// (`VOX_TEST_HOLD_ADDRESS_MS`): long enough that its first post's push meets the anchor first.
const HOLD_ADDRESS_MS: u64 = 10_000;

/// One `yes` per core, for as long as this is held; killed by PID when dropped, and checked gone.
struct Load(Vec<Child>);

impl Load {
    fn start() -> Self {
        let cores = std::thread::available_parallelism().map_or(8, std::num::NonZeroUsize::get);
        let children = (0..cores)
            .map(|_| {
                Command::new("yes")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn yes")
            })
            .collect();
        eprintln!("[proof] load: {cores} `yes` process(es), one per core");
        Self(children)
    }
}

impl Drop for Load {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
        }
        let mut left = 0usize;
        for c in &mut self.0 {
            if c.wait().is_err() {
                left += 1;
            }
        }
        eprintln!("[proof] load stopped: {left} left");
    }
}

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

fn daemon(name: &str, data: &Path, spec: &str, pass_file: &Path, env: &[(&str, &str)]) -> VoxProc {
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
        env,
    );
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("CANNOT MEASURE (staging not achieved): {name}'s daemon never answered `vox room list`");
}

#[test]
#[ignore = "real vox processes, production Argon2id and deliberate CPU load; run alone, in release"]
fn a_member_that_just_joined_is_not_refused_by_its_anchor() {
    test_knobs::require(&["VOX_TEST_HOLD_ADDRESS_MS"]);
    // A join per joiner; unlocks: a `vox id` and a daemon per member, two `trust add`s per joiner,
    // and the room created.
    watchdog::arm_for_setup(JOINERS.len() as u32, 4 * JOINERS.len() as u32 + 3);
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).unwrap();

    let anchor_dir = dir("anchor");
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

    // ---- everyone, consenting to alice and alice to them ------------------------------------
    let alice_dir = dir("alice");
    let fp = |d: &Path| {
        let (ok, out, err) = vox_once(d, &args(&["id"]));
        assert!(ok, "CANNOT MEASURE (staging not achieved): vox id: {err}");
        out.trim().to_owned()
    };
    let alice_fp = fp(&alice_dir);
    // Who is who, so a failure names the peer it failed with, not only its fingerprint.
    let anchor_fp = anchor
        .transcript()
        .lines()
        .find_map(|l| l.split("identity ").nth(1))
        .map(|f| f.trim().to_owned())
        .expect("CANNOT MEASURE (staging not achieved): the anchor names its identity");
    let mut names: Vec<(String, &str)> =
        vec![(anchor_fp, "the anchor"), (alice_fp.clone(), "alice")];
    let joiners: Vec<(&str, std::path::PathBuf)> = JOINERS.iter().map(|n| (*n, dir(n))).collect();
    for (name, d) in &joiners {
        let their = fp(d);
        names.push((their.clone(), name));
        let (ok, out, err) = vox_once(&alice_dir, &args(&["trust", "add", &their, "--name", name]));
        assert!(
            ok,
            "CANNOT MEASURE (staging not achieved): alice trusts {name}: {out}{err}"
        );
        let (ok, out, err) = vox_once(d, &args(&["trust", "add", &alice_fp, "--name", "alice"]));
        assert!(
            ok,
            "CANNOT MEASURE (staging not achieved): {name} trusts alice: {out}{err}"
        );
    }

    let mut alice = daemon("alice", &alice_dir, &spec, &idpass, &[]);
    let (ok, out, err) = vox_in(
        &alice_dir,
        &["room", "create", "--name", "family"],
        &format!("{ROOM_PASS}\n"),
    );
    assert!(
        ok,
        "CANNOT MEASURE (staging not achieved): vox room create: {out}{err}"
    );
    let (ok, list, err) = vox_once(&alice_dir, &args(&["room", "list"]));
    assert!(
        ok,
        "CANNOT MEASURE (staging not achieved): vox room list: {err}"
    );
    let room = list
        .lines()
        .find(|l| l.contains("family"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("CANNOT MEASURE (staging not achieved): room not listed: {list}"))
        .to_owned();

    // The joiners' daemons are up before the load: what is measured is the join, not start-up.
    let hold = HOLD_ADDRESS_MS.to_string();
    let mut procs: Vec<(&str, std::path::PathBuf, VoxProc)> = joiners
        .into_iter()
        .map(|(name, d)| {
            let p = daemon(
                name,
                &d,
                &spec,
                &idpass,
                &[("VOX_TEST_HOLD_ADDRESS_MS", &hold)],
            );
            (name, d, p)
        })
        .collect();

    // ---- under load: each joins and posts at once; alice must read it -----------------------
    let mut read_after: Vec<(&str, Duration)> = Vec::new();
    {
        let _load = Load::start();
        for (name, d, _) in &procs {
            let (ok, link, err) = vox_once(&alice_dir, &args(&["room", "invite", &room]));
            assert!(
                ok,
                "CANNOT MEASURE (staging not achieved): vox room invite: {err}"
            );
            let (ok, out, err) = vox_in(
                d,
                &["room", "join", link.trim(), "--name", "family"],
                &format!("{ROOM_PASS}\n"),
            );
            assert!(ok, "PRODUCT: {name}'s `vox room join` failed: {out}{err}");
            let said = format!("{name} is here");
            let (ok, _, err) = vox_once(d, &args(&["room", "post", &room, &said]));
            assert!(ok, "PRODUCT: {name}'s `vox room post` failed: {err}");
            let posted = Instant::now();
            loop {
                let (_, read, _) = vox_once(&alice_dir, &args(&["room", "read", &room]));
                if read.contains(&said) {
                    read_after.push((name, posted.elapsed()));
                    break;
                }
                assert!(
                    posted.elapsed() < READ_WITHIN,
                    "PRODUCT: alice did not read {name}'s first post within {READ_WITHIN:?} of it \
                     being posted"
                );
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
    // Let a retry that is still owed finish and be reported.
    std::thread::sleep(Duration::from_secs(5));

    // ---- what each joiner reported --------------------------------------------------------
    let mut misnamed = Vec::new();
    let mut not_yet = 0usize;
    // Alice's reports count too: the member that let a joiner in pushes to it at once, and was
    // refused as "authenticator invalid" while the joiner was still sealing its key.
    let mut everyone: Vec<(&str, &mut VoxProc)> = vec![("alice", &mut alice)];
    everyone.extend(procs.iter_mut().map(|(name, _, p)| (*name, p)));
    for (name, p) in everyone {
        for l in p
            .transcript()
            .lines()
            .filter(|l| l.contains("did not complete"))
        {
            if l.contains(NOT_YET) {
                not_yet += 1;
            }
            if l.contains("governance") || l.contains("malformed") || l.contains("authenticator") {
                misnamed.push(format!("{name} {l}"));
            }
        }
    }
    println!(
        "[proof] {} joiner(s) read by alice after {:?}; {not_yet} sync(s) told \"not a member yet\"; \
         {} misnamed",
        read_after.len(),
        read_after,
        misnamed.len()
    );
    let who = |l: &str| -> String {
        names
            .iter()
            .filter(|(fp, _)| l.contains(&fp[..12]))
            .map(|(_, n)| (*n).to_owned())
            .collect::<Vec<_>>()
            .join(",")
    };
    let misnamed: Vec<String> = misnamed
        .into_iter()
        .map(|l| format!("{l}   [peer: {}]", who(&l)))
        .collect();
    assert!(
        misnamed.is_empty(),
        "PRODUCT: a member that had just joined reported a failed sync as a governance, \
         malformed-data or authenticator failure: {misnamed:#?}"
    );
    // Green only if the window was met: with no sync told "not a member yet", nothing above was
    // asked of the anchor while it knew a joiner only by its pre-join record, and the defect would
    // have passed too.
    assert!(
        not_yet > 0,
        "CANNOT MEASURE (staging not achieved): no joiner's sync was told \"not a member yet\", so \
         no joiner synced with the anchor while it knew it only by its pre-join record, though each \
         held its address record back for {HOLD_ADDRESS_MS} ms"
    );
    let _ = anchor.transcript();
}
