//! A joiner whose proof of work is slow must still get in, and one too slow for any member must
//! be told so (V210-87, #279).
//!
//! **The defect.** A member answering a join waits for the joiner's Equihash solution for a time
//! derived from the difficulty it demanded: 120s at the base difficulty. In the unoptimized build,
//! on a busy machine, one solve took 22–194s, so newcomers were turned away over and over and
//! never joined. The refusing side's own report, from the host daemon's stderr, was
//! `a join did not complete — answering <joiner>: peer unreachable: quic stream: peer sent no frame
//! in time`: the wait for the `Solve` frame ran out while the joiner was still grinding. The
//! joiner was then told "the anchor answered, but no member it knows could be reached" — about a
//! member that had been reached and had waited. A slow device is the same window as a slow build.
//!
//! **What this drives, with real binaries.** An anchor (`vox node`), alice (`vox id`,
//! `vox daemon`, `vox room create`, `vox room link`) and bob (`vox id`, `vox daemon`,
//! `vox room join`). Bob's daemon is started with `VOX_TEST_SOLVE_AT_LEAST_MS`, the product's
//! test-only floor on its own grind, inert when unset: the release build solves in a second or
//! two, and nothing else stages a joiner slower than the member's patience deterministically.
//!
//! 1. `a_joiner_slower_than_the_old_patience_gets_in`: bob's grind lasts at least 150s, past the
//!    old 120s and inside the new 480s. Bob's `vox room join` must succeed, alice's stderr must
//!    carry no refusal of him, and the join time is printed.
//! 2. `a_joiner_slower_than_the_patience_is_told_why`: bob's grind lasts at least 485s, past the
//!    new 480s. The join must fail saying this device took that long against a member's 480s, and
//!    not that no member could be reached; alice's stderr must carry her own report of the wait
//!    running out, which is the refusing side naming the gate.
//!
//! Expected values are hard-coded (480s, 150s, 485s), not read from the product, so a changed
//! patience goes red here. A grind the floor did not lengthen is PRODUCT (staging), never green.
//!
//! **Mutations that must turn it red.**
//! - `SOLVE_BUDGET_PER_EXPECTED_SOLVE` back to 30s in `joinstream.rs` (the cause): case 1 red,
//!   alice gives up at 120s with `peer sent no frame in time`; case 2 red, the patience named is
//!   not 480s.
//! - Drop the late-grind check in `run_initiator` (the old report): case 2 red, bob is told no
//!   member could be reached.

// Optional (decider, 2026-10-01): it blocks nothing and CI only compiles it. Without
// `--features optional-proofs` a stand-in takes its place and says it was not run
// (`support/optional_proof.rs`). How to run it: docs/release/optional-proofs.md.
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(
    a_joiner_slower_than_the_old_patience_gets_in,
    a_joiner_slower_than_the_patience_is_told_why
);

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/test_knobs.rs"]
mod test_knobs;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "identity passphrase";
const ROOM_PASS: &str = "channel passphrase";

/// What a member waits for the joiner's solve at the base difficulty, as this proof expects it.
const PATIENCE_SECS: u64 = 480;
/// The old wait: a grind past it and inside [`PATIENCE_SECS`] was refused and now gets in.
const OLD_PATIENCE_SECS: u64 = 120;
/// Case 1's grind floor: past the old wait, well inside the new one.
const SLOW_GRIND_MS: u64 = 150_000;
/// Case 2's grind floor: past the new wait, so the member has stopped waiting by then.
const TOO_SLOW_GRIND_MS: u64 = 485_000;
/// How long a daemon may take to answer after it starts (production Argon2id unlock).
const START_PATIENCE: Duration = Duration::from_secs(240);

fn profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

/// A child process killed and reaped when dropped, by its own handle.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Who {
    data: PathBuf,
    cfg: PathBuf,
    pass: PathBuf,
}

impl Who {
    fn new(tmp: &Path, name: &str) -> Self {
        let w = Who {
            data: tmp.join(name).join("data"),
            cfg: tmp.join(name).join("cfg"),
            pass: tmp.join(format!("{name}.pass")),
        };
        std::fs::create_dir_all(&w.cfg).expect("APPARATUS: create a staging directory");
        std::fs::write(&w.pass, IDENTITY).expect("APPARATUS: write a staging file");
        w
    }

    /// `vox …` as this profile, with `input` on stdin; `(ok, stdout, stderr)`.
    fn vox(&self, args: &[&str], input: Option<&str>) -> (bool, String, String) {
        let mut child = Command::new(VOX)
            .args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
            .env_remove("VOX_ROOM")
            .env_remove("VOX_SESSION")
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("APPARATUS: spawn vox");
        if let Some(text) = input {
            let mut pipe = child.stdin.take().expect("APPARATUS: a piped stdio handle");
            pipe.write_all(text.as_bytes())
                .expect("PRODUCT (staging): vox exited without reading its stdin");
        }
        let out = child.wait_with_output().expect("APPARATUS: vox ran");
        let o = (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        );
        eprintln!(
            "[receipt] vox {} -> ok {}\n  stdout: {}\n  stderr: {}",
            args.join(" "),
            o.0,
            o.1.trim(),
            o.2.trim()
        );
        o
    }

    /// `vox daemon` for this profile, stderr to `err`, answering on its socket before this returns.
    fn daemon(&self, anchor: &str, err: &Path, env: &[(&str, String)]) -> Proc {
        let mut cmd = Command::new(VOX);
        cmd.args(["daemon", "--listen", "127.0.0.1:0", "--anchor", anchor])
            .arg("--passphrase-file")
            .arg(&self.pass)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(err).expect("APPARATUS: create a staging file"),
            ));
        for (k, v) in env {
            cmd.env(k, v);
        }
        let proc = Proc(cmd.spawn().expect("APPARATUS: spawn vox daemon"));
        let started = Instant::now();
        while !self.vox(&["room", "list"], None).0 {
            assert!(
                started.elapsed() < START_PATIENCE,
                "PRODUCT (staging): a daemon never answered; its stderr:\n{}",
                std::fs::read_to_string(err).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(500));
        }
        proc
    }
}

struct Staged {
    _anchor: Proc,
    _alice: Proc,
    _bob: Proc,
    bob: Who,
    alice_err: PathBuf,
    link: String,
}

/// An anchor, alice's room on it, and bob's daemon with its grind floored at `grind_ms`.
fn stage(tmp: &Path, grind_ms: u64) -> Staged {
    let anchor_who = Who::new(tmp, "anchor");
    let out = tmp.join("anchor.out");
    let anchor = Proc(
        Command::new(VOX)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &anchor_who.data)
            .env("VOX_CONFIG_DIR", &anchor_who.cfg)
            .stdout(Stdio::from(
                std::fs::File::create(&out).expect("APPARATUS: create a staging file"),
            ))
            .stderr(Stdio::null())
            .spawn()
            .expect("APPARATUS: spawn vox node"),
    );
    let started = Instant::now();
    let spec = loop {
        let text = std::fs::read_to_string(&out).unwrap_or_default();
        if let Some(s) = text
            .split_whitespace()
            .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        {
            break s.to_owned();
        }
        assert!(
            started.elapsed() < START_PATIENCE,
            "PRODUCT (staging): the anchor never printed its spec"
        );
        std::thread::sleep(Duration::from_millis(250));
    };

    let (alice, bob) = (Who::new(tmp, "alice"), Who::new(tmp, "bob"));
    // Both identities, then both daemons, at once: each unlock is production Argon2id, and the
    // too-slow case has to fit its 485s grind inside the watchdog after them.
    let alice_err = tmp.join("alice.daemon.err");
    let bob_err = tmp.join("bob.daemon.err");
    let (alice_proc, bob_proc) = std::thread::scope(|sc| {
        let ids = [&alice, &bob].map(|w| sc.spawn(move || w.vox(&["id"], None).0));
        for id in ids {
            assert!(
                id.join().unwrap_or_else(|e| std::panic::resume_unwind(e)),
                "PRODUCT (staging): vox id failed"
            );
        }
        let a = sc.spawn(|| alice.daemon(&spec, &alice_err, &[]));
        let b = sc.spawn(|| {
            bob.daemon(
                &spec,
                &bob_err,
                &[("VOX_TEST_SOLVE_AT_LEAST_MS", grind_ms.to_string())],
            )
        });
        (
            a.join().unwrap_or_else(|e| std::panic::resume_unwind(e)),
            b.join().unwrap_or_else(|e| std::panic::resume_unwind(e)),
        )
    });
    assert!(
        alice
            .vox(
                &["room", "create", "--passphrase-file", "-", "--name", "slow"],
                Some(ROOM_PASS)
            )
            .0,
        "PRODUCT (staging): room create failed"
    );
    let id = alice
        .vox(&["room", "list"], None)
        .1
        .split_whitespace()
        .next()
        .expect("PRODUCT: the new room in `vox room list`")
        .to_owned();
    let link = alice.vox(&["room", "link", &id], None).1.trim().to_owned();
    Staged {
        _anchor: anchor,
        _alice: alice_proc,
        _bob: bob_proc,
        bob,
        alice_err,
        link,
    }
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "a grind floored at 150s, production Argon2id and a real anchor; optional, run it in release"]
fn a_joiner_slower_than_the_old_patience_gets_in() {
    test_knobs::require(&["VOX_TEST_SOLVE_AT_LEAST_MS"]);
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let s = stage(tmp.path(), SLOW_GRIND_MS);

    let t = Instant::now();
    let (ok, out, err) = s.bob.vox(
        &["room", "join", "--passphrase-file", "-", &s.link],
        Some(ROOM_PASS),
    );
    let took = t.elapsed();
    let alice_said = std::fs::read_to_string(&s.alice_err).unwrap_or_default();
    eprintln!(
        "[proof] {} slow joiner (grind ≥ {}s): join {} in {:.1}s",
        profile(),
        SLOW_GRIND_MS / 1000,
        if ok { "got in" } else { "refused" },
        took.as_secs_f64()
    );
    assert!(
        ok,
        "PRODUCT: a joiner grinding {}s — past the old {OLD_PATIENCE_SECS}s, inside {PATIENCE_SECS}s — was \
         refused after {:.1}s\n  bob: {out}{err}\n  alice's own report:\n{alice_said}",
        SLOW_GRIND_MS / 1000,
        took.as_secs_f64()
    );
    assert!(
        took >= Duration::from_millis(SLOW_GRIND_MS),
        "PRODUCT (staging): the join took {:.1}s, under the {}s grind floor — the floor did not apply",
        took.as_secs_f64(),
        SLOW_GRIND_MS / 1000
    );
    assert!(
        // The join's own report, not a sync's (`sync of room … did not complete`).
        !alice_said.contains("a join did not complete"),
        "PRODUCT: alice reported a join that did not complete although bob got in:\n{alice_said}"
    );
    eprintln!(
        "[proof] {} slow joiner: 1/1 got in, grind floor {}s, join {:.1}s",
        profile(),
        SLOW_GRIND_MS / 1000,
        took.as_secs_f64()
    );
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "a grind floored at 485s, production Argon2id and a real anchor; optional, run it in release"]
fn a_joiner_slower_than_the_patience_is_told_why() {
    test_knobs::require(&["VOX_TEST_SOLVE_AT_LEAST_MS"]);
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let s = stage(tmp.path(), TOO_SLOW_GRIND_MS);

    let t = Instant::now();
    let (ok, out, err) = s.bob.vox(
        &["room", "join", "--passphrase-file", "-", &s.link],
        Some(ROOM_PASS),
    );
    let took = t.elapsed();
    let said = format!("{out}{err}");
    // The daemon writes its report as the exchange fails; give it a moment to land.
    let refusal = "peer sent no frame in time";
    let deadline = Instant::now() + Duration::from_secs(10);
    let alice_said = loop {
        let text = std::fs::read_to_string(&s.alice_err).unwrap_or_default();
        if text.contains(refusal) || Instant::now() >= deadline {
            break text;
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    eprintln!(
        "[proof] {} too-slow joiner (grind ≥ {}s): join {} in {:.1}s",
        profile(),
        TOO_SLOW_GRIND_MS / 1000,
        if ok { "got in" } else { "refused" },
        took.as_secs_f64()
    );
    assert!(
        took >= Duration::from_millis(TOO_SLOW_GRIND_MS),
        "PRODUCT (staging): the join ended after {:.1}s, under the {}s grind floor: {said}",
        took.as_secs_f64(),
        TOO_SLOW_GRIND_MS / 1000
    );
    assert!(
        !ok,
        "PRODUCT: a joiner grinding {}s got in although a member waits {PATIENCE_SECS}s: {said}",
        TOO_SLOW_GRIND_MS / 1000
    );
    // The refusing side names the gate: its wait for the solve ran out.
    assert!(
        alice_said.contains("a join did not complete") && alice_said.contains(refusal),
        "PRODUCT: alice did not report her wait for the solve running out:\n{alice_said}"
    );
    // And the joiner is told why, in numbers, not that nobody could be reached.
    assert!(
        !said.contains("no member it knows could be reached"),
        "PRODUCT: bob was told no member could be reached, about a member that answered and waited: {said}"
    );
    let waits = format!("a member waits {PATIENCE_SECS}s");
    assert!(
        said.contains("to solve the join's proof of work") && said.contains(&waits),
        "PRODUCT: bob was not told his grind outlasted a member's {PATIENCE_SECS}s: {said}"
    );
    // The advice says "this device took longer…"; the member's own line carries the number.
    let solved: u64 = said
        .split("this device took ")
        .skip(1)
        .find_map(|r| r.split('s').next().and_then(|n| n.trim().parse().ok()))
        .unwrap_or_else(|| panic!("PRODUCT: no 'this device took Ns' in: {said}"));
    assert!(
        solved >= TOO_SLOW_GRIND_MS / 1000,
        "PRODUCT: bob said his grind took {solved}s, under its {}s floor: {said}",
        TOO_SLOW_GRIND_MS / 1000
    );
    eprintln!(
        "[proof] {} too-slow joiner: 1/1 told why (took {solved}s, a member waits {PATIENCE_SECS}s), \
         alice's report names the solve wait",
        profile()
    );
}
