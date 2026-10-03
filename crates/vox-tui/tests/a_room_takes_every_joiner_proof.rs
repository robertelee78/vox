//! Every joiner of a large room gets in (V210-104, #299), through the shipped binary.
//!
//! **Optional** (301 real joins, about eight minutes in release): it runs only with the
//! `optional-proofs` feature and blocks nothing, not CI and not the release gate. Run it with
//! `cargo test --release -p vox-tui --features optional-proofs --test a_room_takes_every_joiner_proof -- --ignored --nocapture`.
//! Without the feature a stand-in, `optional_proof_not_run::every_joiner_of_a_three_hundred_member_room_gets_in`,
//! says `OPTIONAL PROOF NOT RUN`, so it never reads as a pass.
//!
//! **The defect.** When a node is handed a second connection from a peer it already holds one to,
//! it probes the held one, and closed it if nothing came back within the probe's patience (250 ms
//! at least). The probe exists to tell a dead connection from a live one, but a connection to the
//! very process that just sent the newcomer is never dead: a late answer is a busy peer. An anchor
//! serving a room of hundreds of offline members is busy — it dials every one of them — and a
//! joiner's `vox connect` dials it twice (its own anchor, and the join's board). Each end closed
//! the connection the join's room fetch was riding, and the join failed 0.26 s in with
//! `fetching room …: peer unreachable: quic stream: closed by the peer`, which the person was told
//! as "the anchor could not be reached". Measured on 300 joins: 2, 5, 3 and 5 failures in four
//! runs; on integrate 69616f40 at 200 joins, 1 failure in three runs, so it predates #261 and #297.
//!
//! **What this drives.** An anchor (`vox node`); a host (`vox id`, `vox serve`), the member every
//! join goes through; 300 joiners (`vox id`, `vox connect`), the one-shot join a person runs, four
//! at a time; then one more. All on 127.0.0.1.
//!
//! **Asserted:** every one of the 301 joins succeeds. A red names each failed joiner, what its
//! `vox connect` said, and what the anchor and the host said of their connection to it — a
//! product verdict. Apparatus faults say so: a `vox id` or a staging line that never came is
//! `CANNOT MEASURE`, and the watchdog names itself.
//!
//! **Mutation that must turn it red:** an unanswered probe closing the held connection again
//! (`ConnectionManager::file_inner`): joins fail `closed by the peer` again, at the 1–2% the defect
//! ran at, so one run of 301 joins is expected to show several.
//!
//! **A rate claim, so more than one run.** At the measured rate (2, 5, 3, 5 and 8 failures in five
//! runs of 300), 301 joins with no failure happen by chance about 1% of the time, and three such
//! runs in a row about once in a million.

#![cfg(unix)]
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(every_joiner_of_a_three_hundred_member_room_gets_in);

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use world::{after_label, args, echo_service, vox_once, VoxProc};

/// How many join before the one that is measured last.
const MEMBERS: usize = 300;
/// Joins running at once. A member demands more work once four joins are in flight
/// (`Difficulty::ADAPT_THRESHOLD`), so more at once would only make each one slower.
const AT_ONCE: usize = 4;
/// Joins per batch, for the progress lines.
const BATCH: usize = 25;

fn profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

fn dir(tmp: &Path, name: &str) -> PathBuf {
    let d = tmp.join(name);
    std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a staging directory");
    d
}

/// An anchor and a host serving a room, on 127.0.0.1.
struct Room {
    /// In a mutex only so the joiners' threads may share the room: nothing locks it but a red.
    _anchor: Mutex<VoxProc>,
    host: Mutex<VoxProc>,
    spec: String,
    address: String,
    pass_file: String,
    /// Last, so it is removed after every process using it is gone.
    tmp: tempfile::TempDir,
}

fn stage() -> Room {
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let anchor_dir = dir(tmp.path(), "anchor");
    let host_dir = dir(tmp.path(), "host");
    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("the anchor's spec", |l| l.contains("@/ip4/127.0.0.1/udp/"))
        .split_whitespace()
        .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        .expect("PRODUCT (staging): the anchor's spec")
        .to_owned();
    let (ok, _, err) = vox_once(&host_dir, &args(&["id"]));
    assert!(ok, "PRODUCT (staging): vox id (host): {err}");
    let mut host = VoxProc::spawn(
        "host",
        &host_dir,
        &args(&[
            "serve",
            &echo_service().to_string(),
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    // Read in this order, as `vox serve` prints them; the room line is not needed.
    host.expect_line("room", |l| l.starts_with("room "));
    let address = after_label(
        &host.expect_line("address", |l| l.starts_with("address ")),
        "address",
    );
    let passphrase = after_label(
        &host.expect_line("passphrase", |l| l.starts_with("passphrase ")),
        "passphrase",
    );
    let pass_file = tmp.path().join("room-passphrase");
    std::fs::write(&pass_file, &passphrase).expect("APPARATUS: write a staging file");
    Room {
        _anchor: Mutex::new(anchor),
        host: Mutex::new(host),
        spec,
        address,
        pass_file: pass_file
            .to_str()
            .expect("APPARATUS: a path that is not UTF-8")
            .to_owned(),
        tmp,
    }
}

/// What one joiner's `vox id` then `vox connect` did.
struct Joined {
    /// The joiner's fingerprint, as `vox id` printed it.
    fp: String,
    ok: bool,
    took: Duration,
    said: String,
}

impl Room {
    /// Make an identity at `name` and join the room with it.
    fn join(&self, name: &str) -> Joined {
        let d = dir(self.tmp.path(), name);
        let (ok, fp, err) = vox_once(&d, &args(&["id"]));
        assert!(ok, "PRODUCT (staging): vox id ({name}): {fp}{err}");
        let t = Instant::now();
        let (ok, out, err) = vox_once(
            &d,
            &args(&[
                "connect",
                &self.address,
                "--passphrase-file",
                &self.pass_file,
                "--anchor",
                &self.spec,
                "--listen",
                "127.0.0.1:0",
            ]),
        );
        Joined {
            fp: fp.trim().to_owned(),
            ok,
            took: t.elapsed(),
            said: format!("{out}{err}"),
        }
    }
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "optional: 301 real joins with production Argon2id and proof of work; run in release"]
fn every_joiner_of_a_three_hundred_member_room_gets_in() {
    watchdog::arm_for(Duration::from_secs(if cfg!(debug_assertions) {
        6 * 60 * 60
    } else {
        90 * 60
    }));
    let r = stage();
    let next = AtomicUsize::new(0);
    let joined = AtomicUsize::new(0);
    let failed: Mutex<Vec<(usize, String, String)>> = Mutex::new(Vec::new());
    let first = Instant::now();
    let slowest = Mutex::new(Duration::ZERO);
    std::thread::scope(|sc| {
        for _ in 0..AT_ONCE {
            sc.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= MEMBERS {
                    return;
                }
                let j = r.join(&format!("m{i:03}"));
                {
                    let mut s = slowest
                        .lock()
                        .expect("APPARATUS: a lock the proof holds was poisoned");
                    *s = (*s).max(j.took);
                }
                if j.ok {
                    joined.fetch_add(1, Ordering::SeqCst);
                } else {
                    failed
                        .lock()
                        .expect("APPARATUS: a lock the proof holds was poisoned")
                        .push((i, j.fp, j.said));
                }
                let done = i + 1;
                if done.is_multiple_of(BATCH) {
                    eprintln!(
                        "[proof] {} batch {}: {done} joins started and run, {} joined, {} failed, \
                         {:.0}s since the first",
                        profile(),
                        done / BATCH,
                        joined.load(Ordering::SeqCst),
                        failed
                            .lock()
                            .expect("APPARATUS: a lock the proof holds was poisoned")
                            .len(),
                        first.elapsed().as_secs_f64()
                    );
                }
            });
        }
    });
    let staged = joined.load(Ordering::SeqCst);
    let last = r.join("last");
    let since_first = first.elapsed();
    let failed = failed
        .into_inner()
        .expect("APPARATUS: a lock the proof holds was poisoned");
    eprintln!(
        "[proof] {} {staged} of {MEMBERS} staged joins succeeded, {} failed; the next joiner: {} \
         in {:.1}s, {:.0}s after the first join began; slowest staged join {:.1}s",
        profile(),
        failed.len(),
        if last.ok { "joined" } else { "REFUSED" },
        last.took.as_secs_f64(),
        since_first.as_secs_f64(),
        slowest
            .lock()
            .expect("APPARATUS: a lock the proof holds was poisoned")
            .as_secs_f64(),
    );
    let shown: Vec<String> = failed
        .iter()
        .take(3)
        .map(|(i, fp, said)| {
            // What the anchor and the host said about this joiner, so a red names which end
            // closed what.
            let short: String = fp.chars().take(12).collect();
            let about = |p: &Mutex<VoxProc>| {
                p.lock()
                    .expect("APPARATUS: a lock the proof holds was poisoned")
                    .said_since(first)
                    .into_iter()
                    .filter(|l| l.contains(&format!("connection to {short}")))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            format!(
                "m{i:03} ({short}): {said}\n  the anchor said of it:\n{}\n  the host said of it:\n{}",
                about(&r._anchor),
                about(&r.host)
            )
        })
        .collect();
    assert!(
        failed.is_empty() && staged == MEMBERS,
        "{} of {MEMBERS} joins failed as the room grew ({} {}), the first at m{:03}:\n{}",
        failed.len(),
        profile(),
        if last.ok {
            "the next got in"
        } else {
            "the next too"
        },
        failed.first().map_or(0, |f| f.0),
        shown.join("\n")
    );
    assert!(
        last.ok,
        "PRODUCT: the room had {} members and its next joiner was refused ({}):\n{}\nthe host said:\n{}",
        staged + 1,
        profile(),
        last.said,
        r.host.lock().expect("APPARATUS: a lock the proof holds was poisoned").said_since(first).join("\n")
    );
}
