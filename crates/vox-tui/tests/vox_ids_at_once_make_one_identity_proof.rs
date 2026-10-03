//! V210-91 (#285) — **`vox id` run several times at once on a fresh profile makes one identity**,
//! through the shipped binary.
//!
//! Nothing serialised a profile's creation across processes. Two `vox id`s started together both
//! saw no vault, and each made an identity: the second moved the first's store aside (left as
//! `store.redb.orphaned-<secs>`) and renamed its own vault over the first's. Both exited 0 and
//! printed a fingerprint, and one of those identities no longer existed — a person told "this is
//! you" about a key that was already gone.
//!
//! Creation now holds a lock on the profile directory from its check for a vault to the vault's
//! write, so a second `vox id` waits and then finds the first one's vault, and refuses, naming the
//! concurrent creation.
//!
//! Staging: [`TRIALS`] fresh profiles; in each, [`AT_ONCE`] `vox id`s are started together (the
//! production Argon2id seal makes the window seconds wide), all with the same passphrase, and then
//! a later `vox id` reads the profile back. Asserted, per trial:
//!
//! - at least one run exits 0 (a trial in which none does made no identity at all);
//! - **every run that exits 0 printed the fingerprint the later `vox id` shows** — so no run
//!   reported an identity the profile does not hold, and exactly one identity was made;
//! - every run that fails says why in words a person can act on: the concurrent creation, or a vox
//!   already holding the profile — never an internal error;
//! - no `*.orphaned-*` and no `vault.tmp` is left in the profile directory.
//!
//! Mutation that must turn it red: creation without the directory lock (the unserialised create,
//! with the vault's replacing rename): two runs print different fingerprints, and a store is left
//! aside.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "identity passphrase for the one-identity proof";
/// Fresh profiles tried.
const TRIALS: usize = 20;
/// `vox id`s started together on each.
const AT_ONCE: usize = 3;
/// What the loser of the race says.
const CONCURRENT: &str = "another vox created this profile's identity at the same time";
/// What a run says that finds the winner still holding the profile: one serving it, or one that
/// has not finished.
const BUSY: [&str; 2] = [
    "a vox is already running for this profile",
    "another vox is still using this profile",
];

/// A child killed and reaped by its own handle when dropped, never by a name pattern.
struct Proc(Option<Child>);

impl Drop for Proc {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn vox_id(data: &Path) -> Command {
    let mut c = Command::new(VOX);
    c.arg("id")
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .env_remove("VOX_TEST_CLOCK_SKEW_MS")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}

/// Names in the profile directory that a finished creation must not leave.
fn leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|d| {
            d.filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.contains(".orphaned-") || n == "vault.tmp")
                .collect()
        })
        .unwrap_or_default()
}

#[test]
#[ignore = "real binaries and production Argon2id; the release gate runs it"]
fn vox_ids_started_at_once_make_one_identity_and_report_only_it() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: could not make a temporary directory");
    let (mut succeeded, mut concurrent, mut busy, mut unreadable) =
        (0usize, 0usize, 0usize, 0usize);
    let (mut wrong, mut unnamed, mut left_behind, mut none_made) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for trial in 1..=TRIALS {
        let data: PathBuf = tmp.path().join(format!("p{trial}"));
        std::fs::create_dir_all(data.join("cfg"))
            .unwrap_or_else(|e| panic!("APPARATUS: could not make {}: {e}", data.display()));
        let mut runs: Vec<Proc> = (0..AT_ONCE)
            .map(|_| {
                Proc(Some(vox_id(&data).spawn().unwrap_or_else(|e| {
                    panic!("APPARATUS: could not spawn {VOX} id: {e}")
                })))
            })
            .collect();
        let outs: Vec<(bool, String, String)> = runs
            .iter_mut()
            .map(|p| {
                let child = p.0.take().expect("APPARATUS: a run was reaped twice");
                let out = child
                    .wait_with_output()
                    .unwrap_or_else(|e| panic!("APPARATUS: could not wait for a vox id: {e}"));
                (
                    out.status.success(),
                    String::from_utf8_lossy(&out.stdout).trim().to_owned(),
                    String::from_utf8_lossy(&out.stderr).trim().to_owned(),
                )
            })
            .collect();
        let later = vox_id(&data)
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: could not run the later vox id: {e}"));
        let held = String::from_utf8_lossy(&later.stdout).trim().to_owned();
        let left = leftovers(&data.join("default"));
        let oks = outs.iter().filter(|o| o.0).count();
        eprintln!(
            "[proof] trial {trial}: {oks}/{AT_ONCE} exited 0; later vox id ok={} {held}; leftovers {left:?}",
            later.status.success()
        );
        for (ok, out, err) in &outs {
            eprintln!("[proof]   ok={ok} out={out:?} err={err:?}");
        }
        // The staging is met here (a fresh profile, runs started together), so a trial in
        // which no run made the identity is the defect, not an unmet precondition.
        if oks == 0 {
            none_made.push(format!("trial {trial}: {outs:?}"));
        }
        // A profile the later `vox id` cannot read holds no identity at all, so every
        // fingerprint a run printed for it is one the profile does not hold.
        let held = if later.status.success() && !held.is_empty() {
            held
        } else {
            unreadable += 1;
            format!(
                "no readable identity ({:?})",
                String::from_utf8_lossy(&later.stderr).trim()
            )
        };
        for (ok, out, err) in &outs {
            if *ok {
                succeeded += 1;
                if *out != held {
                    wrong.push(format!(
                        "trial {trial}: printed {out}, the profile holds {held}"
                    ));
                }
            } else if err.contains(CONCURRENT) {
                concurrent += 1;
            } else if BUSY.iter().any(|b| err.contains(b)) {
                busy += 1;
            } else {
                unnamed.push(format!("trial {trial}: {err:?}"));
            }
        }
        if !left.is_empty() {
            left_behind.push(format!("trial {trial}: {left:?}"));
        }
    }
    eprintln!(
        "[proof] {TRIALS} trials x {AT_ONCE}: exited 0 {succeeded}, refused as concurrent {concurrent}, refused as busy {busy}; reported a fingerprint the profile does not hold {}, failed without naming the concurrent creation {}, trials leaving files behind {}, trials whose profile a later `vox id` could not read {unreadable}, trials in which no run made the identity {}",
        wrong.len(),
        unnamed.len(),
        left_behind.len(),
        none_made.len()
    );
    // The claim first: a run that says "this is you" about a key the profile does not hold.
    assert!(
        wrong.is_empty(),
        "PRODUCT: `vox id` reported identities the profile does not hold: {wrong:#?}"
    );
    assert!(
        none_made.is_empty(),
        "PRODUCT: no `vox id` of {AT_ONCE} made the profile's identity: {none_made:#?}"
    );
    assert!(
        left_behind.is_empty(),
        "PRODUCT: `vox id` left files behind in the profile: {left_behind:#?}"
    );
    assert!(
        unnamed.is_empty(),
        "PRODUCT: a failed `vox id` did not name the concurrent creation: {unnamed:#?}"
    );
}
