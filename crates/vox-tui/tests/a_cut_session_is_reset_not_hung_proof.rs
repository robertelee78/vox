//! V210-81 (#272) — **a session Vox cuts on purpose reaches the local application as a reset,
//! never a hang**, through the shipped binary.
//!
//! When a host withdraws reach — here by stopping `vox room send`, which removes the offer's
//! service (PRD-001 R22) — every live session on it is cut, and the application at the far end
//! must see its connection reset (R23). The tunnel end does that with a zero-linger close of its
//! local socket. On macOS loopback that RST is lost when the socket still holds bytes queued
//! toward an application that is reading them: the application is left with an ESTABLISHED
//! connection that never delivers another byte (found by inv-share-stall through `vox room get`).
//!
//! Staging, all real processes: Alice and Bob are `vox daemon`s in one room. Each round Alice
//! offers a fresh [`FILE_BYTES`]-byte file with `vox room send`; Bob runs `vox room get`, which
//! reads its daemon's forward as fast as it can; as soon as the first bytes land, Alice's
//! `vox room send` is interrupted (SIGINT), cutting the session with megabytes still queued
//! toward the collector. `vox room get` gives up on a transfer silent for 30 s.
//!
//! Asserted: in every one of [`ROUNDS`] rounds the collector ends within [`BOUND`] (a reset, and
//! so an error naming the connection), never by stalling.
//!
//! ## Preconditions (else CANNOT MEASURE)
//! Each collector had received bytes, and not the whole file, when the offer was withdrawn.
//!
//! ## Mutation
//! Reset the local socket at once (`abort_local` without waiting for its queue to empty), and
//! collectors stall: red.

#![cfg(unix)]

#[path = "support/sync_pair.rs"]
mod sync_pair;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sync_pair::{Member, ID_PASS, VOX};

/// Rounds: 30 in release; 3 in a debug build, whose hashing of each offered file and whose joins
/// (a proof of work) otherwise take the run past the watchdog's budget.
const ROUNDS: usize = if cfg!(debug_assertions) { 3 } else { 30 };
const FILE_BYTES: usize = 64 << 20;
/// A collector that is reset ends at once; one that hangs is given up on by `vox room get` after
/// 30 s of silence.
const BOUND: Duration = Duration::from_secs(20);

struct Kid(Child);

impl Drop for Kid {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_vox(m: &Member, args: &[&str], out: &Path) -> Kid {
    let child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", &m.dir)
        .env("VOX_CONFIG_DIR", m.dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", ID_PASS)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_ROOM_PASSPHRASE")
        .env_remove("VOX_SESSION")
        .stdin(Stdio::null())
        .stdout(Stdio::from(std::fs::File::create(out).unwrap()))
        .stderr(Stdio::from(
            std::fs::File::create(out.with_extension("err")).unwrap(),
        ))
        .spawn()
        .expect("spawn vox");
    Kid(child)
}

fn bytes_in(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter_map(|e| e.metadata().ok())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0)
}

fn said(out: &Path) -> String {
    format!(
        "{}{}",
        std::fs::read_to_string(out).unwrap_or_default(),
        std::fs::read_to_string(out.with_extension("err")).unwrap_or_default()
    )
}

#[derive(Debug, PartialEq, Eq)]
enum End {
    Reset,
    Stalled,
    Other,
}

#[test]
#[ignore = "two real daemons with production Argon2id; CI runs it in release"]
fn a_cut_session_is_reset_not_hung() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    alice.trust(&bob);
    bob.trust(&alice);
    let _alice_d = alice.daemon(None);
    let _bob_d = bob.daemon(None);
    let room = alice.create("pair");
    bob.join(&alice.invite(&room), "pair");
    let mut rb = bob.reader();
    let cb = rb.room(&room);

    let mut ends = Vec::new();
    for round in 0..ROUNDS {
        // A fresh file each round: the offer's tag is derived from the content.
        let name = format!("r{round}.bin");
        let file = root.join(&name);
        {
            let mut f = std::fs::File::create(&file).unwrap();
            let chunk: Vec<u8> = (0..1 << 20)
                .map(|i: u32| (i.wrapping_mul(31).wrapping_add(round as u32) % 251) as u8)
                .collect();
            for _ in 0..FILE_BYTES >> 20 {
                f.write_all(&chunk).unwrap();
            }
        }
        let send_out = root.join(format!("send{round}.out"));
        let send = spawn_vox(
            &alice,
            &["room", "send", &room, file.to_str().unwrap()],
            &send_out,
        );
        let t0 = Instant::now();
        while !rb.texts(cb).iter().any(|t| t.contains(&name)) {
            assert!(
                t0.elapsed() < Duration::from_secs(60),
                "CANNOT MEASURE: round {round}: Bob never read the offer\n{}",
                said(&send_out)
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let dir = root.join(format!("get{round}"));
        std::fs::create_dir_all(&dir).unwrap();
        let get_out = root.join(format!("get{round}.out"));
        let mut get = spawn_vox(
            &bob,
            &[
                "room",
                "get",
                &room,
                &name,
                "--out",
                dir.join(&name).to_str().unwrap(),
            ],
            &get_out,
        );
        let t1 = Instant::now();
        while bytes_in(&dir) == 0 {
            assert!(
                t1.elapsed() < Duration::from_secs(60),
                "CANNOT MEASURE: round {round}: the collector received nothing\n{}",
                said(&get_out)
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        // Withdraw the offer, as a person stops `vox room send`.
        let ok = Command::new("kill")
            .args(["-INT", &send.0.id().to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "kill -INT vox room send");
        let cut = Instant::now();
        let held = bytes_in(&dir);
        let end = loop {
            if let Some(status) = get.0.try_wait().unwrap() {
                let text = said(&get_out);
                break if status.success() {
                    // The whole file arrived before the cut took effect.
                    panic!(
                        "CANNOT MEASURE: round {round}: the collector finished before the cut \
                         ({held} bytes at the cut)"
                    );
                } else if text.contains("stalled") {
                    End::Stalled
                } else if text.contains("reset") || text.contains("reading the transfer") {
                    End::Reset
                } else {
                    eprintln!("[proof] round {round}: collector said: {}", text.trim());
                    End::Other
                };
            }
            if cut.elapsed() > BOUND {
                break End::Stalled;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        eprintln!(
            "[proof] round {round}: cut at {held} of {FILE_BYTES} bytes; the collector ended \
             {end:?} after {:?}",
            cut.elapsed()
        );
        drop(get);
        drop(send);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&file);
        ends.push(end);
    }
    let count = |e: End| ends.iter().filter(|x| **x == e).count();
    let (reset, stalled, other) = (count(End::Reset), count(End::Stalled), count(End::Other));
    eprintln!("[proof] {ROUNDS} cut transfers: {reset} reset, {stalled} stalled, {other} other");
    assert!(
        stalled == 0 && reset == ROUNDS,
        "every transfer Vox cuts on purpose must reach the collector as a reset: {reset} of \
         {ROUNDS} reset, {stalled} stalled past {BOUND:?}, {other} other"
    );
}
