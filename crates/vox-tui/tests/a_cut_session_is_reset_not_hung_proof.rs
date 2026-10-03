//! V210-81 (#272) — **a session Vox cuts on purpose reaches the local application as a reset,
//! never a hang and never a clean end**, through the shipped binary.
//!
//! When a host withdraws reach — here by stopping `vox room send`, which removes the offer's
//! service (PRD-001 R22) — every live session on it is cut, and the application at the far end
//! must see its connection reset (R23). The tunnel end does that with a zero-linger close of its
//! local socket. On macOS loopback that RST is lost when the socket still holds bytes queued
//! toward an application that is reading them: the application is left with an ESTABLISHED
//! connection that never delivers another byte (found by inv-share-stall through `vox room get`).
//!
//! And the offer's own end must not beat the cut with a clean close: `vox room send` used to exit
//! as soon as the service was removed, and its exit closed each transfer's socket gracefully. When
//! that close reached the host's splice before the cut did, the stream was finished, and the
//! collector read a clean, truncated end ("the transfer does not match what was announced"). A
//! SIGTERM did the same with no cut at all, since it ended the process where it stood.
//!
//! Staging, all real processes: Alice and Bob are `vox daemon`s in one room. Each round Alice
//! offers a fresh [`FILE_BYTES`]-byte file with `vox room send`; Bob runs `vox room get`, which
//! reads its daemon's forward as fast as it can; as soon as the first bytes land, Alice's
//! `vox room send` is stopped, with megabytes still queued toward the collector. `vox room get`
//! gives up on a transfer silent for 30 s. Two arms:
//!
//! - **Ctrl-C** ([`ROUNDS`] rounds, SIGINT): as a person stops it. The node's cut and the
//!   offer's own close race; either may arrive first.
//! - **SIGTERM** ([`TERM_ROUNDS`] rounds): as `kill` or a service manager stops it. Before the
//!   fix a SIGTERM ended `vox room send` where it stood, with no cut of its own, so most rounds
//!   ended in the clean, truncated end. Not every round: the node's withdrawal can still win, and
//!   a verifier's mutant with only that half restored reset 4 of 10.
//!
//! - **Frozen daemon** (once): Alice's daemon is stopped with SIGSTOP, as a wedged daemon is, and
//!   her `vox room send` of a small offer is sent SIGTERM. It asked the daemon to withdraw the
//!   offer and waited for the answer with no bound, so only SIGKILL ended it.
//!
//! Asserted: in every round of both arms the collector ends within [`BOUND`] with a reset (an
//! error naming the connection), never by stalling and never with a clean end. With the daemon
//! frozen, `vox room send` exits within [`STOP_WITHIN`] of SIGTERM, saying [`FROZEN_SAID`].
//!
//! ## Preconditions (else PRODUCT (staging))
//! Each collector had received bytes, and not the whole file, when the offer was stopped.
//!
//! ## Mutation
//! Reset the local socket at once (`abort_local` without waiting for its queue to empty), and
//! collectors stall: red. Let `vox room send` close an unfinished transfer gracefully (the old
//! exit), and rounds end with a clean, truncated end: red. Wait for the offer's withdrawal with no
//! bound (no `REMOVE_SERVICE_PATIENCE`), and the frozen-daemon arm is still running at
//! [`STOP_WITHIN`]: red.

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
/// Rounds of the SIGTERM arm, whose red was every round.
const TERM_ROUNDS: usize = if cfg!(debug_assertions) { 2 } else { 10 };
const FILE_BYTES: usize = 64 << 20;
/// A collector that is reset ends at once; one that hangs is given up on by `vox room get` after
/// 30 s of silence.
const BOUND: Duration = Duration::from_secs(20);
/// How long a `vox room send` whose daemon is stopped may take to exit on SIGTERM: the 5 s it
/// waits for the daemon to withdraw the offer, and as long again for the process to start
/// exiting and be seen to.
const STOP_WITHIN: Duration = Duration::from_secs(10);
/// What it says when its daemon did not answer.
const FROZEN_SAID: &str = "the daemon did not answer within 5s";

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
        .stdout(Stdio::from(
            std::fs::File::create(out).expect("APPARATUS: create the stdout file"),
        ))
        .stderr(Stdio::from(
            std::fs::File::create(out.with_extension("err"))
                .expect("APPARATUS: create the stderr file"),
        ))
        .spawn()
        .expect("APPARATUS: spawn vox");
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
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let root = tmp.path();
    let alice = Member::new(root, "alice");
    let bob = Member::new(root, "bob");
    alice.trust(&bob);
    bob.trust(&alice);
    let alice_d = alice.daemon(None);
    let _bob_d = bob.daemon(None);
    let room = alice.create("pair");
    bob.join(&alice.invite(&room), "pair");
    let mut rb = bob.reader();
    let cb = rb.room(&room);

    let mut ends = Vec::new();
    let arms = std::iter::repeat_n("-INT", ROUNDS).chain(std::iter::repeat_n("-TERM", TERM_ROUNDS));
    for (round, sig) in arms.enumerate() {
        // A fresh file each round: the offer's tag is derived from the content.
        let name = format!("r{round}.bin");
        let file = root.join(&name);
        {
            let mut f = std::fs::File::create(&file).expect("APPARATUS: create the offered file");
            let chunk: Vec<u8> = (0..1 << 20)
                .map(|i: u32| (i.wrapping_mul(31).wrapping_add(round as u32) % 251) as u8)
                .collect();
            for _ in 0..FILE_BYTES >> 20 {
                f.write_all(&chunk)
                    .expect("APPARATUS: write the offered file");
            }
        }
        let send_out = root.join(format!("send{round}.out"));
        let send = spawn_vox(
            &alice,
            &[
                "room",
                "send",
                &room,
                file.to_str().expect("APPARATUS: a UTF-8 path"),
            ],
            &send_out,
        );
        let t0 = Instant::now();
        while !rb.texts(cb).iter().any(|t| t.contains(&name)) {
            assert!(
                t0.elapsed() < Duration::from_secs(60),
                "PRODUCT (staging): round {round}: Bob never read the offer\n{}",
                said(&send_out)
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let dir = root.join(format!("get{round}"));
        std::fs::create_dir_all(&dir).expect("APPARATUS: create the download directory");
        let get_out = root.join(format!("get{round}.out"));
        let mut get = spawn_vox(
            &bob,
            &[
                "room",
                "get",
                &room,
                &name,
                "--out",
                dir.join(&name).to_str().expect("APPARATUS: a UTF-8 path"),
            ],
            &get_out,
        );
        let t1 = Instant::now();
        while bytes_in(&dir) == 0 {
            assert!(
                t1.elapsed() < Duration::from_secs(60),
                "PRODUCT (staging): round {round}: the collector received nothing\n{}",
                said(&get_out)
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        // Stop the offer, as a person (`-INT`) or a service manager (`-TERM`) stops
        // `vox room send`.
        let ok = Command::new("kill")
            .args([sig, &send.0.id().to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(ok, "APPARATUS: kill {sig} of vox room send did not take");
        let cut = Instant::now();
        let held = bytes_in(&dir);
        let end = loop {
            if let Some(status) = get
                .0
                .try_wait()
                .expect("APPARATUS: poll vox room get's exit")
            {
                let text = said(&get_out);
                break if status.success() {
                    // The whole file arrived before the cut took effect.
                    panic!(
                        "PRODUCT (staging): round {round}: the collector finished before the cut \
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
            "[proof] round {round} ({sig}): cut at {held} of {FILE_BYTES} bytes; the collector \
             ended {end:?} after {:?}",
            cut.elapsed()
        );
        drop(get);
        drop(send);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&file);
        ends.push((sig, end));
    }
    // The frozen-daemon arm: Alice's daemon is stopped (SIGSTOP), then her `vox room send` is sent
    // SIGTERM. It cannot withdraw the offer, and is to stop anyway, saying so.
    let name = "frozen.bin";
    let file = root.join(name);
    std::fs::write(&file, b"an offer whose daemon will not answer")
        .expect("APPARATUS: write the offered file");
    let send_out = root.join("send-frozen.out");
    let mut send = spawn_vox(
        &alice,
        &[
            "room",
            "send",
            &room,
            file.to_str().expect("APPARATUS: a UTF-8 path"),
        ],
        &send_out,
    );
    let t0 = Instant::now();
    while !rb.texts(cb).iter().any(|t| t.contains(name)) {
        assert!(
            t0.elapsed() < Duration::from_secs(60),
            "PRODUCT (staging): the frozen-daemon arm: Bob never read the offer\n{}",
            said(&send_out)
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    alice_d.signal("-STOP");
    let ok = Command::new("kill")
        .args(["-TERM", &send.0.id().to_string()])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(ok, "APPARATUS: kill -TERM of vox room send did not take");
    let termed = Instant::now();
    let exited = loop {
        if send
            .0
            .try_wait()
            .expect("APPARATUS: poll vox room send's exit")
            .is_some()
        {
            break Some(termed.elapsed());
        }
        if termed.elapsed() > STOP_WITHIN {
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    alice_d.signal("-CONT");
    drop(send);
    let frozen_said = said(&send_out);
    eprintln!(
        "[proof] frozen daemon: vox room send exited {exited:?} after SIGTERM, saying: {}",
        frozen_said.trim()
    );

    let mut red = Vec::new();
    for (sig, rounds) in [("-INT", ROUNDS), ("-TERM", TERM_ROUNDS)] {
        let count = |e: End| ends.iter().filter(|(s, x)| *s == sig && *x == e).count();
        let (reset, stalled, other) = (count(End::Reset), count(End::Stalled), count(End::Other));
        eprintln!(
            "[proof] {sig}: {rounds} cut transfers: {reset} reset, {stalled} stalled, {other} other"
        );
        if reset != rounds {
            red.push(format!(
                "{sig}: {reset} of {rounds} reset, {stalled} stalled past {BOUND:?}, {other} other"
            ));
        }
    }
    assert!(
        red.is_empty(),
        "PRODUCT: every transfer Vox cuts on purpose must reach the collector as a reset: {}",
        red.join("; ")
    );
    assert!(
        exited.is_some() && frozen_said.contains(FROZEN_SAID),
        "PRODUCT: with its daemon stopped, a SIGTERM'd `vox room send` did not exit within \
         {STOP_WITHIN:?} saying {FROZEN_SAID:?}: exited {exited:?} (None: still running), said \
         {frozen_said:?}"
    );
}
