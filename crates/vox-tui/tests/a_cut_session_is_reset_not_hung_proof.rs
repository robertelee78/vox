//! V210-81 (#272) — **a session Vox cuts on purpose reaches the local application as a reset,
//! never a hang and never a clean end**, through the shipped binary.
//!
//! When a host withdraws reach — here by `vox share stop`, which removes the share's service
//! (PRD-001 R22) — every live session on it is cut, and the application at the far end must see
//! its connection reset (R23). The tunnel end does that with a zero-linger close of its local
//! socket. On macOS loopback that RST is lost when the socket still holds bytes queued toward an
//! application that is reading them: the application is left with an ESTABLISHED connection that
//! never delivers another byte (found by inv-share-stall through `vox room get`).
//!
//! And the share's own end must not beat the cut with a clean close: the server that hands the
//! file over is stopped with the share too, and a graceful close of a transfer it had not finished
//! would reach the host's splice as a finished stream, and the collector would read a clean,
//! truncated end ("the transfer does not match what was announced"). Each unfinished transfer is
//! reset instead.
//!
//! Staging, all real processes: Alice and Bob are `vox daemon`s in one room. Each round Alice
//! shares a fresh [`FILE_BYTES`]-byte file with `vox share`, which returns once her daemon serves
//! it; a collector on Bob's side reads his daemon's forward as fast as it can; as soon as the
//! first bytes land, Alice runs `vox share stop`, with megabytes still queued toward the
//! collector. Two arms:
//!
//! - **`vox room get`** ([`ROUNDS`] rounds), which gives up on a transfer silent for 30 s. The
//!   node's cut and the server's own reset race; either may arrive first.
//! - **Raw collector** ([`RAW_ROUNDS`] rounds): not `vox room get` but a plain socket on the same
//!   forward of Bob's daemon, sending the same request. What any application reaching a service
//!   through Vox sees.
//!
//! Asserted: in every round of the `vox room get` arm the collector ends within [`BOUND`] with
//! a reset, or with Vox's own words for one ([`WITHDRAWN_SAID`] when the host says it withdrew
//! access, [`STOPPED_SAID`] when it only refused the transfer after part of it came: `vox room
//! get` follows its node's events, and says why a transfer failed instead of the socket's error,
//! #406), never by
//! stalling and never with a clean end; in every round of the raw arm the socket is reset
//! (`ECONNRESET`), never closed cleanly and never left hanging.
//!
//! ## Preconditions (else PRODUCT (staging))
//! Each collector had received bytes, and not the whole file, when the share was stopped.
//!
//! ## Mutation
//! Reset the local socket at once (`abort_local` without waiting for its queue to empty), and
//! collectors stall: red. Let the share's server close an unfinished transfer gracefully when the
//! share stops, and rounds end with a clean, truncated end: red.

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

/// Rounds: 30 in release; 3 in a debug build, whose hashing of each shared file and whose joins
/// (a proof of work) otherwise take the run past the watchdog's budget.
const ROUNDS: usize = if cfg!(debug_assertions) { 3 } else { 30 };
/// Rounds of the raw-collector arm.
const RAW_ROUNDS: usize = if cfg!(debug_assertions) { 2 } else { 10 };
/// What `vox room get` says of a transfer its sharer withdrew mid-way, when the host says it
/// withdrew access (#406).
const WITHDRAWN_SAID: &str = "was withdrawn while it was being collected";
/// What it says when the host only refused it after part of it came: all that is known is that
/// it stopped partway, and the host's own reason (#496).
const STOPPED_SAID: &str = "stopped partway";
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

/// `vox share` of `file` by `m` in `room`: returns once `m`'s daemon serves it, with its tag.
fn share(m: &Member, room: &str, file: &Path, what: &str) -> String {
    let (ok, out, err) = m.vox(
        &[
            "share",
            room,
            file.to_str().expect("APPARATUS: a UTF-8 path"),
        ],
        None,
    );
    assert!(
        ok,
        "PRODUCT (staging): {what}: `vox share` failed: {out}{err}"
    );
    out.lines()
        .find_map(|l| l.split(" as ").nth(1).map(|t| t.trim().to_owned()))
        .unwrap_or_else(|| panic!("PRODUCT (staging): {what}: `vox share` named no tag: {out}"))
}

/// `vox share stop`: the share's service is withdrawn, which cuts what it carries.
fn stop_share(m: &Member, room: &str, tag: &str, what: &str) {
    let (ok, out, err) = m.vox(&["share", "stop", room, tag], None);
    assert!(
        ok && out.contains("no longer sharing"),
        "PRODUCT (staging): {what}: `vox share stop` failed: {out}{err}"
    );
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
    /// `vox room get` said, in Vox's words, that the sharer withdrew the offer mid-transfer.
    Explained,
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
    let _alice_d = alice.daemon(None);
    let _bob_d = bob.daemon(None);
    let room = alice.create("pair");
    bob.join(&alice.invite(&room), "pair");
    let mut rb = bob.reader();
    let cb = rb.room(&room);

    let mut ends = Vec::new();
    for round in 0..ROUNDS {
        // A fresh file each round, so each round's collector can only be collecting its own.
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
        let tag = share(&alice, &room, &file, &format!("round {round}"));
        let t0 = Instant::now();
        while !rb.texts(cb).iter().any(|t| t.contains(&name)) {
            assert!(
                t0.elapsed() < Duration::from_secs(60),
                "PRODUCT (staging): round {round}: Bob never read the share"
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
        // Stop the share, as its sharer does.
        let held = bytes_in(&dir);
        let cut = Instant::now();
        stop_share(&alice, &room, &tag, &format!("round {round}"));
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
                } else if text.contains(WITHDRAWN_SAID) || text.contains(STOPPED_SAID) {
                    End::Explained
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
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&file);
        ends.push(end);
    }
    // The raw arm: a plain socket on Bob's daemon's forward, as any application has.
    let mut raw = Vec::new();
    for round in 0..RAW_ROUNDS {
        let name = format!("raw{round}.bin");
        let file = root.join(&name);
        {
            let mut f = std::fs::File::create(&file).expect("APPARATUS: create the offered file");
            let chunk: Vec<u8> = (0..1 << 20)
                .map(|i: u32| (i.wrapping_mul(37).wrapping_add(round as u32) % 251) as u8)
                .collect();
            for _ in 0..FILE_BYTES >> 20 {
                f.write_all(&chunk)
                    .expect("APPARATUS: write the offered file");
            }
        }
        let tag = share(&alice, &room, &file, &format!("raw round {round}"));
        let t0 = Instant::now();
        while !rb.texts(cb).iter().any(|t| t.contains(&name)) {
            assert!(
                t0.elapsed() < Duration::from_secs(60),
                "PRODUCT (staging): raw round {round}: Bob never read the share"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let host = rb
            .author_of(cb, &name)
            .expect("PRODUCT (staging): the offer has no author");
        let local = rb.forward(cb, host, &tag);
        let mut sock =
            std::net::TcpStream::connect(&local).expect("APPARATUS: connect to the forward");
        sock.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("APPARATUS: set a read timeout");
        write!(
            sock,
            "GET /{name} HTTP/1.1\r\nHost: vox\r\nConnection: close\r\n\r\n"
        )
        .expect("APPARATUS: write the request");
        let mut buf = vec![0u8; 64 << 10];
        let mut got = 0usize;
        let t1 = Instant::now();
        // The head and the first of the body, as `vox room get` has when the share is stopped.
        while got < 64 << 10 {
            match std::io::Read::read(&mut sock, &mut buf) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => {
                    panic!("PRODUCT (staging): raw round {round}: reading before the cut: {e}")
                }
            }
            assert!(
                t1.elapsed() < Duration::from_secs(60),
                "PRODUCT (staging): raw round {round}: the raw collector received {got} bytes"
            );
        }
        let cut = Instant::now();
        stop_share(&alice, &room, &tag, &format!("raw round {round}"));
        let end = loop {
            match std::io::Read::read(&mut sock, &mut buf) {
                // Draining what was queued: the reset comes after it (macOS, see above).
                Ok(n) if n > 0 => got += n,
                Ok(_) => break End::Other,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break End::Reset,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => {
                    eprintln!("[proof] raw round {round}: the socket ended with {e}");
                    break End::Other;
                }
            }
            if cut.elapsed() > BOUND {
                break End::Stalled;
            }
        };
        assert!(
            got < FILE_BYTES,
            "PRODUCT (staging): raw round {round}: the whole file arrived before the cut"
        );
        eprintln!(
            "[proof] raw round {round}: {got} of {FILE_BYTES} bytes; the socket ended \
             {end:?} after {:?}",
            cut.elapsed()
        );
        drop(sock);
        let _ = std::fs::remove_file(&file);
        raw.push(end);
    }

    let mut red = Vec::new();
    let count = |e: End| ends.iter().filter(|x| **x == e).count();
    let (reset, explained, stalled, other) = (
        count(End::Reset),
        count(End::Explained),
        count(End::Stalled),
        count(End::Other),
    );
    eprintln!(
        "[proof] vox room get: {ROUNDS} cut transfers: {reset} reset, {explained} explained \
         (withdrawn, or stopped partway), {stalled} stalled, {other} other"
    );
    if reset + explained != ROUNDS {
        red.push(format!(
            "vox room get: {reset} of {ROUNDS} reset and {explained} explained, {stalled} stalled \
             past {BOUND:?}, {other} other"
        ));
    }
    let raw_reset = raw.iter().filter(|e| **e == End::Reset).count();
    eprintln!(
        "[proof] raw collector: {RAW_ROUNDS} cut transfers: {raw_reset} reset; {:?}",
        raw
    );
    if raw_reset != RAW_ROUNDS {
        red.push(format!(
            "raw collector: {raw_reset} of {RAW_ROUNDS} reset: {raw:?}"
        ));
    }
    assert!(
        red.is_empty(),
        "PRODUCT: every transfer Vox cuts on purpose must reach the collector as a reset: {}",
        red.join("; ")
    );
}
