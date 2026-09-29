//! **The path-MTU ceiling follows the socket buffer the OS granted** (#174, V29-26), proved by
//! running the product and reading what each `vox` process says about itself.
//!
//! Every Vox endpoint asks the OS for a 4 MiB UDP receive buffer and reads back what it got. The
//! 8192-byte path-MTU ceiling (PRD-001 R41) was measured with that buffer; on a smaller one a
//! burst of large datagrams overflows it, quinn reads the loss as a black hole and pins the path
//! at 1200. So the product takes 8192 only on a full grant and otherwise keeps quinn's 1452, and
//! a process that falls back says so on stderr, once:
//!
//! ```text
//! vox: UDP receive buffer <N> KiB: path-MTU ceiling 1452 bytes, not 8192 — <why>
//! ```
//!
//! v0.2.9's first tag took 8192 whatever the buffer, and CI's ubuntu runner (whose default
//! `net.core.rmem_max` caps the grant at about 208 KiB) pinned the dialler at 1200. R41 does not
//! catch a return of that rule: it measures throughput, and quinn-proto 0.11.18 no longer
//! mistakes the overflow for a black hole (#206), so R41 stayed green on a mutant running 8192
//! on a 416 KiB grant (verdict on #174). This proof is the gate.
//!
//! **What this drives, with real binaries.** The shared harness world: an anchor (`vox node`), a
//! host (`vox serve` of a loopback echo service), a guest joined by `vox connect`, and then the
//! guest's `vox forward`, through which one payload is echoed so that each endpoint has carried
//! traffic. Nothing in this process runs a node. Then each long-running process (anchor, host,
//! forward) is killed by its PID and its whole output read to EOF, so a notice cannot be missed
//! because it had not been read yet.
//!
//! **The grant is read the way the product reads it:** a UDP socket on loopback asks for
//! `SO_RCVBUF` = 4 MiB and reads `SO_RCVBUF` back. A full grant reads back as 4 MiB on macOS, and
//! as 8 MiB on Linux, which reports twice what it stores. Both numbers are hard-coded here, not
//! taken from the product.
//!
//! **What is asserted, for every one of the three processes:**
//! - the grant is full: **no** "path-MTU ceiling" line at all;
//! - the grant is short: exactly **one** such line, and it is exactly
//!   `vox: UDP receive buffer <grant / 1024> KiB: path-MTU ceiling 1452 bytes, not 8192`, the
//!   KiB being the grant this test read back itself.
//!
//! On a Mac (`kern.ipc.maxsockbuf` 8 MiB by default) the grant is full, and a short one there is
//! CANNOT MEASURE rather than a pass, so the no-notice arm is always the one measured. On CI's
//! ubuntu runner the grant is short and the notice arm is measured; a Linux host that grants the
//! full buffer is CANNOT MEASURE too, so the Linux arm can never pass silently on the no-notice
//! path, which the always-8192 mutant would also pass. Both arms are in CI's release
//! `--ignored` job, which runs on both runners.
//!
//! **Mutations that must turn it red.**
//! - The ceiling ignores the buffer and is always 8192 (`mtu_ceiling_for` returns
//!   `MAX_UDP_PAYLOAD` whatever `effective` is; v0.2.9's first-tag rule): the compiler removes the
//!   notice's branch, so on Linux's short grant every process is silent and this goes red at the
//!   first one. **The product has no knob that forces a small buffer**, and raising or lowering
//!   `kern.ipc.maxsockbuf` needs root, so on a Mac this mutant stays green: the Linux arm, in CI,
//!   is what catches it.
//! - The ceiling ignores the buffer and is always 1452: a Mac's full grant prints the notice, and
//!   this goes red there.
//! - The threshold drops back to 4 MiB on Linux (Linux's doubled read-back taken as the grant):
//!   an `rmem_max` between 2 and 4 MiB would take 8192; the default runner reads back 416 KiB, so
//!   this is reasoned, not measured, here.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::sync::mpsc;
use std::time::{Duration, Instant};

use world::{echo_service, round_trip, VoxProc, World};

/// What every Vox endpoint asks for, each way.
const ASKED: usize = 4 * 1024 * 1024;
/// What `SO_RCVBUF` reads back when [`ASKED`] was granted in full: Linux reports twice what it
/// stores (`sk_rcvbuf = 2 * min(val, rmem_max)`), other platforms report the grant.
#[cfg(target_os = "linux")]
const FULL_READ_BACK: usize = 8 * 1024 * 1024;
#[cfg(not(target_os = "linux"))]
const FULL_READ_BACK: usize = 4 * 1024 * 1024;

/// The substring every fallback notice carries, and nothing else the product prints does.
const NOTICE: &str = "path-MTU ceiling";

/// Ask the OS for the buffer a Vox endpoint asks for, on the same kind of socket, and read back
/// what it granted.
fn granted_receive_buffer() -> usize {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind a loopback UDP socket");
    let sock = socket2::SockRef::from(&socket);
    sock.set_recv_buffer_size(ASKED)
        .expect("ask for a 4 MiB receive buffer");
    sock.recv_buffer_size().expect("read SO_RCVBUF back")
}

/// Kill `proc` by its PID and read everything it said, to EOF on both pipes.
fn everything_said(mut proc: VoxProc) -> Vec<String> {
    let _ = proc.child.kill();
    let _ = proc.child.wait();
    let mut said = std::mem::take(&mut proc.seen);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(
            !left.is_zero(),
            "CANNOT MEASURE: {}'s output did not reach EOF within 30 s of its exit, so a notice \
             could still be unread. It said:\n{}",
            proc.name,
            said.join("\n")
        );
        match proc.lines.recv_timeout(left) {
            Ok(line) => said.push(line),
            Err(mpsc::RecvTimeoutError::Disconnected) => return said,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

#[test]
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; CI runs it in release"]
fn a_process_reports_the_1452_ceiling_exactly_when_its_buffer_is_short() {
    watchdog::arm();

    let granted = granted_receive_buffer();
    let short = granted < FULL_READ_BACK;
    eprintln!(
        "[proof] asked {ASKED} bytes, SO_RCVBUF read back {granted} ({} KiB), full reads back \
         {FULL_READ_BACK}: the grant is {}",
        granted / 1024,
        if short { "short" } else { "full" }
    );
    if cfg!(target_os = "macos") {
        assert!(
            !short,
            "CANNOT MEASURE: this Mac granted {granted} bytes of the 4 MiB asked for \
             (kern.ipc.maxsockbuf below 8 MiB?); the macOS arm of this proof is the full grant"
        );
    }
    if cfg!(target_os = "linux") {
        assert!(
            short,
            "CANNOT MEASURE: this Linux host granted the full {granted} bytes read back \
             (net.core.rmem_max at least 4 MiB?); the Linux arm of this proof is the short grant, \
             and a full one here would pass without ever measuring the 1452 notice"
        );
    }
    let expected_notice = format!(
        "vox: UDP receive buffer {} KiB: path-MTU ceiling 1452 bytes, not 8192",
        granted / 1024
    );

    let mut w = World::new(echo_service(), true);
    let guest_dir = w.guest_dir.clone();
    let (forward, at) = w.forward("forward", &guest_dir);
    // 64 KiB: enough to fill several datagrams at either ceiling, so every endpoint has carried
    // traffic when it is read.
    let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    let back = round_trip(at, &payload, Duration::from_secs(120))
        .expect("CANNOT MEASURE: the forward did not carry a connection through the world");
    assert!(
        back == payload,
        "CANNOT MEASURE: the echo came back altered ({} bytes)",
        back.len()
    );
    eprintln!("[proof] echoed {} bytes through the forward", back.len());

    let host = w.host.take().expect("the world's host");
    // Moved out (the temp dir stays with `w`) so it is killed last, after everything that
    // reaches through it.
    let anchor = w.anchor;
    let mut checked = 0;
    for proc in [forward, host, anchor] {
        let name = proc.name.clone();
        let said = everything_said(proc);
        let notices: Vec<&String> = said.iter().filter(|l| l.contains(NOTICE)).collect();
        eprintln!(
            "[proof] {name}: {} lines, {} path-MTU ceiling notice(s)",
            said.len(),
            notices.len()
        );
        if short {
            assert_eq!(
                notices.len(),
                1,
                "{name}: the OS granted {granted} bytes, short of {FULL_READ_BACK}, so {name} must \
                 run the 1452 ceiling and say so once. It said:\n{}",
                said.join("\n")
            );
            let line = notices[0].strip_prefix("! ").unwrap_or(notices[0]);
            assert!(
                line.starts_with(&expected_notice),
                "{name}: the notice must read {expected_notice:?}…, got {line:?}"
            );
        } else {
            assert!(
                notices.is_empty(),
                "{name}: the OS granted the full {granted} bytes, so {name} must run the 8192 \
                 ceiling and print no fallback notice. It printed:\n{}",
                notices
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 3, "anchor, host and forward were each read");
    eprintln!(
        "[proof] {checked} processes checked: the {} arm",
        if short {
            "short-grant (1452 notice)"
        } else {
            "full-grant (8192, no notice)"
        }
    );
}
