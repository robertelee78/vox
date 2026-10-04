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
//! **Both arms run on a Mac.** Its grant is full (`kern.ipc.maxsockbuf` 8 MiB by default; a
//! short one is CANNOT MEASURE), so the no-notice arm is measured first. Then the short arm is
//! staged without root: every `vox` — the daemons the clients start included — runs with the
//! test-only DYLD interposer
//! (`crates/vox-test-interpose`) and `VOX_INTERPOSE_RCVBUF_CAP` = [`CAP`], which makes each
//! `setsockopt(SO_RCVBUF, 4 MiB)` ask for 1 MiB instead. The kernel really grants 1 MiB and the
//! product reads it back, exactly as on a host whose `maxsockbuf` is small; the binary is
//! unchanged. Each process's own clamp is checked in the interposer's log, so a process the
//! interposer did not reach is CANNOT MEASURE, never a product verdict. On CI's ubuntu runner the
//! grant is short and the notice arm is measured; a Linux host that grants the full buffer is
//! CANNOT MEASURE, so the Linux arm can never pass silently on the no-notice path, which the
//! always-8192 mutant would also pass. All arms are in CI's release `--ignored` job, which runs on
//! both runners.
//!
//! **Mutations that must turn it red.**
//! - The ceiling ignores the buffer and is always 8192 (`mtu_ceiling_for` returns
//!   `MAX_UDP_PAYLOAD` whatever `effective` is; v0.2.9's first-tag rule): the compiler removes the
//!   notice's branch, so on Linux's short grant every process is silent and this goes red at the
//!   first one; on a Mac the staged 1 MiB arm goes red the same way.
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

#[cfg(target_os = "macos")]
#[path = "support/syscalls.rs"]
mod syscalls;

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

/// What the staged short arm on a Mac caps each `SO_RCVBUF` request at
/// (`VOX_INTERPOSE_RCVBUF_CAP`): 1 MiB, a quarter of what the product asks for.
#[cfg(target_os = "macos")]
const CAP: usize = 1024 * 1024;

/// The substring every fallback notice carries, and nothing else the product prints does.
const NOTICE: &str = "path-MTU ceiling";

/// Ask the OS for `asked` bytes of receive buffer, on the same kind of socket a Vox endpoint
/// uses, and read back what it granted.
fn granted_receive_buffer(asked: usize) -> usize {
    let socket =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("APPARATUS: bind a loopback UDP socket");
    let sock = socket2::SockRef::from(&socket);
    sock.set_recv_buffer_size(asked)
        .unwrap_or_else(|e| panic!("APPARATUS: ask for a {asked}-byte receive buffer: {e}"));
    sock.recv_buffer_size()
        .expect("APPARATUS: read SO_RCVBUF back")
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
            "APPARATUS, CANNOT MEASURE: {}'s output did not reach EOF within 30 s of its exit, so a notice \
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

/// Run one arm: a world, an echo through its forward, then every long-running process killed and
/// read. `granted` is what each process's socket was granted, as this test read it back; `short`
/// whether that is short of a full grant. `staged`, on a Mac's short arm, is the interposer's log,
/// in which each process must have recorded its own clamp.
fn run_arm(granted: usize, short: bool, staged: Option<&std::path::Path>) {
    let expected_notice = format!(
        "vox: UDP receive buffer {} KiB: path-MTU ceiling 1452 bytes, not 8192",
        granted / 1024
    );

    let mut w = World::new(echo_service(), true);
    let guest_dir = w.guest_dir.clone();
    let (mut forward, at) = w.forward("forward", &guest_dir);
    // 64 KiB: enough to fill several datagrams at either ceiling, so every endpoint has carried
    // traffic when it is read. A forward that cannot carry it is the product failing at the very
    // thing the ceiling is for, so it is a PRODUCT red, quoting both ends.
    let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    let back = match round_trip(at, &payload, Duration::from_secs(120)) {
        Ok(back) => back,
        Err(e) => panic!(
            "PRODUCT: the forward did not carry a 64 KiB echo within 120 s: {e}\n\
             vox forward said:\n{}\nvox serve said:\n{}",
            forward.transcript(),
            w.host.as_mut().map(|h| h.transcript()).unwrap_or_default()
        ),
    };
    assert!(
        back == payload,
        "PRODUCT: the echo came back altered ({} of {} bytes)\nvox forward said:\n{}",
        back.len(),
        payload.len(),
        forward.transcript()
    );
    eprintln!("[proof] echoed {} bytes through the forward", back.len());

    // Since ADR-026 (D-3) the UDP socket is each data root's daemon's: `vox forward` and
    // `vox serve` are clients, so the endpoints measured are the guest's and the host's daemons
    // (their pid from `.daemon/lock`, what they said from `.daemon/log`), and the anchor.
    let daemon_of = |name: &str, dir: &std::path::Path| -> (String, u32, Vec<String>) {
        let pid: u32 = std::fs::read_to_string(dir.join(".daemon").join("lock"))
            .ok()
            .and_then(|t| t.split_whitespace().next()?.parse().ok())
            .unwrap_or_else(|| panic!("PRODUCT (staging): no daemon holds {}", dir.display()));
        let log = std::fs::read_to_string(dir.join(".daemon").join("log")).unwrap_or_default();
        // The log holds every daemon this data root has run (one started for an attach before
        // this one, say): only the running daemon's lines, after the last one's "stopped".
        let lines: Vec<String> = log.lines().map(str::to_owned).collect();
        let from = lines
            .iter()
            .rposition(|l| l.starts_with("vox daemon: stopped"))
            .map_or(0, |i| i + 1);
        (name.to_owned(), pid, lines[from..].to_vec())
    };
    let guest_daemon = daemon_of("the guest's daemon", &w.guest_dir);
    let host_daemon = daemon_of("the host's daemon", &w.host_dir);
    drop(forward);
    drop(w.host.take());
    let anchor = w.anchor;
    let anchor_said = (
        anchor.name.clone(),
        anchor.child.id(),
        everything_said(anchor),
    );
    for (name, pid, said) in [guest_daemon, host_daemon, anchor_said] {
        if let Some(log) = staged {
            staged_for(log, pid, &name);
        }
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
                "PRODUCT: {name}: the OS granted {granted} bytes, short of {FULL_READ_BACK}, so \
                 {name} must run the 1452 ceiling and say so once. It said:\n{}",
                said.join("\n")
            );
            let line = notices[0].strip_prefix("! ").unwrap_or(notices[0]);
            assert!(
                line.starts_with(&expected_notice),
                "PRODUCT: {name}: the notice must read {expected_notice:?}…, got {line:?}"
            );
        } else {
            assert!(
                notices.is_empty(),
                "PRODUCT: {name}: the OS granted the full {granted} bytes, so {name} must run the \
                 8192 ceiling and print no fallback notice. It printed:\n{}",
                notices
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
    }
}

/// The staged short arm reached `pid`: the interposer's log holds a clamp of its `SO_RCVBUF`
/// request to [`CAP`]. Without it the process ran on the full grant, and its silence would be no
/// verdict on the product.
#[cfg(target_os = "macos")]
fn staged_for(log: &std::path::Path, pid: u32, name: &str) {
    let text = std::fs::read_to_string(log).unwrap_or_else(|e| {
        panic!(
            "APPARATUS, CANNOT MEASURE: no interposer log {}: {e}",
            log.display()
        )
    });
    let clamped = syscalls::parse(&text).iter().any(|e| {
        e.pid == pid
            && e.ret == 0
            && matches!(e.call, syscalls::Call::RcvBuf { asked, set }
                if asked > CAP as u64 && set == CAP as u64)
    });
    assert!(
        clamped,
        "APPARATUS, CANNOT MEASURE: {name} (pid {pid}) recorded no SO_RCVBUF request \
         clamped to {CAP} bytes, so the interposer did not stage its short grant"
    );
}

#[cfg(not(target_os = "macos"))]
fn staged_for(_log: &std::path::Path, _pid: u32, _name: &str) {
    unreachable!("APPARATUS: the staged arm runs only on a Mac");
}

#[test]
#[ignore = "production Argon2id profiles + a real PoW, driving the real binary; CI runs it in release"]
fn a_process_reports_the_1452_ceiling_exactly_when_its_buffer_is_short() {
    watchdog::arm();

    let granted = granted_receive_buffer(ASKED);
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
            "APPARATUS, CANNOT MEASURE: this Mac granted {granted} bytes of the 4 MiB asked for \
             (kern.ipc.maxsockbuf below 8 MiB?); the macOS arms of this proof start from a full \
             grant"
        );
    }
    if cfg!(target_os = "linux") {
        assert!(
            short,
            "APPARATUS, CANNOT MEASURE: this Linux host granted the full {granted} bytes read back \
             (net.core.rmem_max at least 4 MiB?); the Linux arm of this proof is the short grant, \
             and a full one here would pass without ever measuring the 1452 notice"
        );
    }
    run_arm(granted, short, None);
    eprintln!(
        "[proof] 3 processes checked: the {} arm",
        if short {
            "short-grant (1452 notice)"
        } else {
            "full-grant (8192, no notice)"
        }
    );

    #[cfg(target_os = "macos")]
    {
        let clamped = granted_receive_buffer(CAP);
        assert!(
            clamped < FULL_READ_BACK,
            "APPARATUS, CANNOT MEASURE: asking for {CAP} bytes read back {clamped}, not short of \
             {FULL_READ_BACK}"
        );
        let dir = tempfile::tempdir().expect("APPARATUS: no temp dir for the interposer log");
        let log = dir.path().join("rcvbuf.tsv");
        // Every `vox` the world starts inherits these, and only these processes are interposed.
        std::env::set_var("DYLD_INSERT_LIBRARIES", syscalls::interposer());
        std::env::set_var("VOX_INTERPOSE_RCVBUF_CAP", CAP.to_string());
        std::env::set_var("VOX_INTERPOSE_LOG", &log);
        eprintln!(
            "[proof] staged short arm: each SO_RCVBUF request capped at {CAP} bytes, which reads \
             back {clamped} ({} KiB)",
            clamped / 1024
        );
        run_arm(clamped, true, Some(&log));
        for k in [
            "DYLD_INSERT_LIBRARIES",
            "VOX_INTERPOSE_RCVBUF_CAP",
            "VOX_INTERPOSE_LOG",
        ] {
            std::env::remove_var(k);
        }
        eprintln!("[proof] 3 processes checked: the staged short-grant (1452 notice) arm");
    }
}
