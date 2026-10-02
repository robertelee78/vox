//! SCRATCH (never committed): V210-158 (#381) re-measure. Each run: anchor, `vox serve` of a
//! loopback echo, a guest's `vox forward`, a 32 MiB echo through it, every process's receive
//! buffer request capped by the interposer at `VOX_158_CAP` bytes (unset: no cap), and each
//! process's QUIC path read from the throwaway `VOX_TEST_PATH_STATS` diag.

#![cfg(target_os = "macos")]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

#[path = "support/syscalls.rs"]
mod syscalls;

use std::sync::mpsc;
use std::time::{Duration, Instant};

use world::{echo_service, round_trip, VoxProc, World};

fn everything_said(mut proc: VoxProc) -> Vec<String> {
    let _ = proc.child.kill();
    let _ = proc.child.wait();
    let mut said = std::mem::take(&mut proc.seen);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(!left.is_zero(), "APPARATUS: {} output not at EOF", proc.name);
        match proc.lines.recv_timeout(left) {
            Ok(line) => said.push(line),
            Err(mpsc::RecvTimeoutError::Disconnected) => return said,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

#[test]
#[ignore = "scratch measurement"]
fn v210_158_remeasure() {
    watchdog::arm();
    let runs: usize = std::env::var("VOX_158_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    let cap: Option<usize> = std::env::var("VOX_158_CAP").ok().and_then(|v| v.parse().ok());
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("rcvbuf.tsv");
    std::env::set_var("VOX_TEST_PATH_STATS", "1");
    if let Some(cap) = cap {
        std::env::set_var("DYLD_INSERT_LIBRARIES", syscalls::interposer());
        std::env::set_var("VOX_INTERPOSE_RCVBUF_CAP", cap.to_string());
        std::env::set_var("VOX_INTERPOSE_LOG", &log);
    }
    let payload: Vec<u8> = (0..32 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let mut holed = 0;
    for run in 1..=runs {
        let mut w = World::new(echo_service(), true);
        let guest_dir = w.guest_dir.clone();
        let (forward, at) = w.forward("forward", &guest_dir);
        let t0 = Instant::now();
        let back = round_trip(at, &payload, Duration::from_secs(300));
        let took = t0.elapsed();
        let ok = back.as_ref().is_ok_and(|b| *b == payload);
        // A tick or two more so the last path line follows the transfer.
        std::thread::sleep(Duration::from_millis(2500));
        let host = w.host.take().unwrap();
        let anchor = w._anchor;
        let mut run_holes = 0u64;
        let mut summary = Vec::new();
        for proc in [forward, host, anchor] {
            let name = proc.name.clone();
            let pid = proc.child.id();
            let said = everything_said(proc);
            let staged = cap.is_none() || {
                let text = std::fs::read_to_string(&log).unwrap_or_default();
                syscalls::parse(&text).iter().any(|e| {
                    e.pid == pid && matches!(e.call, syscalls::Call::RcvBuf { set, .. } if Some(set as usize) == cap)
                })
            };
            let paths: Vec<(u64, u64)> = said
                .iter()
                .filter_map(|l| {
                    let l = l.strip_prefix("! ").unwrap_or(l);
                    let rest = l.strip_prefix("vox: PATH ")?;
                    let f: Vec<&str> = rest.split_whitespace().collect();
                    let mtu = f.get(2)?.parse().ok()?;
                    let bh = f.get(4)?.parse().ok()?;
                    Some((mtu, bh))
                })
                .collect();
            let max_mtu = paths.iter().map(|p| p.0).max().unwrap_or(0);
            let last_mtu = paths.last().map_or(0, |p| p.0);
            let holes = paths.iter().map(|p| p.1).max().unwrap_or(0);
            run_holes += holes;
            summary.push(format!(
                "{name}: staged {staged}, {} path lines, mtu max {max_mtu} last {last_mtu}, black holes {holes}",
                paths.len()
            ));
        }
        if run_holes > 0 {
            holed += 1;
        }
        eprintln!(
            "[158] run {run}/{runs} cap {cap:?}: echo {} in {took:?} ({:.0} MB/s); {}",
            if ok { "intact" } else { "FAILED" },
            (2.0 * payload.len() as f64) / took.as_secs_f64() / 1e6,
            summary.join("; ")
        );
    }
    eprintln!("[158] RESULT cap {cap:?}: {holed} of {runs} runs had a black hole");
}
