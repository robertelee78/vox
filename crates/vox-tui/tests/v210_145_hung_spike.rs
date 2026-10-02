//! V210-145 (#364) SPIKE, never merged: a deliberately hung proof, so the hung-proof watchdog's
//! dump can be seen on CI ubuntu. It starts a `vox node` and a `vox daemon` (two descendants, as a
//! real proof would have) and then waits for ever. The watchdog, armed with a short budget by
//! `VOX_TEST_WATCHDOG_SECS`, must dump this process's threads and each descendant's, under its pid
//! and command line, before it kills them and aborts.
//!
//! With `VOX_SPIKE_PTRACER=1` (Linux), this process and each child declare any process may trace
//! them (`PR_SET_PTRACER_ANY`; the children do it between fork and exec), to learn whether that
//! lets the watchdog's `gdb` attach under Yama's `ptrace_scope=1` with no privilege.
//!
//! Built only with `--features test-knobs`, and `#[ignore]`d: it is red by design.

#![cfg(all(unix, feature = "test-knobs"))]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use world::{fingerprint, mkdir, IDENTITY, VOX};

fn ptracer_any() -> bool {
    std::env::var("VOX_SPIKE_PTRACER").as_deref() == Ok("1")
}

/// `vox <args>` in `dir`, its output to `log`; with [`ptracer_any`], the child declares any
/// process may trace it before it execs.
fn spawn(dir: &Path, args: &[&str], log: &Path) -> Child {
    let out = std::fs::File::create(log).expect("APPARATUS: a log file");
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .stdin(Stdio::null())
        .stdout(out.try_clone().expect("APPARATUS: a log file"))
        .stderr(out);
    #[cfg(target_os = "linux")]
    if ptracer_any() {
        use std::os::unix::process::CommandExt as _;
        // SAFETY: one prctl(2) between fork and exec, which allocates nothing and takes no lock.
        unsafe {
            cmd.pre_exec(|| {
                rustix::process::set_ptracer(rustix::process::PTracer::Any)
                    .map_err(std::io::Error::from)
            });
        }
    }
    cmd.spawn().expect("APPARATUS: spawn vox")
}

/// Wait up to 60 s for `log` to hold `want`.
fn until(log: &Path, want: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !std::fs::read_to_string(log)
        .unwrap_or_default()
        .contains(want)
    {
        assert!(
            Instant::now() < deadline,
            "APPARATUS: {} never said {want:?}",
            log.display()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[test]
#[ignore = "V210-145 spike: hangs on purpose, for the watchdog's dump; never in a gate"]
fn v210_145_a_hung_proof_with_two_vox_descendants() {
    #[cfg(target_os = "linux")]
    if ptracer_any() {
        rustix::process::set_ptracer(rustix::process::PTracer::Any)
            .expect("APPARATUS: PR_SET_PTRACER on this process");
    }
    watchdog::arm();
    let tmp = world::tempdir();
    let (node_dir, daemon_dir) = (tmp.path().join("node"), tmp.path().join("daemon"));
    for d in [&node_dir, &daemon_dir] {
        mkdir(&d.join("cfg"));
    }
    let node_log = tmp.path().join("node.log");
    let node = spawn(&node_dir, &["node", "--listen", "127.0.0.1:0"], &node_log);
    until(&node_log, "@/ip4/127.0.0.1/udp/");
    fingerprint(&daemon_dir, "daemon");
    let pass = tmp.path().join("pass");
    std::fs::write(&pass, format!("{IDENTITY}\n")).expect("APPARATUS: the passphrase file");
    let daemon_log = tmp.path().join("daemon.log");
    let daemon = spawn(
        &daemon_dir,
        &[
            "daemon",
            "--passphrase-file",
            pass.to_str().expect("a UTF-8 path"),
            "--listen",
            "127.0.0.1:0",
        ],
        &daemon_log,
    );
    until(&daemon_log, "control socket");
    eprintln!(
        "[spike] descendants up: vox node pid {}, vox daemon pid {}; ptracer-any {}; now hanging",
        node.id(),
        daemon.id(),
        ptracer_any()
    );
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}
