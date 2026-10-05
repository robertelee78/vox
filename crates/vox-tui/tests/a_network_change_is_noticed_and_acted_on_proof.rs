//! ADR-012 N-49–N-52 (#413, #414) — **a move to another network is noticed and acted on at once**,
//! through the shipped `vox`.
//!
//! The work is in `tests/netchange/network_change.py`: a daemon D, which listens on every address
//! and advertises A, and its peer P, which can reach D only at A, share a room. The machine then
//! gains B, routes by it, and loses A, as a real interface change the operating system says. Four
//! claims, each printed as a `CLAIM <name> ok|RED` line:
//!
//! - `redial`: with nothing sent, D holds a new connection to P within 3 s (it found the one it
//!   accepted stranded, closed it and dialled P again);
//! - `said`: D's log says the change exactly once, within 1 s of it;
//! - `status`: D's `vox status --json` names the change, and lists B and not A, within 2 s;
//! - `reads`: P reads a post D sends after the change within 5 s of it, not after
//!   `SILENCE_IS_DEATH` (30 s);
//! - `router` (Linux only): before the move, the default route alone changes its next hop, with no
//!   address coming or going, and D says that one change, naming the route, within 1 s (N-50,
//!   N-53). The macOS form does not stage it, since it would change the machine's own default
//!   route.
//!
//! **Linux** is the proof: an unprivileged user and network namespace, whose interfaces the
//! driver changes itself. **macOS** is opt-in heavy (`VOX_PROOF_NETCHANGE_MACOS=1`): the driver
//! makes `lo0` aliases and a host route with `sudo`, which the operator answers, and undoes them.
//!
//! **Mutations that must turn it red:** the event socket never opened (`NetWatch::open` returning
//! its error) → `said`, `status`, `redial` and `reads` red; no redial of the stranded peers
//! (`dial_stranded` doing nothing) → `redial` red; a default route's move ignored
//! (`NetChange::between` comparing the addresses only) → `router` red.
//!
//! A `vox` step on the way that fails is `PRODUCT:`; the driver's own failures (no `unshare`, a
//! crash) are APPARATUS, CANNOT MEASURE, never a pass.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::process::Command;

const VOX: &str = env!("CARGO_BIN_EXE_vox");

/// How many claims the driver makes here: `router` is staged on Linux only.
const CLAIMS: usize = if cfg!(target_os = "linux") { 5 } else { 4 };

/// Run the driver and judge what it printed.
fn drive() {
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/netchange/network_change.py"
    );
    let out = Command::new("python3")
        .args([script, VOX])
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run python3 {script}: {e}"));
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!("{said}");
    let claims: Vec<&str> = said.lines().filter(|l| l.contains(" CLAIM ")).collect();
    let red: Vec<&&str> = claims.iter().filter(|l| l.contains(" RED:")).collect();
    match out.status.code() {
        Some(0) => assert!(
            claims.len() == CLAIMS && red.is_empty() && said.contains("netchange PASS"),
            "APPARATUS: the driver exited 0 without {CLAIMS} claims ok and a PASS: {said}"
        ),
        Some(1) => panic!(
            "PRODUCT: a move to another network must be noticed and acted on at once; red: \
             {red:?}\n{said}"
        ),
        other => panic!("APPARATUS, CANNOT MEASURE: the driver ended {other:?}: {said}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "real daemons and a real network change in an unprivileged namespace; run in release"]
fn a_move_to_another_network_is_noticed_and_acted_on() {
    watchdog::arm();
    drive();
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "opt-in heavy: changes lo0 aliases and a host route with sudo; the operator runs it"]
fn a_move_to_another_network_is_noticed_and_acted_on() {
    watchdog::arm();
    if std::env::var("VOX_PROOF_NETCHANGE_MACOS").as_deref() != Ok("1") {
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr(),
            "HEAVY PROOF NOT RUN: a_move_to_another_network_is_noticed_and_acted_on on macOS \
             changes lo0 aliases and a host route with sudo; the operator runs it with \
             VOX_PROOF_NETCHANGE_MACOS=1 after `sudo -v`. The Linux form is the proof."
        );
        return;
    }
    drive();
}
