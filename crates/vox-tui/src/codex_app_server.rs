//! Keeping Codex's app-server running (the decider, 2026-10-06, as ctm does), so a plain `codex`
//! session can be followed and driven from Vox: `codex app-server daemon start`, which starts it
//! only when it is not running. Starting it runs no model (ADR-029 DR-7).
//!
//! It is running when its control socket, `$CODEX_HOME/app-server-control/app-server-control.sock`,
//! takes a connection: opened and closed, nothing sent. `vox setup` waits for that ([`ensure`]);
//! a hook, which must not hold Codex up, only asks for it ([`start_detached`]). Never `bootstrap`
//! (it installs durable management) and never `restart` (it interrupts work).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long [`ensure`] waits for the app-server to take a connection after asking it to start.
pub const START_WITHIN: Duration = Duration::from_secs(10);

/// The app-server's control socket under `codex_home`.
#[must_use]
pub fn control_socket(codex_home: &Path) -> PathBuf {
    codex_home
        .join("app-server-control")
        .join("app-server-control.sock")
}

/// The `CODEX_HOME` Codex runs under: its own variable, else Codex's default, `~/.codex`.
#[must_use]
pub fn codex_home_from_env() -> Option<PathBuf> {
    std::env::var_os("CODEX_HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|h| !h.is_empty())
                .map(|h| PathBuf::from(h).join(".codex"))
        })
}

/// Whether the app-server under `codex_home` takes a connection now.
#[must_use]
pub fn running(codex_home: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(control_socket(codex_home)).is_ok()
}

/// What [`ensure`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Started {
    /// It was running already.
    Already,
    /// It was started now.
    Now,
}

/// Make sure Codex's app-server under `codex_home` is running, starting it with `codex` (the
/// program found on `PATH`) if it is not, and waiting up to [`START_WITHIN`] for it to take a
/// connection.
///
/// # Errors
/// Why it is not running: `codex` could not be run, it refused, or it never took a connection.
pub fn ensure(codex: &Path, codex_home: &Path) -> Result<Started, String> {
    if running(codex_home) {
        return Ok(Started::Already);
    }
    let out = std::process::Command::new(codex)
        .args(["app-server", "daemon", "start"])
        .env("CODEX_HOME", codex_home)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("{} could not be run: {e}", codex.display()))?;
    if !out.status.success() {
        let said = String::from_utf8_lossy(&out.stderr);
        let said = said.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
        return Err(format!(
            "`codex app-server daemon start` failed ({}){}",
            out.status,
            if said.is_empty() {
                String::new()
            } else {
                format!(": {}", said.trim())
            }
        ));
    }
    let deadline = Instant::now() + START_WITHIN;
    while Instant::now() < deadline {
        if running(codex_home) {
            return Ok(Started::Now);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(format!(
        "it was asked to start, and {} took no connection within {} s",
        control_socket(codex_home).display(),
        START_WITHIN.as_secs()
    ))
}

/// Ask `codex` to start its app-server and do not wait: for a hook, which must not hold Codex up.
pub fn start_detached(codex: &Path) {
    let _ = std::process::Command::new(codex)
        .args(["app-server", "daemon", "start"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}
