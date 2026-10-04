//! Starting the account's daemon from a client (ADR-026 S-2).
//!
//! A client that may attach a node (a session-holding verb, an agent's hook, the TUI, `vox node
//! attach`) and finds no daemon starts `vox daemon` detached, with the daemon's stdout and stderr
//! in `<data root>/.daemon/log` from its first line, and waits up to [`START_WITHIN`] for its
//! socket to answer. Two clients doing so at once end with one daemon: the second daemon cannot
//! take the account lock (D-1) and leaves, and both clients find the first one's socket.

use std::path::Path;
use std::time::{Duration, Instant};

use vox_core::node::daemonipc::DaemonClient;
use vox_core::node::paths::Account;

use crate::app::AppError;

/// How long a client waits for a daemon it started to answer (S-2).
pub const START_WITHIN: Duration = Duration::from_secs(15);

/// The hidden flag a client starts the daemon with: no foreground node, its own session, and an
/// exit once it has no node and no connection (L-8).
pub const AS_DETACHED: &str = "--as-detached";

/// What [`ensure_daemon`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Daemon {
    /// One was running already.
    Running,
    /// This call started it.
    Started,
}

/// Make sure `account`'s daemon is running: if its socket does not answer, start one detached,
/// listening on `listen`, and wait for it.
///
/// # Errors
/// If the daemon cannot be started, or does not answer within [`START_WITHIN`]: the error says so
/// and quotes the end of the daemon's log.
pub async fn ensure_daemon(
    account: &Account,
    listen: std::net::SocketAddr,
    anchors: &[String],
) -> Result<Daemon, AppError> {
    let socket = account.socket();
    match DaemonClient::open_noting(&socket, Some(crate::client::say_daemon_waiting)).await {
        Ok(_) => return Ok(Daemon::Running),
        // **A daemon that took the connection and has not greeted is running**: busy, or stopped
        // (Ctrl-Z). Starting another would only meet its lock (D-1) and wait out the start bound
        // silently; this says what it is, and how to go on.
        Err(e @ vox_core::error::Error::Ipc(vox_core::error::IpcHandshake::Silent { .. })) => {
            return Err(AppError::Usage(format!("{e}")))
        }
        Err(_) => {}
    }
    let log_path = account.log_file();
    vox_core::node::paths::create_private_dir(&account.daemon_dir())
        .map_err(|e| AppError::Usage(e.to_string()))?;
    let log = open_log(&log_path)?;
    let exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("daemon")
        .arg(AS_DETACHED)
        .arg("--listen")
        .arg(listen.to_string())
        .arg("--data-dir")
        .arg(&account.data_root)
        .arg("--config-dir")
        .arg(&account.config_dir);
    for a in anchors {
        cmd.arg("--anchor").arg(a);
    }
    // The daemon reads no passphrase from the client's environment: every node it attaches is
    // given its passphrase over the socket (C-6).
    cmd.env_remove("VOX_IDENTITY_PASSPHRASE")
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    let mut child = cmd.spawn().map_err(|e| {
        AppError::Usage(format!(
            "could not start the daemon: {e}; its log is {}",
            log_path.display()
        ))
    })?;
    // Reaped on its own thread: the daemon outlives most clients, and one that ends first (the
    // second of two started at once) must not stay a zombie for the client's life.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    let t0 = Instant::now();
    while t0.elapsed() < START_WITHIN {
        if DaemonClient::open(&socket).await.is_ok() {
            return Ok(Daemon::Started);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(AppError::Usage(format!(
        "the daemon did not start within {} s. Its log, {}, ends:\n{}",
        START_WITHIN.as_secs(),
        log_path.display(),
        tail(&log_path, 20)
    )))
}

/// The daemon's log, appended to, `0600`.
fn open_log(path: &Path) -> Result<std::fs::File, AppError> {
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    o.open(path).map_err(|e| {
        AppError::Usage(format!(
            "could not open the daemon's log {}: {e}",
            path.display()
        ))
    })
}

/// The last `n` lines of `path`, or a note that it could not be read.
fn tail(path: &Path, n: usize) -> String {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let lines: Vec<&str> = text.lines().collect();
            lines[lines.len().saturating_sub(n)..].join("\n")
        }
        Err(e) => format!("(it could not be read: {e})"),
    }
}
