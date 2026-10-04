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
    if DaemonClient::open(&socket).await.is_ok() {
        return Ok(Daemon::Running);
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
    // Where this start's lines begin: a daemon that fails is reported in its own words, not in
    // an earlier start's.
    let from = std::fs::metadata(&log_path).map_or(0, |m| m.len());
    let mut child = cmd.spawn().map_err(|e| {
        AppError::Usage(format!(
            "could not start the daemon: {e}; its log is {}",
            log_path.display()
        ))
    })?;
    let t0 = Instant::now();
    let outcome = loop {
        if DaemonClient::open(&socket).await.is_ok() {
            break Ok(Daemon::Started);
        }
        // **A daemon that ended is not waited for** (S-2): it said why in its log, and the
        // client says it at once. One that ended because another took the lock first left
        // that one answering.
        if let Ok(Some(_)) = child.try_wait() {
            if DaemonClient::open(&socket).await.is_ok() {
                break Ok(Daemon::Running);
            }
            break Err(AppError::Usage(format!(
                "the daemon stopped as it started; it said (its log is {}):\n{}",
                log_path.display(),
                since(&log_path, from)
            )));
        }
        if t0.elapsed() >= START_WITHIN {
            break Err(AppError::Usage(format!(
                "the daemon did not start within {} s. Its log, {}, ends:\n{}",
                START_WITHIN.as_secs(),
                log_path.display(),
                tail(&log_path, 20)
            )));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    // Reaped on its own thread: the daemon outlives most clients, and one that ends first must
    // not stay a zombie for the client's life.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    outcome
}

/// What `path` holds past byte `from`: this start's lines.
fn since(path: &Path, from: u64) -> String {
    match std::fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(bytes.get(from as usize..).unwrap_or_default())
            .trim_end()
            .to_owned(),
        Err(e) => format!("(it could not be read: {e})"),
    }
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
