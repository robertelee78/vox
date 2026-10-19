//! Starting the account's daemon from a client (ADR-026 S-2).
//!
//! A client that may attach a node (a session-holding verb, an agent's hook, the TUI, `vox node
//! attach`) and finds no daemon starts `vox daemon` detached, with the daemon's stdout and stderr
//! captured privately during startup, then in the bounded `<data root>/.daemon/log`, and waits up to [`START_WITHIN`] for its
//! socket to answer. Two clients doing so at once end with one daemon: the second daemon cannot
//! take the account lock (D-1) and leaves, and both clients find the first one's socket.

use std::path::Path;
use std::time::{Duration, Instant};

use vox_core::node::daemonipc::DaemonClient;
use vox_core::node::paths::Account;

use crate::app::AppError;

/// How long a client waits for a daemon it started to answer (S-2).
pub const START_WITHIN: Duration = Duration::from_secs(15);

/// The whole time an agent hook gives a daemon probe and cold start before returning its bounded
/// answer. The daemon continues under its reaper and the next turn uses the saved registration.
const HOOK_WITHIN: Duration = Duration::from_millis(500);

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

/// What the hook's bounded daemon path found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookDaemon {
    /// A daemon greeted on this version.
    Ready,
    /// This hook started a daemon which is still preparing its control socket.
    Starting,
    /// The existing daemon socket did not answer within the hook's bound. It must not be raced by
    /// another daemon start.
    Unanswered,
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
        // **Root can use no daemon, and is told so at once** (ADR-026 C-1): starting one would
        // only wait out the start bound and blame the start.
        Err(e @ vox_core::error::Error::Ipc(vox_core::error::IpcHandshake::Root)) => {
            return Err(AppError::Usage(format!("{e}")))
        }
        Err(e @ vox_core::error::Error::Ipc(vox_core::error::IpcHandshake::Version { .. })) => {
            return Err(AppError::Usage(e.to_string()));
        }
        Err(_) => {}
    }
    start_daemon(&std::env::current_exe()?, account, listen, anchors).await
}

/// Find or begin a daemon for an agent hook, without making the model's turn wait for network
/// presence and computer management to finish. A newly started child is owned by a reaper thread
/// before this returns.
///
/// # Errors
/// As [`ensure_daemon`], when an existing daemon is unusable or the new child definitely failed
/// before the hook's short bound.
pub async fn ensure_daemon_for_hook(
    account: &Account,
    listen: std::net::SocketAddr,
    anchors: &[String],
) -> Result<HookDaemon, AppError> {
    let began = Instant::now();
    let socket = account.socket();
    let greeted = tokio::time::timeout(
        HOOK_WITHIN,
        DaemonClient::open_noting(&socket, Some(crate::client::say_daemon_waiting)),
    )
    .await;
    match greeted {
        Err(_) => return Ok(HookDaemon::Unanswered),
        Ok(Ok(_)) => return Ok(HookDaemon::Ready),
        Ok(Err(e @ vox_core::error::Error::Ipc(vox_core::error::IpcHandshake::Silent { .. }))) => {
            return Err(AppError::Usage(format!("{e}")))
        }
        Ok(Err(e @ vox_core::error::Error::Ipc(vox_core::error::IpcHandshake::Root))) => {
            return Err(AppError::Usage(format!("{e}")))
        }
        Ok(Err(e @ vox_core::error::Error::Ipc(vox_core::error::IpcHandshake::Version { .. }))) => {
            return Err(AppError::Usage(e.to_string()))
        }
        Ok(Err(_)) => {}
    }
    let remaining = HOOK_WITHIN.saturating_sub(began.elapsed());
    start_daemon_bounded(
        &std::env::current_exe()?,
        account,
        listen,
        anchors,
        remaining,
        true,
    )
    .await
    .map(|answer| answer.map_or(HookDaemon::Starting, |_| HookDaemon::Ready))
}

/// Start `exe` as `account`'s daemon, detached, listening on `listen`, and wait for it to answer:
/// [`ensure_daemon`]'s start, and `vox update`'s restart onto the vox it put in place.
///
/// # Errors
/// As [`ensure_daemon`].
pub async fn start_daemon(
    exe: &Path,
    account: &Account,
    listen: std::net::SocketAddr,
    anchors: &[String],
) -> Result<Daemon, AppError> {
    // This path serves interactive commands and update handoffs, which require a definitive
    // answer rather than an agent hook's bounded "still starting" result.
    start_daemon_bounded(exe, account, listen, anchors, START_WITHIN, false)
        .await
        .map(Option::unwrap)
}

/// Start the daemon and wait up to `within` for its socket. When `pending_ok`, an otherwise healthy
/// child still starting at that bound is `Ok(None)`. The child moves to its reaper immediately, so
/// returning early can neither abandon an unreaped child nor stop the daemon.
async fn start_daemon_bounded(
    exe: &Path,
    account: &Account,
    listen: std::net::SocketAddr,
    anchors: &[String],
    within: Duration,
    pending_ok: bool,
) -> Result<Option<Daemon>, AppError> {
    let socket = account.socket();
    let log_path = account.log_file();
    vox_core::node::paths::create_private_dir(&account.daemon_dir())
        .map_err(|e| AppError::Usage(e.to_string()))?;
    // Competing starters must not append raw lines to the winning daemon's log.
    // The winning daemon imports these startup diagnostics once it owns the lock.
    // An unlinked file also keeps a failed start's own output available to this caller.
    let startup = tempfile::tempfile()?;
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
        .stdout(startup.try_clone()?)
        .stderr(startup.try_clone()?);
    // Where this start's lines begin: a daemon that fails is reported in its own words, not in
    // an earlier start's.
    let from = std::fs::metadata(&log_path).map_or(0, |m| m.len());
    let mut child = cmd.spawn().map_err(|e| {
        AppError::Usage(format!(
            "could not start the daemon: {e}; its log is {}",
            log_path.display()
        ))
    })?;
    // Own the child from the moment it exists. In particular, an agent hook may return while this
    // daemon is still starting; dropping its bounded future must not leave the child unreaped.
    let (ended_tx, ended_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = ended_tx.send(child.wait());
    });
    let t0 = Instant::now();
    let mut lost = false;
    let outcome = loop {
        // Once a socket accepts but does not greet, `observe` has its own ten-second bound. Keep
        // that wait inside this caller's (shorter, for a hook) total bound too.
        let remaining = within.saturating_sub(t0.elapsed());
        if !remaining.is_zero()
            && matches!(
                tokio::time::timeout(remaining, DaemonClient::observe(&socket)).await,
                Ok(Ok(_))
            )
        {
            break Ok(Some(Daemon::Started));
        }
        // **A daemon that ended is not waited for** (S-2): it said why in its log, and the
        // client says it at once. One that ended because another took the lock first left
        // that one answering.
        if !lost {
            match ended_rx.try_recv() {
                Ok(Ok(_)) => {
                    let remaining = within.saturating_sub(t0.elapsed());
                    if !remaining.is_zero()
                        && matches!(
                            tokio::time::timeout(remaining, DaemonClient::observe(&socket)).await,
                            Ok(Ok(_))
                        )
                    {
                        break Ok(Some(Daemon::Running));
                    }
                    // **Lost the race to another start** (D-1, S-2): that daemon holds the lock
                    // and may not have bound the socket yet. Its socket is waited for within the
                    // same bound.
                    if startup_text(&startup).contains("a daemon is already running") {
                        lost = true;
                        continue;
                    }
                    break Err(AppError::Usage(format!(
                        "the daemon stopped as it started; it said (its log is {}):\n{}",
                        log_path.display(),
                        format_args!("{}\n{}", startup_text(&startup), since(&log_path, from))
                    )));
                }
                Ok(Err(e)) => {
                    break Err(AppError::Usage(format!(
                        "could not wait for the daemon process: {e}; its log is {}",
                        log_path.display()
                    )));
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    break Err(AppError::Usage(format!(
                        "could not observe the daemon process; its log is {}",
                        log_path.display()
                    )));
                }
            }
        }
        if t0.elapsed() >= within {
            if pending_ok {
                break Ok(None);
            }
            break Err(AppError::Usage(format!(
                "the daemon did not start within {} s. Its log, {}, ends:\n{}",
                within.as_secs(),
                log_path.display(),
                format_args!("{}\n{}", startup_text(&startup), tail(&log_path, 20))
            )));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    outcome
}

/// What `path` holds past byte `from`: this start's lines.
fn since(path: &Path, from: u64) -> String {
    match std::fs::read(path) {
        Ok(bytes) => String::from_utf8_lossy(bytes.get(from as usize..).unwrap_or(&bytes))
            .trim_end()
            .to_owned(),
        Err(e) => format!("(it could not be read: {e})"),
    }
}

/// Read startup output without moving the child's shared descriptor offset.
fn startup_text(file: &std::fs::File) -> String {
    use std::os::unix::fs::FileExt as _;
    let len = file.metadata().map_or(0, |m| m.len());
    let mut bytes = vec![0; usize::try_from(len.min(64 * 1024)).unwrap_or(0)];
    let read = file
        .read_at(&mut bytes, len.saturating_sub(64 * 1024))
        .unwrap_or(0);
    String::from_utf8_lossy(&bytes[..read])
        .trim_end()
        .to_owned()
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
