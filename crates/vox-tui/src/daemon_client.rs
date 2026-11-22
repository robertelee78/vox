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

/// How long a client waits for a daemon it started, or for a room first seen preparing.
pub const START_WITHIN: Duration = Duration::from_secs(15);

/// Cadence for a client checking whether the node has become available.
pub(crate) const NODE_WAIT_POLL: Duration = Duration::from_millis(50);

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
        Err(_) => {}
    }
    if restarting(account)? {
        if wait_for_restart(account, START_WITHIN).await? {
            return Ok(Daemon::Running);
        }
        return Err(AppError::Usage(format!(
            "the restarting daemon did not answer within {} s; see {} and retry",
            START_WITHIN.as_secs(),
            account.log_file().display()
        )));
    }
    #[cfg(target_os = "macos")]
    {
        let began = Instant::now();
        let manager = tokio::time::timeout(
            vox_core::node::ipc::ANSWER_WITHIN,
            crate::update::restart::pending_login_item(account),
        )
        .await
        .map_err(|_| AppError::Usage(
            "the login item did not answer the daemon startup check within 10 s; no daemon was started. Check Keep Running in Vox.app and the daemon log, then retry.".into(),
        ))??;
        if let Some(manager) = manager {
            manager.wait(&socket, None, true, began).await?;
            return Ok(Daemon::Running);
        }
    }
    start_daemon(
        &std::env::current_exe()?,
        account,
        listen,
        anchors,
        env!("CARGO_PKG_VERSION"),
    )
    .await
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
        Err(_) if restarting(account)? => {
            eprintln!("vox: waiting for the daemon restart");
            return Ok(HookDaemon::Starting);
        }
        Err(_) => return Ok(HookDaemon::Unanswered),
        Ok(Ok(_)) => return Ok(HookDaemon::Ready),
        Ok(Err(e @ vox_core::error::Error::Ipc(vox_core::error::IpcHandshake::Silent { .. }))) => {
            return Err(AppError::Core(e))
        }
        Ok(Err(e @ vox_core::error::Error::Ipc(vox_core::error::IpcHandshake::Root))) => {
            return Err(AppError::Core(e))
        }
        Ok(Err(
            e @ vox_core::error::Error::Ipc(vox_core::error::IpcHandshake::Protocol { .. }),
        )) => return Err(AppError::Core(e)),
        Ok(Err(_)) => {}
    }
    let remaining = HOOK_WITHIN.saturating_sub(began.elapsed());
    if restarting(account)? {
        return Ok(if wait_for_restart(account, remaining).await? {
            HookDaemon::Ready
        } else {
            HookDaemon::Starting
        });
    }
    #[cfg(target_os = "macos")]
    {
        let check = crate::update::restart::pending_login_item(account);
        let manager =
            tokio::time::timeout(HOOK_WITHIN.saturating_sub(began.elapsed()), check).await;
        match manager {
            Ok(Ok(None)) => {}
            Ok(Ok(Some(_))) => {
                eprintln!("vox: waiting for the daemon restart");
                return Ok(HookDaemon::Starting);
            }
            Err(_) => {
                eprintln!("vox: the login-item startup check did not finish; no daemon was started; retry on the next turn");
                return Ok(HookDaemon::Unanswered);
            }
            Ok(Err(e)) => return Err(e),
        }
    }
    let remaining = HOOK_WITHIN.saturating_sub(began.elapsed());
    start_daemon_bounded(
        &std::env::current_exe()?,
        account,
        listen,
        anchors,
        env!("CARGO_PKG_VERSION"),
        remaining,
        Start::Hook,
    )
    .await
    .map(|answer| answer.map_or(HookDaemon::Starting, |_| HookDaemon::Ready))
}

/// Start `exe` as `account`'s daemon, detached, listening on `listen`, and wait for `expected_version`:
/// [`ensure_daemon`]'s current version, or `vox update`'s selected upgrade or rollback version.
///
/// # Errors
/// As [`ensure_daemon`].
pub async fn start_daemon(
    exe: &Path,
    account: &Account,
    listen: std::net::SocketAddr,
    anchors: &[String],
    expected_version: &str,
) -> Result<Daemon, AppError> {
    // This path serves interactive commands and update handoffs, which require a definitive
    // answer rather than an agent hook's bounded "still starting" result.
    start_daemon_bounded(
        exe,
        account,
        listen,
        anchors,
        expected_version,
        START_WITHIN,
        Start::Client,
    )
    .await
    .map(Option::unwrap)
}

/// The replacement owns the handoff before it signals the old daemon.
pub(crate) async fn replace_daemon(
    exe: &Path,
    account: &Account,
    listen: std::net::SocketAddr,
    anchors: &[String],
    expected_version: &str,
    old_pid: u32,
    within: Duration,
) -> Result<(), AppError> {
    start_daemon_bounded(
        exe,
        account,
        listen,
        anchors,
        expected_version,
        within,
        Start::Replacement(old_pid),
    )
    .await?;
    Ok(())
}

/// This flock is held by the replacement until it serves, not by its mortal caller.
pub(crate) fn restart_lock(account: &Account) -> Result<std::fs::File, AppError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    vox_core::node::layout::refuse_old_layout(account)
        .map_err(|e| AppError::Usage(e.to_string()))?;
    vox_core::node::paths::create_private_dir(&account.daemon_dir())
        .map_err(|e| AppError::Usage(e.to_string()))?;
    Ok(std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(account.restart_lock_file())?)
}

pub(crate) fn restarting(account: &Account) -> Result<bool, AppError> {
    let file = restart_lock(account)?;
    match file.try_lock_shared() {
        Ok(()) => Ok(false),
        Err(std::fs::TryLockError::WouldBlock) => Ok(true),
        Err(std::fs::TryLockError::Error(e)) => Err(AppError::Usage(format!(
            "cannot check the daemon restart: {e}"
        ))),
    }
}

async fn wait_for_restart(account: &Account, within: Duration) -> Result<bool, AppError> {
    eprintln!("vox: waiting for the daemon restart");
    let began = Instant::now();
    loop {
        match tokio::time::timeout(
            within.saturating_sub(began.elapsed()),
            DaemonClient::open(&account.socket()),
        )
        .await
        {
            Ok(Ok(_)) => return Ok(true),
            Ok(Err(vox_core::error::Error::Ipc(vox_core::error::IpcHandshake::Unreachable {
                ..
            }))) => {}
            Ok(Err(error)) => return Err(AppError::Core(error)),
            Err(_) => return Ok(false),
        }
        if began.elapsed() >= within {
            return Ok(false);
        }
        tokio::time::sleep(NODE_WAIT_POLL).await;
    }
}

#[derive(Clone, Copy)]
enum Start {
    Client,
    Hook,
    Replacement(u32),
}

/// Start the daemon and wait up to `within` for its socket. For a hook, an otherwise healthy
/// child still starting at that bound is `Ok(None)`. The child moves to its reaper immediately, so
/// returning early can neither abandon an unreaped child nor stop the daemon.
async fn start_daemon_bounded(
    exe: &Path,
    account: &Account,
    listen: std::net::SocketAddr,
    anchors: &[String],
    expected_version: &str,
    within: Duration,
    start: Start,
) -> Result<Option<Daemon>, AppError> {
    let pending_ok = matches!(start, Start::Hook);
    let replacing = match start {
        Start::Replacement(pid) => Some(pid),
        Start::Client | Start::Hook => None,
    };
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
    if let Some(pid) = replacing {
        cmd.arg("--replace-pid").arg(pid.to_string());
    }
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
                Ok(Ok(daemon)) if daemon.version == expected_version
                    && Some(daemon.pid) != replacing
                    && (expected_version != env!("CARGO_PKG_VERSION")
                        || daemon.protocol == vox_core::node::ipc::PROTOCOL_VERSION)
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
                            Ok(Ok(daemon)) if daemon.version == expected_version
                                && Some(daemon.pid) != replacing
                                && (expected_version != env!("CARGO_PKG_VERSION")
                                    || daemon.protocol == vox_core::node::ipc::PROTOCOL_VERSION)
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
        tokio::time::sleep(NODE_WAIT_POLL).await;
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
