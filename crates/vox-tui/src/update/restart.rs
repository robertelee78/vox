//! After `vox update` (or `--rollback`) puts a vox in place, Vox.app on a Mac or the standalone
//! binary elsewhere, the account's vox daemon is restarted onto it (decider, 2026-10-07: "I know
//! not to update something if I'm in the middle of a transaction"), so nothing keeps running the
//! version the update replaced.
//!
//! The daemon receives its normal termination signal, as `vox daemon`'s own stop does: every node detaches and its keys
//! are wiped. The new one attaches again every node whose passphrase it keeps (`--keep`, or the
//! Keychain the app stores it in). Any other node that was attached stays detached, and the update
//! names each one with the command that attaches it again.
//!
//! How the daemon was started decides how it is started again:
//!
//! - by a client (`--as-detached`): the new vox is started the same way, on the same address and
//!   anchors;
//! - as the app's login item (macOS): launchd starts it again, from the bundle now in place;
//! - as the main process of a systemd user unit (Linux): `systemctl --user restart` that unit;
//! - in a terminal, or by anything else (`vox daemon`): the installed binary starts it detached
//!   on the same configured address and anchors; the terminal's old daemon ends.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use vox_core::node::daemonipc::{DaemonClient, DaemonObservation, NodeState};
use vox_core::node::paths::{Account, NodeName};

/// How long the old daemon is given to stop: it detaches every node first, each within its own
/// bound (`SHUTDOWN_PATIENCE`).
const STOP_WITHIN: Duration = Duration::from_secs(30);
/// How long the new daemon is given to attach again the nodes it keeps.
const REATTACH_WITHIN: Duration = Duration::from_secs(30);
/// The app's login item (`Contents/Library/LaunchAgents/us.vox.daemon.plist`).
#[cfg(target_os = "macos")]
const LOGIN_ITEM: &str = "us.vox.daemon";

/// How the running daemon was started, and so how it is started again.
#[derive(serde::Serialize, serde::Deserialize)]
pub(super) enum Started {
    /// By a client.
    ByClient,
    /// By launchd, as the app's login item: its `gui/<uid>/<label>` target.
    #[cfg(target_os = "macos")]
    LoginItem(String),
    /// By systemd, as the main process of this user unit.
    #[cfg(target_os = "linux")]
    UserUnit(String),
    /// In a terminal, or by anything else.
    ByHand,
}

/// Original daemon startup authority, captured before a transition can stop it.
#[derive(serde::Serialize, serde::Deserialize)]
pub(super) enum DaemonIntent {
    Absent,
    Running {
        started: Started,
        listen: std::net::SocketAddr,
        anchors: Vec<String>,
        attached: Vec<String>,
    },
}

#[cfg(target_os = "macos")]
impl DaemonIntent {
    pub(super) fn is_valid(&self) -> bool {
        match self {
            Self::Absent => true,
            Self::Running {
                started,
                anchors,
                attached,
                ..
            } => {
                let authority = match started {
                    Started::LoginItem(target) => {
                        *target
                            == format!("gui/{}/{LOGIN_ITEM}", rustix::process::getuid().as_raw())
                    }
                    Started::ByClient | Started::ByHand => true,
                };
                authority
                    && anchors
                        .iter()
                        .all(|anchor| !anchor.is_empty() && !anchor.contains('\0'))
                    && attached.iter().all(|name| NodeName::parse(name).is_ok())
            }
        }
    }
}

/// Identity of the exact daemon observed when its startup intent was captured.
#[cfg(target_os = "macos")]
#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct DaemonProcess {
    pid: u32,
    start_seconds: u64,
    start_microseconds: u64,
}

#[cfg(target_os = "macos")]
impl DaemonProcess {
    pub(super) fn is_valid(&self) -> bool {
        self.pid > 1
            && self.pid <= i32::MAX as u32
            && self.start_seconds > 0
            && self.start_microseconds < 1_000_000
    }
}

#[cfg(target_os = "macos")]
fn daemon_process(pid: u32) -> Result<DaemonProcess, crate::app::AppError> {
    let raw = i32::try_from(pid)
        .map_err(|_| crate::app::AppError::Usage("invalid daemon process id".into()))?;
    let info = libproc::proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(raw, 0).map_err(|e| {
        crate::app::AppError::Usage(format!("cannot inspect daemon pid {pid}: {e}"))
    })?;
    Ok(DaemonProcess {
        pid,
        start_seconds: info.pbi_start_tvsec,
        start_microseconds: info.pbi_start_tvusec,
    })
}

#[cfg(target_os = "macos")]
fn same_daemon_process(a: &DaemonProcess, b: &DaemonProcess) -> bool {
    a.pid == b.pid
        && a.start_seconds == b.start_seconds
        && a.start_microseconds == b.start_microseconds
}

#[cfg(target_os = "macos")]
fn require_daemon_executable(pid: u32, helper: &Path) -> Result<(), crate::app::AppError> {
    use crate::app::AppError;
    let expected = std::fs::canonicalize(helper).map_err(|e| {
        AppError::Usage(format!(
            "cannot inspect installed daemon helper {}: {e}",
            helper.display()
        ))
    })?;
    let actual = crate::claude_injector::exe_of(pid)
        .ok_or_else(|| AppError::Usage(format!("cannot inspect executable of daemon pid {pid}")))?;
    if actual != expected {
        return Err(AppError::Usage(format!(
            "daemon pid {pid} runs {} rather than installed helper {}; refusing to stop it",
            actual.display(),
            expected.display()
        )));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn capture_daemon_state(
    account: &Account,
    helper: &Path,
) -> Result<(DaemonIntent, Option<DaemonProcess>), crate::app::AppError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let daemon = match DaemonClient::observe(&account.socket()).await {
            Ok(daemon) => daemon,
            Err(vox_core::error::Error::Ipc(vox_core::error::IpcHandshake::Unreachable {
                ..
            })) => return Ok((DaemonIntent::Absent, None)),
            Err(e) => return Err(crate::app::AppError::Usage(e.to_string())),
        };
        let process = daemon_process(daemon.pid)?;
        require_daemon_executable(daemon.pid, helper)?;
        let words = arguments(daemon.pid);
        if words.is_empty() {
            return Err(crate::app::AppError::Usage(
                "cannot inspect the original daemon's startup arguments".into(),
            ));
        }
        let value = words
            .windows(2)
            .find(|words| words[0] == "--listen")
            .map(|words| words[1].as_str())
            .or_else(|| words.iter().find_map(|word| word.strip_prefix("--listen=")))
            .unwrap_or(crate::client::DEFAULT_LISTEN);
        let listen = value.parse().map_err(|e| {
            crate::app::AppError::Usage(format!(
                "cannot parse the original daemon's listen address: {e}"
            ))
        })?;
        let anchors = words
            .iter()
            .enumerate()
            .filter_map(|(index, word)| {
                if word == "--anchor" {
                    words.get(index + 1).cloned()
                } else {
                    word.strip_prefix("--anchor=").map(str::to_owned)
                }
            })
            .collect();
        let started = how_started(daemon.pid);
        let again = DaemonClient::observe(&account.socket())
            .await
            .map_err(|e| {
                crate::app::AppError::Usage(format!(
                    "daemon changed while capturing startup intent: {e}"
                ))
            })?;
        if again.pid != process.pid || !same_daemon_process(&process, &daemon_process(again.pid)?) {
            return Err(crate::app::AppError::Usage(
                "daemon changed while capturing startup intent".into(),
            ));
        }
        require_daemon_executable(again.pid, helper)?;
        Ok((
            DaemonIntent::Running {
                started,
                listen,
                anchors,
                attached: daemon
                    .attached
                    .iter()
                    .map(|node| node.name.as_str().to_owned())
                    .collect(),
            },
            Some(process),
        ))
    })
}

/// Stop only the daemon whose startup intent and process identity were captured.
#[cfg(target_os = "macos")]
pub(super) fn stop_captured_daemon(
    account: &Account,
    intent: &DaemonIntent,
    process: Option<&DaemonProcess>,
    helper: &Path,
) -> Result<(), crate::app::AppError> {
    use crate::app::AppError;
    if process.is_some_and(|process| !process.is_valid()) {
        return Err(AppError::Usage(
            "invalid captured daemon process identity".into(),
        ));
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let daemon = match DaemonClient::observe(&account.socket()).await {
            Ok(daemon) => Some(daemon),
            Err(vox_core::error::Error::Ipc(vox_core::error::IpcHandshake::Unreachable { .. })) => None,
            Err(e) => return Err(AppError::Usage(format!("cannot observe daemon before stopping it: {e}"))),
        };
        match (intent, process, daemon) {
            (DaemonIntent::Absent, None, None) => Ok(()),
            (DaemonIntent::Running { .. }, Some(expected), None) => {
                if gone_within(expected.pid, Duration::ZERO).await {
                    Ok(())
                } else {
                    Err(AppError::Usage("captured daemon process is still present but its socket is unreachable".into()))
                }
            }
            (DaemonIntent::Running { .. }, Some(expected), Some(current))
                if current.pid == expected.pid
                    && same_daemon_process(expected, &daemon_process(current.pid)?) =>
            {
                require_daemon_executable(current.pid, helper)?;
                if let DaemonIntent::Running { started: Started::LoginItem(target), .. } = intent {
                    if !matches!(how_started(current.pid), Started::LoginItem(actual) if actual == *target) {
                        return Err(AppError::Usage(
                            "the captured login-item daemon is no longer launchd's matching job".into(),
                        ));
                    }
                }
                if !same_daemon_process(expected, &daemon_process(current.pid)?) {
                    return Err(AppError::Usage("daemon changed before it could be stopped".into()));
                }
                let pid = i32::try_from(expected.pid).ok()
                    .and_then(rustix::process::Pid::from_raw)
                    .ok_or_else(|| AppError::Usage("invalid daemon process id".into()))?;
                rustix::process::kill_process(pid, rustix::process::Signal::TERM)
                    .map_err(|e| AppError::Usage(format!("the captured daemon could not be stopped: {e}")))?;
                if !gone_within(expected.pid, STOP_WITHIN).await {
                    return Err(AppError::Usage(format!(
                        "the captured daemon (pid {}) did not stop within {} s",
                        expected.pid, STOP_WITHIN.as_secs()
                    )));
                }
                match DaemonClient::observe(&account.socket()).await {
                    Err(vox_core::error::Error::Ipc(vox_core::error::IpcHandshake::Unreachable { .. })) => Ok(()),
                    Ok(_) => Err(AppError::Usage("a daemon appeared after the captured daemon stopped".into())),
                    Err(e) => Err(AppError::Usage(format!("cannot confirm daemon stopped: {e}"))),
                }
            }
            _ => Err(AppError::Usage(
                "daemon identity changed or was not captured; refusing to stop it".into(),
            )),
        }
    })
}

/// Restart the account's daemon, if one runs, onto `helper`, the vox now in place, and say what that did: the version it runs, and each node it no longer has attached.
///
/// Returns the nodes it left detached.
/// A failed restart is an error, not a successful handoff with no detached nodes.
pub(super) fn restart_daemon(
    helper: &Path,
    now: &str,
) -> Result<Vec<NodeName>, crate::app::AppError> {
    let account = Account::of(None, None)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(restart_checked(&account, helper, now, false, None))
}

/// Restart a particular account and propagate failures to the app handoff.
#[cfg(target_os = "macos")]
pub(super) fn restart_daemon_checked(
    account: &Account,
    helper: &Path,
    now: &str,
    intent: Option<&DaemonIntent>,
) -> Result<Vec<NodeName>, crate::app::AppError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let required = matches!(intent, Some(DaemonIntent::Running { .. }));
    let detached = rt.block_on(restart_checked(account, helper, now, required, intent))?;
    say_detached(&detached);
    Ok(detached)
}

/// The explicit repair offered when a client finds a daemon of a different release.
pub(crate) fn restart_current(account: &Account) -> Result<(), crate::app::AppError> {
    let helper = std::env::current_exe()?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let detached = rt.block_on(restart_checked(
        account,
        &helper,
        env!("CARGO_PKG_VERSION"),
        true,
        None,
    ))?;
    say_detached(&detached);
    Ok(())
}

async fn restart_checked(
    account: &Account,
    helper: &Path,
    now: &str,
    start_if_absent: bool,
    intent: Option<&DaemonIntent>,
) -> Result<Vec<NodeName>, crate::app::AppError> {
    use crate::app::AppError;
    let default_listen = crate::client::DEFAULT_LISTEN.parse().map_err(|e| {
        AppError::Usage(format!("the default daemon listen address is invalid: {e}"))
    })?;
    let socket = account.socket();
    // Read only Hello, then close. An optional absent daemon needs no node inspection.
    let before = match DaemonClient::observe(&socket).await {
        Ok(daemon) => Some(daemon),
        Err(vox_core::error::Error::Ipc(vox_core::error::IpcHandshake::Unreachable { .. })) => {
            if !start_if_absent {
                return Ok(Vec::new());
            }
            None
        }
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    let mut kept = crate::host::read_attach_file(&account.attach_file())
        .into_iter()
        .map(|(name, _)| name)
        .collect::<Vec<_>>();
    // No-passphrase nodes also start themselves, even after Forget. Wait for their actual
    // startup before reporting the update complete.
    for name in account.nodes_on_disk() {
        let paths = account.node_paths_as_they_are(&name);
        let headless = !paths.vault_file().is_file()
            && vox_core::node::headless::identity_file(&paths).is_file();
        if (headless || !paths.requires_passphrase()?) && !kept.contains(&name) {
            kept.push(name);
        }
    }
    #[cfg(target_os = "macos")]
    if let (Some(intent), Some(existing)) = (intent, before.as_ref()) {
        let DaemonIntent::Running {
            started, attached, ..
        } = intent
        else {
            return Err(AppError::Usage(
                "a daemon appeared although the captured startup intent was absent".into(),
            ));
        };
        if existing.version != now {
            return Err(AppError::Usage(format!(
                "an unexpected daemon runs vox {} rather than {now}; refusing to stop it",
                existing.version
            )));
        }
        let process = daemon_process(existing.pid)?;
        require_daemon_executable(existing.pid, helper)?;
        if let Started::LoginItem(target) = started {
            if !matches!(how_started(existing.pid), Started::LoginItem(actual) if actual == *target)
            {
                return Err(AppError::Usage(
                    "the replacement daemon is not the captured launchd login item".into(),
                ));
            }
        }
        let after = wait_for_replacement(account, now, None, &kept).await?;
        if after.pid != process.pid || !same_daemon_process(&process, &daemon_process(after.pid)?) {
            return Err(AppError::Usage(
                "the replacement daemon changed during handoff".into(),
            ));
        }
        require_daemon_executable(after.pid, helper)?;
        println!(
            "the vox daemon runs vox {} (pid {}), and its remembered nodes are Ready",
            after.version, after.pid
        );
        let missing = attached
            .iter()
            .filter(|name| {
                !after.attached.iter().any(|node| {
                    node.name.as_str() == name.as_str() && node.state == NodeState::Attached
                })
            })
            .map(|name| NodeName::parse(name).map_err(|e| AppError::Usage(e.to_string())))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(missing);
    }
    let Some(before) = before else {
        let attached = if let Some(DaemonIntent::Running {
            started,
            listen,
            anchors,
            attached,
        }) = intent
        {
            start_selected(account, helper, *listen, anchors, started, now).await?;
            attached.as_slice()
        } else {
            crate::daemon_client::start_daemon(helper, account, default_listen, &[], now).await?;
            &[]
        };
        let after = wait_for_replacement(account, now, None, &kept).await?;
        #[cfg(target_os = "macos")]
        if intent.is_some() {
            require_daemon_executable(after.pid, helper)?;
        }
        println!("the vox daemon was started and runs vox {} (pid {}), and its remembered nodes are Ready",
                after.version, after.pid);
        let missing = attached
            .iter()
            .filter(|name| {
                !after.attached.iter().any(|node| {
                    node.name.as_str() == name.as_str() && node.state == NodeState::Attached
                })
            })
            .map(|name| NodeName::parse(name).map_err(|e| AppError::Usage(e.to_string())))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(missing);
    };
    let started = how_started(before.pid);
    let words = arguments(before.pid);
    let anchors = words
        .windows(2)
        .filter(|w| w[0] == "--anchor")
        .map(|w| w[1].clone())
        .collect::<Vec<_>>();
    let listen = words
        .windows(2)
        .find(|w| w[0] == "--listen")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(default_listen);
    let attached = before
        .attached
        .iter()
        .map(|n| n.name.clone())
        .collect::<Vec<_>>();
    // The updater process still runs its original release after the binary is replaced. It
    // can ask its matching daemon for the names of services/forwards about to end. A repair
    // from a different release reads Hello only, as every other mismatched client must.
    let held = if before.version == env!("CARGO_PKG_VERSION") {
        match tokio::time::timeout(Duration::from_secs(10), held_names(account, &attached)).await {
            Ok(Ok(names)) => names,
            result => {
                let why = match result {
                    Ok(Err(e)) => e.to_string(),
                    Err(_) => "the daemon did not answer within 10 s".to_owned(),
                    Ok(Ok(_)) => unreachable!("successful snapshot handled above"),
                };
                println!(
                    "held session names could not be determined for nodes {}: {why}; restarting the daemon",
                    attached.iter().map(NodeName::as_str).collect::<Vec<_>>().join(", ")
                );
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    // A normal termination signal follows the daemon's own bounded shutdown path. Its pid
    // came from this user's authenticated control socket, never a stale lock-file pid.
    #[cfg(target_os = "linux")]
    let by_unit = matches!(started, Started::UserUnit(_));
    #[cfg(not(target_os = "linux"))]
    let by_unit = false;
    if !by_unit {
        let pid = i32::try_from(before.pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .ok_or_else(|| AppError::Usage("the daemon gave an invalid process id".into()))?;
        rustix::process::kill_process(pid, rustix::process::Signal::TERM)
            .map_err(|e| AppError::Usage(format!("the daemon could not be stopped: {e}")))?;
        if !gone_within(before.pid, STOP_WITHIN).await {
            return Err(AppError::Usage(format!(
                "the daemon (pid {}) did not stop within {} s; it still runs vox {}",
                before.pid,
                STOP_WITHIN.as_secs(),
                before.version,
            )));
        }
    }
    start_selected(account, helper, listen, &anchors, &started, now).await?;
    let after = wait_for_replacement(account, now, Some(before.pid), &kept).await?;
    let ended = match (held.is_empty(), attached.is_empty()) {
        (false, _) => format!(
            "; held sessions {} ended, along with other connections on nodes {}",
            held.join(", "),
            attached
                .iter()
                .map(NodeName::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        (true, false) => format!(
            "; any held sessions on nodes {} ended",
            attached
                .iter()
                .map(NodeName::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        (true, true) => String::new(),
    };
    println!("the vox daemon was restarted and runs vox {} (pid {}), and its remembered nodes are Ready{ended}",
        after.version, after.pid);
    let missing = attached
        .into_iter()
        .filter(|a| {
            !after
                .attached
                .iter()
                .any(|n| &n.name == a && n.state == NodeState::Attached)
        })
        .collect::<Vec<_>>();
    Ok(missing)
}

async fn start_selected(
    account: &Account,
    helper: &Path,
    listen: std::net::SocketAddr,
    anchors: &[String],
    started: &Started,
    expected_version: &str,
) -> Result<(), crate::app::AppError> {
    use crate::app::AppError;
    match started {
        #[cfg(target_os = "macos")]
        Started::LoginItem(target) => {
            let out = Command::new("/bin/launchctl")
                .args(["kickstart", target])
                .bounded_output()?;
            if !out.status.success() {
                return Err(AppError::Usage(format!(
                    "launchd did not restart the daemon: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
            }
        }
        #[cfg(target_os = "linux")]
        Started::UserUnit(unit) => {
            let out = Command::new("systemctl")
                .args(["--user", "restart", unit])
                .bounded_output()?;
            if !out.status.success() {
                return Err(AppError::Usage(format!(
                    "systemd did not restart the daemon: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
            }
        }
        Started::ByClient | Started::ByHand => {
            crate::daemon_client::start_daemon(helper, account, listen, anchors, expected_version)
                .await?;
        }
    }
    Ok(())
}

async fn wait_for_replacement(
    account: &Account,
    now: &str,
    previous_pid: Option<u32>,
    kept: &[NodeName],
) -> Result<DaemonObservation, crate::app::AppError> {
    use crate::app::AppError;
    let socket = account.socket();
    let t0 = Instant::now();
    let mut preparing = None;
    // Keep the authenticated replacement continuously observed while remembered nodes prepare.
    let mut _held_after = None;
    loop {
        if let Ok(daemon) = DaemonClient::observe_held(&socket).await {
            if daemon.version == now
                && (now != env!("CARGO_PKG_VERSION")
                    || daemon.protocol == vox_core::node::ipc::PROTOCOL_VERSION)
                && Some(daemon.pid) != previous_pid
            {
                let pending =
                    kept.iter()
                        .filter(|name| {
                            !daemon.attached.iter().any(|node| {
                                node.name == **name && node.state == NodeState::Attached
                            })
                        })
                        .map(NodeName::as_str)
                        .collect::<Vec<_>>();
                if pending.is_empty() {
                    return Ok(daemon);
                }
                preparing = Some(pending.join(", "));
                _held_after = Some(daemon);
            }
        }
        if t0.elapsed() >= REATTACH_WITHIN {
            return Err(AppError::Usage(match preparing {
                Some(nodes) => format!(
                    "the new daemon answered on vox {now}, but these remembered nodes did not become Ready within {} s: {nodes}; its log is {}",
                    REATTACH_WITHIN.as_secs(), account.log_file().display()),
                None => format!(
                    "the daemon did not return with its remembered nodes Ready on vox {now} within {} s; its log is {}",
                    REATTACH_WITHIN.as_secs(), account.log_file().display()),
            }));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Named services and forwards on the matching daemon, before ending their held connections.
async fn held_names(
    account: &Account,
    nodes: &[NodeName],
) -> Result<Vec<String>, crate::app::AppError> {
    use vox_core::node::ipc::{Frame, IpcClient, NodeSocket, Request};
    let mut names = Vec::new();
    for node in nodes {
        let at = NodeSocket::one_shot(account.socket(), node.clone());
        let report = vox_core::node::status::request(&at)
            .await
            .map_err(|e| crate::app::AppError::Usage(e.to_string()))?;
        let report: serde_json::Value = serde_json::from_str(&report).map_err(|e| {
            crate::app::AppError::Usage(format!("the daemon's status did not parse: {e}"))
        })?;
        let mut client = IpcClient::open_at(&at)
            .await
            .map_err(|e| crate::app::AppError::Usage(e.to_string()))?;
        if let Some(rooms) = report["rooms"].as_array() {
            for room in rooms {
                let Some(id) = room["id"]
                    .as_str()
                    .and_then(|r| vox_core::node::link::b32_decode(r, "room").ok())
                else {
                    continue;
                };
                if let Frame::Services { room, services, .. } = client
                    .request(&Request::Services {
                        channel_id: id,
                        after: None,
                        revision: None,
                    })
                    .await
                    .map_err(|e| crate::app::AppError::Usage(e.to_string()))?
                {
                    for (service, _) in services {
                        names.push(format!("{node}/{room}/{service}"));
                    }
                }
            }
        }
        if let Some(forwards) = report["forwards"].as_array() {
            for f in forwards {
                names.push(format!(
                    "{node} forward {} at {}",
                    f["service"].as_str().unwrap_or("unknown"),
                    f["local"].as_str().unwrap_or("unknown")
                ));
            }
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
}

/// Name each node the restart left detached, with the command that attaches it again.
pub(super) fn say_detached(nodes: &[NodeName]) {
    if nodes.is_empty() {
        return;
    }
    eprintln!("\nACTION REQUIRED ON THIS COMPUTER");
    eprintln!("These previously Ready nodes are now Locked; no passphrase was remembered:");
    for node in nodes {
        eprintln!("  {node}: vox node unlock -- {node}");
    }
    eprintln!("Unlock them on this computer to resume their rooms and connections.\n");
}

/// Whether process `pid` has ended within `bound`.
async fn gone_within(pid: u32, bound: Duration) -> bool {
    let Ok(raw_pid) = i32::try_from(pid) else {
        return true;
    };
    let Some(process) = rustix::process::Pid::from_raw(raw_pid) else {
        return true;
    };
    let t0 = Instant::now();
    loop {
        let alive = !matches!(
            rustix::process::test_kill_process(process),
            Err(rustix::io::Errno::SRCH)
        );
        #[cfg(target_os = "macos")]
        if alive {
            let stopped = match libproc::proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(raw_pid, 0)
            {
                Ok(info) => info.pbi_status == nix::libc::SZOMB,
                // The pinned libproc wrapper captures return code and numeric errno in this format.
                // A zombie can return ESRCH here while kill(pid, 0) still sees its retained PID.
                // Never interpret an unavailable/permission-denied/unknown query as an exit.
                Err(error) => {
                    error
                        .strip_prefix("return code = 0, errno = ")
                        .and_then(|value| value.split_once(", message = "))
                        .and_then(|(code, _)| code.parse::<i32>().ok())
                        == Some(nix::libc::ESRCH)
                }
            };
            if stopped {
                return true;
            }
        }
        if !alive {
            return true;
        }
        if t0.elapsed() >= bound {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// How the daemon `pid` was started: by launchd's login item or a systemd user unit when either
/// names it, by a client when its arguments carry the flag a client starts it with, by hand
/// otherwise.
fn how_started(pid: u32) -> Started {
    #[cfg(target_os = "macos")]
    {
        let target = format!("gui/{}/{LOGIN_ITEM}", rustix::process::getuid().as_raw());
        if let Ok(o) = Command::new("/bin/launchctl")
            .args(["print", &target])
            .bounded_output()
        {
            let launchd_pid = String::from_utf8_lossy(&o.stdout)
                .lines()
                .find_map(|l| l.trim().strip_prefix("pid = ").map(str::to_owned));
            if o.status.success() && launchd_pid.as_deref() == Some(pid.to_string().as_str()) {
                return Started::LoginItem(target);
            }
        }
    }
    #[cfg(target_os = "linux")]
    if let Some(unit) = user_unit(pid) {
        return Started::UserUnit(unit);
    }
    let words = arguments(pid);
    if !words.iter().any(|w| w == crate::daemon_client::AS_DETACHED) {
        return Started::ByHand;
    }
    Started::ByClient
}

/// Process `pid`'s arguments.
#[cfg(target_os = "linux")]
fn arguments(pid: u32) -> Vec<String> {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| {
            b.split(|&c| c == 0)
                .filter(|w| !w.is_empty())
                .map(|w| String::from_utf8_lossy(w).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Process `pid`'s arguments, as `ps` gives them: joined by spaces, so split at them. An anchor
/// spec (`<fingerprint>@<multiaddr>`) and the flag holds no space, so each is one word.
#[cfg(not(target_os = "linux"))]
fn arguments(pid: u32) -> Vec<String> {
    Command::new("/bin/ps")
        .args(["-ww", "-o", "args=", "-p", &pid.to_string()])
        .bounded_output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The systemd user unit `pid` is the main process of, if it is: a `.service` in the user
/// manager's tree (`…/user@<uid>.service/…/<unit>.service`), whose `MainPID` is `pid`. A daemon
/// started from a terminal is in a session's or an app's `.scope`, and is not.
#[cfg(target_os = "linux")]
fn user_unit(pid: u32) -> Option<String> {
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let path = cgroup.lines().find_map(|l| l.strip_prefix("0::"))?;
    let (_, inside) = path.split_once(".slice/user@")?;
    let unit = inside
        .rsplit('/')
        .next()
        .filter(|u| u.ends_with(".service") && !u.starts_with("user@"))?
        .to_owned();
    let main = Command::new("systemctl")
        .args(["--user", "show", "--property=MainPID", "--value", &unit])
        .bounded_output()
        .ok()?;
    (String::from_utf8_lossy(&main.stdout).trim() == pid.to_string()).then_some(unit)
}

/// OS service managers and process inspection are bounded too: a stalled helper cannot leave
/// an update (or the app's Restart Daemon action) waiting forever.
trait BoundedOutput {
    fn bounded_output(&mut self) -> std::io::Result<std::process::Output>;
}
impl BoundedOutput for Command {
    fn bounded_output(&mut self) -> std::io::Result<std::process::Output> {
        let mut child = self
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        let began = Instant::now();
        loop {
            if child.try_wait()?.is_some() {
                return child.wait_with_output();
            }
            if began.elapsed() >= STOP_WITHIN {
                let _ = child.kill();
                let _ = child.wait();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "the service manager or process lookup did not answer within 30 s",
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
