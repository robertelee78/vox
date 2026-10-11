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

use vox_core::node::daemonipc::{DaemonClient, NodeState};
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
enum Started {
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

/// Restart the account's daemon, if one runs, onto `helper`, the vox now in place, and say what that did: the version it runs, and each node it no longer has attached.
///
/// The nodes it left detached are returned, for [`say_next`].
pub(super) fn restart_daemon(helper: &Path, now: &str) -> Vec<NodeName> {
    let account = match Account::of(None, None) {
        Ok(a) => a,
        Err(e) => {
            println!("the vox daemon was not restarted: {e}; restart it to run {now}");
            return Vec::new();
        }
    };
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            println!("the vox daemon was not restarted: {e}; restart it to run {now}");
            return Vec::new();
        }
    };
    rt.block_on(restart(&account, helper, now))
}

/// The explicit repair offered when a client finds a daemon of a different release.
pub(crate) fn restart_current(account: &Account) -> Result<(), crate::app::AppError> {
    let helper = std::env::current_exe()?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(restart_checked(
        account,
        &helper,
        env!("CARGO_PKG_VERSION"),
        true,
    ))?;
    Ok(())
}

async fn restart(account: &Account, helper: &Path, now: &str) -> Vec<NodeName> {
    match restart_checked(account, helper, now, false).await {
        Ok(nodes) => nodes,
        Err(e) => {
            println!("the vox daemon was not restarted: {e}");
            Vec::new()
        }
    }
}

async fn restart_checked(
    account: &Account,
    helper: &Path,
    now: &str,
    start_if_absent: bool,
) -> Result<Vec<NodeName>, crate::app::AppError> {
    use crate::app::AppError;
    let socket = account.socket();
    // Read only Hello, then close. Even the updater sends no request to another release.
    let before = match DaemonClient::observe(&socket).await {
        Ok(d) => d,
        Err(vox_core::error::Error::Ipc(vox_core::error::IpcHandshake::Unreachable { .. })) => {
            if !start_if_absent {
                return Ok(Vec::new());
            }
            crate::daemon_client::start_daemon(
                helper,
                account,
                crate::client::DEFAULT_LISTEN
                    .parse()
                    .expect("default listen"),
                &[],
            )
            .await?;
            println!("the vox daemon was started and runs vox {now}");
            return Ok(Vec::new());
        }
        Err(e) => return Err(AppError::Usage(e.to_string())),
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
        .unwrap_or_else(|| {
            crate::client::DEFAULT_LISTEN
                .parse()
                .expect("default listen")
        });
    let attached = before
        .attached
        .iter()
        .map(|n| n.name.clone())
        .collect::<Vec<_>>();
    // The updater process still runs its original release after the binary is replaced. It
    // can ask its matching daemon for the names of services/forwards about to end. A repair
    // from a different release reads Hello only, as every other mismatched client must.
    let held = if before.version == env!("CARGO_PKG_VERSION") {
        tokio::time::timeout(Duration::from_secs(10), held_names(account, &attached))
            .await
            .map_err(|_| {
                AppError::Usage("the daemon did not name its held sessions within 10 s".into())
            })??
    } else {
        Vec::new()
    };
    let kept = crate::host::read_attach_file(&account.attach_file())
        .into_iter()
        .map(|(name, _)| name)
        .collect::<Vec<_>>();

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
    match started {
        #[cfg(target_os = "macos")]
        Started::LoginItem(target) => {
            let out = Command::new("/bin/launchctl")
                .args(["kickstart", &target])
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
                .args(["--user", "restart", &unit])
                .bounded_output()?;
            if !out.status.success() {
                return Err(AppError::Usage(format!(
                    "systemd did not restart the daemon: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                )));
            }
        }
        Started::ByClient | Started::ByHand => {
            crate::daemon_client::start_daemon(helper, account, listen, &anchors).await?;
        }
    }
    let t0 = Instant::now();
    let after = loop {
        let greeting = DaemonClient::observe(&socket).await;
        let ready = greeting.as_ref().is_ok_and(|d| {
            d.version == now
                && d.pid != before.pid
                && kept.iter().all(|k| {
                    d.attached
                        .iter()
                        .any(|n| &n.name == k && n.state == NodeState::Attached)
                })
        });
        if ready {
            break greeting.expect("greeting checked");
        }
        if t0.elapsed() >= REATTACH_WITHIN {
            return Err(AppError::Usage(format!(
                "the daemon did not return with its remembered nodes Ready on vox {now} within {} s; its log is {}",
                REATTACH_WITHIN.as_secs(), account.log_file().display(),
            )));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
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
    say_detached(&missing);
    Ok(missing)
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
                    .request(&Request::Services { channel_id: id })
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
fn say_detached(nodes: &[NodeName]) {
    for node in nodes {
        println!(
            "node {node} is detached, as the daemon remembers no passphrase for it; attach it \
             again with `vox node attach {node}`"
        );
    }
}

/// The last line of an update or a rollback: what to do next, given the nodes the restart left
/// `detached` (#666).
pub(super) fn say_next(detached: &[NodeName]) {
    match detached {
        [] => println!("Next: run `vox status` to see your nodes and rooms on this version"),
        [node] => println!(
            "Next: run `vox node attach {node}`; it asks for the passphrase once and then \
             remembers it"
        ),
        nodes => println!(
            "Next: attach each: {}; each asks for its passphrase once and then remembers it",
            nodes
                .iter()
                .map(|n| vox_text::shell::command(&["vox", "node", "attach", n.as_str()]))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Whether process `pid` has ended within `bound`.
async fn gone_within(pid: u32, bound: Duration) -> bool {
    let t0 = Instant::now();
    loop {
        let alive = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .is_some_and(|p| rustix::process::test_kill_process(p).is_ok());
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
