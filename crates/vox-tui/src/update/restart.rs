//! After `vox update` (or `--rollback`) puts a vox in place, Vox.app on a Mac or the standalone
//! binary elsewhere, the account's vox daemon is restarted onto it (decider, 2026-10-07: "I know
//! not to update something if I'm in the middle of a transaction"), so nothing keeps running the
//! version the update replaced.
//!
//! The daemon is asked to stop, as `vox daemon`'s own stop does: every node detaches and its keys
//! are wiped. The new one attaches again every node whose passphrase it keeps (`--keep`, or the
//! Keychain the app stores it in). Any other node that was attached stays detached, and the update
//! names each one with the command that attaches it again.
//!
//! How the daemon was started decides how it is started again:
//!
//! - by a client (`--as-detached`): the new vox is started the same way, on the same address and
//!   anchors; with no node it would keep attached, it is left stopped, and the next command that
//!   needs it starts the new vox;
//! - as the app's login item (macOS): launchd starts it again, from the bundle now in place;
//! - as the main process of a systemd user unit (Linux): `systemctl --user restart` that unit;
//! - in a terminal, or by anything else (`vox daemon`): it is left running, and the person is
//!   told, because only whoever started it can start it again the same way.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use vox_core::node::daemonipc::{
    DaemonClient, DaemonFrame, DaemonRequest, DaemonStatus, NodeState,
};
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
    /// By a client, with these anchors.
    ByClient(Vec<String>),
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

async fn restart(account: &Account, helper: &Path, now: &str) -> Vec<NodeName> {
    let socket = account.socket();
    // No daemon: the next command that needs one starts the vox now in place.
    let Ok(before) = status(&socket).await else {
        return Vec::new();
    };
    let started = how_started(before.pid);
    if matches!(started, Started::ByHand) {
        println!(
            "the vox daemon (pid {}) was started by `vox daemon`, so it is left running vox {}: \
             stop it and start it again to run {now}",
            before.pid, before.version
        );
        return Vec::new();
    }
    let attached: Vec<NodeName> = before
        .nodes
        .iter()
        .filter(|n| matches!(n.state, NodeState::Attached | NodeState::Attaching))
        .map(|n| n.name.clone())
        .collect();
    let kept: Vec<NodeName> = before
        .nodes
        .iter()
        .filter(|n| n.keep)
        .map(|n| n.name.clone())
        .collect();

    // ---- stop the old one (systemd stops a unit's itself) ------------------------------------
    #[cfg(target_os = "linux")]
    let by_unit = matches!(started, Started::UserUnit(_));
    #[cfg(not(target_os = "linux"))]
    let by_unit = false;
    let stopped = by_unit
        || match DaemonClient::open(&socket).await {
            Ok(mut d) => matches!(d.request(DaemonRequest::Stop).await, Ok(DaemonFrame::Ok)),
            Err(_) => false,
        };
    if !stopped || (!by_unit && !gone_within(before.pid, STOP_WITHIN).await) {
        println!(
            "the vox daemon (pid {}) did not stop within {} s, so it still runs vox {}; restart \
             it to run {now}",
            before.pid,
            STOP_WITHIN.as_secs(),
            before.version
        );
        return Vec::new();
    }

    // ---- start the new one ----------------------------------------------------------------
    match started {
        Started::ByClient(_) if kept.is_empty() => {
            println!(
                "the vox daemon was stopped; the next vox command that needs it starts vox {now}"
            );
            say_detached(&attached);
            return attached;
        }
        Started::ByClient(anchors) => {
            let listen = before
                .listen
                .parse()
                .or_else(|_| crate::client::DEFAULT_LISTEN.parse())
                .unwrap_or(std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
            if let Err(e) =
                crate::daemon_client::start_daemon(helper, account, listen, &anchors).await
            {
                println!("the vox daemon was stopped, and vox {now} did not start: {e}");
                say_detached(&attached);
                return attached;
            }
        }
        #[cfg(target_os = "macos")]
        Started::LoginItem(target) => {
            let kicked = Command::new("/bin/launchctl")
                .args(["kickstart", &target])
                .output();
            if !kicked.as_ref().is_ok_and(|o| o.status.success()) {
                println!(
                    "the vox daemon was stopped, and launchd did not start it again ({}); open \
                     Vox to start it",
                    kicked.map_or_else(
                        |e| e.to_string(),
                        |o| String::from_utf8_lossy(&o.stderr).trim().to_owned()
                    )
                );
                say_detached(&attached);
                return attached;
            }
        }
        #[cfg(target_os = "linux")]
        Started::UserUnit(unit) => {
            let restarted = Command::new("systemctl")
                .args(["--user", "restart", &unit])
                .output();
            if !restarted.as_ref().is_ok_and(|o| o.status.success()) {
                println!(
                    "the vox daemon runs as the systemd user unit {unit}, and `systemctl --user \
                     restart {unit}` failed ({}); run it to run {now}",
                    restarted.map_or_else(
                        |e| e.to_string(),
                        |o| String::from_utf8_lossy(&o.stderr).trim().to_owned()
                    )
                );
                return Vec::new();
            }
            println!("the systemd user unit {unit} was restarted");
        }
        Started::ByHand => unreachable!("left running above"),
    }

    // ---- what the new one has attached ------------------------------------------------------
    let t0 = Instant::now();
    let after = loop {
        let now_status = status(&socket).await;
        let settled = now_status.as_ref().is_ok_and(|s| {
            kept.iter().all(|k| {
                s.nodes
                    .iter()
                    .any(|n| &n.name == k && n.state == NodeState::Attached)
            })
        });
        if settled || t0.elapsed() >= REATTACH_WITHIN {
            break now_status;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    match after {
        Ok(after) => {
            println!(
                "the vox daemon was restarted and runs vox {} (pid {})",
                after.version, after.pid
            );
            let missing: Vec<NodeName> = attached
                .into_iter()
                .filter(|a| {
                    !after
                        .nodes
                        .iter()
                        .any(|n| &n.name == a && n.state == NodeState::Attached)
                })
                .collect();
            say_detached(&missing);
            missing
        }
        Err(e) => {
            println!(
                "the vox daemon was restarted from {}, and does not answer this vox ({e}); \
                 `vox node list` shows which nodes are attached",
                helper.display()
            );
            let unkept: Vec<NodeName> =
                attached.into_iter().filter(|a| !kept.contains(a)).collect();
            say_detached(&unkept);
            unkept
        }
    }
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

/// The daemon's own account of itself.
async fn status(socket: &Path) -> Result<DaemonStatus, String> {
    let mut d = DaemonClient::open(socket)
        .await
        .map_err(|e| e.to_string())?;
    match d.request(DaemonRequest::Status).await {
        Ok(DaemonFrame::Status(s)) => Ok(s),
        Ok(other) => Err(format!("it answered {other:?}")),
        Err(e) => Err(e.to_string()),
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
            .output()
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
    let anchors = words
        .windows(2)
        .filter(|w| w[0] == "--anchor")
        .map(|w| w[1].clone())
        .collect();
    Started::ByClient(anchors)
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
        .output()
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
        .output()
        .ok()?;
    (String::from_utf8_lossy(&main.stdout).trim() == pid.to_string()).then_some(unit)
}
