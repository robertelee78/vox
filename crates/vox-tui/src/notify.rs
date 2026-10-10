//! PRD-001 R37 — a running daemon tells its operator when something goes wrong, and
//! when it stops being wrong, with a desktop notification.
//!
//! The conditions are exactly `vox status`'s unhealthy lines (`vox_core::node::status`),
//! so what interrupts a person is what they would have seen had they looked. Each
//! condition has a stable key, and the notifier remembers which are active:
//!
//! - a condition notifies **once when it starts**, and **once when it clears**;
//! - a condition that holds does not notify again, however long it holds and however
//!   often it is checked.
//!
//! A notifier that fired every check would be switched off within the hour, and then it
//! would not be there for the one that mattered.
//!
//! ## Where a notification goes
//!
//! - `VOX_NOTIFY_COMMAND`, when set: that program, run as `<cmd> <title> <body>`. For
//!   routing notifications somewhere else, and how the proof observes them.
//! - macOS: `osascript -e 'display notification …'`.
//! - Linux: `notify-send`, when it is installed.
//! - Anywhere else, or when none of those exist: the daemon's stderr only.
//!
//! Every notification is also written to stderr, so a daemon run under a service manager
//! leaves the same record in its log.
//!
//! **Opt out** with `notify = off` in the profile's `config` file. Phone push is out of
//! scope: it needs a service to push through, and Vox runs none.

use std::collections::BTreeMap;
use std::time::Duration;

use vox_core::node::actor::NodeHandle;
use vox_core::node::paths::Paths;
use vox_core::node::status::Unhealthy;

/// How often the daemon checks its own status.
pub const CHECK_EVERY: Duration = Duration::from_secs(5);

/// One notification to raise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// The short line.
    pub title: String,
    /// The detail.
    pub body: String,
}

/// What the notifier has already said.
#[derive(Debug, Default)]
pub struct Tracker {
    /// Active condition key → the message it was raised with.
    active: BTreeMap<String, String>,
}

impl Tracker {
    /// The notifications `now` calls for: one per condition that has just started, and
    /// one per condition that has just cleared. Nothing for one that continues.
    pub fn observe(&mut self, now: &[Unhealthy]) -> Vec<Note> {
        let mut notes = Vec::new();
        for u in now {
            if !self.active.contains_key(&u.key) {
                notes.push(Note {
                    title: "Vox: needs attention".into(),
                    body: u.message.clone(),
                });
                self.active.insert(u.key.clone(), u.message.clone());
            }
        }
        let current: std::collections::BTreeSet<&str> =
            now.iter().map(|u| u.key.as_str()).collect();
        let cleared: Vec<String> = self
            .active
            .keys()
            .filter(|k| !current.contains(k.as_str()))
            .cloned()
            .collect();
        for key in cleared {
            if let Some(was) = self.active.remove(&key) {
                notes.push(Note {
                    title: "Vox: recovered".into(),
                    body: format!("cleared: {was}"),
                });
            }
        }
        notes
    }
}

/// Whether the profile's settings turn notifications off (`notify = off`).
#[must_use]
pub fn disabled(paths: &Paths) -> bool {
    let Ok(text) = std::fs::read_to_string(paths.config_file()) else {
        return false;
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .any(|(k, v)| {
            k.trim() == "notify"
                && matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "off" | "false" | "no"
                )
        })
}

/// The program a notification is handed to instead of the desktop's, run as
/// `<program> <title> <body>`: the node's `notify-command = <program>` setting (ADR-026 F-2: its
/// own `config/config`, else the account's), else `VOX_NOTIFY_COMMAND`.
///
/// **A setting of the node, not of the process** (V030-35): several nodes share one daemon, and
/// an environment variable would hand every node's notices to one program. The variable stays
/// for a daemon run by hand in the foreground, whose environment is the person's own.
#[must_use]
pub fn command(paths: &Paths) -> Option<std::ffi::OsString> {
    let set = std::fs::read_to_string(paths.config_file())
        .ok()
        .and_then(|text| {
            text.lines()
                .map(str::trim)
                .filter(|l| !l.starts_with('#'))
                .filter_map(|l| l.split_once('='))
                .find(|(k, _)| k.trim() == "notify-command")
                .map(|(_, v)| v.trim().to_owned())
        })
        .filter(|v| !v.is_empty());
    set.map(std::ffi::OsString::from)
        .or_else(|| std::env::var_os("VOX_NOTIFY_COMMAND"))
}

/// Raise one notification. Never blocks the caller for long, and never fails it: a
/// desktop that cannot show a notification is not a reason to stop watching.
fn raise(note: &Note, command: Option<&std::ffi::OsStr>) {
    eprintln!("vox daemon: {} — {}", note.title, note.body);
    if let Some(cmd) = command {
        let _ = std::process::Command::new(cmd)
            .arg(&note.title)
            .arg(&note.body)
            .status();
        return;
    }
    if cfg!(target_os = "macos") {
        // AppleScript string literals: backslash and double quote are the escapes.
        let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!(
            "display notification \"{}\" with title \"{}\"",
            esc(&note.body),
            esc(&note.title)
        );
        let _ = std::process::Command::new("osascript")
            .arg("-e")
            .arg(script)
            .status();
    } else if cfg!(target_os = "linux") {
        let _ = std::process::Command::new("notify-send")
            .arg(&note.title)
            .arg(&note.body)
            .status();
    }
}

/// Raise one notification for the person at node `paths`'s machine, where the daemon's watcher
/// raises its own (#666: a node that waits for its passphrase), unless the node has notifications
/// off. Waits for the notification program, so it is for a moment that happens once.
pub fn raise_for(paths: &Paths, title: &str, body: &str) {
    if disabled(paths) {
        return;
    }
    let note = Note {
        title: title.to_owned(),
        body: body.to_owned(),
    };
    raise(&note, command(paths).as_deref());
}

/// Raise `note` from the TUI (ADR-028 R-10): to the node's notification program when it has one
/// (`notify-command`, `VOX_NOTIFY_COMMAND`), run off the TUI's thread; else to the terminal the TUI
/// draws in, as an OSC 9 desktop notification, or as a bell over SSH, where a terminal's OSC 9
/// reaches no desktop.
pub(crate) fn raise_from_tui(note: &Note, command: Option<&std::ffi::OsStr>) {
    use std::io::Write as _;
    if let Some(cmd) = command {
        let (cmd, title, body) = (cmd.to_owned(), note.title.clone(), note.body.clone());
        std::thread::spawn(move || {
            let _ = std::process::Command::new(cmd)
                .arg(title)
                .arg(body)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        });
        return;
    }
    let over_ssh =
        std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some();
    // The terminal shows the escape's text: control characters are taken out, as everywhere a
    // member's name is shown.
    let plain = |s: &str| s.chars().filter(|c| !c.is_control()).collect::<String>();
    let seq = if over_ssh {
        "\x07".to_owned()
    } else {
        format!("\x1b]9;{}: {}\x07", plain(&note.title), plain(&note.body))
    };
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(seq.as_bytes());
    let _ = out.flush();
}

/// Watch `node`'s status for as long as the daemon runs, raising a notification when a
/// condition starts and when it clears.
pub async fn watch(node: NodeHandle, paths: Paths) {
    if disabled(&paths) {
        eprintln!(
            "vox daemon: notifications off (notify = off in {})",
            paths.config_file().display()
        );
        return;
    }
    let command = command(&paths);
    let mut tracker = Tracker::default();
    let mut every = tokio::time::interval(CHECK_EVERY);
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        every.tick().await;
        let Ok(report) = node.status().await else {
            return; // the node stopped
        };
        for note in tracker.observe(&report.unhealthy) {
            // Off the runtime: a notification program is a child process to wait for.
            let command = command.clone();
            let _ = tokio::task::spawn_blocking(move || raise(&note, command.as_deref())).await;
        }
    }
}
