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

/// Raise one notification. Never blocks the caller for long, and never fails it: a
/// desktop that cannot show a notification is not a reason to stop watching.
fn raise(note: &Note) {
    eprintln!("vox daemon: {} — {}", note.title, note.body);
    if let Some(cmd) = std::env::var_os("VOX_NOTIFY_COMMAND") {
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
            let _ = tokio::task::spawn_blocking(move || raise(&note)).await;
        }
    }
}
