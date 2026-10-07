//! ADR-029 DR-1 — **driving a Claude Code session through its terminal**, as the operator would:
//! text typed as the operator's input, Esc, Ctrl-C and slash commands.
//!
//! Claude Code gives an outside process no way to do this (its messaging socket delivers a peer's
//! message, never the operator's input, and runs no slash command; read from 2.1.292). The decider
//! solved it in claude-telegram-mirror (ctm) by typing into the session's tmux pane, and ruled
//! (2026-10-06) that Vox must not regress from it. This is ctm's injector
//! (`rust-crates/ctm/src/injector.rs`), carried over, with one difference: **the pane is never
//! guessed** (DR-5). ctm falls back to a positional target when `$TMUX_PANE` is unset, which its
//! own log says "may misroute"; here no recorded pane is a refusal that says why.
//!
//! - **The pane** is the one the session's own hook recorded at registration
//!   ([`crate::wake::TmuxPane`]: `$TMUX`'s socket, `$TMUX_PANE`, and the `tmux` its `PATH` finds).
//! - **Before every send** the pane must exist and must not be back at a shell: a pane whose Claude
//!   Code exited would take the text as a shell command.
//! - **Text** is typed literally (`send-keys -l`), and submitted only once it is seen in Claude's
//!   input box; the box must then empty, with Enter tried up to three times, or the driver is told
//!   the text would not submit (DR-6). Reading the box is what ctm learned after a long message's
//!   Enter was swallowed.
//! - **Esc** interrupts, **Ctrl-C** stops: one key each, as ctm sends them.
//! - **A slash command** is checked against ctm's characters (letters, digits, `_ - / space`),
//!   typed and submitted.
//!
//! Every tmux call passes its arguments as arguments: nothing goes through a shell.

use std::process::Command;
use std::time::{Duration, Instant};

use crate::wake::TmuxPane;

/// The most text one send types, as ctm caps it. Longer is refused, not cut.
pub const MAX_TEXT_CHARS: usize = 8192;
/// How long typed text has to appear in the input box before Enter.
const SETTLE: Duration = Duration::from_millis(1500);
/// How long the box has to empty after each Enter.
const SUBMIT: Duration = Duration::from_millis(1500);
const POLL: Duration = Duration::from_millis(100);
/// Extra Enters when the first did not submit.
const SUBMIT_RETRIES: u32 = 2;
/// A horizontal rule in Claude Code's TUI: its input box sits between the last two. Counting `─`
/// tolerates a label on the rule (Claude Code writes the session's name there).
const RULE_MIN_DASHES: usize = 20;

/// What a driver asks of the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Act {
    /// Typed as the operator's input, and submitted.
    Text(String),
    /// Esc.
    Interrupt,
    /// Ctrl-C.
    Stop,
    /// A slash command with its arguments, `/compact`, `/clear`, `/rename <name>`.
    Slash(String),
}

/// Do `act` in the session whose registration recorded `pane`. `Err` says, in words, why it was
/// not done or did not take: every time (DR-6).
///
/// # Errors
/// No pane recorded, the pane gone or back at a shell, tmux failing, text over
/// [`MAX_TEXT_CHARS`] or that would not submit, a slash command with other characters.
pub fn drive(pane: Option<&TmuxPane>, act: &Act) -> Result<(), String> {
    let Some(p) = pane else {
        return Err(
            "this Claude Code session is not running in tmux, so Vox cannot type into it; start \
             Claude Code inside tmux"
                .into(),
        );
    };
    check(p)?;
    match act {
        Act::Interrupt => key(p, "Escape"),
        Act::Stop => key(p, "C-c"),
        Act::Slash(cmd) => {
            let cmd = if cmd.starts_with('/') {
                cmd.trim().to_owned()
            } else {
                format!("/{}", cmd.trim())
            };
            if cmd.len() < 2
                || !cmd
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ' ' | '/'))
            {
                return Err(format!(
                    "{cmd:?} was not sent: a slash command may hold only letters, digits, `_`, \
                     `-`, `/` and spaces"
                ));
            }
            literal(p, &cmd)?;
            key(p, "Enter")
        }
        Act::Text(text) => {
            if text.trim().is_empty() {
                return Err("there is no text to send".into());
            }
            let n = text.chars().count();
            if n > MAX_TEXT_CHARS {
                return Err(format!(
                    "the text was not sent: it is {n} characters, and one send types at most \
                     {MAX_TEXT_CHARS}"
                ));
            }
            submit(p, text)
        }
    }
}

/// `tmux -S <socket> <args>`, its output, or why it failed.
fn tmux(p: &TmuxPane, args: &[&str]) -> Result<String, String> {
    let out = Command::new(&p.bin)
        .arg("-S")
        .arg(&p.socket)
        .args(args)
        .output()
        .map_err(|e| format!("tmux ({}) could not be run: {e}", p.bin))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

/// The recorded pane is usable: its socket and pane well-formed, the pane alive, and not back at
/// a shell.
fn check(p: &TmuxPane) -> Result<(), String> {
    let pane_ok = p.pane.len() > 1
        && p.pane.starts_with('%')
        && p.pane[1..].chars().all(|c| c.is_ascii_digit());
    if !pane_ok || !p.socket.starts_with('/') || p.socket.contains("..") || p.socket.len() > 256 {
        return Err(format!(
            "the session's recorded tmux pane ({} on {}) is not one Vox can address",
            p.pane, p.socket
        ));
    }
    let state = tmux(
        p,
        &[
            "display-message",
            "-p",
            "-t",
            &p.pane,
            "#{pane_title}\u{1f}#{pane_current_command}",
        ],
    )
    .map_err(|e| {
        format!(
            "the session's tmux pane {} is gone ({e}): its terminal closed, or tmux restarted",
            p.pane
        )
    })?;
    let line = state.trim_end_matches(['\n', '\r']);
    let (title, command) = line.split_once('\u{1f}').unwrap_or(("", line));
    let shell = matches!(
        command
            .trim()
            .trim_start_matches('-')
            .to_ascii_lowercase()
            .as_str(),
        "zsh" | "bash" | "sh" | "fish" | "dash" | "ksh" | "tcsh" | "csh" | "ash" | "login"
    );
    if shell && !title.contains("Claude Code") {
        return Err(format!(
            "the session's tmux pane {} is back at a shell prompt: Claude Code is no longer \
             running there, so nothing was typed",
            p.pane
        ));
    }
    Ok(())
}

fn key(p: &TmuxPane, k: &str) -> Result<(), String> {
    tmux(p, &["send-keys", "-t", &p.pane, k])
        .map(|_| ())
        .map_err(|e| format!("tmux did not send {k}: {e}"))
}

fn literal(p: &TmuxPane, text: &str) -> Result<(), String> {
    tmux(p, &["send-keys", "-t", &p.pane, "-l", text])
        .map(|_| ())
        .map_err(|e| format!("tmux did not type the text: {e}"))
}

fn capture(p: &TmuxPane) -> Option<String> {
    tmux(p, &["capture-pane", "-t", &p.pane, "-p"]).ok()
}

/// Poll the pane until `pred` holds or `budget` runs out; `false` when the pane cannot be read.
fn wait_until(p: &TmuxPane, budget: Duration, pred: impl Fn(&str) -> bool) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        match capture(p) {
            Some(pane) if pred(&pane) => return true,
            Some(_) => {}
            None => return false,
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(POLL);
    }
}

/// Type `text` and submit it, confirming it left the input box (ctm's `inject`).
fn submit(p: &TmuxPane, text: &str) -> Result<(), String> {
    literal(p, text)?;
    let marker = submit_marker(text);
    if !marker.is_empty() {
        // An input box that cannot be found is nothing to wait for.
        wait_until(p, SETTLE, |pane| {
            composer_contains(pane, &marker).unwrap_or(true)
        });
    }
    for attempt in 0..=SUBMIT_RETRIES {
        key(p, "Enter")?;
        if marker.is_empty() {
            return Ok(());
        }
        // Submitted: the text has left the box. A box that cannot be found is not a failure.
        if wait_until(p, SUBMIT, |pane| {
            composer_contains(pane, &marker) != Some(true)
        }) {
            return Ok(());
        }
        if attempt == SUBMIT_RETRIES {
            break;
        }
    }
    Err(format!(
        "the text is in Claude Code's input box but would not submit after {} Enters",
        SUBMIT_RETRIES + 1
    ))
}

/// A short tail of `text`, to recognise it on screen: the end, because a long message scrolls,
/// with whitespace and control characters dropped so the TUI's wrapping cannot break it.
#[must_use]
pub fn submit_marker(text: &str) -> String {
    let squashed: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .collect();
    let n = squashed.chars().count();
    squashed.chars().skip(n.saturating_sub(24)).collect()
}

/// Claude Code's input box: the lines between the last two horizontal rules; `None` when the pane
/// has no such pair.
#[must_use]
pub fn composer_region(pane: &str) -> Option<String> {
    let lines: Vec<&str> = pane.lines().collect();
    let rules: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.chars().filter(|c| *c == '─').count() >= RULE_MIN_DASHES)
        .map(|(i, _)| i)
        .collect();
    let [.., top, bottom] = rules[..] else {
        return None;
    };
    Some(lines[top + 1..bottom].join(""))
}

/// Whether `marker` is still in the input box; `None` when the box cannot be found.
#[must_use]
pub fn composer_contains(pane: &str, marker: &str) -> Option<bool> {
    if marker.is_empty() {
        return None;
    }
    let region: String = composer_region(pane)?
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .collect();
    Some(region.contains(marker))
}
