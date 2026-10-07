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
//! - **The pane** is the one the session's own hook proved ([`bind_here`]), refreshed by every hook,
//!   keyed by session id: `$TMUX`'s socket, `$TMUX_PANE` (`%N`, stable for the pane's life, which
//!   tmux always sets inside a pane: dropping ctm's positional fallback loses nothing real), the
//!   pane's process, and the session's process, found by walking the hook's own ancestry up to the
//!   pane's process, with its start time from the process table (never from the hook's input).
//! - **Before every send** ([`check`]) all of it is checked again; each case it settles is named
//!   beside its check.
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

/// Held while a send types into a pane.
static SENDING: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

/// Do `act` in the session `reg` registers. `Err` says, in words, why it was not done or did not
/// take: every time (DR-6).
///
/// # Errors
/// No pane proven, the pane gone or no longer the session's, tmux failing, text over
/// [`MAX_TEXT_CHARS`] or that would not submit, a slash command with other characters.
pub fn drive(reg: &crate::wake::Session, act: &Act) -> Result<(), String> {
    let Some(p) = reg.tmux.as_ref() else {
        // Case: a drive before any hook bound the session, or a session outside tmux.
        return Err(reg.tmux_why.clone().unwrap_or_else(|| {
            "this Claude Code session is not running in tmux, so Vox cannot type into it; start \
             Claude Code inside tmux"
                .into()
        }));
    };
    // One send at a time, to any pane (ctm's lock): two drives never interleave their keys.
    let _one = SENDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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

/// One process, as the process table says.
#[derive(Debug, Clone)]
struct Proc {
    ppid: u32,
    start: String,
    name: String,
}

/// The process table: pid → parent, start time (`lstart`) and name. One `ps` for the whole walk.
fn processes() -> Result<std::collections::HashMap<u32, Proc>, String> {
    let out = Command::new("/bin/ps")
        .args(["-ax", "-o", "pid=,ppid=,lstart=,comm="])
        .output()
        .map_err(|e| format!("the process table could not be read: {e}"))?;
    let mut table = std::collections::HashMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        // `lstart` is five words: "Tue Oct  6 18:04:12 2026".
        let w: Vec<&str> = line.split_whitespace().collect();
        if w.len() < 8 {
            continue;
        }
        let (Ok(pid), Ok(ppid)) = (w[0].parse::<u32>(), w[1].parse::<u32>()) else {
            continue;
        };
        let name = w[7..].join(" ");
        let name = name.rsplit('/').next().unwrap_or(&name).to_owned();
        table.insert(
            pid,
            Proc {
                ppid,
                start: w[2..7].join(" "),
                name,
            },
        );
    }
    Ok(table)
}

/// The chain from `pid` up through its parents, `pid` first, ending at init or a loop.
fn ancestry(table: &std::collections::HashMap<u32, Proc>, pid: u32) -> Vec<u32> {
    let mut chain = vec![pid];
    let mut at = pid;
    while let Some(p) = table.get(&at) {
        if p.ppid <= 1 || chain.contains(&p.ppid) || chain.len() > 64 {
            break;
        }
        chain.push(p.ppid);
        at = p.ppid;
    }
    chain
}

/// What this process's environment says of its tmux pane: `Ok(None)` outside tmux (no `$TMUX`),
/// `Err` why when tmux is named but no pane can be. Called by the session's hook; the daemon
/// proves it ([`prove`]).
///
/// # Errors
/// `$TMUX` set without `$TMUX_PANE`, or no `tmux` on `PATH`.
pub fn claim_here() -> Result<Option<crate::wake::TmuxClaim>, String> {
    let Ok(server) = std::env::var("TMUX") else {
        return Ok(None);
    };
    let socket = server
        .split(',')
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    // Case: `$TMUX` without `$TMUX_PANE`. tmux always sets both inside a pane, so this is not a
    // pane this process is in. ctm fell back to a positional target here, which tmux resolves to
    // the ACTIVE pane (ROUTING-002); never.
    let pane = std::env::var("TMUX_PANE")
        .map(|p| p.trim().to_owned())
        .ok()
        .filter(|p| !p.is_empty())
        .ok_or("$TMUX is set but $TMUX_PANE is not, so Vox cannot tell which pane it runs in")?;
    let bin = std::env::var_os("PATH")
        .and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join("tmux"))
                .find(|t| t.is_file())
        })
        .ok_or("no tmux on the session's PATH")?
        .display()
        .to_string();
    Ok(Some(crate::wake::TmuxClaim {
        socket,
        pane,
        bin,
        hook_pid: std::process::id(),
    }))
}

/// Prove `claim`, in the daemon, while the hook that made it waits: the pane exists on its server,
/// and the hook runs under the pane's process. The session's process is the pane's own process
/// when the session is the pane's command, else the pane's child on the hook's chain: Claude Code
/// itself, or the wrapper that started it (a shell script, `npx`, a version shim), which lives as
/// long as the session. Its start time comes from the process table.
///
/// # Errors
/// The pane malformed or unknown to tmux, or the hook not under the pane's process.
pub fn prove(
    claim: &crate::wake::TmuxClaim,
    harnesses: &[std::path::PathBuf],
) -> Result<TmuxPane, String> {
    let mut found = TmuxPane {
        socket: claim.socket.clone(),
        pane: claim.pane.clone(),
        bin: claim.bin.clone(),
        pane_pid: 0,
        process: 0,
        process_start: String::new(),
        process_name: String::new(),
    };
    shape(&found)?;
    let pane_pid: u32 = tmux(
        &found,
        &["display-message", "-p", "-t", &found.pane, "#{pane_pid}"],
    )
    .map_err(|e| format!("tmux did not answer for pane {} ({e})", found.pane))?
    .trim()
    .parse()
    .map_err(|_| format!("tmux gave no process for pane {}", found.pane))?;
    let table = processes()?;
    let chain = ancestry(&table, claim.hook_pid);
    // **The hook must be the harness's own** (the lead's ruling after a proof's hook, started
    // beneath the operator's real pane by a test, bound a made-up session to it and typed into it,
    // 2026-10-07): its parent, after at most one `sh -c`, is a harness process, known by its
    // executable's path as the kernel gives it, never by a name or a variable. Anything else
    // beneath a pane (a test, a script, another node's hook) proves nothing.
    let parent = chain.get(1).copied().unwrap_or(0);
    let harness = if exe_of(parent).as_deref().is_some_and(is_shell) {
        chain.get(2).copied().unwrap_or(0)
    } else {
        parent
    };
    let harness_exe = exe_of(harness);
    if !harness_exe
        .as_deref()
        .is_some_and(|e| harnesses.iter().any(|h| h == e))
    {
        return Err(format!(
            "the hook that named tmux pane {} was not started by Claude Code itself (it was started \
             by {}), so the pane is not proven",
            found.pane,
            harness_exe.map_or_else(|| format!("process {harness}"), |e| e.display().to_string())
        ));
    }
    let Some(at) = chain.iter().position(|&p| p == pane_pid) else {
        // Case: nested tmux is fine (the innermost server's variables are the hook's, and its
        // chain reaches that pane). ssh, or variables inherited by a process outside the pane, is
        // not: the chain never reaches the pane's process.
        return Err(format!(
            "this session does not run under tmux pane {}'s process, though $TMUX_PANE names it",
            found.pane
        ));
    };
    // The harness itself must run beneath the pane, through any wrapper (a script, `npx`, a
    // version shim): the pane's process is on its chain.
    let Some(h_at) = chain.iter().position(|&p| p == harness) else {
        return Err("the session's harness left the process table".into());
    };
    if at < h_at {
        return Err(format!(
            "Claude Code does not run under tmux pane {}'s process, though the hook does",
            found.pane
        ));
    }
    // The session's process is Claude Code itself: it lives exactly as long as the session.
    let process = harness;
    let p = table
        .get(&process)
        .ok_or("the session's process left the process table")?;
    found.pane_pid = pane_pid;
    found.process = process;
    found.process_start.clone_from(&p.start);
    found.process_name.clone_from(&p.name);
    Ok(found)
}

/// A process's executable, as the kernel has it: `/proc/<pid>/exe` on Linux; on macOS, the
/// process's first text mapping, as `lsof` reads it from the kernel. `None` when it cannot be read.
fn exe_of(pid: u32) -> Option<std::path::PathBuf> {
    if pid <= 1 {
        return None;
    }
    if cfg!(target_os = "linux") {
        return std::fs::read_link(format!("/proc/{pid}/exe")).ok();
    }
    let out = Command::new("/usr/sbin/lsof")
        .args(["-a", "-p", &pid.to_string(), "-d", "txt", "-Fn"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix('n'))
        .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| std::path::PathBuf::from(p)))
}

/// Whether `exe` is a POSIX shell a harness runs its hook command through (`sh -c`).
fn is_shell(exe: &std::path::Path) -> bool {
    exe.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| matches!(n, "sh" | "bash" | "zsh" | "dash" | "ksh"))
        && (exe.starts_with("/bin") || exe.starts_with("/usr/bin"))
}

/// The executables that are Claude Code on this machine, each resolved:
///
/// - every `<HOME>/.local/share/claude/versions/*` (Claude Code's native install);
/// - the `claude` the daemon's `PATH` finds;
/// - each path the account's `harnesses` file names, one per line (`#` starts a comment), for an
///   install elsewhere.
///
/// Read when a hook's pane is proven, so an update that adds a version is taken at once.
#[must_use]
pub fn harnesses(config_dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let versions = std::path::Path::new(&home).join(".local/share/claude/versions");
        if let Ok(dir) = std::fs::read_dir(versions) {
            out.extend(
                dir.flatten()
                    .filter_map(|e| std::fs::canonicalize(e.path()).ok()),
            );
        }
    }
    if let Some(found) = std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join("claude"))
            .find(|c| c.is_file())
    }) {
        out.extend(std::fs::canonicalize(found).ok());
    }
    if let Ok(text) = std::fs::read_to_string(config_dir.join("harnesses")) {
        out.extend(
            text.lines()
                .map(|l| l.split('#').next().unwrap_or_default().trim())
                .filter(|l| !l.is_empty())
                .filter_map(|l| std::fs::canonicalize(l).ok()),
        );
    }
    out
}

/// The recorded socket and pane are well-formed.
fn shape(p: &TmuxPane) -> Result<(), String> {
    let pane_ok = p.pane.len() > 1
        && p.pane.starts_with('%')
        && p.pane[1..].chars().all(|c| c.is_ascii_digit());
    if !pane_ok || !p.socket.starts_with('/') || p.socket.contains("..") || p.socket.len() > 256 {
        return Err(format!(
            "the session's tmux pane ({} on {}) is not one Vox can address",
            p.pane, p.socket
        ));
    }
    Ok(())
}

/// The recorded pane is still the session's, now: each check names the case it settles.
fn check(p: &TmuxPane) -> Result<(), String> {
    shape(p)?;
    // Case: the tmux server restarted, or the pane closed. The key is (socket, %N): a pane of
    // another server with the same %N is never this one, and a restarted server's %N is a new pane
    // with a new process.
    let now = tmux(p, &["display-message", "-p", "-t", &p.pane, "#{pane_pid}"]).map_err(|e| {
        format!(
            "the session's tmux pane {} is gone ({e}): its terminal closed, or tmux restarted",
            p.pane
        )
    })?;
    if now.trim().parse::<u32>().ok() != Some(p.pane_pid) {
        return Err(format!(
            "tmux pane {} is not the pane the session ran in (its process changed): tmux \
             restarted, or the pane was reused; the session is known again after its next turn",
            p.pane
        ));
    }
    // Case: Claude Code exited (the pane back at a shell), or a new session took the pane after
    // one that ended without a SessionEnd: the session's process is gone, or is another process
    // under the same pid.
    let table = processes()?;
    let alive = table
        .get(&p.process)
        .is_some_and(|q| q.start == p.process_start);
    if !alive {
        return Err(format!(
            "the session is no longer running in tmux pane {}: its process ({} {}) has ended, \
             so nothing was typed",
            p.pane, p.process_name, p.process
        ));
    }
    // Case: the process still lives but left the pane (moved by a wrapper, the pane respawned).
    // A pane moved, split, swapped or renumbered keeps its %N and its process: input follows it.
    if p.process != p.pane_pid && !ancestry(&table, p.process).contains(&p.pane_pid) {
        return Err(format!(
            "the session's process no longer runs under tmux pane {}",
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
