//! `vox agent doctor` (V030-16): whether a session is wired up, and what to do where it is not.
//!
//! A hand-opened session needs a hook or plugin installed once, and when it is not, nothing
//! says so: F17 (OpenCode registering as `unknown`) went unseen that way. The doctor checks
//! each piece a session's room read and wakes depend on, and prints one line per check, `ok`,
//! `warn` or `fail`, with a one-line fix wherever it is not `ok`. It exits non-zero on any
//! `fail`.
//!
//! The rule between the two: **`warn` is something not set up, `fail` is something set up that
//! will not work.** A harness with no Vox hook is a `warn`, since this machine may not use it
//! with Vox; a hook that runs twice, a stale plugin or a Codex hook Codex will not run is a
//! `fail`. A harness that is not installed here at all is `ok`, saying so.
//!
//! What it reads is what the product writes, never a guess: the harnesses' own settings files,
//! Codex's own `hooks/list`, the session records the drain writes every turn, and the node's
//! own status report for trust in each direction. It changes nothing, posts nothing and wakes
//! no one: a wake endpoint is probed by connecting and closing.

use std::path::{Path, PathBuf};

use vox_core::hash::Digest32;
use vox_core::node::ipc::{Frame, IpcClient, Request};
use vox_core::node::link::b32_encode;
use vox_core::node::paths::Paths;

use crate::app::AppError;

/// The Claude Code hook events `vox agent hook` must run on, each exactly once at user scope.
/// `vox agent plugin claude` prints an entry for each.
pub const CLAUDE_HOOK_EVENTS: &[&str] = &["UserPromptSubmit"];

/// A check's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Works.
    Ok,
    /// Not set up, or cannot be told: worth knowing, not broken.
    Warn,
    /// Set up and will not work.
    Fail,
}

impl Level {
    fn token(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Warn => "warn",
            Level::Fail => "fail",
        }
    }
}

/// One line of the report.
#[derive(Debug, Clone)]
struct Check {
    id: String,
    level: Level,
    detail: String,
    fix: Option<String>,
}

fn ok(id: impl Into<String>, detail: impl Into<String>) -> Check {
    Check {
        id: id.into(),
        level: Level::Ok,
        detail: detail.into(),
        fix: None,
    }
}

fn warn(id: impl Into<String>, detail: impl Into<String>, fix: impl Into<String>) -> Check {
    Check {
        id: id.into(),
        level: Level::Warn,
        detail: detail.into(),
        fix: Some(fix.into()),
    }
}

fn fail(id: impl Into<String>, detail: impl Into<String>, fix: impl Into<String>) -> Check {
    Check {
        id: id.into(),
        level: Level::Fail,
        detail: detail.into(),
        fix: Some(fix.into()),
    }
}

/// A check that needs the node or the room, which did not answer: said rather than dropped.
fn not_checked(id: &str, what: &str) -> Check {
    Check {
        id: id.into(),
        level: Level::Warn,
        detail: format!("not checked: it needs {what}"),
        fix: Some(format!("fix {what} first (see above)")),
    }
}

/// `vox agent doctor`.
///
/// # Errors
/// Exit 1 when any check fails; the report is printed first.
pub async fn doctor(
    paths: &Paths,
    room: Option<&str>,
    codex: &str,
    json: bool,
) -> Result<(), AppError> {
    let mut checks = Vec::new();

    // ---- the node, and the room ----
    let mut client = match crate::room_cli::attach(paths).await {
        Ok(c) => {
            checks.push(ok(
                "node",
                format!("the node answers at {}", paths.socket_file().display()),
            ));
            Some(c)
        }
        Err(e) => {
            checks.push(fail(
                "node",
                e.to_string(),
                "start this profile's node: `vox daemon` (or `vox tui`)",
            ));
            None
        }
    };
    let channel = match client.as_mut() {
        Some(c) => match crate::ping::room_or_only(c, room).await {
            Ok(id) => {
                checks.push(ok("room", format!("room {}", b32_encode(&id))));
                Some(id)
            }
            Err(e) => {
                checks.push(fail(
                    "room",
                    e.to_string(),
                    "name the room with --room or VOX_ROOM; `vox room list` shows them",
                ));
                None
            }
        },
        None => {
            checks.push(not_checked("room", "the node"));
            None
        }
    };

    // ---- the harnesses' wiring ----
    checks.extend(claude_hooks());
    checks.push(codex_hook(codex));
    checks.push(opencode_plugin());

    // ---- the drain, sessions, trust and versions ----
    match (client.as_mut(), channel) {
        (Some(c), Some(id)) => checks.push(drain_self_test(paths, c, id).await),
        _ => checks.push(not_checked("drain", "the node and the room")),
    }
    checks.extend(sessions(paths, channel).await);
    match (client.as_mut(), channel) {
        (Some(_), Some(id)) => checks.extend(trust(paths, id).await),
        _ => checks.push(not_checked("trust", "the node and the room")),
    }
    match (client.as_mut(), channel) {
        (Some(c), Some(id)) => checks.extend(versions(c, id).await),
        _ => checks.push(not_checked("versions", "the node and the room")),
    }

    let failed = checks.iter().filter(|c| c.level == Level::Fail).count();
    if json {
        let out = serde_json::json!({
            "schema": "vox.agent.doctor/1",
            "room": channel.map(|id| b32_encode(&id)),
            "ok": failed == 0,
            "checks": checks.iter().map(|c| serde_json::json!({
                "check": c.id,
                "status": c.level.token(),
                "detail": c.detail,
                "fix": c.fix,
            })).collect::<Vec<_>>(),
        });
        println!("{out}");
    } else {
        for c in &checks {
            println!("{:<5} {}: {}", c.level.token(), c.id, c.detail);
            if let Some(fix) = &c.fix {
                println!("      fix: {fix}");
            }
        }
    }
    if failed > 0 {
        return Err(AppError::Refused {
            code: 1,
            message: format!(
                "{failed} check{} failed",
                if failed == 1 { "" } else { "s" }
            ),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------- Claude Code

/// Whether `command` runs `vox agent hook`: a program named `vox` (or a path to one), then
/// `agent hook`. Looser than Codex's trust rule on purpose: this only counts entries, it
/// authorises nothing.
fn runs_vox_hook(command: &str) -> bool {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    tokens
        .windows(3)
        .any(|w| (w[0] == "vox" || w[0].ends_with("/vox")) && w[1] == "agent" && w[2] == "hook")
}

/// Claude Code's user settings file: `$CLAUDE_CONFIG_DIR/settings.json`, else
/// `~/.claude/settings.json`.
fn claude_dir() -> Option<PathBuf> {
    std::env::var_os("CLAUDE_CONFIG_DIR")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .or_else(|| home().map(|h| h.join(".claude")))
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

/// How many entries for `event` in the settings file at `path` run `vox agent hook`, or why
/// the file could not be read. A file that does not exist holds none.
fn hook_count(path: &Path, event: &str) -> Result<usize, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(format!("{} cannot be read: {e}", path.display())),
    };
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        format!(
            "{} is not JSON ({e}), so Claude Code reads none of its hooks",
            path.display()
        )
    })?;
    Ok(v["hooks"][event]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|group| group["hooks"].as_array().into_iter().flatten())
        .filter(|h| h["command"].as_str().is_some_and(runs_vox_hook))
        .count())
}

/// One check per required event: an entry running `vox agent hook`, once, at user scope.
fn claude_hooks() -> Vec<Check> {
    let Some(dir) = claude_dir() else {
        return vec![warn(
            "claude-hook",
            "HOME is not set, so Claude Code's settings cannot be found",
            "run the doctor from the environment Claude Code runs in",
        )];
    };
    let user = dir.join("settings.json");
    let project: Vec<PathBuf> = std::env::current_dir()
        .map(|cwd| {
            vec![
                cwd.join(".claude").join("settings.json"),
                cwd.join(".claude").join("settings.local.json"),
            ]
        })
        .unwrap_or_default();
    CLAUDE_HOOK_EVENTS
        .iter()
        .map(|event| {
            let id = format!("claude-hook {event}");
            if !dir.exists() {
                return ok(
                    id,
                    format!("Claude Code is not set up here (no {})", dir.display()),
                );
            }
            let at_user = match hook_count(&user, event) {
                Ok(n) => n,
                Err(e) => return fail(id, e, format!("make {} valid JSON", user.display())),
            };
            let mut at_project = Vec::new();
            for p in &project {
                match hook_count(p, event) {
                    Ok(0) => {}
                    Ok(n) => at_project.push((p, n)),
                    Err(e) => return fail(id, e, format!("make {} valid JSON", p.display())),
                }
            }
            let total = at_user + at_project.iter().map(|(_, n)| n).sum::<usize>();
            match (at_user, total) {
                (1, 1) => ok(
                    id,
                    format!("runs `vox agent hook` once, from {}", user.display()),
                ),
                (_, 0) => warn(
                    id,
                    format!(
                        "no `vox agent hook` entry for {event} in {}",
                        user.display()
                    ),
                    format!(
                        "merge what `vox agent plugin claude` prints into {}",
                        user.display()
                    ),
                ),
                (0, _) => warn(
                    id,
                    format!(
                        "`vox agent hook` runs on {event} only at project scope ({}): a \
                         session started anywhere else does not read its room",
                        at_project
                            .iter()
                            .map(|(p, _)| p.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    format!("move the entry into {}", user.display()),
                ),
                (_, n) => fail(
                    id,
                    format!(
                        "`vox agent hook` runs {n} times on every {event} ({} in {}{}): each \
                         message is given to the model {n} times",
                        at_user,
                        user.display(),
                        at_project
                            .iter()
                            .map(|(p, k)| format!(", {k} in {}", p.display()))
                            .collect::<String>()
                    ),
                    format!(
                        "keep one entry, in {}, and remove the others",
                        user.display()
                    ),
                ),
            }
        })
        .collect()
}

// ---------------------------------------------------------------- Codex

/// Codex's hook: present, and trusted, as Codex itself reports.
fn codex_hook(codex: &str) -> Check {
    let id = "codex-hook";
    let installed = std::process::Command::new(codex)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !installed {
        return ok(id, format!("Codex is not installed here (no `{codex}`)"));
    }
    // `$CODEX_HOME`, else `~/.codex`: where Codex keeps its hooks and their trust.
    let home_dir = std::env::var_os("CODEX_HOME")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .or_else(|| home().map(|h| h.join(".codex")));
    if let Some(dir) = home_dir.filter(|d| !d.exists()) {
        return ok(
            id,
            format!("Codex is not set up here (no {})", dir.display()),
        );
    }
    match crate::codex_trust::status(codex) {
        Err(e) => warn(
            id,
            format!("could not ask Codex for its hooks: {e}"),
            "run `codex app-server` by hand to see why it does not start",
        ),
        Ok(entries) if entries.is_empty() => warn(
            id,
            "Codex has no hook running `vox agent hook`",
            "merge what `vox agent plugin codex` prints into Codex's hooks.json, then run \
             `vox agent trust codex`",
        ),
        Ok(entries) => {
            let untrusted: Vec<&String> =
                entries.iter().filter(|(_, t)| !t).map(|(c, _)| c).collect();
            if untrusted.is_empty() {
                ok(
                    id,
                    format!(
                        "Codex trusts its {} `vox agent hook` entr{}",
                        entries.len(),
                        if entries.len() == 1 { "y" } else { "ies" }
                    ),
                )
            } else {
                fail(
                    id,
                    format!(
                        "Codex does not trust {}: it will not run {}",
                        untrusted
                            .iter()
                            .map(|c| format!("{c:?}"))
                            .collect::<Vec<_>>()
                            .join(", "),
                        if untrusted.len() == 1 { "it" } else { "them" }
                    ),
                    "`vox agent trust codex`",
                )
            }
        }
    }
}

// ---------------------------------------------------------------- OpenCode

/// OpenCode's configuration directory: `$OPENCODE_CONFIG_DIR`, else
/// `$XDG_CONFIG_HOME/opencode`, else `~/.config/opencode`.
fn opencode_dir() -> Option<PathBuf> {
    let var = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    var("OPENCODE_CONFIG_DIR")
        .or_else(|| var("XDG_CONFIG_HOME").map(|x| x.join("opencode")))
        .or_else(|| home().map(|h| h.join(".config").join("opencode")))
}

/// Every plugin file under `dir`'s `plugin` and `plugins` directories that runs
/// `vox agent hook`.
fn vox_plugins(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    for sub in ["plugin", "plugins"] {
        let Ok(entries) = std::fs::read_dir(dir.join(sub)) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            if !matches!(
                path.extension().and_then(|x| x.to_str()),
                Some("js" | "ts" | "mjs")
            ) {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&path) {
                if text.contains("agent hook") {
                    out.push((path, text));
                }
            }
        }
    }
    out.sort();
    out
}

/// OpenCode's plugin: present once, and byte for byte the one this build prints.
fn opencode_plugin() -> Check {
    let id = "opencode-plugin";
    let Some(dir) = opencode_dir() else {
        return warn(
            id,
            "HOME is not set, so OpenCode's configuration cannot be found",
            "run the doctor from the environment OpenCode runs in",
        );
    };
    let mut found = vox_plugins(&dir);
    if let Ok(cwd) = std::env::current_dir() {
        found.extend(vox_plugins(&cwd.join(".opencode")));
    }
    let target = dir.join("plugin").join("vox.js");
    match found.as_slice() {
        [] if !dir.exists() => ok(
            id,
            format!("OpenCode is not set up here (no {})", dir.display()),
        ),
        [] => warn(
            id,
            format!("no Vox plugin in {}", dir.join("plugin").display()),
            format!("`vox agent plugin opencode > {}`", target.display()),
        ),
        [(path, text)] if text == crate::agent_hook::OPENCODE_PLUGIN => {
            ok(id, format!("{} is this build's plugin", path.display()))
        }
        [(path, _)] => fail(
            id,
            format!(
                "{} is not the plugin this vox ({}) prints: an older or edited copy",
                path.display(),
                crate::coord::VERSION
            ),
            format!("`vox agent plugin opencode > {}`", path.display()),
        ),
        many => fail(
            id,
            format!(
                "{} Vox plugins load into every OpenCode session ({}): each runs the drain",
                many.len(),
                many.iter()
                    .map(|(p, _)| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "keep one, and remove the others",
        ),
    }
}

// ---------------------------------------------------------------- the drain

/// Whether a file can be made, and removed, in `dir`.
fn writable(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{} cannot be made: {e}", dir.display()))?;
    let probe = dir.join(format!(".vox-doctor-{}", std::process::id()));
    std::fs::write(&probe, b"").map_err(|e| format!("{} is not writable: {e}", dir.display()))?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// What the drain does every turn, short of showing anything: read the room through the
/// node, and be able to record where it read to and how its session is woken.
async fn drain_self_test(paths: &Paths, client: &mut IpcClient, channel_id: Digest32) -> Check {
    let id = "drain";
    let read = Request::Read {
        channel_id,
        since: None,
        after: None,
        limit: 1,
    };
    match client.request(&read).await {
        Ok(Frame::Rows { .. }) => {}
        Ok(Frame::Error { reason }) => {
            return fail(
                id,
                format!("the node refused the drain's read: {reason}"),
                "open the room on this node (`vox tui`, or a line for it in `vox daemon`'s \
                 input)",
            )
        }
        Ok(other) => {
            return fail(
                id,
                format!("the node answered the drain's read with {other:?}"),
                "restart the node with this vox",
            )
        }
        Err(e) => {
            return fail(
                id,
                format!("the drain's read failed: {e}"),
                "restart the node",
            )
        }
    }
    for (dir, what) in [
        (paths.cursor_dir(), "where each session has read to"),
        (paths.session_dir(), "how each session is woken"),
    ] {
        if let Err(e) = writable(&dir) {
            return fail(
                id,
                format!("the drain cannot record {what}: {e}"),
                format!("make {} writable by this user", dir.display()),
            );
        }
    }
    ok(id, "the drain reads the room and can record its place")
}

// ---------------------------------------------------------------- sessions

/// How long a session may read `busy` with no hook activity before it counts as idle (V030-20).
const BUSY_IDLE_MS: u64 = 10 * 60 * 1000;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Each session registered for this room (or every room, when none resolved): when it was
/// first seen and last drained, idle or busy, and whether its wake endpoint is alive.
async fn sessions(paths: &Paths, channel: Option<Digest32>) -> Vec<Check> {
    let room = channel.map(|id| b32_encode(&id));
    let mut list: Vec<crate::wake::Session> = crate::wake::registered(paths)
        .into_iter()
        .filter(|s| room.as_ref().is_none_or(|r| *r == s.room))
        .collect();
    list.sort_by(|a, b| a.session.cmp(&b.session));
    if list.is_empty() {
        return vec![warn(
            "sessions",
            "no session has read this room yet: a session registers on its first turn",
            "open a session with the hook or plugin installed (`vox agent plugin <harness>`) \
             and VOX_ROOM set",
        )];
    }
    let mut out = Vec::new();
    for s in &list {
        let id = format!("session {}", s.session);
        let seen = |ms: u64| {
            if ms == 0 {
                "not recorded".to_owned()
            } else {
                crate::ping::ago_ms(ms)
            }
        };
        let quiet_ms = now_ms().saturating_sub(s.state_ms);
        let state = if s.state.is_empty() {
            "idle or busy unknown (no hook has recorded it)".to_owned()
        } else if s.state == "busy" && quiet_ms > BUSY_IDLE_MS {
            // A turn interrupted with Esc never runs Stop, so busy is not believed for ever.
            format!(
                "busy, but no hook activity for {}m, so treated as idle",
                quiet_ms / 60_000
            )
        } else {
            format!("{} since {}", s.state, seen(s.state_ms))
        };
        let reach = crate::wake::reach(s).await;
        let what = format!(
            "{} session{}, first seen {}, last drained {}, {state}",
            s.harness,
            if s.name.is_empty() {
                String::new()
            } else {
                format!(" answering to {:?}", s.name)
            },
            seen(s.first_seen_ms),
            seen(s.last_drained_ms),
        );
        let known = matches!(s.harness.as_str(), "claude" | "opencode" | "codex");
        out.push(if let crate::wake::Reach::Gone(why) = &reach {
            warn(
                id,
                format!("{what}; its wake endpoint is gone ({why})"),
                "nothing, if the session ended; a running one registers again on its next turn",
            )
        } else if !known {
            warn(
                id,
                format!(
                    "{what}; Vox could not tell which harness ran it, so it cannot be \
                     interrupted"
                ),
                "for OpenCode, install the plugin (`vox agent plugin opencode`); for Claude \
                 Code, run the hook from Claude Code itself",
            )
        } else if s.name.is_empty() {
            warn(
                id,
                format!("{what}; it answers to no name, so nothing addressed can wake it"),
                "set VOX_AGENT_NAME in the harness's environment",
            )
        } else if reach == crate::wake::Reach::Interrupt {
            ok(id, format!("{what}; its wake endpoint answers"))
        } else {
            ok(
                id,
                format!("{what}; it cannot be interrupted and reads at its next turn"),
            )
        });
    }
    out
}

// ---------------------------------------------------------------- trust

/// Trust in each direction with every other member, from the node's own status report:
/// `trusted` (this keyring trusts it) and `readable` (it released its sender key to this node,
/// which it does only once it trusts this node).
async fn trust(paths: &Paths, channel_id: Digest32) -> Vec<Check> {
    let report = match vox_core::node::status::request(&paths.socket_file()).await {
        Ok(r) => r,
        Err(e) => {
            return vec![warn(
                "trust",
                format!("the node's status could not be read: {e}"),
                "run the doctor again",
            )]
        }
    };
    let v: serde_json::Value = serde_json::from_str(&report).unwrap_or_default();
    let room_key = b32_encode(&channel_id);
    let Some(room) = v["rooms"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| r["id"].as_str() == Some(room_key.as_str()))
    else {
        return vec![warn(
            "trust",
            "the node's status does not list this room",
            "open the room on this node",
        )];
    };
    let me = v["identity"].as_str().unwrap_or("").to_owned();
    let others: Vec<&serde_json::Value> = room["members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|m| m["me"] != true)
        .collect();
    if others.is_empty() {
        return vec![ok("trust", "you are this room's only member")];
    }
    others
        .iter()
        .map(|m| {
            let fp = m["id"].as_str().unwrap_or("");
            let short: String = fp.chars().take(crate::ident::AUTHOR_CHARS).collect();
            let id = format!("trust {short}");
            match (m["trusted"].as_bool(), m["readable"].as_bool()) {
                (Some(true), Some(true)) => ok(id, "you trust each other"),
                (Some(false), _) => warn(
                    id,
                    "you do not trust it: you cannot read it, and it cannot read you",
                    format!("`vox trust add {fp} <name>` (asks for your identity passphrase)"),
                ),
                (Some(true), Some(false)) => warn(
                    id,
                    "you trust it, but it has not released its key to you: it has not trusted \
                     you, or has not reached you since it did",
                    format!("ask its operator to run `vox trust add {me} <name>`"),
                ),
                _ => warn(
                    id,
                    "whether it trusts you could not be read (the room was busy)",
                    "run the doctor again",
                ),
            }
        })
        .collect()
}

// ---------------------------------------------------------------- versions

/// Every other working session's version stamp against this vox's: work coordination is
/// refused across versions (ADR-021 §5).
async fn versions(client: &mut IpcClient, channel_id: Digest32) -> Vec<Check> {
    let snap = match crate::coord::snapshot(client, channel_id).await {
        Ok(s) => s,
        Err(e) => {
            return vec![warn(
                "versions",
                format!("the room could not be read: {e}"),
                "run the doctor again",
            )]
        }
    };
    let table = &snap.table;
    if table.participants.is_empty() {
        return vec![ok(
            "versions",
            format!(
                "no other session has announced a version here; this is vox {}",
                table.mine
            ),
        )];
    }
    table
        .participants
        .iter()
        .map(|p| {
            let who = format!(
                "{} session {}",
                crate::ident::author_id(&p.author),
                p.session
            );
            let id = format!("version {who}");
            match &p.stamp {
                vox_agentcomms::version::Stamp::Match => ok(id, format!("runs vox {}", table.mine)),
                other => warn(
                    id,
                    format!(
                        "runs {}, this is vox {}: work coordination is refused until they match",
                        other.describe(&table.mine),
                        table.mine
                    ),
                    "run the same vox on every machine in the room",
                ),
            }
        })
        .collect()
}
