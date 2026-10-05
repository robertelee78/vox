//! `vox agent doctor` (V030-16): whether this node's agent sessions are wired up, and what to do
//! where they are not.
//!
//! A hand-opened session needs a hook or plugin installed once, and when it is not, nothing says
//! so: F17 (OpenCode registering as `unknown`) went unseen that way. The doctor checks each piece a
//! session's drain and wakes depend on, and prints one line per check, `ok`, `warn` or `fail`,
//! with a one-line fix wherever it is not `ok`. It exits non-zero on any `fail`.
//!
//! The rule between the two: **`warn` is something not set up, `fail` is something set up that
//! will not work.** A harness with no Vox hook is a `warn`, since this machine may not use it with
//! Vox; a hook that runs twice, a stale plugin or a Codex hook Codex has not trusted is a `fail`.
//! A harness not set up here at all is `ok`, saying so.
//!
//! **It only reads.** The harnesses' own settings files, the session records the drain writes
//! every turn, and the node's answers. It starts no harness and no model (not even Codex's
//! app-server: Codex's trust is read from the `config.toml` Codex writes), changes nothing, posts
//! nothing and wakes no one: a wake endpoint is probed by connecting and closing.

use std::path::{Path, PathBuf};

use vox_core::hash::Digest32;
use vox_core::node::ipc::{Frame, IpcClient, Request};
use vox_core::node::link::b32_encode;
use vox_core::node::paths::Paths;

use crate::app::AppError;

/// A check's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
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
    warn(
        id,
        format!("not checked: it needs {what}"),
        format!("fix {what} first (see above)"),
    )
}

/// `vox agent doctor`.
///
/// # Errors
/// Exit 1 when any check fails; the report is printed first.
pub async fn doctor(paths: &Paths, room: Option<&str>, json: bool) -> Result<(), AppError> {
    let mut checks = Vec::new();

    // ---- the node, and the room ----
    let mut client = match crate::room_cli::attach(paths).await {
        Ok(c) => {
            checks.push(ok(
                "node",
                format!("the node answers at {}", paths.account().socket().display()),
            ));
            Some(c)
        }
        Err(e) => {
            checks.push(fail(
                "node",
                e.to_string(),
                format!(
                    "attach this node: `vox node attach {}` (it starts the daemon if none runs)",
                    paths
                        .profile_dir
                        .file_name()
                        .map_or_else(|| "<node>".into(), |n| n.to_string_lossy())
                ),
            ));
            None
        }
    };
    let channel = match client.as_mut() {
        Some(c) => match room_or_only(c, room).await {
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
    let node = paths
        .profile_dir
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| vox_core::node::paths::NodeName::parse(n).ok());
    match &node {
        Some(node) => {
            checks.extend(claude_hooks(node));
            checks.push(codex_hook(node));
            checks.push(opencode_plugin(node));
        }
        None => checks.push(fail(
            "node-name",
            format!("{} is not a node's directory", paths.profile_dir.display()),
            "name the node with --node",
        )),
    }

    // ---- the drain, sessions, trust and versions ----
    match (client.as_mut(), channel) {
        (Some(c), Some(id)) => {
            checks.push(drain_self_test(paths, c, id).await);
        }
        _ => checks.push(not_checked("drain", "the node and the room")),
    }
    checks.extend(sessions(paths).await);
    match (client.as_mut(), channel) {
        (Some(c), Some(id)) => {
            checks.extend(trust(c, id).await);
            checks.extend(versions(c, id).await);
        }
        _ => {
            checks.push(not_checked("trust", "the node and the room"));
            checks.push(not_checked("versions", "the node and the room"));
        }
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

/// The room `room` names, or from `VOX_ROOM`, or the node's only room.
async fn room_or_only(client: &mut IpcClient, room: Option<&str>) -> Result<Digest32, AppError> {
    let named = room
        .map(str::to_owned)
        .or_else(|| std::env::var("VOX_ROOM").ok())
        .filter(|r| !r.trim().is_empty());
    if let Some(r) = named {
        return crate::room_cli::room_of(client, r.trim()).await;
    }
    let rooms = match client.rooms().await {
        Ok(Frame::Rooms { rooms }) => rooms,
        Ok(Frame::Error { reason }) => return Err(AppError::Usage(reason)),
        Ok(other) => return Err(crate::client::unexpected(&other)),
        Err(e) => return Err(AppError::Usage(e.to_string())),
    };
    match rooms.as_slice() {
        [(id, _, _, _)] => Ok(*id),
        [] => Err(AppError::Usage(
            "this node holds no rooms yet: join or create one first".into(),
        )),
        _ => Err(AppError::Usage(
            "this node holds several rooms: name one with --room, or set VOX_ROOM".into(),
        )),
    }
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

/// `$var`, else `$HOME/<under>`.
fn dir_of(var: &str, under: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .or_else(|| home().map(|h| h.join(under)))
}

// ---------------------------------------------------------------- Claude Code

/// The Claude Code events `vox agent plugin claude` prints an entry for: read from what it
/// prints, so the doctor and the plugin cannot disagree.
fn claude_events() -> Vec<String> {
    serde_json::from_str::<serde_json::Value>(crate::agent_hook::CLAUDE_HOOKS)
        .ok()
        .and_then(|v| v["hooks"].as_object().map(|m| m.keys().cloned().collect()))
        .unwrap_or_default()
}

/// Whether `command` runs `vox agent hook`: a program named `vox` (or a path to one), then
/// `agent hook`. Looser than Codex's trust rule on purpose: this only counts entries, it
/// authorises nothing.
fn runs_vox_hook(command: &str) -> bool {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    tokens
        .windows(3)
        .any(|w| (w[0] == "vox" || w[0].ends_with("/vox")) && w[1] == "agent" && w[2] == "hook")
}

/// The node a hook command acts as: the value of its `--node`, or `None` when it names none
/// (such a hook refuses, ADR-020 2.1).
fn hook_node(command: &str) -> Option<&str> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    tokens.windows(2).find(|w| w[0] == "--node").map(|w| w[1])
}

/// What a `vox agent hook` entry acting as some node other than `node` is told: none, or which.
fn wrong_node(command: &str, node: &vox_core::node::paths::NodeName) -> Option<String> {
    match hook_node(command) {
        Some(n) if n == node.as_str() => None,
        Some(n) => Some(format!("acts as node {n}, not this node ({node})")),
        None => Some("names no node (`--node`), so it refuses every turn".to_owned()),
    }
}

/// The commands of the entries for `event` in the settings file at `path` that run `vox agent
/// hook`, or why the file could not be read. A file that does not exist holds none.
fn hook_commands(path: &Path, event: &str) -> Result<Vec<String>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
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
        .filter_map(|h| h["command"].as_str().filter(|c| runs_vox_hook(c)))
        .map(str::to_owned)
        .collect())
}

/// One check per event: an entry running `vox agent hook`, once, at user scope.
fn claude_hooks(node: &vox_core::node::paths::NodeName) -> Vec<Check> {
    let Some(dir) = dir_of("CLAUDE_CONFIG_DIR", ".claude") else {
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
    claude_events()
        .iter()
        .map(|event| {
            let id = format!("claude-hook {event}");
            if !dir.exists() {
                return ok(
                    id,
                    format!("Claude Code is not set up here (no {})", dir.display()),
                );
            }
            let user_commands = match hook_commands(&user, event) {
                Ok(c) => c,
                Err(e) => return fail(id, e, format!("make {} valid JSON", user.display())),
            };
            let at_user = user_commands.len();
            let mut at_project = Vec::new();
            for p in &project {
                match hook_commands(p, event).map(|c| c.len()) {
                    Ok(0) => {}
                    Ok(n) => at_project.push((p, n)),
                    Err(e) => return fail(id, e, format!("make {} valid JSON", p.display())),
                }
            }
            let total = at_user + at_project.iter().map(|(_, n)| n).sum::<usize>();
            let plugin = format!("vox agent plugin claude --node {node}");
            match (at_user, total) {
                (1, 1) => match wrong_node(&user_commands[0], node) {
                    None => ok(
                        id,
                        format!(
                            "runs `vox agent hook --node {node}` once, from {}",
                            user.display()
                        ),
                    ),
                    Some(why) => fail(
                        id,
                        format!("the `vox agent hook` entry in {} {why}", user.display()),
                        format!("replace it with what `{plugin}` prints"),
                    ),
                },
                (_, 0) => warn(
                    id,
                    format!(
                        "no `vox agent hook` entry for {event} in {}",
                        user.display()
                    ),
                    format!("merge what `{plugin}` prints into {}", user.display()),
                ),
                (0, _) => warn(
                    id,
                    format!(
                        "`vox agent hook` runs on {event} only at project scope ({}): a session \
                         started anywhere else is not wired up",
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
                        "`vox agent hook` runs {n} times on every {event} ({at_user} in {}{}): \
                         each message is given to the model {n} times",
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

/// `UserPromptSubmit` as Codex spells an event in a hook's key: `user_prompt_submit`.
fn snake(event: &str) -> String {
    let mut out = String::new();
    for (i, c) in event.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

/// Whether Codex's `config.toml` text records a trusted hash for the hook `key`: Codex's own
/// "trust" writes `[hooks.state."<key>"]` with `trusted_hash = …` (measured against codex-cli
/// 0.160.0; see [`crate::codex_trust`]).
fn trusted_in(config: &str, key: &str) -> bool {
    let header = format!(
        "[hooks.state.{}]",
        serde_json::Value::String(key.to_owned())
    );
    let dotted = format!(
        "hooks.state.{}.trusted_hash",
        serde_json::Value::String(key.to_owned())
    );
    let mut inside = false;
    for line in config.lines().map(str::trim) {
        if line.starts_with(&dotted) {
            return true;
        }
        if line.starts_with('[') {
            inside = line == header;
        } else if inside && line.starts_with("trusted_hash") && line.contains('=') {
            return true;
        }
    }
    false
}

/// Codex's hook: a Vox entry in its user `hooks.json`, in the shape Codex runs, and trusted, as
/// Codex's own `config.toml` records it. Read from the files: no Codex process is started.
fn codex_hook(node: &vox_core::node::paths::NodeName) -> Check {
    let id = "codex-hook";
    let Some(dir) = dir_of("CODEX_HOME", ".codex") else {
        return warn(
            id,
            "HOME is not set, so Codex's configuration cannot be found",
            "run the doctor from the environment Codex runs in",
        );
    };
    if !dir.exists() {
        return ok(
            id,
            format!("Codex is not set up here (no {})", dir.display()),
        );
    }
    let hooks_file = dir.join("hooks.json");
    let plugin = format!("merge what `vox agent plugin codex --node {node}` prints into");
    let hooks: serde_json::Value = match std::fs::read_to_string(&hooks_file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => serde_json::Value::Null,
        Err(e) => {
            return fail(
                id,
                format!("{} cannot be read: {e}", hooks_file.display()),
                format!("make {} readable", hooks_file.display()),
            )
        }
        Ok(t) => match serde_json::from_str(&t) {
            Ok(v) => v,
            Err(e) => {
                return fail(
                    id,
                    format!(
                        "{} is not JSON ({e}), so Codex runs none of its hooks",
                        hooks_file.display()
                    ),
                    format!("make {} valid JSON", hooks_file.display()),
                )
            }
        },
    };
    // Every Vox entry, as Codex keys it: `<hooks.json>:<event>:<group>:<entry>`, the path as
    // Codex resolves it (macOS's `/var` is `/private/var`).
    let real = std::fs::canonicalize(&hooks_file).unwrap_or_else(|_| hooks_file.clone());
    let mut keys = Vec::new();
    let mut wrong = Vec::new();
    let mut bare = 0;
    for (event, groups) in hooks["hooks"].as_object().into_iter().flatten() {
        for (g, group) in groups.as_array().into_iter().flatten().enumerate() {
            if group["command"].as_str().is_some_and(runs_vox_hook) {
                bare += 1;
            }
            for (h, hook) in group["hooks"].as_array().into_iter().flatten().enumerate() {
                if let Some(command) = hook["command"].as_str().filter(|c| runs_vox_hook(c)) {
                    keys.push(format!("{}:{}:{g}:{h}", real.display(), snake(event)));
                    if let Some(why) = wrong_node(command, node) {
                        wrong.push(why);
                    }
                }
            }
        }
    }
    if keys.is_empty() {
        return if bare > 0 {
            fail(
                id,
                format!(
                    "{} has a `vox agent hook` entry directly under its event, which Codex does \
                     not run: an entry belongs inside a group's `hooks` list",
                    hooks_file.display()
                ),
                format!("replace it with what `vox agent plugin codex --node {node}` prints"),
            )
        } else {
            warn(
                id,
                format!(
                    "Codex has no hook running `vox agent hook` in {}",
                    hooks_file.display()
                ),
                format!(
                    "{plugin} {}, then run `vox agent trust codex`",
                    hooks_file.display()
                ),
            )
        };
    }
    if let Some(why) = wrong.first() {
        return fail(
            id,
            format!(
                "the `vox agent hook` entry in {} {why}",
                hooks_file.display()
            ),
            format!(
                "replace it with what `vox agent plugin codex --node {node}` prints, then run \
                 `vox agent trust codex`"
            ),
        );
    }
    let config_file = dir.join("config.toml");
    let config = std::fs::read_to_string(&config_file).unwrap_or_default();
    let untrusted: Vec<&String> = keys.iter().filter(|k| !trusted_in(&config, k)).collect();
    if untrusted.is_empty() {
        ok(
            id,
            format!(
                "Codex has recorded trust in {} for its {} `vox agent hook` entr{}",
                config_file.display(),
                keys.len(),
                if keys.len() == 1 { "y" } else { "ies" }
            ),
        )
    } else {
        fail(
            id,
            format!(
                "Codex has not trusted {}, so it will not run {}",
                untrusted
                    .iter()
                    .map(|k| k.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                if untrusted.len() == 1 { "it" } else { "them" }
            ),
            "`vox agent trust codex`",
        )
    }
}

// ---------------------------------------------------------------- OpenCode

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
fn opencode_plugin(node: &vox_core::node::paths::NodeName) -> Check {
    let id = "opencode-plugin";
    let this = crate::agent_hook::opencode_plugin(node);
    let dir = std::env::var_os("OPENCODE_CONFIG_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("XDG_CONFIG_HOME")
                .filter(|v| !v.is_empty())
                .map(|x| PathBuf::from(x).join("opencode"))
        })
        .or_else(|| home().map(|h| h.join(".config").join("opencode")));
    let Some(dir) = dir else {
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
            format!(
                "`vox agent plugin opencode --node {node} > {}`",
                target.display()
            ),
        ),
        [(path, text)] if *text == this => {
            ok(id, format!("{} is this build's plugin", path.display()))
        }
        [(path, _)] => fail(
            id,
            format!(
                "{} is not the plugin this vox ({}) prints for node {node}: an older or edited copy, or another node's",
                path.display(),
                crate::coord::VERSION
            ),
            format!(
                "`vox agent plugin opencode --node {node} > {}`",
                path.display()
            ),
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

/// What the drain does every turn, short of showing anything: read the room through the node,
/// and be able to record where it read to and how its session is woken.
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
                "open the room on this node",
            )
        }
        Ok(other) => {
            return fail(
                id,
                format!(
                    "the node did not answer the drain's read: {}",
                    crate::client::unexpected(&other)
                ),
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

/// Each session registered on this node (a session hears every room its node holds): when it was
/// first seen and last drained, idle or busy, and whether its wake endpoint is alive.
async fn sessions(paths: &Paths) -> Vec<Check> {
    let mut list = crate::wake::registered(paths);
    list.sort_by(|a, b| a.session.cmp(&b.session));
    if list.is_empty() {
        return vec![warn(
            "sessions",
            "no agent session has drained on this node yet: a session registers on its first turn",
            "open a session with the hook or plugin installed (`vox agent plugin <harness>`)",
        )];
    }
    let busy_idle = crate::wake::Settings::load(paths).0.busy_idle;
    let now = crate::wake::now_millis();
    let seen = |ms: u64| {
        if ms == 0 {
            "not recorded".to_owned()
        } else {
            crate::ping::ago_ms(ms)
        }
    };
    let mut out = Vec::new();
    for s in &list {
        let id = format!("session {}", s.session);
        let what = format!(
            "{} session, first seen {}, last drained {}, {}",
            s.harness,
            seen(s.first_seen_ms),
            seen(s.last_drained_ms),
            if s.idle(now, busy_idle) {
                "idle"
            } else {
                "busy"
            },
        );
        out.push(match crate::wake::reach(s).await {
            crate::wake::Reach::Gone(why) => warn(
                id,
                format!("{what}; its wake endpoint is gone ({why})"),
                "nothing, if the session ended; a running one registers again on its next turn",
            ),
            crate::wake::Reach::Interrupt => ok(id, format!("{what}; its wake endpoint answers")),
            crate::wake::Reach::Turn if s.harness == "codex" => ok(
                id,
                format!("{what}; Vox never interrupts Codex, so it reads at its next turn"),
            ),
            crate::wake::Reach::Turn => warn(
                id,
                format!(
                    "{what}; Vox could not tell which harness ran it, so it cannot be interrupted"
                ),
                "for OpenCode, install the plugin (`vox agent plugin opencode`); for Claude Code, \
                 run the hook from Claude Code itself",
            ),
        });
    }
    out
}

// ---------------------------------------------------------------- trust

/// Trust in each direction with every other member of the room, from the room's log through the
/// node (`Consents`, V030-17).
async fn trust(client: &mut IpcClient, channel_id: Digest32) -> Vec<Check> {
    let (outbound, inbound) = match client.request(&Request::Consents { channel_id }).await {
        Ok(Frame::Consents { outbound, inbound }) => (outbound, inbound),
        Ok(other) => {
            return vec![warn(
                "trust",
                format!(
                    "the node did not say who trusts whom: {}",
                    crate::client::unexpected(&other)
                ),
                "restart the node with this vox",
            )]
        }
        Err(e) => {
            return vec![warn(
                "trust",
                format!("the node did not say who trusts whom: {e}"),
                "run the doctor again",
            )]
        }
    };
    let members = match client.request(&Request::Roster { channel_id }).await {
        Ok(Frame::Members { members }) => members,
        other => {
            let why = match other {
                Ok(f) => crate::client::unexpected(&f).to_string(),
                Err(e) => e.to_string(),
            };
            return vec![warn(
                "trust",
                format!("the room's members could not be read: {why}"),
                "run the doctor again",
            )];
        }
    };
    let me = client.me();
    let others: Vec<Digest32> = members.into_iter().filter(|m| Some(*m) != me).collect();
    if others.is_empty() {
        return vec![ok("trust", "you are this room's only member")];
    }
    others
        .iter()
        .map(|fp| {
            let name = crate::ident::name_of(fp);
            let id = format!("trust {name}");
            let full = b32_encode(fp);
            match (outbound.contains(fp), inbound.contains(fp)) {
                (true, true) => ok(id, "you trust each other"),
                (false, _) => warn(
                    id,
                    "you have not trusted it: it cannot read you, and you do not read it",
                    format!("`vox trust add {full} <name>` (asks for your identity passphrase)"),
                ),
                (true, false) => warn(
                    id,
                    "you trust it, but it has not trusted you: it cannot read you",
                    format!(
                        "ask its operator to trust you: `vox trust add {} <name>`",
                        me.map(|m| b32_encode(&m)).unwrap_or_default()
                    ),
                ),
            }
        })
        .collect()
}

// ---------------------------------------------------------------- versions

/// Every other working session's version stamp against this vox's: work coordination is refused
/// across versions (ADR-021 §5).
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
            let id = format!(
                "version {} session {}",
                crate::ident::name_of(&p.author),
                p.session
            );
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
