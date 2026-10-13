//! Node-free, secret-free handoff to Vox.app (ADR-031 HK-3/4, NC-2/3).
//! One request and answer per harness live in the account's configuration. They are notices,
//! not authority to create or attach anything: only the app's secure fields do that.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vox_core::node::paths::{Account, NodeName};

use crate::app::AppError;
use crate::client::NodeArgs;

#[derive(Deserialize, Serialize)]
pub(crate) struct Request {
    pub harness: String,
    pub dir: String,
    pub node: String,
    pub id: String,
    pub sessions: Vec<String>,
    pub explicit: bool,
}

#[derive(Deserialize, Serialize)]
struct Answer {
    request: String,
    outcome: String,
    node: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    made_node: Option<String>,
}

pub(crate) fn key(harness: &str) -> Option<&'static str> {
    match harness {
        "claude" | "claude-code" => Some("claude"),
        "codex" => Some("codex"),
        "opencode" => Some("opencode"),
        _ => None,
    }
}

fn file(account: &Account, harness: &str, suffix: &str) -> PathBuf {
    account
        .config_dir
        .join("agent-setup")
        .join(format!("{harness}{suffix}"))
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    // These are three short local records, never a transcript or a passphrase store.
    if std::fs::metadata(path).ok()?.len() > 16 * 1024 {
        return None;
    }
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn request(account: &Account, harness: &str) -> Option<Request> {
    read(&file(account, harness, ".json"))
}

pub(crate) fn declined(account: &Account, harness: &str) -> bool {
    file(account, harness, ".declined").is_file()
}

fn write_request(account: &Account, value: &Request) -> Result<(), AppError> {
    let path = file(account, &value.harness, ".json");
    vox_core::node::paths::create_private_dir(&account.config_dir.join("agent-setup"))?;
    let bytes = serde_json::to_vec(value).map_err(|e| AppError::Usage(e.to_string()))?;
    vox_core::node::paths::write_private_file_unique(&path, &bytes)?;
    Ok(())
}

fn request_lock(account: &Account, harness: &str) -> Result<std::fs::File, AppError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    vox_core::node::paths::create_private_dir(&account.config_dir.join("agent-setup"))?;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(file(account, harness, ".lock"))?;
    lock.try_lock().map_err(|_| {
        AppError::Usage("another setup request is being recorded; try again".into())
    })?;
    Ok(lock)
}

/// Record a harness the app may offer to set up. A prior answer/request is never overwritten by
/// a light hook, even when a second session arrives while the person is deciding.
pub(crate) fn offer(account: &Account, harness: &'static str, dir: &Path) -> Result<(), AppError> {
    let _lock = request_lock(account, harness)?;
    if declined(account, harness) {
        return Ok(());
    }
    if let Some(mut previous) = request(account, harness) {
        if !previous.explicit && previous.dir.is_empty() && !dir.as_os_str().is_empty() {
            previous.dir = dir.display().to_string();
            write_request(account, &previous)?;
        }
        return Ok(());
    }
    let wiring = crate::setup::Wiring::of(harness)?;
    if crate::setup::connected(account, &wiring).is_some() {
        return Ok(());
    }
    write_request(
        account,
        &Request {
            harness: harness.into(),
            dir: dir.display().to_string(),
            node: crate::setup::suggested_name(harness, &crate::setup::host_name()),
            id: "offer".into(),
            sessions: Vec::new(),
            explicit: false,
        },
    )
}

/// Discover the same harnesses installation found; an app does not need an agent turn before it
/// can offer Set Up. Called only by the app's existing hook-installation command.
pub(crate) fn discover(account: &Account) {
    for h in &crate::skill_pack::HARNESSES {
        if crate::skill_pack::present(h) {
            let _ = offer(account, h.key, Path::new(""));
        }
    }
}

/// Terminal setup can finish an offer too; the app must stop offering a harness now wired to a
/// Ready node. Like the app's answer, this contains only the outcome and node name.
pub(crate) fn completed(account: &Account, harness: &str, node: &NodeName) -> Result<(), AppError> {
    let _lock = request_lock(account, harness)?;
    let Some(request) = request(account, harness) else {
        return Ok(());
    };
    let bytes = serde_json::to_vec(&Answer {
        request: request.id,
        outcome: "ready".into(),
        node: node.to_string(),
        made_node: Some(node.to_string()),
    })
    .map_err(|e| AppError::Usage(e.to_string()))?;
    vox_core::node::paths::write_private_file_unique(
        &file(account, harness, ".answer.json"),
        &bytes,
    )?;
    Ok(())
}

/// Local app installation, never the desktop of a Mac reached over SSH. The app records its
/// exact bundle at launch; the normal bundle/CLI install is also found before the first launch.
pub(crate) fn local_app(account: &Account) -> Option<PathBuf> {
    if !cfg!(target_os = "macos")
        || ["SSH_CONNECTION", "SSH_TTY"]
            .iter()
            .any(|v| std::env::var_os(v).is_some())
    {
        return None;
    }
    let registered: Option<serde_json::Value> = read(&account.config_dir.join("app/bundle.json"));
    if let Some(bundle) = registered.as_ref().and_then(|v| v["bundle"].as_str()) {
        let bundle = PathBuf::from(bundle);
        if bundle.join("Contents/MacOS/Vox").is_file() {
            return Some(bundle);
        }
    }
    // A nondefault data root belongs to its own app instance; do not wake a different profile.
    if !vox_core::node::paths::default_data_root().is_ok_and(|p| p == account.data_root) {
        return None;
    }
    let executable = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok());
    let bundled = executable
        .as_deref()
        .and_then(|p| {
            p.ancestors()
                .find(|p| p.extension().is_some_and(|x| x == "app"))
        })
        .map(Path::to_path_buf);
    let home = std::env::var_os("HOME").map(|p| PathBuf::from(p).join("Applications/Vox.app"));
    [bundled, home, Some(PathBuf::from("/Applications/Vox.app"))]
        .into_iter()
        .flatten()
        .find(|p| p.join("Contents/MacOS/Vox").is_file())
}

/// The CLI starts only the app handoff, then returns. No secret is read or returned here.
pub(crate) fn request_in_app(
    args: &NodeArgs,
    harness: &'static str,
    name: &NodeName,
) -> Result<bool, AppError> {
    let account = args.account()?;
    let Some(bundle) = local_app(&account) else {
        return Ok(false);
    };
    let dir = std::env::current_dir()?;
    let session = crate::coord::session_if_named();
    let lock = request_lock(&account, harness)?;
    let current = request(&account, harness);
    let waiting = current.filter(|r| {
        r.explicit
            && read::<Answer>(&file(&account, harness, ".answer.json"))
                .is_none_or(|a| a.request != r.id)
    });
    if let Some(mut waiting) = waiting {
        if waiting.node != name.as_str() {
            return Err(AppError::Usage(format!(
                "Vox is already asking about node {}; answer that request first",
                waiting.node
            )));
        }
        if let Some(session) = session.filter(|s| !waiting.sessions.contains(s)) {
            if waiting.sessions.len() >= 64 {
                return Err(AppError::Usage(
                    "Vox already has 64 sessions waiting for this setup; answer it in Vox first"
                        .into(),
                ));
            }
            waiting.sessions.push(session);
            write_request(&account, &waiting)?;
        }
    } else {
        write_request(
            &account,
            &Request {
                harness: harness.into(),
                dir: dir.display().to_string(),
                node: name.to_string(),
                id: format!("{}-{}", std::process::id(), crate::wake::now_millis()),
                sessions: session.into_iter().collect(),
                explicit: true,
            },
        )?;
    }
    drop(lock);
    if declined(&account, harness) {
        println!(
            "vox: the person declined setup for {harness}; they can choose Set Up in Vox Settings."
        );
        return Ok(true);
    }
    // Explicit roots also reach a stopped app. In particular, a scratch request can never open
    // that bundle on the person's real profile. No harness environment or secret is forwarded.
    let status = std::process::Command::new("/usr/bin/open")
        .arg("-a")
        .arg(bundle)
        .arg("--env")
        .arg(format!("VOX_DATA_DIR={}", account.data_root.display()))
        .arg("--env")
        .arg(format!("VOX_CONFIG_DIR={}", account.config_dir.display()))
        .arg(format!("vox://agent-setup?harness={harness}"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        return Err(AppError::Usage(
            "Vox.app could not be opened; the setup request is saved for when it opens".into(),
        ));
    }
    println!("vox: Vox has asked the person to set up {harness} in its own window.");
    Ok(true)
}

/// An explicit request's one-sentence outcome. A declined unsolicited offer is silence instead.
pub(crate) fn outcome(account: &Account, harness: &str, session: &str) -> Option<String> {
    let r = request(account, harness)?;
    if !r.explicit || !r.sessions.iter().any(|s| s == session) {
        return None;
    }
    let answer: Option<Answer> = read(&file(account, harness, ".answer.json"));
    let answer = answer.filter(|a| a.request == r.id);
    let state = answer
        .as_ref()
        .map(|a| a.outcome.as_str())
        .unwrap_or_else(|| {
            if declined(account, harness) {
                "declined"
            } else {
                "pending"
            }
        });
    let words = match state {
        "ready" => format!(
            "Vox node {} is made and Ready.",
            NodeName::parse(&answer.as_ref()?.node).ok()?
        ),
        "declined" => format!("The person declined Vox node setup for {harness}."),
        _ => format!("The person has not answered Vox node setup for {harness} yet."),
    };
    crate::agent_hook::first_in_session(
        account,
        &format!("setup-{harness}-{}-{state}", r.id),
        session,
    )
    .then_some(words)
}

/// The light hook is node-free, even if a harness cached it while the app replaced its hook.
pub(crate) fn light_words(
    account: &Account,
    harness: &'static str,
    session: &str,
    dir: &Path,
) -> Option<String> {
    if request(account, harness)
        .is_some_and(|r| r.explicit && r.sessions.iter().any(|s| s == session))
    {
        return outcome(account, harness, session);
    }
    if declined(account, harness) {
        return None;
    }
    let wiring = crate::setup::Wiring::of(harness).ok()?;
    if crate::setup::connected(account, &wiring).is_some() {
        return None;
    }
    let _ = offer(account, harness, dir);
    if !crate::agent_hook::first_in_session(account, &format!("light-{harness}"), session) {
        return None;
    }
    Some(if local_app(account).is_some() {
        format!("{harness} has no Vox node on this machine; Vox offers Set Up, and you may start it with `vox agent setup {harness}`.")
    } else {
        format!("{harness} has no Vox node on this machine; ask the operator to run `vox agent setup {harness}` in a terminal outside this session.")
    })
}
