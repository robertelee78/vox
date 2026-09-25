//! Trust Vox's Codex drain hook the way Codex itself does (ADR-020 M19.11).
//!
//! Codex runs a `hooks.json` entry only once its hash is recorded as trusted; until then
//! the entry sits "under review" and the room never drains into the session. Codex's own
//! "Trust all" writes `hooks.state."<key>".trusted_hash = <currentHash>` into its
//! `config.toml`, and its app-server exposes exactly the two calls that does:
//! `hooks/list` (each hook with its `key`, `currentHash` and `trustStatus`) and
//! `config/batchWrite`. So Vox asks Codex, rather than computing Codex's hash itself —
//! which ctm and Orca both learned drifts between Codex versions.
//!
//! Measured against codex-cli 0.157.0 with an isolated `CODEX_HOME`, not read from
//! documentation: the app-server speaks newline-delimited JSON-RPC on stdio; after
//! `initialize` it may emit notifications before answering; the hash covers the hook's
//! definition (its command text), not the binary, so upgrading `vox` keeps trust unless
//! the entry's command changes. A trusted entry whose command then changes lists as
//! `modified` — neither `trusted` nor `untrusted` — so anything but `trusted` is re-granted.
//!
//! **Only Vox's own entries** — commands running `vox agent hook` — are trusted. Another
//! tool's hook is that tool's decision, and trusting it here would be granting an
//! authority nobody asked for.

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// How long one app-server call may take.
const CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// What `trust` did.
#[derive(Debug, Default)]
pub struct Report {
    /// Vox hook entries Codex reported.
    pub found: usize,
    /// Of those, how many were untrusted and are now trusted.
    pub trusted_now: usize,
}

struct AppServer {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    next_id: u64,
}

impl AppServer {
    fn start(codex: &str) -> Result<Self, String> {
        let mut child = Command::new(codex)
            .arg("app-server")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("could not start `{codex} app-server`: {e}"))?;
        let stdin = child.stdin.take().ok_or("no stdin for the app-server")?;
        let stdout = child.stdout.take().ok_or("no stdout from the app-server")?;
        let (tx, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            lines,
            next_id: 1,
        })
    }

    fn send(&mut self, msg: &Value) -> Result<(), String> {
        writeln!(self.stdin, "{msg}").map_err(|e| format!("writing to the app-server: {e}"))
    }

    /// One request and its response, skipping the notifications Codex interleaves.
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        let deadline = Instant::now() + CALL_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    let Ok(msg) = serde_json::from_str::<Value>(&line) else {
                        continue;
                    };
                    if msg.get("id").and_then(Value::as_u64) != Some(id) {
                        continue;
                    }
                    if let Some(err) = msg.get("error") {
                        return Err(format!("Codex refused {method}: {err}"));
                    }
                    return Ok(msg.get("result").cloned().unwrap_or(Value::Null));
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(format!(
                        "Codex did not answer {method} within {CALL_TIMEOUT:?}"
                    ))
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(format!("the app-server exited before answering {method}"))
                }
            }
        }
    }
}

impl Drop for AppServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Vox's hook entries in a `hooks/list` result: `(key, currentHash, trusted)`, once each.
fn ours(listed: &Value) -> Vec<(String, String, bool)> {
    let mut out: Vec<(String, String, bool)> = Vec::new();
    for h in listed["data"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|d| d["hooks"].as_array().into_iter().flatten())
    {
        let command = h["command"].as_str().unwrap_or_default();
        if !command.contains("vox agent hook") {
            continue;
        }
        let (Some(key), Some(hash)) = (h["key"].as_str(), h["currentHash"].as_str()) else {
            continue;
        };
        if out.iter().any(|(k, _, _)| k == key) {
            continue; // the same hook is reported once per cwd
        }
        out.push((
            key.to_owned(),
            hash.to_owned(),
            h["trustStatus"].as_str() == Some("trusted"),
        ));
    }
    out
}

/// Trust every untrusted Vox hook entry Codex knows about, through Codex's own RPCs, and
/// read the result back.
///
/// # Errors
/// If the app-server cannot be started or answers with an error, or if an entry still
/// reads untrusted after the write.
pub fn trust(codex: &str) -> Result<Report, String> {
    let mut app = AppServer::start(codex)?;
    app.call(
        "initialize",
        json!({"clientInfo": {"name": "vox", "version": env!("CARGO_PKG_VERSION")}}),
    )?;
    app.send(&json!({"jsonrpc": "2.0", "method": "initialized"}))?;
    let listed = ours(&app.call("hooks/list", json!({}))?);
    let edits: Vec<Value> = listed
        .iter()
        .filter(|(_, _, trusted)| !trusted)
        .map(|(key, hash, _)| {
            json!({
                // A dotted TOML path whose middle segment is a quoted key: it holds `/`,
                // `.` and `:`, so it is serialised as a JSON string.
                "keyPath": format!("hooks.state.{}.trusted_hash", Value::String(key.clone())),
                "value": hash,
                "mergeStrategy": "replace",
            })
        })
        .collect();
    let report = Report {
        found: listed.len(),
        trusted_now: edits.len(),
    };
    if edits.is_empty() {
        return Ok(report);
    }
    app.call("config/batchWrite", json!({ "edits": edits }))?;
    let after = ours(&app.call("hooks/list", json!({}))?);
    if let Some((key, _, _)) = after.iter().find(|(_, _, trusted)| !trusted) {
        return Err(format!(
            "Codex still reports {key} as untrusted after the write"
        ));
    }
    Ok(report)
}
