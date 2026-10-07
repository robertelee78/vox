//! ADR-020 2.1, 8.2 and ADR-026 N-6 (#408): **an agent's wiring acts only as its own node**,
//! through the shipped `vox` binary, as an agent setting itself up runs it.
//!
//! 1. `vox agent plugin claude --node <name>` prints hook entries that run `vox agent hook --node
//!    <name>` on every event, and `VOX_NODE` = the node in the session's environment, so the
//!    agent's own `vox` commands act as its node, never a person's on the same machine.
//! 2. `vox agent plugin codex --node <name>` prints the entry with `--node <name>`.
//! 3. `vox agent plugin opencode --node <name>` prints the plugin with the node written in: its
//!    drain runs `--node`, and its shells get `VOX_NODE`. Nothing of the template is left.
//! 4. `vox agent doctor --node <name>` fails a hook entry that names no node, or another node,
//!    saying which and how to fix it, and passes the entry the plugin prints.
//! 5. `vox agent hook` without `--node` refuses.
//!
//! No harness and no model runs: the harnesses' settings are files in this test's directories.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const VOX: &str = env!("CARGO_BIN_EXE_vox");

struct Dirs {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Dirs {
    fn new() -> Self {
        let tmp = tempfile::Builder::new()
            .prefix("vw")
            .tempdir_in("/private/tmp")
            .expect("APPARATUS: a temp dir");
        let root = tmp.path().to_path_buf();
        for d in ["claude", "codex", "oc", "c", "home"] {
            std::fs::create_dir_all(root.join(d)).expect("APPARATUS: a directory");
        }
        Self { _tmp: tmp, root }
    }

    fn vox(&self, args: &[&str]) -> (bool, String, String) {
        let mut c = Command::new(VOX);
        c.env_clear()
            // A proof's daemon never takes port 1080 (.cargo/config.toml).
            .env("VOX_PROXY", "127.0.0.1:0");
        if let Some(p) = std::env::var_os("PATH") {
            c.env("PATH", p);
        }
        let r = &self.root;
        let out = c
            .args(args)
            .current_dir(r)
            .env("HOME", r.join("home"))
            .env("VOX_DATA_DIR", r.join("d"))
            .env("VOX_CONFIG_DIR", r.join("c"))
            .env(
                "VOX_IDENTITY_PASSPHRASE",
                "the agent node's identity passphrase",
            )
            .env("CLAUDE_CONFIG_DIR", r.join("claude"))
            .env("CODEX_HOME", r.join("codex"))
            .env("OPENCODE_CONFIG_DIR", r.join("oc"))
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: run vox {args:?}: {e}"));
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn claude_settings(&self) -> PathBuf {
        self.root.join("claude").join("settings.json")
    }
}

/// The doctor's line for `id`, with its fix line.
fn doctor_line(out: &str, id: &str) -> String {
    let lines: Vec<&str> = out.lines().collect();
    lines
        .iter()
        .position(|l| l.split_whitespace().nth(1) == Some(id) || l.contains(&format!(" {id}:")))
        .map(|i| lines[i..(i + 2).min(lines.len())].join("\n"))
        .unwrap_or_default()
}

fn write(path: &Path, text: &str) {
    std::fs::write(path, text).expect("APPARATUS: write a harness file");
}

#[test]
#[ignore = "real binary; run in release"]
fn an_agents_hooks_act_only_as_its_own_node() {
    let d = Dirs::new();
    let node = "claude-mbp";

    // ---- (1) Claude Code ----
    let (ok, printed, err) = d.vox(&["agent", "plugin", "claude", "--node", node]);
    assert!(ok, "PRODUCT: vox agent plugin claude failed: {err}");
    let v: serde_json::Value = serde_json::from_str(&printed)
        .unwrap_or_else(|e| panic!("PRODUCT: the Claude settings are not JSON ({e}): {printed}"));
    for event in ["UserPromptSubmit", "Stop", "SessionEnd"] {
        assert_eq!(
            v["hooks"][event][0]["hooks"][0]["command"],
            format!("vox agent hook --node {node}"),
            "PRODUCT: the {event} hook must act as the agent's node: {printed}"
        );
    }
    assert_eq!(
        v["env"]["VOX_NODE"], node,
        "PRODUCT: Claude's settings must name the node in the session's environment, so the \
         agent's own `vox` commands act as its node: {printed}"
    );

    // ---- (2) Codex ----
    let (ok, printed, err) = d.vox(&["agent", "plugin", "codex", "--node", "codex-mbp"]);
    assert!(ok, "PRODUCT: vox agent plugin codex failed: {err}");
    let v: serde_json::Value = serde_json::from_str(&printed)
        .unwrap_or_else(|e| panic!("PRODUCT: the Codex entry is not JSON ({e}): {printed}"));
    assert_eq!(
        v["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"], "vox agent hook --node codex-mbp",
        "PRODUCT: the Codex hook must act as the agent's node: {printed}"
    );

    // ---- (3) OpenCode ----
    let (ok, plugin, err) = d.vox(&["agent", "plugin", "opencode", "--node", "oc-mbp"]);
    assert!(ok, "PRODUCT: vox agent plugin opencode failed: {err}");
    assert!(
        plugin.contains(r#"const VOX_NODE = "oc-mbp""#)
            && plugin.contains("agent hook --node ${VOX_NODE}")
            && plugin.contains("output.env.VOX_NODE = VOX_NODE")
            && !plugin.contains("@VOX_NODE@"),
        "PRODUCT: the OpenCode plugin must carry its node into the drain and every shell, with \
         nothing of the template left"
    );

    // ---- (4) the doctor ----
    let (ok, out, err) = d.vox(&["node", "create", node]);
    assert!(ok, "APPARATUS: vox node create: {out}{err}");
    let hook = |command: &str| {
        format!(
            r#"{{"hooks":{{"UserPromptSubmit":[{{"hooks":[{{"type":"command","command":"{command}"}}]}}]}}}}"#
        )
    };
    for (entry, says) in [
        ("vox agent hook", "names no node"),
        (
            "vox agent hook --node someone-else",
            "acts as node someone-else",
        ),
    ] {
        write(&d.claude_settings(), &hook(entry));
        let (_, out, err) = d.vox(&["agent", "doctor", "--node", node]);
        let line = doctor_line(&format!("{out}{err}"), "claude-hook UserPromptSubmit");
        println!("[proof] (4) entry {entry:?}: {line}");
        assert!(
            line.starts_with("fail") && line.contains(says) && line.contains("--node claude-mbp"),
            "PRODUCT: the doctor must fail a hook entry that {says}, and say what to install \
             instead; it said:\n{line}\nall:\n{out}{err}"
        );
    }
    let (_, settings, _) = d.vox(&["agent", "plugin", "claude", "--node", node]);
    write(&d.claude_settings(), &settings);
    let (_, out, err) = d.vox(&["agent", "doctor", "--node", node]);
    let line = doctor_line(&format!("{out}{err}"), "claude-hook UserPromptSubmit");
    println!("[proof] (4) the printed settings: {line}");
    assert!(
        line.starts_with("ok"),
        "PRODUCT: the doctor must pass the entry the plugin prints for this node; it said:\n{line}"
    );

    // ---- (5) a hook without --node refuses ----
    let (ok, _, err) = d.vox(&["agent", "hook"]);
    assert!(
        !ok && err.contains("--node"),
        "PRODUCT: a hook without --node must refuse, naming it: {err}"
    );
}
