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
//! And **`vox setup` wires each installed harness to a node of its own** (ADR-029 §7, #552), typed
//! at a real terminal (a pty) as an operator types it: with Claude Code and OpenCode on `PATH` and
//! Codex not, it says Codex is not found and makes no node for it; it makes `claude-<host>` and
//! `opencode-<host>` with the passphrases typed; it installs each one's hook where the harness
//! reads it, which `vox agent doctor` passes, keeping what Claude's settings already held, in its
//! order, and
//! replacing the Vox hook for another node there; on macOS it offers a node for the person, and
//! skipping it makes none (`vox node list` lists exactly the two); and it prints each node's
//! fingerprint, grouped with its art, as `vox id` has it, with its alias, harness, host, OS and
//! Vox version. Mutant: a harness not on `PATH` taken as found (a node made for Codex).
//!
//! And **`vox setup` keeps Codex's app-server running** when it wires Codex (the decider,
//! 2026-10-06): it says first that it will, and that this runs no model; it asks the `codex` it
//! found on `PATH` for `app-server daemon start` under the Codex home it wires, waits for the
//! app-server's control socket to take a connection, and says it is running. The `codex` here is a
//! stand-in that records what it was asked and, on that command, listens on the control socket;
//! the real Codex is never run. Mutant: setup wires Codex without starting its app-server.
//!
//! No harness and no model runs: the harnesses' settings are files in this test's directories,
//! and the harnesses' programs on `PATH` are stand-ins that only exist.

#![cfg(unix)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// `vox setup` on a pseudo-terminal, as an operator runs it: what it printed, as text, and a way
/// to answer it. Killed by its own handle when dropped.
struct Setup {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    input: Box<dyn Write + Send>,
    said: Arc<Mutex<String>>,
}

impl Drop for Setup {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Setup {
    fn spawn(d: &Dirs, path: &str) -> Self {
        use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem as _};
        let pair = NativePtySystem::default()
            .openpty(PtySize {
                rows: 50,
                cols: 200,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("APPARATUS: open a pty");
        let r = &d.root;
        let mut cmd = CommandBuilder::new(VOX);
        cmd.arg("setup");
        cmd.env_clear();
        cmd.cwd(r);
        for (k, v) in [
            ("PATH", path.to_owned()),
            ("HOME", r.join("home").display().to_string()),
            ("USER", "proof".to_owned()),
            ("TERM", "xterm-256color".to_owned()),
            ("VOX_DATA_DIR", r.join("d").display().to_string()),
            ("VOX_CONFIG_DIR", r.join("c").display().to_string()),
            ("VOX_PROXY", "127.0.0.1:0".to_owned()),
            ("CLAUDE_CONFIG_DIR", r.join("claude").display().to_string()),
            ("CODEX_HOME", r.join("codex").display().to_string()),
            ("OPENCODE_CONFIG_DIR", r.join("oc").display().to_string()),
        ] {
            cmd.env(k, v);
        }
        let child = pair
            .slave
            .spawn_command(cmd)
            .expect("APPARATUS: spawn vox setup");
        drop(pair.slave);
        let mut reader = pair
            .master
            .try_clone_reader()
            .expect("APPARATUS: pty reader");
        let input = pair.master.take_writer().expect("APPARATUS: pty writer");
        let said = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&said);
        let master = pair.master;
        std::thread::spawn(move || {
            let _master = master;
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => sink
                        .lock()
                        .unwrap()
                        .push_str(&String::from_utf8_lossy(&buf[..n])),
                }
            }
        });
        Self { child, input, said }
    }

    fn said(&self) -> String {
        self.said.lock().unwrap().replace('\r', "")
    }

    /// Wait up to 120 s (a node's passphrase is sealed with production Argon2id) for the
    /// `n`-th `want` in what setup said, then type `keys`.
    fn answer(&mut self, want: &str, n: usize, keys: &str) {
        let deadline = Instant::now() + Duration::from_secs(120);
        while self.said().matches(want).count() < n {
            assert!(
                Instant::now() < deadline && self.child.try_wait().ok().flatten().is_none(),
                "PRODUCT: `vox setup` never asked {want:?} (the {n}th time); it said:\n{}",
                self.said()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        // Raw mode is set only once the question is printed: let it settle before typing.
        std::thread::sleep(Duration::from_millis(200));
        self.input
            .write_all(keys.as_bytes())
            .and_then(|()| self.input.flush())
            .expect("APPARATUS: type into vox setup");
    }

    /// Wait up to 120 s for setup to exit: its exit status.
    fn finish(&mut self) -> portable_pty::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                std::thread::sleep(Duration::from_millis(200));
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "PRODUCT: `vox setup` did not finish within 120 s of its last answer; it said:\n{}",
                self.said()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

#[test]
#[ignore = "real binary, production Argon2id, a pty; run in release"]
fn setup_makes_a_node_for_each_installed_harness() {
    let d = Dirs::new();
    // Claude Code and OpenCode are installed; Codex is not. Stand-ins that only exist.
    let bin = d.root.join("bin");
    std::fs::create_dir_all(&bin).expect("APPARATUS: a bin directory");
    for program in ["claude", "opencode"] {
        let p = bin.join(program);
        write(&p, "#!/bin/sh\nexit 0\n");
        std::fs::set_permissions(
            &p,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
        )
        .expect("APPARATUS: make a stand-in executable");
    }
    // `hostname` and `sw_vers` are in /bin and /usr/bin; no harness is.
    let path = format!("{}:/usr/bin:/bin", bin.display());
    for program in ["claude", "codex", "opencode"] {
        for dir in ["/usr/bin", "/bin"] {
            assert!(
                !Path::new(dir).join(program).exists(),
                "APPARATUS: {dir}/{program} exists, so this machine cannot stage a harness that \
                 is not installed"
            );
        }
    }
    // Claude's settings already hold the person's own hook, a setting, and a Vox hook for
    // another node, which setup is to replace.
    write(
        &d.claude_settings(),
        r#"{"theme":"dark","hooks":{"UserPromptSubmit":[{"hooks":[{"type":"command","command":"vox agent hook --node someone-else"},{"type":"command","command":"echo mine"}]}]}}"#,
    );

    let mut setup = Setup::spawn(&d, &path);
    // ---- Codex is said not found, and offered nothing ----
    // Read before anything is answered: what it found is said first, and a question for Codex
    // would come before OpenCode's.
    setup.answer("wire Claude Code to it?", 1, "");
    let found = setup.said();
    assert!(
        found
            .lines()
            .any(|l| l.trim_start().starts_with("Codex") && l.contains("not found")),
        "PRODUCT: `vox setup` must say Codex, which is not on PATH, is not found:\n{found}"
    );
    setup.answer("wire Claude Code to it?", 1, "\r");
    setup.answer("passphrase for claude-", 1, "claude passphrase\r");
    setup.answer("again:", 1, "claude passphrase\r");
    setup.answer("wire OpenCode to it?", 1, "\r");
    setup.answer("passphrase for opencode-", 1, "opencode passphrase\r");
    setup.answer("again:", 2, "opencode passphrase\r");
    if cfg!(target_os = "macos") {
        // The person's node is offered, and skipped.
        setup.answer("Create a node for you?", 1, "\r");
    }
    let status = setup.finish();
    let said = setup.said();
    println!("[proof] vox setup said:\n{said}");
    assert!(
        status.success(),
        "PRODUCT: `vox setup` failed ({status:?}):\n{said}"
    );

    assert!(
        !said.contains("wire Codex"),
        "PRODUCT: `vox setup` must offer Codex, which is not installed, nothing:\n{said}"
    );

    // ---- exactly the two nodes ----
    let (ok, listed, err) = d.vox(&["node", "list"]);
    assert!(ok, "PRODUCT (staging): vox node list: {err}");
    let nodes: Vec<&str> = listed
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|w| w.contains('-'))
        .collect();
    let host = nodes
        .iter()
        .find_map(|n| n.strip_prefix("claude-"))
        .unwrap_or_default()
        .to_owned();
    println!("[proof] vox node list:\n{listed}");
    assert!(
        !host.is_empty()
            && nodes.contains(&format!("opencode-{host}").as_str())
            && nodes.len() == 2,
        "PRODUCT: `vox setup` must make claude-<host> and opencode-<host> and nothing else (no \
         node for Codex, none for the person who skipped it): `vox node list` says:\n{listed}"
    );

    // ---- each node's card: its fingerprint, grouped, with art, and its facts ----
    for (harness, name) in [("Claude Code", "claude"), ("OpenCode", "opencode")] {
        let node = format!("{name}-{host}");
        let (ok, id, err) = d.vox(&["id", "--node", &node]);
        assert!(ok, "PRODUCT (staging): vox id --node {node}: {err}");
        let fp = id.trim();
        let first: Vec<&str> = (0..5).map(|i| &fp[i * 4..i * 4 + 4]).collect();
        let facts = format!("alias {node} · harness {harness} · host {host} · ");
        let card_row = said
            .lines()
            .find(|l| l.contains(&first.join(" ")))
            .unwrap_or_default();
        let fact_row = said
            .lines()
            .find(|l| l.contains(&facts))
            .unwrap_or_default();
        println!("[proof] {node}: {card_row:?} / {fact_row:?}");
        assert!(
            card_row.contains(['◢', '◣', '◤', '◥'])
                && fact_row.contains(&format!("vox {}", env!("CARGO_PKG_VERSION"))),
            "PRODUCT: `vox setup` must print {node}'s fingerprint ({fp}) grouped with its art, \
             and its alias, harness, host, OS and Vox version:\n{said}"
        );
    }

    // ---- each hook installed where its harness reads it, acting as its node ----
    for (check, node) in [
        ("claude-hook UserPromptSubmit", format!("claude-{host}")),
        ("opencode-plugin", format!("opencode-{host}")),
    ] {
        let (_, out, err) = d.vox(&["agent", "doctor", "--node", &node]);
        let line = doctor_line(&format!("{out}{err}"), check);
        println!("[proof] doctor --node {node}: {line}");
        assert!(
            line.starts_with("ok"),
            "PRODUCT: after `vox setup`, `vox agent doctor --node {node}` must pass {check}; it \
             said:\n{line}\nall:\n{out}{err}"
        );
    }
    let kept = std::fs::read_to_string(d.claude_settings()).unwrap_or_default();
    // In the order the person had it: `theme` was first, then `hooks`.
    let in_order = matches!(
        (kept.find("\"theme\""), kept.find("\"hooks\"")),
        (Some(t), Some(h)) if t < h
    );
    assert!(
        kept.contains("echo mine") && in_order && !kept.contains("someone-else"),
        "PRODUCT: `vox setup` must keep what Claude's settings held, in its order, and replace \
         the Vox hook for another node: {kept}"
    );
}

/// A stand-in `codex`: it records each command it is given in `$CODEX_HOME/asked`, and on
/// `app-server daemon start` it leaves a process listening on the app-server's control socket, its
/// pid in `$CODEX_HOME/listener.pid`, as Codex's daemon would. Never the real Codex.
const CODEX_STANDIN: &str = r#"#!/usr/bin/env python3
import os, socket, sys, time
home = os.environ.get("CODEX_HOME") or os.path.join(os.environ["HOME"], ".codex")
os.makedirs(home, exist_ok=True)
with open(os.path.join(home, "asked"), "a") as f:
    f.write(" ".join(sys.argv[1:]) + "\n")
if sys.argv[1:4] == ["app-server", "daemon", "start"]:
    d = os.path.join(home, "app-server-control")
    os.makedirs(d, exist_ok=True)
    if os.fork() == 0:
        os.setsid()
        null = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(null, fd)
        s = socket.socket(socket.AF_UNIX)
        s.bind(os.path.join(d, "app-server-control.sock"))
        s.listen(4)
        with open(os.path.join(home, "listener.pid"), "w") as f:
            f.write(str(os.getpid()))
        time.sleep(300)
        os._exit(0)
"#;

#[test]
#[ignore = "real binary, production Argon2id, a pty; run in release"]
fn setup_keeps_codex_app_server_running() {
    let d = Dirs::new();
    let bin = d.root.join("bin");
    std::fs::create_dir_all(&bin).expect("APPARATUS: a bin directory");
    let codex = bin.join("codex");
    write(&codex, CODEX_STANDIN);
    std::fs::set_permissions(
        &codex,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
    )
    .expect("APPARATUS: make the stand-in executable");
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let codex_home = d.root.join("codex");

    let mut setup = Setup::spawn(&d, &path);
    setup.answer("wire Codex to it?", 1, "\r");
    setup.answer("passphrase for codex-", 1, "codex passphrase\r");
    setup.answer("again:", 1, "codex passphrase\r");
    if cfg!(target_os = "macos") {
        setup.answer("Create a node for you?", 1, "\r");
    }
    let status = setup.finish();
    let said = setup.said();
    let asked = std::fs::read_to_string(codex_home.join("asked")).unwrap_or_default();
    // The stand-in's listener is this test's to stop, by its own pid.
    if let Ok(pid) = std::fs::read_to_string(codex_home.join("listener.pid")) {
        let _ = Command::new("kill").arg(pid.trim()).status();
    }
    println!("[proof] vox setup said:\n{said}\n[proof] the stand-in codex was asked:\n{asked}");
    assert!(
        status.success(),
        "PRODUCT: `vox setup` failed ({status:?}):\n{said}"
    );
    let before = said.find("Codex's app-server is to be kept running");
    let after = said.find("Codex's app-server is running");
    assert!(
        matches!((before, after), (Some(b), Some(a)) if b < a) && said.contains("it runs no model"),
        "PRODUCT: `vox setup` must say first that it is to keep Codex's app-server running and \
         that this runs no model, then that it is running:\n{said}"
    );
    assert!(
        asked.lines().any(|l| l.trim() == "app-server daemon start")
            && !asked.contains("bootstrap")
            && !asked.contains("restart"),
        "PRODUCT: `vox setup` must ask the `codex` on PATH for `app-server daemon start`, and \
         never bootstrap or restart; it asked:\n{asked}"
    );
}
