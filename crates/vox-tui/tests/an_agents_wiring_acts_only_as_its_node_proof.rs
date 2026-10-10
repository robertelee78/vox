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
//! And **the operator names each harness's node** (#665): setup suggests `<harness>-<host>`, and
//! Enter keeps it (OpenCode here); a name typed instead is the node made and the one its hook
//! names (Claude Code here, `my-claude`), and a name `vox node create` would refuse (`Bad Name!`)
//! is refused with its reason and asked again. Mutant: the typed name ignored, the suggestion
//! always taken; red as PRODUCT (no node `my-claude`).
//!
//! And **a harness's node may have no passphrase** (ADR-005 J-2, V030-36): OpenCode's is typed as
//! Enter alone, twice; setup says once that its key is then kept unencrypted, makes it, and wires
//! its plugin, which `vox agent doctor` passes. Mutant: an empty identity passphrase refused again;
//! red as PRODUCT.
//!
//! And **each node setup makes is attached at once, and remembered** (#666): setup's daemon is
//! stopped, a new one started, and with nobody typing `vox node list` says OpenCode's node (made
//! with no passphrase) is attached, and on macOS Claude Code's too, its typed passphrase read
//! from the Keychain. The Keychain is a keychain file of this test's own (`VOX_TEST_KEYCHAIN`,
//! the `test-knobs` feature), never the person's. Mutant: the daemon's Keychain lookup off; red
//! as PRODUCT on my-claude.
//!
//! And **a harness connected already is left as it is** (#666): `vox setup` run again says Claude
//! Code is connected to node my-claude and OpenCode to its node, each left as it is, and offers no
//! second node; `vox agent connect claude --node another` says the same and makes no node.
//! Mutant: the hook's node not looked at (`Wiring::wired_node` ignored); red as PRODUCT.
//!
//! And **the doctor judges each harness against its own node** (#666): `vox agent doctor --node
//! opencode-<host>` says Claude Code is wired to its own node my-claude and passes it, rather than
//! failing it and telling the operator to rewire it onto OpenCode's node. Mutant: every harness
//! judged against the asking node; red as PRODUCT.
//!
//! And **a node renamed takes everything with it** (#666): `vox node rename my-claude
//! claude-m5max-work` leaves the node attached under the new name with the same fingerprint, and
//! no my-claude; Claude Code's settings run its hook as the new name and set VOX_NODE to it; the
//! hook registers as it and a post as it lands in its room; and on macOS a daemon restart attaches
//! it again by the new name, its passphrase moved in the Keychain. Mutant: the harnesses' settings
//! not rewritten; red as PRODUCT.
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

#[path = "support/test_knobs.rs"]
mod test_knobs;

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
            // Short, for the socket path: macOS's /private/tmp, else /tmp (Linux).
            .tempdir_in(if cfg!(target_os = "macos") {
                "/private/tmp"
            } else {
                "/tmp"
            })
            .expect("APPARATUS: a temp dir");
        let root = tmp.path().to_path_buf();
        for d in ["claude", "codex", "oc", "c", "home"] {
            std::fs::create_dir_all(root.join(d)).expect("APPARATUS: a directory");
        }
        // **Never the person's login keychain** (#666): a passphrase typed to setup is stored in
        // the Keychain, so this test's `vox` keeps it in a keychain file of its own
        // (VOX_TEST_KEYCHAIN), made here unlocked with an empty password. `create-keychain`
        // makes the file and changes no search list and no default; with HOME the test's own,
        // nothing of the person's is read either.
        if cfg!(target_os = "macos") {
            let made = Command::new("/usr/bin/security")
                .args(["create-keychain", "-p", ""])
                .arg(root.join("k.keychain-db"))
                .env("HOME", root.join("home"))
                .stdin(Stdio::null())
                .status();
            assert!(
                made.is_ok_and(|s| s.success()),
                "APPARATUS: `security create-keychain` did not make the test's keychain file"
            );
        }
        Self { _tmp: tmp, root }
    }

    /// The test's keychain file (macOS), as `VOX_TEST_KEYCHAIN` names it.
    fn keychain(&self) -> PathBuf {
        self.root.join("k.keychain-db")
    }

    fn vox(&self, args: &[&str]) -> (bool, String, String) {
        self.vox_with(args, &[])
    }

    /// `vox args`, with `extra` set in its environment after the test's own.
    fn vox_with(&self, args: &[&str], extra: &[(&str, &str)]) -> (bool, String, String) {
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
            .env("VOX_TEST_KEYCHAIN", self.keychain())
            .envs(extra.iter().copied())
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

    /// The pid of the daemon serving this test's data root, if one runs.
    fn daemon_pid(&self) -> Option<u32> {
        std::fs::read_to_string(self.root.join("d/.daemon/lock"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// `vox node list`'s line for `node`.
    fn listed(&self, node: &str) -> String {
        let (_, out, _) = self.vox(&["node", "list"]);
        out.lines()
            .find(|l| l.split_whitespace().next() == Some(node))
            .unwrap_or_default()
            .to_owned()
    }
}

impl Drop for Dirs {
    /// The daemon setup started is this test's to stop, by its own pid.
    fn drop(&mut self) {
        if let Some(pid) = self.daemon_pid() {
            let _ = Command::new("kill").arg(pid.to_string()).status();
        }
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
            ("VOX_TEST_KEYCHAIN", d.keychain().display().to_string()),
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
    if cfg!(target_os = "macos") {
        test_knobs::require(&["VOX_TEST_KEYCHAIN"]);
    }
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
    setup.answer("a node for Claude Code [claude-", 1, "");
    let found = setup.said();
    assert!(
        found
            .lines()
            .any(|l| l.trim_start().starts_with("Codex") && l.contains("not found")),
        "PRODUCT: `vox setup` must say Codex, which is not on PATH, is not found:\n{found}"
    );
    // A name `vox node create` refuses is refused, with its reason, and asked again; then a name
    // of the operator's own is taken.
    setup.answer("a node for Claude Code [claude-", 1, "Bad Name!\r");
    setup.answer("a node for Claude Code [claude-", 2, "my-claude\r");
    setup.answer("passphrase for my-claude", 1, "claude passphrase\r");
    setup.answer("again:", 1, "claude passphrase\r");
    // Enter keeps the suggestion.
    setup.answer("a node for OpenCode [opencode-", 1, "\r");
    // No passphrase, Enter alone twice (ADR-005 J-2): taken, and what it means said.
    setup.answer("passphrase for opencode-", 1, "\r");
    setup.answer("again:", 2, "\r");
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

    let refused = said.find("\"Bad Name!\" holds ' '");
    let asked_again = said
        .match_indices("a node for Claude Code [claude-")
        .nth(1)
        .map(|(i, _)| i);
    assert!(
        matches!((refused, asked_again), (Some(r), Some(a)) if r < a),
        "PRODUCT: `vox setup` must refuse the name `Bad Name!` as `vox node create` does, saying \
         why, then ask for Claude Code's node again:\n{said}"
    );
    let none_said = said.find(
        "no identity passphrase: this node's identity key is kept on this machine unencrypted",
    );
    let opencode_made = said.find("created node opencode-");
    assert!(
        matches!((none_said, opencode_made), (Some(n), Some(m)) if n < m),
        "PRODUCT: `vox setup` must make OpenCode's node with no passphrase (Enter alone, twice), \
         saying first that its key is then kept unencrypted:\n{said}"
    );
    assert!(
        !said.contains("a node for Codex"),
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
        .find_map(|n| n.strip_prefix("opencode-"))
        .unwrap_or_default()
        .to_owned();
    println!("[proof] vox node list:\n{listed}");
    assert!(
        !host.is_empty() && nodes.contains(&"my-claude") && nodes.len() == 2,
        "PRODUCT: `vox setup` must make my-claude (the name typed for Claude Code) and \
         opencode-<host> (the suggestion kept) and nothing else (no node for Codex, none for the \
         person who skipped it): `vox node list` says:\n{listed}"
    );

    // ---- each node's card: its fingerprint, grouped, with art, and its facts ----
    for (harness, node) in [
        ("Claude Code", "my-claude".to_owned()),
        ("OpenCode", format!("opencode-{host}")),
    ] {
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
        ("claude-hook UserPromptSubmit", "my-claude".to_owned()),
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
    // ---- each harness is judged against its own node (#666): OpenCode's node's doctor leaves
    // Claude Code, wired to my-claude, as my-claude's ----
    let (ok, out, err) = d.vox(&["agent", "doctor", "--node", &format!("opencode-{host}")]);
    let line = doctor_line(&format!("{out}{err}"), "claude-hook");
    println!("[proof] doctor --node opencode-{host}, on Claude Code: {line}");
    assert!(
        line.starts_with("ok") && line.contains("wired to node my-claude") && !out.contains("fail  claude-hook"),
        "PRODUCT: `vox agent doctor --node opencode-{host}` must leave Claude Code, wired to its own \
         node my-claude, as that node's, not fail it ({ok}): {line}\nall:\n{out}{err}"
    );
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

    // ---- each node made is attached at once, and one with no passphrase comes back by itself
    // after the daemon restarts (#666) ----
    let opencode = format!("opencode-{host}");
    for node in ["my-claude", opencode.as_str()] {
        let line = d.listed(node);
        assert!(
            line.contains(" attached"),
            "PRODUCT: `vox setup` must attach node {node} at once: `vox node list` says {line:?}"
        );
    }
    let pid = d
        .daemon_pid()
        .expect("PRODUCT: `vox setup` attached its nodes, but no daemon holds the lock");
    let _ = Command::new("kill").arg(pid.to_string()).status();
    let gone = Instant::now() + Duration::from_secs(30);
    while d.daemon_pid() == Some(pid)
        && Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    {
        assert!(
            Instant::now() < gone,
            "APPARATUS: the daemon did not stop within 30 s"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let (ok, out, err) = d.vox(&["daemon", "--detach"]);
    assert!(ok, "PRODUCT (staging): vox daemon --detach: {out}{err}");
    // OpenCode's, made with none, everywhere; Claude Code's, its typed passphrase in the
    // Keychain, where there is one (macOS).
    let mut back_by_itself = vec![(opencode.clone(), "made with no passphrase")];
    if cfg!(target_os = "macos") {
        back_by_itself.push((
            "my-claude".to_owned(),
            "its typed passphrase in the Keychain",
        ));
    }
    for (node, how) in back_by_itself {
        let back = Instant::now() + Duration::from_secs(60);
        let mut line = d.listed(&node);
        while !line.contains(" attached") && Instant::now() < back {
            std::thread::sleep(Duration::from_millis(200));
            line = d.listed(&node);
        }
        println!("[proof] after a restart, with nobody typing ({how}): {line:?}");
        assert!(
            line.contains(" attached"),
            "PRODUCT: node {node}, {how}, must be attached again by the daemon's own start, \
             with nobody typing: `vox node list` says {line:?}\nlog:\n{}",
            std::fs::read_to_string(d.root.join("d/.daemon/log")).unwrap_or_default()
        );
    }

    // ---- a harness connected already is left as it is (#666) ----
    let mut again = Setup::spawn(&d, &path);
    // A node offered for a harness connected already is the defect, said as that, not as a
    // question setup never reached.
    let deadline = Instant::now() + Duration::from_secs(120);
    while !again.said().contains("Create a node for you?") && Instant::now() < deadline {
        let said = again.said();
        assert!(
            !said.contains("a node for Claude Code") && !said.contains("a node for OpenCode"),
            "PRODUCT: `vox setup` run again offered a second node for a harness connected \
             already:\n{said}"
        );
        if again.child.try_wait().ok().flatten().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if cfg!(target_os = "macos") {
        again.answer("Create a node for you?", 1, "\r");
    }
    let status = again.finish();
    let second = again.said();
    println!("[proof] vox setup, run again, said:\n{second}");
    let (_, listed, _) = d.vox(&["node", "list"]);
    assert!(
        status.success()
            && second.contains("Claude Code is connected to node my-claude; left as it is")
            && second.contains(&format!(
                "OpenCode is connected to node {opencode}; left as it is"
            ))
            && !second.contains("a node for Claude Code")
            && listed.lines().filter(|l| l.contains('-')).count() == 2,
        "PRODUCT: `vox setup` run again must say each harness is connected to its node and leave \
         it as it is, offering no second node ({status:?}):\n{second}\n`vox node list`:\n{listed}"
    );
    let (ok, out, err) = d.vox(&["agent", "connect", "claude", "--node", "another"]);
    let (_, listed, _) = d.vox(&["node", "list"]);
    println!("[proof] vox agent connect claude --node another said: {out}{err}");
    assert!(
        ok && out.contains("Claude Code is connected to node my-claude; left as it is")
            && !listed.contains("another")
            && std::fs::read_to_string(d.claude_settings())
                .unwrap_or_default()
                .contains("--node my-claude"),
        "PRODUCT: `vox agent connect claude --node another` must say Claude Code is connected to \
         node my-claude and leave it as it is, making no node: {out}{err}\n`vox node list`:\n\
         {listed}"
    );

    // ---- a node renamed: everything this machine holds follows it, and its identity stays
    // (#666) ----
    let (_, before, _) = d.vox(&["id", "--node", "my-claude"]);
    let fp = before.trim().to_owned();
    // Where there is no Keychain (Linux) my-claude is attached and not remembered, and rename
    // asks for its passphrase to attach it again: given here as a script gives it.
    let (ok, out, err) = d.vox_with(
        &["node", "rename", "my-claude", "claude-m5max-work"],
        &[("VOX_IDENTITY_PASSPHRASE", "claude passphrase")],
    );
    println!("[proof] vox node rename my-claude claude-m5max-work said: {out}{err}");
    assert!(
        ok,
        "PRODUCT: `vox node rename my-claude claude-m5max-work` failed: {out}{err}"
    );
    let renamed = d.listed("claude-m5max-work");
    let (_, after, _) = d.vox(&["id", "--node", "claude-m5max-work"]);
    assert!(
        renamed.contains(" attached")
            && d.listed("my-claude").is_empty()
            && !fp.is_empty()
            && after.trim() == fp,
        "PRODUCT: renamed, the node must be attached as claude-m5max-work with the same \
         fingerprint ({fp}), and no node my-claude be left: `vox node list` says \
         {renamed:?}; its fingerprint is now {:?}",
        after.trim()
    );
    let settings = std::fs::read_to_string(d.claude_settings()).unwrap_or_default();
    assert!(
        settings.contains("vox agent hook --node claude-m5max-work")
            && settings
                .split_whitespace()
                .collect::<String>()
                .contains("\"VOX_NODE\":\"claude-m5max-work\"")
            && !settings.contains("my-claude"),
        "PRODUCT: renamed, Claude Code's settings must run its hook as claude-m5max-work and \
         set VOX_NODE to it, naming my-claude nowhere: {settings}"
    );
    // The hook the settings now run registers its session as the new name, and a post as it
    // lands in its room.
    let pass = d.root.join("room.pass");
    write(&pass, "\n");
    let pass = pass.display().to_string();
    let as_new = [("VOX_NODE", "claude-m5max-work")];
    let (ok, out, err) = d.vox_with(
        &[
            "room",
            "create",
            "--passphrase-file",
            &pass,
            "--name",
            "work",
        ],
        &as_new,
    );
    assert!(
        ok,
        "PRODUCT (staging): room create as claude-m5max-work: {out}{err}"
    );
    let (_, list, _) = d.vox_with(&["room", "list"], &as_new);
    let room = list
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    let hook = Command::new(VOX)
        .args(["agent", "hook", "--node", "claude-m5max-work"])
        .current_dir(&d.root)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", d.root.join("home"))
        .env("VOX_DATA_DIR", d.root.join("d"))
        .env("VOX_CONFIG_DIR", d.root.join("c"))
        .env("VOX_PROXY", "127.0.0.1:0")
        .env("VOX_TEST_KEYCHAIN", d.keychain())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin
                .take()
                .expect("APPARATUS: the hook's stdin")
                .write_all(br#"{"hook_event_name":"UserPromptSubmit","session_id":"s-renamed"}"#)?;
            c.wait_with_output()
        })
        .expect("APPARATUS: run the hook");
    let hook_said = String::from_utf8_lossy(&hook.stdout).into_owned();
    let (ok, out, err) = d.vox_with(&["room", "post", &room, "posted as the new name"], &as_new);
    let (_, read, _) = d.vox_with(&["room", "read", &room], &as_new);
    println!("[proof] the hook as claude-m5max-work said: {hook_said:?}; the room reads:\n{read}");
    assert!(
        hook.status.success()
            && !hook_said.contains("not attached")
            && !hook_said.contains("could not read")
            && ok
            && read.contains("posted as the new name"),
        "PRODUCT: renamed, the hook must register as claude-m5max-work and a post as it must land \
         in its room: the hook said {hook_said:?}; the post said {out}{err}; the room reads:\n\
         {read}"
    );
    // A restart keeps it attached by its new name, with nobody typing, where it is remembered.
    if cfg!(target_os = "macos") {
        if let Some(pid) = d.daemon_pid() {
            let _ = Command::new("kill").arg(pid.to_string()).status();
            let gone = Instant::now() + Duration::from_secs(30);
            while d.daemon_pid() == Some(pid) && Instant::now() < gone {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        let (ok, out, err) = d.vox(&["daemon", "--detach"]);
        assert!(ok, "PRODUCT (staging): vox daemon --detach: {out}{err}");
        let back = Instant::now() + Duration::from_secs(60);
        let mut line = d.listed("claude-m5max-work");
        while !line.contains(" attached") && Instant::now() < back {
            std::thread::sleep(Duration::from_millis(200));
            line = d.listed("claude-m5max-work");
        }
        assert!(
            line.contains(" attached"),
            "PRODUCT: renamed, claude-m5max-work must be attached again by the daemon's own \
             start, its passphrase in the Keychain under its new name: {line:?}\nlog:\n{}",
            std::fs::read_to_string(d.root.join("d/.daemon/log")).unwrap_or_default()
        );
    }
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
    if cfg!(target_os = "macos") {
        test_knobs::require(&["VOX_TEST_KEYCHAIN"]);
    }
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
    setup.answer("a node for Codex [codex-", 1, "\r");
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
