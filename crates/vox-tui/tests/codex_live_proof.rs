//! ADR-020 **M19.11-live** (#169) — **a trusted Codex hook feeds the room to a live Codex turn,
//! and an untrusted one feeds it nothing.**
//!
//! `codex_trust_proof` proves, through Codex's own `hooks/list`, that `vox agent trust codex`
//! trusts Vox's entry and nothing else. It cannot prove the entry then *fires*: that takes a
//! model turn, and a sign-in. This proof takes both, on the decider's request (2026-10-03):
//!
//! 1. the agent's own node, made as its skill says (`vox node create`, ADR-026 N-6), attached with
//!    `vox node attach`, which starts the account's daemon; a room made with `vox room create`,
//!    and a codeword posted into it with `vox room post` — a token that appears nowhere in the
//!    prompt, the hook entry or Codex;
//! 2. two isolated `CODEX_HOME`s, each holding exactly the `hooks.json` that `vox agent plugin
//!    codex --node <node>` prints (`vox agent hook --node <node>`, ADR-020 2.1), and nothing of
//!    the operator's Codex configuration;
//! 3. `vox agent trust codex` run against one of them alone, and Codex's own `hooks/list` asked
//!    in both: `trusted` in one, `untrusted` in the other;
//! 4. one `codex exec` turn in each, the same prompt, which asks for a codeword if the context
//!    holds one. **Trusted:** the codeword is in what Codex recorded the model was given (its
//!    session log) and in the model's answer. **Untrusted:** it is in neither.
//!
//! The untrusted turn is the control: the same binary, prompt and room, with the one thing
//! under test (the trust grant) removed.
//!
//! ## Every Codex here is sandboxed, and holds one credential
//!
//! A model's turn may run a shell. Every `codex exec` runs under macOS `sandbox-exec` whose
//! profile ([`oc_sandbox::sandbox_profile`]) reads only the system, Codex's own install
//! directory, the `vox` binary and this run's root, and writes only the root. Before any turn a
//! shell under that profile must fail to read, find or list a canary planted in the operator's
//! real HOME; and no turn's output, nor its session log, may hold the canary's text. Codex runs
//! in a cleared environment: `PATH` (this run's `bin` with a copy of `vox`, then the system's),
//! a `HOME`, `TMPDIR` and `CODEX_HOME` inside the root, and the run's `VOX_DATA_DIR` /
//! `VOX_CONFIG_DIR` for the hook. The only thing of the operator's that enters is a copy of
//! `~/.codex/auth.json` — Codex's own sign-in, nothing else from `~/.codex` — mode 0600, copied
//! in just before the turns and removed after them, however the test ends.
//!
//! **A refresh inside the copy never strands the operator's sign-in.** A refresh rotates the
//! refresh token, so a refresh done on the copy would leave the operator's own file holding a
//! spent one. Codex does not refresh on `last_refresh`'s age alone (0.160.0 ran a turn on a
//! nine-day-old one without refreshing), so the age is not a reason to refuse. Instead, when a
//! turn's copy is removed — after the turn, or as a panic unwinds — its bytes are compared with
//! what was copied in: if Codex rewrote it, and the operator's `~/.codex/auth.json` is still
//! byte for byte what was copied, the new sign-in is written back (a temporary file in
//! `~/.codex`, mode 0600, flushed, then renamed over it); if the operator's file changed
//! meanwhile it is left as it is, and the run says so loudly. Each turn says "Codex rotated its
//! sign-in; the operator's file was updated" or "unchanged". The file's contents are never
//! printed. A run killed by a signal (the watchdog's abort, SIGTERM) runs no destructor: its
//! copy is unlinked by the signal handler, and a rotation made in that turn is not written back.
//!
//! **No hook of the operator's runs.** `CODEX_HOME` is inside the root and holds only the
//! `hooks.json` under test, so `~/.codex/hooks.json` is never read; every turn's output is
//! checked not to name the operator's `~/.codex` at all.
//!
//! **A dry run stops before Codex.** With `VOX_PROOF_STOP_BEFORE_CODEX=1` the proof does its
//! setup, the node, daemon, room and codeword, both homes, and the
//! sandbox's canary probe, then stops before the first thing that starts Codex (`vox agent trust
//! codex`, which runs Codex's app-server) and before the sign-in is copied anywhere. It says
//! `STOPPED BEFORE CODEX` and passes.
//!
//! **Never a login screen.** `codex exec` does not prompt; a turn that fails for want of a
//! sign-in is `CANNOT MEASURE`, and the run stops there.
//!
//! **Which side a red is on.** What `vox` did — the drain absent from a trusted turn, or present
//! in an untrusted one — is `PRODUCT:`. The model provider refusing, Codex not starting, or a
//! fault of this proof's own is `APPARATUS:` / `CANNOT MEASURE`. A trusted turn whose session
//! log holds the codeword but whose answer does not is `CANNOT MEASURE` for the answer (the
//! model's choice), and green for the injection, which is the claim.

// Optional (decider, 2026-10-01): it blocks nothing, and only a build with `live-model-sandbox`
// starts a model (2026-10-02). docs/release/optional-proofs.md says how to run it.
#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(
    a_live_codex_turn_reads_the_room_only_through_a_trusted_hook,
    a_live_codex_session_is_mirrored_and_driven
);

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/oc_sandbox.rs"]
mod oc_sandbox;

#[path = "support/typed.rs"]
mod typed;

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
/// The agent's own node (ADR-026 N-6): `<harness>-<host>`, as the skill names it.
const NODE: &str = "codex-proof";

/// What the model is asked: tiny, and naming no codeword.
const PROMPT: &str = "If your context contains a Vox room message with a codeword, reply with \
                      only that codeword. Otherwise reply with only the word none. Do not run \
                      any command.";

/// The daemon `vox node attach` started for the run's data root, stopped by its own PID (the
/// one in `.daemon/lock`) when dropped.
struct Daemon(PathBuf);

impl Drop for Daemon {
    fn drop(&mut self) {
        let pid = std::fs::read_to_string(self.0.join(".daemon/lock"))
            .ok()
            .and_then(|t| t.trim().parse::<u32>().ok());
        if let Some(pid) = pid {
            let _ = Command::new("/bin/kill")
                .args(["-TERM", &pid.to_string()])
                .status();
            let t0 = Instant::now();
            while t0.elapsed() < Duration::from_secs(15)
                && Command::new("/bin/kill")
                    .args(["-0", &pid.to_string()])
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success())
            {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// A dry run (`VOX_PROOF_STOP_BEFORE_CODEX=1`): everything up to the first thing that starts Codex.
fn dry_run() -> bool {
    std::env::var("VOX_PROOF_STOP_BEFORE_CODEX").is_ok_and(|v| v == "1")
}

fn vox(data: &Path, cfg: &Path, args: &[&str], input: Option<&str>) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        // Every node has a passphrase (ADR-028 K-11); the operator attaches the agent's node
        // before Codex starts, and its hook finds it attached.
        .env(
            "VOX_IDENTITY_PASSPHRASE",
            "the agent node's identity passphrase",
        )
        .env("VOX_NODE", NODE)
        .env("VOX_LISTEN", "127.0.0.1:0")
        .env_remove("VOX_ROOM")
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot start `vox {}`: {e}", args.join(" ")));
    if let Some(text) = input {
        let mut pipe = child
            .stdin
            .take()
            .unwrap_or_else(|| panic!("APPARATUS: `vox {}` has no stdin pipe", args.join(" ")));
        let _ = pipe.write_all(text.as_bytes());
        drop(pipe);
    }
    let out = child.wait_with_output().unwrap_or_else(|e| {
        panic!(
            "APPARATUS: cannot collect `vox {}`'s output: {e}",
            args.join(" ")
        )
    });
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The installed Codex, every symlink resolved, and its release directory (the binary's
/// `bin/`'s parent): all of the operator's `~/.codex` the sandbox may read.
fn codex_install() -> (PathBuf, PathBuf) {
    let found = std::env::var_os("PATH")
        .and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join("codex"))
                .find(|p| p.is_file())
        })
        .unwrap_or_else(|| panic!("APPARATUS, CANNOT MEASURE: codex is not on PATH"));
    let bin = oc_sandbox::real(&found);
    let release = bin
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| panic!("APPARATUS: codex's binary has no release directory"))
        .to_path_buf();
    (bin, release)
}

/// **A turn's copy of the operator's sign-in, and what becomes of it** (see the module doc): when
/// dropped — after the turn, or as a panic unwinds — a copy Codex rewrote is written back to the
/// operator's file if that file is still what was copied, then the copy is removed. Never prints
/// the sign-in.
struct CodexSignIn {
    copy: Option<oc_sandbox::Credential>,
    copy_path: PathBuf,
    operator: PathBuf,
    copied: Vec<u8>,
    /// What happened, once the copy is gone.
    outcome: std::rc::Rc<std::cell::RefCell<Option<String>>>,
}

impl CodexSignIn {
    fn copy(operator: &Path, to: &Path, copied: &[u8]) -> Self {
        Self {
            copy: Some(oc_sandbox::Credential::copy_file(operator, to)),
            copy_path: to.to_path_buf(),
            operator: operator.to_path_buf(),
            copied: copied.to_vec(),
            outcome: std::rc::Rc::default(),
        }
    }

    /// Write `bytes` over the operator's file: a temporary file beside it, mode 0600, flushed,
    /// renamed over it, and the directory flushed.
    fn write_back(&self, bytes: &[u8]) -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt as _;
        let dir = self
            .operator
            .parent()
            .ok_or_else(|| std::io::Error::other("the operator's file has no directory"))?;
        let tmp = dir.join(format!(".auth.json.vox-proof-{}", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        let written = f.write_all(bytes).and_then(|()| f.sync_all());
        drop(f);
        if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, &self.operator)) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        std::fs::File::open(dir)?.sync_all()
    }
}

impl Drop for CodexSignIn {
    fn drop(&mut self) {
        let now = std::fs::read(&self.copy_path).ok();
        let said = match now {
            Some(b) if b != self.copied => {
                if std::fs::read(&self.operator).ok().as_deref() == Some(self.copied.as_slice()) {
                    match self.write_back(&b) {
                        Ok(()) => {
                            "Codex rotated its sign-in; the operator's file was updated".to_owned()
                        }
                        Err(e) => {
                            let s = format!(
                                "Codex rotated its sign-in, and writing it back to the operator's \
                                 ~/.codex/auth.json FAILED ({e}): that file may hold a spent \
                                 refresh token; run `codex login status`"
                            );
                            eprintln!("[proof] !!! {s}");
                            s
                        }
                    }
                } else {
                    let s = "Codex rotated its sign-in, but the operator's ~/.codex/auth.json \
                             changed while the turn ran, so it was LEFT AS IT IS: it may hold a \
                             spent refresh token; run `codex login status`"
                        .to_owned();
                    eprintln!("[proof] !!! {s}");
                    s
                }
            }
            Some(_) => "unchanged".to_owned(),
            None => "the copy was gone before it could be compared".to_owned(),
        };
        drop(self.copy.take());
        *self.outcome.borrow_mut() = Some(said);
    }
}

/// One isolated Codex: its `CODEX_HOME`, `HOME` and `TMPDIR`, all under the run's root.
struct CodexHome {
    codex_home: PathBuf,
    home: PathBuf,
    tmp: PathBuf,
}

impl CodexHome {
    fn new(root: &Path, name: &str) -> Self {
        let base = root.join(name);
        let me = Self {
            codex_home: base.join("codex"),
            home: base.join("home"),
            tmp: base.join("tmp"),
        };
        for d in [&me.codex_home, &me.home, &me.tmp] {
            std::fs::create_dir_all(d)
                .unwrap_or_else(|e| panic!("APPARATUS: cannot make {d:?}: {e}"));
        }
        me
    }

    /// `program` in a cleared environment: only what Codex and the hook need, every path in
    /// the run's root.
    fn command(&self, program: &Path, path: &str, data: &Path, cfg: &Path) -> Command {
        let mut c = Command::new(program);
        c.env_clear()
            // A proof's daemon never takes port 1080 (.cargo/config.toml).
            .env("VOX_PROXY", "127.0.0.1:0")
            .env("PATH", path)
            .env("HOME", &self.home)
            .env("TMPDIR", &self.tmp)
            .env("CODEX_HOME", &self.codex_home)
            .env("VOX_DATA_DIR", data)
            .env("VOX_CONFIG_DIR", cfg)
            .env("LANG", "en_US.UTF-8");
        c
    }
}

/// `command -> trustStatus` for every hook Codex lists, asked of Codex's own app-server.
fn trust_status(codex: &Path, h: &CodexHome, path: &str, data: &Path, cfg: &Path) -> String {
    let mut child = h
        .command(codex, path, data, cfg)
        .arg("app-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot start codex app-server: {e}"));
    let mut stdin = child
        .stdin
        .take()
        .expect("APPARATUS: codex app-server has no stdin pipe");
    let mut lines = BufReader::new(
        child
            .stdout
            .take()
            .expect("APPARATUS: codex app-server has no stdout pipe"),
    )
    .lines();
    let mut ask = |id: u64, method: &str| -> serde_json::Value {
        writeln!(
            stdin,
            "{}",
            serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method,
                "params": if method == "initialize" {
                    serde_json::json!({"clientInfo": {"name": "proof", "version": "0"}})
                } else { serde_json::json!({}) }})
        )
        .unwrap_or_else(|e| panic!("APPARATUS: cannot write to codex app-server: {e}"));
        loop {
            let line = lines
                .next()
                .unwrap_or_else(|| {
                    panic!("APPARATUS: codex app-server closed before answering {method}")
                })
                .unwrap_or_else(|e| panic!("APPARATUS: cannot read codex app-server: {e}"));
            let v: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
            if v["id"] == id {
                return v["result"].clone();
            }
        }
    };
    ask(1, "initialize");
    let listed = ask(2, "hooks/list");
    let _ = child.kill();
    let _ = child.wait();
    let statuses: Vec<String> = listed["data"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|d| d["hooks"].as_array().cloned().unwrap_or_default())
        .filter(|h| h["command"] == format!("vox agent hook --node {NODE}"))
        .map(|h| h["trustStatus"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(
        statuses.len(),
        1,
        "PRODUCT: Codex must list exactly one `vox agent hook --node {NODE}` entry from what `vox \
         agent plugin codex --node {NODE}` prints; it lists {statuses:?}"
    );
    statuses[0].clone()
}

/// Every file under `dir`, recursively, read as text and joined: Codex's session logs.
fn session_logs(dir: &Path) -> String {
    let mut out = String::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "jsonl") {
                out += &std::fs::read_to_string(&p).unwrap_or_default();
                out.push('\n');
            }
        }
    }
    out
}

/// The line of `text` holding `needle`, cut to a readable length around it.
fn evidence(text: &str, needle: &str) -> Option<String> {
    let line = text.lines().find(|l| l.contains(needle))?;
    let at = line.find(needle)?;
    let mut from = at.saturating_sub(240);
    while !line.is_char_boundary(from) {
        from -= 1;
    }
    let mut to = (at + needle.len() + 120).min(line.len());
    while !line.is_char_boundary(to) {
        to += 1;
    }
    Some(line[from..to].to_owned())
}

/// What a turn left: everything it printed, its last message, and its session logs.
struct Turn {
    said: String,
    answer: String,
    logs: String,
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "drives a real Codex model turn; optional, on the decider's request, in release"]
fn a_live_codex_turn_reads_the_room_only_through_a_trusted_hook() {
    watchdog::arm_for(Duration::from_secs(900));
    if !oc_sandbox::live_model_allowed(
        "codex_live_proof::a_live_codex_turn_reads_the_room_only_through_a_trusted_hook",
    ) {
        return;
    }
    let (codex, codex_release) = codex_install();

    // ---- the sign-in: present ----
    let real_home = watchdog::temp_home::real_home()
        .unwrap_or_else(|| panic!("APPARATUS: HOME is unset, so Codex's sign-in cannot be found"));
    let auth_src = real_home.join(".codex/auth.json");
    let auth_bytes = std::fs::read(&auth_src).unwrap_or_else(|_| {
        panic!("CANNOT MEASURE: no ~/.codex/auth.json, so no Codex turn can run; sign in to Codex")
    });
    let _: serde_json::Value = serde_json::from_slice(&auth_bytes)
        .unwrap_or_else(|_| panic!("APPARATUS: ~/.codex/auth.json is not JSON"));

    // ---- the run's root: short, so the node's socket sits in its profile ----
    std::fs::create_dir_all("/private/tmp/vc")
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make /private/tmp/vc: {e}"));
    let tmp = tempfile::Builder::new()
        .prefix("cxl-")
        .tempdir_in("/private/tmp/vc")
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make a temp directory: {e}"));
    let root = oc_sandbox::real(tmp.path());
    let data = root.join("vd");
    let cfg = root.join("vc");
    let bin = root.join("bin");
    let work = root.join("work");
    for d in [&bin, &work] {
        std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("APPARATUS: cannot make {d:?}: {e}"));
    }
    // A copy of this `vox` (not a link) where the hook's bare `vox` finds it.
    std::fs::copy(VOX, bin.join("vox"))
        .unwrap_or_else(|e| panic!("APPARATUS: cannot copy vox into the run: {e}"));
    let path = format!("{}:{}", bin.display(), oc_sandbox::SANDBOX_PATH);

    // ---- the agent's own node, its daemon, a real room, and a codeword only the room knows ----
    let (ok, out, err) = vox(&data, &cfg, &["node", "create", NODE], None);
    assert!(ok, "PRODUCT: `vox node create {NODE}` failed: {out}{err}");
    let (ok, out, err) = vox(&data, &cfg, &["node", "attach", NODE], None);
    let _daemon = Daemon(data.clone());
    assert!(
        ok,
        "PRODUCT (staging): `vox node attach {NODE}` (which starts the daemon) failed: {out}{err}"
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    while !vox(&data, &cfg, &["room", "list"], None).0 {
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): the daemon never answered; its log: {:?}",
            std::fs::read_to_string(data.join(".daemon/log")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let (ok, _, err) = vox(
        &data,
        &cfg,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "agents",
        ],
        Some("channel passphrase\n"),
    );
    assert!(ok, "PRODUCT (staging): `vox room create` refused: {err}");
    let (_, list, _) = vox(&data, &cfg, &["room", "list"], None);
    let room = list
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("PRODUCT (staging): `vox room list` shows no room: {list:?}"))
        .to_owned();
    let codeword = format!(
        "ZORVEL-{:06}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|e| panic!("APPARATUS: the clock is before 1970: {e}"))
            .subsec_micros()
    );
    let (ok, _, err) = vox(
        &data,
        &cfg,
        &[
            "room",
            "post",
            &room,
            &format!("The codeword for this mission is {codeword}."),
        ],
        None,
    );
    assert!(ok, "PRODUCT (staging): `vox room post` refused: {err}");
    println!("[proof] room {room} holds codeword {codeword}, posted through `vox room post`");

    // ---- two isolated Codex homes, each with exactly what `vox agent plugin codex` prints ----
    let plugin = Command::new(VOX)
        .args(["agent", "plugin", "codex", "--node", NODE])
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run vox agent plugin codex: {e}"));
    assert!(
        plugin.status.success(),
        "PRODUCT: `vox agent plugin codex --node {NODE}` failed"
    );
    let trusted = CodexHome::new(&root, "trusted");
    let untrusted = CodexHome::new(&root, "untrusted");
    for h in [&trusted, &untrusted] {
        std::fs::write(h.codex_home.join("hooks.json"), &plugin.stdout)
            .unwrap_or_else(|e| panic!("APPARATUS: cannot write hooks.json: {e}"));
    }

    // ---- the sandbox, probed against the canary before any turn ----
    let canary = oc_sandbox::Canary::plant();
    let profile = root.join("codex.sb");
    std::fs::write(
        &profile,
        oc_sandbox::sandbox_profile(&[&root], &[&codex_release]),
    )
    .unwrap_or_else(|e| panic!("APPARATUS: cannot write the sandbox profile: {e}"));
    oc_sandbox::probe_profile(&profile, &canary, "codex");

    // ---- a dry run stops here: nothing above started Codex or copied its sign-in ----
    if dry_run() {
        // What the trusted turn's hook will run, run here the way Codex would run it: the
        // printed command, under the same sandbox and the same cleared environment, with a
        // hook input as Codex sends one. It reaches the daemon and drains the codeword.
        let command = format!("vox agent hook --node {NODE}");
        let mut hook = trusted.command(Path::new("/usr/bin/sandbox-exec"), &path, &data, &cfg);
        hook.arg("-f")
            .arg(&profile)
            .args(["/bin/sh", "-c", &command])
            .current_dir(&work)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = hook
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot run the hook in the sandbox: {e}"));
        let _ = child
            .stdin
            .take()
            .map(|mut i| i.write_all(br#"{"session_id":"dry-run","turn_id":"t1"}"#));
        let out = child
            .wait_with_output()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot collect the hook's output: {e}"));
        let drained = String::from_utf8_lossy(&out.stdout).into_owned();
        canary.check(&drained, "the sandboxed hook's output");
        assert!(
            out.status.success() && drained.contains(&codeword),
            "PRODUCT: `{command}`, run as Codex would run it in the sandbox, did not drain the \
             room's codeword: {drained}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        println!(
            "[proof] the printed hook, run in the sandbox as Codex runs it, drained {codeword}"
        );
        println!(
            "[proof] STOPPED BEFORE CODEX: node {NODE}, daemon, room {room}, codeword, both homes \
             and the sandbox probe are ready; no Codex was started and no sign-in was copied"
        );
        return;
    }

    // ---- the trust grant, in one home alone; Codex's own answer for both ----
    let out = trusted
        .command(Path::new(VOX), &path, &data, &cfg)
        .args(["agent", "trust", "codex", "--codex"])
        .arg(&codex)
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run vox agent trust codex: {e}"));
    let said =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && said.contains("1 newly trusted"),
        "PRODUCT: `vox agent trust codex` must trust Vox's entry: {said}"
    );
    let t = trust_status(&codex, &trusted, &path, &data, &cfg);
    let u = trust_status(&codex, &untrusted, &path, &data, &cfg);
    println!("[proof] Codex's hooks/list: trusted home {t:?}, untrusted home {u:?}");
    assert_eq!(
        t, "trusted",
        "PRODUCT: Codex does not list Vox's entry as trusted after `vox agent trust codex`"
    );
    assert_eq!(
        u, "untrusted",
        "APPARATUS (precondition not met): the untrusted home's entry is not untrusted"
    );

    // ---- one turn in each home ----
    let turn = |h: &CodexHome, name: &str| -> Turn {
        let auth = h.codex_home.join("auth.json");
        let credential = CodexSignIn::copy(&auth_src, &auth, &auth_bytes);
        let signin = std::rc::Rc::clone(&credential.outcome);
        let last = h.tmp.join("last-message.txt");
        let mut cmd = h.command(Path::new("/usr/bin/sandbox-exec"), &path, &data, &cfg);
        cmd.arg("-f")
            .arg(&profile)
            .arg(&codex)
            .args([
                "exec",
                "--json",
                "--skip-git-repo-check",
                "--sandbox",
                "read-only",
                "-c",
                "cli_auth_credentials_store=\"file\"",
                "-c",
                "model_reasoning_effort=\"low\"",
                "-C",
            ])
            .arg(&work)
            .arg("-o")
            .arg(&last)
            .arg(PROMPT)
            .current_dir(&work)
            .stdin(Stdio::null());
        let started = Instant::now();
        let out = cmd
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot run codex exec: {e}"));
        // Compared, never printed: did Codex rewrite its sign-in (a refresh)? Written back to the
        // operator's file if it did, as the copy is removed.
        drop(credential);
        let signin = signin.borrow().clone().unwrap_or_default();
        assert!(
            !auth.exists(),
            "APPARATUS: the sandbox's copy of auth.json was not removed"
        );
        let said = format!(
            "{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let answer = std::fs::read_to_string(&last).unwrap_or_default();
        let logs = session_logs(&h.codex_home.join("sessions"));
        for (what, text) in [
            ("output", &said),
            ("answer", &answer),
            ("session log", &logs),
        ] {
            canary.check(text, &format!("the {name} Codex turn's {what}"));
        }
        std::fs::write(root.join(format!("{name}.out")), &said)
            .unwrap_or_else(|e| panic!("APPARATUS: cannot keep the turn's output: {e}"));
        println!(
            "[proof] {name} turn: exit {:?} after {:.1}s; answer {:?}; the sign-in: {signin}; copy \
             removed",
            out.status.code(),
            started.elapsed().as_secs_f64(),
            answer.trim()
        );
        assert!(
            signin == "unchanged" || signin.ends_with("the operator's file was updated"),
            "APPARATUS: {signin}"
        );
        // **No hook of the operator's ran** (module doc): nothing the turn said names their
        // `~/.codex`, where Codex would have read their `hooks.json`.
        let theirs = real_home.join(".codex").display().to_string();
        let named = said.contains(&theirs);
        println!("[proof] {name} turn: the operator's ~/.codex named in its output: {named}");
        assert!(
            !named,
            "APPARATUS: the {name} turn read the operator's ~/.codex (its output names it), so \
             its hooks.json may have run: {}",
            evidence(&said, &theirs).unwrap_or_default()
        );
        let low = said.to_ascii_lowercase();
        if !out.status.success()
            && ["401", "unauthorized", "login", "logged in", "sign in"]
                .iter()
                .any(|s| low.contains(s))
        {
            panic!(
                "CANNOT MEASURE: the {name} Codex turn was refused for its sign-in; not retrying, \
                 and never driving a login. Its output is in {name}.out"
            );
        }
        assert!(
            out.status.success(),
            "APPARATUS, CANNOT MEASURE: the {name} Codex turn failed (exit {:?}); its output \
             is in {name}.out",
            out.status.code()
        );
        Turn { said, answer, logs }
    };

    let u = turn(&untrusted, "untrusted");
    let t = turn(&trusted, "trusted");

    // ---- the verdicts ----
    let injected = evidence(&t.logs, &codeword);
    println!(
        "[proof] trusted turn, the session log line that carries the room: {}",
        injected.as_deref().unwrap_or("(none)")
    );
    assert!(
        injected.is_some(),
        "PRODUCT: the trusted hook never fed the room to the turn: codeword {codeword} is not in \
         what Codex recorded it was given; its output: {}",
        t.said
    );
    assert!(
        !u.logs.contains(&codeword) && !u.said.contains(&codeword) && !u.answer.contains(&codeword),
        "PRODUCT: the untrusted hook fed the room to the turn: codeword {codeword} reached it \
         without `vox agent trust codex`: {}",
        evidence(&u.logs, &codeword)
            .or_else(|| evidence(&u.said, &codeword))
            .unwrap_or_else(|| u.answer.clone())
    );
    println!("[proof] untrusted turn: codeword absent from its output, answer and session log");
    assert!(
        t.answer.contains(&codeword),
        "CANNOT MEASURE (the answer only): the room reached the trusted turn's context, but the \
         model answered {:?}",
        t.answer.trim()
    );
    println!("[proof] trusted turn: the model answered with the codeword {codeword}");
}

// ---- ADR-029 #541, #544: a live Codex session's Session, read and driven -----------------------

/// The person whose room it is, with drive on the agent's node.
const PERSON: &str = "person";

/// What the live session is asked first: one shell command the read-only sandbox refuses, so
/// Codex asks approval for it, and a one-word reply.
const SESSION_PROMPT: &str = "Use one shell command to create the file e1 containing vox-live \
                              (ask for approval if the sandbox blocks it), then reply with only \
                              the word done.";

/// What the person types into the session from Vox: a turn long enough to interrupt.
const LONG_TURN: &str =
    "Run the shell command `sleep 120` and then reply with only the word slept.";

/// `vox` as `node` in the run's data root. A keyring change is typed at a terminal, as a person
/// types it (ADR-028 K-13).
fn vox_as(
    data: &Path,
    cfg: &Path,
    node: &str,
    args: &[&str],
    input: Option<&str>,
) -> (bool, String) {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", cfg)
        .env(
            "VOX_IDENTITY_PASSPHRASE",
            format!("the {node} node's identity passphrase"),
        )
        .env("VOX_NODE", node)
        .env("VOX_LISTEN", "127.0.0.1:0")
        .env("VOX_PROXY", "127.0.0.1:0")
        .env_remove("VOX_ROOM")
        .env_remove("VOX_ROOM_PASSPHRASE");
    if typed::is_keyring_change(args) {
        return typed::keyring(&cmd);
    }
    let mut child = cmd
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot start `vox {}`: {e}", args.join(" ")));
    if let (Some(text), Some(mut pipe)) = (input, child.stdin.take()) {
        let _ = pipe.write_all(text.as_bytes());
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: `vox {}`: {e}", args.join(" ")));
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn staged_as(data: &Path, cfg: &Path, node: &str, args: &[&str], input: Option<&str>) -> String {
    let (ok, said) = vox_as(data, cfg, node, args, input);
    assert!(
        ok,
        "APPARATUS (staging): `vox {}` as {node} failed: {said}",
        args.join(" ")
    );
    said
}

/// Where Codex's app-server for `codex_home` puts its socket: `<CODEX_HOME>/app-server-control/
/// app-server-control.sock` is a link to `/private/tmp/codex-daemon-<uid>/<sha256 of that path>`
/// (read from Codex 0.160.1's behaviour, 2026-10-06). The sandbox lets the run write that one
/// socket and its lock, and nothing else there.
fn codex_daemon_socket(codex_home: &Path) -> PathBuf {
    use sha2::Digest as _;
    let link = codex_home.join("app-server-control/app-server-control.sock");
    let hash = sha2::Sha256::digest(link.display().to_string().as_bytes());
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    let uid = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|e| panic!("APPARATUS: cannot read this user's id: {e}"));
    PathBuf::from(format!("/private/tmp/codex-daemon-{uid}/{hex}"))
}

/// Codex's interactive TUI under a pty (`tests/pty/live_tui.py`), one JSON line per command.
struct Tui {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    lines: std::sync::mpsc::Receiver<String>,
}

impl Tui {
    fn ask(&mut self, command: &str, within: Duration) -> serde_json::Value {
        writeln!(self.stdin, "{command}")
            .unwrap_or_else(|e| panic!("APPARATUS: cannot drive Codex's terminal: {e}"));
        let line = self.lines.recv_timeout(within).unwrap_or_else(|e| {
            panic!(
                "APPARATUS: Codex's terminal driver did not answer {command:?} in {within:?}: {e}"
            )
        });
        let v: serde_json::Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("APPARATUS: the terminal driver said {line:?}: {e}"));
        if let Some(what) = v.get("login") {
            panic!(
                "APPARATUS, CANNOT MEASURE: Codex showed a sign-in or trust screen ({what}); \
                 nothing was typed into it, and the run stops here"
            );
        }
        v
    }

    fn type_line(&mut self, text: &str) {
        self.ask(&format!("type {text}"), Duration::from_secs(60));
        self.ask("key enter", Duration::from_secs(10));
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "quit");
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(10) {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The person's view of Session `id`: its plain lines, and its JSON lines.
fn session_view(data: &Path, cfg: &Path, room: &str, id: &str) -> (String, Vec<serde_json::Value>) {
    let (_, plain) = vox_as(data, cfg, PERSON, &["room", "session", room, id], None);
    let (_, json) = vox_as(
        data,
        cfg,
        PERSON,
        &["room", "session", room, id, "--json"],
        None,
    );
    let json = json
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .collect();
    (plain, json)
}

/// Wait until Session `id` shows a line `pred` takes, within `within`: the plain view then.
fn session_until(
    data: &Path,
    cfg: &Path,
    room: &str,
    id: &str,
    within: Duration,
    what: &str,
    pred: impl Fn(&str, &[serde_json::Value]) -> bool,
) -> (String, Vec<serde_json::Value>) {
    let deadline = Instant::now() + within;
    loop {
        let (plain, json) = session_view(data, cfg, room, id);
        if pred(&plain, &json) {
            return (plain, json);
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: within {within:?}, {PERSON} (with drive) never read {what} in the live Codex \
             session's Session; `vox room session` said:\n{plain}"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "drives a live Codex session's model turns; optional, on the decider's request, in release"]
fn a_live_codex_session_is_mirrored_and_driven() {
    watchdog::arm_for(Duration::from_secs(1200));
    if !oc_sandbox::live_model_allowed(
        "codex_live_proof::a_live_codex_session_is_mirrored_and_driven",
    ) {
        return;
    }
    let (codex, codex_release) = codex_install();
    let real_home = watchdog::temp_home::real_home()
        .unwrap_or_else(|| panic!("APPARATUS: HOME is unset, so Codex's sign-in cannot be found"));
    let auth_src = real_home.join(".codex/auth.json");
    let auth_bytes = std::fs::read(&auth_src).unwrap_or_else(|_| {
        panic!("CANNOT MEASURE: no ~/.codex/auth.json, so no Codex turn can run; sign in to Codex")
    });

    // ---- the run's root: short, for the sockets under it ----
    std::fs::create_dir_all("/private/tmp/vc")
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make /private/tmp/vc: {e}"));
    let tmp = tempfile::Builder::new()
        .prefix("cxs-")
        .tempdir_in("/private/tmp/vc")
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make a temp directory: {e}"));
    let root = oc_sandbox::real(tmp.path());
    let (data, cfg, bin, work) = (
        root.join("vd"),
        root.join("vc"),
        root.join("bin"),
        root.join("work"),
    );
    for d in [&bin, &work] {
        std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("APPARATUS: cannot make {d:?}: {e}"));
    }
    std::fs::copy(VOX, bin.join("vox"))
        .unwrap_or_else(|e| panic!("APPARATUS: cannot copy vox into the run: {e}"));
    let path = format!("{}:{}", bin.display(), oc_sandbox::SANDBOX_PATH);

    // ---- (1) the person and the agent's node, one room, the agent trusting the person with drive
    for node in [PERSON, NODE] {
        staged_as(&data, &cfg, node, &["node", "create", node], None);
    }
    let (ok, said) = vox_as(&data, &cfg, PERSON, &["node", "attach", PERSON], None);
    let _daemon = Daemon(data.clone());
    assert!(
        ok,
        "APPARATUS (staging): `vox node attach {PERSON}` failed: {said}"
    );
    staged_as(&data, &cfg, NODE, &["node", "attach", NODE], None);
    staged_as(
        &data,
        &cfg,
        PERSON,
        &["room", "create", "--passphrase-file", "-", "--name", "work"],
        Some("room passphrase\n"),
    );
    let list = staged_as(&data, &cfg, PERSON, &["room", "list"], None);
    let room = list
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("APPARATUS (staging): `vox room list` shows no room: {list:?}"))
        .to_owned();
    let link = staged_as(&data, &cfg, PERSON, &["room", "link", &room], None)
        .trim()
        .to_owned();
    let person_fp = staged_as(&data, &cfg, PERSON, &["id"], None)
        .trim()
        .to_owned();
    let agent_fp = staged_as(&data, &cfg, NODE, &["id"], None)
        .trim()
        .to_owned();
    staged_as(
        &data,
        &cfg,
        PERSON,
        &["trust", "add", &agent_fp, "--name", NODE],
        None,
    );
    staged_as(
        &data,
        &cfg,
        NODE,
        &["room", "join", "--passphrase-file", "-", &link],
        Some("room passphrase\n"),
    );
    staged_as(
        &data,
        &cfg,
        NODE,
        &["trust", "add", &person_fp, "--name", PERSON, "--drive"],
        None,
    );
    println!("[proof] (1) room {room}: {NODE} trusts {PERSON} with drive");

    // ---- (2) Codex's home: Vox's hooks, trusted through Codex's own RPCs; its app-server ----
    let h = CodexHome::new(&root, "s");
    let plugin = Command::new(VOX)
        .args(["agent", "plugin", "codex", "--node", NODE])
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run vox agent plugin codex: {e}"));
    assert!(
        plugin.status.success(),
        "PRODUCT: `vox agent plugin codex --node {NODE}` failed"
    );
    std::fs::write(h.codex_home.join("hooks.json"), &plugin.stdout)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot write hooks.json: {e}"));
    std::fs::write(
        h.codex_home.join("config.toml"),
        format!(
            "approval_policy = \"on-request\"\nsandbox_mode = \"read-only\"\n\
             cli_auth_credentials_store = \"file\"\nmodel_reasoning_effort = \"low\"\n\
             [projects.\"{}\"]\ntrust_level = \"trusted\"\n",
            work.display()
        ),
    )
    .unwrap_or_else(|e| panic!("APPARATUS: cannot write config.toml: {e}"));
    let out = h
        .command(Path::new(VOX), &path, &data, &cfg)
        .args(["agent", "trust", "codex", "--codex"])
        .arg(&codex)
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run vox agent trust codex: {e}"));
    assert!(
        out.status.success(),
        "PRODUCT (staging): `vox agent trust codex` failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let socket = codex_daemon_socket(&h.codex_home);
    let lock = PathBuf::from(format!("{}.lock", socket.display()));
    let canary = oc_sandbox::Canary::plant();
    let profile = root.join("codex.sb");
    std::fs::write(
        &profile,
        oc_sandbox::sandbox_profile(&[&root, &socket, &lock], &[&codex_release]),
    )
    .unwrap_or_else(|e| panic!("APPARATUS: cannot write the sandbox profile: {e}"));
    oc_sandbox::probe_profile(&profile, &canary, "codex session");

    let auth = h.codex_home.join("auth.json");
    let credential = CodexSignIn::copy(&auth_src, &auth, &auth_bytes);
    let signin = std::rc::Rc::clone(&credential.outcome);
    let server_log = root.join("app-server.log");
    let mut server = h.command(Path::new("/usr/bin/sandbox-exec"), &path, &data, &cfg);
    server
        .arg("-f")
        .arg(&profile)
        .arg(&codex)
        .args(["app-server", "--listen", "unix://"])
        // Codex runs the hooks here: they register the session in this room (ADR-029 RB-2).
        .env("VOX_ROOM", &room)
        .current_dir(&work)
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&server_log).unwrap_or_else(|e| panic!("APPARATUS: {e}")))
        .stderr(Stdio::from(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&server_log)
                .unwrap_or_else(|e| panic!("APPARATUS: {e}")),
        ));
    let server = server
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot start codex app-server: {e}"));
    // Stopped by its own PID however the proof ends.
    struct Stopped(std::process::Child);
    impl Drop for Stopped {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let server = Stopped(server);
    let control = h
        .codex_home
        .join("app-server-control/app-server-control.sock");
    let t0 = Instant::now();
    while std::os::unix::net::UnixStream::connect(&control).is_err() {
        assert!(
            t0.elapsed() < Duration::from_secs(30),
            "APPARATUS: Codex's app-server never listened at {control:?}; its log:\n{}",
            std::fs::read_to_string(&server_log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    println!("[proof] (2) Codex's app-server listens; Vox's hooks are trusted");

    // ---- (3) the operator's session: a plain `codex` in a terminal, which joins it ----
    let screen = root.join("tui.screen");
    let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pty/live_tui.py");
    let mut tui_cmd = h.command(
        Path::new("python3"),
        &format!("{path}:/usr/bin"),
        &data,
        &cfg,
    );
    tui_cmd
        .arg(&driver)
        .arg(&screen)
        .args(["/usr/bin/sandbox-exec", "-f"])
        .arg(&profile)
        .arg(&codex)
        .args(["--no-alt-screen", "-C"])
        .arg(&work)
        .env("TERM", "xterm-256color")
        .env("VOX_ROOM", &room)
        .current_dir(&work)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = tui_cmd
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot start Codex's terminal: {e}"));
    let stdin = child
        .stdin
        .take()
        .expect("APPARATUS: the terminal driver's stdin");
    let out = child
        .stdout
        .take()
        .expect("APPARATUS: the terminal driver's stdout");
    let (tx, lines) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut tui = Tui {
        child,
        stdin,
        lines,
    };
    tui.ask("wait 30 (?i)(context|codex)", Duration::from_secs(60));
    std::thread::sleep(Duration::from_secs(3));
    tui.type_line(SESSION_PROMPT);
    println!("[proof] (3) the operator typed the first prompt at Codex's terminal");

    // The session's id, as its Session names it.
    let deadline = Instant::now() + Duration::from_secs(120);
    let id = loop {
        let (_, json) = vox_as(
            &data,
            &cfg,
            PERSON,
            &["room", "sessions", &room, "--json"],
            None,
        );
        let found = json
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .find(|s| s["harness"] == "codex" && s["open"] == true)
            .and_then(|s| s["id"].as_str().map(str::to_owned));
        if let Some(id) = found {
            break id;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: within 120 s of the operator's first prompt, no open Codex Session appeared \
             in room {room}; `vox room sessions` said:\n{json}"
        );
        std::thread::sleep(Duration::from_secs(1));
    };
    println!("[proof] (3) Session {id} is open");

    // ---- (4) the approval waits in the Session; the person approves it from Vox ----
    let (plain, json) = session_until(
        &data,
        &cfg,
        &room,
        &id,
        Duration::from_secs(240),
        "an approval waiting",
        |p, _| p.contains("approve or reject?"),
    );
    println!("[proof] (4) Session {id} while the approval waits:\n{plain}");
    let reference = json
        .iter()
        .find(|l| l["kind"] == "approval" && l["waiting"] == true)
        .and_then(|l| l["ref"].as_str().map(str::to_owned))
        .unwrap_or_else(|| {
            panic!(
                "PRODUCT: the waiting approval's line in `vox room session --json` names no ref, \
                 so a person cannot answer it from Vox: {json:?}"
            )
        });
    let (ok, said) = vox_as(
        &data,
        &cfg,
        PERSON,
        &["room", "session", &room, &id, "--approve", &reference],
        None,
    );
    println!("[proof] (4) {PERSON} --approve {reference}: {said}");
    assert!(
        ok,
        "PRODUCT: approving from the Session must be handed to the session; it said: {said}"
    );
    let (plain, _) = session_until(
        &data,
        &cfg,
        &room,
        &id,
        Duration::from_secs(240),
        "the turn's end",
        |p, _| p.contains("approved here") && p.contains("— turn ended —"),
    );
    println!("[proof] (4) Session {id} after the turn:\n{plain}");
    assert!(
        work.join("e1").is_file(),
        "PRODUCT: Codex reads the approval as given in Vox, yet the command it approved did not \
         run: no {:?}",
        work.join("e1")
    );

    // ---- (5) the person types a long turn into the session from Vox, then interrupts it ----
    let (ok, said) = vox_as(
        &data,
        &cfg,
        PERSON,
        &["room", "session", &room, &id, "--say", LONG_TURN],
        None,
    );
    println!("[proof] (5) {PERSON} --say: {said}");
    assert!(
        ok,
        "PRODUCT: typed text from Vox must reach the idle session; it said: {said}"
    );
    session_until(
        &data,
        &cfg,
        &room,
        &id,
        Duration::from_secs(240),
        "the typed turn running its command",
        |p, _| p.contains("typed in Vox by") && p.contains("sleep 120"),
    );
    let tui_saw = tui.ask("wait 60 sleep 120", Duration::from_secs(90));
    println!("[proof] (5) Codex's own terminal shows the typed turn: {tui_saw}");
    let (ok, said) = vox_as(
        &data,
        &cfg,
        PERSON,
        &["room", "session", &room, &id, "--interrupt"],
        None,
    );
    println!("[proof] (5) {PERSON} --interrupt: {said}");
    assert!(
        ok,
        "PRODUCT: an interrupt from Vox must reach the running turn; it said: {said}"
    );
    let started = Instant::now();
    let (plain, _) = session_until(
        &data,
        &cfg,
        &room,
        &id,
        Duration::from_secs(60),
        "the interrupted turn's end",
        |p, _| p.matches("— turn ended —").count() >= 2,
    );
    println!(
        "[proof] (5) the interrupted turn ended {:.1}s after the interrupt (its command sleeps \
         120 s):\n{plain}",
        started.elapsed().as_secs_f64()
    );
    assert!(
        tui_saw["found"] == true,
        "PRODUCT: both surfaces stay live (DR-3): the operator's own terminal never showed the \
         turn typed in Vox"
    );

    // ---- the end: the operator quits; the sign-in copy goes; nothing leaked ----
    tui.type_line("/quit");
    drop(tui);
    drop(server);
    drop(credential);
    let signin = signin.borrow().clone().unwrap_or_default();
    println!("[proof] the sign-in: {signin}; copy removed");
    for (what, text) in [
        (
            "terminal",
            std::fs::read_to_string(&screen).unwrap_or_default(),
        ),
        (
            "app-server log",
            std::fs::read_to_string(&server_log).unwrap_or_default(),
        ),
        ("session logs", session_logs(&h.codex_home.join("sessions"))),
        ("Session", plain),
    ] {
        canary.check(&text, &format!("the live Codex session's {what}"));
    }
    assert!(
        signin == "unchanged" || signin.ends_with("the operator's file was updated"),
        "APPARATUS: {signin}"
    );
}
