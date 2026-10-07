//! ADR-029 #542, #544 (optional, live) — **a live OpenCode session reaches its Session through
//! Vox's plugin, and a member with drive answers its approval and interrupts it from Vox.**
//!
//! `a_codex_and_an_opencode_session_are_mirrored_and_driven_proof` proves the same with the
//! shipped plugin hosted under node and OpenCode's bus events played to it; this is the real
//! OpenCode, in its own terminal, running a model, on the decider's request only:
//!
//! 1. One daemon, two nodes: `person`, whose room it is, and the agent's node `oc-proof`, which
//!    joins it and trusts `person` with drive.
//! 2. A plain `opencode` in a terminal (a pty), in a project whose plugin is what `vox agent
//!    plugin opencode --node oc-proof` prints, its shell asking permission for every command.
//! 3. The operator types a prompt that runs one shell command. The Session shows the request
//!    waiting; `person` approves it with `vox room session --approve`; OpenCode runs the command
//!    and the Session reads "approved here", the reply and the turn's end.
//! 4. `person` types a long turn into the session from Vox; once its command runs, `person`
//!    interrupts it, and the turn ends long before the command would have.
//!
//! **Confined** (support/oc_sandbox.rs): `sandbox-exec`, a throwaway HOME, a cleared
//! environment, OpenCode's own provider credential alone, a canary in the real HOME probed before
//! any turn and looked for in everything the session showed. **Never a login screen**: the
//! terminal driver stops and this proof says APPARATUS rather than type into one.
//!
//! **Which side a red is on.** What `vox room session` showed, and what OpenCode did (the file
//! the approved command makes), are `PRODUCT:`. Setup that did not happen is `APPARATUS
//! (staging):`; a model or provider that would not answer is `CANNOT MEASURE`.
//!
//! Optional (decider, 2026-10-01): it blocks nothing, and only a build with `live-model-sandbox`
//! starts a model. docs/release/optional-proofs.md says how to run it.

#![cfg_attr(not(feature = "optional-proofs"), allow(dead_code, unused_imports))]
#![cfg(unix)]

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(a_live_opencode_session_is_mirrored_and_driven);

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
const PERSON: &str = "person";
const NODE: &str = "oc-proof";

/// The operator's prompt: one shell command, which OpenCode asks permission for.
const PROMPT: &str = "Run the shell command `touch e1` in the current directory, then reply with \
                      only the word done.";

/// What the person types from Vox: a turn long enough to interrupt.
const LONG_TURN: &str = "Run the shell command `sleep 120`, then reply with only the word slept.";

/// The daemon `vox node attach` started, stopped by its own PID when dropped.
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

/// `vox` as `node`. A keyring change is typed at a terminal (ADR-028 K-13).
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
        .env_remove("VOX_ROOM");
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

/// OpenCode's terminal under a pty (`tests/pty/live_tui.py`), one JSON line per command.
struct Tui {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    lines: std::sync::mpsc::Receiver<String>,
    /// What the terminal drew, and where a copy is kept once the run's directory is gone.
    screen: PathBuf,
    keep: PathBuf,
}

impl Tui {
    fn ask(&mut self, command: &str, within: Duration) -> serde_json::Value {
        writeln!(self.stdin, "{command}")
            .unwrap_or_else(|e| panic!("APPARATUS: cannot drive OpenCode's terminal: {e}"));
        let line = self.lines.recv_timeout(within).unwrap_or_else(|e| {
            panic!(
                "APPARATUS: OpenCode's terminal driver did not answer {command:?} in {within:?}: \
                 {e}"
            )
        });
        let v: serde_json::Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("APPARATUS: the terminal driver said {line:?}: {e}"));
        if let Some(what) = v.get("login") {
            panic!(
                "APPARATUS, CANNOT MEASURE: OpenCode showed a sign-in or trust screen ({what}); \
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
        self.keep();
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

impl Tui {
    /// Keep what the terminal drew outside the run's directory, and say where.
    fn keep(&self) {
        if std::fs::copy(&self.screen, &self.keep).is_ok() {
            println!(
                "[proof] what the terminal drew is kept at {}",
                self.keep.display()
            );
        }
    }
}

/// The person's view of Session `id`: plain and JSON lines.
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

/// Wait until Session `id` shows what `pred` takes, within `within`.
fn session_until(
    data: &Path,
    cfg: &Path,
    room: &str,
    id: &str,
    within: Duration,
    what: &str,
    pred: impl Fn(&str) -> bool,
) -> (String, Vec<serde_json::Value>) {
    let deadline = Instant::now() + within;
    loop {
        let (plain, json) = session_view(data, cfg, room, id);
        if pred(&plain) {
            return (plain, json);
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: within {within:?}, {PERSON} (with drive) never read {what} in the live \
             OpenCode session's Session; `vox room session` said:\n{plain}"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "drives a live OpenCode session's model turns; optional, on the decider's request, in release"]
fn a_live_opencode_session_is_mirrored_and_driven() {
    watchdog::arm_for(Duration::from_secs(1200));
    if !oc_sandbox::live_model_allowed(
        "opencode_live_session_proof::a_live_opencode_session_is_mirrored_and_driven",
    ) {
        return;
    }
    std::fs::create_dir_all("/private/tmp/vc")
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make /private/tmp/vc: {e}"));
    let tmp = tempfile::Builder::new()
        .prefix("ocs-")
        .tempdir_in("/private/tmp/vc")
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make a temp directory: {e}"));
    let data = oc_sandbox::real(tmp.path()).join("vd");
    let cfg = oc_sandbox::real(tmp.path()).join("vc");

    // ---- (1) the person and the agent's node, one room, drive ----
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
    let said = staged_as(&data, &cfg, PERSON, &["room", "link", &room], None);
    let link = said
        .split_whitespace()
        .find(|w| w.starts_with("vox://"))
        .unwrap_or_else(|| panic!("APPARATUS (staging): `vox room link` printed no link: {said}"))
        .to_owned();
    let person_fp = staged_as(&data, &cfg, PERSON, &["id"], None)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    let agent_fp = staged_as(&data, &cfg, NODE, &["id"], None)
        .split_whitespace()
        .next()
        .unwrap_or_default()
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

    // ---- (2) OpenCode, confined, its project carrying Vox's plugin ----
    let sb = oc_sandbox::OcSandbox::new(tmp.path());
    let profile = sb.profile("session", &[&data, &cfg], &[Path::new(VOX)]);
    let fixture = sb.root.join("oc");
    let oc_cfg = fixture.join("config");
    let project = fixture.join("project");
    for d in [oc_cfg.join("opencode"), project.join(".opencode/plugin")] {
        std::fs::create_dir_all(&d).unwrap_or_else(|e| panic!("APPARATUS: cannot make {d:?}: {e}"));
    }
    let plugin = staged_as(
        &data,
        &cfg,
        NODE,
        &["agent", "plugin", "opencode", "--node", NODE],
        None,
    );
    std::fs::write(project.join(".opencode/plugin/vox.js"), plugin)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot install the plugin: {e}"));
    std::fs::write(
        project.join("opencode.json"),
        serde_json::json!({
            "$schema": "https://opencode.ai/config.json",
            "model": oc_sandbox::model(),
            "permission": { "bash": "ask" }
        })
        .to_string(),
    )
    .unwrap_or_else(|e| panic!("APPARATUS: cannot write opencode.json: {e}"));
    let oc_tmp = sb.root.join("t");
    std::fs::create_dir_all(&oc_tmp)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make {oc_tmp:?}: {e}"));

    // ---- (3) the operator's session: a plain `opencode` in a terminal ----
    let screen = sb.root.join("tui.screen");
    let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pty/live_tui.py");
    let inner = sb.opencode(&profile, &[], &project);
    let mut cmd = Command::new("/usr/bin/python3");
    cmd.arg(&driver).arg(&screen).arg(inner.get_program());
    cmd.args(inner.get_args());
    cmd.env_clear();
    for (k, v) in inner.get_envs() {
        if let Some(v) = v {
            cmd.env(k, v);
        }
    }
    cmd.env("TERM", "xterm-256color")
        .env("TMPDIR", &oc_tmp)
        .env("XDG_CONFIG_HOME", &oc_cfg)
        .env("VOX_DATA_DIR", &data)
        .env("VOX_CONFIG_DIR", &cfg)
        .env("VOX_ROOM", &room)
        .env("VOX_BIN", VOX)
        .current_dir(&project)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot start OpenCode's terminal: {e}"));
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
    let keep = PathBuf::from(format!(
        "/private/tmp/vc/kept-{}-tui.screen",
        std::process::id()
    ));
    let mut tui = Tui {
        child,
        stdin,
        lines,
        screen: screen.clone(),
        keep,
    };
    tui.ask(
        "wait 60 (?i)(opencode|ask anything|kimi)",
        Duration::from_secs(90),
    );
    std::thread::sleep(Duration::from_secs(3));
    tui.type_line(PROMPT);
    println!("[proof] (3) the operator typed the first prompt at OpenCode's terminal");

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
            .find(|s| s["harness"] == "opencode" && s["open"] == true)
            .and_then(|s| s["id"].as_str().map(str::to_owned));
        if let Some(id) = found {
            break id;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: within 120 s of the operator's prompt, no open OpenCode Session appeared in \
             room {room}; `vox room sessions` said:\n{json}"
        );
        std::thread::sleep(Duration::from_secs(1));
    };
    println!("[proof] (3) Session {id} is open");

    // ---- (4) the permission waits in the Session; the person approves it from Vox ----
    let (plain, json) = session_until(
        &data,
        &cfg,
        &room,
        &id,
        Duration::from_secs(240),
        "an approval waiting",
        |p| p.contains("approve or reject?"),
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
        |p| p.contains("approved here") && p.contains("— turn ended —"),
    );
    println!("[proof] (4) Session {id} after the turn:\n{plain}");
    assert!(
        project.join("e1").is_file(),
        "PRODUCT: OpenCode took the approval given in Vox, yet the command did not run: no e1"
    );

    // ---- (5) a long turn typed from Vox, then interrupted from Vox ----
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
        "PRODUCT: typed text from Vox must reach the session; it said: {said}"
    );
    // The long turn's command asks permission too: approved from Vox, so it runs.
    let (_, json) = session_until(
        &data,
        &cfg,
        &room,
        &id,
        Duration::from_secs(240),
        "the typed turn's command waiting",
        |p| p.contains("sleep 120") && p.contains("approve or reject?"),
    );
    if let Some(r) = json
        .iter()
        .rev()
        .find(|l| l["kind"] == "approval" && l["waiting"] == true)
        .and_then(|l| l["ref"].as_str())
    {
        let _ = vox_as(
            &data,
            &cfg,
            PERSON,
            &["room", "session", &room, &id, "--approve", r],
            None,
        );
    }
    std::thread::sleep(Duration::from_secs(5));
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
        |p| p.matches("— turn ended —").count() >= 2,
    );
    println!(
        "[proof] (5) the interrupted turn ended {:.1}s after the interrupt (its command sleeps \
         120 s):\n{plain}",
        started.elapsed().as_secs_f64()
    );

    drop(tui);
    for (what, text) in [
        (
            "terminal",
            std::fs::read_to_string(&screen).unwrap_or_default(),
        ),
        ("Session", plain),
    ] {
        sb.check(&text, &format!("the live OpenCode session's {what}"));
    }
}
