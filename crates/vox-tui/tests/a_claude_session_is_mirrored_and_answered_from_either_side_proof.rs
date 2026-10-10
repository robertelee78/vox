//! ADR-029 SC-1, DR-3, DR-4 (#540, #545) — **a Claude Code session's activity reaches its Session,
//! whole, and an approval there is retired by what the harness did, not by what Vox sent.**
//!
//! The harness is a stand-in, as apparatus: it speaks Claude Code 2.1.292's own hook JSON to the
//! shipped `vox agent hook` (the input shapes read from the binary and confirmed by a sandboxed
//! live spike, 2026-10-06), and writes the session's transcript as Claude Code does. For a
//! permission request it keeps Claude Code's rule: the first of the terminal and the hook to
//! answer wins, and the transcript records which.
//!
//! The reader is a person's node with drive, reading with `vox room session` as a person would.
//!
//! 1. One data root, one daemon, two nodes: `person`, whose room it is, and the agent node
//!    `claude-a`, which joins it. `claude-a` trusts `person` with drive; `person` trusts it back.
//! 2. One turn of session S, through the hook as Claude Code runs it: the prompt, a Bash call
//!    whose output is 100 KiB (more than one entry holds), a second Bash call that asks
//!    permission, answered at the terminal (the stand-in writes the call's result to the
//!    transcript), and the turn's end with its reply.
//! 3. `person` reads Session S: the prompt "typed at the terminal"; the first call with its
//!    output whole in one Details view; the second call "answered in the terminal: approved";
//!    the reply; "— turn ended —". The permission hook, which waited for an answer from the
//!    Session, exits printing nothing once the terminal answered: it gave Claude Code no decision.
//!
//! **Which side a red is on.** What `vox room session` printed, or what the hook printed or did
//! not do, is `PRODUCT:`. Setup that the product refused (`vox node create`, the room, trust) is
//! `APPARATUS (staging):` with what it said; a fixture this proof could not make is `APPARATUS:`.
//!
//! **Mutations that must turn it red:** the turn's end not mirrored (`Stop` gives no `turn-end`)
//! → no "— turn ended —" line (#540); a request retired by its waiting hook's release rather than
//! by the transcript → no "answered in the terminal" (#545).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/typed.rs"]
mod typed;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A short root for the run's directories: a Unix socket's path must fit the platform's bound
/// (104 bytes on macOS), which the system's temporary directory does not leave room for.
#[cfg(target_os = "macos")]
const SHORT_ROOT: &str = "/private/tmp/vc";
#[cfg(not(target_os = "macos"))]
const SHORT_ROOT: &str = "/tmp/vc";

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const PERSON: &str = "person";
const AGENT: &str = "claude-a";
/// Claude Code's own id for the session.
const SESSION: &str = "5e55a0d1-4c0e-4f00-9a1b-0c0ffee54000";

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

struct World {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    data: PathBuf,
    cfg: PathBuf,
}

impl World {
    fn command(&self, node: &str, args: &[&str]) -> Command {
        let mut c = Command::new(VOX);
        c.env_clear()
            // A proof's daemon never takes port 1080 (.cargo/config.toml).
            .env("VOX_PROXY", "127.0.0.1:0")
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.root.join("home"))
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env("VOX_IDENTITY_PASSPHRASE", format!("pass of {node}"))
            .env("VOX_NODE", node)
            .env("VOX_LISTEN", "127.0.0.1:0")
            .args(args);
        c
    }

    fn vox(&self, node: &str, args: &[&str], input: Option<&str>) -> (bool, String, String) {
        // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028
        // K-13).
        if typed::is_keyring_change(args) {
            let (ok, shown) = typed::keyring(&self.command(node, args));
            return (ok, shown.clone(), shown);
        }
        let mut child = self
            .command(node, args)
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
            if let Some(mut pipe) = child.stdin.take() {
                let _ = pipe.write_all(text.as_bytes());
            }
        }
        let out = child
            .wait_with_output()
            .unwrap_or_else(|e| panic!("APPARATUS: `vox {}`: {e}", args.join(" ")));
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn staged(&self, node: &str, args: &[&str], input: Option<&str>) -> String {
        let (ok, out, err) = self.vox(node, args, input);
        assert!(
            ok,
            "APPARATUS (staging): `vox {}` as {node} failed: {out}{err}",
            args.join(" ")
        );
        out
    }

    /// Claude Code running its hook for `event`: `vox agent hook --node claude-a --room ROOM`,
    /// with the event's JSON on stdin and Claude Code's environment for an interactive session.
    fn hook(&self, room: &str, event: &serde_json::Value) -> Child {
        let mut child = self
            .command(AGENT, &["agent", "hook", "--node", AGENT, "--room", room])
            .env("CLAUDE_CODE_ENTRYPOINT", "cli")
            .current_dir(self.root.join("work"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot start `vox agent hook`: {e}"));
        if let Some(mut pipe) = child.stdin.take() {
            pipe.write_all(event.to_string().as_bytes())
                .unwrap_or_else(|e| panic!("APPARATUS: cannot give the hook its event: {e}"));
        }
        child
    }

    /// A hook that must finish as a hook does: within 15 s, exit 0. What it printed.
    fn hook_done(&self, room: &str, event: &serde_json::Value) -> String {
        let child = self.hook(room, event);
        let name = event["hook_event_name"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let out = wait_within(child, Duration::from_secs(15))
            .unwrap_or_else(|| panic!("PRODUCT: the {name} hook did not finish within 15 s"));
        assert!(
            out.status.success(),
            "PRODUCT: the {name} hook exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

/// `child`'s output once it exits within `limit`, or `None` (it is killed, by its PID).
fn wait_within(mut child: Child, limit: Duration) -> Option<std::process::Output> {
    let t0 = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().ok(),
            Ok(None) if t0.elapsed() < limit => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// The transcript Claude Code keeps for the session, as the stand-in writes it: one JSON line
/// per message.
struct Transcript(PathBuf);

impl Transcript {
    /// A tool call's result, as Claude Code records it in a user message.
    fn tool_result(&self, id: &str, content: &str, is_error: bool) {
        let line = serde_json::json!({
            "type": "user",
            "sessionId": SESSION,
            "message": { "role": "user", "content": [
                { "type": "tool_result", "tool_use_id": id, "content": content, "is_error": is_error }
            ] },
        });
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.0)
            .unwrap_or_else(|e| panic!("APPARATUS: cannot write the transcript: {e}"));
        writeln!(f, "{line}").unwrap_or_else(|e| panic!("APPARATUS: the transcript: {e}"));
    }
}

/// The fields every Claude Code hook input carries, for session S.
fn base(event: &str, work: &Path, transcript: &Path) -> serde_json::Value {
    base_for(SESSION, event, work, transcript)
}

/// The fields every Claude Code hook input carries, for `session`.
fn base_for(session: &str, event: &str, work: &Path, transcript: &Path) -> serde_json::Value {
    serde_json::json!({
        "session_id": session,
        "transcript_path": transcript.display().to_string(),
        "cwd": work.display().to_string(),
        "permission_mode": "default",
        "hook_event_name": event,
    })
}

fn with(mut v: serde_json::Value, extra: serde_json::Value) -> serde_json::Value {
    if let (Some(m), Some(e)) = (v.as_object_mut(), extra.as_object()) {
        for (k, x) in e {
            m.insert(k.clone(), x.clone());
        }
    }
    v
}

impl World {
    /// The world every arm starts from: one data root, one daemon, `person` and the agent node
    /// `claude-a` in one room, `claude-a` trusting `person` with drive and `person` trusting it.
    /// The world, its daemon's guard, and the room's id.
    fn setup() -> (World, Daemon, String) {
        std::fs::create_dir_all(SHORT_ROOT)
            .unwrap_or_else(|e| panic!("APPARATUS: cannot make {SHORT_ROOT}: {e}"));
        let tmp = tempfile::Builder::new()
            .prefix("cs-")
            .tempdir_in(SHORT_ROOT)
            .unwrap_or_else(|e| panic!("APPARATUS: cannot make a temp directory: {e}"));
        let root = tmp.path().to_path_buf();
        for d in ["home", "work"] {
            std::fs::create_dir_all(root.join(d))
                .unwrap_or_else(|e| panic!("APPARATUS: cannot make {d}: {e}"));
        }
        let w = World {
            data: root.join("vd"),
            cfg: root.join("vc"),
            root,
            _tmp: tmp,
        };

        // ---- (1) two nodes in one daemon, one room, trust with drive ----
        for node in [PERSON, AGENT] {
            w.staged(node, &["node", "create", node], None);
        }
        let (ok, out, err) = w.vox(PERSON, &["node", "attach", PERSON], None);
        let daemon = Daemon(w.data.clone());
        assert!(
            ok,
            "APPARATUS (staging): `vox node attach {PERSON}` failed: {out}{err}"
        );
        w.staged(AGENT, &["node", "attach", AGENT], None);
        let person_fp = w.staged(PERSON, &["id"], None).trim().to_owned();
        let agent_fp = w.staged(AGENT, &["id"], None).trim().to_owned();
        w.staged(
            PERSON,
            &["room", "create", "--passphrase-file", "-", "--name", "work"],
            Some("room passphrase\n"),
        );
        let list = w.staged(PERSON, &["room", "list"], None);
        let room = list
            .split_whitespace()
            .next()
            .unwrap_or_else(|| {
                panic!("APPARATUS (staging): `vox room list` shows no room: {list:?}")
            })
            .to_owned();
        let link = w
            .staged(PERSON, &["room", "link", &room], None)
            .trim()
            .to_owned();
        w.staged(PERSON, &["trust", "add", &agent_fp, "--name", AGENT], None);
        w.staged(
            AGENT,
            &["room", "join", "--passphrase-file", "-", &link],
            Some("room passphrase\n"),
        );
        w.staged(
            AGENT,
            &["trust", "add", &person_fp, "--name", PERSON, "--drive"],
            None,
        );
        println!("[proof] (1) room {room}: {AGENT} trusts {PERSON} with drive");
        (w, daemon, room)
    }
}

#[test]
#[ignore = "real binary; run in release"]
fn a_claude_sessions_activity_reaches_its_session_and_the_terminal_answer_is_said() {
    watchdog::arm_for(Duration::from_secs(600));
    let (w, _daemon, room) = World::setup();
    let work = w.root.join("work");
    let transcript = Transcript(work.join(format!("{SESSION}.jsonl")));
    std::fs::write(&transcript.0, "")
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make the transcript: {e}"));

    // ---- (2) one turn of session S, through the hook ----
    let prompt = "List big.txt, then make e1.";
    w.hook_done(
        &room,
        &with(
            base("UserPromptSubmit", &work, &transcript.0),
            serde_json::json!({ "prompt": prompt, "prompt_id": "p-1" }),
        ),
    );
    // A tool call whose output no one entry holds.
    let big: String = (1..=4000)
        .map(|i| format!("line-{i:05} the quick brown fox jumps over the lazy dog\n"))
        .collect();
    assert!(
        big.len() > 3 * 64 * 1024,
        "APPARATUS: the output must be more than three entries hold"
    );
    let cat = serde_json::json!({ "command": "cat big.txt", "description": "Show big.txt" });
    w.hook_done(
        &room,
        &with(
            base("PreToolUse", &work, &transcript.0),
            serde_json::json!({ "tool_name": "Bash", "tool_input": cat, "tool_use_id": "toolu_A" }),
        ),
    );
    transcript.tool_result("toolu_A", &big, false);
    w.hook_done(
        &room,
        &with(
            base("PostToolUse", &work, &transcript.0),
            serde_json::json!({
                "tool_name": "Bash", "tool_input": cat, "tool_use_id": "toolu_A",
                "tool_response": { "stdout": big, "stderr": "", "interrupted": false },
                "duration_ms": 12,
            }),
        ),
    );
    // A call that asks permission: the hook waits for the Session while the terminal answers.
    let touch = serde_json::json!({ "command": "touch e1", "description": "Make e1" });
    w.hook_done(
        &room,
        &with(
            base("PreToolUse", &work, &transcript.0),
            serde_json::json!({ "tool_name": "Bash", "tool_input": touch, "tool_use_id": "toolu_B" }),
        ),
    );
    let asking = w.hook(
        &room,
        &with(
            base("PermissionRequest", &work, &transcript.0),
            serde_json::json!({
                "tool_name": "Bash", "tool_input": touch, "prompt_id": "p-1",
                "permission_suggestions": [],
            }),
        ),
    );
    // The person at the terminal says yes after a moment: Claude Code runs the call and records
    // its result. The hook is still waiting; its answer, if it gave one now, would be ignored.
    std::thread::sleep(Duration::from_secs(2));
    transcript.tool_result("toolu_B", "", false);
    w.hook_done(
        &room,
        &with(
            base("PostToolUse", &work, &transcript.0),
            serde_json::json!({
                "tool_name": "Bash", "tool_input": touch, "tool_use_id": "toolu_B",
                "tool_response": { "stdout": "", "stderr": "", "interrupted": false },
                "duration_ms": 3,
            }),
        ),
    );
    let asked = wait_within(asking, Duration::from_secs(15)).unwrap_or_else(|| {
        panic!(
            "PRODUCT: the PermissionRequest hook was still waiting 15 s after the terminal \
             answered: Vox did not see the harness settle the request"
        )
    });
    let said = String::from_utf8_lossy(&asked.stdout).into_owned();
    println!(
        "[proof] (2) the permission hook exited {:?}, printing {said:?}",
        asked.status.code()
    );
    assert!(
        asked.status.success() && said.trim().is_empty(),
        "PRODUCT: once the terminal answered, the permission hook must give Claude Code no \
         decision of its own; it printed {said:?} and exited {:?}",
        asked.status.code()
    );
    let reply = "Done: big.txt is listed and e1 is made.";
    w.hook_done(
        &room,
        &with(
            base("Stop", &work, &transcript.0),
            serde_json::json!({ "stop_hook_active": false, "last_assistant_message": reply }),
        ),
    );

    // ---- (3) the person reads Session S ----
    let want_end = "— turn ended —";
    let deadline = Instant::now() + Duration::from_secs(120);
    let (plain, json) = loop {
        let (ok, plain, err) = w.vox(PERSON, &["room", "session", &room, SESSION], None);
        let (_, json, _) = w.vox(
            PERSON,
            &["room", "session", &room, SESSION, "--json", "--details"],
            None,
        );
        if ok && plain.contains(want_end) {
            break (plain, json);
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: within 120 s, {PERSON} (with drive) never read Session {SESSION} to its \
             turn's end; `vox room session` said:\n{plain}{err}"
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    println!("[proof] (3) `vox room session` as {PERSON}:\n{plain}");
    let lines: Vec<&str> = plain.lines().collect();
    let at = |needle: &str| lines.iter().position(|l| l.contains(needle));
    let typed = at(&format!("typed at the terminal: {prompt}"));
    let listed = at("Bash: cat big.txt → line-00001");
    let approved = at("Bash: touch e1 — answered in the terminal: approved");
    let replied = at(&format!("reply: {reply}"));
    let ended = at(want_end);
    assert!(
        typed.is_some() && listed.is_some() && replied.is_some() && ended.is_some(),
        "PRODUCT: the Session must show the prompt, the first call with its result, the reply and \
         the turn's end; it showed:\n{plain}"
    );
    assert!(
        approved.is_some(),
        "PRODUCT: the approval answered at the terminal must read \"answered in the terminal: \
         approved\"; the Session showed:\n{plain}"
    );
    assert!(
        typed < listed && listed < approved && approved < replied && replied < ended,
        "PRODUCT: the Session must keep the turn's order; it showed:\n{plain}"
    );
    // The first call's output, whole, in one Details view.
    let whole = json
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| {
            v["line"]
                .as_str()
                .is_some_and(|l| l.starts_with("Bash: cat big.txt"))
        })
        .and_then(|v| v["details"]["output"].as_str().map(str::to_owned))
        .unwrap_or_default();
    println!(
        "[proof] (3) Details of `cat big.txt`: {} bytes of output, {} sent",
        whole.len(),
        big.len()
    );
    assert!(
        whole == big,
        "PRODUCT: the output of `cat big.txt` ({} bytes, more than one entry holds) must arrive \
         whole in one Details view; it showed {} bytes",
        big.len(),
        whole.len()
    );
}

// ---- driving through tmux (ADR-029 DR-1, DR-5; #544's Claude Code adapter) ---------------------

/// A scratch tmux server for this run: its own socket under the run root, never the operator's.
/// Its panes run `/bin/sh` with the agent node's environment, as a person's terminal would, and
/// a stand-in for Claude Code is started in a pane by typing its command, so the shell stays when
/// it exits.
struct Tmux {
    bin: String,
    socket: PathBuf,
    env: Vec<(String, String)>,
}

impl Tmux {
    fn new(w: &World, room: &str, name: &str) -> Self {
        let bin = [
            "/opt/homebrew/bin/tmux",
            "/usr/local/bin/tmux",
            "/usr/bin/tmux",
        ]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .unwrap_or_else(|| panic!("APPARATUS, CANNOT MEASURE: no tmux on this machine"))
        .to_owned();
        let tmux_dir = Path::new(&bin)
            .parent()
            .map(|d| d.display().to_string())
            .unwrap_or_default();
        let env = vec![
            ("PATH".into(), format!("{tmux_dir}:/usr/bin:/bin")),
            ("HOME".into(), w.root.join("home").display().to_string()),
            ("VOX_PROXY".into(), "127.0.0.1:0".into()),
            ("VOX_DATA_DIR".into(), w.data.display().to_string()),
            ("VOX_CONFIG_DIR".into(), w.cfg.display().to_string()),
            ("VOX_IDENTITY_PASSPHRASE".into(), format!("pass of {AGENT}")),
            ("VOX_NODE".into(), AGENT.into()),
            ("VOX_LISTEN".into(), "127.0.0.1:0".into()),
            ("VOX_ROOM_ID".into(), room.into()),
            ("CLAUDE_CODE_ENTRYPOINT".into(), "cli".into()),
            ("LANG".into(), "en_US.UTF-8".into()),
            ("TERM".into(), "xterm-256color".into()),
        ];
        let t = Self {
            bin,
            socket: w.root.join(format!("{name}.sock")),
            env,
        };
        let out = t
            .cmd(&["new-session", "-d", "-x", "120", "-y", "30", "/bin/sh"])
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot start tmux: {e}"));
        assert!(
            out.status.success(),
            "APPARATUS: the scratch tmux server did not start: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        t
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(&self.bin);
        c.env_clear()
            .envs(self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .arg("-S")
            .arg(&self.socket)
            .arg("-f")
            .arg("/dev/null")
            .args(args);
        c
    }

    fn run(&self, args: &[&str]) -> String {
        let out = self
            .cmd(args)
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: tmux {args:?}: {e}"));
        assert!(
            out.status.success(),
            "APPARATUS: tmux {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// A new window running a shell; its pane id.
    fn pane(&self) -> String {
        self.run(&["new-window", "-P", "-F", "#{pane_id}", "/bin/sh"])
    }

    fn type_line(&self, pane: &str, line: &str) {
        self.run(&["send-keys", "-t", pane, "-l", line]);
        self.run(&["send-keys", "-t", pane, "Enter"]);
    }

    fn screen(&self, pane: &str) -> String {
        self.run(&["capture-pane", "-p", "-t", pane])
    }
}

impl Drop for Tmux {
    fn drop(&mut self) {
        let _ = self.cmd(&["kill-server"]).output();
    }
}

/// One stand-in Claude Code, started in `pane` (through `wrapper`, a shell script, when given):
/// what it was given, and how to make it run its session's hook.
struct StandIn {
    log: PathBuf,
    control: PathBuf,
    dir: PathBuf,
    hooks: std::cell::Cell<u32>,
}

impl StandIn {
    fn start(w: &World, t: &Tmux, pane: &str, room: &str, name: &str, wrapper: bool) -> Self {
        let dir = w.root.join(name);
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|e| panic!("APPARATUS: cannot make {dir:?}: {e}"));
        let s = Self {
            log: dir.join("log"),
            control: dir.join("control"),
            dir,
            hooks: std::cell::Cell::new(0),
        };
        let hook = serde_json::json!([VOX, "agent", "hook", "--node", AGENT, "--room", room]);
        let script = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/claude_pane_standin.py"
        );
        let run = format!(
            "python3 {script} --log {} --control {} --hook '{hook}'",
            s.log.display(),
            s.control.display()
        );
        let line = if wrapper {
            // A wrapper that is not exec'd: Claude Code started through a script, an `npx`, a
            // version shim. The stand-in is then the pane's grandchild.
            let w = s.dir.join("wrapper.sh");
            std::fs::write(&w, format!("#!/bin/sh\n{run}\nexit $?\n"))
                .unwrap_or_else(|e| panic!("APPARATUS: cannot write the wrapper: {e}"));
            format!("/bin/sh {}", w.display())
        } else {
            run
        };
        t.type_line(pane, &line);
        let t0 = Instant::now();
        while !s.said().contains("\"started\"") {
            assert!(
                t0.elapsed() < Duration::from_secs(15),
                "APPARATUS: the stand-in did not start in pane {pane}: {}",
                t.screen(pane)
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        s.log_tmux(name);
        s
    }

    /// Print the tmux variables the stand-in, and so every hook it runs, holds.
    fn log_tmux(&self, name: &str) {
        let started = self
            .said()
            .lines()
            .find_map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).ok()?;
                v.get("started")?;
                Some(v)
            })
            .unwrap_or_default();
        println!(
            "[proof] stand-in {name}: its hooks hold TMUX={:?} TMUX_PANE={:?}",
            started["TMUX"].as_str().unwrap_or_default(),
            started["TMUX_PANE"].as_str().unwrap_or_default()
        );
    }

    fn said(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Run the session's hook for `event`, as the stand-in's child, and wait for it to finish.
    fn hook(&self, event: &serde_json::Value) {
        self.hook_as("hook", event);
    }

    /// Run the session's hook for `event` through another process between the stand-in and the
    /// hook (a tool or script the session runs), so the hook's parent is not the harness.
    fn hook_via_another(&self, event: &serde_json::Value) {
        self.hook_as("hookvia", event);
    }

    /// The stand-in's own process id, as it recorded it.
    fn pid(&self) -> u32 {
        self.said()
            .lines()
            .find_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()?["started"].as_u64())
            .and_then(|p| u32::try_from(p).ok())
            .unwrap_or_else(|| panic!("APPARATUS: the stand-in recorded no process id"))
    }

    /// A stand-in started by this proof itself, outside every pane, with `env` (as a process
    /// that inherited a pane's `$TMUX` and `$TMUX_PANE` would have them).
    fn start_outside(w: &World, room: &str, name: &str, env: &[(String, String)]) -> (Self, Child) {
        let dir = w.root.join(name);
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|e| panic!("APPARATUS: cannot make {dir:?}: {e}"));
        let s = Self {
            log: dir.join("log"),
            control: dir.join("control"),
            dir,
            hooks: std::cell::Cell::new(0),
        };
        let hook = serde_json::json!([VOX, "agent", "hook", "--node", AGENT, "--room", room]);
        let script = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/claude_pane_standin.py"
        );
        let child = Command::new("python3")
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .args([script, "--log"])
            .arg(&s.log)
            .arg("--control")
            .arg(&s.control)
            .args(["--hook", &hook.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot start the stand-in: {e}"));
        let t0 = Instant::now();
        while !s.said().contains("\"started\"") {
            assert!(
                t0.elapsed() < Duration::from_secs(15),
                "APPARATUS: the stand-in did not start outside the panes"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        s.log_tmux(name);
        (s, child)
    }

    fn hook_as(&self, how: &str, event: &serde_json::Value) {
        let n = self.hooks.get() + 1;
        self.hooks.set(n);
        let file = self.dir.join(format!("event-{n}.json"));
        std::fs::write(&file, event.to_string())
            .unwrap_or_else(|e| panic!("APPARATUS: cannot write a hook event: {e}"));
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.control)
            .unwrap_or_else(|e| panic!("APPARATUS: the stand-in's control: {e}"));
        writeln!(f, "{how} {}", file.display())
            .unwrap_or_else(|e| panic!("APPARATUS: the stand-in's control: {e}"));
        let needle = format!("\"hook\": \"event-{n}.json\"");
        let t0 = Instant::now();
        while !self.said().contains(&needle) {
            assert!(
                t0.elapsed() < Duration::from_secs(20),
                "APPARATUS: the stand-in's hook {n} did not finish within 20 s"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Write one line to the stand-in's control: `ask` puts up a permission prompt, `unask` takes
    /// it down.
    fn control(&self, line: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.control)
            .unwrap_or_else(|e| panic!("APPARATUS: the stand-in's control: {e}"));
        writeln!(f, "{line}").unwrap_or_else(|e| panic!("APPARATUS: the stand-in's control: {e}"));
        std::thread::sleep(Duration::from_millis(300));
    }

    fn exit(&self) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.control)
            .unwrap_or_else(|e| panic!("APPARATUS: the stand-in's control: {e}"));
        writeln!(f, "exit").unwrap_or_else(|e| panic!("APPARATUS: the stand-in's control: {e}"));
        let t0 = Instant::now();
        while !self.said().contains("\"exited\"") {
            assert!(
                t0.elapsed() < Duration::from_secs(10),
                "APPARATUS: the stand-in did not exit"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        std::thread::sleep(Duration::from_millis(300));
    }

    /// Whether the stand-in was given `entry` (one JSON line it recorded) within `wait`.
    fn got(&self, entry: &serde_json::Value, wait: Duration) -> bool {
        let line = entry.to_string().replace(':', ": ").replace(',', ", ");
        let t0 = Instant::now();
        loop {
            if self.said().lines().any(|l| l == line) {
                return true;
            }
            if t0.elapsed() >= wait {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// `vox room session ROOM SESSION <act...>` as the person, the driver: (succeeded, what it said).
fn drive(w: &World, room: &str, session: &str, act: &[&str]) -> (bool, String) {
    let mut args = vec!["room", "session", room, session];
    args.extend_from_slice(act);
    let (ok, out, err) = w.vox(PERSON, &args, None);
    (ok, format!("{out}{err}").trim().to_owned())
}

/// A prompt event for `session`, as the stand-in's hook gets it: registers it, binds its pane and
/// opens its Session.
fn prompt(w: &World, session: &str) -> serde_json::Value {
    let work = w.root.join("work");
    let t = work.join(format!("{session}.jsonl"));
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&t);
    with(
        base_for(session, "UserPromptSubmit", &work, &t),
        serde_json::json!({ "prompt": "hello", "prompt_id": "p" }),
    )
}

fn event(w: &World, session: &str, name: &str, extra: serde_json::Value) -> serde_json::Value {
    let work = w.root.join("work");
    let t = work.join(format!("{session}.jsonl"));
    with(base_for(session, name, &work, &t), extra)
}

/// Wait until `session`'s Session is listed in the room, as the driver sees it.
fn session_listed(w: &World, room: &str, session: &str) {
    let t0 = Instant::now();
    loop {
        let (_, out, _) = w.vox(PERSON, &["room", "sessions", room, "--json"], None);
        if out.contains(session) {
            return;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(60),
            "APPARATUS (staging): within 60 s, {PERSON} never saw Session {session} listed: {out}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

const S1: &str = "11111111-aaaa-4000-8000-000000000001";
const S2: &str = "22222222-bbbb-4000-8000-000000000002";
const S3: &str = "33333333-cccc-4000-8000-000000000003";
const S4: &str = "44444444-dddd-4000-8000-000000000004";
const S5: &str = "55555555-eeee-4000-8000-000000000005";
const S6: &str = "66666666-ffff-4000-8000-000000000006";
const S8: &str = "88888888-1111-4000-8000-000000000008";

/// ADR-029 DR-1, DR-5 — **input reaches exactly the session it is for, or is refused with why.**
///
/// A driver (`person`, trusted by `claude-a` with drive) drives Claude Code sessions in panes of a
/// scratch tmux server with `vox room session … --say/--interrupt/--stop/--slash`; each pane holds
/// a stand-in that records the keys it gets and runs the session's hook as its child, as Claude
/// Code does. One arm per case the pane↔session mapping must settle (the mapping note, approved
/// 2026-10-06):
///
/// 1. two sessions in one server: each one's text, Esc, Ctrl-C and slash command reach only its
///    own pane;
///    1b. a slash command with an argument (`/rename frogs`) reaches the pane whole and the
///    Session says it whole; the name Claude Code then writes into the transcript, with no hook
///    run (a `/rename` runs none), renames the Session within 15 s;
///    1c. while the session asks for permission in its terminal (its input box replaced by the
///    prompt), `--say "1"` and `--slash` are refused, saying it is asking something, and the prompt
///    gets no key; once the prompt is gone, `--say` reaches the session; a prompt that comes up as
///    the keys arrive gets no Enter, and the driver is told the keys may have reached it;
/// 2. a sub-agent's hook leaves its session's binding as it was;
/// 3. a session started through a wrapper (a shell script, not exec'd) is still bound;
/// 4. the pane swapped with another and moved to a new window: input follows the pane;
/// 5. a second server whose pane is also %0: each session reaches its own server;
/// 6. `$TMUX`/`$TMUX_PANE` naming a pane the harness does not run in (as ssh forwarding or an
///    inherited environment gives): refused;
/// 7. the session exited, its pane back at the shell: refused, and the shell got nothing;
/// 8. a new session in the same process and pane (`/clear`): the old one is refused;
/// 9. the same session resumed in another pane: input goes to the new pane;
/// 10. a session first seen by a tool hook (no prompt yet): bound; one never seen: refused;
/// 11. a file a driver sends into a session (`--file`, #546) lands, and the session's terminal
///     is told its path ("person sent you a file: <path> — <note>"), the file there byte for byte.
/// 12. a hook started inside a pane by a process other than the harness (a tool the session ran,
///     a test beneath a person's pane): the pane is not proven, and nothing is typed into it.
///
/// **Which side a red is on.** What `vox room session` printed, or what a stand-in got or did not
/// get, is `PRODUCT:`. A tmux server, stand-in or event this proof could not stage is
/// `APPARATUS:`.
///
/// **Mutations, one per check that can fail on its own:** the injector types into the first pane
/// of the server (arm 1); the session's process must be the hook's own parent (arm 3); the
/// pane is recorded by its position, not its id (arm 4); the slash line said by its command alone,
/// or the transcript not read for a name (arm 1b, `…--reads2--v043-rename-*` mutants); an input box that cannot be found taken
/// for one that took the text (arm 1c); one session per pane ignores the server
/// (arm 5); the hook's ancestry not required to reach the pane (arm 6); the session's process not
/// checked at the send (arm 7); one session per pane not kept (arm 8); a later hook not rebinding
/// (arm 9); a tool hook not registering (arm 10); the session not told where its file landed
/// (arm 11); the hook's parent not required to be the harness (arm 12).
#[test]
#[ignore = "real binary; run in release"]
fn a_driver_reaches_exactly_the_session_it_names_or_is_told_why() {
    watchdog::arm_for(Duration::from_secs(900));
    let (w, _daemon, room) = World::setup();
    let t = Tmux::new(&w, &room, "t1");

    // ---- 1. two sessions in one server ----
    let p1 = t.pane();
    let p2 = t.pane();
    let a = StandIn::start(&w, &t, &p1, &room, "a", false);
    // **The stand-in is the harness here** (the lead's binding rule, 2026-10-07: a hook's parent
    // must be the harness, known by its executable's path from the kernel). The daemon's
    // `harnesses` file names the stand-in's executable, as it names a Claude Code installed
    // somewhere other than its native install; nothing else changes.
    // Read from the kernel, as the daemon reads it: no `lsof`, which a sandbox may refuse to run.
    #[cfg(target_os = "macos")]
    let exe = i32::try_from(a.pid())
        .ok()
        .and_then(|pid| libproc::proc_pid::pidpath(pid).ok());
    #[cfg(not(target_os = "macos"))]
    let exe = std::fs::read_link(format!("/proc/{}/exe", a.pid()))
        .ok()
        .map(|p| p.display().to_string());
    let exe = exe
        .unwrap_or_else(|| panic!("APPARATUS: the kernel did not give the stand-in's executable"));
    std::fs::create_dir_all(&w.cfg)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make the config dir: {e}"));
    std::fs::write(w.cfg.join("harnesses"), format!("{exe}\n"))
        .unwrap_or_else(|e| panic!("APPARATUS: cannot write the harnesses file: {e}"));
    println!("[proof] the harness the daemon recognises: {exe}");
    let b = StandIn::start(&w, &t, &p2, &room, "b", false);
    a.hook(&prompt(&w, S1));
    b.hook(&prompt(&w, S2));
    session_listed(&w, &room, S1);
    session_listed(&w, &room, S2);
    for (s, mine, other, text) in [(S1, &a, &b, "for one"), (S2, &b, &a, "for two")] {
        let (ok, said) = drive(&w, &room, s, &["--say", text]);
        println!("[proof] 1. --say {text:?} to {s}: {said}");
        let typed = serde_json::json!({ "typed": text });
        assert!(
            ok && mine.got(&typed, Duration::from_secs(10)),
            "PRODUCT: arm 1: {text:?} must reach {s}'s pane; vox said {said:?}"
        );
        assert!(
            !other.got(&typed, Duration::from_millis(500)),
            "PRODUCT: arm 1: {text:?}, sent to {s}, reached the other session's pane"
        );
    }
    for (act, got) in [
        (vec!["--interrupt"], serde_json::json!({ "key": "Escape" })),
        (vec!["--stop"], serde_json::json!({ "key": "C-c" })),
        (
            vec!["--slash", "/compact"],
            serde_json::json!({ "typed": "/compact" }),
        ),
    ] {
        let (ok, said) = drive(&w, &room, S1, &act);
        println!("[proof] 1. {act:?} to {S1}: {said}");
        assert!(
            ok && a.got(&got, Duration::from_secs(10)) && !b.got(&got, Duration::from_millis(300)),
            "PRODUCT: arm 1: {act:?} must reach {S1}'s pane alone; vox said {said:?}"
        );
    }

    // ---- 1b. a slash command with its argument arrives whole, and is said whole; the name the
    // harness gives it after (a `/rename`, which runs no hook) renames the Session (v0.4.3) ----
    let (ok, said) = drive(&w, &room, S1, &["--slash", "/rename frogs"]);
    println!("[proof] 1b. --slash \"/rename frogs\" to {S1}: {said}");
    assert!(
        ok && a.got(
            &serde_json::json!({ "typed": "/rename frogs" }),
            Duration::from_secs(10)
        ),
        "PRODUCT: arm 1b: \"/rename frogs\" must reach {S1}'s pane whole; vox said {said:?}"
    );
    let t0 = Instant::now();
    let mut read = String::new();
    while t0.elapsed() < Duration::from_secs(30) && !read.contains("/rename frogs sent by") {
        read = w.vox(PERSON, &["room", "session", &room, S1], None).1;
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(
        read.contains("/rename frogs sent by"),
        "PRODUCT: arm 1b: {S1}'s Session must say the slash command as sent, \"/rename frogs sent \
         by …\"; `vox room session` says: {}",
        read.lines().rev().take(6).collect::<Vec<_>>().join(" | ")
    );
    // Claude Code writes the new name into the session's transcript and runs no hook: the stand-in
    // does the same, appending the line Claude Code 2.1.29x writes.
    {
        use std::io::Write as _;
        let t = w.root.join("work").join(format!("{S1}.jsonl"));
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&t)
            .unwrap_or_else(|e| panic!("APPARATUS: cannot open {S1}'s transcript: {e}"));
        // Claude Code's own title first (what an earlier "cc rename frogs" made it, as the
        // decider's session had), then the name the person set: the person's must win, exactly.
        for line in [
            serde_json::json!({ "type": "ai-title", "aiTitle": "Frogs rename", "sessionId": S1 }),
            serde_json::json!({ "type": "custom-title", "customTitle": "frogs", "sessionId": S1 }),
        ] {
            writeln!(f, "{line}")
                .unwrap_or_else(|e| panic!("APPARATUS: cannot write {S1}'s transcript: {e}"));
        }
    }
    let t0 = Instant::now();
    let mut named = String::new();
    let renamed = loop {
        let (_, out, _) = w.vox(PERSON, &["room", "sessions", &room, "--json"], None);
        named = out
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .find(|v| v["session"].as_str() == Some(S1) || v["id"].as_str() == Some(S1))
            .map(|v| v["name"].to_string())
            .unwrap_or(named);
        if named == "\"frogs\"" {
            break true;
        }
        if t0.elapsed() > Duration::from_secs(15) {
            break false;
        }
        std::thread::sleep(Duration::from_millis(300));
    };
    assert!(
        renamed,
        "PRODUCT: arm 1b: renamed \"frogs\" by its person in its transcript, after Claude Code's own \
         title \"Frogs rename\" and with no hook run, {S1}'s Session must be called exactly \
         \"frogs\" within 15 s; `vox room sessions --json` says its name is {named}"
    );
    println!("[proof] 1b. \"/rename frogs\" arrived whole and is said whole; the transcript's rename named the Session \"frogs\" with no hook run");

    // ---- 1c. Claude Code asking a question in its terminal: nothing typed answers it ----
    a.control("ask");
    let asked = Instant::now();
    while !t.screen(&p1).contains("Do you want to proceed?") {
        assert!(
            asked.elapsed() < Duration::from_secs(10),
            "APPARATUS: arm 1c: the stand-in's permission prompt did not show in {p1}: {}",
            t.screen(&p1)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    for act in [vec!["--say", "1"], vec!["--slash", "/compact"]] {
        let (ok, said) = drive(&w, &room, S1, &act);
        println!("[proof] 1c. {act:?} to {S1} while it asks for permission: {said}");
        let answered = a.said().lines().any(|l| l.contains("\"answered\""));
        assert!(
            !ok && said.contains("asking something in its terminal") && !answered,
            "PRODUCT: arm 1c: while {S1} asks for permission in its terminal, {act:?} must be \
             refused with why and type nothing (typed keys answer the prompt); vox said {said:?}, \
             and the prompt got: {:?}",
            a.said()
                .lines()
                .filter(|l| l.contains("\"answered\""))
                .collect::<Vec<_>>()
        );
    }
    a.control("unask");
    let (ok, said) = drive(&w, &room, S1, &["--say", "after the question"]);
    println!("[proof] 1c. --say to {S1} once the prompt is gone: {said}");
    assert!(
        ok && a.got(
            &serde_json::json!({ "typed": "after the question" }),
            Duration::from_secs(10)
        ),
        "PRODUCT: arm 1c: once {S1}'s prompt is gone, --say must reach it; vox said {said:?}"
    );
    // A prompt that comes up as the keys arrive (the window between Vox's look and its keys):
    // Enter is never pressed into it, and Vox says the keys may have reached it.
    a.control("ask-on-key");
    let (ok, said) = drive(&w, &room, S1, &["--say", "raced by a prompt"]);
    println!("[proof] 1c. --say to {S1} as a prompt comes up: {said}");
    let enter = a.said().lines().any(|l| l == r#"{"answered": "\r"}"#);
    assert!(
        !ok && said.contains("came up in Claude Code's terminal as Vox typed") && !enter,
        "PRODUCT: arm 1c: a prompt that came up as Vox typed must get no Enter, and the driver \
         must be told the keys may have reached it; vox said {said:?}, Enter reached the prompt: \
         {enter}"
    );
    a.control("unask");

    // ---- 2. a sub-agent's hook keeps its session's binding ----
    a.hook(&event(
        &w,
        S1,
        "PreToolUse",
        serde_json::json!({ "tool_name": "Read", "tool_input": { "file_path": "x" },
            "tool_use_id": "toolu_sub", "agent_id": "ag-1", "agent_type": "explore" }),
    ));
    let (ok, said) = drive(&w, &room, S1, &["--say", "after the sub-agent"]);
    assert!(
        ok && a.got(
            &serde_json::json!({ "typed": "after the sub-agent" }),
            Duration::from_secs(10)
        ),
        "PRODUCT: arm 2: a sub-agent's hook must leave {S1} bound to its pane; vox said {said:?}"
    );

    // ---- 3. a session started through a wrapper ----
    let p3 = t.pane();
    let c = StandIn::start(&w, &t, &p3, &room, "c", true);
    c.hook(&prompt(&w, S3));
    session_listed(&w, &room, S3);
    let (ok, said) = drive(&w, &room, S3, &["--say", "through the wrapper"]);
    println!("[proof] 3. --say to {S3}, started through a wrapper: {said}");
    assert!(
        ok && c.got(
            &serde_json::json!({ "typed": "through the wrapper" }),
            Duration::from_secs(10)
        ),
        "PRODUCT: arm 3: a session started through a wrapper must be driven in its pane; vox said \
         {said:?}"
    );

    // ---- 4. panes swapped and moved: input follows the pane ----
    t.run(&["swap-pane", "-s", &p1, "-t", &p2]);
    t.run(&["break-pane", "-d", "-s", &p1]);
    let (ok, said) = drive(&w, &room, S1, &["--say", "after the move"]);
    println!("[proof] 4. --say to {S1} after its pane was swapped and moved: {said}");
    assert!(
        ok && a.got(
            &serde_json::json!({ "typed": "after the move" }),
            Duration::from_secs(10)
        ) && !b.got(
            &serde_json::json!({ "typed": "after the move" }),
            Duration::from_millis(300)
        ),
        "PRODUCT: arm 4: after its pane was swapped and moved, {S1}'s input must follow its pane; \
         vox said {said:?}"
    );

    // ---- 5. a second server, whose pane is also %0 ----
    // Server one's own %0 holds a session too, so the two %0s are each bound.
    let first = t.run(&["display-message", "-p", "-t", ":0.0", "#{pane_id}"]);
    let g = StandIn::start(&w, &t, &first, &room, "g", false);
    g.hook(&prompt(&w, S8));
    let t2 = Tmux::new(&w, &room, "t2");
    let q0 = t2.run(&["display-message", "-p", "-t", ":0.0", "#{pane_id}"]);
    let d = StandIn::start(&w, &t2, &q0, &room, "d", false);
    d.hook(&prompt(&w, S4));
    session_listed(&w, &room, S8);
    session_listed(&w, &room, S4);
    println!("[proof] 5. server t1's first pane {first}, server t2's {q0}");
    for (s, mine, other, text) in [(S4, &d, &g, "to server two"), (S8, &g, &d, "to server one")] {
        let (ok, said) = drive(&w, &room, s, &["--say", text]);
        println!("[proof] 5. --say {text:?} to {s}: {said}");
        assert!(
            ok && mine.got(&serde_json::json!({ "typed": text }), Duration::from_secs(10))
                && !other.got(&serde_json::json!({ "typed": text }), Duration::from_millis(300)),
            "PRODUCT: arm 5: with two servers' %0 each bound, {text:?} must reach {s}'s own server \
             alone; vox said {said:?}"
        );
    }

    // ---- 6. $TMUX_PANE naming a pane the harness does not run in ----
    // A harness started outside every pane that inherited a pane's variables (as ssh forwarding,
    // or a process started from a pane, would give them): its hook is the harness's own, but the
    // harness is not beneath the pane.
    let mut env = t.env.clone();
    env.push(("TMUX".into(), format!("{},1,0", t.socket.display())));
    env.push(("TMUX_PANE".into(), p2.clone()));
    let (out, mut outside) = StandIn::start_outside(&w, &room, "out", &env);
    out.hook(&prompt(&w, S5));
    let _ = outside.kill();
    let _ = outside.wait();
    session_listed(&w, &room, S5);
    let (ok, said) = drive(&w, &room, S5, &["--say", "not for this pane"]);
    println!("[proof] 6. --say to {S5}, whose $TMUX_PANE names {p2} it is not in: {said}");
    assert!(
        !ok && said.contains("does not run under tmux pane")
            && !b.got(
                &serde_json::json!({ "typed": "not for this pane" }),
                Duration::from_millis(500)
            ),
        "PRODUCT: arm 6: a session whose $TMUX_PANE names a pane its harness does not run in \
         must be refused with why, and that pane must get nothing; vox said {said:?}"
    );

    // ---- 7. the session exited, the pane back at its shell ----
    c.exit();
    let (ok, said) = drive(&w, &room, S3, &["--say", "echo LEAKED-INTO-SHELL"]);
    println!("[proof] 7. --say to {S3} after it exited: {said}");
    std::thread::sleep(Duration::from_millis(500));
    let shell = t.screen(&p3);
    assert!(
        !ok && said.contains("no longer running") && !shell.contains("LEAKED-INTO-SHELL"),
        "PRODUCT: arm 7: a session that exited must be refused, saying so, and its pane's shell \
         must get nothing; vox said {said:?}; the pane shows:\n{shell}"
    );

    // ---- 8. a new session in the same process and pane (`/clear`) ----
    b.hook(&prompt(&w, S6));
    session_listed(&w, &room, S6);
    let (ok, said) = drive(&w, &room, S2, &["--say", "to the cleared session"]);
    println!("[proof] 8. --say to {S2} after {S6} started in its pane and process: {said}");
    assert!(
        !ok && said.contains("now runs another session")
            && !b.got(
                &serde_json::json!({ "typed": "to the cleared session" }),
                Duration::from_millis(500)
            ),
        "PRODUCT: arm 8: after a new session took its pane, {S2} must be refused with why; vox \
         said {said:?}"
    );
    let (ok, said) = drive(&w, &room, S6, &["--say", "to the new session"]);
    assert!(
        ok && b.got(
            &serde_json::json!({ "typed": "to the new session" }),
            Duration::from_secs(10)
        ),
        "PRODUCT: arm 8: the new session {S6} must be driven in the pane; vox said {said:?}"
    );

    // ---- 9. the same session resumed in another pane ----
    a.exit();
    let p4 = t.pane();
    let e = StandIn::start(&w, &t, &p4, &room, "e", false);
    e.hook(&event(
        &w,
        S1,
        "SessionStart",
        serde_json::json!({ "source": "resume" }),
    ));
    let (ok, said) = drive(&w, &room, S1, &["--say", "after the resume"]);
    println!("[proof] 9. --say to {S1} resumed in {p4}: {said}");
    assert!(
        ok && e.got(
            &serde_json::json!({ "typed": "after the resume" }),
            Duration::from_secs(10)
        ),
        "PRODUCT: arm 9: {S1}, resumed in another pane, must be driven there; vox said {said:?}"
    );

    // ---- 10. first seen by a tool hook; never seen ----
    let never = "77777777-0000-4000-8000-000000000007";
    let (ok, said) = drive(&w, &room, never, &["--say", "to no one"]);
    println!("[proof] 10. --say to a session never seen: {said}");
    assert!(
        !ok,
        "PRODUCT: arm 10: a session Vox has never seen must be refused; vox said {said:?}"
    );
    let p5 = t.pane();
    let f = StandIn::start(&w, &t, &p5, &room, "f", false);
    let s7 = "77777777-1111-4000-8000-000000000007";
    f.hook(&event(
        &w,
        s7,
        "PreToolUse",
        serde_json::json!({ "tool_name": "Bash", "tool_input": { "command": "ls" }, "tool_use_id": "toolu_first" }),
    ));
    // The Session opens as the daemon takes the hook; until it is listed, a drive is refused.
    let t0 = Instant::now();
    let (ok, said) = loop {
        let (ok, said) = drive(&w, &room, s7, &["--say", "after a tool hook"]);
        if ok || t0.elapsed() > Duration::from_secs(60) {
            break (ok, said);
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    println!("[proof] 10. --say to {s7}, first seen by a tool hook: {said}");
    assert!(
        ok && f.got(&serde_json::json!({ "typed": "after a tool hook" }), Duration::from_secs(10)),
        "PRODUCT: arm 10: a session first seen by a tool hook must be bound by it; vox said {said:?}"
    );

    // ---- 11. a file sent into the session: it lands, and the session is told where (#546) ----
    let sent = w.root.join("for-s1.txt");
    let bytes = "a file for session one\n".repeat(64);
    std::fs::write(&sent, &bytes)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot write the file: {e}"));
    let sent_s = sent.display().to_string();
    let (ok, said) = drive(&w, &room, S1, &["--file", &sent_s, "--note", "for you"]);
    println!("[proof] 11. --file to {S1}: {said}");
    assert!(
        ok,
        "PRODUCT: arm 11: the file must be taken for {S1}; vox said {said:?}"
    );
    let t0 = Instant::now();
    let told = loop {
        let line = e.said().lines().find_map(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .ok()?
                .get("typed")?
                .as_str()
                .filter(|t| t.starts_with("person sent you a file: ") && t.ends_with(" — for you"))
                .map(str::to_owned)
        });
        if let Some(line) = line {
            break Some(line);
        }
        if t0.elapsed() > Duration::from_secs(60) {
            break None;
        }
        std::thread::sleep(Duration::from_millis(300));
    };
    println!("[proof] 11. {S1}'s pane was told: {told:?}");
    let Some(told) = told else {
        panic!(
            "PRODUCT: arm 11: within 60 s, {S1}'s terminal must be told the file's path \
             (\"person sent you a file: <path> — for you\"); its pane got:\n{}",
            e.said()
        )
    };
    let path = told
        .trim_start_matches("person sent you a file: ")
        .trim_end_matches(" — for you");
    let landed = std::fs::read_to_string(path).unwrap_or_default();
    assert!(
        landed == bytes,
        "PRODUCT: arm 11: the path {S1} was told ({path}) must hold the file sent, byte for byte; \
         it holds {} bytes of {}",
        landed.len(),
        bytes.len()
    );
    // The driver reads what came of it on the drive's own line: taken, then landed and told
    // (the results paired with the drive by its tag).
    let t0 = Instant::now();
    let shown = loop {
        let (_, plain, _) = w.vox(PERSON, &["room", "session", &room, S1], None);
        let line = plain
            .lines()
            .find(|l| l.starts_with("file sent in by you: for-s1.txt ("))
            .map(str::to_owned);
        if let Some(l) = line.filter(|l| l.contains("and the session was told")) {
            break l;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(60),
            "PRODUCT: arm 11: within 60 s, the driver's Session must show the file sent in and \
             what came of it on one line (\"file sent in by you: for-s1.txt (…) — accepted, \
             pulling … — landed …, and the session was told\"); it showed:\n{plain}"
        );
        std::thread::sleep(Duration::from_millis(300));
    };
    println!("[proof] 11. the driver's Session: {shown}");
    assert!(
        shown.contains(" — accepted, pulling 1472 bytes"),
        "PRODUCT: arm 11: the file's line must carry the first result, \"accepted, pulling 1472 \
         bytes\", before the landing; it read {shown:?}"
    );

    // ---- 12. a hook started inside a pane by something other than the harness ----
    // The stand-in (the harness) runs a tool, and the tool starts the hook: as a test or a script
    // run beneath a person's real pane would. Its pane is never proven, under any session id.
    let p6 = t.pane();
    let h = StandIn::start(&w, &t, &p6, &room, "h", false);
    let s9 = "99999999-0000-4000-8000-000000000009";
    h.hook_via_another(&prompt(&w, s9));
    session_listed(&w, &room, s9);
    let (ok, said) = drive(&w, &room, s9, &["--say", "from a stranger"]);
    println!("[proof] 12. --say to {s9}, whose hook a tool in the pane started: {said}");
    assert!(
        !ok && said.contains("was not started by Claude Code itself")
            && !h.got(
                &serde_json::json!({ "typed": "from a stranger" }),
                Duration::from_millis(500)
            ),
        "PRODUCT: arm 12: a pane named by a hook the harness did not start itself must not be \
         proven, and nothing may be typed into it; vox said {said:?}"
    );
    // The tool ends with the stand-in.
    h.exit();
}

/// The ref a waiting request's line says to answer it with: the word after `flag` on the
/// "waiting:" line under the line holding `line`.
fn waiting_ref(plain: &str, line: &str, flag: &str) -> Option<String> {
    let lines: Vec<&str> = plain.lines().collect();
    let at = lines.iter().position(|l| l.contains(line))?;
    let next = lines.get(at + 1)?.trim();
    // The command a person would run, whole: `vox room session ROOM SESSION --approve <ref>`.
    let rest = next
        .strip_prefix("waiting: vox room session ")?
        .split(flag)
        .nth(1)?;
    Some(
        rest.split(|c: char| c.is_whitespace() || c == ',')
            .next()?
            .to_owned(),
    )
}

/// ADR-029 DR-3, DR-4 (#545) — **an approval or a question is answered from either side, and the
/// harness's own record says which answer took effect.**
///
/// The stand-in harness keeps Claude Code's rule, read from 2.1.292 and seen live: its prompt and
/// the `PermissionRequest` hook are open together, the first to answer claims the request, and the
/// transcript records the outcome (a `tool_result`, an error for a rejection, carrying the
/// rejection's text). `person`, with drive, answers with `vox room session … --approve/--reject/
/// --answer` and reads the Session.
///
/// 1. approved in the Session first: the hook gives Claude Code the approval; the Session reads
///    "approved here";
/// 2. rejected in the Session, with a reason: the hook gives the rejection with that reason; the
///    Session reads "rejected here";
/// 3. a question answered in the Session: the hook gives the answers with the question's input;
///    the Session reads "answered here: Blue";
/// 4. the race: the terminal claims a rejection, then the Session's approval reaches the hook
///    before the harness has recorded the rejection. Exactly one takes effect, the terminal's: the
///    Session reads "answered in the terminal: rejected", and an answer after the record is
///    refused, saying it was answered at the terminal.
/// 5. approved from the Session's own node: `claude-a`, the node the session runs on, approves
///    with `vox room session` as its operator (ADR-029 SC-2), trusting nobody but `person`. The
///    hook gives the approval; once the harness records it, `claude-a` (what the app reads) reads
///    "approved here" and `person` "answered in Vox by claude-a: approved", with no request waiting
///    on either.
/// 6. a file sent in from the Session's own node: it lands whole on that node, where the Session
///    says (no tunnel runs from a node to itself, so it is copied from the share).
/// 7. another node on the same daemon, through the own-node path: the test, as an attacker
///    (apparatus), writes the own-node drive request (`OwnDrive`) for `claude-a`'s Session on
///    `person`'s own connection to the daemon. It is refused, and the hook is still waiting
///    3 s later: that path drives only the attached node's own Sessions.
/// 8. renamed mid-session (`/rename`, which Claude Code writes into the transcript as a
///    `custom-title` line): at the session's next hook event, which posts no message to the room,
///    its Session reads the new name in `vox room sessions` (ADR-029 MD-1).
///
/// **Mutations that must turn it red** (#545's own): the request closed when the Session's answer
/// is sent → arm 4 reads "approved here". A node's own drive refused as an untrusted node's (DR-2
/// without the node itself) → arm 5 is refused. A file from the node itself pulled as from another
/// node → arm 6 reads "did not arrive whole". The sink not posting its `resolved` entry → arm 5's
/// request still waits. The own-node request served as whichever attached node
/// holds the Session (not the one the connection is attached as) → arm 7's request is delivered.
/// A renamed session's Session not renamed until its next message (the rename record dropped) →
/// arm 8 reads the old name.
#[test]
#[ignore = "real binary; run in release"]
fn an_approval_is_answered_from_either_side_and_the_first_answer_wins() {
    watchdog::arm_for(Duration::from_secs(600));
    let (w, _daemon, room) = World::setup();
    let work = w.root.join("work");
    let transcript = Transcript(work.join(format!("{SESSION}.jsonl")));
    std::fs::write(&transcript.0, "")
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make the transcript: {e}"));
    let ev = |name: &str, extra: serde_json::Value| with(base(name, &work, &transcript.0), extra);
    w.hook_done(
        &room,
        &ev(
            "UserPromptSubmit",
            serde_json::json!({ "prompt": "make e2, e3, e4", "prompt_id": "p-1" }),
        ),
    );
    session_listed(&w, &room, SESSION);
    let session_says = |want: &str| -> String {
        let t0 = Instant::now();
        loop {
            let (_, plain, err) = w.vox(PERSON, &["room", "session", &room, SESSION], None);
            if plain.contains(want) {
                return plain;
            }
            assert!(
                t0.elapsed() < Duration::from_secs(60),
                "PRODUCT: within 60 s the Session never read {want:?}; it read:\n{plain}{err}"
            );
            std::thread::sleep(Duration::from_millis(300));
        }
    };
    // One permission request: the call starts, the hook asks and waits.
    let ask = |id: &str, tool: &str, input: &serde_json::Value| -> Child {
        w.hook_done(
            &room,
            &ev(
                "PreToolUse",
                serde_json::json!({ "tool_name": tool, "tool_input": input, "tool_use_id": id }),
            ),
        );
        let child = w.hook(
            &room,
            &ev(
                "PermissionRequest",
                serde_json::json!({ "tool_name": tool, "tool_input": input,
                    "permission_suggestions": [] }),
            ),
        );
        std::thread::sleep(Duration::from_secs(1));
        child
    };
    let decision = |child: Child| -> serde_json::Value {
        let out = wait_within(child, Duration::from_secs(20))
            .unwrap_or_else(|| panic!("PRODUCT: the permission hook never gave an answer"));
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap_or(serde_json::Value::Null)
            ["hookSpecificOutput"]["decision"]
            .clone()
    };

    // ---- 1. approved in the Session ----
    let e2 = serde_json::json!({ "command": "touch e2" });
    let hook = ask("toolu_2", "Bash", &e2);
    // A person approves with the ref the Session prints, and nothing else.
    let plain = session_says("Bash: touch e2 — approve or reject?");
    let printed = waiting_ref(&plain, "Bash: touch e2 — approve or reject?", "--approve ");
    println!("[proof] 1. the Session names the approval's ref: {printed:?}");
    let Some(printed) = printed else {
        panic!(
            "PRODUCT: arm 1: a waiting approval must say how to answer it, with its ref \
             (\"waiting: vox room session ROOM SESSION --approve <ref>\"); the Session read:\n{plain}"
        );
    };
    let (ok, said) = drive(&w, &room, SESSION, &["--approve", &printed]);
    println!("[proof] 1. --approve toolu_2: {said}");
    let d = decision(hook);
    assert!(
        ok && d["behavior"] == "allow",
        "PRODUCT: arm 1: the Session's approval must reach Claude Code through its hook; vox said \
         {said:?}, the hook gave {d}"
    );
    // The harness takes it: the call runs.
    transcript.tool_result("toolu_2", "", false);
    w.hook_done(
        &room,
        &ev(
            "PostToolUse",
            serde_json::json!({ "tool_name": "Bash", "tool_input": e2, "tool_use_id": "toolu_2",
                "tool_response": { "stdout": "", "stderr": "", "interrupted": false } }),
        ),
    );
    session_says("Bash: touch e2 — approved here");

    // ---- 2. rejected in the Session, with a reason ----
    let e3 = serde_json::json!({ "command": "touch e3" });
    let hook = ask("toolu_3", "Bash", &e3);
    let (ok, said) = drive(&w, &room, SESSION, &["--reject", "toolu_3", "not now"]);
    println!("[proof] 2. --reject toolu_3: {said}");
    let d = decision(hook);
    let message = d["message"].as_str().unwrap_or_default().to_owned();
    assert!(
        ok && d["behavior"] == "deny"
            && message.contains("rejected in Vox by")
            && message.contains("not now"),
        "PRODUCT: arm 2: the Session's rejection must reach Claude Code with its reason; the hook \
         gave {d}"
    );
    transcript.tool_result("toolu_3", &message, true);
    session_says("Bash: touch e3 — rejected here");

    // ---- 3. a question answered in the Session ----
    let q = serde_json::json!({ "questions": [ { "question": "Which colour?", "header": "Colour",
        "multiSelect": false, "options": [ { "label": "Red", "description": "red" },
        { "label": "Blue", "description": "blue" } ] } ] });
    let hook = ask("toolu_q", "AskUserQuestion", &q);
    let plain = session_says("question: Which colour?");
    let printed =
        waiting_ref(&plain, "question: Which colour?", "--answer ").unwrap_or_else(|| {
            panic!(
                "PRODUCT: arm 3: a waiting question must say how to answer it, with its ref; the \
             Session read:\n{plain}"
            )
        });
    let (ok, said) = drive(
        &w,
        &room,
        SESSION,
        &["--answer", &printed, "Which colour?=Blue"],
    );
    println!("[proof] 3. --answer toolu_q: {said}");
    let d = decision(hook);
    assert!(
        ok && d["behavior"] == "allow"
            && d["updatedInput"]["answers"]["Which colour?"] == "Blue"
            && d["updatedInput"]["questions"] == q["questions"],
        "PRODUCT: arm 3: the Session's answer must reach Claude Code as the question's input with \
         its answers; the hook gave {d}"
    );
    let line = serde_json::json!({
        "type": "user", "sessionId": SESSION,
        "message": { "role": "user", "content": [ { "type": "tool_result", "tool_use_id": "toolu_q",
            "content": "User has answered your questions: \"Which colour?\"=\"Blue\"." } ] },
        "toolUseResult": { "questions": q["questions"], "answers": { "Which colour?": "Blue" } },
    });
    std::fs::OpenOptions::new()
        .append(true)
        .open(&transcript.0)
        .and_then(|mut f| writeln!(f, "{line}"))
        .unwrap_or_else(|e| panic!("APPARATUS: the transcript: {e}"));
    session_says("— answered here: Blue");

    // ---- 4. the race: the terminal claims first ----
    let e4 = serde_json::json!({ "command": "touch e4" });
    let hook = ask("toolu_4", "Bash", &e4);
    // The terminal's rejection has claimed the request (Claude Code's first-claim rule); the
    // Session's approval then reaches the hook, which the harness no longer listens to.
    let (_, said) = drive(&w, &room, SESSION, &["--approve", "toolu_4"]);
    println!("[proof] 4. --approve toolu_4 after the terminal claimed it: {said}");
    let _late = decision(hook);
    transcript.tool_result(
        "toolu_4",
        "The user doesn't want to proceed with this tool use. The tool use was rejected (eg. if it \
         was a file edit, the new_string was NOT written to the file). STOP what you are doing and \
         wait for the user to tell you how to proceed.",
        true,
    );
    let plain = session_says("Bash: touch e4 — answered in the terminal: rejected");
    assert!(
        !plain.contains("Bash: touch e4 — approved here"),
        "PRODUCT: arm 4: only the terminal's rejection took effect; the Session must not also say \
         it was approved here:\n{plain}"
    );
    let (ok, said) = drive(&w, &room, SESSION, &["--approve", "toolu_4"]);
    println!("[proof] 4. a second --approve toolu_4 after the record: {said}");
    assert!(
        !ok && said.contains("already answered at the terminal"),
        "PRODUCT: arm 4: an answer after the harness settled the request must be refused, saying \
         it was answered at the terminal; vox said {said:?}"
    );

    // ---- 5. approved from the Session's own node ----
    let e5 = serde_json::json!({ "command": "touch e5" });
    let hook = ask("toolu_5", "Bash", &e5);
    session_says("Bash: touch e5 — approve or reject?");
    let (ok, out, err) = w.vox(
        AGENT,
        &["room", "session", &room, SESSION, "--approve", "toolu_5"],
        None,
    );
    let said = format!("{out}{err}").trim().to_owned();
    println!("[proof] 5. --approve toolu_5 from {AGENT}, the Session's own node: {said}");
    let d = decision(hook);
    assert!(
        ok && d["behavior"] == "allow",
        "PRODUCT: arm 5: the Session's own node must approve its own Session's request; vox said \
         {said:?}, the hook gave {d}"
    );
    transcript.tool_result("toolu_5", "", false);
    // Once the harness records it, nothing waits any more: on the Session's own node, which
    // answered and reads it as answered here (what the app reads, CL-1), and on the other
    // member's, which reads who answered. `waiting` is what `pending` counts.
    for (reader, reads) in [
        (AGENT, "approved here".to_owned()),
        (PERSON, format!("answered in Vox by {AGENT}: approved")),
    ] {
        let t0 = Instant::now();
        let (still, request) = loop {
            let (_, out, _) = w.vox(reader, &["room", "session", &room, SESSION, "--json"], None);
            let lines: Vec<serde_json::Value> = out
                .lines()
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            let still = lines.iter().filter(|l| l["waiting"] == true).count();
            let request = lines
                .iter()
                .find(|l| l["ref"] == "toolu_5" && l["kind"] == "approval")
                .map(|l| l["line"].as_str().unwrap_or_default().to_owned());
            let settled = request.as_deref().is_some_and(|r| r.ends_with(&reads));
            if (still == 0 && settled) || t0.elapsed() > Duration::from_secs(60) {
                break (still, request);
            }
            std::thread::sleep(Duration::from_millis(300));
        };
        println!("[proof] 5. {reader} reads: {request:?}, {still} request(s) waiting");
        assert!(
            still == 0 && request.as_deref().is_some_and(|r| r.ends_with(&reads)),
            "PRODUCT: arm 5: once the harness records the approval, {reader} must read the request \
             as {reads:?} and none waiting (pending 0); it read {request:?} with {still} waiting"
        );
    }
    session_says(&format!(
        "Bash: touch e5 — answered in Vox by {AGENT}: approved"
    ));
    // ---- 6. a file sent in from the Session's own node ----
    // This world's stand-in runs in no tmux, so the session itself is not told; what is proved is
    // that the file lands whole on the node and the Session says where.
    let sent = w.root.join("from-its-own-node.txt");
    std::fs::write(&sent, "bytes from the session's own node\n")
        .unwrap_or_else(|e| panic!("APPARATUS: cannot write the file to send: {e}"));
    let (ok, out, err) = w.vox(
        AGENT,
        &[
            "room",
            "session",
            &room,
            SESSION,
            "--file",
            &sent.to_string_lossy(),
        ],
        None,
    );
    let said = format!("{out}{err}").trim().to_owned();
    println!("[proof] 6. --file from {AGENT}, the Session's own node: {said}");
    assert!(
        ok,
        "PRODUCT: arm 6: the Session's own node must be able to send its Session a file; vox said \
         {said:?}"
    );
    let plain =
        session_says("from-its-own-node.txt (34 bytes) — accepted, pulling 34 bytes ✗ landed at ");
    let landed = plain
        .split("landed at ")
        .nth(1)
        .and_then(|r| r.split(", but").next())
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    let got = std::fs::read(&landed).unwrap_or_default();
    println!(
        "[proof] 6. landed at {}: {} bytes",
        landed.display(),
        got.len()
    );
    assert!(
        got == b"bytes from the session's own node\n",
        "PRODUCT: arm 6: the file sent from the Session's own node must land whole where the \
         Session says ({}); read {} bytes",
        landed.display(),
        got.len()
    );

    // ---- 7. another node on the same daemon, through the own-node path ----
    let e7 = serde_json::json!({ "command": "touch e7" });
    let mut hook = ask("toolu_7", "Bash", &e7);
    session_says("Bash: touch e7 — approve or reject?");
    let link = w.staged(PERSON, &["room", "link", &room], None);
    let room_id = link
        .trim()
        .strip_prefix("vox://")
        .and_then(|r| r.split('?').next())
        .and_then(|id| vox_core::node::link::b32_decode(id, "room").ok())
        .unwrap_or_else(|| panic!("APPARATUS (staging): no room id in `vox room link`: {link:?}"));
    let socket = w.data.join(".daemon").join("vox.sock");
    let at = vox_core::node::ipc::NodeSocket::one_shot(
        socket,
        vox_core::node::paths::NodeName::parse(PERSON).expect("APPARATUS: a node name"),
    );
    let forged = vox_core::node::drive_input::OwnDrive {
        room: room_id,
        request: vox_agentcomms::drive::Request {
            v: 1,
            session: SESSION.to_owned(),
            action: vox_agentcomms::drive::Action::Approve {
                r#ref: "toolu_7".to_owned(),
            },
        },
    }
    .to_bytes()
    .expect("APPARATUS: the forged request");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: a runtime");
    let answer = rt.block_on(async {
        let (mut stream, me) = vox_core::node::ipc::open_as(&at)
            .await
            .unwrap_or_else(|e| panic!("APPARATUS: {PERSON}'s connection to the daemon: {e}"));
        vox_core::node::ipc::write_frame(&mut stream, &forged)
            .await
            .unwrap_or_else(|e| panic!("APPARATUS: writing the forged request: {e}"));
        let body = tokio::time::timeout(
            Duration::from_secs(30),
            vox_core::node::ipc::read_frame(&mut stream),
        )
        .await;
        (me, body)
    });
    let (me, body) = answer;
    let said = match &body {
        Ok(Ok(Some(b))) => vox_core::node::drive_input::parse_own_answer(b)
            .map_or_else(|| format!("{b:?}"), |a| format!("ok={} {}", a.ok, a.said)),
        other => format!("{other:?}"),
    };
    println!(
        "[proof] 7. {PERSON} (connection attached as {:?}) asks the own-node path to approve \
         {AGENT}'s request: {said}",
        me.map(|m| vox_core::node::link::b32_encode(&m)[..12].to_owned())
    );
    let t0 = Instant::now();
    let mut answered = None;
    while t0.elapsed() < Duration::from_secs(3) {
        if let Ok(Some(status)) = hook.try_wait() {
            answered = Some(status);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        answered.is_none() && !said.starts_with("ok=true"),
        "PRODUCT: arm 7: another node on the same daemon must not drive {AGENT}'s Session through \
         the own-node path; the daemon answered {said:?}, and the hook {}",
        if answered.is_some() {
            "gave an answer"
        } else {
            "still waits"
        }
    );
    // Released as its operator would: the Session's own node rejects it.
    let (ok, out, err) = w.vox(
        AGENT,
        &["room", "session", &room, SESSION, "--reject", "toolu_7"],
        None,
    );
    let d = decision(hook);
    assert!(
        ok && d["behavior"] == "deny",
        "PRODUCT: arm 7: the Session's own node must still answer the request; vox said \
         {out}{err}, the hook gave {d}"
    );

    // ---- 8. renamed mid-session: the Session takes the name before any message ----
    let renamed = "renamed mid-session";
    std::fs::OpenOptions::new()
        .append(true)
        .open(&transcript.0)
        .and_then(|mut f| {
            writeln!(
                f,
                "{}",
                serde_json::json!({ "type": "custom-title", "customTitle": renamed, "sessionId": SESSION })
            )
        })
        .unwrap_or_else(|e| panic!("APPARATUS: the transcript: {e}"));
    w.hook_done(
        &room,
        &ev(
            "Stop",
            serde_json::json!({ "stop_hook_active": false, "last_assistant_message": "" }),
        ),
    );
    let t0 = Instant::now();
    let listed = loop {
        let (_, out, _) = w.vox(PERSON, &["room", "sessions", &room, "--json"], None);
        // One JSON object per line, one line per Session.
        let named = out
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .find(|s| s["id"] == SESSION)
            .and_then(|s| s["name"].as_str().map(str::to_owned));
        if named.as_deref() == Some(renamed) || t0.elapsed() > Duration::from_secs(30) {
            break (named, out);
        }
        std::thread::sleep(Duration::from_millis(300));
    };
    println!(
        "[proof] 8. after a rename and a hook event, the Session is named {:?}",
        listed.0
    );
    assert!(
        listed.0.as_deref() == Some(renamed),
        "PRODUCT: arm 8: a session renamed mid-session must show its new name ({renamed:?}) in \
         `vox room sessions` without posting a message; it lists {:?}:\n{}",
        listed.0,
        listed.1
    );
}

const S9: &str = "99999999-2222-4000-8000-000000000009";
/// A second person's node, which keeps drive while `person` loses it.
const KEEPER: &str = "keeper";

/// `node`'s `can_drive` for `session` in `room`, as `vox room sessions --json` says it; `None`
/// while the Session is not listed open.
fn can_drive(w: &World, node: &str, room: &str, session: &str) -> Option<bool> {
    let (_, out, _) = w.vox(node, &["room", "sessions", room, "--json"], None);
    out.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v["id"] == session && v["open"] == true)
        .and_then(|v| v["can_drive"].as_bool())
}

/// Wait up to `limit` for `node`'s `can_drive` on `session` to be `want`; what it last was.
fn can_drive_becomes(
    w: &World,
    node: &str,
    room: &str,
    session: &str,
    want: bool,
    limit: Duration,
) -> Option<bool> {
    let t0 = Instant::now();
    loop {
        let now = can_drive(w, node, room, session);
        if now == Some(want) || t0.elapsed() >= limit {
            return now;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// ADR-029 SC-2a, SC-2b; ADR-028 K-14 (#662) — **drive is held as soon as it is given, on a
/// Session that has written nothing yet, and it is gone as soon as it is taken back, from that
/// member alone.**
///
/// 1. The world above: `claude-a` trusts `person` with drive. Session S9 does one turn in the
///    room, then is moved with `vox agent room` to a second room, where its Session opens and
///    writes nothing (as a session Vox moves when the person picks its room). A third node,
///    `keeper`, is in the second room, and `claude-a` trusts it with drive too.
/// 2. Within 10 s, with no entry in the second room, `vox room sessions --json` says
///    `"can_drive":true` for S9 to `person` and to `keeper`: `claude-a` made its drive key there
///    and released it.
/// 3. `claude-a`'s operator takes drive back from `person`, `vox trust read person`, typed at a
///    terminal. Within 10 s, with no entry since, `person` reads `"can_drive":false`; `keeper`,
///    asked every 0.3 s from before the change until 5 s after `person` lost it, reads `true`
///    every time. What `claude-a` and `keeper`, which both read under the new key, show of both
///    rooms and of S9 (`vox room list`, `vox room read`, `vox room sessions --json`, `vox room
///    session --details`) is exactly what each showed before: the entry that says the key
///    changed is in no row, Session, message or list.
/// 4. S9 then calls a tool: `keeper` reads that call; `person` does not.
///
/// **Which side a red is on.** What `vox room sessions` or `vox room session` printed is
/// `PRODUCT:`; staging the product refused is `APPARATUS (staging):`.
///
/// **Mutations that must turn it red:** the drive key not begun until the Session's first entry
/// (arm 2); no entry under the new key when drive is taken back (arm 3, `person`); the new key not
/// released to a member that keeps drive (arm 3, `keeper`); the key change posted as a room
/// message rather than an entry no Session has (arm 3, "showed in a room or a Session").
#[test]
#[ignore = "real binary; run in release"]
fn drive_given_on_an_idle_session_is_held_at_once_and_taken_back_at_once() {
    watchdog::arm_for(Duration::from_secs(600));
    let (w, _daemon, room) = World::setup();

    // ---- (1) S9 works in the room, then is moved to a second room, where it writes nothing ----
    w.hook_done(&room, &prompt(&w, S9));
    session_listed(&w, &room, S9);
    w.staged(
        PERSON,
        &[
            "room",
            "create",
            "--passphrase-file",
            "-",
            "--name",
            "second",
        ],
        Some("second passphrase\n"),
    );
    let list = w.staged(PERSON, &["room", "list"], None);
    let second = list
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some("second"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| {
            panic!("APPARATUS (staging): `vox room list` shows no room `second`: {list}")
        })
        .to_owned();
    let link = w
        .staged(PERSON, &["room", "link", &second], None)
        .lines()
        .find(|l| l.starts_with("vox://"))
        .unwrap_or_else(|| panic!("APPARATUS (staging): `vox room link` printed no link"))
        .to_owned();
    w.staged(KEEPER, &["node", "create", KEEPER], None);
    w.staged(KEEPER, &["node", "attach", KEEPER], None);
    for node in [AGENT, KEEPER] {
        w.staged(
            node,
            &["room", "join", "--passphrase-file", "-", &link],
            Some("second passphrase\n"),
        );
    }
    let agent_fp = w.staged(AGENT, &["id"], None).trim().to_owned();
    let keeper_fp = w.staged(KEEPER, &["id"], None).trim().to_owned();
    w.staged(KEEPER, &["trust", "add", &agent_fp, "--name", AGENT], None);
    w.staged(
        AGENT,
        &["trust", "add", &keeper_fp, "--name", KEEPER, "--drive"],
        None,
    );
    w.staged(AGENT, &["agent", "room", &second, "--session", S9], None);
    session_listed(&w, &second, S9);
    println!("[proof] (1) S9 moved to room {second}, where it has written nothing");

    // ---- (2) drive held at once, with no entry ----
    for node in [PERSON, KEEPER] {
        let held = can_drive_becomes(&w, node, &second, S9, true, Duration::from_secs(10));
        println!("[proof] (2) {node}'s can_drive on the idle Session: {held:?}");
        assert_eq!(
            held,
            Some(true),
            "PRODUCT: {AGENT} trusts {node} with drive and S9's Session is open in room \
             {second}, yet within 10 s `vox room sessions --json` did not say \"can_drive\":true \
             for it (it said {held:?}): the drive key waits for the Session's first entry"
        );
    }

    // ---- (3) drive taken back from person, at a terminal: gone at once, for person alone ----
    // What a node shows of its rooms and Sessions, before: the key change must add nothing.
    let shown = |node: &str| -> String {
        let mut all = w.staged(node, &["room", "list"], None);
        for r in [&room, &second] {
            let (_, read, _) = w.vox(node, &["room", "read", r], None);
            let (_, listed, _) = w.vox(node, &["room", "sessions", r, "--json"], None);
            let (_, view, _) = w.vox(node, &["room", "session", r, S9, "--details"], None);
            all += &format!("{read}{listed}{view}");
        }
        all
    };
    let (own_before, keeper_before) = (shown(AGENT), shown(KEEPER));
    let person_fp = w.staged(PERSON, &["id"], None).trim().to_owned();
    w.staged(AGENT, &["trust", "read", &person_fp], None);
    let t0 = Instant::now();
    let mut lost_at = None;
    let mut keeper_seen = Vec::new();
    while lost_at.map_or(t0.elapsed() < Duration::from_secs(10), |at: Instant| {
        at.elapsed() < Duration::from_secs(5)
    }) {
        keeper_seen.push(can_drive(&w, KEEPER, &second, S9));
        if lost_at.is_none() && can_drive(&w, PERSON, &second, S9) == Some(false) {
            lost_at = Some(Instant::now());
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    let after = can_drive(&w, PERSON, &second, S9);
    println!(
        "[proof] (3) after `vox trust read`, person's can_drive: {after:?}; keeper's, asked {} \
         times: {keeper_seen:?}",
        keeper_seen.len()
    );
    assert!(
        lost_at.is_some() && after == Some(false),
        "PRODUCT: {AGENT} took drive back from {PERSON} (`vox trust read`), yet within 10 s \
         `vox room sessions --json` still did not say \"can_drive\":false for S9 in room \
         {second} (it said {after:?})"
    );
    assert!(
        keeper_seen.iter().all(|k| *k == Some(true)),
        "PRODUCT: {KEEPER} keeps drive from {AGENT}, yet while {PERSON} lost it, its \
         `vox room sessions --json` said, asked every 0.3 s: {keeper_seen:?}"
    );
    // The entry that says the key changed is no Session's, nor a message: the nodes that read
    // under the new key show their rooms and Sessions exactly as before.
    let (own_after, keeper_after) = (shown(AGENT), shown(KEEPER));
    let person_after = shown(PERSON);
    assert!(
        own_after == own_before
            && keeper_after == keeper_before
            && !format!("{own_after}{keeper_after}{person_after}").contains("drive-key"),
        "PRODUCT: the key change showed in a room or a Session: {AGENT}'s node showed before\n\
         {own_before}\nand after\n{own_after}\n{KEEPER}'s showed before\n{keeper_before}\nand \
         after\n{keeper_after}"
    );

    // ---- (4) what S9 does next: keeper reads it, person does not ----
    let call =
        serde_json::json!({ "command": "echo after-drive-was-taken", "description": "Echo" });
    w.hook_done(
        &second,
        &event(
            &w,
            S9,
            "PreToolUse",
            serde_json::json!({ "tool_name": "Bash", "tool_input": call, "tool_use_id": "toolu_9" }),
        ),
    );
    let mut kept = String::new();
    let t0 = Instant::now();
    while !kept.contains("after-drive-was-taken") && t0.elapsed() < Duration::from_secs(15) {
        kept = w.vox(KEEPER, &["room", "session", &second, S9], None).1;
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(
        kept.contains("after-drive-was-taken"),
        "PRODUCT: {KEEPER} keeps drive from {AGENT}, yet within 15 s it did not read the call S9 \
         made after {PERSON} lost drive: {kept}"
    );
    let (ok, seen) = drive(&w, &second, S9, &[]);
    println!("[proof] (4) person's view of S9 after the call (ok {ok}):\n{seen}");
    assert!(
        ok && seen.contains(" · open") && !seen.contains("after-drive-was-taken"),
        "PRODUCT: {PERSON} no longer has drive from {AGENT}, yet reads the call S9 made after it \
         was taken back:\n{seen}"
    );
}
