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
        std::fs::create_dir_all("/private/tmp/vc")
            .unwrap_or_else(|e| panic!("APPARATUS: cannot make /private/tmp/vc: {e}"));
        let tmp = tempfile::Builder::new()
            .prefix("cs-")
            .tempdir_in("/private/tmp/vc")
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
        s
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
/// 12. a hook started inside a pane by a process other than the harness (a tool the session ran,
///     a test beneath a person's pane): the pane is not proven, and nothing is typed into it.
///
/// **Which side a red is on.** What `vox room session` printed, or what a stand-in got or did not
/// get, is `PRODUCT:`. A tmux server, stand-in or event this proof could not stage is
/// `APPARATUS:`.
///
/// **Mutations, one per check that can fail on its own:** the injector types into the first pane
/// of the server (arm 1); the session's process must be the hook's own parent (arm 3); the
/// pane is recorded by its position, not its id (arm 4); one session per pane ignores the server
/// (arm 5); the hook's ancestry not required to reach the pane (arm 6); the session's process not
/// checked at the send (arm 7); one session per pane not kept (arm 8); a later hook not rebinding
/// (arm 9); a tool hook not registering (arm 10); the hook's parent not required to be the
/// harness (arm 12).
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
    let exe = Command::new("/usr/sbin/lsof")
        .args(["-a", "-p", &a.pid().to_string(), "-d", "txt", "-Fn"])
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .find_map(|l| l.strip_prefix('n').map(str::to_owned))
        })
        .unwrap_or_else(|| panic!("APPARATUS: the stand-in's executable is not known to lsof"));
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
///
/// **Mutation that must turn it red** (#545's own): the request closed when the Session's answer
/// is sent → arm 4 reads "approved here".
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
    let (ok, said) = drive(&w, &room, SESSION, &["--approve", "toolu_2"]);
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
    let (ok, said) = drive(
        &w,
        &room,
        SESSION,
        &["--answer", "toolu_q", "Which colour?=Blue"],
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
}
