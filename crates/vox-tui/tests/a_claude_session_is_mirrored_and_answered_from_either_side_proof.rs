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
//! `PRODUCT (staging):` with what it said; a fixture this proof could not make is `APPARATUS:`.
//!
//! **Mutations that must turn it red:** the turn's end not mirrored (`Stop` gives no `turn-end`)
//! → no "— turn ended —" line (#540); a request retired by its waiting hook's release rather than
//! by the transcript → no "answered in the terminal" (#545).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

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
            "PRODUCT (staging): `vox {}` as {node} failed: {out}{err}",
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

/// The fields every Claude Code hook input carries.
fn base(event: &str, work: &Path, transcript: &Path) -> serde_json::Value {
    serde_json::json!({
        "session_id": SESSION,
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

#[test]
#[ignore = "real binary; run in release"]
fn a_claude_sessions_activity_reaches_its_session_and_the_terminal_answer_is_said() {
    watchdog::arm_for(Duration::from_secs(600));
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
    let work = w.root.join("work");
    let transcript = Transcript(work.join(format!("{SESSION}.jsonl")));
    std::fs::write(&transcript.0, "")
        .unwrap_or_else(|e| panic!("APPARATUS: cannot make the transcript: {e}"));

    // ---- (1) two nodes in one daemon, one room, trust with drive ----
    for node in [PERSON, AGENT] {
        w.staged(node, &["node", "create", node], None);
    }
    let (ok, out, err) = w.vox(PERSON, &["node", "attach", PERSON], None);
    let _daemon = Daemon(w.data.clone());
    assert!(
        ok,
        "PRODUCT (staging): `vox node attach {PERSON}` failed: {out}{err}"
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
        .unwrap_or_else(|| panic!("PRODUCT (staging): `vox room list` shows no room: {list:?}"))
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
