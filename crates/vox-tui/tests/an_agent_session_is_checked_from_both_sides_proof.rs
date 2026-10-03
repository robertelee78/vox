//! V030-16 — **a person checks that an agent session is wired up**, from this side with
//! `vox agent doctor` and from the other side with `vox room ping`.
//!
//! A new journey, so a new file: the wiring a person installs once (Claude Code's hook entries,
//! a Codex hook and its trust, the OpenCode plugin), the session that registers through it, and
//! a member on another node asking that node which sessions it holds. None of the existing
//! proofs stages a harness's settings at all.
//!
//! Two `vox daemon`s, alice and bob, in one room through an anchor (`support::room`). Bob's
//! harness wiring is installed in a home of its own **from vox's own output**, as a person
//! follows it: `vox agent plugin claude` into `settings.json`, `vox agent plugin opencode`
//! into the plugin directory, `vox agent plugin codex` into `hooks.json` and then
//! `vox agent trust codex` against the installed Codex (its app-server only: no model turn).
//! Bob's session registers through the drain hook as Claude Code runs it, at a stand-in
//! messaging socket.
//!
//! **Asserted:**
//!
//! 1. on that wiring the doctor reports every check `ok` and exits 0;
//! 2. each check, broken alone, names its own fix: an unknown room; the Claude hook twice,
//!    and missing; Codex's trust of its hook withdrawn; the OpenCode plugin edited; the drain's cursor directory unwritable; the session's wake endpoint gone; bob
//!    not trusting alice; alice announcing another vox version; bob's node stopped (exit 1 on
//!    every `fail`);
//! 3. alice's `vox room ping <room> bob` is answered by bob's **daemon**: from bob's node,
//!    naming `session-bob`, that an urgent message interrupts it, and when it last read;
//! 4. pings and pongs never wake anyone: bob's session socket receives no message from a
//!    ping, even one marked urgent by hand;
//! 5. no drain shows a ping or a pong, on either node, though each read past them;
//! 6. a ping to a stopped node ends in a named timeout that says what it cannot tell apart,
//!    exit 1.
//!
//! **Every red names its side**: `PRODUCT:` quoting what vox printed; `APPARATUS:` where the
//! staging did not happen (a breakage that did not take, a missing Codex); `CANNOT MEASURE:`
//! where the claim was not reached.
//!
//! **Mutation-checked:** the OpenCode plugin check inverted (an edited plugin is `ok`) goes red
//! at (1); the drain showing plumbing goes red at (5); a ping routed to the wake judge with
//! the plumbing guard removed from `may_interrupt` goes red at (4).

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use support::{until, Out, Worker};

/// Bob's harness home: where Claude Code, Codex and OpenCode keep what a person installs.
struct Home {
    root: PathBuf,
}

impl Home {
    fn claude(&self) -> PathBuf {
        self.root.join(".claude").join("settings.json")
    }
    fn codex(&self) -> PathBuf {
        self.root.join(".codex")
    }
    fn plugin(&self) -> PathBuf {
        self.root.join(".config/opencode/plugin/vox.js")
    }
    /// Every variable the three harnesses read their homes from, pointed here.
    fn env(&self) -> Vec<(&'static str, String)> {
        let s = |p: PathBuf| p.to_string_lossy().into_owned();
        vec![
            ("HOME", s(self.root.clone())),
            ("CLAUDE_CONFIG_DIR", s(self.root.join(".claude"))),
            ("CODEX_HOME", s(self.codex())),
            ("XDG_CONFIG_HOME", s(self.root.join(".config"))),
            ("OPENCODE_CONFIG_DIR", s(self.root.join(".config/opencode"))),
        ]
    }
}

/// `vox …` as bob, inside his harness home.
fn bob_vox(bob: &Worker, home: &Home, args: &[&str], stdin: Option<&str>) -> Out {
    let env = home.env();
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    bob.vox_env(None, &env, args, stdin)
}

/// `vox agent doctor --json` for bob's room, and its report.
fn doctor(bob: &Worker, home: &Home, room: &str) -> (Out, serde_json::Value) {
    let o = bob_vox(
        bob,
        home,
        &["agent", "doctor", "--room", room, "--json"],
        None,
    );
    let v = o.json();
    (o, v)
}

/// The check whose id starts with `id`, or a PRODUCT red: the doctor did not report it.
fn check<'a>(report: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    report["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|c| c["check"].as_str().is_some_and(|c| c.starts_with(id)))
        .unwrap_or_else(|| panic!("PRODUCT: the doctor reported no `{id}` check: {report}"))
}

/// Assert the doctor reports `id` as `status` with a fix containing `fix`, and that it exits
/// non-zero exactly when something failed.
#[track_caller]
fn expect(case: &str, o: &Out, report: &serde_json::Value, id: &str, status: &str, fix: &str) {
    let c = check(report, id);
    println!(
        "[proof] {case}: {id} -> {} / fix: {}",
        c["status"], c["fix"]
    );
    assert_eq!(
        c["status"], status,
        "PRODUCT: {case}: the doctor must report `{id}` as {status}: {c}"
    );
    assert!(
        c["fix"].as_str().is_some_and(|f| f.contains(fix)),
        "PRODUCT: {case}: the `{id}` fix must say {fix:?}: {c}"
    );
    let failed = report["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|c| c["status"] == "fail");
    assert_eq!(
        o.ok, !failed,
        "PRODUCT: {case}: the doctor must exit non-zero exactly when a check fails (exit {:?}): \
         {report}",
        o.code
    );
}

/// A stand-in Claude Code messaging socket: every connection's bytes, once it closes.
fn listen(path: &Path) -> mpsc::Receiver<String> {
    let listener = UnixListener::bind(path)
        .unwrap_or_else(|e| panic!("APPARATUS: bind the stand-in session socket: {e}"));
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = String::new();
            let _ = stream.read_to_string(&mut buf);
            if tx.send(buf).is_err() {
                return;
            }
        }
    });
    rx
}

/// Every message (non-empty connection) bob's session socket has received so far, after
/// `settle`. A probe connects and closes without a byte; a wake writes frames.
fn messages(inbox: &mpsc::Receiver<String>, settle: Duration) -> Vec<String> {
    std::thread::sleep(settle);
    inbox.try_iter().filter(|m| !m.is_empty()).collect()
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap())
        .unwrap_or_else(|e| panic!("APPARATUS: make {}: {e}", path.parent().unwrap().display()));
    std::fs::write(path, text)
        .unwrap_or_else(|e| panic!("APPARATUS: write {}: {e}", path.display()));
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("APPARATUS: read {}: {e}", path.display()))
}

#[test]
#[ignore = "an anchor and two vox daemons with production Argon2id; CI runs it in release"]
fn an_agent_session_is_checked_from_both_sides() {
    watchdog::arm();
    assert!(
        std::process::Command::new("codex")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success()),
        "APPARATUS: this proof needs `codex` on PATH to stage Codex's hook trust; an absent \
         Codex is not a pass"
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let r = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let room = r.id.clone();
    let home = Home {
        root: tmp.path().join("bobhome"),
    };

    // ---- bob's wiring, installed from vox's own output ----
    let (alice, bob) = (&r.workers[0], &r.workers[1]);
    let claude = bob_vox(bob, &home, &["agent", "plugin", "claude"], None);
    claude.expect_ok("`vox agent plugin claude`");
    write(&home.claude(), &claude.stdout);
    let plugin = bob_vox(bob, &home, &["agent", "plugin", "opencode"], None);
    plugin.expect_ok("`vox agent plugin opencode`");
    write(&home.plugin(), &plugin.stdout);
    let codex = bob_vox(bob, &home, &["agent", "plugin", "codex"], None);
    codex.expect_ok("`vox agent plugin codex`");
    write(&home.codex().join("hooks.json"), &codex.stdout);
    bob_vox(bob, &home, &["agent", "trust", "codex"], None).expect_ok("`vox agent trust codex`");

    // ---- bob's session registers, as Claude Code's hook runs it ----
    let sock = tmp.path().join("s.sock");
    let inbox = listen(&sock);
    let sock_s = sock.to_string_lossy().into_owned();
    let hook_input = r#"{"session_id":"session-bob","hook_event_name":"UserPromptSubmit","cwd":"/tmp","prompt":"hi"}"#;
    let session_env = [
        ("CLAUDE_CODE_MESSAGING_SOCKET", sock_s.as_str()),
        ("CLAUDE_CODE_MESSAGING_TOKEN", "a-token"),
    ];
    bob.vox_env(
        None,
        &session_env,
        &["agent", "hook", "--room", &room],
        Some(hook_input),
    )
    .expect_ok("bob's session's first drain");

    // ---- (1) the healthy baseline ----
    let (o, report) = doctor(bob, &home, &room);
    let not_ok: Vec<&serde_json::Value> = report["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["status"] != "ok")
        .collect();
    println!(
        "[proof] (1) wired as vox says: {} check(s) not ok",
        not_ok.len()
    );
    assert!(
        not_ok.is_empty() && o.ok,
        "PRODUCT (1): on wiring installed from vox's own output, every check must be ok and \
         the doctor exit 0 (exit {:?}); not ok: {not_ok:?}",
        o.code
    );
    let session = check(&report, "session session-bob");
    let detail = session["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("first seen")
            && detail.contains("last drained")
            && !detail.contains("not recorded")
            && detail.contains("its wake endpoint answers"),
        "PRODUCT (1): bob's session record must say when it was first seen and last drained, \
         and that its wake endpoint answers: {session}"
    );
    assert!(
        check(&report, "trust ")["detail"]
            .as_str()
            .is_some_and(|d| d.contains("each other")),
        "PRODUCT (1): alice and bob trust each other: {report}"
    );

    // ---- (3), (4) alice pings bob: his daemon answers, nobody is woken ----
    let ping = alice.vox(
        None,
        &["room", "ping", &room, "bob", "--json", "--wait", "120"],
    );
    ping.expect_ok("alice's `vox room ping <room> bob`");
    let answer = ping.json();
    println!("[proof] (3) ping answer: {answer}");
    assert_eq!(
        answer["node"].as_str(),
        Some(bob.b32().as_str()),
        "PRODUCT (3): the answer must come from bob's node: {}",
        ping.stdout
    );
    let s = &answer["sessions"][0];
    assert!(
        s["session"] == "session-bob"
            && s["reach"] == "interrupt"
            && s["last_read_ms"].as_u64().is_some_and(|t| t > 0),
        "PRODUCT (3): the answer must name session-bob, that an urgent message interrupts it, \
         and when it last read: {s}"
    );
    // A ping marked urgent by hand is still the daemons' business.
    alice
        .vox_in(
            None,
            &["room", "post", &room, "-"],
            Some(&format!(
                r#"{{"v":1,"type":"ping","to":["{}"],"urgent":true,"body":"URGENT-PING"}}"#,
                bob.b32()
            )),
        )
        .expect_ok("alice's hand-made urgent ping");
    until(
        alice,
        None,
        "bob's daemon to answer the urgent ping",
        &["room", "read", &room, "--json"],
        |o| {
            o.ndjson()
                .iter()
                .filter(|r| r["envelope"]["type"] == "pong")
                .count()
                >= 2
        },
    );
    let woke = messages(&inbox, Duration::from_secs(6));
    println!(
        "[proof] (4) messages to bob's session from two pings: {}",
        woke.len()
    );
    assert!(
        woke.is_empty(),
        "PRODUCT (4): a ping must never wake a session; bob's session received {woke:?}"
    );

    // ---- (5) no drain shows a ping or a pong ----
    alice
        .vox_in(None, &["room", "post", &room, "-"], Some("AFTER-THE-PINGS"))
        .expect_ok("alice's marker after the pings");
    until(
        bob,
        None,
        "alice's marker to reach bob",
        &["room", "read", &room],
        |o| o.stdout.contains("AFTER-THE-PINGS"),
    );
    for (who, w, env) in [
        ("bob's session", bob, &session_env[..]),
        ("a fresh session of alice's", alice, &[][..]),
    ] {
        let session_id = if w.name == "bob" {
            "session-bob"
        } else {
            "alice-fresh"
        };
        let input = format!(r#"{{"session_id":"{session_id}","cwd":"/tmp"}}"#);
        let drained = w.vox_env(
            None,
            env,
            &["agent", "hook", "--room", &room, "--format", "text"],
            Some(&input),
        );
        drained.expect_ok(&format!("{who}'s drain"));
        assert!(
            drained.stdout.contains("AFTER-THE-PINGS"),
            "CANNOT MEASURE (5): {who}'s drain must read past the pings to the marker: {}",
            drained.stdout
        );
        for plumbing in [
            "which agent sessions does this node hold",
            "agent session on this node",
            "URGENT-PING",
        ] {
            assert!(
                !drained.stdout.contains(plumbing),
                "PRODUCT (5): {who}'s drain showed a ping or a pong ({plumbing:?}): {}",
                drained.stdout
            );
        }
    }
    println!("[proof] (5) neither drain showed a ping or a pong");

    // ---- (2) each check, broken alone ----
    let (o, v) = doctor(bob, &home, "zzzzzzzz");
    expect("an unknown room", &o, &v, "room", "fail", "--room");

    let wired = read(&home.claude());
    let mut twice: serde_json::Value = serde_json::from_str(&wired).unwrap();
    let entry = twice["hooks"]["UserPromptSubmit"][0].clone();
    twice["hooks"]["UserPromptSubmit"]
        .as_array_mut()
        .expect("APPARATUS: vox's claude snippet has a UserPromptSubmit list")
        .push(entry);
    write(&home.claude(), &twice.to_string());
    let (o, v) = doctor(bob, &home, &room);
    expect(
        "the Claude hook twice",
        &o,
        &v,
        "claude-hook UserPromptSubmit",
        "fail",
        "keep one",
    );
    write(&home.claude(), "{}");
    let (o, v) = doctor(bob, &home, &room);
    expect(
        "the Claude hook missing",
        &o,
        &v,
        "claude-hook UserPromptSubmit",
        "warn",
        "vox agent plugin claude",
    );
    write(&home.claude(), &wired);

    // Codex's trust, as Codex wrote it, withdrawn: its `config.toml` without the hook's state.
    let config_file = home.codex().join("config.toml");
    let config = read(&config_file);
    assert!(
        config.contains("trusted_hash"),
        "APPARATUS: `vox agent trust codex` left no trusted_hash in {}: {config}",
        config_file.display()
    );
    let untrusted: String = config
        .lines()
        .filter(|l| !l.contains("hooks.state") && !l.trim_start().starts_with("trusted_hash"))
        .map(|l| format!("{l}\n"))
        .collect();
    write(&config_file, &untrusted);
    let (o, v) = doctor(bob, &home, &room);
    expect(
        "Codex's trust of its hook withdrawn",
        &o,
        &v,
        "codex-hook",
        "fail",
        "vox agent trust codex",
    );
    write(&config_file, &config);

    let js = read(&home.plugin());
    write(&home.plugin(), &format!("{js}\n// edited by hand\n"));
    let (o, v) = doctor(bob, &home, &room);
    expect(
        "the OpenCode plugin edited",
        &o,
        &v,
        "opencode-plugin",
        "fail",
        "vox agent plugin opencode >",
    );
    write(&home.plugin(), &js);

    let cursors = bob.paths.cursor_dir();
    std::fs::set_permissions(&cursors, std::fs::Permissions::from_mode(0o500))
        .unwrap_or_else(|e| panic!("APPARATUS: chmod {}: {e}", cursors.display()));
    let probe = cursors.join("apparatus-probe");
    if std::fs::write(&probe, b"").is_ok() {
        let _ = std::fs::remove_file(&probe);
        panic!(
            "APPARATUS: staging not achieved: {} is still writable at mode 0500 (running as \
             root?)",
            cursors.display()
        );
    }
    let (o, v) = doctor(bob, &home, &room);
    std::fs::set_permissions(&cursors, std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|e| panic!("APPARATUS: chmod {} back: {e}", cursors.display()));
    expect(
        "the cursor directory unwritable",
        &o,
        &v,
        "drain",
        "fail",
        "writable",
    );

    std::fs::remove_file(&sock)
        .unwrap_or_else(|e| panic!("APPARATUS: remove the session socket: {e}"));
    let (o, v) = doctor(bob, &home, &room);
    expect(
        "bob's session's wake endpoint gone",
        &o,
        &v,
        "session session-bob",
        "warn",
        "registers again",
    );

    // Before trust is withdrawn: once bob no longer trusts alice, his node reads nothing of hers.
    alice
        .vox_in(
            None,
            &["room", "post", &room, "-"],
            Some(
                r#"{"v":1,"type":"hello","from":"old-alice","body":"OLD-VERSION-HELLO","data":{"vox":"0.0.1"}}"#,
            ),
        )
        .expect_ok("alice's hello from an older vox");
    until(
        bob,
        None,
        "alice's old-version hello to reach bob",
        &["room", "read", &room],
        |o| o.stdout.contains("OLD-VERSION-HELLO"),
    );
    let (o, v) = doctor(bob, &home, &room);
    expect(
        "alice on another vox version",
        &o,
        &v,
        "version ",
        "warn",
        "same vox",
    );

    bob.vox(
        None,
        &[
            "trust",
            "remove",
            &alice.b32(),
            "--identity-passphrase-file",
            bob.pass.to_str().unwrap(),
        ],
    )
    .expect_ok("bob's `vox trust remove` of alice");
    let (o, v) = doctor(bob, &home, &room);
    expect(
        "bob not trusting alice",
        &o,
        &v,
        "trust ",
        "warn",
        "vox trust add",
    );
    assert!(
        check(&v, "trust ")["detail"]
            .as_str()
            .is_some_and(|d| d.contains("you have not trusted it")),
        "PRODUCT: bob no longer trusts alice, and his doctor must say so: {v}"
    );

    // ---- bob's node stops: the doctor and a ping both say so ----
    let pid = r.workers[1]
        .daemon_pid()
        .expect("APPARATUS: bob's daemon is running");
    let killed = std::process::Command::new("kill")
        .arg(pid.to_string())
        .status()
        .is_ok_and(|s| s.success());
    assert!(killed, "APPARATUS: could not stop bob's daemon (pid {pid})");
    let (alice, bob) = (&r.workers[0], &r.workers[1]);
    let mut stopped = false;
    for _ in 0..40 {
        if !bob.vox(None, &["room", "list"]).ok {
            stopped = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(
        stopped,
        "APPARATUS: bob's daemon still answers 10 s after it was stopped"
    );
    let (o, v) = doctor(bob, &home, &room);
    expect("bob's node stopped", &o, &v, "node", "fail", "vox daemon");

    // ---- (6) a ping to a stopped node: a named timeout ----
    let ping = alice.vox(None, &["room", "ping", &room, "bob", "--wait", "15"]);
    println!(
        "[proof] (6) ping to a stopped node: exit {:?}: {}",
        ping.code,
        ping.stderr.trim()
    );
    assert!(
        ping.code == Some(1)
            && ping.stderr.contains("no answer from bob's node within 15s")
            && ping.stderr.contains("offline")
            && ping.stderr.contains("trust"),
        "PRODUCT (6): a ping nobody answers must end in a named timeout saying what it cannot \
         tell apart, exit 1: {ping:?}"
    );
}
