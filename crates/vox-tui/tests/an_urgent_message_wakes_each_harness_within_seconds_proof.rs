//! PRD-001 R16 (#170) — **an urgent message wakes an idle agent on another node within seconds**,
//! for each harness Vox supports, with no model involved.
//!
//! R16's scope for v0.3.0 (#170, restated from the decider's ruling in `docs/release/v0.3.0.md`
//! §D, Decisions): a Claude Code or OpenCode session is woken within [`WITHIN`] of an urgent message
//! addressed to it landing on another node, by a notice that carries no byte of the message
//! (V030-15). A Codex session is never woken: the decider's "Not doing: waking Codex by starting a
//! headless `codex exec` (Vox never spawns instances)", and v0.3.0 has no Codex wake path. It reads
//! the message at its next turn.
//!
//! **Every participant is the shipped binary** (`support/room.rs`): an anchor (`vox node`),
//! alice's and bob's `vox daemon`, a room both joined. Bob has three sessions, registered the way
//! each harness's hook registers one, by `vox agent hook` in a **cleared** environment:
//! - `cc`, Claude Code: `CLAUDE_CODE_MESSAGING_SOCKET`/`_TOKEN` name a stand-in for Claude Code's
//!   messaging socket, which records what the daemon writes;
//! - `oc`, OpenCode: `VOX_OPENCODE_WAKE_SOCKET`/`_TOKEN` name a stand-in for the Vox OpenCode
//!   plugin's wake socket, which takes each prompt (`{"ok":true}`) and records it;
//! - `cx`, Codex: `VOX_HARNESS=codex` and no wake endpoint, as the Codex hook registers.
//!
//! No `vox` command plays a harness session, so the two sockets are the only stand-ins. A `codex`
//! is put first on the daemons' `PATH` that records any call to it and runs nothing.
//!
//! Over [`ROUNDS`] rounds alice posts, on her own daemon, one urgent message addressed to bob's node
//! (by its whole fingerprint, as `to` names nodes, V210-161), where all three sessions are, each
//! with its own canary. Nothing reaches bob's node but by sync. Each round:
//! 1. **`cc` and `oc` are each woken, within [`WITHIN`] of alice's post returning**, by a notice
//!    naming one urgent message from alice, with the token each registered; the latency of every
//!    wake is printed, so the bound is read against its spread;
//! 2. **no byte of any message reaches either endpoint** (the canaries);
//! 3. then each session's turn drains the room, as its harness would, so the next round's wake is
//!    not held back by V030-15's one-outstanding-notice rule.
//!
//! And over the run:
//! 4. **`cx` is never woken, and nothing is started for it**: the `codex` on the daemons' `PATH` is
//!    never called;
//! 5. **`cx` reads every message at its next turn**: one Codex drain after the last round shows each
//!    canary exactly once;
//! 6. **`vox room tail` shows messages that arrived by sync**: a tail started on bob's node before
//!    the rounds prints each canary exactly once. The TUI half is `tui_addressee_names.py`, where
//!    alice's message reaches bob's own `vox tui` only by sync and is read off its screen
//!    (`an_addressee_is_shown_by_the_readers_own_name_proof`).
//!
//! Every red says PRODUCT, with what the product sent or said, or APPARATUS, naming the staging
//! that was not achieved.
//!
//! **Mutation**, one per claim: a Codex wake that starts `codex exec` (red at 4); the message put
//! back in the notice (red at 2); the daemon waking only on its own appends, never on an entry
//! synced from a peer, as before F15 (red at 1).

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Read as _;
use std::os::unix::net::UnixListener;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use support::{until, Worker};

/// "Within seconds": the most an urgent message may take, from alice's `vox room post` returning
/// on her node to the notice reaching bob's session on his. Bob's daemon sweeps every 2 s, and the
/// message must first sync to his node.
const WITHIN: Duration = Duration::from_secs(5);
/// Rounds of the measurement: enough to show the spread, not one sample.
const ROUNDS: usize = 6;
/// How long to wait for a notice before calling it missing (well past [`WITHIN`], so a late wake
/// is measured and reported, not lost).
const PATIENCE: Duration = Duration::from_secs(30);

/// A stand-in Claude Code messaging socket: each connection's bytes, and when they arrived.
fn claude_socket(path: &std::path::Path) -> mpsc::Receiver<(Instant, String)> {
    let listener =
        UnixListener::bind(path).expect("APPARATUS: bind the stand-in Claude Code socket");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = String::new();
            let _ = stream.read_to_string(&mut buf);
            if tx.send((Instant::now(), buf)).is_err() {
                return;
            }
        }
    });
    rx
}

/// A stand-in for the Vox OpenCode plugin's wake socket. It takes every prompt, as the plugin does
/// when OpenCode accepts it, and records when it arrived, the auth line and the prompt line.
fn opencode_socket(path: &std::path::Path) -> mpsc::Receiver<(Instant, String, String)> {
    use std::io::{BufRead as _, Write as _};
    let listener =
        UnixListener::bind(path).expect("APPARATUS: bind the stand-in OpenCode plugin socket");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let at = Instant::now();
            let mut reader = std::io::BufReader::new(&stream);
            let (mut auth, mut prompt) = (String::new(), String::new());
            if reader.read_line(&mut auth).is_err() || reader.read_line(&mut prompt).is_err() {
                continue;
            }
            let _ = writeln!(&stream, r#"{{"ok":true}}"#);
            if tx.send((at, auth, prompt)).is_err() {
                return;
            }
        }
    });
    rx
}

/// `vox agent hook …` as bob's harness runs it, in a **cleared** environment: `PATH`, `HOME`,
/// bob's profile directories, and exactly the harness variables in `env`. Nothing this test
/// process inherited — a real Claude Code session's messaging socket above all — reaches it.
fn hook(bob: &Worker, env: &[(&str, &str)], args: &[&str], stdin: Option<&str>) -> String {
    use std::io::Write as _;
    let mut cmd = std::process::Command::new(support::VOX);
    cmd.env_clear()
        // A proof's daemon never takes port 1080 (.cargo/config.toml).
        .env("VOX_PROXY", "127.0.0.1:0");
    for key in ["PATH", "HOME", "TMPDIR"] {
        if let Some(v) = std::env::var_os(key) {
            cmd.env(key, v);
        }
    }
    cmd.args(args)
        .env("VOX_DATA_DIR", &bob.data)
        .env("VOX_CONFIG_DIR", &bob.cfg)
        .envs(env.iter().copied())
        .stdin(if stdin.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("APPARATUS: spawn `vox agent hook`");
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("APPARATUS: `vox agent hook`'s stdin")
            .write_all(input.as_bytes())
            .expect("APPARATUS: write the hook input to `vox agent hook`");
    }
    let out = child
        .wait_with_output()
        .expect("APPARATUS: wait for `vox agent hook`");
    eprintln!(
        "[receipt] vox {} -> {:?}; stderr: {}",
        args.join(" "),
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    assert!(
        out.status.success(),
        "PRODUCT: `vox agent hook` must exit 0 whatever happens, so it never breaks a turn; it \
         exited {:?}",
        out.status.code()
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The `(harness, endpoint)` bob's daemon will wake `session` by, as the hook registered it.
fn registered(bob: &Worker, session: &str) -> (String, String) {
    let body = std::fs::read(bob.paths.session_file(session)).unwrap_or_else(|e| {
        panic!("PRODUCT (staging): `vox agent hook` registered no session {session}: {e}")
    });
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_else(|e| {
        panic!("PRODUCT: the session record `vox agent hook` wrote does not parse: {e}")
    });
    (
        v["harness"].as_str().unwrap_or_default().to_owned(),
        v["endpoint"].as_str().unwrap_or_default().to_owned(),
    )
}

/// Alice posts `text` exactly as given on her daemon; when the post returned.
fn post(alice: &Worker, room: &str, text: &str) -> Instant {
    let o = alice.vox_in(None, &["room", "post", room, "-"], Some(text));
    assert!(
        o.ok,
        "PRODUCT (staging): alice's `vox room post` failed: {o:?}"
    );
    Instant::now()
}

/// The user message a stand-in Claude Code frame carries: what the harness would put before the
/// model.
fn claude_notice(frame: &str) -> Option<String> {
    frame
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["type"] == "user")
        .find_map(|v| v["message"]["content"].as_str().map(str::to_owned))
}

/// The prompt text an OpenCode plugin wake carries.
fn opencode_notice(prompt: &str) -> String {
    serde_json::from_str::<serde_json::Value>(prompt.trim())
        .ok()
        .and_then(|v| v["text"].as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Record a failed claim and carry on, so one mutant shows every red.
fn check(failures: &mut Vec<String>, ok: bool, what: String) {
    if !ok {
        eprintln!("[red] {what}");
        failures.push(what);
    }
}

#[test]
#[ignore = "an anchor and two vox daemons with production Argon2id; CI runs it in release"]
fn an_urgent_message_wakes_each_harness_on_another_node_within_seconds() {
    // **No real `codex` can be reached.** A product that wakes Codex by starting `codex exec` (the
    // mutant that proves (4), or a regression) must find a stand-in, never a real Codex with this
    // machine's login, which would be a live model turn. So every process here gets a PATH of only
    // the stand-in's directory and `/usr/bin:/bin`, nothing from the user's PATH, and an empty
    // CODEX_HOME. The stand-in records every call and runs nothing; a call it does not expect
    // fails loudly. Set before anything else starts, so every child inherits it.
    //
    // **Nor the operator's home.** `support/room.rs` gives this process, and so every daemon and
    // hook it starts, an empty temporary HOME and XDG dirs before `main`, and checks a child sees
    // them (`vox-core/tests/support/temp_home.rs`), so nothing here can read or write anything
    // under the real home (#170's verifier).
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let bin = tmp.path().join("bin");
    let codex_home = tmp.path().join("codex-home");
    for d in [&bin, &codex_home] {
        std::fs::create_dir_all(d).expect("APPARATUS: create a temp dir");
    }
    let ran = tmp.path().join("codex-ran");
    let codex = bin.join("codex");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(
            &codex,
            format!(
                "#!/bin/sh\n\
                 # The R16 proof's stand-in for `codex`: records the call, runs nothing.\n\
                 if [ \"$1\" = exec ] && [ $# -eq 2 ]; then\n\
                 \x20 printf 'exec %s\\n' \"$2\" >> '{ran}'\n\
                 \x20 exit 0\n\
                 fi\n\
                 printf 'UNEXPECTED %s\\n' \"$*\" >> '{ran}'\n\
                 echo \"R16 proof's stand-in codex: unexpected call: $*\" >&2\n\
                 exit 97\n",
                ran = ran.display()
            ),
        )
        .expect("APPARATUS: write the stand-in `codex`");
        std::fs::set_permissions(&codex, std::fs::Permissions::from_mode(0o755))
            .expect("APPARATUS: make the stand-in `codex` executable");
    }
    let path = format!("{}:/usr/bin:/bin", bin.display());
    // Before any other thread exists: the watchdog and the runtime start below.
    std::env::set_var("PATH", &path);
    std::env::set_var("CODEX_HOME", &codex_home);
    let found = std::process::Command::new("/bin/sh")
        .args(["-c", "command -v codex"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    assert_eq!(
        std::path::Path::new(&found),
        codex.as_path(),
        "CANNOT MEASURE (APPARATUS): under the test's PATH ({path}), `codex` must resolve to the \
         stand-in and nothing else; it resolved to {found:?}. Stopped before anything was posted."
    );

    watchdog::arm();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: a tokio runtime");
    let r = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&r.workers[0], &r.workers[1]);
    let room = r.id.clone();
    let bob_err = || std::fs::read_to_string(tmp.path().join("bob.daemon.err")).unwrap_or_default();
    let mut failures = Vec::new();

    // ---- bob's three sessions register with his daemon, as each harness's hook does ----
    let cc_sock = tmp.path().join("cc.sock");
    let cc_inbox = claude_socket(&cc_sock);
    let cc_s = cc_sock.to_string_lossy().into_owned();
    let cc_env = [
        ("CLAUDE_CODE_MESSAGING_SOCKET", cc_s.as_str()),
        ("CLAUDE_CODE_MESSAGING_TOKEN", "cc-token"),
        ("VOX_AGENT_NAME", "cc"),
    ];
    let oc_sock = tmp.path().join("oc.sock");
    let oc_inbox = opencode_socket(&oc_sock);
    let oc_s = oc_sock.to_string_lossy().into_owned();
    let oc_env = [
        ("VOX_OPENCODE_WAKE_SOCKET", oc_s.as_str()),
        ("VOX_OPENCODE_WAKE_TOKEN", "oc-token"),
        ("VOX_AGENT_NAME", "oc"),
    ];
    let cx_env = [("VOX_HARNESS", "codex"), ("VOX_AGENT_NAME", "cx")];
    // Each session's turn: the drain its harness runs at the start of one.
    let cc_turn = |prompt: &str| {
        let input = serde_json::json!({
            "session_id": "session-cc",
            "hook_event_name": "UserPromptSubmit",
            "prompt": prompt,
            "cwd": "/tmp",
            "transcript_path": "/tmp/t.jsonl",
            "permission_mode": "default",
            "prompt_id": "p",
        })
        .to_string();
        hook(
            bob,
            &cc_env,
            &["agent", "hook", "--node", "default", "--room", &room],
            Some(&input),
        )
    };
    let oc_turn = || {
        hook(
            bob,
            &oc_env,
            &[
                "agent",
                "hook",
                "--node",
                "default",
                "--room",
                &room,
                "--session",
                "session-oc",
            ],
            None,
        )
    };
    let cx_turn = || {
        hook(
            bob,
            &cx_env,
            &[
                "agent",
                "hook",
                "--node",
                "default",
                "--room",
                &room,
                "--session",
                "session-cx",
                "--format",
                "codex",
            ],
            None,
        )
    };
    let _ = cc_turn("hi");
    let _ = oc_turn();
    let _ = cx_turn();
    for (session, want) in [
        ("session-cc", ("claude".to_owned(), cc_s.clone())),
        ("session-oc", ("opencode".to_owned(), oc_s.clone())),
        ("session-cx", ("codex".to_owned(), String::new())),
    ] {
        assert_eq!(
            registered(bob, session),
            want,
            "PRODUCT (staging): `vox agent hook` must register {session} as the harness and at the \
             endpoint it was given (the test's own, never a real session's)"
        );
    }

    // Bob's daemon must be in sync with alice, and every session must have read everything so far.
    let _ = post(alice, &room, "SYNC-MARKER");
    until(
        bob,
        None,
        "alice's marker to reach bob",
        &["room", "read", &room],
        |o| o.stdout.contains("SYNC-MARKER"),
    );
    let _ = cc_turn("hi");
    let _ = oc_turn();
    let _ = cx_turn();

    // ---- (6) `vox room tail` on bob's node, as a person runs it: it must show what syncs ----
    let tail_out = tmp.path().join("bob.tail.out");
    let mut tail_cmd = std::process::Command::new(support::VOX);
    tail_cmd
        .args(["room", "tail", &room])
        .env("VOX_DATA_DIR", &bob.data)
        .env("VOX_CONFIG_DIR", &bob.cfg)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(
            std::fs::File::create(&tail_out).expect("APPARATUS: create the tail's output file"),
        ))
        .stderr(std::process::Stdio::null());
    for v in support::HARNESS_SESSION_VARS {
        tail_cmd.env_remove(v);
    }
    let mut tail = tail_cmd.spawn().expect("APPARATUS: spawn `vox room tail`");

    // ---- the rounds: one urgent message to all three, measured to each wake ----
    // `to` names a node by its whole fingerprint (V210-161): bob's, where all three sessions are.
    let bob_fp = bob.b32();
    let (mut cc_lat, mut oc_lat) = (Vec::new(), Vec::new());
    for n in 1..=ROUNDS {
        let canary = format!("CANARY-R16-{n}");
        let posted = post(
            alice,
            &room,
            &format!(
                r#"{{"v":1,"type":"ask","to":["{bob_fp}"],"urgent":true,"body":"{canary} wake up"}}"#
            ),
        );
        let cc_got = cc_inbox.recv_timeout(PATIENCE).ok();
        let oc_got = oc_inbox.recv_timeout(PATIENCE).ok();
        let cc_at = cc_got.as_ref().map(|(t, _)| (*t - posted).as_secs_f64());
        let oc_at = oc_got.as_ref().map(|(t, ..)| (*t - posted).as_secs_f64());
        cc_lat.push(cc_at);
        oc_lat.push(oc_at);
        let cc_frame = cc_got.map(|(_, f)| f).unwrap_or_default();
        let (oc_auth, oc_prompt) = oc_got.map(|(_, a, p)| (a, p)).unwrap_or_default();
        let cc_text = claude_notice(&cc_frame).unwrap_or_default();
        let oc_text = opencode_notice(&oc_prompt);
        println!(
            "[proof] round {n}: cc woken after {}, oc after {} (bound {} s); cc notice {cc_text:?}; \
             oc notice {oc_text:?}",
            cc_at.map_or("never".to_owned(), |s| format!("{s:.2} s")),
            oc_at.map_or("never".to_owned(), |s| format!("{s:.2} s")),
            WITHIN.as_secs()
        );
        for (who, at, text, auth_ok) in [
            (
                "cc (Claude Code)",
                cc_at,
                &cc_text,
                cc_frame.contains("cc-token"),
            ),
            (
                "oc (OpenCode)",
                oc_at,
                &oc_text,
                oc_auth.contains("oc-token"),
            ),
        ] {
            check(
                &mut failures,
                at.is_some_and(|s| s <= WITHIN.as_secs_f64())
                    && text.contains("1 urgent message addressed to you from alice")
                    && auth_ok,
                format!(
                    "PRODUCT (1) round {n}: {who} must be woken within {} s of alice's post, by a \
                     notice naming one urgent message from alice, with its registered token; \
                     woken after {at:?} s with {text:?}; bob's daemon:\n{}",
                    WITHIN.as_secs(),
                    bob_err()
                ),
            );
        }
        check(
            &mut failures,
            !cc_frame.contains(&canary)
                && !cc_frame.contains("wake up")
                && !oc_prompt.contains(&canary)
                && !oc_prompt.contains("wake up"),
            format!(
                "PRODUCT (2) round {n}: no byte of the message may reach a wake endpoint; Claude \
                 Code got {cc_frame:?}, OpenCode got {oc_prompt:?}"
            ),
        );
        // (3) each woken session's turn reads the room, as its harness would.
        let cc_read = cc_turn(&cc_text);
        let oc_read = oc_turn();
        assert!(
            cc_read.contains(&canary) && oc_read.contains(&canary),
            "PRODUCT (staging) (3) round {n}: the woken sessions' turns (`vox agent hook`) must read the message, or the \
             next round's wake is held back by the outstanding notice; cc read {cc_read:?}, oc \
             read {oc_read:?}"
        );
    }
    let spread = |v: &[Option<f64>]| {
        v.iter()
            .map(|x| x.map_or("never".to_owned(), |s| format!("{s:.2}")))
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!(
        "[proof] wake latency over {ROUNDS} rounds, seconds from alice's post: Claude Code [{}], \
         OpenCode [{}]; bound {} s",
        spread(&cc_lat),
        spread(&oc_lat),
        WITHIN.as_secs()
    );

    // ---- (4) and (5): Codex ----
    let codex_calls = std::fs::read_to_string(&ran).unwrap_or_default();
    println!("[proof] (4) `codex` called by the daemons: {codex_calls:?}");
    check(
        &mut failures,
        codex_calls.is_empty(),
        format!(
            "PRODUCT (4): Vox never starts an instance of anything (docs/release/v0.3.0.md §D); \
             the daemons called `codex` with: {codex_calls:?}"
        ),
    );
    let cx_read = cx_turn();
    let counts: Vec<usize> = (1..=ROUNDS)
        .map(|n| cx_read.matches(&format!("CANARY-R16-{n} ")).count())
        .collect();
    println!("[proof] (5) cx's next turn read each round's message {counts:?} time(s)");
    check(
        &mut failures,
        counts.iter().all(|&c| c == 1),
        format!(
            "PRODUCT (5): a Codex session must read every message at its next turn, once each; \
             counts per round {counts:?}; it read: {cx_read}"
        ),
    );

    // ---- (6) `vox room tail` showed every message that reached bob's node by sync ----
    let deadline = Instant::now() + Duration::from_secs(10);
    let tailed = loop {
        let t = std::fs::read_to_string(&tail_out).unwrap_or_default();
        if (1..=ROUNDS).all(|n| t.contains(&format!("CANARY-R16-{n} ")))
            || Instant::now() > deadline
        {
            break t;
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    // Stopped by its own handle (its PID), never by name.
    let _ = tail.kill();
    let _ = tail.wait();
    let tail_counts: Vec<usize> = (1..=ROUNDS)
        .map(|n| tailed.matches(&format!("CANARY-R16-{n} ")).count())
        .collect();
    println!(
        "[proof] (6) bob's `vox room tail` showed each round's message {tail_counts:?} time(s)"
    );
    check(
        &mut failures,
        tail_counts.iter().all(|&c| c == 1),
        format!(
            "PRODUCT (6): `vox room tail` on bob's node must show each message that arrived by \
             sync, once; counts per round {tail_counts:?}; it printed: {tailed}"
        ),
    );

    assert!(
        failures.is_empty(),
        "PRODUCT: {} claim(s) failed:\n- {}",
        failures.len(),
        failures.join("\n- ")
    );
}
