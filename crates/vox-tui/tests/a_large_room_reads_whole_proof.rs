//! **A room past one IPC frame of history reads whole** — `vox room read`, `tail` and
//! `board`, through the shipped binary, on the node the history reached by sync.
//!
//! A `Read` reply used to be every row after the cursor in one frame, and the client
//! refuses a frame over `MAX_FRAME` (256 KiB). So once a room's rows passed 256 KiB the
//! CLI could not read it at all: `vox room tail` exited with "declared size exceeds hard
//! limit: ipc frame length" (found 2026-09-25 when `adapter_stream_proof` was made to lag
//! by bytes). A reply is now bounded by `ROWS_BUDGET` and the client pages.
//!
//! What this drives: alice posts 160 rows of 32 KiB (5 MiB) and one row of the
//! largest text a post may carry (64 KiB); bob, which received them by sync, must then
//!
//! 1. `read --json` every one of them, in full;
//! 2. `tail --since <before the first> --json` every one of them;
//! 3. answer `board --json`, which folds the whole room.
//!
//! alice posts as a person does, with no session: such a post is kept as its words alone. A
//! post from a session carries the session's id and name around its words (ADR-029 MD-1), so
//! the largest words alone do not fit with them:
//!
//! 4. the same 64 KiB posted as a session is refused, saying how long it is as the room keeps it,
//!    that the session's id and name are in that, the most a post holds, and by how much to
//!    shorten it. It said "that is longer than this field allows" (#549). Mutant: those words
//!    back: red PRODUCT.
//!
//! The maximum row is the bound a page relies on: a reply always carries at least
//! one row, so the largest row must fit a frame by itself.
//!
//! **A room past one frame of Session entries reads whole** (ADR-034 FR-1, PF-1). A room's Session
//! entries were answered in one frame: the decider's room held 2,331 (an 837 KB reply), the client
//! failed on the frame length without reading past it, and Vox.app kept the connection it could no
//! longer read, so every later call failed at once, a room create among them. alice's agent opens
//! a Session through its real hook, and its node is handed 2,400 entries of about 300 bytes through
//! its own control socket, as the hook hands them; then
//!
//! 5. `vox room session --json` prints every one of them, in order;
//! 6. the app's client (`VoxClient`, the library Vox.app links), attached to alice's node on her
//!    daemon, lists the Session in `sessions` and reads every entry in `session_read`;
//! 7. and `create_room` on that same client then makes a room.
//!
//! At the real 256 KiB frame: no frame knob may be set. Mutant: the daemon answers a page with
//! every entry (`session_page` without its budget): red PRODUCT at 5, the reply too large to send.
//!
//! **Every red names its side** (V210-106). `PRODUCT:` quotes what a `vox` command did: a row
//! missing, shown twice, out of order or cut short is the product's. `APPARATUS:` is this harness
//! failing to run a process or a runtime.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead as _, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use support::{until, Out, VOX};
use vox_core::node::ipc::{Frame, IpcClient, NodeSocket, Request};

/// Rows of this many bytes of body, and how many: 5 MiB, twenty frames' worth.
const ROW: usize = 32 * 1024;
const ROWS: usize = 160;

/// The largest text a post may carry (`vox_core::node::content::MAX_TEXT_LEN`). A plain
/// `vox room post` stores its body as the row's text, so this row is exactly that size.
const MAX_TEXT: usize = 64 * 1024;

/// How many Session entries alice's node is handed, and about how long each is: past 2,331, the
/// decider's room, and four frames' worth.
const SESSION_ENTRIES: usize = 2400;
const SESSION_ENTRY: usize = 300;

/// The harness session id of alice's agent.
const SESSION: &str = "5b1d0c6e-7a2f-4e3b-8c9d-large-room-session";

/// A transport delay on the app's held connection must not leave its controls waiting for ever.
/// The daemon stays responsive to other connections: this specifically exercises the FFI's
/// total bound, beyond the core's daemon-liveness probe. The next request must open a new
/// connection, and the node must stay Ready (ADR-034 WT-1, WT-2, WT-5; #698).
#[test]
#[ignore = "real daemon and the app's 60-second request deadline; run in release on demand"]
fn an_app_request_times_out_and_reconnects_without_losing_its_node() {
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("APPARATUS: runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: scratch profile");
    // The shared journey proves readability by exchanging rows, so it needs two members.
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let alice = &room.workers[0];
    let node = alice.paths.account().nodes_on_disk()[0].clone();
    let socket = alice.paths.account().socket();
    let upstream = socket.with_extension("upstream");
    std::fs::rename(&socket, &upstream).expect("APPARATUS: move scratch daemon socket");
    let listener = UnixListener::bind(&socket).expect("APPARATUS: bind delayed transport");
    let armed = Arc::new(AtomicBool::new(false));
    let delayed = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    // Let the one held reply go on panic too; no paused worker or daemon survives this proof.
    struct Release(Arc<AtomicBool>);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let _release = Release(Arc::clone(&release));
    let (arm_proxy, delayed_proxy, release_proxy) = (
        Arc::clone(&armed),
        Arc::clone(&delayed),
        Arc::clone(&release),
    );
    std::thread::spawn(move || {
        for accepted in listener.incoming() {
            let Ok(mut down) = accepted else { break };
            let Ok(mut up) = UnixStream::connect(&upstream) else {
                break;
            };
            let Ok(mut down_read) = down.try_clone() else {
                break;
            };
            let Ok(mut up_write) = up.try_clone() else {
                break;
            };
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut down_read, &mut up_write);
                let _ = up_write.shutdown(std::net::Shutdown::Write);
            });
            let (armed, delayed, release) = (
                Arc::clone(&arm_proxy),
                Arc::clone(&delayed_proxy),
                Arc::clone(&release_proxy),
            );
            std::thread::spawn(move || {
                let mut bytes = [0; 8192];
                while let Ok(n) = up.read(&mut bytes) {
                    if n == 0 {
                        break;
                    }
                    if armed.swap(false, Ordering::SeqCst) {
                        delayed.store(true, Ordering::SeqCst);
                        while !release.load(Ordering::SeqCst) {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                    }
                    if down.write_all(&bytes[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    let client = rt
        .block_on(vox_ffi::VoxClient::open(
            alice.data.to_string_lossy().into_owned(),
        ))
        .expect("PRODUCT: the app could not connect to the running daemon");
    let pass = vox_ffi::Passphrase::new(support::ID_PASS.as_bytes().to_vec())
        .expect("APPARATUS: passphrase");
    rt.block_on(client.attach(node.as_str().to_owned(), Some(pass)))
        .expect("PRODUCT: the app could not attach its node");
    armed.store(true, Ordering::SeqCst);
    let began = Instant::now();
    let answer = rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(65), client.sessions(room.id.clone())).await
    });
    assert!(
        delayed.load(Ordering::SeqCst),
        "APPARATUS: no app reply was delayed"
    );
    let answer = answer.expect("PRODUCT: the app's request still waits after its 60-second bound");
    let reason = answer
        .expect_err("PRODUCT: the app answered before the delayed reply arrived")
        .to_string();
    assert!(
        reason.contains("60 seconds"),
        "PRODUCT: the app's deadline said: {reason}"
    );
    release.store(true, Ordering::SeqCst);
    let next = rt.block_on(client.sessions(room.id.clone()));
    assert!(
        next.is_ok(),
        "PRODUCT: the app's next request could not reconnect: {next:?}"
    );
    let state = alice.vox(None, &["status", "--json"]);
    assert!(
        state.ok,
        "PRODUCT: the node was not Ready after the app reconnected: {state:?}"
    );
    let nodes = alice.vox(None, &["node", "list"]);
    assert!(
        nodes.ok
            && nodes.stdout.lines().any(|l| l.contains(node.as_str())
                && (l.contains("Ready") || l.contains("ready") || l.contains("attached"))
                && !l.contains("detached")),
        "PRODUCT: the app's node did not stay Ready: {nodes:?}"
    );
    rt.block_on(client.close());
    eprintln!("[proof] delayed app reply ended in {reason} after {:?}; the next call succeeded and the node stayed Ready", began.elapsed());
}

/// Entry `n` of alice's Session, in the harnesses' activity format: a reply of about
/// [`SESSION_ENTRY`] bytes, its words naming it.
fn session_entry(n: usize) -> (String, String) {
    let head = format!("SESSION-ENTRY-{n:04} ");
    let text = format!("{head}{}", "y".repeat(SESSION_ENTRY - 80 - head.len()));
    let body =
        serde_json::json!({ "v": 1, "session": SESSION, "kind": "reply", "seq": n, "text": text })
            .to_string();
    (text, body)
}

fn body(i: usize, len: usize) -> String {
    let head = format!("LARGE-ROOM-{i:03} ");
    format!("{head}{}", "x".repeat(len - head.len()))
}

#[test]
#[ignore = "two networked nodes with production Argon2id and 5 MiB of history; CI runs it in release"]
fn a_room_past_one_frame_of_history_reads_whole() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("APPARATUS: could not build a runtime: {e}"));
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a temporary directory: {e}"));
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&room.workers[0], &room.workers[1]);
    let r = room.id.as_str();

    // The cursor tail starts from: the last row before the large ones.
    let before = bob.vox(None, &["room", "read", r, "--json"]);
    assert!(
        before.ok,
        "PRODUCT (staging): bob's `vox room read --json` failed: {before:?}"
    );
    let start = before
        .ndjson()
        .last()
        .and_then(|x| x["entry_hash"].as_str().map(str::to_owned))
        .unwrap_or_else(|| {
            panic!("PRODUCT (staging): bob's room has no row with an entry_hash before the large ones: {before:?}")
        });

    let mut sent = Vec::new();
    for i in 0..ROWS {
        sent.push(body(i, ROW));
    }
    sent.push(body(ROWS, MAX_TEXT));
    for b in &sent {
        let o = alice.vox_in(None, &["room", "post", r, "-"], Some(b));
        assert!(
            o.ok,
            "PRODUCT (staging): alice's `vox room post` of {} bytes was refused: {o:?}",
            b.len()
        );
    }
    // 4. The largest words, posted as a session.
    let as_session = alice.vox_in(
        Some("a1"),
        &["room", "post", r, "-"],
        Some(&body(0, MAX_TEXT)),
    );
    let over = as_session
        .stderr
        .split("this post is ")
        .nth(1)
        .and_then(|t| t.split(' ').next())
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or(0);
    let told = &as_session.stderr;
    assert!(
        !as_session.ok
            && over > MAX_TEXT
            && told.contains("with the id and name of the session posting it")
            && told.contains(&format!("a post holds at most {MAX_TEXT} bytes"))
            && told.contains(&format!("{} bytes shorter", over - MAX_TEXT)),
        "PRODUCT: words that fill a post refused as a session's must be told how long the post is \
         with the session's id and name, the most a post holds, and by how much to shorten it; \
         vox said: {as_session:?}"
    );
    let total: usize = sent.iter().map(String::len).sum();
    assert!(
        total >= 1024 * 1024,
        "APPARATUS: this proof stages at least 1 MiB of history, not {total}"
    );

    // 1. `read --json`, on the node the rows reached by sync.
    let read = until(
        bob,
        None,
        "every large row to reach bob and read back",
        &["room", "read", r, "--json"],
        |o: &Out| o.ok && o.stdout.contains(&format!("LARGE-ROOM-{ROWS:03} ")),
    );
    let got: Vec<String> = read
        .ndjson()
        .iter()
        .filter_map(|x| x["envelope"]["body"].as_str().map(str::to_owned))
        .filter(|b| b.starts_with("LARGE-ROOM-"))
        .collect();
    same_rows("read --json", &got, &sent);
    let max_row = read
        .ndjson()
        .iter()
        .find(|x| {
            x["envelope"]["body"]
                .as_str()
                .is_some_and(|b| b.starts_with(&format!("LARGE-ROOM-{ROWS:03} ")))
        })
        .and_then(|x| x["text"].as_str().map(str::len))
        .unwrap_or_else(|| {
            panic!("PRODUCT: bob's `read --json` shows no text for the largest row (LARGE-ROOM-{ROWS:03})")
        });
    eprintln!(
        "[proof] {} rows, {total} bytes of body; the largest row's text is {max_row} bytes",
        sent.len()
    );
    assert_eq!(
        max_row, MAX_TEXT,
        "PRODUCT: the largest row must carry exactly MAX_TEXT_LEN and read back whole"
    );

    // 2. `tail --since`, which pages the same history before it follows.
    let mut cmd = Command::new(VOX);
    cmd.args(["room", "tail", r, "--since", &start, "--json"])
        .env("VOX_DATA_DIR", &bob.data)
        .env("VOX_CONFIG_DIR", &bob.cfg)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    support::strip_harness_env(&mut cmd);
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: could not spawn {VOX} room tail: {e}"));
    let stdout = child
        .stdout
        .take()
        .expect("APPARATUS: tail's stdout was piped");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { return };
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    let mut tailed = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    while tailed.len() < sent.len() && Instant::now() < deadline {
        let Ok(line) = rx.recv_timeout(Duration::from_secs(1)) else {
            if child.try_wait().ok().flatten().is_some() {
                break; // it exited: the frame-limit failure did exactly this
            }
            continue;
        };
        let row: serde_json::Value = serde_json::from_str(&line).unwrap_or_else(|e| {
            panic!("PRODUCT: `vox room tail --json` printed a bad NDJSON row ({e}): {line}")
        });
        if let Some(b) = row["envelope"]["body"].as_str() {
            if b.starts_with("LARGE-ROOM-") {
                tailed.push(b.to_owned());
            }
        }
    }
    let exited = child.try_wait().ok().flatten();
    let _ = child.kill();
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not wait for tail: {e}"));
    assert!(
        exited.is_none(),
        "PRODUCT: `vox room tail` must still be running, not exit ({exited:?}): {}",
        String::from_utf8_lossy(&out.stderr)
    );
    same_rows("tail --since", &tailed, &sent);

    // 3. `board --json` folds the whole room.
    let board = bob.vox(None, &["room", "board", r, "--json"]);
    assert!(
        board.ok,
        "PRODUCT: `vox room board --json` over a large room failed: {board:?}"
    );
    assert_eq!(
        board.json()["schema"],
        "vox.room.board/1",
        "PRODUCT: `vox room board --json` over a large room answered another schema: {}",
        board.stdout
    );

    // ---- 5–7: a room past one frame of Session entries (ADR-034 FR-1) ----
    assert!(
        std::env::var_os("VOX_TEST_MAX_FRAME").is_none(),
        "APPARATUS: VOX_TEST_MAX_FRAME is set; this proof runs at the real 256 KiB frame"
    );
    // alice's node, whatever `vox id` named it.
    let node = match alice.paths.account().nodes_on_disk().as_slice() {
        [one] => one.clone(),
        many => panic!(
            "APPARATUS: alice's data root holds {} nodes, not one",
            many.len()
        ),
    };
    // alice's agent opens its Session through its real hook, as Claude Code runs it.
    let hooked = alice.vox_env(
        None,
        &[("CLAUDE_CODE_ENTRYPOINT", "cli")],
        &["agent", "hook", "--node", node.as_str(), "--room", r],
        Some(&format!(
            r#"{{"session_id":"{SESSION}","hook_event_name":"UserPromptSubmit","cwd":"/tmp","transcript_path":"/tmp/t.jsonl","prompt":"go"}}"#
        )),
    );
    // The hook never fails its harness: what it could not do, it says on stderr.
    assert!(
        hooked.ok && hooked.stderr.trim().is_empty(),
        "PRODUCT (staging): alice's agent hook did not open its Session: {hooked:?}"
    );
    // Its entries, handed to alice's node on its control socket as the hook hands them.
    let entries: Vec<(String, String)> = (1..=SESSION_ENTRIES).map(session_entry).collect();
    let staged: usize = entries.iter().map(|(_, b)| b.len()).sum();
    assert!(
        staged > 2 * vox_core::node::ipc::MAX_FRAME,
        "APPARATUS: this proof stages more than two frames of Session entries, not {staged} bytes"
    );
    rt.block_on(async {
        let at = NodeSocket::one_shot(alice.paths.account().socket(), node.clone());
        let mut c = IpcClient::open_at(&at)
            .await
            .unwrap_or_else(|e| panic!("PRODUCT (staging): alice's node did not answer: {e}"));
        for (_, body) in &entries {
            let req = Request::AppendSession {
                channel_id: room.cid,
                session_id: SESSION.to_owned(),
                body: body.clone(),
            };
            match c.request(&req).await {
                Ok(Frame::Appended { .. }) => {}
                other => {
                    panic!("PRODUCT (staging): alice's node refused a Session entry: {other:?}")
                }
            }
        }
    });
    let wanted: Vec<String> = entries.iter().map(|(t, _)| format!("reply: {t}")).collect();
    eprintln!("[proof] {SESSION_ENTRIES} Session entries staged, {staged} bytes of body");

    // 5. `vox room session --json`.
    let shown = alice.vox(None, &["room", "session", r, SESSION, "--json"]);
    assert!(
        shown.ok,
        "PRODUCT: `vox room session --json` over {SESSION_ENTRIES} Session entries failed: {}",
        shown.stderr.trim()
    );
    let lines: Vec<String> = shown
        .ndjson()
        .iter()
        .filter(|v| v["kind"] == "reply")
        .filter_map(|v| v["line"].as_str().map(str::to_owned))
        .collect();
    same_entries("vox room session --json", &lines, &wanted);

    // 6. The app's client, attached to alice's node on her daemon.
    let pass = |p: &str| {
        vox_ffi::Passphrase::new(p.as_bytes().to_vec())
            .unwrap_or_else(|e| panic!("APPARATUS: a passphrase: {e}"))
    };
    let data = alice.data.to_string_lossy().into_owned();
    let client = rt
        .block_on(vox_ffi::VoxClient::open(data))
        .unwrap_or_else(|e| {
            panic!("PRODUCT (staging): the app's client did not reach alice's daemon: {e}")
        });
    rt.block_on(client.attach(node.as_str().to_owned(), Some(pass(support::ID_PASS))))
        .unwrap_or_else(|e| {
            panic!("PRODUCT (staging): the app's client did not attach alice's node: {e}")
        });
    let listed = rt.block_on(client.sessions(room.id.clone()));
    let listed = listed.unwrap_or_else(|e| {
        panic!("PRODUCT: the app's `sessions` over {SESSION_ENTRIES} Session entries failed: {e}")
    });
    assert!(
        listed.iter().any(|s| s.session_id == SESSION),
        "PRODUCT: the app's `sessions` does not list alice's Session: {listed:?}"
    );
    let read = rt
        .block_on(client.session_read(room.id.clone(), alice.b32(), SESSION.to_owned()))
        .unwrap_or_else(|e| {
            panic!("PRODUCT: the app's `session_read` over {SESSION_ENTRIES} Session entries failed: {e}")
        });
    let app_lines: Vec<String> = read
        .entries
        .iter()
        .map(|e| e.line.clone())
        .filter(|l| l.starts_with("reply: "))
        .collect();
    same_entries("the app's session_read", &app_lines, &wanted);

    // 7. And the client still works: a room is made on it.
    let made =
        rt.block_on(client.create_room("after-the-large-read".into(), pass(support::ROOM_PASS)));
    rt.block_on(client.close());
    let made = made.unwrap_or_else(|e| {
        panic!(
            "PRODUCT: the app's `create_room` after reading the large room's Sessions failed: {e}"
        )
    });
    eprintln!(
        "[proof] the CLI printed {} entries, the app read {}, and made room {made}",
        lines.len(),
        app_lines.len()
    );
}

/// Assert that `got`, the Session lines `verb` showed, are `wanted`'s entries: each once, in order,
/// and each line the start of its entry's line. A red says which, and is the product's.
fn same_entries(verb: &str, got: &[String], wanted: &[String]) {
    let name = |l: &str| {
        l.split(' ')
            .find(|w| w.starts_with("SESSION-ENTRY-"))
            .unwrap_or_default()
            .to_owned()
    };
    assert!(
        got.len() == wanted.len(),
        "PRODUCT: `{verb}` shows {} of the {} Session entries; the first missing is {:?}",
        got.len(),
        wanted.len(),
        wanted
            .iter()
            .map(|w| name(w))
            .find(|n| !got.iter().any(|g| name(g) == *n))
    );
    for (g, w) in got.iter().zip(wanted) {
        // A line is cut to one line's length and ends "…" then.
        let shown = g.strip_suffix('…').unwrap_or(g);
        assert!(
            name(g) == name(w) && w.starts_with(shown),
            "PRODUCT: `{verb}` shows {:?} where {} was written, in that place",
            g.chars().take(60).collect::<String>(),
            name(w)
        );
    }
}

/// Assert that `got`, the large rows `verb` showed bob, are `sent`: each once, whole and in the
/// order alice posted them. A red says which, and is the product's.
fn same_rows(verb: &str, got: &[String], sent: &[String]) {
    let name = |b: &str| b.split(' ').next().unwrap_or_default().to_owned();
    let names: Vec<String> = got.iter().map(|b| name(b)).collect();
    let mut distinct = names.clone();
    distinct.sort();
    distinct.dedup();
    assert!(
        distinct.len() == names.len(),
        "PRODUCT: `{verb}` shows {} large rows for {} distinct ones: a row shown more than once",
        names.len(),
        distinct.len()
    );
    let wanted: Vec<String> = sent.iter().map(|b| name(b)).collect();
    let missing: Vec<&String> = wanted.iter().filter(|n| !names.contains(n)).collect();
    assert!(
        missing.is_empty(),
        "PRODUCT: `{verb}` shows {} of the {} large rows; missing {missing:?}",
        names.len(),
        wanted.len()
    );
    assert!(
        names == wanted,
        "PRODUCT: `{verb}` shows every large row once, but not in the order posted: {names:?}"
    );
    for (g, s) in got.iter().zip(sent) {
        assert!(
            g == s,
            "PRODUCT: `{verb}` shows {} cut or changed: {} bytes, not the {} posted",
            name(s),
            g.len(),
            s.len()
        );
    }
}
