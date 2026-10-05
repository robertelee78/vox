//! #412 (V030-38) — **a crash in the middle of a join never costs the member the room**: after a
//! kill at any point of `vox room join`, the restarted node either holds the room open, by itself,
//! or does not hold it, and a join made again lets the member in. Never a room held closed that
//! nothing opens, never "an internal error". Driven through the shipped `vox` binary.
//!
//! **The defect.** The join wrote the room in one batch and remembered it as open (#208) in a
//! second write after it. A kill between the two restarted a node holding the room closed: the
//! daemon reopens only the rooms it remembers, and every join made again was refused because the
//! room was in the profile, reported as "an internal error — a bug in vox". The member could not
//! get back in. Found by the held-key arm of the crash-consent proof at its third kill point.
//!
//! **The staging.** An anchor; for each kill point `k` from 1, a host `host<k>` that trusts alice
//! and that she trusts, with a room of its own; alice's `vox daemon` under the syscall interposer
//! (`crates/vox-test-interpose`). Once alice's store has gone [`QUIET`], the kill point is armed at
//! `k` and alice runs `vox room join`: her daemon SIGKILLs itself right after the `k`-th flush of
//! its store that follows. The host's daemon is stopped, alice's restarted, then the host's.
//!
//! **Asserted,** per kill point, killed or not: alice's `vox room list` does not show the room
//! `[closed]`; if it does not show it at all, `vox room join` again succeeds (and is never an
//! internal error); then alice posts `post <k>` and the host reads it within [`BOUND`].
//! Preconditions: at least [`MIN_KILLS`] kill points fell inside the join, and the sweep ended
//! inside [`MAX_POINTS`] (`APPARATUS` otherwise).
//!
//! **Mutation that must turn it red:** the room remembered as open after the join's batch, not in
//! it — a kill between the two leaves it `[closed]`.
//!
//! **The one step that is not a `vox` command** is the crash: the interposer is test apparatus,
//! loaded into the unmodified binary with `DYLD_INSERT_LIBRARIES` (macOS). Everything else is the
//! shipped binary, killed by its PID when dropped.

#![cfg(target_os = "macos")]

#[path = "support/ports.rs"]
mod ports;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/attach.rs"]
mod attach;

#[path = "support/syscalls.rs"]
mod syscalls;

#[path = "support/test_knobs.rs"]
mod test_knobs;

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDENTITY: &str = "an identity passphrase";
const ROOMPASS: &str = "the room passphrase";

/// A child process, killed by its own PID when dropped.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn command(dir: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        // In the environment, not argv: a command line is world-readable (ADR-015).
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM")
        .env_remove("VOX_SESSION");
    cmd
}

/// A verb as a person runs it since ADR-026 L-2: one that needs its node attached, run while no
/// daemon holds the data root, runs with the node attached by `vox node attach` and let go after.
fn vox(dir: &std::path::Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let verb: Vec<&str> = args.to_vec();
    match attach::needs(dir, &verb) {
        Some(node) => {
            attach::Root::at(dir, IDENTITY).attached(&node, || vox_plain(dir, args, stdin))
        }
        None => vox_plain(dir, args, stdin),
    }
}

fn vox_plain(dir: &Path, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut child = command(dir, args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: spawn vox");
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().expect("APPARATUS: stdin");
        pipe.write_all(text.as_bytes())
            .expect("PRODUCT (staging): vox exited without reading its stdin");
    }
    let out = child.wait_with_output().expect("APPARATUS: wait");
    let mut err = String::from_utf8_lossy(&out.stderr).into_owned();
    // A process ended by a signal says nothing on stderr: say how it ended, so a verb killed by
    // the watchdog's abort is not read as a verb that failed without a cause (#295).
    if !out.status.success() {
        err.push_str(&format!(" [vox {}: {}]", args.join(" "), out.status));
    }
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        err,
    )
}

/// The loopback port the daemon at `dir` chose, from its own `vox status --json` (#410): a daemon
/// starts on port 0 and its restarts come back on the port read here, never one picked ahead.
fn listening_port(dir: &Path) -> u16 {
    let (_, status, _) = vox(dir, &["status", "--json"], None);
    ports::loopback_listen(&status)
        .unwrap_or_else(|| panic!("PRODUCT (staging): no loopback listen address in {status}"))
        .port()
}

/// Start `vox daemon` on `port` (0: its own choice) with the identity passphrase piped in; `extra`
/// is its environment.
fn daemon(dir: &Path, port: u16, anchor: &str, tag: &str, extra: &[(&str, &Path)]) -> Proc {
    daemon_given(dir, port, anchor, tag, extra, &[])
}

/// [`daemon`], given `rooms` too: each a line on its stdin after the identity passphrase, the room
/// passphrase a person gives `vox daemon` for a room it holds closed.
fn daemon_given(
    dir: &Path,
    port: u16,
    anchor: &str,
    tag: &str,
    extra: &[(&str, &Path)],
    rooms: &[&str],
) -> Proc {
    let err = std::fs::File::options()
        .create(true)
        .append(true)
        .open(dir.join(format!("daemon-{tag}.err")))
        .expect("APPARATUS: open a log file");
    let listen = format!("127.0.0.1:{port}");
    // No anchor given ("") is a daemon with none, as a person runs one on its own.
    let mut argv = vec!["daemon", "--listen", &listen];
    if !anchor.is_empty() {
        argv.extend(["--anchor", anchor]);
    }
    let mut cmd = command(dir, &argv);
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(err))
        .spawn()
        .expect("APPARATUS: spawn vox daemon");
    let mut pipe = child.stdin.take().expect("APPARATUS: daemon stdin");
    let mut lines = format!("{IDENTITY}\n");
    for r in rooms {
        lines.push_str(r);
        lines.push('\n');
    }
    pipe.write_all(lines.as_bytes())
        .expect("PRODUCT (staging): vox exited without reading its stdin");
    drop(pipe);
    Proc(child)
}

/// `vox room list` once the daemon answers.
fn attached(dir: &Path, tag: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last = String::new();
    while Instant::now() < deadline {
        let (ok, out, err) = vox(dir, &["room", "list"], None);
        if ok {
            return out;
        }
        let said =
            std::fs::read_to_string(dir.join(format!("daemon-{tag}.err"))).unwrap_or_default();
        assert!(
            !ports::bind_refused(&said),
            "{}: {tag}'s daemon:\n{said}",
            ports::APPARATUS_BIND
        );
        last = err;
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("PRODUCT (staging): {tag}'s daemon never answered: {last}");
}

/// Every `pre <k>` and `post <k>` this profile reads in `room`. A row it cannot open carries a
/// marker, not a post, and is not counted.
fn texts(dir: &Path, room: &str) -> BTreeSet<String> {
    let (ok, out, err) = vox(
        dir,
        &["room", "read", room, "--json", "--limit", "500"],
        None,
    );
    assert!(ok, "PRODUCT (staging): vox room read --json refused: {err}");
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|row| row["text"].as_str().map(str::to_owned))
        .filter(|t| t.starts_with("pre ") || t.starts_with("post "))
        .collect()
}

fn alive(p: &mut Proc) -> bool {
    p.0.try_wait().ok().flatten().is_none()
}

/// How long the host has to read the post alice makes after the restart.
const BOUND: Duration = Duration::from_secs(90);
/// How long a join has to reach the kill point before the sweep is over.
const PAST_THE_END: Duration = Duration::from_secs(8);
/// How long alice's store must go unflushed before a kill point is armed.
const QUIET: Duration = Duration::from_secs(3);
/// A join is a few dozen transactions; a sweep longer than this measures something else.
const MAX_POINTS: u64 = 48;
/// Fewer kill points than this inside a join cannot have visited its boundaries.
const MIN_KILLS: u64 = 3;

#[test]
#[ignore = "real vox daemons under the syscall interposer, production Argon2id; CI runs it in release"]
fn a_crash_inside_a_join_never_costs_the_member_the_room() {
    watchdog::arm_for_debug_total(Duration::from_millis(1_270_000), 2);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let root = tmp.path();
    let alice = root.join("alice");
    std::fs::create_dir_all(alice.join("cfg")).expect("APPARATUS: create a staging directory");
    let arm = root.join("kill-arm");
    let log = root.join("alice-interpose.tsv");
    let interposer = syscalls::interposer().to_path_buf();
    let env: Vec<(&str, &Path)> = vec![
        ("DYLD_INSERT_LIBRARIES", &interposer),
        ("VOX_INTERPOSE_LOG", &log),
        ("VOX_INTERPOSE_KILL_ARM", &arm),
    ];

    // ---- the anchor, and alice ---------------------------------------------------------------
    let anchor_dir = root.join("anchor");
    std::fs::create_dir_all(anchor_dir.join("cfg")).expect("APPARATUS: create a staging directory");
    let anchor_out = anchor_dir.join("node.out");
    let _anchor = Proc(
        command(&anchor_dir, &["node", "--listen", "127.0.0.1:0"])
            .stdout(Stdio::from(
                std::fs::File::create(&anchor_out).expect("APPARATUS: create a staging file"),
            ))
            .stderr(Stdio::null())
            .spawn()
            .expect("APPARATUS: spawn the anchor"),
    );
    let t0 = Instant::now();
    let spec = loop {
        let out = std::fs::read_to_string(&anchor_out).unwrap_or_default();
        if let Some(l) = out.lines().find(|l| l.contains("@/ip4/127.0.0.1/udp/")) {
            break l.trim().to_owned();
        }
        assert!(
            t0.elapsed() < Duration::from_secs(60),
            "PRODUCT (staging): the anchor printed no spec:\n{out}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let (ok, alice_fp, err) = vox(&alice, &["id"], None);
    assert!(ok, "PRODUCT (staging): vox id: {err}");
    let alice_fp = alice_fp.trim().to_owned();
    let mut alice_daemon = daemon(&alice, 0, &spec, "alice", &env);
    attached(&alice, "alice");
    let alice_port = listening_port(&alice);
    let flushes = || {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .filter(|l| l.contains("\tsync\t") && l.contains("store.redb"))
            .count()
    };
    assert!(
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .any(|l| l.split('\t').nth(2) == Some("open")),
        "APPARATUS: the syscall recorder recorded no `open` by alice's daemon in {}: it is not \
         recording",
        log.display()
    );

    // ---- one trial per kill point ----------------------------------------------------------
    let mut kills = 0u64;
    let (mut kept, mut lost) = (Vec::new(), Vec::new());
    let mut ended_at = None;
    for k in 1..=MAX_POINTS {
        let host: PathBuf = root.join(format!("host{k}"));
        std::fs::create_dir_all(host.join("cfg")).expect("APPARATUS: create a staging directory");
        let (ok, host_fp, err) = vox(&host, &["id"], None);
        assert!(ok, "PRODUCT (staging): vox id: {err}");
        let host_fp = host_fp.trim().to_owned();
        let mut host_daemon = daemon(&host, 0, &spec, "host", &[]);
        attached(&host, "host");
        let host_port = listening_port(&host);
        let (ok, _, err) = vox(&host, &["trust", "add", &alice_fp, "--name", "alice"], None);
        assert!(ok, "PRODUCT (staging): host{k} trusts alice: {err}");
        let (ok, _, err) = vox(
            &alice,
            &["trust", "add", &host_fp, "--name", &format!("host{k}")],
            None,
        );
        assert!(ok, "PRODUCT (staging): alice trusts host{k}: {err}");
        let before: BTreeSet<String> = attached(&host, "host")
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        let (ok, _, err) = vox(
            &host,
            &["room", "create", "--passphrase-file", "-", "--name", "h"],
            Some(&format!("{ROOMPASS}\n")),
        );
        assert!(ok, "PRODUCT (staging): host{k}'s room create: {err}");
        let room = attached(&host, "host")
            .split_whitespace()
            .filter(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
            .map(str::to_owned)
            .find(|w| !before.contains(w))
            .expect("PRODUCT (staging): no new room id in the host's `room list`");
        let (ok, link, err) = vox(&host, &["room", "invite", &room], None);
        assert!(ok, "PRODUCT (staging): host{k}'s room invite: {err}");
        let link = link.trim().to_owned();
        let join = || {
            vox(
                &alice,
                &[
                    "room",
                    "join",
                    "--passphrase-file",
                    "-",
                    &link,
                    "--name",
                    &format!("h{k}"),
                ],
                Some(&format!("{ROOMPASS}\n")),
            )
        };

        // A quiet store, then the join with the kill point armed.
        let t = Instant::now();
        let (mut seen, mut since) = (flushes(), Instant::now());
        while since.elapsed() < QUIET {
            assert!(
                t.elapsed() < Duration::from_secs(60),
                "PRODUCT (staging): alice's daemon kept flushing its store; it never went quiet \
                 before kill point {k}"
            );
            std::thread::sleep(Duration::from_millis(200));
            let now = flushes();
            if now != seen {
                (seen, since) = (now, Instant::now());
            }
        }
        std::fs::write(&arm, k.to_string()).expect("APPARATUS: write a staging file");
        let _ = join();
        let t = Instant::now();
        while alive(&mut alice_daemon) && t.elapsed() < PAST_THE_END {
            std::thread::sleep(Duration::from_millis(50));
        }
        std::fs::remove_file(&arm).expect("APPARATUS: remove a staging file");
        let killed = !alive(&mut alice_daemon);
        if killed {
            kills += 1;
            // The host's daemon is down while alice's comes back (V210-78's F-B2).
            drop(host_daemon);
            drop(alice_daemon);
            alice_daemon = daemon(&alice, alice_port, &spec, "alice", &env);
            attached(&alice, "alice");
            host_daemon = daemon(&host, host_port, &spec, "host", &[]);
            attached(&host, "host");
        }

        // **The claim**: held open by itself, or not held and joined again; never held closed.
        let listed = attached(&alice, "alice");
        let line = listed
            .lines()
            .find(|l| l.contains(&room[..12]))
            .map(str::to_owned);
        assert!(
            !line.as_deref().is_some_and(|l| l.contains("[closed]")),
            "PRODUCT: held-closed at kill point {k}: after alice's restart she holds host{k}'s room \
             closed, which no restart reopens:\n{listed}\nalice's daemon said:\n{}",
            std::fs::read_to_string(alice.join("daemon-alice.err")).unwrap_or_default()
        );
        if line.is_none() {
            lost.push(k);
            let (ok, out, err) = join();
            assert!(
                ok && !err.contains("internal error"),
                "PRODUCT: kill point {k}: the join the crash lost could not be made again: \
                 {out}{err}"
            );
        } else if killed {
            kept.push(k);
        }
        // Posted once her copy of the room may be written to (V210-164), and read by the host.
        let after = format!("post {k}");
        let t = Instant::now();
        loop {
            let (ok, _, err) = vox(&alice, &["room", "post", &room, &after], None);
            if ok {
                break;
            }
            assert!(
                t.elapsed() < Duration::from_secs(60),
                "PRODUCT: kill point {k}: alice is back in host{k}'s room and cannot post: {err}"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
        let t = Instant::now();
        let mut read = false;
        while t.elapsed() < BOUND && !read {
            read = texts(&host, &room).contains(&after);
            if !read {
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        println!(
            "[proof] join kill point {k}: alice's daemon {}; the room {}; host{k} reads `{after}`: \
             {read}",
            if killed { "killed" } else { "not reached" },
            if lost.contains(&k) {
                "was lost and joined again"
            } else if killed {
                "was kept, open"
            } else {
                "joined"
            }
        );
        assert!(
            read,
            "PRODUCT: kill point {k}: host{k} never read `{after}`, which alice posted once back in \
             its room"
        );
        drop(host_daemon);
        if !killed {
            ended_at = Some(k);
            break;
        }
    }
    println!(
        "[proof] {kills} kill point(s) inside the join, the sweep ended at {ended_at:?}; the room \
         kept open after {kept:?}, lost and joined again after {lost:?}"
    );
    assert!(
        ended_at.is_some(),
        "APPARATUS (precondition not met): every one of {MAX_POINTS} kill points fell inside the \
         join, so the sweep is too short to reach its end"
    );
    assert!(
        kills >= MIN_KILLS,
        "APPARATUS (precondition not met): only {kills} kill point(s) fell inside the join: too few \
         crashes to measure"
    );
    drop(alice_daemon);
}

/// **A room held closed is opened by joining it again** (#412), the way the refusal to post in it
/// now says. A client closes the room over the control socket, as `vox tui` does; the daemon is
/// restarted, and does not reopen a room that was closed; `vox room post` is refused, saying to
/// join it again; `vox room join` with its address and passphrase opens it, and the host reads
/// what alice posts next. Mutation: a join of a room the profile holds refused as before, "an
/// internal error".
#[test]
#[ignore = "real vox daemons, production Argon2id; CI runs it in release"]
fn a_room_held_closed_is_opened_by_joining_it_again() {
    watchdog::arm_for_debug_total(Duration::from_millis(600_000), 2);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let root = tmp.path();
    let (alice, host) = (root.join("alice"), root.join("host"));
    for d in [&alice, &host] {
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a staging directory");
    }
    let anchor_dir = root.join("anchor");
    std::fs::create_dir_all(anchor_dir.join("cfg")).expect("APPARATUS: create a staging directory");
    let anchor_out = anchor_dir.join("node.out");
    let _anchor = Proc(
        command(&anchor_dir, &["node", "--listen", "127.0.0.1:0"])
            .stdout(Stdio::from(
                std::fs::File::create(&anchor_out).expect("APPARATUS: create a staging file"),
            ))
            .stderr(Stdio::null())
            .spawn()
            .expect("APPARATUS: spawn the anchor"),
    );
    let t0 = Instant::now();
    let spec = loop {
        let out = std::fs::read_to_string(&anchor_out).unwrap_or_default();
        if let Some(l) = out.lines().find(|l| l.contains("@/ip4/127.0.0.1/udp/")) {
            break l.trim().to_owned();
        }
        assert!(
            t0.elapsed() < Duration::from_secs(60),
            "PRODUCT (staging): the anchor printed no spec:\n{out}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let fp = |dir: &Path| {
        let (ok, out, err) = vox(dir, &["id"], None);
        assert!(ok, "PRODUCT (staging): vox id: {err}");
        out.trim().to_owned()
    };
    let (alice_fp, host_fp) = (fp(&alice), fp(&host));
    let mut alice_daemon = daemon(&alice, 0, &spec, "alice", &[]);
    attached(&alice, "alice");
    let alice_port = listening_port(&alice);
    let _host_daemon = daemon(&host, 0, &spec, "host", &[]);
    attached(&host, "host");
    for (dir, other, name) in [(&alice, &host_fp, "host"), (&host, &alice_fp, "alice")] {
        let (ok, _, err) = vox(dir, &["trust", "add", other, "--name", name], None);
        assert!(ok, "PRODUCT (staging): {name} trusted: {err}");
    }
    let (ok, _, err) = vox(
        &host,
        &["room", "create", "--passphrase-file", "-", "--name", "h"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): the host's room create: {err}");
    let short = attached(&host, "host")
        .split_whitespace()
        .find(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(str::to_owned)
        .expect("PRODUCT (staging): no room id in the host's `room list`");
    let (ok, link, err) = vox(&host, &["room", "invite", &short], None);
    assert!(ok, "PRODUCT (staging): the host's room invite: {err}");
    let link = link.trim().to_owned();
    // The room's whole id, as its address carries it: `vox://<id>?…`.
    let room = link
        .strip_prefix("vox://")
        .and_then(|r| r.split('?').next())
        .map(str::to_owned)
        .expect("PRODUCT (staging): the host's address does not begin vox://<room id>");
    let join = || {
        vox(
            &alice,
            &[
                "room",
                "join",
                "--passphrase-file",
                "-",
                &link,
                "--name",
                "h",
            ],
            Some(&format!("{ROOMPASS}\n")),
        )
    };
    let (ok, _, err) = join();
    assert!(ok, "PRODUCT (staging): alice's first join: {err}");

    // Closed as a client closes it (`vox tui`, ADR-026 C-7), then the daemon restarted.
    let channel_id = vox_core::node::link::b32_decode(&room, "room id")
        .expect("APPARATUS: the room id `room list` printed decodes");
    let socket = alice.join(".daemon").join("vox.sock");
    let closed = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: a runtime")
        .block_on(async {
            let mut client = attach::client_at(&socket, "default").await?;
            client
                .request(&vox_core::node::ipc::Request::CloseRoom { channel_id })
                .await
                .map_err(|e| e.to_string())
        });
    assert!(
        matches!(closed, Ok(vox_core::node::ipc::Frame::Ok)),
        "PRODUCT (staging): alice's daemon did not close the room: {closed:?}"
    );
    drop(alice_daemon);
    alice_daemon = daemon(&alice, alice_port, &spec, "alice", &[]);
    let listed = attached(&alice, "alice");
    assert!(
        listed
            .lines()
            .any(|l| l.contains(&room[..12]) && l.contains("[closed]")),
        "PRODUCT (staging): after the restart alice does not hold the room closed:\n{listed}"
    );

    // The refusal says what opens it, and that is what opens it.
    let (ok, _, refused) = vox(&alice, &["room", "post", &room, "while closed"], None);
    println!(
        "[proof] a post in the closed room: ok={ok}; it said: {}",
        refused.trim()
    );
    assert!(
        !ok && refused.contains("join it again"),
        "PRODUCT: the refusal to post in a closed room does not say to join it again: {refused}"
    );
    // **A passphrase line that opens nothing says why** (#412): the daemon restarted with a room
    // line that is not this room's passphrase names the room it did not open, and what refused it.
    drop(alice_daemon);
    let pass_file = root.join("alice-passphrases");
    std::fs::write(
        &pass_file,
        format!("{IDENTITY}\nnot this room's passphrase\n"),
    )
    .expect("APPARATUS: write a staging file");
    let log = alice.join("daemon-alice-file.err");
    let mut given = Proc(
        command(
            &alice,
            &[
                "daemon",
                "--listen",
                &format!("127.0.0.1:{alice_port}"),
                "--anchor",
                &spec,
                "--passphrase-file",
                pass_file.to_str().expect("APPARATUS: a UTF-8 path"),
            ],
        )
        .env_remove("VOX_IDENTITY_PASSPHRASE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(&log).expect("APPARATUS: create a staging file"),
        ))
        .spawn()
        .expect("APPARATUS: spawn vox daemon"),
    );
    attached(&alice, "alice");
    let said = std::fs::read_to_string(&log).unwrap_or_default();
    let named = said
        .lines()
        .find(|l| l.contains("that line did not open room") && l.contains(&room[..12]))
        .map(str::to_owned);
    println!("[proof] a daemon given a wrong room passphrase said: {named:?}");
    assert!(
        named.is_some(),
        "PRODUCT: a daemon given a room line that opened nothing did not say which room, or \
         why:\n{said}"
    );
    let _ = given.0.kill();
    let _ = given.0.wait();
    alice_daemon = daemon(&alice, alice_port, &spec, "alice", &[]);
    attached(&alice, "alice");

    let (ok, out, err) = join();
    println!(
        "[proof] joining the closed room again: ok={ok}; {}{}",
        out.trim(),
        err.trim()
    );
    assert!(
        ok && !err.contains("internal error"),
        "PRODUCT: joining a room this node holds closed did not open it: {out}{err}"
    );
    let t = Instant::now();
    loop {
        let (ok, _, err) = vox(
            &alice,
            &["room", "post", &room, "post after the join"],
            None,
        );
        if ok {
            break;
        }
        assert!(
            t.elapsed() < Duration::from_secs(60),
            "PRODUCT: alice joined the closed room again and cannot post in it: {err}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    let t = Instant::now();
    let mut read = false;
    while t.elapsed() < BOUND && !read {
        read = texts(&host, &room).contains("post after the join");
        if !read {
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    println!("[proof] the host reads what alice posted after joining again: {read}");
    assert!(
        read,
        "PRODUCT: the host never read what alice posted once she joined the closed room again"
    );
    drop(alice_daemon);
}

/// **A room the daemon does not reopen says why** (#412): a remembered room whose reopen fails
/// is held closed, and the daemon's log names it and what refused it — a closed room with no word
/// was one nobody could tell how to get back. The failure is driven by `VOX_TEST_REOPEN_FAILS`
/// (test-knobs only), which makes every reopen fail with the reason it carries.
///
/// **The note is said before the unlock's answer**, and the daemon used to take the answer first
/// about one run in ten and never read it: the log stayed silent. `VOX_TEST_ANSWER_FIRST`
/// (test-knobs only) stages that interleaving every run: the daemon takes the node's answer to
/// its unlock before reading anything the node said, so only reading what was said before the
/// answer, after it, puts the note in the log.
///
/// Mutations, each red every run: the note not sent; the read of what was said before the answer
/// removed (`apply_saying_waits` without its drain).
#[test]
#[ignore = "a real vox daemon, production Argon2id; CI runs it in release"]
fn a_room_that_does_not_reopen_says_why() {
    test_knobs::require(&["VOX_TEST_REOPEN_FAILS", "VOX_TEST_ANSWER_FIRST"]);
    watchdog::arm_for_debug_total(Duration::from_millis(300_000), 2);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let alice = tmp.path().join("alice");
    std::fs::create_dir_all(alice.join("cfg")).expect("APPARATUS: create a staging directory");
    let (ok, _, err) = vox(&alice, &["id"], None);
    assert!(ok, "PRODUCT (staging): vox id: {err}");
    let first = daemon(&alice, 0, "", "alice", &[]);
    attached(&alice, "alice");
    let port = listening_port(&alice);
    let (ok, _, err) = vox(
        &alice,
        &["room", "create", "--passphrase-file", "-", "--name", "r"],
        Some(&format!("{ROOMPASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): vox room create: {err}");
    let room = attached(&alice, "alice")
        .split_whitespace()
        .find(|w| w.len() >= 8 && w.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(str::to_owned)
        .expect("PRODUCT (staging): no room id in alice's `room list`");
    drop(first);

    let why = "the test knob refused it";
    let knob = std::path::PathBuf::from(why);
    // The daemon takes the node's answer to its unlock before reading anything the node said
    // (VOX_TEST_ANSWER_FIRST): the interleaving that lost the note, staged every run rather than
    // one run in ten. What the node said before it answered must still reach the log.
    let first_answer = std::path::PathBuf::from("1");
    let _second = daemon(
        &alice,
        port,
        "",
        "alice",
        &[
            ("VOX_TEST_REOPEN_FAILS", &knob),
            ("VOX_TEST_ANSWER_FIRST", &first_answer),
        ],
    );
    let listed = attached(&alice, "alice");
    let said = std::fs::read_to_string(alice.join("daemon-alice.err")).unwrap_or_default();
    let note = said
        .lines()
        .find(|l| l.contains("did not reopen") && l.contains(&room[..12]))
        .map(str::to_owned);
    println!(
        "[proof] the room is listed closed: {}; the daemon said: {note:?}",
        listed.contains("[closed]")
    );
    assert!(
        listed.contains("[closed]"),
        "PRODUCT (staging): the room reopened although its reopen was made to fail:\n{listed}"
    );
    assert!(
        note.as_deref().is_some_and(|n| n.contains(why)),
        "PRODUCT: a room that did not reopen was not named in the daemon's log with why:\n{said}"
    );
}
