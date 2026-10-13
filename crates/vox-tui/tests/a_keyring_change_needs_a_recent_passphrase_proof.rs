//! **A keyring change needs the identity passphrase unless one was entered for a keyring change
//! in the last 30 minutes, whatever the client; attaching opens no window** (V210-159, decider
//! 2026-10-02, option A; ADR-028 K-12) — driven through the shipped binary and its control socket.
//! Run on demand, with the `test-knobs` feature: `VOX_TEST_KEYRING_WINDOW_SECS` shortens the
//! window to [`WINDOW`].
//!
//! **An agent-marked CLI cannot widen trust** (ADR-031 LT-8, #677): with an empty identity
//! passphrase and within a protected node's open window, each existing harness marker makes
//! `trust add` and `trust drive` refuse with the operator-only sentence and leave the keyring
//! unchanged. The same unmarked commands succeed. Refusal precedes naming and passphrase prompts,
//! including at a terminal. These marks are staged apparatus, not a live-harness observation.
//!
//! Asserted, against a `vox daemon` given its passphrase in `VOX_IDENTITY_PASSPHRASE`:
//! 1. right after the attach, a `vox trust add` with no passphrase and no terminal is refused at
//!    once saying the passphrase is needed, nothing changes, and `vox status` says the keyring asks
//!    for the passphrase (K-12: the attach's passphrase opens no window);
//!    with both nodes' windows closed, Alice creates a room and Bob joins, binds a repository to
//!    it, and leaves, giving only the distinct room passphrase. Each command has stdin open and
//!    unwritten, and must finish without identity authorization (ADR-031 KP-1, #734). Room lists
//!    and `vox agent status` show the results; neither node's keyring window opens;
//! 2. **the passphrase is typed, and taken from nothing else** (K-13): a `vox trust add` with
//!    `VOX_IDENTITY_PASSPHRASE` set, and one with `--identity-passphrase-file`, are refused and
//!    change nothing; the same add typed at a terminal (a pty) is made; then `vox status` says
//!    `keyring open Nm` (K-9), and a second trust add with no passphrase is made;
//! 3. past the window, `vox trust remove` with no passphrase is refused at once and nothing
//!    changes, and `vox status` says the keyring asks for the passphrase;
//! 4. past the window, a raw control-socket `Trust` with no passphrase is refused the same way; one
//!    with a wrong passphrase is refused; one with the right passphrase succeeds;
//! 5. past the window again, a `vox trust add` with none is refused, and a `vox trust remove`
//!    typed at a terminal succeeds.
//!
//! **A change given the right passphrase is always made.** Every change whose passphrase was just
//! checked waits [`PROVED_DELAY`], longer than [`WINDOW`], between the check and the change
//! (`VOX_TEST_PROVED_CHANGE_DELAY_MS`), as when the clock moves on between the two. The
//! right-passphrase changes of 2, 4 and 5 must still succeed.
//!
//! **What an entry grants is part of it** (ADR-028 K-14, #525): in 2 bob is trusted with `--drive`
//! and `vox trust list` says `read + drive`; in 3, past the window, `vox trust read` with no
//! passphrase is refused for it and bob still has drive; in 4 carol is trusted with drive over the
//! raw socket; in 5, typed at a terminal, `vox trust read` makes bob `read`; and 6, carol still
//! has drive after the daemon restarts, when the keyring is read back from the disk.
//!
//! Mutations: the window opened at the attach — red, PRODUCT (1: the change with no passphrase is
//! made). `VOX_IDENTITY_PASSPHRASE` read for a keyring change again — red, PRODUCT (2: the change
//! given the variable is made). No window check in the node — red, PRODUCT (the change past the
//! window is made). A change given the right passphrase put through the window like one given none
//! — red, PRODUCT (it is refused as needing the passphrase it was given). The window reported open after it closed —
//! red, PRODUCT. The capability dropped when the keyring is saved — red, PRODUCT (6: carol reads
//! `read` after the restart).
//! Adding an identity-passphrase requirement to room create, join, bind or leave — red, PRODUCT:
//! the room command is refused or waits instead of completing with only the room passphrase.
//! Removing the agent-session refusal — red, PRODUCT: a marked `trust add` succeeds on the
//! empty-passphrase node instead of refusing.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/attach.rs"]
mod attach;

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[path = "support/typed.rs"]
mod typed;

use std::io::BufRead as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use vox_core::node::ipc::{Frame, Request};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity pass phrase";
const KNOB: &str = "VOX_TEST_KEYRING_WINDOW_SECS";
/// The shortened window.
const WINDOW: Duration = Duration::from_secs(6);
/// How long a refused change may take to be refused: at once.
const ANSWERS_WITHIN: Duration = Duration::from_secs(10);
/// Every change whose passphrase was just checked waits this long between the check and the
/// change (`VOX_TEST_PROVED_CHANGE_DELAY_MS`): past [`WINDOW`], so the change finds the window the
/// check restarted already gone, and must be made anyway.
const PROVED_DELAY: Duration = Duration::from_secs(8);
const DELAY_KNOB: &str = "VOX_TEST_PROVED_CHANGE_DELAY_MS";
const AGENT_REFUSAL: &str = "vox: to grant trust or drive, run this command in your own terminal or in Vox.app outside the agent session.";

fn vox_cmd(dir: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(VOX);
    c.args(args);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("VOX_")
            || matches!(
                k.to_str(),
                Some("CLAUDE_CODE_SESSION_ID" | "CODEX_THREAD_ID")
            )
        {
            c.env_remove(k);
        }
    }
    c.env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"));
    c
}

/// A command with stdin open and unwritten and no terminal, as an agent's harness runs it:
/// (succeeded, what it said). Red past [`ANSWERS_WITHIN`] (plus [`PROVED_DELAY`], which a
/// change given its passphrase waits by design).
fn run(cmd: &mut Command) -> (bool, String) {
    // A real join may do the production proof of work. Give it the product's patience, as the
    // other room journeys do; ordinary commands retain the short no-input bound.
    let bound = if cmd.get_args().any(|a| a == "join") {
        Duration::from_secs(540)
    } else {
        ANSWERS_WITHIN + PROVED_DELAY
    };
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(cmd, || {
            rustix::process::setsid()?;
            Ok(())
        });
    }
    let t0 = Instant::now();
    let mut child = cmd.spawn().expect("APPARATUS: spawn vox");
    let held = child.stdin.take();
    while child.try_wait().expect("APPARATUS: wait").is_none() {
        if t0.elapsed() > bound {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "PRODUCT: `vox {:?}` was still waiting with stdin open and unwritten after \
                 {bound:?}",
                cmd.get_args().collect::<Vec<_>>()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(held);
    let out = child.wait_with_output().expect("APPARATUS: output");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn profile(root: &Path, name: &str, passphrase: &str) -> (std::path::PathBuf, String) {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).expect("APPARATUS: profile dir");
    let out = vox_cmd(&dir, &["id"])
        .env("VOX_IDENTITY_PASSPHRASE", passphrase)
        .stdin(Stdio::null())
        .output()
        .expect("APPARATUS: spawn vox id");
    assert!(
        out.status.success(),
        "CANNOT MEASURE: `vox id` did not make {name}'s identity: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (dir, String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// The line `vox trust list` gives `fp`, or nothing.
fn entry<'a>(list: &'a str, fp: &str) -> &'a str {
    list.lines().find(|l| l.starts_with(fp)).unwrap_or_default()
}

/// Reap every scratch daemon even when a product assertion fails.
struct Daemon(std::process::Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `vox daemon` on `dir`, unlocked from the environment with the shortened window, and where its
/// control socket is, if it said.
fn start_daemon(dir: &Path, passphrase: &str) -> (Daemon, Option<std::path::PathBuf>) {
    let mut daemon = vox_cmd(dir, &["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_IDENTITY_PASSPHRASE", passphrase)
        .env(KNOB, WINDOW.as_secs().to_string())
        .env(DELAY_KNOB, PROVED_DELAY.as_millis().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("APPARATUS: spawn vox daemon");
    let mut out = std::io::BufReader::new(daemon.stdout.take().expect("APPARATUS: stdout"));
    let mut line = String::new();
    while out.read_line(&mut line).is_ok_and(|n| n > 0) {
        if let Some(at) = line.trim().strip_prefix("vox daemon: control socket ") {
            let sock = std::path::PathBuf::from(at);
            // Drained, so the daemon never blocks on a full pipe.
            std::thread::spawn(move || std::io::copy(&mut out, &mut std::io::sink()));
            return (Daemon(daemon), Some(sock));
        }
        line.clear();
    }
    (Daemon(daemon), None)
}

/// Room commands do not borrow the identity authorization of a keyring change (ADR-031 KP-1).
/// Both identities are protected, already unlocked, and have never authorized a keyring change.
fn rooms_with_closed_keyrings(root: &Path, alice: &Path, bob: &Path, carol: &str) {
    let (_peer, sock) = start_daemon(bob, IDPASS);
    assert!(
        sock.is_some(),
        "APPARATUS: Bob's daemon did not announce its control socket"
    );
    let room_pass = root.join("room-passphrase");
    std::fs::write(&room_pass, "a separate room pass phrase\n")
        .expect("APPARATUS: room passphrase file");
    let pass_file = room_pass.to_str().expect("APPARATUS: path");
    let repo = root.join("bound-repo");
    let home = root.join("harness-home");
    std::fs::create_dir_all(&repo).expect("APPARATUS: repository directory");
    std::fs::create_dir_all(home.join(".claude")).expect("APPARATUS: harness directory");
    std::fs::write(
        home.join(".claude/settings.json"),
        r#"{"hooks":{"UserPromptSubmit":[{"hooks":[{"type":"command","command":"vox agent hook --node default"}]}]}}"#,
    )
    .expect("APPARATUS: wire the scratch harness to Bob's node");
    let repo = std::fs::canonicalize(repo).expect("APPARATUS: canonical repository");
    let dir = repo.to_str().expect("APPARATUS: path");
    let closed = |node: &Path| {
        let (ok, said) = run(&mut vox_cmd(node, &["status"]));
        assert!(
            ok && said.lines().any(|l| l == "keyring asks for the passphrase")
                && !said.contains("keyring open"),
            "PRODUCT: room commands must leave the keyring window closed; status said: {said}"
        );
    };
    let room_command = |node: &Path, args: &[&str], expected: &str| {
        closed(node);
        let (ok, said) = run(&mut vox_cmd(node, args));
        assert!(
            ok && said.contains(expected) && !said.contains("identity passphrase"),
            "PRODUCT: `vox {args:?}` with the keyring window closed must complete without \
             identity-passphrase authorization; succeeded {ok}, said:\n{said}"
        );
        closed(node);
        eprintln!("[proof] closed keyring, `vox {args:?}`: {said}");
    };

    room_command(
        alice,
        &[
            "room",
            "create",
            "--name",
            "keyring-scope",
            "--passphrase-file",
            pass_file,
        ],
        "vox: created keyring-scope",
    );
    let (ok, invite) = run(&mut vox_cmd(alice, &["room", "link", "keyring-scope"]));
    assert!(ok, "PRODUCT: the created room must be invitable: {invite}");
    let link = invite
        .lines()
        .find(|l| l.starts_with("vox://"))
        .unwrap_or_else(|| panic!("PRODUCT: room invite gave no room address: {invite}"));
    let room = link
        .trim_start_matches("vox://")
        .split('?')
        .next()
        .unwrap_or_else(|| panic!("PRODUCT: room invite gave no room ID: {invite}"));
    let short: String = room.chars().take(12).collect();
    room_command(
        bob,
        &["room", "join", link, "--passphrase-file", pass_file],
        "vox: joined keyring-scope",
    );
    for node in [alice, bob] {
        let (ok, listed) = run(&mut vox_cmd(node, &["room", "list"]));
        assert!(
            ok && listed.contains("keyring-scope"),
            "PRODUCT: each node must list the created and joined room: {listed}"
        );
    }
    room_command(
        bob,
        &[
            "room",
            "join",
            link,
            "--passphrase-file",
            pass_file,
            "--bind",
            dir,
        ],
        &format!("vox: bound {dir}"),
    );
    let (ok, binding) = run(vox_cmd(
        bob,
        &["agent", "status", "--harness", "claude", "--dir", dir],
    )
    .env("HOME", &home)
    .env("CLAUDE_CONFIG_DIR", home.join(".claude")));
    assert!(
        ok && binding.contains(&format!("this repo ({dir}) works in room {short}.")),
        "PRODUCT: the bound repository must work in the joined room: {binding}"
    );
    room_command(bob, &["room", "leave", "keyring-scope"], "vox: left room");
    let (ok, listed) = run(&mut vox_cmd(bob, &["room", "list"]));
    assert!(
        ok && !listed.contains("keyring-scope"),
        "PRODUCT: leaving must remove the room from Bob's room list: {listed}"
    );
    let (ok, said) = run(&mut vox_cmd(
        bob,
        &["trust", "add", carol, "--name", "control"],
    ));
    assert!(
        !ok && said.contains("identity passphrase") && !trusted(bob).contains(carol),
        "PRODUCT: after the room commands a keyring change must still need the identity \
         passphrase and leave the keyring unchanged: {said}"
    );
}

fn trusted(dir: &Path) -> String {
    let (ok, said) = run(&mut vox_cmd(dir, &["trust", "list"]));
    assert!(
        ok,
        "PRODUCT: `vox trust list` failed against the running node: {said}"
    );
    said
}

/// A raw `Trust` request on the control socket, as any client of it sends one.
fn raw_trust(sock: &Path, target: &str, petname: &str, passphrase: &str, drive: bool) -> Frame {
    let target =
        vox_core::node::link::b32_decode(target, "fingerprint").expect("APPARATUS: a fingerprint");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("APPARATUS: runtime");
    rt.block_on(async {
        // The account socket, as node `default` (ADR-026 C-2): what every client sends on.
        let mut client = attach::client_at(sock, "default")
            .await
            .unwrap_or_else(|e| panic!("CANNOT MEASURE: the control socket did not answer: {e}"));
        tokio::time::timeout(
            ANSWERS_WITHIN + PROVED_DELAY,
            client.request(&Request::Trust {
                target,
                petname: petname.to_owned(),
                identity_passphrase: zeroize::Zeroizing::new(passphrase.to_owned()),
                full_history: false,
                drive,
            }),
        )
        .await
        .expect("PRODUCT: a raw Trust request was not answered in time")
        .expect("PRODUCT: a raw Trust request broke the connection")
    })
}

/// Every supported shell marker refuses both widening verbs, regardless of keyring authorization.
fn marked_refusals(dir: &Path, newcomer: &str, read_only: &str) {
    let before = trusted(dir);
    for marker in ["VOX_SESSION", "CLAUDE_CODE_SESSION_ID", "CODEX_THREAD_ID"] {
        for args in [
            vec!["trust", "add", newcomer, "--name", "newcomer"],
            vec!["trust", "add", newcomer, "--name", "newcomer", "--drive"],
            vec!["trust", "drive", read_only],
        ] {
            let (ok, said) = run(vox_cmd(dir, &args).env(marker, "keyring-agent"));
            assert!(
                !ok && said.trim() == AGENT_REFUSAL,
                "PRODUCT: {marker}-marked `vox {args:?}` must refuse a trust widening with the \
                 operator-only sentence; succeeded {ok}, said:\n{said}"
            );
        }
    }
    let after = trusted(dir);
    assert_eq!(
        after, before,
        "PRODUCT: refused agent-marked trust commands must leave the visible keyring unchanged"
    );
    eprintln!("[proof] all three harness markers refused trust add/drive: {AGENT_REFUSAL}");
}

/// The original LT-8 failure: an empty passphrase must not authorize a marked agent's grants.
fn empty_passphrase_refusals(root: &Path, bob: &str, carol: &str) {
    let (dir, _) = profile(root, "no-passphrase", "");
    let (_daemon, sock) = start_daemon(&dir, "");
    assert!(
        sock.is_some(),
        "APPARATUS: empty-passphrase daemon did not start"
    );
    let (ok, said) = run(&mut vox_cmd(&dir, &["trust", "add", bob, "--name", "bob"]));
    assert!(
        ok && entry(&trusted(&dir), bob).ends_with("bob  read"),
        "PRODUCT: the person's unmarked trust add must work with an empty passphrase: {said}"
    );
    marked_refusals(&dir, carol, bob);
    let (ok, said) = run(&mut vox_cmd(&dir, &["trust", "drive", bob]));
    assert!(
        ok && entry(&trusted(&dir), bob).ends_with("bob  read + drive"),
        "PRODUCT: the person's unmarked trust drive must work with an empty passphrase: {said}"
    );
}

#[test]
fn a_keyring_change_past_the_window_needs_the_passphrase_from_every_client() {
    watchdog::arm();
    test_knobs::require(&[KNOB, DELAY_KNOB]);
    let needed = vox_core::node::api::Fault::PassphraseNeeded.explain();
    let needed_first = needed.lines().next().unwrap_or_default();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let (alice, _) = profile(tmp.path(), "alice", IDPASS);
    let (bob_dir, bob) = profile(tmp.path(), "bob", IDPASS);
    let (_, carol) = profile(tmp.path(), "carol", IDPASS);
    let (_, dave) = profile(tmp.path(), "dave", IDPASS);
    let (_, erin) = profile(tmp.path(), "erin", IDPASS);
    let pass_file = tmp.path().join("idpass");
    std::fs::write(&pass_file, format!("{IDPASS}\n")).expect("APPARATUS: passphrase file");

    empty_passphrase_refusals(tmp.path(), &bob, &carol);

    // Refuse even before selecting a node or asking for the missing trust name.
    let (ok, said) = run(
        vox_cmd(&tmp.path().join("not-attached"), &["trust", "add", &bob])
            .env("VOX_SESSION", "keyring-agent"),
    );
    assert!(
        !ok && said.trim() == AGENT_REFUSAL,
        "PRODUCT: a marked trust add must refuse before naming or daemon access: {said}"
    );

    let (daemon, sock) = start_daemon(&alice, IDPASS);
    let Some(sock) = sock else {
        panic!("CANNOT MEASURE: the daemon never said where its control socket is");
    };
    let kill = drop;

    // A terminal and a correct passphrase do not make an agent-marked process the person.
    for args in [
        vec!["trust", "add", bob.as_str()],
        vec!["trust", "add", bob.as_str(), "--name", "bob"],
    ] {
        let (ok, said) = typed::typed(
            vox_cmd(&alice, &args).env("CODEX_THREAD_ID", "keyring-agent"),
            IDPASS,
        );
        assert!(
            !ok && said.trim() == AGENT_REFUSAL,
            "PRODUCT: a marked terminal must refuse before naming or passphrase prompts: {said}"
        );
    }

    // 1. Right after the attach: the attach's passphrase opened no window (K-12).
    let (ok, said) = run(&mut vox_cmd(
        &alice,
        &["trust", "add", &bob, "--name", "bob"],
    ));
    let list = trusted(&alice);
    if ok || !said.contains(needed_first) || list.contains(&bob) {
        kill(daemon);
        panic!(
            "PRODUCT: right after the attach, `vox trust add` with no passphrase must be refused \
             for it: attaching opens no keyring window (ADR-028 K-12). It succeeded {ok}, \
             saying:\n{said}\nthe keyring now:\n{list}"
        );
    }
    let (ok, attach_said) = run(&mut vox_cmd(&alice, &["status"]));
    if !(ok
        && attach_said
            .lines()
            .any(|l| l == "keyring asks for the passphrase")
        && !attach_said.contains("keyring open"))
    {
        kill(daemon);
        panic!(
            "PRODUCT: right after the attach, `vox status` must say the keyring asks for the \
             passphrase (ADR-028 K-12); it said:\n{attach_said}"
        );
    }

    // KP-1: only changing the keyring needs this authorization, never room work.
    rooms_with_closed_keyrings(tmp.path(), &alice, &bob_dir, &carol);

    // 2. K-13: the passphrase is typed, never taken from the environment or a file.
    let add_bob = ["trust", "add", bob.as_str(), "--name", "bob", "--drive"];
    let (by_variable, variable_said) =
        run(vox_cmd(&alice, &add_bob).env("VOX_IDENTITY_PASSPHRASE", IDPASS));
    let (by_file, file_said) = run(&mut vox_cmd(
        &alice,
        &[
            &add_bob[..],
            &[
                "--identity-passphrase-file",
                pass_file.to_str().expect("APPARATUS: path"),
            ],
        ]
        .concat(),
    ));
    let list = trusted(&alice);
    if by_variable || by_file || list.contains(&bob) {
        kill(daemon);
        panic!(
            "PRODUCT: a keyring change must take its passphrase only as typed at a terminal \
             (ADR-028 K-13): with VOX_IDENTITY_PASSPHRASE set it succeeded {by_variable}, \
             saying:\n{variable_said}\nwith --identity-passphrase-file it succeeded {by_file}, \
             saying:\n{file_said}\nthe keyring now:\n{list}"
        );
    }
    // Typed at a terminal: made, and the window opens.
    let (ok, said) = typed::typed(&vox_cmd(&alice, &add_bob), IDPASS);
    let entered = Instant::now();
    if !ok {
        kill(daemon);
        panic!(
            "PRODUCT: `vox trust add` with the passphrase typed at a terminal was refused: {said}"
        );
    }
    // K-14: bob was trusted with drive, and the list says so.
    let drive_list = trusted(&alice);
    if !entry(&drive_list, &bob).ends_with("bob  read + drive") {
        kill(daemon);
        panic!(
            "PRODUCT: bob was trusted with --drive, and `vox trust list` must say `read + drive` \
             for him; it said:\n{drive_list}"
        );
    }
    let (ok, open_said) = run(&mut vox_cmd(&alice, &["status"]));
    let (again_ok, again_said) = run(&mut vox_cmd(
        &alice,
        &["trust", "add", &erin, "--name", "erin"],
    ));
    let in_window = entered.elapsed() < WINDOW;
    if !(ok && open_said.lines().any(|l| l.starts_with("keyring open ")) && again_ok) {
        kill(daemon);
        if !in_window {
            panic!(
                "CANNOT MEASURE: the checks after the keyring change ran past the {WINDOW:?} \
                 window"
            );
        }
        panic!(
            "PRODUCT: within the window a keyring change opened, `vox status` must say `keyring \
             open Nm` and a second change needs no passphrase; status said:\n{open_said}\nthe \
             second change (succeeded {again_ok}):\n{again_said}"
        );
    }

    marked_refusals(&alice, &dave, &erin);
    let (drive_ok, drive_said) = run(&mut vox_cmd(&alice, &["trust", "drive", &erin]));
    assert!(
        entered.elapsed() < WINDOW,
        "APPARATUS: the marked-refusal controls ran past the open {WINDOW:?} keyring window"
    );
    assert!(
        drive_ok && entry(&trusted(&alice), &erin).ends_with("erin  read + drive"),
        "PRODUCT: the person's unmarked trust drive must work inside the keyring window: {drive_said}"
    );

    // 3. Past the window, the CLI with nothing to give: refused at once, nothing changed.
    std::thread::sleep((WINDOW + Duration::from_secs(2)).saturating_sub(entered.elapsed()));
    let (ok, said) = run(&mut vox_cmd(&alice, &["trust", "remove", &bob]));
    let list = trusted(&alice);
    if ok || !said.contains(needed_first) || !list.contains(&bob) {
        kill(daemon);
        panic!(
            "PRODUCT: past the window, `vox trust remove` with no passphrase was not refused for \
             it (succeeded {ok}); it said:\n{said}\nthe keyring now:\n{list}"
        );
    }

    // K-14: changing what an entry grants is a keyring change, refused past the window for want
    // of the passphrase, and nothing changes.
    let (read_ok, read_said) = run(&mut vox_cmd(&alice, &["trust", "read", &bob]));
    let list = trusted(&alice);
    if read_ok || !read_said.contains(needed_first) || !entry(&list, &bob).ends_with("read + drive")
    {
        kill(daemon);
        panic!(
            "PRODUCT: past the window, `vox trust read` with no passphrase must be refused for it \
             and leave bob with drive (succeeded {read_ok}); it said:\n{read_said}\nthe \
             keyring now:\n{list}"
        );
    }

    // K-9: past the window, `vox status` says a keyring change will ask for the passphrase.
    let (ok, closed_said) = run(&mut vox_cmd(&alice, &["status"]));
    if !(ok
        && closed_said
            .lines()
            .any(|l| l == "keyring asks for the passphrase")
        && !closed_said.contains("keyring open"))
    {
        kill(daemon);
        panic!(
            "PRODUCT: past the window, `vox status` must say the keyring asks for the passphrase, \
             not that it is open; it said:\n{closed_said}"
        );
    }
    eprintln!(
        "[proof] vox status, open: {:?}; past the window: {:?}",
        open_said.lines().find(|l| l.starts_with("keyring")),
        closed_said.lines().find(|l| l.starts_with("keyring"))
    );

    // 4. Past the window, a raw socket request: none given, then a wrong one, then the right one,
    // which trusts carol with drive (K-14).
    let none = raw_trust(&sock, &carol, "carol", "", true);
    let wrong = raw_trust(&sock, &carol, "carol", "not the passphrase", true);
    let after_refusals = trusted(&alice);
    let right = raw_trust(&sock, &carol, "carol", IDPASS, true);
    let after_right = trusted(&alice);
    let refused = |f: &Frame| matches!(f, Frame::Error { .. });
    if !matches!(&none, Frame::Error { reason } if reason == needed)
        || !refused(&wrong)
        || after_refusals.contains(&carol)
        || right != Frame::Ok
        || !after_right.contains(&carol)
    {
        kill(daemon);
        panic!(
            "PRODUCT: past the window, the control socket did not refuse a Trust without the \
             passphrase and make it with it.\n none given: {none:?}\n wrong: {wrong:?}\n right: \
             {right:?}\nkeyring after the refusals:\n{after_refusals}\nafter the right \
             one:\n{after_right}"
        );
    }

    // 5. Past the window again: the CLI given the passphrase typed at a terminal.
    std::thread::sleep(WINDOW + Duration::from_secs(2));
    let (refused_ok, refused_said) = run(&mut vox_cmd(
        &alice,
        &["trust", "add", &dave, "--name", "d"],
    ));
    // K-14: typed at a terminal, `vox trust read` makes bob read only.
    let (to_read, to_read_said) = typed::typed(&vox_cmd(&alice, &["trust", "read", &bob]), IDPASS);
    let read_list = trusted(&alice);
    let given = typed::typed(&vox_cmd(&alice, &["trust", "remove", &bob]), IDPASS);
    let list = trusted(&alice);
    kill(daemon);
    assert!(
        to_read && entry(&read_list, &bob).ends_with("bob  read"),
        "PRODUCT: `vox trust read` typed at a terminal must make bob `read`: \
         {to_read_said}\nthe keyring:\n{read_list}"
    );
    assert!(
        !refused_ok && refused_said.contains(needed_first) && !list.contains(&dave),
        "PRODUCT: past the window again, `vox trust add` with no passphrase was not refused for \
         it: {refused_said}\nthe keyring:\n{list}"
    );
    assert!(
        given.0 && !list.contains(&bob),
        "PRODUCT: past the window, `vox trust remove` typed at a terminal did not make the \
         change: {}\nthe keyring:\n{list}",
        given.1
    );
    eprintln!("the window held for the CLI and the control socket alike; the keyring:\n{list}");

    // 6. K-14: what an entry grants is saved with it. The daemon starts again and reads the
    // keyring back from the disk: carol, trusted with drive over the socket, still has it.
    let (again, sock_again) = start_daemon(&alice, IDPASS);
    if sock_again.is_none() {
        kill(again);
        panic!("CANNOT MEASURE: the restarted daemon never said where its control socket is");
    }
    let restarted = trusted(&alice);
    kill(again);
    assert!(
        entry(&restarted, &carol).ends_with("carol  read + drive"),
        "PRODUCT: carol was trusted with drive, and after the daemon restarted `vox trust list` \
         must still say `read + drive` for her; it said:\n{restarted}"
    );
}
