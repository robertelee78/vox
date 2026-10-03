//! **Two nodes of one `vox daemon` answer at one address, and a detach leaves the other there**
//! (ADR-026 §9.1's network half, D-3, D-5; #403), every participant the shipped `vox` binary.
//!
//! **Staging.** One account runs `vox daemon --node a` on `127.0.0.1:0`; node `b` is attached to the
//! same daemon by its agent's hook. Where the daemon listens is `.daemon/port`, the data root's one
//! port. A remote, on an account of its own, runs `vox serve` told that both `a` and `b` are anchors
//! at that one address.
//!
//! **What must hold.**
//! 1. The remote connects to `a` and to `b`, both at the daemon's one ip:port: the daemon answers
//!    as whichever node the dial names (the identity exchange), and neither binds a socket of its
//!    own.
//! 2. Once `b` detaches (its only session ends), a second remote told the same is answered by `a`
//!    at that address and told that nothing there answers as `b`.
//!
//! A red is PRODUCT, quoting what the processes said; a daemon or remote that never got going is
//! PRODUCT (staging).
//!
//! **The mutant that must turn it red:** a bind per node (the interim before the presence: every
//! node after the first on a port of its own) — `b` is then not at the daemon's address.
//!
//! `#[ignore]`d: production Argon2id. Run it in release.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use world::{args, echo_service, mkdir, tempdir, vox_once, VoxProc, IDENTITY, VOX};

/// Make node `name` in the account at `dir`, as a person does (`vox node create`): its
/// fingerprint.
fn make_node(dir: &Path, name: &str) -> String {
    let pf = pass_file(dir);
    let (ok, out, err) = vox_once(
        dir,
        &args(&["node", "create", name, "--passphrase-file", &pf]),
    );
    assert!(ok, "APPARATUS: vox node create {name}: {out}{err}");
    let (ok, out, err) = vox_once(dir, &args(&["id", "--node", name]));
    assert!(ok, "APPARATUS: vox --node {name} id: {out}{err}");
    out.trim().to_owned()
}

/// The identity passphrase in a file under `dir`, for the verbs that read one.
fn pass_file(dir: &Path) -> String {
    let p = dir.join("identity.pass");
    std::fs::write(&p, format!("{IDENTITY}\n")).expect("APPARATUS: passphrase file");
    p.to_str().expect("APPARATUS: utf-8 path").to_owned()
}

/// An agent hook turn of `session` as node `node`, in the account at `dir`.
fn hook(dir: &Path, node: &str, session: &str, event: &str) -> (bool, String) {
    let mut child = Command::new(VOX)
        .args(["agent", "hook", "--node", node])
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env("VOX_LISTEN", "127.0.0.1:0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: spawn vox agent hook: {e}"));
    let input = format!(r#"{{"hook_event_name":"{event}","session_id":"{session}"}}"#);
    let _ = child
        .stdin
        .take()
        .expect("APPARATUS: stdin")
        .write_all(input.as_bytes());
    let out = child.wait_with_output().expect("APPARATUS: hook output");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn short(fp: &str) -> String {
    fp.chars().take(26).collect()
}

/// A remote on its own account at `dir` (node `r`, its own daemon), serving an echo service and
/// told `a` and `b` are anchors at `at`.
fn remote(dir: &Path, at: &str, a: &str, b: &str) -> VoxProc {
    mkdir(&dir.join("cfg"));
    let _ = make_node(dir, "r");
    let pf = pass_file(dir);
    let service = echo_service().to_string();
    VoxProc::spawn(
        "remote",
        dir,
        &args(&[
            "serve",
            "--node",
            "r",
            "--identity-passphrase-file",
            &pf,
            &format!("{service}={service}"),
            "--anchor",
            &format!("{a}@{at}"),
            "--anchor",
            &format!("{b}@{at}"),
            "--listen",
            "127.0.0.1:0",
        ]),
    )
}

#[test]
#[ignore = "real vox daemons and production Argon2id; run in release"]
fn two_nodes_answer_at_one_address_and_a_detach_leaves_the_other() {
    watchdog::arm();
    let tmp = tempdir();
    let home = tmp.path().join("h");
    mkdir(&home.join("cfg"));
    let fa = make_node(&home, "a");
    let fb = make_node(&home, "b");
    let pass = tmp.path().join("pass");
    std::fs::write(&pass, format!("{IDENTITY}\n")).expect("APPARATUS: passphrase file");
    let mut daemon = VoxProc::spawn(
        "daemon",
        &home,
        &args(&[
            "daemon",
            "--node",
            "a",
            "--passphrase-file",
            pass.to_str().expect("APPARATUS: utf-8 path"),
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    daemon.expect_staging("its identity", |l| l.contains("vox daemon: identity"));
    let (ok, said) = hook(&home, "b", "s-b", "UserPromptSubmit");
    assert!(ok, "PRODUCT (staging): b's hook failed: {said}");
    daemon.expect_staging("node b attached", |l| {
        l.contains("vox daemon: node b attached")
    });
    let port: u16 = std::fs::read_to_string(home.join(".daemon/port"))
        .ok()
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or_else(|| panic!("PRODUCT (staging): the daemon recorded no port"));
    let at = format!("/ip4/127.0.0.1/udp/{port}");
    eprintln!(
        "[proof] the daemon listens on 127.0.0.1:{port}; a = {}, b = {}",
        short(&fa),
        short(&fb)
    );

    // 1. Both nodes, one address.
    let mut r1 = remote(&tmp.path().join("r1"), &at, &fa, &fb);
    for (name, fp) in [("a", &fa), ("b", &fb)] {
        let connected = format!("connection to {} — connected to this anchor", short(fp));
        let got = r1.line_within(Duration::from_secs(60), |l| l.contains(&connected));
        assert!(
            got.is_some(),
            "PRODUCT: the remote did not reach node {name} at the daemon's one address \
             127.0.0.1:{port}.\nremote:\n{}\ndaemon:\n{}",
            r1.transcript(),
            daemon.transcript()
        );
        eprintln!("[proof] the remote reached node {name} at 127.0.0.1:{port}");
    }
    drop(r1);

    // 2. b detaches; a is still there, and nothing answers as b.
    let (ok, said) = hook(&home, "b", "s-b", "SessionEnd");
    assert!(ok, "PRODUCT (staging): b's SessionEnd failed: {said}");
    daemon.expect_staging("node b detached", |l| {
        l.contains("vox daemon: node b detached")
    });
    let t0 = Instant::now();
    let mut r2 = remote(&tmp.path().join("r2"), &at, &fa, &fb);
    let a_line = format!("connection to {} — connected to this anchor", short(&fa));
    let reached_a = r2.line_within(Duration::from_secs(60), |l| l.contains(&a_line));
    assert!(
        reached_a.is_some(),
        "PRODUCT: after b detached, node a was not reachable at 127.0.0.1:{port}.\nremote:\n{}\n\
         daemon:\n{}",
        r2.transcript(),
        daemon.transcript()
    );
    let nothing = format!("nothing at 127.0.0.1:{port} answers as {}", short(&fb));
    let refused_b = r2.line_within(Duration::from_secs(60), |l| l.contains(&nothing));
    assert!(
        refused_b.is_some(),
        "PRODUCT: after b detached, the remote was not told nothing at the address answers as b.\n\
         remote:\n{}",
        r2.transcript()
    );
    eprintln!(
        "[proof] after b detached: a reached, b refused, {:?} after the second remote started",
        t0.elapsed()
    );
}

/// **The daemon reads its relay limits from `.daemon/config`** (ADR-012 N-45, ADR-026 F-2): a
/// value that is not a number stops it, naming the key, instead of running on the built-in limits.
/// (The limits holding is proved on the presence's ledger in process.) Mutant: the daemon not
/// reading `.daemon/config`.
#[test]
#[ignore = "real vox daemon; run in release"]
fn the_daemon_reads_its_relay_limits_from_its_config() {
    watchdog::arm();
    let tmp = tempdir();
    let home = tmp.path().join("h");
    mkdir(&home.join("cfg"));
    mkdir(&home.join(".daemon"));
    std::fs::write(home.join(".daemon/config"), "relay-circuits = many\n")
        .expect("APPARATUS: write .daemon/config");
    let mut child = Command::new(VOX)
        .args(["daemon", "--listen", "127.0.0.1:0"])
        .env("VOX_DATA_DIR", &home)
        .env("VOX_CONFIG_DIR", home.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("APPARATUS: run vox daemon");
    // Bounded: a daemon that ignores its config runs on, and is stopped here by its own PID.
    let t0 = Instant::now();
    while child.try_wait().ok().flatten().is_none() && t0.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(100));
    }
    let ran_on = child.try_wait().ok().flatten().is_none();
    if ran_on {
        let _ = child.kill();
    }
    let out = child.wait_with_output().expect("APPARATUS: daemon output");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!(
        "[proof] vox daemon with `relay-circuits = many` said: {}",
        said.trim()
    );
    assert!(
        !ran_on && !out.status.success() && said.contains("relay-circuits"),
        "PRODUCT: a daemon whose config sets relay-circuits to no number must stop and name it; \
         it exited {} saying: {said}",
        out.status
    );
}
