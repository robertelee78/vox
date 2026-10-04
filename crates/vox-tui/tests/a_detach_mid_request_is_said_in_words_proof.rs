//! ADR-026 L-3 and PRD-001 R36 (#406) — a one-shot verb whose node is detached while its request
//! is in flight stops with a sentence that says so, and exits non-zero. It printed
//! `vox: unexpected reply: NodeDetached { node: NodeName("n") }`, a struct dump. Driven through
//! the shipped `vox` binary, as a person types it:
//!
//! ```text
//! vox node create n
//! vox daemon --node n …              (its secret work staged slow: VOX_TEST_SECRET_WORK_DELAY_MS)
//! vox room create --node n --name r … (in flight: its seal is held by the knob)
//! vox node detach n                   (while the create waits)
//! ```
//!
//! The claim: the create exits non-zero saying "node n was detached from the vox daemon, so this
//! stopped", and prints no frame's debug form. Mutant: the `NodeDetached` arm dropped from
//! `client::unexpected`, red as `PRODUCT: the create did not say its node was detached`.

#![cfg(all(unix, feature = "test-knobs"))]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");

/// How long the daemon holds each piece of secret work: long enough to detach mid-seal.
const SEAL_MS: u64 = 8_000;

/// A child `vox`, stopped by its own PID when dropped.
struct Kid(Child);

impl Drop for Kid {
    fn drop(&mut self) {
        let _ = Command::new("kill").arg(self.0.id().to_string()).status();
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if self.0.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn vox(root: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(VOX);
    cmd.args(args)
        .env("VOX_DATA_DIR", root.join("data"))
        .env("VOX_CONFIG_DIR", root.join("cfg"))
        .env_remove("VOX_NODE")
        .env_remove("VOX_PROFILE")
        .env_remove("VOX_IDENTITY_PASSPHRASE")
        .env_remove("VOX_ANCHORS")
        .env_remove("VOX_LISTEN")
        .env_remove("VOX_TEST_SECRET_WORK_DELAY_MS")
        .stdin(Stdio::null());
    cmd
}

/// Run to its end: success, stdout + stderr.
fn run(root: &Path, args: &[&str]) -> (bool, String) {
    let out = vox(root, args).output().expect("APPARATUS: run vox");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
#[ignore = "real vox daemon with production Argon2id; run on demand in release"]
fn a_one_shot_verb_says_in_words_that_its_node_was_detached_mid_request() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let root = tmp.path();
    std::fs::create_dir_all(root.join("cfg")).expect("APPARATUS: harness file I/O");
    let id_pass = root.join("id.pass");
    let room_pass = root.join("room.pass");
    std::fs::write(&id_pass, "n's identity passphrase\n").expect("APPARATUS: harness file I/O");
    std::fs::write(&room_pass, "r's room passphrase\n").expect("APPARATUS: harness file I/O");
    let id_pass = id_pass.to_str().unwrap();

    let (ok, said) = run(root, &["node", "create", "n", "--passphrase-file", id_pass]);
    assert!(ok, "PRODUCT (staging): vox node create n failed:\n{said}");

    // ---- the daemon, its secret work staged slow, holding n ---------------------------------
    let log = std::fs::File::create(root.join("daemon.log")).expect("APPARATUS: harness file I/O");
    let _daemon = Kid(vox(
        root,
        &[
            "daemon",
            "--node",
            "n",
            "--listen",
            "127.0.0.1:0",
            "--passphrase-file",
            id_pass,
        ],
    )
    .env("VOX_TEST_SECRET_WORK_DELAY_MS", SEAL_MS.to_string())
    .stdout(Stdio::from(log.try_clone().expect("APPARATUS: log")))
    .stderr(Stdio::from(log))
    .spawn()
    .expect("APPARATUS: spawn vox daemon"));
    let daemon_said = || std::fs::read_to_string(root.join("daemon.log")).unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let (_, out) = run(root, &["node", "list"]);
        if out
            .lines()
            .any(|l| l.split_whitespace().take(2).eq(["n", "attached"]))
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): n never showed attached:\n{out}\ndaemon:\n{}",
            daemon_said()
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // ---- a room create in flight, and a detach under it --------------------------------------
    let started = Instant::now();
    let create = vox(
        root,
        &[
            "room",
            "create",
            "--node",
            "n",
            "--name",
            "r",
            "--passphrase-file",
            room_pass.to_str().unwrap(),
        ],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .expect("APPARATUS: spawn vox room create");
    std::thread::sleep(Duration::from_secs(2));
    let (detached, detach_said) = run(root, &["node", "detach", "n"]);
    let out = create
        .wait_with_output()
        .expect("APPARATUS: wait for vox room create");
    let took = started.elapsed();
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    println!(
        "[proof] room create exited {:?} after {:.1} s, saying: {}",
        out.status.code(),
        took.as_secs_f64(),
        said.trim()
    );
    assert!(
        detached,
        "PRODUCT (staging): vox node detach n failed:\n{detach_said}"
    );
    assert!(
        took >= Duration::from_secs(2),
        "CANNOT MEASURE: the create ended in {:.1} s, before the detach was sent: {said}",
        took.as_secs_f64()
    );
    assert!(
        !out.status.success(),
        "PRODUCT: the create succeeded although its node was detached while it ran (ADR-026 L-3): \
         {said}"
    );

    // ---- the claim ------------------------------------------------------------------------
    assert!(
        said.contains("node n was detached from the vox daemon, so this stopped"),
        "PRODUCT: the create did not say its node was detached: {said}"
    );
    assert!(
        !said.contains("NodeDetached") && !said.contains("NodeName(") && !said.contains(" { "),
        "PRODUCT: the create printed a frame's debug form: {said}"
    );
}
