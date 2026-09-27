//! **A failed attach says why, in a person's words** (#191, V210-18) — driven through the
//! shipped binary.
//!
//! Every verb that talks to a running node first attaches to its control socket. When the
//! socket file exists but the attach fails, the CLI said "a control socket exists … but nothing
//! answered — the node may have stopped", and threw the actual error away. Four different
//! failures read as that one sentence: a refused connect (a stale socket), a node that closed
//! before greeting, a node speaking another control protocol, and a malformed frame. On
//! 2026-09-25 a drain proof's model got that sentence from a `vox` of another version while the
//! node was live and answering, and nothing in the message could tell the two apart. Carrying
//! the raw error was not enough either: the handshake failures read "malformed identity bundle:
//! ipc protocol version", which names a problem that does not exist.
//!
//! What it asserts, for `vox room list` against three sockets that each fail one way, on the
//! words a person reads:
//!
//! 1. a **stale socket** (bound, then its listener gone): "nothing is listening on it", the OS
//!    reason, and that the node may have stopped;
//! 2. a socket that **closes before greeting**: "the node closed the connection before
//!    greeting";
//! 3. a node on **another protocol**: "speaks a different control protocol", both protocol
//!    numbers, and "update one of them" — and *not* that the node may have stopped, which is
//!    false there.
//!
//! No message may say "identity bundle", and each exits non-zero.
//!
//! Mutations, each red: the old `attach`, which drops the error (0 of 3); the new `attach` over
//! the old errors, "malformed identity bundle: …" (red on the identity-bundle words).

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::Write as _;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::Command;

use vox_core::node::ipc::{Frame, PROTOCOL_VERSION};

const VOX: &str = env!("CARGO_BIN_EXE_vox");

/// `vox room list` against the profile at `dir`: (exit ok, stderr).
fn room_list(dir: &Path) -> (bool, String) {
    let out = Command::new(VOX)
        .args(["room", "list"])
        .env("VOX_DATA_DIR", dir.join("d"))
        .env("VOX_CONFIG_DIR", dir.join("c"))
        .env_remove("VOX_ROOM")
        .env_remove("VOX_ANCHORS")
        .output()
        .expect("run vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A fresh profile directory and where its control socket goes.
fn profile() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let sock_dir = tmp.path().join("d").join("default");
    std::fs::create_dir_all(&sock_dir).unwrap();
    std::fs::create_dir_all(tmp.path().join("c")).unwrap();
    let sock = sock_dir.join("node.sock");
    (tmp, sock)
}

/// Serve one connection on `sock` with `answer`, on a thread.
fn serve_once(sock: &Path, answer: impl FnOnce(std::os::unix::net::UnixStream) + Send + 'static) {
    let l = UnixListener::bind(sock).unwrap();
    std::thread::spawn(move || {
        if let Ok((s, _)) = l.accept() {
            answer(s);
        }
    });
}

/// Run the case; how many of `said` it said, and how many of `unsaid` it avoided.
fn check(case: &str, dir: &Path, said: &[&str], unsaid: &[&str]) -> (usize, usize) {
    let (ok, err) = room_list(dir);
    eprintln!("[receipt] {case}: exit ok={ok}\n  stderr: {}", err.trim());
    assert!(!ok, "{case}: `vox room list` must fail: {err}");
    let hit = said.iter().filter(|w| err.contains(*w)).count();
    let avoided = unsaid.iter().filter(|w| !err.contains(*w)).count();
    eprintln!(
        "[receipt] {case}: says {hit} of {} expected phrases, avoids {avoided} of {} wrong ones",
        said.len(),
        unsaid.len()
    );
    for w in said {
        assert!(err.contains(w), "{case}: the message must say {w:?}: {err}");
    }
    for w in unsaid {
        assert!(
            !err.contains(w),
            "{case}: the message must not say {w:?}: {err}"
        );
    }
    (hit, avoided)
}

#[test]
fn a_failed_attach_says_why_in_a_persons_words() {
    watchdog::arm();
    let internal = ["identity bundle", "ipc "];

    // (1) A stale socket: the file is there, nobody listens.
    let (stale, sock) = profile();
    drop(UnixListener::bind(&sock).unwrap());
    check(
        "stale socket",
        stale.path(),
        &[
            "nothing is listening on it",
            "Connection refused",
            "may have stopped",
        ],
        &internal,
    );

    // (2) A node that closes before greeting.
    let (closed, sock) = profile();
    serve_once(&sock, drop);
    check(
        "closed before greeting",
        closed.path(),
        &["the node closed the connection before greeting"],
        &internal,
    );

    // (3) A node on another protocol: a well-formed greeting with another version.
    let (other, sock) = profile();
    serve_once(&sock, |mut s| {
        let body = Frame::Hello {
            protocol: PROTOCOL_VERSION + 1,
            me: None,
        }
        .to_bytes();
        let len = u32::try_from(body.len()).unwrap().to_be_bytes();
        let _ = s.write_all(&len);
        let _ = s.write_all(&body);
        std::thread::sleep(std::time::Duration::from_secs(2));
    });
    let mine = format!("this vox is protocol {PROTOCOL_VERSION}");
    let theirs = format!("the node is protocol {}", PROTOCOL_VERSION + 1);
    let mut unsaid = internal.to_vec();
    unsaid.push("may have stopped");
    check(
        "other protocol",
        other.path(),
        &[
            "speaks a different control protocol",
            &mine,
            &theirs,
            "update one of them",
        ],
        &unsaid,
    );
    eprintln!("[receipt] 3 of 3 failures said in a person's words");
}
