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
//! What it asserts, for `vox room list` against the data root's account socket (ADR-026 C-1) failing
//! three ways, on the words a person reads:
//!
//! 1. a **stale socket** (bound, then its listener gone): no vox daemon is running for this data
//!    root, and how to start one;
//! 2. a socket that **closes before greeting**: it accepted, "the node closed the connection before
//!    greeting", and that it may be stopping;
//! 3. a daemon on **another protocol**: "speaks a different control protocol", both protocol
//!    numbers, and "update one of them" — and *not* that it may be stopping, which is false there.
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
        .expect("APPARATUS: run vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A fresh data root holding node `default` (made by `vox id`), and where the data root's
/// account socket goes (`<data>/.daemon/vox.sock`, ADR-026 C-1): every verb reaches its node
/// through it.
fn profile() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let (data, cfg) = (tmp.path().join("d"), tmp.path().join("c"));
    std::fs::create_dir_all(&cfg).expect("APPARATUS: create a staging directory");
    let made = Command::new(VOX)
        .args(["id"])
        .env("VOX_DATA_DIR", &data)
        .env("VOX_CONFIG_DIR", &cfg)
        .env("VOX_IDENTITY_PASSPHRASE", "identity passphrase")
        .output()
        .expect("APPARATUS: run vox id");
    assert!(
        made.status.success(),
        "PRODUCT (staging): vox id: {}",
        String::from_utf8_lossy(&made.stderr)
    );
    let sock = vox_core::node::paths::Account::of(Some(&data), Some(&cfg))
        .expect("APPARATUS: the account")
        .socket();
    std::fs::create_dir_all(sock.parent().expect("APPARATUS: a socket has a directory"))
        .expect("APPARATUS: create the socket's directory");
    (tmp, sock)
}

/// Serve every connection on `sock` with `answer`, on a thread — holding the data root's daemon lock
/// (`<socket's dir>/lock`) meanwhile, as a daemon does, so a client takes what answers there for
/// the daemon and reaches it.
fn serve_once(sock: &Path, answer: impl Fn(std::os::unix::net::UnixStream) + Send + 'static) {
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(sock.with_file_name("lock"))
        .expect("APPARATUS: the daemon lock");
    lock.try_lock().expect("APPARATUS: take the daemon lock");
    let l = UnixListener::bind(sock).expect("APPARATUS: bind a socket");
    // Every connection the same way: a client may look at the daemon's greeting (to resolve its
    // node) before it opens the connection it sends its request on.
    std::thread::spawn(move || {
        let _held = lock;
        for s in l.incoming().map_while(Result::ok) {
            answer(s);
        }
    });
}

/// Run the case; how many of `said` it said, and how many of `unsaid` it avoided.
fn check(case: &str, dir: &Path, said: &[&str], unsaid: &[&str]) -> (usize, usize) {
    let (ok, err) = room_list(dir);
    eprintln!("[receipt] {case}: exit ok={ok}\n  stderr: {}", err.trim());
    assert!(!ok, "PRODUCT: {case}: `vox room list` must fail: {err}");
    let hit = said.iter().filter(|w| err.contains(*w)).count();
    let avoided = unsaid.iter().filter(|w| !err.contains(*w)).count();
    eprintln!(
        "[receipt] {case}: says {hit} of {} expected phrases, avoids {avoided} of {} wrong ones",
        said.len(),
        unsaid.len()
    );
    for w in said {
        assert!(
            err.contains(w),
            "PRODUCT: {case}: the message must say {w:?}: {err}"
        );
    }
    for w in unsaid {
        assert!(
            !err.contains(w),
            "PRODUCT: {case}: the message must not say {w:?}: {err}"
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
    drop(UnixListener::bind(&sock).expect("APPARATUS: bind a socket"));
    check(
        "stale socket",
        stale.path(),
        // Since ADR-026 a refused connect means no daemon holds the data root: said as that,
        // with how to start one.
        &[
            "no vox daemon is running for this data root",
            "Start one:  vox daemon",
        ],
        &internal,
    );

    // (2) A node that closes before greeting.
    let (closed, sock) = profile();
    serve_once(&sock, drop);
    check(
        "closed before greeting",
        closed.path(),
        &[
            "accepted, but the node closed the connection before greeting",
            "may be stopping",
        ],
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
        let len = u32::try_from(body.len())
            .expect("APPARATUS: a request the proof built fits in u32")
            .to_be_bytes();
        let _ = s.write_all(&len);
        let _ = s.write_all(&body);
        std::thread::sleep(std::time::Duration::from_secs(2));
    });
    let mine = format!("this vox is protocol {PROTOCOL_VERSION}");
    let theirs = format!("the node is protocol {}", PROTOCOL_VERSION + 1);
    let mut unsaid = internal.to_vec();
    unsaid.push("may be stopping");
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
