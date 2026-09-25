//! PRD-001 R30/R31 — **an app embeds the node**, proved with the shipped artifact driven
//! the way an app drives it.
//!
//! `scripts/build-xcframework.sh` builds `VoxFFI.xcframework` and its Swift bindings; a
//! Swift program (`crates/vox-ffi/swift-harness/main.swift`) is compiled with `swiftc`
//! against the macOS slice, so what runs is the static library an app links and the Swift
//! an app calls — nothing in between. On the other side is a real `vox daemon`, driven by
//! the real `vox` verbs.
//!
//! What must hold:
//!
//! 1. The embedded node joins a room the daemon created, and its post shows in the
//!    daemon's `vox room read`.
//! 2. A message the daemon posts reaches the Swift program **through its event
//!    listener**.
//! 3. An app stream from Swift to a `vox app listen` on the daemon carries a mebibyte
//!    there and back, SHA-256 equal, and a datagram flow carries 100 datagrams there and
//!    back.

#![cfg(target_os = "macos")]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vox_core::node::actor::Node;
use vox_core::node::api::{NodeCommand, Secret};
use vox_core::node::paths::Paths;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const TIMEOUT: Duration = Duration::from_secs(120);

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A child, killed by its PID however the test ends.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Daemon {
    data: PathBuf,
    cfg: PathBuf,
}

impl Daemon {
    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(VOX);
        c.args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env("VOX_IDENTITY_PASSPHRASE", "daemon identity")
            .env_remove("VOX_ROOM")
            .env_remove("VOX_ANCHORS");
        c
    }

    fn run(&self, args: &[&str], stdin: &str) -> String {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "vox {args:?} failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

/// Build the xcframework and the harness, exactly as a person would.
fn build_harness(out: &Path) -> PathBuf {
    let status = Command::new(root().join("scripts/build-xcframework.sh"))
        .env("OUT", out)
        .status()
        .expect("run build-xcframework.sh");
    assert!(status.success(), "build-xcframework.sh failed");
    let lib = out.join("VoxFFI.xcframework/macos-arm64_x86_64");
    let harness = out.join("harness");
    let swiftc = Command::new("swiftc")
        .arg("-O")
        .arg("-o")
        .arg(&harness)
        .arg(root().join("crates/vox-ffi/swift-harness/main.swift"))
        .arg(out.join("swift/vox_ffi.swift"))
        .arg("-I")
        .arg(lib.join("Headers"))
        .arg("-L")
        .arg(&lib)
        .args([
            "-lvox_ffi",
            "-framework",
            "Security",
            "-framework",
            "SystemConfiguration",
        ])
        .output()
        .expect("run swiftc");
    assert!(
        swiftc.status.success(),
        "swiftc failed: {}",
        String::from_utf8_lossy(&swiftc.stderr)
    );
    harness
}

/// Read a child's stdout on a thread, as lines.
fn lines(from: impl std::io::Read + Send + 'static) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(from).lines() {
            let Ok(line) = line else { return };
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    rx
}

/// Wait for a line starting with `prefix`, keeping every line seen.
fn expect(rx: &mpsc::Receiver<String>, seen: &Arc<Mutex<Vec<String>>>, prefix: &str) -> String {
    if let Some(l) = seen.lock().unwrap().iter().find(|l| l.starts_with(prefix)) {
        return l.clone();
    }
    let until = Instant::now() + TIMEOUT;
    while Instant::now() < until {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                seen.lock().unwrap().push(line.clone());
                if line.starts_with("ERROR") {
                    panic!("the harness failed: {line}");
                }
                if line.starts_with(prefix) {
                    return line;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    panic!(
        "the harness never said {prefix:?}; it said: {:?}",
        seen.lock().unwrap()
    );
}

/// A `vox app listen` on the daemon whose output is fed straight back into it: an echo.
/// `limit` bytes are echoed, then its input ends.
fn echo_listener(d: &Daemon, room: &str, label: &str, limit: Option<usize>) -> Proc {
    let mut child = d
        .command(&["app", "listen", room, label])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut from = child.stdout.take().unwrap();
    let mut into: ChildStdin = child.stdin.take().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        let mut echoed = 0;
        while limit.is_none_or(|l| echoed < l) {
            match from.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if into.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = into.flush();
                    echoed += n;
                }
            }
        }
    });
    Proc(child)
}

#[test]
#[ignore = "builds the xcframework, compiles Swift, runs a real daemon; CI runs it in release on macOS"]
fn a_swift_app_embeds_the_node_and_talks_to_a_daemon() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let harness = build_harness(&tmp.path().join("build"));

    // The daemon's identity, made once, then the profile handed to a real `vox daemon`.
    let d = Daemon {
        data: tmp.path().join("daemon/data"),
        cfg: tmp.path().join("daemon/cfg"),
    };
    let daemon_fp = {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let paths = Paths::resolve("default", Some(&d.data), Some(&d.cfg)).unwrap();
            let node = Node::spawn_networked(paths, "127.0.0.1:0".parse().unwrap()).unwrap();
            assert!(node
                .apply(NodeCommand::CreateIdentity {
                    passphrase: Secret::new(b"daemon identity".to_vec()),
                })
                .await
                .is_done());
            let fp = node.view().identity.unwrap().fingerprint;
            assert!(node.apply(NodeCommand::Shutdown).await.is_done());
            vox_core::node::link::b32_encode(&fp)
        })
    };
    let mut daemon = d
        .command(&["daemon", "--listen", "127.0.0.1:0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    daemon
        .stdin
        .take()
        .unwrap()
        .write_all(b"daemon identity\n")
        .unwrap();
    let daemon_out = lines(daemon.stdout.take().unwrap());
    let _daemon = Proc(daemon);
    let dseen = Arc::new(Mutex::new(Vec::new()));
    expect(&daemon_out, &dseen, "vox daemon: control socket");

    d.run(&["room", "create", "--name", "calls"], "room passphrase\n");
    let room = d
        .run(&["room", "list"], "")
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    let link = d.run(&["room", "invite", &room], "").trim().to_owned();

    // The app.
    let mut app = Command::new(&harness)
        .args([
            tmp.path().join("app").to_str().unwrap(),
            &link,
            "room passphrase",
            &daemon_fp,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut to_app = app.stdin.take().unwrap();
    let from_app = lines(app.stdout.take().unwrap());
    let _app = Proc(app);
    let seen = Arc::new(Mutex::new(Vec::new()));

    let app_fp = expect(&from_app, &seen, "FP ")[3..].to_owned();
    let joined = expect(&from_app, &seen, "JOINED ");
    expect(&from_app, &seen, "POSTED");
    // The daemon decides to trust the app, as a person would with `vox trust add`.
    d.run(&["trust", "add", &app_fp, "--name", "swift"], "");

    // (1) The app's post, as the daemon's own `vox room read` shows it.
    let until = Instant::now() + TIMEOUT;
    let mut read = String::new();
    while Instant::now() < until {
        read = d.run(&["room", "read", &room], "");
        if read.contains("hello from swift") {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    // The daemon's listeners, then the daemon's message, then go.
    let _echo = echo_listener(&d, &room, "echo/v1", Some(1 << 20));
    let _dgram = echo_listener(&d, &room, "dgram/v1", None);
    std::thread::sleep(Duration::from_secs(1));
    d.run(&["room", "post", &room, "hello from daemon"], "");
    writeln!(to_app).unwrap();

    // (3) The app stream and the datagram flow.
    let stream = expect(&from_app, &seen, "STREAM ");
    let dgrams = expect(&from_app, &seen, "DGRAMS ");
    // (2) The daemon's message, through the event listener.
    let got = expect(&from_app, &seen, "GOT hello from daemon");
    writeln!(to_app).unwrap();
    expect(&from_app, &seen, "DONE");

    eprintln!(
        "{joined}\ndaemon's read shows the app's post: {}\n{stream}\n{dgrams}\n{got}\nall the \
         harness said: {:?}",
        read.contains("hello from swift"),
        seen.lock().unwrap()
    );
    assert!(
        read.contains("hello from swift"),
        "the daemon must read the app's post: {read}"
    );
    let parts: Vec<&str> = stream.split_whitespace().collect();
    assert_eq!(parts[1], "1048576", "a mebibyte must come back: {stream}");
    assert_eq!(
        parts[2], parts[4],
        "and be byte-for-byte what was sent: {stream}"
    );
    assert_eq!(dgrams, "DGRAMS 100", "all 100 datagrams must come back");
    assert_eq!(got, "GOT hello from daemon");
}
