//! PRD-001 R30/R31, ADR-014 M-2–M-6 — **a Swift app uses Vox through VoxFFI**, proved with the
//! shipped artifact driven the way an app drives it.
//!
//! `scripts/build-xcframework.sh` builds `VoxFFI.xcframework` and its Swift bindings; two Swift
//! programs (`crates/vox-ffi/swift-harness/{client,node}/main.swift`) are compiled with `swiftc`
//! against the macOS slice, so what runs is the static library an app links and the Swift an app
//! calls — nothing in between. Every other participant is the shipped `vox` binary, driven by the
//! real `vox` verbs.
//!
//! **The macOS app's client** (`VoxClient`, ADR-014 M-2): the Swift program hosts no node. It
//! reaches the account's real `vox daemon`, attaches a node made by `vox node create` with that
//! node's passphrase, and acts as it. What must hold:
//!
//! 1. It joins a room a peer (a second `vox daemon`, its own data root) created, and its post shows
//!    in the peer's `vox room read`; read back at once, its own room holds the post: a post is
//!    answered once the node has it.
//! 2. A message the peer posts reaches the Swift program **through its listener**.
//! 3. `lanUp` brings the app's node onto the room's family LAN through the root helper, here a
//!    stand-in answering the helper's protocol (apparatus, no root: `support/lan_standin.rs`):
//!    the helper is asked for the node's LAN addresses, the answer names the interface it handed
//!    over, the LAN says the port it was told to allow, and `lanDown` takes it down (ADR-013,
//!    ADR-014 M-10, #439). The real helper and `utun` are `scripts/family-lan-proof.sh`.
//! 4. When the client closes, the daemon detaches the node it attached (`vox node list` says
//!    `detached`): the app's hold ends with it (M-6).
//!
//! **The iOS app's embedded node** (`VoxNode`, ADR-026 S-4's exception): the Swift program runs
//! the node in its own process, against a real `vox daemon`. What must hold:
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

#[path = "support/lan_standin.rs"]
mod lan_standin;

use std::io::{BufRead as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

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
    /// The identity passphrase its verbs are given.
    identity: &'static str,
}

impl Daemon {
    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(VOX);
        c.args(args)
            .env("VOX_DATA_DIR", &self.data)
            .env("VOX_CONFIG_DIR", &self.cfg)
            .env("VOX_IDENTITY_PASSPHRASE", self.identity)
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

/// The two Swift programs, built once for every test in this binary.
struct Harnesses {
    /// `swift-harness/client`: the macOS app's `VoxClient`.
    client: PathBuf,
    /// `swift-harness/node`: the iOS app's `VoxNode`.
    node: PathBuf,
}

/// Build the xcframework and both harnesses, exactly as a person would, once.
fn harnesses() -> &'static Harnesses {
    static BUILT: OnceLock<(tempfile::TempDir, Harnesses)> = OnceLock::new();
    &BUILT
        .get_or_init(|| {
            let dir = tempfile::tempdir().unwrap();
            let built = build_harnesses(dir.path());
            (dir, built)
        })
        .1
}

fn build_harnesses(out: &Path) -> Harnesses {
    // The script runs rustup and cargo: they get the operator's toolchain homes. Under the
    // proof's temporary HOME the rustup proxy found no toolchain, downloaded a bare one, and the
    // script refused for want of the iOS targets the operator's toolchain has.
    let built = watchdog::temp_home::real_toolchain(
        Command::new(root().join("scripts/build-xcframework.sh"))
            .env("OUT", out)
            // The macOS slice is all a macOS app links, and all this proof runs.
            .env("XCFRAMEWORK_SLICES", "macos"),
    )
    .output()
    .expect("APPARATUS: could not start build-xcframework.sh");
    if !built.status.success() {
        // A red names its reason and its side: a toolchain this machine lacks is the machine's,
        // anything else the script (shipped with vox) did is the product's.
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&built.stdout),
            String::from_utf8_lossy(&built.stderr)
        );
        let side = if said.contains("is not installed; run: rustup target add") {
            "CANNOT MEASURE (precondition unmet): this machine lacks a Rust target the \
             xcframework needs"
        } else {
            "PRODUCT (staging)"
        };
        panic!(
            "{side}: build-xcframework.sh exited {}; it said:\n{said}",
            built.status
        );
    }
    let lib = out.join("VoxFFI.xcframework/macos-arm64");
    let swiftc = |program: &str| {
        let harness = out.join(format!("{program}-harness"));
        let swiftc = Command::new("swiftc")
            .arg("-O")
            .arg("-o")
            .arg(&harness)
            .arg(root().join(format!("crates/vox-ffi/swift-harness/{program}/main.swift")))
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
            .expect("APPARATUS: could not start swiftc");
        assert!(
            swiftc.status.success(),
            "PRODUCT (staging): swiftc refused the {program} harness against the generated \
             bindings: {}",
            String::from_utf8_lossy(&swiftc.stderr)
        );
        harness
    };
    Harnesses {
        client: swiftc("client"),
        node: swiftc("node"),
    }
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
                    panic!("PRODUCT: a VoxFFI call failed in the Swift program: {line}");
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
        "PRODUCT: the Swift program never said {prefix:?} (each line follows a VoxFFI call \
         answering); it said: {:?}",
        seen.lock().unwrap()
    );
}

impl Daemon {
    /// Start a real `vox daemon` on this data root with `stdin` piped in, and wait until its
    /// control socket is up. Its stdout is kept read for as long as it runs.
    fn start(&self, stdin: &str) -> (Proc, mpsc::Receiver<String>) {
        let mut daemon = self
            .command(&["daemon", "--listen", "127.0.0.1:0"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("APPARATUS: could not start vox daemon");
        daemon
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = lines(daemon.stdout.take().unwrap());
        let daemon = Proc(daemon);
        let seen = Arc::new(Mutex::new(Vec::new()));
        expect(&out, &seen, "vox daemon: control socket");
        (daemon, out)
    }

    /// A room this daemon's node creates, and its link.
    fn room(&self) -> (String, String) {
        self.run(
            &[
                "room",
                "create",
                "--passphrase-file",
                "-",
                "--name",
                "calls",
            ],
            "room passphrase\n",
        );
        let room = self
            .run(&["room", "list"], "")
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        let link = self.run(&["room", "link", &room], "").trim().to_owned();
        (room, link)
    }

    /// Its node's identity, made by `vox id` as a person setting up a profile would.
    fn id(&self) -> String {
        let fp = self.run(&["id"], "").trim().to_owned();
        assert_eq!(
            fp.len(),
            vox_core::node::link::B32_DIGEST_LEN,
            "PRODUCT: `vox id` must print the whole fingerprint: {fp:?}"
        );
        fp
    }

    /// Wait until this daemon's `vox room read` shows `text`, and return what it showed.
    fn read_until(&self, room: &str, text: &str) -> String {
        let until = Instant::now() + TIMEOUT;
        let mut read = String::new();
        while Instant::now() < until {
            read = self.run(&["room", "read", room], "");
            if read.contains(text) {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        read
    }
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
    let tmp = tempfile::tempdir().unwrap();
    // Built before the watchdog is armed: the build is a release compile of the workspace plus
    // the bindings, minutes on a CI runner, and the 600 s budget bounds a hung *proof*, not cargo
    // (#257: the watchdog killed aws-lc-sys's build script mid-compile).
    let harness = &harnesses().node;
    watchdog::arm();

    // The daemon's identity, then the profile handed to a real `vox daemon`.
    let d = Daemon {
        data: tmp.path().join("daemon/data"),
        cfg: tmp.path().join("daemon/cfg"),
        identity: "daemon identity",
    };
    let daemon_fp = d.id();
    let (_daemon, _daemon_out) = d.start("daemon identity\n");
    let (room, link) = d.room();

    // The app.
    let mut app = Command::new(harness)
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
    let read = d.read_until(&room, "hello from swift");

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

#[test]
#[ignore = "builds the xcframework, compiles Swift, runs two real daemons; run on macOS by hand"]
fn a_swift_app_acts_as_a_node_through_the_daemon() {
    let tmp = tempfile::tempdir().unwrap();
    // Built before the watchdog is armed, as above.
    let harness = &harnesses().client;
    watchdog::arm();

    // The peer: another data root, its own `vox daemon`, its node made by `vox id`.
    let peer = Daemon {
        data: tmp.path().join("peer/data"),
        cfg: tmp.path().join("peer/cfg"),
        identity: "peer identity",
    };
    let peer_fp = peer.id();
    let (_peer_daemon, _peer_out) = peer.start("peer identity\n");
    let (room, link) = peer.room();

    // The app's data root: its daemon runs first, with no node, then the node is made by
    // `vox node create`, so nothing but the app attaches it.
    let mine = Daemon {
        data: tmp.path().join("app/data"),
        cfg: tmp.path().join("app/cfg"),
        identity: "alice identity",
    };
    let (_daemon, _daemon_out) = mine.start("");
    mine.run(&["node", "create", "alice"], "");

    let mut app = Command::new(harness)
        .args([
            mine.data.to_str().unwrap(),
            "alice",
            "alice identity",
            &link,
            "room passphrase",
            &peer_fp,
        ])
        .env("VOX_DATA_DIR", &mine.data)
        .env("VOX_CONFIG_DIR", &mine.cfg)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("APPARATUS: could not start the Swift program");
    let mut to_app = app.stdin.take().unwrap();
    let from_app = lines(app.stdout.take().unwrap());
    let _app = Proc(app);
    let seen = Arc::new(Mutex::new(Vec::new()));

    let app_fp = expect(&from_app, &seen, "FP ")[3..].to_owned();
    let listed = mine.run(&["node", "list"], "");
    let joined = expect(&from_app, &seen, "JOINED ");
    let posted = expect(&from_app, &seen, "POSTED ");
    // The peer decides to trust the app's node, as a person would with `vox trust add`.
    peer.run(&["trust", "add", &app_fp, "--name", "swift"], "");

    // (1) The app's post, as the peer's own `vox room read` shows it.
    let read = peer.read_until(&room, "hello from swift");
    // (2) The peer's message, through the listener.
    peer.run(&["room", "post", &room, "hello from the peer"], "");
    writeln!(to_app).unwrap();
    let got = expect(&from_app, &seen, "GOT hello from the peer");
    // (3) The family LAN, through a stand-in helper.
    let helper = tmp.path().join("helper.sock");
    let os = lan_standin::Os::default();
    os.serve(&helper);
    writeln!(to_app, "{}", helper.display()).unwrap();
    let lan_up = expect(&from_app, &seen, "LAN_UP ");
    let lan_said = expect(&from_app, &seen, "LAN_SAID ");
    expect(&from_app, &seen, "LAN_DOWN");
    let asked = os.asked.lock().unwrap().clone();
    // (4) The app closes; the daemon lets the node go.
    writeln!(to_app).unwrap();
    expect(&from_app, &seen, "CLOSED");
    let until = Instant::now() + TIMEOUT;
    let mut after = String::new();
    while Instant::now() < until {
        after = mine.run(&["node", "list"], "");
        if after
            .lines()
            .any(|l| l.starts_with("alice") && l.contains("detached"))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    eprintln!(
        "{joined}\nwhile attached, `vox node list` said: {listed}{posted}\npeer's read shows the \
         app's post: {}\n{got}\nhelper asked {asked:?}; {lan_up}; {lan_said}\nafter close, `vox node list` said: {after}all the Swift program \
         said: {:?}",
        read.contains("hello from swift"),
        seen.lock().unwrap()
    );
    assert!(
        listed
            .lines()
            .any(|l| l.starts_with("alice") && l.contains("attached") && !l.contains("detached")),
        "PRODUCT: the app's attach must show in `vox node list` as attached; it said: {listed}"
    );
    assert_eq!(
        posted, "POSTED 1",
        "PRODUCT: a post answered must be in the room read back at once, exactly once"
    );
    assert!(
        read.contains("hello from swift"),
        "PRODUCT: the peer must read the app's post: {read}"
    );
    assert_eq!(got, "GOT hello from the peer");
    assert!(
        asked.len() == 1
            && asked[0].starts_with("up 100.")
            && asked[0]
                .split_whitespace()
                .nth(2)
                .is_some_and(|v6| v6.starts_with("fd")),
        "PRODUCT: `lanUp` must ask the helper once for the node's LAN addresses (100.64.0.0/10, \
         fd00::/8); it asked {asked:?}"
    );
    assert!(
        lan_up.starts_with("LAN_UP vox lan up on utun-standin"),
        "PRODUCT: `lanUp` must answer once the LAN is up on the interface the helper handed over; \
         it said {lan_up:?}"
    );
    assert!(
        lan_said.contains("reachable over the LAN: ports 5000"),
        "PRODUCT: the LAN must carry the port `lanUp` was told to allow, as `vox lan up --allow` \
         says it; it said {lan_said:?}"
    );
    assert!(
        after
            .lines()
            .any(|l| l.starts_with("alice") && l.contains("detached")),
        "PRODUCT: once the app closed, its node must be detached; `vox node list` said: {after}"
    );
}
