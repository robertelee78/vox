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
//! 3. A service the peer shares (`vox service add`) is listed by `services` at the address the
//!    app's own `vox service list` prints, with the commands (each with the canonical address)
//!    and needs `vox service list --json` gives (ADR-028 S-3, #444); `forward` to that address
//!    carries bytes to the peer's
//!    service and back; `stopForward` ends it; `status` is the report `vox status --json` gives
//!    for the same node (ADR-014 #436).
//! 4. A file the app shares to the peer (`share`, with a note) is served: the peer's node pulls
//!    it by itself into its files directory, byte for byte, and `shares` lists it as the app's own
//!    `vox share list` does. A file the peer shares to the app (`vox share --to`) is pulled by the
//!    app's node by itself, and `pulled` gives where, byte for byte (ADR-028 F-1–F-4, #436).
//! 5. `lanUp` brings the app's node onto the room's family LAN through the root helper, here a
//!    stand-in answering the helper's protocol (apparatus, no root: `support/lan_standin.rs`):
//!    the helper is asked for the node's LAN addresses, the answer names the interface it handed
//!    over, the LAN says the port it was told to allow, and `lanDown` takes it down (ADR-013,
//!    ADR-014 M-10, #439). The real helper and `utun` are `scripts/family-lan-proof.sh`.
//! 6. When the client closes, the daemon detaches the node it attached (`vox node list` says
//!    `detached`): the app's hold ends with it (M-6).
//!
//! 6. **One-step sharing** (ADR-028 S-4, #444): with a stand-in listening on every interface,
//!    `listening` lists it (its port, `every_interface`) and says under the list that another
//!    user's listeners may be missing; `servicePreview` says, before anything is shared, that it
//!    listens on every interface; `serviceAdd` with the preview's tag and endpoint shares it, and
//!    the peer reaches it by its own `vox service list` and `vox forward`.
//!
//! 7. **What a message carries for showing, and a room's name**: a message the peer posts with
//!    a link carries the card the peer's node fetched (ADR-028 F-10), and `read` gives its title,
//!    description and image; the image the peer's file share announced (F-9) comes with its
//!    dimensions, a JPEG thumbnail and a BlurHash. Once the peer has pulled the app's file share
//!    whole, `pulledBy` names it, by the app's name for it, against that share's announcement
//!    (F-7). `renameRoom` on the peer's room is refused
//!    with the node's own sentence; on a room the app created and the peer joined, it renames
//!    the room for both, and the peer's own `vox room list` shows the new name (R-1). The card
//!    is fetched from a local server, so this test needs `--features vox-tui/test-knobs`
//!    (`VOX_TEST_CARD_ALLOW`) and refuses as CANNOT MEASURE without it.
//!
//! Mutant for (3): `services` drops the address (`SharedService.address` empty): red PRODUCT.
//! Mutant for (3): the FFI's commands carry the readable address: red PRODUCT.
//! Mutant for (6): `servicePreview` says no warning: red PRODUCT.
//! Mutants for (7), one per claim, each red PRODUCT: `RoomMessage.card` always nil;
//! `RoomMessage.image` always nil; `renameRoom` answers without asking the node; `pulledBy`
//! always empty.
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

#[path = "support/test_knobs.rs"]
mod test_knobs;
#[path = "support/typed.rs"]
mod typed;
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
        // A keyring change's passphrase is typed at a terminal, as a person types it (ADR-028
        // K-13).
        if typed::is_keyring_change(args) {
            let (ok, shown) = typed::keyring(&self.command(args));
            assert!(
                ok,
                "PRODUCT (staging): `vox {}` failed: {shown}",
                args.join(" ")
            );
            return shown;
        }
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
            "PRODUCT (staging): `vox {}` failed: {}{}",
            args.join(" "),
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

/// A local web server answering `/page` with a page naming a title, a description and an image,
/// and `/img.png` with [`CARD_IMAGE`].
fn card_server() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("APPARATUS: bind the link card's local server");
    let at = listener
        .local_addr()
        .expect("APPARATUS: the server's address");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut buf) {
                    Ok(n) if n > 0 => head.extend_from_slice(&buf[..n]),
                    _ => break,
                }
            }
            let path = String::from_utf8_lossy(&head)
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            let (ty, body): (&str, Vec<u8>) = if path == "/img.png" {
                ("image/png", CARD_IMAGE.to_vec())
            } else {
                (
                    "text/html; charset=utf-8",
                    b"<html><head><title>Fallback</title>\
                      <meta property=\"og:title\" content=\"The quarterly report\">\
                      <meta property=\"og:description\" content=\"Numbers &amp; notes for Q3\">\
                      <meta property=\"og:image\" content=\"/img.png\"></head></html>"
                        .to_vec(),
                )
            };
            let _ = s.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {ty}\r\nContent-Length: {}\r\nConnection: \
                     close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = s.write_all(&body);
        }
    });
    at
}

/// The image the card's page names: 1 KB, well under what a card carries.
const CARD_IMAGE: &[u8; 1024] = &[0x5a; 1024];

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
#[ignore = "builds the xcframework, compiles Swift, runs two real daemons; run on macOS by hand, with `--features vox-tui/test-knobs`"]
fn a_swift_app_acts_as_a_node_through_the_daemon() {
    let tmp = tempfile::tempdir().unwrap();
    // Built before the watchdog is armed, as above.
    let harness = &harnesses().client;
    test_knobs::require(&["VOX_TEST_CARD_ALLOW"]);
    // Before any daemon starts: the peer's node fetches the card from this server alone.
    let card_at = card_server();
    std::env::set_var("VOX_TEST_CARD_ALLOW", card_at.to_string());
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

    // (3) The peer shares an echo service; the app lists it, forwards to it, and reports.
    let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_at = echo.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for conn in echo.incoming() {
            let Ok(mut conn) = conn else { return };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = conn.read(&mut buf) {
                    if n == 0 || conn.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
            });
        }
    });
    peer.run(&["service", "add", &room, "echo", &echo_at], "");
    writeln!(to_app).unwrap();
    let shared = expect(&from_app, &seen, "SHARED ");
    let commands = expect(&from_app, &seen, "COMMANDS ")[9..].to_owned();
    let needs = expect(&from_app, &seen, "NEEDS ")[6..].to_owned();
    let address = shared
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    // What the app's own data root's `vox service list` prints for the same node and room.
    let cli_list = mine.run(&["service", "list", &joined[7..]], "");
    let cli_address = cli_list
        .lines()
        .find(|l| l.contains(" by ") && !l.contains(" by you "))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_default()
        .to_owned();
    assert!(
        !cli_address.is_empty(),
        "APPARATUS: `vox service list` on the app's data root listed no share of the peer's to \
         compare with: {cli_list}"
    );
    assert_eq!(
        address, cli_address,
        "PRODUCT: `services` must list the peer's share at the address `vox service list` \
         prints; it said {shared:?}"
    );
    // Its commands and needs, word for word as `vox service list --json` gives them (ADR-028
    // S-3): every command carrying the canonical address.
    let cli_json: serde_json::Value =
        serde_json::from_str(&mine.run(&["service", "list", "--json", &joined[7..]], ""))
            .unwrap_or_default();
    let cli_share = cli_json["shared"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["by"] != "you"))
        .cloned()
        .unwrap_or_default();
    let cli_commands = cli_share["commands"]
        .as_array()
        .map(|cs| {
            cs.iter()
                .map(|c| {
                    format!(
                        "{}={}",
                        c["what"].as_str().unwrap_or(""),
                        c["command"].as_str().unwrap_or("")
                    )
                })
                .collect::<Vec<_>>()
                .join(" | ")
        })
        .unwrap_or_default();
    let cli_needs = cli_share["needs"]
        .as_array()
        .map(|ns| {
            ns.iter()
                .map(|n| {
                    let holds = if n["holds"].as_bool() == Some(true) {
                        "yes"
                    } else {
                        "no"
                    };
                    format!("{}={holds}", n["need"].as_str().unwrap_or(""))
                })
                .collect::<Vec<_>>()
                .join(" | ")
        })
        .unwrap_or_default();
    let canonical = cli_share["address"].as_str().unwrap_or_default().to_owned();
    eprintln!("the app's commands: {commands}\nits needs: {needs}");
    assert!(
        !cli_commands.is_empty() && !canonical.is_empty(),
        "APPARATUS: `vox service list --json` gave no share of the peer's to compare with: \
         {cli_json}"
    );
    assert!(
        commands == cli_commands && commands.contains(&canonical),
        "PRODUCT: the app's commands for the share must be `vox service list --json`'s, each with \
         the canonical address {canonical}: the app said {commands:?}, the CLI {cli_commands:?}"
    );
    assert_eq!(
        needs, cli_needs,
        "PRODUCT: the app's needs for the share must be `vox service list --json`'s"
    );
    writeln!(to_app).unwrap();
    let bound = expect(&from_app, &seen, "BOUND ")[6..].to_owned();
    let mut through = String::new();
    if let Ok(mut s) = std::net::TcpStream::connect(&bound) {
        let _ = s.set_read_timeout(Some(TIMEOUT));
        let _ = s.write_all(b"through vox\n");
        let mut buf = [0u8; 64];
        while !through.ends_with('\n') {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => through.push_str(&String::from_utf8_lossy(&buf[..n])),
            }
        }
    }
    writeln!(to_app, "{bound}").unwrap();
    expect(&from_app, &seen, "STOPPED");
    let refused_after = std::net::TcpStream::connect(&bound).is_err();
    let status = expect(&from_app, &seen, "STATUS ")[7..].to_owned();
    let status: serde_json::Value = serde_json::from_str(&status).unwrap_or_default();
    let cli_status: serde_json::Value =
        serde_json::from_str(&mine.run(&["status", "--json"], "")).unwrap_or_default();

    // (4) Files both ways.
    let to_peer = tmp.path().join("from-swift.bin");
    let to_peer_bytes: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(&to_peer, &to_peer_bytes).unwrap();
    writeln!(to_app, "{}", to_peer.display()).unwrap();
    let shared_file = expect(&from_app, &seen, "SHARED_FILE ");
    let listed_files = expect(&from_app, &seen, "LISTED_FILES ");
    let cli_shares = mine.run(&["share", "list", &joined[7..]], "");
    let room_dir = |d: &Daemon| -> Option<PathBuf> {
        let nodes = std::fs::read_dir(d.data.join("nodes")).ok()?;
        nodes
            .filter_map(Result::ok)
            .map(|n| n.path().join("files").join(&joined[7..]))
            .find(|p| p.exists())
    };
    let until = Instant::now() + TIMEOUT;
    let mut at_peer: Option<Vec<u8>> = None;
    while Instant::now() < until && at_peer.is_none() {
        at_peer = room_dir(&peer).and_then(|d| std::fs::read(d.join("from-swift.bin")).ok());
        std::thread::sleep(Duration::from_millis(250));
    }
    // An image, so its announcement carries a preview (7).
    let from_peer = tmp.path().join("from-peer.png");
    image::RgbImage::from_fn(48, 32, |x, y| {
        image::Rgb([(x * 5) as u8, (y * 7) as u8, 90])
    })
    .save(&from_peer)
    .expect("APPARATUS: write the peer's image");
    let from_peer_bytes = std::fs::read(&from_peer).unwrap();
    peer.run(
        &[
            "share",
            &room,
            from_peer.to_str().unwrap(),
            "--to",
            &app_fp,
            "-m",
            "from the peer",
        ],
        "",
    );
    writeln!(to_app).unwrap();
    let pulled = expect(&from_app, &seen, "PULLED ")[7..].to_owned();
    let at_app = std::fs::read(&pulled).ok();

    // (5) The family LAN, through a stand-in helper.
    let helper = tmp.path().join("helper.sock");
    let os = lan_standin::Os::default();
    os.serve(&helper);
    writeln!(to_app, "{}", helper.display()).unwrap();
    let lan_up = expect(&from_app, &seen, "LAN_UP ");
    let lan_said = expect(&from_app, &seen, "LAN_SAID ");
    expect(&from_app, &seen, "LAN_DOWN");
    let asked = os.asked.lock().unwrap().clone();

    // (6) One-step sharing (ADR-028 S-4, #444): a stand-in listens on every interface here; the
    // app lists it, previews it (the warning said first), shares it, and the peer reaches it.
    let stand_in = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
    let stand_in_port = stand_in.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in stand_in.incoming() {
            let Ok(mut conn) = conn else { return };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = conn.read(&mut buf) {
                    if n == 0 || conn.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
            });
        }
    });
    writeln!(to_app, "{stand_in_port}").unwrap();
    let listening = expect(&from_app, &seen, "LISTENING ");
    let missing = expect(&from_app, &seen, "MISSING ");
    let preview = expect(&from_app, &seen, "PREVIEW ");
    let offered = expect(&from_app, &seen, "OFFERED ");
    let tag = offered[8..].trim().to_owned();
    // The peer finds it by its own `vox service list`, and forwards to it as a person would.
    let until = Instant::now() + TIMEOUT;
    let mut peer_list = String::new();
    let mut peer_address = String::new();
    while Instant::now() < until {
        peer_list = peer.run(&["service", "list", &room], "");
        if let Some(a) = peer_list
            .lines()
            .find(|l| l.contains(" by swift") && l.trim_start().starts_with(&format!("{tag}.")))
            .and_then(|l| l.split_whitespace().next())
        {
            peer_address = a.to_owned();
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let mut reached = String::new();
    if !peer_address.is_empty() {
        let mut fwd = peer
            .command(&["forward", &peer_address, "127.0.0.1:0"])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("APPARATUS: could not start the peer's vox forward");
        let fwd_out = lines(fwd.stdout.take().unwrap());
        let _fwd = Proc(fwd);
        let at = fwd_out
            .recv_timeout(TIMEOUT)
            .ok()
            .and_then(|l| {
                l.strip_prefix("vox: forwarding ")
                    .and_then(|r| r.split_whitespace().next())
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        if let Ok(mut s) = std::net::TcpStream::connect(&at) {
            let _ = s.set_read_timeout(Some(TIMEOUT));
            let _ = s.write_all(b"shared in one step\n");
            let mut buf = [0u8; 64];
            while !reached.ends_with('\n') {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => reached.push_str(&String::from_utf8_lossy(&buf[..n])),
                }
            }
        }
    }
    eprintln!(
        "{listening}\n{missing}\n{preview}\n{offered}\nthe peer's `vox service list`: \
         {peer_list}the peer reached {peer_address:?}: {reached:?}"
    );
    assert!(
        listening.contains(&format!(":{stand_in_port}")) && listening.ends_with("EVERY true"),
        "PRODUCT: `listening` must list the stand-in on port {stand_in_port}, on every interface: \
         {listening}"
    );
    assert!(
        missing.contains("another user's services"),
        "PRODUCT: `listening` must say that another user's listeners may be missing: {missing}"
    );
    assert!(
        preview.contains("listens on every interface of this machine"),
        "PRODUCT: `servicePreview` must say, before it is shared, that the stand-in listens on \
         every interface: {preview}"
    );
    assert_eq!(
        reached, "shared in one step\n",
        "PRODUCT: the peer must reach the service the app shared in one step, by its own `vox \
         service list` and `vox forward`: it found {peer_address:?} in {peer_list}"
    );

    // (7) A link card and an image preview, as `read` gives them; then a room's one name.
    peer.run(
        &[
            "room",
            "post",
            &room,
            &format!("the numbers: http://{card_at}/page"),
        ],
        "",
    );
    writeln!(to_app).unwrap();
    let card = expect(&from_app, &seen, "CARD ");
    let image = expect(&from_app, &seen, "IMAGE ");
    let pulled_by = expect(&from_app, &seen, "PULLED_BY ");
    let refused = expect(&from_app, &seen, "REFUSED ");
    let created = expect(&from_app, &seen, "CREATED ");
    let (made, made_link) = {
        let mut w = created[8..].split_whitespace();
        (
            w.next().unwrap_or_default().to_owned(),
            w.next().unwrap_or_default().to_owned(),
        )
    };
    peer.run(
        &["room", "join", &made_link, "--passphrase-file", "-"],
        "mine passphrase\n",
    );
    writeln!(to_app).unwrap();
    let renamed = expect(&from_app, &seen, "RENAMED");
    // `vox room list` shows a room by its short id, then its name.
    let shows_renamed = |l: &str, id: &str| {
        let mut w = l.split_whitespace();
        w.next().is_some_and(|s| id.starts_with(s)) && w.next() == Some("renamed")
    };
    let until = Instant::now() + TIMEOUT;
    let mut peer_rooms = String::new();
    while Instant::now() < until {
        peer_rooms = peer.run(&["room", "list"], "");
        if peer_rooms.lines().any(|l| shows_renamed(l, &made)) {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    eprintln!("{card}\n{image}\n{pulled_by}\n{refused}\n{created}\n{renamed}\nthe peer's `vox room list`: {peer_rooms}");
    assert_eq!(
        card,
        format!(
            "CARD The quarterly report | Numbers & notes for Q3 | {}",
            CARD_IMAGE.len()
        ),
        "PRODUCT: `read` must give the link card the peer's node fetched: its title, description \
         and image"
    );
    assert!(
        image.starts_with("IMAGE 48x32 JPEG true BLURHASH ") && image.len() > 31,
        "PRODUCT: `read` must give the image the peer's share announced: 48x32, a JPEG thumbnail \
         and a BlurHash: {image}"
    );
    assert_eq!(
        pulled_by, "PULLED_BY peer SAME true",
        "PRODUCT: `pulledBy` must say the peer pulled the app's file share whole, by the name the \
         app trusts it under, against the share's own announcement"
    );
    assert!(
        refused.contains("this identity is not its admin"),
        "PRODUCT: `renameRoom` on a room this node may not rename must throw the node's refusal: \
         {refused}"
    );
    assert!(
        peer_rooms.lines().any(|l| shows_renamed(l, &made)),
        "PRODUCT: a room the app renamed must show its new name in the peer's own `vox room \
         list`: {peer_rooms}"
    );

    // (8) The app closes; the daemon lets the node go.
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
         app's post: {}\n{got}\n{shared}\n`vox service list` said: {cli_list}BOUND {bound}, \
         echoed {through:?}, refused once stopped: {refused_after}\nstatus identity {} (vox \
         status: {})\n{shared_file}; {listed_files}; the peer has it: {}; PULLED {pulled}, matches: {}\n\
         helper asked {asked:?}; {lan_up}; {lan_said}\nafter close, `vox node list` said: {after}all \
         the Swift program said: {:?}",
        read.contains("hello from swift"),
        status["identity"],
        cli_status["identity"],
        at_peer.as_deref() == Some(&to_peer_bytes[..]),
        at_app.as_deref() == Some(&from_peer_bytes[..]),
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
        at_peer.as_deref() == Some(&to_peer_bytes[..]),
        "PRODUCT: a file the app shares to the peer must reach the peer's files directory byte \
         for byte; {shared_file}; the peer has {:?} bytes",
        at_peer.as_ref().map(Vec::len)
    );
    assert!(
        listed_files.starts_with("LISTED_FILES 1 from-swift.bin")
            && cli_shares.contains("from-swift.bin"),
        "PRODUCT: `shares` must list the app's share as `vox share list` does: {listed_files} \
         against {cli_shares}"
    );
    assert!(
        at_app.as_deref() == Some(&from_peer_bytes[..]),
        "PRODUCT: a file the peer shares to the app must be pulled by the app's node, and `pulled` \
         must say where, byte for byte: it said {pulled:?}, holding {:?} bytes",
        at_app.as_ref().map(Vec::len)
    );
    assert_eq!(
        through, "through vox\n",
        "PRODUCT: a forward to {address} must carry bytes to the peer's service and back"
    );
    assert!(
        refused_after,
        "PRODUCT: once stopped, the forward at {bound} must accept nothing"
    );
    assert!(
        status["identity"].is_string() && status["identity"] == cli_status["identity"],
        "PRODUCT: `status` must be the node's report, as `vox status --json` gives it: identity \
         {} against {}",
        status["identity"],
        cli_status["identity"]
    );
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
