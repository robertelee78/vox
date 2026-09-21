//! **The room-bound service feature, proved by running the product** (ADR-017, M17.15).
//!
//! Every other test of this feature drives the node's **library API** —
//! `h.apply(NodeCommand::…)` against an in-process actor. That is not the product. The
//! decider's rule is blunt about it: *"I ONLY care about tests that actually prove the
//! feature/product works"*, and *"if we have cargo tests at all they have to be real or
//! they're just noise"*.
//!
//! The M17 rehearsal was run by hand and found **three defects no library test could**,
//! every one in the seam between a binary and a node: a generated passphrase that did not
//! match itself, an anchor address printed that could not be dialled, and a race between
//! binding and dialling. Those are the argument for this file. A rehearsal that only ever
//! happens by hand catches a defect once; the same rehearsal as a proof catches it every
//! time.
//!
//! ## What runs here
//!
//! Real child processes of the shipped `vox` binary, three separate profiles, and a real
//! TCP service:
//!
//! 1. a **real TCP echo service** on loopback — standing in for `sshd`, and enough,
//!    because what is under test is whether bytes cross the overlay untouched;
//! 2. `vox node` — the headless anchor, whose printed `<fingerprint>@<addr>` line this
//!    test **parses and uses**, so an unusable spec (defect 2 above) fails here;
//! 3. `vox serve <port>` — the host. Its printed room id, `vox://` address and
//!    **generated passphrase** are parsed and used verbatim, so a passphrase that does
//!    not match itself (defect 1) fails here;
//! 4. `vox connect <address>` — the guest joining with that passphrase, one-shot;
//! 5. `vox up <room>` — the guest's SOCKS5 entry point, whose bound address is parsed;
//! 6. a **real SOCKS5 client** in this test, sending the `.vox` hostname (`socks5h`
//!    style, the name not an address), then real bytes through it, which must come back
//!    byte-identical.
//!
//! Nothing here reaches into `vox_core`. If a person could not do it from a shell, this
//! test does not do it either.
//!
//! ## Why it is `#[ignore]`d
//!
//! Production Argon2id on three profiles plus a real ADR-005 proof of work, so it costs
//! tens of seconds. CI runs it in release with the other real-parameter proofs.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
/// Generous: three production Argon2id derivations and a real PoW happen inside it.
const LINE_TIMEOUT: Duration = Duration::from_secs(180);

/// A `vox` child process whose stdout is read line by line on its own thread, so a
/// long-running command can be waited on for a specific line without blocking it.
struct VoxProc {
    name: &'static str,
    child: Child,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl VoxProc {
    fn spawn(name: &'static str, data: &std::path::Path, args: &[String]) -> Self {
        let mut child = Command::new(VOX)
            .args(args)
            .env("VOX_DATA_DIR", data)
            .env("VOX_CONFIG_DIR", data.join("cfg"))
            // Every profile's identity passphrase, supplied the way a script would.
            .env("VOX_IDENTITY_PASSPHRASE", "identity passphrase")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {name}: {e}"));
        let out = child.stdout.take().expect("stdout");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        // Stderr is drained too, and kept out of the event stream: a full pipe would
        // block the child, which is a hang rather than a failure (ADR-018 §6).
        if let Some(err) = child.stderr.take() {
            let name_owned = name.to_owned();
            std::thread::spawn(move || {
                for line in BufReader::new(err).lines().map_while(Result::ok) {
                    eprintln!("[{name_owned} stderr] {line}");
                }
            });
        }
        Self {
            name,
            child,
            lines: rx,
            seen: Vec::new(),
        }
    }

    /// Wait for the first line matching `pred`, returning it. Every line seen is kept so
    /// a failure can show what the command actually said.
    fn expect_line(&mut self, what: &str, pred: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + LINE_TIMEOUT;
        for line in &self.seen {
            if pred(line) {
                return line.clone();
            }
        }
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "{}: timed out waiting for {what}. It said:\n{}",
                self.name,
                self.seen.join("\n")
            );
            match self.lines.recv_timeout(left.min(Duration::from_secs(5))) {
                Ok(line) => {
                    eprintln!("[{} ] {line}", self.name);
                    let hit = pred(&line);
                    self.seen.push(line.clone());
                    if hit {
                        return line;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => panic!(
                    "{}: exited before saying {what}. It said:\n{}",
                    self.name,
                    self.seen.join("\n")
                ),
            }
        }
    }
}

impl Drop for VoxProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Run a one-shot `vox` verb to completion.
fn vox_once(data: &std::path::Path, args: &[String]) -> (bool, String, String) {
    let out = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", "identity passphrase")
        .stdin(Stdio::null())
        .output()
        .expect("run vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The value after a fixed-width label, as `vox` prints its key/value lines.
fn after_label(line: &str, label: &str) -> String {
    line.strip_prefix(label)
        .unwrap_or_else(|| panic!("line {line:?} does not start with {label:?}"))
        .trim()
        .to_owned()
}

/// A real TCP echo service on loopback: `sshd`'s stand-in. Returns its port.
fn echo_service() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// Speak RFC 1928 to `proxy`, asking it to CONNECT to `host:port` **by name** — which is
/// the `socks5h` behaviour `vox up` requires, and the reason a `.vox` name never reaches
/// a resolver.
fn socks5_connect(proxy: SocketAddr, host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy)?;
    s.set_read_timeout(Some(Duration::from_secs(60)))?;
    // Greeting: one method, "no authentication".
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut hello = [0u8; 2];
    s.read_exact(&mut hello)?;
    assert_eq!(hello, [0x05, 0x00], "proxy refused the no-auth method");
    // CONNECT, address type 3 (domain name).
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    assert_eq!(head[0], 0x05, "not a SOCKS5 reply");
    // A refusal is returned rather than asserted, so the caller's retry can tell a
    // not-ready-yet from a never-works. Asserting here made the retry loop dead code and
    // turned the first transient refusal into a failure.
    if head[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "proxy refused the CONNECT, SOCKS reply code {}",
            head[1]
        )));
    }
    // Drain the bound address so the stream is positioned at the payload.
    let skip = match head[3] {
        0x01 => 4 + 2,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            usize::from(l[0]) + 2
        }
        0x04 => 16 + 2,
        other => panic!("unknown address type {other} in reply"),
    };
    let mut sink = vec![0u8; skip];
    s.read_exact(&mut sink)?;
    Ok(s)
}

#[test]
#[ignore = "three production Argon2id profiles + a real PoW, and drives the real binary; CI runs it in release"]
fn a_room_bound_service_carries_real_bytes_through_the_real_binaries() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let anchor_dir = tmp.path().join("anchor");
    let host_dir = tmp.path().join("host");
    let guest_dir = tmp.path().join("guest");
    for d in [&anchor_dir, &host_dir, &guest_dir] {
        std::fs::create_dir_all(d.join("cfg")).unwrap();
    }

    // 1. the service a person is actually trying to reach
    let service_port = echo_service();

    // 2. `vox node` — the anchor. Its printed --anchor spec is what everything else uses,
    //    so a spec nobody can dial fails right here.
    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &["node".into(), "--listen".into(), "127.0.0.1:0".into()],
    );
    let spec_line = anchor.expect_line("an --anchor spec", |l| {
        l.trim_start().contains('@') && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
    });
    let anchor_spec = spec_line.trim().to_owned();
    assert!(
        !anchor_spec.contains("0.0.0.0"),
        "an anchor spec must be dialable, not a wildcard bind: {anchor_spec}"
    );

    // 3. `vox serve` — the host. Room id, address and the GENERATED passphrase are taken
    //    from its own stdout and used verbatim; nothing is shared in-process.
    let mut host = VoxProc::spawn(
        "host",
        &host_dir,
        &[
            "serve".into(),
            service_port.to_string(),
            "--anchor".into(),
            anchor_spec.clone(),
            "--listen".into(),
            "127.0.0.1:0".into(),
        ],
    );
    let room = after_label(
        &host.expect_line("the room id", |l| l.starts_with("room ")),
        "room",
    );
    let address = after_label(
        &host.expect_line("the vox:// address", |l| l.starts_with("address ")),
        "address",
    );
    let passphrase = after_label(
        &host.expect_line("the generated passphrase", |l| l.starts_with("passphrase ")),
        "passphrase",
    );
    let hostname_line = host.expect_line("the .vox hostname", |l| l.starts_with("port "));
    let hostname = hostname_line
        .split_whitespace()
        .last()
        .expect("a hostname on the port line")
        .to_owned();
    assert!(address.starts_with("vox://"), "address: {address}");
    assert!(hostname.ends_with(".vox"), "hostname: {hostname}");
    assert!(
        !address.contains(&passphrase),
        "the passphrase MUST NOT be in the address (ADR-005)"
    );

    // 4. `vox connect` — the guest joins with the address and that passphrase, verbatim.
    //    A passphrase that does not match itself fails here, which is defect 1.
    let (ok, out, err) = vox_once(
        &guest_dir,
        &[
            "connect".into(),
            address.clone(),
            "--passphrase".into(),
            passphrase.clone(),
            "--anchor".into(),
            anchor_spec.clone(),
            "--listen".into(),
            "127.0.0.1:0".into(),
        ],
    );
    assert!(ok, "vox connect failed.\nstdout:\n{out}\nstderr:\n{err}");
    assert!(
        out.contains("joined") && out.contains(&hostname),
        "connect should say what the room answers on.\n{out}"
    );

    // 5. `vox up` — the guest's entry point. Parse where it bound.
    let mut up = VoxProc::spawn(
        "up",
        &guest_dir,
        &[
            "up".into(),
            room.clone(),
            // `vox up` needs the room passphrase even though the join is durable: the
            // room's store is sealed under it (ADR-010), so opening the room requires it
            // every time. A guest therefore keeps the passphrase for as long as it wants
            // to reach the service, not merely to join once.
            "--passphrase".into(),
            passphrase.clone(),
            "--bind".into(),
            "127.0.0.1:0".into(),
            "--anchor".into(),
            anchor_spec.clone(),
            "--listen".into(),
            "127.0.0.1:0".into(),
        ],
    );
    let up_line = up.expect_line("the proxy's bound address", |l| l.starts_with("vox up on "));
    let bound: SocketAddr = up_line
        .split_whitespace()
        .nth(3)
        .expect("an address in the up line")
        .parse()
        .expect("a socket address");

    // 6. A real SOCKS5 client, the `.vox` NAME (not an address), and real bytes.
    let payload = b"the product works or it does not";
    // **One CONNECT, first try, no retry loop** — and that is an assertion about the
    // product, not test convenience.
    //
    // The proxy binds before it can reach the host, deliberately, so the first request can
    // arrive before this node has read the board. This rehearsal originally retried here
    // and logged *two* refusals over about four seconds — which for a person is `ssh`
    // failing and then working if they try again. `node::up::reach_host_with_patience` now
    // waits inside the request instead, so a single CONNECT succeeds. If that regresses,
    // this line goes red rather than quietly costing every user their first attempt.
    let mut stream = socks5_connect(bound, &hostname, service_port).unwrap_or_else(|e| {
        panic!("the FIRST SOCKS5 CONNECT to {hostname}:{service_port} must succeed: {e}")
    });
    stream
        .write_all(payload)
        .expect("write through the overlay");
    let mut back = vec![0u8; payload.len()];
    stream
        .read_exact(&mut back)
        .expect("read the echo back through the overlay");
    assert_eq!(
        back, payload,
        "bytes must cross the overlay unchanged — this is the whole feature"
    );

    // And the host reports who reached it, which is the only place attribution can come
    // from: the service itself sees every Vox client as 127.0.0.1 (ADR-017 decision 6).
    let reached = host.expect_line("the host to report a client reaching the service", |l| {
        l.contains("reached")
    });
    assert!(
        reached.contains(&service_port.to_string()),
        "the host should name the service that was reached: {reached}"
    );

    drop(up);
    drop(host);
    drop(anchor);
}
