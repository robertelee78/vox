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
        let tx_err = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        // Stderr is drained too — a full pipe would block the child, which is a hang rather
        // than a failure (ADR-018 §6) — and joins the stream prefixed `! `, because the
        // reasons a person is shown (a refusal, above all) are printed there. The prefix
        // keeps every stdout pattern below from matching one by accident.
        if let Some(err) = child.stderr.take() {
            std::thread::spawn(move || {
                for line in BufReader::new(err).lines().map_while(Result::ok) {
                    if tx_err.send(format!("! {line}")).is_err() {
                        break;
                    }
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
    // Longer than `node::up::HOST_PATIENCE`, or this times out on the proxy's own wait and
    // reports EAGAIN instead of what the proxy decided.
    //
    // **Derived, not restated.** This was a hand-written 150s beside that comment; when
    // HOST_PATIENCE was raised to 300s the comment stayed true and the number stopped being,
    // and this gate then failed at ~155s with `Resource temporarily unavailable` — which
    // reads like a race in the service path and is not one. Two of us spent real time on it.
    // Adding to the constant makes the invariant hold by construction.
    s.set_read_timeout(Some(
        vox_core::node::up::HOST_PATIENCE + Duration::from_secs(30),
    ))?;
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
        !l.starts_with("! ")
            && l.trim_start().contains('@')
            && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
    });
    let anchor_spec = spec_line.trim().to_owned();
    assert!(
        !anchor_spec.contains("0.0.0.0"),
        "an anchor spec must be dialable, not a wildcard bind: {anchor_spec}"
    );

    // 3. The decision. `vox id` on the guest prints its fingerprint; the host runs
    //    `vox trust add` with it. This is the whole authorization under ADR-017 decision 3
    //    as revised — joining grants nothing, so without this step the guest reaches
    //    nothing, which the control at the end of this proof asserts.
    //
    //    It happens before `vox serve` starts because redb is single-writer: a one-shot
    //    verb cannot open a profile a running `vox serve` holds.
    let (ok, guest_id, err) = vox_once(&guest_dir, &["id".into()]);
    assert!(ok, "vox id must print the guest's fingerprint: {err}");
    let guest_fp = guest_id.trim().to_owned();
    assert_eq!(
        guest_fp.len(),
        52,
        "a fingerprint is 52 base32 characters, alone on the line: {guest_fp:?}"
    );
    let (ok, out, err) = vox_once(
        &host_dir,
        &[
            "trust".into(),
            "add".into(),
            guest_fp.clone(),
            "--name".into(),
            "the guest".into(),
        ],
    );
    assert!(
        ok,
        "the host must be able to trust the guest.\nstdout:\n{out}\nstderr:\n{err}"
    );
    assert!(
        out.contains("reach every service"),
        "trusting must say plainly that it grants service reach, since that is the whole \
         decision a person is making:\n{out}"
    );
    let (ok, listed, _) = vox_once(&host_dir, &["trust".into(), "list".into()]);
    assert!(
        ok && listed.contains(&guest_fp),
        "the ring must show it:\n{listed}"
    );

    // 4. `vox serve` — the host. Room id, address and the GENERATED passphrase are taken
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
    // Parsed from `vox serve`'s own output, which is the point: this proof is coupled to the
    // product's surface on purpose, so changing what a person sees means updating the proof.
    // (It caught me doing exactly that — M17.7 moved the hostname onto the `serving` line and
    // this timed out until it was brought back into step.)
    let hostname_line = host.expect_line("the .vox hostname", |l| {
        l.starts_with("serving ") && l.contains(".vox")
    });
    let hostname = hostname_line
        .split_whitespace()
        .last()
        .expect("a hostname on the serving line")
        .to_owned();
    // And the line that tells a person who can actually reach it must no longer say
    // "anyone who joins", which was true only of the withdrawn model.
    let audience = host.expect_line("who can reach the service", |l| {
        l.starts_with("who can reach it:")
    });
    assert!(
        audience.contains("trusted"),
        "serve must name trust as what governs reach, not joining: {audience}"
    );
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
    let t0 = Instant::now();
    let mut stream = socks5_connect(bound, &hostname, service_port).unwrap_or_else(|e| {
        panic!("the FIRST SOCKS5 CONNECT to {hostname}:{service_port} must succeed: {e}")
    });
    eprintln!(
        "[test] first CONNECT succeeded after {:?} — this is what a person waits for \
         between `vox up` and their first `ssh`",
        t0.elapsed()
    );
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
        !l.starts_with("! ") && l.contains("reached")
    });
    assert!(
        reached.contains(&service_port.to_string()),
        "the host should name the service that was reached: {reached}"
    );

    drop(up);

    // ---- the control: an UNTRUSTED joiner reaches nothing (M17.7) ----
    //
    // This is the half that makes the rest mean something, and it is verified finding #1
    // stated as a test. A second guest holds the same address and the same passphrase — the
    // full credentials — and the host never decided about it. Under the withdrawn model that
    // was sufficient: a room created by `vox serve` authorized every admitted member, so
    // joining WAS the authorization. It must now reach nothing.
    let stranger_dir = tmp.path().join("stranger");
    std::fs::create_dir_all(stranger_dir.join("cfg")).unwrap();
    let (ok, out, err) = vox_once(
        &stranger_dir,
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
    assert!(
        ok,
        "the stranger must still be able to JOIN — the passphrase is the join credential and \
         always was; what changed is that joining grants no reach.\nstdout:\n{out}\nstderr:\n{err}"
    );
    let mut stranger_up = VoxProc::spawn(
        "stranger-up",
        &stranger_dir,
        &[
            "up".into(),
            room.clone(),
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
    let s_line = stranger_up.expect_line("the stranger's proxy address", |l| {
        l.starts_with("vox up on ")
    });
    let s_bound: SocketAddr = s_line
        .split_whitespace()
        .nth(3)
        .expect("an address")
        .parse()
        .expect("a socket address");
    // **The reply is the host's answer** (PRD-001 R23, D6). The proxy used to reply
    // "succeeded" before it had asked the host, so this control had to accept a success and
    // then look for a stream that carried nothing — which is to say it asserted the defect.
    // The host answers before a single byte flows, so the refusal must be the SOCKS reply
    // itself: code 2, "connection not allowed by ruleset".
    let t0 = Instant::now();
    let refused = socks5_connect(s_bound, &hostname, service_port);
    let waited = t0.elapsed();
    match refused {
        Ok(_) => panic!(
            "an untrusted joiner holding the address AND the passphrase was told its CONNECT \
             succeeded — the proxy must answer with the host's refusal (PRD-001 R23)"
        ),
        Err(e) => {
            eprintln!("[test] the untrusted joiner was refused after {waited:?}: {e}");
            assert!(
                e.to_string().contains("SOCKS reply code 2"),
                "the refusal must be SOCKS code 2 (not allowed), not a transport error: {e}"
            );
        }
    }
    // And the stranger's own node says why, on its own terminal — the remote side learns
    // nothing it did not already say.
    let why = stranger_up.expect_line("the refusal's reason on the stranger's terminal", |l| {
        l.starts_with("! ") && l.contains("the host refused")
    });
    eprintln!("[test] the stranger's vox up said: {why}");

    drop(stranger_up);
    drop(host);
    drop(anchor);
}
