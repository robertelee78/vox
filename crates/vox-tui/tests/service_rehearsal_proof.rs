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
//! 3. `vox serve <port>=<port>` — the host, sharing the service under the name `<port>`.
//!    Its printed room id, `vox://` address and **generated passphrase** are parsed and used
//!    verbatim, so a passphrase that does not match itself (defect 1) fails here;
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

#[path = "support/attach.rs"]
mod attach;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Write the room passphrase `pass` beside the profile at `dir`, for `--passphrase-file`: a
/// room passphrase is never taken from argv or the environment (V210-72).
fn room_pass_file(dir: &std::path::Path, pass: &str) -> String {
    std::fs::create_dir_all(dir).expect("APPARATUS: create the profile dir");
    let at = dir.join("room-passphrase");
    std::fs::write(&at, pass).expect("APPARATUS: write the room passphrase file");
    at.to_str()
        .expect("APPARATUS: a non-UTF-8 temp path")
        .to_owned()
}
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
            .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn vox for {name}: {e}"));
        let out = child
            .stdout
            .take()
            .expect("APPARATUS: the piped stdout was not opened");
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
                "PRODUCT: {} did not say {what} within {LINE_TIMEOUT:?}. It said:\n{}",
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
                    "PRODUCT: {} exited before saying {what}. It said:\n{}",
                    self.name,
                    self.seen.join("\n")
                ),
            }
        }
    }

    /// Everything the command has said so far, for a red that quotes it.
    fn transcript(&mut self) -> String {
        while let Ok(line) = self.lines.try_recv() {
            self.seen.push(line);
        }
        self.seen.join("\n")
    }
}

impl Drop for VoxProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Run a one-shot `vox` verb to completion.
/// A verb as a person runs it since ADR-026 L-2: one that needs its node attached, run while no
/// daemon holds the data root, runs with the node attached by `vox node attach` and let go after.
fn vox_once(data: &std::path::Path, args: &[String]) -> (bool, String, String) {
    let verb: Vec<&str> = args.iter().map(String::as_str).collect();
    match attach::needs(data, &verb) {
        Some(node) => attach::Root::at(data, "identity passphrase")
            .attached(&node, || vox_once_plain(data, args)),
        None => vox_once_plain(data, args),
    }
}

fn vox_once_plain(data: &std::path::Path, args: &[String]) -> (bool, String, String) {
    let out = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", "identity passphrase")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run vox {args:?}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The value after a fixed-width label, as `vox` prints its key/value lines.
fn after_label(line: &str, label: &str) -> String {
    line.strip_prefix(label)
        .unwrap_or_else(|| {
            panic!("PRODUCT: vox printed {line:?}, which does not start with {label:?}")
        })
        .trim()
        .to_owned()
}

/// A real TCP echo service on loopback: `sshd`'s stand-in. Returns its port.
fn echo_service() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("APPARATUS: bind the echo service");
    let port = listener
        .local_addr()
        .expect("APPARATUS: the echo service's address")
        .port();
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

/// An `sshd` stand-in that greets with an SSH banner, so the sharer's node detects it as `ssh`
/// (ADR-028 S-2), and reports on the channel the first line each client sends: a real `ssh`
/// client that reached it sends its own `SSH-2.0-…` banner.
fn ssh_banner_service() -> (u16, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("APPARATUS: bind the ssh stand-in");
    let port = listener
        .local_addr()
        .expect("APPARATUS: the ssh stand-in's address")
        .port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let tx = tx.clone();
            std::thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
                if s.write_all(b"SSH-2.0-VoxProofStandIn\r\n").is_err() {
                    return;
                }
                let mut line = String::new();
                if BufReader::new(&s).read_line(&mut line).is_ok() && !line.is_empty() {
                    let _ = tx.send(line.trim().to_owned());
                }
            });
        }
    });
    (port, rx)
}

/// Speak RFC 1928 to `proxy`, asking it to CONNECT to `host:port` **by name** — which is
/// the `socks5h` behaviour `vox up` requires, and the reason a `.vox` name never reaches
/// a resolver.
///
/// Every way the proxy can fail the handshake is returned, not asserted, so the caller's red
/// can quote what `vox up` said alongside it: each one is the product's answer.
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
    if hello != [0x05, 0x00] {
        return Err(std::io::Error::other(format!(
            "proxy refused the no-auth method: {hello:02x?}"
        )));
    }
    // CONNECT, address type 3 (domain name).
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[0] != 0x05 {
        return Err(std::io::Error::other(format!(
            "not a SOCKS5 reply: {head:02x?}"
        )));
    }
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
        other => {
            return Err(std::io::Error::other(format!(
                "unknown address type {other} in reply"
            )))
        }
    };
    let mut sink = vec![0u8; skip];
    s.read_exact(&mut sink)?;
    Ok(s)
}

#[test]
#[ignore = "three production Argon2id profiles + a real PoW, and drives the real binary; CI runs it in release"]
fn a_room_bound_service_carries_real_bytes_through_the_real_binaries() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
    let anchor_dir = tmp.path().join("anchor");
    let host_dir = tmp.path().join("host");
    let guest_dir = tmp.path().join("guest");
    for d in [&anchor_dir, &host_dir, &guest_dir] {
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a profile dir");
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
        "PRODUCT: an anchor spec must be dialable, not a wildcard bind: {anchor_spec}"
    );

    // 3. The decision. `vox id` on the guest prints its fingerprint; the host runs
    //    `vox trust add` with it. This is the whole authorization under ADR-017 decision 3
    //    as revised — joining grants nothing, so without this step the guest reaches
    //    nothing, which the control at the end of this proof asserts.
    //
    //    Since ADR-026 the host makes its node first (C-3: a verb acts as a node that
    //    exists), and the trust is made with that node attached (L-2).
    let (ok, _, err) = vox_once(&host_dir, &["id".into()]);
    assert!(ok, "PRODUCT (staging): vox id (host): {err}");
    let (ok, guest_id, err) = vox_once(&guest_dir, &["id".into()]);
    assert!(
        ok,
        "PRODUCT: vox id must print the guest's fingerprint: {err}"
    );
    let guest_fp = guest_id.trim().to_owned();
    assert_eq!(
        guest_fp.len(),
        52,
        "PRODUCT: a fingerprint is 52 base32 characters, alone on the line: {guest_fp:?}"
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
        "PRODUCT: the host must be able to trust the guest.\nstdout:\n{out}\nstderr:\n{err}"
    );
    assert!(
        out.contains("reach every service"),
        "PRODUCT: trusting must say plainly that it grants service reach, since that is the whole \
         decision a person is making:\n{out}"
    );
    let (ok, listed, list_err) = vox_once(&host_dir, &["trust".into(), "list".into()]);
    assert!(
        ok && listed.contains(&guest_fp),
        "PRODUCT: `vox trust list` must show the guest:\n{listed}\nstderr:\n{list_err}"
    );

    // 4. `vox serve` — the host. Room id, address and the GENERATED passphrase are taken
    //    from its own stdout and used verbatim; nothing is shared in-process.
    let mut host = VoxProc::spawn(
        "host",
        &host_dir,
        &[
            "serve".into(),
            format!("{service_port}={service_port}"),
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
    // this timed out until it was brought back into step; V030-25 made it the `sharing` line,
    // `sharing <endpoint> as <service>.<node>.<room>.vox`; ADR-028 S-1 made it the name and the
    // canonical address, `sharing <endpoint> as <name> — <canonical>`.)
    let hostname_line = host.expect_line("the service's .vox address", |l| {
        l.starts_with("sharing ") && l.contains(" — ") && l.contains(".vox")
    });
    let hostname = hostname_line
        .split(" — ")
        .nth(1)
        .and_then(|a| a.split_whitespace().next())
        .unwrap_or_else(|| panic!("PRODUCT: no address on the sharing line: {hostname_line:?}"))
        .to_owned();
    // And the line that tells a person who can actually reach it must no longer say
    // "anyone who joins", which was true only of the withdrawn model.
    let audience = host.expect_line("who can reach the service", |l| {
        l.starts_with("who can reach it:")
    });
    assert!(
        audience.contains("trusted"),
        "PRODUCT: serve must name trust as what governs reach, not joining: {audience}"
    );
    assert!(
        address.starts_with("vox://"),
        "PRODUCT: serve printed an address that is not vox://: {address}"
    );
    assert!(
        hostname_line.contains(&format!(" as {service_port} — "))
            && hostname.ends_with(&format!(".{room}.vox"))
            && hostname.split('.').count() == 4
            && hostname.split('.').all(|l| l == "vox" || l.len() == 52),
        "PRODUCT: serve printed no canonical <service fp>.<node fp>.<room id>.vox for service \
         {service_port} in room {room}: {hostname_line}"
    );
    assert!(
        !address.contains(&passphrase),
        "PRODUCT: the passphrase MUST NOT be in the address (ADR-005): {address}"
    );

    // 4. `vox connect` — the guest joins with the address and that passphrase, verbatim.
    //    A passphrase that does not match itself fails here, which is defect 1.
    let (ok, out, err) = vox_once(
        &guest_dir,
        &[
            "connect".into(),
            address.clone(),
            "--passphrase-file".into(),
            room_pass_file(&guest_dir, &passphrase),
            "--anchor".into(),
            anchor_spec.clone(),
            "--listen".into(),
            "127.0.0.1:0".into(),
        ],
    );
    assert!(
        ok,
        "PRODUCT: vox connect failed.\nstdout:\n{out}\nstderr:\n{err}"
    );
    // A room answers on nothing (V030-25): `vox connect` says how to see what is shared
    // there, not a name for the room.
    assert!(
        out.contains("joined") && out.contains("vox service list"),
        "PRODUCT: connect should say how to see what is shared in the room it joined.\n{out}"
    );

    // 5. `vox up --watch` — the guest's entry point, the daemon's proxy. Parse where it is.
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
            "--passphrase-file".into(),
            room_pass_file(&guest_dir, &passphrase),
            "--watch".into(),
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
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| panic!("PRODUCT: `vox up` printed no socket address: {up_line:?}"));

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
        panic!(
            "PRODUCT: the FIRST SOCKS5 CONNECT to {hostname}:{service_port} must succeed: {e}\n\
             vox up said:\n{}\nvox serve said:\n{}",
            up.transcript(),
            host.transcript()
        )
    });
    eprintln!(
        "[test] first CONNECT succeeded after {:?} — this is what a person waits for \
         between `vox up` and their first `ssh`",
        t0.elapsed()
    );
    if let Err(e) = stream.write_all(payload) {
        panic!(
            "PRODUCT: the overlay stream refused a write: {e}\nvox up said:\n{}\nvox serve said:\n{}",
            up.transcript(),
            host.transcript()
        );
    }
    let mut back = vec![0u8; payload.len()];
    if let Err(e) = stream.read_exact(&mut back) {
        panic!(
            "PRODUCT: the echo never came back through the overlay: {e}\nvox up said:\n{}\n\
             vox serve said:\n{}",
            up.transcript(),
            host.transcript()
        );
    }
    assert_eq!(
        back, payload,
        "PRODUCT: bytes must cross the overlay unchanged — this is the whole feature"
    );

    // And the host reports who reached it, which is the only place attribution can come
    // from: the service itself sees every Vox client as 127.0.0.1 (ADR-017 decision 6).
    let reached = host.expect_line("the host to report a client reaching the service", |l| {
        !l.starts_with("! ") && l.contains("reached")
    });
    assert!(
        reached.contains(&service_port.to_string()),
        "PRODUCT: the host should name the service that was reached: {reached}"
    );

    // ---- ADR-028 S-3 (#490): what reaching a share needs, and whether it holds, as the guest's
    // `vox service list` says it (a copied command reaching the service across members' own
    // names is a_service_is_reached_only_by_its_address_proof's).
    let (ssh_port, _ssh_heard) = ssh_banner_service();
    let (ok, out, err) = vox_once(
        &host_dir,
        &[
            "service".into(),
            "add".into(),
            room.clone(),
            "nas-ssh".into(),
            format!("127.0.0.1:{ssh_port}"),
        ],
    );
    assert!(ok, "PRODUCT (staging): the host shares nas-ssh: {out}{err}");
    let listing = |dir: &std::path::Path, want: &dyn Fn(&str) -> bool| {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let (ok, out, err) = vox_once(dir, &["service".into(), "list".into(), room.clone()]);
            if ok && want(&out) {
                return out;
            }
            assert!(
                Instant::now() < deadline,
                "PRODUCT: `vox service list` never showed what was expected: {out}{err}"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    };
    let guest_list = listing(&guest_dir, &|o| o.contains("nas-ssh."));
    // What it needs, and that it holds: the host trusts the guest, and is online.
    let trust_line = guest_list
        .lines()
        .skip_while(|l| !l.contains("nas-ssh."))
        .find(|l| l.contains("needs") && l.contains("trusts this node"))
        .unwrap_or_default()
        .to_owned();
    assert!(
        trust_line.ends_with(": yes"),
        "PRODUCT: the guest's listing must say the host trusts it: {trust_line:?}\n{guest_list}"
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
    std::fs::create_dir_all(stranger_dir.join("cfg")).expect("APPARATUS: create a profile dir");
    let (ok, out, err) = vox_once(
        &stranger_dir,
        &[
            "connect".into(),
            address.clone(),
            "--passphrase-file".into(),
            room_pass_file(&stranger_dir, &passphrase),
            "--anchor".into(),
            anchor_spec.clone(),
            "--listen".into(),
            "127.0.0.1:0".into(),
        ],
    );
    assert!(
        ok,
        "PRODUCT: the stranger must still be able to JOIN — the passphrase is the join credential and \
         always was; what changed is that joining grants no reach.\nstdout:\n{out}\nstderr:\n{err}"
    );
    let mut stranger_up = VoxProc::spawn(
        "stranger-up",
        &stranger_dir,
        &[
            "up".into(),
            room.clone(),
            "--passphrase-file".into(),
            room_pass_file(&stranger_dir, &passphrase),
            "--watch".into(),
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
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| panic!("PRODUCT: `vox up` printed no socket address: {s_line:?}"));
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
            "PRODUCT: an untrusted joiner holding the address AND the passphrase was told its \
             CONNECT succeeded — the proxy must answer with the host's refusal (PRD-001 R23)\n\
             the stranger's vox up said:\n{}\nvox serve said:\n{}",
            stranger_up.transcript(),
            host.transcript()
        ),
        Err(e) => {
            eprintln!("[test] the untrusted joiner was refused after {waited:?}: {e}");
            assert!(
                e.to_string().contains("SOCKS reply code 2"),
                "PRODUCT: the refusal must be SOCKS code 2 (not allowed), not a transport \
                 error: {e}\nthe stranger's vox up said:\n{}",
                stranger_up.transcript()
            );
        }
    }
    // And the stranger's own node says why, on its own terminal — the remote side learns
    // nothing it did not already say.
    let why = stranger_up.expect_line("the refusal's reason on the stranger's terminal", |l| {
        l.starts_with("! ") && l.contains("the host refused")
    });
    eprintln!("[test] the stranger's vox up said: {why}");
    // ADR-028 S-3: its listing names the condition that does not hold, before it tries.
    let (_, stranger_list, _) = vox_once(
        &stranger_dir,
        &["service".into(), "list".into(), room.clone()],
    );
    let stranger_needs = stranger_list
        .lines()
        .skip_while(|l| !l.contains("nas-ssh."))
        .find(|l| l.contains("needs") && l.contains("trusts this node"))
        .unwrap_or_default()
        .to_owned();
    eprintln!("[test] S-3: the stranger's listing:\n{stranger_list}");
    assert!(
        stranger_needs.contains(": NO") && stranger_needs.contains("must trust this node"),
        "PRODUCT: the untrusted joiner's `vox service list` must name what is missing, that the \
         host does not trust it: {stranger_needs:?}\n{stranger_list}"
    );

    drop(stranger_up);
    drop(host);
    drop(anchor);
}
