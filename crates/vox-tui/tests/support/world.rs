//! The shared harness for the proofs that drive real `vox` processes through a real
//! anchor: a child process read line by line, one-shot verbs, loopback services, and a
//! [`World`] of one anchor, one `vox serve` host and one joined guest.
//!
//! Included with `#[path]` by each proof that needs it, which is why not every item is
//! used by every includer.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const VOX: &str = env!("CARGO_BIN_EXE_vox");
pub const IDENTITY: &str = "identity passphrase";
/// Generous: production Argon2id derivations and a real PoW happen inside it.
pub const LINE_TIMEOUT: Duration = Duration::from_secs(180);

/// A `vox` child process whose stdout **and stderr** are read line by line, so a proof can
/// wait for what the product *says*. Stderr lines are prefixed `! ` so no stdout pattern
/// can match one by accident — the reasons this file asserts on are printed to stderr.
pub struct VoxProc {
    pub name: String,
    pub child: Child,
    pub lines: mpsc::Receiver<String>,
    pub seen: Vec<String>,
}

impl VoxProc {
    pub fn spawn(name: &str, data: &Path, args: &[String]) -> Self {
        let mut child = Command::new(VOX)
            .args(args)
            .env("VOX_DATA_DIR", data)
            .env("VOX_CONFIG_DIR", data.join("cfg"))
            .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
            .env_remove("VOX_ROOM_PASSPHRASE")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {name}: {e}"));
        let (tx, rx) = mpsc::channel();
        let out = child.stdout.take().expect("stdout");
        let err = child.stderr.take().expect("stderr");
        let tx_err = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        // Drained on its own thread: a full pipe would block the child, which is a hang
        // rather than a failure (ADR-018 §6).
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                if tx_err.send(format!("! {line}")).is_err() {
                    break;
                }
            }
        });
        Self {
            name: name.to_owned(),
            child,
            lines: rx,
            seen: Vec::new(),
        }
    }

    /// Wait up to `within` for the first line matching `pred`. Every line seen is kept so a
    /// failure shows what the command actually said.
    pub fn expect_within(
        &mut self,
        within: Duration,
        what: &str,
        pred: impl Fn(&str) -> bool,
    ) -> String {
        if let Some(line) = self.seen.iter().find(|l| pred(l)) {
            return line.clone();
        }
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "{}: timed out after {within:?} waiting for {what}. It said:\n{}",
                self.name,
                self.seen.join("\n")
            );
            match self.lines.recv_timeout(left.min(Duration::from_secs(5))) {
                Ok(line) => {
                    eprintln!("[{}] {line}", self.name);
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

    /// Everything the process has said so far, including lines nobody waited for — for a
    /// failure message, so it shows the whole story rather than the part a proof asked about.
    pub fn transcript(&mut self) -> String {
        while let Ok(line) = self.lines.try_recv() {
            self.seen.push(line);
        }
        self.seen.join("\n")
    }

    pub fn expect_line(&mut self, what: &str, pred: impl Fn(&str) -> bool) -> String {
        self.expect_within(LINE_TIMEOUT, what, pred)
    }
}

impl Drop for VoxProc {
    fn drop(&mut self) {
        // By the child's own handle — its PID — never by pattern (ADR-018 §6), and reaped,
        // so nothing outlives the proof.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Run a one-shot `vox` verb to completion.
pub fn vox_once(data: &Path, args: &[String]) -> (bool, String, String) {
    let out = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::null())
        .output()
        .expect("run vox");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

pub fn after_label(line: &str, label: &str) -> String {
    line.strip_prefix(label)
        .unwrap_or_else(|| panic!("line {line:?} does not start with {label:?}"))
        .trim()
        .to_owned()
}

pub fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

/// A real TCP echo service on loopback. Returns its port.
pub fn echo_service() -> u16 {
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

/// What the crashing backend sends before it resets.
pub const PARTIAL: &[u8] = b"the first half of a reply";

/// A backend that **crashes mid-reply**: reads a request, sends [`PARTIAL`], waits long
/// enough for it to cross the overlay, then resets its socket (zero linger, so the kernel
/// sends RST rather than FIN). Returns its port.
pub fn resetting_service() -> u16 {
    let std_listener = TcpListener::bind("127.0.0.1:0").expect("bind resetting backend");
    let port = std_listener.local_addr().unwrap().port();
    std_listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    continue;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 256];
                    if !matches!(s.read(&mut buf).await, Ok(n) if n > 0) {
                        return;
                    }
                    let _ = s.write_all(PARTIAL).await;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    s.set_zero_linger().unwrap();
                    drop(s);
                });
            }
        });
    });
    port
}

/// The host's handshake bound (`HANDSHAKE_TIMEOUT`, 30 s) with a margin. See [`World::new`].
pub const ACCEPT_WINDOW: Duration = Duration::from_secs(35);

/// One host, one anchor, one guest who has joined the host's `vox serve` room.
pub struct World {
    pub tmp: tempfile::TempDir,
    /// Held for its lifetime: the anchor must outlive everything that reaches through it.
    pub _anchor: VoxProc,
    pub anchor_spec: String,
    pub host_dir: PathBuf,
    pub guest_dir: PathBuf,
    pub host: Option<VoxProc>,
    pub host_fp: String,
    pub room: String,
    pub address: String,
    pub passphrase: String,
    pub service_port: u16,
}

impl World {
    /// Anchor, host serving `service_port`, and a guest joined — trusted by the host only if
    /// `trusted`, which is the whole authorization (ADR-017 decision 3).
    pub fn new(service_port: u16, trusted: bool) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let (host_dir, guest_dir) = (tmp.path().join("host"), tmp.path().join("guest"));
        let anchor_dir = tmp.path().join("anchor");
        for d in [&anchor_dir, &host_dir, &guest_dir] {
            std::fs::create_dir_all(d.join("cfg")).unwrap();
        }
        let mut anchor = VoxProc::spawn(
            "anchor",
            &anchor_dir,
            &args(&["node", "--listen", "127.0.0.1:0"]),
        );
        let anchor_spec = anchor
            .expect_line("an --anchor spec", |l| {
                !l.starts_with("! ")
                    && l.trim_start().contains('@')
                    && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
            })
            .trim()
            .to_owned();

        let (ok, guest_fp, err) = vox_once(&guest_dir, &args(&["id"]));
        assert!(ok, "vox id (guest): {err}");
        let guest_fp = guest_fp.trim().to_owned();
        let (ok, host_fp, err) = vox_once(&host_dir, &args(&["id"]));
        assert!(ok, "vox id (host): {err}");
        let host_fp = host_fp.trim().to_owned();
        assert_eq!(
            (guest_fp.len(), host_fp.len()),
            (52, 52),
            "two fingerprints"
        );
        if trusted {
            let (ok, out, err) = vox_once(
                &host_dir,
                &args(&["trust", "add", &guest_fp, "--name", "the guest"]),
            );
            assert!(ok, "trust add: {out}\n{err}");
        }

        let mut host = VoxProc::spawn(
            "host",
            &host_dir,
            &args(&[
                "serve",
                &service_port.to_string(),
                "--anchor",
                &anchor_spec,
                "--listen",
                "127.0.0.1:0",
            ]),
        );
        let room = after_label(
            &host.expect_line("room", |l| l.starts_with("room ")),
            "room",
        );
        let address = after_label(
            &host.expect_line("address", |l| l.starts_with("address ")),
            "address",
        );
        let passphrase = after_label(
            &host.expect_line("passphrase", |l| l.starts_with("passphrase ")),
            "passphrase",
        );
        let w = Self {
            tmp,
            _anchor: anchor,
            anchor_spec,
            host_dir,
            guest_dir,
            host: Some(host),
            host_fp,
            room,
            address,
            passphrase,
            service_port,
        };
        let (ok, _, out, err) = w.join(&w.guest_dir);
        assert!(ok, "vox connect failed.\nstdout:\n{out}\nstderr:\n{err}");
        // **Wait out the host's accept window before anything dials it.** While the node's
        // accept loop awaits each handshake inline (PRD-001 D8, owned on
        // `fix/accept-loop-split`), the one-shot `vox connect` above leaves the host deaf to
        // everybody for up to its 30 s handshake bound, and a dialer that retries inside that
        // window keeps it deaf: measured, a `vox up` never reached a host that was up for
        // 300 s. That is D8's to prove and fix, not these proofs', so they step around it —
        // and this wait is to be removed once the accept loop is split.
        std::thread::sleep(ACCEPT_WINDOW);
        w
    }

    /// `vox connect` the profile at `dir` into this world's room, with the address and the
    /// passphrase exactly as `vox serve` printed them. Returns whether it joined, how long
    /// it took, and what it said.
    pub fn join(&self, dir: &Path) -> (bool, Duration, String, String) {
        let t0 = Instant::now();
        let (ok, out, err) = vox_once(
            dir,
            &args(&[
                "connect",
                &self.address,
                "--passphrase",
                &self.passphrase,
                "--anchor",
                &self.anchor_spec,
                "--listen",
                "127.0.0.1:0",
            ]),
        );
        (ok, t0.elapsed(), out, err)
    }

    /// Kill the host's `vox serve` and bring the same identity and room back as
    /// `vox daemon`, on a **new** port — a restart and a path change at once.
    pub fn restart_host_as_daemon(&mut self) {
        let old_pid = self.host.as_ref().map(|h| h.child.id());
        drop(self.host.take());
        if let Some(pid) = old_pid {
            // Reaped by the drop; say so rather than assume it (ADR-018 §6).
            eprintln!("[test] host `vox serve` pid {pid} killed and reaped");
        }
        let pass_file = self.tmp.path().join("daemon-passphrases");
        std::fs::write(&pass_file, format!("{IDENTITY}\n{}\n", self.passphrase)).unwrap();
        let mut daemon = VoxProc::spawn(
            "host-daemon",
            &self.host_dir,
            &args(&[
                "daemon",
                "--passphrase-file",
                pass_file.to_str().unwrap(),
                "--anchor",
                &self.anchor_spec,
                "--listen",
                "127.0.0.1:0",
            ]),
        );
        let room = self.room.clone();
        daemon.expect_line("the daemon to hold the room open", |l| {
            l.starts_with("vox daemon: holding room") && l.contains(&room)
        });
        self.host = Some(daemon);
    }

    /// `vox up <room>` from `dir`; returns it and the SOCKS address it bound.
    pub fn up(&self, name: &str, dir: &Path) -> (VoxProc, SocketAddr) {
        let mut up = VoxProc::spawn(
            name,
            dir,
            &args(&[
                "up",
                &self.room,
                "--passphrase",
                &self.passphrase,
                "--bind",
                "127.0.0.1:0",
                "--anchor",
                &self.anchor_spec,
                "--listen",
                "127.0.0.1:0",
            ]),
        );
        let line = up.expect_line("the proxy's bound address", |l| l.starts_with("vox up on "));
        let bound: SocketAddr = line
            .split_whitespace()
            .nth(3)
            .expect("an address in the up line")
            .parse()
            .expect("a socket address");
        (up, bound)
    }

    /// `vox forward <room> <host> <port>` from `dir`; returns it and the address it bound.
    pub fn forward(&self, name: &str, dir: &Path) -> (VoxProc, SocketAddr) {
        let mut fwd = VoxProc::spawn(
            name,
            dir,
            &args(&[
                "forward",
                &self.room,
                &self.host_fp,
                &self.service_port.to_string(),
                "127.0.0.1:0",
                "--passphrase",
                &self.passphrase,
                "--anchor",
                &self.anchor_spec,
                "--listen",
                "127.0.0.1:0",
            ]),
        );
        let line = fwd.expect_line("the forward's bound address", |l| {
            l.starts_with("vox: 127.0.0.1:") && l.contains('→')
        });
        let bound: SocketAddr = line
            .split_whitespace()
            .nth(1)
            .expect("an address")
            .parse()
            .expect("a socket address");
        (fwd, bound)
    }
}

/// Speak RFC 1928 to `proxy` and CONNECT to `host:port` **by name** (`socks5h`), returning
/// the reply code — `0` is success — and the stream positioned at the payload.
pub fn socks5_connect(proxy: SocketAddr, host: &str, port: u16) -> (u8, TcpStream) {
    let mut s = TcpStream::connect(proxy).expect("connect to the proxy");
    // Longer than the proxy's own patience, so its verdict is what this reports.
    s.set_read_timeout(Some(
        vox_core::node::up::HOST_PATIENCE + Duration::from_secs(30),
    ))
    .unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut hello = [0u8; 2];
    s.read_exact(&mut hello).unwrap();
    assert_eq!(hello, [0x05, 0x00], "proxy refused the no-auth method");
    let mut req = vec![0x05, 0x01, 0x00, 0x03, u8::try_from(host.len()).unwrap()];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).unwrap();
    let mut head = [0u8; 4];
    s.read_exact(&mut head).unwrap();
    assert_eq!(head[0], 0x05, "not a SOCKS5 reply");
    let skip = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        other => panic!("unexpected address type {other} in reply"),
    };
    let mut sink = vec![0u8; skip];
    s.read_exact(&mut sink).unwrap();
    (head[1], s)
}

/// Connect through `at`, send `payload`, and read the echo, waiting up to `patience` for the
/// forward to reach its host. Returns what came back.
pub fn round_trip(at: SocketAddr, payload: &[u8], patience: Duration) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(at)?;
    s.set_read_timeout(Some(patience))?;
    s.write_all(payload)?;
    let mut back = vec![0u8; payload.len()];
    s.read_exact(&mut back)?;
    Ok(back)
}

/// How a read ended: bytes, an orderly EOF, a reset, or still open when the clock ran out.
#[derive(Debug, PartialEq, Eq)]
pub enum Ending {
    Eof,
    Reset,
    OtherError(ErrorKind),
    StillOpen,
}

/// Read until the connection ends or `within` passes, returning the bytes read and how it
/// ended. A read timeout is reported as [`Ending::StillOpen`], never as an error — mixing
/// the two would let a session that was never cut pass a proof that it was.
pub fn read_to_end_within(s: &mut TcpStream, within: Duration) -> (Vec<u8>, Ending) {
    let deadline = Instant::now() + within;
    let mut got = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return (got, Ending::StillOpen);
        }
        // macOS refuses `SO_RCVTIMEO` with EINVAL on a socket that has already been reset,
        // so a failure here is not the proof's to report: the read below says what happened.
        let _ = s.set_read_timeout(Some(left));
        match s.read(&mut buf) {
            Ok(0) => return (got, Ending::Eof),
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return (got, Ending::StillOpen)
            }
            Err(e) if e.kind() == ErrorKind::ConnectionReset => return (got, Ending::Reset),
            Err(e) => return (got, Ending::OtherError(e.kind())),
        }
    }
}
