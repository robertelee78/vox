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

    /// The first line matching `pred` within `within`, or `None` if the process exits or
    /// the time runs out first — for a caller that has something better to do than fail.
    pub fn wait_for(&mut self, within: Duration, pred: impl Fn(&str) -> bool) -> Option<String> {
        if let Some(line) = self.seen.iter().find(|l| pred(l)) {
            return Some(line.clone());
        }
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    eprintln!("[{}] {line}", self.name);
                    let hit = pred(&line);
                    self.seen.push(line.clone());
                    if hit {
                        return Some(line);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => return None,
                Err(mpsc::RecvTimeoutError::Disconnected) => return None,
            }
        }
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

/// The path a world forces between its guest and its host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathKind {
    /// Everyone on IPv4 loopback: the guest dials the host straight.
    Direct,
    /// The host on IPv6 loopback, the guest on IPv4, the anchor on both: nothing but a
    /// relay circuit through the anchor can join them.
    Relayed,
}

impl PathKind {
    /// Where the host listens.
    #[must_use]
    pub fn host_listen(self) -> &'static str {
        match self {
            PathKind::Direct => "127.0.0.1:0",
            PathKind::Relayed => "[::1]:0",
        }
    }
}

/// How a [`World`] is built.
pub struct Setup {
    /// What the host serves: `<port>`, `<port>/udp`, …
    pub specs: Vec<String>,
    /// Whether the host trusts the guest.
    pub trusted: bool,
    /// The path between them.
    pub path: PathKind,
    /// Put something between the guest and the anchor: given the anchor's IPv4 address,
    /// return the address the guest should use instead (a lossy proxy, say).
    #[allow(clippy::type_complexity)]
    pub guest_leg: Option<Box<dyn Fn(SocketAddr) -> Option<SocketAddr>>>,
}

/// A UDP port free on the dual-stack wildcard, for an anchor that must be reachable over
/// both IPv4 and IPv6 loopback.
#[must_use]
pub fn free_dual_stack_port() -> u16 {
    let s = std::net::UdpSocket::bind("[::]:0").expect("bind [::]:0");
    s.local_addr().unwrap().port()
}

/// The socket address in an `--anchor` spec (`<fp>@/ip4/<ip>/udp/<port>`).
#[must_use]
pub fn spec_addr(spec: &str) -> SocketAddr {
    let parts: Vec<&str> = spec.split('/').collect();
    let port: u16 = parts[parts.len() - 1].parse().expect("a port in the spec");
    let ip: std::net::IpAddr = parts[parts.len() - 3].parse().expect("an ip in the spec");
    SocketAddr::new(ip, port)
}

/// `spec` with its address replaced by `addr`.
#[must_use]
pub fn respec(spec: &str, addr: SocketAddr) -> String {
    let fp = spec.split('@').next().unwrap();
    match addr {
        SocketAddr::V4(a) => format!("{fp}@/ip4/{}/udp/{}", a.ip(), a.port()),
        SocketAddr::V6(a) => format!("{fp}@/ip6/{}/udp/{}", a.ip(), a.port()),
    }
}

/// A UDP proxy on IPv4 loopback in front of `upstream`: every datagram crosses it after
/// `delay`, and while `drop_every` is non-zero every `drop_every`-th one from the client
/// side is lost. Returns its address, the count of datagrams it dropped, and the knob —
/// so a proof can let setup through clean and switch the loss on for the measurement. One
/// upstream socket per client address, as a NAT would.
#[must_use]
pub fn lossy_proxy(
    upstream: SocketAddr,
    delay: Duration,
) -> (
    SocketAddr,
    std::sync::Arc<std::sync::atomic::AtomicU64>,
    std::sync::Arc<std::sync::atomic::AtomicU64>,
) {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    let front = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = front.local_addr().unwrap();
    front.set_nonblocking(true).unwrap();
    let dropped = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&dropped);
    let knob = Arc::new(AtomicU64::new(0));
    let every = Arc::clone(&knob);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let front = Arc::new(tokio::net::UdpSocket::from_std(front).unwrap());
            let mut backs: std::collections::HashMap<SocketAddr, Arc<tokio::net::UdpSocket>> =
                std::collections::HashMap::new();
            let mut seen = 0u64;
            let mut buf = vec![0u8; 65_535];
            loop {
                let Ok((n, client)) = front.recv_from(&mut buf).await else {
                    continue;
                };
                let back = if let Some(b) = backs.get(&client) {
                    Arc::clone(b)
                } else {
                    let b = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
                    b.connect(upstream).await.unwrap();
                    backs.insert(client, Arc::clone(&b));
                    // The return leg: delayed, never dropped.
                    let (b2, front2) = (Arc::clone(&b), Arc::clone(&front));
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65_535];
                        while let Ok(n) = b2.recv(&mut buf).await {
                            let d = buf[..n].to_vec();
                            let f = Arc::clone(&front2);
                            tokio::spawn(async move {
                                tokio::time::sleep(delay).await;
                                let _ = f.send_to(&d, client).await;
                            });
                        }
                    });
                    b
                };
                seen += 1;
                let drop_every = every.load(Ordering::Relaxed);
                if drop_every > 0 && seen.is_multiple_of(drop_every) {
                    counted.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let d = buf[..n].to_vec();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = back.send(&d).await;
                });
            }
        });
    });
    (addr, dropped, knob)
}

/// One host, one anchor, one guest who has joined the host's `vox serve` room.
pub struct World {
    pub tmp: tempfile::TempDir,
    /// The anchor, held for the world's lifetime: it must outlive everything that reaches
    /// through it. Its status lines say how many circuits it carries.
    pub anchor: VoxProc,
    /// The anchor spec the host uses.
    pub host_anchor: String,
    /// The anchor spec every guest uses — the same as the host's on a direct path.
    pub guest_anchor: String,
    /// The path the world forces between guest and host.
    pub path: PathKind,
    pub host_dir: PathBuf,
    pub guest_dir: PathBuf,
    pub host: Option<VoxProc>,
    pub host_fp: String,
    /// The guest's fingerprint, for the host to trust or untrust.
    pub guest_fp: String,
    pub room: String,
    pub address: String,
    pub passphrase: String,
    pub service_port: u16,
}

impl World {
    /// Anchor, host serving `service_port`, and a guest joined — trusted by the host only if
    /// `trusted`, which is the whole authorization (ADR-017 decision 3).
    pub fn new(service_port: u16, trusted: bool) -> Self {
        Self::build(&Setup {
            specs: vec![service_port.to_string()],
            trusted,
            path: PathKind::Direct,
            guest_leg: None,
        })
    }

    /// A world serving `setup.specs` (`<port>`, `<port>/udp`) on the path `setup.path`.
    pub fn build(setup: &Setup) -> Self {
        let trusted = setup.trusted;
        let tmp = tempfile::tempdir().unwrap();
        let (host_dir, guest_dir) = (tmp.path().join("host"), tmp.path().join("guest"));
        let anchor_dir = tmp.path().join("anchor");
        for d in [&anchor_dir, &host_dir, &guest_dir] {
            std::fs::create_dir_all(d.join("cfg")).unwrap();
        }
        let (anchor, host_anchor, guest_anchor) = match setup.path {
            PathKind::Direct => {
                let mut anchor = VoxProc::spawn(
                    "anchor",
                    &anchor_dir,
                    &args(&["node", "--listen", "127.0.0.1:0"]),
                );
                let spec = anchor
                    .expect_line("an --anchor spec", |l| {
                        !l.starts_with("! ")
                            && l.trim_start().contains('@')
                            && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
                    })
                    .trim()
                    .to_owned();
                let guest = match &setup.guest_leg {
                    Some(leg) => leg(spec_addr(&spec)).map_or(spec.clone(), |a| respec(&spec, a)),
                    None => spec.clone(),
                };
                (anchor, spec, guest)
            }
            PathKind::Relayed => {
                // **A relay forced without touching the product.** The anchor listens
                // dual-stack; the host lives on IPv6 loopback only and the guest on IPv4
                // loopback only, so each reaches the anchor and neither can send a single
                // packet to the other. Every direct rung fails by construction and the
                // only path between them is a circuit the anchor carries.
                // The port is picked free and then released, so another process can take
                // it first; a few fresh tries cover that race.
                let (port, anchor, id) = (0..5)
                    .find_map(|_| {
                        let port = free_dual_stack_port();
                        let mut anchor = VoxProc::spawn(
                            "anchor",
                            &anchor_dir,
                            &args(&["node", "--listen", &format!("[::]:{port}")]),
                        );
                        let id = anchor
                            .wait_for(LINE_TIMEOUT, |l| l.starts_with("vox node: identity "))?;
                        Some((port, anchor, id))
                    })
                    .expect("an anchor on a free dual-stack port");
                let fp = id.split_whitespace().last().unwrap().to_owned();
                let v4 = SocketAddr::from(([127, 0, 0, 1], port));
                let guest_addr = setup
                    .guest_leg
                    .as_ref()
                    .and_then(|leg| leg(v4))
                    .unwrap_or(v4);
                let guest = match guest_addr {
                    SocketAddr::V4(a) => format!("{fp}@/ip4/{}/udp/{}", a.ip(), a.port()),
                    SocketAddr::V6(a) => format!("{fp}@/ip6/{}/udp/{}", a.ip(), a.port()),
                };
                (anchor, format!("{fp}@/ip6/::1/udp/{port}"), guest)
            }
        };
        let anchor_spec = host_anchor.clone();
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
            &[
                vec!["serve".to_owned()],
                setup.specs.clone(),
                args(&[
                    "--anchor",
                    &anchor_spec,
                    "--listen",
                    setup.path.host_listen(),
                ]),
            ]
            .concat(),
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
            anchor,
            host_anchor,
            guest_anchor,
            path: setup.path,
            host_dir,
            guest_dir,
            host: Some(host),
            host_fp,
            guest_fp,
            room,
            address,
            passphrase,
            service_port: setup
                .specs
                .first()
                .and_then(|s| s.split('/').next())
                .and_then(|p| p.parse().ok())
                .unwrap_or(0),
        };
        let (ok, _, out, err) = w.join(&w.guest_dir);
        assert!(ok, "vox connect failed.\nstdout:\n{out}\nstderr:\n{err}");
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
                &self.guest_anchor,
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
                &self.host_anchor,
                "--listen",
                self.path.host_listen(),
            ]),
        );
        let room = self.room.clone();
        daemon.expect_line("the daemon to hold the room open", |l| {
            l.starts_with("vox daemon: holding room") && l.contains(&room)
        });
        self.host = Some(daemon);
    }

    /// `vox forward <room>.vox <spec> 0` from `dir` — the `.vox` form ADR-022 names, where
    /// the name gives the room and its host — returning it and the address it bound.
    pub fn forward_vox(&self, name: &str, dir: &Path, spec: &str) -> (VoxProc, SocketAddr) {
        let mut fwd = VoxProc::spawn(
            name,
            dir,
            &args(&[
                "forward",
                &format!("{}.vox", self.room),
                spec,
                "0",
                "--passphrase",
                &self.passphrase,
                "--anchor",
                &self.guest_anchor,
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
                &self.guest_anchor,
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
                &self.guest_anchor,
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
