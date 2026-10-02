//! The shared harness for the proofs that drive real `vox` processes through a real
//! anchor: a child process read line by line, one-shot verbs, loopback services, and a
//! [`World`] of one anchor, one `vox serve` host and one joined guest.
//!
//! Included with `#[path]` by each proof that needs it, which is why not every item is
//! used by every includer.
//!
//! **Every red here names its side** (V210-106): `PRODUCT:` when `vox` said or did the wrong
//! thing — quoting what it said, stderr included — and `APPARATUS:` or `CANNOT MEASURE:` when the
//! fault is this harness's or the machine's (a spawn, a temp dir, a socket of the proof's own, a
//! runner that stalled), naming the fault.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
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
    /// Every stderr line with **when it was read**, so a proof's red can say when each thing
    /// the product noticed happened, not only that it did.
    pub timed: Arc<Mutex<Vec<(Instant, String)>>>,
    /// When it was started, so a red can say how long it had.
    pub started: Instant,
}

/// The longest a wait that asked for at most [`POLL`] may overrun it before this process counts
/// as **stalled** — not scheduled, so not watching — rather than the product as silent.
pub const STALL: Duration = Duration::from_secs(5);
/// The longest one wait for a line lasts before the harness looks at the clock again.
const POLL: Duration = Duration::from_secs(1);

impl VoxProc {
    pub fn spawn(name: &str, data: &Path, args: &[String]) -> Self {
        Self::spawn_env(name, data, args, &[])
    }

    /// [`VoxProc::spawn`] with extra environment, for the proofs' test-only knobs.
    pub fn spawn_env(name: &str, data: &Path, args: &[String], env: &[(&str, &str)]) -> Self {
        Self::spawn_exe(Path::new(VOX), name, data, args, env)
    }

    /// [`VoxProc::spawn_env`] with another `vox` binary (a previous release, for a migration).
    pub fn spawn_exe(
        exe: &Path,
        name: &str,
        data: &Path,
        args: &[String],
        env: &[(&str, &str)],
    ) -> Self {
        let mut child = Command::new(exe)
            .args(args)
            .envs(env.iter().copied())
            .env("VOX_DATA_DIR", data)
            .env("VOX_CONFIG_DIR", data.join("cfg"))
            .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
            .env_remove("VOX_ROOM_PASSPHRASE")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| {
                panic!("APPARATUS: could not spawn {name} ({}): {e}", exe.display())
            });
        let started = Instant::now();
        let (tx, rx) = mpsc::channel();
        let out = child.stdout.take().expect("APPARATUS: a piped stdout");
        let err = child.stderr.take().expect("APPARATUS: a piped stderr");
        let tx_err = tx.clone();
        let timed = Arc::new(Mutex::new(Vec::new()));
        let timed_err = Arc::clone(&timed);
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
                timed_err
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((Instant::now(), line.clone()));
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
            timed,
            started,
        }
    }

    /// Wait up to `within` for the first line matching `pred`, **a claim**: `vox` not saying it
    /// is a `PRODUCT:` red. Every line seen is kept so a failure shows what the command actually
    /// said. A wait this process overslept by more than [`STALL`] is `CANNOT MEASURE:` instead —
    /// a runner that did not schedule the harness cannot say the product was silent.
    pub fn expect_within(
        &mut self,
        within: Duration,
        what: &str,
        pred: impl Fn(&str) -> bool,
    ) -> String {
        self.wait_for("PRODUCT:", within, what, pred)
            .unwrap_or_else(|why| panic!("{why}"))
    }

    /// [`Self::expect_within`], handing back why it did not come instead of panicking, so a proof
    /// can say which side a missing line is on: a precondition the scene never reached
    /// (apparatus), or something the product failed to say. The reason carries the same labels
    /// [`Self::expect_within`] would have panicked with, the stall check included.
    pub fn try_expect_within(
        &mut self,
        within: Duration,
        what: &str,
        pred: impl Fn(&str) -> bool,
    ) -> Result<String, String> {
        self.wait_for("PRODUCT:", within, what, pred)
    }

    /// [`VoxProc::expect_within`] for **staging** — a state the proof needs before it can measure
    /// anything, which the product may legitimately not reach (a path that did not end up
    /// relayed). Not reaching it is `CANNOT MEASURE: staging not achieved`, never a verdict.
    pub fn expect_staging_within(
        &mut self,
        within: Duration,
        what: &str,
        pred: impl Fn(&str) -> bool,
    ) -> String {
        self.wait_for("CANNOT MEASURE: staging not achieved:", within, what, pred)
            .unwrap_or_else(|why| panic!("{why}"))
    }

    /// The one wait loop: the first line matching `pred` within `within`, or why not, labelled
    /// `side` — or `CANNOT MEASURE: the runner stalled:` if this process overslept a wait by
    /// more than [`STALL`], and `PRODUCT:` with its exit status if it exited first.
    fn wait_for(
        &mut self,
        side: &str,
        within: Duration,
        what: &str,
        pred: impl Fn(&str) -> bool,
    ) -> Result<String, String> {
        if let Some(line) = self.seen.iter().find(|l| pred(l)) {
            return Ok(line.clone());
        }
        let t0 = Instant::now();
        let deadline = t0 + within;
        // The harness's own clock: how far past what it asked for one wait came back.
        let mut overslept = Duration::ZERO;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                let side = if overslept > STALL {
                    "CANNOT MEASURE: the runner stalled:"
                } else {
                    side
                };
                return Err(format!(
                    "{side} {} did not say {what} within {within:?} (it has run {:?}; this \
                     harness overslept one wait by at most {overslept:?}, so it was watching). It \
                     said:\n{}",
                    self.name.clone(),
                    self.started.elapsed(),
                    self.transcript()
                ));
            }
            let ask = left.min(POLL);
            let asked = Instant::now();
            let got = self.lines.recv_timeout(ask);
            overslept = overslept.max(asked.elapsed().saturating_sub(ask));
            match got {
                Ok(line) => {
                    eprintln!("[{}] {line}", self.name);
                    let hit = pred(&line);
                    self.seen.push(line.clone());
                    if hit {
                        return Ok(line);
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(format!(
                        "PRODUCT: {} exited ({}) after {:?}, before saying {what}. It said:\n{}",
                        self.name.clone(),
                        self.exit_status(),
                        self.started.elapsed(),
                        self.seen.join("\n")
                    ))
                }
            }
        }
    }

    /// How the process ended, for a red: its exit status, or that it still runs (its output
    /// closed without it exiting), or why that could not be read.
    pub fn exit_status(&mut self) -> String {
        // Its output has closed; give the exit a moment to be reaped before asking.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return status.to_string(),
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => return "still running, with its output closed".to_owned(),
                Err(e) => return format!("exit status unreadable: {e}"),
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

    /// Every stderr line so far, each with its time relative to `t0` in seconds.
    pub fn said_since(&self, t0: Instant) -> Vec<String> {
        self.timed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(at, l)| {
                let (sign, d) = match at.checked_duration_since(t0) {
                    Some(d) => ("+", d),
                    None => ("-", t0.duration_since(*at)),
                };
                format!("[{sign}{:.3}s] {l}", d.as_secs_f64())
            })
            .collect()
    }

    pub fn expect_line(&mut self, what: &str, pred: impl Fn(&str) -> bool) -> String {
        self.expect_within(LINE_TIMEOUT, what, pred)
    }

    /// [`VoxProc::expect_staging_within`], with [`LINE_TIMEOUT`].
    pub fn expect_staging(&mut self, what: &str, pred: impl Fn(&str) -> bool) -> String {
        self.expect_staging_within(LINE_TIMEOUT, what, pred)
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
        .unwrap_or_else(|e| panic!("APPARATUS: could not run {VOX} {args:?}: {e}"));
    // **How it ended, not only whether it succeeded** (V210-85). A `vox connect` killed by the
    // watchdog's SIGKILL read as `false` with empty output — the same as a verb that failed and
    // said nothing — and was reported as a product failure with no reason.
    if !out.status.success() {
        eprintln!(
            "[vox_once] vox {}: {}",
            args.first().map_or("", String::as_str),
            out.status
        );
    }
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

pub fn after_label(line: &str, label: &str) -> String {
    line.strip_prefix(label)
        .unwrap_or_else(|| {
            panic!("PRODUCT: vox printed {line:?}, which does not start with {label:?}")
        })
        .trim()
        .to_owned()
}

/// Write the room passphrase `pass` beside the profile at `dir`, for `--passphrase-file`: a
/// room passphrase is never taken from argv or the environment (V210-72).
#[allow(dead_code)]
pub fn room_pass_file(dir: &Path, pass: &str) -> String {
    let at = dir.join("room-passphrase");
    std::fs::create_dir_all(dir)
        .and_then(|()| std::fs::write(&at, pass))
        .unwrap_or_else(|e| panic!("APPARATUS: could not write {}: {e}", at.display()));
    utf8(&at)
}

/// `p` as UTF-8, for an argument; a temp path that is not is the apparatus's fault.
pub fn utf8(p: &Path) -> String {
    p.to_str()
        .unwrap_or_else(|| panic!("APPARATUS: the path {} is not UTF-8", p.display()))
        .to_owned()
}

/// A fresh temp dir, or an `APPARATUS:` red naming why there is none.
pub fn tempdir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap_or_else(|e| panic!("APPARATUS: no temp dir: {e}"))
}

/// `create_dir_all`, or an `APPARATUS:` red naming the directory.
pub fn mkdir(d: &Path) {
    std::fs::create_dir_all(d)
        .unwrap_or_else(|e| panic!("APPARATUS: could not create {}: {e}", d.display()));
}

pub fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

/// A real TCP echo service on loopback that **counts every connection it accepts**, so a
/// proof can say the service was never dialled. Returns its port and the count.
pub fn counting_echo_service() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|e| panic!("APPARATUS: could not bind the counting echo service: {e}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("APPARATUS: the counting echo service has no address: {e}"))
        .port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            count.fetch_add(1, Ordering::SeqCst);
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
    (port, accepted)
}

/// A real TCP echo service on loopback. Returns its port.
pub fn echo_service() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|e| panic!("APPARATUS: could not bind the echo service: {e}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("APPARATUS: the echo service has no address: {e}"))
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

/// What the crashing backend sends before it resets.
pub const PARTIAL: &[u8] = b"the first half of a reply";

/// A backend that **crashes mid-reply**: reads a request, sends [`PARTIAL`], waits long
/// enough for it to cross the overlay, then resets its socket (zero linger, so the kernel
/// sends RST rather than FIN). Returns its port.
pub fn resetting_service() -> u16 {
    let std_listener = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|e| panic!("APPARATUS: could not bind the resetting backend: {e}"));
    let port = std_listener
        .local_addr()
        .unwrap_or_else(|e| panic!("APPARATUS: the resetting backend has no address: {e}"))
        .port();
    std_listener
        .set_nonblocking(true)
        .unwrap_or_else(|e| panic!("APPARATUS: the resetting backend: {e}"));
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|e| panic!("APPARATUS: the resetting backend's runtime: {e}"));
        rt.block_on(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let listener = tokio::net::TcpListener::from_std(std_listener)
                .unwrap_or_else(|e| panic!("APPARATUS: the resetting backend's listener: {e}"));
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
                    s.set_zero_linger().unwrap_or_else(|e| {
                        panic!("APPARATUS: the resetting backend's linger: {e}")
                    });
                    drop(s);
                });
            }
        });
    });
    port
}

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
        let tmp = tempdir();
        let (host_dir, guest_dir) = (tmp.path().join("host"), tmp.path().join("guest"));
        let anchor_dir = tmp.path().join("anchor");
        for d in [&anchor_dir, &host_dir, &guest_dir] {
            mkdir(&d.join("cfg"));
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

        let guest_fp = fingerprint(&guest_dir, "guest");
        let host_fp = fingerprint(&host_dir, "host");
        if trusted {
            let (ok, out, err) = vox_once(
                &host_dir,
                &args(&["trust", "add", &guest_fp, "--name", "the guest"]),
            );
            assert!(
                ok,
                "PRODUCT (staging): the host's `vox trust add` of the guest failed.\nstdout:\n{out}\nstderr:\n{err}"
            );
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
        let mut w = Self {
            tmp,
            _anchor: anchor,
            anchor_spec,
            host_dir,
            guest_dir,
            host: Some(host),
            host_fp,
            guest_fp,
            room,
            address,
            passphrase,
            service_port,
        };
        let (ok, took, out, err) = w.join(&w.guest_dir);
        if !ok {
            let host = w.host.as_mut().map(VoxProc::transcript).unwrap_or_default();
            panic!(
                "PRODUCT (staging): the guest's `vox connect` failed after {took:?}.\nstdout:\n{out}\n\
                 stderr:\n{err}\nthe host's `vox serve` said:\n{host}"
            );
        }
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
                "--passphrase-file",
                &self.passphrase_file(),
                "--anchor",
                &self.anchor_spec,
                "--listen",
                "127.0.0.1:0",
            ]),
        );
        (ok, t0.elapsed(), out, err)
    }

    /// The room passphrase in a file, for `--passphrase-file`: a room passphrase is never
    /// taken from argv or the environment (V210-72).
    pub fn passphrase_file(&self) -> String {
        room_pass_file(self.tmp.path(), &self.passphrase)
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
        std::fs::write(&pass_file, format!("{IDENTITY}\n{}\n", self.passphrase))
            .unwrap_or_else(|e| panic!("APPARATUS: could not write {}: {e}", pass_file.display()));
        let mut daemon = VoxProc::spawn(
            "host-daemon",
            &self.host_dir,
            &args(&[
                "daemon",
                "--passphrase-file",
                &utf8(&pass_file),
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
                "--passphrase-file",
                &self.passphrase_file(),
                "--bind",
                "127.0.0.1:0",
                "--anchor",
                &self.anchor_spec,
                "--listen",
                "127.0.0.1:0",
            ]),
        );
        let line = up.expect_line("the proxy's bound address", |l| l.starts_with("vox up on "));
        let bound = address_in(&mut up, &line, 3);
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
                "--passphrase-file",
                &self.passphrase_file(),
                "--anchor",
                &self.anchor_spec,
                "--listen",
                "127.0.0.1:0",
            ]),
        );
        let line = fwd.expect_line("the forward's bound address", |l| {
            l.starts_with("vox: 127.0.0.1:") && l.contains('→')
        });
        let bound = address_in(&mut fwd, &line, 1);
        (fwd, bound)
    }
}

/// `vox id` in `dir`: the identity's fingerprint, made on first use. `PRODUCT:` if it fails or
/// prints something that is not a fingerprint.
pub fn fingerprint(dir: &Path, who: &str) -> String {
    let (ok, out, err) = vox_once(dir, &args(&["id"]));
    let fp = out.trim().to_owned();
    assert!(
        ok && fp.len() == 52,
        "PRODUCT (staging): `vox id` ({who}) did not print a fingerprint (exit ok: {ok}).\n\
         stdout:\n{out}\nstderr:\n{err}"
    );
    fp
}

/// The socket address that is word `nth` of `line`, which `p` printed. `PRODUCT:` quoting the line
/// and everything `p` said if there is none.
pub fn address_in(p: &mut VoxProc, line: &str, nth: usize) -> SocketAddr {
    match line.split_whitespace().nth(nth).map(str::parse::<SocketAddr>) {
        Some(Ok(at)) => at,
        other => panic!(
            "PRODUCT: {} printed {line:?}, whose word {nth} is not a socket address ({other:?}). It \
             said:\n{}",
            p.name.clone(),
            p.transcript()
        ),
    }
}

/// Speak RFC 1928 to `proxy` and CONNECT to `host:port` **by name** (`socks5h`), returning
/// the reply code — `0` is success — and the stream positioned at the payload.
///
/// The proxy is `vox up`, so a proxy that refuses the connection, closes or stalls mid-handshake,
/// or answers something that is not SOCKS5 is a `PRODUCT:` red quoting every byte it sent.
pub fn socks5_connect(proxy: SocketAddr, host: &str, port: u16) -> (u8, TcpStream) {
    let mut s = TcpStream::connect(proxy).unwrap_or_else(|e| {
        panic!(
            "PRODUCT: the proxy at {proxy}, which said it was listening, refused a connection: {e}"
        )
    });
    // Longer than the proxy's own patience, so its verdict is what this reports.
    let patience = vox_core::node::up::HOST_PATIENCE + Duration::from_secs(30);
    s.set_read_timeout(Some(patience)).unwrap_or_else(|e| {
        panic!("APPARATUS: could not set a read timeout on the proxy socket: {e}")
    });
    let mut got = Vec::new();
    socks_write(&mut s, &[0x05, 0x01, 0x00], "its greeting", &got);
    let hello = socks_read(&mut s, 2, "its method choice", &mut got);
    assert!(
        hello == [0x05, 0x00],
        "PRODUCT: the proxy refused the no-auth method: it sent {got:02x?}"
    );
    let len = u8::try_from(host.len()).unwrap_or_else(|_| {
        panic!("APPARATUS: the proof's host name {host:?} is too long for SOCKS5")
    });
    let mut req = vec![0x05, 0x01, 0x00, 0x03, len];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    socks_write(&mut s, &req, "the CONNECT request", &got);
    let head = socks_read(&mut s, 4, "its CONNECT reply", &mut got);
    assert!(
        head[0] == 0x05,
        "PRODUCT: the proxy's CONNECT reply is not SOCKS5: it sent {got:02x?}"
    );
    let skip = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        other => panic!(
            "PRODUCT: the proxy's CONNECT reply has address type {other}, which is neither IPv4 nor \
             IPv6: it sent {got:02x?}"
        ),
    };
    socks_read(
        &mut s,
        skip,
        "the bound address in its CONNECT reply",
        &mut got,
    );
    (head[1], s)
}

/// Send `bytes` to the proxy, or a `PRODUCT:` red: it closed on us mid-handshake.
fn socks_write(s: &mut TcpStream, bytes: &[u8], what: &str, got: &[u8]) {
    if let Err(e) = s.write_all(bytes) {
        panic!(
            "PRODUCT: the proxy closed or failed during the SOCKS handshake, before taking {what}: \
             {e} (kind {:?}). Before that it sent {got:02x?}",
            e.kind()
        );
    }
}

/// Read exactly `n` bytes of the proxy's reply, appending them to `got`, or a `PRODUCT:` red quoting
/// everything it did send: it closed, reset or went silent mid-handshake.
fn socks_read(s: &mut TcpStream, n: usize, what: &str, got: &mut Vec<u8>) -> Vec<u8> {
    let t0 = Instant::now();
    let mut part = vec![0u8; n];
    let mut have = 0;
    while have < n {
        match s.read(&mut part[have..]) {
            Ok(0) => panic!(
                "PRODUCT: the proxy closed the connection during the SOCKS handshake, {have} of {n} \
                 bytes into {what}. Everything it sent: {:02x?}",
                [&got[..], &part[..have]].concat()
            ),
            Ok(k) => have += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => panic!(
                "PRODUCT: the proxy failed during the SOCKS handshake, {have} of {n} bytes into \
                 {what}, after {:?}: {e} (kind {:?}). Everything it sent: {:02x?}",
                t0.elapsed(),
                e.kind(),
                [&got[..], &part[..have]].concat()
            ),
        }
    }
    got.extend_from_slice(&part);
    part
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
