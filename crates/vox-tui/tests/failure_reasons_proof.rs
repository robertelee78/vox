//! PRD-001 **R36** — every failure a person commonly hits names its cause, and where the cause
//! is known, the fix. Driven entirely through the shipped binary.
//!
//! Each case below was found by inducing the failure and reading what came back. Before this
//! change they said, respectively: `cannot join: Failed(Refused)`, `cannot join:
//! Failed(IdentityExists)`, `could not unlock this profile's identity: Failed(Internal)` (for a
//! taken `--listen` port), `cannot bring the proxy up: Failed(Unreachable) — is its host
//! reachable?` (for a taken `--bind` port), five minutes of "waiting for a path" (for a taken
//! forward port), `Failed(NotConsented)`, and — for a forward into a host that has not trusted
//! you — nothing at all, on either side, while `ssh` got a connection reset.
//!
//! What it asserts, per case, is the **specific** cause in the message, and for every output
//! that no `Failed(` enum token reaches a person at all.
//!
//! 1. `vox room join` with the wrong room passphrase → the member refused, and the likely cause
//!    is the passphrase;
//! 2. `vox room join` of a room already held → it is already held;
//! 3. `vox daemon --listen` on a UDP port something else holds → that port, in use;
//! 4. `vox up --bind` on a TCP port something else holds → that address, in use — promptly;
//! 5. `vox forward` onto a local port something else holds → that address, in use — promptly,
//!    not after the path-waiting loop;
//! 6. `vox trust remove` of someone never trusted → there is nothing to remove;
//! 7. a forward into a host that has not trusted you → the guest is told the host refused and
//!    why that usually is, and the **host** logs whom it refused and why;
//! 8. a room that is not there → "nothing here matches".

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";

/// A long-running `vox`, killed by its own PID however the test ends; stdout and stderr
/// collected separately.
struct Proc {
    name: &'static str,
    child: Child,
    out: Arc<Mutex<Vec<String>>>,
    err: Arc<Mutex<Vec<String>>>,
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn collect(stream: impl Read + Send + 'static) -> Arc<Mutex<Vec<String>>> {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            sink.lock().unwrap().push(line);
        }
    });
    lines
}

impl Proc {
    fn spawn(name: &'static str, dir: &std::path::Path, args: &[&str], stdin: &str) -> Self {
        let mut child = Command::new(VOX)
            .args(args)
            .env("VOX_DATA_DIR", dir)
            .env("VOX_CONFIG_DIR", dir.join("cfg"))
            .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
            .env_remove("VOX_ROOM")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {name}: {e}"));
        let mut pipe = child.stdin.take().expect("stdin");
        pipe.write_all(stdin.as_bytes()).expect("write stdin");
        drop(pipe);
        let out = collect(child.stdout.take().expect("stdout"));
        let err = collect(child.stderr.take().expect("stderr"));
        Self {
            name,
            child,
            out,
            err,
        }
    }

    fn stdout(&self) -> Vec<String> {
        self.out.lock().unwrap().clone()
    }

    fn stderr(&self) -> String {
        self.err.lock().unwrap().join("\n")
    }

    fn expect_out(&self, what: &str, pred: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            if let Some(l) = self.stdout().into_iter().find(|l| pred(l)) {
                return l;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "{}: never printed {what}; stdout {:#?}\nstderr:\n{}",
            self.name,
            self.stdout(),
            self.stderr()
        );
    }

    fn expect_err(&self, what: &str, secs: u64, pred: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            let e = self.stderr();
            if pred(&e) {
                return e;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "{}: never said {what} on stderr; it said:\n{}",
            self.name,
            self.stderr()
        );
    }
}

/// One `vox` command, run to completion, with a bound on how long it may take — a failure
/// that is only reported after minutes is its own defect. Returns (success, stderr, elapsed).
fn vox(
    dir: &std::path::Path,
    args: &[&str],
    stdin: &str,
    within: Duration,
) -> (bool, String, Duration) {
    let started = Instant::now();
    let mut child = Command::new(VOX)
        .args(args)
        .env("VOX_DATA_DIR", dir)
        .env("VOX_CONFIG_DIR", dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDPASS)
        .env_remove("VOX_ROOM")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vox");
    let mut pipe = child.stdin.take().expect("stdin");
    pipe.write_all(stdin.as_bytes()).expect("write");
    drop(pipe);
    let out = collect(child.stdout.take().expect("stdout"));
    let err = collect(child.stderr.take().expect("stderr"));
    let status = loop {
        if let Some(s) = child.try_wait().expect("wait") {
            break s;
        }
        if started.elapsed() > within {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "`vox {}` took longer than {within:?} to report its failure; it had said:\n{}\n{}",
                args.join(" "),
                out.lock().unwrap().join("\n"),
                err.lock().unwrap().join("\n")
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // Let the reader threads take the last lines.
    std::thread::sleep(Duration::from_millis(100));
    let said = format!(
        "{}\n{}",
        out.lock().unwrap().join("\n"),
        err.lock().unwrap().join("\n")
    );
    (status.success(), said, started.elapsed())
}

/// The failure must name `wants` (every one of them) and never an enum token.
fn assert_says(case: &str, said: &str, wants: &[&str]) {
    assert!(
        !said.contains("Failed("),
        "{case}: an enum token reached the person instead of a cause:\n{said}"
    );
    for w in wants {
        assert!(
            said.contains(w),
            "{case}: the message must name the cause ({w:?}); it said:\n{said}"
        );
    }
    eprintln!("[{case}] {}", said.trim().replace('\n', " / "));
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
#[ignore = "four real vox processes, production Argon2id and a real PoW; CI runs it in release"]
fn every_common_failure_names_its_cause() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, host_dir, joiner_dir, guest_dir, spare_dir) = (
        dir("anchor"),
        dir("host"),
        dir("joiner"),
        dir("guest"),
        dir("spare"),
    );
    let quick = Duration::from_secs(90);

    // A real service to offer: an echo server.
    let service = TcpListener::bind("127.0.0.1:0").unwrap();
    let service_port = service.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in service.incoming() {
            let Ok(mut s) = s else { continue };
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

    // ---- the cast: an anchor, a host serving the echo, a joiner's daemon, a guest ----
    let anchor = Proc::spawn(
        "anchor",
        &anchor_dir,
        &["node", "--listen", "127.0.0.1:0"],
        "",
    );
    let spec = anchor
        .expect_out("an anchor spec", |l| {
            l.trim_start().contains('@')
                && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
        })
        .trim()
        .to_owned();
    let mut fps = Vec::new();
    for d in [&host_dir, &joiner_dir, &guest_dir, &spare_dir] {
        let (ok, said, _) = vox(d, &["id"], "", quick);
        assert!(ok, "vox id: {said}");
        fps.push(said.trim().lines().next().unwrap_or_default().to_owned());
    }
    let (host_fp, joiner_fp) = (fps[0].clone(), fps[1].clone());
    let port = service_port.to_string();
    let host = Proc::spawn(
        "host",
        &host_dir,
        &["serve", &port, "--anchor", &spec, "--listen", "127.0.0.1:0"],
        "",
    );
    let field = |label: &str| {
        host.expect_out(label, |l| l.starts_with(label))
            .strip_prefix(label)
            .unwrap()
            .trim()
            .to_owned()
    };
    let (room, address, passphrase) = (field("room"), field("address"), field("passphrase"));
    let joiner = Proc::spawn(
        "joiner-daemon",
        &joiner_dir,
        &["daemon", "--listen", "127.0.0.1:0", "--anchor", &spec],
        &format!("{IDPASS}\n"),
    );
    joiner.expect_out("its control socket", |l| l.contains("control socket"));

    // ---- (1) join with the wrong room passphrase ----
    let (ok, said, _) = vox(
        &joiner_dir,
        &["room", "join", &address, "--name", "svc"],
        "not the passphrase\n",
        quick,
    );
    assert!(!ok, "a wrong passphrase must not join");
    assert_says(
        "join, wrong passphrase",
        &said,
        &["refused the join", "room passphrase is wrong"],
    );

    // ---- (2) join a room already held ----
    let (ok, said, _) = vox(
        &joiner_dir,
        &["room", "join", &address, "--name", "svc"],
        &format!("{passphrase}\n"),
        quick,
    );
    assert!(
        ok,
        "CANNOT MEASURE (2): the right passphrase must join: {said}"
    );
    let (ok, said, _) = vox(
        &joiner_dir,
        &["room", "join", &address, "--name", "svc-again"],
        &format!("{passphrase}\n"),
        quick,
    );
    assert!(!ok, "joining a room already held must fail");
    assert_says("join, already held", &said, &["already holds that room"]);

    // ---- (6) stop trusting someone never trusted, over the daemon's socket ----
    let (ok, said, _) = vox(&joiner_dir, &["trust", "remove", &host_fp], "", quick);
    assert!(!ok, "removing a trust that does not exist must fail");
    assert_says("trust remove, never trusted", &said, &["never trusted"]);

    // ---- (8) a room that is not there ----
    let (ok, said, _) = vox(&joiner_dir, &["room", "post", "zzzzzzzz", "hi"], "", quick);
    assert!(!ok);
    assert_says(
        "post, no such room",
        &said,
        &["nothing here matches \"zzzzzzzz\""],
    );

    // ---- (3) the daemon's UDP port is taken ----
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_addr = udp.local_addr().unwrap().to_string();
    let (ok, said, _) = vox(
        &spare_dir,
        &["daemon", "--listen", &udp_addr],
        &format!("{IDPASS}\n"),
        quick,
    );
    assert!(!ok, "a daemon whose port is taken must not start");
    assert_says(
        "daemon, --listen port in use",
        &said,
        &[
            &format!("cannot listen on {udp_addr}"),
            "already holds that UDP port",
        ],
    );
    drop(udp);

    // ---- the guest joins the service room ----
    let (ok, said, _) = vox(
        &guest_dir,
        &[
            "connect",
            &address,
            "--passphrase",
            &passphrase,
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ],
        "",
        Duration::from_secs(180),
    );
    assert!(ok, "CANNOT MEASURE (4, 5, 7): vox connect failed: {said}");

    // ---- (4) and (5): a local TCP port that is taken ----
    let busy = TcpListener::bind("127.0.0.1:0").unwrap();
    let busy_addr = busy.local_addr().unwrap().to_string();
    let (ok, said, took) = vox(
        &guest_dir,
        &[
            "up",
            &room,
            "--passphrase",
            &passphrase,
            "--bind",
            &busy_addr,
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ],
        "",
        quick,
    );
    assert!(!ok, "vox up on a taken port must fail");
    assert_says(
        "up, --bind port in use",
        &said,
        &[
            &format!("cannot bring the proxy up on {busy_addr}"),
            "already in use",
        ],
    );
    eprintln!("[up, --bind port in use] reported after {took:?}");
    let (ok, said, took) = vox(
        &guest_dir,
        &[
            "forward",
            &room,
            &host_fp,
            &port,
            &busy_addr,
            "--passphrase",
            &passphrase,
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ],
        "",
        quick,
    );
    assert!(!ok, "vox forward onto a taken port must fail");
    assert_says(
        "forward, local port in use",
        &said,
        &[&format!("cannot forward to {busy_addr}"), "already in use"],
    );
    eprintln!("[forward, local port in use] reported after {took:?}");
    drop(busy);

    // ---- (7) a forward into a host that has not trusted this guest ----
    let local = format!("127.0.0.1:{}", free_tcp_port());
    let forward = Proc::spawn(
        "forward",
        &guest_dir,
        &[
            "forward",
            &room,
            &host_fp,
            &port,
            &local,
            "--passphrase",
            &passphrase,
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ],
        "",
    );
    forward.expect_out("the forward's bound address", |l| l.contains(" → "));
    let mut refused = false;
    let deadline = Instant::now() + Duration::from_secs(60);
    while !refused && Instant::now() < deadline {
        // A reset is what `ssh` sees; the question is whether anyone is told why.
        if let Ok(mut s) = TcpStream::connect(&local) {
            let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
            let _ = s.write_all(b"hello");
            let mut buf = [0u8; 16];
            refused = !matches!(s.read(&mut buf), Ok(n) if n > 0);
        }
        if !refused {
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    assert!(
        refused,
        "CANNOT MEASURE (7): an untrusted guest's connection went through"
    );
    let guest_said = forward.expect_err("why the connection was refused", 30, |e| {
        e.contains("refused a connection")
    });
    assert_says(
        "forward, host has not trusted you (guest)",
        &guest_said,
        &[
            "refused a connection",
            "have not run `vox trust add` on you",
        ],
    );
    let host_said = host.expect_err("whom it refused", 30, |e| e.contains("refused"));
    assert_says(
        "forward, host has not trusted you (host)",
        &host_said,
        &[
            &format!("refused {}", &fps[2][..12]),
            "not in your trust keyring",
        ],
    );
    let _ = joiner_fp;

    drop(forward);
    drop(joiner);
    drop(host);
    drop(anchor);
}
