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
//! 8. a room that is not there → "nothing here matches";
//! 9. `vox trust add` when the keyring already holds its 1,024 identities → the keyring is
//!    full, and how to make room. It used to say "that is longer than this field allows"
//!    (the generic size fault), which sent a person looking at the petname. It runs in every
//!    release build; in a debug build only with `--features optional-proofs`, since its 1,100
//!    production-Argon2id `trust add`s take most of an hour there (#295), and the run says so.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Write the room passphrase `pass` beside the profile at `dir`, for `--passphrase-file`: a
/// room passphrase is never taken from argv or the environment (V210-72).
fn room_pass_file(dir: &std::path::Path, pass: &str) -> String {
    std::fs::create_dir_all(dir).expect("APPARATUS: create a staging directory");
    let at = dir.join("room-passphrase");
    std::fs::write(&at, pass).expect("APPARATUS: write a staging file");
    at.to_str()
        .expect("APPARATUS: a path that is not UTF-8")
        .to_owned()
}
const VOX: &str = env!("CARGO_BIN_EXE_vox");
const IDPASS: &str = "an identity passphrase";
/// Twice the most one `vox trust add` took a debug build in case (9)'s fill (see the watchdog's
/// `DEBUG_JOIN` for why twice), eight at a time against one daemon, each checking the passphrase with production Argon2id (#295): 2,200 of them over two
/// runs, median 18.94 s and 20.54 s, most 56.50 s and 74.33 s, the whole fill 2,980.5 s and
/// 3,792.7 s. Release: not counted.
const DEBUG_FILL_ADD: Duration = Duration::from_millis(2 * 74_330);
/// The joins (three `room join`s and `vox connect`) and the other unlocks (four `vox id`s, `serve`,
/// two daemons, `trust remove`, `room post`, `connect`, `up` and two `forward`s) the test makes.
const JOINS: u32 = 4;
const UNLOCKS: u32 = 13;
/// Whether case (9) runs: in every release build, and in a debug build only with the
/// `optional-proofs` feature. A debug build's fill is 1,100 `trust add`s, each a production
/// Argon2id check, and took 2,980.5 s and 3,792.7 s on its own; a heavy proof is opt-in, never in
/// every run (the decider, 2026-09-30). Every other case still blocks in a debug build.
const KEYRING_FILL: bool = !cfg!(debug_assertions) || cfg!(feature = "optional-proofs");
/// The slowest of four whole debug runs of this proof with case (9): 3,265.6 s, 3,408.0 s,
/// 3,566.5 s and 4,225.4 s (#295).
const SLOWEST_DEBUG_RUN: Duration = Duration::from_millis(4_225_400);
/// A release build's budget. Whole release runs took 311.6 s and 439 s at ordinary load, and one
/// at load 77 was still in case (9)'s fill when 600 s ran out (#295). So the slowest run seen
/// took more than 600 s, and the budget is twice that: a hang is minutes or hours over, so the
/// headroom costs the watchdog nothing.
const RELEASE_BUDGET: Duration = Duration::from_secs(2 * 600);

/// Say, past the test harness's capture, that `what` was not run, so a green run never reads as
/// having proven it.
fn not_run(what: &str) {
    let _ = writeln!(
        std::io::stderr(),
        "OPTIONAL PROOF NOT RUN: {what}; it blocks nothing"
    );
}

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
            sink.lock()
                .expect("APPARATUS: a lock the proof holds was poisoned")
                .push(line);
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
            .unwrap_or_else(|e| panic!("APPARATUS: spawn {name}: {e}"));
        let mut pipe = child.stdin.take().expect("APPARATUS: stdin");
        pipe.write_all(stdin.as_bytes())
            .expect("PRODUCT (staging): vox exited without reading its stdin");
        drop(pipe);
        let out = collect(child.stdout.take().expect("APPARATUS: stdout"));
        let err = collect(child.stderr.take().expect("APPARATUS: stderr"));
        Self {
            name,
            child,
            out,
            err,
        }
    }

    fn stdout(&self) -> Vec<String> {
        self.out
            .lock()
            .expect("APPARATUS: a lock the proof holds was poisoned")
            .clone()
    }

    fn stderr(&self) -> String {
        self.err
            .lock()
            .expect("APPARATUS: a lock the proof holds was poisoned")
            .join("\n")
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
            "PRODUCT: {}: never printed {what}; stdout {:#?}\nstderr:\n{}",
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
            "PRODUCT: {}: never said {what} on stderr; it said:\n{}",
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
        .expect("APPARATUS: spawn vox");
    let mut pipe = child.stdin.take().expect("APPARATUS: stdin");
    pipe.write_all(stdin.as_bytes())
        .expect("PRODUCT (staging): vox exited without reading its stdin");
    drop(pipe);
    let out = collect(child.stdout.take().expect("APPARATUS: stdout"));
    let err = collect(child.stderr.take().expect("APPARATUS: stderr"));
    let status = loop {
        if let Some(s) = child.try_wait().expect("APPARATUS: wait") {
            break s;
        }
        if started.elapsed() > within {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "PRODUCT: `vox {}` took longer than {within:?} to report its failure; it had said:\n{}\n{}",
                args.join(" "),
                out.lock().expect("APPARATUS: a lock the proof holds was poisoned").join("\n"),
                err.lock().expect("APPARATUS: a lock the proof holds was poisoned").join("\n")
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // Let the reader threads take the last lines.
    std::thread::sleep(Duration::from_millis(100));
    let said = format!(
        "{}\n{}",
        out.lock()
            .expect("APPARATUS: a lock the proof holds was poisoned")
            .join("\n"),
        err.lock()
            .expect("APPARATUS: a lock the proof holds was poisoned")
            .join("\n")
    );
    (status.success(), said, started.elapsed())
}

/// The failure must name `wants` (every one of them) and never an enum token.
fn assert_says(case: &str, said: &str, wants: &[&str]) {
    assert!(
        !said.contains("Failed("),
        "PRODUCT: {case}: an enum token reached the person instead of a cause:\n{said}"
    );
    for w in wants {
        assert!(
            said.contains(w),
            "PRODUCT: {case}: the message must name the cause ({w:?}); it said:\n{said}"
        );
    }
    eprintln!("[{case}] {}", said.trim().replace('\n', " / "));
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("APPARATUS: bind a socket")
        .local_addr()
        .expect("APPARATUS: read a socket the proof bound")
        .port()
}

#[test]
#[ignore = "four real vox processes, production Argon2id and a real PoW; CI runs it in release"]
fn every_common_failure_names_its_cause() {
    if KEYRING_FILL {
        if cfg!(debug_assertions) {
            // Opted in: the debug fill alone is most of an hour (#295), so the budget is sized on
            // the whole run, not summed from per-add maxima.
            watchdog::arm_for_debug_total(SLOWEST_DEBUG_RUN, 4);
        } else {
            watchdog::arm_for(RELEASE_BUDGET);
        }
    } else {
        // A debug build without case (9): its joins and unlocks at twice their measured most.
        watchdog::arm_for_setup(JOINS, UNLOCKS);
        not_run(
            "case (9), the keyring-full refusal, in a debug build: its 1,100 production-Argon2id \
             `trust add`s take most of an hour there; it runs in every release build, or here \
             with --features optional-proofs",
        );
    }
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a staging directory");
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
    // A join grinds a production proof of work before it is answered, right or wrong: a debug
    // build's measured join cost on top of `quick` (zero in release, where this bound counts).
    let join_quick = quick + watchdog::debug_cost(1, 0);
    // One of eight `trust add`s at once checks the passphrase with production Argon2id: in a
    // debug build that was measured at up to 74.33 s, too near `quick`, so it gets
    // DEBUG_FILL_ADD on top (zero in release).
    let add_quick = quick
        + if cfg!(debug_assertions) {
            DEBUG_FILL_ADD
        } else {
            Duration::ZERO
        };

    // A real service to offer: an echo server.
    let service = TcpListener::bind("127.0.0.1:0").expect("APPARATUS: bind a socket");
    let service_port = service
        .local_addr()
        .expect("APPARATUS: read a socket the proof bound")
        .port();
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
        assert!(ok, "PRODUCT (staging): vox id: {said}");
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
            .expect("APPARATUS: a line matched by its label strips it")
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
        join_quick,
    );
    assert!(!ok, "PRODUCT: a wrong passphrase must not join");
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
        join_quick,
    );
    assert!(
        ok,
        "PRODUCT (staging) (2): the right passphrase must join: {said}"
    );
    let (ok, said, _) = vox(
        &joiner_dir,
        &["room", "join", &address, "--name", "svc-again"],
        &format!("{passphrase}\n"),
        join_quick,
    );
    assert!(!ok, "PRODUCT: joining a room already held must fail");
    assert_says("join, already held", &said, &["already holds that room"]);

    // ---- (6) stop trusting someone never trusted, over the daemon's socket ----
    let (ok, said, _) = vox(&joiner_dir, &["trust", "remove", &host_fp], "", quick);
    assert!(
        !ok,
        "PRODUCT: removing a trust that does not exist must fail"
    );
    assert_says("trust remove, never trusted", &said, &["never trusted"]);

    if KEYRING_FILL {
        // ---- (9) trust past the keyring's limit ----
        // 1,100 distinct identities, eight at a time: more than the keyring holds, whatever it
        // held already. Enough must be trusted to fill it, at least one must be refused, and
        // every refusal must say the keyring is full. Eight at a time is possible because a
        // passphrase check no longer runs on the node's actor (V210-26); one at a time, it
        // took longer than the test watchdog allows.
        let tried = 1_100usize;
        let fill = Instant::now();
        let (refusals, mut took): (Vec<String>, Vec<Duration>) = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8usize)
                .map(|t| {
                    let joiner_dir = &joiner_dir;
                    scope.spawn(move || {
                        let (mut refused, mut took) = (Vec::new(), Vec::new());
                        for n in (t..tried).step_by(8) {
                            let mut id = [0u8; 32];
                            id[..8].copy_from_slice(&(n as u64 + 1).to_be_bytes());
                            id[31] = 0x5A;
                            let fp = vox_core::node::link::b32_encode(&id);
                            let (ok, said, elapsed) = vox(
                                joiner_dir,
                                &["trust", "add", &fp, "--name", &format!("filler-{n}")],
                                "",
                                add_quick,
                            );
                            took.push(elapsed);
                            if !ok {
                                refused.push(said);
                            }
                        }
                        (refused, took)
                    })
                })
                .collect();
            let (mut refused, mut took) = (Vec::new(), Vec::new());
            for h in handles {
                let (r, t) = h.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
                refused.extend(r);
                took.extend(t);
            }
            (refused, took)
        });
        took.sort_unstable();
        let trusted = tried - refusals.len();
        eprintln!(
            "[keyring] {trusted} of {tried} trusted, {} refused, in {:.1?}; one `trust add`, eight \
             at a time: median {:.2?}, most {:.2?}",
            refusals.len(),
            fill.elapsed(),
            took[took.len() / 2],
            took[took.len() - 1]
        );
        assert!(
            trusted >= 1_000,
            "PRODUCT (staging): only {trusted} identities were trusted before the refusals began; the keyring \
             cannot have been full"
        );
        assert!(
            !refusals.is_empty(),
            "PRODUCT (staging) (9): {tried} identities were trusted and the keyring never filled"
        );
        for said in &refusals {
            assert_says(
                "trust add, keyring full",
                said,
                &["keyring is full", "vox trust remove"],
            );
        }
    }

    // ---- (8) a room that is not there ----
    let (ok, said, _) = vox(&joiner_dir, &["room", "post", "zzzzzzzz", "hi"], "", quick);
    assert!(
        !ok,
        "PRODUCT: a post to a room that is not there succeeded: {said}"
    );
    assert_says(
        "post, no such room",
        &said,
        &["nothing here matches \"zzzzzzzz\""],
    );

    // ---- (3) the daemon's UDP port is taken ----
    let udp = UdpSocket::bind("127.0.0.1:0").expect("APPARATUS: bind a socket");
    let udp_addr = udp
        .local_addr()
        .expect("APPARATUS: read a socket the proof bound")
        .to_string();
    let (ok, said, _) = vox(
        &spare_dir,
        &["daemon", "--listen", &udp_addr],
        &format!("{IDPASS}\n"),
        quick,
    );
    assert!(!ok, "PRODUCT: a daemon whose port is taken must not start");
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
            "--passphrase-file",
            &room_pass_file(&guest_dir, &passphrase),
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ],
        "",
        Duration::from_secs(180) + watchdog::debug_cost(1, 0),
    );
    assert!(
        ok,
        "PRODUCT (staging) (4, 5, 7): vox connect failed: {said}"
    );

    // ---- (4) and (5): a local TCP port that is taken ----
    let busy = TcpListener::bind("127.0.0.1:0").expect("APPARATUS: bind a socket");
    let busy_addr = busy
        .local_addr()
        .expect("APPARATUS: read a socket the proof bound")
        .to_string();
    let (ok, said, took) = vox(
        &guest_dir,
        &[
            "up",
            &room,
            "--passphrase-file",
            &room_pass_file(&guest_dir, &passphrase),
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
    assert!(!ok, "PRODUCT: vox up on a taken port must fail");
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
            "--passphrase-file",
            &room_pass_file(&guest_dir, &passphrase),
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ],
        "",
        quick,
    );
    assert!(!ok, "PRODUCT: vox forward onto a taken port must fail");
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
            "--passphrase-file",
            &room_pass_file(&guest_dir, &passphrase),
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ],
        "",
    );
    forward.expect_out("the forward's bound address", |l| l.contains(" → "));
    // Two opposite outcomes, told apart: the forward never took a connection (apparatus), or it
    // took one and the service's echo came back — the host carried an untrusted guest's bytes
    // to the service, which is the product's security failing, never a CANNOT MEASURE.
    let mut refused = false;
    let deadline = Instant::now() + Duration::from_secs(60);
    while !refused && Instant::now() < deadline {
        // A reset is what `ssh` sees; the question is whether anyone is told why.
        if let Ok(mut s) = TcpStream::connect(&local) {
            let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
            let _ = s.write_all(b"hello");
            let mut buf = [0u8; 16];
            match s.read(&mut buf) {
                Ok(n) if n > 0 => panic!(
                    "PRODUCT: the host carried an untrusted guest's bytes to the service (echoed \
                     {n} bytes: {:?})",
                    String::from_utf8_lossy(&buf[..n])
                ),
                _ => refused = true,
            }
        }
        if !refused {
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    assert!(
        refused,
        "PRODUCT (staging) (7): the guest's forward never took a connection on {local} within 60 s"
    );
    // The guest's side: main says this through `up::refusal` (PRD-001 R23), in its own words.
    let guest_said = forward.expect_err("why the connection was refused", 30, |e| {
        e.contains("the host refused")
    });
    assert_says(
        "forward, host has not trusted you (guest)",
        &guest_said,
        &["the host refused", "has not trusted this identity"],
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
