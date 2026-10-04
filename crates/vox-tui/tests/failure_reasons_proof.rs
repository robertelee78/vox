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
//! 2. `vox room join` of a room already held → not a failure: it says the room is already held,
//!    reaches a member at the address, and keeps it as where the host is now (V210-167);
//! 3. `vox daemon --listen` on a UDP port something else holds → that port, in use;
//! 4. `vox up --bind` on a TCP port something else holds → that address, in use — promptly;
//! 5. `vox forward` onto a local port something else holds → that address, in use — promptly,
//!    not after the path-waiting loop;
//! 6. `vox trust remove` of someone never trusted → there is nothing to remove;
//! 7. a forward into a host that has not trusted you → the guest is told the host refused and
//!    why that usually is, and the **host** logs whom it refused and why;
//! 8. a room that is not there → "nothing here matches";
//! 9. `vox trust add` when the keyring is full → the keyring is full, and how to make room. It
//!    used to say "that is longer than this field allows" (the generic size fault), which sent a
//!    person looking at the petname. Blocking, the joiner's daemon runs with the test-only
//!    `VOX_TEST_KEYRING_CAP` at [`SMALL_CAP`], so the same refusal comes after a handful of `trust
//!    add`s (#85: the 1,100-add fill made this proof take six minutes and more). The real cap,
//!    1,024, is filled by the optional heavy arm `a_full_keyring_names_its_cause`.
//!
//! **A red names its side** (#85). What a case asserts about a failure is `PRODUCT:`, quoting what
//! vox said. A `vox` command the scene needs that fails, or never prints what it must, is `PRODUCT
//! (staging):`. The test's own files, sockets, pipes, threads and listeners are `APPARATUS:`. A
//! `vox` built without the test-only knob this proof sets is `CANNOT MEASURE`.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/test_knobs.rs"]
mod test_knobs;

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(a_full_keyring_names_its_cause);

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
/// The keyring cap the blocking case (9) runs the joiner's daemon with (`VOX_TEST_KEYRING_CAP`),
/// and how many identities it then tries to trust: past the cap, whatever the keyring held already.
const SMALL_CAP: usize = 4;
const SMALL_TRIES: usize = SMALL_CAP + 2;
/// Twice the most one `vox trust add` took a debug build in the heavy arm's fill (see the
/// watchdog's `DEBUG_JOIN` for why twice), eight at a time against one daemon, each checking the
/// passphrase with production Argon2id (#295): 2,200 of them over two runs, median 18.94 s and
/// 20.54 s, most 56.50 s and 74.33 s, the whole fill 2,980.5 s and 3,792.7 s. Release: not counted.
#[cfg(feature = "optional-proofs")]
const DEBUG_FILL_ADD: Duration = Duration::from_millis(2 * 74_330);
/// The joins (three `room join`s and `vox connect`) and the other unlocks (four `vox id`s, `serve`,
/// two daemons, `trust remove`, `room post`, `connect`, `up`, two `forward`s and case (9)'s
/// `trust add`s) the blocking test makes.
const JOINS: u32 = 4;
const UNLOCKS: u32 = 13 + SMALL_TRIES as u32;
/// The slowest of four whole debug runs of the heavy fill with the rest of this proof: 3,265.6 s,
/// 3,408.0 s, 3,566.5 s and 4,225.4 s (#295).
#[cfg(feature = "optional-proofs")]
const SLOWEST_DEBUG_RUN: Duration = Duration::from_millis(4_225_400);
/// A release build's budget for the heavy fill. Whole release runs with it took 311.6 s and 439 s
/// at ordinary load, and one at load 77 was still filling when 600 s ran out (#295); twice that.
#[cfg(feature = "optional-proofs")]
const RELEASE_BUDGET: Duration = Duration::from_secs(2 * 600);

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
        Self::spawn_env(name, dir, args, stdin, &[])
    }

    fn spawn_env(
        name: &'static str,
        dir: &std::path::Path,
        args: &[&str],
        stdin: &str,
        env: &[(&str, &str)],
    ) -> Self {
        let mut child = Command::new(VOX)
            .args(args)
            .envs(env.iter().copied())
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

    /// A line the scene needs `vox` to print; one that never comes is the product's (staging).
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

    /// What a case asserts `vox` says on stderr; never said, it is the product's.
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

/// The `n`th made-up identity to trust: a fingerprint no key behind it, distinct per `n`.
fn filler(n: usize) -> String {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&(n as u64 + 1).to_be_bytes());
    id[31] = 0x5A;
    vox_core::node::link::b32_encode(&id)
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
    watchdog::arm_for_setup(JOINS, UNLOCKS);
    test_knobs::require(&["VOX_TEST_KEYRING_CAP"]);
    let tmp = tempfile::tempdir().expect("APPARATUS: a temporary directory");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: a profile directory");
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
    // One `trust add` checks the passphrase with production Argon2id: a debug build's unlock on
    // top of `quick` (zero in release).
    let add_quick = quick + watchdog::debug_cost(0, 1);

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
        &[
            "serve",
            &format!("{port}={port}"),
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ],
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
    // Its keyring capped at SMALL_CAP for case (9), through the test-only knob.
    let small_cap = SMALL_CAP.to_string();
    let joiner = Proc::spawn_env(
        "joiner-daemon",
        &joiner_dir,
        &["daemon", "--listen", "127.0.0.1:0", "--anchor", &spec],
        &format!("{IDPASS}\n"),
        &[("VOX_TEST_KEYRING_CAP", small_cap.as_str())],
    );
    joiner.expect_out("its control socket", |l| l.contains("control socket"));

    // ---- (1) join with the wrong room passphrase ----
    let (ok, said, _) = vox(
        &joiner_dir,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            &address,
            "--name",
            "svc",
        ],
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
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            &address,
            "--name",
            "svc",
        ],
        &format!("{passphrase}\n"),
        join_quick,
    );
    assert!(
        ok,
        "PRODUCT (staging) (2): the right passphrase must join: {said}"
    );
    let (ok, said, _) = vox(
        &joiner_dir,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            &address,
            "--name",
            "svc-again",
        ],
        &format!("{passphrase}\n"),
        join_quick,
    );
    assert!(
        ok,
        "PRODUCT: joining a room already held must take the address as the host's: {said}"
    );
    assert_says(
        "join, already held",
        &said,
        &["already holds", "a member answered at the address"],
    );

    // ---- (6) stop trusting someone never trusted, over the daemon's socket ----
    let (ok, said, _) = vox(&joiner_dir, &["trust", "remove", &host_fp], "", quick);
    assert!(
        !ok,
        "PRODUCT: trust remove, never trusted: removing a trust that does not exist succeeded; it \
         said:\n{said}"
    );
    assert_says("trust remove, never trusted", &said, &["never trusted"]);

    // ---- (9) trust past the keyring's limit (capped at SMALL_CAP by the test-only knob) ----
    // SMALL_TRIES distinct identities, one after another: more than the capped keyring holds,
    // whatever it held already. At least one must be refused, and every refusal must say the
    // keyring is full. The real 1,024 is the heavy arm's (`a_full_keyring_names_its_cause`).
    let mut refusals = Vec::new();
    for n in 0..SMALL_TRIES {
        let (ok, said, _) = vox(
            &joiner_dir,
            &["trust", "add", &filler(n), "--name", &format!("filler-{n}")],
            "",
            add_quick,
        );
        if !ok {
            refusals.push(said);
        }
    }
    eprintln!(
        "[keyring] capped at {SMALL_CAP}: {} of {SMALL_TRIES} trusted, {} refused",
        SMALL_TRIES - refusals.len(),
        refusals.len()
    );
    assert!(
        !refusals.is_empty(),
        "PRODUCT: trust add, keyring full: with the keyring capped at {SMALL_CAP}, all \
         {SMALL_TRIES} identities were trusted — the cap was not enforced"
    );
    // The cap in force, not the shipped one: a message that names a wrong number is how a gate
    // ends up asserting the wrong thing (#85).
    let cap_said = format!("keyring is full ({SMALL_CAP} identities)");
    for said in &refusals {
        assert_says(
            "trust add, keyring full",
            said,
            &[&cap_said, "vox trust remove"],
        );
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
            &format!("{}.{}.{}.vox", port, host_fp, room),
            &busy_addr,
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
            &format!("{}.{}.{}.vox", port, host_fp, room),
            &local,
            "--anchor",
            &spec,
            "--listen",
            "127.0.0.1:0",
        ],
        "",
    );
    forward.expect_out("the forward's bound address", |l| l.contains(" → "));
    // Two opposite outcomes, told apart: the forward never took a connection (staging), or it
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

/// **Optional, heavy:** case (9) at the real cap. `vox trust add` past the 1,024 identities a
/// keyring holds is refused with the keyring-full cause, and how to make room. 1,100 production-
/// Argon2id `trust add`s, eight at a time against one daemon: minutes in a release build, most of
/// an hour in a debug one (#295), so it blocks nothing and runs only with `--features
/// optional-proofs`; without it the stand-in above says it was not run.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "1,100 production-Argon2id `vox trust add`s; optional, run it in release"]
fn a_full_keyring_names_its_cause() {
    if cfg!(debug_assertions) {
        watchdog::arm_for_debug_total(SLOWEST_DEBUG_RUN, 4);
    } else {
        watchdog::arm_for(RELEASE_BUDGET);
    }
    let tmp = tempfile::tempdir().expect("APPARATUS: a temporary directory");
    let dir = tmp.path().join("keyring");
    std::fs::create_dir_all(dir.join("cfg")).expect("APPARATUS: a profile directory");
    let quick = Duration::from_secs(90);
    let add_quick = quick
        + if cfg!(debug_assertions) {
            DEBUG_FILL_ADD
        } else {
            Duration::ZERO
        };
    let (ok, said, _) = vox(&dir, &["id"], "", quick);
    assert!(ok, "PRODUCT (staging): vox id: {said}");
    let daemon = Proc::spawn(
        "keyring-daemon",
        &dir,
        &["daemon", "--listen", "127.0.0.1:0"],
        &format!("{IDPASS}\n"),
    );
    daemon.expect_out("its control socket", |l| l.contains("control socket"));

    // 1,100 distinct identities, eight at a time: more than the keyring holds. Enough must be
    // trusted to fill it, at least one must be refused, and every refusal must say the keyring is
    // full. Eight at a time is possible because a passphrase check no longer runs on the node's
    // actor (V210-26); one at a time, it took longer than the test watchdog allows.
    let tried = 1_100usize;
    let fill = Instant::now();
    let (refusals, mut took): (Vec<String>, Vec<Duration>) = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8usize)
            .map(|t| {
                let dir = &dir;
                scope.spawn(move || {
                    let (mut refused, mut took) = (Vec::new(), Vec::new());
                    for n in (t..tried).step_by(8) {
                        let (ok, said, elapsed) = vox(
                            dir,
                            &["trust", "add", &filler(n), "--name", &format!("filler-{n}")],
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
            let (r, t) = h.join().expect("APPARATUS: a fill thread panicked");
            refused.extend(r);
            took.extend(t);
        }
        (refused, took)
    });
    took.sort_unstable();
    let trusted = tried - refusals.len();
    eprintln!(
        "[keyring] {trusted} of {tried} trusted, {} refused, in {:.1?}; one `trust add`, eight at \
         a time: median {:.2?}, most {:.2?}",
        refusals.len(),
        fill.elapsed(),
        took[took.len() / 2],
        took[took.len() - 1]
    );
    assert!(
        trusted >= 1_000,
        "PRODUCT: trust add, keyring full: only {trusted} of {tried} identities were trusted \
         before the refusals began, short of the 1,024 a keyring holds"
    );
    assert!(
        !refusals.is_empty(),
        "PRODUCT: trust add, keyring full: all {tried} identities were trusted — the keyring's \
         1,024 cap was not enforced"
    );
    for said in &refusals {
        assert_says(
            "trust add, keyring full",
            said,
            &["keyring is full (1,024 identities)", "vox trust remove"],
        );
    }
    drop(daemon);
}
