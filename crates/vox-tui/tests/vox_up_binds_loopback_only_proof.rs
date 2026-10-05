//! ADR-028 S-5 — **the daemon runs the `.vox` proxy while a node is attached, and `vox up` only
//! reports it**; and V210-152 — **`vox up` never reports a proxy that is not running**. Through
//! the shipped binary. Run on demand; not a gate.
//!
//! The proxy used to be `vox up`'s own: `--bind` chose its address, and it ran for as long as
//! `vox up` did. It is now the daemon's, on `127.0.0.1:1080` unless `--proxy` or `VOX_PROXY`
//! says otherwise, from the first node's attach to the last node's detach. V210-152 was a node
//! that answered "up" for a bind it then refused, so a person was told the proxy was up while
//! nothing listened. The daemon now refuses the same address, and `vox up` must say so.
//!
//! **Staging.** Real `vox` processes (`support/world.rs`): an anchor, a host serving an echo
//! service, and a guest who joined and is trusted. Before each case the guest's daemon is
//! stopped, so the next one starts with that case's `VOX_PROXY`.
//!
//! **Asserted.**
//! 1. With `VOX_PROXY=0.0.0.0:<P>`, the guest's `vox up <room>` exits non-zero within 60 s. It
//!    says the address is not on loopback and never prints a `vox up on` line. Nothing listens on
//!    `<P>` afterwards.
//! 2. With `VOX_PROXY` set to an address another socket holds, `vox up` exits non-zero and names
//!    that address.
//! 3. With `VOX_PROXY=127.0.0.1:0`, the guest runs `vox daemon` holding its room, and nobody runs
//!    `vox up`. The daemon says `the .vox proxy is on <A>`, and a SOCKS5 CONNECT through `<A>` to
//!    the host's service carries bytes there and back.
//! 4. `vox up` then exits 0, printing `vox up on <A>` (the same `<A>`) and the ssh block. One
//!    socket listens on `<A>`'s port: the daemon's.
//!
//! **Mutations that must turn it red (PRODUCT).**
//! - Start the proxy only when `vox up` asks (`Router::follow_attached_with_the_proxy` returning
//!   at once): 3 fails, since the daemon never says the proxy is on.
//! - Delete the loopback check in `daemon_proxy::bind`: 1 fails, naming the `vox up on 0.0.0.0:…`
//!   line.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::io::{BufRead as _, Write as _};
use std::net::SocketAddr;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use world::{args, echo_service, reap_daemon, socks5_connect, utf8, VoxProc, World, IDENTITY};

/// How long a refusal may take: a daemon starts, unlocks with production Argon2id and opens the
/// room first.
const REFUSAL: Duration = Duration::from_secs(60);
/// How long the guest's daemon may take to hold its room.
const HOLDING: Duration = Duration::from_secs(180);

/// Run the guest's `vox up <room>` with `VOX_PROXY=proxy` to its end; what it said, and whether it
/// exited successfully. A `vox up on` line is a PRODUCT red when `refuses` is true.
fn up_with(w: &World, name: &str, proxy: &str, refuses: bool) -> (bool, String) {
    reap_daemon(&w.guest_dir);
    let t0 = Instant::now();
    let mut up = VoxProc::spawn_env(
        name,
        &w.guest_dir,
        &args(&[
            "up",
            &w.room,
            "--passphrase-file",
            &w.passphrase_file(),
            "--anchor",
            &w.guest_anchor,
            "--listen",
            "127.0.0.1:0",
        ]),
        &[("VOX_PROXY", proxy)],
    );
    loop {
        let left = REFUSAL.saturating_sub(t0.elapsed());
        assert!(
            !left.is_zero(),
            "PRODUCT: `vox up` with VOX_PROXY={proxy} did not exit within {REFUSAL:?}. It said:\n{}",
            up.transcript()
        );
        match up.lines.recv_timeout(left.min(Duration::from_secs(1))) {
            Ok(line) => {
                eprintln!("[{name}] {line}");
                let said_up = line.starts_with("vox up on ");
                up.seen.push(line.clone());
                assert!(
                    !(refuses && said_up),
                    "PRODUCT: `vox up` reported {line:?} with VOX_PROXY={proxy}, which the daemon \
                     refuses: the person is told the proxy is up while nothing listens"
                );
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    let status = up
        .child
        .wait()
        .unwrap_or_else(|e| panic!("APPARATUS: wait for vox up's exit status: {e}"));
    let said = up.transcript();
    println!(
        "[proof] `vox up` with VOX_PROXY={proxy} exited {status} after {:?}",
        t0.elapsed()
    );
    (status.success(), said)
}

/// A free loopback TCP port, chosen by the kernel.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .unwrap_or_else(|e| panic!("APPARATUS: pick a free TCP port: {e}"))
        .port()
}

/// The PIDs listening on TCP `port`, as `lsof` reports them.
fn listeners(port: u16) -> Vec<String> {
    let out = std::process::Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-Fp"])
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: lsof could not be run: {e}"));
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.strip_prefix('p'))
        .map(str::to_owned)
        .collect()
}

#[test]
#[ignore = "real vox processes, production Argon2id and a real join; run on demand, in release"]
fn the_daemon_runs_the_proxy_and_vox_up_reports_only_what_runs() {
    watchdog::arm();
    let w = World::new(echo_service(), true);

    // ---- 1. a proxy address the network can reach ---------------------------------------------
    let port = free_port();
    let exposed = format!("0.0.0.0:{port}");
    let (ok, said) = up_with(&w, "exposed-up", &exposed, true);
    assert!(
        !ok,
        "PRODUCT: `vox up` with VOX_PROXY={exposed} exited successfully. It said:\n{said}"
    );
    assert!(
        said.contains("not on loopback"),
        "PRODUCT: the refusal must say the address is not on loopback. It said:\n{said}"
    );
    let free = std::net::TcpListener::bind(exposed.as_str());
    println!("[proof] {exposed} free afterwards: {}", free.is_ok());
    assert!(
        free.is_ok(),
        "PRODUCT: the refused proxy left something on {exposed}: {:?}",
        free.err()
    );
    drop(free);

    // ---- 2. a proxy address another socket holds ----------------------------------------------
    let busy = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|e| panic!("APPARATUS: bind a socket: {e}"));
    let busy_addr = busy
        .local_addr()
        .unwrap_or_else(|e| panic!("APPARATUS: read a socket the proof bound: {e}"))
        .to_string();
    let (ok, said) = up_with(&w, "busy-up", &busy_addr, true);
    assert!(
        !ok,
        "PRODUCT: `vox up` with VOX_PROXY={busy_addr}, which is taken, exited successfully. It \
         said:\n{said}"
    );
    assert!(
        said.contains(&format!("could not listen on {busy_addr}")),
        "PRODUCT: the refusal must name the address in use, {busy_addr}. It said:\n{said}"
    );
    drop(busy);

    // ---- 3. a node attached, and no `vox up`: the proxy carries the room ----------------------
    reap_daemon(&w.guest_dir);
    let pass_file = w.tmp.path().join("guest-daemon-passphrases");
    std::fs::write(&pass_file, format!("{IDENTITY}\n{}\n", w.passphrase))
        .unwrap_or_else(|e| panic!("APPARATUS: write the daemon's passphrase file: {e}"));
    let mut daemon = VoxProc::spawn_env(
        "guest-daemon",
        &w.guest_dir,
        &args(&[
            "daemon",
            "--passphrase-file",
            &utf8(&pass_file),
            "--anchor",
            &w.guest_anchor,
            "--listen",
            "127.0.0.1:0",
        ]),
        &[("VOX_PROXY", "127.0.0.1:0")],
    );
    let said = daemon.expect_within(HOLDING, "the daemon to say where its proxy is", |l| {
        l.contains("vox daemon: the .vox proxy is on ")
    });
    let proxy: SocketAddr = said
        .rsplit(' ')
        .next()
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| panic!("PRODUCT: the daemon's proxy line names no address: {said:?}"));
    let room = w.room.clone();
    daemon.expect_within(HOLDING, "the daemon to hold the room open", |l| {
        l.contains("vox daemon: holding room") && l.contains(&room)
    });
    let (code, mut s) = socks5_connect(proxy, &w.service_host(), w.service_port);
    assert_eq!(
        code,
        0,
        "PRODUCT: with the node attached and no `vox up`, the daemon's proxy at {proxy} refused a \
         CONNECT to {} (SOCKS {code}).\ndaemon:\n{}",
        w.service_host(),
        daemon.transcript()
    );
    s.write_all(b"through the daemon's proxy\n")
        .unwrap_or_else(|e| panic!("PRODUCT: the tunnel through {proxy} closed on write: {e}"));
    let mut back = String::new();
    std::io::BufReader::new(&s)
        .read_line(&mut back)
        .unwrap_or_else(|e| panic!("PRODUCT: nothing came back through {proxy}: {e}"));
    println!("[proof] through the daemon's proxy at {proxy}, the service answered {back:?}");
    assert!(
        back.contains("through the daemon's proxy"),
        "PRODUCT: the service's answer through {proxy} was {back:?}"
    );
    drop(s);

    // ---- 4. `vox up` reports that proxy, and starts no other ---------------------------------
    let (ok, said) = up_with_running(&w);
    assert!(
        ok,
        "PRODUCT: `vox up` with the proxy running failed. It said:\n{said}"
    );
    assert!(
        said.contains(&format!("vox up on {proxy} ")) && said.contains("ProxyCommand"),
        "PRODUCT: `vox up` must report the daemon's proxy, {proxy}, and print the ssh block. It \
         said:\n{said}"
    );
    let pids = listeners(proxy.port());
    let daemon_pid = daemon.child.id().to_string();
    println!(
        "[proof] listening on {}: {pids:?}; the daemon is {daemon_pid}",
        proxy.port()
    );
    assert!(
        pids == [daemon_pid.clone()],
        "PRODUCT: after `vox up`, {pids:?} listen on {}; only the daemon ({daemon_pid}) may",
        proxy.port()
    );
}

/// `vox up <room>` against the running daemon (no daemon restart): exited ok, and what it said.
fn up_with_running(w: &World) -> (bool, String) {
    let mut up = VoxProc::spawn(
        "up",
        &w.guest_dir,
        &args(&[
            "up",
            &w.room,
            "--passphrase-file",
            &w.passphrase_file(),
            "--anchor",
            &w.guest_anchor,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    let t0 = Instant::now();
    loop {
        let left = REFUSAL.saturating_sub(t0.elapsed());
        assert!(
            !left.is_zero(),
            "PRODUCT: `vox up` did not exit within {REFUSAL:?}: it must report and exit. It \
             said:\n{}",
            up.transcript()
        );
        match up.lines.recv_timeout(left.min(Duration::from_secs(1))) {
            Ok(line) => {
                eprintln!("[up] {line}");
                up.seen.push(line);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    let status = up
        .child
        .wait()
        .unwrap_or_else(|e| panic!("APPARATUS: wait for vox up's exit status: {e}"));
    (status.success(), up.transcript())
}
