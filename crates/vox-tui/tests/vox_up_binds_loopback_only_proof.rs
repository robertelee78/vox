//! V210-152 — **`vox up` never reports success for a bind it then refuses**, through the shipped
//! binary. Run on demand; not a gate.
//!
//! The node bound the proxy's port and answered `Done` — so `vox up` printed "vox up on
//! 0.0.0.0:…", the `ProxyCommand` block and "Ctrl-C to stop" — and only then did the proxy's own
//! task refuse the address for not being loopback, into a `Result` nobody read. A person was told
//! the proxy was up while nothing listened.
//!
//! **Staging.** Real `vox` processes (`support/world.rs`): an anchor, a host serving an echo
//! service, and a guest who joined.
//!
//! **Asserted.**
//! 1. `vox up <room> --bind 0.0.0.0:<P>` from the guest exits non-zero within 60 s, says the port
//!    must be on loopback, and never prints the `vox up on` line.
//! 2. Nothing listens on `<P>` afterwards.
//! 3. Control: the same guest's `vox up … --bind 127.0.0.1:0` comes up.
//!
//! **Mutation that must turn it red (PRODUCT).** Delete the loopback check in `node::actor`'s
//! `bring_up`. `vox up` then prints its `vox up on 0.0.0.0:…` line and runs on, and assertion 1
//! fails naming that line.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use world::{args, echo_service, VoxProc, World};

/// How long the refusal may take: a node starts, unlocks with production Argon2id and opens the
/// room first.
const REFUSAL: Duration = Duration::from_secs(60);

#[test]
#[ignore = "real vox processes, production Argon2id and a real join; run on demand, in release"]
fn vox_up_refuses_a_bind_the_network_can_reach_and_never_says_it_is_up() {
    watchdog::arm();
    let w = World::new(echo_service(), true);
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .unwrap_or_else(|e| panic!("APPARATUS: pick a free TCP port: {e}"))
        .port();
    let exposed = format!("0.0.0.0:{port}");

    // ---- 1. the guest asks for the proxy on every interface ---------------------------------
    let t0 = Instant::now();
    let mut up = VoxProc::spawn(
        "exposed-up",
        &w.guest_dir,
        &args(&[
            "up",
            &w.room,
            "--passphrase-file",
            &w.passphrase_file(),
            "--bind",
            &exposed,
            "--anchor",
            &w.anchor_spec,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    loop {
        let left = REFUSAL.saturating_sub(t0.elapsed());
        assert!(
            !left.is_zero(),
            "PRODUCT: `vox up … --bind {exposed}` neither exited nor refused within {REFUSAL:?}. \
             It said:\n{}",
            up.transcript()
        );
        match up.lines.recv_timeout(left.min(Duration::from_secs(1))) {
            Ok(line) => {
                eprintln!("[exposed-up] {line}");
                let said_up = line.starts_with("vox up on ");
                up.seen.push(line.clone());
                assert!(
                    !said_up,
                    "PRODUCT: `vox up` reported {line:?} for a bind on every interface, which it \
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
        "[proof] `vox up … --bind {exposed}` exited {status} after {:?}",
        t0.elapsed()
    );
    assert!(
        !status.success(),
        "PRODUCT: `vox up … --bind {exposed}` exited successfully. It said:\n{said}"
    );
    assert!(
        said.contains("loopback"),
        "PRODUCT: the refusal must say the port has to be on loopback. It said:\n{said}"
    );

    // ---- 2. nothing was left listening ------------------------------------------------------
    let free = std::net::TcpListener::bind(exposed.as_str());
    println!("[proof] {exposed} free afterwards: {}", free.is_ok());
    assert!(
        free.is_ok(),
        "PRODUCT: the refused `vox up` left something on {exposed}: {:?}",
        free.err()
    );
    drop(free);

    // ---- 3. control: the same guest on loopback ---------------------------------------------
    let (_up, at) = w.up("loopback-up", &w.guest_dir);
    println!("[proof] control: vox up came up on {at}");
    assert!(
        at.ip().is_loopback(),
        "PRODUCT: the control proxy bound {at}"
    );
}
