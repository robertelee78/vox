//! V210-134 — **a bind failure says why**, through the shipped binary.
//!
//! `vox daemon` printed "cannot listen on …: something else already holds that UDP port" for
//! every local bind failure, an address this machine does not have included ("Can't assign
//! requested address"). For that one the message is false, and it sent people looking for a
//! program that did not exist. Each verb that binds the node's `--listen` address now names the
//! real cause and quotes the operating system.
//!
//! **Two arms, for each of `vox daemon`, `vox node` and `vox serve`:**
//! - **a port another socket holds** (a `UdpSocket` this proof binds on loopback): the verb must
//!   fail, name that address, and say another program holds it;
//! - **an address no interface has** (`192.0.2.1`, TEST-NET-1, RFC 5737): the verb must fail,
//!   say that address is not an address of this machine, and never blame another program.
//!
//! Each arm also requires the operating system's own words to be quoted: "Address already in
//! use" for the first, and the system's text for the second (whatever it is, it is not the
//! first's).
//!
//! **Which side a red is on.** A verb that starts anyway, says the wrong cause, or blames
//! another program for an address the machine does not have is `PRODUCT:`, quoting what it
//! said. This machine having `192.0.2.1` on an interface (so the second arm cannot be staged) is
//! `APPARATUS (precondition not met):`. A fault of this proof's own is `APPARATUS:`.
//!
//! Mutation: `vox daemon`'s old blanket message ("something else already holds that UDP port")
//! for every bind fault → red on the second arm, as PRODUCT.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/world.rs"]
mod world;

use std::io::Write as _;
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use world::{args, vox_once, IDENTITY, VOX};

/// TEST-NET-1 (RFC 5737): documentation only, never assigned to an interface.
const NOT_HERE: &str = "192.0.2.1";
/// A verb that cannot bind fails at once; one still running after this has started anyway.
const FAILS_WITHIN: Duration = Duration::from_secs(60);

/// `vox <argv>` on the profile at `data`, the identity passphrase on stdin and in the
/// environment; `(exit ok, stdout + stderr)`. Killed by PID if it is still running after
/// [`FAILS_WITHIN`], which is then reported as `None` for its status.
fn run(data: &Path, argv: &[&str]) -> (Option<bool>, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .env_remove("VOX_ANCHORS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn vox {argv:?}: {e}"));
    // A vox that does not read its stdin closes it; its status and words are the verdict.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = writeln!(stdin, "{IDENTITY}");
    }
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status.success()),
            Ok(None) if started.elapsed() < FAILS_WITHIN => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(None) => {
                let _ = child.kill();
                break None;
            }
            Err(e) => panic!("APPARATUS: cannot poll vox {argv:?}: {e}"),
        }
    };
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot collect vox {argv:?}: {e}"));
    (
        status,
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

/// The arguments for `verb` listening on `listen`.
fn argv(verb: &str, listen: &str) -> Vec<String> {
    match verb {
        "daemon" => args(&["daemon", "--listen", listen]),
        "node" => args(&["node", "--listen", listen]),
        "serve" => args(&["serve", "22=22", "--listen", listen]),
        other => panic!("APPARATUS: no arguments for vox {other}"),
    }
}

#[test]
#[ignore = "real binaries and production Argon2id; CI runs it in release"]
fn a_bind_failure_names_its_real_cause() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let data = tmp.path().join("profile");
    std::fs::create_dir_all(data.join("cfg")).expect("APPARATUS: cannot make the profile");
    let (ok, _, err) = vox_once(&data, &args(&["id"]));
    assert!(ok, "PRODUCT (staging): vox id failed: {err}");

    // The second arm needs an address no interface has.
    let here = UdpSocket::bind((NOT_HERE, 0));
    assert!(
        here.is_err(),
        "APPARATUS (precondition not met): this machine has {NOT_HERE} on an interface, so no address it lacks \
         can be staged"
    );

    for verb in ["daemon", "node", "serve"] {
        // ---- a port another socket holds ----
        let held = UdpSocket::bind("127.0.0.1:0").expect("APPARATUS: cannot bind a UDP port");
        let taken: SocketAddr = held
            .local_addr()
            .expect("APPARATUS: the held port's address");
        let (status, said) = run(&data, &argv_refs(&argv(verb, &taken.to_string())));
        println!("[proof] vox {verb} on a held port {taken}: exit {status:?}\n{said}");
        assert_eq!(
            status,
            Some(false),
            "PRODUCT: vox {verb} on {taken}, a port another socket holds, did not fail: {said}"
        );
        let names_it = said.contains(&format!("cannot listen on {taken}"));
        let other_program = said.contains("already holds") || said.contains("another program");
        assert!(
            names_it && other_program && said.contains("Address already in use"),
            "PRODUCT: vox {verb} on a port another socket holds must name {taken}, say another \
             program holds it, and quote the system's \"Address already in use\": {said}"
        );
        drop(held);

        // ---- an address no interface has ----
        let absent = format!("{NOT_HERE}:{}", taken.port());
        let (status, said) = run(&data, &argv_refs(&argv(verb, &absent)));
        println!("[proof] vox {verb} on {absent}, not an address of this machine: exit {status:?}\n{said}");
        assert_eq!(
            status,
            Some(false),
            "PRODUCT: vox {verb} on {absent}, an address this machine does not have, did not \
             fail: {said}"
        );
        assert!(
            said.contains(&format!("cannot listen on {absent}"))
                && said.contains("not an address of this machine"),
            "PRODUCT: vox {verb} on {absent} must name it and say it is not an address of this \
             machine: {said}"
        );
        assert!(
            !said.contains("already holds")
                && !said.contains("another program")
                && !said.contains("already in use"),
            "PRODUCT: vox {verb} on {absent} blamed another program for an address this machine \
             does not have: {said}"
        );
        assert!(
            said.contains("os error"),
            "PRODUCT: vox {verb} on {absent} did not quote the system's own words: {said}"
        );
    }
}

fn argv_refs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}
