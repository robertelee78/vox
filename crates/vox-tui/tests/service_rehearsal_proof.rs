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
//! 1. a **real TCP service** on loopback — standing in for `sshd`, and enough, because what
//!    is under test is whether bytes cross the overlay untouched. It records what it
//!    received and answers with a different, fixed reply, so **each direction is checked on
//!    its own against bytes held outside the overlay** (RP-42). An echo could not do that: a
//!    corruption applied the same way on both legs (a byte flipped by each end's splice) was
//!    undone on the way back, and the echo came home intact;
//! 2. `vox node` — the headless anchor, whose printed `<fingerprint>@<addr>` line this
//!    test **parses and uses**, so an unusable spec (defect 2 above) fails here;
//! 3. `vox serve <port>` — the host. Its printed room id, `vox://` address and
//!    **generated passphrase** are parsed and used verbatim, so a passphrase that does
//!    not match itself (defect 1) fails here;
//! 4. `vox connect <address>` — the guest joining with that passphrase, one-shot;
//! 5. `vox up <room>` — the guest's SOCKS5 entry point, whose bound address is parsed;
//! 6. a **real SOCKS5 client** in this test, sending the `.vox` hostname (`socks5h`
//!    style, the name not an address), then real bytes through it: the service must have
//!    received exactly what was sent, and the client must receive exactly what the service
//!    replied.
//!
//! Nothing here reaches into `vox_core`. If a person could not do it from a shell, this
//! test does not do it either.
//!
//! ## Every red names its side
//!
//! The processes, one-shot verbs and SOCKS client are the shared harness's (`support/world.rs`),
//! whose reds are labelled: `PRODUCT:` when `vox` said or did the wrong thing, quoting it, and
//! `APPARATUS:` or `CANNOT MEASURE:` when the fault is the harness's or the machine's — a waited
//! line that did not come while the harness itself was not scheduled is a stalled runner, not a
//! silent product. What is left in this file is labelled the same way (RP-42's verifier).
//!
//! ## Why it is `#[ignore]`d
//!
//! Production Argon2id on three profiles plus a real ADR-005 proof of work, so it costs
//! tens of seconds. CI runs it in release with the other real-parameter proofs.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use world::{
    address_in, after_label, args, fingerprint, mkdir, room_pass_file, socks5_connect, tempdir,
    vox_once, VoxProc, STALL,
};

/// The bytes the client sends: [`REQUEST_LEN`] of them, several of the tunnel's 16 KiB splice
/// chunks, from a fixed seed.
const REQUEST_LEN: usize = 64 * 1024;
/// The bytes the service answers with: different from the request, so a reply is never the
/// request carried back.
const REPLY_LEN: usize = 48 * 1024;

/// `len` deterministic, non-repeating bytes from `seed` (xorshift).
fn pattern(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn request() -> Vec<u8> {
    pattern(0x5eed_5eed_5eed_5eed, REQUEST_LEN)
}

fn reply() -> Vec<u8> {
    pattern(0x0dd0_ba11_c0de_0001, REPLY_LEN)
}

/// What the service got on one connection: the [`REQUEST_LEN`] bytes, or how far it got before the
/// overlay's side of the connection ended or failed.
type Received = Result<Vec<u8>, String>;

/// A real TCP service on loopback: `sshd`'s stand-in. Each connection: read
/// [`REQUEST_LEN`] bytes, hand them to the returned receiver (outside the overlay, for the
/// proof to compare), then answer with [`reply`]. A connection that ends or fails before the
/// request is whole is handed over too, with how many bytes came. Returns its port.
fn recording_service() -> (u16, mpsc::Receiver<Received>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|e| panic!("APPARATUS: could not bind the proof's service: {e}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("APPARATUS: the proof's service has no local address: {e}"))
        .port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut got = vec![0u8; REQUEST_LEN];
                let mut have = 0;
                while have < REQUEST_LEN {
                    match s.read(&mut got[have..]) {
                        Ok(0) => {
                            let _ = tx.send(Err(format!(
                                "the overlay closed the service's connection {have} of \
                                 {REQUEST_LEN} bytes into the request"
                            )));
                            return;
                        }
                        Ok(n) => have += n,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(e) => {
                            let _ = tx.send(Err(format!(
                                "the service's connection failed {have} of {REQUEST_LEN} bytes \
                                 into the request: {e}"
                            )));
                            return;
                        }
                    }
                }
                let _ = tx.send(Ok(got));
                let _ = s.write_all(&reply());
                // Held open until the client closes: the reply is not cut short by our side.
                let _ = s.read(&mut [0u8; 1]);
            });
        }
    });
    (port, rx)
}

/// The next thing the service got, within `within`: `PRODUCT:` if nothing came while this proof
/// was watching, `CANNOT MEASURE: the runner stalled` if it was not scheduled to watch (one
/// wait overslept by more than the harness's [`STALL`]), as the harness's own waits do.
fn service_receipt(rx: &mpsc::Receiver<Received>, within: Duration) -> Received {
    let deadline = Instant::now() + within;
    let mut overslept = Duration::ZERO;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            assert!(
                overslept <= STALL,
                "CANNOT MEASURE: the runner stalled: the service received nothing within \
                 {within:?}, but this proof overslept one wait by {overslept:?}, so it was not \
                 watching"
            );
            panic!(
                "PRODUCT: the service never received the {REQUEST_LEN} bytes sent through the \
                 overlay within {within:?} (this proof overslept one wait by at most \
                 {overslept:?}, so it was watching)"
            );
        }
        let ask = left.min(Duration::from_secs(1));
        let asked = Instant::now();
        let got = rx.recv_timeout(ask);
        overslept = overslept.max(asked.elapsed().saturating_sub(ask));
        match got {
            Ok(r) => return r,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("APPARATUS: the proof's service stopped listening")
            }
        }
    }
}

/// Where two byte strings first differ, for a red that says what changed.
fn first_difference(got: &[u8], want: &[u8]) -> String {
    match got.iter().zip(want).position(|(a, b)| a != b) {
        Some(i) => format!(
            "first difference at byte {i}: got {:#04x}, sent {:#04x}",
            got[i], want[i]
        ),
        None => format!("lengths differ: got {}, sent {}", got.len(), want.len()),
    }
}

#[test]
#[ignore = "three production Argon2id profiles + a real PoW, and drives the real binary; CI runs it in release"]
fn a_room_bound_service_carries_real_bytes_through_the_real_binaries() {
    watchdog::arm();
    let tmp = tempdir();
    let anchor_dir = tmp.path().join("anchor");
    let host_dir = tmp.path().join("host");
    let guest_dir = tmp.path().join("guest");
    for d in [&anchor_dir, &host_dir, &guest_dir] {
        mkdir(&d.join("cfg"));
    }

    // 1. the service a person is actually trying to reach
    let (service_port, service_got) = recording_service();

    // 2. `vox node` — the anchor. Its printed --anchor spec is what everything else uses,
    //    so a spec nobody can dial fails right here.
    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
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
    //    It happens before `vox serve` starts because redb is single-writer: a one-shot
    //    verb cannot open a profile a running `vox serve` holds.
    let guest_fp = fingerprint(&guest_dir, "the guest");
    let (ok, out, err) = vox_once(
        &host_dir,
        &args(&["trust", "add", &guest_fp, "--name", "the guest"]),
    );
    assert!(
        ok,
        "PRODUCT: the host must be able to trust the guest.\nstdout:\n{out}\nstderr:\n{err}"
    );
    assert!(
        out.contains("reach every service"),
        "PRODUCT: trusting must say plainly that it grants service reach, since that is the \
         whole decision a person is making:\n{out}"
    );
    let (ok, listed, err) = vox_once(&host_dir, &args(&["trust", "list"]));
    assert!(
        ok && listed.contains(&guest_fp),
        "PRODUCT: the ring must show the guest it was just told to trust (exit ok: {ok}):\n\
         {listed}\nstderr:\n{err}"
    );

    // 4. `vox serve` — the host. Room id, address and the GENERATED passphrase are taken
    //    from its own stdout and used verbatim; nothing is shared in-process.
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
    // this timed out until it was brought back into step.)
    let hostname_line = host.expect_line("the .vox hostname", |l| {
        l.starts_with("serving ") && l.contains(".vox")
    });
    let hostname = hostname_line
        .split_whitespace()
        .last()
        .unwrap_or_else(|| panic!("PRODUCT: the serving line names no hostname: {hostname_line:?}"))
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
        "PRODUCT: the address is not a vox:// address: {address}"
    );
    assert!(
        hostname.ends_with(".vox"),
        "PRODUCT: the hostname is not a .vox name: {hostname}"
    );
    assert!(
        !address.contains(&passphrase),
        "PRODUCT: the passphrase MUST NOT be in the address (ADR-005)"
    );

    // 4. `vox connect` — the guest joins with the address and that passphrase, verbatim.
    //    A passphrase that does not match itself fails here, which is defect 1.
    let (ok, out, err) = vox_once(
        &guest_dir,
        &args(&[
            "connect",
            &address,
            "--passphrase-file",
            &room_pass_file(&guest_dir, &passphrase),
            "--anchor",
            &anchor_spec,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    assert!(
        ok,
        "PRODUCT: vox connect failed.\nstdout:\n{out}\nstderr:\n{err}"
    );
    assert!(
        out.contains("joined") && out.contains(&hostname),
        "PRODUCT: connect should say what the room answers on.\n{out}"
    );

    // 5. `vox up` — the guest's entry point. Parse where it bound.
    //
    //    `vox up` needs the room passphrase even though the join is durable: the room's store
    //    is sealed under it (ADR-010), so opening the room requires it every time. A guest
    //    therefore keeps the passphrase for as long as it wants to reach the service, not
    //    merely to join once.
    let mut up = VoxProc::spawn(
        "up",
        &guest_dir,
        &args(&[
            "up",
            &room,
            "--passphrase-file",
            &room_pass_file(&guest_dir, &passphrase),
            "--bind",
            "127.0.0.1:0",
            "--anchor",
            &anchor_spec,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    let up_line = up.expect_line("the proxy's bound address", |l| l.starts_with("vox up on "));
    let bound = address_in(&mut up, &up_line, 3);

    // 6. A real SOCKS5 client, the `.vox` NAME (not an address), and real bytes.
    let payload = request();
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
    let (code, mut stream) = socks5_connect(bound, &hostname, service_port);
    assert!(
        code == 0,
        "PRODUCT: the FIRST SOCKS5 CONNECT to {hostname}:{service_port} must succeed; the proxy \
         answered code {code} after {:?}. `vox up` said:\n{}",
        t0.elapsed(),
        up.transcript()
    );
    eprintln!(
        "[test] first CONNECT succeeded after {:?} — this is what a person waits for \
         between `vox up` and their first `ssh`",
        t0.elapsed()
    );
    // Each direction against bytes held outside the overlay (RP-42): what the service
    // received is compared with what was sent, and what came back with what the service sent.
    stream
        .write_all(&payload)
        .unwrap_or_else(|e| panic!("PRODUCT: the overlay did not take the request's bytes: {e}"));
    let received = service_receipt(&service_got, Duration::from_secs(60))
        .unwrap_or_else(|why| panic!("PRODUCT: {why}"));
    assert!(
        received == payload,
        "PRODUCT: bytes must cross the overlay unchanged, toward the service — this is the whole \
         feature; {}",
        first_difference(&received, &payload)
    );
    let mut back = vec![0u8; REPLY_LEN];
    stream.read_exact(&mut back).unwrap_or_else(|e| {
        panic!(
            "PRODUCT: the service's reply did not come back through the overlay: {e} (kind {:?})",
            e.kind()
        )
    });
    assert!(
        back == reply(),
        "PRODUCT: bytes must cross the overlay unchanged, back from the service; {}",
        first_difference(&back, &reply())
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

    drop(up);

    // ---- the control: an UNTRUSTED joiner reaches nothing (M17.7) ----
    //
    // This is the half that makes the rest mean something, and it is verified finding #1
    // stated as a test. A second guest holds the same address and the same passphrase — the
    // full credentials — and the host never decided about it. Under the withdrawn model that
    // was sufficient: a room created by `vox serve` authorized every admitted member, so
    // joining WAS the authorization. It must now reach nothing.
    let stranger_dir = tmp.path().join("stranger");
    mkdir(&stranger_dir.join("cfg"));
    let (ok, out, err) = vox_once(
        &stranger_dir,
        &args(&[
            "connect",
            &address,
            "--passphrase-file",
            &room_pass_file(&stranger_dir, &passphrase),
            "--anchor",
            &anchor_spec,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    assert!(
        ok,
        "PRODUCT: the stranger must still be able to JOIN — the passphrase is the join credential \
         and always was; what changed is that joining grants no reach.\nstdout:\n{out}\nstderr:\n\
         {err}"
    );
    let mut stranger_up = VoxProc::spawn(
        "stranger-up",
        &stranger_dir,
        &args(&[
            "up",
            &room,
            "--passphrase-file",
            &room_pass_file(&stranger_dir, &passphrase),
            "--bind",
            "127.0.0.1:0",
            "--anchor",
            &anchor_spec,
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    let s_line = stranger_up.expect_line("the stranger's proxy address", |l| {
        l.starts_with("vox up on ")
    });
    let s_bound = address_in(&mut stranger_up, &s_line, 3);
    // **The reply is the host's answer** (PRD-001 R23, D6). The proxy used to reply
    // "succeeded" before it had asked the host, so this control had to accept a success and
    // then look for a stream that carried nothing — which is to say it asserted the defect.
    // The host answers before a single byte flows, so the refusal must be the SOCKS reply
    // itself: code 2, "connection not allowed by ruleset".
    let t0 = Instant::now();
    let (code, _refused) = socks5_connect(s_bound, &hostname, service_port);
    let waited = t0.elapsed();
    assert!(
        code != 0,
        "PRODUCT: an untrusted joiner holding the address AND the passphrase was told its CONNECT \
         succeeded — the proxy must answer with the host's refusal (PRD-001 R23)"
    );
    eprintln!("[test] the untrusted joiner was refused after {waited:?}: SOCKS reply code {code}");
    assert!(
        code == 2,
        "PRODUCT: the refusal must be SOCKS code 2 (not allowed), not code {code}. `vox up` said:\n\
         {}",
        stranger_up.transcript()
    );
    // And the stranger's own node says why, on its own terminal — the remote side learns
    // nothing it did not already say.
    let why = stranger_up.expect_line("the refusal's reason on the stranger's terminal", |l| {
        l.starts_with("! ") && l.contains("the host refused")
    });
    eprintln!("[test] the stranger's vox up said: {why}");

    drop(stranger_up);
    drop(host);
    drop(anchor);
}
