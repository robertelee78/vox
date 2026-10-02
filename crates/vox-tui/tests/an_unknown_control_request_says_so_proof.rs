//! V210-38 (#211) — **a request a node does not know is answered as that, not as a corrupt
//! identity**, through the shipped binary's control socket.
//!
//! A client of another vox version sends a request tag this node has never seen. The node answers
//! with an error frame and closes the connection, which is right. But the reason it gave was
//! "malformed identity bundle: ipc request unknown tag": every control-socket decode failure was
//! reported as a malformed identity bundle, which points at identity corruption.
//!
//! What this drives: a real `vox daemon`, and a client that speaks the socket's framing (a 4-byte
//! big-endian length, then a CBOR body) the way an older or newer `vox` would, sending a request
//! with an unknown tag.
//!
//! What it asserts: the node's reply says it does not know the request, and says nothing of an
//! identity bundle.
//!
//! Mutation: the unknown-tag arm restored to `MalformedBundle` turns it red.

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use world::{args, vox_once, VoxProc, IDENTITY};

/// One frame from the node. A node that closes the socket or goes silent mid-frame is the
/// product's red: the client did nothing but speak the socket's own framing.
fn read_frame(s: &mut UnixStream, what: &str) -> Vec<u8> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).unwrap_or_else(|e| {
        panic!("PRODUCT: the node closed or stalled before the length of {what}: {e}")
    });
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut body).unwrap_or_else(|e| {
        panic!("PRODUCT: the node closed or stalled in the body of {what}: {e}")
    });
    body
}

#[test]
#[ignore = "a real vox daemon with production Argon2id; CI runs it in release"]
fn an_unknown_control_request_says_so() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a tempdir");
    let data = tmp.path().join("d");
    std::fs::create_dir_all(data.join("cfg")).expect("APPARATUS: create the data dir");
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).expect("APPARATUS: write the passphrase file");

    let (ok, _, err) = vox_once(&data, &args(&["id"]));
    assert!(ok, "PRODUCT (staging): `vox id` failed: {err}");
    let mut daemon = VoxProc::spawn(
        "daemon",
        &data,
        &args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--passphrase-file",
            idpass.to_str().expect("APPARATUS: a UTF-8 temp path"),
        ]),
    );
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let (ok, out, err) = vox_once(&data, &args(&["room", "list"]));
        if ok {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT (staging): the daemon never answered `vox room list` within 90 s; the last \
             answer: {out}{err}\n--- the daemon said:\n{}",
            daemon.transcript()
        );
        std::thread::sleep(Duration::from_millis(250));
    }

    let socket = data.join("default").join("node.sock");
    assert!(
        socket.exists(),
        "PRODUCT (staging): no control socket at {} (a long path is hashed elsewhere)",
        socket.display()
    );
    let mut s = UnixStream::connect(&socket)
        .unwrap_or_else(|e| panic!("PRODUCT: the control socket refused a connection: {e}"));
    s.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("APPARATUS: set a read timeout");
    let hello = read_frame(&mut s, "the greeting");
    println!("[proof] the node greeted with {} bytes", hello.len());

    // A request with a tag no vox knows: the CBOR array [9999].
    let body = [0x81u8, 0x19, 0x27, 0x0F];
    s.write_all(
        &u32::try_from(body.len())
            .expect("APPARATUS: a request body under 4 GiB")
            .to_be_bytes(),
    )
    .unwrap_or_else(|e| panic!("PRODUCT: the node closed the socket before the request: {e}"));
    s.write_all(&body)
        .unwrap_or_else(|e| panic!("PRODUCT: the node closed the socket mid-request: {e}"));
    let reply = read_frame(&mut s, "the reply to the unknown request");
    let text = String::from_utf8_lossy(&reply).into_owned();
    println!("[proof] the node's reply: {text:?}");

    assert!(
        !text.contains("identity bundle"),
        "PRODUCT: an unknown control request was reported as an identity-bundle error: {text:?}"
    );
    assert!(
        text.contains("does not know this request"),
        "PRODUCT: the reply to an unknown request does not say the node does not know it: \
         {text:?}"
    );
}
