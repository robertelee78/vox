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

fn read_frame(s: &mut UnixStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).expect("a frame length");
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut body).expect("a frame body");
    body
}

#[test]
#[ignore = "a real vox daemon with production Argon2id; CI runs it in release"]
fn an_unknown_control_request_says_so() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("d");
    std::fs::create_dir_all(data.join("cfg")).unwrap();
    let idpass = tmp.path().join("idpass");
    std::fs::write(&idpass, IDENTITY).unwrap();

    let (ok, _, err) = vox_once(&data, &args(&["id"]));
    assert!(ok, "vox id: {err}");
    let _daemon = VoxProc::spawn(
        "daemon",
        &data,
        &args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--passphrase-file",
            idpass.to_str().unwrap(),
        ]),
    );
    let deadline = Instant::now() + Duration::from_secs(90);
    while !vox_once(&data, &args(&["room", "list"])).0 {
        assert!(
            Instant::now() < deadline,
            "the daemon never answered `vox room list`"
        );
        std::thread::sleep(Duration::from_millis(250));
    }

    let socket = data.join("default").join("node.sock");
    assert!(
        socket.exists(),
        "CANNOT MEASURE: no control socket at {} (a long path is hashed elsewhere)",
        socket.display()
    );
    let mut s = UnixStream::connect(&socket).expect("connect to the control socket");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let hello = read_frame(&mut s);
    println!("[proof] the node greeted with {} bytes", hello.len());

    // A request with a tag no vox knows: the CBOR array [9999].
    let body = [0x81u8, 0x19, 0x27, 0x0F];
    s.write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
        .unwrap();
    s.write_all(&body).unwrap();
    let reply = read_frame(&mut s);
    let text = String::from_utf8_lossy(&reply).into_owned();
    println!("[proof] the node's reply: {text:?}");

    assert!(
        !text.contains("identity bundle"),
        "an unknown control request was reported as an identity-bundle error: {text:?}"
    );
    assert!(
        text.contains("does not know this request"),
        "the reply to an unknown request does not say the node does not know it: {text:?}"
    );
}
