//! Manual spike (ADR-015 "verified-actually-working"): a REAL cross-process QUIC
//! handshake over loopback, exercising the M9 transport between two separate OS
//! processes — not a single in-test runtime.
//!
//!   spike_quic server                 # prints ADDR=… ID=… then echoes one stream
//!   spike_quic client <addr> <id-hex> # dials, authenticates the server, round-trips
//!
//! Proves: real UDP/QUIC across a process boundary, composite-identity mutual auth
//! (the client pins the server's fingerprint), and a reliable stream round-trip.

use std::time::{SystemTime, UNIX_EPOCH};

use vox_core::hash::Digest32;
use vox_core::identity::composite::SoftwareRootSigner;
use vox_core::transport::quic::VoxEndpoint;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(d: Digest32) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_id(s: &str) -> Digest32 {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex id");
    }
    out
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("server") => server().await,
        Some("client") => client(&args[2], &args[3]).await,
        _ => eprintln!("usage: spike_quic server | client <addr> <id-hex>"),
    }
}

async fn server() {
    let signer = SoftwareRootSigner::from_component_seeds(&[1u8; 32], &[2u8; 32]).unwrap();
    let ep = VoxEndpoint::bind(&signer, "127.0.0.1:0".parse().unwrap()).unwrap();
    // Print on lines the harness greps for, flushed immediately.
    println!("ADDR={}", ep.local_addr().unwrap());
    println!("ID={}", hex(ep.local_id()));
    eprintln!("server: listening, waiting for a real client process…");

    let conn = ep
        .accept(now())
        .await
        .expect("accept ok")
        .expect("a connection");
    eprintln!("server: peer AUTHENTICATED as {}", hex(conn.peer_id()));
    let (mut send, mut recv) = conn.accept_stream().await.expect("accept stream");
    let msg = recv.read_to_end(4096).await.expect("read");
    eprintln!("server: received {:?}", String::from_utf8_lossy(&msg));
    send.write_all(&msg).await.expect("echo write");
    send.finish().expect("finish");
    eprintln!("server: echoed back, done");
    // Hold the connection briefly so the echo+FIN are delivered before exit.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
}

async fn client(addr: &str, id_hex: &str) {
    let expected = parse_id(id_hex);
    let signer = SoftwareRootSigner::from_component_seeds(&[3u8; 32], &[4u8; 32]).unwrap();
    let ep = VoxEndpoint::bind(&signer, "127.0.0.1:0".parse().unwrap()).unwrap();
    let conn = ep
        .connect(addr.parse().unwrap(), expected, now())
        .await
        .expect("connect+auth");
    println!(
        "client: CONNECTED; server authenticated as {}",
        hex(conn.peer_id())
    );
    let (mut send, mut recv) = conn.open_stream().await.expect("open stream");
    let payload = b"PING from a real, separate client process";
    send.write_all(payload).await.expect("write");
    send.finish().expect("finish");
    let echo = recv.read_to_end(4096).await.expect("read echo");
    let ok = echo == payload;
    println!("client: ECHO {:?}", String::from_utf8_lossy(&echo));
    println!("client: ROUND-TRIP {}", if ok { "OK" } else { "MISMATCH" });
    std::process::exit(if ok { 0 } else { 1 });
}
