//! V210-126 — **the metrics endpoint answers a request that arrives in pieces**, through the
//! shipped binary.
//!
//! `vox daemon --metrics <addr>` serves its counters as Prometheus text (PRD-001 R38). It read a
//! request with one bounded `read`, answered and closed. A request whose request line and headers
//! arrive in separate segments — a slow or proxied scraper's — left the headers unread, and
//! closing with them unread made the OS reset the connection, so the scraper lost the answer
//! (`Connection reset by peer`).
//!
//! **What this drives.** `vox id`, then `vox daemon --metrics 127.0.0.1:0`, whose own stdout names
//! the bound address (`vox daemon: metrics http://…/metrics`). The proof is the scraper: it writes
//! the request line, waits, writes the headers and the blank line that ends them, waits again, and
//! only then reads, as a scraper on a slow path does.
//!
//! **What is asserted.** A complete response: the status line `HTTP/1.1 200`, a `Content-Length`,
//! and exactly that many bytes of body, which carries `vox_up`. A reset, a short body or no status
//! line is `PRODUCT:`. Not being able to start the daemon or reach the address it named is
//! `CANNOT MEASURE`.
//!
//! **Why a file of its own.** No other proof scrapes the metrics endpoint: the proof that came
//! with it was deleted with the non-product tests (V29-17), and the user journeys left drive
//! rooms, not a scraper.
//!
//! **Mutation.** One `read` in place of reading to the end of the head: the scraper is reset or
//! gets nothing, and the proof goes red.

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::io::{Read as _, Write as _};
use std::time::Duration;

use world::{args, vox_once, VoxProc};

/// Between the request line and the headers, and between the headers and the first read: long
/// enough that each write is its own segment and the server has acted on the first before the
/// second arrives.
const GAP: Duration = Duration::from_millis(500);
/// How long the scraper waits for the whole response.
const READ_PATIENCE: Duration = Duration::from_secs(10);

#[test]
#[ignore = "a real vox daemon with production Argon2id; CI runs it in release"]
fn a_scrape_whose_request_arrives_in_pieces_gets_the_whole_response() {
    watchdog::arm();
    let tmp = world::tempdir();
    let data = tmp.path().join("alice");
    world::mkdir(&data.join("cfg"));
    let (ok, _, err) = vox_once(&data, &args(&["id"]));
    assert!(ok, "CANNOT MEASURE (staging): vox id failed: {err}");
    let pass = tmp.path().join("alice.pass");
    std::fs::write(&pass, world::IDENTITY).expect("APPARATUS: write the passphrase file");

    let mut daemon = VoxProc::spawn(
        "alice",
        &data,
        &args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--metrics",
            "127.0.0.1:0",
            "--passphrase-file",
            pass.to_str().expect("APPARATUS: a UTF-8 path"),
        ]),
    );
    let said = daemon.expect_staging("the metrics address", |l| {
        l.starts_with("vox daemon: metrics http://")
    });
    let addr = said
        .trim_start_matches("vox daemon: metrics http://")
        .trim_end_matches("/metrics")
        .to_owned();

    let mut sock = std::net::TcpStream::connect(&addr).unwrap_or_else(|e| {
        panic!("CANNOT MEASURE (staging): the address the daemon named, {addr}, refused: {e}")
    });
    // Set up before anything is sent: once the endpoint has reset the connection, the socket
    // refuses options too, and that would read as this proof's own failure.
    sock.set_nodelay(true).expect("APPARATUS: TCP_NODELAY");
    sock.set_read_timeout(Some(READ_PATIENCE))
        .expect("APPARATUS: a read timeout");
    sock.write_all(b"GET /metrics HTTP/1.1\r\n")
        .expect("APPARATUS: write the request line to a connection just made");
    std::thread::sleep(GAP);
    // The endpoint's to answer from here: a reset that refuses the headers is the product's,
    // and is reported with the read, never as this proof failing.
    let headers = sock
        .write_all(b"Host: localhost\r\nAccept: text/plain\r\nUser-Agent: slow-scraper\r\n\r\n");
    std::thread::sleep(GAP);
    let mut got = Vec::new();
    let read = headers.and_then(|()| sock.read_to_end(&mut got));
    let text = String::from_utf8_lossy(&got).into_owned();

    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let length = head
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .and_then(|n| n.trim().parse::<usize>().ok());
    let complete =
        head.starts_with("HTTP/1.1 200") && length == Some(body.len()) && body.contains("vox_up");
    println!(
        "[proof] a scrape sent as request line, then headers {GAP:?} later: read {:?}, {} bytes, \
         status line {:?}, Content-Length {length:?}, body {} bytes, vox_up {}",
        read.as_ref().map(|_| ()).map_err(std::io::Error::kind),
        got.len(),
        head.lines().next().unwrap_or(""),
        body.len(),
        body.contains("vox_up")
    );
    assert!(
        read.is_ok() && complete,
        "PRODUCT: a request sent in pieces must get the whole metrics response: the read \
         ended {read:?} after {} bytes: {text:?}",
        got.len()
    );
}
