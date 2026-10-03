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
//! **And a head that is never read to its end** (V030-23). The endpoint stops reading a head at
//! 16 KiB or after 2 s; it closed with the rest unread, and the reset that made could overtake the
//! answer on macOS. Two more scrapes, each on its own connection: a head over 16 KiB sent whole,
//! then read; and a head that never ends, written on and on, read once the endpoint has answered.
//!
//! **What is asserted.** For each scrape, a complete response: the status line `HTTP/1.1 200`, a `Content-Length`,
//! and exactly that many bytes of body, which carries `vox_up` and the node's health,
//! `vox_unhealthy <n>` (PRD-001 R38). A reset, a short body or no status line is `PRODUCT:`.
//!
//! **And the health it serves is the node's** (R38). One more scrape, whole: its `vox_unhealthy`
//! is the number of lines `vox status --json` flags under `unhealthy`, read from the same node.
//!
//! vox failing to start, or not answering at the address it named, is `PRODUCT (staging)`: these
//! are vox's own steps.
//!
//! **Why a file of its own.** No other proof scrapes the metrics endpoint: the proof that came
//! with it was deleted with the non-product tests (V29-17), and the user journeys left drive
//! rooms, not a scraper.
//!
//! **Mutations.**
//! - One `read` in place of reading to the end of the head: the scraper is reset or gets nothing,
//!   and the proof goes red.
//! - Closing without draining after the answer: the scrapes whose head was not read to its end
//!   are reset, and the proof goes red.

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
/// How long the scraper of a head that never ends writes before it reads: past the 2 s the
/// endpoint reads a head for, and inside the 2 s it then drains for.
const ENDLESS_READ_AFTER: Duration = Duration::from_secs(3);
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
    assert!(ok, "PRODUCT (staging): vox id failed: {err}");
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

    let mut reds = Vec::new();

    // ---- the request line, then the headers `GAP` later ----
    let mut sock = connect(&addr);
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
    reds.extend(judge("request line, then headers later", read, &got));

    // ---- a head over 16 KiB, sent whole, then read ----
    let mut sock = connect(&addr);
    let mut big = b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nX-Pad: ".to_vec();
    big.resize(big.len() + 20 * 1024, b'a');
    big.extend_from_slice(b"\r\n\r\n");
    let sent = sock.write_all(&big);
    std::thread::sleep(GAP);
    let mut got = Vec::new();
    let read = sent.and_then(|()| sock.read_to_end(&mut got));
    reds.extend(judge("a 20 KiB head", read, &got));

    // ---- a head that never ends, written on while the scraper reads ----
    let mut sock = connect(&addr);
    let mut writer = sock
        .try_clone()
        .expect("APPARATUS: a second handle on the socket");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopped = std::sync::Arc::clone(&stop);
    let pad = std::thread::spawn(move || {
        let _ = writer.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n");
        // Until the scraper has read its answer, or the endpoint refuses more: either ends it. A
        // line every 2 ms, about 5 KB/s: under 16 KiB in the 2 s the endpoint reads for, so it is
        // the time bound that ends the head, and there is always input the endpoint has not read.
        while !stopped.load(std::sync::atomic::Ordering::SeqCst) {
            if writer.write_all(b"X-Pad: a\r\n").is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    });
    // The answer is left unread until the endpoint has stopped reading the head (2 s) and answered:
    // a reset discards what the scraper has not yet read, so a scraper already blocked in `read`
    // can take the answer before the reset lands and hide it.
    std::thread::sleep(ENDLESS_READ_AFTER);
    let mut got = Vec::new();
    let read = sock.read_to_end(&mut got);
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    pad.join().expect("APPARATUS: the writer thread");
    reds.extend(judge("a head that never ends", read, &got));

    // ---- the health it serves is the node's own: a whole scrape against `vox status --json` ----
    let mut sock = connect(&addr);
    let sent = sock.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let mut got = Vec::new();
    let read = sent.and_then(|()| sock.read_to_end(&mut got));
    reds.extend(judge("a whole request", read, &got));
    let served = unhealthy_served(&got);
    let (ok, out, err) = vox_once(&data, &args(&["status", "--json"]));
    assert!(
        ok,
        "PRODUCT: `vox status --json` failed on the running node: {err}"
    );
    let status: serde_json::Value = serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` printed no JSON ({e}): {out}"));
    let flagged = status["unhealthy"].as_array().map(Vec::len);
    println!(
        "[proof] health: the endpoint serves vox_unhealthy {served:?}; `vox status --json` flags \
         {flagged:?}"
    );
    if served.is_none() || served != flagged.map(|n| n as u64) {
        reds.push(format!(
            "  health: the endpoint serves vox_unhealthy {served:?}, but `vox status --json` \
             flags {flagged:?} unhealthy lines"
        ));
    }

    assert!(
        reds.is_empty(),
        "PRODUCT: every scrape must get the whole metrics response, with the node's health and no \
         reset:\n{}",
        reds.join("\n")
    );
}

/// A connection to the endpoint at `addr`, set up before anything is sent: once the endpoint has
/// reset the connection, the socket refuses options too, and that would read as this proof's own
/// failure.
fn connect(addr: &str) -> std::net::TcpStream {
    let sock = std::net::TcpStream::connect(addr).unwrap_or_else(|e| {
        panic!("PRODUCT (staging): the address the daemon named, {addr}, refused: {e}")
    });
    sock.set_nodelay(true).expect("APPARATUS: TCP_NODELAY");
    sock.set_read_timeout(Some(READ_PATIENCE))
        .expect("APPARATUS: a read timeout");
    sock
}

/// Whether `got`, which the scrape `case` read with `read`, is the whole response: the status line
/// `HTTP/1.1 200`, a `Content-Length`, exactly that many bytes of body carrying `vox_up` and a
/// `vox_unhealthy` value, and a read that ended cleanly. `Some` names what was wrong.
fn judge(case: &str, read: std::io::Result<usize>, got: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(got).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let length = head
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .and_then(|n| n.trim().parse::<usize>().ok());
    let health = unhealthy_served(got);
    let complete = head.starts_with("HTTP/1.1 200")
        && length == Some(body.len())
        && body.contains("vox_up")
        && health.is_some();
    println!(
        "[proof] {case}: read {:?}, {} bytes, status line {:?}, Content-Length {length:?}, body {} \
         bytes, vox_up {}, vox_unhealthy {health:?}",
        read.as_ref().map(|_| ()).map_err(std::io::Error::kind),
        got.len(),
        head.lines().next().unwrap_or(""),
        body.len(),
        body.contains("vox_up")
    );
    (read.is_err() || !complete).then(|| {
        format!(
            "  {case}: the read ended {read:?} after {} bytes: {:?}",
            got.len(),
            text.chars().take(300).collect::<String>()
        )
    })
}

/// The value of the `vox_unhealthy` gauge in a scraped response, if it carries one.
fn unhealthy_served(got: &[u8]) -> Option<u64> {
    String::from_utf8_lossy(got)
        .lines()
        // Labelled with the node it counts for (ADR-026 P-1): the profile `default`.
        .find_map(|l| l.strip_prefix("vox_unhealthy{node=\"default\"} "))
        .and_then(|v| v.trim().parse().ok())
}
