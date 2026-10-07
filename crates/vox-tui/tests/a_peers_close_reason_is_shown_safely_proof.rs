//! V210-154 — **a peer's connection-close reason never reaches a terminal unsanitised**, through
//! the shipped binary. Run on demand; not a gate.
//!
//! A QUIC CONNECTION_CLOSE carries a reason the peer writes, and `vox` printed it as it came: quinn
//! renders it into its error text, and that text went into what `vox` says about the connection.
//! So a peer could put escape sequences, carriage returns and line feeds, NEL or bidi controls in
//! front of the person running `vox`: retitle or clear their terminal, or print a line that looks
//! like `vox` said it.
//!
//! **Staging.** The hostile peer is not a person using vox, so it is not a `vox` process: it is a
//! QUIC endpoint of this test's own with a Vox identity (`support/hostile.rs`), which completes
//! each handshake and closes the connection at once with a reason carrying ESC, BEL, CR/LF, NEL,
//! U+2028, the bidi controls and 10 KB of text (QUIC fits what it can of it in one packet). Two
//! real `vox` processes meet it:
//! - `vox node --anchor <hostile>`, which reports each loss of its anchor and why;
//! - `vox connect` of an address naming the hostile peer as the room's host, a joiner.
//!
//! **Asserted (PRODUCT).** `vox node` says why its anchor went, quoting the reason (#191);
//! neither process's output holds any of those characters, nor a line the reason started, nor
//! more of the reason than the cap. **CANNOT MEASURE** if the peer never closed a connection.
//!
//! The close fills a whole packet, and quinn-proto writes it up to 7 bytes over the path MTU when
//! its code is more than a byte (0x7e57 is 4): a receiver whose buffer stopped at the ceiling lost
//! it, met the peer's stateless reset, and reported "reset by peer" with no reason.
//!
//! **Mutations that must turn it red (PRODUCT).** `transport::quic::peer_text` returning its input
//! unchanged: the reason is printed raw, ESC and all. No receive headroom over the path-MTU
//! ceiling (`RECEIVE_HEADROOM` 0): the close is lost and `vox node` says "reset by peer".

#![cfg(unix)]

#[path = "support/hostile.rs"]
mod hostile;
#[path = "support/ports.rs"]
mod ports;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vox_core::node::link::b32_encode;
use vox_core::transport::quic::VoxEndpoint;
use world::{args, VoxProc};

/// What the hostile peer closes with: each kind of character that could break a line or move the
/// cursor, a forged `vox` line, and a long tail.
fn evil_reason() -> String {
    let mut r = String::from("owned\u{1b}]0;title\u{07}\u{1b}[2J\u{1b}[31m");
    r.push_str("\r\nvox: forged line\n");
    r.push_str("\u{85}nel\u{2028}ls\u{2029}ps\u{202E}gnp.exe\u{2066}iso\u{200F}rlm\u{0b}\u{0c}\0");
    r.push_str(&"A".repeat(10 * 1024));
    r
}

/// The characters none of which may reach the terminal raw.
const FORBIDDEN: &[char] = &[
    '\u{1b}', '\u{07}', '\r', '\u{85}', '\u{2028}', '\u{2029}', '\u{202E}', '\u{2066}', '\u{200F}',
    '\u{0b}', '\u{0c}', '\0',
];

/// More of the reason's tail than this, in one run, is more than the cap lets through.
const TAIL_SEEN_AT_MOST: usize = 300;

/// How long each victim is watched.
const WATCH: Duration = Duration::from_secs(25);

fn check(who: &str, said: &[String]) {
    for line in said {
        let text = line.strip_prefix("! ").unwrap_or(line);
        if let Some(c) = text.chars().find(|c| FORBIDDEN.contains(c)) {
            panic!(
                "PRODUCT: {who} printed the peer's close reason raw: U+{:04X} reached the terminal \
                 in {text:?}",
                u32::from(c)
            );
        }
        assert!(
            !text.starts_with("vox: forged line"),
            "PRODUCT: {who} printed a line the peer's close reason started: {text:?}"
        );
        let run = text.split(|c| c != 'A').map(str::len).max().unwrap_or(0);
        assert!(
            run <= TAIL_SEEN_AT_MOST,
            "PRODUCT: {who} printed {run} bytes of the peer's close reason in one line; it is not \
             capped"
        );
    }
}

fn watch(p: &mut VoxProc, within: Duration) -> Vec<String> {
    let until = Instant::now() + within;
    while let Some(left) = until.checked_duration_since(Instant::now()) {
        match p.lines.recv_timeout(left.min(Duration::from_secs(1))) {
            Ok(line) => p.seen.push(line),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    p.seen.clone()
}

#[test]
#[ignore = "real vox processes against a hostile QUIC peer; run on demand, in release"]
fn a_peers_close_reason_never_reaches_the_terminal_raw() {
    watchdog::arm();
    let rt = hostile::Rt::new();
    let signer = hostile::stranger(0x54);
    let ep = Arc::new(
        rt.block_on(async { VoxEndpoint::bind(signer.clone(), "127.0.0.1:0".parse().unwrap()) })
            .unwrap_or_else(|e| panic!("APPARATUS: the hostile peer could not bind: {e}")),
    );
    let at = ep
        .local_addr()
        .unwrap_or_else(|e| panic!("APPARATUS: the hostile peer's address: {e}"));
    let fp = b32_encode(&ep.local_id());
    let closed = Arc::new(AtomicUsize::new(0));
    {
        let (ep, closed) = (Arc::clone(&ep), Arc::clone(&closed));
        let reason = evil_reason();
        rt.spawn(async move {
            let mut held = Vec::new();
            loop {
                match ep.accept(hostile::now_ms()).await {
                    Ok(Some(conn)) => {
                        conn.quinn()
                            .close(quinn::VarInt::from_u32(0x7e57), reason.as_bytes());
                        closed.fetch_add(1, Ordering::Relaxed);
                        // Held, so nothing about this end going away decides what is sent.
                        held.push(conn);
                    }
                    Ok(None) => break,
                    Err(_) => {}
                }
            }
        });
    }
    let tmp = tempfile::tempdir().unwrap();
    let spec = format!("{fp}@/ip4/127.0.0.1/udp/{}", at.port());

    // ---- vox node, with the hostile peer as its anchor ---------------------------------------
    let node_dir = hostile::profile_dir(tmp.path(), "node");
    let mut node = VoxProc::spawn(
        "node",
        &node_dir,
        &args(&["node", "--listen", "127.0.0.1:0", "--anchor", &spec]),
    );
    let said = watch(&mut node, WATCH);
    drop(node);
    println!("[proof] vox node said:\n{}", said.join("\n"));
    assert!(
        closed.load(Ordering::Relaxed) > 0,
        "CANNOT MEASURE: vox node never connected to the hostile peer, so nothing was closed on it"
    );
    assert!(
        said.iter().any(|l| l.contains("owned")),
        "PRODUCT: vox node never said why its anchor went: the anchor's close reason did not reach \
         it, or was not shown"
    );
    check("vox node", &said);

    // ---- a joiner, whose address names the hostile peer as the room's host -------------------
    let joiner_dir = hostile::profile_dir(tmp.path(), "joiner");
    let pass = joiner_dir.join("room-pass");
    std::fs::write(&pass, "a room passphrase\n").unwrap();
    let room = b32_encode(&[0x42u8; 32]);
    let address = format!(
        "vox://{room}?a={fp}&b=/ip4/127.0.0.1/udp/{}&r={fp}",
        at.port()
    );
    let before = closed.load(Ordering::Relaxed);
    let mut joiner = VoxProc::spawn(
        "joiner",
        &joiner_dir,
        &args(&[
            "connect",
            &address,
            "--passphrase-file",
            pass.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
        ]),
    );
    let said = watch(&mut joiner, WATCH);
    drop(joiner);
    println!("[proof] the joiner said:\n{}", said.join("\n"));
    assert!(
        closed.load(Ordering::Relaxed) > before,
        "CANNOT MEASURE: the joiner never connected to the hostile peer"
    );
    check("the joiner", &said);
}
