//! V210-154 — **what a peer says when it closes a connection never reaches a terminal raw**,
//! through the shipped binary.
//!
//! A QUIC peer closes with a reason of its own choosing, and quinn's `Display` of the error is
//! that reason verbatim. Vox printed it: a peer that a node dialled could clear the operator's
//! screen, retitle their terminal, reorder a line with a bidi override, or print a line that
//! reads as vox's own. Every peer-supplied string vox prints is now shown on one line, its
//! control characters, line and paragraph separators and bidi controls replaced, and capped
//! (`vox_core::text::peer_error`, the same rule as V210-123's).
//!
//! **The attacker** is test-side code (apparatus): a raw Vox endpoint with an identity of its own,
//! given to a real `vox node` as its anchor. It accepts the node's connection, then closes it with
//! an unknown application code and a reason carrying ESC sequences (clear screen, set title),
//! CR/LF and a forged `vox node:` line, NEL, U+2028, a bidi override and 10 KB of text. The node
//! says why its anchor connection went (V210-93), and that is where the reason surfaces.
//!
//! Asserted, as PRODUCT, on everything the node printed:
//! 1. it said its anchor closed the connection (the positive control: the reason was printed);
//! 2. none of the reason's ESC, BEL, CR, NEL, U+2028 or bidi characters appears raw;
//! 3. no line starts with the forged `vox node: forged` line;
//! 4. the reason is capped: no run of the 10 KB filler longer than the cap reaches the output.
//!
//! Mutation that must turn it red: `peer_error` printing the reason raw, as quinn does.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::time::{Duration, Instant};

use vox_core::identity::composite::{RootSigner, SoftwareRootSigner};
use vox_core::node::link::b32_encode;
use vox_core::transport::quic::VoxEndpoint;
use world::{args, tempdir, VoxProc};

/// The application error code the attacker closes with: no `WireError`, so the node shows the
/// reason itself rather than naming a code it knows.
const CLOSE_CODE: u32 = 0x77;

/// The characters that must never reach the terminal raw, with a name for the red.
const RAW: &[(char, &str)] = &[
    ('\u{1b}', "ESC"),
    ('\u{07}', "BEL"),
    ('\r', "CR"),
    ('\u{85}', "NEL"),
    ('\u{2028}', "U+2028"),
    ('\u{202E}', "RLO"),
];

/// The attacker's reason: terminal control, a forged line, line separators, a bidi override, and
/// 10 KB of filler (QUIC carries as much of it as fits one packet).
fn hostile_reason() -> String {
    format!(
        "x\u{1b}[2J\u{1b}]0;owned\u{07}\r\nvox node: forged line\u{85}nel\u{2028}ls\u{202E}gnol {}",
        "A".repeat(10 * 1024)
    )
}

#[test]
#[ignore = "a real vox node and a raw Vox endpoint over loopback; CI runs it in release"]
fn a_peer_cannot_write_to_the_terminal() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap_or_else(|e| panic!("APPARATUS: no runtime: {e}"));
    let tmp = tempdir();

    // ---- the attacker: a raw anchor ----
    let signer = SoftwareRootSigner::generate()
        .unwrap_or_else(|e| panic!("APPARATUS: no identity for the attacker: {e:?}"));
    let endpoint = rt.block_on(async {
        VoxEndpoint::bind(&signer, "127.0.0.1:0".parse().expect("an address"))
            .unwrap_or_else(|e| panic!("APPARATUS: the attacker could not bind: {e:?}"))
    });
    let port = endpoint
        .local_addr()
        .unwrap_or_else(|e| panic!("APPARATUS: the attacker has no address: {e:?}"))
        .port();
    let spec = format!(
        "{}@/ip4/127.0.0.1/udp/{port}",
        b32_encode(&signer.public_key().fingerprint())
    );
    let reason = hostile_reason();
    let closer = rt.spawn(async move {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let conn = match tokio::time::timeout(Duration::from_secs(60), endpoint.accept(now)).await {
            Ok(Ok(Some(c))) => c,
            other => return Err(format!("the node never connected: {other:?}")),
        };
        tokio::time::sleep(Duration::from_millis(500)).await;
        conn.quinn()
            .close(quinn::VarInt::from_u32(CLOSE_CODE), reason.as_bytes());
        // Keep the endpoint up long enough for the close to be sent.
        tokio::time::sleep(Duration::from_secs(3)).await;
        Ok(endpoint)
    });

    // ---- the victim: a real `vox node` with the attacker as its anchor ----
    let mut node = VoxProc::spawn(
        "vox node",
        &tmp.path().join("node"),
        &args(&["node", "--listen", "127.0.0.1:0", "--anchor", &spec]),
    );
    let said = node
        .try_expect_within(
            Duration::from_secs(60),
            "that its anchor closed the connection",
            |l| {
                l.contains(&format!(
                    "the peer closed the connection (code {CLOSE_CODE})"
                ))
            },
        )
        .unwrap_or_else(|why| {
            let closed = rt.block_on(closer);
            panic!(
                "{why}\n(the attacker: {:?}; a node that never connected is CANNOT MEASURE, one \
                 that connected and never said why it closed is PRODUCT)",
                closed.map(|r| r.map(|_| ()))
            )
        });
    // Everything the node printed by now, and a moment more for anything the close set off.
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(2) {
        let _ = node.line_within(Duration::from_millis(200), |_| false);
    }
    let all = node.transcript();
    eprintln!("[proof] the node said: {said}");

    // 2. no control, separator or bidi character of the reason, raw
    let raw: Vec<&str> = RAW
        .iter()
        .filter(|(c, _)| all.contains(*c))
        .map(|(_, n)| *n)
        .collect();
    assert!(
        raw.is_empty(),
        "PRODUCT: a peer's close reason reached the terminal with {raw:?} raw:\n{all:?}"
    );
    // 3. no forged line
    let forged: Vec<&str> = all
        .lines()
        .filter(|l| l.trim_start().starts_with("vox node: forged"))
        .collect();
    assert!(
        forged.is_empty(),
        "PRODUCT: a peer's close reason forged a line of vox's own output: {forged:?}"
    );
    // 4. capped
    let longest_filler = all.split(|c| c != 'A').map(str::len).max().unwrap_or(0);
    assert!(
        longest_filler <= vox_core::text::PEER_REASON_MAX,
        "PRODUCT: a peer's close reason reached the terminal uncapped: {longest_filler} bytes of \
         its filler in one run"
    );
    eprintln!(
        "[proof] none of {} raw, no forged line, the reason capped (longest filler run \
         {longest_filler} bytes)",
        RAW.iter().map(|(_, n)| *n).collect::<Vec<_>>().join(", ")
    );
    drop(node);
}
