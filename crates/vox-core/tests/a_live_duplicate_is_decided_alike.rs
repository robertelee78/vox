//! v0.2.9 #6 — **two live connections between the same pair are decided the same way at both
//! ends**, even when one of them arrives from an address the other end has never seen.
//!
//! A restarted peer leaves the far end holding a dead connection (see `SILENCE_IS_DEATH` in
//! `node::net`). The first fix proposed for that was an address rule: "a direct newcomer from a
//! different address than the held connection means the peer moved, so the newcomer replaces the
//! held one". It is wrong for a **live** process behind a NAT that rebinds: the process never
//! restarted, its NAT simply handed it a new external port, and a second dial from it — two
//! concurrent `connect`s racing, a punch landing beside a dial — arrives from that new port.
//! Only the end that *receives* the newcomer sees the address change. The dialling end sees the
//! same anchor address on both connections, so it goes to the tie-break; the anchor, under the
//! address rule, does not. Half the time they keep different connections, and each opens streams
//! on one the other has retired.
//!
//! What this asserts: across many trials, **the connection the anchor keeps at filing time is the
//! connection the member keeps**, and once things settle both ends still hold that same, live
//! connection. The NAT rebinding is real in the sense that matters: `vnet::VirtualNet::rebind`
//! drops the mapping, the second dial leaves from a fresh external port, and the gate asserts the
//! anchor saw the two connections from different addresses — otherwise it would not be staging
//! the case at all.
//!
//! Real QUIC, real handshakes, the real `ConnectionManager` on both ends, over the in-process
//! NAT network. `#[ignore]`d in the debug suite; CI runs it in the release step.

#[path = "support/watchdog.rs"]
mod watchdog;

#[path = "support/vnet.rs"]
mod vnet;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use vnet::{NatKind, VirtualNet};
use vox_core::identity::composite::SoftwareRootSigner;
use vox_core::nat::multiaddr::{EndpointList, Multiaddr};
use vox_core::node::net::{ConnectionManager, Filed};
use vox_core::transport::quic::{Admission, VoxConnection, VoxEndpoint};

/// Trials. Each is an independent coin for the tie-break, so an address rule that disagrees
/// half the time is all but certain to be caught: 0.5^20 is one in a million.
const TRIALS: usize = 24;

fn signer(a: u8) -> SoftwareRootSigner {
    SoftwareRootSigner::from_component_seeds(&[a; 32], &[a ^ 0x5A; 32]).unwrap()
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// A label only this test uses: both ends derive the same bytes from the same connection's TLS
/// exporter, so equal tags mean the **same** connection, never merely two that look alike.
fn tag(conn: &VoxConnection) -> [u8; 8] {
    let mut out = [0u8; 8];
    conn.quinn()
        .export_keying_material(&mut out, b"vox/test/which-connection", b"")
        .expect("exporter");
    out
}

async fn recv_filed(rx: &mut mpsc::UnboundedReceiver<Filed>) -> Filed {
    tokio::time::timeout(Duration::from_secs(20), rx.recv())
        .await
        .expect("the anchor filed the dial")
        .expect("accept loop alive")
}

fn hex(t: [u8; 8]) -> String {
    t.iter().map(|b| format!("{b:02x}")).collect()
}

/// One trial: a member behind a symmetric NAT dials the anchor, its NAT rebinds, and it dials
/// again. Returns (the anchor's choice at filing, the member's choice at filing, both settled
/// choices, whether the anchor saw the two dials from different addresses, and the second dial's
/// tag).
async fn trial(n: usize) -> ([u8; 8], [u8; 8], [u8; 8], [u8; 8], bool, [u8; 8]) {
    let net = VirtualNet::new();
    let c_addr = addr("198.51.100.1:443");
    let m_inner = addr("10.0.1.2:5000");
    let c_sock = net.public(c_addr);
    let m_sock = net.behind_nat(m_inner, NatKind::Symmetric, ip("203.0.113.1"));

    let seed = u8::try_from(2 * n + 1).unwrap();
    let clock = vox_core::time::system_clock();
    let c_ep = Arc::new(VoxEndpoint::bind_abstract(&signer(seed), c_sock).unwrap());
    let m_ep = Arc::new(VoxEndpoint::bind_abstract(&signer(seed + 1), m_sock).unwrap());
    let c_id = c_ep.local_id();
    let anchor = Arc::new(ConnectionManager::new(c_ep, Arc::clone(&clock)));
    let member = ConnectionManager::new(m_ep, Arc::clone(&clock));

    // The anchor's accept loop, shaped as the node's: handshakes finish off the loop and are
    // filed with `finish_incoming`, which retires (and hands back) a duplicate that lost.
    let (filed_tx, mut filed_rx) = mpsc::unbounded_channel::<Filed>();
    let accepting = {
        let anchor = Arc::clone(&anchor);
        tokio::spawn(async move {
            while let Some(incoming) = anchor.accept_incoming().await {
                let anchor = Arc::clone(&anchor);
                let filed_tx = filed_tx.clone();
                tokio::spawn(async move {
                    if let Ok(filed) = anchor
                        .finish_incoming(incoming, Admission::AcceptAnyAuthenticated)
                        .await
                    {
                        let _ = filed_tx.send(filed);
                    }
                });
            }
        })
    };
    // First dial: the member's ordinary connection to its anchor.
    let endpoints = EndpointList::new(vec![Multiaddr::from(c_addr)]).unwrap();
    let first = member.connect(c_id, &endpoints).await.expect("first dial");
    let first_filed = recv_filed(&mut filed_rx).await;
    assert_eq!(tag(&first), tag(&first_filed.kept), "one connection so far");
    // Let the handshake's tail (HANDSHAKE_DONE, NEW_CONNECTION_ID and their ACKs) cross first.
    // Anything the member sends on the first connection *after* the rebind migrates it to the
    // new port at the anchor, and then both connections come from one address and the case is
    // not staged; after the tail the first connection is quiet until its next keep-alive, 20s on.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The NAT rebinds under the live process, and the process dials again.
    let dropped = net.rebind(m_inner);
    assert!(dropped > 0, "trial {n}: the NAT had no mapping to rebind");
    let second = member
        .endpoint()
        .connect(c_addr, c_id, clock())
        .await
        .expect("second dial");
    let second_tag = tag(&second);
    let member_kept = member.adopt(second);
    let second_filed = recv_filed(&mut filed_rx).await;
    let second_seen_from = if tag(&second_filed.kept) == second_tag {
        second_filed
            .kept
            .remote_address()
            .expect("the connection has its path")
    } else {
        second_filed
            .also_serve
            .as_ref()
            .expect("the anchor either kept the newcomer or retired it")
            .remote_address()
            .expect("the connection has its path")
    };
    // Where the anchor places the first connection **now**, as the second is filed: that is the
    // comparison an address rule makes, so it is the one that says whether this was staged.
    let first_seen_from = first_filed
        .kept
        .remote_address()
        .expect("the connection has its path");
    let staged = first_seen_from != second_seen_from;

    // Settled: both ends' current connection, after any close has crossed.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let anchor_now = anchor
        .existing(&member.local_id())
        .map(|c| tag(&c))
        .unwrap_or_default();
    let member_now = member.existing(&c_id).map(|c| tag(&c)).unwrap_or_default();

    let out = (
        tag(&second_filed.kept),
        tag(&member_kept),
        anchor_now,
        member_now,
        staged,
        second_tag,
    );
    drop(second_filed);
    drop(first_filed);
    member.close_all();
    anchor.close_all();
    accepting.abort();
    out
}

#[test]
#[ignore = "24 pairs of real QUIC handshakes over a NAT that rebinds; CI runs it in release"]
fn a_live_duplicate_from_a_rebound_nat_is_decided_alike_at_both_ends() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (mut at_filing, mut settled, mut staged, mut newcomer_kept) = (0, 0, 0, 0);
        for n in 0..TRIALS {
            let (anchor_filed, member_filed, anchor_now, member_now, moved, second) =
                trial(n).await;
            if moved {
                staged += 1;
            }
            if anchor_filed == member_filed {
                // Which one survived is the tie-break's business; counted so the output shows
                // the coin really is a coin — a rule that always kept one would read 0 or TRIALS.
                if anchor_filed == second {
                    newcomer_kept += 1;
                }
            } else {
                at_filing += 1;
                eprintln!(
                    "[test] trial {n}: DISAGREE at filing — anchor kept {}, member kept {}",
                    hex(anchor_filed),
                    hex(member_filed)
                );
            }
            if anchor_now != member_now || anchor_now == [0; 8] {
                settled += 1;
                eprintln!(
                    "[test] trial {n}: DISAGREE settled — anchor holds {}, member holds {}",
                    hex(anchor_now),
                    hex(member_now)
                );
            }
        }
        eprintln!(
            "[test] {TRIALS} trials: {staged} staged a new source port, {at_filing} disagreed at \
             filing, {settled} disagreed once settled; the second dial survived {newcomer_kept} times"
        );
        assert_eq!(
            staged, TRIALS,
            "every trial must present the second dial from a new external port, or it is not \
             the rebinding case: {staged}/{TRIALS}"
        );
        assert_eq!(
            at_filing, 0,
            "{at_filing}/{TRIALS} trials: the anchor and the member kept different connections \
             for a live duplicate — each end then opens streams on one the other has retired"
        );
        assert_eq!(
            settled, 0,
            "{settled}/{TRIALS} trials: the two ends did not settle on the same live connection"
        );
    });
}
