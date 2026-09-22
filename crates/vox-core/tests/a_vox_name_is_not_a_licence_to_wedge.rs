//! A stranger who has only ever been given a `.vox` address must not be able to stop the node.
//!
//! `a_silent_stream_cannot_wedge_the_node` closes the general shape of this — a stream that
//! says nothing must not stop the actor — but it ends with a note claiming the remaining
//! exposure "needs an attacker that is already an admitted member of a room the victim
//! holds, which is the honest severity: an insider denial of service, not an anonymous one".
//!
//! **That note was wrong, and this gate is why it is now deleted.** An audit found a
//! four-step escalation from nothing to `PendingJoiner`:
//!
//! 1. connect — `Admission::AcceptAnyAuthenticated` admits any valid Vox identity;
//! 2. open `Rendezvous`, which the stream-kind gate permits to `Unknown`;
//! 3. PUT a self-signed `PreJoinRecord` naming any channelID. A pre-join deliberately needs
//!    no membership, no passphrase and no proof of work — a joiner has none of those yet —
//!    so this classification is **self-service**;
//! 4. `classify` now answers `PendingJoiner`, which may open `Join` and `Pairwise`.
//!
//! A channelID is not a secret. It is the 52-character `.vox` hostname, and it is in every
//! invite link. So the wedge was reachable by anyone who had ever been handed an address.
//!
//! **Step 3 is asserted to be accepted, and that assertion is the load-bearing one.** The
//! deleted test in the sibling file failed exactly here: an `Unknown` peer's `Sync` stream is
//! refused at the kind gate, so it measured a refusal and called it a wedge. If the pre-join
//! were refused, the attacker would never leave `Unknown`, the `Join` stream would be turned
//! away before reaching the actor, and everything after it would pass against a node that was
//! still wide open. A test that cannot fail is worse than no test.
//!
//! The victim serves the room, so the pre-join is still accepted after the fix — the board
//! holds that channel's genesis. That is the point: the first fix narrows *which* boards a
//! stranger can classify itself against, and this gate proves the second one, that reaching
//! `PendingJoiner` on a board that does serve the room still cannot stop it.
//!
//! Three runs, because a green gate is not evidence:
//!
//! - against the fix, it passes;
//! - with the join request read back inside the actor, it **fails** — the node answers no
//!   command at all, which is the defect;
//! - with the join request read inside the actor *and* step 3 removed, it **passes**. That
//!   last one is the control: without the pre-join the attacker stays `Unknown`, the `Join`
//!   stream is refused at the kind gate, and the gate would have gone green against a node
//!   that was wide open. Step 3 is what makes this a test rather than a ceremony.

#[path = "support/watchdog.rs"]
mod watchdog;

use std::time::{Duration, Instant};

use vox_core::identity::composite::{RootSigner, SoftwareRootSigner};
use vox_core::join::pow::PowParams;
use vox_core::nat::multiaddr::EndpointList;
use vox_core::nat::record::PreJoinRecord;
use vox_core::nat::service::RendezvousClient;
use vox_core::node::actor::{Bind, Node, NodeConfig};
use vox_core::node::api::{NodeCommand, Secret};
use vox_core::node::paths::Paths;
use vox_core::node::prekeys::PrekeyRing;
use vox_core::transport::quic::VoxEndpoint;
use vox_core::transport::streams::{open_typed, StreamKind};

/// Every command must answer inside this. The wedge is unbounded, so the exact value only has
/// to be far below "for ever" and far above a loopback round trip.
const PATIENCE: Duration = Duration::from_secs(2);

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stranger_holding_only_a_vox_name_cannot_stop_the_node() {
    watchdog::arm();
    // The victim runs on the real system clock (`Node::spawn_config`), and a pre-join is
    // time-checked against it, so the attacker's record must be dated now and not at some
    // convenient fixed epoch.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // ---- the victim: an ordinary node with one room open --------------------------------
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::resolve("victim", Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();
    let mut cfg = NodeConfig::new().bind(Bind::Addr("127.0.0.1:0".parse().unwrap()));
    // The join's PoW is not what this gate is about; the M14 gate exercises the real one.
    cfg.pow_params = Some(PowParams { n: 48, k: 5 });
    let victim = Node::spawn_config(paths, cfg).unwrap();
    assert!(victim
        .apply(NodeCommand::CreateIdentity {
            passphrase: secret("victim identity passphrase"),
        })
        .await
        .is_done());
    assert!(victim
        .apply(NodeCommand::CreateChannel {
            local_name: "team".into(),
            passphrase: secret("room passphrase"),
        })
        .await
        .is_done());

    let view = victim.view();
    let channel_id = view.channels[0].channel_id;
    let victim_id = view.identity.unwrap().fingerprint;
    // `listening` is ADR-012 multiaddr text; the attacker dials a socket address.
    let listening = view.listening.clone();
    let victim_addr = listening
        .iter()
        .find_map(|m| {
            let port = m.rsplit_once("/udp/")?.1;
            format!("127.0.0.1:{port}")
                .parse::<std::net::SocketAddr>()
                .ok()
        })
        .unwrap_or_else(|| panic!("the victim advertised no dialable UDP endpoint: {listening:?}"));

    // ---- the attacker: a fresh identity and nothing else ---------------------------------
    // Not a member, never invited, holds no passphrase. All it has is `channel_id`, which is
    // the room's public `.vox` name.
    let attacker = SoftwareRootSigner::from_component_seeds(&[0xA7; 32], &[0x5C; 32]).unwrap();
    let endpoint = VoxEndpoint::bind(&attacker, "127.0.0.1:0".parse().unwrap()).unwrap();
    let conn = endpoint
        .connect(victim_addr, victim_id, now)
        .await
        .expect("step 1: any valid identity is admitted, so the connection must succeed");

    // ---- step 3, and the assertion this whole gate stands on ------------------------------
    let ring = PrekeyRing::generate(&attacker, &[0x3B; 32], now).unwrap();
    let bundle = ring.bundle(&attacker.public_key()).unwrap();
    let prejoin = PreJoinRecord::build(
        &attacker,
        &channel_id,
        bundle,
        EndpointList::new(Vec::new()).unwrap(),
        1,
        now,
    )
    .unwrap();

    let mut rendezvous = RendezvousClient::open(&conn)
        .await
        .expect("step 2: `Unknown` may open a Rendezvous stream");
    if let Err(why) = rendezvous.put(&prejoin.to_wire()).await {
        panic!(
            "step 3 was refused with {why:?}, so this attacker never became a PendingJoiner \
             and everything below it would measure a refusal rather than a wedge — the exact \
             way the deleted test in a_silent_stream_cannot_wedge_the_node.rs fooled itself. \
             The victim serves this channel, so a pre-join for it MUST still be accepted; if \
             that changed deliberately, this gate needs rewriting, not relaxing"
        );
    }

    // The rendezvous stream must be finished before the Join stream is opened. A node serves
    // rendezvous inline in the connection's accept loop, so while this stream is open that
    // loop never accepts another — the attacker would be blocking only itself, and the Join
    // stream would never reach the node at all.
    drop(rendezvous);

    // ---- step 5: open a Join stream and say nothing ----------------------------------------
    // `PendingJoiner` may open this. The bytes never come, and the QUIC keep-alive means the
    // connection never dies on its own, so a handler that reads inline waits for ever.
    let (_silent_send, _silent_recv) = open_typed(&conn, StreamKind::Join)
        .await
        .expect("step 4: a PendingJoiner may open a Join stream");

    // ---- the node must still be a node -----------------------------------------------------
    // Five commands, not one: the wedge shows up as the actor never returning, and a single
    // command could be answered from a queue drained before the silent stream arrived.
    for i in 1..=5_u32 {
        let started = Instant::now();
        let answered = tokio::time::timeout(
            PATIENCE,
            victim.apply(NodeCommand::SendText {
                channel_id,
                text: format!("ordinary work {i}"),
            }),
        )
        .await;
        assert!(
            answered.is_ok(),
            "command {i} of 5 got no answer in {:?} while a stranger held one silent Join \
             stream. The attacker is not a member: it has a valid identity and the room's \
             public .vox name, nothing more. An anchor — always on, always addressable — is \
             the worst case, and this is permanent, because nothing times the stream out",
            started.elapsed()
        );
        assert!(
            answered.unwrap().is_done(),
            "command {i} of 5 was answered but refused, which is a different defect from the \
             wedge this gate measures"
        );
    }

    assert!(victim.apply(NodeCommand::Shutdown).await.is_done());
}
