//! **Security gate — `vox forward` binds loopback only** (ADR-013).
//!
//! A forward is a local TCP listener that carries every connection it accepts into a
//! room-bound service, authorized by *this* node's membership of that room. Bound to a
//! loopback address that is a private door. Bound anywhere the network can reach, it is
//! an open one: whoever connects to the port gets the service, with no room, no
//! passphrase, no key and no consent of their own.
//!
//! `vox up` has enforced loopback-only since it was written — `node::up::serve` refuses a
//! non-loopback bind and drops a non-loopback peer. `vox forward` did not, and it is the
//! easier of the two to abuse: `vox up` makes the caller supply a `.vox` name, while a
//! forward has its target already chosen, so reaching the port is the whole attack.
//!
//! What this gate proves, driving the real node actor through the public `NodeCommand`
//! API:
//!
//! 1. a forward asked to bind a non-loopback address is **refused**;
//! 2. it is refused **before anything is dialled** — the fault is `NotLoopback`, not the
//!    `Unreachable` that the unreachable host in this test would otherwise produce, so
//!    no traffic left the machine on the strength of the request;
//! 3. **nothing was bound**: the test takes the very port it asked for afterwards, which
//!    only succeeds if no listener was left behind;
//! 4. the refusal is specific to the address and not a blanket refusal — the same
//!    request on loopback gets past the check and fails later, for the unrelated reason
//!    that its host cannot be reached.
//!
//! Production Argon2id (two derivations), so `#[ignore]`d in the debug suite and run by
//! CI's release step with the other real-parameter gates.

#[path = "support/watchdog.rs"]
mod watchdog;

use std::net::SocketAddr;
use std::sync::Arc;

use vox_core::hash::Digest32;
use vox_core::node::actor::{Clock, Node, NodeHandle};
use vox_core::node::api::{Fault, NodeCommand, Outcome, Secret};
use vox_core::node::paths::Paths;

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn spawn(rt: &tokio::runtime::Runtime, paths: &Paths) -> NodeHandle {
    let clock: Clock = Arc::new(|| 1_800_000_000);
    rt.block_on(async {
        Node::spawn_with(
            paths.clone(),
            clock,
            vox_core::atrest::sek::Argon2Profile::default(),
        )
    })
    .unwrap()
}

/// A port nothing else on the machine is using, obtained by binding and releasing one.
/// Racy in principle, and harmless here: if something takes it in between, the final
/// assertion fails loudly rather than passing for the wrong reason.
fn a_free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

#[test]
#[ignore = "production Argon2id; CI runs it in release with the other gates"]
fn a_forward_refuses_to_bind_where_the_network_can_reach_it() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let paths = Paths::resolve("gate", Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap();
    let rt = runtime();
    let h = spawn(&rt, &paths);

    let port = a_free_port();
    let exposed: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
    let private: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    rt.block_on(async {
        assert!(h
            .apply(NodeCommand::CreateIdentity {
                passphrase: secret("identity passphrase"),
            })
            .await
            .is_done());
        assert!(h
            .apply(NodeCommand::CreateChannel {
                local_name: "forward gate".into(),
                passphrase: secret("channel passphrase"),
            })
            .await
            .is_done());
        let cid = h.view().channels[0].channel_id;

        // A host this node has never heard of: it holds no board record for it, so any
        // dial on its behalf can only fail. That is what makes assertion 2 meaningful.
        let nobody: Digest32 = [0x5a; 32];

        // (1) and (2): refused, and refused for the right reason. `Unreachable` here
        // would mean the node dialled first and only then looked at the address.
        let out = h
            .apply(NodeCommand::Forward {
                channel_id: cid,
                host: nobody,
                service_tag: "ssh".into(),
                local: exposed,
            })
            .await;
        assert_eq!(
            out,
            Outcome::Failed(Fault::NotLoopback),
            "a forward bound to {exposed} must be refused as non-loopback, before any \
             dial — got {out:?}"
        );

        // (3): nothing was bound. If the refusal had happened after the listener was
        // created, or if the listener leaked, this bind would fail with EADDRINUSE.
        let taken = std::net::TcpListener::bind(exposed)
            .expect("the refused forward must leave no listener behind on the port it asked for");
        drop(taken);

        // (4): the check is about the address, not about refusing forwards. The same
        // request on loopback gets past it and fails further along, where the host
        // cannot be reached.
        let out = h
            .apply(NodeCommand::Forward {
                channel_id: cid,
                host: nobody,
                service_tag: "ssh".into(),
                local: private,
            })
            .await;
        assert!(
            matches!(out, Outcome::Failed(f) if f != Fault::NotLoopback),
            "a loopback forward must pass the address check and fail on reachability \
             instead — got {out:?}"
        );

        assert!(h.apply(NodeCommand::Shutdown).await.is_done());
    });
}
