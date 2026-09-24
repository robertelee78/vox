//! The shared body of the three R42 gates (`perf_r42_first_connect_*_gate.rs`): one
//! topology per binary, so each gets the watchdog's whole budget.
#![allow(dead_code)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::vnet::{self, NatKind, VirtualNet};
use vox_core::identity::composite::RootSigner;
use vox_core::join::pow::PowParams;
use vox_core::nat::bootstrap::{BootstrapNode, BootstrapSet};
use vox_core::nat::multiaddr::{EndpointList, Multiaddr};
use vox_core::node::actor::{Bind, Node, NodeConfig, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::paths::Paths;

pub const TIMEOUT: Duration = Duration::from_secs(120);
/// PRD-001 R42.
pub const TARGET: Duration = Duration::from_millis(2000);
/// At least 20 cold connections per topology.
pub const SAMPLES: usize = 20;
pub const POLL: Duration = Duration::from_millis(5);
/// How long a sample waits for a direct path where one exists before it is recorded as
/// censored at this bound — already five times the target.
pub const DIRECT_WAIT: Duration = Duration::from_secs(10);
/// How long a cold connection is tried before the sample is recorded as unreached, at this
/// bound. Ten times the target; the CLI itself would keep trying for `HOST_PATIENCE`.
pub const GIVE_UP: Duration = Duration::from_secs(20);

pub fn env_ms(name: &str) -> Option<Duration> {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .map(Duration::from_millis)
}
pub fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}
pub fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}
pub fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}
pub fn paths(tmp: &tempfile::TempDir, name: &str) -> Paths {
    Paths::resolve(name, Some(tmp.path()), Some(&tmp.path().join("cfg"))).unwrap()
}
pub fn uptime() -> String {
    std::process::Command::new("uptime")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}

/// min / median / p95 / max, nearest-rank.
pub fn stats(label: &str, samples: &[Duration]) -> (Duration, Duration, Duration, Duration) {
    let mut s = samples.to_vec();
    s.sort();
    let at = |q: f64| s[((q * s.len() as f64).ceil() as usize).clamp(1, s.len()) - 1];
    let out = (s[0], at(0.5), at(0.95), s[s.len() - 1]);
    eprintln!(
        "{label}: n={} min={:?} median={:?} p95={:?} max={:?}",
        s.len(),
        out.0,
        out.1,
        out.2,
        out.3
    );
    out
}

pub fn spawn(
    tmp: &tempfile::TempDir,
    name: &str,
    socket: Arc<vnet::VirtualSocket>,
    anchors: BootstrapSet,
) -> NodeHandle {
    let mut cfg = NodeConfig::new()
        .bind(Bind::Socket(socket))
        .anchors(anchors);
    cfg.pow_params = Some(PowParams { n: 48, k: 5 });
    Node::spawn_config(paths(tmp, name), cfg).unwrap()
}

pub async fn node(
    tmp: &tempfile::TempDir,
    name: &str,
    socket: Arc<vnet::VirtualSocket>,
    anchors: BootstrapSet,
) -> NodeHandle {
    let h = spawn(tmp, name, socket, anchors);
    assert!(h
        .apply(NodeCommand::CreateIdentity {
            passphrase: secret("identity passphrase")
        })
        .await
        .is_done());
    h
}

pub async fn wait_for<T>(h: &NodeHandle, mut f: impl FnMut(NodeEvent) -> Option<T>) -> T {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            match h.next_event().await {
                Some(e) => {
                    if let Some(v) = f(e) {
                        return v;
                    }
                }
                None => panic!("event stream ended"),
            }
        }
    })
    .await
    .expect("event did not arrive")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Topology {
    Open,
    Punch,
    Relay,
}

/// A host socket for `who` (0 = alice, 1+ = bob's restarts) in `topology`, each one on a
/// fresh address and — behind a NAT — a fresh NAT, so nothing carries over.
pub fn host(net: &Arc<VirtualNet>, topology: Topology, who: u8) -> Arc<vnet::VirtualSocket> {
    let private = addr(&format!("10.0.{who}.2:5000"));
    match topology {
        Topology::Open => net.public(addr(&format!("192.0.2.{}:5000", who + 1))),
        Topology::Punch => net.behind_nat(
            private,
            NatKind::PortRestrictedCone,
            ip(&format!("203.0.113.{}", who + 1)),
        ),
        Topology::Relay => net.behind_nat(
            private,
            NatKind::Symmetric,
            ip(&format!("203.0.113.{}", who + 1)),
        ),
    }
}

/// One topology: set up, then `SAMPLES` cold connections.
pub async fn measure(topology: Topology, inject: Duration) -> Measured {
    let tmp = tempfile::tempdir().unwrap();
    let net = VirtualNet::new();
    let c_addr = addr("198.51.100.1:443");
    let c_sock = net.public(c_addr);
    let carol_signer =
        vox_core::node::headless::load_or_create_identity(&paths(&tmp, "anchor")).unwrap();
    let carol_fp = RootSigner::public_key(&carol_signer).fingerprint();
    let _carol = Node::spawn_config(
        paths(&tmp, "anchor"),
        NodeConfig::new()
            .bind(Bind::Socket(c_sock))
            .headless(carol_signer),
    )
    .unwrap();
    let mut anchors = BootstrapSet::new();
    anchors
        .add(
            BootstrapNode::new(
                carol_fp,
                EndpointList::new(vec![Multiaddr::from(c_addr)]).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

    let alice = node(&tmp, "alice", host(&net, topology, 0), anchors.clone()).await;
    let mut bob = node(&tmp, "bob", host(&net, topology, 1), anchors.clone()).await;
    let alice_fp = alice.view().identity.unwrap().fingerprint;
    let bob_fp = bob.view().identity.unwrap().fingerprint;

    assert!(alice
        .apply(NodeCommand::CreateChannel {
            local_name: "room".into(),
            passphrase: secret("room passphrase"),
        })
        .await
        .is_done());
    let cid = wait_for(&alice, |e| match e {
        NodeEvent::ChannelOpened { channel_id } => Some(channel_id),
        _ => None,
    })
    .await;
    assert!(alice
        .apply(NodeCommand::Invite { channel_id: cid })
        .await
        .is_done());
    let url = wait_for(&alice, |e| match e {
        NodeEvent::InviteLink { url, .. } => Some(url),
        _ => None,
    })
    .await;
    let out = bob
        .apply(NodeCommand::JoinChannel {
            link: url,
            local_name: "room".into(),
            passphrase: secret("room passphrase"),
        })
        .await;
    assert!(
        out.is_done(),
        "CANNOT MEASURE ({topology:?}): bob's join failed: {out:?}"
    );
    for (who, peer, name) in [(&alice, bob_fp, "bob"), (&bob, alice_fp, "alice")] {
        assert!(who
            .apply(NodeCommand::Trust {
                fingerprint: peer,
                petname: name.into(),
            })
            .await
            .is_done());
    }
    for (who, peer) in [(&alice, bob_fp), (&bob, alice_fp)] {
        wait_for(who, |e| match e {
            NodeEvent::SenderKeyReceived { peer: p, .. } if p == peer => Some(()),
            _ => None,
        })
        .await;
    }

    let mut samples = Vec::new();
    let mut relayed = 0usize;
    let mut direct_samples = Vec::new();
    let mut censored = 0usize;
    let mut retried = 0usize;
    let mut unreached = 0usize;
    for i in 0..SAMPLES {
        // Cold: the old node is gone, and the new one is somewhere new.
        let _ = bob.apply(NodeCommand::Shutdown).await;
        drop(bob);
        // Cold on alice's side too: wait until she no longer holds a connection to the old
        // node, so the new one is not measured against a stale path she still believes in.
        // Measured, she lets go about 6.5 s after it stops. A new node started before that
        // could not reach her at all — 60 s, every rung, and still unreachable even once
        // she had let go — so the wait comes BEFORE the new node exists. (That is a
        // finding in its own right, recorded in the report rather than measured here.)
        let gone = Instant::now();
        let dropped = tokio::time::timeout(Duration::from_secs(60), async {
            while alice.view().connected > 1 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        if i == 0 {
            eprintln!(
                "[{topology:?}] alice let go of bob's old node after {:?}{}",
                gone.elapsed(),
                if dropped.is_ok() {
                    ""
                } else {
                    " (still held at 60 s)"
                }
            );
        }

        let who = u8::try_from(i + 2).unwrap();
        // The old node's store must let go of the profile before a new node can open it
        // (redb is single-writer). `Shutdown` answering does not mean every task holding the
        // store has ended — measured, a relayed node sometimes still held it — so the new
        // node is retried until the profile is free. Outside the clock, like the Argon2id.
        let socket = host(&net, topology, who);
        let freed = Instant::now();
        bob = loop {
            let mut cfg = NodeConfig::new()
                .bind(Bind::Socket(Arc::clone(&socket) as _))
                .anchors(anchors.clone());
            cfg.pow_params = Some(PowParams { n: 48, k: 5 });
            match Node::spawn_config(paths(&tmp, "bob"), cfg) {
                Ok(h) => break h,
                Err(e) => {
                    assert!(
                        freed.elapsed() < Duration::from_secs(60),
                        "sample {i}: bob's profile was still held 60 s after shutdown: {e}"
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        };
        let out = bob
            .apply(NodeCommand::Unlock {
                passphrase: secret("identity passphrase"),
            })
            .await;
        assert!(out.is_done(), "sample {i}: bob could not unlock: {out:?}");
        let out = bob
            .apply(NodeCommand::OpenChannel {
                channel_id: cid,
                passphrase: secret("room passphrase"),
            })
            .await;
        assert!(
            out.is_done(),
            "sample {i}: bob could not open the room: {out:?}"
        );
        // The first connection is made on demand, by the first thing that needs the peer —
        // measured by hand, a node that has just come up does not dial its room's members
        // by itself (60 s, connected to the anchor only). `Forward` is that first thing for
        // `vox forward` and `vox up`: it runs the ADR-012 ladder to the host and answers
        // once there is a path, which is exactly the wait R42 bounds.
        let t0 = Instant::now();
        tokio::time::sleep(inject).await;
        // Retried the way `vox forward` retries it (`tunnel_cli::forward`: every 500 ms until
        // the host is reachable), so the clock is what a person running it waits for.
        let mut attempts = 0u32;
        let mut last = None;
        let answered = tokio::time::timeout(GIVE_UP, async {
            loop {
                attempts += 1;
                let out = bob
                    .apply(NodeCommand::Forward {
                        channel_id: cid,
                        host: alice_fp,
                        service_tag: "r42".into(),
                        local: "127.0.0.1:0".parse().unwrap(),
                    })
                    .await;
                if out.is_done() {
                    return;
                }
                last = Some(out);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await;
        let elapsed = t0.elapsed();
        if answered.is_err() {
            // **Recorded, not aborted.** A cold node that finds no path at all is the worst
            // sample R42 can have, and aborting on it would hide how often it happens. It
            // counts at `GIVE_UP`, and what the node said about it is printed once so the
            // red names its cause.
            unreached += 1;
            samples.push(elapsed);
            direct_samples.push(elapsed);
            if unreached == 1 {
                while let Ok(Some(e)) =
                    tokio::time::timeout(Duration::from_millis(100), bob.next_event()).await
                {
                    if matches!(
                        e,
                        NodeEvent::PeerUnreachable { .. } | NodeEvent::StillRelayed { .. }
                    ) {
                        eprintln!("[{topology:?} sample {i}, bob said] {e:?}");
                    }
                }
                eprintln!(
                    "[{topology:?} sample {i}] no path in {elapsed:?} over {attempts} attempts; \
                     last {last:?}; bob connected={} relayed={:?}",
                    bob.view().connected,
                    bob.view().relayed_peers
                );
            }
            continue;
        }
        if attempts > 1 {
            retried += 1;
        }
        let via_relay = bob.view().relayed_peers.contains(&alice_fp);
        samples.push(elapsed);
        if via_relay {
            relayed += 1;
        }
        // Where a direct path exists, how long until the node is on it. Bounded at
        // `DIRECT_WAIT`: past that the sample is recorded as that bound, and it is red
        // either way, so waiting out a whole retry interval per sample buys nothing.
        if topology != Topology::Relay {
            let direct = tokio::time::timeout(DIRECT_WAIT, async {
                while bob.view().relayed_peers.contains(&alice_fp) {
                    tokio::time::sleep(POLL).await;
                }
            })
            .await;
            direct_samples.push(if direct.is_ok() {
                t0.elapsed()
            } else {
                censored += 1;
                DIRECT_WAIT + elapsed
            });
        }
    }
    for h in [&alice, &bob] {
        let _ = h.apply(NodeCommand::Shutdown).await;
    }
    Measured {
        any: samples,
        relayed,
        direct: direct_samples,
        censored,
        retried,
        unreached,
    }
}

pub struct Measured {
    /// Until the first request that needs the peer is answered, by any path.
    pub any: Vec<Duration>,
    /// How many of those answers came over a relay.
    pub relayed: usize,
    /// Until the node is on a direct path (open and punch only).
    pub direct: Vec<Duration>,
    /// Direct samples that were still relayed at `DIRECT_WAIT`.
    pub censored: usize,
    /// Samples whose first attempt was refused and had to be retried.
    pub retried: usize,
    /// Samples that found no path at all within `GIVE_UP`, counted at that bound.
    pub unreached: usize,
}

/// Run one topology's gate: measure, print, and assert the PRD target.
pub fn run(topology: Topology) {
    let target = env_ms("VOX_PERF_THRESHOLD_MS").unwrap_or(TARGET);
    let inject = env_ms("VOX_PERF_INJECT_MS").unwrap_or_default();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let mut failures = Vec::new();
    {
        eprintln!("uptime before {topology:?}: {}", uptime());
        let m = rt.block_on(measure(topology, inject));
        let (_, _, _, max) = stats(
            &format!(
                "R42 {topology:?}, any path (first request -> answered), {} of {SAMPLES} \
                 relayed, {} needed a retry, {} found no path in {GIVE_UP:?}",
                m.relayed, m.retried, m.unreached
            ),
            &m.any,
        );
        if topology == Topology::Relay {
            // The topology must be what it claims, or the number means something else.
            assert_eq!(
                m.relayed + m.unreached,
                SAMPLES,
                "every symmetric-NAT sample that found a path must have found a relayed one"
            );
        }
        let over = m.any.iter().filter(|d| **d >= target).count();
        if max >= target {
            failures.push(format!(
                "{topology:?}, any path: {over} of {SAMPLES} took {target:?} or longer ({} found \
                 no path at all in {GIVE_UP:?}), slowest {max:?}",
                m.unreached
            ));
        }
        // Where a direct path exists, R42 is about reaching IT: "including NAT traversal".
        // A first connection that is a relay circuit when a punch or a direct dial would
        // work has not traversed anything.
        if topology != Topology::Relay {
            let (_, _, _, dmax) = stats(
                &format!(
                    "R42 {topology:?}, direct path (first request -> on a direct path), {} \
                     still relayed at {DIRECT_WAIT:?}",
                    m.censored
                ),
                &m.direct,
            );
            let dover = m.direct.iter().filter(|d| **d >= target).count();
            if dmax >= target {
                failures.push(format!(
                    "{topology:?}, direct path: {dover} of {SAMPLES} took {target:?} or longer \
                     ({} still relayed at {DIRECT_WAIT:?}), slowest {dmax:?}",
                    m.censored
                ));
            }
        }
    }
    eprintln!("uptime at end: {}", uptime());
    assert!(
        failures.is_empty(),
        "R42: a first connection must complete in under {target:?}:\n{}",
        failures.join("\n")
    );
}
