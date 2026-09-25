//! PRD-001 R28 / ADR-013 §"The family LAN" — **a room as a LAN**, proved without root:
//! four real networked nodes in one room, each running the LAN engine on a
//! [`vox_core::lan::ChannelTun`] — the interface with the kernel replaced by a pair of
//! channels this test holds. What the test writes into a channel is a packet the operating
//! system sent out of the interface; what it reads out is what the LAN delivered to the
//! operating system. Everything between — the address plan, the routing, the app gate, the
//! datagram flows, the flood fan-out and its caps — is the product's.
//!
//! The scene: alice made the room; bob, dave and carol joined. alice, bob and dave trust
//! each other. **Nobody trusts carol**, and carol trusts all three — the eager outsider,
//! who dials everyone.
//!
//! What must hold, each counted:
//!
//! 1. **One plan.** All four nodes compute the same addresses: four distinct IPv4 hosts in
//!    one /24 of `100.64.0.0/10`, four IPv6 addresses in one `fd…/64`.
//! 2. **Links follow the gate.** alice, bob and dave each link to the other two; carol
//!    links to nobody, though she tried — alice's app layer counts her refusals.
//! 3. **Unicast reaches the member holding the address, unchanged** — UDP over IPv4 and
//!    IPv6, a TCP segment, an ICMP echo, 1280-byte packets — and no member receives a
//!    packet addressed to another.
//! 4. **Floods reach every trusted member and nobody else**: mDNS `224.0.0.251`, SSDP
//!    `239.255.255.250`, the subnet broadcast and the limited broadcast. The subnet
//!    broadcast arrives as a limited broadcast with both checksums right.
//! 5. **The untrusted member gets nothing and gives nothing**: nothing carol's system sends
//!    reaches anyone, and nothing anyone sends reaches carol.
//! 6. **A member cannot speak as another**: bob's system sending as dave's address is
//!    dropped at alice.
//! 7. **Floods are capped**: 1000 mDNS packets at once deliver at most the burst plus the
//!    rate, and the rest are counted as capped.
//! 8. **Withdrawing trust ends the link**: once alice untrusts bob, nothing crosses between
//!    them, while dave still hears alice.
//!
//! And what the shipped binary can show without root: `vox lan up` with no helper refuses
//! before touching the profile and names the command that starts one; the helper without
//! root refuses and listens nowhere; neither creates an interface. The rest of the binary's
//! path — a real `utun`, `ping`, mDNS, broadcast — needs root, and is
//! `scripts/family-lan-proof.sh`, which the decider runs.
//!
//! ## Why the scene is `#[ignore]`d
//! Production Argon2id on four profiles and a real proof of work per join. CI runs it in
//! release.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vox_core::hash::Digest32;
use vox_core::lan::packet::{ipv4_header_ok, ipv4_udp_ok, parse};
use vox_core::lan::plan::LanPlan;
use vox_core::lan::{channel_tun, ChannelTun, Lan, FLOOD_BURST, FLOOD_RATE};
use vox_core::node::actor::{Node, NodeHandle};
use vox_core::node::api::{NodeCommand, NodeEvent, Secret};
use vox_core::node::paths::Paths;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const TIMEOUT: Duration = Duration::from_secs(120);

fn secret(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

// ---- packets, built the way a kernel would ----

fn fold(mut s: u32) -> u16 {
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    s as u16
}

fn sum16(data: &[u8]) -> u32 {
    data.chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], c.get(1).copied().unwrap_or(0)])))
        .sum()
}

fn ip4(proto: u8, src: Ipv4Addr, dst: Ipv4Addr, body: &[u8]) -> Vec<u8> {
    let total = 20 + body.len();
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = proto;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let hc = !fold(sum16(&p));
    p[10..12].copy_from_slice(&hc.to_be_bytes());
    p.extend_from_slice(body);
    p
}

fn udp_body(pseudo: &[u8], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut u = Vec::with_capacity(len);
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&(len as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(payload);
    let mut c = !fold(sum16(pseudo) + sum16(&u));
    if c == 0 {
        c = 0xffff;
    }
    u[6..8].copy_from_slice(&c.to_be_bytes());
    u
}

fn udp4(src: Ipv4Addr, dst: Ipv4Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    ip4(17, src, dst, &udp_body(&pseudo, 40_000, dport, payload))
}

fn udp6(src: Ipv6Addr, dst: Ipv6Addr, dport: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(len as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    let u = udp_body(&pseudo, 40_000, dport, payload);
    let mut p = vec![0u8; 40];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&(len as u16).to_be_bytes());
    p[6] = 17;
    p[7] = 64;
    p[8..24].copy_from_slice(&src.octets());
    p[24..40].copy_from_slice(&dst.octets());
    p.extend_from_slice(&u);
    p
}

/// The packet's payload tag: the bytes after the IP and transport headers that this test
/// wrote there, which is how a delivered packet is matched to the one that was sent.
fn tag_of(p: &[u8]) -> String {
    let at = p
        .windows(4)
        .position(|w| w == b"TAG:")
        .map_or(p.len(), |i| i);
    let end = p[at..]
        .iter()
        .position(|b| *b == b'|')
        .map_or(p.len(), |i| at + i);
    String::from_utf8_lossy(&p[at..end]).into_owned()
}

/// A payload carrying `tag`, padded with a pattern to `len` bytes.
fn payload(tag: &str, len: usize) -> Vec<u8> {
    let mut v = format!("TAG:{tag}|").into_bytes();
    let mut i = 0u8;
    while v.len() < len {
        v.push(i);
        i = i.wrapping_add(7);
    }
    v
}

// ---- the scene ----

struct Member {
    name: &'static str,
    node: NodeHandle,
    id: Digest32,
}

async fn member(tmp: &tempfile::TempDir, name: &'static str) -> Member {
    let data = tmp.path().join(name).join("data");
    let cfg = tmp.path().join(name).join("cfg");
    let paths = Paths::resolve("default", Some(&data), Some(&cfg)).unwrap();
    let node = Node::spawn_networked(paths, "127.0.0.1:0".parse().unwrap()).unwrap();
    assert!(node
        .apply(NodeCommand::CreateIdentity {
            passphrase: secret("identity passphrase"),
        })
        .await
        .is_done());
    let id = node.view().identity.unwrap().fingerprint;
    Member { name, node, id }
}

async fn wait_for<T>(h: &NodeHandle, mut f: impl FnMut(NodeEvent) -> Option<T>) -> T {
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
    .expect("timed out waiting for an event")
}

async fn trust(who: &Member, peer: &Member) {
    assert!(who
        .node
        .apply(NodeCommand::Trust {
            fingerprint: peer.id,
            petname: peer.name.into(),
        })
        .await
        .is_done());
}

/// Poll `f` until it is true, up to [`TIMEOUT`]; panic with `what` if it never is.
async fn until(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + TIMEOUT;
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// One member's LAN and everything its "operating system" received.
struct Host {
    m: Member,
    lan: Lan<ChannelTun>,
    send: tokio::sync::mpsc::Sender<Vec<u8>>,
    got: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Host {
    fn got(&self) -> Vec<Vec<u8>> {
        self.got.lock().unwrap().clone()
    }

    fn v4(&self) -> Ipv4Addr {
        self.lan.plan().of(&self.m.id).unwrap().v4.unwrap()
    }

    fn v6(&self) -> Ipv6Addr {
        self.lan.plan().of(&self.m.id).unwrap().v6
    }

    fn links(&self) -> BTreeSet<Digest32> {
        self.lan.stats().links.into_iter().collect()
    }

    /// Packets delivered here whose tag starts with `prefix`.
    fn tagged(&self, prefix: &str) -> Vec<Vec<u8>> {
        self.got()
            .into_iter()
            .filter(|p| tag_of(p).starts_with(&format!("TAG:{prefix}")))
            .collect()
    }

    async fn emit(&self, p: Vec<u8>) {
        self.send.send(p).await.unwrap();
    }
}

fn host(m: Member, room: [u8; 32]) -> Host {
    let (tun, mut os) = channel_tun(4096);
    let lan = Lan::start(&m.node, room, tun).unwrap();
    let got = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&got);
    tokio::spawn(async move {
        while let Some(p) = os.recv.recv().await {
            sink.lock().unwrap().push(p);
        }
    });
    Host {
        m,
        lan,
        send: os.send,
        got,
    }
}

/// Wait long enough for anything in flight on loopback to land.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(1500)).await;
}

#[test]
#[ignore = "four real nodes with production Argon2id; CI runs it in release"]
fn a_room_is_a_lan_for_its_trusted_members_and_nobody_else() {
    watchdog::arm();
    let rt = rt();
    let tmp = tempfile::tempdir().unwrap();
    rt.block_on(async {
        let alice = member(&tmp, "alice").await;
        let bob = member(&tmp, "bob").await;
        let dave = member(&tmp, "dave").await;
        let carol = member(&tmp, "carol").await;
        assert!(alice
            .node
            .apply(NodeCommand::CreateChannel {
                local_name: "family".into(),
                passphrase: secret("room passphrase"),
            })
            .await
            .is_done());
        let room = alice.node.view().channels[0].channel_id;
        assert!(alice
            .node
            .apply(NodeCommand::Invite { channel_id: room })
            .await
            .is_done());
        let url = wait_for(&alice.node, |e| match e {
            NodeEvent::InviteLink { channel_id, url } if channel_id == room => Some(url),
            _ => None,
        })
        .await;
        for j in [&bob, &dave, &carol] {
            assert!(j
                .node
                .apply(NodeCommand::JoinChannel {
                    link: url.clone(),
                    local_name: "family".into(),
                    passphrase: secret("room passphrase"),
                })
                .await
                .is_done());
        }
        for m in [&alice, &bob, &dave, &carol] {
            let node = m.node.clone();
            until(&format!("{} to see four members", m.name), move || {
                node.view()
                    .open_channels
                    .iter()
                    .find(|c| c.channel_id == room)
                    .is_some_and(|c| c.members.len() == 4)
            })
            .await;
        }
        for (a, b) in [(&alice, &bob), (&alice, &dave), (&bob, &dave)] {
            trust(a, b).await;
            trust(b, a).await;
        }
        for peer in [&alice, &bob, &dave] {
            trust(&carol, peer).await;
        }
        let ids = [alice.id, bob.id, dave.id, carol.id];
        let (a, b, d, c) = (
            host(alice, room),
            host(bob, room),
            host(dave, room),
            host(carol, room),
        );

        // ---- 1. one plan ----
        let expected = LanPlan::new(room, &ids);
        for h in [&a, &b, &d, &c] {
            assert_eq!(h.lan.plan(), expected, "{}'s plan differs", h.m.name);
        }
        let v4s: BTreeSet<Ipv4Addr> = [&a, &b, &d, &c].iter().map(|h| h.v4()).collect();
        let v6s: BTreeSet<Ipv6Addr> = [&a, &b, &d, &c].iter().map(|h| h.v6()).collect();
        let net = expected.subnet_v4.octets();
        eprintln!(
            "[plan] /24 {}  /64 {}  v4 {:?}  v6 {:?}",
            expected.subnet_v4, expected.prefix_v6, v4s, v6s
        );
        assert_eq!((v4s.len(), v6s.len()), (4, 4), "four distinct addresses each");
        assert!(net[0] == 100 && (64..128).contains(&net[1]) && net[3] == 0);
        assert!(v4s.iter().all(|v| v.octets()[..3] == net[..3]
            && (1..=254).contains(&v.octets()[3])));
        assert!(v6s
            .iter()
            .all(|v| v.octets()[..8] == expected.prefix_v6.octets()[..8]
                && v.octets()[0] == 0xfd));

        // ---- 2. links follow the gate ----
        let want = |x: &[Digest32]| x.iter().copied().collect::<BTreeSet<_>>();
        until("the three trusted members to link to each other", || {
            a.links() == want(&[b.m.id, d.m.id])
                && b.links() == want(&[a.m.id, d.m.id])
                && d.links() == want(&[a.m.id, b.m.id])
        })
        .await;
        // carol dials everyone she trusts, and alice's app layer refuses her as untrusted:
        // the escalation is attempted, not merely absent.
        let alice_hub = Arc::clone(a.m.node.app());
        // Waiting for either outcome, so an open gate fails below on what carol got —
        // a link — rather than on a counter that never moved.
        until("carol's open to be answered by alice", || {
            alice_hub.stats().refused_untrusted >= 1 || !c.links().is_empty()
        })
        .await;
        assert!(c.links().is_empty(), "carol linked to {:?}", c.links());
        eprintln!(
            "[links] alice {} bob {} dave {} carol {}; alice refused carol {}x",
            a.links().len(),
            b.links().len(),
            d.links().len(),
            c.links().len(),
            alice_hub.stats().refused_untrusted
        );
        assert!(c.links().is_empty(), "carol linked to {:?}", c.links());

        // ---- 3. unicast reaches the member holding the address, unchanged ----
        let mut sent: Vec<(String, Vec<u8>, &'static str)> = Vec::new();
        for i in 0..50 {
            for (to, v4, v6, name) in [(&b, b.v4(), b.v6(), "bob"), (&d, d.v4(), d.v6(), "dave")] {
                let _ = to;
                let len = if i % 10 == 0 { 1280 - 28 } else { 64 };
                let p4 = udp4(a.v4(), v4, 5000, &payload(&format!("uni/{name}/v4/{i}"), len));
                let p6 = udp6(a.v6(), v6, 5000, &payload(&format!("uni/{name}/v6/{i}"), 64));
                sent.push((tag_of(&p4), p4.clone(), name));
                sent.push((tag_of(&p6), p6.clone(), name));
                a.emit(p4).await;
                a.emit(p6).await;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let tcp = ip4(6, a.v4(), b.v4(), &payload("uni/bob/tcp/0", 60));
        let icmp = ip4(1, a.v4(), b.v4(), &payload("uni/bob/icmp/0", 60));
        sent.push((tag_of(&tcp), tcp.clone(), "bob"));
        sent.push((tag_of(&icmp), icmp.clone(), "bob"));
        a.emit(tcp).await;
        a.emit(icmp).await;
        settle().await;
        let (mut right, mut altered, mut misdelivered) = (0usize, 0usize, 0usize);
        for (h, name) in [(&b, "bob"), (&d, "dave"), (&c, "carol")] {
            for p in h.tagged("uni/") {
                match sent.iter().find(|(t, _, _)| *t == tag_of(&p)) {
                    Some((_, orig, to)) if *to == name => {
                        if *orig == p {
                            right += 1;
                        } else {
                            altered += 1;
                        }
                    }
                    _ => misdelivered += 1,
                }
            }
        }
        eprintln!(
            "[unicast] sent {} | arrived at the right member unchanged {right}, altered {altered}, \
             at the wrong member {misdelivered}",
            sent.len()
        );
        assert_eq!((altered, misdelivered), (0, 0));
        assert!(
            right * 100 >= sent.len() * 95,
            "only {right} of {} unicast packets arrived",
            sent.len()
        );
        for kind in ["uni/bob/tcp/0", "uni/bob/icmp/0"] {
            assert_eq!(b.tagged(kind).len(), 1, "{kind} did not reach bob");
        }

        // ---- 4. floods reach every trusted member and nobody else ----
        let groups: [(&str, Ipv4Addr, u16); 4] = [
            ("mdns", Ipv4Addr::new(224, 0, 0, 251), 5353),
            ("ssdp", Ipv4Addr::new(239, 255, 255, 250), 1900),
            ("subnet", expected.broadcast_v4(), 9999),
            ("limited", Ipv4Addr::BROADCAST, 9999),
        ];
        for i in 0..10 {
            for (kind, dst, port) in groups {
                a.emit(udp4(a.v4(), dst, port, &payload(&format!("flood/{kind}/{i}"), 80)))
                    .await;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        settle().await;
        for (kind, _, _) in groups {
            let (at_b, at_d, at_c) = (
                b.tagged(&format!("flood/{kind}/")).len(),
                d.tagged(&format!("flood/{kind}/")).len(),
                c.tagged(&format!("flood/{kind}/")).len(),
            );
            eprintln!("[flood] {kind}: 10 sent -> bob {at_b}, dave {at_d}, carol {at_c}");
            assert!(at_b >= 9 && at_d >= 9, "{kind} did not reach both trusted members");
            assert_eq!(at_c, 0, "{kind} reached carol");
        }
        let subnet = b.tagged("flood/subnet/");
        let rewritten = subnet
            .iter()
            .filter(|p| {
                parse(p).is_some_and(|h| h.dst == IpAddr::V4(Ipv4Addr::BROADCAST))
                    && ipv4_header_ok(p)
                    && ipv4_udp_ok(p) == Some(true)
            })
            .count();
        eprintln!(
            "[flood] subnet broadcasts at bob as 255.255.255.255 with both checksums right: \
             {rewritten} of {}",
            subnet.len()
        );
        assert_eq!(rewritten, subnet.len());

        // ---- 5. the untrusted member gets nothing and gives nothing ----
        let carol_before = c.lan.stats();
        for i in 0..20 {
            c.emit(udp4(c.v4(), a.v4(), 5000, &payload(&format!("carol/uni/{i}"), 64)))
                .await;
            c.emit(udp4(c.v4(), b.v4(), 5000, &payload(&format!("carol/uni/{i}"), 64)))
                .await;
            c.emit(udp4(
                c.v4(),
                Ipv4Addr::new(224, 0, 0, 251),
                5353,
                &payload(&format!("carol/mdns/{i}"), 64),
            ))
            .await;
        }
        settle().await;
        let from_carol: usize = [&a, &b, &d]
            .iter()
            .map(|h| {
                h.got()
                    .iter()
                    .filter(|p| parse(p).is_some_and(|x| x.src == IpAddr::V4(c.v4())))
                    .count()
            })
            .sum();
        let carol_got = c.got().len();
        let cs = c.lan.stats();
        eprintln!(
            "[untrusted] carol sent 60 -> delivered anywhere {from_carol}; carol's LAN: \
             no_route +{}, floods +{} with {} copies; carol received {carol_got} packets in all",
            cs.no_route - carol_before.no_route,
            cs.floods - carol_before.floods,
            cs.flood_copies
        );
        assert_eq!(from_carol, 0);
        assert_eq!(carol_got, 0);
        assert_eq!(cs.flood_copies, 0);
        assert_eq!(cs.no_route - carol_before.no_route, 40);

        // ---- 6. a member cannot speak as another ----
        let spoofed_before = a.lan.stats().spoofed;
        b.emit(udp4(d.v4(), a.v4(), 5000, &payload("spoof/as-dave", 64)))
            .await;
        b.emit(udp6(d.v6(), a.v6(), 5000, &payload("spoof/as-dave-v6", 64)))
            .await;
        settle().await;
        let spoofed = a.lan.stats().spoofed - spoofed_before;
        let landed = a.tagged("spoof/").len();
        eprintln!("[spoof] bob sent 2 as dave -> alice dropped {spoofed} as spoofed, delivered {landed}");
        assert_eq!((spoofed, landed), (2, 0));

        // ---- 7. floods are capped ----
        tokio::time::sleep(Duration::from_millis((FLOOD_BURST / FLOOD_RATE * 1000.0) as u64 + 500))
            .await;
        let capped_before = a.lan.stats().rate_capped;
        let t0 = Instant::now();
        for i in 0..1000 {
            a.emit(udp4(
                a.v4(),
                Ipv4Addr::new(224, 0, 0, 251),
                5353,
                &payload(&format!("storm/{i}"), 64),
            ))
            .await;
        }
        let elapsed = t0.elapsed().as_secs_f64();
        settle().await;
        let at_b = b.tagged("storm/").len();
        let capped = a.lan.stats().rate_capped - capped_before;
        let bound = FLOOD_BURST + FLOOD_RATE * elapsed + 1.0;
        eprintln!(
            "[cap] 1000 floods in {elapsed:.3}s -> bob got {at_b} (bound {bound:.0}), capped at alice {capped}"
        );
        assert!((at_b as f64) <= bound, "bob got {at_b}, over the bound {bound:.0}");
        assert!(at_b >= 150, "the burst itself did not arrive: {at_b}");
        assert!(capped as f64 >= 1000.0 - bound);

        // ---- 8. withdrawing trust ends the link ----
        assert!(a
            .m
            .node
            .apply(NodeCommand::Untrust {
                fingerprint: b.m.id,
            })
            .await
            .is_done());
        until("alice and bob to lose their link", || {
            !a.links().contains(&b.m.id) && !b.links().contains(&a.m.id)
        })
        .await;
        for i in 0..20 {
            b.emit(udp4(b.v4(), a.v4(), 5000, &payload(&format!("after/uni/{i}"), 64)))
                .await;
            a.emit(udp4(
                a.v4(),
                Ipv4Addr::new(224, 0, 0, 251),
                5353,
                &payload(&format!("after/mdns/{i}"), 64),
            ))
            .await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        settle().await;
        let (at_a, at_b, at_d) = (
            a.tagged("after/uni/").len(),
            b.tagged("after/mdns/").len(),
            d.tagged("after/mdns/").len(),
        );
        eprintln!("[withdrawn] bob->alice {at_a}/20, alice's floods at bob {at_b}/20, at dave {at_d}/20");
        assert_eq!((at_a, at_b), (0, 0));
        assert!(at_d >= 18, "dave stopped hearing alice: {at_d}");
    });
}

fn interfaces() -> String {
    String::from_utf8(
        Command::new("/sbin/ifconfig")
            .arg("-l")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
}

/// With no helper running, `vox lan up` refuses before it touches the profile, names the
/// command that starts the helper, and creates no interface.
#[test]
#[cfg(target_os = "macos")]
fn lan_up_without_a_helper_refuses_and_creates_nothing() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("no-helper.sock");
    let before = interfaces();
    let out = Command::new(VOX)
        .args(["lan", "up", "family", "--helper-socket"])
        .arg(&socket)
        .env("VOX_DATA_DIR", tmp.path().join("data"))
        .env("VOX_CONFIG_DIR", tmp.path().join("cfg"))
        .output()
        .unwrap();
    let after = interfaces();
    let err = String::from_utf8_lossy(&out.stderr);
    eprintln!("[vox lan up] exit {:?}: {err}", out.status.code());
    assert!(!out.status.success());
    assert!(
        err.contains("sudo vox lan helper --socket"),
        "it did not say how to start the helper: {err}"
    );
    assert_eq!(before, after, "an interface appeared or went away");
    assert!(
        !tmp.path().join("data").exists() && !tmp.path().join("cfg").exists(),
        "it touched the profile before refusing"
    );
}

/// The helper, run without root, refuses and leaves no socket behind — it is the one
/// piece that needs root, and says so.
#[test]
#[cfg(target_os = "macos")]
fn the_helper_without_root_refuses_and_listens_nowhere() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("helper.sock");
    let before = interfaces();
    let out = Command::new(VOX)
        .args(["lan", "helper", "--socket"])
        .arg(&socket)
        .env("VOX_DATA_DIR", tmp.path().join("data"))
        .env("VOX_CONFIG_DIR", tmp.path().join("cfg"))
        .env("SUDO_UID", "501")
        .env("SUDO_GID", "20")
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    eprintln!("[vox lan helper] exit {:?}: {err}", out.status.code());
    assert!(!out.status.success());
    assert!(err.contains("sudo vox lan helper"), "{err}");
    assert!(!socket.exists(), "it listened anyway");
    assert_eq!(before, interfaces());
}
