//! V210-70 — **a stranger cannot get a real room evicted from an open anchor by putting the
//! room's own records there itself**, with every node under test running as the shipped binary.
//!
//! A full anchor board gives up a room from the source credited with the most rooms
//! (`nat::store::Source`: the network a peer published from). A room's genesis and its members'
//! records are served to anyone who asks. c4 credited a room to whichever network brought any
//! record the board took for it, so a stranger who knew a room's channel ID (it is in every link
//! and `.vox` name) could fetch the room's records and put them back from its own network: the
//! room was then filed with the stranger's own rooms, where the next flood evicted it, and a real
//! `vox room join` failed in about 60 ms (verifier-261b, 2/2, on the shipped binary). The same
//! went for a board that did not hold the room yet: the stranger brought it there first.
//!
//! A room is now credited to a source only by a record **the peer that brought it wrote** (its
//! creator's genesis, a member's own address or bundle record), and only when the board **stored**
//! it: a re-send of a record it holds stores nothing.
//!
//! **Staging.** Every anchor is a default `vox node` (it serves any room published to it),
//! listening dual-stack on `[::]`. The victim `vox daemon` and the joiner are on `127.0.0.1`. The
//! stranger — a test-side client, because no `vox` command publishes a genesis for a room it holds
//! no state for, or puts another peer's records — has two networks on this one machine, without
//! sudo: `[::1]` (the IPv6 /48 `0000:0000:0000`) and `[fe80::1%lo0]` (the /48 `fe80:0000:0000`).
//! Its flood is 4100 rooms; each genesis is put from `[::1]` by the identity that minted it, and a
//! second identity of the stranger's, witnessed into the room by the first, puts its own bundle
//! for it from `[fe80::1]`. So every flood room is credited to both of the stranger's networks,
//! honestly — both records are written by the peer that brings them.
//!
//! **Asserted.**
//! 1. *A re-send* (verifier-261b's attack): the anchor holds the victim's room in use, with its
//!    member and bundle records. The stranger fetches those records and puts them back, unchanged,
//!    from `[::1]` (the board must take them, or `CANNOT MEASURE`), then floods. The anchor takes at
//!    least 4095 of each kind (fewer is `CANNOT MEASURE`: its board was never full). **It still
//!    serves the room in use, and a real `vox room join` of it succeeds.**
//! 2. *Brought first:* a second anchor, B, has never seen the room. The stranger fetches the room's
//!    genesis and records from the victim's anchor and puts them on B from `[::1]` before anyone
//!    else does (B must take all of them, or `CANNOT MEASURE`), then floods B. **B still serves the
//!    room, and a real joiner whose only anchor is B joins it through B**, from a link naming only B.
//!
//! **Mutations that must turn it red.** In `nat::service`'s `put`:
//! - credit on any admission, from anyone (c4's rule): red on (1) and on (2);
//! - credit a re-send of a held record (`Taken::Held`) to whoever sent it: red on (1);
//! - credit a stored record whoever brought it (drop the "wrote it" test for member records): red on
//!   (2);
//! - credit a genesis to whoever first brings it: red on (2).

#![cfg(unix)]

#[path = "support/hostile.rs"]
mod hostile;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hostile::{create_room, daemon, fingerprint, free_port, profile_dir, stranger, vox_in, Rt};
use vox_core::governance::genesis::{ChannelPolicy, DeniabilityMode, Genesis, HistoryMode};
use vox_core::hash::Digest32;
use vox_core::identity::composite::{RootSigner, SoftwareRootSigner};
use vox_core::nat::record::{Admission, JoinWitness, MemberBundleRecord};
use vox_core::nat::service::{RecordKinds, RendezvousClient};
use vox_core::node::link::{parse_anchor_spec, InviteLink};
use vox_core::node::prekeys::PrekeyRing;
use vox_core::transport::quic::{VoxConnection, VoxEndpoint};
use world::{args, VoxProc, IDENTITY};

const ROOM_PASS: &str = "room passphrase";
/// Stranger rooms: more than the 4096 a board holds from peers.
const ROOMS: usize = 4100;
/// The board is full once the stranger holds this many rooms on it: 4096, less the real room.
const FULL: usize = 4095;
const JOIN_BOUND: Duration = Duration::from_secs(120);
/// How long the victim's room may take to reach its anchor with its records.
const PUBLISH_PATIENCE: Duration = Duration::from_secs(60);
/// The whole binary's time bound: the default, or longer in a debug build, where the anchor
/// verifies 8200 post-quantum records unoptimised.
const BUDGET: Duration = if cfg!(debug_assertions) {
    Duration::from_secs(1500)
} else {
    Duration::from_secs(600)
};

fn policy() -> ChannelPolicy {
    ChannelPolicy {
        history_mode: HistoryMode::ForwardOnly,
        deniability_mode: DeniabilityMode::Attributable,
        ttl: 0,
        min_suite: vox_core::suite::SuiteFloor::DAY_ONE.id(),
    }
}

/// Start `vox node` dual-stack on `[::]:port`; returns it with its IPv4 spec and fingerprint.
fn dual_anchor(name: &str, data: &Path, port: u16) -> (VoxProc, String, Digest32) {
    let mut p = VoxProc::spawn_env(
        name,
        data,
        &args(&["node", "--listen", &format!("[::]:{port}")]),
        &[],
    );
    let spec = p
        .expect_line("an --anchor spec", |l| {
            !l.starts_with("! ")
                && l.trim_start().contains('@')
                && l.trim_start().starts_with(|c: char| c.is_alphanumeric())
        })
        .trim()
        .to_owned();
    let fp = spec.split('@').next().expect("fp@addr").to_owned();
    let id = vox_core::node::link::b32_decode(&fp, "anchor fingerprint").expect("fingerprint");
    (p, format!("{fp}@/ip4/127.0.0.1/udp/{port}"), id)
}

/// The scope id of `fe80::1` on `lo0`, the stranger's second network.
fn lo0_scope() -> u32 {
    let out = std::process::Command::new("ifconfig")
        .arg("lo0")
        .output()
        .expect("CANNOT MEASURE: ifconfig lo0");
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text
        .lines()
        .find(|l| l.contains("fe80::1%lo0"))
        .expect("CANNOT MEASURE: no fe80::1 on lo0, so the stranger has no second network");
    let hex = line
        .split("scopeid 0x")
        .nth(1)
        .expect("CANNOT MEASURE: fe80::1 has no scope id")
        .trim();
    u32::from_str_radix(hex, 16).expect("CANNOT MEASURE: a hex scope id")
}

/// The stranger's two networks, as seen by an anchor on `port`.
struct Networks {
    anchor6: SocketAddr,
    anchor_ll: SocketAddr,
    local6: SocketAddr,
    local_ll: SocketAddr,
}

impl Networks {
    fn to(port: u16) -> Self {
        let scope = lo0_scope();
        let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        Self {
            anchor6: format!("[::1]:{port}").parse().unwrap(),
            anchor_ll: SocketAddr::V6(SocketAddrV6::new(ll, port, 0, scope)),
            local6: "[::1]:0".parse().unwrap(),
            local_ll: SocketAddr::V6(SocketAddrV6::new(ll, 0, 0, scope)),
        }
    }
}

/// Connect as `signer` from `local` to the node at `addr`, pinned to `id`.
async fn connect_from(
    signer: &SoftwareRootSigner,
    local: SocketAddr,
    addr: SocketAddr,
    id: Digest32,
) -> (VoxEndpoint, Arc<VoxConnection>) {
    let endpoint = VoxEndpoint::bind(signer, local).unwrap();
    let conn = endpoint
        .connect(addr, id, hostile::now())
        .await
        .unwrap_or_else(|e| panic!("CANNOT MEASURE: connect {local} -> {addr}: {e:?}"));
    (endpoint, Arc::new(conn))
}

/// A room's records on a board, as wire records: (genesis, member records, bundle records).
type Held = (Option<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>);

/// Everything the board at `anchor` holds for `room`.
fn fetch(rt: &Rt, anchor: SocketAddr, id: Digest32, room: Digest32) -> Held {
    let reader = stranger(0x74);
    rt.block_on(async {
        let (_ep, conn) = hostile::connect(&reader, anchor, id).await;
        let mut client = RendezvousClient::open(&conn)
            .await
            .expect("CANNOT MEASURE: a rendezvous stream to the anchor");
        let set = client
            .get(
                &room,
                0,
                RecordKinds::GENESIS
                    .or(RecordKinds::MEMBERS)
                    .or(RecordKinds::BUNDLES),
            )
            .await
            .expect("CANNOT MEASURE: the anchor answered a GET");
        client.finish();
        (
            set.genesis.map(|g| g.to_wire()),
            set.members.iter().map(|m| m.to_wire()).collect(),
            set.bundles.iter().map(|b| b.to_wire()).collect(),
        )
    })
}

/// What the board at `anchor` holds for `room`: (genesis?, member records, bundle records).
fn board(rt: &Rt, anchor: SocketAddr, id: Digest32, room: Digest32) -> (bool, usize, usize) {
    let (g, m, b) = fetch(rt, anchor, id, room);
    (g.is_some(), m.len(), b.len())
}

/// Wait until the board at `anchor` holds `room`'s genesis, a member record and a bundle record.
fn await_published(rt: &Rt, anchor: SocketAddr, id: Digest32, room: Digest32) {
    let deadline = Instant::now() + PUBLISH_PATIENCE;
    let held = loop {
        let b = board(rt, anchor, id, room);
        if (b.0 && b.1 >= 1 && b.2 >= 1) || Instant::now() >= deadline {
            break b;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    println!("[proof] the victim's anchor holds of the room in use: {held:?}");
    assert!(
        held.0 && held.1 >= 1 && held.2 >= 1,
        "CANNOT MEASURE: the room in use never reached its anchor with its records ({held:?})"
    );
}

/// The stranger, at the anchor on `nets`: first puts `first` (records it did not write) from
/// `[::1]`, then floods `ROOMS` rooms, each genesis from `[::1]` and a witnessed second identity's
/// own bundle for it from `[fe80::1]`. Returns the board's answers to `first`, and how many
/// geneses and bundles it took.
fn flood(rt: &Rt, nets: &Networks, id: Digest32, first: &[Vec<u8>]) -> (Vec<String>, usize, usize) {
    let inventor = stranger(0x73);
    // A second identity for the second network: the anchor keeps one connection per peer.
    let carrier = stranger(0x75);
    let t = hostile::now();
    let ring = PrekeyRing::generate(&carrier, &[0x3E; 32], t).unwrap();
    let carrier_bundle = ring.bundle(&carrier.public_key()).unwrap();
    // Every room's genesis and bundle are signed up front, on every core: three post-quantum
    // signatures a room, 4100 times, would otherwise be most of a debug build's time budget.
    let t0 = Instant::now();
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get().min(8));
    let rooms: Vec<(Vec<u8>, Vec<u8>)> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|w| {
                let (inventor, carrier, bundle) = (&inventor, &carrier, &carrier_bundle);
                scope.spawn(move || {
                    (w..ROOMS)
                        .step_by(threads)
                        .map(|i| {
                            let mut nonce = [0u8; 16];
                            nonce[..8].copy_from_slice(&(i as u64).to_le_bytes());
                            nonce[8] = 0x5c;
                            let now = hostile::now();
                            let g =
                                Genesis::create_with_nonce(inventor, now, policy(), nonce).unwrap();
                            let cid = g.channel_id();
                            let witness =
                                JoinWitness::build(inventor, &cid, 0, &carrier.fingerprint(), now)
                                    .unwrap();
                            let rec = MemberBundleRecord::build(
                                carrier,
                                &cid,
                                0,
                                bundle.clone(),
                                1,
                                now,
                                2 * 60 * 60,
                                Admission::Witnessed(Box::new(witness)),
                            )
                            .unwrap();
                            (i, g.to_wire(), rec.to_wire())
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut all: Vec<_> = workers
            .into_iter()
            .flat_map(|w| w.join().unwrap())
            .collect();
        all.sort_by_key(|(i, _, _)| *i);
        all.into_iter().map(|(_, g, b)| (g, b)).collect()
    });
    println!(
        "[proof] the stranger signed {} rooms in {:?}",
        rooms.len(),
        t0.elapsed()
    );
    rt.block_on(async {
        let (_e1, c6) = connect_from(&inventor, nets.local6, nets.anchor6, id).await;
        let (_e2, cll) = connect_from(&carrier, nets.local_ll, nets.anchor_ll, id).await;
        let mut on6 = RendezvousClient::open(&c6)
            .await
            .expect("CANNOT MEASURE: a rendezvous stream from [::1]");
        let mut onll = RendezvousClient::open(&cll)
            .await
            .expect("CANNOT MEASURE: a rendezvous stream from [fe80::1]");
        let mut answers = Vec::new();
        for wire in first {
            answers.push(format!("{:?}", on6.put(wire).await));
        }
        let (mut geneses, mut bundles) = (0usize, 0usize);
        for (genesis, bundle) in &rooms {
            if on6.put(genesis).await.is_ok() {
                geneses += 1;
            }
            if onll.put(bundle).await.is_ok() {
                bundles += 1;
            }
        }
        on6.finish();
        onll.finish();
        (answers, geneses, bundles)
    })
}

fn assert_full(geneses: usize, bundles: usize) {
    assert!(
        geneses >= FULL && bundles >= FULL,
        "CANNOT MEASURE: the anchor's board was never full of the stranger's rooms ({geneses} \
         geneses, {bundles} bundles taken)"
    );
}

#[test]
#[ignore = "real vox processes with production Argon2id, a flood and a real join; run in release"]
fn a_stranger_resending_a_rooms_records_does_not_get_it_evicted() {
    watchdog::arm_for(BUDGET);
    let tmp = tempfile::tempdir().unwrap();
    let (anchor_dir, victim_dir, joiner_dir) = (
        profile_dir(tmp.path(), "anchor"),
        profile_dir(tmp.path(), "victim"),
        profile_dir(tmp.path(), "joiner"),
    );
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).unwrap();
    let port = free_port();
    let (_anchor, spec, anchor_id) = dual_anchor("anchor", &anchor_dir, port);
    let nets = Networks::to(port);
    fingerprint(&victim_dir);
    fingerprint(&joiner_dir);
    let _victim = daemon("victim", &victim_dir, free_port(), &spec, &pass_file);
    let (room, link) = create_room(&victim_dir, "first", ROOM_PASS);
    let rt = Rt::new();
    await_published(&rt, nets.anchor6, anchor_id, room);

    // The room's own records, as anyone can fetch them, put back unchanged from [::1].
    let (_, members, bundles) = fetch(&rt, nets.anchor6, anchor_id, room);
    let resend: Vec<Vec<u8>> = members.into_iter().chain(bundles).collect();
    let t0 = Instant::now();
    let (answers, geneses, taken) = flood(&rt, &nets, anchor_id, &resend);
    println!(
        "[proof] the stranger re-sent the room's {} record(s) from [::1]: {answers:?}; flood: \
         {geneses}/{ROOMS} geneses from [::1], {taken}/{ROOMS} bundles from [fe80::1], in {:?}",
        resend.len(),
        t0.elapsed()
    );
    assert!(
        answers.len() >= 2 && answers.iter().all(|a| a == "Ok(())"),
        "CANNOT MEASURE: the anchor did not take the re-sent records ({answers:?}), so a credit \
         for them cannot be measured"
    );
    assert_full(geneses, taken);
    let kept = board(&rt, nets.anchor6, anchor_id, room);
    println!("[proof] after the flood the anchor holds of the room in use: {kept:?}");
    assert!(
        kept.0,
        "a stranger re-sent a room's own records from its network and its flood then evicted the \
         room in use from the anchor ({kept:?}): the re-send credited the room to the stranger"
    );

    let _joiner = daemon("joiner", &joiner_dir, free_port(), &spec, &pass_file);
    let t0 = Instant::now();
    let (ok, out, err) = vox_in(
        &joiner_dir,
        &["room", "join", &link, "--name", "first"],
        ROOM_PASS,
    );
    let took = t0.elapsed();
    println!("[proof] real join of the room in use after the flood: ok={ok} in {took:?}");
    assert!(
        ok && took < JOIN_BOUND,
        "a real joiner could not join the room in use after a stranger re-sent its records and \
         flooded the anchor (ok={ok}, {took:?}, bound {JOIN_BOUND:?}): {out}{err}"
    );
}

#[test]
#[ignore = "real vox processes with production Argon2id, a flood and a real join; run in release"]
fn a_stranger_bringing_a_room_to_an_anchor_first_does_not_get_it_evicted() {
    watchdog::arm_for(BUDGET);
    let tmp = tempfile::tempdir().unwrap();
    let (anchor_dir, other_dir, victim_dir, joiner_dir) = (
        profile_dir(tmp.path(), "anchor"),
        profile_dir(tmp.path(), "other"),
        profile_dir(tmp.path(), "victim"),
        profile_dir(tmp.path(), "joiner"),
    );
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).unwrap();
    let port = free_port();
    let (_anchor, spec, anchor_id) = dual_anchor("anchor", &anchor_dir, port);
    let other_port = free_port();
    let (_other, other_spec, other_id) = dual_anchor("other", &other_dir, other_port);
    let nets = Networks::to(other_port);
    let anchor6: SocketAddr = format!("[::1]:{port}").parse().unwrap();
    fingerprint(&victim_dir);
    fingerprint(&joiner_dir);
    let _victim = daemon("victim", &victim_dir, free_port(), &spec, &pass_file);
    let (room, link) = create_room(&victim_dir, "first", ROOM_PASS);
    let rt = Rt::new();
    await_published(&rt, anchor6, anchor_id, room);
    let before = board(&rt, nets.anchor6, other_id, room);
    assert!(
        before == (false, 0, 0),
        "CANNOT MEASURE: anchor B already held the room before the stranger brought it ({before:?})"
    );

    // The room as anyone can fetch it from its own anchor, brought to B first, from [::1].
    let (genesis, members, bundles) = fetch(&rt, anchor6, anchor_id, room);
    let bring: Vec<Vec<u8>> = genesis.into_iter().chain(members).chain(bundles).collect();
    let t0 = Instant::now();
    let (answers, geneses, taken) = flood(&rt, &nets, other_id, &bring);
    println!(
        "[proof] the stranger brought the room to B from [::1] ({} record(s)): {answers:?}; flood: \
         {geneses}/{ROOMS} geneses from [::1], {taken}/{ROOMS} bundles from [fe80::1], in {:?}",
        bring.len(),
        t0.elapsed()
    );
    assert!(
        answers.len() >= 3 && answers.iter().all(|a| a == "Ok(())"),
        "CANNOT MEASURE: B did not take the room the stranger brought ({answers:?})"
    );
    assert_full(geneses, taken);
    let kept = board(&rt, nets.anchor6, other_id, room);
    println!("[proof] after the flood B holds of the room: {kept:?}");
    assert!(
        kept.0,
        "a stranger brought a real room to an anchor before its members did and its flood then \
         evicted the room ({kept:?}): bringing it credited the room to the stranger"
    );

    // A joiner whose only anchor is B, from a link naming only B.
    let victim_link = InviteLink::parse(&link).expect("CANNOT MEASURE: the victim's link parses");
    let b = parse_anchor_spec(&other_spec).expect("CANNOT MEASURE: B's spec parses");
    let link_b = InviteLink::new(room, vec![b], victim_link.responder)
        .expect("a link naming B")
        .to_url();
    let _joiner = daemon("joiner", &joiner_dir, free_port(), &other_spec, &pass_file);
    let t0 = Instant::now();
    let (ok, out, err) = vox_in(
        &joiner_dir,
        &["room", "join", &link_b, "--name", "first"],
        ROOM_PASS,
    );
    let took = t0.elapsed();
    println!("[proof] real join of the room through B after the flood: ok={ok} in {took:?}");
    assert!(
        ok && took < JOIN_BOUND,
        "a real joiner could not join the room through B after a stranger brought it there and \
         flooded B (ok={ok}, {took:?}, bound {JOIN_BOUND:?}): {out}{err}"
    );
}
