//! V210-70 — **a stranger cannot crowd a real room off an open anchor, however it keeps its own
//! rooms, and however long the real room's members have been away**, with every node under test
//! running as the shipped binary.
//!
//! A full anchor board (4096 rooms from peers) used to give up the oldest room with no live
//! member record. Two ways round that:
//! - **A stranger keeps its rooms live.** It is the creator of every room it mints, so it can
//!   publish a member record for each as cheaply as it mints them, and then no room of its was
//!   ever idle: a room created afterwards found the board full and was not served.
//! - **A real room's members are away** longer than their records last (an address 2 h, a bundle
//!   7 d). Its room is then the idle one, and the next stranger's room displaced it.
//!
//! The board now gives up a room from **the source credited with the most rooms**
//! (`nat::store::Source`: the network a peer published from; a room is credited only by a record
//! the board stored that the peer bringing it wrote — its creator's genesis, a member's own address
//! or bundle record — so only its members can credit it; see
//! `a_stranger_resending_a_rooms_records_cannot_crowd_it_out_proof`). A stranger filling it from
//! one network displaces only its own rooms.
//!
//! **Staging.** The anchor (`vox node`, the default: it serves any room published to it) listens
//! dual-stack on `[::]`; the victim `vox daemon` and the joiner are on `127.0.0.1`, and the
//! stranger — a test-side client, because no `vox` command publishes a genesis for a room it holds
//! no state for — reaches the anchor from `[::1]`, another network as far as the anchor can tell.
//!
//! **Asserted.**
//! 1. *Live flood:* the stranger publishes 4100 geneses and a live member record for each, over
//!    one connection. The anchor takes at least 4095 of each (fewer is `CANNOT MEASURE`: its board
//!    was never full of live rooms). It still serves the victim's room in use; the victim then
//!    creates a second room, the anchor serves it, and a real `vox room join` of it succeeds.
//! 2. *A room whose members are away:* the anchor runs with its clock 8 days ahead
//!    (`VOX_TEST_CLOCK_SKEW_MS`, the test-only knob), so every record the victim publishes to it
//!    has already lapsed there — exactly what the anchor sees of a room whose members have been
//!    away past their records — and it holds the room's genesis and nothing else (anything else is
//!    `CANNOT MEASURE`). The same live flood follows; **the anchor still serves the room.** No join
//!    is asserted here: the same skew that ages the room refuses a joiner's fresh records too.
//!
//! **Mutation that must turn it red.** `nat::store::RendezvousStore::eviction_candidate` returning
//! the oldest unpinned room with no live member record (c3's rule), ignoring sources. (1) the anchor then has no idle room
//! to give up and the second room is not on it; (2) the away room is the idle one and is evicted.

#![cfg(unix)]

#[path = "support/hostile.rs"]
mod hostile;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use hostile::{
    connect, create_room, daemon, fingerprint, free_port, profile_dir, stranger, vox_in, Rt,
};
use vox_core::governance::genesis::{ChannelPolicy, DeniabilityMode, Genesis, HistoryMode};
use vox_core::hash::Digest32;
use vox_core::nat::multiaddr::EndpointList;
use vox_core::nat::record::RendezvousRecord;
use vox_core::nat::service::{RecordKinds, RendezvousClient};
use world::{args, VoxProc, IDENTITY};

const ROOM_PASS: &str = "room passphrase";
/// Stranger rooms, each kept live: more than the 4096 a board holds from peers.
const ROOMS: usize = 4100;
/// The anchor's board is full once the stranger holds this many rooms on it: 4096 from peers,
/// less the victim's room.
const FULL: usize = 4095;
/// Eight days, in milliseconds: past a bundle record's 7-day lifetime.
const AWAY_MS: i64 = 8 * 24 * 60 * 60 * 1000;
const JOIN_BOUND: Duration = Duration::from_secs(120);

fn policy() -> ChannelPolicy {
    ChannelPolicy {
        history_mode: HistoryMode::ForwardOnly,
        deniability_mode: DeniabilityMode::Attributable,
        ttl: 0,
        min_suite: vox_core::suite::SuiteFloor::DAY_ONE.id(),
    }
}

/// Start `vox node` dual-stack on `[::]:port`, with `env`; returns it with its IPv4 spec.
fn dual_anchor(data: &Path, port: u16, env: &[(&str, &str)]) -> (VoxProc, String, Digest32) {
    let mut p = VoxProc::spawn_env(
        "anchor",
        data,
        &args(&["node", "--listen", &format!("[::]:{port}")]),
        env,
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

/// Publish `ROOMS` geneses the stranger mints, each followed by a live member record for it,
/// from `[::1]`. Returns how many geneses and records the anchor took.
fn live_flood(rt: &Rt, anchor: SocketAddr, id: Digest32, skew_secs: u64) -> (usize, usize) {
    let inventor = stranger(0x63);
    rt.block_on(async {
        let (_ep, conn) = connect(&inventor, anchor, id).await;
        let mut client = RendezvousClient::open(&conn)
            .await
            .expect("CANNOT MEASURE: a rendezvous stream to the anchor");
        let (mut geneses, mut records) = (0usize, 0usize);
        for i in 0..ROOMS {
            let mut nonce = [0u8; 16];
            nonce[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let g = Genesis::create_with_nonce(&inventor, hostile::now(), policy(), nonce).unwrap();
            if client.put(&g.to_wire()).await.is_ok() {
                geneses += 1;
            }
            // Timestamped by the anchor's clock, so it is live there however that clock runs.
            let t = hostile::now() + skew_secs;
            let rec = RendezvousRecord::build(
                &inventor,
                &g.channel_id(),
                0,
                EndpointList::new(Vec::new()).unwrap(),
                1,
                t,
                2 * 60 * 60,
            )
            .unwrap();
            if client.put(&rec.to_wire()).await.is_ok() {
                records += 1;
            }
        }
        client.finish();
        (geneses, records)
    })
}

/// What the anchor's board holds for `room`: (genesis?, member records, bundle records).
fn board(rt: &Rt, anchor: SocketAddr, id: Digest32, room: Digest32) -> (bool, usize, usize) {
    let reader = stranger(0x64);
    rt.block_on(async {
        let (_ep, conn) = connect(&reader, anchor, id).await;
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
        (set.genesis.is_some(), set.members.len(), set.bundles.len())
    })
}

#[test]
#[ignore = "real vox processes with production Argon2id, a flood and a real join; run in release"]
fn a_stranger_keeping_its_rooms_live_does_not_crowd_out_a_new_room() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (anchor_dir, victim_dir, joiner_dir) = (
        profile_dir(tmp.path(), "anchor"),
        profile_dir(tmp.path(), "victim"),
        profile_dir(tmp.path(), "joiner"),
    );
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).unwrap();
    let port = free_port();
    let (_anchor, spec, anchor_id) = dual_anchor(&anchor_dir, port, &[]);
    let anchor6: SocketAddr = format!("[::1]:{port}").parse().unwrap();
    fingerprint(&victim_dir);
    fingerprint(&joiner_dir);
    let _victim = daemon("victim", &victim_dir, free_port(), &spec, &pass_file);
    let (first, _) = create_room(&victim_dir, "first", ROOM_PASS);
    std::thread::sleep(Duration::from_secs(3));

    let rt = Rt::new();
    let t0 = Instant::now();
    let (geneses, records) = live_flood(&rt, anchor6, anchor_id, 0);
    println!(
        "[proof] live flood from [::1]: the anchor took {geneses}/{ROOMS} geneses and {records}/{ROOMS} \
         live member records, in {:?}",
        t0.elapsed()
    );
    assert!(
        geneses >= FULL && records >= FULL,
        "CANNOT MEASURE: the anchor's board was never full of live stranger rooms ({geneses} \
         geneses, {records} records taken)"
    );
    let (kept, _, _) = board(&rt, anchor6, anchor_id, first);
    println!("[proof] the anchor still serves the room in use: {kept}");
    assert!(
        kept,
        "a stranger's live rooms displaced a room in use from the anchor"
    );

    let (second, second_link) = create_room(&victim_dir, "second", ROOM_PASS);
    std::thread::sleep(Duration::from_secs(3));
    let (served, _, _) = board(&rt, anchor6, anchor_id, second);
    println!("[proof] the anchor serves the room created after the live flood: {served}");
    assert!(
        served,
        "a room created after a stranger filled the anchor with {ROOMS} rooms it keeps live is not \
         on the anchor: the stranger crowded it out"
    );
    let _joiner = daemon("joiner", &joiner_dir, free_port(), &spec, &pass_file);
    let t0 = Instant::now();
    let (ok, out, err) = vox_in(
        &joiner_dir,
        &["room", "join", &second_link, "--name", "second"],
        ROOM_PASS,
    );
    let took = t0.elapsed();
    println!("[proof] join of the room created after the live flood: ok={ok} in {took:?}");
    assert!(
        ok && took < JOIN_BOUND,
        "a real joiner could not join a room created after a stranger's live flood (ok={ok}, \
         {took:?}, bound {JOIN_BOUND:?}): {out}{err}"
    );
}

#[test]
#[ignore = "real vox processes with production Argon2id and a flood; run in release"]
fn a_room_whose_members_are_away_is_not_crowded_out() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (anchor_dir, victim_dir) = (
        profile_dir(tmp.path(), "anchor"),
        profile_dir(tmp.path(), "victim"),
    );
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).unwrap();
    let port = free_port();
    let skew = AWAY_MS.to_string();
    let (_anchor, spec, anchor_id) =
        dual_anchor(&anchor_dir, port, &[("VOX_TEST_CLOCK_SKEW_MS", &skew)]);
    let anchor6: SocketAddr = format!("[::1]:{port}").parse().unwrap();
    fingerprint(&victim_dir);
    let _victim = daemon("victim", &victim_dir, free_port(), &spec, &pass_file);
    let (away, _) = create_room(&victim_dir, "away", ROOM_PASS);
    let rt = Rt::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    let held = loop {
        let b = board(&rt, anchor6, anchor_id, away);
        if b.0 || Instant::now() >= deadline {
            break b;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    println!(
        "[proof] the anchor holds of the away room: genesis {}, {} member record(s), {} bundle(s)",
        held.0, held.1, held.2
    );
    assert!(
        held == (true, 0, 0),
        "CANNOT MEASURE: the anchor should hold the away room's genesis and no live record \
         (it holds {held:?})"
    );

    let skew_secs = (AWAY_MS / 1000) as u64;
    let (geneses, records) = live_flood(&rt, anchor6, anchor_id, skew_secs);
    println!(
        "[proof] live flood from [::1]: the anchor took {geneses}/{ROOMS} geneses and \
         {records}/{ROOMS} live member records"
    );
    assert!(
        geneses >= FULL && records >= FULL,
        "CANNOT MEASURE: the anchor's board was never full of live stranger rooms ({geneses} \
         geneses, {records} records taken)"
    );
    let (kept, _, _) = board(&rt, anchor6, anchor_id, away);
    println!("[proof] the anchor still serves the away room: {kept}");
    assert!(
        kept,
        "a stranger's {ROOMS} live rooms displaced from the anchor a room whose members have been \
         away past their records"
    );
}
