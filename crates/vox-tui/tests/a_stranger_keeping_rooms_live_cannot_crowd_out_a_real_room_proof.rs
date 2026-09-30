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
//! (`nat::store::Source`: the network a peer published from). A room is credited to the networks
//! its records came from, and only to its **authors'** once it has any (`nat::store::Credit`: the
//! peer that brought a record wrote it — the genesis's creator, or the member who signed it). A
//! stranger filling it from one network, or from a few, displaces only its own rooms, and
//! re-sending a real room's records does not get that room filed under the stranger's network.
//!
//! **Staging.** The anchor (`vox node`, the default: it serves any room published to it) listens
//! dual-stack on `[::]`; the victim `vox daemon` and the joiner are on `127.0.0.1`, and the
//! stranger — a test-side client, because no `vox` command publishes a genesis for a room it holds
//! no state for — reaches the anchor from `[::1]`, another network as far as the anchor can tell,
//! and in (3) also from `127.0.0.1`: a stranger on the victim's own network as well as another.
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
//! 3. *Replay, then a flood from two networks:* once the anchor holds the victim's room with a
//!    member and a bundle record, the stranger fetches them from the anchor and puts each back from
//!    `[::1]` (at least one taken, else `CANNOT MEASURE`: nothing was re-sent). It then publishes
//!    4100 geneses from `[::1]`, each with a live member record, sends each record again from
//!    `127.0.0.1`, and publishes 8 more rooms from `[::1]`, which the full board must make room for
//!    with every stranger room credited to both networks. The anchor takes at least 4095 of each
//!    (else `CANNOT MEASURE`), **still serves the victim's room**, and a real `vox room join` of it
//!    succeeds.
//!
//! **Mutations that must turn it red.**
//! - `nat::store::RendezvousStore::eviction_candidate` returning the oldest unpinned room with no
//!   live member record (c3's rule), ignoring sources. (1) the anchor then has no idle room to give
//!   up and the second room is not on it; (2) the away room is the idle one and is evicted.
//! - `nat::service`'s `credit` calling every record authored, whoever brought it (c4's rule). (3)
//!   the replay files the victim's room under `[::1]` beside the stranger's rooms; credited to the
//!   same two networks, live like them and older than all of them, it goes first.
//! - `nat::store::RendezvousStore::eviction_candidate` ordering a source's rooms by fewest sources
//!   first instead of by how many rooms their sources hold (c4's order). (3) the victim's network
//!   holds the most rooms — the stranger's, and the victim's — and the victim's room, credited to
//!   that network alone, goes first.

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

/// Fetch `room`'s member and bundle records from the anchor and put each back, from `[::1]`, as
/// a stranger that wrote none of them. Returns (fetched, taken back).
fn replay(rt: &Rt, anchor: SocketAddr, id: Digest32, room: Digest32) -> (usize, usize) {
    let replayer = stranger(0x65);
    rt.block_on(async {
        let (_ep, conn) = connect(&replayer, anchor, id).await;
        let mut client = RendezvousClient::open(&conn)
            .await
            .expect("CANNOT MEASURE: a rendezvous stream to the anchor");
        let set = client
            .get(&room, 0, RecordKinds::MEMBERS.or(RecordKinds::BUNDLES))
            .await
            .expect("CANNOT MEASURE: the anchor answered a GET");
        let wires: Vec<Vec<u8>> = set
            .members
            .iter()
            .map(RendezvousRecord::to_wire)
            .chain(set.bundles.iter().map(|b| b.to_wire()))
            .collect();
        let mut taken = 0usize;
        for w in &wires {
            if client.put(w).await.is_ok() {
                taken += 1;
            }
        }
        client.finish();
        (wires.len(), taken)
    })
}

/// Extra geneses published once every stranger room is credited to both networks, so the board
/// must choose what to evict with those credits in place.
const AFTER: usize = 8;

/// A live member record for `room`, written by `author`.
fn live_record(
    author: &impl vox_core::identity::composite::RootSigner,
    room: &Digest32,
) -> Vec<u8> {
    RendezvousRecord::build(
        author,
        room,
        0,
        EndpointList::new(Vec::new()).unwrap(),
        1,
        hostile::now(),
        2 * 60 * 60,
    )
    .unwrap()
    .to_wire()
}

/// One stranger's flood from two networks. A node keeps one connection per peer, so in turn:
/// 1. from `[::1]`, `ROOMS` geneses, each with a live member record;
/// 2. from `127.0.0.1`, each of those records again, so its rooms are credited to both networks;
/// 3. from `[::1]`, [`AFTER`] more geneses with records, which the full board must make room for.
///
/// Returns (geneses, records from `[::1]`, records from `127.0.0.1`) the anchor took.
fn two_network_flood(rt: &Rt, port: u16, id: Digest32) -> (usize, usize, usize) {
    let inventor = stranger(0x66);
    let v6: SocketAddr = format!("[::1]:{port}").parse().unwrap();
    let v4: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    rt.block_on(async {
        let (mut geneses, mut from_a, mut from_b) = (0usize, 0usize, 0usize);
        let mut records = Vec::with_capacity(ROOMS);
        let publish = |range: std::ops::Range<usize>| {
            let mut out = Vec::new();
            for i in range {
                let mut nonce = [0u8; 16];
                nonce[..8].copy_from_slice(&(i as u64).to_le_bytes());
                let g =
                    Genesis::create_with_nonce(&inventor, hostile::now(), policy(), nonce).unwrap();
                out.push((g.to_wire(), live_record(&inventor, &g.channel_id())));
            }
            out
        };
        for (step, range) in [(1, 0..ROOMS), (3, ROOMS..ROOMS + AFTER)] {
            let batch = publish(range);
            let (_ep, conn) = connect(&inventor, v6, id).await;
            let mut a = RendezvousClient::open(&conn)
                .await
                .expect("CANNOT MEASURE: a rendezvous stream from [::1]");
            for (g, rec) in &batch {
                if a.put(g).await.is_ok() {
                    geneses += 1;
                }
                if a.put(rec).await.is_ok() {
                    from_a += 1;
                }
            }
            a.finish();
            if step == 1 {
                records.extend(batch.into_iter().map(|(_, rec)| rec));
                drop(conn);
                let (_ep, conn) = connect(&inventor, v4, id).await;
                let mut b = RendezvousClient::open(&conn)
                    .await
                    .expect("CANNOT MEASURE: a rendezvous stream from 127.0.0.1");
                for rec in &records {
                    if b.put(rec).await.is_ok() {
                        from_b += 1;
                    }
                }
                b.finish();
            }
        }
        (geneses, from_a, from_b)
    })
}

#[test]
#[ignore = "real vox processes with production Argon2id, a flood and a real join; run in release"]
fn a_stranger_replaying_a_real_rooms_records_cannot_get_it_evicted() {
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
    let (room, link) = create_room(&victim_dir, "real", ROOM_PASS);
    let rt = Rt::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    let held = loop {
        let b = board(&rt, anchor6, anchor_id, room);
        if (b.0 && b.1 > 0 && b.2 > 0) || Instant::now() >= deadline {
            break b;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    println!(
        "[proof] the anchor holds of the real room: genesis {}, {} member record(s), {} bundle(s)",
        held.0, held.1, held.2
    );
    assert!(
        held.0 && held.1 > 0 && held.2 > 0,
        "CANNOT MEASURE: the anchor should hold the real room's genesis, a member record and a \
         bundle (it holds {held:?})"
    );

    let (fetched, taken) = replay(&rt, anchor6, anchor_id, room);
    println!(
        "[proof] replay from [::1]: fetched {fetched} record(s), the anchor took {taken} back"
    );
    assert!(
        taken > 0,
        "CANNOT MEASURE: the anchor took none of the real room's records back from the stranger \
         ({fetched} fetched), so nothing was replayed"
    );

    let t0 = Instant::now();
    let (geneses, from_a, from_b) = two_network_flood(&rt, port, anchor_id);
    println!(
        "[proof] flood from [::1] and 127.0.0.1: the anchor took {geneses}/{} geneses, \
         {from_a}/{} live records from [::1] and {from_b}/{ROOMS} from 127.0.0.1, in {:?}",
        ROOMS + AFTER,
        ROOMS + AFTER,
        t0.elapsed()
    );
    assert!(
        geneses >= FULL + AFTER && from_a >= FULL + AFTER && from_b >= FULL,
        "CANNOT MEASURE: the anchor's board was never full of stranger rooms live from two \
         networks ({geneses} geneses, {from_a} and {from_b} records taken)"
    );
    let (kept, _, _) = board(&rt, anchor6, anchor_id, room);
    println!("[proof] the anchor still serves the real room: {kept}");
    assert!(
        kept,
        "a stranger that re-sent a real room's records from [::1], then flooded the anchor from \
         [::1] and 127.0.0.1, got the real room evicted"
    );
    let _joiner = daemon("joiner", &joiner_dir, free_port(), &spec, &pass_file);
    let t0 = Instant::now();
    let (ok, out, err) = vox_in(
        &joiner_dir,
        &["room", "join", &link, "--name", "real"],
        ROOM_PASS,
    );
    let took = t0.elapsed();
    println!("[proof] join of the real room after the replay and the flood: ok={ok} in {took:?}");
    assert!(
        ok && took < JOIN_BOUND,
        "a real joiner could not join the real room after a stranger replayed its records and \
         flooded the anchor (ok={ok}, {took:?}, bound {JOIN_BOUND:?}): {out}{err}"
    );
}
