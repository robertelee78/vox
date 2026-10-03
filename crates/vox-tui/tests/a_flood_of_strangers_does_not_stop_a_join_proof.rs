//! V210-70 — **a flood from strangers does not stop a real room being joined through a node**,
//! with every node under test running as the shipped binary.
//!
//! Two stores on a board were bounded by refusing whatever came next, and anyone could fill
//! them:
//! - **Pre-join slots.** A pre-join record needs nothing but a key — a joiner has no membership,
//!   passphrase or proof of work yet — and a room's name is public (it is the `.vox` name and it
//!   is in every invite link). A full bucket of 256 refused every later pre-join, so strangers
//!   who put 256 of them on a room's boards refused every real joiner for the two hours the
//!   records live.
//! - **Geneses.** A board took a genesis from any peer, up to 4096, and never let one go. A
//!   member node that anyone had filled could not put a room it created *later* on its own board,
//!   and an anchor anyone had filled took no new room at all, so rooms created later could not be
//!   joined through either.
//!
//! **Staging.** The anchor (`vox node`), the victim `vox daemon` holding the room, and the joiner
//! are the real binary. The strangers are test-side clients speaking the Vox wire protocol, each
//! with an identity of its own: no `vox` command publishes a bare pre-join, or a genesis for a
//! room it holds no state for, and the attacker is not a person using vox.
//!
//! **Asserted.**
//! 1. 300 strangers, each on its own connection, put a pre-join for the room on the anchor and on
//!    the victim, and at least 256 of them are taken by each — the slots really are full. Fewer is
//!    `CANNOT MEASURE`.
//! 2. 4100 geneses for rooms one stranger invented are offered, over one connection, to the
//!    victim and to the anchor (a default `vox node`, which serves any room published to it). The
//!    anchor takes at least 4095 — its 4096 rooms from peers less the room in use — so its board
//!    is full (fewer is `CANNOT MEASURE`), and it still
//!    serves the room in use: a room with live members is never displaced by empty ones.
//! 3. The victim then creates a second room, and **both** boards serve its genesis — what a
//!    joiner reaching either fetches first. (A join races both boards, so a join alone could
//!    succeed through one and say nothing about the other.)
//! 4. A real joiner joins **each** room with `vox room join`, and both joins succeed within 120 s.
//!
//! **Mutations that must turn it red.**
//! - `nat::store::RendezvousStore::accept_prejoin`: refuse a new pre-join at capacity again ("pre-join channel at
//!   capacity") instead of letting the oldest arrival go. The joiner's own pre-join is refused and
//!   its join fails.
//! - `nat::service`'s `put`: take a peer's genesis on any board (drop the `serve_rooms` gate)
//!   and count the node's own geneses against the cap. The victim's board fills with strangers'
//!   rooms and its second room never reaches it (assertion 3).
//! - `nat::store::RendezvousStore::accept_genesis`: refuse a genesis at capacity again instead of
//!   evicting the oldest one with no live members. The anchor's board stays full of strangers'
//!   rooms and the second room never reaches it (assertion 3).

#![cfg(unix)]

#[path = "support/hostile.rs"]
mod hostile;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::time::{Duration, Instant};

use hostile::{
    connect, create_room, daemon, fingerprint, free_port, profile_dir, put, stranger, vox_in, Rt,
};
use vox_core::governance::genesis::{ChannelPolicy, Genesis};
use vox_core::identity::composite::{RootSigner, SoftwareRootSigner};
use vox_core::nat::multiaddr::EndpointList;
use vox_core::nat::record::PreJoinRecord;
use vox_core::node::prekeys::PrekeyRing;
use world::IDENTITY;

const ROOM_PASS: &str = "room passphrase";
/// Strangers putting a pre-join on each board: more than the 256 slots a room has.
const PREJOINS: usize = 300;
/// The slots a room's pre-join bucket has, which the flood must fill.
const SLOTS: usize = 256;
/// Stranger geneses offered to the victim: more than the 4096 a board would hold.
const GENESES: usize = 4100;
/// A real join, with the flood in place, must finish inside this.
const JOIN_BOUND: Duration = Duration::from_secs(120);

/// Put a pre-join for `room` from `count` strangers, each on its own connection, on the node at
/// `addr`. Returns how many the node took.
fn flood_prejoins(
    rt: &Rt,
    addr: std::net::SocketAddr,
    id: vox_core::hash::Digest32,
    room: vox_core::hash::Digest32,
    count: usize,
    salt: u8,
) -> usize {
    let mut took = 0;
    for batch in (0..count).collect::<Vec<_>>().chunks(20) {
        took += flood_batch(rt, addr, id, room, batch, salt);
    }
    took
}

fn flood_batch(
    rt: &Rt,
    addr: std::net::SocketAddr,
    id: vox_core::hash::Digest32,
    room: vox_core::hash::Digest32,
    batch: &[usize],
    salt: u8,
) -> usize {
    let mut tasks = Vec::new();
    for &i in batch {
        tasks.push(rt.spawn(async move {
            let mut seed = [salt; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let mut other = [salt ^ 0x33; 32];
            other[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let s = SoftwareRootSigner::from_component_seeds(&seed, &other).unwrap();
            let t = hostile::now();
            let ring = PrekeyRing::generate(&s, &seed, t).unwrap();
            let bundle = ring.bundle(&s.public_key()).unwrap();
            let record = PreJoinRecord::build(
                &s,
                &room,
                bundle,
                EndpointList::new(Vec::new()).unwrap(),
                1,
                t,
            )
            .unwrap();
            let (ep, conn) = connect(&s, addr, id).await;
            let ok = put(&conn, &record.to_wire()).await.is_ok();
            conn.quinn().close(0u32.into(), b"done");
            drop(ep);
            ok
        }));
    }
    rt.block_on(async {
        let mut took = 0;
        for t in tasks {
            if t.await.unwrap_or(false) {
                took += 1;
            }
        }
        took
    })
}

fn join(dir: &std::path::Path, link: &str, name: &str) -> (bool, Duration, String) {
    let t0 = Instant::now();
    let (ok, out, err) = vox_in(
        dir,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            link,
            "--name",
            name,
        ],
        ROOM_PASS,
    );
    (ok, t0.elapsed(), format!("{out}{err}"))
}

#[test]
#[ignore = "real vox processes with production Argon2id, a flood and two real joins; run in release"]
fn a_flood_of_strangers_does_not_stop_a_real_join_through_a_node() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (anchor_dir, victim_dir, joiner_dir) = (
        profile_dir(tmp.path(), "anchor"),
        profile_dir(tmp.path(), "victim"),
        profile_dir(tmp.path(), "joiner"),
    );
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).unwrap();

    let anchor_port = free_port();
    let (_anchor, spec) = hostile::anchor(&anchor_dir, &format!("127.0.0.1:{anchor_port}"));
    let anchor_id = vox_core::node::link::b32_decode(
        spec.split('@').next().expect("an anchor spec"),
        "anchor fingerprint",
    )
    .expect("the anchor's fingerprint");
    let victim_id = fingerprint(&victim_dir);
    fingerprint(&joiner_dir);
    let victim_port = free_port();
    let _victim = daemon("victim", &victim_dir, victim_port, &spec, &pass_file);
    let (room, link) = create_room(&victim_dir, "first", ROOM_PASS);
    // The anchor holds the room once the victim has published it there.
    std::thread::sleep(Duration::from_secs(3));
    let victim_addr = format!("127.0.0.1:{victim_port}").parse().unwrap();
    let anchor_addr = format!("127.0.0.1:{anchor_port}").parse().unwrap();

    let rt = Rt::new();

    // ---- 1. the pre-join slots, filled on both boards --------------------------------------
    let t0 = Instant::now();
    let on_anchor = flood_prejoins(&rt, anchor_addr, anchor_id, room, PREJOINS, 0x41);
    let on_victim = flood_prejoins(&rt, victim_addr, victim_id, room, PREJOINS, 0x42);
    println!(
        "[proof] pre-join flood: {on_anchor}/{PREJOINS} taken by the anchor, \
         {on_victim}/{PREJOINS} by the victim, in {:?}",
        t0.elapsed()
    );
    assert!(
        on_anchor >= SLOTS && on_victim >= SLOTS,
        "CANNOT MEASURE: the flood did not fill the room's {SLOTS} pre-join slots \
         (anchor took {on_anchor}, victim {on_victim})"
    );

    // ---- 2. stranger geneses, then a room created after them -------------------------------
    let t0 = Instant::now();
    let inventor = stranger(0x61);
    let geneses: Vec<Vec<u8>> = (0..GENESES)
        .map(|i| {
            let mut nonce = [0u8; 16];
            nonce[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let policy = ChannelPolicy {
                history_mode: vox_core::governance::genesis::HistoryMode::ForwardOnly,
                deniability_mode: vox_core::governance::genesis::DeniabilityMode::Attributable,
                ttl: 0,
                min_suite: vox_core::suite::SuiteFloor::DAY_ONE.id(),
            };
            Genesis::create_with_nonce(&inventor, hostile::now(), policy, nonce)
                .unwrap()
                .to_wire()
        })
        .collect();
    let offer = |addr: std::net::SocketAddr, id: vox_core::hash::Digest32| {
        rt.block_on(async {
            let (_ep, conn) = connect(&inventor, addr, id).await;
            let mut client = vox_core::nat::service::RendezvousClient::open(&conn)
                .await
                .expect("CANNOT MEASURE: a rendezvous stream");
            let mut taken = 0usize;
            for g in &geneses {
                if client.put(g).await.is_ok() {
                    taken += 1;
                }
            }
            client.finish();
            taken
        })
    };
    // What any joiner that reaches a board fetches first: the room's genesis. A join races every
    // board it knows, so a join alone can succeed through either node and say nothing about the
    // other; these say it of each board.
    let serves = |addr: std::net::SocketAddr, id: vox_core::hash::Digest32, room| {
        rt.block_on(async {
            let (_ep, conn) = connect(&inventor, addr, id).await;
            let mut client = vox_core::nat::service::RendezvousClient::open(&conn)
                .await
                .expect("CANNOT MEASURE: a rendezvous stream");
            let set = client
                .get(&room, 0, vox_core::nat::service::RecordKinds::GENESIS)
                .await;
            client.finish();
            set.map(|s| s.genesis.is_some())
        })
    };
    let on_victim = offer(victim_addr, victim_id);
    let on_anchor = offer(anchor_addr, anchor_id);
    println!(
        "[proof] genesis flood: the victim took {on_victim}/{GENESES} stranger geneses, the \
         anchor {on_anchor}/{GENESES}, in {:?}",
        t0.elapsed()
    );
    assert!(
        on_anchor >= 4095,
        "CANNOT MEASURE: the anchor took only {on_anchor} of {GENESES} stranger geneses, so its \
         board was never full (it holds 4096 rooms from peers, one of them the room in use)"
    );
    let first_kept = serves(anchor_addr, anchor_id, room);
    println!("[proof] the anchor still serves the room in use: {first_kept:?}");
    assert!(
        matches!(first_kept, Ok(true)),
        "strangers' {GENESES} empty rooms displaced a room in use from the anchor ({first_kept:?})"
    );
    let (second, second_link) = create_room(&victim_dir, "second", ROOM_PASS);
    std::thread::sleep(Duration::from_secs(3));
    let on_victim_board = serves(victim_addr, victim_id, second);
    let on_anchor_board = serves(anchor_addr, anchor_id, second);
    println!(
        "[proof] the second room's genesis is served by the victim: {on_victim_board:?}, by the \
         anchor: {on_anchor_board:?}"
    );
    assert!(
        matches!(on_victim_board, Ok(true)),
        "a room the victim created after strangers offered its board {GENESES} geneses is not on \
         the victim's own board ({on_victim_board:?}): nobody reaching that node can join it \
         through it"
    );
    assert!(
        matches!(on_anchor_board, Ok(true)),
        "a room created after a stranger filled the anchor with {GENESES} geneses is not on the \
         anchor ({on_anchor_board:?}): an anchor that serves any room published to it serves no \
         new one"
    );

    // ---- 3. real joins, through the flooded nodes ------------------------------------------
    let _joiner = daemon("joiner", &joiner_dir, free_port(), &spec, &pass_file);
    let (ok1, took1, said1) = join(&joiner_dir, &link, "first");
    println!("[proof] join of the flooded room: ok={ok1} in {took1:?}");
    let (ok2, took2, said2) = join(&joiner_dir, &second_link, "second");
    println!("[proof] join of the room created after the genesis flood: ok={ok2} in {took2:?}");
    let _ = room;
    assert!(
        ok1 && took1 < JOIN_BOUND,
        "a real joiner could not join a room whose pre-join slots strangers had filled \
         (ok={ok1}, {took1:?}, bound {JOIN_BOUND:?}): {said1}"
    );
    assert!(
        ok2 && took2 < JOIN_BOUND,
        "a real joiner could not join a room its host created after strangers flooded the host's \
         board with {GENESES} geneses (ok={ok2}, {took2:?}, bound {JOIN_BOUND:?}): {said2}"
    );
}
