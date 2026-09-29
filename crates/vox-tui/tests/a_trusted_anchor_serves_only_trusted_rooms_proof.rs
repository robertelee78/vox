//! V210-70 — **`vox node --serve trusted` serves only rooms made by someone its operator
//! trusts**, with every node under test running as the shipped binary.
//!
//! An anchor keeps a board for any room brought to it (`--serve anyone`, the default — the
//! decider, 2026-09-29, via agent_comms). `--serve trusted` is the operator's other choice: the
//! anchor serves only rooms whose genesis names a creator in its profile's `vox trust` list, and
//! a stranger's room gets neither a board (rendezvous) nor a relay there. The default's
//! behaviour is `a_board_admits_only_verified_members_proof`'s step 4.
//!
//! **Staging.** The anchor's operator makes an identity in the anchor's profile (`vox id`) and
//! trusts the victim (`vox trust add`), and runs `vox node --serve trusted`. The victim `vox
//! daemon` creates a room; bravo and charlie join it with `vox room join`, then their daemons
//! are stopped and hostile peers connect to the anchor **as bravo and as charlie** — their real
//! identities, read from their profiles — and as a stranger with two identities of its own. No
//! `vox` command publishes a genesis for a room it holds no state for, or asks a node for a
//! circuit to an identity of its choosing; the attacker is not a person using vox.
//!
//! **Asserted.**
//! 1. *The trusted creator's room works end to end:* both joins succeed, the anchor's board
//!    serves the room's genesis, and the anchor carries a circuit from bravo to charlie.
//! 2. *A stranger's room gets no rendezvous:* the anchor refuses its genesis, its board serves
//!    nothing for that room, and it refuses the bundle of a second identity the stranger
//!    witnessed into it.
//! 3. *No relay:* the anchor carries no circuit from the stranger to its own second identity,
//!    nor to charlie, and nobody is offered one.
//!
//! **Mutation that must turn it red.** `nat::service::AnchorRooms::may_anchor` answering `true`
//! for `CreatedBy` (serve any creator's room). The anchor then takes the stranger's room and
//! relays between its two identities.

#![cfg(unix)]

#[path = "support/hostile.rs"]
mod hostile;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hostile::{
    answer_circuits, ask_circuit, connect, create_room, daemon, fingerprint, free_port,
    member_signer, profile_dir, put, stranger, vox_in, CircuitAnswer, Rt,
};
use vox_core::governance::genesis::{ChannelPolicy, DeniabilityMode, Genesis, HistoryMode};
use vox_core::hash::Digest32;
use vox_core::identity::composite::RootSigner;
use vox_core::nat::multiaddr::EndpointList;
use vox_core::nat::record::{Admission, JoinWitness, MemberBundleRecord, RendezvousRecord};
use vox_core::nat::service::{RecordKinds, RendezvousClient};
use vox_core::node::prekeys::PrekeyRing;
use vox_core::transport::quic::VoxConnection;
use world::{args, vox_once, IDENTITY};

const ROOM_PASS: &str = "room passphrase";
/// How long the control may take to open: the anchor learns the members from the victim.
const CONTROL_PATIENCE: Duration = Duration::from_secs(60);

/// Whether the board on `conn` serves a genesis for `room`.
fn board_has(rt: &Rt, conn: &VoxConnection, room: &Digest32) -> Result<bool, String> {
    rt.block_on(async {
        let mut client = RendezvousClient::open(conn)
            .await
            .map_err(|e| format!("{e:?}"))?;
        let set = client
            .get(room, 0, RecordKinds::GENESIS)
            .await
            .map_err(|e| format!("{e:?}"));
        client.finish();
        set.map(|s| s.genesis.is_some())
    })
}

fn attack(
    rt: &Rt,
    asker: &VoxConnection,
    target: Digest32,
    offered: &AtomicUsize,
) -> (CircuitAnswer, usize) {
    let before = offered.load(Ordering::SeqCst);
    let answer = rt.block_on(ask_circuit(asker, target));
    std::thread::sleep(Duration::from_millis(500));
    (answer, offered.load(Ordering::SeqCst) - before)
}

#[test]
#[ignore = "real vox processes with production Argon2id and two real joins; run in release"]
fn a_trusted_anchor_serves_only_rooms_its_operator_trusts() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let (anchor_dir, victim_dir, bravo_dir, charlie_dir) = (
        profile_dir(tmp.path(), "anchor"),
        profile_dir(tmp.path(), "victim"),
        profile_dir(tmp.path(), "bravo"),
        profile_dir(tmp.path(), "charlie"),
    );
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).unwrap();

    // ---- the operator trusts the victim, and serves only trusted rooms ---------------------
    let victim_id = fingerprint(&victim_dir);
    let charlie_id = fingerprint(&charlie_dir);
    fingerprint(&bravo_dir);
    fingerprint(&anchor_dir);
    let victim_b32 = vox_core::node::link::b32_encode(&victim_id);
    let (ok, out, err) = vox_once(
        &anchor_dir,
        &args(&["trust", "add", &victim_b32, "--name", "victim"]),
    );
    assert!(
        ok,
        "CANNOT MEASURE: the operator's vox trust add: {out}{err}"
    );
    let anchor_port = free_port();
    let (mut anchor, spec) = hostile::anchor_with(
        &anchor_dir,
        &format!("127.0.0.1:{anchor_port}"),
        &["--serve", "trusted"],
    );
    let said = anchor.transcript();
    println!(
        "[proof] the anchor said: {}",
        said.lines().next().unwrap_or_default()
    );
    assert!(
        said.contains("serving only rooms made by the 1 identity this profile trusts"),
        "CANNOT MEASURE: `vox node --serve trusted` did not say it serves only trusted rooms: {said}"
    );
    let anchor_id = vox_core::node::link::b32_decode(
        spec.split('@').next().expect("an anchor spec"),
        "anchor fingerprint",
    )
    .expect("the anchor's fingerprint");

    // ---- 1. the trusted creator's room, end to end -----------------------------------------
    let victim_port = free_port();
    let _victim = daemon("victim", &victim_dir, victim_port, &spec, &pass_file);
    let (room, link) = create_room(&victim_dir, "team", ROOM_PASS);
    for (name, dir) in [("bravo", &bravo_dir), ("charlie", &charlie_dir)] {
        let d = daemon(name, dir, free_port(), &spec, &pass_file);
        let (ok, out, err) = vox_in(dir, &["room", "join", &link, "--name", "team"], ROOM_PASS);
        println!("[proof] {name} joins the trusted creator's room: ok={ok}");
        assert!(
            ok,
            "a member could not join a trusted creator's room: {out}{err}"
        );
        std::thread::sleep(Duration::from_secs(3));
        drop(d);
    }
    let bravo = member_signer(&bravo_dir);
    let charlie = member_signer(&charlie_dir);
    let anchor_addr = format!("127.0.0.1:{anchor_port}").parse().unwrap();
    let rt = Rt::new();
    let (_b, bravo_a) = rt.block_on(connect(&*bravo, anchor_addr, anchor_id));
    let (_c, charlie_a) = rt.block_on(connect(&*charlie, anchor_addr, anchor_id));
    let offered = answer_circuits(&rt, charlie_a);
    let served = board_has(&rt, &bravo_a, &room);
    println!("[proof] the anchor's board serves the trusted room's genesis: {served:?}");
    assert!(
        served == Ok(true),
        "a `--serve trusted` anchor does not keep the board of a room its operator's trusted \
         identity made ({served:?})"
    );
    let deadline = Instant::now() + CONTROL_PATIENCE;
    let control = loop {
        let a = rt.block_on(ask_circuit(&bravo_a, charlie_id));
        if a == CircuitAnswer::Opened || Instant::now() >= deadline {
            break a;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let control_offers = offered.load(Ordering::SeqCst);
    println!("[proof] bravo → charlie through the anchor: {control:?}, offered {control_offers}");
    assert!(
        control == CircuitAnswer::Opened && control_offers >= 1,
        "a `--serve trusted` anchor would not relay between two members of a trusted room \
         ({control:?}, {control_offers} offered)"
    );

    // ---- 2. a stranger's room: no rendezvous ------------------------------------------------
    let s = stranger(0x51);
    let s2 = stranger(0x52);
    let policy = ChannelPolicy {
        history_mode: HistoryMode::ForwardOnly,
        deniability_mode: DeniabilityMode::Attributable,
        ttl: 0,
        min_suite: vox_core::suite::SuiteFloor::DAY_ONE.id(),
    };
    let genesis = Genesis::create(&s, hostile::now(), policy).unwrap();
    let fake = genesis.channel_id();
    let t = hostile::now();
    let ring2 = PrekeyRing::generate(&s2, &[0x3D; 32], t).unwrap();
    let witness = JoinWitness::build(&s, &fake, 0, &s2.fingerprint(), t).unwrap();
    let s2_bundle = MemberBundleRecord::build(
        &s2,
        &fake,
        0,
        ring2.bundle(&s2.public_key()).unwrap(),
        1,
        t,
        3600,
        Admission::Witnessed(Box::new(witness)),
    )
    .unwrap()
    .to_wire();
    let s2_address = RendezvousRecord::build(
        &s2,
        &fake,
        0,
        EndpointList::new(Vec::new()).unwrap(),
        1,
        t,
        3600,
    )
    .unwrap()
    .to_wire();
    let (_s, s_a) = rt.block_on(connect(&s, anchor_addr, anchor_id));
    let (_s2, s2_a) = rt.block_on(connect(&s2, anchor_addr, anchor_id));
    let offered_s2 = answer_circuits(&rt, Arc::clone(&s2_a));
    let published = rt.block_on(put(&s_a, &genesis.to_wire()));
    let joined = rt.block_on(put(&s2_a, &s2_bundle));
    let addressed = rt.block_on(put(&s2_a, &s2_address));
    // The adoption pass runs on the anchor's tick.
    std::thread::sleep(Duration::from_secs(2));
    let on_board = board_has(&rt, &s_a, &fake);
    println!(
        "[proof] stranger's room on the anchor: genesis {published:?}, witnessed bundle \
         {joined:?}, address {addressed:?}, board serves it: {on_board:?}"
    );
    assert!(
        published.is_err() && joined.is_err() && on_board == Ok(false),
        "a `--serve trusted` anchor kept the board of a room a stranger made (genesis \
         {published:?}, bundle {joined:?}, served {on_board:?})"
    );

    // ---- 3. and no relay ----------------------------------------------------------------------
    let (to_self, got_self) = attack(&rt, &s_a, s2.fingerprint(), &offered_s2);
    println!("[proof] stranger → its own second identity through the anchor: {to_self:?}, offered {got_self}");
    let (to_charlie, got_charlie) = attack(&rt, &s_a, charlie_id, &offered);
    println!(
        "[proof] stranger → charlie through the anchor: {to_charlie:?}, offered {got_charlie}"
    );
    assert!(
        to_self != CircuitAnswer::Opened && got_self == 0,
        "a `--serve trusted` anchor relayed between two identities of a stranger whose room it \
         should not serve ({to_self:?}, {got_self} offered)"
    );
    assert!(
        to_charlie != CircuitAnswer::Opened && got_charlie == 0,
        "a `--serve trusted` anchor carried a stranger's circuit to a member ({to_charlie:?}, \
         {got_charlie} offered)"
    );
}
