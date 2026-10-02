//! V210-70 — **a board admits as a member only a verified member of a room, and a stranger
//! cannot use a node as a relay**, with every node under test running as the shipped binary.
//!
//! A node carries relays — hole-punch coordination and circuits — for peers it classes as
//! members, and it classed as a member anybody its board knew in some room. Three ways in needed
//! no admission at all:
//! - **A genesis the peer minted itself.** Any node took a genesis from any peer, and its creator
//!   was then a member there: an unknown peer invented a room and was in.
//! - **A key vouched with no witness.** A board took a bundle for an unknown key whenever the
//!   peer that sent it was a member, so any member could put any key on another node's board.
//! - **Another room on an anchor.** An anchor keeps a board for any room a peer brings it, so
//!   there a stranger's own room *is* a room the anchor serves — and membership of any room
//!   was enough to have the anchor open a circuit to a member of every other.
//!
//! **Staging.** Everything that can be real is: an anchor (`vox node`), the victim `vox daemon`
//! that creates the room, and two members, bravo and charlie, who join it with `vox room join`.
//! Then bravo's and charlie's daemons are stopped and hostile peers connect **as bravo and as
//! charlie** — their real identities, read from their profiles — and as strangers with fresh
//! keys. No `vox` command publishes a genesis for a room it holds no state for, a bundle for a
//! key that never joined, or asks a node for a circuit to an identity of its choosing; the
//! attacker is not a person using vox. The nodes under test are the shipped binary.
//!
//! **Asserted.** Every attack is a circuit to charlie, whom a real member reaches:
//! 1. *Controls:* bravo asks the victim, and then the anchor, for a circuit to charlie, and each
//!    is carried — so a circuit through each node does open, and the zeros below measure
//!    something. Either failing is `PRODUCT (staging)`: the node would not carry a circuit
//!    between two real members.
//! 2. A stranger publishes a room it minted to the victim, with a second identity of its own
//!    witnessed into it, and asks the victim for a circuit to that second identity, and to
//!    charlie. **Neither is carried**, and nobody is offered one.
//! 3. Bravo publishes the bundle of X, a key nobody admitted, to the victim with no witness; X
//!    publishes its own address record and asks for a circuit to charlie. **Not carried.**
//!    - (3b) X2 publishes a bundle whose join witness names bravo but is signed by a stranger,
//!      and asks for a circuit to charlie. **The bundle is refused and nothing is carried.**
//!    - (3c) A stranger P puts a pre-join naming another identity Q, on the victim and on the
//!      anchor. **Both refuse it.**
//! 4. The stranger publishes its genesis to the anchor — which takes it: keeping a room's board
//!    is what an anchor is for — and asks the anchor for a circuit to charlie. **Not carried.**
//!
//! What each escalation step got is printed; with each defect, its steps are all accepted.
//!
//! **Every red names its side.** An attack the node carried is `PRODUCT:`. A staging step the
//! product performs (a join, a control circuit, the anchor taking a room) is `PRODUCT (staging):`.
//! A record the attacker could not build, or a temp file it could not write, is
//! `CANNOT MEASURE (harness error):`.
//!
//! **Mutations that must turn it red**, one assertion each:
//! - (2) `nat::service`'s `put`: take a peer's genesis on any board (drop the `serve_any_room`
//!   gate).
//! - (3) `nat::service`'s `put`: admit a bundle for an unknown author under the key it carries
//!   whenever the publisher is a known member and not the author (the old vouch).
//! - (3b) `nat::service`'s `witnessed_key`: skip `JoinWitness::verify` (take any witness that
//!   names a key this board knows).
//! - (3c) `nat::service`'s `put`: drop the check that a pre-join comes from the identity it names.
//! - (4) `node::network::NodeNet::relays_between`: return `true` for any two peers.

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
use vox_core::nat::record::{
    Admission, JoinWitness, MemberBundleRecord, PreJoinRecord, RendezvousRecord,
};
use vox_core::node::prekeys::PrekeyRing;
use vox_core::transport::quic::VoxConnection;
use world::IDENTITY;

const ROOM_PASS: &str = "room passphrase";
/// How long a control may take to open: the anchor learns the members from the victim's mirror.
const CONTROL_PATIENCE: Duration = Duration::from_secs(60);

/// Ask for circuits from `asker` to charlie until one opens or `patience` runs out.
fn control(
    rt: &Rt,
    asker: &VoxConnection,
    charlie: Digest32,
    offered: &AtomicUsize,
    patience: Duration,
    via: &str,
) {
    let deadline = Instant::now() + patience;
    let before = offered.load(Ordering::SeqCst);
    let answer = loop {
        let a = rt.block_on(ask_circuit(asker, charlie));
        if a == CircuitAnswer::Opened || Instant::now() >= deadline {
            break a;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let got = offered.load(Ordering::SeqCst) - before;
    println!(
        "[proof] control: bravo → charlie through the {via}: {answer:?}, charlie offered {got}"
    );
    assert!(
        answer == CircuitAnswer::Opened && got >= 1,
        "PRODUCT (staging): the {via} would not carry a circuit between two real members \
         ({answer:?}, {got} offered), so a refusal below would measure nothing"
    );
}

/// Ask for a circuit from `asker` to charlie and return what the node said and how many
/// circuits charlie was offered meanwhile.
fn attack(
    rt: &Rt,
    asker: &VoxConnection,
    charlie: Digest32,
    offered: &AtomicUsize,
) -> (CircuitAnswer, usize) {
    let before = offered.load(Ordering::SeqCst);
    let answer = rt.block_on(ask_circuit(asker, charlie));
    // Anything offered to charlie from here on came from this request.
    std::thread::sleep(Duration::from_millis(500));
    (answer, offered.load(Ordering::SeqCst) - before)
}

#[test]
#[ignore = "real vox processes with production Argon2id and two real joins; run in release"]
fn a_board_admits_only_verified_members_and_relays_only_within_a_room() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("CANNOT MEASURE (harness error): a temp dir");
    let (anchor_dir, victim_dir, bravo_dir, charlie_dir) = (
        profile_dir(tmp.path(), "anchor"),
        profile_dir(tmp.path(), "victim"),
        profile_dir(tmp.path(), "bravo"),
        profile_dir(tmp.path(), "charlie"),
    );
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n"))
        .expect("CANNOT MEASURE (harness error): the identity passphrase file");

    // ---- the real room ------------------------------------------------------------------
    let anchor_port = free_port();
    let (_anchor, spec) = hostile::anchor(&anchor_dir, &format!("127.0.0.1:{anchor_port}"));
    let anchor_id = vox_core::node::link::b32_decode(
        spec.split('@')
            .next()
            .expect("PRODUCT (staging): the anchor printed an empty spec"),
        "anchor fingerprint",
    )
    .expect("PRODUCT (staging): the anchor's spec carries no fingerprint");
    let victim_id = fingerprint(&victim_dir);
    let charlie_id = fingerprint(&charlie_dir);
    let bravo_id = fingerprint(&bravo_dir);
    let victim_port = free_port();
    let _victim = daemon("victim", &victim_dir, victim_port, &spec, &pass_file);
    let (room, link) = create_room(&victim_dir, "team", ROOM_PASS);
    for (name, dir) in [("bravo", &bravo_dir), ("charlie", &charlie_dir)] {
        let d = daemon(name, dir, free_port(), &spec, &pass_file);
        let (ok, out, err) = vox_in(dir, &["room", "join", &link, "--name", "team"], ROOM_PASS);
        assert!(
            ok,
            "PRODUCT (staging): {name} could not join the room: {out}{err}"
        );
        // Let the victim file the new member, and mirror it to the anchor, before it goes.
        std::thread::sleep(Duration::from_secs(3));
        drop(d);
    }
    let bravo = member_signer(&bravo_dir);
    let charlie = member_signer(&charlie_dir);
    let victim_addr = format!("127.0.0.1:{victim_port}")
        .parse()
        .expect("CANNOT MEASURE (harness error): the victim's address");
    let anchor_addr = format!("127.0.0.1:{anchor_port}")
        .parse()
        .expect("CANNOT MEASURE (harness error): the anchor's address");

    let rt = Rt::new();
    let (_b1, bravo_v) = rt.block_on(connect(&*bravo, victim_addr, victim_id));
    let (_b2, bravo_a) = rt.block_on(connect(&*bravo, anchor_addr, anchor_id));
    let (_c1, charlie_v) = rt.block_on(connect(&*charlie, victim_addr, victim_id));
    let (_c2, charlie_a) = rt.block_on(connect(&*charlie, anchor_addr, anchor_id));
    let offered_v = answer_circuits(&rt, charlie_v);
    let offered_a = answer_circuits(&rt, charlie_a);

    // ---- 1. the controls ----------------------------------------------------------------
    control(
        &rt,
        &bravo_v,
        charlie_id,
        &offered_v,
        CONTROL_PATIENCE,
        "victim",
    );
    control(
        &rt,
        &bravo_a,
        charlie_id,
        &offered_a,
        CONTROL_PATIENCE,
        "anchor",
    );

    // ---- 2. a stranger's own room, on the victim -------------------------------------------
    // The stranger mints a room and witnesses a second identity of its own into it, the way a
    // real creator admits a joiner: two peers that share a room, if the victim takes it.
    let s = stranger(0x51);
    let s2 = stranger(0x52);
    let policy = ChannelPolicy {
        history_mode: HistoryMode::ForwardOnly,
        deniability_mode: DeniabilityMode::Attributable,
        ttl: 0,
        min_suite: vox_core::suite::SuiteFloor::DAY_ONE.id(),
    };
    let genesis = Genesis::create(&s, hostile::now(), policy)
        .expect("CANNOT MEASURE (harness error): the stranger's genesis");
    let fake = genesis.channel_id();
    let minted = genesis.to_wire();
    let t = hostile::now();
    let ring2 = PrekeyRing::generate(&s2, &[0x3D; 32], t)
        .expect("CANNOT MEASURE (harness error): a prekey ring");
    let witness = JoinWitness::build(&s, &fake, 0, &s2.fingerprint(), t)
        .expect("CANNOT MEASURE (harness error): a join witness");
    let s2_bundle = MemberBundleRecord::build(
        &s2,
        &fake,
        0,
        ring2
            .bundle(&s2.public_key())
            .expect("CANNOT MEASURE (harness error): a prekey bundle"),
        1,
        t,
        3600,
        Admission::Witnessed(Box::new(witness)),
    )
    .expect("CANNOT MEASURE (harness error): the second identity's bundle")
    .to_wire();
    let s2_address = RendezvousRecord::build(
        &s2,
        &fake,
        0,
        EndpointList::new(Vec::new())
            .expect("CANNOT MEASURE (harness error): an empty endpoint list"),
        1,
        t,
        3600,
    )
    .expect("CANNOT MEASURE (harness error): the second identity's address record")
    .to_wire();
    let (_s1, s_v) = rt.block_on(connect(&s, victim_addr, victim_id));
    let (_s3, s2_v) = rt.block_on(connect(&s2, victim_addr, victim_id));
    let offered_s2 = answer_circuits(&rt, Arc::clone(&s2_v));
    let published = rt.block_on(put(&s_v, &minted));
    let joined = rt.block_on(put(&s2_v, &s2_bundle));
    let addressed2 = rt.block_on(put(&s2_v, &s2_address));
    println!(
        "[proof] step: a stranger publishes a room it minted to the victim → {published:?}; its \
         second identity's witnessed bundle → {joined:?}, address → {addressed2:?}"
    );
    let (asked, got) = attack(&rt, &s_v, s2.fingerprint(), &offered_s2);
    println!(
        "[proof] stranger → its own second identity through the victim: {asked:?}, offered {got}"
    );
    assert!(
        asked != CircuitAnswer::Opened && got == 0,
        "PRODUCT: the victim relayed between two identities of a stranger that published a room it \
         minted: a genesis made its creator a member of a node that holds no such room ({asked:?}, \
         {got} offered; genesis {published:?}, bundle {joined:?}, address {addressed2:?})"
    );
    let (asked, got) = attack(&rt, &s_v, charlie_id, &offered_v);
    println!("[proof] stranger → charlie through the victim: {asked:?}, charlie offered {got}");
    assert!(
        asked != CircuitAnswer::Opened && got == 0,
        "PRODUCT: a stranger that published a genesis it minted had the victim carry its circuit \
         to a real member ({asked:?}, {got} offered; the genesis: {published:?})"
    );

    // ---- 3. a key nobody witnessed, vouched for by a real member ---------------------------
    let x = stranger(0x77);
    let t = hostile::now();
    let ring = PrekeyRing::generate(&x, &[0x3C; 32], t)
        .expect("CANNOT MEASURE (harness error): a prekey ring");
    let bundle = ring
        .bundle(&x.public_key())
        .expect("CANNOT MEASURE (harness error): a prekey bundle");
    let x_bundle = MemberBundleRecord::build(&x, &room, 0, bundle, 1, t, 3600, Admission::Creator)
        .expect("CANNOT MEASURE (harness error): X's bundle");
    let x_address = RendezvousRecord::build(
        &x,
        &room,
        0,
        EndpointList::new(Vec::new())
            .expect("CANNOT MEASURE (harness error): an empty endpoint list"),
        1,
        t,
        3600,
    )
    .expect("CANNOT MEASURE (harness error): X's address record");
    let vouched = rt.block_on(put(&bravo_v, &x_bundle.to_wire()));
    println!("[proof] step: bravo publishes X's bundle with no witness → {vouched:?}");
    let (_x1, x_v) = rt.block_on(connect(&x, victim_addr, victim_id));
    let addressed = rt.block_on(put(&x_v, &x_address.to_wire()));
    println!("[proof] step: X publishes its own address record → {addressed:?}");
    let (asked, got) = attack(&rt, &x_v, charlie_id, &offered_v);
    println!("[proof] X → charlie through the victim: {asked:?}, charlie offered {got}");
    assert!(
        asked != CircuitAnswer::Opened && got == 0,
        "PRODUCT: a key no member witnessed was treated as a member of the victim's board: the \
         victim carried its circuit to a real member ({asked:?}, {got} offered) after a member \
         published its bundle with no join witness (bundle {vouched:?}, address {addressed:?})"
    );

    // ---- 3b. a forged witness ----------------------------------------------------------------
    // A witness that names bravo — a real member — as the one who admitted X, but is signed by
    // a stranger. Only the witness's signature separates it from a real one.
    let x2 = stranger(0x78);
    let forger = stranger(0x79);
    let t = hostile::now();
    let ring = PrekeyRing::generate(&x2, &[0x3E; 32], t)
        .expect("CANNOT MEASURE (harness error): a prekey ring");
    let mut forged = JoinWitness::build(&forger, &room, 0, &x2.fingerprint(), t)
        .expect("CANNOT MEASURE (harness error): the forged witness");
    forged.witness_id = bravo_id;
    let x2_bundle = MemberBundleRecord::build(
        &x2,
        &room,
        0,
        ring.bundle(&x2.public_key())
            .expect("CANNOT MEASURE (harness error): a prekey bundle"),
        1,
        t,
        3600,
        Admission::Witnessed(Box::new(forged)),
    )
    .expect("CANNOT MEASURE (harness error): X2's bundle")
    .to_wire();
    let x2_address = RendezvousRecord::build(
        &x2,
        &room,
        0,
        EndpointList::new(Vec::new())
            .expect("CANNOT MEASURE (harness error): an empty endpoint list"),
        1,
        t,
        3600,
    )
    .expect("CANNOT MEASURE (harness error): X2's address record")
    .to_wire();
    let (_x2, x2_v) = rt.block_on(connect(&x2, victim_addr, victim_id));
    let forged_bundle = rt.block_on(put(&x2_v, &x2_bundle));
    let forged_address = rt.block_on(put(&x2_v, &x2_address));
    println!(
        "[proof] step: X2 publishes a bundle whose witness names bravo but a stranger signed → \
         {forged_bundle:?}; its address → {forged_address:?}"
    );
    let (asked, got) = attack(&rt, &x2_v, charlie_id, &offered_v);
    println!("[proof] X2 → charlie through the victim: {asked:?}, charlie offered {got}");
    assert!(
        forged_bundle.is_err() && asked != CircuitAnswer::Opened && got == 0,
        "PRODUCT: a bundle whose join witness is forged — naming bravo, signed by a stranger — was \
         taken and its key treated as a member ({forged_bundle:?}, {asked:?}, {got} offered)"
    );

    // ---- 3c. a pre-join put by one identity for another --------------------------------------
    let p = stranger(0x81);
    let q = stranger(0x82);
    let t = hostile::now();
    let qring = PrekeyRing::generate(&q, &[0x3F; 32], t)
        .expect("CANNOT MEASURE (harness error): a prekey ring");
    let q_prejoin = PreJoinRecord::build(
        &q,
        &room,
        qring
            .bundle(&q.public_key())
            .expect("CANNOT MEASURE (harness error): a prekey bundle"),
        EndpointList::new(Vec::new())
            .expect("CANNOT MEASURE (harness error): an empty endpoint list"),
        1,
        t,
    )
    .expect("CANNOT MEASURE (harness error): Q's pre-join")
    .to_wire();
    let (_p1, p_v) = rt.block_on(connect(&p, victim_addr, victim_id));
    let (_p2, p_a) = rt.block_on(connect(&p, anchor_addr, anchor_id));
    let on_victim = rt.block_on(put(&p_v, &q_prejoin));
    let on_anchor = rt.block_on(put(&p_a, &q_prejoin));
    println!("[proof] step: P puts Q's pre-join → victim {on_victim:?}, anchor {on_anchor:?}");
    assert!(
        on_victim.is_err() && on_anchor.is_err(),
        "PRODUCT: a pre-join was taken from an identity other than the one it names — one \
         connection can fill a room's pre-join slots (victim {on_victim:?}, anchor {on_anchor:?})"
    );

    // ---- 4. the stranger's own room, on the anchor ----------------------------------------
    let (_s2, s_a) = rt.block_on(connect(&s, anchor_addr, anchor_id));
    let anchored = rt.block_on(put(&s_a, &minted));
    println!("[proof] step: the stranger publishes its genesis to the anchor → {anchored:?}");
    assert!(
        anchored.is_ok(),
        "PRODUCT (staging): the anchor refused the stranger's room ({anchored:?}); an anchor keeps \
         a board for any room brought to it, so this is the case that has to be safe"
    );
    // The anchor adopts a room on its tick; give it one.
    std::thread::sleep(Duration::from_secs(2));
    let (asked, got) = attack(&rt, &s_a, charlie_id, &offered_a);
    println!("[proof] stranger → charlie through the anchor: {asked:?}, charlie offered {got}");
    assert!(
        asked != CircuitAnswer::Opened && got == 0,
        "PRODUCT: the anchor carried a circuit from the creator of a room a stranger brought it to \
         a member of a different room ({asked:?}, {got} offered)"
    );
}
