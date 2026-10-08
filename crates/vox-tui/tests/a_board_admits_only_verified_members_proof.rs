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
//! 5. *The member node's own check* (RP-28). A compromised member — bravo's real identity —
//!    connects to the victim afresh and serves its **own** board, with two forged authors on it:
//!    F1 claims to be the room's creator, F2 carries a join witness that names bravo but a
//!    stranger signed. The victim reads that board on its own sync, as it reads any member's, and
//!    nothing but `ChannelState::admit_from_board` stands between those records and its author
//!    table. Then bravo's log offers F1's feed — a consent grant naming the victim, and a post —
//!    on a sync session, and F1 connects as itself and delivers its sender key, sealed into a
//!    session opened from the victim's own bundle, as a member's node does. **`vox room read` on
//!    the victim never shows F1's post, and `vox room roster` lists neither F1 nor F2**, while it
//!    shows the victim's own post and lists the real members. That the victim asked bravo's board,
//!    and asked bravo's log for F1's feed, is asserted first.
//!
//! What each escalation step got is printed; with each defect, its steps are all accepted.
//!
//! **Every red names its side.** An attack the node carried is `PRODUCT:`. A staging step the
//! product performs (a join, a control circuit, the anchor taking a room) is `PRODUCT (staging):`.
//! A record the attacker could not build, or a temp file it could not write, is
//! `APPARATUS (harness error):`.
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
//! - (5) `node::channel::ChannelState::admit_from_board`: admit the key without checking its
//!   evidence. The roster lists both, and F1's post renders.

#![cfg(unix)]

#[path = "support/hostile.rs"]
mod hostile;
#[path = "support/ports.rs"]
mod ports;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hostile::{
    answer_circuits, ask_circuit, connect, create_room, daemon, fingerprint, member_signer,
    profile_dir, put, stranger, vox_in, CircuitAnswer, Rt,
};
use vox_core::governance::genesis::{ChannelPolicy, Genesis, HistoryMode};
use vox_core::governance::membership::issue_consent_grant;
use vox_core::group::{SenderChain, Skdm};
use vox_core::hash::{sha256, Digest32};
use vox_core::identity::composite::RootSigner;
use vox_core::identity::keyagreement::{PrekeyBundlePublic, X25519IdentityKey};
use vox_core::log::entry::{Entry, EntrySkeleton, ZERO_HASH};
use vox_core::log::feed::lipmaa;
use vox_core::log::sync::{
    frontier_session_room, ApplyReport, FeedFrontier, SessionRoom, WantRange,
};
use vox_core::nat::multiaddr::EndpointList;
use vox_core::nat::record::{
    Admission, JoinWitness, MemberBundleRecord, PreJoinRecord, RendezvousRecord,
};
use vox_core::nat::service::{
    RecordKinds, RendezvousClient, RendezvousRequest, RendezvousResponse, MAX_RENDEZVOUS_FRAME,
};
use vox_core::node::content::Content;
use vox_core::node::link::b32_encode;
use vox_core::node::pairwise_stream::{hello_frame, skdm_frame, write_pairwise, KEY_TAKEN};
use vox_core::node::prekeys::PrekeyRing;
use vox_core::node::syncstream::{accept_sync, open_sync, read_sync_request};
use vox_core::pairwise::session::Session;
use vox_core::suite::{algo, SuiteFloor, VOX_SUITE_1};
use vox_core::transport::framing::{read_frame, write_frame};
use vox_core::transport::quic::VoxConnection;
use vox_core::transport::streams::{accept_typed, StreamKind};
use vox_core::wire::WireError;
use world::IDENTITY;

const ROOM_PASS: &str = "room passphrase";
/// What F1, the forged creator, posts.
const FORGED_POST: &str = "a post by an author nobody admitted";
/// What the victim posts itself.
const CONTROL_POST: &str = "the victim's own post";
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

/// What a board served on a hostile member's connection saw: how many `GET`s the node asked for
/// `room`, and how many it was answered in full (every record, then `END`).
struct Served {
    asked: Arc<AtomicUsize>,
    answered: Arc<AtomicUsize>,
}

/// One author's feed in a hostile member's log: advertised in its `HAVE`, served for any `WANT`
/// of it, and nothing asked for or taken in return.
struct Feed {
    author: Digest32,
    /// The entries' wire bytes, `seq` 1 first.
    entries: Vec<Vec<u8>>,
    head: Digest32,
    /// How many of its entries a node asked for and was sent.
    served: AtomicUsize,
}

impl SessionRoom for Feed {
    fn frontiers(&self) -> Result<(Vec<FeedFrontier>, u64), WireError> {
        let frontier = FeedFrontier {
            author_id: self.author,
            max_seq: self.entries.len() as u64,
            head_hash: self.head,
        };
        Ok((vec![frontier], 0))
    }

    fn wants(&self, _remote: &[FeedFrontier]) -> Result<Vec<WantRange>, WireError> {
        Ok(Vec::new())
    }

    fn entries(&self, wants: &[WantRange]) -> Result<Vec<Vec<u8>>, WireError> {
        let n = self.entries.len() as u64;
        let out: Vec<Vec<u8>> = wants
            .iter()
            .filter(|w| w.author_id == self.author)
            .flat_map(|w| w.from_seq.max(1)..=w.to_seq.min(n))
            .map(|seq| self.entries[(seq - 1) as usize].clone())
            .collect();
        self.served.fetch_add(out.len(), Ordering::SeqCst);
        Ok(out)
    }

    fn apply(&self, _staged: Vec<Vec<u8>>) -> ApplyReport {
        ApplyReport::default()
    }

    fn generation(&self) -> Result<u64, WireError> {
        Ok(0)
    }
}

/// Serve a member's board and log on `conn`, as the member they belong to: every `GET` for `room`
/// is answered with `records`, every `PUT` is accepted, every `sync` of `room` is answered with
/// `feed`, and any other stream is dropped.
fn serve_board(
    rt: &Rt,
    conn: Arc<VoxConnection>,
    room: Digest32,
    records: Vec<Vec<u8>>,
    feed: Arc<Feed>,
) -> Served {
    let served = Served {
        asked: Arc::new(AtomicUsize::new(0)),
        answered: Arc::new(AtomicUsize::new(0)),
    };
    let (asked, answered) = (Arc::clone(&served.asked), Arc::clone(&served.answered));
    rt.spawn(async move {
        while let Ok((kind, mut send, mut recv)) = accept_typed(&conn).await {
            if kind == StreamKind::Sync {
                let feed = Arc::clone(&feed);
                tokio::spawn(async move {
                    if read_sync_request(&mut recv).await.ok().map(|(c, _)| c) != Some(room) {
                        return;
                    }
                    let handle = tokio::runtime::Handle::current();
                    let _ = tokio::task::spawn_blocking(move || {
                        frontier_session_room(&mut accept_sync(handle, send, recv), &*feed)
                    })
                    .await;
                });
                continue;
            }
            if kind != StreamKind::Rendezvous {
                continue;
            }
            let (asked, answered, records) =
                (Arc::clone(&asked), Arc::clone(&answered), records.clone());
            tokio::spawn(async move {
                while let Ok(Some(frame)) = read_frame(&mut recv, MAX_RENDEZVOUS_FRAME).await {
                    let replies = match RendezvousRequest::from_frame(&frame) {
                        Ok(RendezvousRequest::Get { channel_id, .. }) if channel_id == room => {
                            asked.fetch_add(1, Ordering::SeqCst);
                            let mut r: Vec<_> = records
                                .iter()
                                .cloned()
                                .map(RendezvousResponse::Record)
                                .collect();
                            r.push(RendezvousResponse::End);
                            r
                        }
                        Ok(RendezvousRequest::Get { .. }) => vec![RendezvousResponse::End],
                        Ok(RendezvousRequest::Put { .. }) => vec![RendezvousResponse::Accepted],
                        Err(_) => break,
                    };
                    let whole = replies.len() > 1;
                    let mut ok = true;
                    for reply in replies {
                        ok &= write_frame(&mut send, &reply.to_frame()).await.is_ok();
                    }
                    if ok && whole {
                        answered.fetch_add(1, Ordering::SeqCst);
                    }
                }
                let _ = send.finish();
            });
        }
    });
    served
}

/// A signed entry in `author`'s feed of `room`, at `seq`, after `prev` (the feed's entries so
/// far, `seq` 1 first) — as a member's node writes one.
fn feed_entry(author: &dyn RootSigner, room: Digest32, prev: &[Entry], payload: Vec<u8>) -> Entry {
    let seq = prev.len() as u64 + 1;
    let hash_of = |s: u64| prev[(s - 1) as usize].entry_hash();
    let skeleton = EntrySkeleton {
        author_id: author.fingerprint(),
        seq,
        prev_hash: if seq == 1 {
            ZERO_HASH
        } else {
            hash_of(seq - 1)
        },
        lipmaa_backlink: if seq == 1 {
            ZERO_HASH
        } else {
            hash_of(lipmaa(seq))
        },
        channel_id: room,
        epoch: 0,
        algo_ids: [algo::COMPOSITE_ED25519_ML_DSA_65, algo::AES_256_GCM],
        payload_hash: sha256(&payload),
        payload_len: payload.len() as u64,
        end_of_feed: false,
        // v0.3.0's ordering fields (ADR-023): no claimed time and nothing seen, as a fresh feed.
        claimed_ms: 0,
        seen: Vec::new(),
    };
    Entry::build_signed(author, skeleton, payload).expect("APPARATUS (harness error): a feed entry")
}

/// Deliver `skdm` to the node on `conn` as a member's node does: a session opened from the node's
/// own `bundle`, with its hello and the sealed key on one `pairwise` stream. Whether the node took
/// the key, and what it said.
async fn deliver_key(
    conn: &VoxConnection,
    room: Digest32,
    bundle: &PrekeyBundlePublic,
    skdm: &Skdm,
) -> (bool, String) {
    let ik = X25519IdentityKey::generate().expect("APPARATUS (harness error): a DH key");
    let (initial, mut session) =
        Session::initiate(&ik, bundle, &room, 0, VOX_SUITE_1.id, SuiteFloor::DAY_ONE)
            .expect("APPARATUS (harness error): a session from the victim's bundle");
    let frames = vec![
        hello_frame(&room, &initial),
        skdm_frame(&room, &mut session, skdm).expect("APPARATUS (harness error): the sealed key"),
    ];
    let mut recv = match write_pairwise(conn, &frames).await {
        Ok(r) => r,
        Err(e) => return (false, format!("not taken: {e:?}")),
    };
    match tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(8)).await {
        Ok(Ok(b)) if b == [KEY_TAKEN] => (true, "taken".into()),
        Ok(Ok(b)) => (false, format!("answered {b:?}")),
        Ok(Err(e)) => (false, format!("refused: {e}")),
        Err(_) => (false, "no answer in 5s".into()),
    }
}

#[test]
#[ignore = "real vox processes with production Argon2id and two real joins; run in release"]
fn a_board_admits_only_verified_members_and_relays_only_within_a_room() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS (harness error): a temp dir");
    let (anchor_dir, victim_dir, bravo_dir, charlie_dir) = (
        profile_dir(tmp.path(), "anchor"),
        profile_dir(tmp.path(), "victim"),
        profile_dir(tmp.path(), "bravo"),
        profile_dir(tmp.path(), "charlie"),
    );
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n"))
        .expect("APPARATUS (harness error): the identity passphrase file");

    // ---- the real room ------------------------------------------------------------------
    // On a port of its own choosing, read back from its spec (#410).
    let (_anchor, spec) = hostile::anchor(&anchor_dir, "127.0.0.1:0");
    let anchor_port = ports::spec_port(&spec);
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
    let _victim = daemon("victim", &victim_dir, 0, &spec, &pass_file);
    let victim_port = hostile::listening_port(&victim_dir);
    let (room, link) = create_room(&victim_dir, "team", ROOM_PASS);
    for (name, dir) in [("bravo", &bravo_dir), ("charlie", &charlie_dir)] {
        let d = daemon(name, dir, 0, &spec, &pass_file);
        let (ok, out, err) = vox_in(
            dir,
            &["room", "join", "--passphrase-file", "-", &link],
            ROOM_PASS,
        );
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
        .expect("APPARATUS (harness error): the victim's address");
    let anchor_addr = format!("127.0.0.1:{anchor_port}")
        .parse()
        .expect("APPARATUS (harness error): the anchor's address");

    let rt = Rt::new();
    let (b1, bravo_v) = rt.block_on(connect(&bravo, victim_addr, victim_id));
    let (_b2, bravo_a) = rt.block_on(connect(&bravo, anchor_addr, anchor_id));
    let (_c1, charlie_v) = rt.block_on(connect(&charlie, victim_addr, victim_id));
    let (_c2, charlie_a) = rt.block_on(connect(&charlie, anchor_addr, anchor_id));
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
        ttl_ms: 0,
        min_suite: vox_core::suite::SuiteFloor::DAY_ONE.id(),
    };
    let genesis = Genesis::create(&s, hostile::now_ms(), policy)
        .expect("APPARATUS (harness error): the stranger's genesis");
    let fake = genesis.channel_id();
    let minted = genesis.to_wire();
    let t = hostile::now_ms();
    let ring2 = PrekeyRing::generate(&s2, &[0x3D; 32], t)
        .expect("APPARATUS (harness error): a prekey ring");
    let witness = JoinWitness::build(&s, &fake, 0, &s2.fingerprint(), t)
        .expect("APPARATUS (harness error): a join witness");
    let s2_bundle = MemberBundleRecord::build(
        &s2,
        &fake,
        0,
        ring2
            .bundle(&s2.public_key())
            .expect("APPARATUS (harness error): a prekey bundle"),
        1,
        t,
        3_600_000,
        Admission::Witnessed(Box::new(witness)),
    )
    .expect("APPARATUS (harness error): the second identity's bundle")
    .to_wire();
    let s2_address = RendezvousRecord::build(
        &s2,
        &fake,
        0,
        EndpointList::new(Vec::new()).expect("APPARATUS (harness error): an empty endpoint list"),
        1,
        t,
        3_600_000,
    )
    .expect("APPARATUS (harness error): the second identity's address record")
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
    let t = hostile::now_ms();
    let ring =
        PrekeyRing::generate(&x, &[0x3C; 32], t).expect("APPARATUS (harness error): a prekey ring");
    let bundle = ring
        .bundle(&x.public_key())
        .expect("APPARATUS (harness error): a prekey bundle");
    let x_bundle =
        MemberBundleRecord::build(&x, &room, 0, bundle, 1, t, 3_600_000, Admission::Creator)
            .expect("APPARATUS (harness error): X's bundle");
    let x_address = RendezvousRecord::build(
        &x,
        &room,
        0,
        EndpointList::new(Vec::new()).expect("APPARATUS (harness error): an empty endpoint list"),
        1,
        t,
        3_600_000,
    )
    .expect("APPARATUS (harness error): X's address record");
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
    let t = hostile::now_ms();
    let ring = PrekeyRing::generate(&x2, &[0x3E; 32], t)
        .expect("APPARATUS (harness error): a prekey ring");
    let mut forged = JoinWitness::build(&forger, &room, 0, &x2.fingerprint(), t)
        .expect("APPARATUS (harness error): the forged witness");
    forged.witness_id = bravo_id;
    let x2_bundle = MemberBundleRecord::build(
        &x2,
        &room,
        0,
        ring.bundle(&x2.public_key())
            .expect("APPARATUS (harness error): a prekey bundle"),
        1,
        t,
        3_600_000,
        Admission::Witnessed(Box::new(forged)),
    )
    .expect("APPARATUS (harness error): X2's bundle")
    .to_wire();
    let x2_address = RendezvousRecord::build(
        &x2,
        &room,
        0,
        EndpointList::new(Vec::new()).expect("APPARATUS (harness error): an empty endpoint list"),
        1,
        t,
        3_600_000,
    )
    .expect("APPARATUS (harness error): X2's address record")
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
    let t = hostile::now_ms();
    let qring =
        PrekeyRing::generate(&q, &[0x3F; 32], t).expect("APPARATUS (harness error): a prekey ring");
    let q_prejoin = PreJoinRecord::build(
        &q,
        &room,
        qring
            .bundle(&q.public_key())
            .expect("APPARATUS (harness error): a prekey bundle"),
        EndpointList::new(Vec::new()).expect("APPARATUS (harness error): an empty endpoint list"),
        1,
        t,
    )
    .expect("APPARATUS (harness error): Q's pre-join")
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

    // ---- 3d. a board record's lifetime is judged to the millisecond (#562) -----------------
    // Two strangers each put their own pre-join, which lives `DEFAULT_TTL_MS` from its stamp: R1's
    // stamped to end 900 ms from now, R2's to have ended 300 ms ago. Sent in the first 100 ms of a
    // second, R1's end falls in the same whole second as now: a board that judged lifetimes in
    // whole seconds would call it over on arrival.
    let lifetime = vox_core::nat::store::DEFAULT_TTL_MS;
    let (r1, r2) = (stranger(0x83), stranger(0x84));
    let (_r1c, r1_v) = rt.block_on(connect(&r1, victim_addr, victim_id));
    let (_r2c, r2_v) = rt.block_on(connect(&r2, victim_addr, victim_id));
    let prejoin =
        |who: &Arc<vox_core::identity::composite::SoftwareRootSigner>, seed: u8, stamp| {
            let ring = PrekeyRing::generate(&**who, &[seed; 32], stamp)
                .expect("APPARATUS (harness error): a prekey ring");
            PreJoinRecord::build(
                &**who,
                &room,
                ring.bundle(&who.public_key())
                    .expect("APPARATUS (harness error): a prekey bundle"),
                EndpointList::new(Vec::new())
                    .expect("APPARATUS (harness error): an empty endpoint list"),
                1,
                stamp,
            )
            .expect("APPARATUS (harness error): a pre-join")
        };
    // Both pre-joins are built and signed **before** their second starts (a prekey ring takes tens
    // of ms to make, more on a slow machine), stamped for a second two seconds ahead; then they
    // are sent in that second's first 100 ms. Building them inside the window spun forever on a
    // Linux host where two rings take longer than the window: a watchdog abort, not a verdict.
    let mut tries = 0;
    let (r1_rec, r2_rec, second, sent_at) = loop {
        tries += 1;
        assert!(
            tries <= 10,
            "APPARATUS (staging not achieved): in 10 tries the two pre-joins were never sent within \
             the first 100 ms of the second they were stamped for"
        );
        let second = (hostile::now_ms() / 1_000 + 2) * 1_000;
        let built = (
            prejoin(&r1, 0x43, second + 900 - lifetime),
            prejoin(&r2, 0x44, second - 300 - lifetime),
        );
        let now = hostile::now_ms();
        if now >= second {
            continue;
        }
        std::thread::sleep(Duration::from_millis(second - now));
        let now = hostile::now_ms();
        if now - second < 100 {
            break (built.0, built.1, second, now);
        }
    };
    let (inside, inside_read) = rt.block_on(async {
        let put = put(&r1_v, &r1_rec.to_wire()).await;
        let mut client = RendezvousClient::open(&r1_v)
            .await
            .expect("PRODUCT (staging): the victim would not open a rendezvous stream");
        let read = client.get(&room, 0, RecordKinds::PREJOINS).await;
        client.finish();
        (put, read)
    });
    let read_at = hostile::now_ms();
    let past = rt.block_on(put(&r2_v, &r2_rec.to_wire()));
    let r1_served = inside_read.as_ref().is_ok_and(|set| {
        set.prejoins
            .iter()
            .any(|p| p.asserted_id() == r1.fingerprint())
    });
    println!(
        "[proof] step: a pre-join with 900 ms of its lifetime left, sent {} ms into a second \
         → {inside:?}, read back {} ms later: {}; one 300 ms past its lifetime → {past:?}",
        sent_at - second,
        read_at - sent_at,
        if r1_served { "served" } else { "not served" }
    );
    assert!(
        read_at - second < 900,
        "APPARATUS (staging not achieved): the put and the read ended {} ms into the second, past \
         the record's 900 ms; nothing below would measure the lifetime",
        read_at - second
    );
    assert!(
        inside.is_ok() && r1_served,
        "PRODUCT: a board record with 900 ms of its lifetime left must be taken and served; the \
         victim said {inside:?} and served {}",
        if r1_served { "it" } else { "no such record" }
    );
    assert!(
        past.as_ref().is_err_and(|e| e.contains("policy")),
        "PRODUCT: a board record 300 ms past its lifetime must be refused as expired; the victim \
         said {past:?}"
    );

    // ---- 3e. an author changes its claim at most once a second (#562) ----------------------
    // R3 puts a pre-join, then a changed one (new prekeys) stamped 500 ms later, then another
    // stamped a whole second after its first. Times are milliseconds now; the board still bounds a
    // changed claim to one a second, as it did when a change in the same second was not newer.
    let r3 = stranger(0x85);
    let (_r3c, r3_v) = rt.block_on(connect(&r3, victim_addr, victim_id));
    let t = hostile::now_ms();
    let changed = |seed: u8, seq: u64, stamp: u64| {
        let ring = PrekeyRing::generate(&*r3, &[seed; 32], stamp)
            .expect("APPARATUS (harness error): a prekey ring");
        PreJoinRecord::build(
            &*r3,
            &room,
            ring.bundle(&r3.public_key())
                .expect("APPARATUS (harness error): a prekey bundle"),
            EndpointList::new(Vec::new())
                .expect("APPARATUS (harness error): an empty endpoint list"),
            seq,
            stamp,
        )
        .expect("APPARATUS (harness error): a pre-join")
        .to_wire()
    };
    let first = rt.block_on(put(&r3_v, &changed(0x45, 1, t)));
    let too_soon = rt.block_on(put(&r3_v, &changed(0x46, 2, t + 500)));
    let a_second_on = rt.block_on(put(&r3_v, &changed(0x47, 3, t + 1_000)));
    println!(
        "[proof] step: one author's pre-join → {first:?}; changed 500 ms later → {too_soon:?}; \
         changed 1 s after the first → {a_second_on:?}"
    );
    assert!(
        first.is_ok() && a_second_on.is_ok(),
        "PRODUCT (staging): the board must take an author's pre-join, and a change of it a second \
         later ({first:?}, then {a_second_on:?})"
    );
    assert!(
        too_soon.as_ref().is_err_and(|e| e.contains("newer record")),
        "PRODUCT: an author's changed claim 500 ms after its last must be refused as not newer \
         (one change a second, as when times were seconds); the victim said {too_soon:?}"
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

    // ---- 5. forged authors on a member's own board, read by the victim ---------------------
    // F1 claims the creator's place; F2's witness names bravo, but a stranger signed it. Both
    // records are self-signed by the key they carry, so they verify as records: only the member
    // node's admission check can turn them away.
    let f1 = stranger(0x91);
    let f2 = stranger(0x92);
    let f2_forger = stranger(0x93);
    let t = hostile::now_ms();
    let f1_ring = PrekeyRing::generate(&f1, &[0x40; 32], t)
        .expect("APPARATUS (harness error): a prekey ring");
    let f1_bundle = MemberBundleRecord::build(
        &f1,
        &room,
        0,
        f1_ring
            .bundle(&f1.public_key())
            .expect("APPARATUS (harness error): a prekey bundle"),
        1,
        t,
        3_600_000,
        Admission::Creator,
    )
    .expect("APPARATUS (harness error): F1's bundle")
    .to_wire();
    let f2_ring = PrekeyRing::generate(&f2, &[0x41; 32], t)
        .expect("APPARATUS (harness error): a prekey ring");
    let mut f2_witness = JoinWitness::build(&f2_forger, &room, 0, &f2.fingerprint(), t)
        .expect("APPARATUS (harness error): F2's forged witness");
    f2_witness.witness_id = bravo_id;
    let f2_bundle = MemberBundleRecord::build(
        &f2,
        &room,
        0,
        f2_ring
            .bundle(&f2.public_key())
            .expect("APPARATUS (harness error): a prekey bundle"),
        1,
        t,
        3_600_000,
        Admission::Witnessed(Box::new(f2_witness)),
    )
    .expect("APPARATUS (harness error): F2's bundle")
    .to_wire();
    // F1's log, as its node would write it once admitted: a consent grant naming the victim,
    // then a post under a fresh sender key. The key is F1's to deliver, over its own connection.
    let room_ref = b32_encode(&room);
    let mut f1_chain = SenderChain::new(&room, 0, &f1.fingerprint(), 0, t)
        .expect("APPARATUS (harness error): F1's sender key");
    let (iteration, chain_key) = f1_chain.current_position();
    let f1_skdm = f1_chain
        .skdm_for(&f1, iteration, chain_key)
        .expect("APPARATUS (harness error): F1's key message");
    let grant = issue_consent_grant(&f1, &room, 0, victim_id, &f1_skdm, HistoryMode::ForwardOnly)
        .expect("APPARATUS (harness error): F1's consent grant")
        .to_wire();
    let post = Content::text(t * 1000, FORGED_POST)
        .expect("APPARATUS (harness error): F1's post")
        .to_canonical_vec();
    let sealed = f1_chain
        .encrypt(&post)
        .expect("APPARATUS (harness error): F1's sealed post")
        .to_wire();
    let mut f1_log = vec![feed_entry(&f1, room, &[], grant)];
    f1_log.push(feed_entry(&f1, room, &f1_log, sealed));
    let feed = Arc::new(Feed {
        author: f1.fingerprint(),
        head: f1_log[1].entry_hash(),
        entries: f1_log.iter().map(Entry::to_wire).collect(),
        served: AtomicUsize::new(0),
    });
    // The victim's own post: `vox room read` on it renders something, so an absence below
    // measures what it would render.
    let (ok, out, err) = vox_in(&victim_dir, &["room", "post", &room_ref, CONTROL_POST], "");
    assert!(
        ok,
        "PRODUCT (staging): the victim could not post in its own room: {out}{err}"
    );
    // Bravo's earlier connection goes, so the victim takes the new one — and a new connection
    // from a member is synced with at once (ADR-025 D2), which is when it reads bravo's board.
    drop((b1, bravo_v));
    std::thread::sleep(Duration::from_secs(1));
    let (_b3, bravo_v2) = rt.block_on(connect(&bravo, victim_addr, victim_id));
    let served = serve_board(
        &rt,
        Arc::clone(&bravo_v2),
        room,
        vec![f1_bundle, f2_bundle],
        Arc::clone(&feed),
    );
    let deadline = Instant::now() + CONTROL_PATIENCE;
    while served.answered.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
    }
    let (asked, answered) = (
        served.asked.load(Ordering::SeqCst),
        served.answered.load(Ordering::SeqCst),
    );
    println!(
        "[proof] step: bravo serves a board holding F1 (false creator) and F2 (forged witness) → \
         the victim asked it {asked} time(s), answered in full {answered}"
    );
    assert!(
        asked >= 1,
        "PRODUCT (staging): the victim never read the board of its member bravo within \
         {CONTROL_PATIENCE:?} of bravo connecting, so the forged authors were never offered to it"
    );
    assert!(
        answered >= 1,
        "APPARATUS (harness error): the victim asked bravo's board {asked} time(s) but the \
         test could not answer it in full"
    );
    // The victim admits from what it read before its session goes on; give its view a moment to
    // take any author it took, then bravo offers F1's log on a sync of its own.
    std::thread::sleep(Duration::from_secs(3));
    let mut sync = rt
        .block_on(open_sync(&bravo_v2, rt.handle().clone(), &room, 0))
        .expect("PRODUCT (staging): bravo's sync stream to the victim");
    let session = frontier_session_room(&mut sync, &*feed);
    let sent = feed.served.load(Ordering::SeqCst);
    println!(
        "[proof] step: bravo offers F1's consent grant and post from its log → {sent} entr(ies) \
         sent to the victim over all sessions; bravo's own session: {session:?}"
    );
    assert!(
        sent >= 2,
        "PRODUCT (staging): the victim never asked bravo for F1's feed, which bravo's log \
         advertised, so F1's post was never offered to it ({sent} sent; {session:?})"
    );
    // F1 delivers its key to the victim from the victim's own bundle, as a member's node does.
    let (_f1_ep, f1_v) = rt.block_on(connect(&f1, victim_addr, victim_id));
    let victim_bundle = rt
        .block_on(async {
            let mut c = RendezvousClient::open(&f1_v).await?;
            let set = c.get(&room, 0, RecordKinds::BUNDLES).await;
            c.finish();
            set
        })
        .unwrap_or_else(|e| {
            panic!("PRODUCT (staging): the test could not read the victim's board: {e:?}")
        })
        .bundles
        .into_iter()
        .find(|b| b.author_id == victim_id)
        .map(|b| b.prekey_bundle)
        .expect("PRODUCT (staging): the victim's board holds no bundle of its own");
    let mut bundle = victim_bundle;
    bundle.one_time_prekey = None;
    bundle.one_time_prekey_sig = None;
    let deadline = Instant::now() + Duration::from_secs(20);
    let (taken, said) = loop {
        let (taken, said) = rt.block_on(deliver_key(&f1_v, room, &bundle, &f1_skdm));
        if taken || Instant::now() >= deadline {
            break (taken, said);
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    println!("[proof] step: F1 delivers its sender key to the victim → {said}");
    // A post the victim took renders as soon as it holds the key; give it the time it takes.
    let deadline = Instant::now() + Duration::from_secs(if taken { 10 } else { 2 });
    let read = loop {
        let (ok, out, err) = vox_in(&victim_dir, &["room", "read", &room_ref], "");
        if out.contains(FORGED_POST) || Instant::now() >= deadline {
            break (ok, out, err);
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let (ok, read, err) = read;
    println!("[proof] the victim's `vox room read`:\n{read}");
    assert!(
        ok && read.contains(CONTROL_POST),
        "PRODUCT (staging): the victim's `vox room read` does not show its own post, so an absence \
         below would measure nothing (ok {ok}):\n{read}{err}"
    );
    let (ok, roster, err) = vox_in(&victim_dir, &["room", "roster", &room_ref], "");
    println!("[proof] the victim's `vox room roster`:\n{roster}");
    let listed = |id: &Digest32| roster.lines().any(|l| l.trim() == b32_encode(id));
    assert!(
        ok && listed(&bravo_id) && listed(&charlie_id),
        "PRODUCT (staging): the victim's `vox room roster` does not list its real members bravo \
         and charlie, so an absence below would measure nothing (ok {ok}):\n{roster}{err}"
    );
    let (f1_listed, f2_listed) = (listed(&f1.fingerprint()), listed(&f2.fingerprint()));
    let rendered = read.contains(FORGED_POST);
    assert!(
        !f1_listed && !f2_listed && !rendered,
        "PRODUCT: the victim admitted an author with no real evidence, read from a member's board: \
         its roster lists F1, who falsely claims to be the creator ({f1_listed}), or F2, whose \
         witness a stranger signed in bravo's name ({f2_listed}); its `vox room read` shows F1's \
         post ({rendered}), its key {said}:\n{roster}\n{read}"
    );
}

/// A member's roster of `team`, as `vox room roster` prints it.
fn roster(dir: &std::path::Path) -> String {
    let (ok, out, err) = vox_in(dir, &["room", "roster", "team"], "");
    format!("{}{out}{err}", if ok { "" } else { "(roster failed) " })
}

/// The admission notices `conn`'s node holds on its board for `room`, as the attacker reads them.
async fn notices_on(conn: &VoxConnection, room: &Digest32) -> Vec<Vec<u8>> {
    let mut client = RendezvousClient::open(conn)
        .await
        .expect("CANNOT MEASURE: the node's board stream did not open");
    let set = client
        .get(room, 0, RecordKinds::NOTICES)
        .await
        .expect("CANNOT MEASURE: the node's board did not answer a read");
    client.finish();
    set.notices.iter().map(|n| n.to_wire()).collect()
}

/// Whether `conn`'s node's board serves `who`'s address in `room`: its member record and its
/// bundle record, as the attacker reads them. What every other member reaches it by, and what an
/// anchor carries to it by.
async fn serves_member(conn: &VoxConnection, room: &Digest32, who: &Digest32) -> (bool, bool) {
    let mut client = RendezvousClient::open(conn)
        .await
        .expect("CANNOT MEASURE: the node's board stream did not open");
    let set = client
        .get(room, 0, RecordKinds::ALL)
        .await
        .expect("CANNOT MEASURE: the node's board did not answer a read");
    client.finish();
    (
        set.members.iter().any(|r| r.author_id == *who),
        set.bundles.iter().any(|b| b.author_id == *who),
    )
}

/// #520 — **every member learns of an admitted newcomer while it is offline, and an admission
/// replayed after a member left admits it nowhere.** The decider (2026-10-06): when a member lets a
/// newcomer in, every member learns of it, so every member's list matches; who reads whom does not
/// change. The lead's condition: a replayable admission must never make a departed node an author.
///
/// **Staging.** The host (`vox daemon`) creates `team`; carol, then spy, join it through the host
/// and stop, so neither is online for what follows; then x joins and **leaves** (`vox room leave`),
/// and stops. Before x leaves, the proof, holding spy's real key as an attacker would, reads x's
/// admission notice off the host's board. Everything asserted is what the shipped binary does.
///
/// **Asserted.**
/// 1. The host keeps x's admission notice on its board after x joined (#520): without it nobody
///    could learn of x while x is offline. Missing is `PRODUCT`.
/// 2. *Replay where the leave is known* (b): the attacker puts x's notice back on the host's board
///    after x left: **refused, `withdrawn`**.
/// 3. *Replay where it is not* (the withdraw notice): carol, who saw neither x's join nor its leave
///    nor any withdraw, starts again and syncs with the host. She learns spy, admitted while she
///    was away and offline since (the offline newcomer, from its notice), and **never lists x**;
///    and the attacker's replay of x's notice to carol's board is **refused, `withdrawn`**: the
///    withdraw reached her with the notice, first.
/// 4. *A rejoin outlives its old leave*: x joins again through the host, and the host's and
///    carol's boards serve x's member and bundle records within 60 s and still serve them 40 s of
///    syncs later. x's withdraw goes from board to board with the room's notices; it takes off
///    only what x signed before it left. Taking more left a rejoined member with no address on any
///    board: no member could reach it, no anchor would carry to it, and a member that trusted it
///    could release it no key.
/// 5. *A key that cannot go says why, once*: spy's own withdraw, stamped now, takes its bundle off
///    carol's board; spy, connected, stays a member. carol's operator trusts spy at a terminal, and
///    over the next 30 s carol's node says exactly once that her key to spy waits for a bundle. It
///    failed on every tick's retry and said nothing.
///
/// **Mutations**, one each: (1) the admitting member keeps no notice — red PRODUCT (no notice on
/// the host's board). (2) `nat::store::accept_notice` ignores withdraws — red PRODUCT (2: the
/// replay is taken). (3) `ChannelState::admit_from_notice` ignores withdraws and the board passes
/// withdraws on after notices — red PRODUCT (3: carol lists x). (4) `RendezvousStore::withdraw_member`
/// takes every record of the member, whenever signed — red PRODUCT (4: x's records gone). (5)
/// `release_key_to` says nothing when it has no session — red PRODUCT (5: said 0 times); (5b) it
/// says it on every retry — red PRODUCT (5: said many times).
#[test]
#[ignore = "real vox processes with production Argon2id and three real joins; run in release"]
fn an_admission_reaches_every_member_and_never_outlives_a_leave() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS (harness error): a temp dir");
    let (anchor_dir, host_dir, carol_dir, spy_dir, x_dir) = (
        profile_dir(tmp.path(), "anchor"),
        profile_dir(tmp.path(), "host"),
        profile_dir(tmp.path(), "carol"),
        profile_dir(tmp.path(), "spy"),
        profile_dir(tmp.path(), "x"),
    );
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n"))
        .expect("APPARATUS (harness error): the identity passphrase file");
    let (_anchor, spec) = hostile::anchor(&anchor_dir, "127.0.0.1:0");
    // Every identity made before any daemon starts: `fingerprint` makes it.
    let host_id = fingerprint(&host_dir);
    let carol_id = fingerprint(&carol_dir);
    let (spy_id, x_id) = (fingerprint(&spy_dir), fingerprint(&x_dir));
    let host = std::cell::RefCell::new(daemon("host", &host_dir, 0, &spec, &pass_file));
    let host_port = hostile::listening_port(&host_dir);
    let host_addr = format!("127.0.0.1:{host_port}")
        .parse()
        .expect("APPARATUS (harness error): the host's address");
    let (room, link) = create_room(&host_dir, "team", ROOM_PASS);
    let join = |name: &str, dir: &std::path::Path| {
        let mut d = daemon(name, dir, 0, &spec, &pass_file);
        let (ok, out, err) = vox_in(
            dir,
            &["room", "join", "--passphrase-file", "-", &link],
            ROOM_PASS,
        );
        assert!(
            ok,
            "PRODUCT (staging): {name} could not join: {out}{err}\n---- {name}'s daemon ----\n{}\n---- the host's daemon ----\n{}",
            d.transcript(),
            host.borrow_mut().transcript()
        );
        // Let the host file the new member before it goes.
        std::thread::sleep(Duration::from_secs(3));
        d
    };
    drop(join("carol", &carol_dir));
    drop(join("spy", &spy_dir));
    let x = join("x", &x_dir);

    // ---- 1. the host keeps x's notice ------------------------------------------------------
    let spy = member_signer(&spy_dir);
    let rt = Rt::new();
    let (_s1, spy_host) = rt.block_on(connect(&spy, host_addr, host_id));
    let x_hex = b32_encode(&x_id);
    let captured = rt
        .block_on(notices_on(&spy_host, &room))
        .into_iter()
        .find(|w| {
            vox_core::nat::notice::AdmissionNotice::from_wire(w).is_ok_and(|n| n.joiner() == x_id)
        });
    let Some(captured) = captured else {
        panic!("PRODUCT: x joined through the host, and the host's board holds no admission notice of x (#520)");
    };

    // x leaves, as a person does, and stops.
    let (ok, out, err) = vox_in(&x_dir, &["room", "leave", "team"], "");
    assert!(ok, "PRODUCT (staging): x could not leave: {out}{err}");
    std::thread::sleep(Duration::from_secs(3));
    drop(x);

    // ---- 2. a replay where the leave is known ---------------------------------------------
    let at_host = rt.block_on(put(&spy_host, &captured));
    assert!(
        matches!(&at_host, Err(why) if why.contains("withdrawn")),
        "PRODUCT: x left, and its admission notice put back on the host's board must be refused \
         as withdrawn; the board answered {at_host:?}"
    );

    // ---- 3. a replay where nothing of the leave was seen ----------------------------------
    // Started here rather than through `daemon`, so a daemon that does not come up says why.
    let mut carol_d = world::VoxProc::spawn(
        "carol",
        &carol_dir,
        &world::args(&[
            "daemon",
            "--listen",
            "127.0.0.1:0",
            "--anchor",
            &spec,
            "--passphrase-file",
            pass_file
                .to_str()
                .expect("APPARATUS (harness error): a UTF-8 path"),
        ]),
    );
    let up_by = Instant::now() + Duration::from_secs(90);
    let mut answered = vox_in(&carol_dir, &["room", "list"], "");
    while !answered.0 && Instant::now() < up_by {
        std::thread::sleep(Duration::from_millis(500));
        answered = vox_in(&carol_dir, &["room", "list"], "");
    }
    assert!(
        answered.0,
        "PRODUCT (staging): carol's daemon, started again, never answered `vox room list` within \
         90 s; it said:\n{}{}\nits daemon said:\n{}",
        answered.1,
        answered.2,
        carol_d.transcript()
    );
    let deadline = Instant::now() + Duration::from_secs(90);
    let spy_hex = b32_encode(&spy_id);
    let mut seen = roster(&carol_dir);
    while !seen.contains(&spy_hex) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        seen = roster(&carol_dir);
    }
    assert!(
        seen.contains(&spy_hex),
        "PRODUCT: spy was admitted while carol was away and has been offline since; back, carol \
         must list spy within 90 s (#520: every member learns of a newcomer, offline or not). \
         Her roster:\n{seen}"
    );
    let carol_port = hostile::listening_port(&carol_dir);
    let carol_addr = format!("127.0.0.1:{carol_port}")
        .parse()
        .expect("APPARATUS (harness error): carol's address");
    let (_s2, spy_carol) = rt.block_on(connect(&spy, carol_addr, carol_id));
    let at_carol = rt.block_on(put(&spy_carol, &captured));
    // Time for anything the replay could set off: a board that grew asks the node to admit.
    std::thread::sleep(Duration::from_secs(5));
    let after = roster(&carol_dir);
    eprintln!(
        "[proof] replay at the host: {at_host:?}; at carol: {at_carol:?}; carol's roster:\n{after}"
    );
    assert!(
        !after.contains(&x_hex) && !seen.contains(&x_hex),
        "PRODUCT: x left before carol came back, and carol must never list x, though its \
         admission was offered by the host and replayed to her; her roster:\n{after}"
    );
    assert!(
        matches!(&at_carol, Err(why) if why.contains("withdrawn")),
        "PRODUCT: x left, and its admission notice replayed to carol's board must be refused as \
         withdrawn: the withdraw reaches her with the notice; her board answered {at_carol:?}"
    );

    // ---- 4. x joins again: every board serves it, and keeps serving it --------------------
    // Its withdraw stays with every member and goes from board to board (#520); it must take
    // off only what x signed before it left, never the address x signs after joining again.
    let _x = join("x", &x_dir);
    let boards = [
        ("the host", host_addr, host_id),
        ("carol", carol_addr, carol_id),
    ];
    let read_boards = || -> Vec<(&str, (bool, bool))> {
        boards
            .iter()
            .map(|(name, addr, id)| {
                let (_s, conn) = rt.block_on(connect(&spy, *addr, *id));
                (*name, rt.block_on(serves_member(&conn, &room, &x_id)))
            })
            .collect()
    };
    let all_serve = |seen: &[(&str, (bool, bool))]| seen.iter().all(|(_, (m, b))| *m && *b);
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut seen = read_boards();
    while !all_serve(&seen) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_secs(1));
        seen = read_boards();
    }
    assert!(
        all_serve(&seen),
        "PRODUCT: x joined again, and within 60 s the host's and carol's boards must serve its \
         member and bundle records, which every member reaches it by; (member, bundle) served: \
         {seen:?}"
    );
    // Long enough for every member's next sync, each of which exchanges boards and passes the
    // room's withdraws on (SYNC_INTERVAL_SECS is 30).
    std::thread::sleep(Duration::from_secs(40));
    let kept = read_boards();
    eprintln!("[proof] rejoin: (member, bundle) served after 40 s of syncs: {kept:?}");
    assert!(
        all_serve(&kept),
        "PRODUCT: x joined again; 40 s of syncs later the host's and carol's boards must still \
         serve its member and bundle records; (member, bundle) served: {kept:?}"
    );

    // ---- 5. a key that cannot go says why, once --------------------------------------------
    // Staged as spy itself may: its own withdraw, stamped now, on carol's board takes its bundle
    // off, and spy stays a member of the room. spy is connected to carol (the attacker's
    // connection), so carol's key to it fails for want of a bundle to open a session from.
    let (_s3, spy_carol) = rt.block_on(connect(&spy, carol_addr, carol_id));
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("APPARATUS (harness error): the clock")
        .as_millis() as u64;
    let withdraw = vox_core::nat::withdraw::BoardWithdraw::build(
        spy.as_ref(),
        &room,
        0,
        vox_core::nat::withdraw::WithdrawScope::Member,
        now_ms,
    )
    .expect("APPARATUS (harness error): spy's withdraw");
    let taken = rt.block_on(put(&spy_carol, &withdraw.to_wire()));
    let (_, bundle_left) = rt.block_on(serves_member(&spy_carol, &room, &spy_id));
    assert!(
        taken.is_ok() && !bundle_left,
        "PRODUCT (staging): spy's own withdraw on carol's board must take its bundle off: put \
         {taken:?}, bundle still served: {bundle_left}"
    );
    let before = carol_d.transcript().len();
    let mut trust = std::process::Command::new(world::VOX);
    trust
        .args(["trust", "add", &spy_hex, "--name", "spy"])
        .env("VOX_DATA_DIR", &carol_dir)
        .env("VOX_CONFIG_DIR", carol_dir.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY);
    let (trusted, screen) = world::typed::keyring(&trust);
    assert!(
        trusted,
        "PRODUCT (staging): carol's `vox trust add` of spy, typed at a terminal, failed: {screen}"
    );
    // Thirty ticks of retries: said once over all of them, not on each.
    std::thread::sleep(Duration::from_secs(30));
    let transcript = carol_d.transcript();
    let said: Vec<&str> = transcript[before..]
        .lines()
        .filter(|l| {
            l.contains(&spy_hex[..20])
                && l.contains("waits: this node's board holds no prekey bundle of it yet")
        })
        .collect();
    eprintln!("[proof] carol's key to spy, its bundle off her board: {said:#?}");
    assert!(
        said.len() == 1,
        "PRODUCT: carol trusted spy, whose bundle her board does not hold; over 30 s her node must \
         say once that her key waits for one, and said {} time(s): {said:#?}",
        said.len()
    );
}
