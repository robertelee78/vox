//! V210-70 — **a stranger cannot crowd a real room off an open anchor**: however it keeps its own
//! rooms, however long the real room's members have been away, and whatever of the real room's own
//! records it puts there itself. Every node under test runs as the shipped binary.
//!
//! A full anchor board (4096 rooms from peers) gives up a room from **the source credited with the
//! most rooms** (`nat::source::Source`: the network a peer put records from). A room is credited to
//! a source only by a record the peer putting it **wrote** — its creator's genesis, a member's own
//! address or bundle record — whether or not the board already held it. What each test rules out:
//! 1. *A stranger keeps its rooms live.* It is the creator of every room it mints, so it can publish
//!    a member record for each as cheaply as it mints them. The oldest-idle-room rule this replaced
//!    then had nothing to evict, and a room created afterwards was not served.
//! 2. *A real room's members are away* longer than their records last (an address 2 h, a bundle
//!    7 d). Under that rule their room was the idle one, and the next stranger's room displaced it.
//! 3. *A stranger re-sends a real room's records.* A room's genesis and records are served to anyone
//!    who asks. Credited to whoever put them (c4), the re-send filed the room under the stranger's
//!    network, where its flood evicted it, and a real join failed in about 60 ms.
//! 4. *A stranger re-seeds a restarted anchor.* An anchor's board is in memory. Credited only when a
//!    put stored something new (c5), a stranger that put the room's records back first left the
//!    member's own republish a no-op: the room was credited to no one, and a flood of rooms
//!    credited to no one evicted it; a real join failed in about 26 ms.
//!
//! **Staging.** Every anchor is a default `vox node` (it serves any room published to it), listening
//! dual-stack on `[::]`. The victim `vox daemon` and the joiner are on `127.0.0.1`. The stranger is
//! a test-side client — no `vox` command publishes a genesis for a room it holds no state for, or
//! puts another peer's records — with two networks on this one machine, without sudo: `[::1]` and
//! a second loopback address ([`SECOND`]). On macOS that is `[fe80::1%lo0]`, the link-local address
//! lo0 always has; Linux gives lo no link-local address, but routes all of `127.0.0.0/8` to it, so
//! there it is `127.0.0.2`, an IPv4 address and so a source of its own (V210-125). The anchor
//! listens dual-stack, and the victim and the joiner are on `127.0.0.1`, a third source.
//!
//! **Asserted.**
//! 1. *Live flood:* the stranger publishes 4100 geneses and a live member record for each, from
//!    `[::1]`. The anchor still serves the victim's room in use; a room the victim creates
//!    afterwards is served; a real `vox room join` of it succeeds.
//! 2. *Away:* the anchor runs with its clock 8 days ahead (`VOX_TEST_CLOCK_STEP_MS`, which moves the seconds clock; since v0.3.0
//!    `VOX_TEST_CLOCK_SKEW_MS` moves only the milliseconds), so it holds the
//!    victim's genesis and no live record; after the same live flood it still serves the room.
//! 3. *Re-send:* the stranger fetches the room in use's member and bundle records and puts them back
//!    unchanged from `[::1]`, then floods 4100 rooms credited to both its networks (each genesis put
//!    from `[::1]` by its creator, and a witnessed second identity's own bundle from [`SECOND`]).
//!    The anchor still serves the room, and a real join of it succeeds.
//! 4. *Re-seed after a restart:* the victim's daemon is stopped (SIGSTOP), the anchor is restarted,
//!    and the stranger puts the room's genesis and records back from `[::1]`; the victim resumes and
//!    republishes. The stranger then floods 4100 rooms credited to no one (each genesis put by an
//!    identity that did not mint it, each bundle by one that did not write it). The anchor still
//!    serves the room, and a real join of it succeeds.
//!
//! A board that never filled, a record the anchor would not take, a member record the victim's
//! republish renewed rather than left as it was (the no-op path not exercised), or a setup step
//! that did not happen is `PRODUCT (staging)`. Every other red says what the product did.
//!
//! **Mutations that must turn it red.** `eviction_candidate` returning c3's rule (1, 2); crediting
//! a record to whoever put it (3); crediting a record only when it stored something new (4).

#![cfg(unix)]

#[path = "support/hostile.rs"]
mod hostile;
#[path = "support/test_knobs.rs"]
mod test_knobs;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hostile::{create_room, daemon, fingerprint, free_port, profile_dir, stranger, vox_in, Rt};
use vox_core::governance::genesis::{ChannelPolicy, Genesis, HistoryMode};
use vox_core::hash::Digest32;
use vox_core::identity::composite::{RootSigner, SoftwareRootSigner};
use vox_core::nat::multiaddr::EndpointList;
use vox_core::nat::record::{Admission, JoinWitness, MemberBundleRecord, RendezvousRecord};
use vox_core::nat::service::{RecordKinds, RendezvousClient};
use vox_core::node::prekeys::PrekeyRing;
use vox_core::transport::quic::{VoxConnection, VoxEndpoint};
use world::{args, VoxProc, IDENTITY};

const ROOM_PASS: &str = "room passphrase";
/// Stranger rooms: more than the 4096 a board holds from peers.
const ROOMS: usize = 4100;
/// The board is full once the stranger holds this many rooms on it: 4096, less the real room.
const FULL: usize = 4095;
/// Eight days, in milliseconds: past a bundle record's 7-day lifetime.
const AWAY_MS: i64 = 8 * 24 * 60 * 60 * 1000;
const JOIN_BOUND: Duration = Duration::from_secs(120);
/// How long the victim's room may take to reach its anchor with its records.
const PUBLISH_PATIENCE: Duration = Duration::from_secs(60);
/// How long the victim is given to republish to a restarted anchor.
const REPUBLISH_SETTLE: Duration = Duration::from_secs(45);
/// The whole binary's time bound: the default, or longer in a debug build, where the anchor
/// verifies tens of thousands of post-quantum signatures unoptimised.
const BUDGET: Duration = if cfg!(debug_assertions) {
    Duration::from_secs(2400)
} else {
    Duration::from_secs(900)
};

fn policy() -> ChannelPolicy {
    ChannelPolicy {
        history_mode: HistoryMode::ForwardOnly,
        ttl: 0,
        min_suite: vox_core::suite::SuiteFloor::DAY_ONE.id(),
    }
}

/// Start `vox node` dual-stack on `[::]:port`, with `env`; returns it with its IPv4 spec and
/// fingerprint.
fn dual_anchor(
    name: &str,
    data: &Path,
    port: u16,
    env: &[(&str, &str)],
) -> (VoxProc, String, Digest32) {
    let mut p = VoxProc::spawn_env(
        name,
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
    let fp = spec.split('@').next().expect("PRODUCT: fp@addr").to_owned();
    let id =
        vox_core::node::link::b32_decode(&fp, "anchor fingerprint").expect("PRODUCT: fingerprint");
    (p, format!("{fp}@/ip4/127.0.0.1/udp/{port}"), id)
}

/// The stranger's second network, as the reds name it.
#[cfg(target_os = "macos")]
const SECOND: &str = "[fe80::1%lo0]";
#[cfg(not(target_os = "macos"))]
const SECOND: &str = "127.0.0.2";

/// The scope id of `fe80::1` on `lo0`, the stranger's second network on macOS.
#[cfg(target_os = "macos")]
fn lo0_scope() -> u32 {
    let out = std::process::Command::new("ifconfig")
        .arg("lo0")
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not run ifconfig lo0: {e}"));
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text
        .lines()
        .find(|l| l.contains("fe80::1%lo0"))
        .unwrap_or_else(|| {
            panic!(
                "APPARATUS (precondition not met): no fe80::1 on lo0, so the stranger has no \
                 second network:\n{text}"
            )
        });
    let hex = line
        .split("scopeid 0x")
        .nth(1)
        .unwrap_or_else(|| panic!("APPARATUS: ifconfig shows fe80::1 with no scope id: {line}"))
        .trim();
    u32::from_str_radix(hex, 16)
        .unwrap_or_else(|e| panic!("APPARATUS: fe80::1's scope id {hex:?} is not hex: {e}"))
}

/// The stranger's two networks, as seen by an anchor on `port`: `[::1]`, and [`SECOND`].
struct Networks {
    anchor6: SocketAddr,
    anchor_ll: SocketAddr,
    local6: SocketAddr,
    local_ll: SocketAddr,
}

impl Networks {
    #[cfg(target_os = "macos")]
    fn to(port: u16) -> Self {
        use std::net::{Ipv6Addr, SocketAddrV6};
        let scope = lo0_scope();
        let ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        Self {
            anchor6: format!("[::1]:{port}")
                .parse()
                .expect("APPARATUS: a socket address the proof wrote"),
            anchor_ll: SocketAddr::V6(SocketAddrV6::new(ll, port, 0, scope)),
            local6: "[::1]:0"
                .parse()
                .expect("APPARATUS: a socket address the proof wrote"),
            local_ll: SocketAddr::V6(SocketAddrV6::new(ll, 0, 0, scope)),
        }
    }

    /// Linux routes all of `127.0.0.0/8` to lo, so `127.0.0.2` needs no setup; the anchor is
    /// reached at `127.0.0.1` from it.
    #[cfg(not(target_os = "macos"))]
    fn to(port: u16) -> Self {
        Self {
            anchor6: format!("[::1]:{port}")
                .parse()
                .expect("APPARATUS: a socket address the proof wrote"),
            anchor_ll: format!("127.0.0.1:{port}")
                .parse()
                .expect("APPARATUS: a socket address the proof wrote"),
            local6: "[::1]:0"
                .parse()
                .expect("APPARATUS: a socket address the proof wrote"),
            local_ll: "127.0.0.2:0"
                .parse()
                .expect("APPARATUS: a socket address the proof wrote"),
        }
    }
}

/// Connect as `signer` from `local` to the node at `addr`, pinned to `id`.
async fn connect_from(
    signer: &Arc<SoftwareRootSigner>,
    local: SocketAddr,
    addr: SocketAddr,
    id: Digest32,
) -> (VoxEndpoint, Arc<VoxConnection>) {
    let endpoint = VoxEndpoint::bind(Arc::clone(signer) as Arc<_>, local)
        .expect("APPARATUS: bind the stand-in peer's endpoint");
    let conn = endpoint
        .connect(addr, id, hostile::now())
        .await
        .unwrap_or_else(|e| panic!("PRODUCT (staging): connect {local} -> {addr}: {e:?}"));
    (endpoint, Arc::new(conn))
}

/// A room's records on a board, as wire records: (genesis, member records, bundle records).
type Held = (Option<Vec<u8>>, Vec<Vec<u8>>, Vec<Vec<u8>>);

/// Everything the board at `anchor` holds for `room`.
fn fetch(rt: &Rt, anchor: SocketAddr, id: Digest32, room: Digest32) -> Held {
    let reader = stranger(0x64);
    rt.block_on(async {
        let (_ep, conn) = hostile::connect(&reader, anchor, id).await;
        let mut client = RendezvousClient::open(&conn)
            .await
            .expect("PRODUCT (staging): a rendezvous stream to the anchor");
        let set = client
            .get(
                &room,
                0,
                RecordKinds::GENESIS
                    .or(RecordKinds::MEMBERS)
                    .or(RecordKinds::BUNDLES),
            )
            .await
            .expect("PRODUCT (staging): the anchor answered a GET");
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
    println!("[proof] the anchor holds of the room in use: {held:?}");
    assert!(
        held.0 && held.1 >= 1 && held.2 >= 1,
        "PRODUCT (staging): the room in use never reached its anchor with its records ({held:?})"
    );
}

/// Publish `ROOMS` geneses the stranger mints, each followed by a live member record for it,
/// from `[::1]`. Returns how many geneses and records the anchor took.
fn live_flood(rt: &Rt, anchor: SocketAddr, id: Digest32, skew_secs: u64) -> (usize, usize) {
    let inventor = stranger(0x63);
    rt.block_on(async {
        let (_ep, conn) = hostile::connect(&inventor, anchor, id).await;
        let mut client = RendezvousClient::open(&conn)
            .await
            .expect("PRODUCT (staging): a rendezvous stream to the anchor");
        let (mut geneses, mut records) = (0usize, 0usize);
        for i in 0..ROOMS {
            let mut nonce = [0u8; 16];
            nonce[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let g = Genesis::create_with_nonce(&inventor, hostile::now(), policy(), nonce)
                .expect("APPARATUS: build the stand-in peer's records");
            if client.put(&g.to_wire()).await.is_ok() {
                geneses += 1;
            }
            // Timestamped by the anchor's clock, so it is live there however that clock runs.
            let t = hostile::now() + skew_secs;
            let rec = RendezvousRecord::build(
                &inventor,
                &g.channel_id(),
                0,
                EndpointList::new(Vec::new())
                    .expect("APPARATUS: build the stand-in peer's records"),
                1,
                t,
                2 * 60 * 60,
            )
            .expect("APPARATUS: build the stand-in peer's records");
            if client.put(&rec.to_wire()).await.is_ok() {
                records += 1;
            }
        }
        client.finish();
        (geneses, records)
    })
}

/// How a two-network flood's rooms come to be credited.
#[derive(Clone, Copy, Debug)]
enum Credit {
    /// To both of the stranger's networks: each genesis put from `[::1]` by the identity that
    /// minted it, each bundle from [`SECOND`] by the identity that wrote it.
    Honest,
    /// To no one: each genesis put by the identity that did not mint it, each bundle by the one
    /// that did not write it. Both are stored; neither credits.
    Nobody,
}

/// The stranger, at the anchor on `nets`: first puts `first` (records it did not write) from
/// `[::1]`, then floods `ROOMS` rooms, each with a genesis minted by one identity and a live bundle
/// written by a second identity it witnessed in, credited as `credit` says. Returns the board's
/// answers to `first`, and how many geneses and bundles it took.
fn flood(
    rt: &Rt,
    nets: &Networks,
    id: Digest32,
    first: &[Vec<u8>],
    credit: Credit,
) -> (Vec<String>, usize, usize) {
    let inventor = stranger(0x73);
    // A second identity for the second network: the anchor keeps one connection per peer.
    let carrier = stranger(0x75);
    let t = hostile::now();
    let ring = PrekeyRing::generate(&carrier, &[0x3E; 32], t)
        .expect("APPARATUS: generate the stand-in peer's prekeys");
    let carrier_bundle = ring
        .bundle(&carrier.public_key())
        .expect("APPARATUS: build the stand-in peer's records");
    // Every room is signed up front, on every core: three post-quantum signatures a room.
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
                            let g = Genesis::create_with_nonce(inventor, now, policy(), nonce)
                                .expect("APPARATUS: build the stand-in peer's records");
                            let cid = g.channel_id();
                            let witness =
                                JoinWitness::build(inventor, &cid, 0, &carrier.fingerprint(), now)
                                    .expect("APPARATUS: build the stand-in peer's records");
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
                            .expect("APPARATUS: build the stand-in peer's records");
                            (i, g.to_wire(), rec.to_wire())
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut all: Vec<_> = workers
            .into_iter()
            .flat_map(|w| w.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect();
        all.sort_by_key(|(i, _, _)| *i);
        all.into_iter().map(|(_, g, b)| (g, b)).collect()
    });
    println!(
        "[proof] the stranger signed {} rooms in {:?}",
        rooms.len(),
        t0.elapsed()
    );
    // Who puts each genesis (from [::1]) and each bundle (from SECOND).
    let (on6_signer, onll_signer) = match credit {
        Credit::Honest => (&inventor, &carrier),
        Credit::Nobody => (&carrier, &inventor),
    };
    rt.block_on(async {
        let (_e1, c6) = connect_from(on6_signer, nets.local6, nets.anchor6, id).await;
        let (_e2, cll) = connect_from(onll_signer, nets.local_ll, nets.anchor_ll, id).await;
        let mut on6 = RendezvousClient::open(&c6)
            .await
            .expect("PRODUCT (staging): a rendezvous stream from [::1]");
        let mut onll = RendezvousClient::open(&cll).await.unwrap_or_else(|e| {
            panic!("PRODUCT (staging): no rendezvous stream from {SECOND}: {e:?}")
        });
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

fn assert_full(geneses: usize, others: usize) {
    assert!(
        geneses >= FULL && others >= FULL,
        "PRODUCT (staging): the anchor's board was never full of the stranger's rooms ({geneses} \
         geneses, {others} records taken)"
    );
}

/// A real `vox room join` of `link` from `dir`, which must succeed within the bound. A join that
/// fails and a join that succeeds too slowly are told apart.
fn real_join(dir: &Path, link: &str, name: &str, what: &str) {
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
    let took = t0.elapsed();
    println!("[proof] real join of {what}: ok={ok} in {took:?}");
    assert!(
        ok,
        "PRODUCT: a real joiner could not join {what} (after {took:?}): {out}{err}"
    );
    assert!(
        took < JOIN_BOUND,
        "PRODUCT: a real joiner joined {what}, but only after {took:?}, over the {JOIN_BOUND:?} bound"
    );
}

fn signal(proc: &VoxProc, sig: &str) {
    let pid = proc.child.id().to_string();
    let ok = std::process::Command::new("kill")
        .args([sig, &pid])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "APPARATUS: kill {sig} {pid} failed");
}

#[test]
#[ignore = "real vox processes with production Argon2id, a flood and a real join; run in release"]
fn a_stranger_keeping_its_rooms_live_does_not_crowd_out_a_new_room() {
    watchdog::arm_for(BUDGET);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let (anchor_dir, victim_dir, joiner_dir) = (
        profile_dir(tmp.path(), "anchor"),
        profile_dir(tmp.path(), "victim"),
        profile_dir(tmp.path(), "joiner"),
    );
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).expect("APPARATUS: write a staging file");
    let port = free_port();
    let (_anchor, spec, anchor_id) = dual_anchor("anchor", &anchor_dir, port, &[]);
    let anchor6: SocketAddr = format!("[::1]:{port}")
        .parse()
        .expect("APPARATUS: a socket address the proof wrote");
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
    assert_full(geneses, records);
    let (kept, _, _) = board(&rt, anchor6, anchor_id, first);
    println!("[proof] the anchor still serves the room in use: {kept}");
    assert!(
        kept,
        "PRODUCT: a stranger's live rooms displaced a room in use from the anchor"
    );

    let (second, second_link) = create_room(&victim_dir, "second", ROOM_PASS);
    std::thread::sleep(Duration::from_secs(3));
    let (served, _, _) = board(&rt, anchor6, anchor_id, second);
    println!("[proof] the anchor serves the room created after the live flood: {served}");
    assert!(
        served,
        "PRODUCT: a room created after a stranger filled the anchor with {ROOMS} rooms it keeps live is not \
         on the anchor: the stranger crowded it out"
    );
    let _joiner = daemon("joiner", &joiner_dir, free_port(), &spec, &pass_file);
    real_join(
        &joiner_dir,
        &second_link,
        "second",
        "a room created after a stranger's live flood",
    );
}

#[test]
#[ignore = "real vox processes with production Argon2id and a flood; run in release"]
fn a_room_whose_members_are_away_is_not_crowded_out() {
    test_knobs::require(&["VOX_TEST_CLOCK_STEP_MS"]);
    watchdog::arm_for(BUDGET);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let (anchor_dir, victim_dir) = (
        profile_dir(tmp.path(), "anchor"),
        profile_dir(tmp.path(), "victim"),
    );
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).expect("APPARATUS: write a staging file");
    let port = free_port();
    let skew = AWAY_MS.to_string();
    let (_anchor, spec, anchor_id) = dual_anchor(
        "anchor",
        &anchor_dir,
        port,
        &[("VOX_TEST_CLOCK_STEP_MS", &skew)],
    );
    let anchor6: SocketAddr = format!("[::1]:{port}")
        .parse()
        .expect("APPARATUS: a socket address the proof wrote");
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
        "PRODUCT (staging): the anchor should hold the away room's genesis and no live record \
         (it holds {held:?})"
    );

    let skew_secs = (AWAY_MS / 1000) as u64;
    let (geneses, records) = live_flood(&rt, anchor6, anchor_id, skew_secs);
    println!(
        "[proof] live flood from [::1]: the anchor took {geneses}/{ROOMS} geneses and \
         {records}/{ROOMS} live member records"
    );
    assert_full(geneses, records);
    let (kept, _, _) = board(&rt, anchor6, anchor_id, away);
    println!("[proof] the anchor still serves the away room: {kept}");
    assert!(
        kept,
        "PRODUCT: a stranger's {ROOMS} live rooms displaced from the anchor a room whose members have been \
         away past their records"
    );
}

#[test]
#[ignore = "real vox processes with production Argon2id, a flood and a real join; run in release"]
fn a_stranger_resending_a_rooms_records_does_not_get_it_evicted() {
    watchdog::arm_for(BUDGET);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let (anchor_dir, victim_dir, joiner_dir) = (
        profile_dir(tmp.path(), "anchor"),
        profile_dir(tmp.path(), "victim"),
        profile_dir(tmp.path(), "joiner"),
    );
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).expect("APPARATUS: write a staging file");
    let port = free_port();
    let (_anchor, spec, anchor_id) = dual_anchor("anchor", &anchor_dir, port, &[]);
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
    let (answers, geneses, taken) = flood(&rt, &nets, anchor_id, &resend, Credit::Honest);
    println!(
        "[proof] the stranger re-sent the room's {} record(s) from [::1]: {answers:?}; flood: \
         {geneses}/{ROOMS} geneses from [::1], {taken}/{ROOMS} bundles from {SECOND}, in {:?}",
        resend.len(),
        t0.elapsed()
    );
    assert!(
        answers.len() >= 2 && answers.iter().all(|a| a == "Ok(())"),
        "PRODUCT (staging): the anchor did not take the re-sent records ({answers:?}), so a credit \
         for them cannot be measured"
    );
    assert_full(geneses, taken);
    let kept = board(&rt, nets.anchor6, anchor_id, room);
    println!("[proof] after the flood the anchor holds of the room in use: {kept:?}");
    assert!(
        kept.0,
        "PRODUCT: a stranger re-sent a room's own records from its network and its flood then evicted the \
         room in use from the anchor ({kept:?}): the re-send credited the room to the stranger"
    );
    let _joiner = daemon("joiner", &joiner_dir, free_port(), &spec, &pass_file);
    real_join(
        &joiner_dir,
        &link,
        "first",
        "the room in use after a stranger re-sent its records and flooded the anchor",
    );
}

#[test]
#[ignore = "real vox processes with production Argon2id, an anchor restart, a flood and a real join; run in release"]
fn a_stranger_reseeding_a_restarted_anchor_does_not_get_a_room_evicted() {
    watchdog::arm_for(BUDGET);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let (anchor_dir, victim_dir, joiner_dir) = (
        profile_dir(tmp.path(), "anchor"),
        profile_dir(tmp.path(), "victim"),
        profile_dir(tmp.path(), "joiner"),
    );
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).expect("APPARATUS: write a staging file");
    let port = free_port();
    let (anchor, spec, anchor_id) = dual_anchor("anchor", &anchor_dir, port, &[]);
    let nets = Networks::to(port);
    fingerprint(&victim_dir);
    fingerprint(&joiner_dir);
    let victim = daemon("victim", &victim_dir, free_port(), &spec, &pass_file);
    let (room, link) = create_room(&victim_dir, "first", ROOM_PASS);
    let rt = Rt::new();
    await_published(&rt, nets.anchor6, anchor_id, room);
    let (genesis, members, bundles) = fetch(&rt, nets.anchor6, anchor_id, room);
    let seeded_member = members.first().cloned();
    let seed: Vec<Vec<u8>> = genesis.into_iter().chain(members).chain(bundles).collect();

    // The victim is held still while the anchor restarts, so the stranger is first to the board.
    signal(&victim, "-STOP");
    drop(anchor);
    let (_anchor, spec2, id2) = dual_anchor("anchor", &anchor_dir, port, &[]);
    assert!(
        spec2 == spec && id2 == anchor_id,
        "PRODUCT (staging): the restarted anchor came back as {spec2}, not {spec}"
    );
    let reseeder = stranger(0x77);
    let answers = rt.block_on(async {
        let (_e, c) = connect_from(&reseeder, nets.local6, nets.anchor6, anchor_id).await;
        let mut client = RendezvousClient::open(&c)
            .await
            .expect("PRODUCT (staging): a rendezvous stream from [::1]");
        let mut out = Vec::new();
        for wire in &seed {
            out.push(format!("{:?}", client.put(wire).await));
        }
        client.finish();
        out
    });
    println!(
        "[proof] the anchor restarted; the stranger put the room's {} record(s) back from [::1]: \
         {answers:?}",
        seed.len()
    );
    assert!(
        answers.len() >= 3 && answers.iter().all(|a| a == "Ok(())"),
        "PRODUCT (staging): the restarted anchor did not take the room the stranger put back \
         ({answers:?})"
    );
    signal(&victim, "-CONT");
    std::thread::sleep(REPUBLISH_SETTLE);
    let (_, members_now, _) = fetch(&rt, nets.anchor6, anchor_id, room);
    println!(
        "[proof] {REPUBLISH_SETTLE:?} after the victim resumed the anchor holds the stranger's copy \
         of its member record unchanged: {}",
        members_now.first() == seeded_member.as_ref()
    );
    assert!(
        members_now.first() == seeded_member.as_ref(),
        "PRODUCT (staging): the victim's republish renewed its member record, so the republish of a \
         record the board already holds was not exercised"
    );

    let t0 = Instant::now();
    let (_, geneses, taken) = flood(&rt, &nets, anchor_id, &[], Credit::Nobody);
    println!(
        "[proof] flood credited to no one: {geneses}/{ROOMS} geneses, {taken}/{ROOMS} bundles, in \
         {:?}",
        t0.elapsed()
    );
    assert_full(geneses, taken);
    let kept = board(&rt, nets.anchor6, anchor_id, room);
    println!("[proof] after the flood the restarted anchor holds of the room in use: {kept:?}");
    assert!(
        kept.0,
        "PRODUCT: the restarted anchor gave up the room in use to a flood credited to no one ({kept:?}), \
         though its member resumed {REPUBLISH_SETTLE:?} before the flood: the stranger put the \
         room back first, and the member's own puts credited nothing"
    );
    let _joiner = daemon("joiner", &joiner_dir, free_port(), &spec, &pass_file);
    real_join(
        &joiner_dir,
        &link,
        "first",
        "the room in use after a stranger re-seeded the restarted anchor and flooded it",
    );
}

#[test]
#[ignore = "real vox processes with production Argon2id, an anchor restart, a flood and a real join; run in release"]
fn a_non_creator_members_republish_keeps_a_room_credited() {
    // The room in use is kept alive by a member who did not create it: its creator is away, so the
    // creator's genesis re-put (which also credits) never happens. After a restart the stranger
    // re-seeds the room's records first, and the only thing that can credit the room is the live
    // member's own republish of its address record — a re-send the board already holds. If that
    // credits (the putter wrote it), the room is filed under the member's network and a flood
    // credited to no one leaves it; if a put must store something new to credit, the member's
    // re-send credits nothing, the room is credited to no one with the flood, and it is evicted.
    watchdog::arm_for(BUDGET);
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let (anchor_dir, creator_dir, member_dir, joiner_dir) = (
        profile_dir(tmp.path(), "anchor"),
        profile_dir(tmp.path(), "creator"),
        profile_dir(tmp.path(), "member"),
        profile_dir(tmp.path(), "joiner"),
    );
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).expect("APPARATUS: write a staging file");
    let port = free_port();
    let (anchor, spec, anchor_id) = dual_anchor("anchor", &anchor_dir, port, &[]);
    let nets = Networks::to(port);
    fingerprint(&creator_dir);
    fingerprint(&member_dir);
    fingerprint(&joiner_dir);
    let creator = daemon("creator", &creator_dir, free_port(), &spec, &pass_file);
    let (room, creator_link) = create_room(&creator_dir, "first", ROOM_PASS);
    let member = daemon("member", &member_dir, free_port(), &spec, &pass_file);
    let (ok, out, err) = vox_in(
        &member_dir,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            &creator_link,
            "--name",
            "first",
        ],
        ROOM_PASS,
    );
    assert!(
        ok,
        "PRODUCT (staging): the member could not join the room: {out}{err}"
    );

    // Both members' records on the board, and the member's own invite for the final join (the
    // creator will be away).
    let rt = Rt::new();
    let deadline = Instant::now() + PUBLISH_PATIENCE;
    let two = loop {
        let b = board(&rt, nets.anchor6, anchor_id, room);
        if b.1 >= 2 || Instant::now() >= deadline {
            break b;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    println!("[proof] the anchor holds of the room, two members expected: {two:?}");
    assert!(
        two.0 && two.1 >= 2,
        "PRODUCT (staging): both members' records never reached the anchor ({two:?})"
    );
    let (ok, member_link, err) = {
        let (listed, list, _) = world::vox_once(&member_dir, &args(&["room", "list"]));
        assert!(
            listed,
            "PRODUCT (staging): the member's vox room list failed"
        );
        let short = list
            .lines()
            .find(|l| l.contains("first"))
            .and_then(|l| l.split_whitespace().next())
            .expect("PRODUCT (staging): the member does not list the room");
        let (ok, link, err) = world::vox_once(&member_dir, &args(&["room", "invite", short]));
        (ok, link.trim().to_owned(), err)
    };
    assert!(ok, "PRODUCT (staging): the member could not invite: {err}");

    let (genesis, members, bundles) = fetch(&rt, nets.anchor6, anchor_id, room);
    let seeded_members = members.clone();
    // Bundles before address records: a member who joined is known to the board by its
    // witnessed bundle, so its address record is taken only once that bundle is there.
    let seed: Vec<Vec<u8>> = genesis.into_iter().chain(bundles).chain(members).collect();

    // The creator goes away for good; only the member keeps the room live. The member is held
    // still so the stranger is first to the restarted board.
    signal(&creator, "-STOP");
    signal(&member, "-STOP");
    drop(anchor);
    let (_anchor, spec2, id2) = dual_anchor("anchor", &anchor_dir, port, &[]);
    assert!(
        spec2 == spec && id2 == anchor_id,
        "PRODUCT (staging): the restarted anchor came back as {spec2}, not {spec}"
    );
    let reseeder = stranger(0x77);
    let answers = rt.block_on(async {
        let (_e, c) = connect_from(&reseeder, nets.local6, nets.anchor6, anchor_id).await;
        let mut client = RendezvousClient::open(&c)
            .await
            .expect("PRODUCT (staging): a rendezvous stream from [::1]");
        let mut out = Vec::new();
        for wire in &seed {
            out.push(format!("{:?}", client.put(wire).await));
        }
        client.finish();
        out
    });
    println!(
        "[proof] the anchor restarted; the stranger re-seeded the room's {} record(s) from [::1]: \
         {answers:?}",
        seed.len()
    );
    assert!(
        answers.len() >= 4 && answers.iter().all(|a| a == "Ok(())"),
        "PRODUCT (staging): the restarted anchor did not take the room the stranger put back \
         ({answers:?})"
    );
    // Only the member comes back; the creator stays away, so no genesis re-put by its creator can
    // credit the room.
    signal(&member, "-CONT");
    std::thread::sleep(REPUBLISH_SETTLE);
    let (_, members_now, _) = fetch(&rt, nets.anchor6, anchor_id, room);
    let held_unchanged = seeded_members.iter().all(|m| members_now.contains(m));
    println!(
        "[proof] {REPUBLISH_SETTLE:?} after the member resumed, the anchor still holds the \
         stranger's copies of the members' records unchanged: {held_unchanged} ({} record(s))",
        members_now.len()
    );
    assert!(
        held_unchanged,
        "PRODUCT (staging): a member's republish renewed its record rather than being a no-op the \
         board already held, so the re-send path was not exercised"
    );

    let t0 = Instant::now();
    let (_, geneses, taken) = flood(&rt, &nets, anchor_id, &[], Credit::Nobody);
    println!(
        "[proof] flood credited to no one: {geneses}/{ROOMS} geneses, {taken}/{ROOMS} bundles, in \
         {:?}",
        t0.elapsed()
    );
    assert_full(geneses, taken);
    let kept = board(&rt, nets.anchor6, anchor_id, room);
    println!(
        "[proof] after the flood the anchor holds of the room kept live by a non-creator: {kept:?}"
    );
    assert!(
        kept.0,
        "PRODUCT: the restarted anchor gave up a room whose creator is away and whose live member re-sent \
         its own record ({kept:?}): a member's own put of a record the board already holds credited \
         nothing, so the room was credited to no one with the flood"
    );
    let _joiner = daemon("joiner", &joiner_dir, free_port(), &spec, &pass_file);
    real_join(
        &joiner_dir,
        &member_link,
        "first",
        "a room whose creator is away, after a stranger re-seeded the restarted anchor and flooded it",
    );
}
