//! RP-04 — **a stranger holding only a `.vox` address cannot stop a node**, through the shipped
//! binary.
//!
//! A room's channelID is its public `.vox` name; it is in every invite link. A stranger with
//! any valid Vox identity and that name can climb from `Unknown` to `PendingJoiner` by itself:
//!
//! 1. connect — any authenticated Vox identity is admitted;
//! 2. open `Rendezvous`, which `Unknown` may;
//! 3. PUT a self-signed pre-join record naming the room — it needs no membership, passphrase
//!    or proof of work, because a joiner has none of those yet;
//! 4. it is now `PendingJoiner`, which may open `Join`.
//!
//! The join request used to be read inside the node's actor, which is one task and the only
//! writer of channel state. A `Join` stream that says nothing then held the whole node for
//! `framing::FRAME_PATIENCE` (30 s), and the stranger could open another every 30 s for ever.
//!
//! **Staging.** The node under test is the real `vox` binary: an anchor (`vox node`) and a
//! victim `vox daemon` holding a room made with `vox room create`. The stranger is a
//! test-side client speaking the Vox wire protocol with a fresh identity and nothing else: no
//! `vox` command can publish a bare pre-join and then open a silent `Join` stream, and the
//! attacker is not a person using vox. It is handed only the victim's fingerprint and address
//! (what any peer dialling it has) and the room's id, which is the `.vox` name.
//!
//! **Asserted.**
//! 1. Step 3 is **accepted** by the victim. This is the load-bearing assertion: if it were
//!    refused the stranger would stay `Unknown`, its `Join` streams would be refused at the
//!    stream-kind gate, and everything after would measure a refusal against a node that could
//!    still be wide open. A refusal is `CANNOT MEASURE`, never a pass.
//! 2. While the stranger holds silent `Join` streams open (a new one every 2 s, none carrying a
//!    byte after its kind), **five `vox room post` on the victim, 2 s apart, each return in
//!    under 5 s**, and the victim's `vox room read` shows all five.
//! 3. The attack was still holding: the stranger's connection never closed, at least four
//!    silent streams were opened, and the first is still open at the victim's end — accepted
//!    and waited on, not refused.
//!
//! **Mutation that must turn it red.** Put the join-request read back on the actor: in
//! `node::actor`'s per-connection stream loop, forward `Inbound::Join` to the actor unread,
//! and have the actor `read_join_request(..).await` before `answer_inbound_join`. Each silent
//! stream then parks the actor for `FRAME_PATIENCE`, and the first post takes ~30 s.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use vox_core::identity::composite::{RootSigner, SoftwareRootSigner};
use vox_core::nat::multiaddr::EndpointList;
use vox_core::nat::record::PreJoinRecord;
use vox_core::nat::service::RendezvousClient;
use vox_core::node::prekeys::PrekeyRing;
use vox_core::transport::quic::VoxEndpoint;
use vox_core::transport::streams::{open_typed, StreamKind};
use world::{args, vox_once, VoxProc, IDENTITY, VOX};

/// An ordinary post must answer inside this while the attack holds. A loopback post takes
/// well under a second; the defect holds the node for 30 s per silent stream.
const PATIENCE: Duration = Duration::from_secs(5);
/// How many posts are measured.
const POSTS: usize = 5;
/// How often the attacker opens another silent stream.
const SILENT_EVERY: Duration = Duration::from_secs(2);
/// The pause between measured posts: five posts span 8 s, so at least four silent streams
/// are open by the last one.
const GAP: Duration = Duration::from_secs(2);
const SETUP: Duration = Duration::from_secs(120);
const ROOM_PASS: &str = "room passphrase";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn vox_in(data: &Path, argv: &[&str], stdin: &str) -> (bool, String, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run vox");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().expect("vox finished");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Run a one-shot `vox` verb, killing it (by PID) if it has not finished in `cap`. Returns
/// whether it succeeded, how long it ran, and what it printed. A verb still running at `cap`
/// is reported as a failure with its elapsed time, never waited on for ever.
fn vox_timed(data: &Path, argv: &[&str], cap: Duration) -> (bool, Duration, String) {
    let out_file = data.join(format!("timed-{}.out", std::process::id()));
    let t0 = Instant::now();
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .stdin(Stdio::null())
        .stdout(Stdio::from(std::fs::File::create(&out_file).unwrap()))
        .stderr(Stdio::from(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&out_file)
                .unwrap(),
        ))
        .spawn()
        .expect("run vox");
    let ok = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.success();
        }
        if t0.elapsed() >= cap {
            let _ = child.kill();
            let _ = child.wait();
            break false;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let took = t0.elapsed();
    (
        ok,
        took,
        std::fs::read_to_string(&out_file).unwrap_or_default(),
    )
}

/// The test-side client's runtime, shut down **without waiting** when dropped: a session
/// thread blocked on a victim that never answers must not hold the test open past its
/// verdict (ADR-018 §6).
struct Rt(Option<tokio::runtime::Runtime>);

impl std::ops::Deref for Rt {
    type Target = tokio::runtime::Runtime;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}

impl Drop for Rt {
    fn drop(&mut self) {
        if let Some(rt) = self.0.take() {
            rt.shutdown_background();
        }
    }
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn daemon(name: &str, data: &Path, listen: &str, spec: &str, pass_file: &Path) -> VoxProc {
    let p = VoxProc::spawn(
        name,
        data,
        &args(&[
            "daemon",
            "--listen",
            listen,
            "--anchor",
            spec,
            "--passphrase-file",
            pass_file.to_str().unwrap(),
        ]),
    );
    let deadline = Instant::now() + SETUP;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("CANNOT MEASURE: {name}'s daemon never answered `vox room list`");
}

fn fingerprint(data: &Path) -> [u8; 32] {
    let (ok, out, err) = vox_once(data, &args(&["id"]));
    assert!(ok, "CANNOT MEASURE: vox id: {err}");
    vox_core::node::link::b32_decode(out.trim(), "fingerprint")
        .unwrap_or_else(|e| panic!("CANNOT MEASURE: vox id printed no fingerprint ({e:?}): {out}"))
}

#[test]
#[ignore = "real vox processes and production Argon2id; run in release"]
fn a_stranger_with_only_the_rooms_name_does_not_stop_the_node() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, victim_dir) = (dir("anchor"), dir("victim"));
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).unwrap();

    // ---- the victim, through the shipped binary -----------------------------------------
    let mut anchor = VoxProc::spawn(
        "anchor",
        &anchor_dir,
        &args(&["node", "--listen", "127.0.0.1:0"]),
    );
    let spec = anchor
        .expect_line("the anchor's spec", |l| l.contains("@/ip4/127.0.0.1/udp/"))
        .split_whitespace()
        .find(|w| w.contains("@/ip4/127.0.0.1/udp/"))
        .unwrap()
        .to_owned();
    let victim_id = fingerprint(&victim_dir);
    let victim_listen = format!("127.0.0.1:{}", free_udp_port());
    let _victim = daemon("victim", &victim_dir, &victim_listen, &spec, &pass_file);
    let (ok, out, err) = vox_in(
        &victim_dir,
        &["room", "create", "--name", "team"],
        ROOM_PASS,
    );
    assert!(ok, "CANNOT MEASURE: room create: {out}\n{err}");
    let (_, list, _) = vox_once(&victim_dir, &args(&["room", "list"]));
    let prefix = list
        .split_whitespace()
        .next()
        .expect("CANNOT MEASURE: the new room in `vox room list`")
        .to_owned();
    let (ok, _, err) = vox_once(&victim_dir, &args(&["room", "post", &prefix, "hello"]));
    assert!(ok, "CANNOT MEASURE: first post: {err}");
    let (_, rows, _) = vox_once(&victim_dir, &args(&["room", "read", &prefix, "--json"]));
    // The room's id in full: the `.vox` name, and all the stranger is given.
    let room = rows
        .lines()
        .find_map(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .ok()?
                .get("room")?
                .as_str()
                .map(str::to_owned)
        })
        .expect("CANNOT MEASURE: the victim's read names its room");
    let cid = vox_core::node::link::b32_decode(&room, "room id").expect("a room id");

    // ---- the stranger: a fresh identity and the room's name, nothing else ---------------
    let rt = Rt(Some(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap(),
    ));
    let _enter = rt.enter();
    let stranger = SoftwareRootSigner::from_component_seeds(&[0xA7; 32], &[0x5C; 32]).unwrap();
    let (_endpoint, conn) = rt.block_on(async {
        let t = now();
        let endpoint = VoxEndpoint::bind(&stranger, "127.0.0.1:0".parse().unwrap()).unwrap();
        let conn = endpoint
            .connect(victim_listen.parse().unwrap(), victim_id, t)
            .await
            .expect("CANNOT MEASURE: step 1 — a valid identity must be admitted");

        // ---- step 3, the assertion this proof stands on ---------------------------------
        let ring = PrekeyRing::generate(&stranger, &[0x3B; 32], t).unwrap();
        let bundle = ring.bundle(&stranger.public_key()).unwrap();
        let prejoin = PreJoinRecord::build(
            &stranger,
            &cid,
            bundle,
            EndpointList::new(Vec::new()).unwrap(),
            1,
            t,
        )
        .unwrap();
        let mut rendezvous = RendezvousClient::open(&conn)
            .await
            .expect("CANNOT MEASURE: step 2 — `Unknown` may open a Rendezvous stream");
        if let Err(why) = rendezvous.put(&prejoin.to_wire()).await {
            panic!(
                "CANNOT MEASURE: step 3 — the victim refused the stranger's pre-join ({why:?}), \
                 so the stranger never became a PendingJoiner and its Join streams would be \
                 refused at the stream-kind gate: this would measure a refusal, not a wedge"
            );
        }
        // Finished before `Join` is opened: rendezvous is served inline on the connection's
        // stream loop, so an open one would block only the stranger's own next stream.
        drop(rendezvous);
        (endpoint, Arc::new(conn))
    });
    println!("[proof] escalation: the victim accepted the stranger's pre-join for the room");

    // ---- the attack holds while a person uses the node -------------------------------------
    let silent = Arc::new(std::sync::Mutex::new(Vec::new()));
    let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let attack = {
        let (conn, silent, opened) = (Arc::clone(&conn), Arc::clone(&silent), Arc::clone(&opened));
        rt.spawn(async move {
            loop {
                match open_typed(&conn, StreamKind::Join).await {
                    // Kept, never written to: zero bytes after the stream's kind.
                    Ok(pair) => {
                        silent.lock().unwrap().push(pair);
                        opened.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    Err(e) => eprintln!("[proof] could not open a silent stream: {e:?}"),
                }
                tokio::time::sleep(SILENT_EVERY).await;
            }
        })
    };
    let t0 = Instant::now();
    while opened.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "CANNOT MEASURE: no silent Join stream could be opened"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(500));

    let mut took = Vec::new();
    for i in 1..=POSTS {
        if i > 1 {
            std::thread::sleep(GAP);
        }
        let text = format!("posted while a stranger holds silent join streams {i}");
        let (ok, t, said) = vox_timed(&victim_dir, &["room", "post", &room, &text], PATIENCE * 8);
        println!(
            "[proof] post {i}/{POSTS}: ok={ok} in {t:?} with {} silent Join stream(s) open",
            opened.load(std::sync::atomic::Ordering::SeqCst)
        );
        took.push(t);
        assert!(
            ok && t < PATIENCE,
            "post {i} of {POSTS} on the victim took {t:?} (ok={ok}; bound {PATIENCE:?}) while a \
             stranger holding only the room's .vox name held silent Join streams open — anyone \
             ever handed an address can stop the node. It said: {said}"
        );
    }
    let (ok, t, read) = vox_timed(&victim_dir, &["room", "read", &room], PATIENCE * 8);
    let shown = (1..=POSTS)
        .filter(|i| {
            read.contains(&format!(
                "posted while a stranger holds silent join streams {i}"
            ))
        })
        .count();
    println!("[proof] read: ok={ok} in {t:?}, shows {shown}/{POSTS} posts");
    assert!(
        ok && t < PATIENCE && shown == POSTS,
        "the victim's `vox room read` took {t:?} (ok={ok}) and showed {shown} of {POSTS} posts \
         made during the attack:\n{read}"
    );

    // ---- the attack was still holding ---------------------------------------------------
    attack.abort();
    let streams = opened.load(std::sync::atomic::Ordering::SeqCst);
    let mut held = std::mem::take(&mut *silent.lock().unwrap());
    let first_still_held = rt.block_on(async {
        let (_send, recv) = held.first_mut().expect("a silent stream");
        let mut buf = [0u8; 16];
        tokio::time::timeout(Duration::from_millis(300), recv.read(&mut buf))
            .await
            .is_err()
    });
    assert!(
        first_still_held,
        "CANNOT MEASURE: the victim had already closed or refused the first silent Join stream, \
         so the attack was not holding"
    );
    assert!(
        conn.quinn().close_reason().is_none(),
        "CANNOT MEASURE: the stranger's connection closed during the attack: {:?}",
        conn.quinn().close_reason()
    );
    assert!(
        streams >= 4,
        "CANNOT MEASURE: only {streams} silent stream(s) were opened"
    );
    println!(
        "[proof] {POSTS} posts, slowest {:?}, while {streams} silent Join streams were held",
        took.iter().max().unwrap()
    );
    drop(held);
}
