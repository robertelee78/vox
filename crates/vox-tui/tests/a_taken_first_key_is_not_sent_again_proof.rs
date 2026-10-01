//! V210-95 (#289) — **a member who has taken the room's first key is remembered as having it**,
//! through the shipped binary.
//!
//! A sender key is recorded as delivered once the member answers that it took it (V210-88), and
//! the record is what keeps the node from sending it again. The room's first key is generation 0,
//! and `note_delivered` defaulted a missing record to 0 before comparing: a taken generation-0
//! key looked recorded already, so it was kept in memory and never written. After the node
//! restarted, nothing said the member held it, and the node sent the room's first key again, to
//! every member, on every restart.
//!
//! **Staging.** Every node is the real `vox` binary, set up as a person sets it up: an anchor, a
//! victim `vox daemon` that creates a room, and mallory, who joins it with `vox room join`.
//! Mallory's daemon is then stopped, and **her identity**, from the profile the binary wrote,
//! connects to the victim through a test-side wire client, which answers every key the victim
//! sends her by taking it (`KEY_TAKEN`) — what her own node does with a key it opens. No `vox`
//! command can count the keys a node is sent, which is why a wire client plays the member. The
//! victim trusts mallory (`vox trust add`); its consent writes her the room's first key, and she
//! takes it. The victim's daemon is then stopped and started again, as after a reboot (it reopens
//! the room by itself, #208), and mallory's identity connects to it again. One arm stops it with
//! SIGTERM; the other **kills it with SIGKILL** once her answer has had time to reach it, as a
//! crash or a power cut would, so the delivery must be in the store by then and not merely written
//! out on a clean stop.
//!
//! **Asserted.** In [`WATCH`] after the restart, the victim sends mallory **no key**: she took it,
//! and the node remembers. `CANNOT MEASURE` if the first key never reached her before the restart,
//! or if the restarted victim opened no stream to her at all in [`WATCH`] (then it never reached
//! her, and "no key" would measure nothing).
//!
//! **Mutation that must turn it red.** `note_delivered` defaulting a missing record to 0 before it
//! compares, as before: generation 0 is never written, and the restarted victim sends it again.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/raw_sync.rs"]
mod raw_sync;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;
#[path = "support/world.rs"]
mod world;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vox_core::node::pairwise_stream::{PairwiseFrame, KEY_TAKEN, MAX_PAIRWISE_FRAME};
use vox_core::node::paths::Paths;
use vox_core::transport::framing::read_frame_within;
use vox_core::transport::quic::VoxConnection;
use vox_core::transport::streams::StreamKind;
use world::{args, vox_once, VoxProc, IDENTITY, VOX};

/// How long the consent has to put its first key on mallory's connection.
const FIRST_KEY_WITHIN: Duration = Duration::from_secs(45);
/// How long after the restart the victim is watched for a key sent again: a key owed is sent on
/// the next tick after the member is reached, within a few seconds.
const WATCH: Duration = Duration::from_secs(30);
const SETUP: Duration = Duration::from_secs(120);
const ROOM_PASS: &str = "room passphrase";

/// What mallory's identity saw on one connection: every stream the victim opened, and which of
/// them carried a key.
#[derive(Debug, Default)]
struct Seen {
    streams: usize,
    keys: Vec<Duration>,
}

/// Answer every stream the victim opens on `conn` as mallory's node would: a sync is answered as a
/// member, and a key is taken (`KEY_TAKEN`). Records what arrived, timed from `t0`.
fn answer_as_mallory(rt: &Rt, conn: Arc<VoxConnection>, t0: Instant) -> Arc<Mutex<Seen>> {
    let seen: Arc<Mutex<Seen>> = Arc::new(Mutex::new(Seen::default()));
    let record = Arc::clone(&seen);
    rt.spawn(async move {
        while let Ok((kind, mut send, mut recv)) =
            vox_core::transport::streams::accept_typed(&conn).await
        {
            let record = Arc::clone(&record);
            tokio::spawn(async move {
                record.lock().unwrap().streams += 1;
                if kind != StreamKind::Pairwise {
                    let Ok((_cid, _epoch)) =
                        vox_core::node::syncstream::read_sync_request(&mut recv).await
                    else {
                        return;
                    };
                    let t = vox_core::node::syncstream::accept_sync(
                        tokio::runtime::Handle::current(),
                        send,
                        recv,
                    );
                    let _ = tokio::task::spawn_blocking(move || {
                        raw_sync::session(t, &raw_sync::Ask::Everything, None)
                    })
                    .await;
                    return;
                }
                let mut key = false;
                while let Ok(Some(f)) =
                    read_frame_within(&mut recv, MAX_PAIRWISE_FRAME, Duration::from_secs(5)).await
                {
                    match PairwiseFrame::from_frame(&f) {
                        Ok(PairwiseFrame::Skdm { .. }) => {
                            key = true;
                            break;
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                if key {
                    record.lock().unwrap().keys.push(t0.elapsed());
                    let _ = send.write_all(&[KEY_TAKEN]).await;
                }
                let _ = send.finish();
            });
        }
    });
    seen
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

/// How the victim's daemon goes down before it is started again.
#[derive(Clone, Copy, Debug)]
enum Halt {
    /// SIGTERM: a clean stop, as `vox` is stopped from tmux or systemd.
    Term,
    /// SIGKILL: a crash or a power cut, with no chance to write anything on the way out.
    Kill,
}

/// Stop a process by its PID, with SIGTERM or SIGKILL, and reap it.
fn stop(mut p: VoxProc, halt: Halt) {
    let signal = match halt {
        Halt::Term => "-TERM",
        Halt::Kill => "-KILL",
    };
    let _ = Command::new("kill")
        .args([signal, &p.child.id().to_string()])
        .status();
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if matches!(p.child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // Drop kills it by PID.
}

fn fingerprint(data: &Path) -> [u8; 32] {
    let (ok, out, err) = vox_once(data, &args(&["id"]));
    assert!(ok, "CANNOT MEASURE: vox id: {err}");
    vox_core::node::link::b32_decode(out.trim(), "fingerprint")
        .unwrap_or_else(|e| panic!("CANNOT MEASURE: vox id printed no fingerprint ({e:?}): {out}"))
}

#[test]
#[ignore = "real vox processes, production Argon2id and a real join; run in release"]
fn a_taken_first_key_is_not_sent_again_after_a_restart() {
    taken_first_key_after(Halt::Term);
}

#[test]
#[ignore = "real vox processes, production Argon2id and a real join; run in release"]
fn a_taken_first_key_is_not_sent_again_after_a_crash() {
    taken_first_key_after(Halt::Kill);
}

fn taken_first_key_after(halt: Halt) {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).unwrap();
        d
    };
    let (anchor_dir, victim_dir, mallory_dir) = (dir("anchor"), dir("victim"), dir("mallory"));
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).unwrap();

    // ---- staging, all through the shipped binary ----------------------------------------
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
    let mallory_id = fingerprint(&mallory_dir);
    let mallory_b32 = vox_core::node::link::b32_encode(&mallory_id);
    let victim_port = free_udp_port();
    let victim_listen = format!("127.0.0.1:{victim_port}");
    let victim = daemon("victim", &victim_dir, &victim_listen, &spec, &pass_file);
    let mallory = daemon("mallory", &mallory_dir, "127.0.0.1:0", &spec, &pass_file);

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
    let (ok, link, err) = vox_once(&victim_dir, &args(&["room", "invite", &prefix]));
    assert!(ok, "CANNOT MEASURE: room invite: {err}");
    let link = link.trim().to_owned();
    let joined = (1..=6).any(|attempt| {
        let (ok, out, err) = vox_in(
            &mallory_dir,
            &["room", "join", &link, "--name", "team"],
            ROOM_PASS,
        );
        if !ok {
            eprintln!("[proof] mallory's join attempt {attempt} refused: {out} {err}");
            std::thread::sleep(Duration::from_secs(5));
        }
        ok
    });
    assert!(joined, "CANNOT MEASURE: mallory could not join the room");

    // Mallory's node goes; her identity stays, in the profile the binary wrote.
    stop(mallory, Halt::Term);

    let rt = Rt(Some(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap(),
    ));
    let _enter = rt.enter();
    let mallory_paths = Paths::resolve(
        "default",
        Some(&mallory_dir),
        Some(&mallory_dir.join("cfg")),
    )
    .unwrap();
    let connect = |rt: &Rt| {
        rt.block_on(async {
            let endpoint = raw_sync::endpoint_as_member(&mallory_paths, IDENTITY.as_bytes()).await;
            let deadline = Instant::now() + SETUP;
            loop {
                match endpoint
                    .connect(victim_listen.parse().unwrap(), victim_id, raw_sync::now())
                    .await
                {
                    Ok(conn) => break (endpoint, Arc::new(conn)),
                    Err(e) if Instant::now() < deadline => {
                        let _ = e;
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(e) => panic!("CANNOT MEASURE: mallory's identity did not connect: {e:?}"),
                }
            }
        })
    };

    // ---- before: the victim trusts mallory, and she takes the room's first key -----------
    let (endpoint, conn) = connect(&rt);
    let before = answer_as_mallory(&rt, Arc::clone(&conn), Instant::now());
    let (ok, out, err) = vox_in(
        &victim_dir,
        &["trust", "add", &mallory_b32, "--name", "mallory"],
        "",
    );
    assert!(
        ok,
        "CANNOT MEASURE: the victim could not trust mallory: {out}\n{err}"
    );
    let deadline = Instant::now() + FIRST_KEY_WITHIN;
    while before.lock().unwrap().keys.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    let taken = before.lock().unwrap().keys.len();
    assert!(
        taken >= 1,
        "CANNOT MEASURE: no key reached mallory within {FIRST_KEY_WITHIN:?} of the victim \
         trusting her"
    );
    // The victim records the key as delivered when her answer reaches it.
    std::thread::sleep(Duration::from_secs(3));
    let taken = before.lock().unwrap().keys.len();

    // ---- the victim restarts, and mallory's identity connects again ---------------------
    drop(conn);
    drop(endpoint);
    stop(victim, halt);
    let _victim = daemon("victim", &victim_dir, &victim_listen, &spec, &pass_file);
    let (_endpoint, conn) = connect(&rt);
    let after = answer_as_mallory(&rt, Arc::clone(&conn), Instant::now());
    std::thread::sleep(WATCH);
    let (streams, resent) = {
        let a = after.lock().unwrap();
        (a.streams, a.keys.clone())
    };
    println!(
        "[proof] {halt:?}: before the restart mallory took {taken} key(s); in {WATCH:?} after it \
         the victim opened {streams} stream(s) to her, {} of them with a key: {resent:?}",
        resent.len()
    );
    assert!(
        streams >= 1,
        "CANNOT MEASURE: the restarted victim opened no stream to mallory in {WATCH:?}"
    );
    assert!(
        resent.is_empty(),
        "after a {halt:?} the restarted victim sent mallory the room's key again ({} time(s), at \
         {resent:?}) though she had taken it: it did not remember the delivery",
        resent.len()
    );
    drop(anchor.child.kill());
}
