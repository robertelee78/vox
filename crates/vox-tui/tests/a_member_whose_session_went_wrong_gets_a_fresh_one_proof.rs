//! V210-71 (#262), follow-up A — **a member whose session with this node went wrong gets a fresh
//! one, not the same refusal for ever**, through the shipped binary.
//!
//! Every key this node sends a member is sealed under their pairwise session before its write is
//! tried, so each write that fails uses one message of the session up. A member whose writes
//! kept failing was pushed past the gap its ratchet accepts (`MAX_SKIP`, 1000): every key after
//! that did not open, and the member answered each one "the key did not open under the session
//! it holds" (`KeyRefusal::CannotOpen`). The same answer comes when the two ends simply hold
//! different sessions. The node kept the session and re-sent under it: refused the same way, for
//! good, and the member never read this node again. A refusal saying the member holds *no*
//! session was already cured by a fresh one (V210-78); `CannotOpen` now is too.
//!
//! **Staging.** Every node is the real `vox` binary, set up as a person sets it up: an anchor, a
//! victim `vox daemon` that creates a room, and mallory, who joins it with `vox room join` (so the
//! victim holds a join-path session with her). Mallory's daemon is then stopped, and **her
//! identity**, from the profile the binary wrote, connects to the victim through a test-side wire
//! client: no `vox` command can refuse a key it could open. The victim then trusts mallory
//! (`vox trust add`), and its consent writes her its sender key, under the join session, on that
//! connection. The client answers every stream that carries a key with the `CannotOpen` reset,
//! the answer a session past `MAX_SKIP` produces, and records how each stream began.
//!
//! **Asserted.** After the first key is refused, a later stream from the victim carrying a key
//! **opens a fresh session**: its first frame is a `Hello`. `PRODUCT (staging)` if no key reached
//! mallory at all (the consent never wrote one), or if none was sealed under an existing session
//! to begin with (then the first stream already carries a hello, and nothing is measured).
//!
//! **What this does not stage:** a thousand failed writes. A peer that withholds stream credit
//! cannot be configured through `vox` or this client; the ratchet's refusal past `MAX_SKIP` is the
//! `CannotOpen` answer staged here, so the cure is what is measured.
//!
//! **Mutation that must turn it red.** In `NetEvent::SkdmRefused`, forget the session on
//! `NoSession` only, as before: every retry is then a bare key under the dead session, and no
//! stream after the refusal opens with a hello.

#![cfg(unix)]

#[path = "support/ports.rs"]
mod ports;
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

use vox_core::node::pairwise_stream::{KeyRefusal, PairwiseFrame, MAX_PAIRWISE_FRAME};
use vox_core::node::paths::Paths;
use vox_core::transport::framing::read_frame_within;
use vox_core::transport::streams::StreamKind;
use world::{args, vox_once, VoxProc, IDENTITY, VOX};

/// How long the victim has to offer a fresh session after its first key is refused: a refused
/// key is re-sent after a 2 s backoff, doubling.
const FRESH_WITHIN: Duration = Duration::from_secs(45);
/// How long the consent has to put its first key on mallory's connection.
const FIRST_KEY_WITHIN: Duration = Duration::from_secs(45);
const SETUP: Duration = Duration::from_secs(120);
const ROOM_PASS: &str = "room passphrase";

/// One pairwise stream the victim opened: whether it began with a `Hello`, and whether it carried
/// a key, with when it arrived.
#[derive(Debug, Clone)]
struct Seen {
    at: Duration,
    hello_first: bool,
    key: bool,
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
        .expect("APPARATUS: run vox");
    child
        .stdin
        .take()
        .expect("APPARATUS: a piped stdio handle")
        .write_all(stdin.as_bytes())
        .expect("PRODUCT (staging): vox exited without reading its stdin");
    let out = child.wait_with_output().expect("APPARATUS: vox finished");
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
        self.0
            .as_ref()
            .expect("APPARATUS: a process the proof started")
    }
}

impl Drop for Rt {
    fn drop(&mut self) {
        if let Some(rt) = self.0.take() {
            rt.shutdown_background();
        }
    }
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
            pass_file
                .to_str()
                .expect("APPARATUS: a path that is not UTF-8"),
        ]),
    );
    let deadline = Instant::now() + SETUP;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("PRODUCT (staging): {name}'s daemon never answered `vox room list`");
}

/// Stop a process with SIGTERM by its PID and reap it.
fn stop(mut p: VoxProc) {
    let _ = Command::new("kill")
        .args(["-TERM", &p.child.id().to_string()])
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
    assert!(ok, "PRODUCT (staging): vox id: {err}");
    vox_core::node::link::b32_decode(out.trim(), "fingerprint").unwrap_or_else(|e| {
        panic!("PRODUCT (staging): vox id printed no fingerprint ({e:?}): {out}")
    })
}

#[test]
#[ignore = "real vox processes, production Argon2id and a real join; run in release"]
fn a_member_whose_session_went_wrong_is_offered_a_fresh_one() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg")).expect("APPARATUS: create a staging directory");
        d
    };
    let (anchor_dir, victim_dir, mallory_dir) = (dir("anchor"), dir("victim"), dir("mallory"));
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n")).expect("APPARATUS: write a staging file");

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
        .expect("APPARATUS: the line matched for the spec holds it")
        .to_owned();

    let victim_id = fingerprint(&victim_dir);
    let mallory_id = fingerprint(&mallory_dir);
    let mallory_b32 = vox_core::node::link::b32_encode(&mallory_id);
    let mut victim = daemon("victim", &victim_dir, "127.0.0.1:0", &spec, &pass_file);
    // Where the victim chose to listen, from its own report (#410).
    let victim_listen =
        ports::loopback_listen(&vox_once(&victim_dir, &args(&["status", "--json"])).1)
            .expect("PRODUCT (staging): the victim reports a loopback listen address")
            .to_string();
    let mallory = daemon("mallory", &mallory_dir, "127.0.0.1:0", &spec, &pass_file);

    let (ok, out, err) = vox_in(
        &victim_dir,
        &["room", "create", "--passphrase-file", "-", "--name", "team"],
        ROOM_PASS,
    );
    assert!(ok, "PRODUCT (staging): room create: {out}\n{err}");
    let (_, list, _) = vox_once(&victim_dir, &args(&["room", "list"]));
    let prefix = list
        .split_whitespace()
        .next()
        .expect("PRODUCT (staging): the new room in `vox room list`")
        .to_owned();
    let (ok, link, err) = vox_once(&victim_dir, &args(&["room", "link", &prefix]));
    assert!(ok, "PRODUCT (staging): room link: {err}");
    let link = link.trim().to_owned();
    let joined = (1..=6).any(|attempt| {
        let (ok, out, err) = vox_in(
            &mallory_dir,
            &["room", "join", "--passphrase-file", "-", &link],
            ROOM_PASS,
        );
        if !ok {
            eprintln!("[proof] mallory's join attempt {attempt} refused: {out} {err}");
            std::thread::sleep(Duration::from_secs(5));
        }
        ok
    });
    assert!(joined, "PRODUCT (staging): mallory could not join the room");

    // Mallory's node goes; her identity stays, in the profile the binary wrote.
    stop(mallory);

    let rt = Rt(Some(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("APPARATUS: start a runtime"),
    ));
    let _enter = rt.enter();
    let mallory_paths = Paths::resolve(
        "default",
        Some(&mallory_dir),
        Some(&mallory_dir.join("cfg")),
    )
    .expect("APPARATUS: resolve a profile's paths");
    let (_endpoint, conn) = rt.block_on(async {
        let endpoint = raw_sync::endpoint_as_member(&mallory_paths, IDENTITY.as_bytes()).await;
        let conn = endpoint
            .connect(
                victim_listen
                    .parse()
                    .expect("PRODUCT (staging): vox printed a listen address that does not parse"),
                victim_id,
                raw_sync::now(),
            )
            .await
            .expect(
                "PRODUCT (staging): the victim did not take a connection from mallory's identity",
            );
        (endpoint, Arc::new(conn))
    });

    // Every stream the victim opens: a sync is answered as a member would, a pairwise one is
    // recorded and, if it carries a key, refused with `CannotOpen`.
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
    let t0 = Instant::now();
    {
        let conn = Arc::clone(&conn);
        let seen = Arc::clone(&seen);
        rt.spawn(async move {
            while let Ok((kind, mut send, mut recv)) =
                vox_core::transport::streams::accept_typed(&conn).await
            {
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
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
                    let mut frames = Vec::new();
                    while let Ok(Some(f)) =
                        read_frame_within(&mut recv, MAX_PAIRWISE_FRAME, Duration::from_secs(5))
                            .await
                    {
                        match PairwiseFrame::from_frame(&f) {
                            Ok(frame) => frames.push(frame),
                            Err(_) => break,
                        }
                        if matches!(frames.last(), Some(PairwiseFrame::Skdm { .. })) {
                            break;
                        }
                    }
                    let key = frames
                        .iter()
                        .any(|f| matches!(f, PairwiseFrame::Skdm { .. }));
                    let hello_first = matches!(frames.first(), Some(PairwiseFrame::Hello { .. }));
                    if key {
                        let _ = send.reset(KeyRefusal::CannotOpen.code());
                    } else {
                        let _ = send.finish();
                    }
                    seen.lock()
                        .expect("APPARATUS: a lock the proof holds was poisoned")
                        .push(Seen {
                            at: t0.elapsed(),
                            hello_first,
                            key,
                        });
                });
            }
        });
    }

    // ---- the victim trusts mallory: its consent writes her the key ----------------------
    let (ok, out, err) = vox_in(
        &victim_dir,
        &["trust", "add", &mallory_b32, "--name", "mallory"],
        "",
    );
    assert!(
        ok,
        "PRODUCT (staging): the victim could not trust mallory: {out}\n{err}"
    );

    let keys = |seen: &Arc<Mutex<Vec<Seen>>>| -> Vec<Seen> {
        seen.lock()
            .expect("APPARATUS: a lock the proof holds was poisoned")
            .iter()
            .filter(|s| s.key)
            .cloned()
            .collect()
    };
    let deadline = Instant::now() + FIRST_KEY_WITHIN;
    while keys(&seen).is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    let first = keys(&seen).first().cloned();
    let Some(first) = first else {
        panic!(
            "PRODUCT (staging): no key reached mallory within {FIRST_KEY_WITHIN:?} of the victim \
             trusting her; streams seen: {:?}\nvictim:\n{}",
            seen.lock()
                .expect("APPARATUS: a lock the proof holds was poisoned"),
            victim.transcript()
        );
    };
    assert!(
        !first.hello_first,
        "PRODUCT (staging): the victim's first key already opened a fresh session (a hello first), so no \
         existing session was refused: {:?}",
        seen.lock()
            .expect("APPARATUS: a lock the proof holds was poisoned")
    );

    // ---- after the refusal: a later key opens a fresh session ---------------------------
    let deadline = Instant::now() + FRESH_WITHIN;
    let fresh = loop {
        let after: Vec<Seen> = keys(&seen).into_iter().skip(1).collect();
        if let Some(s) = after.iter().find(|s| s.hello_first) {
            break Some(s.clone());
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let all = seen
        .lock()
        .expect("APPARATUS: a lock the proof holds was poisoned")
        .clone();
    let later = keys(&seen).len().saturating_sub(1);
    println!(
        "[proof] first key at {:?} under the existing session, refused CannotOpen; {later} later \
         key(s); a fresh session (hello first) offered at {:?}; every stream: {all:?}",
        first.at,
        fresh.as_ref().map(|s| s.at)
    );
    assert!(
        fresh.is_some(),
        "PRODUCT: the victim never offered mallory a fresh session in {FRESH_WITHIN:?} after she refused \
         its key as not opening under the session it holds: {later} later key(s), each under the \
         same session, so she can never read it"
    );
    drop(anchor.child.kill());
}
