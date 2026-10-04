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
//! and the node remembers. `PRODUCT (staging)` if the first key never reached her before the restart,
//! or if, after [`WATCH`], **a key the restarted victim does owe her** does not reach her: the
//! victim stops trusting her and trusts her again (`vox trust remove`, `vox trust add`), which
//! rotates its key and consents to her afresh, and that key must arrive on the same connection
//! within [`FIRST_KEY_WITHIN`]. That is the positive control: it shows the key-delivery path of
//! the restarted node reaches her, so "no key in [`WATCH`]" is the node remembering, not a path
//! that never ran. (Counting any stream, as this did, proved only that a sync ran; a node that
//! owes nothing opens no pairwise stream at all, so a pairwise-stream count cannot be required.)
//!
//! **Which side a red is on.** A key sent again, or a daemon that would not stop on SIGTERM, is
//! `PRODUCT:`; a `vox` step of the setup that failed, or a key the node owed that never came, is
//! `PRODUCT (staging):`; mallory's own connection not made is `PRODUCT (staging):`; a fault of this proof's own (a runtime,
//! a file, a signal it could not send) is `APPARATUS:`. Mallory joins **once**: a join turned away
//! is the product's red, not something to retry past.
//!
//! **Mutation that must turn it red.** `note_delivered` defaulting a missing record to 0 before it
//! compares, as before: generation 0 is never written, and the restarted victim sends it again.

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
    /// The pairwise streams among them: the path a key is delivered on.
    pairwise: usize,
    keys: Vec<Duration>,
}

fn lock(seen: &Mutex<Seen>) -> std::sync::MutexGuard<'_, Seen> {
    seen.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
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
                lock(&record).streams += 1;
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
                lock(&record).pairwise += 1;
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
                    lock(&record).keys.push(t0.elapsed());
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
        .unwrap_or_else(|e| panic!("APPARATUS: cannot start vox {argv:?}: {e}"));
    child
        .stdin
        .take()
        .expect("APPARATUS: vox was started without a stdin pipe")
        .write_all(stdin.as_bytes())
        .unwrap_or_else(|e| panic!("APPARATUS: cannot write vox {argv:?}'s stdin: {e}"));
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot wait for vox {argv:?}: {e}"));
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
                .expect("APPARATUS: the passphrase file's path is not UTF-8"),
        ]),
    );
    let mut p = p;
    let deadline = Instant::now() + SETUP;
    while Instant::now() < deadline {
        if vox_once(data, &args(&["room", "list"])).0 {
            return p;
        }
        if matches!(p.child.try_wait(), Ok(Some(_))) && ports::bind_refused(&p.transcript()) {
            panic!(
                "{}: {name}'s daemon on {listen}:\n{}",
                ports::APPARATUS_BIND,
                p.transcript()
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("PRODUCT: {name}'s `vox daemon` never answered `vox room list` within {SETUP:?}");
}

/// How the victim's daemon goes down before it is started again.
#[derive(Clone, Copy, Debug)]
enum Halt {
    /// SIGTERM: a clean stop, as `vox` is stopped from tmux or systemd.
    Term,
    /// SIGKILL: a crash or a power cut, with no chance to write anything on the way out.
    Kill,
}

/// Stop a process by its PID, with SIGTERM or SIGKILL, and reap it. The signal must be sent
/// (APPARATUS); a daemon must stop on it (PRODUCT for SIGTERM; a SIGKILL that did not end it is
/// APPARATUS, since nothing a process does can survive one).
fn stop(mut p: VoxProc, halt: Halt) {
    let signal = match halt {
        Halt::Term => "-TERM",
        Halt::Kill => "-KILL",
    };
    let sent = Command::new("kill")
        .args([signal, &p.child.id().to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(sent, "APPARATUS: {signal} could not be sent to {}", p.name);
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if matches!(p.child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    match halt {
        Halt::Term => {
            let said = p.transcript();
            panic!(
                "PRODUCT: {}'s `vox daemon` did not stop within 20 s of SIGTERM\n{said}",
                p.name
            )
        }
        Halt::Kill => panic!("APPARATUS: {} was still running 20 s after SIGKILL", p.name),
    }
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
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let dir = |n: &str| {
        let d = tmp.path().join(n);
        std::fs::create_dir_all(d.join("cfg"))
            .unwrap_or_else(|e| panic!("APPARATUS: cannot make {}: {e}", d.display()));
        d
    };
    let (anchor_dir, victim_dir, mallory_dir) = (dir("anchor"), dir("victim"), dir("mallory"));
    let pass_file = tmp.path().join("identity.pass");
    std::fs::write(&pass_file, format!("{IDENTITY}\n"))
        .expect("APPARATUS: cannot write the passphrase file");

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
        .expect("APPARATUS: the matched spec line has no spec word")
        .to_owned();

    let victim_id = fingerprint(&victim_dir);
    let mallory_id = fingerprint(&mallory_dir);
    let mallory_b32 = vox_core::node::link::b32_encode(&mallory_id);
    let victim = daemon("victim", &victim_dir, "127.0.0.1:0", &spec, &pass_file);
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
    let (ok, link, err) = vox_once(&victim_dir, &args(&["room", "invite", &prefix]));
    assert!(ok, "PRODUCT (staging): room invite: {err}");
    let link = link.trim().to_owned();
    let (joined, out, err) = vox_in(
        &mallory_dir,
        &[
            "room",
            "join",
            "--passphrase-file",
            "-",
            &link,
            "--name",
            "team",
        ],
        ROOM_PASS,
    );
    assert!(
        joined,
        "PRODUCT: mallory's `vox room join` was refused: {out}\n{err}"
    );

    // Mallory's node goes; her identity stays, in the profile the binary wrote.
    stop(mallory, Halt::Term);

    let rt = Rt(Some(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("APPARATUS: the member's runtime"),
    ));
    let _enter = rt.enter();
    let mallory_paths = Paths::resolve(
        "default",
        Some(&mallory_dir),
        Some(&mallory_dir.join("cfg")),
    )
    .expect("APPARATUS: mallory's profile paths");
    let victim_addr: std::net::SocketAddr = victim_listen
        .parse()
        .expect("APPARATUS: the victim's listen address");
    let connect = |rt: &Rt| {
        rt.block_on(async {
            let endpoint = raw_sync::endpoint_as_member(&mallory_paths, IDENTITY.as_bytes()).await;
            let deadline = Instant::now() + SETUP;
            loop {
                match endpoint
                    .connect(victim_addr, victim_id, raw_sync::now())
                    .await
                {
                    Ok(conn) => break (endpoint, Arc::new(conn)),
                    Err(e) if Instant::now() < deadline => {
                        let _ = e;
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(e) => {
                        panic!("PRODUCT (staging): mallory's identity did not connect: {e:?}")
                    }
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
        "PRODUCT (staging): the victim could not trust mallory: {out}\n{err}"
    );
    let deadline = Instant::now() + FIRST_KEY_WITHIN;
    while lock(&before).keys.is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    let taken = lock(&before).keys.len();
    assert!(
        taken >= 1,
        "PRODUCT (staging): no key reached mallory within {FIRST_KEY_WITHIN:?} of the victim \
         trusting her"
    );
    // The victim records the key as delivered when her answer reaches it.
    std::thread::sleep(Duration::from_secs(3));
    let taken = lock(&before).keys.len();

    // ---- the victim restarts, and mallory's identity connects again ---------------------
    drop(conn);
    drop(endpoint);
    stop(victim, halt);
    let mut victim = daemon("victim", &victim_dir, &victim_listen, &spec, &pass_file);
    let (_endpoint, conn) = connect(&rt);
    let after = answer_as_mallory(&rt, Arc::clone(&conn), Instant::now());
    std::thread::sleep(WATCH);
    let (streams, pairwise, resent) = {
        let a = lock(&after);
        (a.streams, a.pairwise, a.keys.clone())
    };
    println!(
        "[proof] {halt:?}: before the restart mallory took {taken} key(s); in {WATCH:?} after it \
         the victim opened {streams} stream(s) to her, {pairwise} pairwise, {} of them with a \
         key: {resent:?}",
        resent.len()
    );
    assert!(
        resent.is_empty(),
        "PRODUCT: after a {halt:?} the restarted victim sent mallory the room's key again ({} time(s), at \
         {resent:?}) though she had taken it: it did not remember the delivery",
        resent.len()
    );

    // ---- the positive control: a key the restarted victim does owe her reaches her -------------
    // Timed from before the re-trust: its consent may deliver the key before `vox trust add`
    // returns.
    let owed_at = Instant::now();
    for verb in [
        vec!["trust", "remove", &mallory_b32],
        vec!["trust", "add", &mallory_b32, "--name", "mallory"],
    ] {
        let (ok, out, err) = vox_in(&victim_dir, &verb, "");
        assert!(
            ok,
            "PRODUCT (staging): the positive control's `vox {}` failed: {out}\n{err}",
            verb.join(" ")
        );
    }
    while lock(&after).keys.is_empty() && owed_at.elapsed() < FIRST_KEY_WITHIN {
        std::thread::sleep(Duration::from_millis(100));
    }
    let owed = lock(&after).keys.len();
    println!(
        "[proof] {halt:?}: positive control — {owed} key(s) reached her {:?} after the victim began \
         re-trusting her",
        owed_at.elapsed()
    );
    assert!(
        owed >= 1,
        "PRODUCT (staging): a key the restarted victim owed mallory (it re-trusted her) did not reach \
         her within {FIRST_KEY_WITHIN:?}, so its key-delivery path never reached her and \"no key \
         sent again\" measures nothing. The restarted victim's daemon said:\n{}",
        victim.transcript()
    );
    drop(anchor.child.kill());
}
