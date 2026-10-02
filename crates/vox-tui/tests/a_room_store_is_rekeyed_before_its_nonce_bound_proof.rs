//! V210-136 (#355) — **a room's at-rest key is rotated before AES-GCM's random-nonce bound**,
//! through the shipped binary.
//!
//! Every sealed store write draws a fresh random 96-bit nonce, and AES-GCM's bound for random
//! nonces is 2^32 seals per key. A room's store key never changed, so a long-lived room had no
//! bound at all. Now each sealed write is counted, and once a key has sealed `ROTATE_AT` times
//! (2^30) the room's whole store is re-sealed under the next data-key generation in one store
//! transaction, the old data key is wiped, and the store file is rewritten without the old
//! generation's pages. The threshold is lowered here through the `test-knobs`-only
//! `VOX_TEST_AT_REST_ROTATE_AT`, so a few posts cross it.
//!
//! Every step is a `vox` process with its own `VOX_DATA_DIR`/`VOX_CONFIG_DIR`, killed by its PID.
//! The one thing test-side code does is read the store file the binary wrote, after the binary
//! has stopped: what someone holding the disk sees.
//!
//! 1. **Rotation.** A room gets [`POSTS`] posts under the normal threshold, and the daemon stops.
//!    The ciphertext of every room segment is noted from `store.redb`. The daemon starts again
//!    with the threshold lowered, and is asserted to:
//!    - say generation ≥ 1 for the room in `vox status --json` (`at_rest_generation`);
//!    - read every post back;
//!    - leave none of the noted ciphertext anywhere in the profile's files once it has stopped
//!      (the rewrite of the store file, V210-40's lesson);
//!    - still read every post, at the new generation, after a plain restart.
//! 2. **A kill mid-rotation loses nothing.** With `VOX_TEST_AT_REST_ROTATE_PAUSE_MS` the daemon
//!    stops inside the re-seal transaction, before its commit, and says so; it is SIGKILLed
//!    there. Restarted, every post reads; restarted with the low threshold and no pause, the
//!    rotation completes and every post still reads.
//! 3. **A store from before generations opens unchanged.** The released previous binary
//!    (checked against its published SHA-256) writes a room; this build's daemon reads every
//!    post of it at generation 0.
//!
//! **Mutations.** No rotation (`rotate_at_rest_if_due` never re-seals): (1) is red, as PRODUCT,
//! on the generation. No store rewrite after a rotation: (1) is red on the old ciphertext still
//! in the file. A re-seal that commits in more than one transaction, or drops what it cannot
//! open, loses posts in (2).

#![cfg(unix)]

#[path = "support/world.rs"]
mod world;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/previous_release.rs"]
mod previous_release;

#[path = "support/test_knobs.rs"]
mod test_knobs;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use vox_core::atrest::store::SegmentKind;
use vox_core::node::store::Store;

use world::{IDENTITY, VOX};

const ROOM_PASS: &str = "the room passphrase";
/// Posts in each room: enough that the room's seals pass a lowered threshold many times over.
const POSTS: usize = 12;
/// The lowered threshold: crossed by the seals of creating a room and posting to it.
const LOW: &str = "8";
const PATIENCE: Duration = Duration::from_secs(120);

fn vox(exe: &Path, data: &Path, argv: &[&str], stdin: Option<&str>) -> (bool, String, String) {
    let mut child = Command::new(exe)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", data.join("cfg"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .env_remove("VOX_SESSION")
        .env_remove("VOX_ROOM")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: could not spawn {} {argv:?}: {e}", exe.display()));
    if let Some(s) = stdin {
        child
            .stdin
            .take()
            .expect("APPARATUS: a piped stdin")
            .write_all(s.as_bytes())
            .unwrap_or_else(|e| panic!("APPARATUS: could not write vox's stdin: {e}"));
    }
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not wait for vox {argv:?}: {e}"));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A running `vox daemon`, killed by its PID when dropped.
struct Daemon {
    child: Child,
    err: PathBuf,
}

impl Daemon {
    fn start(exe: &Path, data: &Path, tag: &str, env: &[(&str, &str)]) -> Self {
        let err = data.join(format!("daemon-{tag}.err"));
        let mut cmd = Command::new(exe);
        cmd.args(["daemon", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", data)
            .env("VOX_CONFIG_DIR", data.join("cfg"))
            .env_remove("VOX_TEST_AT_REST_ROTATE_AT")
            .env_remove("VOX_TEST_AT_REST_ROTATE_PAUSE_MS")
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&err).unwrap_or_else(
                |e| panic!("APPARATUS: could not create {}: {e}", err.display()),
            )));
        let mut child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("APPARATUS: could not spawn {} daemon: {e}", exe.display()));
        let mut pipe = child.stdin.take().expect("APPARATUS: a piped stdin");
        pipe.write_all(format!("{IDENTITY}\n").as_bytes())
            .unwrap_or_else(|e| panic!("APPARATUS: could not write the daemon's stdin: {e}"));
        drop(pipe);
        let d = Self { child, err };
        let deadline = Instant::now() + PATIENCE;
        while !vox(exe, data, &["room", "list"], None).0 {
            assert!(
                Instant::now() < deadline,
                "PRODUCT (staging): the daemon never answered `vox room list`; it said: {}",
                d.said()
            );
            std::thread::sleep(Duration::from_millis(250));
        }
        d
    }

    fn said(&self) -> String {
        std::fs::read_to_string(&self.err).unwrap_or_default()
    }

    /// Wait until the daemon has said `what`.
    fn until_said(&self, what: &str) {
        let deadline = Instant::now() + PATIENCE;
        while !self.said().contains(what) {
            assert!(
                Instant::now() < deadline,
                "PRODUCT: the daemon never said {what:?}; it said: {}",
                self.said()
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// SIGTERM, a clean stop, and wait for it.
    fn stop(mut self) {
        signal("TERM", self.child.id());
        let deadline = Instant::now() + PATIENCE;
        while self.child.try_wait().ok().flatten().is_none() {
            assert!(
                Instant::now() < deadline,
                "PRODUCT: the daemon did not stop on SIGTERM; it said: {}",
                self.said()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn signal(sig: &str, pid: u32) {
    let ok = Command::new("kill")
        .args([&format!("-{sig}"), &pid.to_string()])
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "APPARATUS: could not send SIG{sig} to {pid}");
}

/// A profile with an identity, and a room of [`POSTS`] posts made by `exe`; returns the room id.
fn room_with_posts(exe: &Path, data: &Path, tag: &str) -> String {
    let (ok, _, err) = vox(exe, data, &["id"], None);
    assert!(ok, "PRODUCT (staging): `vox id` failed: {err}");
    let d = Daemon::start(exe, data, &format!("{tag}-make"), &[]);
    let (ok, _, err) = vox(
        exe,
        data,
        &["room", "create", "--name", "kept"],
        Some(&format!("{ROOM_PASS}\n")),
    );
    assert!(ok, "PRODUCT (staging): `vox room create` failed: {err}");
    let (ok, list, err) = vox(exe, data, &["room", "list"], None);
    assert!(ok, "PRODUCT (staging): `vox room list` failed: {err}");
    let room = list
        .lines()
        .find(|l| l.contains("kept"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_else(|| panic!("PRODUCT (staging): the new room is not listed: {list}"))
        .to_owned();
    for i in 1..=POSTS {
        let (ok, _, err) = vox(
            exe,
            data,
            &["room", "post", &room, &format!("kept-post-{i}")],
            None,
        );
        assert!(ok, "PRODUCT (staging): post {i} was refused: {err}");
    }
    d.stop();
    room
}

/// Every `kept-post-<i>` the room reads back.
fn posts(data: &Path, room: &str) -> Vec<String> {
    let (ok, out, err) = vox(
        Path::new(VOX),
        data,
        &["room", "read", room, "--json"],
        None,
    );
    assert!(ok, "PRODUCT: `vox room read --json` failed: {err}");
    let mut got: Vec<String> = out
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v["text"].as_str().map(str::to_owned))
        .filter(|t| t.starts_with("kept-post-"))
        .collect();
    got.sort();
    got
}

fn all_posts() -> Vec<String> {
    let mut v: Vec<String> = (1..=POSTS).map(|i| format!("kept-post-{i}")).collect();
    v.sort();
    v
}

/// The room's at-rest generation, as `vox status --json` reports it.
fn generation(data: &Path, room: &str) -> Option<u64> {
    let (ok, out, err) = vox(Path::new(VOX), data, &["status", "--json"], None);
    assert!(ok, "PRODUCT: `vox status --json` failed: {err}");
    let v: serde_json::Value = serde_json::from_str(&out)
        .unwrap_or_else(|e| panic!("PRODUCT: `vox status --json` printed no JSON ({e}): {out}"));
    fn find(v: &serde_json::Value, room: &str) -> Option<u64> {
        match v {
            serde_json::Value::Object(m) => {
                if m.get("room").and_then(serde_json::Value::as_str) == Some(room) {
                    if let Some(g) = m
                        .get("at_rest_generation")
                        .and_then(serde_json::Value::as_u64)
                    {
                        return Some(g);
                    }
                }
                m.values().find_map(|x| find(x, room))
            }
            serde_json::Value::Array(a) => a.iter().find_map(|x| find(x, room)),
            _ => None,
        }
    }
    find(&v, room)
}

fn until_generation_at_least(data: &Path, room: &str, at_least: u64, d: &Daemon) -> u64 {
    let deadline = Instant::now() + PATIENCE;
    loop {
        if let Some(g) = generation(data, room).filter(|g| *g >= at_least) {
            return g;
        }
        assert!(
            Instant::now() < deadline,
            "PRODUCT: past the lowered threshold, the room's store was never re-keyed: \
             `vox status --json` says generation {:?}; the daemon said: {}",
            generation(data, room),
            d.said()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn store_file(data: &Path) -> PathBuf {
    data.join("default").join("store.redb")
}

/// A distinctive run of each of the room's sealed segments, read from the stopped profile's store.
fn room_ciphertext(data: &Path, room: &str) -> Vec<Vec<u8>> {
    let cid = vox_core::node::link::b32_decode(room, "room id")
        .unwrap_or_else(|e| panic!("APPARATUS: {room} is not a room id: {e:?}"));
    let store = Store::open_read_only(&store_file(data))
        .unwrap_or_else(|e| panic!("APPARATUS: could not open the stopped profile's store: {e}"));
    let mut out = Vec::new();
    for kind in [
        SegmentKind::LogDb,
        SegmentKind::PlaintextCache,
        SegmentKind::Index,
        SegmentKind::KeyMaterial,
    ] {
        for (_, seg) in store
            .segments(&cid, kind)
            .unwrap_or_else(|e| panic!("APPARATUS: could not read the room's segments: {e}"))
        {
            out.push(seg.ciphertext[..32.min(seg.ciphertext.len())].to_vec());
        }
    }
    out
}

/// How many of `needles` occur anywhere in the profile's files, read as raw bytes.
fn still_on_disk(data: &Path, needles: &[Vec<u8>]) -> usize {
    let dir = data.join("default");
    let files: Vec<Vec<u8>> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("APPARATUS: could not list {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| std::fs::read(e.path()).unwrap_or_default())
        .collect();
    needles
        .iter()
        .filter(|n| {
            files
                .iter()
                .any(|f| f.windows(n.len()).any(|w| w == n.as_slice()))
        })
        .count()
}

#[test]
#[ignore = "real vox daemons and production Argon2id; CI runs it in release"]
fn a_room_store_is_rekeyed_and_reads_whole() {
    test_knobs::require(&["VOX_TEST_AT_REST_ROTATE_AT"]);
    watchdog::arm();
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a temporary directory: {e}"));
    let data = tmp.path().join("p");
    std::fs::create_dir_all(data.join("cfg"))
        .unwrap_or_else(|e| panic!("APPARATUS: could not create the profile dir: {e}"));
    let exe = Path::new(VOX);
    let room = room_with_posts(exe, &data, "rotate");
    let before = room_ciphertext(&data, &room);
    assert!(
        still_on_disk(&data, &before) == before.len() && !before.is_empty(),
        "APPARATUS: the room's own ciphertext is not found in its own store ({} of {} runs)",
        still_on_disk(&data, &before),
        before.len()
    );

    // ---- past the threshold: re-keyed, and the store file rewritten ----
    let d = Daemon::start(exe, &data, "low", &[("VOX_TEST_AT_REST_ROTATE_AT", LOW)]);
    let g = until_generation_at_least(&data, &room, 1, &d);
    d.until_said("the store file was rewritten without the old at-rest key's pages");
    let read = posts(&data, &room);
    println!(
        "[proof] after the re-key: generation {g}, {} of {POSTS} posts read",
        read.len()
    );
    assert_eq!(
        read,
        all_posts(),
        "PRODUCT: a re-keyed room must still read every post"
    );
    d.stop();
    let left = still_on_disk(&data, &before);
    println!(
        "[proof] {left} of {} runs of the old generation's ciphertext are still in the profile's \
         files",
        before.len()
    );
    assert_eq!(
        left, 0,
        "PRODUCT: after a re-key the old key's ciphertext must be gone from the store file, not \
         left in its freed pages"
    );

    // ---- a plain restart reads the re-keyed store ----
    let d = Daemon::start(exe, &data, "after", &[]);
    let g2 = until_generation_at_least(&data, &room, 1, &d);
    assert_eq!(
        posts(&data, &room),
        all_posts(),
        "PRODUCT: after a restart, a re-keyed room must still read every post (generation {g2})"
    );
    d.stop();
}

#[test]
#[ignore = "real vox daemons and production Argon2id; CI runs it in release"]
fn a_kill_during_the_rekey_loses_nothing() {
    test_knobs::require(&[
        "VOX_TEST_AT_REST_ROTATE_AT",
        "VOX_TEST_AT_REST_ROTATE_PAUSE_MS",
    ]);
    watchdog::arm();
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a temporary directory: {e}"));
    let data = tmp.path().join("p");
    std::fs::create_dir_all(data.join("cfg"))
        .unwrap_or_else(|e| panic!("APPARATUS: could not create the profile dir: {e}"));
    let exe = Path::new(VOX);
    let room = room_with_posts(exe, &data, "kill");

    // ---- killed inside the re-seal transaction, before it commits ----
    let d = Daemon::start(
        exe,
        &data,
        "paused",
        &[
            ("VOX_TEST_AT_REST_ROTATE_AT", LOW),
            ("VOX_TEST_AT_REST_ROTATE_PAUSE_MS", "600000"),
        ],
    );
    d.until_said("re-sealing at rest, not yet committed");
    d.kill();

    let d = Daemon::start(exe, &data, "after-kill", &[]);
    assert_eq!(
        posts(&data, &room),
        all_posts(),
        "PRODUCT: a daemon killed in the middle of a re-key must lose no post"
    );
    d.stop();

    // ---- the rotation then completes ----
    let d = Daemon::start(exe, &data, "again", &[("VOX_TEST_AT_REST_ROTATE_AT", LOW)]);
    let g = until_generation_at_least(&data, &room, 1, &d);
    assert_eq!(
        posts(&data, &room),
        all_posts(),
        "PRODUCT: the re-key that follows a killed one must lose no post (generation {g})"
    );
    d.stop();
}

#[test]
#[ignore = "the previous release's binary, real daemons and production Argon2id; CI runs it in release"]
fn a_store_from_before_generations_opens_unchanged() {
    watchdog::arm();
    let tmp = tempfile::tempdir()
        .unwrap_or_else(|e| panic!("APPARATUS: could not make a temporary directory: {e}"));
    let data = tmp.path().join("p");
    std::fs::create_dir_all(data.join("cfg"))
        .unwrap_or_else(|e| panic!("APPARATUS: could not create the profile dir: {e}"));
    let old = previous_release::previous_release();
    let room = room_with_posts(&old, &data, "old");

    let d = Daemon::start(Path::new(VOX), &data, "new", &[]);
    let read = posts(&data, &room);
    let g = until_generation_at_least(&data, &room, 0, &d);
    println!(
        "[proof] {} wrote the room; this build reads {} of {POSTS} posts at generation {g}",
        previous_release::PREVIOUS,
        read.len()
    );
    assert_eq!(
        read,
        all_posts(),
        "PRODUCT: a room written before at-rest generations existed must read every post"
    );
    assert_eq!(
        g, 0,
        "PRODUCT: a store from before generations must open at generation 0, unchanged"
    );
    d.stop();
}
