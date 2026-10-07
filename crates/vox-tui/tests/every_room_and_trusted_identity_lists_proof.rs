//! **V210-16 — every room and every trusted identity is listed, however many there are**,
//! through the shipped `vox` binary.
//!
//! A `Rooms` reply used to be the whole list in one IPC frame, and the client refuses a
//! frame over its limit (256 KiB): past about 1,540 rooms at the then 128-byte local-name limit,
//! `vox room list` and every command that resolves a room by name failed with "declared size
//! exceeds hard limit: ipc frame length". A reply is now one page (`PAGE_ENTRIES` entries,
//! bounded by bytes too) and the client asks for every page. `Trusted` is paged the same way.
//!
//! **At the scale a node really has.** The decider puts a node's rooms at "a couple of hundred
//! at most" (2026-09-28). Reaching the real 256 KiB frame takes about 1,540 rooms, each sealed
//! with production Argon2id, which never fitted this proof's watchdog. So this proof runs every
//! process with `VOX_TEST_MAX_FRAME` = [`FRAME`] (`ipc::frame_limit`, test-only, which only
//! lowers the limit): 200 rooms then outgrow one frame, as 1,540 do at the real one.
//!
//! What this drives, on alice's node, and then `vox room list` and `vox trust list` must
//! name every one:
//!
//! - **200 rooms at the 63-character name limit** (a room name is one part of a service address,
//!   `vox_core::governance::name::MAX_ROOM_NAME`): about 20 KB, past one whole 16 KiB frame. This
//!   is the defect itself: without paging, `vox room list` fails with "ipc frame length".
//!   Created eight at a time: a room create seals its key with production Argon2id on a
//!   blocking thread, so creates in parallel use the machine's cores;
//! - **200 trusted identities** at the 64-byte petname limit: about 26 KB, past one frame and
//!   four pages.
//!
//! The room list is checked first, straight after the rooms exist, so the defect's check
//! never waits on the slower phase.
//!
//! Mutation: a `Rooms` or `Trusted` reply that is not paged (the whole list at once) fails with
//! "ipc frame length".

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/test_knobs.rs"]
mod test_knobs;

use std::collections::BTreeSet;

/// Trusted identities: past one [`FRAME`] and four pages.
const TRUSTED: usize = 200;

/// The petname limit (`vox_core::node::trust::MAX_PETNAME`).
const PETNAME: usize = 64;

/// Rooms: past one [`FRAME`] at the 63-character name limit; the decider's realistic ceiling.
const ROOMS: usize = 200;

/// The IPC frame limit every process in this proof runs with (`VOX_TEST_MAX_FRAME`).
const FRAME: usize = 16 * 1024;

/// Room creates in flight at once.
const PARALLEL: usize = 8;

#[test]
#[ignore = "networked nodes, 200 rooms and 200 trusted identities with production Argon2id; CI runs it in release"]
fn every_room_and_trusted_identity_is_listed_past_one_page() {
    test_knobs::require(&["VOX_TEST_MAX_FRAME"]);
    watchdog::arm();
    // Every process this proof starts inherits it: the daemons page their replies to it, and
    // each `vox` command refuses a frame over it.
    std::env::set_var("VOX_TEST_MAX_FRAME", FRAME.to_string());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("APPARATUS: start a runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    // Two workers: the harness proves a room readable by posts between its members.
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let alice = &room.workers[0];
    let pass = alice
        .pass
        .to_str()
        .expect("APPARATUS: a path that is not UTF-8")
        .to_owned();

    // Rooms: the harness made one; make the rest.
    let names: BTreeSet<String> = (1..ROOMS)
        // At the room-name limit, 63 characters: a longer name is refused (`vox room create`
        // names the limit), which is the product's rule, not this proof's subject.
        .map(|i| format!("page-room-{i:05}-{}", "r".repeat(63 - 16)))
        .collect();
    let started = std::time::Instant::now();
    let queue: Vec<&String> = names.iter().collect();
    // Progress every 100 rooms, with the time the last hundred took: a create that grows slower
    // as rooms accumulate shows here, where a total time cannot tell growth from a steady cost.
    let made = std::sync::atomic::AtomicUsize::new(0);
    let last = std::sync::Mutex::new(started);
    let (made, last) = (&made, &last);
    std::thread::scope(|scope| {
        for chunk in queue.chunks(queue.len().div_ceil(PARALLEL)) {
            scope.spawn(move || {
                for name in chunk {
                    let o = alice.vox_in(
                        None,
                        &["room", "create", "--passphrase-file", "-", "--name", name],
                        Some("page room passphrase"),
                    );
                    assert!(o.ok, "PRODUCT (staging): room create {name}: {o:?}");
                    let n = made.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    if n % 100 == 0 {
                        let mut prev = last
                            .lock()
                            .expect("APPARATUS: a lock the proof holds was poisoned");
                        eprintln!(
                            "[progress] {n} rooms at {:.1}s; the last 100 took {:.1}s",
                            started.elapsed().as_secs_f64(),
                            prev.elapsed().as_secs_f64()
                        );
                        *prev = std::time::Instant::now();
                    }
                }
            });
        }
    });
    eprintln!(
        "[proof] {} rooms created in {:?}",
        names.len(),
        started.elapsed()
    );

    // Every room, by name.
    let list = alice.vox(None, &["room", "list"]);
    assert!(list.ok, "PRODUCT: `vox room list` failed: {list:?}");
    let listed: BTreeSet<String> = names
        .iter()
        .filter(|n| list.stdout.contains(n.as_str()))
        .cloned()
        .collect();
    let rooms_shown = list.stdout.lines().filter(|l| !l.trim().is_empty()).count();
    eprintln!(
        "[proof] vox room list: {} of {} created rooms named, {rooms_shown} lines",
        listed.len(),
        names.len()
    );
    assert_eq!(
        listed, names,
        "PRODUCT: vox room list names every room, past one page"
    );

    // Trusted identities: synthetic fingerprints, each distinct.
    let mut fingerprints: BTreeSet<String> = BTreeSet::new();
    let started = std::time::Instant::now();
    for i in 0..TRUSTED {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
        id[31] = 0xA5;
        let fp = vox_core::node::link::b32_encode(&id);
        let o = alice.vox(
            None,
            &[
                "trust",
                "add",
                &fp,
                "--name",
                &{
                    let head = format!("page-peer-{i:05}-");
                    format!("{head}{}", "p".repeat(PETNAME - head.len()))
                },
                "--identity-passphrase-file",
                &pass,
            ],
        );
        assert!(o.ok, "PRODUCT (staging): trust add {fp}: {o:?}");
        if (i + 1) % 50 == 0 {
            eprintln!(
                "[progress] {} trusted at {:.1}s",
                i + 1,
                started.elapsed().as_secs_f64()
            );
        }
        fingerprints.insert(fp);
    }
    eprintln!(
        "[proof] {} trusted identities added in {:?}",
        fingerprints.len(),
        started.elapsed()
    );

    // Every trusted identity, by fingerprint.
    let trust = alice.vox(
        None,
        &["trust", "list", "--identity-passphrase-file", &pass],
    );
    assert!(trust.ok, "PRODUCT: `vox trust list` failed: {trust:?}");
    let shown: BTreeSet<String> = fingerprints
        .iter()
        .filter(|fp| trust.stdout.contains(fp.as_str()))
        .cloned()
        .collect();
    eprintln!(
        "[proof] vox trust list: {} of {} trusted fingerprints shown",
        shown.len(),
        fingerprints.len()
    );
    assert_eq!(
        shown, fingerprints,
        "PRODUCT: vox trust list shows every trusted identity, past one page"
    );
}
