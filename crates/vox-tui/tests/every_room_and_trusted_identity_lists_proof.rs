//! **V210-16 — every room and every trusted identity is listed, however many there are**,
//! through the shipped `vox` binary.
//!
//! A `Rooms` reply used to be the whole list in one IPC frame, and the client refuses a
//! frame over `MAX_FRAME` (256 KiB): past about 1,540 rooms at the 128-byte local-name
//! limit, `vox room list` and every command that resolves a room by name failed with
//! "declared size exceeds hard limit: ipc frame length". Rooms are unbounded. A reply is now
//! one page (`PAGE_ENTRIES` entries, bounded by bytes too) and the client asks for every
//! page. `Trusted` is paged the same way; the keyring itself stops at `MAX_TRUSTED`
//! (1,024), about 100 KiB, so it never crossed a frame.
//!
//! What this drives, on alice's node, and then `vox room list` and `vox trust list` must
//! name every one:
//!
//! - **1,600 rooms at the 128-byte name limit — about 270 KiB, past one whole frame.** This
//!   is the defect itself: without paging, `vox room list` fails with "ipc frame length".
//!   Created eight at a time: a room create seals its key with production Argon2id on a
//!   blocking thread, so creates in parallel use the machine's cores;
//! - **200 trusted identities** at the 64-byte petname limit: four pages. Filling the
//!   whole keyring (1,024) would add ~6 minutes of Argon2id on the node's actor, one per
//!   `trust add` (V210-26), and prove nothing more about paging.
//!
//! The room list is checked first, straight after the rooms exist, so the defect's check
//! never waits on the slower phase.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::collections::BTreeSet;

/// Trusted identities: more than three pages. The keyring itself is capped at
/// `MAX_TRUSTED` (1,024, ~100 KiB), so it never crossed a frame; this shows it pages.
const TRUSTED: usize = 200;

/// The petname limit (`vox_core::node::trust::MAX_PETNAME`).
const PETNAME: usize = 64;

/// Rooms: past one 256 KiB frame at the 128-byte name limit.
const ROOMS: usize = 1_600;

/// Room creates in flight at once.
const PARALLEL: usize = 8;

#[test]
#[ignore = "networked nodes, 1,600 rooms and 200 trusted identities (~6 min); CI runs it in release"]
fn every_room_and_trusted_identity_is_listed_past_one_page() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    // Two workers: the harness proves a room readable by posts between its members.
    let room = rt.block_on(support::room(tmp.path(), &["alice", "bob"]));
    let alice = &room.workers[0];
    let pass = alice.pass.to_str().unwrap().to_owned();

    // Rooms: the harness made one; make the rest.
    let names: BTreeSet<String> = (1..ROOMS)
        .map(|i| format!("page-room-{i:05}-{}", "r".repeat(128 - 16)))
        .collect();
    let started = std::time::Instant::now();
    let queue: Vec<&String> = names.iter().collect();
    std::thread::scope(|scope| {
        for chunk in queue.chunks(queue.len().div_ceil(PARALLEL)) {
            scope.spawn(move || {
                for name in chunk {
                    let o = alice.vox_in(
                        None,
                        &["room", "create", "--name", name],
                        Some("page room passphrase"),
                    );
                    assert!(o.ok, "room create {name}: {o:?}");
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
    assert!(list.ok, "{list:?}");
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
        "vox room list names every room, past one page"
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
        assert!(o.ok, "trust add {fp}: {o:?}");
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
    assert!(trust.ok, "{trust:?}");
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
        "vox trust list shows every trusted identity, past one page"
    );
}
