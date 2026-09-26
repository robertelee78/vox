//! **V210-16 — every room and every trusted identity is listed, however many there are**,
//! through the shipped `vox` binary.
//!
//! `Rooms` and `Trusted` replies used to be the whole list in one IPC frame, and the
//! client refuses a frame over `MAX_FRAME` (256 KiB): about 1,500 rooms at the longest
//! local name, or 2,600 trusted identities, and `vox room list`, every command that
//! resolves a room by name, and `vox trust list` stopped working. A reply is now one page
//! (`PAGE_ENTRIES` entries, bounded by bytes too) and the client asks for every page.
//!
//! What this drives, on alice's node: 100 rooms and 100 trusted identities — more than one
//! page of each — and then `vox room list` and `vox trust list` must name every one.

#![cfg(unix)]

#[path = "support/room.rs"]
mod support;
#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::collections::BTreeSet;

/// More than one page of each (`PAGE_ENTRIES` is 64).
const N: usize = 100;

#[test]
#[ignore = "networked nodes with production Argon2id and 100 rooms; CI runs it in release"]
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
    let mut names: BTreeSet<String> = BTreeSet::new();
    for i in 1..N {
        let name = format!("page-room-{i:03}");
        let o = alice.vox_in(
            None,
            &["room", "create", "--name", &name],
            Some("page room passphrase"),
        );
        assert!(o.ok, "room create {name}: {o:?}");
        names.insert(name);
    }

    // Trusted identities: synthetic fingerprints, each distinct.
    let mut fingerprints: BTreeSet<String> = BTreeSet::new();
    for i in 0..N {
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
                &format!("page-peer-{i:03}"),
                "--identity-passphrase-file",
                &pass,
            ],
        );
        assert!(o.ok, "trust add {fp}: {o:?}");
        fingerprints.insert(fp);
    }

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
