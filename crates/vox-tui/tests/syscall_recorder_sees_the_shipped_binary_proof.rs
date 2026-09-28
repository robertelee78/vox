//! The apparatus check for `crates/vox-test-interpose` (V210-55 #241, #242): **loaded into the
//! shipped `vox` binary, unmodified, it records the calls that decide durability, in order.**
//!
//! A proof built on the recorder is only as good as the recorder. So before any proof asserts that
//! vox flushes a file before publishing it, this one shows the recorder sees each kind of call the
//! real binary makes, on a real `vox id`:
//! - the vault's temporary file being created, with its flags and mode, and renamed into place;
//! - at least one flush of the profile's store (redb flushes on every commit), resolved to the
//!   store's path;
//! - every event from the `vox` process itself.
//!
//! It asserts nothing about whether vox's order is durable; the proofs that use the recorder do.
//! Mutation: an interposer that stops recording `fcntl(F_FULLFSYNC)` fails the second point.

#![cfg(target_os = "macos")]

#[path = "support/world.rs"]
mod world;

#[path = "support/syscalls.rs"]
mod syscalls;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::path::Path;

use syscalls::{norm, recorded, Call, O_CREAT};
use world::{IDENTITY, VOX};

#[test]
#[ignore = "real vox with production Argon2id under DYLD_INSERT_LIBRARIES; run in release"]
fn the_recorder_sees_what_the_shipped_binary_does() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("person");
    std::fs::create_dir_all(data.join("cfg")).unwrap();
    let (ok, out, err, events) = recorded(Path::new(VOX), &data, &["id"], None, IDENTITY);
    assert!(
        ok,
        "CANNOT MEASURE: `vox id` failed under the recorder: {out}{err}"
    );

    let profile = norm(&data.join("default/vault.cbor"))
        .parent()
        .unwrap()
        .to_owned();
    let vault = profile.join("vault.cbor");
    let store = profile.join("store.redb");
    let created = events.iter().find(|e| {
        matches!(&e.call, Call::Open { path, flags, .. }
            if norm(path).parent() == Some(profile.as_path()) && flags & O_CREAT != 0
                && norm(path) != store)
    });
    let renamed = events
        .iter()
        .find(|e| matches!(&e.call, Call::Rename { to, .. } if norm(to) == vault));
    let store_syncs = events
        .iter()
        .filter(|e| matches!(&e.call, Call::Sync { path, .. } if norm(path) == store))
        .count();
    let pids: std::collections::BTreeSet<u32> = events.iter().map(|e| e.pid).collect();
    println!(
        "[proof] `vox id` under the recorder: {} calls from {} process(es); the vault's file \
         created = {:?}; renamed into vault.cbor = {}; flushes of store.redb = {store_syncs}",
        events.len(),
        pids.len(),
        created.map(|e| &e.call),
        renamed.is_some()
    );
    assert!(
        created.is_some(),
        "the recorder saw no file created in the profile"
    );
    assert!(
        renamed.is_some(),
        "the recorder saw no rename onto vault.cbor"
    );
    assert!(
        store_syncs > 0,
        "the recorder saw no flush of store.redb, which redb flushes on every commit"
    );
    assert_eq!(
        pids.len(),
        1,
        "events from more than the one vox process: {pids:?}"
    );
}
