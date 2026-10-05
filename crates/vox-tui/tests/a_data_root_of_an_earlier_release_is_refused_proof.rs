//! V030-46 (#423, ADR-026 F-3) — **Vox carries no code for data from earlier releases: a fresh
//! data root works end to end, and one laid out by a release before v0.3.0 is refused with a
//! plain reason and left byte for byte unchanged**, through the shipped binary.
//!
//! Nobody has run a Vox release (decider, 2026-10-04), so nothing needs migrating: Vox carries no
//! code that reads, converts or moves such a data root. What is left is a refusal, before anything
//! is written.
//!
//! **Arm 1, fresh data roots, end to end** (`support/room.rs`): an anchor and two members, each
//! made by `vox id`, attached in its own `vox daemon`; `vox room create`, `invite`, `join` and
//! `trust add`; each posts until the other reads it. Then bob posts once more and alice reads it.
//!
//! **Arm 2, a data root of an earlier release.** A data root laid out as v0.2.x left it: a
//! directory `default/` of the root itself holding `vault.cbor`, `store.redb` and `port` (their
//! contents do not matter: they must never be read), beside a file of the person's own. Every way
//! in is tried — `vox id`, `vox node list`, `vox node attach default`, `vox room list`,
//! `vox status`, `vox daemon` and `vox node` — and each must fail, saying "<root> is not a Vox
//! data directory this version reads: <root>/default is not a node", and never "profile". The
//! data root is snapshotted before and after (every path, every file's bytes): it must be
//! identical. The config directory and `HOME` are outside it, so nothing legitimate writes inside
//! it.
//!
//! **Which side a red is on.** A verb that succeeds, one that refuses for another reason, or a
//! data root that changed is `PRODUCT:`; the proof's own I/O is `APPARATUS:`.
//!
//! Mutation: the refusal removed (`refuse_old_layout` answering `Ok`) → red: the verbs run, and
//! `nodes/` and `.daemon/` appear in the old data root.

#![cfg(unix)]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/room.rs"]
mod room;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The binary under proof.
const VOX: &str = env!("CARGO_BIN_EXE_vox");
/// An identity passphrase, for a verb that would ask for one (none gets that far).
const IDENTITY: &str = "identity passphrase";

/// What every refusal must say.
const REASON: &str = "is not a Vox data directory this version reads";
/// What it says of the directory that is not a node.
const NOT_A_NODE: &str = "is not a node";

/// Every path under `root` with its bytes (`None` for a directory; a fixed marker for a socket or
/// a link).
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("APPARATUS: listing {}: {e}", dir.display()));
        for e in entries {
            let e = e.unwrap_or_else(|e| panic!("APPARATUS: an entry of {}: {e}", dir.display()));
            let p = e.path();
            let rel = p
                .strip_prefix(root)
                .expect("APPARATUS: under the root")
                .to_owned();
            let kind = e
                .file_type()
                .unwrap_or_else(|e| panic!("APPARATUS: the type of {}: {e}", p.display()));
            if kind.is_dir() {
                out.insert(rel, None);
                walk(&p, root, out);
            } else if !kind.is_file() {
                // A socket or a link: its presence is what counts, and it has no bytes to read.
                out.insert(rel, Some(b"(not a regular file)".to_vec()));
            } else {
                let bytes = std::fs::read(&p)
                    .unwrap_or_else(|e| panic!("APPARATUS: reading {}: {e}", p.display()));
                out.insert(rel, Some(bytes));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// `vox <argv>` on data root `data`, with the config directory and `HOME` outside it, killed by
/// its PID if it has not ended within a minute (a daemon that started anyway). `(exited ok, what
/// it said)`; `None` for the exit when it had to be killed.
fn run_on(data: &Path, outside: &Path, argv: &[&str]) -> (Option<bool>, String) {
    let mut child = Command::new(VOX)
        .args(argv)
        .env("VOX_DATA_DIR", data)
        .env("VOX_CONFIG_DIR", outside.join("cfg"))
        .env("HOME", outside.join("home"))
        .env("VOX_IDENTITY_PASSPHRASE", IDENTITY)
        .env_remove("VOX_ROOM_PASSPHRASE")
        .env_remove("VOX_ANCHORS")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn vox {argv:?}: {e}"));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s.success()),
            Ok(None) if started.elapsed() < Duration::from_secs(60) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                break None;
            }
            Err(e) => panic!("APPARATUS: cannot poll vox {argv:?}: {e}"),
        }
    };
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot collect vox {argv:?}: {e}"));
    (
        status,
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr),
    )
}

#[test]
#[ignore = "an anchor and two real daemons with production Argon2id; run in release"]
fn a_fresh_data_root_works_end_to_end() {
    watchdog::arm();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("APPARATUS: a runtime");
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let r = rt.block_on(room::room(tmp.path(), &["alice", "bob"]));
    let (alice, bob) = (&r.workers[0], &r.workers[1]);
    let posted = "written on a fresh data root";
    let out = bob.vox(None, &["room", "post", &r.id, posted]);
    assert!(
        out.ok,
        "PRODUCT: bob's `vox room post` failed: {}",
        out.stderr.trim()
    );
    let until = Instant::now() + Duration::from_secs(60);
    let read = loop {
        let out = alice.vox(None, &["room", "read", &r.id]);
        if out.ok && out.stdout.contains(posted) {
            break true;
        }
        if Instant::now() > until {
            break false;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    println!(
        "[proof] fresh data roots: room {} created, joined, trusted; alice reads bob's post: {read}",
        r.id
    );
    assert!(
        read,
        "PRODUCT: alice never read bob's post on fresh data roots"
    );
}

#[test]
#[ignore = "real binaries; run in release"]
fn a_data_root_of_an_earlier_release_is_refused_and_unchanged() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: a temp dir");
    let data = tmp.path().join("data");
    let outside = tmp.path().join("outside");
    for d in [
        data.join("default"),
        outside.join("cfg"),
        outside.join("home"),
    ] {
        std::fs::create_dir_all(&d).expect("APPARATUS: staging directories");
    }
    // A data root as v0.2.x left it: a node's files in a directory of the root itself.
    let folder = data.join("default");
    std::fs::write(folder.join("vault.cbor"), b"a vault of an earlier release")
        .expect("APPARATUS: staging vault.cbor");
    std::fs::write(folder.join("store.redb"), b"a store of an earlier release")
        .expect("APPARATUS: staging store.redb");
    std::fs::write(folder.join("port"), b"41234\n").expect("APPARATUS: staging port");
    std::fs::write(data.join("notes.txt"), b"a file of the person's own")
        .expect("APPARATUS: staging notes.txt");
    let before = snapshot(&data);

    let verbs: [&[&str]; 7] = [
        &["id"],
        &["node", "list"],
        &["node", "attach", "default"],
        &["room", "list"],
        &["status"],
        &["daemon", "--listen", "127.0.0.1:0"],
        &["node", "--listen", "127.0.0.1:0"],
    ];
    let mut red = Vec::new();
    for argv in verbs {
        let (status, said) = run_on(&data, &outside, argv);
        let names_it = said.contains(&format!("{} {REASON}", data.display()))
            && said.contains(&format!("{} {NOT_A_NODE}", folder.display()))
            && !said.to_lowercase().contains("profile");
        println!(
            "[proof] vox {}: exit ok = {status:?}; says why = {names_it}",
            argv.join(" ")
        );
        if status != Some(false) || !names_it {
            red.push(format!(
                "`vox {}` must fail saying the data root {REASON} and that {} {NOT_A_NODE}, \
                 never \"profile\"; it ended {status:?} and said: {said}",
                argv.join(" "),
                folder.display()
            ));
        }
    }
    let after = snapshot(&data);
    if after != before {
        let added: Vec<_> = after.keys().filter(|k| !before.contains_key(*k)).collect();
        let changed: Vec<_> = before
            .iter()
            .filter(|(k, v)| after.get(*k) != Some(v))
            .map(|(k, _)| k)
            .collect();
        red.push(format!(
            "the refused data root changed: added {added:?}; changed or removed {changed:?}"
        ));
    }
    println!(
        "[proof] the data root after every verb: {} paths, unchanged = {}",
        after.len(),
        after == before
    );
    assert!(red.is_empty(), "PRODUCT: {red:#?}");
}
