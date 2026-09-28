//! V210-56 (#242) — **`vox update` leaves a runnable `vox` whatever instant the power goes**,
//! through the shipped binary.
//!
//! An update or a rollback swaps binaries with a copy and renames. `fs::copy` returns once the bytes
//! are handed to the kernel (on APFS it is a clone), and a rename can reach the disk before the
//! copy's own data and metadata do. So a power loss in between could leave an empty or partial file
//! under the name `vox` or `.vox-previous`: the binary that had to survive. Each copy is now flushed
//! before the rename that publishes it, and the directory after each rename.
//!
//! **What is measured, and what cannot be.** A power loss cannot be staged from userspace, and a
//! `SIGKILL` keeps the page cache, so killing `vox update` at each step would pass with or without
//! the flushes (it passed on the unfixed code). What can be observed is the **order of the calls**
//! the shipped binary makes. It is run unmodified under `crates/vox-test-interpose`
//! (`support/syscalls.rs`, macOS), and the order is judged here:
//!
//! 1. the copy of the active binary is filled (a clone, a copy or writes) and then **flushed**,
//!    after its last content and before the rename that makes it `.vox-previous`;
//! 2. the rename of `.vox-previous` onto `vox` is followed by a **directory flush before the next
//!    rename**, so the new `vox` is on disk before the old one's name is reused;
//! 3. the last rename is followed by a directory flush.
//!
//! **Only `--rollback`.** `vox update` proper runs inside the binary being replaced, which is a
//! published release, so the fixed publish path can be driven only once a release carrying it
//! exists. `--rollback` is local, is the same copy-and-rename, and runs this build's code. The
//! publish path takes the same `copy_durably` and directory flushes (read in `update.rs`).
//!
//! Mutations: the flush of a copy removed → red on (1); the directory flush between the two
//! renames removed → red on (2).

#![cfg(target_os = "macos")]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/syscalls.rs"]
mod syscalls;

use std::path::{Path, PathBuf};
use std::process::Command;

use syscalls::{norm, Call, Event};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// An install as `install.sh` makes one: the real `vox`, and a marker naming its channel.
fn install_dir(root: &Path) -> PathBuf {
    let dir = root.join("bin");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(VOX, dir.join("vox")).unwrap();
    std::fs::write(
        dir.join(".vox-standalone.json"),
        "{\"kind\":\"vox.install-channel\",\"schema_version\":1,\"package\":\"vox\",\
         \"channel\":\"stable\"}\n",
    )
    .unwrap();
    dir
}

/// "The vox you had before": runnable, and told apart from the real one by its `--version`.
fn previous_stub(path: &Path, version: &str) {
    std::fs::write(path, format!("#!/bin/sh\necho \"vox {version}\"\n")).unwrap();
    let mut p = std::fs::metadata(path).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut p, 0o755);
    std::fs::set_permissions(path, p).unwrap();
}

/// What `path --version` says, or `None` if it did not run.
fn version_of(path: &Path) -> Option<String> {
    let out = Command::new(path)
        .arg("--version")
        .env_clear()
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Index of the first event after `from` matching `pred`.
fn find(events: &[Event], from: usize, pred: impl Fn(&Call) -> bool) -> Option<usize> {
    events[from..]
        .iter()
        .position(|e| pred(&e.call))
        .map(|k| from + k)
}

#[test]
#[ignore = "a real install directory and the shipped binary under the syscall recorder; the macOS \
            release gate runs it"]
fn a_rollback_leaves_a_runnable_vox_whatever_instant_the_power_goes() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let dir = install_dir(tmp.path());
    let (active, previous) = (dir.join("vox"), dir.join(".vox-previous"));
    let scratch = dir.join(".vox-rollback.partial");
    previous_stub(&previous, "0.0.1");

    // ---- the shipped binary, unmodified, under the recorder; nothing of the person's touched ---
    let log = tmp.path().join("calls.tsv");
    let out = Command::new(&active)
        .args(["update", "--rollback"])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("VOX_NO_SHELL_SETUP", "1")
        .env("DYLD_INSERT_LIBRARIES", syscalls::interposer())
        .env("VOX_INTERPOSE_LOG", &log)
        .output()
        .expect("run vox update --rollback");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "vox update --rollback failed: {said}");
    let events = syscalls::parse(&std::fs::read_to_string(&log).unwrap_or_default());
    let (now_active, now_previous) = (version_of(&active), version_of(&previous));
    eprintln!(
        "[proof] after --rollback: vox reports {now_active:?}, .vox-previous reports \
         {now_previous:?}; {} calls recorded",
        events.len()
    );
    assert_eq!(
        now_active.as_deref(),
        Some("vox 0.0.1"),
        "CANNOT MEASURE: the rollback did not put the previous binary back: {said}"
    );
    assert!(
        now_previous.as_deref().is_some_and(|v| v.contains(VERSION)),
        "CANNOT MEASURE: the rollback did not keep the replaced binary as .vox-previous"
    );

    // ---- the order of the calls that did it --------------------------------------------------
    let (active_n, previous_n, scratch_n, dir_n) = (
        norm(&active),
        norm(&previous),
        norm(&scratch),
        std::fs::canonicalize(&dir).unwrap(),
    );
    let is_dir_sync = |c: &Call| matches!(c, Call::Sync { path, .. } if std::fs::canonicalize(path).unwrap_or_else(|_| path.clone()) == dir_n);
    let first_rename = find(
        &events,
        0,
        |c| matches!(c, Call::Rename { from, to } if norm(from) == previous_n && norm(to) == active_n),
    );
    let second_rename = find(
        &events,
        0,
        |c| matches!(c, Call::Rename { from, to } if norm(from) == scratch_n && norm(to) == previous_n),
    );
    let (Some(first), Some(second)) = (first_rename, second_rename) else {
        panic!(
            "CANNOT MEASURE: the recorder did not see both renames ({first_rename:?}, \
             {second_rename:?}) in {} calls:\n{events:#?}",
            events.len()
        );
    };
    for e in &events {
        if matches!(&e.call, Call::Rename { .. })
            || e.call.fills(&scratch_n)
            || matches!(&e.call, Call::Sync { .. })
        {
            eprintln!(
                "[calls] {:>4} {:?} ret {} errno {}",
                e.seq, e.call, e.ret, e.errno
            );
        }
    }
    let mut failures: Vec<String> = Vec::new();

    // 1. the copy is filled, then flushed, before the rename that publishes it.
    let last_fill = events[..second]
        .iter()
        .rposition(|e| e.call.fills(&scratch_n));
    match last_fill {
        None => failures.push(
            "CANNOT MEASURE: no write, clone or copy into the rollback's copy was recorded"
                .to_owned(),
        ),
        Some(k) => {
            let flushed = events[k + 1..second].iter().any(|e| {
                e.ret == 0 && matches!(&e.call, Call::Sync { path, .. } if norm(path) == scratch_n)
            });
            if !flushed {
                failures.push(format!(
                    "(1) the copy of the active binary was not flushed after it was filled (call \
                     {}) and before it was renamed to .vox-previous (call {})",
                    events[k].seq, events[second].seq
                ));
            }
        }
    }
    // 2. the first rename is on disk before the second.
    let dir_ok = |e: &Event| e.ret == 0 || e.errno == 22 || e.errno == 45;
    if !events[first + 1..second]
        .iter()
        .any(|e| is_dir_sync(&e.call) && dir_ok(e))
    {
        failures.push(format!(
            "(2) no directory flush between putting .vox-previous back as vox (call {}) and \
             reusing the name .vox-previous (call {})",
            events[first].seq, events[second].seq
        ));
    }
    // 3. the last rename is on disk.
    if !events[second + 1..]
        .iter()
        .any(|e| is_dir_sync(&e.call) && dir_ok(e))
    {
        failures.push(format!(
            "(3) no directory flush after the last rename (call {})",
            events[second].seq
        ));
    }
    eprintln!("[proof] {} of 3 claims failed", failures.len());
    assert!(
        failures.is_empty(),
        "a rollback does not survive every power loss:\n{}",
        failures.join("\n")
    );
}
