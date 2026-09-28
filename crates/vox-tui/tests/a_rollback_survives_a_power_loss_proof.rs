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

/// Run `vox update --rollback` from `dir`'s own `vox`, nothing of the person's touched.
fn rollback(dir: &Path, home: &Path) -> (bool, String) {
    let out = Command::new(dir.join("vox"))
        .args(["update", "--rollback"])
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("VOX_NO_SHELL_SETUP", "1")
        .output()
        .expect("run vox update --rollback");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// **A rollback a power loss interrupted is finished by the next one, not refused** (#242, the
/// verifier's follow-up). `do_rollback` copies `vox` to `.vox-rollback.partial`, renames
/// `.vox-previous` onto `vox`, then renames the copy to `.vox-previous`. A power loss between the
/// renames left `vox` (the rolled-back binary) and the partial copy (the other one), with no
/// `.vox-previous`, and every later `--rollback` refused: "no previous vox was retained". Staged
/// here directly, as each state a power loss can leave (the binary that runs the next rollback is
/// whatever is `vox` then, so this build is `vox`, and the other binary is a runnable stub):
///
/// 1. **between the renames** — `--rollback` finishes the swap and stops there: `vox` is still
///    this build, `.vox-previous` is the other binary, no partial is left;
/// 2. **before the first rename** — the partial is only a copy of `vox`: it is discarded, and the
///    rollback runs;
/// 3. **a partial that does not run** (cut short before its flush) — it is never installed: it is
///    discarded, `vox` is untouched, and with no previous the rollback refuses.
///
/// Mutation: the recovery removed → (1) is refused.
#[test]
#[ignore = "real install directories and the shipped binary; the macOS release gate runs it"]
fn an_interrupted_rollback_is_finished_by_the_next_one() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let mut failures: Vec<String> = Vec::new();

    // 1. between the renames
    {
        let root = tmp.path().join("between");
        let dir = install_dir(&root);
        previous_stub(&dir.join(".vox-rollback.partial"), "0.0.1");
        let (ok, said) = rollback(&dir, &home);
        let (active, previous) = (
            version_of(&dir.join("vox")),
            version_of(&dir.join(".vox-previous")),
        );
        let partial_left = dir.join(".vox-rollback.partial").exists();
        eprintln!(
            "[proof] (1) between the renames: ok={ok}; vox {active:?}; .vox-previous {previous:?}; \
             partial left: {partial_left}; said {:?}",
            said.trim()
        );
        if !(ok
            && active.as_deref().is_some_and(|v| v.contains(VERSION))
            && previous.as_deref() == Some("vox 0.0.1")
            && !partial_left)
        {
            failures.push(format!(
                "(1) an interrupted rollback was not finished: ok={ok}, vox {active:?}, \
                 .vox-previous {previous:?}, partial left {partial_left}: {said}"
            ));
        }
    }
    // 2. before the first rename
    {
        let root = tmp.path().join("before");
        let dir = install_dir(&root);
        previous_stub(&dir.join(".vox-previous"), "0.0.1");
        std::fs::copy(dir.join("vox"), dir.join(".vox-rollback.partial")).unwrap();
        let (ok, said) = rollback(&dir, &home);
        let (active, previous) = (
            version_of(&dir.join("vox")),
            version_of(&dir.join(".vox-previous")),
        );
        let partial_left = dir.join(".vox-rollback.partial").exists();
        eprintln!(
            "[proof] (2) before the first rename: ok={ok}; vox {active:?}; .vox-previous \
             {previous:?}; partial left: {partial_left}"
        );
        if !(ok
            && active.as_deref() == Some("vox 0.0.1")
            && previous.as_deref().is_some_and(|v| v.contains(VERSION))
            && !partial_left)
        {
            failures.push(format!(
                "(2) a rollback over a leftover copy did not run cleanly: ok={ok}, vox {active:?}, \
                 .vox-previous {previous:?}, partial left {partial_left}: {said}"
            ));
        }
    }
    // 3. a partial that does not run
    {
        let root = tmp.path().join("broken");
        let dir = install_dir(&root);
        std::fs::write(dir.join(".vox-rollback.partial"), b"").unwrap();
        let (ok, said) = rollback(&dir, &home);
        let active = version_of(&dir.join("vox"));
        let partial_left = dir.join(".vox-rollback.partial").exists();
        let previous_made = dir.join(".vox-previous").exists();
        eprintln!(
            "[proof] (3) an empty partial: ok={ok}; vox {active:?}; partial left: {partial_left}; \
             .vox-previous made: {previous_made}; said {:?}",
            said.trim()
        );
        if !(!ok
            && said.contains("no previous vox was retained")
            && active.as_deref().is_some_and(|v| v.contains(VERSION))
            && !partial_left
            && !previous_made)
        {
            failures.push(format!(
                "(3) an empty partial was not discarded safely: ok={ok}, vox {active:?}, partial \
                 left {partial_left}, .vox-previous made {previous_made}: {said}"
            ));
        }
    }
    eprintln!("[proof] {} of 3 states failed", failures.len());
    assert!(
        failures.is_empty(),
        "a rollback does not recover what a power loss left:\n{}",
        failures.join("\n")
    );
}
