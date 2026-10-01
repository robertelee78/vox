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
    syscalls::assert_the_recorder_saw_vox(&events, "`vox update --rollback`");
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
    rollback_with(dir, home, false, None)
}

/// [`rollback`], with the shell set-up it runs afterwards allowed (`shell`, against the private
/// `home`) and under the syscall recorder when `log` is given.
fn rollback_with(dir: &Path, home: &Path, shell: bool, log: Option<&Path>) -> (bool, String) {
    let mut cmd = Command::new(dir.join("vox"));
    cmd.args(["update", "--rollback"])
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("SHELL", "/bin/zsh");
    if !shell {
        cmd.env("VOX_NO_SHELL_SETUP", "1");
    }
    if let Some(log) = log {
        cmd.env("DYLD_INSERT_LIBRARIES", syscalls::interposer())
            .env("VOX_INTERPOSE_LOG", log);
    }
    let out = cmd.output().expect("run vox update --rollback");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// A leftover that exits 0 but is not a `vox`, or that hangs.
fn impostor(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    let mut p = std::fs::metadata(path).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut p, 0o755);
    std::fs::set_permissions(path, p).unwrap();
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

/// #247's verifier's gaps, each shown on the shipped binary:
///
/// 4. a leftover that **hangs** is not a `vox`: it is discarded within the check's timeout, never
///    installed, and the rollback answers in seconds;
/// 5. a leftover that exits 0 but does not say `vox <version>` is not installed either;
/// 6. the recovery path is **durable** (read with the syscall recorder): finishing an interrupted
///    swap flushes the directory after its rename; discarding a leftover copy flushes the
///    directory before anything new is put under that name;
/// 7. finishing an interrupted rollback refreshes shell completions, as a rollback does;
/// 8. a leftover that leaves a child holding its stdout cannot keep the check past its bound;
/// 9. `vox 1.2.3.4` is not a vox version.
///
/// And nothing a staged leftover started is left running afterwards.
///
/// Mutations: the flushes of the recovery path removed → red on (6); completions skipped → red on
/// (7); the check's timeout or its `vox <version>` rule removed → red on (4) or (5).
#[test]
#[ignore = "real install directories and the shipped binary; the macOS release gate runs it"]
fn the_recovery_path_is_bounded_durable_and_complete() {
    watchdog::arm();
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let mut failures: Vec<String> = Vec::new();

    // 4. a leftover that hangs
    {
        let dir = install_dir(&tmp.path().join("hangs"));
        impostor(&dir.join(".vox-rollback.partial"), "sleep 613");
        let t0 = std::time::Instant::now();
        let (ok, said) = rollback(&dir, &home);
        let took = t0.elapsed();
        let installed = dir.join(".vox-previous").exists();
        let left = dir.join(".vox-rollback.partial").exists();
        eprintln!(
            "[proof] (4) a hanging leftover: ok={ok} in {took:?}; installed as .vox-previous: \
             {installed}; left: {left}"
        );
        if ok || installed || left || took > std::time::Duration::from_secs(20) {
            failures.push(format!(
                "(4) a hanging leftover: ok={ok}, took {took:?}, installed {installed}, left \
                 {left}: {said}"
            ));
        }
    }
    // 5. a leftover that answers, but not as a vox
    {
        let dir = install_dir(&tmp.path().join("impostor"));
        impostor(&dir.join(".vox-rollback.partial"), "echo hello world");
        let (ok, said) = rollback(&dir, &home);
        let installed = dir.join(".vox-previous").exists();
        eprintln!(
            "[proof] (5) a leftover that says \"hello world\": ok={ok}; installed: {installed}"
        );
        if ok || installed {
            failures.push(format!(
                "(5) a leftover that is not a vox was installed: ok={ok}, installed {installed}: \
                 {said}"
            ));
        }
    }
    // 8. a leftover that leaves a child holding its stdout: the check is still bounded
    {
        let dir = install_dir(&tmp.path().join("holds-stdout"));
        impostor(
            &dir.join(".vox-rollback.partial"),
            "sleep 31.5 &\necho \"vox 0.0.1\"",
        );
        let t0 = std::time::Instant::now();
        let (ok, said) = rollback(&dir, &home);
        let took = t0.elapsed();
        eprintln!("[proof] (8) a leftover whose child holds stdout: ok={ok} in {took:?}");
        if took > std::time::Duration::from_secs(20) {
            failures.push(format!(
                "(8) a leftover's child holding stdout kept the rollback {took:?}: {said}"
            ));
        }
    }
    // 9. a version with a fourth number is not a vox's
    {
        let dir = install_dir(&tmp.path().join("four-numbers"));
        impostor(&dir.join(".vox-rollback.partial"), "echo \"vox 1.2.3.4\"");
        let (ok, said) = rollback(&dir, &home);
        let installed = dir.join(".vox-previous").exists();
        eprintln!(
            "[proof] (9) a leftover that says \"vox 1.2.3.4\": ok={ok}; installed: {installed}"
        );
        if ok || installed {
            failures.push(format!(
                "(9) a leftover saying vox 1.2.3.4 was installed: ok={ok}: {said}"
            ));
        }
    }
    // 6a. finishing the swap flushes the directory after its rename
    {
        let dir = install_dir(&tmp.path().join("durable-finish"));
        previous_stub(&dir.join(".vox-rollback.partial"), "0.0.1");
        let log = tmp.path().join("finish.tsv");
        let (ok, said) = rollback_with(&dir, &home, false, Some(&log));
        let events = syscalls::parse(&std::fs::read_to_string(&log).unwrap_or_default());
        syscalls::assert_the_recorder_saw_vox(&events, "(6a) finishing the swap");
        let (scratch, previous, dir_n) = (
            norm(&dir.join(".vox-rollback.partial")),
            norm(&dir.join(".vox-previous")),
            std::fs::canonicalize(&dir).unwrap(),
        );
        let renamed = find(
            &events,
            0,
            |c| matches!(c, Call::Rename { from, to } if norm(from) == scratch && norm(to) == previous),
        );
        let flushed_after = renamed.is_some_and(|i| {
            events[i + 1..].iter().any(|e| {
                (e.ret == 0 || e.errno == 22 || e.errno == 45)
                    && matches!(&e.call, Call::Sync { path, .. }
                        if std::fs::canonicalize(path).unwrap_or_else(|_| path.clone()) == dir_n)
            })
        });
        eprintln!(
            "[proof] (6a) finishing the swap: ok={ok}; {} calls; rename seen: {}; directory \
             flushed after it: {flushed_after}",
            events.len(),
            renamed.is_some()
        );
        if !ok || renamed.is_none() {
            failures.push(format!(
                "CANNOT MEASURE (6a): the recovery or its rename was not seen: ok={ok}: {said}"
            ));
        } else if !flushed_after {
            failures.push("(6a) the directory was not flushed after finishing the swap".to_owned());
        }
    }
    // 6b. discarding a leftover copy flushes the directory before the name is used again
    {
        let dir = install_dir(&tmp.path().join("durable-discard"));
        previous_stub(&dir.join(".vox-previous"), "0.0.1");
        std::fs::copy(dir.join("vox"), dir.join(".vox-rollback.partial")).unwrap();
        let log = tmp.path().join("discard.tsv");
        let (ok, said) = rollback_with(&dir, &home, false, Some(&log));
        let events = syscalls::parse(&std::fs::read_to_string(&log).unwrap_or_default());
        syscalls::assert_the_recorder_saw_vox(&events, "(6b) discarding a leftover copy");
        let (scratch, dir_n) = (
            norm(&dir.join(".vox-rollback.partial")),
            std::fs::canonicalize(&dir).unwrap(),
        );
        let refilled = events.iter().position(|e| e.call.fills(&scratch));
        let flushed_before = refilled.is_some_and(|i| {
            events[..i].iter().any(|e| {
                (e.ret == 0 || e.errno == 22 || e.errno == 45)
                    && matches!(&e.call, Call::Sync { path, .. }
                        if std::fs::canonicalize(path).unwrap_or_else(|_| path.clone()) == dir_n)
            })
        });
        eprintln!(
            "[proof] (6b) discarding a leftover copy: ok={ok}; {} calls; the name refilled: {}; \
             directory flushed before that: {flushed_before}",
            events.len(),
            refilled.is_some()
        );
        if !ok || refilled.is_none() {
            failures.push(format!(
                "CANNOT MEASURE (6b): the rollback after the discard was not seen: ok={ok}: {said}"
            ));
        } else if !flushed_before {
            failures.push(
                "(6b) the directory was not flushed between discarding the leftover and reusing \
                 its name"
                    .to_owned(),
            );
        }
    }
    // 7. completions, as a rollback refreshes them
    {
        let normal = install_dir(&tmp.path().join("shell-normal"));
        previous_stub(&normal.join(".vox-previous"), "0.0.1");
        let (ok_n, said_n) = rollback_with(&normal, &tmp.path().join("home-n"), true, None);
        let finish = install_dir(&tmp.path().join("shell-finish"));
        previous_stub(&finish.join(".vox-rollback.partial"), "0.0.1");
        let (ok_f, said_f) = rollback_with(&finish, &tmp.path().join("home-f"), true, None);
        // What follows the recovery's own line is the shell set-up's, as after a rollback. This
        // build's set-up says `vox shell-setup: <shell>: …`; its paths name the private HOME, so
        // the prefix is what is compared.
        let tail_f: Vec<&str> = said_f.lines().skip(1).collect();
        let refreshed = tail_f.iter().any(|l| l.starts_with("vox shell-setup:"));
        eprintln!(
            "[proof] (7) completions: a normal rollback ok={ok_n} printed {} line(s) after its \
             own; the finished recovery ok={ok_f} printed {}, the shell set-up's among them: \
             {refreshed}",
            said_n.lines().count().saturating_sub(1),
            tail_f.len()
        );
        if !(ok_f && refreshed) {
            failures.push(format!(
                "(7) finishing an interrupted rollback did not refresh completions: {said_f}"
            ));
        }
    }
    // Nothing the staged leftovers started outlives the test: a check that kills only the
    // leftover leaves its children behind (#247, verifier).
    let stray: Vec<String> = ["sleep 613", "sleep 31.5"]
        .iter()
        .flat_map(|pat| {
            let out = Command::new("pgrep").args(["-f", pat]).output().ok();
            out.map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
        })
        .collect();
    for pid in &stray {
        let _ = Command::new("kill").args(["-KILL", pid]).status();
    }
    eprintln!("[proof] processes the leftovers left running: {stray:?}");
    if !stray.is_empty() {
        failures.push(format!(
            "the leftovers' children outlived the rollback: {stray:?} (killed by PID now)"
        ));
    }
    eprintln!("[proof] {} of 8 claims failed", failures.len());
    assert!(
        failures.is_empty(),
        "the recovery path is not bounded, durable and complete:\n{}",
        failures.join("\n")
    );
}
