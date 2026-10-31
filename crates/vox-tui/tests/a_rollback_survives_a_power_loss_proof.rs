//! Rollback recovery and unsafe-leftover refusal through the shipped binary.
//!
//! These journeys prove what a person gets after interrupted rollback staging, including
//! runnable versions, refusal of invalid executables and cleanup of their child processes.
//! They do not simulate power loss or claim to prove durability from syscall ordering.
//! Durability remains a source-review and spike obligation, not a mechanism gate (ADR-018).

#![cfg(target_os = "macos")]

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::path::{Path, PathBuf};
use std::process::Command;

const VOX: &str = env!("CARGO_BIN_EXE_vox");
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// An install as `install.sh` makes one: the real `vox`, and a marker naming its channel.
fn install_dir(root: &Path) -> PathBuf {
    let dir = root.join("bin");
    std::fs::create_dir_all(&dir).expect("APPARATUS: cannot make the install directory");
    std::fs::copy(VOX, dir.join("vox")).expect("APPARATUS: cannot copy vox into the install");
    std::fs::write(
        dir.join(".vox-standalone.json"),
        "{\"kind\":\"vox.install-channel\",\"schema_version\":1,\"package\":\"vox\",\
         \"channel\":\"stable\"}\n",
    )
    .expect("APPARATUS: cannot write the install's channel marker");
    dir
}

/// Stage the other genuinely compiled binary, never a script impersonating a release.
fn previous_binary(path: &Path) -> String {
    let binary = std::env::var_os("VOX_PROOF_NEXT_BINARY").expect(
        "APPARATUS: set VOX_PROOF_NEXT_BINARY to a genuinely compiled different-version vox",
    );
    let version = version_of(Path::new(&binary))
        .expect("APPARATUS: next-version binary does not report its version");
    assert!(
        version.starts_with("vox ") && version != format!("vox {VERSION}"),
        "APPARATUS: next-version binary must report a different vox version: {version}"
    );
    std::fs::copy(binary, path).expect("APPARATUS: cannot copy the next-version binary");
    make_runnable(path);
    version
}

/// Mode 0755, as an installed binary has.
fn make_runnable(path: &Path) {
    let mut p = std::fs::metadata(path)
        .expect("APPARATUS: cannot read a staged file's mode")
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut p, 0o755);
    std::fs::set_permissions(path, p).expect("APPARATUS: cannot make a staged file runnable");
}

/// The most the apparatus may take — `/usr/bin/true` here and now — before a rollback
/// over its bound is the runner's, not the product's.
const APPARATUS_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// The apparatus clock: how long this machine takes, now, to start a process that is **not**
/// vox (`/usr/bin/true`), spawned as vox is. A stalled runner stalls this too; a vox that is slow,
/// even only to start, does not, so it reads as the product's (the #332 trap).
fn apparatus_spawn() -> std::time::Duration {
    let t = std::time::Instant::now();
    let ok = std::process::Command::new("/usr/bin/true")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap_or_else(|e| panic!("APPARATUS: spawn /usr/bin/true for the apparatus clock: {e}"))
        .success();
    assert!(
        ok,
        "APPARATUS: /usr/bin/true failed, so the apparatus clock cannot be read"
    );
    t.elapsed()
}

/// What `path --version` says, or `None` if it did not run.
fn version_of(path: &Path) -> Option<String> {
    let scratch = path.parent()?;
    let out = Command::new(path)
        .arg("--version")
        .env_clear()
        .env("VOX_DATA_DIR", scratch.join("version-data"))
        .env("VOX_CONFIG_DIR", scratch.join("version-config"))
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// Run rollback from the owned install with both profile roots isolated.
fn rollback(dir: &Path, home: &Path) -> (bool, String) {
    let out = Command::new(dir.join("vox"))
        .args(["update", "--rollback"])
        .env_clear()
        .env("HOME", home)
        .env("VOX_DATA_DIR", home.join("data"))
        .env("VOX_CONFIG_DIR", home.join("config"))
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("VOX_NO_SHELL_SETUP", "1")
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot run vox update --rollback: {e}"));
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
    std::fs::write(path, format!("#!/bin/sh\n{body}\n"))
        .expect("APPARATUS: cannot write a staged leftover");
    make_runnable(path);
}

/// **A rollback a power loss interrupted is finished by the next one, not refused** (#242, the
/// verifier's follow-up). `do_rollback` copies `vox` to `.vox-rollback.partial`, renames
/// `.vox-previous` onto `vox`, then renames the copy to `.vox-previous`. A power loss between the
/// renames left `vox` (the rolled-back binary) and the partial copy (the other one), with no
/// `.vox-previous`, and every later `--rollback` refused: "no previous vox was retained". Staged
/// here directly, as each state a power loss can leave (the binary that runs the next rollback is
/// whatever is `vox` then, so this build is `vox`, and the other binary is genuinely compiled):
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
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).expect("APPARATUS: cannot make the private HOME");
    let mut failures: Vec<String> = Vec::new();

    // 1. between the renames
    {
        let root = tmp.path().join("between");
        let dir = install_dir(&root);
        let other_version = previous_binary(&dir.join(".vox-rollback.partial"));
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
            && previous.as_deref() == Some(other_version.as_str())
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
        let other_version = previous_binary(&dir.join(".vox-previous"));
        std::fs::copy(dir.join("vox"), dir.join(".vox-rollback.partial"))
            .expect("APPARATUS: cannot stage the leftover copy");
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
            && active.as_deref() == Some(other_version.as_str())
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
        std::fs::write(dir.join(".vox-rollback.partial"), b"")
            .expect("APPARATUS: cannot stage the empty leftover");
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
        "PRODUCT: a rollback does not recover what a power loss left:\n{}",
        failures.join("\n")
    );
}

/// #247's verifier's gaps, each shown on the shipped binary:
///
/// 4. a leftover that **hangs** is not a `vox`: it is discarded within the check's timeout, never
///    installed, and the rollback answers in seconds;
/// 5. a leftover that exits 0 but does not say `vox <version>` is not installed either;
/// 8. a leftover that leaves a child holding its stdout cannot keep the check past its bound;
/// 9. `vox 1.2.3.4` is not a vox version.
///
/// And nothing a staged leftover started is left running afterwards.
///
/// Mutations: disabling the executable/version refusal or child cleanup must fail these
/// consumer-visible rejection and process-lifetime assertions.
#[test]
#[ignore = "real install directories and the shipped binary; the macOS release gate runs it"]
fn recovery_refuses_unsafe_leftovers_without_leaking_children() {
    watchdog::arm();
    let tmp = tempfile::tempdir().expect("APPARATUS: no temp dir");
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).expect("APPARATUS: cannot make the private HOME");
    let mut failures: Vec<String> = Vec::new();
    // The proof's own machinery (the runner, the staged leftovers) failing.
    let mut unmeasured: Vec<String> = Vec::new();
    // Each staged leftover records the PIDs of the children it starts, so what they leave
    // running is found by PID, never by a name pattern.
    let pids = tmp.path().join("leftover-children");

    // 4. a leftover that hangs
    {
        let dir = install_dir(&tmp.path().join("hangs"));
        impostor(
            &dir.join(".vox-rollback.partial"),
            &format!("sleep 613 &\necho $! >> '{}'\nwait", pids.display()),
        );
        let t0 = std::time::Instant::now();
        let (ok, said) = rollback(&dir, &home);
        let took = t0.elapsed();
        let installed = dir.join(".vox-previous").exists();
        let left = dir.join(".vox-rollback.partial").exists();
        eprintln!(
            "[proof] (4) a hanging leftover: ok={ok} in {took:?}; installed as .vox-previous: \
             {installed}; left: {left}"
        );
        let apparatus = apparatus_spawn();
        if ok || installed || left {
            failures.push(format!(
                "(4) a hanging leftover: ok={ok}, installed {installed}, left {left}: {said}"
            ));
        } else if took > std::time::Duration::from_secs(20) && apparatus > APPARATUS_BUDGET {
            unmeasured.push(format!(
                "(4) apparatus took {apparatus:?} (budget {APPARATUS_BUDGET:?}) beside a rollback \
                 of {took:?}"
            ));
        } else if took > std::time::Duration::from_secs(20) {
            failures.push(format!(
                "(4) a hanging leftover kept the rollback {took:?} (apparatus {apparatus:?}): \
                 {said}"
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
            &format!(
                "sleep 31.5 &\necho $! >> '{}'\necho \"vox 0.0.1\"",
                pids.display()
            ),
        );
        let t0 = std::time::Instant::now();
        let (ok, said) = rollback(&dir, &home);
        let took = t0.elapsed();
        eprintln!("[proof] (8) a leftover whose child holds stdout: ok={ok} in {took:?}");
        let apparatus = apparatus_spawn();
        if took > std::time::Duration::from_secs(20) && apparatus > APPARATUS_BUDGET {
            unmeasured.push(format!(
                "(8) apparatus took {apparatus:?} (budget {APPARATUS_BUDGET:?}) beside a rollback \
                 of {took:?}"
            ));
        } else if took > std::time::Duration::from_secs(20) {
            failures.push(format!(
                "(8) a leftover's child holding stdout kept the rollback {took:?} (apparatus \
                 {apparatus:?}): {said}"
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
    // Nothing the staged leftovers started outlives the test: a check that kills only the
    // leftover leaves its children behind (#247, verifier). Each child's PID was recorded as it
    // started; one still alive is a stray, killed here by that PID.
    let recorded: Vec<String> = std::fs::read_to_string(&pids)
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    if recorded.len() < 2 {
        unmeasured.push(format!(
            "the leftovers recorded {} child PID(s), not the 2 they start: {recorded:?}",
            recorded.len()
        ));
    }
    let stray: Vec<String> = recorded
        .iter()
        .filter(|pid| {
            Command::new("kill")
                .args(["-0", pid])
                .status()
                .is_ok_and(|s| s.success())
        })
        .cloned()
        .collect();
    for pid in &stray {
        let killed = Command::new("kill")
            .args(["-KILL", pid])
            .status()
            .is_ok_and(|s| s.success());
        assert!(killed, "APPARATUS: kill -KILL {pid} did not take");
    }
    eprintln!("[proof] processes the leftovers left running: {stray:?} of {recorded:?}");
    if !stray.is_empty() {
        failures.push(format!(
            "the leftovers' children outlived the rollback: {stray:?} (killed by PID now)"
        ));
    }
    assert!(
        failures.is_empty(),
        "PRODUCT: rollback accepted unsafe leftover input or leaked its children:\n{}",
        failures.join("\n")
    );
    assert!(
        unmeasured.is_empty(),
        "APPARATUS: {}",
        unmeasured.join("\n")
    );
}
