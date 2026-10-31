//! `vox update` for a macOS install: Vox.app is replaced whole (ADR-014 M-29, ADR-028 I-3).
//!
//! `install.sh` lays an install out in one folder, `/Applications` or `~/Applications`:
//!
//! - `Vox.app`, carrying this binary at `Contents/Helpers/vox`, which `~/.local/bin/vox` links to;
//! - `.vox-standalone.json`, the marker, beside the bundle because a file inside it would break
//!   its code seal;
//! - `.Vox.app.previous`, the bundle the last update or install replaced, for `--rollback`;
//! - `.vox-standalone.lock`, held for a whole transition.
//!
//! The target updater uses its pinned vox record and fetches the app record for that exact
//! version, downloads the app, and unpacks it beside the bundle as `.Vox.app.partial`. It verifies
//! every part before anything is renamed: the vox inside is byte for byte the vox the record names,
//! and Apple vouches for both under the Developer IDs that signed the installed ones. Then one
//! `renameatx_np(RENAME_SWAP)` puts the new bundle in place, so `Vox.app` is never missing or
//! partial; the old one becomes `.Vox.app.previous`. A rollback is the same swap the other way.
//! The daemon is then restarted onto the new version ([`super::restart`]); an app that was
//! running from this bundle is normally quit before the swap and relaunched afterward.

use std::fs;
use std::io::{BufRead as _, Read as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use super::{
    apple_required, codesign_ok, download_asset, fetch_app_record_at, fetch_record,
    run_shell_setup, signing_identity, sync_dir, target_triple, usage, InstallLock, Validated,
    IO_BUFFER_BYTES, MAX_VERSION_OUTPUT_BYTES,
};
use crate::app::AppError;

/// The bundle's name in its folder.
const BUNDLE: &str = "Vox.app";
/// The bundle the last transition replaced, kept for `--rollback`.
const PREVIOUS: &str = ".Vox.app.previous";
/// A verified candidate waiting to be swapped in; scratch whenever no update is running.
const PARTIAL: &str = ".Vox.app.partial";
/// Where the download is unpacked before its one `Vox.app` is moved to [`PARTIAL`].
const UNPACK_PARTIAL: &str = ".Vox.app.unpack.partial";
/// The CLI inside the bundle.
const HELPER: &str = "Contents/Helpers/vox";
/// The journal of a publish under way: it holds the version being published and the bundle that
/// was [`PREVIOUS`], so a publish cut short is finished or undone by the next transition
/// ([`recover`]) instead of losing the replaced bundle.
const PUBLISHING: &str = ".Vox.app.publishing";
/// In [`PUBLISHING`]: the version the publish puts in place.
const PUBLISHING_VERSION: &str = "version";
const TRANSITION: &str = "transition.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct Transition {
    kind: TransitionKind,
    version: String,
    source: BundleIdentity,
    target: BundleIdentity,
    daemon_data_root: Vec<u8>,
    daemon_config_dir: Vec<u8>,
    daemon: super::restart::DaemonIntent,
    app: Option<AppIntent>,
    #[serde(default)]
    daemon_complete: bool,
    #[serde(default)]
    app_complete: bool,
    handoff_complete: bool,
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
enum TransitionKind {
    Update,
    Rollback,
    Refresh,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct BundleIdentity {
    device: u64,
    inode: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AppIntent {
    pid: u32,
    started: u64,
    data_root: Vec<u8>,
    config_dir: Vec<u8>,
    home: Option<Vec<u8>>,
    xdg_data: Option<Vec<u8>>,
    xdg_config: Option<Vec<u8>>,
}

fn bundle_identity(path: &Path) -> Result<BundleIdentity, AppError> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| usage(format!("cannot inspect {}: {e}", path.display())))?;
    if !metadata.is_dir() {
        return Err(usage(format!(
            "{} is not a bundle directory",
            path.display()
        )));
    }
    Ok(BundleIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn path_exists(path: &Path) -> Result<bool, AppError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(usage(format!("cannot inspect {}: {e}", path.display()))),
    }
}

fn write_transition_in(journal: &Path, transition: &Transition) -> Result<(), AppError> {
    use std::io::Write as _;
    let temporary = journal.join("transition.tmp");
    let destination = journal.join(TRANSITION);
    let bytes = serde_json::to_vec(transition)
        .map_err(|e| usage(format!("cannot encode transition: {e}")))?;
    let mut file = fs::File::create(&temporary)
        .map_err(|e| usage(format!("cannot create {}: {e}", temporary.display())))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| {
            usage(format!(
                "cannot write and sync {}: {e}",
                temporary.display()
            ))
        })?;
    fs::rename(&temporary, &destination).map_err(|e| {
        usage(format!(
            "cannot rename {} to {}: {e}",
            temporary.display(),
            destination.display()
        ))
    })?;
    sync_dir(journal)
        .map_err(|e| usage(format!("cannot sync directory {}: {e}", journal.display())))
}

fn write_transition(apps: &Path, transition: &Transition) -> Result<(), AppError> {
    write_transition_in(&apps.join(PUBLISHING), transition)?;
    sync_dir(apps).map_err(|e| usage(format!("cannot sync directory {}: {e}", apps.display())))
}

fn transition_record(
    source: &Path,
    target: &Path,
    kind: TransitionKind,
    version: &str,
    app: &Option<StoppedApp>,
) -> Result<Transition, AppError> {
    use std::os::unix::ffi::OsStrExt as _;
    let account = match app.as_ref() {
        Some(app) => vox_core::node::paths::Account {
            data_root: app.account.data_root.clone(),
            config_dir: app.account.config_dir.clone(),
        },
        None => vox_core::node::paths::Account::of(None, None)
            .map_err(|e| usage(format!("cannot resolve daemon account: {e}")))?,
    };
    let daemon_data_root = account.data_root.as_os_str().as_bytes().to_vec();
    let daemon_config_dir = account.config_dir.as_os_str().as_bytes().to_vec();
    let app = app.as_ref().map(|app| AppIntent {
        pid: app.identity.pid,
        started: app.identity.started,
        data_root: app.account.data_root.as_os_str().as_bytes().to_vec(),
        config_dir: app.account.config_dir.as_os_str().as_bytes().to_vec(),
        home: app.environment[2].as_ref().map(|s| s.as_bytes().to_vec()),
        xdg_data: app.environment[3].as_ref().map(|s| s.as_bytes().to_vec()),
        xdg_config: app.environment[4].as_ref().map(|s| s.as_bytes().to_vec()),
    });
    Ok(Transition {
        kind,
        version: version.to_owned(),
        source: bundle_identity(source)?,
        target: bundle_identity(target)?,
        daemon_data_root,
        daemon_config_dir,
        daemon: super::restart::capture_daemon_intent(&account)?,
        app,
        daemon_complete: false,
        app_complete: false,
        handoff_complete: false,
    })
}

fn prepare_transition(
    apps: &Path,
    candidate: &Path,
    kind: TransitionKind,
    version: &str,
    app: &Option<StoppedApp>,
) -> Result<Transition, AppError> {
    let transition = transition_record(&apps.join(BUNDLE), candidate, kind, version, app)?;
    let journal = apps.join(PUBLISHING);
    if path_exists(&journal)? {
        return Err(usage(format!(
            "journal {} already exists",
            journal.display()
        )));
    }
    let preparing = tempfile::Builder::new()
        .prefix(".Vox.app.prepare.")
        .tempdir_in(apps)
        .map_err(|e| {
            usage(format!(
                "cannot create transition preparation directory in {}: {e}",
                apps.display()
            ))
        })?;
    write_transition_in(preparing.path(), &transition)?;
    fs::rename(preparing.path(), &journal)
        .map_err(|e| usage(format!("cannot publish journal {}: {e}", journal.display())))?;
    sync_dir(apps).map_err(|e| usage(format!("cannot sync directory {}: {e}", apps.display())))?;
    Ok(transition)
}

/// **Test-only**: abort the process right after a publish's swap, before the replaced bundle is
/// renamed to [`PREVIOUS`], so a proof can stand a publish cut short at its one awkward moment.
/// Nothing a person runs sets it; not compiled in without the `test-knobs` feature (V210-105).
#[cfg(feature = "test-knobs")]
const TEST_ABORT_AFTER_SWAP_ENV: &str = "VOX_TEST_ABORT_AFTER_SWAP";

/// Check the channel or refresh the installed bundle without downloading a candidate.
pub(super) fn update(
    apps: &Path,
    channel: &str,
    exe: &Path,
    check_only: bool,
) -> Result<(), AppError> {
    if check_only {
        let vox = fetch_record(channel, target_triple())?;
        let current = installed_version(apps)?;
        if vox.version > current {
            println!(
                "Vox {} is available on {channel} (this is {current})",
                vox.version_text
            );
        } else {
            println!(
                "Vox {current} is current (the newest {channel} release is {})",
                vox.version_text
            );
        }
        return Ok(());
    }
    let _lock = InstallLock::acquire(apps)?;
    if repair_locked(apps, exe)? {
        return Ok(());
    }
    refresh(apps, exe)
}

/// Repair retained local work after a release lookup fails, without requiring network access.
pub(super) fn repair(apps: &Path, exe: &Path) -> Result<bool, AppError> {
    let _lock = InstallLock::acquire(apps)?;
    repair_locked(apps, exe)
}

fn repair_locked(apps: &Path, exe: &Path) -> Result<bool, AppError> {
    let repaired = recover(apps)?;
    if repaired.is_empty() {
        return Ok(false);
    }
    if !repaired.handoff_done {
        let active = apps.join(BUNDLE);
        let now = app_version(&active)
            .ok_or_else(|| usage("the repaired Vox.app has no readable version"))?;
        journaled_refresh(apps, &active, &now)?;
    }
    shell_setup_from(apps, exe);
    repaired.say_without_swap();
    Ok(true)
}

fn installed_version(apps: &Path) -> Result<semver::Version, AppError> {
    let helper = apps.join(BUNDLE).join(HELPER);
    let version = super::binary_version(&helper).ok_or_else(|| {
        usage(format!(
            "cannot identify installed version at {}",
            helper.display()
        ))
    })?;
    semver::Version::parse(&version)
        .map_err(|_| usage(format!("installed version {version:?} is not SemVer")))
}

fn refresh(apps: &Path, exe: &Path) -> Result<(), AppError> {
    let active = apps.join(BUNDLE);
    let now = app_version(&active).ok_or_else(|| {
        usage(format!(
            "cannot identify installed version at {}",
            active.display()
        ))
    })?;
    journaled_refresh(apps, &active, &now)?;
    shell_setup_from(apps, exe);
    sweep(apps, &mut Recovery::default())?;
    println!("Vox {now} is current; {}", super::skill_said());
    Ok(())
}

/// Apply the already verified helper release, with the target engine owning the transaction.
pub(super) fn apply(apps: &Path, exe: &Path, vox: &Validated) -> Result<(), AppError> {
    let _lock = InstallLock::acquire(apps)?;
    let channel = super::Marker::read(&apps.join(super::MARKER_NAME))?.channel;
    if channel != vox.record.channel {
        return Err(usage(
            "the install channel changed while the update was being prepared",
        ));
    }
    match super::detect_channel(exe)? {
        super::Channel::Bundle {
            apps_dir,
            channel: owned_channel,
        } if apps_dir == apps && owned_channel == channel => {}
        _ => {
            return Err(usage(
                "the original helper no longer belongs to this bundle install",
            ))
        }
    }
    let repaired = repair_locked(apps, exe)?;
    let current = installed_version(apps)?;
    if vox.version <= current {
        return if repaired { Ok(()) } else { refresh(apps, exe) };
    }
    let app = fetch_app_record_at(&channel, &vox.target, &vox.version_text)?;
    if app.version != vox.version {
        return Err(usage(format!(
            "the {channel} release offers vox {} but Vox.app {}; they are applied together or not at all",
            vox.version_text, app.version_text
        )));
    }

    let active = apps.join(BUNDLE);
    if !active.join(HELPER).is_file() {
        return Err(usage(format!(
            "{} holds the install marker but no {BUNDLE} with {HELPER}",
            apps.display()
        )));
    }

    let mut downloading = tempfile::Builder::new()
        .prefix("vox-update.")
        .tempfile()
        .map_err(|e| {
            usage(format!(
                "cannot create temporary download in {}: {e}",
                std::env::temp_dir().display()
            ))
        })?;
    download_asset(
        &app,
        &format!("Vox-{}-{}.zip", app.version_text, app.target),
        downloading.as_file_mut(),
    )?;
    downloading.as_file().sync_all().map_err(|e| {
        usage(format!(
            "cannot sync download {}: {e}",
            downloading.path().display()
        ))
    })?;
    let zip = downloading.into_temp_path();

    let staged = unpack(apps, &zip)?;
    if let Err(refused) = verify(&active, &staged, vox) {
        return Err(match clear_candidate(&staged) {
            Ok(()) => refused,
            Err(cleanup) => usage(format!("{refused}; candidate cleanup failed: {cleanup}")),
        });
    }
    let running = inspect_app(&active)?;
    let mut transition = prepare_transition(
        apps,
        &staged,
        TransitionKind::Update,
        &vox.version_text,
        &running,
    )?;
    stop_captured_app(&active, &running)?;
    let aside = match publish(apps, &vox.version_text) {
        Ok(aside) => aside,
        Err(e) => {
            return Err(transition_failed_journal(
                apps,
                &running,
                &mut transition,
                e,
            ))
        }
    };

    println!("updated: {} -> Vox {}", active.display(), vox.version_text);
    println!(
        "         the previous Vox.app is kept at {} for `vox update --rollback`",
        apps.join(PREVIOUS).display()
    );

    let handoff = transition_handoff(apps, &active, &vox.version_text, &running, &mut transition);
    shell_setup_from(apps, exe);
    let mut failures = Vec::new();
    if let Some(e) = aside {
        failures.push(e.to_string());
    }
    if let Err(e) = handoff {
        failures.push(e.to_string());
    }
    if !failures.is_empty() {
        return Err(usage(format!(
            "Vox {} is installed; transition incomplete: {}; run `vox update` for local repair",
            vox.version_text,
            failures.join("; ")
        )));
    }
    finish_journal(apps).and_then(|()| sweep(apps, &mut Recovery::default()))
        .map_err(|e| usage(format!("Vox {} is installed and handoff completed, but cleanup failed: {e}; run `vox update` for local repair", vox.version_text)))
}

/// `vox update --rollback` for the Vox.app in `apps`: swap it with `.Vox.app.previous`, so a
/// rollback is itself reversible.
///
/// # Errors
/// No previous bundle, or a failed swap.
pub(super) fn rollback(apps: &Path, exe: &Path) -> Result<(), AppError> {
    let active = apps.join(BUNDLE);
    let previous = apps.join(PREVIOUS);
    let _lock = InstallLock::acquire(apps)?;
    let repaired = recover(apps)?;
    if !repaired.is_empty() {
        if !repaired.handoff_done {
            let now = app_version(&active)
                .ok_or_else(|| usage("the repaired Vox.app has no readable version"))?;
            journaled_refresh(apps, &active, &now)?;
        }
        shell_setup_from(apps, exe);
        repaired.say_without_swap();
        return Ok(());
    }
    if !previous.join(HELPER).is_file() {
        return Err(usage(format!(
            "no previous Vox.app was retained in {} — nothing to roll back to",
            apps.display()
        )));
    }
    let running = inspect_app(&active)?;
    let was = app_version(&active).ok_or_else(|| usage("active Vox.app version is unavailable"))?;
    let target =
        app_version(&previous).ok_or_else(|| usage("previous Vox.app version is unavailable"))?;
    let mut transition =
        prepare_transition(apps, &previous, TransitionKind::Rollback, &target, &running)?;
    stop_captured_app(&active, &running)?;
    // The kept bundle becomes an application again before it is swapped in; the one it replaces
    // is set aside after, so neither is ever both in place and set aside.
    if let Err(e) = restore(&previous) {
        return Err(transition_failed_journal(
            apps,
            &running,
            &mut transition,
            e,
        ));
    }
    if let Err(failed) = swap(&previous, &active) {
        // Nothing was swapped: the kept bundle is set aside again, never left an application.
        let error = match set_aside(&previous) {
            Ok(()) => failed,
            Err(aside) => AppError::Usage(format!(
                "the rollback swap failed ({failed}), and {aside}; run `vox update` to repair, \
                 and until then open Vox as {}",
                active.display()
            )),
        };
        return Err(transition_failed_journal(
            apps,
            &running,
            &mut transition,
            error,
        ));
    }
    let sync_error = sync_dir(apps)
        .err()
        .map(|e| usage(format!("cannot sync directory {}: {e}", apps.display())));
    // The rollback is done at this point. A set-aside that fails is reported last, after the
    // active bundle is registered and the daemon restarted, so a failed step never leaves the
    // rest of the transition undone or invites a second --rollback that would reverse it.
    let aside = set_aside(&previous);
    if let Err(said) = launch_services(true, &active) {
        println!("note: {said}; the current Vox.app is in place and opens by path");
    }
    let now = app_version(&active).unwrap_or_else(|| "unknown".to_owned());
    println!("rolled back: {} -> Vox {now}", active.display());
    println!(
        "         Vox {was} is kept at {} for --rollback",
        previous.display()
    );
    let handoff = transition_handoff(apps, &active, &now, &running, &mut transition);
    shell_setup_from(apps, exe);
    let mut failures = Vec::new();
    if let Some(e) = sync_error {
        failures.push(e.to_string());
    }
    if let Err(e) = aside {
        failures.push(e.to_string());
    }
    if let Err(e) = handoff {
        failures.push(e.to_string());
    }
    if !failures.is_empty() {
        return Err(usage(format!(
            "rollback to Vox {now} is already in place; do not repeat --rollback; run `vox update` for local repair: {}",
            failures.join("; ")
        )));
    }
    finish_journal(apps).map_err(|e| usage(format!(
        "rollback to Vox {now} is already in place; do not repeat --rollback; run `vox update` for local repair: {e}"
    )))
}

/// Exchange two paths in one step (`renameatx_np` with `RENAME_SWAP`): each name holds a whole
/// bundle before and after, never neither.
fn swap(a: &Path, b: &Path) -> Result<(), AppError> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        a,
        rustix::fs::CWD,
        b,
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .map_err(|e| {
        usage(format!(
            "cannot exchange {} and {}: {e}",
            a.display(),
            b.display()
        ))
    })
}

/// Make the verified `.Vox.app.partial` the bundle, keeping the one it replaces.
///
/// **Journalled** ([`PUBLISHING`]): the bundle that was [`PREVIOUS`] is moved into the journal
/// rather than removed, so a swap that fails puts it back, and a publish cut short between the
/// swap and the rename (which leaves the replaced bundle under the partial name) is finished by
/// [`recover`] rather than having that bundle cleared as scratch.
fn publish(apps: &Path, version: &str) -> Result<Option<AppError>, AppError> {
    let staged = apps.join(PARTIAL);
    let previous = apps.join(PREVIOUS);
    let journal = apps.join(PUBLISHING);
    // The authoritative transition was persisted before the app was stopped.
    if path_exists(&previous)? {
        fs::rename(&previous, journal.join(BUNDLE)).map_err(|e| {
            usage(format!(
                "cannot rename {} to {}: {e}",
                previous.display(),
                journal.join(BUNDLE).display()
            ))
        })?;
    }
    let before_swap = sync_dir(apps)
        .map_err(|e| usage(format!("cannot sync directory {}: {e}", apps.display())))
        .and_then(|()| swap(&staged, &apps.join(BUNDLE)));
    if let Err(failed) = before_swap {
        let kept = journal.join(BUNDLE);
        let restored = if path_exists(&kept).unwrap_or(true) {
            fs::rename(&kept, &previous).map_err(|e| {
                usage(format!(
                    "cannot restore {} to {}: {e}",
                    kept.display(),
                    previous.display()
                ))
            })
        } else {
            Ok(())
        };
        return Err(match restored {
            Ok(()) => failed,
            Err(e) => usage(format!(
                "{failed}; rollback authority restoration failed: {e}"
            )),
        });
    }
    sync_dir(apps).map_err(|e| {
        usage(format!(
            "cannot sync directory {} after exchange: {e}",
            apps.display()
        ))
    })?;
    #[cfg(feature = "test-knobs")]
    if std::env::var_os(TEST_ABORT_AFTER_SWAP_ENV).is_some_and(|v| !v.is_empty()) {
        std::process::abort();
    }
    // The swap left the replaced bundle under the partial name.
    fs::rename(&staged, &previous).map_err(|e| {
        usage(format!(
            "cannot rename {} to {}: {e}",
            staged.display(),
            previous.display()
        ))
    })?;
    sync_dir(apps).map_err(|e| {
        usage(format!(
            "cannot sync directory {} after rename: {e}",
            apps.display()
        ))
    })?;
    let aside = set_aside(&previous);
    if let Err(said) = launch_services(true, &apps.join(BUNDLE)) {
        println!("note: {said}; the current Vox.app is in place and opens by path");
    }
    // Cleanup is deferred until the owned handoff has completed.
    // The publish is done at this point; a set-aside that failed is the caller's to report
    // after it has restarted the daemon, never a reason to leave the transition half finished.
    Ok(aside.err().map(|e| {
        AppError::Usage(format!(
            "Vox {version} is in place, but the replaced Vox.app was not set aside: {e}; run \
             `vox update` again to finish, and until then open Vox as {}",
            apps.join(BUNDLE).display()
        ))
    }))
}

fn finish_journal(apps: &Path) -> Result<(), AppError> {
    let journal = apps.join(PUBLISHING);
    let older = journal.join(BUNDLE);
    match fs::symlink_metadata(&older) {
        Ok(_) => {
            if in_use(&older) {
                retire(apps, &older)?;
            } else {
                set_aside(&older)?;
                clear(&older)?;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(usage(format!("cannot inspect {}: {e}", older.display()))),
    }
    // The live journal must never lose its record through a partial recursive removal.
    // Retire its completed authority atomically; interrupted disposal is then only cleanup.
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let completed = apps.join(format!("{COMPLETED_PREFIX}{ms}.{}", std::process::id()));
    fs::rename(&journal, &completed).map_err(|e| {
        usage(format!(
            "cannot retire completed journal {} to {}: {e}",
            journal.display(),
            completed.display()
        ))
    })?;
    sync_dir(apps).map_err(|e| {
        usage(format!(
            "cannot sync directory {} after retiring completed journal: {e}",
            apps.display()
        ))
    })?;
    clear(&completed)
}

/// Bundles retired by earlier transitions while code from them was running: `.Vox.app.retired.*`.
const RETIRED_PREFIX: &str = ".Vox.app.retired.";
/// Completed journals awaiting disposal; these never contain a retained executable.
const COMPLETED_PREFIX: &str = ".Vox.app.retired.journal.";

/// Rename `bundle` aside as retired: a daemon not restarted since an earlier update runs from it.
fn retire(apps: &Path, bundle: &Path) -> Result<(), AppError> {
    set_aside(bundle)?;
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let name = format!("{RETIRED_PREFIX}{ms}.{}", std::process::id());
    let retired = apps.join(name);
    fs::rename(bundle, &retired).map_err(|e| {
        usage(format!(
            "cannot rename {} to {}: {e}",
            bundle.display(),
            retired.display()
        ))
    })?;
    Ok(())
}

/// Tell LaunchServices about a bundle: `register` adds or refreshes the bundle in place;
/// otherwise a record made for a bundle now set aside is taken out. The set-aside bundle has no
/// `Info.plist` ([`set_aside`]), which is what keeps it unlaunchable; this call only clears the
/// record a running app may still re-register when it quits. Best effort: a refusal is said,
/// not fatal. Measured 2026-10-19: both bundles registered as `us.vox.app` with the same
/// CFBundleVersion, and reopening Vox launched the replaced 0.4.4 against the 0.4.6 daemon.
const LSREGISTER: &str = "/System/Library/Frameworks/CoreServices.framework/Frameworks/\
                          LaunchServices.framework/Support/lsregister";

fn launch_services(register: bool, bundle: &Path) -> Result<(), String> {
    let flag = if register { "-f" } else { "-u" };
    let verb = if register { "register" } else { "release" };
    match Command::new(LSREGISTER)
        .arg(flag)
        .arg(bundle)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
    {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => {
            let failure = format!(
                "LaunchServices did not {verb} {} ({status})",
                bundle.display()
            );
            if register {
                return Err(failure);
            }
            match registered_path(bundle) {
                Ok(false) => Ok(()),
                Ok(true) => Err(failure),
                Err(e) => Err(format!(
                    "{failure}; could not confirm registration absence: {e}"
                )),
            }
        }
        Err(e) => Err(format!(
            "LaunchServices was not told to {verb} {}: {e}",
            bundle.display()
        )),
    }
}

/// A failed unregister is harmless only if a successful full database dump independently proves
/// that this exact path is absent. NSWorkspace's available-applications query filters records.
fn registered_path(bundle: &Path) -> Result<bool, String> {
    let wanted = fs::canonicalize(bundle)
        .map_err(|e| format!("cannot canonicalize {}: {e}", bundle.display()))?;
    let mut child = Command::new(LSREGISTER)
        .arg("-dump")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot run lsregister -dump: {e}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or("lsregister -dump has no output stream")?;
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = Vec::new();
    let mut paths = 0_usize;
    let mut identifiers = 0_usize;
    let mut found = false;
    let mut parse_error = None;
    loop {
        line.clear();
        // Never let a malformed database record allocate unbounded memory.
        match (&mut reader).take(65_537).read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) if line.len() > 65_536 => {
                parse_error = Some("oversized LaunchServices database line".to_owned());
                break;
            }
            Ok(_) => {}
            Err(e) => {
                parse_error = Some(format!("cannot read lsregister -dump: {e}"));
                break;
            }
        }
        let Ok(text) = std::str::from_utf8(&line) else {
            parse_error = Some("LaunchServices database dump is not UTF-8".to_owned());
            break;
        };
        let text = text.trim();
        if let Some(value) = text.strip_prefix("path:") {
            paths += 1;
            let value = value.trim();
            let value = match value.rsplit_once(" (0x") {
                Some((before, suffix)) if !suffix.contains('/') => {
                    let Some(hex) = suffix.strip_suffix(')') else {
                        parse_error = Some("ambiguous LaunchServices path annotation".to_owned());
                        break;
                    };
                    if hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                        parse_error = Some("invalid LaunchServices path annotation".to_owned());
                        break;
                    }
                    before
                }
                _ => value,
            };
            let path = Path::new(value);
            if !path.is_absolute() {
                parse_error =
                    Some("LaunchServices database contains a non-absolute path".to_owned());
                break;
            }
            if path == wanted {
                found = true;
            } else if !found {
                match fs::canonicalize(path) {
                    Ok(path) => found = path == wanted,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        parse_error = Some(format!(
                            "cannot resolve registration path {} while checking {}: {e}",
                            path.display(),
                            wanted.display()
                        ));
                        break;
                    }
                }
            }
        } else if text.starts_with("identifier:") {
            identifiers += 1;
        }
    }
    if parse_error.is_some() {
        // Closing the pipe ensures a producer cannot block while we wait for it.
        drop(reader);
        let _ = child.kill();
    }
    let status = child
        .wait()
        .map_err(|e| format!("cannot wait for lsregister -dump: {e}"))?;
    if let Some(error) = parse_error {
        return Err(error);
    }
    if !status.success() {
        return Err(format!("lsregister -dump exited {status}"));
    }
    if paths == 0 || identifiers == 0 {
        return Err(format!(
            "cannot parse LaunchServices database (paths={paths}, identifiers={identifiers})"
        ));
    }
    Ok(found)
}

/// A set-aside bundle's `Info.plist`, kept under this name until a rollback restores it. Without
/// `Contents/Info.plist` the folder is no application bundle: LaunchServices cannot register it,
/// not even when the app still running from it quits, so opening Vox by its identifier never
/// lands on it (ADR-014 M-29a). `lsregister -u` is the second measure, for a record already made.
const KEPT_INFO_PLIST: &str = "Contents/Info.plist.kept";
const INFO_PLIST: &str = "Contents/Info.plist";

/// Remove the exact registration and disable the bundle even when removal fails.
fn set_aside(bundle: &Path) -> Result<(), AppError> {
    let unregister = launch_services(false, bundle).err();
    let plist = bundle.join(INFO_PLIST);
    let kept = bundle.join(KEPT_INFO_PLIST);
    let disable = match fs::symlink_metadata(&plist) {
        Ok(_) => fs::rename(&plist, &kept)
            .map_err(|e| {
                format!(
                    "cannot rename {} to {}: {e}",
                    plist.display(),
                    kept.display()
                )
            })
            .err(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => Some(format!("cannot inspect {}: {e}", plist.display())),
    };
    match (unregister, disable) {
        (None, None) => Ok(()),
        (Some(e), None) | (None, Some(e)) => Err(usage(e)),
        (Some(a), Some(b)) => Err(usage(format!("{a}; {b}"))),
    }
}

/// Make a set-aside bundle an application again, for the swap that brings it back.
fn restore(bundle: &Path) -> Result<(), AppError> {
    let kept = bundle.join(KEPT_INFO_PLIST);
    let plist = bundle.join(INFO_PLIST);
    if path_exists(&kept)? {
        fs::rename(&kept, &plist).map_err(|e| {
            usage(format!(
                "cannot rename {} to {}: {e}",
                kept.display(),
                plist.display()
            ))
        })?;
    }
    Ok(())
}

/// Remove the retired bundles nothing runs from any more.
fn sweep(apps: &Path, repaired: &mut Recovery) -> Result<(), AppError> {
    let entries = fs::read_dir(apps)
        .map_err(|e| usage(format!("cannot read directory {}: {e}", apps.display())))?;
    for entry in entries {
        let entry =
            entry.map_err(|e| usage(format!("cannot read entry in {}: {e}", apps.display())))?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(COMPLETED_PREFIX)
        {
            clear(&entry.path())?;
            repaired.retired_removed += 1;
            continue;
        }
        let retired = entry
            .file_name()
            .to_string_lossy()
            .starts_with(RETIRED_PREFIX);
        if retired {
            // Set aside first, again if an earlier attempt failed: the record goes and the
            // bundle is no application even if it then cannot be removed. One still in use stays.
            let path = entry.path();
            let was_application = path.join(INFO_PLIST).is_file();
            set_aside(&path)?;
            repaired.retired_set_aside += usize::from(was_application);
            if !in_use(&entry.path()) {
                clear(&entry.path())?;
                repaired.retired_removed += 1;
            }
        }
    }
    Ok(())
}

/// Whether any process runs one of `bundle`'s executables, as `lsof` reports it. When `lsof`
/// cannot say, the bundle is taken to be in use: kept is the safe side.
fn in_use(bundle: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    let Ok(contents) = fs::canonicalize(bundle.join("Contents")) else {
        return true;
    };
    let mut files = Vec::new();
    let mut dirs = vec![bundle.join("Contents")];
    while let Some(dir) = dirs.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            return true;
        };
        for entry in entries {
            let Ok(entry) = entry else { return true };
            let Ok(meta) = fs::symlink_metadata(entry.path()) else {
                return true;
            };
            if meta.file_type().is_symlink() {
                // Only links resolved inside the traversed tree are accounted for by its files.
                if !fs::canonicalize(entry.path()).is_ok_and(|target| target.starts_with(&contents))
                {
                    return true;
                }
            } else if meta.is_dir() {
                dirs.push(entry.path());
            } else if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                files.push(entry.path());
            }
        }
    }
    if files.is_empty() {
        return true;
    }
    // The pids, not the status: lsof exits 1 when any one file named is not open.
    Command::new("/usr/sbin/lsof")
        .arg("-t")
        .args(&files)
        .env_clear()
        .output()
        .map_or(true, |out| {
            !out.stdout.is_empty()
                || (!out.status.success()
                    && (out.status.code() != Some(1) || !out.stderr.is_empty()))
        })
}

/// Finish or undo a publish that was cut short (see [`publish`]); nothing when none was. Run
/// under the install lock, before anything else reads `apps`.
///
/// With no [`PREVIOUS`] but a bundle under [`PARTIAL`], the journal's version says which side of
/// the swap the publish stopped on: if [`BUNDLE`] is that version, the swap happened and the
/// partial name holds the replaced bundle, which becomes [`PREVIOUS`]; otherwise the partial is
/// the unpublished candidate, and goes. Either way the journal's earlier previous bundle comes
/// back when nothing has taken its place.
fn recover(apps: &Path) -> Result<Recovery, AppError> {
    let mut repaired = Recovery::default();
    let journal = apps.join(PUBLISHING);
    let journal_present = match fs::symlink_metadata(&journal) {
        Ok(meta) if meta.is_dir() => true,
        Ok(_) => {
            return Err(usage(format!(
                "journal {} is not a directory",
                journal.display()
            )))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            return Err(usage(format!(
                "cannot inspect journal {}: {e}",
                journal.display()
            )))
        }
    };
    if !journal_present {
        let mut failures = Vec::new();
        if let Err(e) = sweep(apps, &mut repaired) {
            failures.push(e.to_string());
        }
        let previous = apps.join(PREVIOUS);
        match path_exists(&previous) {
            Ok(true) => {
                repaired.previous_set_aside = previous.join(INFO_PLIST).is_file();
                if let Err(e) = set_aside(&previous) {
                    failures.push(e.to_string());
                }
            }
            Ok(false) => {}
            Err(e) => failures.push(e.to_string()),
        }
        if !failures.is_empty() {
            let active = apps.join(BUNDLE);
            let handoff = app_version(&active)
                .ok_or_else(|| {
                    usage(format!(
                        "cannot identify installed version at {}",
                        active.display()
                    ))
                })
                .and_then(|version| journaled_refresh(apps, &active, &version));
            if let Err(e) = handoff {
                failures.push(e.to_string());
            }
            return Err(usage(format!(
                "installed app cleanup is incomplete: {}; run `vox update` for local repair",
                failures.join("; ")
            )));
        }
        return Ok(repaired);
    }
    let transition_path = journal.join(TRANSITION);
    match fs::symlink_metadata(&transition_path) {
        Ok(_) => return recover_transition(apps, &transition_path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(usage(format!(
                "cannot inspect {}: {e}",
                transition_path.display()
            )))
        }
    }
    let staged = apps.join(PARTIAL);
    let previous = apps.join(PREVIOUS);
    let version_path = journal.join(PUBLISHING_VERSION);
    let published = fs::read_to_string(&version_path).map_err(|e| {
        usage(format!(
            "cannot read journal {}: {e}",
            version_path.display()
        ))
    })?;
    if semver::Version::parse(published.trim()).is_err() {
        return Err(usage(format!(
            "invalid version in journal {}",
            version_path.display()
        )));
    }
    let active_version = app_version(&apps.join(BUNDLE)).ok_or_else(|| {
        usage(format!(
            "cannot identify active version at {}; journal retained",
            apps.join(BUNDLE).display()
        ))
    })?;
    let previous_present = path_exists(&previous)?;
    let staged_present = path_exists(&staged)?;
    let staged_version = if staged_present {
        Some(app_version(&staged).ok_or_else(|| {
            usage(format!(
                "cannot identify staged bundle at {}; journal retained",
                staged.display()
            ))
        })?)
    } else {
        None
    };
    if staged_present
        && (previous_present
            || (active_version == published.trim()
                && staged_version.as_deref() == Some(published.trim())))
    {
        return Err(usage(format!(
            "ambiguous legacy journal {}; no bundles removed",
            journal.display()
        )));
    }
    if staged_present
        && active_version != published.trim()
        && staged_version.as_deref() != Some(published.trim())
    {
        return Err(usage(format!(
            "ambiguous legacy journal {}; no bundles removed",
            journal.display()
        )));
    }
    if !staged_present && (active_version != published.trim() || !previous_present) {
        return Err(usage(format!(
            "ambiguous legacy journal {}; no bundles removed",
            journal.display()
        )));
    }
    if !staged_present {
        let previous_version = app_version(&previous).ok_or_else(|| {
            usage(format!(
                "cannot identify retained bundle at {}; journal retained",
                previous.display()
            ))
        })?;
        if previous_version == published.trim() {
            return Err(usage(format!(
                "ambiguous same-version legacy journal {}; no bundles removed",
                journal.display()
            )));
        }
    }
    // Upgrade only an unambiguous legacy layout. Capture only an app observed now; a legacy
    // journal cannot tell us whether an earlier updater had already stopped a different app.
    let active = apps.join(BUNDLE);
    let running = inspect_app(&active)?;
    let (source, target) = if active_version == published.trim() {
        (if staged_present { &staged } else { &previous }, &active)
    } else {
        (&active, &staged)
    };
    let transition = transition_record(
        source,
        target,
        TransitionKind::Update,
        published.trim(),
        &running,
    )?;
    write_transition(apps, &transition)?;
    recover_transition(apps, &transition_path)
}

/// Recover using the bundle identities and owned handoff captured before the app was stopped.
fn recover_transition(apps: &Path, path: &Path) -> Result<Recovery, AppError> {
    use std::os::unix::ffi::OsStringExt as _;
    let bytes =
        fs::read(path).map_err(|e| usage(format!("cannot read {}: {e}", path.display())))?;
    let mut transition: Transition = serde_json::from_slice(&bytes)
        .map_err(|e| usage(format!("cannot parse {}: {e}", path.display())))?;
    let valid_root = |bytes: &[u8]| {
        !bytes.contains(&0)
            && PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())).is_absolute()
    };
    if (transition.source == transition.target)
        != matches!(transition.kind, TransitionKind::Refresh)
        || semver::Version::parse(&transition.version).is_err()
        || !valid_root(&transition.daemon_data_root)
        || !valid_root(&transition.daemon_config_dir)
        || !transition.daemon.is_valid()
        || (transition.handoff_complete && !(transition.daemon_complete && transition.app_complete))
        || transition.app.as_ref().is_some_and(|app| {
            app.pid == 0
                || app.started == 0
                || !valid_root(&app.data_root)
                || !valid_root(&app.config_dir)
                || app.data_root != transition.daemon_data_root
                || app.config_dir != transition.daemon_config_dir
                || app.home.as_ref().is_some_and(|v| v.contains(&0))
                || app.xdg_data.as_ref().is_some_and(|v| v.contains(&0))
                || app.xdg_config.as_ref().is_some_and(|v| v.contains(&0))
        })
    {
        return Err(usage(format!(
            "invalid transition {}; no bundles removed",
            path.display()
        )));
    }
    let active = apps.join(BUNDLE);
    let previous = apps.join(PREVIOUS);
    let staged = apps.join(PARTIAL);
    let kept = apps.join(PUBLISHING).join(BUNDLE);
    let current = bundle_identity(&active)?;
    let committed =
        if matches!(transition.kind, TransitionKind::Refresh) && current == transition.source {
            false
        } else if current == transition.target {
            true
        } else if current == transition.source {
            false
        } else {
            return Err(usage(format!(
                "ambiguous transition {}: active bundle identity changed; no bundles removed",
                path.display()
            )));
        };
    let now = app_version(&active).ok_or_else(|| {
        usage(format!(
            "cannot identify installed version at {}",
            active.display()
        ))
    })?;
    if (committed || matches!(transition.kind, TransitionKind::Refresh))
        && now != transition.version
    {
        return Err(usage(format!(
            "installed version does not match {}; no bundles removed",
            path.display()
        )));
    }
    let mut errors = Vec::new();
    let normalize = || -> Result<(), AppError> {
        match (&transition.kind, committed) {
            (TransitionKind::Update, true) => {
                if !path_exists(&previous)? {
                    if bundle_identity(&staged)? != transition.source {
                        return Err(usage(
                            "retained update bundle identity does not match journal",
                        ));
                    }
                    fs::rename(&staged, &previous).map_err(|e| {
                        usage(format!(
                            "cannot rename {} to {}: {e}",
                            staged.display(),
                            previous.display()
                        ))
                    })?;
                }
                if bundle_identity(&previous)? != transition.source {
                    return Err(usage("previous bundle identity does not match journal"));
                }
                set_aside(&previous)?;
            }
            (TransitionKind::Update, false) => {
                if path_exists(&kept)? {
                    if path_exists(&previous)? {
                        return Err(usage(
                            "ambiguous rollback authority: both journal and previous bundles exist",
                        ));
                    }
                    fs::rename(&kept, &previous).map_err(|e| {
                        usage(format!(
                            "cannot restore {} to {}: {e}",
                            kept.display(),
                            previous.display()
                        ))
                    })?;
                }
            }
            (TransitionKind::Rollback, _) => {
                let expected = if committed {
                    &transition.source
                } else {
                    &transition.target
                };
                if &bundle_identity(&previous)? != expected {
                    return Err(usage("rollback bundle identity does not match journal"));
                }
                set_aside(&previous)?;
            }
            (TransitionKind::Refresh, _) => {}
        }
        Ok(())
    };
    if let Err(e) = normalize() {
        errors.push(e.to_string());
    }
    if let Err(e) = sync_dir(apps) {
        errors.push(format!("cannot sync directory {}: {e}", apps.display()));
    }
    if !transition.handoff_complete {
        let app = transition.app.as_ref().map(|intent| StoppedApp {
            identity: AppIdentity {
                pid: intent.pid,
                started: intent.started,
            },
            account: vox_core::node::paths::Account {
                data_root: PathBuf::from(std::ffi::OsString::from_vec(intent.data_root.clone())),
                config_dir: PathBuf::from(std::ffi::OsString::from_vec(intent.config_dir.clone())),
            },
            environment: [
                None,
                None,
                intent.home.clone().map(std::ffi::OsString::from_vec),
                intent.xdg_data.clone().map(std::ffi::OsString::from_vec),
                intent.xdg_config.clone().map(std::ffi::OsString::from_vec),
            ],
        });
        if !transition.daemon_complete {
            let account = vox_core::node::paths::Account {
                data_root: PathBuf::from(std::ffi::OsString::from_vec(
                    transition.daemon_data_root.clone(),
                )),
                config_dir: PathBuf::from(std::ffi::OsString::from_vec(
                    transition.daemon_config_dir.clone(),
                )),
            };
            match super::restart::restart_daemon_checked(
                &account,
                &active.join(HELPER),
                &now,
                Some(&transition.daemon),
            ) {
                Ok(detached) => {
                    super::restart::say_next(&detached);
                    transition.daemon_complete = true;
                    if let Err(e) = write_transition(apps, &transition) {
                        errors.push(e.to_string());
                    }
                }
                Err(e) => errors.push(format!(
                    "installed Vox {now}, but daemon handoff failed: {e}"
                )),
            }
        }
        let app_handoff = || -> Result<(), AppError> {
            let mut app_already_restored = false;
            if let Some(saved) = app.as_ref() {
                if let Some(current) = inspect_app(&active)? {
                    if current.identity.pid == saved.identity.pid
                        && current.identity.started == saved.identity.started
                    {
                        if !committed {
                            return Ok(());
                        }
                        stop_captured_app(&active, &app)?;
                    } else {
                        let same_profile = current.account.data_root == saved.account.data_root
                            && current.account.config_dir == saved.account.config_dir
                            && current.environment[2..] == saved.environment[2..];
                        if !same_profile
                            || !pid_executes(&active_executable(&active)?, current.identity.pid)?
                        {
                            return Err(usage("another app instance is running; refusing to guess interrupted handoff identity"));
                        }
                        let confirmed = inspect_app(&active)?.ok_or_else(|| {
                            usage("replacement app exited while its identity was checked")
                        })?;
                        if confirmed.identity.pid != current.identity.pid
                            || confirmed.identity.started != current.identity.started
                            || confirmed.account.data_root != current.account.data_root
                            || confirmed.account.config_dir != current.account.config_dir
                            || confirmed.environment[2..] != current.environment[2..]
                        {
                            return Err(usage(
                                "replacement app changed while its identity was checked",
                            ));
                        }
                        // The exact active executable and captured profile are already running.
                        // Do not quit or launch a second instance after an interrupted relaunch.
                        app_already_restored = true;
                    }
                }
            }
            if app_already_restored {
                Ok(())
            } else {
                relaunch_app(&active, &app)
            }
        };
        if !transition.app_complete {
            match app_handoff() {
                Ok(()) => {
                    transition.app_complete = true;
                    if let Err(e) = write_transition(apps, &transition) {
                        errors.push(e.to_string());
                    }
                }
                Err(e) => errors.push(e.to_string()),
            }
        }
        if transition.daemon_complete && transition.app_complete {
            transition.handoff_complete = true;
            if let Err(e) = write_transition(apps, &transition) {
                errors.push(e.to_string());
            }
        }
    }
    if !errors.is_empty() {
        return Err(usage(format!(
            "Vox {now} is installed; transition remains incomplete{}: {}; run `vox update` for local repair",
            if committed && matches!(transition.kind, TransitionKind::Rollback) {
                "; do not repeat --rollback"
            } else { "" },
            errors.join("; ")
        )));
    }
    if !committed && matches!(transition.kind, TransitionKind::Update) && path_exists(&staged)? {
        if bundle_identity(&staged)? != transition.target {
            return Err(usage("staged bundle identity changed; journal retained"));
        }
        if in_use(&staged) {
            retire(apps, &staged)?;
        } else {
            clear(&staged)?;
        }
    }
    finish_journal(apps).map_err(|e| usage(format!(
        "Vox {now} is installed and handoff completed{}; cleanup failed: {e}; run `vox update` for local repair",
        if committed && matches!(transition.kind, TransitionKind::Rollback) { "; do not repeat --rollback" } else { "" }
    )))?;
    Ok(Recovery {
        interrupted_publish: true,
        handoff_done: true,
        ..Recovery::default()
    })
}

/// Work left by an earlier transition, reported after the active daemon has been restarted.
#[derive(Default)]
struct Recovery {
    interrupted_publish: bool,
    handoff_done: bool,
    previous_set_aside: bool,
    retired_set_aside: usize,
    retired_removed: usize,
}

impl Recovery {
    fn is_empty(&self) -> bool {
        !self.interrupted_publish
            && !self.previous_set_aside
            && self.retired_set_aside == 0
            && self.retired_removed == 0
    }

    fn say_without_swap(&self) {
        print!("vox: repaired an earlier app transition without swapping Vox.app:");
        if self.interrupted_publish {
            print!(" finished an update cut short;");
        }
        if self.previous_set_aside {
            print!(" made the kept previous bundle non-launchable again;");
        }
        if self.retired_set_aside > 0 {
            print!(
                " made {} retired bundle(s) non-launchable;",
                self.retired_set_aside
            );
        }
        if self.retired_removed > 0 {
            print!(
                " removed {} retired bundle(s) no process still used;",
                self.retired_removed
            );
        }
        println!();
    }
}

/// Unpack the downloaded zip beside the bundle, on its filesystem, and return the one Vox.app
/// it held, moved to `.Vox.app.partial`.
fn unpack(apps: &Path, zip: &Path) -> Result<PathBuf, AppError> {
    let unpacked = apps.join(UNPACK_PARTIAL);
    let staged = apps.join(PARTIAL);
    clear(&unpacked)?;
    clear_candidate(&staged)?;
    fs::create_dir(&unpacked).map_err(|e| {
        usage(format!(
            "cannot create directory {}: {e}",
            unpacked.display()
        ))
    })?;
    let out = Command::new("/usr/bin/ditto")
        .args(["-x", "-k"])
        .arg(zip)
        .arg(&unpacked)
        .output()
        .map_err(|e| {
            usage(format!(
                "cannot unpack {} to {} with ditto: {e}",
                zip.display(),
                unpacked.display()
            ))
        })?;
    if !out.status.success() {
        let _ = clear(&unpacked);
        return Err(usage("the downloaded Vox.app did not unpack"));
    }
    let entries: Vec<String> = fs::read_dir(&unpacked)
        .map_err(|e| usage(format!("cannot read directory {}: {e}", unpacked.display())))?
        .map(|entry| {
            entry
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .map_err(|e| usage(format!("cannot read entry in {}: {e}", unpacked.display())))
        })
        .collect::<Result<_, _>>()?;
    let bundle = unpacked.join(BUNDLE);
    let is_dir = fs::symlink_metadata(&bundle).is_ok_and(|m| m.is_dir());
    if entries != [BUNDLE] || !is_dir {
        let _ = clear(&unpacked);
        return Err(usage(format!(
            "the downloaded zip holds {entries:?}, not exactly {BUNDLE}"
        )));
    }
    fs::rename(&bundle, &staged).map_err(|e| {
        usage(format!(
            "cannot rename {} to {}: {e}",
            bundle.display(),
            staged.display()
        ))
    })?;
    clear(&unpacked)?;
    Ok(staged)
}

/// Everything about the candidate is checked before it is published.
fn verify(active: &Path, staged: &Path, vox: &Validated) -> Result<(), AppError> {
    let helper = staged.join(HELPER);
    let meta = fs::symlink_metadata(&helper)
        .map_err(|_| usage(format!("the new Vox.app carries no {HELPER}")))?;
    // One binary of one version: the vox inside is the vox the release published.
    if !meta.is_file() || meta.len() != vox.size || sha256_of(&helper)? != vox.sha256 {
        return Err(usage(format!(
            "the vox inside the new Vox.app is not the vox {} the release record names",
            vox.version_text
        )));
    }
    let says = app_version(staged).unwrap_or_default();
    if says != vox.version_text {
        return Err(usage(format!(
            "the new Vox.app says it is version {says:?}, not {}",
            vox.version_text
        )));
    }
    if apple_required() {
        verify_apple(active, staged)?;
    }
    let probe = tempfile::tempdir().map_err(AppError::Io)?;
    let out = Command::new(&helper)
        .arg("--version")
        .env_clear()
        .env("VOX_DATA_DIR", probe.path().join("data"))
        .env("VOX_CONFIG_DIR", probe.path().join("config"))
        .output()
        .map_err(AppError::Io)?;
    if !out.status.success()
        || out.stdout.len() > MAX_VERSION_OUTPUT_BYTES
        || out.stdout != format!("vox {}\n", vox.version_text).into_bytes()
    {
        return Err(usage(format!(
            "release trust check failed: the new Vox.app's vox does not say it is {}",
            vox.version_text
        )));
    }
    Ok(())
}

/// Apple vouches for the new bundle and its vox, each under the Developer ID that signed the
/// installed one (ADR-015 17.12, ADR-028 I-2).
fn verify_apple(active: &Path, staged: &Path) -> Result<(), AppError> {
    let named = |what: &str, e: AppError| match e {
        AppError::Usage(m) => usage(format!(
            "{what}: {}",
            m.trim_start_matches("release trust check failed: ")
        )),
        other => other,
    };
    for (what, installed, candidate) in [
        (
            "the new Vox.app",
            active.to_path_buf(),
            staged.to_path_buf(),
        ),
        (
            "the new Vox.app's vox",
            active.join(HELPER),
            staged.join(HELPER),
        ),
    ] {
        let strict = ["--verify", "--strict", "--deep", "--all-architectures"];
        codesign_ok(&candidate, &strict, "its code signature does not verify")
            .map_err(|e| named(what, e))?;
        let theirs = signing_identity(&candidate).map_err(|e| named(what, e))?;
        codesign_ok(
            &installed,
            &strict,
            "the installed one's own signature does not verify",
        )
        .map_err(|e| named(what, e))?;
        let ours = signing_identity(&installed).map_err(|e| named(what, e))?;
        if ours != theirs {
            return Err(usage(format!(
                "release trust check failed for {what}: its Developer ID is not the one that \
                 signed the installed one"
            )));
        }
    }
    codesign_ok(
        staged,
        &[
            "--verify",
            "--strict",
            "--deep",
            "--all-architectures",
            "--check-notarization",
            "--test-requirement",
            "=notarized",
        ],
        "Apple did not confirm its notarization ticket",
    )
    .map_err(|e| named("the new Vox.app", e))
}

/// The bundle's `CFBundleShortVersionString`.
fn app_version(bundle: &Path) -> Option<String> {
    let plist = [INFO_PLIST, KEPT_INFO_PLIST]
        .iter()
        .map(|p| bundle.join(p))
        .find(|p| p.is_file())?;
    let out = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :CFBundleShortVersionString"])
        .arg(plist)
        .env_clear()
        .output()
        .ok()?;
    if !out.status.success() || out.stdout.len() > MAX_VERSION_OUTPUT_BYTES {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    Some(text.trim().to_owned()).filter(|v| !v.is_empty())
}

fn sha256_of(path: &Path) -> Result<[u8; 32], AppError> {
    let mut file =
        fs::File::open(path).map_err(|e| usage(format!("cannot open {}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; IO_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| usage(format!("cannot read {}: {e}", path.display())))?;
        if read == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&buffer[..read]);
    }
}

fn clear_candidate(path: &Path) -> Result<(), AppError> {
    if path_exists(path)? && in_use(path) {
        return Err(usage(format!(
            "cannot safely remove {}: executable use is active or unknown",
            path.display()
        )));
    }
    clear(path)
}

/// Remove `path` if it is there, scratch from a transition that was cut short or the bundle
/// about to be replaced. Read-only folders inside are made writable first: a folder's entries
/// cannot be removed while it is read-only.
fn clear(path: &Path) -> Result<(), AppError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(usage(format!("cannot inspect {}: {e}", path.display()))),
    };
    if meta.is_dir() {
        writable(path)?;
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
    .map_err(|e| {
        usage(format!(
            "cannot remove {}: {e}; retain it and run `vox update` for local repair",
            path.display()
        ))
    })
}

fn writable(dir: &Path) -> Result<(), AppError> {
    let mode = fs::symlink_metadata(dir)
        .map_err(|e| usage(format!("cannot inspect {}: {e}", dir.display())))?
        .permissions()
        .mode();
    if mode & 0o700 != 0o700 {
        fs::set_permissions(dir, fs::Permissions::from_mode(mode | 0o700))
            .map_err(|e| usage(format!("cannot chmod {}: {e}", dir.display())))?;
    }
    for entry in fs::read_dir(dir)
        .map_err(|e| usage(format!("cannot read directory {}: {e}", dir.display())))?
    {
        let entry =
            entry.map_err(|e| usage(format!("cannot read entry in {}: {e}", dir.display())))?;
        if entry
            .file_type()
            .map_err(|e| usage(format!("cannot inspect {}: {e}", entry.path().display())))?
            .is_dir()
        {
            writable(&entry.path())?;
        }
    }
    Ok(())
}

/// Verify the process maps this file as executable text, not merely that it opened the file.
fn pid_executes(path: &Path, pid: u32) -> Result<bool, AppError> {
    let out = Command::new("/usr/sbin/lsof")
        .args(["-a", "-t", "-d", "txt", "-p"])
        .arg(pid.to_string())
        .arg(path)
        .env_clear()
        .output()
        .map_err(|e| {
            usage(format!(
                "cannot inspect executable {} for pid {pid}: {e}",
                path.display()
            ))
        })?;
    if !out.status.success() && (out.status.code() != Some(1) || !out.stderr.is_empty()) {
        return Err(usage(format!(
            "cannot inspect executable {} for pid {pid}: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let text =
        std::str::from_utf8(&out.stdout).map_err(|_| usage("lsof returned invalid process IDs"))?;
    let mut matched = false;
    for line in text.lines() {
        let found: u32 = line
            .parse()
            .map_err(|_| usage("lsof returned invalid process IDs"))?;
        matched |= found == pid;
    }
    Ok(matched)
}

fn active_executable(bundle: &Path) -> Result<PathBuf, AppError> {
    let plist = bundle.join(INFO_PLIST);
    let out = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :CFBundleExecutable"])
        .arg(&plist)
        .env_clear()
        .output()
        .map_err(|e| usage(format!("cannot inspect {}: {e}", plist.display())))?;
    if !out.status.success() || out.stdout.len() > MAX_VERSION_OUTPUT_BYTES {
        return Err(usage(format!(
            "cannot identify executable in {}",
            plist.display()
        )));
    }
    let name = std::str::from_utf8(&out.stdout)
        .map_err(|_| usage(format!("invalid executable name in {}", plist.display())))?
        .trim();
    let path = Path::new(name);
    if name.is_empty()
        || path.components().count() != 1
        || !matches!(
            path.components().next(),
            Some(std::path::Component::Normal(_))
        )
    {
        return Err(usage(format!(
            "invalid executable name in {}",
            plist.display()
        )));
    }
    let executable = bundle.join("Contents/MacOS").join(name);
    if !executable.is_file() {
        return Err(usage(format!(
            "active app executable {} is unavailable",
            executable.display()
        )));
    }
    Ok(executable)
}

/// AppKit identifies a running application by its bundle URL, executable URL and PID.
/// Never address it by display name or bundle identifier: another install can share both.
/// `terminate` is the ordinary, cancellable application quit, not a forced signal.
const APP_HANDOFF: &str = r#"
ObjC.import('AppKit');
ObjC.import('Foundation');
function run(argv) {
    const action = argv[0];
    const url = $.NSURL.fileURLWithPath($(argv[1])).URLByResolvingSymlinksInPath;
    const bundle = $.NSBundle.bundleWithURL(url);
    if (!bundle || !bundle.executableURL) throw new Error('bundle executable is unavailable');
    const wantedBundle = ObjC.unwrap(url.path);
    const wantedExecutable = ObjC.unwrap(bundle.executableURL.URLByResolvingSymlinksInPath.path);
    function matching() {
        const apps = $.NSWorkspace.sharedWorkspace.runningApplications;
        const found = [];
        for (let i = 0; i < apps.count; i++) {
            const app = apps.objectAtIndex(i);
            const bundleURL = app.bundleURL;
            if (bundleURL.isNil()) continue;
            const appBundle = ObjC.unwrap(bundleURL.URLByResolvingSymlinksInPath.path);
            if (appBundle !== wantedBundle) continue;
            const executableURL = app.executableURL;
            const executable = executableURL.isNil() ? null
                : ObjC.unwrap(executableURL.URLByResolvingSymlinksInPath.path);
            if (executable !== wantedExecutable)
                throw new Error('running application at bundle path has a different or unavailable executable');
            if (!app.isTerminated) found.push(app);
        }
        return found;
    }
    function identity(app) {
        // Integer microseconds survive JSON and Rust parsing without a rounded f64 identity.
        const started = Math.round(Number(app.launchDate.timeIntervalSince1970) * 1e6);
        if (!Number.isSafeInteger(started) || started <= 0) throw new Error('application launch date is unavailable; the app was not quit');
        return { pid: Number(app.processIdentifier), started };
    }
    if (action === 'inspect' || action === 'stop') {
        const apps = matching();
        if (apps.length === 0) {
            if (action === 'stop') throw new Error('application exited before the quit request');
            return 'not-running';
        }
        if (apps.length !== 1) throw new Error('multiple applications run from this bundle; none was stopped');
        const app = apps[0];
        const instance = identity(app);
        if (action === 'inspect') return JSON.stringify(instance);
        if (instance.pid !== Number(argv[2]) || instance.started !== Number(argv[3]))
            throw new Error('application changed before the quit request; none was stopped');
        if (!app.terminate) throw new Error('application pid ' + instance.pid + ' refused the quit request');
        for (let i = 0; i < 150; i++) {
            if (app.isTerminated) return 'stopped';
            $.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(0.2));
        }
        throw new Error('application pid ' + instance.pid + ' did not quit within 30 seconds');
    }
    const oldPid = Number(argv[2]);
    const oldStarted = Number(argv[3]);
    for (let i = 0; i < 150; i++) {
        const apps = matching();
        for (const app of apps) {
            const instance = identity(app);
            if (instance.pid !== oldPid || instance.started !== oldStarted) return String(instance.pid);
        }
        $.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(0.2));
    }
    throw new Error('no replacement process from the installed bundle appeared within 30 seconds');
}
"#;

#[derive(serde::Deserialize)]
struct AppIdentity {
    pid: u32,
    started: u64,
}

struct StoppedApp {
    identity: AppIdentity,
    account: vox_core::node::paths::Account,
    environment: [Option<std::ffi::OsString>; 5],
}

fn app_handoff(
    action: &str,
    active: &Path,
    identity: Option<&AppIdentity>,
) -> Result<String, AppError> {
    let mut command = Command::new("/usr/bin/osascript");
    command.args(["-l", "JavaScript", "-e", APP_HANDOFF, "--", action]);
    command.arg(active);
    if let Some(identity) = identity {
        command
            .arg(identity.pid.to_string())
            .arg(identity.started.to_string());
    }
    let out = command.output().map_err(|e| {
        usage(format!(
            "could not inspect or control {}: {e}",
            active.display()
        ))
    })?;
    if !out.status.success() {
        return Err(usage(format!(
            "application handoff for {} failed: {}",
            active.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn inspect_app(active: &Path) -> Result<Option<StoppedApp>, AppError> {
    let result = app_handoff("inspect", active, None)?;
    if result == "not-running" {
        return Ok(None);
    }
    let identity: AppIdentity = serde_json::from_str(&result)
        .map_err(|_| usage("application handoff returned an invalid process identity"))?;
    if identity.pid == 0 || identity.started == 0 {
        return Err(usage(
            "application handoff returned an invalid process identity",
        ));
    }
    let env = vox_sockdrops::process_profile_env(identity.pid)
        .ok_or_else(|| usage("cannot read the running Vox app's profile; the app was not quit"))?;
    let root = |explicit: &Option<std::ffi::OsString>,
                xdg: &Option<std::ffi::OsString>|
     -> Result<PathBuf, AppError> {
        let path = if let Some(value) = explicit {
            PathBuf::from(value)
        } else if let Some(value) = xdg.as_ref().filter(|v| !v.is_empty()) {
            PathBuf::from(value).join("vox")
        } else {
            let home = env[2]
                .as_ref()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| usage("the running Vox app has no HOME; it was not quit"))?;
            PathBuf::from(home).join("Library/Application Support/vox")
        };
        if !path.is_absolute() {
            return Err(usage(
                "the running Vox app has a relative profile path; it was not quit",
            ));
        }
        Ok(path)
    };
    let account = vox_core::node::paths::Account {
        data_root: root(&env[0], &env[3])?,
        config_dir: root(&env[1], &env[4])?,
    };
    Ok(Some(StoppedApp {
        identity,
        account,
        environment: env,
    }))
}

fn stop_captured_app(active: &Path, app: &Option<StoppedApp>) -> Result<(), AppError> {
    let Some(app) = app else { return Ok(()) };
    app_handoff("stop", active, Some(&app.identity))?;
    Ok(())
}

fn restart_for_handoff(
    active: &Path,
    now: &str,
    stopped: &Option<StoppedApp>,
    intent: Option<&super::restart::DaemonIntent>,
) -> Result<(), AppError> {
    use vox_core::node::paths::Account;
    let restart = |account: &Account| {
        let detached =
            super::restart::restart_daemon_checked(account, &active.join(HELPER), now, intent)
                .map_err(|e| {
                    usage(format!(
                        "{} is in place, but the daemon restart failed: {e}",
                        active.display()
                    ))
                })?;
        super::restart::say_next(&detached);
        Ok::<(), AppError>(())
    };
    if let Some(app) = stopped {
        restart(&app.account)
    } else {
        let account = Account::of(None, None).map_err(|e| {
            usage(format!(
                "{} is in place, but the updater's daemon account could not be resolved: {e}",
                active.display()
            ))
        })?;
        restart(&account)
    }
}

fn relaunch_app(active: &Path, stopped: &Option<StoppedApp>) -> Result<(), AppError> {
    let Some(app) = stopped else {
        return Ok(());
    };
    let mut open = Command::new("/usr/bin/open");
    open.arg("-n");
    // Pass resolved roots, never the updater's potentially different profile environment.
    for (key, value) in [
        ("VOX_DATA_DIR", &app.account.data_root),
        ("VOX_CONFIG_DIR", &app.account.config_dir),
    ] {
        let mut assignment = std::ffi::OsString::from(format!("{key}="));
        assignment.push(value);
        open.arg("--env").arg(assignment);
    }
    for (key, value) in ["HOME", "XDG_DATA_HOME", "XDG_CONFIG_HOME"]
        .into_iter()
        .zip(app.environment[2..].iter())
    {
        open.env_remove(key);
        if let Some(value) = value {
            let mut assignment = std::ffi::OsString::from(format!("{key}="));
            assignment.push(value);
            open.arg("--env").arg(assignment);
        }
    }
    let out = open.arg(active).output().map_err(|e| {
        usage(format!(
            "{} is installed, but could not be relaunched: {e}",
            active.display()
        ))
    })?;
    if !out.status.success() {
        return Err(usage(format!(
            "{} is installed, but LaunchServices could not relaunch it: {}",
            active.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let new_pid = app_handoff("wait", active, Some(&app.identity)).map_err(|e| {
        usage(format!(
            "{} is installed, but its relaunch was not confirmed: {e}",
            active.display()
        ))
    })?;
    println!("relaunched {} (pid {new_pid})", active.display());
    Ok(())
}

fn journaled_refresh(apps: &Path, active: &Path, version: &str) -> Result<(), AppError> {
    let running = inspect_app(active)?;
    let mut transition =
        prepare_transition(apps, active, TransitionKind::Refresh, version, &running)?;
    stop_captured_app(active, &running)?;
    transition_handoff(apps, active, version, &running, &mut transition)?;
    finish_journal(apps)
}

fn transition_handoff(
    apps: &Path,
    active: &Path,
    version: &str,
    stopped: &Option<StoppedApp>,
    transition: &mut Transition,
) -> Result<(), AppError> {
    let mut failures = Vec::new();
    if !transition.daemon_complete {
        match restart_for_handoff(active, version, stopped, Some(&transition.daemon)) {
            Ok(()) => {
                transition.daemon_complete = true;
                if let Err(e) = write_transition(apps, transition) {
                    failures.push(e.to_string());
                }
            }
            Err(e) => failures.push(e.to_string()),
        }
    }
    if !transition.app_complete {
        match relaunch_app(active, stopped) {
            Ok(()) => {
                transition.app_complete = true;
                if let Err(e) = write_transition(apps, transition) {
                    failures.push(e.to_string());
                }
            }
            Err(e) => failures.push(e.to_string()),
        }
    }
    if transition.daemon_complete && transition.app_complete {
        transition.handoff_complete = true;
        if let Err(e) = write_transition(apps, transition) {
            failures.push(e.to_string());
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(usage(failures.join("; ")))
    }
}

/// Report the original failure without skipping an independently possible owned handoff.
fn transition_failed_journal(
    apps: &Path,
    stopped: &Option<StoppedApp>,
    transition: &mut Transition,
    error: AppError,
) -> AppError {
    let active = apps.join(BUNDLE);
    let version = app_version(&active);
    let mut failures = vec![error.to_string()];
    let reopened = version
        .as_ref()
        .ok_or_else(|| {
            usage("active app version is unavailable; the stopped app was not relaunched")
        })
        .and_then(|version| transition_handoff(apps, &active, version, stopped, transition));
    if let Err(e) = reopened {
        failures.push(e.to_string());
    }
    let committed_rollback = matches!(transition.kind, TransitionKind::Rollback)
        && bundle_identity(&active).is_ok_and(|identity| identity == transition.target);
    usage(format!(
        "Vox {} is installed{}; transition incomplete: {}; run `vox update` for local repair",
        version.as_deref().unwrap_or("with unknown version"),
        if committed_rollback {
            "; do not repeat --rollback"
        } else {
            ""
        },
        failures.join("; ")
    ))
}

/// Refresh completions and the agent skill pack through the path the person ran, when that is
/// the link outside the bundle; the rc block records that directory, never one inside the bundle.
/// Run from inside the bundle, only the skill pack is refreshed.
fn shell_setup_from(apps: &Path, exe: &Path) {
    let inside = exe
        .parent()
        .and_then(|dir| fs::canonicalize(dir).ok())
        .is_some_and(|dir| dir.starts_with(apps));
    if inside {
        super::run_skill_install(exe);
    } else {
        run_shell_setup(exe);
    }
}
