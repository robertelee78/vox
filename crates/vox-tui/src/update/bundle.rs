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
//! An update fetches vox's record and the app's, requires one version, downloads the app, and
//! unpacks it beside the bundle as `.Vox.app.partial`. It verifies every part before anything is
//! renamed: the vox inside is byte for byte the vox the record names, the app says that version,
//! and Apple vouches for both under the Developer IDs that signed the installed ones. Then one
//! `renameatx_np(RENAME_SWAP)` puts the new bundle in place, so `Vox.app` is never missing or
//! partial; the old one becomes `.Vox.app.previous`. A rollback is the same swap the other way.
//! The daemon is then restarted onto the new version ([`super::restart`]); an app that was
//! running from this bundle is normally quit before the swap and relaunched afterward.

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use super::{
    apple_required, codesign_ok, download_asset, fetch_app_record, fetch_record, run_shell_setup,
    signing_identity, sync_dir, target_triple, usage, InstallLock, Validated, IO_BUFFER_BYTES,
    MAX_VERSION_OUTPUT_BYTES,
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

/// **Test-only**: abort the process right after a publish's swap, before the replaced bundle is
/// renamed to [`PREVIOUS`], so a proof can stand a publish cut short at its one awkward moment.
/// Nothing a person runs sets it; not compiled in without the `test-knobs` feature (V210-105).
#[cfg(feature = "test-knobs")]
const TEST_ABORT_AFTER_SWAP_ENV: &str = "VOX_TEST_ABORT_AFTER_SWAP";

/// `vox update [--check]` for the Vox.app in `apps`.
///
/// # Errors
/// No release, a release whose app and vox disagree, a transfer or verification failure, or a
/// failed swap. Nothing in `apps` is changed by a refusal.
pub(super) fn update(
    apps: &Path,
    channel: &str,
    exe: &Path,
    check_only: bool,
) -> Result<(), AppError> {
    let target = target_triple();
    let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|_| usage("this binary's own version is not SemVer"))?;
    // A local repair must not depend on GitHub being reachable, nor perform another exchange.
    // Hold the same lock through recovery and any subsequent publication.
    let _lock = if check_only {
        None
    } else {
        Some(InstallLock::acquire(apps)?)
    };
    if !check_only {
        let repaired = recover(apps)?;
        if !repaired.is_empty() {
            let active = apps.join(BUNDLE);
            let now = app_version(&active)
                .ok_or_else(|| usage("the repaired Vox.app has no readable version"))?;
            let running = stop_app(&active)?;
            restart_for_handoff(&active, &now, &running)?;
            shell_setup_from(apps, exe);
            relaunch_app(&active, &running)?;
            repaired.say_without_swap();
            return Ok(());
        }
    }
    let vox = fetch_record(channel, target)?;
    let app = fetch_app_record(channel, target)?;
    if app.version != vox.version {
        return Err(usage(format!(
            "the {channel} release offers vox {} but Vox.app {}; they are applied together or not \
             at all",
            vox.version_text, app.version_text
        )));
    }
    if vox.version <= current {
        println!(
            "Vox {current} is current (the newest {channel} release is {})",
            vox.version_text
        );
        // **An update still updates** (decider, v0.4.2): with nothing newer, completions and the
        // agent skill pack are refreshed on the Vox.app in place. `--check` changes nothing.
        if !check_only {
            let active = apps.join(BUNDLE);
            let running = stop_app(&active)?;
            restart_for_handoff(&active, &current.to_string(), &running)?;
            relaunch_app(&active, &running)?;
            shell_setup_from(apps, exe);
            println!("Vox {current} is current; {}", super::skill_said());
        }
        return Ok(());
    }
    println!(
        "Vox {} is available on {channel} (this is {current})",
        vox.version_text
    );
    if check_only {
        return Ok(());
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
        .map_err(AppError::Io)?;
    download_asset(
        &app,
        &format!("Vox-{}-{}.zip", app.version_text, app.target),
        downloading.as_file_mut(),
    )?;
    downloading.as_file().sync_all().map_err(AppError::Io)?;
    let zip = downloading.into_temp_path();

    let staged = unpack(apps, &zip)?;
    if let Err(refused) = verify(&active, &staged, &vox) {
        let _ = clear(&staged);
        return Err(refused);
    }
    let running = match stop_app(&active) {
        Ok(running) => running,
        Err(e) => {
            let _ = clear(&staged);
            return Err(e);
        }
    };
    let aside = match publish(apps, &vox.version_text) {
        Ok(aside) => aside,
        Err(e) => return Err(transition_failed(&active, &running, e)),
    };

    println!("updated: {} -> Vox {}", active.display(), vox.version_text);
    println!(
        "         the previous Vox.app is kept at {} for `vox update --rollback`",
        apps.join(PREVIOUS).display()
    );

    restart_for_handoff(&active, &vox.version_text, &running)?;
    shell_setup_from(apps, exe);
    relaunch_app(&active, &running)?;
    match aside {
        Some(error) => Err(error),
        None => Ok(()),
    }
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
    recover(apps)?;
    if !previous.join(HELPER).is_file() {
        return Err(usage(format!(
            "no previous Vox.app was retained in {} — nothing to roll back to",
            apps.display()
        )));
    }
    let running = stop_app(&active)?;
    let was = app_version(&active).unwrap_or_else(|| "unknown".to_owned());
    // The kept bundle becomes an application again before it is swapped in; the one it replaces
    // is set aside after, so neither is ever both in place and set aside.
    if let Err(e) = restore(&previous) {
        return Err(transition_failed(&active, &running, e));
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
        return Err(transition_failed(&active, &running, error));
    }
    if let Err(e) = sync_dir(apps) {
        return Err(transition_failed(&active, &running, e));
    }
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
    restart_for_handoff(&active, &now, &running).map_err(|e| {
        usage(format!(
            "rollback to Vox {now} is already in place; do not repeat --rollback: {e}"
        ))
    })?;
    shell_setup_from(apps, exe);
    relaunch_app(&active, &running).map_err(|e| {
        usage(format!(
            "rollback to Vox {now} is already in place; do not repeat --rollback: {e}"
        ))
    })?;
    // Said, not failed: the rollback is committed, and a command that reports failure invites
    // the same command again, which would roll back once more and reverse it. The repair is
    // `vox update`, which sets the kept bundle aside under the lock without swapping anything.
    if let Err(e) = aside {
        println!(
            "vox: the rollback is done, but the replaced Vox.app was not set aside: {e}; run \
             `vox update` to repair (it swaps nothing), and until then open Vox as {}",
            active.display()
        );
    }
    Ok(())
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
    .map_err(|e| AppError::Io(e.into()))
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
    clear(&journal)?;
    fs::create_dir(&journal).map_err(AppError::Io)?;
    fs::write(journal.join(PUBLISHING_VERSION), version).map_err(AppError::Io)?;
    if fs::symlink_metadata(&previous).is_ok() {
        fs::rename(&previous, journal.join(BUNDLE)).map_err(AppError::Io)?;
    }
    sync_dir(apps)?;
    if let Err(failed) = swap(&staged, &apps.join(BUNDLE)) {
        // Nothing was swapped: the previous bundle goes back where it was.
        let _ = recover(apps);
        return Err(failed);
    }
    sync_dir(apps)?;
    #[cfg(feature = "test-knobs")]
    if std::env::var_os(TEST_ABORT_AFTER_SWAP_ENV).is_some_and(|v| !v.is_empty()) {
        std::process::abort();
    }
    // The swap left the replaced bundle under the partial name.
    fs::rename(&staged, &previous).map_err(AppError::Io)?;
    sync_dir(apps)?;
    let aside = set_aside(&previous);
    if let Err(said) = launch_services(true, &apps.join(BUNDLE)) {
        println!("note: {said}; the current Vox.app is in place and opens by path");
    }
    // The bundle that was previous before this publish goes, unless something still runs from
    // it: then it is retired, and a later transition removes it (see [`sweep`]).
    let older = journal.join(BUNDLE);
    if fs::symlink_metadata(&older).is_ok() {
        if in_use(&older) {
            retire(apps, &older)?;
        } else {
            clear(&older)?;
        }
    }
    clear(&journal)?;
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

/// Bundles retired by earlier transitions while code from them was running: `.Vox.app.retired.*`.
const RETIRED_PREFIX: &str = ".Vox.app.retired.";

/// Rename `bundle` aside as retired: a daemon not restarted since an earlier update runs from it.
fn retire(apps: &Path, bundle: &Path) -> Result<(), AppError> {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let name = format!("{RETIRED_PREFIX}{ms}.{}", std::process::id());
    let retired = apps.join(name);
    fs::rename(bundle, &retired).map_err(AppError::Io)?;
    set_aside(&retired)
}

/// Tell LaunchServices about a bundle: `register` adds or refreshes the bundle in place;
/// otherwise a record made for a bundle now set aside is taken out. The set-aside bundle has no
/// `Info.plist` ([`set_aside`]), which is what keeps it unlaunchable; this call only clears the
/// record a running app may still re-register when it quits. Best effort: a refusal is said,
/// not fatal. Measured 2026-10-19: both bundles registered as `us.vox.app` with the same
/// CFBundleVersion, and reopening Vox launched the replaced 0.4.4 against the 0.4.6 daemon.
fn launch_services(register: bool, bundle: &Path) -> Result<(), String> {
    const LSREGISTER: &str = "/System/Library/Frameworks/CoreServices.framework/Frameworks/\
                              LaunchServices.framework/Support/lsregister";
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
        Ok(status) => Err(format!(
            "LaunchServices did not {verb} {} ({status})",
            bundle.display()
        )),
        Err(e) => Err(format!(
            "LaunchServices was not told to {verb} {}: {e}",
            bundle.display()
        )),
    }
}

/// A set-aside bundle's `Info.plist`, kept under this name until a rollback restores it. Without
/// `Contents/Info.plist` the folder is no application bundle: LaunchServices cannot register it,
/// not even when the app still running from it quits, so opening Vox by its identifier never
/// lands on it (ADR-014 M-29a). `lsregister -u` is the second measure, for a record already made.
const KEPT_INFO_PLIST: &str = "Contents/Info.plist.kept";
const INFO_PLIST: &str = "Contents/Info.plist";

/// Set a replaced or retired bundle aside: its LaunchServices record removed, then no
/// `Info.plist`. The rename is the guarantee (a folder without `Contents/Info.plist` is no
/// application, whatever record remains); the record removal is the second measure, said when it
/// fails and tried again by every later transition that finds the bundle still there (`sweep`,
/// `recover`, the next publish), until it succeeds.
fn set_aside(bundle: &Path) -> Result<(), AppError> {
    if let Err(said) = launch_services(false, bundle) {
        println!("note: {said}; tried again at the next update or rollback");
    }
    let plist = bundle.join(INFO_PLIST);
    if !plist.is_file() {
        return Ok(());
    }
    fs::rename(&plist, bundle.join(KEPT_INFO_PLIST)).map_err(|e| {
        AppError::Usage(format!(
            "{} is still an application: its Info.plist could not be set aside ({e})",
            bundle.display()
        ))
    })
}

/// Make a set-aside bundle an application again, for the swap that brings it back.
fn restore(bundle: &Path) -> Result<(), AppError> {
    let kept = bundle.join(KEPT_INFO_PLIST);
    if kept.is_file() {
        fs::rename(&kept, bundle.join(INFO_PLIST)).map_err(AppError::Io)?;
    }
    Ok(())
}

/// Remove the retired bundles nothing runs from any more.
fn sweep(apps: &Path, repaired: &mut Recovery) -> Result<(), AppError> {
    let entries = fs::read_dir(apps).map_err(AppError::Io)?;
    for entry in entries.filter_map(Result::ok) {
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
    let mut files = Vec::new();
    let mut dirs = vec![bundle.join("Contents")];
    while let Some(dir) = dirs.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let Ok(meta) = fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if meta.is_dir() {
                dirs.push(entry.path());
            } else if meta.is_file() && meta.permissions().mode() & 0o100 != 0 {
                files.push(entry.path());
            }
        }
    }
    if files.is_empty() {
        return false;
    }
    // The pids, not the status: lsof exits 1 when any one file named is not open.
    Command::new("/usr/sbin/lsof")
        .arg("-t")
        .args(&files)
        .env_clear()
        .output()
        .map_or(true, |out| !out.stdout.is_empty())
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
    sweep(apps, &mut repaired)?;
    let journal = apps.join(PUBLISHING);
    if fs::symlink_metadata(&journal).is_err() {
        // No publish was cut short. A previous bundle is set aside again under the lock: one an
        // earlier release left as an application (before M-29a), or one whose record removal
        // failed last time.
        let previous = apps.join(PREVIOUS);
        if fs::symlink_metadata(&previous).is_ok() {
            repaired.previous_set_aside = previous.join(INFO_PLIST).is_file();
            set_aside(&previous)?;
        }
        return Ok(repaired);
    }
    let staged = apps.join(PARTIAL);
    let previous = apps.join(PREVIOUS);
    let published = fs::read_to_string(journal.join(PUBLISHING_VERSION)).unwrap_or_default();
    repaired.interrupted_publish = true;
    if fs::symlink_metadata(&previous).is_err() && staged.join(HELPER).is_file() {
        if app_version(&apps.join(BUNDLE)).as_deref() == Some(published.trim()) {
            fs::rename(&staged, &previous).map_err(AppError::Io)?;
            set_aside(&previous)?;
            println!(
                "vox: an update was cut short after Vox {} was put in place; the Vox.app it \
                 replaced is kept at {} for `vox update --rollback`",
                published.trim(),
                previous.display()
            );
        } else {
            clear(&staged)?;
        }
    }
    let kept = journal.join(BUNDLE);
    if fs::symlink_metadata(&previous).is_err() && fs::symlink_metadata(&kept).is_ok() {
        // No exchange happened: restore the rollback bundle held by the journal.
        fs::rename(&kept, &previous).map_err(AppError::Io)?;
    }
    // The previous bundle is set aside again under the lock, before anything else reads `apps`:
    // one an earlier release left as an application, or one whose record removal failed.
    if fs::symlink_metadata(&previous).is_ok() {
        repaired.previous_set_aside |= previous.join(INFO_PLIST).is_file();
        set_aside(&previous)?;
    }
    // Recovery has the same live-code retention obligation as an uninterrupted publish.
    if fs::symlink_metadata(&kept).is_ok() {
        if in_use(&kept) {
            retire(apps, &kept)?;
            repaired.retired_set_aside += 1;
        } else {
            set_aside(&kept)?;
            clear(&kept)?;
            repaired.retired_removed += 1;
        }
    }
    if let Err(said) = launch_services(true, &apps.join(BUNDLE)) {
        println!("note: {said}; the current Vox.app is in place and opens by path");
    }
    sync_dir(apps)?;
    clear(&journal)?;
    Ok(repaired)
}

/// Work left by an earlier transition, reported after the active daemon has been restarted.
#[derive(Default)]
struct Recovery {
    interrupted_publish: bool,
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
    clear(&staged)?;
    fs::create_dir(&unpacked).map_err(AppError::Io)?;
    let out = Command::new("/usr/bin/ditto")
        .args(["-x", "-k"])
        .arg(zip)
        .arg(&unpacked)
        .output()
        .map_err(AppError::Io)?;
    if !out.status.success() {
        let _ = clear(&unpacked);
        return Err(usage("the downloaded Vox.app did not unpack"));
    }
    let entries: Vec<String> = fs::read_dir(&unpacked)
        .map_err(AppError::Io)?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let bundle = unpacked.join(BUNDLE);
    let is_dir = fs::symlink_metadata(&bundle).is_ok_and(|m| m.is_dir());
    if entries != [BUNDLE] || !is_dir {
        let _ = clear(&unpacked);
        return Err(usage(format!(
            "the downloaded zip holds {entries:?}, not exactly {BUNDLE}"
        )));
    }
    fs::rename(&bundle, &staged).map_err(AppError::Io)?;
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
    let mut file = fs::File::open(path).map_err(AppError::Io)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; IO_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer).map_err(AppError::Io)?;
        if read == 0 {
            return Ok(hasher.finalize().into());
        }
        hasher.update(&buffer[..read]);
    }
}

/// Remove `path` if it is there, scratch from a transition that was cut short or the bundle
/// about to be replaced. Read-only folders inside are made writable first: a folder's entries
/// cannot be removed while it is read-only.
fn clear(path: &Path) -> Result<(), AppError> {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if meta.is_dir() {
        writable(path)?;
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
    .map_err(|e| {
        usage(format!(
            "cannot clear {}: {e}\n       remove it by hand, then run this again",
            path.display()
        ))
    })
}

fn writable(dir: &Path) -> Result<(), AppError> {
    let mode = fs::symlink_metadata(dir)
        .map_err(AppError::Io)?
        .permissions()
        .mode();
    fs::set_permissions(dir, fs::Permissions::from_mode(mode | 0o700)).map_err(AppError::Io)?;
    for entry in fs::read_dir(dir).map_err(AppError::Io)? {
        let entry = entry.map_err(AppError::Io)?;
        if entry.file_type().map_err(AppError::Io)?.is_dir() {
            writable(&entry.path())?;
        }
    }
    Ok(())
}

/// PIDs with a particular owned file open; never a process-name match.
fn pids_using(path: &Path) -> Result<Vec<u32>, AppError> {
    let out = Command::new("/usr/sbin/lsof")
        .arg("-t")
        .arg(path)
        .env_clear()
        .output()
        .map_err(|e| usage(format!("cannot inspect {}: {e}", path.display())))?;
    if !out.status.success() && (out.status.code() != Some(1) || !out.stderr.is_empty()) {
        return Err(usage(format!(
            "cannot inspect {}: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    String::from_utf8(out.stdout)
        .map_err(|_| usage("lsof returned invalid process IDs"))?
        .lines()
        .map(|line| {
            line.parse()
                .map_err(|_| usage("lsof returned invalid process IDs"))
        })
        .collect()
}

/// Finish the app handoff only when the caller is the newly installed helper invoked by the
/// still-running updater that owns this exact install's lock and retained executable.
pub(super) fn post_install_delegate() -> Result<(), AppError> {
    let Some(parent) = crate::claude_injector::proc_of(std::process::id()).map(|p| p.ppid) else {
        return Ok(());
    };
    let Some(args) = vox_sockdrops::process_args(parent) else {
        return Ok(());
    };
    if args.get(1).map(String::as_str) != Some("update") || args.iter().any(|arg| arg == "--check")
    {
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(AppError::Io)?;
    let super::Channel::Bundle { apps_dir: apps, .. } = super::detect_channel(&exe)? else {
        return Ok(());
    };
    let previous = apps.join(PREVIOUS);
    if !previous.join(HELPER).is_file() {
        return Ok(());
    }
    if !pids_using(&previous.join(HELPER))?.contains(&parent) {
        return Ok(());
    }
    let lock = apps.join(super::LOCK_NAME);
    if !pids_using(&lock)?.contains(&parent) {
        return Err(usage(
            "the updater does not hold the install lock; the app was not quit",
        ));
    }
    let lock_file = fs::OpenOptions::new().read(true).write(true).open(&lock)?;
    match rustix::fs::flock(
        &lock_file,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    ) {
        Ok(()) => return Err(usage("the install lock is not held; the app was not quit")),
        Err(e) if e == rustix::io::Errno::AGAIN => {}
        Err(e) => return Err(usage(format!("cannot verify the install lock: {e}"))),
    }
    let plist = [KEPT_INFO_PLIST, INFO_PLIST]
        .iter()
        .map(|name| previous.join(name))
        .find(|path| path.is_file())
        .ok_or_else(|| {
            usage("the retained app's Info.plist is unavailable; the app was not quit")
        })?;
    let out = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :CFBundleExecutable"])
        .arg(plist)
        .env_clear()
        .output()?;
    if !out.status.success() || out.stdout.len() > MAX_VERSION_OUTPUT_BYTES {
        return Err(usage(
            "the retained app's executable cannot be identified; the app was not quit",
        ));
    }
    let name = std::str::from_utf8(&out.stdout)
        .map_err(|_| usage("the retained app's executable name is invalid"))?
        .trim();
    let name_path = Path::new(name);
    if name.is_empty()
        || name_path.components().count() != 1
        || !matches!(
            name_path.components().next(),
            Some(std::path::Component::Normal(_))
        )
    {
        return Err(usage(
            "the retained app's executable name is invalid; the app was not quit",
        ));
    }
    let previous_executable = previous.join("Contents/MacOS").join(name);
    if !previous_executable.is_file() {
        return Err(usage(
            "the retained app executable is missing; the app was not quit",
        ));
    }
    let active = apps.join(BUNDLE);
    let old_pids = pids_using(&previous_executable)?;
    if old_pids.is_empty() {
        println!("vox: no previously running Vox app needs a restart");
        return Ok(());
    }
    let stopped = stop_app_from(&active, Some(&previous_executable))?.ok_or_else(|| {
        usage("the retained app process could not be identified; it was not quit")
    })?;
    let stopped = Some(stopped);
    let now = app_version(&active).ok_or_else(|| {
        usage("the installed app version cannot be identified; the app was not relaunched")
    })?;
    restart_for_handoff(&active, &now, &stopped)?;
    relaunch_app(&active, &stopped)?;
    println!("vox: the installed Vox app was relaunched; no manual restart is needed");
    Ok(())
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
    const legacy = action === 'legacy-inspect' || action === 'legacy-stop';
    const previousBundle = legacy
        ? ObjC.unwrap(url.URLByDeletingLastPathComponent.URLByAppendingPathComponent('.Vox.app.previous').URLByResolvingSymlinksInPath.path)
        : '';
    const previousExecutable = legacy
        ? ObjC.unwrap($.NSURL.fileURLWithPath($(argv[4])).URLByResolvingSymlinksInPath.path)
        : '';
    function matching() {
        const apps = $.NSWorkspace.sharedWorkspace.runningApplications;
        const found = [];
        for (let i = 0; i < apps.count; i++) {
            const app = apps.objectAtIndex(i);
            const bundleURL = app.bundleURL;
            if (bundleURL.isNil()) continue;
            const appBundle = ObjC.unwrap(bundleURL.URLByResolvingSymlinksInPath.path);
            if (appBundle !== wantedBundle && (!legacy || appBundle !== previousBundle)) continue;
            const executableURL = app.executableURL;
            const executable = executableURL.isNil() ? null
                : ObjC.unwrap(executableURL.URLByResolvingSymlinksInPath.path);
            if (executable !== wantedExecutable && (!legacy || executable !== previousExecutable))
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
    if (action === 'inspect' || action === 'stop' || legacy) {
        const apps = matching();
        if (apps.length === 0) {
            if (action === 'stop' || action === 'legacy-stop') throw new Error('application exited before the quit request');
            return 'not-running';
        }
        if (apps.length !== 1) throw new Error('multiple applications run from this bundle; none was stopped');
        const app = apps[0];
        const instance = identity(app);
        if (action === 'inspect' || action === 'legacy-inspect') return JSON.stringify(instance);
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
    previous_executable: Option<&Path>,
) -> Result<String, AppError> {
    let mut command = Command::new("/usr/bin/osascript");
    command.args(["-l", "JavaScript", "-e", APP_HANDOFF, "--", action]);
    command.arg(active);
    if let Some(identity) = identity {
        command
            .arg(identity.pid.to_string())
            .arg(identity.started.to_string());
    }
    if let Some(previous) = previous_executable {
        if identity.is_none() {
            command.args(["0", "0"]);
        }
        command.arg(previous);
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

fn stop_app(active: &Path) -> Result<Option<StoppedApp>, AppError> {
    stop_app_from(active, None)
}

fn stop_app_from(active: &Path, previous: Option<&Path>) -> Result<Option<StoppedApp>, AppError> {
    let action = if previous.is_some() {
        "legacy-inspect"
    } else {
        "inspect"
    };
    let result = app_handoff(action, active, None, previous)?;
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
    if let Some(previous) = previous {
        if !pids_using(previous)?.contains(&identity.pid) {
            return Err(usage(
                "the running app is not using the retained executable; it was not quit",
            ));
        }
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
    let action = if previous.is_some() {
        "legacy-stop"
    } else {
        "stop"
    };
    app_handoff(action, active, Some(&identity), previous)?;
    Ok(Some(StoppedApp {
        identity,
        account,
        environment: env,
    }))
}

fn restart_for_handoff(
    active: &Path,
    now: &str,
    stopped: &Option<StoppedApp>,
) -> Result<(), AppError> {
    use vox_core::node::paths::Account;
    let restart = |account: &Account| {
        let detached = super::restart::restart_daemon_checked(account, &active.join(HELPER), now)
            .map_err(|e| {
            usage(format!(
                "{} is in place, but the daemon restart failed: {e}{}",
                active.display(),
                if stopped.is_some() {
                    "; the stopped app was not relaunched"
                } else {
                    ""
                }
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
    let new_pid = app_handoff("wait", active, Some(&app.identity), None).map_err(|e| {
        usage(format!(
            "{} is installed, but its relaunch was not confirmed: {e}",
            active.display()
        ))
    })?;
    println!("relaunched {} (pid {new_pid})", active.display());
    Ok(())
}

/// A publication can fail before or after its atomic swap. Reopen whichever bundle remains
/// active, and report both the original failure and any failure to reopen it.
fn transition_failed(active: &Path, stopped: &Option<StoppedApp>, error: AppError) -> AppError {
    let reopened = app_version(active)
        .ok_or_else(|| {
            usage("the active app version is unavailable; the stopped app was not relaunched")
        })
        .and_then(|version| restart_for_handoff(active, &version, stopped))
        .and_then(|()| relaunch_app(active, stopped));
    match reopened {
        Ok(()) => usage(format!(
            "the app transition did not finish: {error}; {} is in place",
            active.display()
        )),
        Err(relaunch) => usage(format!(
            "the app transition did not finish: {error}; {relaunch}"
        )),
    }
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
