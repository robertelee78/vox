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
//! The daemon is then restarted onto the new version ([`super::restart`]); an open app keeps
//! running the old one until restarted, and the person is asked to restart it.

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
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
/// The durable journal of a publish or rollback under way. It holds the exact filesystem objects
/// on each side of the exchange, so recovery never guesses from a version string.
const PUBLISHING: &str = ".Vox.app.publishing";
/// In [`PUBLISHING`]: the fully flushed transition record.
const TRANSITION_STATE: &str = "state";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransitionKind {
    Publish,
    Rollback,
}

struct Transition {
    kind: TransitionKind,
    active_id: u64,
    target_id: u64,
    version: String,
}

/// **Test-only**: abort the process right after a publish or rollback exchange, before the
/// displaced bundle is retained, so a proof can stand a transition cut short at that boundary.
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
    if check_only {
        let (vox, _) = fetch_pair(channel, target)?;
        if vox.version <= current {
            println!(
                "Vox {current} is current (the newest {channel} release is {})",
                vox.version_text
            );
        } else {
            println!(
                "Vox {} is available on {channel} (this is {current})",
                vox.version_text
            );
        }
        return Ok(());
    }

    // Acquire the transition lock and recover before any network dependency. A person can
    // always finish a durable local transition, and every release decision is then made once,
    // under the same lock, against the app actually installed at that moment.
    let _lock = InstallLock::acquire(apps)?;
    let repaired = recover(apps)?;
    let active = apps.join(BUNDLE);
    require_bundle(&active, BUNDLE)?;
    if !active.join(HELPER).is_file() {
        return Err(usage(format!(
            "{} holds the install marker but no {BUNDLE} with {HELPER}",
            apps.display()
        )));
    }
    if repaired.finished_rollback() {
        return finish_recovered_rollback(apps, &active, exe, repaired);
    }

    let (vox, app) = fetch_pair(channel, target)?;
    let installed_text = active_app_version(&active).ok_or_else(|| {
        usage(format!(
            "the active {} has no readable Contents/Info.plist version",
            active.display()
        ))
    })?;
    let installed = semver::Version::parse(&installed_text).map_err(|_| {
        usage(format!(
            "the active {} says its version is {installed_text:?}, not SemVer",
            active.display()
        ))
    })?;
    if vox.version <= installed {
        println!(
            "Vox {installed} is current (the newest {channel} release is {})",
            vox.version_text
        );
        // **An update still updates** (decider, v0.4.2): with nothing newer, completions and the
        // agent skill pack are refreshed on the Vox.app in place. `--check` changes nothing.
        shell_setup_from(apps, exe);
        println!("Vox {installed} is current; {}", super::skill_said());
        repaired.say_without_swap();
        return Ok(());
    }
    println!(
        "Vox {} is available on {channel} (installed: {installed})",
        vox.version_text
    );
    repaired.say_before_transition();

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
    let aside = publish(apps, &vox.version_text)?;

    println!("updated: {} -> Vox {}", active.display(), vox.version_text);
    println!(
        "         the previous Vox.app is kept at {} for `vox update --rollback`",
        apps.join(PREVIOUS).display()
    );
    ask_to_restart(&installed_text, &vox.version_text);
    let detached = super::restart::restart_daemon(&active.join(HELPER), &vox.version_text);
    shell_setup_from(apps, exe);
    super::restart::say_next(&detached);
    match aside {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn fetch_pair(channel: &str, target: &str) -> Result<(Validated, Validated), AppError> {
    let vox = fetch_record(channel, target)?;
    let app = fetch_app_record(channel, target)?;
    if app.version != vox.version {
        return Err(usage(format!(
            "the {channel} release offers vox {} but Vox.app {}; they are applied together or not \
             at all",
            vox.version_text, app.version_text
        )));
    }
    Ok((vox, app))
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
    if repaired.finished_rollback() {
        return finish_recovered_rollback(apps, &active, exe, repaired);
    }
    repaired.say_before_transition();
    require_bundle(&active, BUNDLE)?;
    require_bundle(&previous, PREVIOUS)?;
    if !previous.join(HELPER).is_file() {
        return Err(usage(format!(
            "no previous Vox.app was retained in {} — nothing to roll back to",
            apps.display()
        )));
    }
    let was = active_app_version(&active).unwrap_or_else(|| "unknown".to_owned());
    let now = bundle_version(&previous).unwrap_or_else(|| "unknown".to_owned());
    let transition = Transition {
        kind: TransitionKind::Rollback,
        active_id: file_id(&active)?,
        target_id: file_id(&previous)?,
        version: now.clone(),
    };
    begin_transition(apps, &transition)?;
    // The journal is durable before the kept plist is restored. Recovery can therefore finish a
    // pre-swap exchange or a post-swap set-aside without guessing which app moved.
    restore(&previous)?;
    if let Err(failed) = swap(&previous, &active) {
        // Nothing was swapped. The journal-backed recovery retries the exact rollback; if the
        // exchange failure was transient it completes the user's command, otherwise the journal
        // remains for the next command.
        return match recover(apps) {
            Ok(recovered) if recovered.finished_rollback() => {
                finish_recovered_rollback(apps, &active, exe, recovered)
            }
            Ok(_) => Err(failed),
            Err(repair) => Err(usage(format!(
                "the rollback swap failed ({failed}), and its durable repair failed ({repair}); \
                 run `vox update` to finish the recorded transition"
            ))),
        };
    }
    sync_dir(apps)?;
    #[cfg(feature = "test-knobs")]
    if std::env::var_os(TEST_ABORT_AFTER_SWAP_ENV).is_some_and(|v| !v.is_empty()) {
        std::process::abort();
    }
    // The rollback is done at this point. A set-aside that fails is reported last, after the
    // active bundle is registered and the daemon restarted, so a failed step never leaves the
    // rest of the transition undone or invites a second --rollback that would reverse it.
    let aside = set_aside(&previous);
    let registration = launch_services(true, &active);
    if aside.is_ok() && registration.is_ok() {
        finish_transition(apps)?;
    }
    let now = active_app_version(&active).unwrap_or(now);
    println!("rolled back: {} -> Vox {now}", active.display());
    println!(
        "         Vox {was} is kept at {} for --rollback",
        previous.display()
    );
    ask_to_restart(&was, &now);
    let detached = super::restart::restart_daemon(&active.join(HELPER), &now);
    shell_setup_from(apps, exe);
    super::restart::say_next(&detached);
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
    if let Err(e) = registration {
        println!(
            "vox: the rollback is done, but {e}; run `vox update` to retry the recorded \
             registration, and until then open Vox as {}",
            active.display()
        );
    }
    Ok(())
}

fn finish_recovered_rollback(
    apps: &Path,
    active: &Path,
    exe: &Path,
    repaired: Recovery,
) -> Result<(), AppError> {
    require_bundle(active, BUNDLE)?;
    let now = active_app_version(active).unwrap_or_else(|| "unknown".to_owned());
    let was = bundle_version(&apps.join(PREVIOUS)).unwrap_or_else(|| "unknown".to_owned());
    println!(
        "finished the interrupted rollback: {} is Vox {now}",
        active.display()
    );
    ask_to_restart(&was, &now);
    let detached = super::restart::restart_daemon(&active.join(HELPER), &now);
    shell_setup_from(apps, exe);
    super::restart::say_next(&detached);
    repaired.say_without_swap();
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

fn begin_transition(apps: &Path, transition: &Transition) -> Result<(), AppError> {
    let journal = apps.join(PUBLISHING);
    if path_exists(&journal)? {
        return Err(usage(format!(
            "{} still holds an unfinished app transition; run `vox update` to repair it",
            journal.display()
        )));
    }
    fs::create_dir(&journal).map_err(AppError::Io)?;
    sync_dir(apps)?;
    let kind = match transition.kind {
        TransitionKind::Publish => "publish",
        TransitionKind::Rollback => "rollback",
    };
    let state = journal.join(TRANSITION_STATE);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&state)
        .map_err(AppError::Io)?;
    write!(
        file,
        "vox-app-transition-v1\nkind={kind}\nactive_id={}\ntarget_id={}\nversion={}\n",
        transition.active_id, transition.target_id, transition.version
    )
    .map_err(AppError::Io)?;
    file.sync_all().map_err(AppError::Io)?;
    sync_dir(&journal)?;
    sync_dir(apps)
}

fn read_transition(journal: &Path) -> Result<Option<Transition>, AppError> {
    let state = journal.join(TRANSITION_STATE);
    let meta = match fs::symlink_metadata(&state) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(AppError::Io(e)),
    };
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(usage(format!(
            "{} is not a direct transition-state file; leave it in place and report this",
            state.display()
        )));
    }
    let text = match fs::read_to_string(&state) {
        Ok(text) => text,
        Err(e) => return Err(AppError::Io(e)),
    };
    let mut lines = text.lines();
    if lines.next() != Some("vox-app-transition-v1") {
        return Err(usage(format!(
            "{} has an unreadable app-transition record; leave it in place and report this",
            state.display()
        )));
    }
    let field = |line: Option<&str>, name: &str| -> Result<String, AppError> {
        line.and_then(|line| line.strip_prefix(&format!("{name}=")))
            .map(str::to_owned)
            .ok_or_else(|| {
                usage(format!(
                    "{} has an incomplete app-transition record; leave it in place and report this",
                    state.display()
                ))
            })
    };
    let kind = match field(lines.next(), "kind")?.as_str() {
        "publish" => TransitionKind::Publish,
        "rollback" => TransitionKind::Rollback,
        _ => {
            return Err(usage(format!(
                "{} names an unknown app transition; leave it in place and report this",
                state.display()
            )))
        }
    };
    let active_id = field(lines.next(), "active_id")?.parse().map_err(|_| {
        usage(format!(
            "{} has an invalid active filesystem identity",
            state.display()
        ))
    })?;
    let target_id = field(lines.next(), "target_id")?.parse().map_err(|_| {
        usage(format!(
            "{} has an invalid target filesystem identity",
            state.display()
        ))
    })?;
    let version = field(lines.next(), "version")?;
    if lines.next().is_some() {
        return Err(usage(format!(
            "{} has unexpected app-transition data; leave it in place and report this",
            state.display()
        )));
    }
    Ok(Some(Transition {
        kind,
        active_id,
        target_id,
        version,
    }))
}

fn finish_transition(apps: &Path) -> Result<(), AppError> {
    clear(&apps.join(PUBLISHING))
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
    let active = apps.join(BUNDLE);
    require_bundle(&active, BUNDLE)?;
    require_bundle(&staged, PARTIAL)?;
    require_optional_bundle(&previous, PREVIOUS)?;
    let transition = Transition {
        kind: TransitionKind::Publish,
        active_id: file_id(&active)?,
        target_id: file_id(&staged)?,
        version: version.to_owned(),
    };
    begin_transition(apps, &transition)?;
    if path_exists(&previous)? {
        fs::rename(&previous, journal.join(BUNDLE)).map_err(AppError::Io)?;
        sync_dir(&journal)?;
        sync_dir(apps)?;
    }
    if let Err(failed) = swap(&staged, &active) {
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
    let registration = launch_services(true, &active);
    if let Err(error) = aside {
        // The active app is committed. Keep the durable journal so the next update can finish
        // disarming the displaced bundle before it considers another candidate.
        return Ok(Some(usage(format!(
            "Vox {version} is in place, but the replaced Vox.app was not set aside: {error}; run \
             `vox update` again to finish the recorded transition, and until then open Vox as {}",
            active.display()
        ))));
    }
    if let Err(error) = registration {
        return Ok(Some(usage(format!(
            "Vox {version} is in place, but {error}; run `vox update` again to retry the \
             recorded registration, and until then open Vox as {}",
            active.display()
        ))));
    }
    // The bundle that was previous before this publish goes, unless something still runs from
    // it: then it is retired, and a later transition removes it (see [`sweep`]).
    let older = journal.join(BUNDLE);
    if path_exists(&older)? {
        require_bundle(&older, "the journal's retained bundle")?;
        if in_use(&older) {
            retire(apps, &older)?;
        } else {
            clear(&older)?;
        }
    }
    finish_transition(apps)?;
    Ok(None)
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
    sync_dir(apps)?;
    set_aside(&retired).map(|_| ())
}

/// Tell LaunchServices about a bundle: `register` adds or refreshes the bundle in place;
/// otherwise a record made for a bundle now set aside is taken out. The set-aside bundle has no
/// `Info.plist` ([`set_aside`]), which is what keeps it unlaunchable; this call only clears the
/// record a running app may still re-register when it quits. A displaced-bundle release is
/// retried after a refusal; an active-bundle registration keeps the transition journal until a
/// later command succeeds. Measured 2026-10-19: both bundles registered as `us.vox.app` with the same
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
fn set_aside(bundle: &Path) -> Result<bool, AppError> {
    require_bundle(bundle, "the bundle being set aside")?;
    if let Err(said) = launch_services(false, bundle) {
        println!("note: {said}; tried again at the next update or rollback");
    }
    let plist = bundle.join(INFO_PLIST);
    let kept = bundle.join(KEPT_INFO_PLIST);
    if !plist.is_file() {
        return if kept.is_file() {
            Ok(false)
        } else {
            Err(usage(format!(
                "{} has neither a live nor kept Info.plist; it was not removed",
                bundle.display()
            )))
        };
    }
    if path_exists(&kept)? {
        return Err(usage(format!(
            "{} has both a live and kept Info.plist; neither was replaced",
            bundle.display()
        )));
    }
    fs::rename(&plist, &kept).map_err(|e| {
        AppError::Usage(format!(
            "{} is still an application: its Info.plist could not be set aside ({e})",
            bundle.display()
        ))
    })?;
    sync_dir(&bundle.join("Contents"))?;
    Ok(true)
}

/// Make a set-aside bundle an application again, for the swap that brings it back.
fn restore(bundle: &Path) -> Result<(), AppError> {
    require_bundle(bundle, "the bundle being restored")?;
    let kept = bundle.join(KEPT_INFO_PLIST);
    let live = bundle.join(INFO_PLIST);
    if path_exists(&kept)? && path_exists(&live)? {
        return Err(usage(format!(
            "{} has both a live and kept Info.plist; neither was replaced",
            bundle.display()
        )));
    }
    if kept.is_file() {
        fs::rename(&kept, live).map_err(AppError::Io)?;
        sync_dir(&bundle.join("Contents"))?;
    }
    Ok(())
}

/// Remove the retired bundles nothing runs from any more.
fn sweep(apps: &Path, repaired: &mut Recovery) -> Result<(), AppError> {
    let entries = fs::read_dir(apps).map_err(AppError::Io)?;
    for entry in entries {
        let entry = entry.map_err(AppError::Io)?;
        let retired = entry
            .file_name()
            .to_string_lossy()
            .starts_with(RETIRED_PREFIX);
        if retired {
            require_bundle(&entry.path(), "a reserved retired-bundle path")?;
            // Set aside first, again if an earlier attempt failed: the record goes and the
            // bundle is no application even if it then cannot be removed. One still in use stays.
            if set_aside(&entry.path())? {
                repaired.retired_set_aside += 1;
            }
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
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => return true,
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => return true,
            };
            let meta = match fs::symlink_metadata(entry.path()) {
                Ok(meta) => meta,
                Err(_) => return true,
            };
            if meta.file_type().is_symlink() {
                continue;
            } else if meta.is_dir() {
                dirs.push(entry.path());
            } else if meta.is_file() && meta.permissions().mode() & 0o100 != 0 {
                files.push(entry.path());
            }
        }
    }
    if files.is_empty() {
        return true;
    }
    // `lsof` exits 1 with no output when none of the exact files is open. Any output, diagnostic,
    // other status, or inability to ask is uncertainty and keeps the bundle.
    match Command::new("/usr/sbin/lsof")
        .arg("-t")
        .args(&files)
        .env_clear()
        .output()
    {
        Ok(out) if !out.stdout.is_empty() => true,
        Ok(out)
            if out.status.code() == Some(1) && out.stdout.is_empty() && out.stderr.is_empty() =>
        {
            false
        }
        _ => true,
    }
}

/// Finish or undo a transition cut short under the install lock. The durable record names the
/// exact filesystem objects, so an equal version or a kept plist can never be mistaken for proof
/// that the exchange happened.
fn recover(apps: &Path) -> Result<Recovery, AppError> {
    let mut repaired = Recovery::default();
    sweep(apps, &mut repaired)?;
    let active = apps.join(BUNDLE);
    let staged = apps.join(PARTIAL);
    let previous = apps.join(PREVIOUS);
    let journal = apps.join(PUBLISHING);
    require_bundle(&active, BUNDLE)?;
    require_optional_bundle(&staged, PARTIAL)?;
    require_optional_bundle(&previous, PREVIOUS)?;
    require_optional_dir(&journal, PUBLISHING)?;
    if !path_exists(&journal)? {
        // No publish was cut short. A previous bundle is set aside again under the lock: one an
        // earlier release left as an application (before M-29a), or one whose record removal
        // failed last time.
        if path_exists(&previous)? {
            repaired.previous_set_aside = set_aside(&previous)?;
        }
        return Ok(repaired);
    }
    let kept = journal.join(BUNDLE);
    require_optional_bundle(&kept, "the journal's retained bundle")?;
    let Some(transition) = read_transition(&journal)? else {
        // The directory can reach disk before its state file. No bundle mutation is permitted
        // until that state file is flushed, so this is unambiguously before the exchange.
        if path_exists(&staged)? {
            clear(&staged)?;
        }
        finish_transition(apps)?;
        repaired.interrupted_transition = Some(InterruptedTransition::BeforePublish(String::new()));
        return Ok(repaired);
    };
    let active_id = file_id(&active)?;
    match transition.kind {
        TransitionKind::Publish if active_id == transition.target_id => {
            repaired.interrupted_transition =
                Some(InterruptedTransition::Published(transition.version.clone()));
            if path_exists(&previous)? {
                if file_id(&previous)? != transition.active_id {
                    return Err(transition_conflict(
                        &journal,
                        "the retained previous app changed",
                    ));
                }
            } else {
                if !path_exists(&staged)? || file_id(&staged)? != transition.active_id {
                    return Err(transition_conflict(
                        &journal,
                        "the replaced app is under neither recorded name",
                    ));
                }
                fs::rename(&staged, &previous).map_err(AppError::Io)?;
                sync_dir(apps)?;
            }
            repaired.previous_set_aside |= set_aside(&previous)?;
            if path_exists(&kept)? {
                if in_use(&kept) {
                    retire(apps, &kept)?;
                } else {
                    clear(&kept)?;
                }
            }
        }
        TransitionKind::Publish if active_id == transition.active_id => {
            repaired.interrupted_transition = Some(InterruptedTransition::BeforePublish(
                transition.version.clone(),
            ));
            if path_exists(&staged)? {
                if file_id(&staged)? != transition.target_id {
                    return Err(transition_conflict(
                        &journal,
                        "the unpublished candidate changed",
                    ));
                }
                clear(&staged)?;
            }
            if path_exists(&kept)? {
                if path_exists(&previous)? {
                    return Err(transition_conflict(
                        &journal,
                        "two different previous bundles are present",
                    ));
                }
                fs::rename(&kept, &previous).map_err(AppError::Io)?;
                sync_dir(&journal)?;
                sync_dir(apps)?;
            }
            if path_exists(&previous)? {
                repaired.previous_set_aside |= set_aside(&previous)?;
            }
        }
        TransitionKind::Rollback if active_id == transition.target_id => {
            repaired.interrupted_transition = Some(InterruptedTransition::RolledBack(
                transition.version.clone(),
            ));
            if !path_exists(&previous)? || file_id(&previous)? != transition.active_id {
                return Err(transition_conflict(
                    &journal,
                    "the displaced app is not the recorded active app",
                ));
            }
            repaired.previous_set_aside |= set_aside(&previous)?;
        }
        TransitionKind::Rollback if active_id == transition.active_id => {
            repaired.interrupted_transition = Some(InterruptedTransition::BeforeRollback(
                transition.version.clone(),
            ));
            if !path_exists(&previous)? || file_id(&previous)? != transition.target_id {
                return Err(transition_conflict(
                    &journal,
                    "the rollback app is not the recorded target",
                ));
            }
            restore(&previous)?;
            swap(&previous, &active)?;
            sync_dir(apps)?;
            repaired.previous_set_aside |= set_aside(&previous)?;
        }
        _ => {
            return Err(transition_conflict(
                &journal,
                "the active app is neither recorded side of the exchange",
            ))
        }
    }
    launch_services(true, &active).map_err(|said| {
        usage(format!(
            "the recorded app transition is repaired, but {said}; its journal is retained so \
             `vox update` can retry registration"
        ))
    })?;
    finish_transition(apps)?;
    Ok(repaired)
}

fn transition_conflict(journal: &Path, detail: &str) -> AppError {
    usage(format!(
        "cannot finish the recorded app transition in {}: {detail}; no path was removed",
        journal.display()
    ))
}

/// Work an earlier or interrupted transition left for the next update. It is accumulated so a
/// repair-only `vox update` can say, as its final line, both what it repaired and that it did not
/// exchange the active bundle (ADR-014 M-29a).
#[derive(Default)]
struct Recovery {
    interrupted_transition: Option<InterruptedTransition>,
    previous_set_aside: bool,
    retired_set_aside: usize,
    retired_removed: usize,
}

enum InterruptedTransition {
    /// The journal exists but the active app is not its version: the candidate never published.
    BeforePublish(String),
    /// The journal's version is active: finish retaining the bundle it replaced.
    Published(String),
    /// Recovery completed a rollback whose exchange had not happened yet.
    BeforeRollback(String),
    /// The rollback exchange happened; finish disarming the displaced app.
    RolledBack(String),
}

impl Recovery {
    fn finished_rollback(&self) -> bool {
        matches!(
            &self.interrupted_transition,
            Some(InterruptedTransition::RolledBack(_) | InterruptedTransition::BeforeRollback(_))
        )
    }

    fn is_empty(&self) -> bool {
        self.interrupted_transition.is_none()
            && !self.previous_set_aside
            && self.retired_set_aside == 0
            && self.retired_removed == 0
    }

    fn detail(&self) -> String {
        let mut parts = Vec::new();
        if let Some(interrupted) = &self.interrupted_transition {
            parts.push(match interrupted {
                InterruptedTransition::BeforePublish(version) if !version.is_empty() => format!(
                    "finished the update cut short before Vox {version} was put in place and discarded its unpublished candidate"
                ),
                InterruptedTransition::BeforePublish(_) => {
                    "finished an update cut short before its candidate was put in place and discarded its unpublished candidate".to_owned()
                }
                InterruptedTransition::Published(version) => format!(
                    "finished the update cut short after Vox {version} was put in place and kept the replaced app for rollback"
                ),
                InterruptedTransition::BeforeRollback(version) => format!(
                    "finished the rollback cut short before Vox {version} was put in place and kept the replaced app for rollback"
                ),
                InterruptedTransition::RolledBack(version) => format!(
                    "finished the rollback cut short after Vox {version} was put in place and kept the replaced app for rollback"
                ),
            });
        }
        if self.previous_set_aside {
            parts.push("made the kept previous bundle non-launchable again".to_owned());
        }
        if self.retired_set_aside > 0 {
            parts.push(format!(
                "made {} retired bundle(s) non-launchable",
                self.retired_set_aside
            ));
        }
        if self.retired_removed > 0 {
            parts.push(format!(
                "removed {} retired bundle(s) no process still used",
                self.retired_removed
            ));
        }
        parts.join("; ")
    }

    fn say_before_transition(&self) {
        if !self.is_empty() {
            println!("vox: repaired an earlier app transition: {}", self.detail());
        }
    }

    fn say_without_swap(&self) {
        if !self.is_empty() {
            println!(
                "vox: repaired an earlier app transition without swapping Vox.app: {}",
                self.detail()
            );
        }
    }
}

/// Unpack the downloaded zip beside the bundle, on its filesystem, and return the one Vox.app
/// it held, moved to `.Vox.app.partial`.
fn unpack(apps: &Path, zip: &Path) -> Result<PathBuf, AppError> {
    let unpacked = apps.join(UNPACK_PARTIAL);
    let staged = apps.join(PARTIAL);
    require_optional_dir(&unpacked, UNPACK_PARTIAL)?;
    require_optional_bundle(&staged, PARTIAL)?;
    clear(&unpacked)?;
    clear(&staged)?;
    fs::create_dir(&unpacked).map_err(AppError::Io)?;
    sync_dir(apps)?;
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
        .map(|entry| {
            entry
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .map_err(AppError::Io)
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
    sync_tree(&bundle)?;
    sync_dir(&unpacked)?;
    fs::rename(&bundle, &staged).map_err(AppError::Io)?;
    sync_dir(&unpacked)?;
    sync_dir(apps)?;
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
    let says = active_app_version(staged).unwrap_or_default();
    if says != vox.version_text {
        return Err(usage(format!(
            "the new Vox.app says it is version {says:?}, not {}",
            vox.version_text
        )));
    }
    if apple_required() {
        verify_apple(active, staged)?;
    }
    let out = Command::new(&helper)
        .arg("--version")
        .env_clear()
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

/// An active bundle's `CFBundleShortVersionString`. Evidence about [`BUNDLE`] comes only from
/// its real Info.plist; a kept plist is never evidence that a swap happened.
fn active_app_version(bundle: &Path) -> Option<String> {
    plist_version(&bundle.join(INFO_PLIST))
}

/// A bundle's version while it is deliberately set aside, or while it is active.
fn bundle_version(bundle: &Path) -> Option<String> {
    active_app_version(bundle).or_else(|| plist_version(&bundle.join(KEPT_INFO_PLIST)))
}

fn plist_version(plist: &Path) -> Option<String> {
    if !plist.is_file() {
        return None;
    }
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

fn path_exists(path: &Path) -> Result<bool, AppError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(AppError::Io(e)),
    }
}

fn require_optional_dir(path: &Path, name: &str) -> Result<(), AppError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(AppError::Io(e)),
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(usage(format!(
            "reserved app-transition path {} ({name}) is not a direct directory; no transition was attempted",
            path.display()
        )));
    }
    Ok(())
}

fn require_optional_bundle(path: &Path, name: &str) -> Result<(), AppError> {
    require_optional_dir(path, name)
}

fn require_bundle(path: &Path, name: &str) -> Result<(), AppError> {
    require_optional_bundle(path, name)?;
    if !path_exists(path)? {
        return Err(usage(format!(
            "reserved app-transition path {} ({name}) is missing",
            path.display()
        )));
    }
    Ok(())
}

fn file_id(path: &Path) -> Result<u64, AppError> {
    fs::symlink_metadata(path)
        .map(|meta| meta.ino())
        .map_err(AppError::Io)
}

/// Flush every regular file and directory in a verified candidate before its name can be
/// exchanged into place. Symlinks are metadata in their parent directory and are never followed.
fn sync_tree(path: &Path) -> Result<(), AppError> {
    let meta = fs::symlink_metadata(path).map_err(AppError::Io)?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    if meta.is_file() {
        return fs::File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(AppError::Io);
    }
    if meta.is_dir() {
        for entry in fs::read_dir(path).map_err(AppError::Io)? {
            sync_tree(&entry.map_err(AppError::Io)?.path())?;
        }
        return sync_dir(path);
    }
    Ok(())
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
    let removed = if meta.is_dir() {
        writable(path)?;
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    removed.map_err(|e| {
        usage(format!(
            "cannot clear {}: {e}\n       remove it by hand, then run this again",
            path.display()
        ))
    })?;
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
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

/// The bundle is in place, but an app already open is not: say so, and ask. The daemon is
/// restarted by the update itself ([`super::restart`]).
fn ask_to_restart(was: &str, now: &str) {
    println!("restart Vox to run {now}: an open Vox keeps running {was} until it is restarted");
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
