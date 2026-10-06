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
//! The app and the daemon keep running the old version until restarted, and the person is asked
//! to restart both.

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
        return Ok(());
    }
    println!(
        "Vox {} is available on {channel} (this is {current})",
        vox.version_text
    );
    if check_only {
        return Ok(());
    }

    // The lock first: what is in `apps` is read only while no other transition changes it.
    let _lock = InstallLock::acquire(apps)?;
    recover(apps)?;
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
    publish(apps, &vox.version_text)?;

    println!("updated: {} -> Vox {}", active.display(), vox.version_text);
    println!(
        "         the previous Vox.app is kept at {} for `vox update --rollback`",
        apps.join(PREVIOUS).display()
    );
    ask_to_restart(current.to_string().as_str(), &vox.version_text);
    shell_setup_from(apps, exe);
    Ok(())
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
    let was = app_version(&active).unwrap_or_else(|| "unknown".to_owned());
    swap(&previous, &active)?;
    sync_dir(apps)?;
    let now = app_version(&active).unwrap_or_else(|| "unknown".to_owned());
    println!("rolled back: {} -> Vox {now}", active.display());
    println!(
        "         Vox {was} is kept at {} for --rollback",
        previous.display()
    );
    ask_to_restart(&was, &now);
    shell_setup_from(apps, exe);
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
fn publish(apps: &Path, version: &str) -> Result<(), AppError> {
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
    clear(&journal)
}

/// Bundles retired by earlier transitions while code from them was running: `.Vox.app.retired.*`.
const RETIRED_PREFIX: &str = ".Vox.app.retired.";

/// Rename `bundle` aside as retired: a daemon not restarted since an earlier update runs from it.
fn retire(apps: &Path, bundle: &Path) -> Result<(), AppError> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let name = format!("{RETIRED_PREFIX}{secs}.{}", std::process::id());
    fs::rename(bundle, apps.join(name)).map_err(AppError::Io)
}

/// Remove the retired bundles nothing runs from any more.
fn sweep(apps: &Path) -> Result<(), AppError> {
    let Ok(entries) = fs::read_dir(apps) else {
        return Ok(());
    };
    for entry in entries.filter_map(Result::ok) {
        let retired = entry
            .file_name()
            .to_string_lossy()
            .starts_with(RETIRED_PREFIX);
        if retired && !in_use(&entry.path()) {
            clear(&entry.path())?;
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
fn recover(apps: &Path) -> Result<(), AppError> {
    sweep(apps)?;
    let journal = apps.join(PUBLISHING);
    if fs::symlink_metadata(&journal).is_err() {
        return Ok(());
    }
    let staged = apps.join(PARTIAL);
    let previous = apps.join(PREVIOUS);
    let published = fs::read_to_string(journal.join(PUBLISHING_VERSION)).unwrap_or_default();
    if fs::symlink_metadata(&previous).is_err() && staged.join(HELPER).is_file() {
        if app_version(&apps.join(BUNDLE)).as_deref() == Some(published.trim()) {
            fs::rename(&staged, &previous).map_err(AppError::Io)?;
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
        fs::rename(&kept, &previous).map_err(AppError::Io)?;
    }
    sync_dir(apps)?;
    clear(&journal)
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

/// The bundle's `CFBundleShortVersionString`.
fn app_version(bundle: &Path) -> Option<String> {
    let out = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :CFBundleShortVersionString"])
        .arg(bundle.join("Contents/Info.plist"))
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

/// The bundle is in place, but what is already running is not: say so, and ask.
fn ask_to_restart(was: &str, now: &str) {
    println!(
        "restart Vox and the vox daemon to run {now}: both keep running {was} until they are \
         restarted"
    );
}

/// Refresh completions through the path the person ran, when that is the link outside the
/// bundle; the rc block records that directory, never one inside the bundle.
fn shell_setup_from(apps: &Path, exe: &Path) {
    let inside = exe
        .parent()
        .and_then(|dir| fs::canonicalize(dir).ok())
        .is_some_and(|dir| dir.starts_with(apps));
    if !inside {
        run_shell_setup(exe);
    }
}
