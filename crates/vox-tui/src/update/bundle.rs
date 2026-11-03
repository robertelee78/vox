//! Target-owned macOS update: archive and verify the installed signed application, exchange an
//! authenticated candidate, retire displaced trees, then complete the captured handoff. A
//! durable archive beside the install is the offline rollback authority; interrupted precommit
//! transitions restore the verified source, and committed transitions resume handoff only.

use std::fs;
use std::io::{BufRead as _, Read as _};
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
/// Retained bundle name used by older updater versions during legacy recovery.
const PREVIOUS: &str = ".Vox.app.previous";
/// A verified candidate waiting to be swapped in; scratch whenever no update is running.
const PARTIAL: &str = ".Vox.app.partial";
/// Where the download is unpacked before its one `Vox.app` is moved to [`PARTIAL`].
const UNPACK_PARTIAL: &str = ".Vox.app.unpack.partial";
/// The CLI inside the bundle.
const HELPER: &str = "Contents/Helpers/vox";
/// Durable transition and staged rollback archives, held under the installation lock.
const PUBLISHING: &str = ".Vox.app.publishing";
/// The version file used by older updater journals.
const PUBLISHING_VERSION: &str = "version";
const TRANSITION: &str = "transition.json";
const ROLLBACK_ARCHIVE: &str = ".Vox.app.rollback.zip";
const ROLLBACK_AUTHORITY: &str = ".Vox.app.rollback.json";
const SOURCE_ARCHIVE: &str = "source.zip";
const PRIOR_ARCHIVE: &str = "prior.zip";
const PRIOR_AUTHORITY: &str = "prior.json";

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
enum FilesystemPhase {
    Prepared,
    Stopped,
    Exchanged,
    Retiring,
    Restoring,
    FilesystemCommitted,
    HandingOff,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveTransition {
    phase: FilesystemPhase,
    #[serde(default)]
    legacy: bool,
    #[serde(default)]
    legacy_path: Option<Vec<u8>>,
    #[serde(default)]
    legacy_superseded: Option<ArchiveAuthority>,
    #[serde(default)]
    legacy_superseded_identity: Option<BundleIdentity>,
    source_archive: ArchiveAuthority,
    previous_archive: Option<ArchiveAuthority>,
    restoration: Option<BundleIdentity>,
    restoration_directory: Option<BundleIdentity>,
    restoration_path: Option<Vec<u8>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidatePreparation {
    directory: BundleIdentity,
    staged: Option<BundleIdentity>,
    verification_directory: Option<BundleIdentity>,
    verification_path: Option<Vec<u8>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPreparation {
    directory: BundleIdentity,
    verification_directory: Option<BundleIdentity>,
    verification_path: Option<Vec<u8>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Transition {
    #[serde(default, deserialize_with = "deserialize_identity_format")]
    identity_format: IdentityFormat,
    #[serde(
        default,
        deserialize_with = "deserialize_present",
        skip_serializing_if = "Option::is_none"
    )]
    identity_history: Option<IdentityHistory>,
    #[serde(
        default,
        deserialize_with = "deserialize_present",
        skip_serializing_if = "Option::is_none"
    )]
    readoption_target: Option<BundleIdentity>,
    kind: TransitionKind,
    version: String,
    source: BundleIdentity,
    target: BundleIdentity,
    daemon_data_root: Vec<u8>,
    daemon_config_dir: Vec<u8>,
    daemon: super::restart::DaemonIntent,
    #[serde(default)]
    daemon_process: Option<super::restart::DaemonProcess>,
    #[serde(default)]
    archive: Option<ArchiveTransition>,
    #[serde(default)]
    candidate_preparation: Option<CandidatePreparation>,
    #[serde(default)]
    legacy_preparation: Option<LegacyPreparation>,
    #[serde(default)]
    legacy_no_handoff: bool,
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

#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StableIdentity {
    volume: [u8; 16],
    birth_seconds: i64,
    birth_nanoseconds: i64,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct BundleIdentity {
    device: u64,
    inode: u64,
    #[serde(
        default,
        deserialize_with = "deserialize_present",
        skip_serializing_if = "Option::is_none"
    )]
    stable: Option<StableIdentity>,
}

fn deserialize_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Clone, Copy, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
enum IdentityFormat {
    #[default]
    #[serde(rename = "original-legacy")]
    OriginalLegacy,
    #[serde(rename = "durable-v1")]
    Durable,
    #[serde(rename = "legacy-continuation-v1")]
    LegacyContinuation,
}

fn deserialize_identity_format<'de, D>(deserializer: D) -> Result<IdentityFormat, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let format = <IdentityFormat as serde::Deserialize>::deserialize(deserializer)?;
    if format == IdentityFormat::OriginalLegacy {
        return Err(serde::de::Error::custom(
            "original legacy identity format must be absent",
        ));
    }
    Ok(format)
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityHistory {
    roles: [Option<BundleIdentity>; 10],
    durable_roles: std::cell::Cell<u16>,
}

impl BundleIdentity {
    fn valid(&self) -> bool {
        self.inode != 0
            && self.stable.as_ref().is_none_or(|stable| {
                stable.volume != [0; 16]
                    && stable.birth_seconds > 0
                    && (0..1_000_000_000).contains(&stable.birth_nanoseconds)
            })
    }

    fn matches(&self, current: &Self) -> bool {
        match (&self.stable, &current.stable) {
            (Some(a), Some(b)) => self.inode == current.inode && a == b,
            (None, Some(_)) | (None, None) => {
                self.device == current.device && self.inode == current.inode
            }
            (Some(_), None) => false,
        }
    }
}

fn saved_matches(saved: Option<&BundleIdentity>, current: &BundleIdentity) -> bool {
    saved.is_some_and(|identity| identity.matches(current))
}

impl Transition {
    fn identities(&self) -> [Option<&BundleIdentity>; 10] {
        [
            Some(&self.source),
            Some(&self.target),
            self.archive
                .as_ref()
                .and_then(|a| a.legacy_superseded_identity.as_ref()),
            self.archive.as_ref().and_then(|a| a.restoration.as_ref()),
            self.archive
                .as_ref()
                .and_then(|a| a.restoration_directory.as_ref()),
            self.candidate_preparation.as_ref().map(|a| &a.directory),
            self.candidate_preparation
                .as_ref()
                .and_then(|a| a.staged.as_ref()),
            self.candidate_preparation
                .as_ref()
                .and_then(|a| a.verification_directory.as_ref()),
            self.legacy_preparation.as_ref().map(|a| &a.directory),
            self.legacy_preparation
                .as_ref()
                .and_then(|a| a.verification_directory.as_ref()),
        ]
    }

    fn validate_identities(&self, writing: bool) -> Result<(), AppError> {
        let roles = self.identities();
        if roles.iter().flatten().any(|identity| !identity.valid()) {
            return Err(usage("invalid transition identity; all files retained"));
        }
        match self.identity_format {
            IdentityFormat::OriginalLegacy => {
                if self.identity_history.is_some()
                    || self.readoption_target.is_some()
                    || roles
                        .iter()
                        .flatten()
                        .any(|identity| identity.stable.is_some())
                {
                    return Err(usage(
                        "invalid original legacy identity format; all files retained",
                    ));
                }
            }
            IdentityFormat::Durable => {
                if self.identity_history.is_some()
                    || self.readoption_target.is_some()
                    || roles
                        .iter()
                        .flatten()
                        .any(|identity| identity.stable.is_none())
                {
                    return Err(usage("invalid durable identity format; all files retained"));
                }
            }
            IdentityFormat::LegacyContinuation => {
                let history = self
                    .identity_history
                    .as_ref()
                    .ok_or_else(|| usage("missing legacy identity history; all files retained"))?;
                let mut mask = history.durable_roles.get();
                if history.roles[0].is_none()
                    || history.roles[1].is_none()
                    || mask & !0x03ff != 0
                    || history
                        .roles
                        .iter()
                        .flatten()
                        .any(|v| !v.valid() || v.stable.is_some())
                {
                    return Err(usage("invalid legacy identity history; all files retained"));
                }
                for (index, identity) in roles.into_iter().enumerate() {
                    if let Some(identity) = identity {
                        let bit = 1 << index;
                        if identity.stable.is_some() {
                            if !writing && mask & bit == 0 {
                                return Err(usage("unrecorded fresh identity; all files retained"));
                            }
                            mask |= bit;
                        } else if mask & bit != 0 || history.roles[index].as_ref() != Some(identity)
                        {
                            return Err(usage(
                                "legacy identity changed or downgraded; all files retained",
                            ));
                        }
                    }
                }
                if let Some(target) = &self.readoption_target {
                    if !target.valid() || target.stable.is_none() {
                        return Err(usage("invalid readoption identity; all files retained"));
                    }
                }
                if writing {
                    history.durable_roles.set(mask);
                }
            }
        }
        Ok(())
    }

    fn continue_legacy(&mut self) {
        let roles = self.identities().map(|role| role.cloned());
        self.identity_history = Some(IdentityHistory {
            roles,
            durable_roles: std::cell::Cell::new(0),
        });
        self.identity_format = IdentityFormat::LegacyContinuation;
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AppIntent {
    pid: u32,
    started: u64,
    data_root: Vec<u8>,
    config_dir: Vec<u8>,
    home: Option<Vec<u8>>,
    xdg_data: Option<Vec<u8>>,
    xdg_config: Option<Vec<u8>>,
}

fn replacement_directory(active: &Path) -> Result<PathBuf, AppError> {
    use std::os::unix::fs::MetadataExt as _;
    let directory = vox_sockdrops::replacement_directory(active).map_err(|e| {
        usage(format!(
            "cannot create replacement directory for {}: {e}",
            active.display()
        ))
    })?;
    let metadata = fs::symlink_metadata(&directory).map_err(AppError::Io)?;
    if !directory.is_absolute()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.dev() != bundle_identity(active)?.device
    {
        return Err(usage(format!(
            "replacement directory {} is not private on the installation volume",
            directory.display()
        )));
    }
    Ok(directory)
}

fn bundle_identity(path: &Path) -> Result<BundleIdentity, AppError> {
    use std::os::macos::fs::MetadataExt as _;
    use std::os::unix::fs::MetadataExt as _;
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| usage(format!("cannot inspect {}: {e}", path.display())))?;
    if !metadata.is_dir() {
        return Err(usage(format!(
            "{} is not a bundle directory",
            path.display()
        )));
    }
    let volume = vox_sockdrops::volume_uuid(path)
        .map_err(|e| usage(format!("cannot identify volume of {}: {e}", path.display())))?;
    let after = fs::symlink_metadata(path)
        .map_err(|e| usage(format!("cannot reinspect {}: {e}", path.display())))?;
    if !after.is_dir()
        || metadata.dev() != after.dev()
        || metadata.ino() != after.ino()
        || metadata.st_birthtime() != after.st_birthtime()
        || metadata.st_birthtime_nsec() != after.st_birthtime_nsec()
    {
        return Err(usage(format!(
            "{} changed during identity capture",
            path.display()
        )));
    }
    let identity = BundleIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        stable: Some(StableIdentity {
            volume,
            birth_seconds: metadata.st_birthtime(),
            birth_nanoseconds: metadata.st_birthtime_nsec(),
        }),
    };
    if !identity.valid() {
        return Err(usage(format!(
            "{} has no valid durable identity",
            path.display()
        )));
    }
    Ok(identity)
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
    transition.validate_identities(true)?;
    let mut temporary = tempfile::Builder::new()
        .prefix("transition.")
        .tempfile_in(journal)
        .map_err(|e| {
            usage(format!(
                "cannot create transition in {}: {e}",
                journal.display()
            ))
        })?;
    let destination = journal.join(TRANSITION);
    let bytes = serde_json::to_vec(transition)
        .map_err(|e| usage(format!("cannot encode transition: {e}")))?;
    temporary
        .as_file_mut()
        .write_all(&bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|e| {
            usage(format!(
                "cannot write and sync {}: {e}",
                temporary.path().display()
            ))
        })?;
    fs::rename(temporary.path(), &destination).map_err(|e| {
        usage(format!(
            "cannot rename {} to {}: {e}",
            temporary.path().display(),
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
    active: &Path,
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
    let (daemon, daemon_process) =
        super::restart::capture_daemon_state(&account, &active.join(HELPER))?;
    Ok(Transition {
        identity_format: IdentityFormat::Durable,
        identity_history: None,
        readoption_target: None,
        kind,
        version: version.to_owned(),
        source: bundle_identity(source)?,
        target: bundle_identity(target)?,
        daemon_data_root,
        daemon_config_dir,
        daemon,
        daemon_process,
        archive: None,
        candidate_preparation: None,
        legacy_preparation: None,
        legacy_no_handoff: false,
        app,
        daemon_complete: false,
        app_complete: false,
        handoff_complete: false,
    })
}

fn publish_new_journal(apps: &Path, transition: &Transition) -> Result<(), AppError> {
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
        .map_err(AppError::Io)?;
    write_transition_in(preparing.path(), transition)?;
    fs::rename(preparing.path(), &journal)
        .map_err(|e| usage(format!("cannot publish journal {}: {e}", journal.display())))?;
    sync_dir(apps)
}

fn prepare_candidate_journal(apps: &Path) -> Result<Transition, AppError> {
    use std::os::unix::fs::DirBuilderExt as _;
    let active = apps.join(BUNDLE);
    let unpacked = apps.join(UNPACK_PARTIAL);
    if path_exists(&unpacked)?
        || path_exists(&apps.join(PARTIAL))?
        || path_exists(&apps.join(PUBLISHING))?
    {
        return Err(usage(
            "unexpected candidate staging or journal exists; all files retained",
        ));
    }
    let running = inspect_app(&active)?;
    let version =
        app_version(&active).ok_or_else(|| usage("active Vox.app version is unavailable"))?;
    let mut transition = transition_record(
        &active,
        &active,
        &active,
        TransitionKind::Refresh,
        &version,
        &running,
    )?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&unpacked)
        .map_err(|e| usage(format!("cannot create {}: {e}", unpacked.display())))?;
    transition.candidate_preparation = Some(CandidatePreparation {
        directory: bundle_identity(&unpacked)?,
        staged: None,
        verification_directory: None,
        verification_path: None,
    });
    if let Err(error) = publish_new_journal(apps, &transition) {
        return match fs::remove_dir(&unpacked) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(usage(format!(
                "{error}; cannot remove empty {}: {cleanup}",
                unpacked.display()
            ))),
        };
    }
    Ok(transition)
}

fn stage_candidate(
    apps: &Path,
    candidate: &Path,
    transition: &mut Transition,
) -> Result<PathBuf, AppError> {
    let unpacked = apps.join(UNPACK_PARTIAL);
    let staged = apps.join(PARTIAL);
    let preparation = transition
        .candidate_preparation
        .as_ref()
        .ok_or_else(|| usage("missing candidate preparation authority"))?;
    if candidate != unpacked.join(BUNDLE)
        || !preparation.directory.matches(&bundle_identity(&unpacked)?)
        || path_exists(&staged)?
    {
        return Err(usage(
            "candidate staging identity changed; all files retained",
        ));
    }
    let identity = bundle_identity(candidate)?;
    transition
        .candidate_preparation
        .as_mut()
        .ok_or_else(|| usage("missing candidate preparation authority"))?
        .staged = Some(identity);
    write_transition(apps, transition)?;
    move_durable(candidate, &staged)?;
    vox_sockdrops::remove_item(&unpacked)
        .map_err(|e| usage(format!("cannot remove {}: {e}", unpacked.display())))?;
    Ok(staged)
}

fn prepare_transition(
    apps: &Path,
    candidate: &Path,
    kind: TransitionKind,
    version: &str,
    app: &Option<StoppedApp>,
) -> Result<Transition, AppError> {
    use std::os::unix::ffi::OsStrExt as _;
    let active = apps.join(BUNDLE);
    let mut transition = transition_record(&active, &active, candidate, kind, version, app)?;
    if matches!(kind, TransitionKind::Refresh) {
        publish_new_journal(apps, &transition)?;
        return Ok(transition);
    }
    let journal = apps.join(PUBLISHING);
    let bytes = fs::read(journal.join(TRANSITION)).map_err(AppError::Io)?;
    let mut preparing: Transition = serde_json::from_slice(&bytes)
        .map_err(|e| usage(format!("invalid candidate preparation journal: {e}")))?;
    let preparation = preparing
        .candidate_preparation
        .as_ref()
        .ok_or_else(|| usage("missing candidate preparation authority"))?;
    if !preparing.source.matches(&transition.source)
        || !saved_matches(preparation.staged.as_ref(), &transition.target)
        || candidate != apps.join(PARTIAL)
    {
        return Err(usage(
            "candidate or source identity changed during preparation",
        ));
    }
    let archive_path = journal.join(SOURCE_ARCHIVE);
    let source_archive = archive_authority(&active, &archive_path)?;
    let previous_archive = read_rollback_authority(apps)?;
    let replacement = replacement_directory(&active)?;
    let preparation = preparing
        .candidate_preparation
        .as_mut()
        .ok_or_else(|| usage("missing candidate preparation authority"))?;
    preparation.verification_directory = Some(bundle_identity(&replacement)?);
    preparation.verification_path = Some(replacement.join(BUNDLE).as_os_str().as_bytes().to_vec());
    write_transition(apps, &preparing)?;
    let checked = extract_archive(&archive_path, &source_archive, &replacement).and_then(|path| {
        launch_services(false, &path).map_err(usage)?;
        Ok(())
    });
    let cleanup = vox_sockdrops::remove_item(&replacement).map_err(|e| {
        usage(format!(
            "cannot remove replacement directory {}: {e}",
            replacement.display()
        ))
    });
    match (checked, cleanup) {
        (Err(e), Err(cleanup)) => return Err(usage(format!("{e}; {cleanup}"))),
        (Err(e), _) | (_, Err(e)) => return Err(e),
        _ => {}
    }
    transition.archive = Some(ArchiveTransition {
        phase: FilesystemPhase::Prepared,
        legacy: false,
        legacy_path: None,
        legacy_superseded: None,
        legacy_superseded_identity: None,
        source_archive,
        previous_archive,
        restoration: None,
        restoration_directory: None,
        restoration_path: None,
    });
    write_transition(apps, &transition)?;
    Ok(transition)
}

/// **Test-only**: abort after exchange and its directory sync, before retirement or commit.
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
    shell_setup_from(apps, exe)?;
    repaired.say_without_swap(apps)?;
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
    shell_setup_from(apps, exe)?;
    sweep(apps, &mut Recovery::default())?;
    println!("Vox {now} is current");
    Ok(())
}

/// Apply the already verified helper release, with the target engine owning the transaction.
pub(super) fn apply(
    apps: &Path,
    exe: &Path,
    vox: &Validated,
    supplied_archive: Option<&Path>,
) -> Result<(), AppError> {
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

    use std::io::Seek as _;
    let mut downloaded = None;
    let zip_file = if let Some(path) = supplied_archive {
        verified_release_zip(path, &app)?
    } else {
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
        let (mut file, path) = downloading.into_parts();
        file.rewind().map_err(AppError::Io)?;
        downloaded = Some(path);
        file
    };
    let zip: &Path = match supplied_archive {
        Some(path) => path,
        None => downloaded
            .as_deref()
            .ok_or_else(|| usage("downloaded app archive is unavailable"))?,
    };
    let mut preparation = prepare_candidate_journal(apps)?;
    let staged =
        unpack(apps, zip, zip_file, &mut preparation).map_err(|e| preparation_failed(apps, e))?;
    verify(&active, &staged, vox).map_err(|e| preparation_failed(apps, e))?;
    let running = inspect_app(&active).map_err(|e| preparation_failed(apps, e))?;
    let mut transition = prepare_transition(
        apps,
        &staged,
        TransitionKind::Update,
        &vox.version_text,
        &running,
    )
    .map_err(|e| preparation_failed(apps, e))?;
    if let Err(e) = stop_transaction(apps, &running, &mut transition)
        .and_then(|()| publish(apps, &mut transition))
    {
        return Err(transition_failed_journal(
            apps,
            &running,
            &mut transition,
            e,
        ));
    }
    transition
        .archive
        .as_mut()
        .ok_or_else(|| usage("missing archive transaction authority"))?
        .phase = FilesystemPhase::HandingOff;
    write_transition(apps, &transition)?;
    let handoff = transition_handoff(apps, &active, &vox.version_text, &running, &mut transition);
    let integration = shell_setup_from(apps, exe);
    let mut failures = Vec::new();
    if let Err(e) = handoff {
        failures.push(e.to_string());
    }
    if let Err(e) = integration {
        failures.push(format!("integration failed: {e}"));
    }
    if !failures.is_empty() {
        return Err(usage(format!(
            "CLI and app Vox {} are installed; transition incomplete (app handoff: {}; daemon handoff: {}): {}; run `vox update` for local repair",
            vox.version_text,
            if transition.app_complete { "complete" } else { "incomplete" },
            if transition.daemon_complete { "complete" } else { "incomplete" },
            failures.join("; ")
        )));
    }
    finish_journal(apps)?;
    println!(
        "updated: {} -> Vox {}; previous version retained for rollback",
        active.display(),
        vox.version_text
    );
    Ok(())
}

/// Restore the authenticated offline archive, retaining the replaced version for the next rollback.
pub(super) fn rollback(apps: &Path, exe: &Path) -> Result<(), AppError> {
    let active = apps.join(BUNDLE);
    let _lock = InstallLock::acquire(apps)?;
    let repaired = recover(apps)?;
    if !repaired.is_empty() && !repaired.legacy_migrated {
        if !repaired.handoff_done {
            let now = app_version(&active)
                .ok_or_else(|| usage("the repaired Vox.app has no readable version"))?;
            journaled_refresh(apps, &active, &now)?;
        }
        shell_setup_from(apps, exe)?;
        repaired.say_without_swap(apps)?;
        return Ok(());
    }
    let authority = read_rollback_authority(apps)?
        .ok_or_else(|| usage("no rollback archive was retained — nothing to roll back to"))?;
    let mut preparation = prepare_candidate_journal(apps)?;
    let candidate = extract_archive(
        &apps.join(ROLLBACK_ARCHIVE),
        &authority,
        &apps.join(UNPACK_PARTIAL),
    )
    .map_err(|e| preparation_failed(apps, e))?;
    let staged = stage_candidate(apps, &candidate, &mut preparation)
        .map_err(|e| preparation_failed(apps, e))?;
    let running = inspect_app(&active).map_err(|e| preparation_failed(apps, e))?;
    let was = app_version(&active)
        .ok_or_else(|| preparation_failed(apps, usage("active Vox.app version is unavailable")))?;
    let now = authority.version.clone();
    let mut transition =
        prepare_transition(apps, &staged, TransitionKind::Rollback, &now, &running)
            .map_err(|e| preparation_failed(apps, e))?;
    if let Err(e) = stop_transaction(apps, &running, &mut transition)
        .and_then(|()| publish(apps, &mut transition))
    {
        return Err(transition_failed_journal(
            apps,
            &running,
            &mut transition,
            e,
        ));
    }
    transition
        .archive
        .as_mut()
        .ok_or_else(|| usage("missing archive transaction authority"))?
        .phase = FilesystemPhase::HandingOff;
    write_transition(apps, &transition)?;
    let handoff = transition_handoff(apps, &active, &now, &running, &mut transition);
    let integration = shell_setup_from(apps, exe);
    let mut failures = Vec::new();
    if let Err(e) = handoff {
        failures.push(e.to_string());
    }
    if let Err(e) = integration {
        failures.push(format!("integration failed: {e}"));
    }
    if !failures.is_empty() {
        return Err(usage(format!(
            "CLI and app Vox {now} are installed; rollback incomplete (app handoff: {}; daemon handoff: {}); do not repeat --rollback: {}",
            if transition.app_complete { "complete" } else { "incomplete" },
            if transition.daemon_complete { "complete" } else { "incomplete" },
            failures.join("; ")
        )));
    }
    finish_journal(apps)?;
    println!(
        "rolled back: {} -> Vox {now}; Vox {was} retained for rollback",
        active.display()
    );
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
    .map_err(|e| {
        usage(format!(
            "cannot exchange {} and {}: {e}",
            a.display(),
            b.display()
        ))
    })
}

fn stop_transaction(
    apps: &Path,
    running: &Option<StoppedApp>,
    transition: &mut Transition,
) -> Result<(), AppError> {
    use std::os::unix::ffi::OsStringExt as _;
    let active = apps.join(BUNDLE);
    let account = vox_core::node::paths::Account {
        data_root: PathBuf::from(std::ffi::OsString::from_vec(
            transition.daemon_data_root.clone(),
        )),
        config_dir: PathBuf::from(std::ffi::OsString::from_vec(
            transition.daemon_config_dir.clone(),
        )),
    };
    stop_captured_app(&active, running)?;
    super::restart::stop_captured_daemon(
        &account,
        &transition.daemon,
        transition.daemon_process.as_ref(),
        &active.join(HELPER),
    )?;
    transition
        .archive
        .as_mut()
        .ok_or_else(|| usage("missing archive transaction authority"))?
        .phase = FilesystemPhase::Stopped;
    write_transition(apps, transition)
}

/// Exchange the candidate, retire the displaced tree, then commit archive authority.
fn publish(apps: &Path, transition: &mut Transition) -> Result<(), AppError> {
    let active = apps.join(BUNDLE);
    let staged = apps.join(PARTIAL);
    if !transition.source.matches(&bundle_identity(&active)?)
        || !transition.target.matches(&bundle_identity(&staged)?)
    {
        return Err(usage(
            "bundle identities changed before exchange; all files retained",
        ));
    }
    swap(&staged, &active)?;
    sync_dir(apps)?;
    #[cfg(feature = "test-knobs")]
    if std::env::var_os(TEST_ABORT_AFTER_SWAP_ENV).is_some_and(|v| !v.is_empty()) {
        std::process::abort();
    }
    transition
        .archive
        .as_mut()
        .ok_or_else(|| usage("missing archive transaction authority"))?
        .phase = FilesystemPhase::Exchanged;
    write_transition(apps, transition)?;
    if !transition.target.matches(&bundle_identity(&active)?)
        || !transition.source.matches(&bundle_identity(&staged)?)
    {
        return Err(usage(
            "bundle identities changed after exchange; all files retained",
        ));
    }
    transition
        .archive
        .as_mut()
        .ok_or_else(|| usage("missing archive transaction authority"))?
        .phase = FilesystemPhase::Retiring;
    write_transition(apps, transition)?;
    launch_services(false, &staged).map_err(usage)?;
    if !transition.target.matches(&bundle_identity(&active)?)
        || !transition.source.matches(&bundle_identity(&staged)?)
    {
        return Err(usage(
            "bundle identities changed before retirement; all files retained",
        ));
    }
    vox_sockdrops::remove_item(&staged).map_err(|e| {
        usage(format!(
            "cannot retire displaced bundle {}: {e}",
            staged.display()
        ))
    })?;
    sync_dir(apps)?;
    promote_archive(
        apps,
        transition
            .archive
            .as_ref()
            .ok_or_else(|| usage("missing archive transaction authority"))?,
    )?;
    launch_services(true, &active).map_err(usage)?;
    transition
        .archive
        .as_mut()
        .ok_or_else(|| usage("missing archive transaction authority"))?
        .phase = FilesystemPhase::FilesystemCommitted;
    write_transition(apps, transition)?;
    Ok(())
}

fn finish_journal(apps: &Path) -> Result<(), AppError> {
    let journal = apps.join(PUBLISHING);
    let older = journal.join(BUNDLE);
    if path_exists(&older)? {
        return Err(usage(format!(
            "unresolved legacy bundle {} retained",
            older.display()
        )));
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

/// Register the active bundle or unregister an exact displaced bundle path.
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

/// The legacy disabled-plist name is accepted only when reconstructing a private copy.
const KEPT_INFO_PLIST: &str = "Contents/Info.plist.kept";
const INFO_PLIST: &str = "Contents/Info.plist";

/// Dispose completed journals; preserve unknown legacy retired bundles.
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
            return Err(usage(format!(
                "unresolved legacy retired bundle {} retained",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

/// Recover the exact recorded transaction under the install lock; preserve ambiguous authority.
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
        let unpacked = apps.join(UNPACK_PARTIAL);
        if path_exists(&unpacked)? {
            use std::os::unix::fs::MetadataExt as _;
            let meta = fs::symlink_metadata(&unpacked).map_err(AppError::Io)?;
            if !meta.is_dir()
                || meta.uid() != rustix::process::getuid().as_raw()
                || meta.mode() & 0o077 != 0
                || path_exists(&apps.join(PARTIAL))?
            {
                return Err(usage(format!(
                    "unrecorded candidate directory {} retained",
                    unpacked.display()
                )));
            }
            fs::remove_dir(&unpacked).map_err(|e| {
                usage(format!(
                    "unrecorded nonempty or inaccessible candidate directory {} retained: {e}",
                    unpacked.display()
                ))
            })?;
            sync_dir(apps)?;
        }
        sweep(apps, &mut repaired)?;
        let previous = apps.join(PREVIOUS);
        if path_exists(&previous)? {
            if read_rollback_authority(apps)?.is_some() {
                return Err(usage(
                    "both legacy bundle and archive rollback authorities exist; all retained",
                ));
            }
            let active = apps.join(BUNDLE);
            let version = app_version(&active)
                .ok_or_else(|| usage("active Vox.app version is unavailable"))?;
            let running = inspect_app(&active)?;
            let mut transition = transition_record(
                &previous,
                &active,
                &active,
                TransitionKind::Update,
                &version,
                &running,
            )?;
            transition.legacy_no_handoff = true;
            let preparing = tempfile::Builder::new()
                .prefix(".Vox.app.prepare.")
                .tempdir_in(apps)
                .map_err(AppError::Io)?;
            write_transition_in(preparing.path(), &transition)?;
            fs::rename(preparing.path(), &journal).map_err(|e| {
                usage(format!(
                    "cannot publish legacy journal {}: {e}",
                    journal.display()
                ))
            })?;
            sync_dir(apps)?;
            return recover_transition(apps, &journal.join(TRANSITION));
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
        &active,
        target,
        TransitionKind::Update,
        published.trim(),
        &running,
    )?;
    write_transition(apps, &transition)?;
    recover_transition(apps, &transition_path)
}

fn stopped_from_transition(transition: &Transition) -> Option<StoppedApp> {
    use std::os::unix::ffi::OsStringExt as _;
    transition.app.as_ref().map(|intent| StoppedApp {
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
    })
}

fn reconcile_app_handoff(
    active: &Path,
    stopped: &Option<StoppedApp>,
    committed: bool,
) -> Result<(), AppError> {
    let mut app_already_restored = false;
    if let Some(saved) = stopped.as_ref() {
        if let Some(current) = inspect_app(active)? {
            if current.identity.pid == saved.identity.pid
                && current.identity.started == saved.identity.started
            {
                if !committed {
                    return Ok(());
                }
                stop_captured_app(active, stopped)?;
            } else {
                let same_profile = current.account.data_root == saved.account.data_root
                    && current.account.config_dir == saved.account.config_dir
                    && current.environment[2..] == saved.environment[2..];
                if !same_profile
                    || !pid_executes(&active_executable(active)?, current.identity.pid)?
                {
                    return Err(usage("another app instance is running; refusing to guess interrupted handoff identity"));
                }
                let confirmed = inspect_app(active)?.ok_or_else(|| {
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
                app_already_restored = true;
            }
        }
    }
    if app_already_restored {
        Ok(())
    } else {
        relaunch_app(active, stopped)
    }
}

fn preparation_failed(apps: &Path, error: AppError) -> AppError {
    let path = apps.join(PUBLISHING).join(TRANSITION);
    match recover_transition(apps, &path) {
        Ok(_) => error,
        Err(cleanup) => usage(format!(
            "{error}; candidate preparation cleanup failed: {cleanup}; journal retained"
        )),
    }
}

fn recover_candidate_preparation(apps: &Path, transition: &Transition) -> Result<(), AppError> {
    use std::os::unix::ffi::OsStringExt as _;
    let preparation = transition
        .candidate_preparation
        .as_ref()
        .ok_or_else(|| usage("missing candidate preparation authority"))?;
    if !matches!(transition.kind, TransitionKind::Refresh)
        || transition.archive.is_some()
        || transition.source != transition.target
        || !transition
            .source
            .matches(&bundle_identity(&apps.join(BUNDLE))?)
    {
        return Err(usage(
            "candidate preparation active identity changed; all files retained",
        ));
    }
    let unpacked = apps.join(UNPACK_PARTIAL);
    let staged = apps.join(PARTIAL);
    if path_exists(&unpacked)? && !preparation.directory.matches(&bundle_identity(&unpacked)?) {
        return Err(usage(
            "candidate preparation directory identity changed; all files retained",
        ));
    }
    if path_exists(&staged)?
        && !saved_matches(preparation.staged.as_ref(), &bundle_identity(&staged)?)
    {
        return Err(usage(
            "staged candidate identity changed; all files retained",
        ));
    }
    match (
        &preparation.verification_directory,
        &preparation.verification_path,
    ) {
        (None, None) => {}
        (Some(identity), Some(bytes)) => {
            let path = PathBuf::from(std::ffi::OsString::from_vec(bytes.clone()));
            let parent = path
                .parent()
                .ok_or_else(|| usage("invalid snapshot verification path"))?;
            if !path.is_absolute() || path.file_name() != Some(std::ffi::OsStr::new(BUNDLE)) {
                return Err(usage(
                    "invalid snapshot verification path; all files retained",
                ));
            }
            if path_exists(parent)? {
                if !identity.matches(&bundle_identity(parent)?) {
                    return Err(usage(
                        "snapshot verification directory identity changed; all files retained",
                    ));
                }
                if path_exists(&path)? {
                    bundle_identity(&path)?;
                    launch_services(false, &path).map_err(usage)?;
                }
                vox_sockdrops::remove_item(parent).map_err(|e| {
                    usage(format!(
                        "cannot remove snapshot verification directory {}: {e}",
                        parent.display()
                    ))
                })?;
            }
        }
        _ => {
            return Err(usage(
                "incomplete snapshot verification authority; all files retained",
            ))
        }
    }
    if path_exists(&unpacked)? {
        let partial_app = unpacked.join(BUNDLE);
        if path_exists(&partial_app)? {
            bundle_identity(&partial_app)?;
            launch_services(false, &partial_app).map_err(usage)?;
        }
        vox_sockdrops::remove_item(&unpacked).map_err(|e| {
            usage(format!(
                "cannot remove candidate directory {}: {e}",
                unpacked.display()
            ))
        })?;
    }
    if path_exists(&staged)? {
        launch_services(false, &staged).map_err(usage)?;
        vox_sockdrops::remove_item(&staged).map_err(|e| {
            usage(format!(
                "cannot remove staged candidate {}: {e}",
                staged.display()
            ))
        })?;
    }
    finish_journal(apps)
}

fn code_directory_hash(path: &Path) -> Result<String, AppError> {
    let output = Command::new("/usr/bin/codesign")
        .args(["--display", "--verbose=4"])
        .arg(path)
        .output()
        .map_err(AppError::Io)?;
    if !output.status.success()
        || output.stderr.len() > super::MAX_SIGNING_INFO_BYTES
        || !output.stdout.is_empty()
    {
        return Err(usage(format!(
            "cannot inspect code signature at {}",
            path.display()
        )));
    }
    let text = std::str::from_utf8(&output.stderr)
        .map_err(|_| usage("code signature information is not UTF-8"))?;
    let hash = super::unique_value(text, "CDHash=")?;
    if hash.is_empty() || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(usage("invalid code directory hash"));
    }
    Ok(hash.to_owned())
}

fn retained_release_error(error: AppError, version: &str) -> AppError {
    let temporary = matches!(&error, AppError::Usage(message)
        if message.starts_with("update transport failed:") || message.contains("is not published"));
    if temporary {
        usage(format!("cannot obtain retained release {version}: {error}; restore release access and run `vox update`"))
    } else {
        usage(format!("cannot authenticate retained release {version}: {error}; all files retained; contact Vox support"))
    }
}

fn unsafe_recovery(error: AppError) -> AppError {
    usage(format!("{error}; all files retained; contact Vox support"))
}

fn readoption_shape(apps: &Path, transition: &Transition) -> Result<(), AppError> {
    let archive = transition
        .archive
        .as_ref()
        .ok_or_else(|| usage("readoption has no archive authority; all files retained"))?;
    if transition.identity_format != IdentityFormat::LegacyContinuation
        || transition
            .identity_history
            .as_ref()
            .is_none_or(|history| history.durable_roles.get() != 0)
        || transition.source.stable.is_some()
        || transition.target.stable.is_some()
        || !matches!(
            transition.kind,
            TransitionKind::Update | TransitionKind::Rollback
        )
        || archive.legacy
        || !matches!(
            archive.phase,
            FilesystemPhase::FilesystemCommitted | FilesystemPhase::HandingOff
        )
        || transition.candidate_preparation.is_some()
        || transition.legacy_preparation.is_some()
        || archive.restoration.is_some()
        || archive.restoration_directory.is_some()
        || archive.restoration_path.is_some()
        || archive.legacy_path.is_some()
        || archive.legacy_superseded.is_some()
        || archive.legacy_superseded_identity.is_some()
        || transition.legacy_no_handoff
        || !transition.app_complete
        || (transition.readoption_target.is_none()
            && (transition.daemon_complete || transition.handoff_complete))
    {
        return Err(usage(
            "ambiguous legacy transition; retain all files and contact Vox support",
        ));
    }
    for path in [
        apps.join(PARTIAL),
        apps.join(UNPACK_PARTIAL),
        apps.join(PREVIOUS),
        apps.join(PUBLISHING).join(BUNDLE),
        apps.join(PUBLISHING).join("legacy-work"),
        apps.join(PUBLISHING).join(SOURCE_ARCHIVE),
        apps.join(PUBLISHING).join("source.json"),
        apps.join(PUBLISHING).join("legacy-superseded.zip"),
    ] {
        if path_exists(&path)? {
            return Err(usage(format!(
                "conflicting transition item {} retained; contact Vox support",
                path.display()
            )));
        }
    }
    let journal = apps.join(PUBLISHING);
    let prior_zip = journal.join(PRIOR_ARCHIVE);
    let prior_record = journal.join(PRIOR_AUTHORITY);
    match archive.previous_archive.as_ref() {
        Some(prior) => {
            if !path_exists(&prior_zip)?
                || !path_exists(&prior_record)?
                || read_archive_record(&prior_record)? != *prior
                || !archive_matches(&prior_zip, prior)?
            {
                return Err(usage(
                    "prior rollback authority changed; all files retained; contact Vox support",
                ));
            }
        }
        None if path_exists(&prior_zip)? || path_exists(&prior_record)? => {
            return Err(usage(
                "unexpected prior rollback authority; all files retained; contact Vox support",
            ));
        }
        None => {}
    }
    Ok(())
}

fn authenticate_readoption(apps: &Path, transition: &mut Transition) -> Result<(), AppError> {
    use std::io::{Seek as _, SeekFrom};
    readoption_shape(apps, transition)?;
    let active = apps.join(BUNDLE);
    let before = bundle_identity(&active)?;
    let volume = vox_sockdrops::volume_uuid(apps)
        .map_err(|e| usage(format!("cannot identify installation volume: {e}")))?;
    if before.device != transition.target.device
        || before.inode != transition.target.inode
        || before
            .stable
            .as_ref()
            .is_none_or(|stable| stable.volume != volume)
    {
        return Err(usage("legacy target inode or installation volume changed; all files retained; contact Vox support"));
    }
    let archive = transition
        .archive
        .as_ref()
        .ok_or_else(|| usage("missing archive authority; all files retained"))?;
    if read_rollback_authority(apps)
        .map_err(unsafe_recovery)?
        .as_ref()
        != Some(&archive.source_archive)
    {
        return Err(usage(
            "rollback authority changed; all files retained; contact Vox support",
        ));
    }
    let scratch = tempfile::Builder::new()
        .prefix("vox-recovery-auth.")
        .tempdir()
        .map_err(AppError::Io)?;
    let source_dir = scratch.path().join("source");
    let target_dir = scratch.path().join("target");
    fs::create_dir(&source_dir).map_err(AppError::Io)?;
    fs::create_dir(&target_dir).map_err(AppError::Io)?;
    extract_archive(
        &apps.join(ROLLBACK_ARCHIVE),
        &archive.source_archive,
        &source_dir,
    )
    .map_err(unsafe_recovery)?;
    let reference = match transition.kind {
        TransitionKind::Rollback => {
            let authority = archive.previous_archive.as_ref().ok_or_else(|| {
                usage("missing prior rollback authority; all files retained; contact Vox support")
            })?;
            let journal = apps.join(PUBLISHING);
            if read_archive_record(&journal.join(PRIOR_AUTHORITY))? != *authority {
                return Err(usage(
                    "prior rollback record changed; all files retained; contact Vox support",
                ));
            }
            extract_archive(&journal.join(PRIOR_ARCHIVE), authority, &target_dir)?
        }
        TransitionKind::Update => {
            let channel = super::Marker::read(&apps.join(super::MARKER_NAME))?.channel;
            let record = fetch_app_record_at(&channel, target_triple(), &transition.version)
                .map_err(|e| retained_release_error(e, &transition.version))?;
            let mut file = tempfile::tempfile().map_err(AppError::Io)?;
            download_asset(
                &record,
                &format!("Vox-{}-{}.zip", record.version_text, record.target),
                &mut file,
            )
            .map_err(|e| retained_release_error(e, &transition.version))?;
            file.seek(SeekFrom::Start(0)).map_err(AppError::Io)?;
            let output = Command::new("/usr/bin/ditto")
                .args(["-x", "-k", "-"])
                .stdin(std::process::Stdio::from(file))
                .arg(&target_dir)
                .output()
                .map_err(AppError::Io)?;
            if !output.status.success() {
                return Err(usage(format!(
                    "cannot extract retained release: {}; all files retained",
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
            let mut entries = fs::read_dir(&target_dir).map_err(AppError::Io)?;
            let entry = entries
                .next()
                .transpose()
                .map_err(AppError::Io)?
                .ok_or_else(|| usage("retained release archive is empty"))?;
            if entry.file_name() != BUNDLE
                || entries.next().transpose().map_err(AppError::Io)?.is_some()
            {
                return Err(usage(
                    "retained release archive has unexpected contents; all files retained",
                ));
            }
            let reference = target_dir.join(BUNDLE);
            bundle_identity(&reference)?;
            if apple_required() {
                verify_apple(&active, &reference).map_err(unsafe_recovery)?;
            }
            reference
        }
        TransitionKind::Refresh => return Err(usage("refresh cannot be readopted")),
    };
    let mut target_authority = archive.source_archive.clone();
    target_authority.version = transition.version.clone();
    verify_local_bundle(&reference, &target_authority).map_err(unsafe_recovery)?;
    verify_local_bundle(&active, &target_authority).map_err(unsafe_recovery)?;
    for (installed, expected) in [
        (active.clone(), reference.clone()),
        (active.join(HELPER), reference.join(HELPER)),
    ] {
        if code_directory_hash(&installed)? != code_directory_hash(&expected)? {
            return Err(usage(format!(
                "signed payload differs at {}; all files retained; contact Vox support",
                installed.display()
            )));
        }
    }
    if sha256_of(&active.join(HELPER))? != sha256_of(&reference.join(HELPER))? {
        return Err(usage("installed helper differs from retained release; all files retained; contact Vox support"));
    }
    let after = bundle_identity(&active)?;
    let after_volume = vox_sockdrops::volume_uuid(apps)
        .map_err(|e| usage(format!("cannot identify installation volume: {e}")))?;
    if !before.matches(&after) || before.device != after.device || volume != after_volume {
        return Err(usage(
            "target changed during authentication; all files retained; contact Vox support",
        ));
    }
    transition.readoption_target = Some(after);
    write_transition(apps, transition)
}

/// Recover using the bundle identities and owned handoff captured before the app was stopped.
fn recover_transition(apps: &Path, path: &Path) -> Result<Recovery, AppError> {
    use std::os::unix::ffi::OsStringExt as _;
    let bytes =
        fs::read(path).map_err(|e| usage(format!("cannot read {}: {e}", path.display())))?;
    let mut transition: Transition = serde_json::from_slice(&bytes).map_err(|e| {
        usage(format!(
            "cannot parse {}: {e}; all files retained; contact Vox support",
            path.display()
        ))
    })?;
    transition
        .validate_identities(false)
        .map_err(unsafe_recovery)?;
    if transition.identity_format == IdentityFormat::OriginalLegacy {
        transition.continue_legacy();
    }
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
        || transition
            .daemon_process
            .as_ref()
            .is_some_and(|process| !process.is_valid())
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
    if let Some(receipt) = transition.readoption_target.as_ref() {
        readoption_shape(apps, &transition)?;
        let current = bundle_identity(&apps.join(BUNDLE))?;
        let volume = vox_sockdrops::volume_uuid(apps)
            .map_err(|e| usage(format!("cannot identify installation volume: {e}")))?;
        if !receipt.matches(&current)
            || current.inode != transition.target.inode
            || current
                .stable
                .as_ref()
                .is_none_or(|stable| stable.volume != volume)
        {
            return Err(usage(
                "readopted target changed; all files retained; contact Vox support",
            ));
        }
    }
    if transition.candidate_preparation.is_some() {
        recover_candidate_preparation(apps, &transition)?;
        return Ok(Recovery {
            interrupted_publish: true,
            handoff_done: true,
            legacy_migrated: true,
            ..Recovery::default()
        });
    }
    if transition.archive.is_none()
        && !matches!(transition.kind, TransitionKind::Refresh)
        && transition
            .source
            .matches(&bundle_identity(&apps.join(BUNDLE))?)
    {
        let previous = apps.join(PREVIOUS);
        let kept = apps.join(PUBLISHING).join(BUNDLE);
        if path_exists(&kept)? {
            if path_exists(&previous)? {
                return Err(usage(
                    "ambiguous legacy rollback authority; all bundles retained",
                ));
            }
            move_durable(&kept, &previous)?;
        }
        let staged = apps.join(PARTIAL);
        if matches!(transition.kind, TransitionKind::Update) && path_exists(&staged)? {
            if !transition.target.matches(&bundle_identity(&staged)?) {
                return Err(usage(
                    "legacy candidate identity changed; all bundles retained",
                ));
            }
            launch_services(false, &staged).map_err(usage)?;
            vox_sockdrops::remove_item(&staged).map_err(|e| {
                usage(format!(
                    "cannot remove unpublished candidate {}: {e}",
                    staged.display()
                ))
            })?;
        }
        if path_exists(&previous)? {
            if matches!(transition.kind, TransitionKind::Rollback)
                && !transition.target.matches(&bundle_identity(&previous)?)
            {
                return Err(usage(
                    "legacy rollback identity changed; all bundles retained",
                ));
            }
            transition.source = bundle_identity(&previous)?;
            transition.target = bundle_identity(&apps.join(BUNDLE))?;
            transition.kind = TransitionKind::Update;
            transition.version = app_version(&apps.join(BUNDLE))
                .ok_or_else(|| usage("active Vox.app version is unavailable"))?;
            write_transition(apps, &transition)?;
        }
    }
    if transition.archive.is_none()
        && !matches!(transition.kind, TransitionKind::Refresh)
        && transition
            .target
            .matches(&bundle_identity(&apps.join(BUNDLE))?)
    {
        prepare_legacy_migration(apps, &mut transition)?;
    }
    if transition.archive.as_ref().is_some_and(|archive| {
        archive.legacy
            && archive.phase != FilesystemPhase::FilesystemCommitted
            && archive.phase != FilesystemPhase::HandingOff
    }) {
        resume_legacy_migration(apps, &mut transition)?;
    }
    if transition.readoption_target.is_none()
        && transition.identity_format == IdentityFormat::LegacyContinuation
        && transition.target.stable.is_none()
        && transition.archive.as_ref().is_some_and(|archive| {
            !archive.legacy
                && matches!(
                    archive.phase,
                    FilesystemPhase::FilesystemCommitted | FilesystemPhase::HandingOff
                )
        })
        && !transition
            .target
            .matches(&bundle_identity(&apps.join(BUNDLE))?)
    {
        authenticate_readoption(apps, &mut transition)?;
    }
    if let Some(archive) = transition.archive.as_ref() {
        if !matches!(
            archive.phase,
            FilesystemPhase::FilesystemCommitted | FilesystemPhase::HandingOff
        ) {
            let stopped = stopped_from_transition(&transition);
            restore_source_and_handoff(apps, &stopped, &mut transition)?;
            return Ok(Recovery {
                interrupted_publish: true,
                handoff_done: true,
                ..Recovery::default()
            });
        }
        if !transition
            .target
            .matches(&bundle_identity(&apps.join(BUNDLE))?)
            && !saved_matches(
                transition.readoption_target.as_ref(),
                &bundle_identity(&apps.join(BUNDLE))?,
            )
            || read_rollback_authority(apps)
                .map_err(unsafe_recovery)?
                .as_ref()
                != Some(&archive.source_archive)
        {
            return Err(usage(
                "committed archive transaction identity changed; all files retained; contact Vox support",
            ));
        }
        if !archive.source_archive.fixture_identity {
            let mut target_authority = archive.source_archive.clone();
            target_authority.version = transition.version.clone();
            verify_local_bundle(&apps.join(BUNDLE), &target_authority).map_err(|error| {
                usage(format!("installed committed bundle failed authentication: {error}; all files retained; contact Vox support"))
            })?;
        }
    }
    if transition.legacy_no_handoff {
        if !transition.archive.as_ref().is_some_and(|archive| {
            archive.legacy && archive.phase == FilesystemPhase::FilesystemCommitted
        }) {
            return Err(usage(
                "legacy migration has no committed archive; journal retained",
            ));
        }
        finish_journal(apps)?;
        return Ok(Recovery {
            interrupted_publish: true,
            handoff_done: true,
            legacy_migrated: true,
            ..Recovery::default()
        });
    }
    let active = apps.join(BUNDLE);
    let current = bundle_identity(&active)?;
    let committed = if matches!(transition.kind, TransitionKind::Refresh)
        && transition.source.matches(&current)
    {
        false
    } else if transition.target.matches(&current)
        || saved_matches(transition.readoption_target.as_ref(), &current)
    {
        true
    } else if transition.source.matches(&current) {
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
    if let Err(e) = sync_dir(apps) {
        errors.push(format!("cannot sync directory {}: {e}", apps.display()));
    }
    if !transition.handoff_complete {
        let app = stopped_from_transition(&transition);
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
                Ok(_detached) => {
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
        if !transition.app_complete {
            match reconcile_app_handoff(&active, &app, committed) {
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
            "CLI and app Vox {now} are installed; handoff incomplete (app: {}; daemon: {}){}: {}; run `vox update` for local repair",
            if transition.app_complete { "complete" } else { "incomplete" },
            if transition.daemon_complete { "complete" } else { "incomplete" },
            if committed && matches!(transition.kind, TransitionKind::Rollback) {
                "; do not repeat --rollback"
            } else { "" },
            errors.join("; ")
        )));
    }
    finish_journal(apps).map_err(|e| usage(format!(
        "Vox {now} is installed and handoff completed{}; cleanup failed: {e}; run `vox update` for local repair",
        if committed && matches!(transition.kind, TransitionKind::Rollback) { "; do not repeat --rollback" } else { "" }
    )))?;
    Ok(Recovery {
        interrupted_publish: true,
        handoff_done: true,
        daemon_was_running: Some(matches!(
            &transition.daemon,
            super::restart::DaemonIntent::Running { .. }
        )),
        ..Recovery::default()
    })
}

/// Work left by an earlier transition, reported after the active daemon has been restarted.
#[derive(Default)]
struct Recovery {
    interrupted_publish: bool,
    handoff_done: bool,
    legacy_migrated: bool,
    retired_removed: usize,
    daemon_was_running: Option<bool>,
}

impl Recovery {
    fn is_empty(&self) -> bool {
        !self.interrupted_publish && self.retired_removed == 0
    }

    fn say_without_swap(&self, apps: &Path) -> Result<(), AppError> {
        let version = app_version(&apps.join(BUNDLE))
            .ok_or_else(|| usage("cannot identify the repaired app version"))?;
        print!("vox: recovered an earlier transition; CLI and app Vox {version}");
        if self.daemon_was_running.is_some() {
            print!("; app handoff recorded complete");
        }
        match self.daemon_was_running {
            Some(true) => print!("; daemon handoff recorded complete"),
            Some(false) => print!("; daemon was not required by captured startup intent"),
            None => {}
        }
        if self.retired_removed > 0 {
            print!(
                " removed {} retired bundle(s) no process still used;",
                self.retired_removed
            );
        }
        println!();
        Ok(())
    }
}

fn verified_release_zip(path: &Path, record: &Validated) -> Result<fs::File, AppError> {
    use std::io::{Seek as _, SeekFrom};
    use std::os::unix::fs::MetadataExt as _;
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| usage(format!("cannot inspect {}: {e}", path.display())))?;
    let mut file =
        fs::File::open(path).map_err(|e| usage(format!("cannot open {}: {e}", path.display())))?;
    let opened = file.metadata().map_err(AppError::Io)?;
    if !metadata.is_file()
        || !opened.is_file()
        || metadata.dev() != opened.dev()
        || metadata.ino() != opened.ino()
        || opened.len() != record.size
    {
        return Err(usage(format!(
            "app archive {} does not match the release record",
            path.display()
        )));
    }
    let parent = path
        .parent()
        .ok_or_else(|| usage("supplied app archive has no directory"))?;
    let directory = fs::symlink_metadata(parent).map_err(AppError::Io)?;
    let uid = rustix::process::getuid().as_raw();
    if !directory.is_dir()
        || directory.uid() != uid
        || directory.mode() & 0o077 != 0
        || opened.uid() != uid
        || opened.mode() & 0o077 != 0
    {
        return Err(usage(
            "supplied app archive is not in an owned private directory",
        ));
    }
    let (size, digest) = hash_open_file(&mut file, Some(record.size))?;
    if size != record.size || digest != record.sha256 {
        return Err(usage(format!(
            "app archive {} does not match the release record",
            path.display()
        )));
    }
    file.seek(SeekFrom::Start(0)).map_err(AppError::Io)?;
    Ok(file)
}

/// Unpack the downloaded zip beside the bundle, on its filesystem, and return the one Vox.app
/// it held, moved to `.Vox.app.partial`.
fn unpack(
    apps: &Path,
    zip: &Path,
    file: fs::File,
    transition: &mut Transition,
) -> Result<PathBuf, AppError> {
    let unpacked = apps.join(UNPACK_PARTIAL);
    let preparation = transition
        .candidate_preparation
        .as_ref()
        .ok_or_else(|| usage("missing candidate preparation authority"))?;
    if !preparation.directory.matches(&bundle_identity(&unpacked)?) {
        return Err(usage("candidate preparation directory identity changed"));
    }
    let out = Command::new("/usr/bin/ditto")
        .args(["-x", "-k", "-"])
        .stdin(std::process::Stdio::from(file))
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
        return Err(usage(format!(
            "cannot unpack {}: {}",
            zip.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
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
        return Err(usage(format!(
            "the downloaded zip holds {entries:?}, not exactly {BUNDLE}"
        )));
    }
    stage_candidate(apps, &bundle, transition)
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

/// Authenticated local rollback authority, without a fresh online notarization claim.
#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ArchiveAuthority {
    size: u64,
    sha256: [u8; 32],
    version: String,
    fixture_identity: bool,
    bundle_team: String,
    bundle_identifier: String,
    helper_team: String,
    helper_identifier: String,
    root_name: Vec<u8>,
}

fn read_archive_record(path: &Path) -> Result<ArchiveAuthority, AppError> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = fs::symlink_metadata(path).map_err(AppError::Io)?;
    let file = fs::File::open(path).map_err(AppError::Io)?;
    let opened = file.metadata().map_err(AppError::Io)?;
    if !metadata.is_file()
        || !opened.is_file()
        || metadata.dev() != opened.dev()
        || metadata.ino() != opened.ino()
        || opened.len() > 65536
        || opened.uid() != rustix::process::getuid().as_raw()
        || opened.mode() & 0o077 != 0
    {
        return Err(usage(format!(
            "invalid private rollback authority at {}",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.take(65537)
        .read_to_end(&mut bytes)
        .map_err(AppError::Io)?;
    if bytes.len() > 65536 {
        return Err(usage(format!(
            "rollback authority {} exceeds its size bound",
            path.display()
        )));
    }
    serde_json::from_slice(&bytes).map_err(|e| {
        usage(format!(
            "invalid rollback authority {}: {e}",
            path.display()
        ))
    })
}

fn read_rollback_authority(apps: &Path) -> Result<Option<ArchiveAuthority>, AppError> {
    let record = apps.join(ROLLBACK_AUTHORITY);
    let archive = apps.join(ROLLBACK_ARCHIVE);
    let exists = (path_exists(&record)?, path_exists(&archive)?);
    if exists == (false, false) {
        return Ok(None);
    }
    if exists != (true, true) {
        return Err(usage(
            "incomplete rollback archive authority; all files retained",
        ));
    }
    let authority = read_archive_record(&record)?;
    if !archive_matches(&archive, &authority)? {
        return Err(usage(format!(
            "rollback archive {} does not match its authority",
            archive.display()
        )));
    }
    Ok(Some(authority))
}

fn move_durable(from: &Path, to: &Path) -> Result<(), AppError> {
    if path_exists(to)? {
        return Err(usage(format!("refusing to overwrite {}", to.display())));
    }
    fs::rename(from, to).map_err(|e| {
        usage(format!(
            "cannot rename {} to {}: {e}",
            from.display(),
            to.display()
        ))
    })?;
    if let Some(parent) = from.parent() {
        sync_dir(parent)?;
    }
    if let Some(parent) = to.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

fn write_archive_record(path: &Path, authority: &ArchiveAuthority) -> Result<(), AppError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let bytes = serde_json::to_vec(authority)
        .map_err(|e| usage(format!("cannot encode rollback authority: {e}")))?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| usage(format!("cannot create {}: {e}", path.display())))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| usage(format!("cannot write and sync {}: {e}", path.display())))
}

fn promote_archive(apps: &Path, archive: &ArchiveTransition) -> Result<(), AppError> {
    let journal = apps.join(PUBLISHING);
    let final_archive = apps.join(ROLLBACK_ARCHIVE);
    let final_record = apps.join(ROLLBACK_AUTHORITY);
    if read_rollback_authority(apps)? != archive.previous_archive {
        return Err(usage(
            "previous rollback authority changed before promotion; all files retained",
        ));
    }
    if !archive_matches(&journal.join(SOURCE_ARCHIVE), &archive.source_archive)? {
        return Err(usage(
            "source archive changed before promotion; all files retained",
        ));
    }
    if archive.previous_archive.is_some() {
        move_durable(&final_archive, &journal.join(PRIOR_ARCHIVE))?;
        move_durable(&final_record, &journal.join(PRIOR_AUTHORITY))?;
    } else if path_exists(&final_archive)? || path_exists(&final_record)? {
        return Err(usage(
            "unexpected rollback authority appeared; retaining all files",
        ));
    }
    let new_record = journal.join("source.json");
    if path_exists(&new_record)? {
        let recorded = read_archive_record(&new_record)?;
        if recorded != archive.source_archive {
            return Err(usage("staged rollback record does not match journal"));
        }
    } else {
        write_archive_record(&new_record, &archive.source_archive)?;
    }
    sync_dir(&journal)?;
    move_durable(&journal.join(SOURCE_ARCHIVE), &final_archive)?;
    move_durable(&new_record, &final_record)
}

fn archive_matches(path: &Path, authority: &ArchiveAuthority) -> Result<bool, AppError> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = fs::symlink_metadata(path).map_err(AppError::Io)?;
    if !meta.is_file() || meta.len() != authority.size {
        return Ok(false);
    }
    let mut file = fs::File::open(path).map_err(AppError::Io)?;
    let opened = file.metadata().map_err(AppError::Io)?;
    if !opened.is_file()
        || opened.dev() != meta.dev()
        || opened.ino() != meta.ino()
        || opened.len() != authority.size
    {
        return Ok(false);
    }
    let (size, digest) = hash_open_file(&mut file, Some(authority.size))?;
    Ok(size == authority.size && digest == authority.sha256)
}

fn restore_previous_authority(apps: &Path, archive: &ArchiveTransition) -> Result<(), AppError> {
    let journal = apps.join(PUBLISHING);
    let final_zip = apps.join(ROLLBACK_ARCHIVE);
    let final_record = apps.join(ROLLBACK_AUTHORITY);
    let source_zip = journal.join(SOURCE_ARCHIVE);
    let source_record = journal.join("source.json");
    let prior_zip = journal.join(PRIOR_ARCHIVE);
    let prior_record = journal.join(PRIOR_AUTHORITY);
    if path_exists(&final_zip)? {
        if archive_matches(&final_zip, &archive.source_archive)? && !path_exists(&source_zip)? {
            move_durable(&final_zip, &source_zip)?;
        } else if match archive.previous_archive.as_ref() {
            Some(previous) => !archive_matches(&final_zip, previous)?,
            None => true,
        } {
            return Err(usage(
                "rollback archive identity is ambiguous; all files retained",
            ));
        }
    }
    if path_exists(&final_record)? {
        let record = read_archive_record(&final_record)?;
        if record == archive.source_archive && !path_exists(&source_record)? {
            move_durable(&final_record, &source_record)?;
        } else if archive.previous_archive.as_ref() != Some(&record) {
            return Err(usage(
                "rollback record identity is ambiguous; all files retained",
            ));
        }
    }
    if let Some(previous) = &archive.previous_archive {
        if path_exists(&prior_zip)? {
            if !archive_matches(&prior_zip, previous)? {
                return Err(usage("saved prior archive does not match journal"));
            }
            move_durable(&prior_zip, &final_zip)?;
        }
        if path_exists(&prior_record)? {
            let record = read_archive_record(&prior_record)?;
            if &record != previous {
                return Err(usage("saved prior rollback record does not match journal"));
            }
            move_durable(&prior_record, &final_record)?;
        }
        if read_rollback_authority(apps)?.as_ref() != Some(previous) {
            return Err(usage("prior rollback authority could not be restored"));
        }
    } else if path_exists(&final_zip)? || path_exists(&final_record)? {
        return Err(usage(
            "unexpected rollback authority retained during restoration",
        ));
    }
    Ok(())
}

fn restore_source_filesystem(apps: &Path, transition: &mut Transition) -> Result<(), AppError> {
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    let active = apps.join(BUNDLE);
    let staged = apps.join(PARTIAL);
    let journal = apps.join(PUBLISHING);
    let current = bundle_identity(&active)?;
    let archive = transition
        .archive
        .as_mut()
        .ok_or_else(|| usage("missing archive transaction authority"))?;
    archive.phase = FilesystemPhase::Restoring;
    write_transition(apps, transition)?;
    let archive = transition
        .archive
        .as_ref()
        .ok_or_else(|| usage("missing archive transaction authority"))?;
    restore_previous_authority(apps, archive)?;
    let is_restored = saved_matches(archive.restoration.as_ref(), &current);
    if !transition.source.matches(&current) && !is_restored {
        if !transition.target.matches(&current) {
            return Err(usage(
                "active bundle identity is ambiguous; all recovery authority retained",
            ));
        }
        let saved = archive
            .restoration_path
            .as_ref()
            .map(|bytes| PathBuf::from(std::ffi::OsString::from_vec(bytes.clone())));
        let existing = match saved {
            Some(path) => {
                let parent = path
                    .parent()
                    .ok_or_else(|| usage("invalid restoration path"))?;
                if path_exists(parent)? {
                    if !saved_matches(
                        archive.restoration_directory.as_ref(),
                        &bundle_identity(parent)?,
                    ) {
                        return Err(usage(
                            "restoration directory identity changed; all files retained",
                        ));
                    }
                    if archive.restoration.is_some() && path_exists(&path)? {
                        if !saved_matches(archive.restoration.as_ref(), &bundle_identity(&path)?) {
                            return Err(usage(
                                "restoration staging identity changed; all files retained",
                            ));
                        }
                        verify_local_bundle(&path, &archive.source_archive)?;
                        Some(path)
                    } else {
                        if path_exists(&path)? {
                            launch_services(false, &path).map_err(usage)?;
                        }
                        vox_sockdrops::remove_item(parent).map_err(|e| {
                            usage(format!(
                                "cannot clear interrupted replacement directory {}: {e}",
                                parent.display()
                            ))
                        })?;
                        None
                    }
                } else {
                    None
                }
            }
            None => None,
        };
        let restore_path = if let Some(path) = existing {
            path
        } else {
            let directory = replacement_directory(&active)?;
            let directory_identity = bundle_identity(&directory)?;
            let name = std::ffi::OsString::from_vec(archive.source_archive.root_name.clone());
            let root = Path::new(&name);
            if root.components().count() != 1
                || !matches!(
                    root.components().next(),
                    Some(std::path::Component::Normal(_))
                )
            {
                return Err(usage("invalid rollback archive root name"));
            }
            let path = directory.join(name);
            let archive = transition
                .archive
                .as_mut()
                .ok_or_else(|| usage("missing archive transaction authority"))?;
            archive.restoration = None;
            archive.restoration_directory = Some(directory_identity);
            archive.restoration_path = Some(path.as_os_str().as_bytes().to_vec());
            write_transition(apps, transition)?;
            let archive = transition
                .archive
                .as_ref()
                .ok_or_else(|| usage("missing archive transaction authority"))?;
            let extracted = extract_archive(
                &journal.join(SOURCE_ARCHIVE),
                &archive.source_archive,
                &directory,
            )?;
            if extracted != path {
                return Err(usage("restoration extracted an unexpected path"));
            }
            let identity = bundle_identity(&path)?;
            let archive = transition
                .archive
                .as_mut()
                .ok_or_else(|| usage("missing archive transaction authority"))?;
            archive.restoration = Some(identity);
            write_transition(apps, transition)?;
            path
        };
        if !transition.target.matches(&bundle_identity(&active)?) {
            return Err(usage("active bundle changed before restoration exchange"));
        }
        swap(&restore_path, &active)?;
        sync_dir(apps)?;
    }
    let archive = transition
        .archive
        .as_ref()
        .ok_or_else(|| usage("missing archive transaction authority"))?;
    let current = bundle_identity(&active)?;
    if !transition.source.matches(&current)
        && !saved_matches(archive.restoration.as_ref(), &current)
    {
        return Err(usage("restored bundle identity does not match journal"));
    }
    verify_local_bundle(&active, &archive.source_archive)?;
    if let Some(bytes) = &archive.restoration_path {
        let path = PathBuf::from(std::ffi::OsString::from_vec(bytes.clone()));
        if let Some(parent) = path.parent() {
            if path_exists(parent)? {
                if !saved_matches(
                    archive.restoration_directory.as_ref(),
                    &bundle_identity(parent)?,
                ) {
                    return Err(usage(
                        "restoration directory identity changed; all files retained",
                    ));
                }
                if path_exists(&path)? {
                    let identity = bundle_identity(&path)?;
                    if !transition.target.matches(&identity)
                        && !saved_matches(archive.restoration.as_ref(), &identity)
                    {
                        return Err(usage(
                            "restoration staging bundle identity changed; all files retained",
                        ));
                    }
                    launch_services(false, &path).map_err(usage)?;
                    vox_sockdrops::remove_item(&path).map_err(|e| {
                        usage(format!(
                            "cannot remove rejected bundle {}: {e}",
                            path.display()
                        ))
                    })?;
                }
                vox_sockdrops::remove_item(parent).map_err(|e| {
                    usage(format!(
                        "cannot remove replacement directory {}: {e}",
                        parent.display()
                    ))
                })?;
            }
        }
    }
    if path_exists(&staged)? {
        let identity = bundle_identity(&staged)?;
        if !transition.source.matches(&identity) && !transition.target.matches(&identity) {
            return Err(usage("staged bundle identity changed; all files retained"));
        }
        launch_services(false, &staged).map_err(usage)?;
        vox_sockdrops::remove_item(&staged).map_err(|e| {
            usage(format!(
                "cannot remove displaced bundle {}: {e}",
                staged.display()
            ))
        })?;
    }
    Ok(())
}

fn clear_legacy_preparation(apps: &Path, transition: &mut Transition) -> Result<(), AppError> {
    use std::os::unix::ffi::OsStringExt as _;
    if transition.archive.is_some() {
        return Err(usage(
            "cannot discard a committed legacy archive preparation",
        ));
    }
    let work = apps.join(PUBLISHING).join("legacy-work");
    if let Some(preparation) = &transition.legacy_preparation {
        match (
            &preparation.verification_directory,
            &preparation.verification_path,
        ) {
            (None, None) => {}
            (Some(identity), Some(bytes)) => {
                let path = PathBuf::from(std::ffi::OsString::from_vec(bytes.clone()));
                let parent = path
                    .parent()
                    .ok_or_else(|| usage("invalid legacy verification path"))?;
                if !path.is_absolute() || path.file_name() != Some(std::ffi::OsStr::new(BUNDLE)) {
                    return Err(usage(
                        "invalid legacy verification path; all files retained",
                    ));
                }
                if path_exists(parent)? {
                    if !identity.matches(&bundle_identity(parent)?) {
                        return Err(usage(
                            "legacy verification directory identity changed; all files retained",
                        ));
                    }
                    if path_exists(&path)? {
                        bundle_identity(&path)?;
                        launch_services(false, &path).map_err(usage)?;
                    }
                    vox_sockdrops::remove_item(parent).map_err(|e| {
                        usage(format!(
                            "cannot remove legacy verification directory {}: {e}",
                            parent.display()
                        ))
                    })?;
                }
            }
            _ => {
                return Err(usage(
                    "incomplete legacy verification authority; all files retained",
                ))
            }
        }
        if path_exists(&work)? {
            if !preparation.directory.matches(&bundle_identity(&work)?) {
                return Err(usage(
                    "legacy staging directory identity changed; all files retained",
                ));
            }
            let copy = work.join("copy").join(BUNDLE);
            if path_exists(&copy)? {
                bundle_identity(&copy)?;
                launch_services(false, &copy).map_err(usage)?;
            }
            vox_sockdrops::remove_item(&work).map_err(|e| {
                usage(format!(
                    "cannot remove legacy staging directory {}: {e}",
                    work.display()
                ))
            })?;
        }
        transition.legacy_preparation = None;
        write_transition(apps, transition)?;
    } else if path_exists(&work)? {
        fs::remove_dir(&work).map_err(|e| {
            usage(format!(
                "unrecorded nonempty legacy staging {} retained: {e}",
                work.display()
            ))
        })?;
    }
    Ok(())
}

fn archive_legacy_bundle(
    apps: &Path,
    original: &Path,
    destination: &Path,
    transition: &mut Transition,
) -> Result<ArchiveAuthority, AppError> {
    use std::os::unix::ffi::OsStrExt as _;
    let copy_dir = apps.join(PUBLISHING).join("legacy-work").join("copy");
    if path_exists(&copy_dir)? || path_exists(destination)? {
        return Err(usage(
            "incomplete legacy archive staging retained; refusing to guess its authority",
        ));
    }
    fs::create_dir(&copy_dir)
        .map_err(|e| usage(format!("cannot create {}: {e}", copy_dir.display())))?;
    let copy = copy_dir.join(BUNDLE);
    let output = Command::new("/usr/bin/ditto")
        .arg(original)
        .arg(&copy)
        .output()
        .map_err(|e| {
            usage(format!(
                "cannot copy legacy bundle {}: {e}",
                original.display()
            ))
        })?;
    if !output.status.success() {
        return Err(usage(format!(
            "cannot copy legacy bundle {}: {}",
            original.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let plist = copy.join(INFO_PLIST);
    let kept = copy.join(KEPT_INFO_PLIST);
    match (path_exists(&plist)?, path_exists(&kept)?) {
        (true, false) => {}
        (false, true) if fs::symlink_metadata(&kept).map_err(AppError::Io)?.is_file() => {
            fs::rename(&kept, &plist).map_err(|e| {
                usage(format!(
                    "cannot reconstruct private copy {}: {e}",
                    copy.display()
                ))
            })?;
        }
        _ => {
            return Err(usage(format!(
                "ambiguous legacy plist layout at {}; original retained",
                original.display()
            )))
        }
    }
    let fixture = !apple_required();
    let active = apps.join(BUNDLE);
    for (old, installed) in [(&copy, &active), (&copy.join(HELPER), &active.join(HELPER))] {
        let old_identity = local_signing_identity(old, fixture)?;
        let active_identity = local_signing_identity(installed, fixture)?;
        if old_identity.1 != active_identity.1 || (!fixture && old_identity.0 != active_identity.0)
        {
            return Err(usage(format!(
                "legacy signing identity does not match active installation at {}",
                original.display()
            )));
        }
    }
    let authority = archive_authority(&copy, destination)?;
    let replacement = replacement_directory(&active)?;
    let preparation = transition
        .legacy_preparation
        .as_mut()
        .ok_or_else(|| usage("missing legacy preparation authority"))?;
    preparation.verification_directory = Some(bundle_identity(&replacement)?);
    preparation.verification_path = Some(replacement.join(BUNDLE).as_os_str().as_bytes().to_vec());
    write_transition(apps, transition)?;
    let extracted = extract_archive(destination, &authority, &replacement)?;
    launch_services(false, &extracted).map_err(usage)?;
    vox_sockdrops::remove_item(&replacement).map_err(|e| {
        usage(format!(
            "cannot remove replacement directory {}: {e}",
            replacement.display()
        ))
    })?;
    let preparation = transition
        .legacy_preparation
        .as_mut()
        .ok_or_else(|| usage("missing legacy preparation authority"))?;
    preparation.verification_directory = None;
    preparation.verification_path = None;
    write_transition(apps, transition)?;
    launch_services(false, &copy).map_err(usage)?;
    vox_sockdrops::remove_item(&copy_dir).map_err(|e| {
        usage(format!(
            "cannot remove private legacy copy {}: {e}",
            copy_dir.display()
        ))
    })?;
    Ok(authority)
}

fn prepare_legacy_migration(apps: &Path, transition: &mut Transition) -> Result<(), AppError> {
    use std::os::unix::ffi::OsStrExt as _;
    let journal = apps.join(PUBLISHING);
    let active = apps.join(BUNDLE);
    if !transition.target.matches(&bundle_identity(&active)?) {
        return Err(usage(
            "legacy journal does not identify the active committed bundle; authority retained",
        ));
    }
    clear_legacy_preparation(apps, transition)?;
    let work = journal.join("legacy-work");
    fs::create_dir(&work).map_err(|e| usage(format!("cannot create {}: {e}", work.display())))?;
    transition.legacy_preparation = Some(LegacyPreparation {
        directory: bundle_identity(&work)?,
        verification_directory: None,
        verification_path: None,
    });
    write_transition(apps, transition)?;
    let possible = [
        apps.join(PREVIOUS),
        apps.join(PARTIAL),
        journal.join(BUNDLE),
    ];
    let mut source = None;
    for path in &possible {
        if path_exists(path)?
            && transition.source.matches(&bundle_identity(path)?)
            && source.replace(path.clone()).is_some()
        {
            return Err(usage(
                "multiple legacy bundles match the source identity; all retained",
            ));
        }
    }
    let source = source
        .ok_or_else(|| usage("legacy source bundle identity is unavailable; all retained"))?;
    for path in &possible[..2] {
        if path != &source && path_exists(path)? {
            return Err(usage(
                "ambiguous legacy retained bundle; all files retained",
            ));
        }
    }
    let superseded = journal.join(BUNDLE);
    let (legacy_superseded, legacy_superseded_identity) =
        if superseded != source && path_exists(&superseded)? {
            let identity = bundle_identity(&superseded)?;
            let authority = archive_legacy_bundle(
                apps,
                &superseded,
                &work.join("legacy-superseded.zip"),
                transition,
            )?;
            (Some(authority), Some(identity))
        } else {
            (None, None)
        };
    let source_archive =
        archive_legacy_bundle(apps, &source, &work.join(SOURCE_ARCHIVE), transition)?;
    let previous_archive = read_rollback_authority(apps)?;
    transition.archive = Some(ArchiveTransition {
        phase: FilesystemPhase::Retiring,
        legacy: true,
        legacy_path: Some(source.as_os_str().as_bytes().to_vec()),
        legacy_superseded,
        legacy_superseded_identity,
        source_archive,
        previous_archive,
        restoration: None,
        restoration_directory: None,
        restoration_path: None,
    });
    write_transition(apps, transition)
}

fn finish_legacy_staging(apps: &Path, transition: &mut Transition) -> Result<(), AppError> {
    let Some(preparation) = transition.legacy_preparation.as_ref() else {
        return Ok(());
    };
    if preparation.verification_directory.is_some() || preparation.verification_path.is_some() {
        return Err(usage(
            "legacy verification is incomplete; all authority retained",
        ));
    }
    let archive = transition
        .archive
        .as_ref()
        .ok_or_else(|| usage("missing legacy archive authority"))?;
    let journal = apps.join(PUBLISHING);
    let work = journal.join("legacy-work");
    if path_exists(&work)? && !preparation.directory.matches(&bundle_identity(&work)?) {
        return Err(usage(
            "legacy staging directory identity changed; all authority retained",
        ));
    }
    for (name, authority) in [
        (SOURCE_ARCHIVE, Some(&archive.source_archive)),
        ("legacy-superseded.zip", archive.legacy_superseded.as_ref()),
    ] {
        let Some(authority) = authority else {
            continue;
        };
        let staged = work.join(name);
        let destination = journal.join(name);
        if path_exists(&staged)? {
            if !archive_matches(&staged, authority)? {
                return Err(usage(format!(
                    "legacy staged archive {} changed",
                    staged.display()
                )));
            }
            move_durable(&staged, &destination)?;
        } else if path_exists(&destination)? {
            if !archive_matches(&destination, authority)? {
                return Err(usage(format!(
                    "legacy archive {} changed",
                    destination.display()
                )));
            }
        } else if name != SOURCE_ARCHIVE
            || !path_exists(&apps.join(ROLLBACK_ARCHIVE))?
            || !archive_matches(&apps.join(ROLLBACK_ARCHIVE), authority)?
        {
            return Err(usage(format!(
                "legacy archive {name} is missing; all authority retained"
            )));
        }
    }
    if path_exists(&work)? {
        fs::remove_dir(&work).map_err(|e| {
            usage(format!(
                "legacy staging {} is not empty: {e}",
                work.display()
            ))
        })?;
        sync_dir(&journal)?;
    }
    transition.legacy_preparation = None;
    write_transition(apps, transition)
}

fn resume_legacy_migration(apps: &Path, transition: &mut Transition) -> Result<(), AppError> {
    use std::os::unix::ffi::OsStringExt as _;
    let journal = apps.join(PUBLISHING);
    if !transition
        .target
        .matches(&bundle_identity(&apps.join(BUNDLE))?)
    {
        return Err(usage(
            "legacy active bundle identity changed; all files retained",
        ));
    }
    finish_legacy_staging(apps, transition)?;
    let archive = transition
        .archive
        .as_ref()
        .ok_or_else(|| usage("missing legacy archive authority"))?;
    if !archive.legacy
        || !transition
            .target
            .matches(&bundle_identity(&apps.join(BUNDLE))?)
    {
        return Err(usage(
            "legacy active bundle identity changed; all files retained",
        ));
    }
    let path = PathBuf::from(std::ffi::OsString::from_vec(
        archive
            .legacy_path
            .clone()
            .ok_or_else(|| usage("missing legacy source path"))?,
    ));
    if path != apps.join(PREVIOUS) && path != apps.join(PARTIAL) && path != journal.join(BUNDLE) {
        return Err(usage("legacy source path is not journal-owned"));
    }
    let current = read_rollback_authority(apps);
    if !matches!(&current, Ok(Some(value)) if value == &archive.source_archive) {
        if let Err(e) = restore_previous_authority(apps, archive) {
            return Err(usage(format!(
                "legacy archive promotion could not be reconciled: {e}; prior inspection: {}",
                current
                    .err()
                    .map_or_else(|| "different authority".to_owned(), |e| e.to_string())
            )));
        }
        promote_archive(apps, archive)?;
    }
    if let Some(superseded) = &archive.legacy_superseded {
        let zip = journal.join("legacy-superseded.zip");
        if !archive_matches(&zip, superseded)? {
            return Err(usage(
                "superseded legacy archive does not match its authority",
            ));
        }
        let old = journal.join(BUNDLE);
        if path_exists(&old)? {
            if !saved_matches(
                archive.legacy_superseded_identity.as_ref(),
                &bundle_identity(&old)?,
            ) {
                return Err(usage(
                    "superseded legacy bundle identity changed; all retained",
                ));
            }
            launch_services(false, &old).map_err(usage)?;
            if !saved_matches(
                archive.legacy_superseded_identity.as_ref(),
                &bundle_identity(&old)?,
            ) {
                return Err(usage(
                    "superseded legacy bundle identity changed before retirement",
                ));
            }
            vox_sockdrops::remove_item(&old)
                .map_err(|e| usage(format!("cannot retire {}: {e}", old.display())))?;
        }
    }
    if path_exists(&path)? {
        if !transition.source.matches(&bundle_identity(&path)?) {
            return Err(usage("legacy source bundle identity changed; all retained"));
        }
        launch_services(false, &path).map_err(usage)?;
        if !transition.source.matches(&bundle_identity(&path)?) {
            return Err(usage(
                "legacy source bundle identity changed before retirement",
            ));
        }
        vox_sockdrops::remove_item(&path)
            .map_err(|e| usage(format!("cannot retire {}: {e}", path.display())))?;
    }
    sync_dir(apps)?;
    transition
        .archive
        .as_mut()
        .ok_or_else(|| usage("missing legacy archive authority"))?
        .phase = FilesystemPhase::FilesystemCommitted;
    write_transition(apps, transition)
}

fn local_signing_identity(path: &Path, fixture: bool) -> Result<(String, String), AppError> {
    if !fixture {
        let identity = signing_identity(path)?;
        return Ok((identity.team_id, identity.identifier));
    }
    if apple_required() {
        return Err(usage(
            "fixture-only rollback authority cannot be used with Apple trust required",
        ));
    }
    let output = Command::new("/usr/bin/codesign")
        .args(["--display", "--verbose=4"])
        .arg(path)
        .output()
        .map_err(AppError::Io)?;
    if !output.status.success()
        || output.stderr.len() > super::MAX_SIGNING_INFO_BYTES
        || !output.stdout.is_empty()
    {
        return Err(usage(format!(
            "cannot read fixture signing identity at {}",
            path.display()
        )));
    }
    let report = std::str::from_utf8(&output.stderr)
        .map_err(|_| usage("fixture signing identity is not UTF-8"))?;
    let hash = super::unique_value(report, "CDHash=")?;
    let identifier = super::unique_value(report, "Identifier=")?;
    if hash.is_empty()
        || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        || identifier.is_empty()
    {
        return Err(usage("fixture signing identity is invalid"));
    }
    Ok((hash.to_owned(), identifier.to_owned()))
}

fn check_local_helper_version(helper: &Path, version: &str) -> Result<bool, AppError> {
    let probe = tempfile::tempdir().map_err(AppError::Io)?;
    let output = Command::new(helper)
        .arg("--version")
        .env_clear()
        .env("VOX_DATA_DIR", probe.path().join("data"))
        .env("VOX_CONFIG_DIR", probe.path().join("config"))
        .output()
        .map_err(|e| usage(format!("cannot inspect helper {}: {e}", helper.display())))?;
    Ok(output.status.success()
        && output.stdout.len() <= MAX_VERSION_OUTPUT_BYTES
        && output.stdout == format!("vox {version}\n").as_bytes())
}

fn verify_local_bundle(bundle: &Path, authority: &ArchiveAuthority) -> Result<(), AppError> {
    let strict = ["--verify", "--strict", "--deep", "--all-architectures"];
    let helper = bundle.join(HELPER);
    for (path, team, identifier) in [
        (bundle, &authority.bundle_team, &authority.bundle_identifier),
        (
            helper.as_path(),
            &authority.helper_team,
            &authority.helper_identifier,
        ),
    ] {
        codesign_ok(path, &strict, "retained local signature does not verify")?;
        let identity = local_signing_identity(path, authority.fixture_identity)?;
        if &identity.0 != team || &identity.1 != identifier {
            return Err(usage(format!(
                "retained signing identity changed at {}",
                path.display()
            )));
        }
    }
    if app_version(bundle).as_deref() != Some(authority.version.as_str())
        || !check_local_helper_version(&helper, &authority.version)?
    {
        return Err(usage(format!(
            "retained app or helper version does not match {}",
            bundle.display()
        )));
    }
    Ok(())
}

fn archive_authority(bundle: &Path, archive: &Path) -> Result<ArchiveAuthority, AppError> {
    use std::os::unix::ffi::OsStrExt as _;
    let version = app_version(bundle)
        .ok_or_else(|| usage(format!("cannot identify {}", bundle.display())))?;
    semver::Version::parse(&version).map_err(|_| usage("retained bundle version is invalid"))?;
    let strict = ["--verify", "--strict", "--deep", "--all-architectures"];
    codesign_ok(
        bundle,
        &strict,
        "source application signature does not verify",
    )?;
    let helper = bundle.join(HELPER);
    codesign_ok(&helper, &strict, "source helper signature does not verify")?;
    let fixture_identity = !apple_required();
    let app_identity = local_signing_identity(bundle, fixture_identity)?;
    let helper_identity = local_signing_identity(&helper, fixture_identity)?;
    if !check_local_helper_version(&helper, &version)? {
        return Err(usage("source application and helper versions differ"));
    }
    let root_name = bundle
        .file_name()
        .ok_or_else(|| usage("source bundle has no name"))?
        .as_bytes()
        .to_vec();
    let output = Command::new("/usr/bin/ditto")
        .args(["-c", "-k", "--sequesterRsrc", "--keepParent"])
        .arg(bundle)
        .arg(archive)
        .output()
        .map_err(|e| {
            usage(format!(
                "cannot archive {} to {}: {e}",
                bundle.display(),
                archive.display()
            ))
        })?;
    if !output.status.success() {
        return Err(usage(format!(
            "cannot archive {} to {}: {}",
            bundle.display(),
            archive.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let file = fs::File::open(archive)
        .map_err(|e| usage(format!("cannot open {}: {e}", archive.display())))?;
    file.sync_all()
        .map_err(|e| usage(format!("cannot sync {}: {e}", archive.display())))?;
    let size = file.metadata().map_err(AppError::Io)?.len();
    Ok(ArchiveAuthority {
        size,
        sha256: sha256_of(archive)?,
        version,
        fixture_identity,
        bundle_team: app_identity.0,
        bundle_identifier: app_identity.1,
        helper_team: helper_identity.0,
        helper_identifier: helper_identity.1,
        root_name,
    })
}

fn extract_archive(
    archive: &Path,
    authority: &ArchiveAuthority,
    destination: &Path,
) -> Result<PathBuf, AppError> {
    use std::io::{Seek as _, SeekFrom};
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::MetadataExt as _;
    let meta = fs::symlink_metadata(archive)
        .map_err(|e| usage(format!("cannot inspect {}: {e}", archive.display())))?;
    let mut file = fs::File::open(archive)
        .map_err(|e| usage(format!("cannot open {}: {e}", archive.display())))?;
    let opened = file.metadata().map_err(AppError::Io)?;
    if !meta.is_file()
        || !opened.is_file()
        || meta.dev() != opened.dev()
        || meta.ino() != opened.ino()
        || opened.len() != authority.size
    {
        return Err(usage(format!(
            "rollback archive {} does not match its authority",
            archive.display()
        )));
    }
    let (size, digest) = hash_open_file(&mut file, Some(authority.size))?;
    if size != authority.size || digest != authority.sha256 {
        return Err(usage(format!(
            "rollback archive {} does not match its authority",
            archive.display()
        )));
    }
    file.seek(SeekFrom::Start(0)).map_err(AppError::Io)?;
    let name = std::ffi::OsString::from_vec(authority.root_name.clone());
    let relative = Path::new(&name);
    if relative.components().count() != 1
        || !matches!(
            relative.components().next(),
            Some(std::path::Component::Normal(_))
        )
    {
        return Err(usage("invalid rollback archive root name"));
    }
    let output = Command::new("/usr/bin/ditto")
        .args(["-x", "-k", "-"])
        .arg(destination)
        .stdin(std::process::Stdio::from(file))
        .output()
        .map_err(|e| usage(format!("cannot extract {}: {e}", archive.display())))?;
    if !output.status.success() {
        return Err(usage(format!(
            "cannot extract {}: {}",
            archive.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let mut entries = fs::read_dir(destination).map_err(AppError::Io)?;
    let entry = entries
        .next()
        .transpose()
        .map_err(AppError::Io)?
        .ok_or_else(|| usage("rollback archive is empty"))?;
    if entry.file_name() != name || entries.next().transpose().map_err(AppError::Io)?.is_some() {
        return Err(usage("rollback archive has unexpected top-level entries"));
    }
    let bundle = destination.join(name);
    bundle_identity(&bundle)?;
    verify_local_bundle(&bundle, authority)?;
    Ok(bundle)
}

fn sha256_of(path: &Path) -> Result<[u8; 32], AppError> {
    let mut file =
        fs::File::open(path).map_err(|e| usage(format!("cannot open {}: {e}", path.display())))?;
    hash_open_file(&mut file, None).map(|(_, digest)| digest)
}

fn hash_open_file(file: &mut fs::File, maximum: Option<u64>) -> Result<(u64, [u8; 32]), AppError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; IO_BUFFER_BYTES];
    let mut size = 0_u64;
    loop {
        let read = file.read(&mut buffer).map_err(AppError::Io)?;
        if read == 0 {
            return Ok((size, hasher.finalize().into()));
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| usage("archive byte count overflow"))?;
        if maximum.is_some_and(|maximum| size > maximum) {
            return Err(usage("archive exceeds its recorded size"));
        }
        hasher.update(&buffer[..read]);
    }
}

/// Remove owned scratch without modifying its contents or permissions.
fn clear(path: &Path) -> Result<(), AppError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(usage(format!("cannot inspect {}: {e}", path.display()))),
    };
    if meta.is_dir() {
        vox_sockdrops::remove_item(path)
            .map_err(|e| usage(format!("cannot remove {}: {e}", path.display())))
    } else {
        fs::remove_file(path).map_err(|e| usage(format!("cannot remove {}: {e}", path.display())))
    }
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
        let _detached =
            super::restart::restart_daemon_checked(account, &active.join(HELPER), now, intent)
                .map_err(|e| {
                    usage(format!(
                        "{} is in place, but the daemon restart failed: {e}",
                        active.display()
                    ))
                })?;

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
    app_handoff("wait", active, Some(&app.identity)).map_err(|e| {
        usage(format!(
            "{} is installed, but its relaunch was not confirmed: {e}",
            active.display()
        ))
    })?;
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

fn restore_source_and_handoff(
    apps: &Path,
    stopped: &Option<StoppedApp>,
    transition: &mut Transition,
) -> Result<(), AppError> {
    use std::os::unix::ffi::OsStringExt as _;
    let filesystem = restore_source_filesystem(apps, transition);
    let active = apps.join(BUNDLE);
    let archive = transition
        .archive
        .as_ref()
        .ok_or_else(|| usage("missing archive transaction authority"))?;
    let identity = bundle_identity(&active)?;
    if !transition.source.matches(&identity)
        && !saved_matches(archive.restoration.as_ref(), &identity)
    {
        return Err(usage(format!(
            "source restoration failed: {}",
            filesystem
                .err()
                .map_or_else(|| "identity mismatch".into(), |e| e.to_string())
        )));
    }
    verify_local_bundle(&active, &archive.source_archive)?;
    launch_services(true, &active).map_err(usage)?;
    let version = archive.source_archive.version.clone();
    let account = vox_core::node::paths::Account {
        data_root: PathBuf::from(std::ffi::OsString::from_vec(
            transition.daemon_data_root.clone(),
        )),
        config_dir: PathBuf::from(std::ffi::OsString::from_vec(
            transition.daemon_config_dir.clone(),
        )),
    };
    if !transition.daemon_complete {
        super::restart::restart_daemon_checked(
            &account,
            &active.join(HELPER),
            &version,
            Some(&transition.daemon),
        )?;
        transition.daemon_complete = true;
        write_transition(apps, transition)?;
    }
    if !transition.app_complete {
        reconcile_app_handoff(&active, stopped, false)?;
        transition.app_complete = true;
        write_transition(apps, transition)?;
    }
    transition_handoff(apps, &active, &version, stopped, transition)?;
    filesystem?;
    finish_journal(apps)
}

/// Report the original failure, restoring only before the filesystem commit boundary.
fn transition_failed_journal(
    apps: &Path,
    stopped: &Option<StoppedApp>,
    transition: &mut Transition,
    error: AppError,
) -> AppError {
    if transition.archive.as_ref().is_some_and(|archive| {
        matches!(
            archive.phase,
            FilesystemPhase::FilesystemCommitted | FilesystemPhase::HandingOff
        )
    }) {
        return usage(format!("{error}; filesystem commit may have completed; retained journal for handoff, no automatic downgrade"));
    }
    match restore_source_and_handoff(apps, stopped, transition) {
        Ok(()) => usage(format!("{error}; previous installation and startup intent restored")),
        Err(restoration) => usage(format!("{error}; automatic source restoration incomplete: {restoration}; recovery authority retained")),
    }
}

/// Refresh completions and the agent skill pack through the path the person ran, when that is
/// the link outside the bundle; the rc block records that directory, never one inside the bundle.
/// Run from inside the bundle, only the skill pack is refreshed.
fn shell_setup_from(apps: &Path, exe: &Path) -> Result<(), AppError> {
    let inside = exe
        .parent()
        .and_then(|dir| fs::canonicalize(dir).ok())
        .is_some_and(|dir| dir.starts_with(apps));
    if inside {
        super::run_skill_install(exe)
    } else {
        run_shell_setup(exe)
    }
}
