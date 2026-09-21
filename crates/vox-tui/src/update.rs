//! `vox update` — self-update from GitHub Releases (ADR-015 §"Install and update").
//!
//! Modelled on `hf2q`'s standalone updater (`src/distribution/standalone{,/update}.rs`), which
//! is the reference implementation in this account. The shape is deliberately the same:
//!
//! 1. Fetch one small **release record** and parse it as strict schema-1 JSON.
//! 2. Compare versions as SemVer, not as text.
//! 3. Stream the asset from the exact tag the record named, hashing as the bytes arrive and
//!    aborting the moment they exceed the size the record promised.
//! 4. **Authenticate the bytes through Apple trust before publishing them**, and require the
//!    candidate to carry the *same Developer ID as the binary it would replace*.
//! 5. Publish under a lock: one candidate, one retained previous, an atomic rename.
//!
//! ## Two deliberate divergences from hf2q
//!
//! **The record is on GitHub, not a vanity domain.** hf2q pins an exact URL and uses
//! `redirect::Policy::none()`, so "the response came from where I asked" is a string equality.
//! vox is GitHub-only by decision, and `releases/latest/download/<name>` *is* a redirect chain,
//! so vox must follow redirects and check the final origin instead. Strictly weaker, and the
//! reason the origin allow-list below is load-bearing rather than belt-and-braces.
//!
//! **vox ships Linux.** hf2q is Apple-Silicon-only and refuses to update anywhere else, so
//! every release it installs is Apple-authenticated. vox cannot do that on Linux: there the
//! only things standing behind an update are TLS to GitHub and the digest in the record. That
//! asymmetry is real, is recorded in ADR-015, and is why a detached release signature stays on
//! the list — it would be what Linux gets instead of Gatekeeper.

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT_ENCODING, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::app::AppError;

/// The repository releases are published from.
const REPO: &str = "robertelee78/vox";

/// Record identity. A file that does not say exactly this is not a vox release record.
const RECORD_KIND: &str = "vox.standalone-release";
/// The record schema this binary understands.
const RECORD_SCHEMA: u32 = 1;
/// Marker identity.
const MARKER_KIND: &str = "vox.install-channel";
/// The marker schema this binary writes and understands.
const MARKER_SCHEMA: u32 = 1;
/// The channel an install follows unless its marker names another.
const DEFAULT_CHANNEL: &str = "stable";

/// The installed binary's file name inside the install directory.
const ACTIVE_NAME: &str = "vox";
/// The marker that says "this install is ours" and names the channel it follows.
const MARKER_NAME: &str = ".vox-standalone.json";
/// The binary this one replaced, kept for `--rollback`.
const PREVIOUS_NAME: &str = ".vox-previous";
/// Held for the whole publish, so two transitions cannot interleave.
const LOCK_NAME: &str = ".vox-standalone.lock";
/// One partial name per transition, so an interrupted download and an interrupted rollback can
/// never be mistaken for one another.
const CANDIDATE_PARTIAL: &str = ".vox-candidate.partial";
const PREVIOUS_PARTIAL: &str = ".vox-previous.partial";
const ROLLBACK_PARTIAL: &str = ".vox-rollback.partial";

const MAX_RECORD_BYTES: usize = 4 * 1024;
const MAX_MARKER_BYTES: usize = 4 * 1024;
const MAX_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const IO_BUFFER_BYTES: usize = 64 * 1024;
/// Only the macOS trust path reads a signature report, so this bound is macOS-only too.
#[cfg(target_os = "macos")]
const MAX_SIGNING_INFO_BYTES: usize = 64 * 1024;
const MAX_VERSION_OUTPUT_BYTES: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RECORD_TIMEOUT: Duration = Duration::from_secs(60);
const ASSET_TIMEOUT: Duration = Duration::from_secs(30 * 60);

fn usage(message: impl Into<String>) -> AppError {
    AppError::Usage(message.into())
}

// ---------------------------------------------------------------- the release record

/// `<channel>-<triple>.json`, as the release workflow writes it.
///
/// `deny_unknown_fields` is the point: a differently shaped JSON file — an error page, another
/// project's record, a future schema — is rejected rather than partially understood.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRecord {
    /// Record kind — MUST be `vox.standalone-release`.
    pub kind: String,
    /// Record schema — MUST be `1`.
    pub schema_version: u32,
    /// Package name — MUST be `vox`.
    pub package: String,
    /// Release channel — MUST be the channel that was asked for.
    pub channel: String,
    /// Target triple — MUST be the one this binary was built for.
    pub target: String,
    /// The released version, which also names the tag (`v<version>`).
    pub version: String,
    /// Exact byte length of the binary.
    pub size: u64,
    /// Lowercase hex SHA-256 of the binary.
    pub sha256: String,
}

/// A record that has been checked against what was asked for.
struct Validated {
    version: semver::Version,
    version_text: String,
    target: String,
    size: u64,
    sha256: [u8; 32],
}

impl ReleaseRecord {
    /// Parse and validate a record for `channel` and `target`.
    ///
    /// # Errors
    /// [`AppError::Usage`] if the bytes are not strict schema-1 JSON, if the record's identity
    /// is not `vox`/`channel`/`target`, or if any field is not canonical.
    fn validate(bytes: &[u8], channel: &str, target: &str) -> Result<Validated, AppError> {
        if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
            return Err(usage("release record size is outside the supported bound"));
        }
        let record: Self = serde_json::from_slice(bytes)
            .map_err(|_| usage("release record is not strict schema-1 JSON"))?;
        if record.kind != RECORD_KIND
            || record.schema_version != RECORD_SCHEMA
            || record.package != "vox"
            || record.channel != channel
            || record.target != target
        {
            return Err(usage(format!(
                "release record identity does not match vox/{channel}/{target}"
            )));
        }
        let version = semver::Version::parse(&record.version)
            .map_err(|_| usage("release record version is not SemVer"))?;
        if record.size == 0 || record.size > MAX_BINARY_BYTES {
            return Err(usage("release record size is outside the supported bound"));
        }
        let mut sha256 = [0_u8; 32];
        if record.sha256.len() != 64 {
            return Err(usage("release record sha256 is not 64 hex characters"));
        }
        for (slot, pair) in sha256.iter_mut().zip(record.sha256.as_bytes().chunks(2)) {
            let hex = core::str::from_utf8(pair)
                .map_err(|_| usage("release record sha256 is not hexadecimal"))?;
            if hex
                .bytes()
                .any(|b| !b.is_ascii_hexdigit() || b.is_ascii_uppercase())
            {
                return Err(usage("release record sha256 is not lowercase hexadecimal"));
            }
            *slot = u8::from_str_radix(hex, 16)
                .map_err(|_| usage("release record sha256 is not hexadecimal"))?;
        }
        Ok(Validated {
            version,
            version_text: record.version,
            target: record.target,
            size: record.size,
            sha256,
        })
    }
}

// ---------------------------------------------------------------- the install marker

/// `.vox-standalone.json`: proof the install is ours, and the channel it follows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    kind: String,
    schema_version: u32,
    package: String,
    channel: String,
}

impl Marker {
    fn read(path: &Path) -> Result<Self, AppError> {
        let bytes = fs::read(path).map_err(AppError::Io)?;
        if bytes.is_empty() || bytes.len() > MAX_MARKER_BYTES {
            return Err(usage("install marker size is outside the supported bound"));
        }
        let marker: Self = serde_json::from_slice(&bytes)
            .map_err(|_| usage("install marker is not strict schema-1 JSON"))?;
        if marker.kind != MARKER_KIND
            || marker.schema_version != MARKER_SCHEMA
            || marker.package != "vox"
        {
            return Err(usage("install marker identity is not vox's"));
        }
        if marker.channel.is_empty()
            || marker.channel.len() > 32
            || !marker
                .channel
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(usage("install marker channel is not canonical"));
        }
        Ok(marker)
    }
}

/// The target triple this binary was built for, or `"unsupported"`.
#[must_use]
pub fn target_triple() -> &'static str {
    // Only the three targets ADR-015 ships are recognised; anything else has no release and
    // says so rather than guessing at an asset name.
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-gnu"
    } else {
        "unsupported"
    }
}

/// How the running binary got here — which decides what `update` may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Channel {
    /// Installed by `install.sh` or a previous `vox update`: the marker is beside the binary.
    Standalone {
        /// The directory holding `vox`, the marker, and `.vox-previous`.
        install_dir: PathBuf,
        /// The release channel the marker names.
        channel: String,
    },
    /// A `cargo build` output. Never overwritten — it is the developer's own artifact.
    Source {
        /// The binary that is running.
        exe: PathBuf,
    },
    /// Anything else: copied by hand, packaged by a distribution, installed by a manager.
    Unmanaged {
        /// The binary that is running.
        exe: PathBuf,
    },
}

/// Classify the running binary. Symlinks are resolved first, so a `~/.local/bin/vox` that
/// points into a real install directory is recognised as that install.
///
/// # Errors
/// [`AppError::Usage`] if a marker is present but is not a canonical vox marker — a corrupt
/// marker is a broken install, not an unmanaged binary, and saying so beats guessing.
pub fn detect_channel(exe: &Path) -> Result<Channel, AppError> {
    let exe = fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf());
    if let Some(dir) = exe.parent() {
        let marker = dir.join(MARKER_NAME);
        if marker.is_file() {
            return Ok(Channel::Standalone {
                install_dir: dir.to_path_buf(),
                channel: Marker::read(&marker)?.channel,
            });
        }
    }
    let text = exe.to_string_lossy();
    if text.contains("/target/debug/")
        || text.contains("/target/release/")
        || text.contains("/target/deps/")
    {
        return Ok(Channel::Source { exe });
    }
    Ok(Channel::Unmanaged { exe })
}

// ---------------------------------------------------------------- transport

fn network(message: impl Into<String>) -> AppError {
    AppError::Usage(format!("update transport failed: {}", message.into()))
}

fn client(timeout: Duration, redirects: reqwest::redirect::Policy) -> Result<Client, AppError> {
    Client::builder()
        .use_rustls_tls()
        .redirect(redirects)
        .referer(false)
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(timeout)
        .user_agent(concat!("vox/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| network(e.to_string()))
}

/// GitHub serves both the `latest/download` record and the pinned asset through redirects, so
/// unlike hf2q this cannot be `Policy::none()`. Every hop is confined to GitHub's own origins
/// and the chain is bounded.
fn github_redirects() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error("too many release redirects");
        }
        let url = attempt.url();
        let allowed = url.scheme() == "https"
            && matches!(
                url.host_str(),
                Some(
                    "github.com"
                        | "release-assets.githubusercontent.com"
                        | "objects.githubusercontent.com"
                )
            );
        if allowed {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

/// The final URL must still be a GitHub origin — the redirect policy stops elsewhere rather
/// than erroring, so without this a stopped redirect would be read as a response body.
fn require_github_origin(response: &Response) -> Result<(), AppError> {
    let url = response.url();
    if url.scheme() != "https"
        || !matches!(
            url.host_str(),
            Some(
                "github.com"
                    | "release-assets.githubusercontent.com"
                    | "objects.githubusercontent.com"
            )
        )
    {
        return Err(network(format!("response left GitHub's origins: {url}")));
    }
    Ok(())
}

fn require_success(response: &Response, expected_length: Option<u64>) -> Result<(), AppError> {
    let status = response.status();
    if !status.is_success() {
        // A 404 is the ordinary "there is no release for this target yet".
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(usage("that release asset is not published"));
        }
        return Err(network(format!("server answered {status}")));
    }
    if response.headers().contains_key(CONTENT_ENCODING) {
        return Err(network("encoded responses are not accepted"));
    }
    if let Some(expected) = expected_length {
        let actual = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if actual != Some(expected) {
            return Err(usage(
                "the asset's length does not match the release record".to_owned(),
            ));
        }
    }
    Ok(())
}

fn read_bounded(response: Response, maximum: usize) -> Result<Vec<u8>, AppError> {
    let mut bytes = Vec::with_capacity(maximum.min(1024));
    response
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| network("read failed"))?;
    if bytes.len() > maximum {
        return Err(usage("release record size is outside the supported bound"));
    }
    Ok(bytes)
}

/// Fetch and validate the newest release record for `channel` and this target.
///
/// # Errors
/// [`AppError::Usage`] if the platform has no release, the transfer fails or leaves GitHub, or
/// the record does not validate.
fn fetch_record(channel: &str, target: &str) -> Result<Validated, AppError> {
    let name = format!("{channel}-{target}.json");
    let url = format!("https://github.com/{REPO}/releases/latest/download/{name}");
    let response = client(RECORD_TIMEOUT, github_redirects())?
        .get(&url)
        .header(ACCEPT_ENCODING, "identity")
        .header(CACHE_CONTROL, "no-cache")
        .send()
        .map_err(|e| network(e.to_string()))?;
    require_github_origin(&response)?;
    require_success(&response, None).map_err(|e| match e {
        AppError::Usage(m) if m == "that release asset is not published" => usage(format!(
            "the {channel} release record for {target} ({name}) is not published"
        )),
        other => other,
    })?;
    let bytes = read_bounded(response, MAX_RECORD_BYTES)?;
    ReleaseRecord::validate(&bytes, channel, target)
}

/// Stream the asset into `destination`, hashing as it arrives.
///
/// The size bound is enforced **during** the transfer, not after it: a server that keeps
/// sending is cut off at the first byte past what the record promised, rather than being
/// allowed to fill the disk and fail the comparison afterwards.
fn download_asset(release: &Validated, destination: &mut fs::File) -> Result<(), AppError> {
    let url = format!(
        "https://github.com/{REPO}/releases/download/v{}/vox-{}",
        release.version_text, release.target
    );
    let mut response = client(ASSET_TIMEOUT, github_redirects())?
        .get(&url)
        .header(ACCEPT_ENCODING, "identity")
        .send()
        .map_err(|e| network(e.to_string()))?;
    require_github_origin(&response)?;
    require_success(&response, Some(release.size))?;

    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; IO_BUFFER_BYTES];
    loop {
        let read = response
            .read(&mut buffer)
            .map_err(|_| network("release asset read failed"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| usage("release asset byte count overflowed"))?;
        if total > release.size {
            return Err(usage("the download is larger than the release record says"));
        }
        hasher.update(&buffer[..read]);
        destination
            .write_all(&buffer[..read])
            .map_err(AppError::Io)?;
    }
    destination.flush().map_err(AppError::Io)?;
    let digest: [u8; 32] = hasher.finalize().into();
    if total != release.size || digest != release.sha256 {
        return Err(usage(
            "the download does not match the release record's size and digest",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------- Apple trust (macOS)

/// What a Developer ID signature says about who signed, and as what.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct SigningIdentity {
    team_id: String,
    identifier: String,
}

#[cfg(target_os = "macos")]
fn trust(message: &'static str) -> AppError {
    AppError::Usage(format!("release trust check failed: {message}"))
}

#[cfg(target_os = "macos")]
fn codesign_ok(path: &Path, args: &[&str], message: &'static str) -> Result<(), AppError> {
    let output = Command::new("/usr/bin/codesign")
        .args(args)
        .arg(path)
        .output()
        .map_err(AppError::Io)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(trust(message))
    }
}

/// Exactly one line with this prefix, or it is not a signature we will reason about.
#[cfg(target_os = "macos")]
fn unique_value<'a>(text: &'a str, prefix: &str) -> Result<&'a str, AppError> {
    let mut found = text.lines().filter_map(|line| line.strip_prefix(prefix));
    let value = found
        .next()
        .ok_or_else(|| trust("signing identity is incomplete"))?;
    if found.next().is_some() {
        return Err(trust("signing identity contains duplicate fields"));
    }
    Ok(value)
}

/// Parse `codesign --display --verbose=4` output into the identity it attests, refusing
/// anything that is not a complete Developer ID signature with a hardened runtime and a secure
/// timestamp.
#[cfg(target_os = "macos")]
fn parse_signing_identity(text: &str) -> Result<SigningIdentity, AppError> {
    let team_id = unique_value(text, "TeamIdentifier=")?;
    if team_id.len() != 10
        || !team_id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return Err(trust("Developer ID team is not canonical"));
    }
    let identifier = unique_value(text, "Identifier=")?;
    if identifier.is_empty()
        || !identifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    {
        return Err(trust("signing identifier is not canonical"));
    }
    let authorities: Vec<&str> = text
        .lines()
        .filter_map(|line| line.strip_prefix("Authority="))
        .collect();
    let prefix = "Developer ID Application: ";
    let suffix = format!(" ({team_id})");
    if authorities.len() != 3
        || !authorities[0].starts_with(prefix)
        || !authorities[0].ends_with(&suffix)
        || authorities[0].len() <= prefix.len() + suffix.len()
        || authorities[1] != "Developer ID Certification Authority"
        || authorities[2] != "Apple Root CA"
    {
        return Err(trust(
            "Developer ID authority chain is incomplete or ambiguous",
        ));
    }
    let code_directory: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("CodeDirectory "))
        .collect();
    let runtime = code_directory.len() == 1
        && code_directory[0]
            .split_ascii_whitespace()
            .find_map(|field| field.strip_prefix("flags=0x"))
            .and_then(|flags| flags.split_once('('))
            .is_some_and(|(hex, names)| {
                !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) && names == "runtime)"
            });
    if !runtime {
        return Err(trust("signature does not enable the hardened runtime"));
    }
    if unique_value(text, "Timestamp=")?.is_empty() {
        return Err(trust("signature has no secure timestamp"));
    }
    Ok(SigningIdentity {
        team_id: team_id.to_owned(),
        identifier: identifier.to_owned(),
    })
}

#[cfg(target_os = "macos")]
fn signing_identity(path: &Path) -> Result<SigningIdentity, AppError> {
    let output = Command::new("/usr/bin/codesign")
        .args(["--display", "--verbose=4"])
        .arg(path)
        .output()
        .map_err(AppError::Io)?;
    // `codesign --display` writes its report to stderr and nothing to stdout.
    if !output.status.success()
        || output.stderr.len() > MAX_SIGNING_INFO_BYTES
        || !output.stdout.is_empty()
    {
        return Err(trust("Apple signing identity could not be read"));
    }
    let text = core::str::from_utf8(&output.stderr)
        .map_err(|_| trust("Apple signing identity was not UTF-8"))?;
    parse_signing_identity(text)
}

/// Authenticate the downloaded bytes before anything is published.
///
/// The load-bearing check is **continuity**: the candidate must carry the same Developer ID as
/// the binary it would replace. A correct record digest only proves the bytes are the ones
/// GitHub is serving; this proves they were signed by whoever signed the vox already installed,
/// and that Apple will still vouch for them.
#[cfg(target_os = "macos")]
fn verify_apple_release(active: &Path, candidate: &Path, version: &str) -> Result<(), AppError> {
    codesign_ok(
        candidate,
        &["--verify", "--strict", "--all-architectures"],
        "candidate code-signature verification failed",
    )?;
    codesign_ok(
        active,
        &["--verify", "--strict", "--all-architectures"],
        "the installed binary's own signature does not verify",
    )?;
    if signing_identity(active)? != signing_identity(candidate)? {
        return Err(trust(
            "the candidate's Developer ID is not the one that signed the installed vox",
        ));
    }
    codesign_ok(
        candidate,
        &[
            "--verify",
            "--strict",
            "--all-architectures",
            "--check-notarization",
            "--test-requirement",
            "=notarized",
        ],
        "Apple did not confirm the candidate's notarization ticket",
    )?;
    let output = Command::new(candidate)
        .arg("--version")
        .env_clear()
        .output()
        .map_err(AppError::Io)?;
    if !output.status.success()
        || output.stdout.len() > MAX_VERSION_OUTPUT_BYTES
        || !output.stderr.is_empty()
        || output.stdout != format!("vox {version}\n").into_bytes()
    {
        return Err(trust(
            "the candidate's version is not the one the record named",
        ));
    }
    Ok(())
}

/// On Linux there is no Apple trust service, so an update rests on TLS to GitHub and the
/// record's digest alone. Stated here rather than silently skipped — see the module docs.
#[cfg(not(target_os = "macos"))]
fn verify_apple_release(_active: &Path, candidate: &Path, version: &str) -> Result<(), AppError> {
    let output = Command::new(candidate)
        .arg("--version")
        .env_clear()
        .output()
        .map_err(AppError::Io)?;
    if !output.status.success()
        || output.stdout.len() > MAX_VERSION_OUTPUT_BYTES
        || !output.stderr.is_empty()
        || output.stdout != format!("vox {version}\n").into_bytes()
    {
        return Err(usage(
            "release trust check failed: the candidate's version is not the one the record named",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------- local publication

/// An exclusive lock on the install directory, held for the whole transition.
struct InstallLock {
    _file: fs::File,
}

impl InstallLock {
    fn acquire(install_dir: &Path) -> Result<Self, AppError> {
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(install_dir.join(LOCK_NAME))
            .map_err(AppError::Io)?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| usage("another vox install transition is already running"))?;
        Ok(Self { _file: file })
    }
}

fn sync_dir(dir: &Path) -> Result<(), AppError> {
    fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(AppError::Io)
}

/// Make a verified candidate the active binary, keeping exactly one previous.
///
/// The previous copy is completed *before* the rename, so a crash anywhere in here leaves a
/// runnable `vox` — the old one or the new one, never a partial file.
fn publish(install_dir: &Path, candidate: &Path) -> Result<(), AppError> {
    let active = install_dir.join(ACTIVE_NAME);
    let previous_partial = install_dir.join(PREVIOUS_PARTIAL);
    fs::copy(&active, &previous_partial).map_err(AppError::Io)?;
    fs::rename(&previous_partial, install_dir.join(PREVIOUS_NAME)).map_err(AppError::Io)?;

    // The download lives in a temporary directory that may be on another filesystem, so it is
    // copied next to the destination before the rename, which must be same-filesystem to be
    // atomic.
    let staged = install_dir.join(CANDIDATE_PARTIAL);
    fs::copy(candidate, &staged).map_err(AppError::Io)?;
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o755)).map_err(AppError::Io)?;
    fs::rename(&staged, &active).map_err(AppError::Io)?;
    sync_dir(install_dir)
}

// ---------------------------------------------------------------- the command

/// `vox update [--check] [--rollback]`.
///
/// # Errors
/// [`AppError::Usage`] with a reason for the person: no release for this platform, a transfer,
/// verification or trust failure, or an install this tooling does not own.
pub fn run(check_only: bool, rollback: bool) -> Result<(), AppError> {
    let exe = std::env::current_exe()
        .map_err(|e| usage(format!("cannot locate the running binary: {e}")))?;
    let installed = detect_channel(&exe)?;

    if rollback {
        let (install_dir, _) = owned(installed, "`vox update --rollback` will not touch it")?;
        return do_rollback(&install_dir);
    }

    // The channel comes from the install's marker; a binary this tooling does not own still
    // gets to *ask* what the default channel holds, which is what `--check` is for.
    let channel = match &installed {
        Channel::Standalone { channel, .. } => channel.clone(),
        Channel::Source { .. } | Channel::Unmanaged { .. } => DEFAULT_CHANNEL.to_owned(),
    };
    let target = target_triple();
    if target == "unsupported" {
        return Err(usage(
            "this platform has no vox release (ADR-015 ships x86_64 Linux and both macOS \
             architectures)",
        ));
    }

    let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|_| usage("this binary's own version is not SemVer"))?;
    let release = fetch_record(&channel, target)?;
    if release.version <= current {
        println!(
            "vox {current} is current (the newest {channel} release is {})",
            release.version_text
        );
        return Ok(());
    }
    println!(
        "vox {} is available on {channel} (this is {current})",
        release.version_text
    );
    if check_only {
        return Ok(());
    }

    // Only an install this tooling made is replaced in place. A source build is the
    // developer's own artifact and overwriting it would destroy work.
    let (install_dir, _) = owned(installed, "`vox update` will not replace it")?;
    let active = install_dir.join(ACTIVE_NAME);
    if !active.is_file() {
        return Err(usage(format!(
            "{} holds the install marker but no `{ACTIVE_NAME}` binary",
            install_dir.display()
        )));
    }
    let _lock = InstallLock::acquire(&install_dir)?;

    let mut candidate = tempfile::Builder::new()
        .prefix("vox-update.")
        .tempfile()
        .map_err(AppError::Io)?;
    download_asset(&release, candidate.as_file_mut())?;
    candidate
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o555))
        .map_err(AppError::Io)?;
    candidate.as_file().sync_all().map_err(AppError::Io)?;
    verify_apple_release(&active, candidate.path(), &release.version_text)?;
    publish(&install_dir, candidate.path())?;

    println!("updated: {} -> {}", active.display(), release.version_text);
    println!(
        "         previous kept at {}",
        install_dir.join(PREVIOUS_NAME).display()
    );
    run_shell_setup(&active);
    Ok(())
}

/// The install directory and channel this tooling owns, or a refusal naming the way forward.
fn owned(installed: Channel, what: &str) -> Result<(PathBuf, String), AppError> {
    match installed {
        Channel::Standalone {
            install_dir,
            channel,
        } => Ok((install_dir, channel)),
        Channel::Source { exe } => Err(usage(format!(
            "{} is a build from source, so {what}.\n       \
             Update it the way you built it:  git pull && cargo build --release",
            exe.display()
        ))),
        Channel::Unmanaged { exe } => Err(usage(format!(
            "{} was not installed by vox's installer (no {MARKER_NAME} beside it), so {what}.\n\
             \x20      To get a self-updating install:  \
             curl -fsSL https://raw.githubusercontent.com/{REPO}/main/install.sh | sh",
            exe.display()
        ))),
    }
}

/// Swap the active binary and `.vox-previous`, so a rollback is itself reversible.
fn do_rollback(install_dir: &Path) -> Result<(), AppError> {
    let active = install_dir.join(ACTIVE_NAME);
    let previous = install_dir.join(PREVIOUS_NAME);
    if !previous.is_file() {
        return Err(usage(format!(
            "no previous vox was retained in {} — nothing to roll back to",
            install_dir.display()
        )));
    }
    let _lock = InstallLock::acquire(install_dir)?;
    let scratch = install_dir.join(ROLLBACK_PARTIAL);
    fs::copy(&active, &scratch).map_err(AppError::Io)?;
    fs::rename(&previous, &active).map_err(AppError::Io)?;
    fs::rename(&scratch, &previous).map_err(AppError::Io)?;
    sync_dir(install_dir)?;
    println!(
        "rolled back: {} -> {}",
        active.display(),
        binary_version(&active).unwrap_or_else(|| "unknown".to_owned())
    );
    run_shell_setup(&active);
    Ok(())
}

/// What `vox --version` on `path` reports, as a bare version string.
fn binary_version(path: &Path) -> Option<String> {
    let out = Command::new(path)
        .arg("--version")
        .env_clear()
        .output()
        .ok()?;
    if !out.status.success() || out.stdout.len() > MAX_VERSION_OUTPUT_BYTES {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .nth(1)
        .map(str::to_owned)
}

/// Completions are generated from the CLI model, so they are refreshed with the CLI. This runs
/// the binary that is now in place — the new model is the one that matters — and honours the
/// same opt-out `vox shell-setup` itself honours.
fn run_shell_setup(active: &Path) {
    if std::env::var_os("VOX_NO_SHELL_SETUP").is_some() {
        return;
    }
    match Command::new(active).arg("shell-setup").output() {
        Ok(o) if o.status.success() => print!("{}", String::from_utf8_lossy(&o.stdout)),
        _ => println!("         note: run `vox shell-setup` to refresh completions"),
    }
}

// There are no unit tests here, deliberately (ADR-018 §2).
//
// The feature is "a released vox replaces itself with the next release, and refuses anything
// that does not verify". `tests/update_proof.rs` measures exactly that through the shipped
// binary against real GitHub, including the cases that must refuse.
