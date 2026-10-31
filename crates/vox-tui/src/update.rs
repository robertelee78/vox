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
//! reason the origin whitelist below is load-bearing rather than belt-and-braces.
//!
//! **vox ships Linux.** hf2q is Apple-Silicon-only and refuses to update anywhere else, so
//! every release it installs is Apple-authenticated. vox cannot do that on Linux: there the
//! only things standing behind an update are TLS to GitHub and the digest in the record. That
//! asymmetry is real, is recorded in ADR-015, and is why a detached release signature stays on
//! the list — it would be what Linux gets instead of Gatekeeper.

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT_ENCODING, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::app::AppError;

#[cfg(target_os = "macos")]
mod bundle;
pub(crate) mod restart;

/// The repository releases are published from.
const REPO: &str = "robertelee78/vox";

/// Record identity. A file that does not say exactly this is not a vox release record.
const RECORD_KIND: &str = "vox.standalone-release";
/// The app's record identity (ADR-014 M-27): `app-<channel>-<triple>.json`, the same schema.
#[cfg(target_os = "macos")]
const APP_RECORD_KIND: &str = "vox.app-release";
#[cfg(target_os = "macos")]
const APP_PACKAGE: &str = "Vox.app";
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
#[cfg(target_os = "macos")]
const MAX_APP_BYTES: u64 = 512 * 1024 * 1024;
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
    record: ReleaseRecord,
    sha256: [u8; 32],
}

impl ReleaseRecord {
    /// Parse and validate a record for `channel` and `target`.
    ///
    /// # Errors
    /// [`AppError::Usage`] if the bytes are not strict schema-1 JSON, if the record's identity
    /// is not `vox`/`channel`/`target`, or if any field is not canonical.
    fn validate(
        bytes: &[u8],
        identity: (&str, &str),
        channel: &str,
        target: &str,
        max_size: u64,
    ) -> Result<Validated, AppError> {
        let (kind, package) = identity;
        if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
            return Err(usage("release record size is outside the supported bound"));
        }
        let record: Self = serde_json::from_slice(bytes)
            .map_err(|_| usage("release record is not strict schema-1 JSON"))?;
        if record.kind != kind
            || record.schema_version != RECORD_SCHEMA
            || record.package != package
            || record.channel != channel
            || record.target != target
        {
            return Err(usage(format!(
                "release record identity does not match {package}/{channel}/{target}"
            )));
        }
        let version = semver::Version::parse(&record.version)
            .map_err(|_| usage("release record version is not SemVer"))?;
        if record.size == 0 || record.size > max_size {
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
            version_text: record.version.clone(),
            target: record.target.clone(),
            size: record.size,
            sha256,
            record,
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
            return Err(usage("the install marker's release line is not canonical"));
        }
        Ok(marker)
    }
}

/// The target triple this binary was built for, or `"unsupported"`.
#[must_use]
pub fn target_triple() -> &'static str {
    // Only the targets a release ships are recognised (ADR-014 M-26a: no Intel macOS); anything
    // else has no release and says so rather than guessing at an asset name.
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
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
    /// On macOS, the `vox` inside a Vox.app that `install.sh` installed (ADR-014 M-28): the
    /// marker is beside the bundle, and an update replaces the whole bundle (M-29).
    Bundle {
        /// The folder holding `Vox.app`, the marker, and `.Vox.app.previous`.
        apps_dir: PathBuf,
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
    if let Some(apps_dir) = bundle_apps_dir(&exe) {
        let marker = apps_dir.join(MARKER_NAME);
        if marker.is_file() {
            return Ok(Channel::Bundle {
                channel: Marker::read(&marker)?.channel,
                apps_dir,
            });
        }
    }
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

/// The folder holding the bundle, when `exe` is `<folder>/Vox.app/Contents/Helpers/vox` on macOS.
fn bundle_apps_dir(exe: &Path) -> Option<PathBuf> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let helpers = exe.parent()?;
    let contents = helpers.parent()?;
    let bundle = contents.parent()?;
    let named = |p: &Path, name: &str| p.file_name().is_some_and(|n| n == name);
    (named(exe, ACTIVE_NAME)
        && named(helpers, "Helpers")
        && named(contents, "Contents")
        && named(bundle, "Vox.app"))
    .then(|| bundle.parent().map(Path::to_path_buf))
    .flatten()
}

// ---------------------------------------------------------------- where releases come from

/// The releases every request is made under: GitHub's, in every build a person installs.
///
/// A build with `test-knobs` reads `VOX_TEST_RELEASE_BASE`, a loopback
/// `http://127.0.0.1:<port>/releases`, so `update_proof` can drive a real update against a local
/// release (#453). An environment variable that moves where a binary fetches its own replacement
/// would be a vulnerability in a shipped build; no shipped build has this one (V210-105).
fn releases_base() -> String {
    #[cfg(feature = "test-knobs")]
    if let Some(base) = test_release_base() {
        return base;
    }
    format!("https://github.com/{REPO}/releases")
}

#[cfg(feature = "test-knobs")]
fn test_release_base() -> Option<String> {
    std::env::var("VOX_TEST_RELEASE_BASE")
        .ok()
        .filter(|b| b.starts_with("http://127.0.0.1:"))
}

/// Whether this run fetches from a test-knobs loopback release rather than GitHub.
fn testing_against_loopback() -> bool {
    #[cfg(feature = "test-knobs")]
    {
        test_release_base().is_some()
    }
    #[cfg(not(feature = "test-knobs"))]
    {
        false
    }
}

/// Whether Apple must vouch for a candidate. Always, except against a test-knobs loopback
/// release, whose bytes are a fixture rather than a release; there `VOX_TEST_APPLE_VERIFY=1`
/// turns the check back on, which is how the proof measures that it refuses unsigned bytes.
#[cfg(target_os = "macos")]
fn apple_required() -> bool {
    #[cfg(feature = "test-knobs")]
    if std::env::var_os("VOX_TEST_APPLE_VERIFY").is_some() {
        return true;
    }
    !testing_against_loopback()
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
    if testing_against_loopback() && url.as_str().starts_with(&releases_base()) {
        return Ok(());
    }
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
    fetch_named(
        &format!("{channel}-{target}.json"),
        (RECORD_KIND, "vox"),
        channel,
        target,
        MAX_BINARY_BYTES,
        None,
    )
}

/// Fetch the app record from the already selected release, never from latest again.
#[cfg(target_os = "macos")]
fn fetch_app_record_at(channel: &str, target: &str, version: &str) -> Result<Validated, AppError> {
    let parsed = semver::Version::parse(version)
        .map_err(|_| usage("selected release version is not SemVer"))?;
    if parsed.to_string() != version {
        return Err(usage("selected release version is not canonical"));
    }
    let record = fetch_named(
        &format!("app-{channel}-{target}.json"),
        (APP_RECORD_KIND, APP_PACKAGE),
        channel,
        target,
        MAX_APP_BYTES,
        Some(version),
    )?;
    if record.version_text != version {
        return Err(usage(
            "app release record does not match the selected version",
        ));
    }
    Ok(record)
}

fn fetch_named(
    name: &str,
    identity: (&str, &str),
    channel: &str,
    target: &str,
    max_size: u64,
    version: Option<&str>,
) -> Result<Validated, AppError> {
    let url = match version {
        Some(version) => format!("{}/download/v{version}/{name}", releases_base()),
        None => format!("{}/latest/download/{name}", releases_base()),
    };
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
    ReleaseRecord::validate(&bytes, identity, channel, target, max_size)
}

/// Stream the asset into `destination`, hashing as it arrives.
///
/// The size bound is enforced **during** the transfer, not after it: a server that keeps
/// sending is cut off at the first byte past what the record promised, rather than being
/// allowed to fill the disk and fail the comparison afterwards.
fn download_asset(
    release: &Validated,
    asset: &str,
    destination: &mut fs::File,
) -> Result<(), AppError> {
    let url = format!(
        "{}/download/v{}/{asset}",
        releases_base(),
        release.version_text
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
            .map_err(|e| {
                usage(format!(
                    "cannot open {}: {e}\n       is this install another account's? it is changed \
                     only by the account that installed it",
                    install_dir.join(LOCK_NAME).display()
                ))
            })?;
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

/// Copy `from` to `to` and **flush the copy** before anyone renames it into place (V210-56, #242).
///
/// `fs::copy` returns once the bytes are handed to the kernel — on APFS it is a clone — and a
/// rename that publishes the copy can reach the disk before the copy's own data and metadata do.
/// A power loss in between left an empty or partial file under the name `vox` or `.vox-previous`:
/// the one binary that had to survive. Every copy that is about to be renamed goes through here.
/// `mode`, when given, is set before the flush, so the flush covers it too.
///
/// **A leftover at `to` is removed first** (V210-83). `to` is always a partial name, so whatever
/// is there is scratch from a transition that was cut short. `fs::copy` carries the source's mode,
/// and the download is `0555`, so a cut-short copy left a read-only partial that the next copy
/// could not open for writing: every later `vox update` failed with a bare "Permission denied".
/// Removing it needs only the directory to be writable, which the rename after it needs anyway.
fn copy_durably(from: &Path, to: &Path, mode: Option<u32>) -> Result<(), AppError> {
    match fs::remove_file(to) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(usage(format!(
                "cannot clear {}, left over from an update that was cut short: {e}\n       \
                 remove it by hand, then run this again",
                to.display()
            )))
        }
    }
    fs::copy(from, to).map_err(AppError::Io)?;
    if let Some(mode) = mode {
        fs::set_permissions(to, fs::Permissions::from_mode(mode)).map_err(AppError::Io)?;
    }
    fs::File::open(to)
        .and_then(|f| f.sync_all())
        .map_err(AppError::Io)
}

/// Make a verified candidate the active binary, keeping exactly one previous.
///
/// The previous copy is completed *before* the rename, so a crash anywhere in here leaves a
/// runnable `vox` — the old one or the new one, never a partial file. **Durably** (V210-56): each
/// copy is flushed before the rename that publishes it, and the directory after each rename, so a
/// power loss at any point leaves the same — not an empty file under a name that looked
/// published.
fn publish(install_dir: &Path, candidate: &Path) -> Result<(), AppError> {
    let active = install_dir.join(ACTIVE_NAME);
    let previous_partial = install_dir.join(PREVIOUS_PARTIAL);
    copy_durably(&active, &previous_partial, None)?;
    fs::rename(&previous_partial, install_dir.join(PREVIOUS_NAME)).map_err(AppError::Io)?;
    sync_dir(install_dir)?;

    // The download lives in a temporary directory that may be on another filesystem, so it is
    // copied next to the destination before the rename, which must be same-filesystem to be
    // atomic.
    let staged = install_dir.join(CANDIDATE_PARTIAL);
    copy_durably(candidate, &staged, Some(0o755))?;
    fs::rename(&staged, &active).map_err(AppError::Io)?;
    sync_dir(install_dir)
}

// ---------------------------------------------------------------- the command

/// `vox update [--check] [--rollback]`.
///
/// # Errors
/// [`AppError::Usage`] with a reason for the person: no release for this platform, a transfer,
/// verification or trust failure, or an install this tooling does not own.
pub fn run(check_only: bool, rollback: bool) -> Result<u8, AppError> {
    use std::os::unix::process::ExitStatusExt as _;

    let exe =
        fs::canonicalize(std::env::current_exe().map_err(AppError::Io)?).map_err(AppError::Io)?;
    let installed = detect_channel(&exe)?;
    if rollback {
        if let Channel::Bundle { apps_dir, channel } = &installed {
            run_bundle(apps_dir, channel, &exe, false, true)?;
        } else {
            let (dir, _) = owned(installed, "`vox update --rollback` will not touch it")?;
            do_rollback(&dir)?;
        }
        return Ok(0);
    }
    let channel = match &installed {
        Channel::Standalone { channel, .. } | Channel::Bundle { channel, .. } => channel.clone(),
        Channel::Source { .. } | Channel::Unmanaged { .. } => DEFAULT_CHANNEL.to_owned(),
    };
    let target = target_triple();
    if target == "unsupported" {
        return Err(usage(
            "this platform has no vox release (releases are built for x86_64 Linux and for Apple \
             Silicon Macs on macOS 13 or later)",
        ));
    }
    if cfg!(target_os = "macos") && matches!(installed, Channel::Standalone { .. }) {
        println!(
            "vox: on a Mac, vox now comes with Vox.app; to move to it, run the installer again: \
             curl -fsSL https://raw.githubusercontent.com/{REPO}/main/install.sh | sh"
        );
    }
    let current_text = match &installed {
        Channel::Standalone { .. } | Channel::Bundle { .. } => binary_version(&exe)
            .ok_or_else(|| usage("cannot identify the installed vox version"))?,
        _ => env!("CARGO_PKG_VERSION").to_owned(),
    };
    let current = semver::Version::parse(&current_text)
        .map_err(|_| usage("installed vox version is not SemVer"))?;
    let release = match fetch_record(&channel, target) {
        Ok(release) => release,
        Err(error) => {
            #[cfg(target_os = "macos")]
            if !check_only {
                if let Channel::Bundle { apps_dir, .. } = &installed {
                    if bundle::repair(apps_dir, &exe)? {
                        return Ok(0);
                    }
                }
            }
            return Err(error);
        }
    };
    if release.version <= current {
        if let Channel::Bundle { apps_dir, channel } = &installed {
            if check_only {
                println!(
                    "Vox {current} is current (the newest {channel} release is {})",
                    release.version_text
                );
            } else {
                run_bundle(apps_dir, channel, &exe, false, false)?;
            }
        } else {
            println!(
                "vox {current} is current (the newest {channel} release is {})",
                release.version_text
            );
            if !check_only {
                if let Ok((dir, _)) = owned(installed, "") {
                    run_shell_setup(&dir.join(ACTIVE_NAME));
                    println!("vox {current} is current; {}", skill_said());
                }
            }
        }
        return Ok(0);
    }
    println!(
        "vox {} is available on {channel} (this is {current})",
        release.version_text
    );
    if check_only {
        return Ok(0);
    }
    match &installed {
        Channel::Standalone { install_dir, .. } if exe == install_dir.join(ACTIVE_NAME) => {}
        Channel::Bundle { .. } => {}
        _ => {
            let _ = owned(installed, "`vox update` will not replace it")?;
            return Err(usage(
                "the install marker does not identify the active vox binary",
            ));
        }
    }
    let dir = tempfile::Builder::new()
        .prefix("vox-update.")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .map_err(AppError::Io)?;
    let candidate = dir.path().join("vox");
    let mut downloading = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(&candidate)
        .map_err(AppError::Io)?;
    let downloaded = download_asset(
        &release,
        &format!("vox-{}", release.target),
        &mut downloading,
    );
    #[cfg(target_os = "macos")]
    let downloaded = downloaded.map_err(|error| {
        if let Channel::Bundle { apps_dir, .. } = &installed {
            match bundle::repair(apps_dir, &exe) {
                Ok(true) => {
                    return usage(format!(
                        "local repair completed; the newer updater could not be downloaded: {error}"
                    ));
                }
                Err(repair) => {
                    return usage(format!("{error}; local repair also failed: {repair}"));
                }
                Ok(false) => {}
            }
        }
        error
    });
    downloaded?;
    downloading
        .set_permissions(fs::Permissions::from_mode(0o555))
        .map_err(AppError::Io)?;
    downloading.sync_all().map_err(AppError::Io)?;
    drop(downloading);
    verify_candidate(&exe, &candidate, &release.version_text)?;
    let request = ApplyRequest {
        installed_exe: exe.as_os_str().as_bytes().to_vec(),
        record: release.record,
    };
    let bytes = serde_json::to_vec(&request).map_err(|_| usage("cannot encode update request"))?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(usage("update request exceeds its size bound"));
    }
    let request_path = dir.path().join("request.json");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&request_path)
        .map_err(AppError::Io)?;
    file.write_all(&bytes).map_err(AppError::Io)?;
    drop(file);
    let status = Command::new(&candidate)
        .arg("update-apply")
        .arg(&request_path)
        .status()
        .map_err(AppError::Io)?;
    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
        .clamp(0, 255) as u8)
}

const MAX_REQUEST_BYTES: usize = MAX_RECORD_BYTES + 32 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyRequest {
    installed_exe: Vec<u8>,
    record: ReleaseRecord,
}

fn verify_candidate(active: &Path, candidate: &Path, version: &str) -> Result<(), AppError> {
    #[cfg(target_os = "macos")]
    if !apple_required() {
        if binary_version(candidate).as_deref() != Some(version) {
            return Err(usage(
                "candidate version does not match the selected release",
            ));
        }
        return Ok(());
    }
    verify_apple_release(active, candidate, version)
}

/// Apply a bootstrap request using this release's updater.
pub(crate) fn apply_request(path: &Path) -> Result<(), AppError> {
    use std::os::unix::fs::MetadataExt as _;

    let uid = rustix::process::getuid().as_raw();
    let directory = path
        .parent()
        .ok_or_else(|| usage("update request has no directory"))?;
    let directory_meta = fs::symlink_metadata(directory).map_err(AppError::Io)?;
    let request_meta = fs::symlink_metadata(path).map_err(AppError::Io)?;
    if !directory_meta.is_dir()
        || directory_meta.uid() != uid
        || directory_meta.mode() & 0o077 != 0
        || !request_meta.is_file()
        || request_meta.uid() != uid
        || request_meta.mode() & 0o077 != 0
    {
        return Err(usage("update request is not in an owned private directory"));
    }
    let file = fs::File::open(path).map_err(AppError::Io)?;
    if !file.metadata().map_err(AppError::Io)?.is_file() {
        return Err(usage("update request is not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(AppError::Io)?;
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err(usage("update request size is outside the supported bound"));
    }
    let request: ApplyRequest =
        serde_json::from_slice(&bytes).map_err(|_| usage("invalid update request"))?;
    let installed_exe = PathBuf::from(std::ffi::OsString::from_vec(request.installed_exe));
    let active = fs::canonicalize(&installed_exe).map_err(AppError::Io)?;
    if active != installed_exe {
        return Err(usage("update request executable is not canonical"));
    }
    let installed = detect_channel(&active)?;
    let channel = match &installed {
        Channel::Standalone {
            install_dir,
            channel,
        } if active == install_dir.join(ACTIVE_NAME) => channel.clone(),
        Channel::Bundle { channel, .. } => channel.clone(),
        _ => return Err(usage("update request does not name an owned installation")),
    };
    let record_bytes =
        serde_json::to_vec(&request.record).map_err(|_| usage("invalid release record"))?;
    let release = ReleaseRecord::validate(
        &record_bytes,
        (RECORD_KIND, "vox"),
        &channel,
        target_triple(),
        MAX_BINARY_BYTES,
    )?;
    if release.version_text != env!("CARGO_PKG_VERSION") {
        return Err(usage(
            "update engine version does not match the selected release",
        ));
    }
    let engine =
        fs::canonicalize(std::env::current_exe().map_err(AppError::Io)?).map_err(AppError::Io)?;
    let request_dir = fs::canonicalize(directory).map_err(AppError::Io)?;
    if engine.parent() != Some(request_dir.as_path())
        || engine.file_name().is_none_or(|name| name != "vox")
    {
        return Err(usage(
            "update engine is not in the request's private directory",
        ));
    }
    let mut engine_file = fs::File::open(&engine).map_err(AppError::Io)?;
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; IO_BUFFER_BYTES];
    loop {
        let n = engine_file.read(&mut buffer).map_err(AppError::Io)?;
        if n == 0 {
            break;
        }
        size = size
            .checked_add(n as u64)
            .ok_or_else(|| usage("engine size overflow"))?;
        if size > release.size {
            return Err(usage("update engine exceeds release size"));
        }
        hasher.update(&buffer[..n]);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if size != release.size || digest != release.sha256 {
        return Err(usage("update engine does not match the release record"));
    }
    verify_candidate(&active, &engine, &release.version_text)?;
    match installed {
        #[cfg(target_os = "macos")]
        Channel::Bundle { apps_dir, .. } => bundle::apply(&apps_dir, &active, &release),
        Channel::Standalone { install_dir, .. } => {
            let _lock = InstallLock::acquire(&install_dir)?;
            if detect_channel(&active)?
                != (Channel::Standalone {
                    install_dir: install_dir.clone(),
                    channel: channel.to_owned(),
                })
            {
                return Err(usage("installation ownership changed during update"));
            }
            let current = binary_version(&active)
                .and_then(|v| semver::Version::parse(&v).ok())
                .ok_or_else(|| usage("cannot identify the installed vox version"))?;
            if current >= release.version {
                println!("vox {current} is already installed; no downgrade performed");
                return Ok(());
            }
            publish(&install_dir, &engine)?;
            println!("updated: {} -> {}", active.display(), release.version_text);
            println!(
                "         previous kept at {}",
                install_dir.join(PREVIOUS_NAME).display()
            );
            let detached = restart::restart_daemon(&active, &release.version_text)?;
            run_shell_setup(&active);
            restart::say_next(&detached);
            Ok(())
        }
        _ => Err(usage("update request does not name an owned installation")),
    }
}

/// A Vox.app install: the whole bundle is updated or rolled back (ADR-014 M-29).
#[cfg(target_os = "macos")]
fn run_bundle(
    apps_dir: &Path,
    channel: &str,
    exe: &Path,
    check_only: bool,
    rollback: bool,
) -> Result<(), AppError> {
    if rollback {
        bundle::rollback(apps_dir, exe)
    } else {
        bundle::update(apps_dir, channel, exe, check_only)
    }
}

#[cfg(not(target_os = "macos"))]
fn run_bundle(_: &Path, _: &str, _: &Path, _: bool, _: bool) -> Result<(), AppError> {
    Err(usage("a Vox.app install exists only on macOS"))
}

/// The install directory and channel this tooling owns, or a refusal naming the way forward.
fn owned(installed: Channel, what: &str) -> Result<(PathBuf, String), AppError> {
    match installed {
        Channel::Standalone {
            install_dir,
            channel,
        } => Ok((install_dir, channel)),
        Channel::Bundle { apps_dir, .. } => Err(usage(format!(
            "{} holds Vox.app, which is updated as a whole, so {what}",
            apps_dir.display()
        ))),
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
    let scratch = install_dir.join(ROLLBACK_PARTIAL);
    let _lock = InstallLock::acquire(install_dir)?;
    // **A rollback a power loss interrupted is finished, not refused** (#242, verifier). The steps
    // below leave two states behind them. Between the renames, the previous binary is already
    // `vox` and the other one is still the scratch copy, with no `.vox-previous`. That rollback
    // happened: its swap is completed, and this one stops there rather than swapping back. Before
    // the first rename, both names are intact and the scratch is only a copy of `vox`: it goes.
    // A scratch that does not run (a copy cut short before its flush) is never installed.
    if scratch.is_file() {
        if !previous.is_file() && runs_as_vox(&scratch) {
            fs::rename(&scratch, &previous).map_err(AppError::Io)?;
            sync_dir(install_dir)?;
            println!(
                "finished a rollback that was interrupted: {} is {}, and {} is kept for --rollback",
                active.display(),
                binary_version(&active).unwrap_or_else(|| "unknown".to_owned()),
                previous.display()
            );
            // As any rollback does: the daemon is restarted onto the binary now in place, which
            // brings its own completions.
            let detached = restart_onto(&active)?;
            run_shell_setup(&active);
            restart::say_next(&detached);
            return Ok(());
        }
        fs::remove_file(&scratch).map_err(AppError::Io)?;
        sync_dir(install_dir)?;
    }
    if !previous.is_file() {
        return Err(usage(format!(
            "no previous vox was retained in {} — nothing to roll back to",
            install_dir.display()
        )));
    }
    // Durably, step by step (V210-56): the copy of the active binary is on disk before either
    // rename, and each rename is on disk before the next — so a power loss anywhere leaves a
    // runnable `vox` under that name, and the other binary under one of the two others.
    copy_durably(&active, &scratch, None)?;
    fs::rename(&previous, &active).map_err(AppError::Io)?;
    sync_dir(install_dir)?;
    fs::rename(&scratch, &previous).map_err(AppError::Io)?;
    sync_dir(install_dir)?;
    println!(
        "rolled back: {} -> {}",
        active.display(),
        binary_version(&active).unwrap_or_else(|| "unknown".to_owned())
    );
    let detached = restart_onto(&active)?;
    run_shell_setup(&active);
    restart::say_next(&detached);
    Ok(())
}

/// Restart the daemon onto the binary a rollback put in place, as the version it says it is.
fn restart_onto(active: &Path) -> Result<Vec<vox_core::node::paths::NodeName>, AppError> {
    let now = binary_version(active).unwrap_or_else(|| "unknown".to_owned());
    restart::restart_daemon(active, &now)
}

/// How long [`runs_as_vox`] waits for `--version` before it counts a binary as not running.
const RUNS_WITHIN: std::time::Duration = std::time::Duration::from_secs(5);

/// Whether `path` is a `vox` that runs: `--version` exits 0 within [`RUNS_WITHIN`] and says
/// exactly `vox <major>.<minor>.<patch>`, with an optional `-<pre-release>` (#247, verifier). A
/// leftover a power loss may have cut short is installed only on this; one that hangs, fails, or
/// answers anything else is not a `vox`.
///
/// **Bounded whatever it starts.** It runs in its own process group, and the whole group is
/// killed on the timeout *and* once it has exited, before its output is read: a leftover that left
/// a child holding stdout would otherwise keep the read open past the bound (a staged one took
/// 12 s and was installed), and one that hung would leave its children behind.
fn runs_as_vox(path: &Path) -> bool {
    use std::os::unix::process::CommandExt as _;
    let Ok(mut child) = Command::new(path)
        .arg("--version")
        .env_clear()
        .process_group(0)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return false;
    };
    let kill_group = |pgid: u32| {
        let _ = Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{pgid}")])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    };
    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < RUNS_WITHIN => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            _ => {
                kill_group(child.id());
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    };
    // Whatever it started is gone before its output is read, so the read ends now.
    kill_group(child.id());
    let mut out = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout
            .by_ref()
            .take(MAX_VERSION_OUTPUT_BYTES as u64 + 1)
            .read_to_end(&mut out);
    }
    status.success() && out.len() <= MAX_VERSION_OUTPUT_BYTES && says_vox_version(&out)
}

/// Whether `out` is exactly `vox <major>.<minor>.<patch>[-<pre-release>]` and a line end.
fn says_vox_version(out: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(out) else {
        return false;
    };
    let Some(version) = text.strip_suffix('\n').unwrap_or(text).strip_prefix("vox ") else {
        return false;
    };
    let (core, pre) = match version.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (version, None),
    };
    let numbers: Vec<&str> = core.split('.').collect();
    numbers.len() == 3
        && numbers
            .iter()
            .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        && pre.is_none_or(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        })
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

/// Completions are generated from the CLI model, and the agent skill pack is the CLI's, so both
/// are refreshed with the CLI: this runs the binary that is now in place — the new one is the one
/// that matters — as every earlier release's update runs it. It honours `VOX_NO_SHELL_SETUP` and
/// `VOX_NO_SKILL_INSTALL` itself, each for its own part.
fn run_shell_setup(active: &Path) {
    match Command::new(active).arg("shell-setup").output() {
        Ok(o) => {
            print!("{}", String::from_utf8_lossy(&o.stdout));
            eprint!("{}", String::from_utf8_lossy(&o.stderr));
            if !o.status.success() {
                println!("         note: run `vox shell-setup` to refresh completions, the agent skill and hooks");
            }
        }
        Err(_) => println!(
            "         note: run `vox shell-setup` to refresh completions, the agent skill and hooks"
        ),
    }
}

/// Where the agent skill pack is now, as a person reads it: the harnesses here whose skills
/// folder holds it, read from disk after the refresh.
fn skill_said() -> String {
    if std::env::var_os("VOX_NO_SKILL_INSTALL").is_some_and(|v| !v.is_empty()) {
        return "the agent skill was left as it is (VOX_NO_SKILL_INSTALL is set)".to_owned();
    }
    let have: Vec<&str> = crate::skill_pack::HARNESSES
        .iter()
        .filter(|h| {
            crate::skill_pack::pack_dir(h.key).is_some_and(|d| d.join("SKILL.md").is_file())
        })
        .map(|h| h.name)
        .collect();
    if have.is_empty() {
        "no harness here has the agent skill: Claude Code, Codex, OpenCode and Oh My Pi were not found"
            .to_owned()
    } else {
        format!("the agent skill is installed for {}", have.join(", "))
    }
}

/// The agent skill pack and missing light hooks, where `vox shell-setup` is not run (a Vox.app
/// update run from inside the bundle). The binary now in place refreshes every harness here,
/// keeping operator changes. `VOX_NO_SKILL_INSTALL` skips only the skill pack.
#[cfg(target_os = "macos")]
fn run_skill_install(active: &Path) {
    for command in ["skill", "plugin"] {
        if command == "skill" && std::env::var_os("VOX_NO_SKILL_INSTALL").is_some() {
            continue;
        }
        match Command::new(active)
            .args(["agent", command, "--install"])
            .output()
        {
            Ok(o) => {
                print!("{}", String::from_utf8_lossy(&o.stdout));
                eprint!("{}", String::from_utf8_lossy(&o.stderr));
                if !o.status.success() {
                    println!("         note: run `vox agent {command} --install` to finish harness setup");
                }
            }
            Err(_) => println!(
                "         note: run `vox agent {command} --install` to finish harness setup"
            ),
        }
    }
}

// There are no unit tests here, deliberately (ADR-018 §2).
//
// The feature is "a released vox replaces itself with the next release, and refuses anything
// that does not verify". `tests/update_proof.rs` measures exactly that through the shipped
// binary against real GitHub, including the cases that must refuse.
