//! `vox update` — self-update from GitHub Releases (ADR-015 §"Install and update").
//!
//! 1. Fetch the per-target **release record** `stable-<triple>.json` through GitHub's
//!    `releases/latest/download/<name>` redirect. No API, no auth, no token.
//! 2. Check the record's identity — `kind`, `schema_version`, `package`, `channel`, `target`
//!    — before any other field of it is used, and compare its version against this binary's.
//! 3. Fetch `vox-<triple>` from the **exact tag the record named** — never `latest`, which can
//!    move between the two requests — bounded by the record's `size`, refusing any redirect
//!    that leaves GitHub.
//! 4. Verify size and SHA-256 **before** anything is renamed.
//! 5. Publish atomically: copy the active binary to `.vox-previous`, rename the candidate into
//!    place, re-verify the digest of what is now active. `--rollback` puts the previous back.
//! 6. Re-run `vox shell-setup`, so completions match the CLI that just landed.
//!
//! ## Why the transport is `curl` and not an HTTP crate
//! `install.sh` already requires `curl`, so it is the one dependency both paths share, and vox
//! already links rustls with `aws_lc_rs` plus a post-quantum provider — adding a second TLS
//! stack for the update path risks a provider conflict for no gain. Every decision that
//! matters (status, origin, size, digest) is made here in Rust; `curl` only moves bytes.
//!
//! ## Two things the spike found, which is why the checks look the way they do
//! Verified against real GitHub on 2026-09-21:
//!
//! - **`--fail` is mandatory.** Without it a `404` exits **0** and writes the body
//!   (`Not Found`) into the output file, which would then be parsed as the release record.
//! - **curl's exit `56` is overloaded** — it means both "404 under `--fail`" and "body exceeded
//!   `--max-filesize`". So the HTTP status is read from `%{http_code}` and never inferred from
//!   the exit code.
//!
//! ## What the record's integrity rests on
//! The record carries the digest the binary is checked against, so **the record is the trust
//! anchor**, and its integrity rests on TLS to `github.com` plus GitHub itself — the same
//! posture as every `curl | sh` installer, and on macOS it is backed a second time by
//! Gatekeeper, which checks the Developer ID signature vox's releases carry. There is no
//! independent release signature yet; that gap is recorded in ADR-015.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::app::AppError;

/// The repository releases are published from.
const REPO: &str = "robertelee78/vox";

/// Record identity. A file that does not say exactly this is not a vox release record.
const RECORD_KIND: &str = "vox.standalone-release";
/// The record schema this binary understands.
const RECORD_SCHEMA: u64 = 1;

/// The installed binary's file name inside the install directory.
const ACTIVE: &str = "vox";
/// The marker written beside the binary by `install.sh` and kept by a successful update.
///
/// Its **presence** is what distinguishes an install this tooling made from a build the user
/// made, and its **first line** names the release channel this install follows — the record it
/// looks up is `<channel>-<triple>.json`. `install.sh` writes `stable`.
const MARKER: &str = ".vox-channel";
/// The channel an install follows when its marker does not name one.
const DEFAULT_CHANNEL: &str = "stable";
/// The previous binary, kept for `--rollback`.
const PREVIOUS: &str = ".vox-previous";
/// The in-flight download, beside the destination so the final rename is atomic.
const CANDIDATE: &str = ".vox-candidate.partial";
/// The rollback's scratch name — distinct from [`CANDIDATE`] so a rollback can never collide
/// with a download that was interrupted.
const ROLLBACK_SCRATCH: &str = ".vox-rollback.partial";

/// The largest release record we will read. A record for one target is ~200 bytes.
const MAX_RECORD_BYTES: u64 = 4096;

/// Origins a release download may legitimately come from. Anything else aborts.
const ALLOWED_ORIGINS: &[&str] = &[
    "https://github.com/",
    "https://release-assets.githubusercontent.com/",
    "https://objects.githubusercontent.com/",
];

/// How the running binary got here — which decides what `update` is allowed to do.
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
#[must_use]
pub fn detect_channel(exe: &Path) -> Channel {
    let exe = fs::canonicalize(exe).unwrap_or_else(|_| exe.to_path_buf());
    if let Some(dir) = exe.parent() {
        let marker = dir.join(MARKER);
        if marker.is_file() {
            return Channel::Standalone {
                install_dir: dir.to_path_buf(),
                channel: read_channel(&marker),
            };
        }
    }
    let s = exe.to_string_lossy();
    if s.contains("/target/debug/") || s.contains("/target/release/") || s.contains("/target/deps/")
    {
        return Channel::Source { exe };
    }
    Channel::Unmanaged { exe }
}

/// The channel named by a marker file's first line.
///
/// A marker that is empty, unreadable, or names something that is not a plain channel token
/// falls back to `stable` rather than refusing: the marker's job is to say "this install is
/// ours", and an install that cannot state a channel still follows the default one.
fn read_channel(marker: &Path) -> String {
    let raw = fs::read_to_string(marker).unwrap_or_default();
    let name = raw.lines().next().unwrap_or_default().trim();
    if !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        name.to_owned()
    } else {
        DEFAULT_CHANNEL.to_owned()
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

/// `stable-<triple>.json`, as the release workflow writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Record kind — MUST be `vox.standalone-release`.
    pub kind: String,
    /// Record schema — MUST be `1`.
    pub schema_version: u64,
    /// Package name — MUST be `vox`.
    pub package: String,
    /// Release channel — MUST be `stable`.
    pub channel: String,
    /// Target triple — MUST be the one asked for.
    pub target: String,
    /// The released version, which also names the tag (`v<version>`).
    pub version: String,
    /// Exact byte length of the binary.
    pub size: u64,
    /// Lowercase hex SHA-256 of the binary.
    pub sha256: String,
}

/// Pull one scalar field out of the record.
///
/// This is a deliberately minimal extractor, not a JSON parser, because the record is a flat
/// object of eight scalars written by our own release workflow — a JSON dependency in the
/// shipped binary buys nothing here. What `deny_unknown_fields` would have bought is bought
/// instead by [`Record::parse`]'s identity checks: a file that does not name this kind, this
/// schema, this package, this channel and this target is rejected before any other field of it
/// is used.
fn field(json: &str, name: &str) -> Option<String> {
    let key = format!("\"{name}\":");
    let rest = json.split_once(&key)?.1.trim_start();
    match rest.chars().next()? {
        '"' => {
            let val: String = rest[1..].chars().take_while(|c| *c != '"').collect();
            (!val.is_empty()).then_some(val)
        }
        c if c.is_ascii_digit() => {
            let val: String = rest.chars().take_while(char::is_ascii_digit).collect();
            (!val.is_empty()).then_some(val)
        }
        _ => None,
    }
}

impl Record {
    /// Parse and validate a record for `channel` and `target`.
    ///
    /// # Errors
    /// [`AppError::Usage`] if a field is missing or malformed, or if the record's identity is
    /// not `vox` / `channel` / `target` at the schema this binary understands.
    pub fn parse(json: &str, channel: &str, target: &str) -> Result<Self, AppError> {
        if json.len() as u64 > MAX_RECORD_BYTES {
            return Err(AppError::Usage(
                "release record is implausibly large".into(),
            ));
        }
        let get = |n: &str| {
            field(json, n).ok_or_else(|| AppError::Usage(format!("release record has no {n}")))
        };
        let num = |n: &str| -> Result<u64, AppError> {
            get(n)?
                .parse()
                .map_err(|_| AppError::Usage(format!("release record {n} is not a number")))
        };
        let rec = Self {
            kind: get("kind")?,
            schema_version: num("schema_version")?,
            package: get("package")?,
            channel: get("channel")?,
            target: get("target")?,
            version: get("version")?,
            size: num("size")?,
            sha256: get("sha256")?,
        };
        if rec.kind != RECORD_KIND
            || rec.schema_version != RECORD_SCHEMA
            || rec.package != "vox"
            || rec.channel != channel
        {
            return Err(AppError::Usage(format!(
                "release record identity is not vox/{channel}/schema {RECORD_SCHEMA} \
                 (kind={} schema={} package={} channel={})",
                rec.kind, rec.schema_version, rec.package, rec.channel
            )));
        }
        if rec.target != target {
            return Err(AppError::Usage(format!(
                "release record is for {} but this binary is {target}",
                rec.target
            )));
        }
        if rec.size == 0 {
            return Err(AppError::Usage("release record size is zero".into()));
        }
        if rec.sha256.len() != 64 || !rec.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AppError::Usage(
                "release record sha256 is not 64 hex characters".into(),
            ));
        }
        // The version goes into a URL path as the tag name, so keep it to tag characters.
        if !rec
            .version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+')
        {
            return Err(AppError::Usage(
                "release record version has characters a tag cannot hold".into(),
            ));
        }
        Ok(rec)
    }
}

/// Split a dotted version into `(major, minor, patch, is_prerelease)`.
///
/// Hand-rolled rather than depending on a SemVer crate: vox's versions are `major.minor.patch`
/// with an optional `-pre` suffix, and comparing three integers is not worth a dependency. A
/// pre-release sorts **below** the same release, which is what makes `0.2.0-rc.1` not an
/// update over `0.2.0`.
fn version_parts(v: &str) -> (u64, u64, u64, bool) {
    let (core, pre) = v.split_once('-').map_or((v, false), |(c, _)| (c, true));
    let mut it = core.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        pre,
    )
}

/// Whether `candidate` is a newer release than `current`.
#[must_use]
pub fn is_newer(candidate: &str, current: &str) -> bool {
    let (a1, a2, a3, a_pre) = version_parts(candidate);
    let (b1, b2, b3, b_pre) = version_parts(current);
    match (a1, a2, a3).cmp(&(b1, b2, b3)) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        // Same numbers: the release supersedes a pre-release of itself, nothing else is newer.
        std::cmp::Ordering::Equal => b_pre && !a_pre,
    }
}

/// Move bytes from `url` into `out`, bounded by `max_bytes`, and return the effective URL the
/// bytes actually came from.
///
/// `--fail` and the independent status check are both required — see the module docs.
fn fetch(url: &str, out: &Path, max_bytes: u64, what: &str) -> Result<String, AppError> {
    let result = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--connect-timeout",
            "10",
            "--max-time",
            "600",
            "--max-filesize",
            &max_bytes.to_string(),
            "--write-out",
            "%{http_code} %{url_effective}",
            "--output",
        ])
        .arg(out)
        .arg(url)
        .output()
        .map_err(|e| AppError::Usage(format!("curl could not be run ({e}) — is it installed?")))?;

    let written = String::from_utf8_lossy(&result.stdout);
    let (code, final_url) = written
        .trim()
        .split_once(' ')
        .map_or((0u16, String::new()), |(c, u)| {
            (c.parse().unwrap_or(0), u.to_owned())
        });

    if !result.status.success() {
        let _ = fs::remove_file(out);
        let why = String::from_utf8_lossy(&result.stderr).trim().to_owned();
        // A 404 is the ordinary "there is no release for this target yet", and saying so beats
        // relaying curl's wording for it.
        if code == 404 {
            return Err(AppError::Usage(format!(
                "{what} is not published (http 404)"
            )));
        }
        return Err(AppError::Usage(if code == 0 {
            format!("download failed: {why}")
        } else {
            format!("download failed (http {code}): {why}")
        }));
    }
    // Belt and braces: `--fail` should have caught a non-2xx, but the status is the authority
    // and the exit code is overloaded.
    if !(200..300).contains(&code) {
        let _ = fs::remove_file(out);
        return Err(AppError::Usage(format!("download returned http {code}")));
    }
    if !ALLOWED_ORIGINS.iter().any(|o| final_url.starts_with(o)) {
        let _ = fs::remove_file(out);
        return Err(AppError::Usage(format!(
            "download redirected off GitHub, refusing: {final_url}"
        )));
    }
    Ok(final_url)
}

/// `(sha256_hex, byte_length)` of a file.
fn sha256_file(path: &Path) -> Result<(String, u64), AppError> {
    let bytes = fs::read(path).map_err(AppError::Io)?;
    let digest = Sha256::digest(&bytes);
    let hex = digest.iter().fold(String::with_capacity(64), |mut s, b| {
        use core::fmt::Write as _;
        // Writing to a String cannot fail; the Result is discarded deliberately, because the
        // crate forbids `unwrap`/`expect` and there is nothing to report.
        let _ = write!(s, "{b:02x}");
        s
    });
    Ok((hex, bytes.len() as u64))
}

fn sync_dir(dir: &Path) -> Result<(), AppError> {
    fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(AppError::Io)
}

/// Fetch and validate the newest release record for `channel` and this target.
///
/// # Errors
/// [`AppError::Usage`] if the platform has no release, the transfer fails or is redirected off
/// GitHub, or the record does not validate.
pub fn latest_record(channel: &str) -> Result<Record, AppError> {
    let target = target_triple();
    if target == "unsupported" {
        return Err(AppError::Usage(
            "this platform has no vox release (ADR-015 ships x86_64 Linux and both macOS \
             architectures)"
                .into(),
        ));
    }
    let tmp = tempfile::tempdir().map_err(AppError::Io)?;
    let path = tmp.path().join("record.json");
    let name = format!("{channel}-{target}.json");
    let url = format!("https://github.com/{REPO}/releases/latest/download/{name}");
    fetch(
        &url,
        &path,
        MAX_RECORD_BYTES,
        &format!("the {channel} release record for {target} ({name})"),
    )?;
    let json = fs::read_to_string(&path).map_err(AppError::Io)?;
    Record::parse(&json, channel, target)
}

/// `vox update [--check] [--rollback]`.
///
/// # Errors
/// [`AppError::Usage`] with a reason for the person: no release for this platform, a transfer
/// or verification failure, or an install this tooling does not own.
pub fn run(check_only: bool, rollback: bool) -> Result<(), AppError> {
    let exe = std::env::current_exe()
        .map_err(|e| AppError::Usage(format!("cannot locate the running binary: {e}")))?;
    let installed = detect_channel(&exe);

    if rollback {
        let (install_dir, _) = owned(installed, "`vox update --rollback` will not touch it")?;
        return do_rollback(install_dir);
    }

    // The channel comes from the install's marker; a binary this tooling does not own still
    // gets to *ask* what the default channel currently holds, which is what `--check` is for.
    let channel = match &installed {
        Channel::Standalone { channel, .. } => channel.clone(),
        Channel::Source { .. } | Channel::Unmanaged { .. } => DEFAULT_CHANNEL.to_owned(),
    };

    let current = env!("CARGO_PKG_VERSION");
    let record = latest_record(&channel)?;
    if !is_newer(&record.version, current) {
        println!(
            "vox {current} is current (the newest {channel} release is {})",
            record.version
        );
        return Ok(());
    }
    println!(
        "vox {} is available on {channel} (this is {current})",
        record.version
    );
    if check_only {
        return Ok(());
    }

    // Only an install this tooling made is replaced in place. A source build is the
    // developer's own artifact and overwriting it would destroy work.
    let (install_dir, _) = owned(installed, "`vox update` will not replace it")?;
    let active = install_dir.join(ACTIVE);
    if !active.is_file() {
        return Err(AppError::Usage(format!(
            "{} has the install marker but no `{ACTIVE}` binary",
            install_dir.display()
        )));
    }

    let candidate = install_dir.join(CANDIDATE);
    let url = format!(
        "https://github.com/{REPO}/releases/download/v{}/vox-{}",
        record.version, record.target
    );
    let from = fetch(
        &url,
        &candidate,
        record.size,
        &format!("vox {} for {}", record.version, record.target),
    )?;

    // Verify everything before anything moves.
    let (digest, size) = sha256_file(&candidate)?;
    if size != record.size || digest != record.sha256 {
        let _ = fs::remove_file(&candidate);
        return Err(AppError::Usage(format!(
            "the download does not match the release record \
             (record {} bytes / {}…, download {size} bytes / {}…)",
            record.size,
            &record.sha256[..16],
            &digest[..16.min(digest.len())]
        )));
    }
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o755)).map_err(AppError::Io)?;

    // Publish. The previous binary is *copied* before the rename, so a crash anywhere in here
    // leaves a runnable `vox` — either the old one or the new one, never a partial file.
    let previous = install_dir.join(PREVIOUS);
    fs::copy(&active, &previous).map_err(AppError::Io)?;
    fs::rename(&candidate, &active).map_err(AppError::Io)?;
    sync_dir(&install_dir)?;

    // Re-verify what is now active, and put the previous one back if it is not what the record
    // described.
    let (d2, s2) = sha256_file(&active)?;
    if s2 != record.size || d2 != record.sha256 {
        let _ = fs::copy(&previous, &active);
        return Err(AppError::Usage(
            "the published binary failed re-verification; the previous one was restored".into(),
        ));
    }
    let reported = binary_version(&active);
    if reported.as_deref() != Some(record.version.as_str()) {
        let _ = fs::copy(&previous, &active);
        return Err(AppError::Usage(format!(
            "the published binary reports version {} but the record said {} — the previous one \
             was restored",
            reported.unwrap_or_else(|| "nothing".into()),
            record.version
        )));
    }

    println!("updated: {} -> {}", active.display(), record.version);
    println!("         from {from}");
    println!("         previous kept at {}", previous.display());
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
        Channel::Source { exe } => Err(AppError::Usage(format!(
            "{} is a build from source, so {what}.\n       \
             Update it the way you built it:  git pull && cargo build --release",
            exe.display()
        ))),
        Channel::Unmanaged { exe } => Err(AppError::Usage(format!(
            "{} was not installed by vox's installer (no {MARKER} beside it), so {what}.\n       \
             To get a self-updating install:  \
             curl -fsSL https://raw.githubusercontent.com/{REPO}/main/install.sh | sh",
            exe.display()
        ))),
    }
}

/// Swap the active binary and `.vox-previous`, so a rollback is itself reversible.
fn do_rollback(install_dir: PathBuf) -> Result<(), AppError> {
    let active = install_dir.join(ACTIVE);
    let previous = install_dir.join(PREVIOUS);
    if !previous.is_file() {
        return Err(AppError::Usage(format!(
            "no previous vox was retained in {} — nothing to roll back to",
            install_dir.display()
        )));
    }
    let scratch = install_dir.join(ROLLBACK_SCRATCH);
    fs::copy(&active, &scratch).map_err(AppError::Io)?;
    fs::rename(&previous, &active).map_err(AppError::Io)?;
    fs::rename(&scratch, &previous).map_err(AppError::Io)?;
    sync_dir(&install_dir)?;
    println!(
        "rolled back: {} -> {}",
        active.display(),
        binary_version(&active).unwrap_or_else(|| "unknown".into())
    );
    run_shell_setup(&active);
    Ok(())
}

/// What `vox --version` on `path` reports, as a bare version string.
fn binary_version(path: &Path) -> Option<String> {
    let out = Command::new(path).arg("--version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.split_whitespace().nth(1).map(str::to_owned)
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
// that does not verify". `tests/update_proof.rs` measures exactly that: it fetches the real
// record from GitHub over the real network, builds a fake install directory with a marker and
// a real `vox` binary in it, and drives `vox update` through the shipped CLI — including the
// cases that must refuse (a source build, a tampered candidate, a record for another target).
