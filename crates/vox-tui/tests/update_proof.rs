//! Proof: `vox update` replaces a vox this tooling installed with the release GitHub is
//! serving, and refuses everything else.
//!
//! That sentence is the feature, so it is what gets measured — through the shipped `vox`
//! binary, against the real `github.com`, with real install directories on disk. Nothing here
//! calls a helper directly.
//!
//! ## What blocks, and what is opt-in
//! [`vox_update_replaces_an_install_it_owns_and_refuses_the_rest`] measures this build: its
//! refusals, the record lookup, `--check`, and `--rollback`. It blocks.
//!
//! [`an_older_release_updates_itself_and_refuses_a_bad_download`] downloads the **published**
//! previous release and runs *its* `vox update` — the journey a person takes, but measuring an
//! artifact this tree cannot change. It is an optional proof (docs/release/optional-proofs.md):
//! it is compiled only with vox-tui's `optional-proofs` feature, and without it a stand-in of the
//! same name says `OPTIONAL PROOF NOT RUN`. It blocks nothing, and it accepts no gap.
//!
//! On macOS it also measures a Vox.app install (ADR-014 M-29): `vox update` replaces the whole
//! bundle, from a loopback release this proof serves, and `--rollback` restores the whole previous
//! one. `vox update` fetches only from GitHub in a build a person installs; the loopback release
//! is reached through `VOX_TEST_RELEASE_BASE`, which only a `test-knobs` build reads, so that part
//! needs `--features vox-tui/test-knobs` and says CANNOT MEASURE without it.
//!
//! A red says which side it is on: `PRODUCT:` for a claim `vox` failed, quoting what it said;
//! `CANNOT MEASURE:` for a claim the world could not be asked (GitHub unreachable, nothing
//! published to update from), and `APPARATUS:` for the proof's own I/O failing. For the blocking
//! test, `VOX_PROOF_ALLOW_UNPROVEN=<id-or-prefix>[,…]` accepts a named CANNOT MEASURE gap; the
//! optional one reads no such variable.

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/optional_proof.rs"]
mod optional_proof;

// This proof counts no requests; `install_sh_proof` does.
#[cfg(target_os = "macos")]
#[allow(dead_code)]
#[path = "support/release_server.rs"]
mod release_server;

#[cfg(target_os = "macos")]
#[path = "support/test_knobs.rs"]
mod test_knobs;
optional_proof::not_run!(an_older_release_updates_itself_and_refuses_a_bad_download);

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The binary under proof: the one cargo just built.
const VOX: &str = env!("CARGO_BIN_EXE_vox");
/// The version that binary reports, and so the version the record is compared against.
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The repository `update.rs` fetches from. Kept in step with it by the `record` claims: a
/// divergence shows up as a 404 for an asset name nobody publishes.
const REPO: &str = "robertelee78/vox";

/// One question put to the real world, and what it answered.
struct Claim {
    id: String,
    status: &'static str,
    detail: String,
}

fn claim(id: &str, ok: bool, detail: impl Into<String>) -> Claim {
    Claim {
        id: id.to_owned(),
        status: if ok { "pass" } else { "fail" },
        detail: detail.into(),
    }
}

fn blocked(id: &str, detail: impl Into<String>) -> Claim {
    Claim {
        id: id.to_owned(),
        status: "blocked",
        detail: detail.into(),
    }
}

/// Everything a child `vox` said, joined, so a claim can look for one string.
fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Run a `vox` with a private `$HOME`, so nothing here can touch the developer's own dotfiles
/// — `vox update` runs `vox shell-setup` on success, and that edits a startup file.
fn vox(bin: &Path, home: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("SHELL", "/bin/zsh")
        .env("TERM", "dumb");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not run {}: {e}", bin.display()))
}

/// A temporary directory, or an apparatus failure.
fn tmpdir() -> tempfile::TempDir {
    tempfile::tempdir().expect("APPARATUS: could not make a temporary directory")
}

/// Mark `path` executable, or fail as the apparatus.
fn make_executable(path: &Path) {
    let mut p = std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("APPARATUS: could not stat {}: {e}", path.display()))
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut p, 0o755);
    std::fs::set_permissions(path, p)
        .unwrap_or_else(|e| panic!("APPARATUS: could not chmod {}: {e}", path.display()));
}

/// Write `body` to `path`, or fail as the apparatus.
fn write(path: &Path, body: &str) {
    std::fs::write(path, body)
        .unwrap_or_else(|e| panic!("APPARATUS: could not write {}: {e}", path.display()));
}

/// Copy `from` to `to`, or fail as the apparatus.
fn copy(from: &Path, to: &Path) {
    std::fs::copy(from, to).unwrap_or_else(|e| {
        panic!(
            "APPARATUS: could not copy {} to {}: {e}",
            from.display(),
            to.display()
        )
    });
}

/// A directory that looks exactly like an install `install.sh` made: a real `vox`, and a marker
/// naming `channel`.
fn install_dir(root: &Path, channel: &str) -> PathBuf {
    let dir = root.join("bin");
    std::fs::create_dir_all(&dir)
        .unwrap_or_else(|e| panic!("APPARATUS: could not make {}: {e}", dir.display()));
    copy(Path::new(VOX), &dir.join("vox"));
    write(&dir.join(".vox-standalone.json"), &marker_json(channel));
    dir
}

/// The install marker `install.sh` writes: strict schema-1 JSON naming the channel.
fn marker_json(channel: &str) -> String {
    format!(
        "{{\"kind\":\"vox.install-channel\",\"schema_version\":1,\"package\":\"vox\",\
         \"channel\":\"{channel}\"}}\n"
    )
}

/// A stand-in for "the vox you had before the update": an executable that answers `--version`
/// the way an older release would. A *copy* of the real binary would be indistinguishable from
/// the new one, so the swap could not be observed; tampering with the real binary's bytes would
/// invalidate the code signature macOS requires. A script is both runnable and distinguishable.
fn previous_stub(path: &Path, version: &str) {
    write(path, &format!("#!/bin/sh\necho \"vox {version}\"\n"));
    make_executable(path);
}

/// A stable fingerprint of a directory: every entry's name and length. Used to prove `--check`
/// changed nothing.
fn snapshot(dir: &Path) -> BTreeMap<String, u64> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("APPARATUS: could not list {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                e.metadata().map(|m| m.len()).unwrap_or_default(),
            )
        })
        .collect()
}

fn target_triple() -> &'static str {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-gnu"
    } else {
        "unsupported"
    }
}

/// `(exit_ok, http_status)` for one `curl --fail` against a real URL. An empty or `000` status
/// means curl reached nothing: the network, not the release.
fn curl_probe(url: &str, out: &Path) -> (bool, String) {
    let mut cmd = Command::new("curl");
    cmd.args([
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
        "60",
        "--write-out",
        "%{http_code}",
        "--output",
    ])
    .arg(out)
    .arg(url);
    let o = cmd
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not run curl: {e}"));
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).trim().to_owned(),
    )
}

/// Whether curl's status says it reached nothing at all.
fn unreachable(code: &str) -> bool {
    code.is_empty() || code == "000"
}

/// Whether `github.com` answers at all, asked for an asset nobody publishes: `Err` names why not.
fn github_reachable() -> Result<(), String> {
    let tmp = tmpdir();
    let url = format!(
        "https://github.com/{REPO}/releases/latest/download/no-such-asset-{}.json",
        std::process::id()
    );
    let (_, code) = curl_probe(&url, &tmp.path().join("probe"));
    if unreachable(&code) {
        Err(format!("curl reached nothing at {url} (http {code:?})"))
    } else {
        Ok(())
    }
}

/// The version `stable` is serving for this target, straight from the release record. `Err`
/// says why there is none: the network, or nothing published.
#[cfg(feature = "optional-proofs")]
fn published_version(triple: &str) -> Result<String, String> {
    let tmp = tmpdir();
    let out = tmp.path().join("record.json");
    let url = format!("https://github.com/{REPO}/releases/latest/download/stable-{triple}.json");
    let (ok, code) = curl_probe(&url, &out);
    if unreachable(&code) {
        return Err(format!("curl reached nothing at {url} (http {code:?})"));
    }
    if !ok {
        return Err(format!(
            "no stable release is published (http {code} for {url}), so there is nothing to \
             update from"
        ));
    }
    let json = std::fs::read_to_string(&out).unwrap_or_default();
    json.split_once("\"version\":\"")
        .map(|(_, rest)| rest.chars().take_while(|c| *c != '"').collect::<String>())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("the stable record names no version: {json:?}"))
}

/// The version of the newest release *other than* `newest` that carries our asset, if GitHub
/// will say. `gh` is the only thing that can list releases without an asset name to guess at;
/// when it is absent or unauthenticated the journey claim is reported unproven, not skipped.
#[cfg(feature = "optional-proofs")]
fn earlier_release(newest: &str) -> Result<String, String> {
    let asset = format!("vox-{}", target_triple());
    // gh's login is the operator's, not the proof's temporary HOME's (see `watchdog::temp_home`).
    let out = watchdog::temp_home::real_gh(&mut Command::new("gh"))
        .args([
            "api",
            "--paginate",
            &format!("repos/{REPO}/releases"),
            "--jq",
            &format!(
                ".[] | select(.draft == false) | select([.assets[].name] | index(\"{asset}\")) \
                 | .tag_name"
            ),
        ])
        .output()
        .map_err(|e| format!("gh could not be run ({e}); it is what lists releases"))?;
    if !out.status.success() {
        return Err(format!(
            "gh could not list releases: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let tags: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().trim_start_matches('v').to_owned())
        .filter(|l| !l.is_empty())
        .collect();
    tags.into_iter()
        .find(|t| t != newest)
        .ok_or_else(|| format!("only one release carries {asset}; there is nothing to update from"))
}

/// The first release whose updater can run on Linux at all.
///
/// `v0.1.0` and `v0.2.0` execute the downloaded candidate to read its `--version` while
/// still holding it open for writing, and Linux returns `ETXTBSY` from `execve` on a file
/// with an open writable descriptor. Every `vox update` on those builds dies there.
#[cfg(feature = "optional-proofs")]
const FIRST_WORKING_LINUX_UPDATER: &str = "0.2.1";

/// Whether `older`'s **own** updater is known to be incapable of updating on this platform.
///
/// This exists because `journey.update_replaces_an_older_install` drives a **published
/// binary**, not this tree: it downloads `v<older>` and runs *its* `vox update`. When that
/// artifact carries a defect, no change to this repository can make the claim pass, and the
/// gate would block for ever the very release that fixes it — including on the release run
/// that first found the defect, which is exactly what happened.
///
/// It is reported **blocked**, never passed. Twice in one week a blocked claim here turned
/// out to be hiding a live defect, so the bar for adding one is: the cause must be known,
/// fixed in this tree, named in the reason with the versions involved, and the condition
/// must **clear itself** — which this does, as soon as the newest release other than the
/// current one carries the fix. It narrows to nothing rather than being renewed.
#[cfg(feature = "optional-proofs")]
fn updater_is_broken_on_this_platform(older: &str) -> bool {
    if cfg!(target_os = "macos") {
        return false; // macOS takes the Developer ID path and never executes the candidate.
    }
    match (
        semver::Version::parse(older),
        semver::Version::parse(FIRST_WORKING_LINUX_UPDATER),
    ) {
        (Ok(o), Ok(fixed)) => o < fixed,
        _ => false,
    }
}

/// The `VOX_PROOF_ALLOW_UNPROVEN` gaps accepted for this run.
fn allowed_gaps() -> Vec<String> {
    std::env::var("VOX_PROOF_ALLOW_UNPROVEN")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Print every claim and receipt, then fail: `PRODUCT:` for a claim `vox` failed, and
/// `CANNOT MEASURE:` for a claim the world could not be asked, unless that gap is accepted
/// (only where `accept_gaps`: an optional proof accepts none).
fn dispose(title: &str, claims: &[Claim], receipts: &BTreeMap<String, String>, accept_gaps: bool) {
    let allowed = if accept_gaps {
        allowed_gaps()
    } else {
        Vec::new()
    };
    println!("\n--- {title} ---");
    for c in claims {
        println!("  [{}] {} — {}", c.status, c.id, c.detail);
    }
    for (k, v) in receipts {
        println!("  receipt {k}:\n{v}");
    }

    let failed: Vec<&Claim> = claims.iter().filter(|c| c.status == "fail").collect();
    let unproven: Vec<&Claim> = claims
        .iter()
        .filter(|c| c.status == "blocked")
        .filter(|c| {
            !allowed
                .iter()
                .any(|a| c.id == *a || c.id.split('.').next().is_some_and(|seg| seg == a.as_str()))
        })
        .collect();
    let list = |cs: &[&Claim]| {
        cs.iter()
            .map(|c| format!("  {} — {}", c.id, c.detail))
            .collect::<Vec<_>>()
            .join("\n")
    };

    assert!(
        failed.is_empty(),
        "PRODUCT: {} claim(s) failed:\n{}",
        failed.len(),
        list(&failed)
    );
    assert!(
        unproven.is_empty(),
        "APPARATUS, CANNOT MEASURE: {} claim(s) unproven — close the gap, or name it in \
         VOX_PROOF_ALLOW_UNPROVEN to accept it deliberately:\n{}",
        unproven.len(),
        list(&unproven)
    );
}

/// `vox --version` as the binary at `path` answers it, or empty if it cannot be run.
fn reports(path: &Path) -> String {
    Command::new(path)
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}

#[test]
fn vox_update_replaces_an_install_it_owns_and_refuses_the_rest() {
    watchdog::arm();
    let mut claims: Vec<Claim> = Vec::new();
    let mut receipts: BTreeMap<String, String> = BTreeMap::new();
    let triple = target_triple();

    // ---- refusals: a binary this tooling does not own is never touched ------------------
    {
        let tmp = tmpdir();
        // The cargo build itself, under target/debug — the developer's own artifact.
        let out = vox(Path::new(VOX), tmp.path(), &["update", "--rollback"], &[]);
        let text = said(&out);
        claims.push(claim(
            "refuse.source_build",
            !out.status.success()
                && text.contains("build from source")
                && text.contains("cargo build --release"),
            format!("`{VOX} update --rollback` said {text:?}"),
        ));
        receipts.insert("refuse.source_build".into(), text);
    }
    {
        let tmp = tmpdir();
        let loose = tmp.path().join("vox");
        copy(Path::new(VOX), &loose);
        let out = vox(&loose, tmp.path(), &["update", "--rollback"], &[]);
        let text = said(&out);
        claims.push(claim(
            "refuse.unmanaged_copy",
            !out.status.success()
                && text.contains(".vox-standalone.json")
                && text.contains("install.sh"),
            format!("a bare copy said {text:?}"),
        ));
        receipts.insert("refuse.unmanaged_copy".into(), text);
    }

    // ---- the record lookup: the marker names the channel, and a 404 never parses --------
    // Both ask the real `github.com`. When curl reaches nothing there, what `vox` says measures
    // the network, so the claims are CANNOT MEASURE rather than judged.
    let network = github_reachable();
    {
        let tmp = tmpdir();
        let dir = install_dir(tmp.path(), "proof-channel");
        let out = vox(&dir.join("vox"), tmp.path(), &["update", "--check"], &[]);
        let text = said(&out);
        claims.push(match &network {
            Err(why) => blocked("channel.marker_names_the_record", why.clone()),
            Ok(()) => claim(
                "channel.marker_names_the_record",
                text.contains(&format!("proof-channel-{triple}.json")),
                format!("a marker saying `proof-channel` looked up {text:?}"),
            ),
        });
        receipts.insert("channel.marker_names_the_record".into(), text);
    }
    {
        let tmp = tmpdir();
        let dir = install_dir(tmp.path(), "stable");
        let before = snapshot(&dir);
        let out = vox(&dir.join("vox"), tmp.path(), &["update", "--check"], &[]);
        let text = said(&out);

        // Either there is a stable release and vox compared versions, or there is not and vox
        // refused. What it must never do is exit 0 having read an error page as a record.
        let compared = text.contains("is current") || text.contains("is available");
        let refused = !out.status.success() && text.contains(&format!("stable-{triple}.json"));
        claims.push(match &network {
            Err(why) => blocked("record.404_never_reads_as_a_release", why.clone()),
            Ok(()) => claim(
                "record.404_never_reads_as_a_release",
                (compared || refused)
                    && !text.contains("Not Found")
                    && (out.status.success() == compared),
                format!(
                    "`vox update --check` on stable said {text:?} (exit_ok={})",
                    out.status.success()
                ),
            ),
        });
        claims.push(claim(
            "check.changes_nothing",
            snapshot(&dir) == before,
            format!("the install directory is {:?}", snapshot(&dir)),
        ));
        receipts.insert("record.stable_check".into(), text.clone());
    }

    // ---- rollback: the binary you had comes back ----------------------------------------
    {
        let tmp = tmpdir();
        let dir = install_dir(tmp.path(), "stable");
        previous_stub(&dir.join(".vox-previous"), "0.0.1-previous");
        let out = vox(&dir.join("vox"), tmp.path(), &["update", "--rollback"], &[]);
        let text = said(&out);
        let now = reports(&dir.join("vox"));
        let kept = reports(&dir.join(".vox-previous"));
        claims.push(claim(
            "rollback.restores_the_previous_binary",
            out.status.success() && now == "vox 0.0.1-previous" && kept.contains(VERSION),
            format!(
                "after --rollback (which said {text:?}): active reports {now:?}, .vox-previous \
                 reports {kept:?}"
            ),
        ));
        receipts.insert("rollback.restores_the_previous_binary".into(), text);
    }
    {
        let tmp = tmpdir();
        let dir = install_dir(tmp.path(), "stable");
        let out = vox(&dir.join("vox"), tmp.path(), &["update", "--rollback"], &[]);
        let text = said(&out);
        claims.push(claim(
            "rollback.refuses_without_a_previous",
            !out.status.success() && text.contains("nothing to roll back to"),
            format!("an install with no .vox-previous said {text:?}"),
        ));
    }

    // ---- the update -> shell-setup edge -------------------------------------------------
    {
        let tmp = tmpdir();
        let home = tmp.path();
        let dir = install_dir(home, "stable");
        copy(Path::new(VOX), &dir.join(".vox-previous"));
        write(&home.join(".zshrc"), "export VOX_PROOF_USER_LINE=kept\n");
        let out = vox(&dir.join("vox"), home, &["update", "--rollback"], &[]);
        let rc = std::fs::read_to_string(home.join(".zshrc")).unwrap_or_default();
        claims.push(claim(
            "rollback.refreshes_completions",
            out.status.success()
                && rc.contains(">>> vox >>>")
                && rc.contains("VOX_PROOF_USER_LINE=kept"),
            format!(
                "after --rollback (which said {:?}) the rc is {rc:?}",
                said(&out)
            ),
        ));
        receipts.insert("rollback.refreshes_completions".into(), said(&out));
    }
    {
        let tmp = tmpdir();
        let home = tmp.path();
        let dir = install_dir(home, "stable");
        copy(Path::new(VOX), &dir.join(".vox-previous"));
        write(&home.join(".zshrc"), "export VOX_PROOF_USER_LINE=kept\n");
        let out = vox(
            &dir.join("vox"),
            home,
            &["update", "--rollback"],
            &[("VOX_NO_SHELL_SETUP", "1")],
        );
        let rc = std::fs::read_to_string(home.join(".zshrc")).unwrap_or_default();
        claims.push(claim(
            "rollback.honours_the_opt_out",
            out.status.success() && rc == "export VOX_PROOF_USER_LINE=kept\n",
            format!(
                "with VOX_NO_SHELL_SETUP=1, --rollback said {:?} and the rc is {rc:?}",
                said(&out)
            ),
        ));
    }

    #[cfg(target_os = "macos")]
    bundle_claims(&mut claims, &mut receipts);

    dispose("vox update proof", &claims, &receipts, true);
}

/// A version newer than this build's, for the release the bundle is updated to.
#[cfg(target_os = "macos")]
const NEWER: &str = "99.0.0";

/// An executable that answers `--version` as a vox of `version` would: distinguishable from
/// this build where a copy of it would not be, and runnable where tampered bytes would not be.
#[cfg(target_os = "macos")]
fn version_stub(path: &Path, version: &str) {
    previous_stub(path, version);
}

/// A Vox.app at `dir/Vox.app` saying `version`, carrying `helper` at `Contents/Helpers/vox`,
/// ad-hoc signed: a Developer ID signature exists only as output of the release workflow.
#[cfg(target_os = "macos")]
fn app_bundle(dir: &Path, version: &str, helper: &Path) -> PathBuf {
    let app = dir.join("Vox.app");
    let contents = app.join("Contents");
    for sub in ["MacOS", "Helpers"] {
        std::fs::create_dir_all(contents.join(sub))
            .unwrap_or_else(|e| panic!("APPARATUS: could not make {}: {e}", contents.display()));
    }
    copy(Path::new(VOX), &contents.join("MacOS/Vox"));
    copy(helper, &contents.join("Helpers/vox"));
    make_executable(&contents.join("Helpers/vox"));
    write(
        &contents.join("Info.plist"),
        &format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \
             \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\
             <key>CFBundleIdentifier</key><string>us.vox.app</string>\
             <key>CFBundleExecutable</key><string>Vox</string>\
             <key>CFBundlePackageType</key><string>APPL</string>\
             <key>CFBundleShortVersionString</key><string>{version}</string>\
             <key>LSMinimumSystemVersion</key><string>13.0</string>\
             </dict></plist>\n"
        ),
    );
    // Nested code first: a bundle whose helper is unsigned cannot be signed, and a version stub
    // is a script, which carries its signature in an extended attribute.
    for code in [contents.join("Helpers/vox"), app.clone()] {
        let signed = Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-"])
            .arg(&code)
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: could not run codesign: {e}"));
        assert!(
            signed.status.success(),
            "APPARATUS: ad-hoc signing the fixture's {} failed: {}",
            code.display(),
            String::from_utf8_lossy(&signed.stderr)
        );
    }
    app
}

/// What a bundle's Info.plist says its version is, or empty.
#[cfg(target_os = "macos")]
fn app_says(app: &Path) -> String {
    Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :CFBundleShortVersionString"])
        .arg(app.join("Contents/Info.plist"))
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut s, b| {
            use core::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// A release of [`NEWER`] under `root`, laid out as GitHub serves it: one app zip, and per
/// channel vox's record and the app's. A channel's `Some(digest)` overrides its vox record's
/// digest; every channel's app record describes the one zip.
#[cfg(target_os = "macos")]
fn bundle_release(root: &Path, channels: &[(&str, Option<&str>)]) {
    let triple = target_triple();
    let work = tmpdir();
    let helper = work.path().join("vox");
    version_stub(&helper, NEWER);
    let app = app_bundle(work.path(), NEWER, &helper);
    let zip_name = format!("Vox-{NEWER}-{triple}.zip");
    let zip = work.path().join(&zip_name);
    let zipped = Command::new("/usr/bin/ditto")
        .args(["-c", "-k", "--keepParent"])
        .arg(&app)
        .arg(&zip)
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not run ditto: {e}"));
    assert!(
        zipped.status.success(),
        "APPARATUS: zipping the fixture app failed"
    );
    let zip_bytes = std::fs::read(&zip).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
    let helper_bytes = std::fs::read(&helper).unwrap_or_else(|e| panic!("APPARATUS: {e}"));

    let assets = root.join(format!("releases/download/v{NEWER}"));
    let records = root.join("releases/latest/download");
    for d in [&assets, &records] {
        std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
    }
    std::fs::write(assets.join(&zip_name), &zip_bytes).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
    let helper_sha = sha256_hex(&helper_bytes);
    for &(channel, vox_sha) in channels {
        let record = |kind: &str, package: &str, size: usize, sha: &str| {
            format!(
                "{{\"kind\":\"{kind}\",\"schema_version\":1,\"package\":\"{package}\",\
             \"channel\":\"{channel}\",\"target\":\"{triple}\",\"version\":\"{NEWER}\",\
             \"size\":{size},\"sha256\":\"{sha}\"}}\n"
            )
        };
        write(
            &records.join(format!("{channel}-{triple}.json")),
            &record(
                "vox.standalone-release",
                "vox",
                helper_bytes.len(),
                vox_sha.unwrap_or(&helper_sha),
            ),
        );
        write(
            &records.join(format!("app-{channel}-{triple}.json")),
            &record(
                "vox.app-release",
                "Vox.app",
                zip_bytes.len(),
                &sha256_hex(&zip_bytes),
            ),
        );
    }
}

/// An install `install.sh` made: `home/Apps/Vox.app` carrying this build, the marker beside it
/// naming `channel` (none when `None`), and `home/bin/vox` a link into it. Returns the link.
#[cfg(target_os = "macos")]
fn bundle_install(home: &Path, channel: Option<&str>) -> PathBuf {
    let apps = home.join("Apps");
    std::fs::create_dir_all(&apps).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
    app_bundle(&apps, VERSION, Path::new(VOX));
    if let Some(channel) = channel {
        write(&apps.join(".vox-standalone.json"), &marker_json(channel));
    }
    let bin = home.join("bin");
    std::fs::create_dir_all(&bin).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
    std::os::unix::fs::symlink(apps.join("Vox.app/Contents/Helpers/vox"), bin.join("vox"))
        .unwrap_or_else(|e| panic!("APPARATUS: could not link vox: {e}"));
    bin.join("vox")
}

/// ADR-014 M-29: a Vox.app install is updated and rolled back as a whole.
#[cfg(target_os = "macos")]
fn bundle_claims(claims: &mut Vec<Claim>, receipts: &mut BTreeMap<String, String>) {
    test_knobs::require(&[
        "VOX_TEST_RELEASE_BASE",
        "VOX_TEST_APPLE_VERIFY",
        "VOX_TEST_ABORT_AFTER_SWAP",
    ]);
    let tree = tmpdir();
    let zeros = "0".repeat(64);
    bundle_release(tree.path(), &[("stable", None), ("badvox", Some(&zeros))]);
    let server = match release_server::serve(tree.path()) {
        Ok(s) => s,
        Err(why) => {
            for id in [
                "bundle.update_replaces_the_whole_bundle",
                "bundle.update_refuses_a_vox_that_is_not_the_records",
                "bundle.apple_gate_refuses_an_unsigned_app",
            ] {
                claims.push(blocked(id, format!("APPARATUS: the release server: {why}")));
            }
            return;
        }
    };
    let base = [
        ("VOX_TEST_RELEASE_BASE", server.base.as_str()),
        ("VOX_NO_SHELL_SETUP", "1"),
    ];

    // ---- the update: both the CLI and the app are the new version, the old kept whole ----
    {
        let tmp = tmpdir();
        let home = tmp.path();
        let link = bundle_install(home, Some("stable"));
        let apps = home.join("Apps");
        let out = vox(&link, home, &["update"], &base);
        let text = said(&out);
        let cli = reports(&link);
        let app = app_says(&apps.join("Vox.app"));
        let prev_cli = reports(&apps.join(".Vox.app.previous/Contents/Helpers/vox"));
        let prev_app = app_says(&apps.join(".Vox.app.previous"));
        claims.push(claim(
            "bundle.update_replaces_the_whole_bundle",
            out.status.success()
                && cli == format!("vox {NEWER}")
                && app == NEWER
                && prev_cli.contains(VERSION)
                && prev_app == VERSION
                && text.contains("restart Vox and the vox daemon"),
            format!(
                "after `vox update` (exit_ok={}): vox reports {cli:?}, Vox.app says {app:?}; \
                 .Vox.app.previous holds vox {prev_cli:?} and app {prev_app:?}; it said {text:?}",
                out.status.success()
            ),
        ));
        receipts.insert("bundle.update".into(), text);
    }

    // ---- refusals: nothing in the install changes -----------------------------------------
    for (id, channel, extra, want) in [
        (
            "bundle.update_refuses_a_vox_that_is_not_the_records",
            "badvox",
            None,
            format!("is not the vox {NEWER} the release record names"),
        ),
        (
            "bundle.apple_gate_refuses_an_unsigned_app",
            "stable",
            Some(("VOX_TEST_APPLE_VERIFY", "1")),
            "the new Vox.app:".to_owned(),
        ),
    ] {
        let tmp = tmpdir();
        let home = tmp.path();
        let link = bundle_install(home, Some(channel));
        let apps = home.join("Apps");
        let env: Vec<(&str, &str)> = base.iter().copied().chain(extra).collect();
        let out = vox(&link, home, &["update"], &env);
        let text = said(&out);
        let cli = reports(&link);
        let app = app_says(&apps.join("Vox.app"));
        let left: Vec<String> = std::fs::read_dir(&apps)
            .map(|d| {
                d.filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.contains("partial") || n.contains("previous"))
                    .collect()
            })
            .unwrap_or_default();
        claims.push(claim(
            id,
            !out.status.success()
                && text.contains(&want)
                && cli.contains(VERSION)
                && app == VERSION
                && left.is_empty(),
            format!(
                "exit_ok={}, vox still reports {cli:?}, Vox.app says {app:?}, left behind \
                 {left:?}, it said {text:?}",
                out.status.success()
            ),
        ));
    }

    // ---- rollback: the previous bundle comes back whole ------------------------------------
    {
        let tmp = tmpdir();
        let home = tmp.path();
        let link = bundle_install(home, Some("stable"));
        let apps = home.join("Apps");
        let old = tmpdir();
        let stub = old.path().join("vox");
        version_stub(&stub, "0.0.1-previous");
        let previous = app_bundle(old.path(), "0.0.1-previous", &stub);
        std::fs::rename(&previous, apps.join(".Vox.app.previous"))
            .unwrap_or_else(|e| panic!("APPARATUS: could not place the previous bundle: {e}"));
        let out = vox(&link, home, &["update", "--rollback"], &base);
        let text = said(&out);
        let cli = reports(&link);
        let app = app_says(&apps.join("Vox.app"));
        let kept = app_says(&apps.join(".Vox.app.previous"));
        claims.push(claim(
            "bundle.rollback_restores_the_whole_previous_bundle",
            out.status.success()
                && cli == "vox 0.0.1-previous"
                && app == "0.0.1-previous"
                && kept == VERSION,
            format!(
                "after --rollback (it said {text:?}): vox reports {cli:?}, Vox.app says {app:?}, \
                 .Vox.app.previous says {kept:?}"
            ),
        ));
    }

    // ---- an update cut short after its swap keeps the bundle it replaced ----------------------
    // The process is aborted (test-only VOX_TEST_ABORT_AFTER_SWAP) between the swap and the rename
    // that names the replaced bundle `.Vox.app.previous`; the next transition must find it, and
    // `--rollback` bring it back, rather than clearing it as a leftover.
    {
        let tmp = tmpdir();
        let home = tmp.path();
        let link = bundle_install(home, Some("stable"));
        let apps = home.join("Apps");
        let env: Vec<(&str, &str)> = base
            .iter()
            .copied()
            .chain([("VOX_TEST_ABORT_AFTER_SWAP", "1")])
            .collect();
        let cut = vox(&link, home, &["update"], &env);
        let cut_app = app_says(&apps.join("Vox.app"));
        let out = vox(&link, home, &["update", "--rollback"], &base);
        let text = said(&out);
        let app = app_says(&apps.join("Vox.app"));
        let kept = app_says(&apps.join(".Vox.app.previous"));
        claims.push(claim(
            "bundle.a_cut_update_keeps_the_bundle_it_replaced",
            !cut.status.success()
                && cut_app == NEWER
                && out.status.success()
                && app == VERSION
                && kept == NEWER
                && text.contains("an update was cut short"),
            format!(
                "the cut update (exit_ok={}) left Vox.app {cut_app:?}; then --rollback (exit_ok={}) \
                 said {text:?}: Vox.app says {app:?}, .Vox.app.previous says {kept:?}",
                cut.status.success(),
                out.status.success()
            ),
        ));
    }

    // ---- a Vox.app install.sh did not make is not touched (M-29) ---------------------------
    {
        let tmp = tmpdir();
        let home = tmp.path();
        let link = bundle_install(home, None);
        let out = vox(&link, home, &["update", "--rollback"], &base);
        let text = said(&out);
        claims.push(claim(
            "bundle.refuses_an_app_install_sh_did_not_make",
            !out.status.success()
                && text.contains(".vox-standalone.json")
                && text.contains("install.sh"),
            format!("a Vox.app with no marker beside it said {text:?}"),
        ));
    }
    drop(server);
}

/// **Optional** (the `optional-proofs` feature): the published previous release updates itself
/// to the newest, and the same binary refuses a download whose digest does not match its record.
/// Both run a binary GitHub already serves, so they measure that artifact as much as this tree.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "optional: runs the published previous release's `vox update` through GitHub"]
fn an_older_release_updates_itself_and_refuses_a_bad_download() {
    watchdog::arm();
    let mut claims: Vec<Claim> = Vec::new();
    let mut receipts: BTreeMap<String, String> = BTreeMap::new();
    let triple = target_triple();

    match published_version(triple).and_then(|newest| Ok((earlier_release(&newest)?, newest))) {
        Err(why) => {
            claims.push(blocked(
                "journey.update_replaces_an_older_install",
                why.clone(),
            ));
            claims.push(blocked("verify.digest_mismatch_is_refused", why));
        }
        Ok((older, newest)) => {
            // The journey: install the older release, run *its* `vox update`, and require that
            // the binary in that directory afterwards is the newer one.
            let tmp = tmpdir();
            let home = tmp.path();
            let dir = home.join("bin");
            std::fs::create_dir_all(&dir)
                .unwrap_or_else(|e| panic!("APPARATUS: could not make {}: {e}", dir.display()));
            let url = format!("https://github.com/{REPO}/releases/download/v{older}/vox-{triple}");
            let (ok, code) = curl_probe(&url, &dir.join("vox"));
            if !ok {
                let why = format!("v{older}'s binary could not be fetched (http {code:?})");
                claims.push(blocked(
                    "journey.update_replaces_an_older_install",
                    why.clone(),
                ));
                claims.push(blocked("verify.digest_mismatch_is_refused", why));
            } else {
                make_executable(&dir.join("vox"));
                write(&dir.join(".vox-standalone.json"), &marker_json("stable"));

                let out = vox(&dir.join("vox"), home, &["update"], &[]);
                let text = said(&out);
                let after = reports(&dir.join("vox"));
                if updater_is_broken_on_this_platform(&older) {
                    // Not a pass, and not this build's failure: a property of an artifact
                    // that is already published and can never change. See the function.
                    claims.push(blocked(
                        "journey.update_replaces_an_older_install",
                        format!(
                            "v{older} shipped the Linux ETXTBSY updater defect (ADR-015): it \
                             executes its downloaded candidate while still holding it open \
                             for writing, so it can never update itself, and nothing in this \
                             tree can change a published binary. Fixed from v{FIRST_WORKING_LINUX_UPDATER}; \
                             a Linux install at v{older} must be replaced by hand once. Clears \
                             itself once the newest release other than the current one reaches \
                             v{FIRST_WORKING_LINUX_UPDATER}. It said: {text:?}"
                        ),
                    ));
                } else {
                    claims.push(claim(
                        "journey.update_replaces_an_older_install",
                        out.status.success() && after.contains(&newest),
                        format!(
                            "v{older} updated itself (it said {text:?}) and now reports \
                             {after:?} (want {newest})"
                        ),
                    ));
                }
                receipts.insert("journey.update".into(), text);

                // The same older binary, pointed at the `proof` channel, whose record names
                // the real asset with a deliberately wrong digest. Nothing on `stable` can
                // express this, which is why the channel exists.
                let tampered = home.join("bin2");
                std::fs::create_dir_all(&tampered).unwrap_or_else(|e| {
                    panic!("APPARATUS: could not make {}: {e}", tampered.display())
                });
                let (ok2, code2) = curl_probe(&url, &tampered.join("vox"));
                if !ok2 {
                    claims.push(blocked(
                        "verify.digest_mismatch_is_refused",
                        format!("could not stage the older binary again (http {code2:?})"),
                    ));
                } else {
                    make_executable(&tampered.join("vox"));
                    write(
                        &tampered.join(".vox-standalone.json"),
                        &marker_json("proof"),
                    );
                    let out = vox(&tampered.join("vox"), home, &["update"], &[]);
                    let text = said(&out);
                    let still = reports(&tampered.join("vox"));
                    if text.contains("proof-") && text.contains("not published") {
                        claims.push(blocked(
                            "verify.digest_mismatch_is_refused",
                            "the release workflow has not published a `proof` channel record \
                             for this target yet",
                        ));
                    } else {
                        claims.push(claim(
                            "verify.digest_mismatch_is_refused",
                            !out.status.success()
                                && text.contains("does not match the release record")
                                && still.contains(&older),
                            format!(
                                "the proof channel's mismatched record was answered with \
                                 {text:?}, and the binary still reports {still:?}"
                            ),
                        ));
                    }
                }
            }
        }
    }

    dispose("vox update journey (optional)", &claims, &receipts, false);
}
