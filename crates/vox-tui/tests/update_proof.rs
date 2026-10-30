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

#[path = "support/attach.rs"]
mod unlock_staging;

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/optional_proof.rs"]
mod optional_proof;

// This proof counts no requests; `install_sh_proof` does.
#[allow(dead_code)]
#[path = "support/release_server.rs"]
mod release_server;

#[path = "support/test_knobs.rs"]
mod test_knobs;
optional_proof::not_run!(
    an_older_release_updates_itself_and_refuses_a_bad_download,
    an_update_and_rollback_leave_one_launchable_vox,
);

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
    vox_command(bin, home, args, extra_env)
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not run {}: {e}", bin.display()))
}

fn vox_command(bin: &Path, home: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Command {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .env_clear()
        .env("HOME", home)
        .env("VOX_DATA_DIR", home.join("data"))
        .env("VOX_CONFIG_DIR", home.join("config"))
        .env("VOX_PROXY", "127.0.0.1:0")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("SHELL", "/bin/zsh")
        .env("TERM", "dumb");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd
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
    let scratch = tmpdir();
    Command::new(path)
        .arg("--version")
        .env("VOX_DATA_DIR", scratch.path().join("data"))
        .env("VOX_CONFIG_DIR", scratch.path().join("config"))
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
        if cfg!(target_os = "macos") {
            claims.push(claim(
                "check.a_standalone_install_on_a_mac_is_told_about_vox_app",
                text.contains("vox now comes with Vox.app") && text.contains("install.sh"),
                format!("`vox update --check` on a standalone install said {text:?}"),
            ));
        }
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
        for d in [".claude", ".codex", ".config/opencode"] {
            std::fs::create_dir_all(home.join(d)).expect("APPARATUS: harness config directory");
        }
        let out = vox(&dir.join("vox"), home, &["update", "--rollback"], &[]);
        assert_light_hooks(home, &said(&out));
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

/// An executable that answers `--version` as a vox of `version` would, and is this build for
/// everything else: distinguishable from this build where a copy of it would not be, runnable
/// where tampered bytes would not be, and the new release's own `vox agent skill --install` when
/// the update runs it.
#[cfg(target_os = "macos")]
fn version_stub(path: &Path, version: &str) {
    write(
        path,
        &format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo \"vox {version}\"; exit 0; fi\nexec \"{VOX}\" \"$@\"\n"
        ),
    );
    make_executable(path);
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

/// A retained bundle is not an application, but preserves its original plist for rollback.
#[cfg(target_os = "macos")]
fn kept_app_says(app: &Path) -> String {
    if app.join("Contents/Info.plist").exists() {
        return String::new();
    }
    Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :CFBundleShortVersionString"])
        .arg(app.join("Contents/Info.plist.kept"))
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
    let work = tmpdir();
    let helper = work.path().join("vox");
    version_stub(&helper, NEWER);
    bundle_release_of(root, NEWER, &helper, channels);
}

/// [`bundle_release`] of `version`, its app carrying `helper` as its vox.
#[cfg(target_os = "macos")]
fn bundle_release_of(root: &Path, version: &str, helper: &Path, channels: &[(&str, Option<&str>)]) {
    let work = tmpdir();
    let app = app_bundle(work.path(), version, helper);
    bundle_release_app(root, version, &app, channels);
}

/// Serve the exact signed bundle bytes; neither the helper nor the plist is rewritten.
#[cfg(target_os = "macos")]
fn bundle_release_app(root: &Path, version: &str, app: &Path, channels: &[(&str, Option<&str>)]) {
    let triple = target_triple();
    let work = tmpdir();
    let zip_name = format!("Vox-{version}-{triple}.zip");
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
    // Signing changes a Mach-O helper: the release record describes the signed bytes.
    let helper_bytes = std::fs::read(app.join("Contents/Helpers/vox"))
        .unwrap_or_else(|e| panic!("APPARATUS: {e}"));

    let assets = root.join(format!("releases/download/v{version}"));
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
             \"channel\":\"{channel}\",\"target\":\"{triple}\",\"version\":\"{version}\",\
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
                "bundle.update_installs_the_agent_skill_pack",
                "bundle.an_earlier_releases_update_installs_the_agent_skill_pack",
                "bundle.update_refuses_a_vox_that_is_not_the_records",
                "bundle.apple_gate_refuses_an_unsigned_app",
            ] {
                claims.push(blocked(id, format!("APPARATUS: the release server: {why}")));
            }
            return;
        }
    };
    // `vox update` restarts the account's daemon: every run here names a scratch account, where
    // none runs, so no update reaches a real one.
    let no_daemon = tmpdir();
    let no_data = no_daemon.path().join("data");
    let no_config = no_daemon.path().join("config");
    let base = [
        ("VOX_TEST_RELEASE_BASE", server.base.as_str()),
        ("VOX_NO_SHELL_SETUP", "1"),
        (
            "VOX_DATA_DIR",
            no_data.to_str().expect("APPARATUS: a UTF-8 temp path"),
        ),
        (
            "VOX_CONFIG_DIR",
            no_config.to_str().expect("APPARATUS: a UTF-8 temp path"),
        ),
    ];

    // ---- the update: both the CLI and the app are the new version, the old kept whole ----
    {
        let tmp = tmpdir();
        let home = tmp.path();
        let link = bundle_install(home, Some("stable"));
        for d in [".claude", ".codex", ".config/opencode"] {
            std::fs::create_dir_all(home.join(d)).expect("APPARATUS: harness config directory");
        }
        let apps = home.join("Apps");
        let out = vox(&link, home, &["update"], &base);
        let text = said(&out);
        assert_light_hooks(home, &text);
        let cli = reports(&link);
        let app = app_says(&apps.join("Vox.app"));
        let prev_cli = reports(&apps.join(".Vox.app.previous/Contents/Helpers/vox"));
        let prev_app = kept_app_says(&apps.join(".Vox.app.previous"));
        claims.push(claim(
            "bundle.update_replaces_the_whole_bundle",
            out.status.success()
                && cli == format!("vox {NEWER}")
                && app == NEWER
                && prev_cli.contains(VERSION)
                && prev_app == VERSION
                && text.contains("restart Vox to run"),
            format!(
                "after `vox update` (exit_ok={}): vox reports {cli:?}, Vox.app says {app:?}; \
                 .Vox.app.previous holds vox {prev_cli:?} and app {prev_app:?}; it said {text:?}",
                out.status.success()
            ),
        ));
        // **The agent skill pack, refreshed with the CLI** (v0.4.1): the new release installs it
        // where Claude Code reads it.
        let pack = home.join(".claude/skills/vox-agent-comms");
        let entry =
            pack.join("SKILL.md").is_file() && pack.join("references/sessions.md").is_file();
        claims.push(claim(
            "bundle.update_installs_the_agent_skill_pack",
            out.status.success() && entry && text.contains("Claude Code: installed"),
            format!(
                "after `vox update`, {} holds SKILL.md and references/sessions.md: {entry}; it \
                 said {text:?}",
                pack.display()
            ),
        ));
        receipts.insert("bundle.update".into(), text);

        // **An update by an earlier release installs it too** (#586): a release's `vox update`
        // is that release's code, and v0.4.0's runs only `<new vox> shell-setup` on the vox it
        // put in place (v0.4.1's also ran `agent skill --install`). So the new vox's own
        // `shell-setup`, run as v0.4.0 ran it (VOX_NO_SHELL_SETUP set, as here), must install the
        // pack, here for Codex (its settings folder only). Mutant: `shell::run` without its
        // `skill_pack::install_all` call; red as PRODUCT, no pack.
        let earlier = tmpdir();
        let home = earlier.path();
        std::fs::create_dir_all(home.join(".codex"))
            .unwrap_or_else(|e| panic!("APPARATUS: a harness folder: {e}"));
        let new_vox = apps.join("Vox.app/Contents/Helpers/vox");
        let out = vox(&new_vox, home, &["shell-setup"], &base);
        let text = said(&out);
        let pack = home.join(".codex/skills/vox-agent-comms");
        let entry =
            pack.join("SKILL.md").is_file() && pack.join("references/sessions.md").is_file();
        claims.push(claim(
            "bundle.an_earlier_releases_update_installs_the_agent_skill_pack",
            out.status.success() && entry && text.contains("Codex: installed"),
            format!(
                "the new release's `vox shell-setup`, as v0.4.0's `vox update` runs it (exit_ok={}): \
                 {} holds SKILL.md and references/sessions.md: {entry}; it said {text:?}",
                out.status.success(),
                pack.display()
            ),
        ));
    }

    // ---- an update with nothing newer still updates (decider, v0.4.2) ---------------------
    // The release serves this very version: `vox update --check` changes nothing, and `vox
    // update` refreshes what an update refreshes on the vox in place, here the agent skill pack
    // for Claude Code (its settings folder, no pack yet), and says so. Mutant: bundle::update's
    // "is current" branch without its refresh; red as PRODUCT, no pack.
    {
        let id = "bundle.a_current_update_refreshes_the_agent_skill_pack";
        let current_tree = tmpdir();
        bundle_release_of(
            current_tree.path(),
            VERSION,
            Path::new(VOX),
            &[("stable", None)],
        );
        match release_server::serve(current_tree.path()) {
            Err(why) => claims.push(blocked(id, format!("APPARATUS: the release server: {why}"))),
            Ok(current_server) => {
                let tmp = tmpdir();
                let home = tmp.path();
                let link = bundle_install(home, Some("stable"));
                for d in [".claude", ".codex", ".config/opencode"] {
                    std::fs::create_dir_all(home.join(d))
                        .expect("APPARATUS: harness config directory");
                }
                let mut env = base;
                env[0] = ("VOX_TEST_RELEASE_BASE", current_server.base.as_str());
                let pack = home.join(".claude/skills/vox-agent-comms/SKILL.md");
                let check = vox(&link, home, &["update", "--check"], &env);
                let after_check = pack.is_file();
                let out = vox(&link, home, &["update"], &env);
                let text = said(&out);
                assert_light_hooks(home, &text);
                let current = format!("Vox {VERSION} is current");
                let refreshed = format!(
                    "Vox {VERSION} is current; the agent skill is installed for Claude Code"
                );
                claims.push(claim(
                    id,
                    check.status.success()
                        && !after_check
                        && out.status.success()
                        && text.contains(&current)
                        && text.contains(&refreshed)
                        && pack.is_file()
                        && reports(&link) == format!("vox {VERSION}"),
                    format!(
                        "with Vox {VERSION} current: `vox update --check` (exit_ok={}) left a pack: \
                         {after_check}, saying {:?}; `vox update` (exit_ok={}) left {} there: {}, \
                         saying {text:?}; wanted {refreshed:?}",
                        check.status.success(),
                        said(&check),
                        out.status.success(),
                        pack.display(),
                        pack.is_file()
                    ),
                ));
                receipts.insert(id.into(), text);
            }
        }
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
        let kept = kept_app_says(&apps.join(".Vox.app.previous"));
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
        // The release's helper is a version stub, not vox; the next transition is run by a vox,
        // so the stub is replaced by this build (the bundle's version is its Info.plist's).
        copy(Path::new(VOX), &apps.join("Vox.app/Contents/Helpers/vox"));
        let out = vox(&link, home, &["update", "--rollback"], &base);
        let text = said(&out);
        let app = app_says(&apps.join("Vox.app"));
        let kept = kept_app_says(&apps.join(".Vox.app.previous"));
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

    // ---- a bundle a running vox came from is not removed from under it ---------------------
    // After one update the previous bundle is the one a not-yet-restarted daemon runs from; the
    // next update replaces that previous bundle, and must keep it until nothing runs from it.
    {
        let tmp = tmpdir();
        let home = tmp.path();
        let link = bundle_install(home, Some("stable"));
        let apps = home.join("Apps");
        let first = vox(&link, home, &["update"], &base);
        let from = apps.join(".Vox.app.previous/Contents/Helpers/vox");
        let scratch = home.join("a-node");
        std::fs::create_dir_all(scratch.join("cfg")).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
        let mut runner = std::process::Command::new(&from)
            .args(["node", "--listen", "127.0.0.1:0"])
            .env("VOX_DATA_DIR", &scratch)
            .env("VOX_CONFIG_DIR", scratch.join("cfg"))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap_or_else(|e| {
                panic!("APPARATUS: could not run vox from the previous bundle: {e}")
            });
        std::thread::sleep(std::time::Duration::from_secs(2));
        let alive = runner.try_wait().ok().flatten().is_none();
        // The active bundle's helper is the release's version stub; the next update is run by a
        // vox of the version before it, so this build goes in its place.
        copy(Path::new(VOX), &apps.join("Vox.app/Contents/Helpers/vox"));
        let second = vox(&link, home, &["update"], &base);
        let retired = |apps: &Path| -> Vec<PathBuf> {
            std::fs::read_dir(apps)
                .map(|d| {
                    d.filter_map(Result::ok)
                        .map(|e| e.path())
                        .filter(|p| {
                            p.file_name().is_some_and(|n| {
                                n.to_string_lossy().starts_with(".Vox.app.retired.")
                            })
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        let kept = retired(&apps);
        let kept_whole = kept
            .iter()
            .any(|r| r.join("Contents/Helpers/vox").is_file());
        let still = runner.try_wait().ok().flatten().is_none();
        let _ = runner.kill();
        let _ = runner.wait();
        copy(Path::new(VOX), &apps.join("Vox.app/Contents/Helpers/vox"));
        let third = vox(&link, home, &["update", "--rollback"], &base);
        let left = retired(&apps);
        if first.status.success() && alive {
            claims.push(claim(
                "bundle.keeps_a_bundle_a_daemon_runs_from",
                second.status.success()
                    && kept_whole
                    && still
                    && third.status.success()
                    && left.is_empty(),
                format!(
                    "the second update (exit_ok={}) kept the bundle the running vox came from as \
                     {kept:?}={kept_whole}, it still running={still}; after it stopped, --rollback \
                     (exit_ok={}) left {left:?}; the second update said {:?}",
                    second.status.success(),
                    third.status.success(),
                    said(&second)
                ),
            ));
        } else {
            claims.push(blocked(
                "bundle.keeps_a_bundle_a_daemon_runs_from",
                format!(
                    "staging: the first update exit_ok={}, a vox running from the previous bundle \
                     alive={alive}",
                    first.status.success()
                ),
            ));
        }
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

/// A genuinely compiled next-release binary, supplied as proof apparatus. Patching version
/// strings in a binary cannot change optimized version comparisons, so it proves a different
/// program. Build this tree with the requested workspace version and supply its path.
fn vox_saying(dir: &Path, version: &str) -> Result<PathBuf, String> {
    let fixture = std::env::var_os("VOX_PROOF_NEXT_BINARY")
        .map(PathBuf::from)
        .ok_or_else(|| format!("set VOX_PROOF_NEXT_BINARY to a vox compiled as {version}"))?;
    let path = dir.join("vox");
    std::fs::copy(&fixture, &path).map_err(|e| format!("copying {}: {e}", fixture.display()))?;
    make_executable(&path);
    let says = reports(&path);
    if says != format!("vox {version}") {
        return Err(format!("the fixture says {says:?}, not vox {version}"));
    }
    Ok(path)
}

/// The release a standalone install updates to, under `root`, as GitHub serves it: vox's record
/// on `stable` naming `version`, and `helper` as its binary.
#[cfg(target_os = "linux")]
fn standalone_release_of(root: &Path, version: &str, helper: &Path) {
    let triple = target_triple();
    let assets = root.join(format!("releases/download/v{version}"));
    let records = root.join("releases/latest/download");
    for d in [&assets, &records] {
        std::fs::create_dir_all(d).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
    }
    copy(helper, &assets.join(format!("vox-{triple}")));
    let bytes = std::fs::read(helper).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
    let sha = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&bytes)
            .iter()
            .fold(String::new(), |mut s, b| {
                use core::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
                s
            })
    };
    write(
        &records.join(format!("stable-{triple}.json")),
        &format!(
            "{{\"kind\":\"vox.standalone-release\",\"schema_version\":1,\"package\":\"vox\",\
             \"channel\":\"stable\",\"target\":\"{triple}\",\"version\":\"{version}\",\
             \"size\":{},\"sha256\":\"{sha}\"}}\n",
            bytes.len()
        ),
    );
}

/// Whatever holds a file under `dir` open: the vox processes a proof started for that account.
fn holders(dir: &Path) -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        let mut pids = Vec::new();
        for proc in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
            let pid = proc.file_name().to_string_lossy().into_owned();
            if !pid.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let holds = std::fs::read_dir(proc.path().join("fd"))
                .into_iter()
                .flatten()
                .flatten()
                .any(|fd| std::fs::read_link(fd.path()).is_ok_and(|t| t.starts_with(dir)));
            if holds {
                pids.push(pid);
            }
        }
        pids
    }
    #[cfg(not(target_os = "linux"))]
    {
        Command::new("/usr/sbin/lsof")
            .arg("-t")
            .arg("+D")
            .arg(dir)
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// ADR-034 UP-1 and UP-2: the real update journey, isolated from unrelated download cases.
#[test]
#[ignore = "real update, production Argon2id; run in release with test-knobs"]
fn an_update_restarts_its_daemon_and_refuses_a_different_local_version() {
    watchdog::arm();
    test_knobs::require(&["VOX_TEST_RELEASE_BASE"]);
    let mut claims = Vec::new();
    let mut receipts = BTreeMap::new();
    daemon_restart_claim(&mut claims, &mut receipts, cfg!(target_os = "macos"));
    dispose("daemon update proof", &claims, &receipts, false);
}

/// Decider 2026-10-07: once `vox update` has put the new vox in place (Vox.app when `bundle`, the
/// standalone binary otherwise), it restarts the running daemon onto the new version. A node it
/// keeps the passphrase of is attached again; any other attached node is detached, and the update
/// names it with the command that attaches it again.
fn daemon_restart_claim(
    claims: &mut Vec<Claim>,
    receipts: &mut BTreeMap<String, String>,
    bundle: bool,
) {
    let id = if bundle {
        "bundle.update_restarts_the_daemon_onto_the_new_version"
    } else {
        "update.restarts_the_daemon_onto_the_new_version"
    };
    // The next release: this build, saying a version above this one's.
    let next: String = std::iter::once('9')
        .chain(VERSION.chars().skip(1))
        .collect();
    let work = tmpdir();
    let helper = match vox_saying(work.path(), &next) {
        Ok(h) => h,
        Err(why) => {
            claims.push(blocked(
                id,
                format!("APPARATUS: the next release's vox: {why}"),
            ));
            return;
        }
    };
    let tree = tmpdir();
    let tmp = tmpdir();
    let home = tmp.path();
    let link = if bundle {
        #[cfg(target_os = "macos")]
        {
            bundle_release_of(tree.path(), &next, &helper, &[("stable", None)]);
            bundle_install(home, Some("stable"))
        }
        #[cfg(not(target_os = "macos"))]
        unreachable!("a Vox.app install is made only on macOS")
    } else {
        #[cfg(target_os = "linux")]
        {
            standalone_release_of(tree.path(), &next, &helper);
            install_dir(home, "stable").join("vox")
        }
        #[cfg(not(target_os = "linux"))]
        unreachable!("a standalone restart is measured only on Linux")
    };
    let server = match release_server::serve(tree.path()) {
        Ok(s) => s,
        Err(why) => {
            claims.push(blocked(id, format!("APPARATUS: the release server: {why}")));
            return;
        }
    };
    let data = home.join("data");
    let config = home.join("config");
    let pass = home.join("pass");
    write(&pass, "update proof passphrase\n");
    let private_keychain = crate::unlock_staging::keychain(&data);
    let env = [
        (
            "VOX_TEST_KEYCHAIN",
            private_keychain.to_str().expect("APPARATUS: Keychain path"),
        ),
        ("VOX_TEST_RELEASE_BASE", server.base.as_str()),
        ("VOX_NO_SHELL_SETUP", "1"),
        (
            "VOX_DATA_DIR",
            data.to_str().expect("APPARATUS: a UTF-8 temp path"),
        ),
        (
            "VOX_CONFIG_DIR",
            config.to_str().expect("APPARATUS: a UTF-8 temp path"),
        ),
        ("VOX_LISTEN", "127.0.0.1:0"),
    ];
    // Start it by hand, the update path that used to deliberately leave the old daemon alive.
    let daemon_log = home.join("hand-daemon.log");
    let log = std::fs::File::create(&daemon_log).expect("APPARATUS: daemon log");
    let mut daemon = Command::new(&link);
    daemon
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("VOX_PROXY", "127.0.0.1:0")
        .envs(env.iter().copied())
        .args(["daemon", "--no-node", "--listen", "127.0.0.1:0"])
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone().expect("APPARATUS: clone log"))
        .stderr(log);
    let mut daemon = daemon.spawn().expect("APPARATUS: start hand daemon");
    let before_pid = daemon.id();
    std::thread::spawn(move || {
        let _ = daemon.wait();
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::fs::read_to_string(data.join(".daemon/lock"))
        .ok()
        .is_none_or(|p| p.trim() != before_pid.to_string())
    {
        assert!(
            std::time::Instant::now() < deadline,
            "APPARATUS: hand daemon never held the scratch root"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let pass_arg = pass.to_str().expect("APPARATUS: a UTF-8 temp path");
    let mut staging = Vec::new();
    for args in [
        &["node", "create", "kept", "--passphrase-file", pass_arg][..],
        &["node", "create", "plain", "--passphrase-file", pass_arg],
        &[
            "node",
            "attach",
            "kept",
            "--keep",
            "--passphrase-file",
            pass_arg,
        ],
    ] {
        let out = vox(&link, home, args, &env);
        if !out.status.success() {
            staging.push(format!("`vox {}` said {:?}", args.join(" "), said(&out)));
        }
    }
    let listed = |link: &Path| -> (bool, bool, String) {
        let out = said(&vox(link, home, &["node", "list"], &env));
        let attached = |name: &str| {
            out.lines()
                .any(|l| l.split_whitespace().take(2).eq([name, "attached"]))
        };
        (attached("kept"), attached("plain"), out)
    };
    let service = std::net::TcpListener::bind("127.0.0.1:0").expect("APPARATUS: local service");
    let service_arg = format!(
        "echo={}",
        service
            .local_addr()
            .expect("APPARATUS: service address")
            .port()
    );
    let held_log = home.join("held-serve.log");
    let log = std::fs::File::create(&held_log).expect("APPARATUS: held serve log");
    let mut serve = Command::new(&link);
    serve
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("VOX_PROXY", "127.0.0.1:0")
        .envs(env.iter().copied())
        .env("VOX_IDENTITY_PASSPHRASE", "update proof passphrase")
        .args([
            "serve",
            &service_arg,
            "--node",
            "plain",
            "--name",
            "update-held",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone().expect("APPARATUS: clone log"))
        .stderr(log);
    let mut serve = serve.spawn().expect("APPARATUS: start held serve");
    let serve_pid = serve.id();
    let (ended_tx, ended_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = ended_tx.send(serve.wait());
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !std::fs::read_to_string(&held_log)
        .unwrap_or_default()
        .contains("vox://")
    {
        assert!(
            std::time::Instant::now() < deadline,
            "APPARATUS: serve never offered its room: {}",
            std::fs::read_to_string(&held_log).unwrap_or_default()
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let (kept_before, plain_before, before) = listed(&link);

    // The other release's CLI refuses this daemon before using a node, and a hook says the
    // same plain fix to its agent. These are two real binaries, with only the release string
    // changed in the staged next release.
    for args in [
        vec!["status", "--node", "kept"],
        vec![
            "agent",
            "hook",
            "--node",
            "kept",
            "--session",
            "version-refusal",
            "--format",
            "text",
        ],
    ] {
        let refusal = said(&vox(&helper, home, &args, &env));
        claims.push(claim(
            "daemon.version_mismatch_refused",
            refusal.contains(VERSION)
                && refusal.contains(&next)
                && refusal.contains("vox daemon --restart"),
            format!("the next release's {} said {refusal:?}", args.join(" ")),
        ));
    }

    let out = vox(&link, home, &["update"], &env);
    let text = said(&out);
    let (kept_after, plain_after, after) = listed(&link);
    let held_ended = ended_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .is_ok();
    if !held_ended {
        let _ = Command::new("/bin/kill")
            .arg(serve_pid.to_string())
            .status();
    }

    // Exercise the current client's remaining callers against the other real release. This
    // direction lets the already-compiled next-version fixture remain independent of the fix.
    for args in [
        vec!["daemon", "--node", "kept"],
        vec!["node", "detach", "kept"],
        vec!["node", "rename", "kept", "renamed-by-mismatch"],
        vec!["agent", "status", "--harness", "claude"],
    ] {
        let refusal = said(&vox(Path::new(VOX), home, &args, &env));
        claims.push(claim(
            "daemon.all_callers_preserve_version_refusal",
            refusal.contains(VERSION)
                && refusal.contains(&next)
                && refusal.contains("vox daemon --restart")
                && !refusal.contains("no vox daemon answers")
                && !refusal.contains("passphrase"),
            format!("the current release's {} said {refusal:?}", args.join(" ")),
        ));
    }
    let mut ending = vox_command(
        Path::new(VOX),
        home,
        &["agent", "hook", "--node", "kept", "--format", "text"],
        &env,
    );
    let mut ending = ending
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("APPARATUS: SessionEnd hook");
    {
        use std::io::Write as _;
        ending
            .stdin
            .take()
            .expect("APPARATUS: hook input")
            .write_all(
                br#"{"hook_event_name":"SessionEnd","session_id":"version-ended","reason":"exit"}"#,
            )
            .expect("APPARATUS: write SessionEnd");
    }
    let refusal = said(&ending.wait_with_output().expect("APPARATUS: hook output"));
    claims.push(claim(
        "daemon.session_end_preserves_version_refusal",
        refusal.contains(VERSION)
            && refusal.contains(&next)
            && refusal.contains("vox daemon --restart"),
        format!("SessionEnd hook against another release said {refusal:?}"),
    ));
    let (_, _, after_refusals) = listed(&link);
    claims.push(claim(
        "daemon.mismatched_rename_preserves_attached_node",
        after_refusals
            .lines()
            .any(|l| l.split_whitespace().take(2).eq(["kept", "attached"]))
            && !after_refusals.contains("renamed-by-mismatch"),
        format!("after the refused rename, vox node list said {after_refusals:?}"),
    ));
    // Uninstall an independent managed copy of this release while the scratch account still
    // runs the other release. It must stop that authenticated daemon before removing its copy.
    let removal = tmpdir();
    let uninstall = if bundle {
        #[cfg(target_os = "macos")]
        {
            bundle_install(removal.path(), Some("stable"))
        }
        #[cfg(not(target_os = "macos"))]
        unreachable!("macOS bundle")
    } else {
        install_dir(removal.path(), "stable").join("vox")
    };
    let removed = said(&vox(&uninstall, home, &["uninstall"], &env));
    claims.push(claim(
        "daemon.uninstall_stops_another_local_version",
        removed.contains("stopped the vox daemon (pid "),
        format!("uninstall against the other release's daemon said {removed:?}"),
    ));

    // Every vox this left running is stopped, by its pid: whichever holds the account's files.
    for pid in holders(&data) {
        let _ = Command::new("/bin/kill").arg(pid).status();
    }

    if !staging.is_empty() || !kept_before || !plain_before {
        claims.push(blocked(
            id,
            format!(
                "APPARATUS: staging two attached nodes failed: {staging:?}; `vox node list` said \
                 {before:?}"
            ),
        ));
        return;
    }
    let restarted = format!("the vox daemon was restarted and runs vox {next}");
    claims.push(claim(
        id,
        out.status.success()
            && text.contains(&restarted)
            && text.contains("held sessions plain/update-held/echo ended")
            && text.contains("node plain is Locked")
            && text.contains("vox node unlock plain")
            && !text.contains("node kept is Locked")
            && kept_after
            && !plain_after
            && held_ended,
        format!(
            "with nodes kept (passphrase kept) and plain attached, `vox update` (exit_ok={}) said \
             {text:?}; then `vox node list` said {after:?} (kept attached={kept_after}, plain \
             attached={plain_after}); wanted {restarted:?} and plain named as detached",
            out.status.success()
        ),
    ));
    receipts.insert(id.into(), text);
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

/// Read the configuration the updated binary installed, as each harness does (HK-1).
fn assert_light_hooks(home: &Path, said: &str) {
    for (harness, rel) in [
        ("claude", ".claude/settings.json"),
        ("codex", ".codex/hooks.json"),
        ("opencode", ".config/opencode/plugin/vox.js"),
    ] {
        let path = home.join(rel);
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(content.contains(&format!("agent hook --light {harness}"))
            && said.contains(path.to_str().expect("APPARATUS: UTF-8 scratch path")),
            "PRODUCT: vox update must install {harness}'s light hook and name {path:?}; file={content:?}; output={said}");
    }
}

/// LaunchServices' own registration tool. Every call in this proof names one exact scratch
/// bundle; cleanup never resets the database and never unregisters the person's Vox.app.
#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
const LSREGISTER: &str = "/System/Library/Frameworks/CoreServices.framework/Frameworks/\
                          LaunchServices.framework/Support/lsregister";

#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
fn lsregister(flag: &str, bundle: &Path) -> Result<(), String> {
    let out = Command::new(LSREGISTER)
        .arg(flag)
        .arg(bundle)
        .output()
        .map_err(|e| format!("could not run lsregister for {}: {e}", bundle.display()))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "lsregister {flag} {} exited {}: {}",
            bundle.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Exact paths LaunchServices currently associates with `identifier`.
#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
fn launch_services_paths(identifier: &str) -> Result<Vec<PathBuf>, String> {
    let out = Command::new(LSREGISTER)
        .arg("-dump")
        .output()
        .map_err(|e| format!("could not ask LaunchServices for its records: {e}"))?;
    if !out.status.success() {
        return Err(format!("lsregister -dump exited {}", out.status));
    }
    let dump = String::from_utf8(out.stdout)
        .map_err(|e| format!("LaunchServices returned a non-UTF-8 database dump: {e}"))?;
    let mut path = None;
    let mut found = Vec::new();
    let mut parsed_paths = 0_usize;
    let mut parsed_identifiers = 0_usize;
    for line in dump.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("path:") {
            let value = value.trim();
            let value = value.split_once(" (0x").map_or(value, |(before, _)| before);
            path = Some(PathBuf::from(value));
            parsed_paths += 1;
        } else if line
            .strip_prefix("identifier:")
            .is_some_and(|value| value.trim() == identifier)
        {
            parsed_identifiers += 1;
            if let Some(value) = path.take() {
                found.push(value);
            }
        } else if line.starts_with("identifier:") {
            parsed_identifiers += 1;
        }
    }
    if parsed_paths == 0 || parsed_identifiers == 0 {
        return Err(format!(
            "could not parse LaunchServices' database dump (paths={parsed_paths}, identifiers={parsed_identifiers})"
        ));
    }
    found.sort();
    found.dedup();
    Ok(found)
}

/// Paths this proof may have registered. Drop removes each embedded extension by its exact path,
/// then repeats `lsregister -u` on the exact outer paths only, as app-proofs.sh does.
#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
struct LaunchServicesCleanup {
    bundles: Vec<PathBuf>,
    extensions: Vec<PathBuf>,
}

#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
impl LaunchServicesCleanup {
    fn new() -> Self {
        Self {
            bundles: Vec::new(),
            extensions: Vec::new(),
        }
    }

    fn register(&mut self, bundle: &Path) -> Result<(), String> {
        lsregister("-f", bundle)?;
        self.remember(bundle);
        Ok(())
    }

    fn remember(&mut self, bundle: &Path) {
        self.bundles.push(bundle.to_path_buf());
        let plugins = bundle.join("Contents/PlugIns");
        match std::fs::read_dir(&plugins) {
            Ok(entries) => {
                self.extensions.extend(
                    entries
                        .map(|entry| {
                            entry.unwrap_or_else(|e| {
                                panic!(
                                    "APPARATUS: could not enumerate {} for cleanup: {e}",
                                    plugins.display()
                                )
                            })
                        })
                        .map(|entry| entry.path())
                        .filter(|path| path.extension().is_some_and(|ext| ext == "appex")),
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!(
                "APPARATUS: could not inspect {} for cleanup: {e}",
                plugins.display()
            ),
        }
    }
}

#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
impl Drop for LaunchServicesCleanup {
    fn drop(&mut self) {
        self.extensions.sort(); self.extensions.dedup();
        self.bundles.sort(); self.bundles.dedup();
        for extension in &self.extensions {
            let _ = Command::new("/usr/bin/pluginkit").arg("-r").arg(extension).output();
        }
        for bundle in &self.bundles { let _ = lsregister("-u", bundle); }
        // Both tools return nonzero for an already absent path. Determine cleanup from their
        // databases rather than treating that exit status as evidence a registration remains.
        let plugins = Command::new("/usr/bin/pluginkit").args(["-m", "-A", "-D", "-v"]).output();
        let records = Command::new(LSREGISTER).arg("-dump").output();
        let check = |out: std::io::Result<Output>, paths: &[PathBuf], label: &str| -> Result<(), String> {
            let out = out.map_err(|e| format!("{label}: {e}"))?;
            if !out.status.success() { return Err(format!("{label}: query exited {}", out.status)); }
            let text = String::from_utf8(out.stdout).map_err(|_| format!("{label}: non-UTF-8 output"))?;
            for path in paths {
                let logical = path.to_string_lossy();
                let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| {
                    let value = logical.as_ref();
                    if value.starts_with("/var/") { PathBuf::from(format!("/private{value}")) } else { path.clone() }
                });
                if text.lines().any(|line| line.contains(logical.as_ref()) || line.contains(canonical.to_string_lossy().as_ref())) {
                    return Err(format!("{label}: scratch path {} remains registered", path.display()));
                }
            }
            Ok(())
        };
        let problems = [check(plugins, &self.extensions, "pluginkit"), check(records, &self.bundles, "LaunchServices")];
        for problem in problems.into_iter().filter_map(Result::err) {
            let message = format!("APPARATUS: cleanup not confirmed: {problem}");
            if std::thread::panicking() { eprintln!("{message}"); } else { panic!("{message}"); }
        }
    }
}

/// What `open -b` and LaunchServices' resulting application record said.
#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
struct OpenedBundle {
    ok: bool,
    path: Option<PathBuf>,
    error: String,
}

/// Ask LaunchServices to open one identifier and observe the exact application from
/// `NSWorkspace.didLaunchApplicationNotification`. The observer is subscribed before `open`,
/// announces that subscription before the request is submitted, and terminates only the exact
/// launched process after recording its bundle path. `open -W` and that notification are the two
/// structural outcomes: a refused request is PRODUCT evidence, while an observer/setup failure is
/// APPARATUS. There is no polling, repeated process spawn, silence threshold, or elapsed verdict.
#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
fn opened_bundle(
    identifier: &str,
    data: &Path,
    config: &Path,
    home: &Path,
) -> Result<OpenedBundle, String> {
    use std::io::BufRead as _;

    std::fs::create_dir_all(home)
        .map_err(|e| format!("could not make scratch HOME {}: {e}", home.display()))?;

    // This process is proof apparatus, not the product oracle. It reports the exact launch event
    // that `open -b` caused and then asks that scratch process to terminate so `open -W` can join.
    const OBSERVER: &str = r#"
import AppKit
import Darwin

let wanted = ProcessInfo.processInfo.environment["VOX_PROOF_OBSERVER_IDENTIFIER"]!
let center = NSWorkspace.shared.notificationCenter
var token: NSObjectProtocol?
token = center.addObserver(
    forName: NSWorkspace.didLaunchApplicationNotification,
    object: nil,
    queue: nil
) { note in
    guard
        let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
        app.bundleIdentifier == wanted
    else { return }
    print("LAUNCHED")
    print(app.bundleIdentifier ?? "")
    print(app.processIdentifier)
    print(app.bundleURL?.path ?? "")
    print(app.forceTerminate() ? "TERMINATED" : "TERMINATE_FAILED")
    fflush(stdout)
    exit(0)
}
print("READY")
fflush(stdout)
withExtendedLifetime(token) { RunLoop.main.run() }
"#;
    let mut observer = Command::new("/usr/bin/swift")
        .args(["-e", OBSERVER])
        .env("VOX_PROOF_OBSERVER_IDENTIFIER", identifier)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start the LaunchServices observer: {e}"))?;
    let observer_stdout = observer
        .stdout
        .take()
        .ok_or_else(|| "LaunchServices observer had no stdout".to_owned())?;
    let mut observer_lines = std::io::BufReader::new(observer_stdout).lines();
    let ready = observer_lines
        .next()
        .transpose()
        .map_err(|e| format!("could not read LaunchServices observer readiness: {e}"))?;
    if ready.as_deref() != Some("READY") {
        let _ = observer.kill();
        let status = observer.wait();
        let mut error = String::new();
        if let Some(mut stderr) = observer.stderr.take() {
            use std::io::Read as _;
            let _ = stderr.read_to_string(&mut error);
        }
        return Err(format!(
            "LaunchServices observer did not become ready: line={ready:?}, status={status:?}, stderr={:?}",
            error.trim()
        ));
    }

    enum Observation {
        Launch(Result<(String, u32, PathBuf, bool), String>),
        Open(std::io::Result<std::process::Output>),
    }
    let (observed_tx, observed_rx) = std::sync::mpsc::channel();
    let launch_tx = observed_tx.clone();
    let observer_reader = std::thread::spawn(move || {
        let mut read = || -> Result<(String, u32, PathBuf, bool), String> {
            let mut next = |what: &str| {
                observer_lines
                    .next()
                    .transpose()
                    .map_err(|e| format!("could not read observer {what}: {e}"))?
                    .ok_or_else(|| format!("observer ended before reporting {what}"))
            };
            if next("event")? != "LAUNCHED" {
                return Err("observer reported an unknown launch event".to_owned());
            }
            let launched_identifier = next("bundle identifier")?;
            let pid = next("process identifier")?
                .parse::<u32>()
                .map_err(|e| format!("observer reported an invalid process identifier: {e}"))?;
            let path = PathBuf::from(next("bundle path")?);
            let terminated = match next("termination result")?.as_str() {
                "TERMINATED" => true,
                "TERMINATE_FAILED" => false,
                other => {
                    return Err(format!(
                        "observer reported unknown termination result {other:?}"
                    ))
                }
            };
            Ok((launched_identifier, pid, path, terminated))
        };
        let _ = launch_tx.send(Observation::Launch(read()));
    });

    let mut opened = Command::new("/usr/bin/open");
    opened
        .args(["-n", "-W", "-b", identifier, "--env"])
        .arg(format!("VOX_DATA_DIR={}", data.display()))
        .arg("--env")
        .arg(format!("VOX_CONFIG_DIR={}", config.display()))
        .arg("--env")
        .arg(format!("HOME={}", home.display()))
        .arg("--env")
        .arg(format!(
            "CLAUDE_CONFIG_DIR={}",
            home.join(".claude").display()
        ))
        .arg("--env")
        .arg(format!("CODEX_HOME={}", home.join(".codex").display()))
        .arg("--env")
        .arg(format!(
            "OPENCODE_CONFIG_DIR={}",
            home.join(".config/opencode").display()
        ))
        .arg("--env")
        .arg(format!(
            "XDG_CONFIG_HOME={}",
            home.join(".config").display()
        ))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let child = match opened.spawn() {
        Ok(child) => child,
        Err(e) => {
            let _ = observer.kill();
            let _ = observer.wait();
            let _ = observer_reader.join();
            return Err(format!(
                "could not submit the open request for {identifier}: {e}"
            ));
        }
    };
    let open_pid = child.id();
    let open_tx = observed_tx;
    let open_waiter = std::thread::spawn(move || {
        let _ = open_tx.send(Observation::Open(child.wait_with_output()));
    });

    let mut open_output = None;
    let launch = loop {
        match observed_rx
            .recv()
            .map_err(|_| "launch observers ended without an outcome".to_owned())?
        {
            Observation::Open(Ok(out)) if !out.status.success() => {
                let _ = observer.kill();
                let _ = observer.wait();
                let _ = observer_reader.join();
                let _ = open_waiter.join();
                return Ok(OpenedBundle {
                    ok: false,
                    path: None,
                    error: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
                });
            }
            Observation::Open(Ok(out)) => open_output = Some(out),
            Observation::Open(Err(e)) => {
                let _ = observer.kill();
                let _ = observer.wait();
                let _ = observer_reader.join();
                let _ = open_waiter.join();
                return Err(format!("could not collect open -W for {identifier}: {e}"));
            }
            Observation::Launch(Ok(result)) => break result,
            Observation::Launch(Err(why)) => {
                let stop_open = Command::new("/bin/kill")
                    .args(["-TERM", &open_pid.to_string()])
                    .output();
                let stop_observer = observer.kill();
                let observer_status = observer.wait();
                let reader_joined = observer_reader.join().is_ok();
                let open_joined = open_waiter.join().is_ok();
                return Err(format!(
                    "LaunchServices observation failed ({why}); cleanup: open={stop_open:?}, observer_stop={stop_observer:?}, observer_status={observer_status:?}, reader_joined={reader_joined}, open_joined={open_joined}"
                ));
            }
        }
    };
    let (launched_identifier, pid, path, terminated) = launch;
    if !terminated {
        let killed = Command::new("/bin/kill")
            .args(["-TERM", &pid.to_string()])
            .output()
            .map_err(|e| format!("could not terminate launched scratch app {pid}: {e}"))?;
        if !killed.status.success() {
            let stop_open = Command::new("/bin/kill")
                .args(["-TERM", &open_pid.to_string()])
                .output();
            let observer_status = observer.wait();
            let reader_joined = observer_reader.join().is_ok();
            let open_joined = open_waiter.join().is_ok();
            return Err(format!(
                "could not terminate launched scratch app {pid}: {}; cleanup: open={stop_open:?}, observer_status={observer_status:?}, reader_joined={reader_joined}, open_joined={open_joined}",
                String::from_utf8_lossy(&killed.stderr).trim(),
            ));
        }
    }
    let out = match open_output {
        Some(out) => out,
        None => match observed_rx
            .recv()
            .map_err(|_| "open -W ended without an outcome".to_owned())?
        {
            Observation::Open(result) => result.map_err(|e| e.to_string())?,
            Observation::Launch(_) => {
                return Err("LaunchServices observer reported the same launch twice".to_owned())
            }
        },
    };
    let observer_status = observer
        .wait()
        .map_err(|e| format!("could not join LaunchServices observer: {e}"))?;
    observer_reader
        .join()
        .map_err(|_| "LaunchServices observer reader panicked".to_owned())?;
    open_waiter
        .join()
        .map_err(|_| "open -W waiter panicked".to_owned())?;
    if !observer_status.success() {
        return Err(format!(
            "LaunchServices observer exited {observer_status} after reporting a launch"
        ));
    }
    Ok(OpenedBundle {
        ok: launched_identifier == identifier,
        path: Some(path),
        error: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
    })
}

#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
fn plist_value(app: &Path, key: &str) -> Result<String, String> {
    let out = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", &format!("Print :{key}")])
        .arg(app.join("Contents/Info.plist"))
        .output()
        .map_err(|e| format!("could not read {key} from {}: {e}", app.display()))?;
    if !out.status.success() {
        return Err(format!("{} has no readable {key}", app.display()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
fn expected_build_version(version: &str) -> Result<String, String> {
    let parsed = semver::Version::parse(version)
        .map_err(|e| format!("the app version {version:?} is not SemVer: {e}"))?;
    Ok(format!(
        "{}.{}.{}",
        parsed
            .major
            .checked_add(1)
            .ok_or_else(|| "the app version's major component cannot be raised".to_owned())?,
        parsed.minor,
        parsed.patch
    ))
}

#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
fn signed(path: &Path) -> Result<(), String> {
    let out = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--deep", "--all-architectures"])
        .arg(path)
        .output()
        .map_err(|e| format!("could not run codesign for {}: {e}", path.display()))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "the restored {} does not verify: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
fn shipped_notarized(path: &Path) -> Result<(), String> {
    signed(path)?;
    let notarized = Command::new("/usr/bin/codesign")
        .args([
            "--verify",
            "--strict",
            "--deep",
            "--all-architectures",
            "--check-notarization",
            "--test-requirement",
            "=notarized",
        ])
        .arg(path)
        .output()
        .map_err(|e| format!("could not ask Apple about {}: {e}", path.display()))?;
    if !notarized.status.success() {
        return Err(format!(
            "Apple did not verify {} as notarized: {}",
            path.display(),
            String::from_utf8_lossy(&notarized.stderr).trim()
        ));
    }
    let details = Command::new("/usr/bin/codesign")
        .args(["-d", "--verbose=4"])
        .arg(path)
        .output()
        .map_err(|e| {
            format!(
                "could not inspect {}'s signing identity: {e}",
                path.display()
            )
        })?;
    let words = String::from_utf8_lossy(&details.stderr);
    if !details.status.success()
        || !words
            .lines()
            .any(|line| line.starts_with("Authority=Developer ID Application:"))
        || words.lines().any(|line| line == "TeamIdentifier=not set")
        || !words.lines().any(|line| {
            line.strip_prefix("TeamIdentifier=")
                .is_some_and(|team| !team.is_empty() && team != "not set")
        })
    {
        return Err(format!(
            "{} is not a Developer ID Application artifact with a team identity: {}",
            path.display(),
            words.trim()
        ));
    }
    Ok(())
}

/// A native application opened by its installed path, held until the proof asks it to quit.
#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
struct HeldApp {
    observer: std::process::Child,
    path: PathBuf,
}

#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
impl HeldApp {
    fn launch(home: &Path, active: &Path, owned_paths: &[PathBuf]) -> Self {
        use std::io::BufRead as _;
        const OBSERVER: &str = r#"
import AppKit
import Foundation
import Darwin
let wanted = CommandLine.arguments[1]
let ownedPaths = Set(CommandLine.arguments.dropFirst(2))
let center = NSWorkspace.shared.notificationCenter
var launched: NSRunningApplication?
var ownsLaunch = false
var askedToQuit = false
var processExit: DispatchSourceProcess?
let launchToken = center.addObserver(forName: NSWorkspace.didLaunchApplicationNotification, object: nil, queue: .main) { note in
    guard let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
          app.bundleIdentifier == wanted else { return }
    launched = app
    ownsLaunch = ownedPaths.contains(app.bundleURL?.path ?? "")
    let pid = app.processIdentifier
    guard pid > 0 else { exit(4) }
    // Unregistering the live displaced app can remove its LaunchServices application record.
    // Observe its physical process, not a later LS termination notification for that record.
    let monitor = DispatchSource.makeProcessSource(identifier: pid, eventMask: .exit, queue: .main)
    monitor.setEventHandler { processExit?.cancel(); exit(askedToQuit ? 0 : 4) }
    processExit = monitor
    monitor.resume()
    print(app.bundleURL?.path ?? "")
    fflush(stdout)
}
DispatchQueue.global().async {
    _ = readLine()
    DispatchQueue.main.async {
        guard ownsLaunch, let app = launched else { exit(2) }
        askedToQuit = true
        if !app.terminate() { _ = app.forceTerminate(); exit(3) }
    }
}
print("READY")
fflush(stdout)
withExtendedLifetime(launchToken) { RunLoop.main.run() }
"#;
        let mut observer = Command::new("/usr/bin/swift")
            .args(["-e", OBSERVER, "us.vox.app"])
            .arg(active)
            .args(owned_paths)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn().expect("APPARATUS: start native launch observer");
        let mut lines = std::io::BufReader::new(observer.stdout.take().expect("APPARATUS: observer stdout"));
        let mut line = String::new();
        lines.read_line(&mut line).expect("APPARATUS: observer readiness");
        assert_eq!(line.trim(), "READY", "APPARATUS: observer did not subscribe");
        let opened = Command::new("/usr/bin/open")
            .args(["-n", "--env"])
            .arg(format!("VOX_DATA_DIR={}", home.join("data").display()))
            .arg("--env").arg(format!("VOX_CONFIG_DIR={}", home.join("config").display()))
            .arg("--env").arg(format!("HOME={}", home.display()))
            .arg(active)
            .output().expect("APPARATUS: open installed scratch application by path");
        assert!(opened.status.success(), "PRODUCT: installed app path launch refused: {}", said(&opened));
        line.clear();
        lines.read_line(&mut line).expect("APPARATUS: exact native launch event");
        let path = PathBuf::from(line.trim());
        let app = Self { observer, path };
        assert_eq!(app.path, active, "PRODUCT: path launch selected the wrong Vox.app");
        app
    }

    fn quit(mut self) {
        use std::io::Write as _;
        if let Some(mut input) = self.observer.stdin.take() {
            let _ = writeln!(input, "QUIT");
        }
        let status = self.observer.wait().expect("APPARATUS: observe graceful app termination");
        assert!(status.success(), "PRODUCT: scratch Vox did not quit gracefully: {status}, launched {:?}", self.path);
    }
}

#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
impl Drop for HeldApp {
    fn drop(&mut self) {
        use std::io::Write as _;
        if let Some(mut input) = self.observer.stdin.take() {
            let _ = writeln!(input, "QUIT");
        }
        let _ = self.observer.wait();
    }
}

/// Cleanup observes only this invocation's authenticated scratch control socket. No pid from
/// another profile, a process-name search, or an identifier-wide operation is used.
#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
struct ScratchDaemonCleanup(PathBuf);

#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
impl Drop for ScratchDaemonCleanup {
    fn drop(&mut self) {
        let stop = || -> Result<(), String> {
            let data = self.0.join("data");
            let config = self.0.join("config");
            let account = vox_core::node::paths::Account::of(Some(&data), Some(&config))
                .map_err(|e| e.to_string())?;
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()
                .map_err(|e| e.to_string())?;
            let hello = match rt.block_on(vox_core::node::daemonipc::DaemonClient::observe(&account.socket())) {
                Ok(hello) => hello,
                Err(vox_core::error::Error::Ipc(vox_core::error::IpcHandshake::Unreachable { .. })) => return Ok(()),
                Err(e) => return Err(e.to_string()),
            };
            Command::new("/bin/kill").args(["-TERM", &hello.pid.to_string()]).status()
                .map_err(|e| e.to_string())?;
            // The daemon owns this lock for its physical lifetime, including store shutdown.
            let lock = std::fs::OpenOptions::new().read(true).write(true).open(account.lock_file())
                .map_err(|e| e.to_string())?;
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)
                .map_err(|e| e.to_string())
        };
        if let Err(error) = stop() {
            let message = format!("APPARATUS: scratch daemon cleanup not confirmed: {error}");
            if std::thread::panicking() { eprintln!("{message}"); } else { panic!("{message}"); }
        }
    }
}

/// Source-bound signed install/update/identifier-open/rollback, plus real transition recovery.
/// The prior artifact is built with the existing test-knobs feature; the candidate is a normal
/// release-feature build. Neither signed artifact is modified after signing or notarization.
#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
#[test]
#[ignore = "optional signed macOS guest journey; docs/release/optional-proofs.md"]
fn an_update_and_rollback_leave_one_launchable_vox() {
    use std::io::BufRead as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let model = Command::new("/usr/sbin/sysctl").args(["-n", "hw.model"]).output()
        .expect("APPARATUS: query guest hardware");
    assert!(String::from_utf8_lossy(&model.stdout).trim().starts_with("VirtualMac"),
        "APPARATUS: this identifier proof runs only in the dedicated macOS guest");
    let prior = PathBuf::from(std::env::var_os("VOX_PROOF_PREVIOUS_SHIPPED_APP")
        .expect("APPARATUS: missing exact signed prior artifact"));
    let candidate = PathBuf::from(std::env::var_os("VOX_PROOF_SHIPPED_APP")
        .expect("APPARATUS: missing exact signed candidate artifact"));
    let before_version = plist_value(&prior, "CFBundleShortVersionString")
        .unwrap_or_else(|e| panic!("APPARATUS: {e}"));
    let after_version = plist_value(&candidate, "CFBundleShortVersionString")
        .unwrap_or_else(|e| panic!("APPARATUS: {e}"));
    let prior_semver = semver::Version::parse(&before_version).expect("APPARATUS: prior SemVer");
    let candidate_semver = semver::Version::parse(&after_version).expect("APPARATUS: candidate SemVer");
    assert!(candidate_semver > prior_semver, "APPARATUS: candidate must be newer than prior");
    for app in [&prior, &candidate] {
        assert_eq!(plist_value(app, "CFBundleIdentifier").as_deref(), Ok("us.vox.app"),
            "APPARATUS: artifact identifier is not the real app identifier");
        shipped_notarized(app).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
    }
    let mut extension_names = Vec::new();
    for app in [&prior, &candidate] {
        let plugins = app.join("Contents/PlugIns");
        for entry in std::fs::read_dir(&plugins).expect("APPARATUS: signed artifact extensions") {
            let entry = entry.expect("APPARATUS: signed extension entry");
            if entry.path().extension().is_some_and(|ext| ext == "appex") {
                extension_names.push(entry.file_name());
            }
        }
    }
    extension_names.sort();
    extension_names.dedup();
    assert!(launch_services_paths("us.vox.app").expect("APPARATUS: read initial registration").is_empty(),
        "APPARATUS: dedicated guest already has us.vox.app registrations; do not clear another run's paths");
    let prior_tree = tmpdir();
    let candidate_tree = tmpdir();
    bundle_release_app(prior_tree.path(), &before_version, &prior, &[("stable", None)]);
    bundle_release_app(candidate_tree.path(), &after_version, &candidate, &[("stable", None)]);
    let prior_release = release_server::serve(prior_tree.path()).expect("APPARATUS: serve prior signed artifact");
    let release = release_server::serve(candidate_tree.path()).expect("APPARATUS: serve signed candidate");
    let mut claims = Vec::new();
    let mut receipts = BTreeMap::new();
    let prior_build = plist_value(&prior, "CFBundleVersion").expect("APPARATUS: prior build number");
    let candidate_build = plist_value(&candidate, "CFBundleVersion").expect("APPARATUS: candidate build number");
    let components = |value: &str| value.split('.').map(str::parse::<u64>).collect::<Result<Vec<_>, _>>();
    claims.push(claim("bundle.signed_build_numbers_follow_release_versions",
        expected_build_version(&before_version).as_deref() == Ok(prior_build.as_str())
            && expected_build_version(&after_version).as_deref() == Ok(candidate_build.as_str())
            && components(&candidate_build).expect("PRODUCT: candidate build number is not numeric")
                > components(&prior_build).expect("PRODUCT: prior build number is not numeric"),
        format!("prior={before_version}/{prior_build}, candidate={after_version}/{candidate_build}")));

    for scenario in ["update-and-rollback", "interrupted-publish", "read-only-and-live-retirement"] {
        let scratch = tempfile::Builder::new().prefix("vox-m29a-").tempdir_in("/Users/Shared")
            .expect("APPARATUS: visible dedicated scratch root");
        let home = scratch.path();
        let apps = home.join("Applications");
        std::fs::create_dir_all(&apps).expect("APPARATUS: scratch Applications");
        std::fs::create_dir_all(home.join("config/app")).expect("APPARATUS: scratch app config");
        write(&home.join("config/app/login-item"), "no\n");
        let active = apps.join("Vox.app");
        let previous = apps.join(".Vox.app.previous");
        let partial = apps.join(".Vox.app.partial");
        let journal_bundle = apps.join(".Vox.app.publishing/Vox.app");
        let helper = active.join("Contents/Helpers/vox");
        let mut cleanup = LaunchServicesCleanup::new();
        let _daemons = ScratchDaemonCleanup(home.to_path_buf());
        // Record exact extension paths before a transition can rename the signed bundle.
        for path in [&active, &previous, &partial, &journal_bundle] {
            cleanup.remember(path);
            for name in &extension_names {
                cleanup.extensions.push(path.join("Contents/PlugIns").join(name));
            }
        }
        let install = Command::new("/bin/sh").arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../../install.sh"))
            .env_clear().env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("HOME", home).env("SHELL", "/bin/zsh")
            .env("VOX_DATA_DIR", home.join("data")).env("VOX_CONFIG_DIR", home.join("config"))
            .env("VOX_APPLICATIONS_DIR", &apps).env("VOX_INSTALL_DIR", home.join("bin"))
            .env("VOX_RELEASE_BASE", &prior_release.base).env("VOX_PROOF_APPLE_VERIFY", "1")
            .env("VOX_NO_SHELL_SETUP", "1").env("VOX_NO_SKILL_INSTALL", "1")
            .output().expect("APPARATUS: launch real scratch installer");
        println!("{scenario} install {}: {}", install.status, said(&install));
        assert!(install.status.success(), "PRODUCT: signed scratch install failed: {}", said(&install));
        cleanup.remember(&active);
        let env = [("VOX_TEST_RELEASE_BASE", release.base.as_str()), ("VOX_TEST_APPLE_VERIFY", "1"),
            ("VOX_NO_SHELL_SETUP", "1"), ("VOX_NO_SKILL_INSTALL", "1")];

        if scenario == "interrupted-publish" {
            let mut daemon = vox_command(&helper, home, &["daemon", "--listen", "127.0.0.1:0"], &env)
                .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::inherit())
                .spawn().expect("APPARATUS: start scratch foreground daemon");
            let mut ready = String::new();
            std::io::BufReader::new(daemon.stdout.take().expect("APPARATUS: daemon stdout"))
                .read_line(&mut ready).expect("APPARATUS: daemon startup event");
            assert!(ready.starts_with("vox daemon: control socket "), "APPARATUS: daemon did not start: {ready}");
            let cut_env: Vec<_> = env.iter().copied().chain([("VOX_TEST_ABORT_AFTER_SWAP", "1")]).collect();
            let cut = vox(&helper, home, &["update"], &cut_env);
            assert!(!cut.status.success() && partial.is_dir(), "APPARATUS: real publish did not reach the cut-after-swap boundary: {}", said(&cut));
            let inode = std::fs::metadata(&active).expect("APPARATUS: published inode").ino();
            let repaired = vox(&helper, home, &["update"], &env);
            let text = said(&repaired);
            println!("interrupted publish repair {}: {text}", repaired.status);
            let last = text.lines().last().unwrap_or("");
            claims.push(claim("bundle.recovery_finishes_a_real_cut_without_another_swap",
                repaired.status.success()
                    && inode == std::fs::metadata(&active).expect("APPARATUS: repaired inode").ino()
                    && kept_app_says(&previous) == before_version
                    && !apps.join(".Vox.app.publishing").exists()
                    && text.contains(&format!("the vox daemon was restarted and runs vox {after_version}"))
                    && last.contains("without swapping Vox.app") && last.contains("cut short"),
                text.clone()));
            let _ = daemon.kill();
            let _ = daemon.wait();
            receipts.insert(scenario.to_owned(), text);
            continue;
        }

        let old_app = HeldApp::launch(home, &active, &cleanup.bundles);
        let updated = vox(&helper, home, &["update"], &env);
        println!("{scenario} update {}: {}", updated.status, said(&updated));
        claims.push(claim("bundle.kept_bundle_is_not_an_application",
            updated.status.success() && kept_app_says(&previous) == before_version,
            format!("update={}, kept version {:?}: {}", updated.status, kept_app_says(&previous), said(&updated))));
        // A failed product prerequisite must reach its own verdict before later apparatus
        // depends on the retained plist. Unwinding still owns the running scratch app.
        if kept_app_says(&previous) != before_version || !updated.status.success() {
            dispose("signed one-launchable-app journey", &claims, &receipts, false);
        }
        old_app.quit();
        claims.push(claim("bundle.quitting_the_renamed_app_does_not_register_it",
            !launch_services_paths("us.vox.app").expect("APPARATUS: records after graceful quit").contains(&previous),
            format!("records={:?}", launch_services_paths("us.vox.app"))));
        let opened = opened_bundle("us.vox.app", &home.join("data"), &home.join("config"), home)
            .unwrap_or_else(|e| panic!("APPARATUS: {e}"));
        claims.push(claim("bundle.identifier_launches_the_signed_updated_bundle",
            opened.ok && opened.path.as_deref() == Some(active.as_path())
                && app_says(&active) == after_version && shipped_notarized(&active).is_ok(),
            format!("selected={:?}, error={:?}", opened.path, opened.error)));

        // Hold the genuinely signed candidate across rollback. The following real update must
        // retire it, not remove code from under the still-running application.
        let live_candidate = if scenario == "read-only-and-live-retirement" {
            Some(HeldApp::launch(home, &active, &cleanup.bundles))
        } else { None };
        let rollback = vox(&helper, home, &["update", "--rollback"], &env);
        println!("{scenario} rollback {}: {}", rollback.status, said(&rollback));
        claims.push(claim("bundle.rollback_restores_the_signed_bundle_and_disarms_the_displaced_one",
            rollback.status.success() && app_says(&active) == before_version
                && shipped_notarized(&active).is_ok() && kept_app_says(&previous) == after_version,
            said(&rollback)));
        if scenario == "update-and-rollback" {
            let opened = opened_bundle("us.vox.app", &home.join("data"), &home.join("config"), home)
                .unwrap_or_else(|e| panic!("APPARATUS: {e}"));
            claims.push(claim("bundle.identifier_launches_the_signed_rollback",
                opened.ok && opened.path.as_deref() == Some(active.as_path()),
                format!("selected={:?}, error={:?}", opened.path, opened.error)));
        } else {
            let updated = vox(&helper, home, &["update"], &env);
            assert!(updated.status.success(), "PRODUCT: second real update failed: {}", said(&updated));
            let retired: Vec<_> = std::fs::read_dir(&apps).expect("APPARATUS: retired directory")
                .map(|e| e.expect("APPARATUS: retired entry").path())
                .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with(".Vox.app.retired."))).collect();
            assert_eq!(retired.len(), 1, "PRODUCT: real update removed the still-running retired bundle");
            let retired = &retired[0];
            cleanup.remember(retired);
            // Reproduce a legacy live application record, not a fabricated transition journal.
            std::fs::rename(retired.join("Contents/Info.plist.kept"), retired.join("Contents/Info.plist"))
                .expect("APPARATUS: restore original signed plist to reproduce failed legacy set-aside");
            cleanup.register(retired).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
            assert!(launch_services_paths("us.vox.app").expect("APPARATUS: seeded record").contains(retired),
                "APPARATUS: exact retained registration was not staged");
            let mode = std::fs::metadata(retired.join("Contents")).expect("APPARATUS: Contents mode").permissions().mode();
            std::fs::set_permissions(retired.join("Contents"), std::fs::Permissions::from_mode(mode & !0o222))
                .expect("APPARATUS: make Contents read-only");
            let refused = vox(&helper, home, &["update"], &env);
            std::fs::set_permissions(retired.join("Contents"), std::fs::Permissions::from_mode(mode))
                .expect("APPARATUS: remove the exact permission obstruction");
            // Unregister happened before the failed rename. Seed the exact record again so the
            // unregister inverse has its own causally staged, independent product assertion.
            cleanup.register(retired).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
            assert!(launch_services_paths("us.vox.app").expect("APPARATUS: re-seeded record").contains(retired),
                "APPARATUS: registration inverse was not staged before repair");
            let inode = std::fs::metadata(&active).expect("APPARATUS: active inode").ino();
            let ready = vox(&helper, home, &["daemon", "--detach", "--listen", "127.0.0.1:0"], &env);
            assert!(ready.status.success(),
                "APPARATUS: authenticated scratch daemon was not ready before restart measurement: {}", said(&ready));
            let repaired = vox(&helper, home, &["update"], &env);
            let text = said(&repaired);
            println!("read-only repair {}: {text}; refusal: {}", repaired.status, said(&refused));
            let records = launch_services_paths("us.vox.app").expect("APPARATUS: records after retained repair");
            claims.push(claim("bundle.kept_bundle_has_no_launchservices_record", !records.contains(retired),
                format!("seeded exact path={}, records={records:?}", retired.display())));
            claims.push(claim("bundle.recovery_repairs_read_only_and_live_retirement_without_a_swap",
                !refused.status.success() && repaired.status.success() && retired.is_dir()
                    && kept_app_says(retired) == after_version
                    && inode == std::fs::metadata(&active).expect("APPARATUS: repaired active inode").ino()
                    && text.contains(&format!("the vox daemon was restarted and runs vox {after_version}"))
                    && text.lines().last().unwrap_or("").contains("without swapping Vox.app")
                    && text.lines().last().unwrap_or("").contains("retired bundle"),
                format!("refusal={}; repair={text}", said(&refused))));
            live_candidate.expect("APPARATUS: owned live candidate").quit();
            let swept = vox(&helper, home, &["update"], &env);
            claims.push(claim("bundle.recovery_removes_retired_code_only_after_graceful_exit",
                swept.status.success() && !retired.exists()
                    && said(&swept).lines().last().unwrap_or("").contains("removed 1 retired bundle"), said(&swept)));
        }
        receipts.insert(scenario.to_owned(), format!("update={}\nrollback={}", said(&updated), said(&rollback)));
    }
    dispose("signed one-launchable-app journey", &claims, &receipts, false);
}
