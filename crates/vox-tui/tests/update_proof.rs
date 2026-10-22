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
//! [`an_update_and_rollback_leave_one_launchable_vox`] extends the same journey on macOS with
//! LaunchServices and the signed shipped app for ADR-014 M-29a. It too is optional and ignored:
//! it is ad hoc QE, never a CI or release gate.
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
/// `APPARATUS:` for a claim whose staging could not ask the world, unless that gap is accepted
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
        "APPARATUS: {} claim(s) unproven — close the staging gap, or name it in \
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
    app_bundle_as(dir, version, "us.vox.app", helper, Path::new(VOX))
}

/// A signed scratch app with an explicit identifier and launcher. The ordinary update journey
/// keeps its historical fixture above; M-29a uses a unique identifier and makes LaunchServices
/// run the release's distinguishable launcher through `open -b`.
#[cfg(target_os = "macos")]
fn app_bundle_as(
    dir: &Path,
    version: &str,
    identifier: &str,
    helper: &Path,
    launcher: &Path,
) -> PathBuf {
    let app = dir.join("Vox.app");
    let contents = app.join("Contents");
    for sub in ["MacOS", "Helpers"] {
        std::fs::create_dir_all(contents.join(sub))
            .unwrap_or_else(|e| panic!("APPARATUS: could not make {}: {e}", contents.display()));
    }
    copy(launcher, &contents.join("MacOS/Vox"));
    make_executable(&contents.join("MacOS/Vox"));
    copy(helper, &contents.join("Helpers/vox"));
    make_executable(&contents.join("Helpers/vox"));
    let parsed = semver::Version::parse(version)
        .unwrap_or_else(|e| panic!("APPARATUS: fixture version {version:?} is not SemVer: {e}"));
    let build = format!("{}.{}.{}", parsed.major + 1, parsed.minor, parsed.patch);
    let url_scheme = identifier.replace('.', "-");
    write(
        &contents.join("Info.plist"),
        &format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \
             \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\
             <key>CFBundleIdentifier</key><string>{identifier}</string>\
             <key>CFBundleExecutable</key><string>Vox</string>\
             <key>CFBundlePackageType</key><string>APPL</string>\
             <key>CFBundleShortVersionString</key><string>{version}</string>\
             <key>CFBundleVersion</key><string>{build}</string>\
             <key>CFBundleURLTypes</key><array><dict>\
             <key>CFBundleURLName</key><string>{identifier} room link</string>\
             <key>CFBundleURLSchemes</key><array><string>{url_scheme}</string></array>\
             <key>CFBundleTypeRole</key><string>Viewer</string>\
             </dict></array>\
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

/// Copy the candidate's real signed app into a scratch bundle, give that fixture the requested
/// release facts and helper, then re-sign it ad hoc after those fixture-only changes. Its main
/// executable remains the shipped Vox app; no script or test double decides which path opened.
#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
fn product_app_bundle_as(
    dir: &Path,
    signed_app: &Path,
    version: &str,
    identifier: &str,
    helper: &Path,
) -> PathBuf {
    let app = dir.join("Vox.app");
    let copied = Command::new("/usr/bin/ditto")
        .arg(signed_app)
        .arg(&app)
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not copy the signed app: {e}"));
    assert!(
        copied.status.success(),
        "APPARATUS: copying the signed app failed: {}",
        String::from_utf8_lossy(&copied.stderr)
    );
    let parsed = semver::Version::parse(version)
        .unwrap_or_else(|e| panic!("APPARATUS: fixture version {version:?} is not SemVer: {e}"));
    let build = format!("{}.{}.{}", parsed.major + 1, parsed.minor, parsed.patch);
    for (key, value) in [
        ("CFBundleIdentifier", identifier),
        ("CFBundleShortVersionString", version),
        ("CFBundleVersion", build.as_str()),
    ] {
        let changed = Command::new("/usr/libexec/PlistBuddy")
            .args(["-c", &format!("Set :{key} {value}")])
            .arg(app.join("Contents/Info.plist"))
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: could not set {key}: {e}"));
        assert!(
            changed.status.success(),
            "APPARATUS: setting {key} on the scratch app failed: {}",
            String::from_utf8_lossy(&changed.stderr)
        );
    }
    let url_scheme = identifier.replace('.', "-");
    for command in [
        "Delete :CFBundleURLTypes".to_owned(),
        "Add :CFBundleURLTypes array".to_owned(),
        "Add :CFBundleURLTypes:0 dict".to_owned(),
        format!("Add :CFBundleURLTypes:0:CFBundleURLName string {identifier} room link"),
        "Add :CFBundleURLTypes:0:CFBundleURLSchemes array".to_owned(),
        format!("Add :CFBundleURLTypes:0:CFBundleURLSchemes:0 string {url_scheme}"),
        "Add :CFBundleURLTypes:0:CFBundleTypeRole string Viewer".to_owned(),
    ] {
        let changed = Command::new("/usr/libexec/PlistBuddy")
            .args(["-c", &command])
            .arg(app.join("Contents/Info.plist"))
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: could not set scratch URL identity: {e}"));
        // The signed app is expected to have URL types; deleting an absent key is the only
        // harmless failure, and even that would mean the shipped fixture is not the app claimed.
        assert!(
            changed.status.success(),
            "APPARATUS: setting the scratch URL identity with {command:?} failed: {}",
            String::from_utf8_lossy(&changed.stderr)
        );
    }
    let extension = app.join("Contents/PlugIns/ShareExtension.appex");
    let extension_plist = extension.join("Contents/Info.plist");
    assert!(
        extension_plist.is_file(),
        "APPARATUS: the candidate app has no embedded ShareExtension Info.plist at {}",
        extension_plist.display()
    );
    let extension_identifier = format!("{identifier}.share");
    let changed = Command::new("/usr/libexec/PlistBuddy")
        .args([
            "-c",
            &format!("Set :CFBundleIdentifier {extension_identifier}"),
        ])
        .arg(&extension_plist)
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not identify the scratch extension: {e}"));
    assert!(
        changed.status.success(),
        "APPARATUS: identifying the scratch extension failed: {}",
        String::from_utf8_lossy(&changed.stderr)
    );
    let identified = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :CFBundleIdentifier"])
        .arg(&extension_plist)
        .output()
        .unwrap_or_else(|e| {
            panic!("APPARATUS: could not read the scratch extension identity: {e}")
        });
    assert!(
        identified.status.success()
            && String::from_utf8_lossy(&identified.stdout).trim() == extension_identifier,
        "APPARATUS: the scratch extension identity is not {extension_identifier:?}: stdout {:?}, stderr {:?}",
        String::from_utf8_lossy(&identified.stdout).trim(),
        String::from_utf8_lossy(&identified.stderr).trim()
    );
    let bundled_vox = app.join("Contents/Helpers/vox");
    std::fs::create_dir_all(
        bundled_vox
            .parent()
            .expect("APPARATUS: the bundled vox path has a parent"),
    )
    .unwrap_or_else(|e| panic!("APPARATUS: could not make Contents/Helpers: {e}"));
    copy(helper, &bundled_vox);
    make_executable(&bundled_vox);
    let signed = Command::new("/usr/bin/codesign")
        .args(["--force", "--deep", "--sign", "-"])
        .arg(&app)
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: could not sign the scratch product app: {e}"));
    assert!(
        signed.status.success(),
        "APPARATUS: signing the scratch product app failed: {}",
        String::from_utf8_lossy(&signed.stderr)
    );
    app
}

/// What an active bundle's real Info.plist says; kept metadata is never active-app evidence.
#[cfg(target_os = "macos")]
fn active_app_says(app: &Path) -> String {
    plist_says(&app.join("Contents/Info.plist"))
}

/// What a deliberately non-launchable retained bundle's exact kept plist says.
#[cfg(target_os = "macos")]
fn kept_app_says(app: &Path) -> String {
    plist_says(&app.join("Contents/Info.plist.kept"))
}

#[cfg(target_os = "macos")]
fn plist_says(info: &Path) -> String {
    Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", "Print :CFBundleShortVersionString"])
        .arg(info)
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
    bundle_release_of_as(
        root,
        version,
        "us.vox.app",
        helper,
        Path::new(VOX),
        channels,
    )
}

#[cfg(target_os = "macos")]
fn bundle_release_of_as(
    root: &Path,
    version: &str,
    identifier: &str,
    helper: &Path,
    launcher: &Path,
    channels: &[(&str, Option<&str>)],
) {
    let work = tmpdir();
    let app = app_bundle_as(work.path(), version, identifier, helper, launcher);
    bundle_release_app(root, version, &app, channels);
}

#[cfg(target_os = "macos")]
fn bundle_release_app(root: &Path, version: &str, app: &Path, channels: &[(&str, Option<&str>)]) {
    let triple = target_triple();
    let work = tmpdir();
    let zip_name = format!("Vox-{version}-{triple}.zip");
    let zip = work.path().join(&zip_name);
    let zipped = Command::new("/usr/bin/ditto")
        .args(["-c", "-k", "--keepParent"])
        .arg(app)
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
    bundle_install_as(
        home,
        channel,
        VERSION,
        "us.vox.app",
        Path::new(VOX),
        Path::new(VOX),
    )
}

#[cfg(target_os = "macos")]
fn bundle_install_as(
    home: &Path,
    channel: Option<&str>,
    version: &str,
    identifier: &str,
    helper: &Path,
    launcher: &Path,
) -> PathBuf {
    let apps = home.join("Apps");
    std::fs::create_dir_all(&apps).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
    app_bundle_as(&apps, version, identifier, helper, launcher);
    if let Some(channel) = channel {
        write(&apps.join(".vox-standalone.json"), &marker_json(channel));
    }
    let bin = home.join("bin");
    std::fs::create_dir_all(&bin).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
    std::os::unix::fs::symlink(apps.join("Vox.app/Contents/Helpers/vox"), bin.join("vox"))
        .unwrap_or_else(|e| panic!("APPARATUS: could not link vox: {e}"));
    bin.join("vox")
}

#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
fn bundle_install_product(
    home: &Path,
    channel: &str,
    signed_app: &Path,
    version: &str,
    identifier: &str,
    helper: &Path,
) -> PathBuf {
    let apps = home.join("Apps");
    std::fs::create_dir_all(&apps).unwrap_or_else(|e| panic!("APPARATUS: {e}"));
    product_app_bundle_as(&apps, signed_app, version, identifier, helper);
    write(&apps.join(".vox-standalone.json"), &marker_json(channel));
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
        let app = active_app_says(&apps.join("Vox.app"));
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
        let app = active_app_says(&apps.join("Vox.app"));
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
        let app = active_app_says(&apps.join("Vox.app"));
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
        let cut_app = active_app_says(&apps.join("Vox.app"));
        // The release's helper is a version stub, not vox; the next transition is run by a vox,
        // so the stub is replaced by this build (the bundle's version is its Info.plist's).
        copy(Path::new(VOX), &apps.join("Vox.app/Contents/Helpers/vox"));
        let out = vox(&link, home, &["update", "--rollback"], &base);
        let text = said(&out);
        let app = active_app_says(&apps.join("Vox.app"));
        let kept = kept_app_says(&apps.join(".Vox.app.previous"));
        claims.push(claim(
            "bundle.a_cut_update_keeps_the_bundle_it_replaced",
            !cut.status.success()
                && cut_app == NEWER
                && out.status.success()
                && app == VERSION
                && kept == NEWER
                && text.contains("finished the update cut short"),
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
    let mut path = None;
    let mut found = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("path:") {
            let value = value.trim();
            let value = value.split_once(" (0x").map_or(value, |(before, _)| before);
            path = Some(PathBuf::from(value));
        } else if line
            .strip_prefix("identifier:")
            .is_some_and(|value| value.trim() == identifier)
        {
            if let Some(value) = path.take() {
                found.push(value);
            }
        }
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
        let mut failures = Vec::new();
        self.extensions.sort();
        self.extensions.dedup();
        for extension in &self.extensions {
            match Command::new("/usr/bin/pluginkit")
                .arg("-r")
                .arg(extension)
                .output()
            {
                Ok(out) if out.status.success() => {}
                Ok(out) => failures.push(format!(
                    "pluginkit -r {} exited {}: {}",
                    extension.display(),
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                )),
                Err(e) => failures.push(format!(
                    "could not run pluginkit -r {}: {e}",
                    extension.display()
                )),
            }
        }
        self.bundles.sort();
        self.bundles.dedup();
        for bundle in &self.bundles {
            if let Err(why) = lsregister("-u", bundle) {
                failures.push(why);
            }
        }
        if !failures.is_empty() {
            let said = format!(
                "APPARATUS: LaunchServices cleanup failed: {}",
                failures.join("; ")
            );
            if std::thread::panicking() {
                eprintln!("{said}");
            } else {
                panic!("{said}");
            }
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

/// Ask LaunchServices to open one identifier, wait causally for either its application record or
/// the completed `open -W`, then read the exact path and terminate that scratch app. There is no
/// elapsed verdict and no retry count: a deadman may call a wedged observation APPARATUS, but a
/// slow launch remains allowed to make progress for as long as it needs.
#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
fn opened_bundle(
    identifier: &str,
    data: &Path,
    config: &Path,
    home: &Path,
) -> Result<OpenedBundle, String> {
    std::fs::create_dir_all(home)
        .map_err(|e| format!("could not make scratch HOME {}: {e}", home.display()))?;
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
    let mut child = opened
        .spawn()
        .map_err(|e| format!("could not open {identifier}: {e}"))?;
    let asn = loop {
        let found = Command::new("/usr/bin/lsappinfo")
            .args(["find", &format!("bundleid={identifier}")])
            .output()
            .map_err(|e| format!("could not ask for the opened app: {e}"))?;
        if let Some(asn) = String::from_utf8_lossy(&found.stdout)
            .lines()
            .next()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            break Some(asn.to_owned());
        }
        if child
            .try_wait()
            .map_err(|e| format!("could not observe open -W: {e}"))?
            .is_some()
        {
            break None;
        }
        // Each query blocks on LaunchServices IPC. Repeating it waits for the causal record; it
        // is not a clock and has no count at which absence becomes a product verdict.
    };
    let mut path = None;
    let mut observation_error = String::new();
    if let Some(asn) = &asn {
        let info = Command::new("/usr/bin/lsappinfo")
            .args(["info", "-only", "bundlepath", asn])
            .output()
            .map_err(|e| format!("could not read the opened app's path: {e}"))?;
        if !info.status.success() {
            return Err(format!(
                "lsappinfo could not read {asn}: {}",
                String::from_utf8_lossy(&info.stderr).trim()
            ));
        }
        let words = String::from_utf8_lossy(&info.stdout);
        path = words.lines().find_map(|line| {
            line.trim()
                .strip_prefix("bundle path=\"")
                .and_then(|value| value.strip_suffix('"'))
                .map(PathBuf::from)
        });
        let killed = Command::new("/usr/bin/lsappinfo")
            .args(["kill", "-hard", asn])
            .output()
            .map_err(|e| format!("could not terminate the scratch app: {e}"))?;
        if !killed.status.success() {
            observation_error = format!(
                "lsappinfo could not terminate {asn}: {}",
                String::from_utf8_lossy(&killed.stderr).trim()
            );
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("could not collect open -W: {e}"))?;
    let mut error = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    if !observation_error.is_empty() {
        if !error.is_empty() {
            error.push_str("; ");
        }
        error.push_str(&observation_error);
    }
    if asn.is_none() && out.status.success() {
        error.push_str("; LaunchServices made no application record for the opened identifier");
    }
    Ok(OpenedBundle {
        ok: out.status.success(),
        path,
        error,
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
fn preceding_patch(version: &str) -> Result<String, String> {
    let parsed = semver::Version::parse(version)
        .map_err(|e| format!("the app version {version:?} is not SemVer: {e}"))?;
    let patch = parsed.patch.checked_sub(1).ok_or_else(|| {
        format!("the candidate {version} has no preceding patch release for this ordering proof")
    })?;
    Ok(format!("{}.{}.{}", parsed.major, parsed.minor, patch))
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

#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
fn last_line(words: &str) -> &str {
    words
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
}

#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
fn place_scratch_app(path: &Path, version: &str, identifier: &str) {
    let work = tmpdir();
    let app = app_bundle_as(
        work.path(),
        version,
        identifier,
        Path::new(VOX),
        Path::new(VOX),
    );
    std::fs::rename(&app, path).unwrap_or_else(|e| {
        panic!(
            "APPARATUS: could not place scratch app at {}: {e}",
            path.display()
        )
    });
}

#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
fn stage_transition(journal: &Path, kind: &str, active: &Path, target: &Path, version: &str) {
    use std::os::unix::fs::MetadataExt as _;
    let active_id = std::fs::symlink_metadata(active)
        .unwrap_or_else(|e| panic!("APPARATUS: read {} identity: {e}", active.display()))
        .ino();
    let target_id = std::fs::symlink_metadata(target)
        .unwrap_or_else(|e| panic!("APPARATUS: read {} identity: {e}", target.display()))
        .ino();
    write(
        &journal.join("state"),
        &format!(
            "vox-app-transition-v1\nkind={kind}\nactive_id={active_id}\ntarget_id={target_id}\nversion={version}\n"
        ),
    );
}

/// ADR-014 M-29a: real scratch updates and rollbacks through the shipped `vox`, with
/// LaunchServices asked exactly as Finder/Dock/Spotlight ask it. Fully optional QE: ignored even
/// when compiled, absent from every CI and release gate.
#[cfg(all(target_os = "macos", feature = "optional-proofs"))]
#[test]
#[ignore = "optional macOS LaunchServices QE; run explicitly (docs/release/optional-proofs.md)"]
fn an_update_and_rollback_leave_one_launchable_vox() {
    test_knobs::require(&["VOX_TEST_RELEASE_BASE", "VOX_TEST_ABORT_AFTER_SWAP"]);
    let mut claims = Vec::new();
    let mut receipts = BTreeMap::new();
    let identity = tmpdir();
    let nonce: String = identity
        .path()
        .file_name()
        .expect("APPARATUS: unique identity directory has a name")
        .to_string_lossy()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let identifier = format!("us.vox.app.proof.m29a.{}.{}", std::process::id(), nonce);
    let shipped_app = std::env::var_os("VOX_PROOF_SHIPPED_APP")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!(
                "APPARATUS: VOX_PROOF_SHIPPED_APP must name the extracted Developer ID signed, notarized Vox.app from the release asset"
            )
        });
    let tree = tmpdir();
    let newer = tmpdir();
    let newer_vox = newer.path().join("vox");
    version_stub(&newer_vox, NEWER);
    let newer_app =
        product_app_bundle_as(newer.path(), &shipped_app, NEWER, &identifier, &newer_vox);
    bundle_release_app(tree.path(), NEWER, &newer_app, &[("stable", None)]);
    let server = release_server::serve(tree.path())
        .unwrap_or_else(|why| panic!("APPARATUS: the scratch release server: {why}"));
    let no_daemon = tmpdir();
    let no_data = no_daemon.path().join("data");
    let no_config = no_daemon.path().join("config");
    let base = [
        ("VOX_TEST_RELEASE_BASE", server.base.as_str()),
        ("VOX_NO_SHELL_SETUP", "1"),
        (
            "VOX_DATA_DIR",
            no_data.to_str().expect("APPARATUS: UTF-8 scratch path"),
        ),
        (
            "VOX_CONFIG_DIR",
            no_config.to_str().expect("APPARATUS: UTF-8 scratch path"),
        ),
    ];

    // ---- update, exact LaunchServices record, and opening by identifier -----------------
    // Mutant seams: omit `launch_services(false, previous)` for the record claim; omit the
    // Info.plist rename in `set_aside` for the non-application claim; and direct the identifier's
    // final registration to the displaced bundle for the independent open-selection claim.
    {
        let tmp = tmpdir();
        let home = tmp.path();
        let link = bundle_install_product(
            home,
            "stable",
            &shipped_app,
            VERSION,
            &identifier,
            Path::new(VOX),
        );
        let apps = home.join("Apps");
        let active = apps.join("Vox.app");
        let previous = apps.join(".Vox.app.previous");
        let mut registrations = LaunchServicesCleanup::new();
        registrations.remember(&active);
        registrations.remember(&previous);
        lsregister("-u", &active).unwrap_or_else(|why| panic!("APPARATUS: {why}"));
        let before_records =
            launch_services_paths(&identifier).unwrap_or_else(|why| panic!("APPARATUS: {why}"));
        assert!(
            !before_records.contains(&active),
            "APPARATUS: the unique scratch identifier already resolved to {} before the update: {before_records:?}",
            active.display()
        );
        let out = vox(&link, home, &["update"], &base);
        let text = said(&out);
        registrations.remember(&active);
        registrations.remember(&previous);
        let records =
            launch_services_paths(&identifier).unwrap_or_else(|why| panic!("APPARATUS: {why}"));
        let opened = opened_bundle(&identifier, &no_data, &no_config, &home.join("launch-home"))
            .unwrap_or_else(|why| panic!("APPARATUS: {why}"));
        claims.push(claim(
            "bundle.kept_bundle_is_not_an_application",
            out.status.success()
                && !previous.join("Contents/Info.plist").exists()
                && previous.join("Contents/Info.plist.kept").is_file(),
            format!(
                "update exit_ok={}; kept Info.plist={}, kept copy={}; said {text:?}",
                out.status.success(),
                previous.join("Contents/Info.plist").exists(),
                previous.join("Contents/Info.plist.kept").is_file()
            ),
        ));
        claims.push(claim(
            "bundle.kept_bundle_has_no_launchservices_record",
            !records.contains(&previous),
            format!("LaunchServices paths for {identifier}: {records:?}"),
        ));
        claims.push(claim(
            "bundle.opening_the_identifier_selects_the_current_bundle",
            out.status.success()
                && records.contains(&active)
                && opened.ok
                && opened.path.as_deref() == Some(active.as_path()),
            format!(
                "`open -b {identifier}` exit_ok={} opened {:?}, wanted {}; stderr {:?}",
                opened.ok,
                opened.path,
                active.display(),
                opened.error
            ),
        ));

        // Restoring the kept plist only under the non-application rollback staging name is the
        // rollback mutant seam: without it the exchange moves bytes but cannot restore a signed,
        // launchable prior app.
        let rollback = vox(&link, home, &["update", "--rollback"], &base);
        let rollback_text = said(&rollback);
        let records =
            launch_services_paths(&identifier).unwrap_or_else(|why| panic!("APPARATUS: {why}"));
        let opened = opened_bundle(
            &identifier,
            &no_data,
            &no_config,
            &home.join("rollback-launch-home"),
        )
        .unwrap_or_else(|why| panic!("APPARATUS: {why}"));
        let signature = signed(&active);
        claims.push(claim(
            "bundle.rollback_restores_one_signed_launchable_prior_bundle",
            rollback.status.success()
                && opened.ok
                && opened.path.as_deref() == Some(active.as_path())
                && active_app_says(&active) == VERSION
                && signature.is_ok()
                && active.join("Contents/Info.plist").is_file()
                && !previous.join("Contents/Info.plist").exists()
                && previous.join("Contents/Info.plist.kept").is_file()
                && !records.contains(&previous),
            format!(
                "rollback exit_ok={}; open exit_ok={} selected {:?}, stderr {:?}; active version {:?}; signature={signature:?}; active plist={}; displaced plist={}; records={records:?}; said {rollback_text:?}",
                rollback.status.success(),
                opened.ok,
                opened.path,
                opened.error,
                active_app_says(&active),
                active.join("Contents/Info.plist").is_file(),
                previous.join("Contents/Info.plist").exists(),
            ),
        ));
        receipts.insert("m29a.update".into(), text);
        receipts.insert("m29a.rollback".into(), rollback_text);
    }

    // A repair-only update needs a record for this build, so it takes the `is current` path after
    // recovery. The active bundle's inode is the causal no-swap observation.
    let current_tree = tmpdir();
    bundle_release_of_as(
        current_tree.path(),
        VERSION,
        &identifier,
        Path::new(VOX),
        Path::new(VOX),
        &[("stable", None)],
    );
    let current_server = release_server::serve(current_tree.path())
        .unwrap_or_else(|why| panic!("APPARATUS: the current scratch release server: {why}"));
    let current_base = [
        ("VOX_TEST_RELEASE_BASE", current_server.base.as_str()),
        ("VOX_NO_SHELL_SETUP", "1"),
        base[2],
        base[3],
    ];

    // ---- reserved transition names never follow a symlink or accept a non-directory -------
    // Mutant seam: replace `symlink_metadata` validation with metadata-following existence.
    {
        use std::os::unix::fs::symlink;
        let mut evidence = Vec::new();
        let mut all_refused = true;
        for kind in ["symlink", "file", "nested-contents-symlink"] {
            let tmp = tmpdir();
            let home = tmp.path();
            let link = bundle_install_as(
                home,
                Some("stable"),
                VERSION,
                &identifier,
                Path::new(VOX),
                Path::new(VOX),
            );
            let apps = home.join("Apps");
            let active = apps.join("Vox.app");
            let reserved = apps.join(".Vox.app.previous");
            match kind {
                "symlink" => symlink(&active, &reserved)
                    .expect("APPARATUS: stage reserved-path symlink to active app"),
                "file" => write(&reserved, "not a bundle\n"),
                "nested-contents-symlink" => {
                    std::fs::create_dir(&reserved)
                        .expect("APPARATUS: stage direct reserved bundle directory");
                    symlink(active.join("Contents"), reserved.join("Contents"))
                        .expect("APPARATUS: stage nested Contents symlink to active app");
                }
                _ => unreachable!(),
            }
            let out = vox(&link, home, &["update"], &current_base);
            let text = said(&out);
            let safe = !out.status.success()
                && std::fs::symlink_metadata(&reserved).is_ok()
                && active.join("Contents/Info.plist").is_file()
                && !active.join("Contents/Info.plist.kept").exists()
                && text.contains("not a direct directory")
                && text.contains("no transition was attempted");
            all_refused &= safe;
            evidence.push(format!(
                "{kind}: exit_ok={}, reserved remains={}, active plist={}, said {text:?}",
                out.status.success(),
                std::fs::symlink_metadata(&reserved).is_ok(),
                active.join("Contents/Info.plist").is_file()
            ));
        }
        claims.push(claim(
            "bundle.reserved_transition_paths_refuse_symlinks_and_non_directories",
            all_refused,
            evidence.join("; "),
        ));
    }

    // ---- a stale updater cannot replace the genuine rollback release ---------------------
    // Mutant seam: remove the under-lock active-app version revalidation in `update`.
    {
        use std::os::unix::fs::MetadataExt as _;
        let tmp = tmpdir();
        let home = tmp.path();
        let link = bundle_install_product(
            home,
            "stable",
            &shipped_app,
            VERSION,
            &identifier,
            Path::new(VOX),
        );
        let apps = home.join("Apps");
        let active = apps.join("Vox.app");
        let previous = apps.join(".Vox.app.previous");
        let first = vox(&link, home, &["update"], &base);
        let rollback_id = std::fs::metadata(&previous)
            .expect("APPARATUS: first update retained rollback app")
            .ino();
        // This exact old shipped binary represents an updater that made its release decision
        // before another updater completed. Its executable path remains inside the active app.
        copy(Path::new(VOX), &active.join("Contents/Helpers/vox"));
        let stale = vox(&link, home, &["update"], &base);
        let after_id = std::fs::metadata(&previous)
            .expect("APPARATUS: stale updater retained rollback app")
            .ino();
        claims.push(claim(
            "bundle.stale_updater_keeps_the_genuine_rollback_release",
            first.status.success()
                && stale.status.success()
                && rollback_id == after_id
                && active_app_says(&active) == NEWER
                && kept_app_says(&previous) == VERSION
                && said(&stale).contains("is current"),
            format!(
                "first exit_ok={}; stale exit_ok={}; rollback inode {rollback_id}->{after_id}; active {:?}, previous {:?}; stale said {:?}",
                first.status.success(),
                stale.status.success(),
                active_app_says(&active),
                kept_app_says(&previous),
                said(&stale)
            ),
        ));
    }

    // ---- recovery: rollback cut after its journal, before its atomic exchange -------------
    // Mutant seam: omit the rollback-before-exchange arm in `recover`.
    {
        use std::os::unix::fs::MetadataExt as _;
        let tmp = tmpdir();
        let home = tmp.path();
        let link = bundle_install_as(
            home,
            Some("stable"),
            VERSION,
            &identifier,
            Path::new(VOX),
            Path::new(VOX),
        );
        let apps = home.join("Apps");
        let active = apps.join("Vox.app");
        let previous = apps.join(".Vox.app.previous");
        place_scratch_app(&previous, "0.4.8", &identifier);
        std::fs::rename(
            previous.join("Contents/Info.plist"),
            previous.join("Contents/Info.plist.kept"),
        )
        .expect("APPARATUS: stage kept rollback app");
        let target_id = std::fs::metadata(&previous)
            .expect("APPARATUS: staged rollback target")
            .ino();
        let journal = apps.join(".Vox.app.publishing");
        std::fs::create_dir(&journal).expect("APPARATUS: make rollback journal");
        stage_transition(&journal, "rollback", &active, &previous, "0.4.8");
        let repaired = vox(&link, home, &["update"], &current_base);
        let text = said(&repaired);
        let active_id = std::fs::metadata(&active)
            .expect("APPARATUS: active app after rollback recovery")
            .ino();
        claims.push(claim(
            "bundle.recovery_finishes_a_journalled_rollback_before_its_exchange",
            repaired.status.success()
                && active_id == target_id
                && active_app_says(&active) == "0.4.8"
                && !previous.join("Contents/Info.plist").exists()
                && previous.join("Contents/Info.plist.kept").is_file()
                && !journal.exists()
                && last_line(&text).contains("completing its recorded Vox.app exchange")
                && last_line(&text).contains("rollback cut short"),
            format!(
                "repair exit_ok={}; target inode={target_id}, active inode={active_id}, version {:?}; previous kept={}; journal={}; final {:?}",
                repaired.status.success(),
                active_app_says(&active),
                previous.join("Contents/Info.plist.kept").is_file(),
                journal.exists(),
                last_line(&text)
            ),
        ));
    }

    // ---- recovery: rollback cut immediately after its atomic exchange --------------------
    // Mutant seam: omit the rollback-after-exchange arm in `recover`.
    {
        use std::os::unix::fs::MetadataExt as _;
        let tmp = tmpdir();
        let home = tmp.path();
        let link = bundle_install_product(
            home,
            "stable",
            &shipped_app,
            VERSION,
            &identifier,
            Path::new(VOX),
        );
        let apps = home.join("Apps");
        let active = apps.join("Vox.app");
        let previous = apps.join(".Vox.app.previous");
        let mut registrations = LaunchServicesCleanup::new();
        registrations.remember(&active);
        registrations.remember(&previous);
        let updated = vox(&link, home, &["update"], &base);
        copy(Path::new(VOX), &active.join("Contents/Helpers/vox"));
        let cut_env: Vec<(&str, &str)> = current_base
            .iter()
            .copied()
            .chain([("VOX_TEST_ABORT_AFTER_SWAP", "1")])
            .collect();
        let cut = vox(&link, home, &["update", "--rollback"], &cut_env);
        let rollback_staged = apps.join(".Vox.rollback.partial");
        registrations.remember(&rollback_staged);
        let before = std::fs::metadata(&active)
            .expect("APPARATUS: active app after interrupted rollback")
            .ino();
        let interrupted_open = opened_bundle(
            &identifier,
            &no_data,
            &no_config,
            &home.join("interrupted-rollback-launch-home"),
        )
        .unwrap_or_else(|why| panic!("APPARATUS: {why}"));
        let interrupted_has_one_application = active.join("Contents/Info.plist").is_file()
            && !previous.exists()
            && rollback_staged.join("Contents/Info.plist").is_file()
            && !rollback_staged
                .file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with(".app"));
        let repaired = vox(&link, home, &["update"], &current_base);
        let text = said(&repaired);
        let after = std::fs::metadata(&active)
            .expect("APPARATUS: active app after rollback repair")
            .ino();
        claims.push(claim(
            "bundle.recovery_finishes_an_interrupted_rollback_without_another_swap",
            updated.status.success()
                && !cut.status.success()
                && interrupted_has_one_application
                && interrupted_open.ok
                && interrupted_open.path.as_deref() == Some(active.as_path())
                && repaired.status.success()
                && before == after
                && active_app_says(&active) == VERSION
                && !previous.join("Contents/Info.plist").exists()
                && previous.join("Contents/Info.plist.kept").is_file()
                && !apps.join(".Vox.app.publishing").exists()
                && last_line(&text).contains("without another Vox.app exchange")
                && last_line(&text).contains("rollback cut short"),
            format!(
                "update exit_ok={}; cut exit_ok={}; interrupted one application={interrupted_has_one_application}, open selected {:?}; repair exit_ok={}; active inode {before}->{after}, version {:?}; previous kept={}; final {:?}",
                updated.status.success(),
                cut.status.success(),
                interrupted_open.path,
                repaired.status.success(),
                active_app_says(&active),
                previous.join("Contents/Info.plist.kept").is_file(),
                last_line(&text)
            ),
        ));
    }

    // ---- recovery: every valid journal state before the atomic swap -----------------------
    // The journal may be cut before an older previous bundle moves, after it moves, or with no
    // older previous bundle. In each case the active app never changed, the unpublished partial
    // is discarded, any rollback bundle is retained, and the shipped command says that exact
    // repair without claiming another swap. Mutant seam: omit the pre-swap recovery/report arm.
    {
        use std::os::unix::fs::MetadataExt as _;
        let mut evidence = Vec::new();
        let mut all_repaired = true;
        for prior in ["unversioned", "none", "unmoved", "journalled"] {
            let tmp = tmpdir();
            let home = tmp.path();
            let link = bundle_install_as(
                home,
                Some("stable"),
                VERSION,
                &identifier,
                Path::new(VOX),
                Path::new(VOX),
            );
            let apps = home.join("Apps");
            let active = apps.join("Vox.app");
            let partial = apps.join(".Vox.app.partial");
            let previous = apps.join(".Vox.app.previous");
            let journal = apps.join(".Vox.app.publishing");
            std::fs::create_dir(&journal).expect("APPARATUS: make publish journal");
            place_scratch_app(&partial, NEWER, &identifier);
            match prior {
                "unversioned" | "none" => {}
                "unmoved" => place_scratch_app(&previous, "0.4.8", &identifier),
                "journalled" => place_scratch_app(&journal.join("Vox.app"), "0.4.8", &identifier),
                _ => unreachable!(),
            }
            if prior != "unversioned" {
                stage_transition(&journal, "publish", &active, &partial, NEWER);
            }
            let before = std::fs::metadata(&active)
                .expect("APPARATUS: active pre-swap app")
                .ino();
            let repaired = vox(&link, home, &["update"], &current_base);
            let text = said(&repaired);
            let after = std::fs::metadata(&active)
                .expect("APPARATUS: active app after pre-swap recovery")
                .ino();
            let previous_ok = if matches!(prior, "unversioned" | "none") {
                !previous.exists()
            } else {
                !previous.join("Contents/Info.plist").exists()
                    && previous.join("Contents/Info.plist.kept").is_file()
            };
            let ok = repaired.status.success()
                && before == after
                && !partial.exists()
                && !journal.exists()
                && previous_ok
                && last_line(&text).contains("without swapping Vox.app")
                && (if prior == "unversioned" {
                    last_line(&text).contains("before its durable record")
                } else {
                    last_line(&text).contains("before Vox 99.0.0 was put in place")
                })
                && (prior == "unversioned"
                    || last_line(&text).contains("discarded its unpublished candidate"));
            all_repaired &= ok;
            evidence.push(format!(
                "{prior}: exit_ok={}, inode {before}->{after}, partial={}, journal={}, previous_ok={previous_ok}, final {:?}",
                repaired.status.success(),
                partial.exists(),
                journal.exists(),
                last_line(&text)
            ));
        }
        claims.push(claim(
            "bundle.recovery_reports_every_pre_swap_journal_state_without_a_swap",
            all_repaired,
            evidence.join("; "),
        ));
    }

    // ---- recovery: a publish cut after its swap, then a same-version update ---------------
    // Mutant seam: omit the published-version branch in `recover`.
    {
        use std::os::unix::fs::MetadataExt as _;
        let tmp = tmpdir();
        let home = tmp.path();
        let link = bundle_install_as(
            home,
            Some("stable"),
            VERSION,
            &identifier,
            Path::new(VOX),
            Path::new(VOX),
        );
        let apps = home.join("Apps");
        let active = apps.join("Vox.app");
        let interrupted_env: Vec<(&str, &str)> = base
            .iter()
            .copied()
            .chain([("VOX_TEST_ABORT_AFTER_SWAP", "1")])
            .collect();
        let cut = vox(&link, home, &["update"], &interrupted_env);
        copy(Path::new(VOX), &active.join("Contents/Helpers/vox"));
        let before = std::fs::metadata(&active)
            .expect("APPARATUS: active app after cut")
            .ino();
        let repaired = vox(&link, home, &["update"], &current_base);
        let text = said(&repaired);
        let after = std::fs::metadata(&active)
            .expect("APPARATUS: active app after repair")
            .ino();
        claims.push(claim(
            "bundle.recovery_finishes_an_interrupted_publish_without_another_swap",
            !cut.status.success()
                && repaired.status.success()
                && before == after
                && active_app_says(&active) == NEWER
                && apps.join(".Vox.app.previous/Contents/Info.plist.kept").is_file()
                && !apps.join(".Vox.app.publishing").exists()
                && last_line(&text).contains("without swapping Vox.app")
                && last_line(&text).contains("cut short"),
            format!(
                "cut exit_ok={}; repair exit_ok={}; active inode {before}->{after}, version {:?}; final {:?}; said {text:?}",
                cut.status.success(),
                repaired.status.success(),
                active_app_says(&active),
                last_line(&text)
            ),
        ));
    }

    // ---- recovery: the replaced app was already retained before interruption -------------
    // A cut after the partial was renamed, and a later cut after it was already set aside, have
    // no remaining rename to reveal the interruption. Journal presence plus the active version
    // must still be reported. Mutant seam: record interruption only in the staged->previous arm.
    {
        use std::os::unix::fs::MetadataExt as _;
        let mut evidence = Vec::new();
        let mut all_repaired = true;
        for already_set_aside in [false, true] {
            let tmp = tmpdir();
            let home = tmp.path();
            let link = bundle_install_as(
                home,
                Some("stable"),
                VERSION,
                &identifier,
                Path::new(VOX),
                Path::new(VOX),
            );
            let apps = home.join("Apps");
            let active = apps.join("Vox.app");
            let previous = apps.join(".Vox.app.previous");
            std::fs::rename(&active, &previous)
                .expect("APPARATUS: retain old active for staged post-swap state");
            place_scratch_app(&active, NEWER, &identifier);
            if already_set_aside {
                std::fs::rename(
                    previous.join("Contents/Info.plist"),
                    previous.join("Contents/Info.plist.kept"),
                )
                .expect("APPARATUS: stage already-set-aside previous app");
            }
            let mut registrations = LaunchServicesCleanup::new();
            registrations.remember(&previous);
            if !already_set_aside {
                registrations
                    .register(&previous)
                    .unwrap_or_else(|why| panic!("APPARATUS: {why}"));
            }
            let journal = apps.join(".Vox.app.publishing");
            std::fs::create_dir(&journal).expect("APPARATUS: make post-swap journal");
            stage_transition(&journal, "publish", &previous, &active, NEWER);
            if !already_set_aside {
                // The publish had an older rollback bundle before the now-active release. Once
                // the replaced active is retained, this third generation is cleared with the
                // journal, another valid boundary before journal removal.
                place_scratch_app(&journal.join("Vox.app"), "0.4.7", &identifier);
            }
            let before = std::fs::metadata(&active)
                .expect("APPARATUS: active post-swap app")
                .ino();
            let repaired = vox(&link, home, &["update"], &current_base);
            let text = said(&repaired);
            let records =
                launch_services_paths(&identifier).unwrap_or_else(|why| panic!("APPARATUS: {why}"));
            let after = std::fs::metadata(&active)
                .expect("APPARATUS: active after post-rename recovery")
                .ino();
            let ok = repaired.status.success()
                && before == after
                && !journal.exists()
                && !previous.join("Contents/Info.plist").exists()
                && previous.join("Contents/Info.plist.kept").is_file()
                && !records.contains(&previous)
                && last_line(&text).contains("without swapping Vox.app")
                && last_line(&text).contains("after Vox 99.0.0 was put in place")
                && last_line(&text).contains("kept the replaced app for rollback");
            all_repaired &= ok;
            evidence.push(format!(
                "set_aside={already_set_aside}: exit_ok={}, inode {before}->{after}, journal={}, previous kept={}, LaunchServices={records:?}, final {:?}",
                repaired.status.success(),
                journal.exists(),
                previous.join("Contents/Info.plist.kept").is_file(),
                last_line(&text)
            ));
        }
        claims.push(claim(
            "bundle.recovery_reports_post_rename_and_post_set_aside_journals",
            all_repaired,
            evidence.join("; "),
        ));
    }

    // ---- recovery: set-aside failed, then the exact obstruction is removed ----------------
    // Mutant seam: omit the no-journal previous-bundle `set_aside` retry in `recover`.
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let tmp = tmpdir();
        let home = tmp.path();
        let link = bundle_install_as(
            home,
            Some("stable"),
            VERSION,
            &identifier,
            Path::new(VOX),
            Path::new(VOX),
        );
        let apps = home.join("Apps");
        let active = apps.join("Vox.app");
        let previous_work = tmpdir();
        let previous = app_bundle_as(
            previous_work.path(),
            "0.4.8",
            &identifier,
            Path::new(VOX),
            Path::new(VOX),
        );
        let kept = apps.join(".Vox.app.previous");
        std::fs::rename(previous, &kept).expect("APPARATUS: place previous app");
        let mut registrations = LaunchServicesCleanup::new();
        registrations.remember(&kept);
        registrations
            .register(&kept)
            .unwrap_or_else(|why| panic!("APPARATUS: {why}"));
        let before = std::fs::metadata(&active)
            .expect("APPARATUS: active app")
            .ino();
        let mut permissions = std::fs::metadata(kept.join("Contents"))
            .expect("APPARATUS: previous Contents")
            .permissions();
        let writable_mode = permissions.mode();
        permissions.set_mode(writable_mode & !0o222);
        std::fs::set_permissions(kept.join("Contents"), permissions)
            .expect("APPARATUS: make previous Contents read-only");
        let refused = vox(&link, home, &["update"], &current_base);
        let mut permissions = std::fs::metadata(kept.join("Contents"))
            .expect("APPARATUS: previous Contents after refusal")
            .permissions();
        permissions.set_mode(writable_mode);
        std::fs::set_permissions(kept.join("Contents"), permissions)
            .expect("APPARATUS: restore previous Contents permissions");
        let repaired = vox(&link, home, &["update"], &current_base);
        let text = said(&repaired);
        let records =
            launch_services_paths(&identifier).unwrap_or_else(|why| panic!("APPARATUS: {why}"));
        let after = std::fs::metadata(&active)
            .expect("APPARATUS: active app after repair")
            .ino();
        claims.push(claim(
            "bundle.recovery_retries_a_failed_set_aside_without_a_swap",
            !refused.status.success()
                && repaired.status.success()
                && before == after
                && !kept.join("Contents/Info.plist").exists()
                && kept.join("Contents/Info.plist.kept").is_file()
                && !records.contains(&kept)
                && last_line(&text).contains("without swapping Vox.app")
                && last_line(&text).contains("previous bundle"),
            format!(
                "refusal exit_ok={} said {:?}; repair exit_ok={}; inode {before}->{after}; LaunchServices={records:?}; final {:?}",
                refused.status.success(),
                said(&refused),
                repaired.status.success(),
                last_line(&text)
            ),
        ));
    }

    // ---- recovery: a retired bundle still executing is disarmed, then swept after exit ----
    // Mutant seam: omit `sweep`'s set-aside-before-in-use check.
    {
        use std::io::{BufRead as _, Write as _};
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let tmp = tmpdir();
        let home = tmp.path();
        let link = bundle_install_as(
            home,
            Some("stable"),
            VERSION,
            &identifier,
            Path::new(VOX),
            Path::new(VOX),
        );
        let apps = home.join("Apps");
        let active = apps.join("Vox.app");
        let work = tmpdir();
        let fixture = app_bundle_as(
            work.path(),
            "0.4.8",
            &identifier,
            Path::new(VOX),
            Path::new(VOX),
        );
        let retired = apps.join(".Vox.app.retired.proof");
        std::fs::rename(fixture, &retired).expect("APPARATUS: place retired app");
        let mut registrations = LaunchServicesCleanup::new();
        registrations.remember(&retired);
        registrations
            .register(&retired)
            .unwrap_or_else(|why| panic!("APPARATUS: {why}"));
        let hold = retired.join("Contents/MacOS/hold");
        copy(Path::new("/bin/sh"), &hold);
        let mut permissions = std::fs::metadata(&hold)
            .expect("APPARATUS: retired hold executable")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&hold, permissions)
            .expect("APPARATUS: chmod retired hold executable");
        let mut child = Command::new(&hold)
            .args(["-c", "echo READY; read answer"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("APPARATUS: start exact retired executable");
        let mut ready = String::new();
        std::io::BufReader::new(child.stdout.take().expect("APPARATUS: retired stdout"))
            .read_line(&mut ready)
            .expect("APPARATUS: read retired readiness event");
        assert_eq!(
            ready.trim(),
            "READY",
            "APPARATUS: retired process did not become ready"
        );
        let before = std::fs::metadata(&active)
            .expect("APPARATUS: active app")
            .ino();
        let first = vox(&link, home, &["update"], &current_base);
        let first_text = said(&first);
        let after = std::fs::metadata(&active)
            .expect("APPARATUS: active app after repair")
            .ino();
        let disarmed = retired.exists()
            && !retired.join("Contents/Info.plist").exists()
            && retired.join("Contents/Info.plist.kept").is_file();
        let first_records =
            launch_services_paths(&identifier).unwrap_or_else(|why| panic!("APPARATUS: {why}"));
        if let Some(mut input) = child.stdin.take() {
            let _ = writeln!(input, "done");
        }
        let status = child.wait().expect("APPARATUS: exact retired process exit");
        let second = vox(&link, home, &["update"], &current_base);
        let second_text = said(&second);
        let second_records =
            launch_services_paths(&identifier).unwrap_or_else(|why| panic!("APPARATUS: {why}"));
        claims.push(claim(
            "bundle.recovery_disarms_a_retired_live_bundle_then_removes_it_after_exit",
            first.status.success()
                && before == after
                && disarmed
                && !first_records.contains(&retired)
                && last_line(&first_text).contains("without swapping Vox.app")
                && last_line(&first_text).contains("retired bundle")
                && status.success()
                && second.status.success()
                && !retired.exists()
                && !second_records.contains(&retired)
                && last_line(&second_text).contains("without swapping Vox.app")
                && last_line(&second_text).contains("removed 1 retired bundle"),
            format!(
                "first exit_ok={}, inode {before}->{after}, disarmed={disarmed}, LaunchServices={first_records:?}, process={status}; second exit_ok={}, retired exists={}, LaunchServices={second_records:?}; first final {:?}; second final {:?}",
                first.status.success(),
                second.status.success(),
                retired.exists(),
                last_line(&first_text),
                last_line(&second_text)
            ),
        ));
    }

    // The exact shipped app build supplied by the QE runner: signature, documented build-number
    // form, and strict increase over the previous release fact staged by the update journey.
    // Mutant seam: restore CURRENT_PROJECT_VERSION=1 in the release app build.
    let short = plist_value(&shipped_app, "CFBundleShortVersionString")
        .unwrap_or_else(|why| panic!("APPARATUS: {why}"));
    let build = plist_value(&shipped_app, "CFBundleVersion")
        .unwrap_or_else(|why| panic!("APPARATUS: {why}"));
    let expected = expected_build_version(&short).unwrap_or_else(|why| panic!("APPARATUS: {why}"));
    let previous = preceding_patch(&short).unwrap_or_else(|why| panic!("APPARATUS: {why}"));
    let previous_build =
        expected_build_version(&previous).unwrap_or_else(|why| panic!("APPARATUS: {why}"));
    let signature = shipped_notarized(&shipped_app);
    let order = (
        semver::Version::parse(&build),
        semver::Version::parse(&previous_build),
    );
    claims.push(claim(
        "bundle.shipped_build_number_grows_in_apples_documented_form",
        signature.is_ok()
            && short == VERSION
            && build == expected
            && matches!(order, (Ok(ref now), Ok(ref before)) if now > before),
        format!(
            "{} says short={short:?}, build={build:?}, expected={expected:?}, previous={previous_build:?}, signature={signature:?}",
            shipped_app.display()
        ),
    ));

    dispose(
        "one launchable Vox optional proof",
        &claims,
        &receipts,
        false,
    );
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
