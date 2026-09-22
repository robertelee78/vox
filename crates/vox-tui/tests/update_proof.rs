//! Proof: `vox update` replaces a vox this tooling installed with the release GitHub is
//! serving, and refuses everything else.
//!
//! That sentence is the feature, so it is what gets measured — through the shipped `vox`
//! binary, against the real `github.com`, with real install directories on disk. Nothing here
//! calls a helper directly.
//!
//! ## Honest coverage
//! Two obligations cannot be met until there is a release to update *from*, and they are
//! reported as **unproven** rather than skipped (ADR-018 §3). The code that proves them is
//! written and self-enabling: it starts measuring the moment a second release exists.
//!
//! Set `VOX_PROOF_ALLOW_UNPROVEN=<id-or-prefix>[,…]` to accept a named gap. The gate command
//! ADR-018 records carries exactly the gaps that are accepted today, and removing one MUST make
//! this proof fail until it is closed.

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

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
    cmd.output().expect("the vox binary ran")
}

/// A directory that looks exactly like an install `install.sh` made: a real `vox`, and a marker
/// naming `channel`.
fn install_dir(root: &Path, channel: &str) -> PathBuf {
    let dir = root.join("bin");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(VOX, dir.join("vox")).unwrap();
    std::fs::write(dir.join(".vox-standalone.json"), marker_json(channel)).unwrap();
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
    std::fs::write(path, format!("#!/bin/sh\necho \"vox {version}\"\n")).unwrap();
    let mut p = std::fs::metadata(path).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut p, 0o755);
    std::fs::set_permissions(path, p).unwrap();
}

/// A stable fingerprint of a directory: every entry's name and length. Used to prove `--check`
/// changed nothing.
fn snapshot(dir: &Path) -> BTreeMap<String, u64> {
    std::fs::read_dir(dir)
        .unwrap()
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
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-gnu"
    } else {
        "unsupported"
    }
}

/// `(exit_ok, http_status, wrote_a_file)` for one curl against a real URL, with the exact
/// arguments `update.rs` uses — minus `--fail` when `fail` is false, which is the whole point.
fn curl_probe(url: &str, out: &Path, fail: bool) -> (bool, String, bool) {
    let mut cmd = Command::new("curl");
    if fail {
        cmd.arg("--fail");
    }
    cmd.args([
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
    let o = cmd.output().expect("curl ran");
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).trim().to_owned(),
        out.exists(),
    )
}

/// The version `stable` is serving for this target, straight from the release record.
fn published_version(triple: &str) -> Option<String> {
    let tmp = tempfile::tempdir().ok()?;
    let out = tmp.path().join("record.json");
    let url = format!("https://github.com/{REPO}/releases/latest/download/stable-{triple}.json");
    let (ok, _, _) = curl_probe(&url, &out, true);
    if !ok {
        return None;
    }
    let json = std::fs::read_to_string(&out).ok()?;
    let rest = json.split_once("\"version\":\"")?.1;
    let v: String = rest.chars().take_while(|c| *c != '"').collect();
    (!v.is_empty()).then_some(v)
}

/// The version of the newest release *other than* `newest` that carries our asset, if GitHub
/// will say. `gh` is the only thing that can list releases without an asset name to guess at;
/// when it is absent or unauthenticated the journey claim is reported unproven, not skipped.
fn earlier_release(newest: &str) -> Result<String, String> {
    let asset = format!("vox-{}", target_triple());
    let out = Command::new("gh")
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

#[test]
fn vox_update_replaces_an_install_it_owns_and_refuses_the_rest() {
    watchdog::arm();
    let mut claims: Vec<Claim> = Vec::new();
    let mut receipts: BTreeMap<String, String> = BTreeMap::new();
    let allowed: Vec<String> = std::env::var("VOX_PROOF_ALLOW_UNPROVEN")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    let triple = target_triple();

    // ---- refusals: a binary this tooling does not own is never touched ------------------
    {
        let tmp = tempfile::tempdir().unwrap();
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
        let tmp = tempfile::tempdir().unwrap();
        let loose = tmp.path().join("vox");
        std::fs::copy(VOX, &loose).unwrap();
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

    // ---- the live-world premise `install.sh` rests on: curl must fail closed ------------
    // `vox update` no longer shells out — it decides the status in Rust through reqwest — but
    // `install.sh` still uses curl, so this premise is load-bearing there and is measured
    // against the live endpoint rather than assumed.
    {
        let tmp = tempfile::tempdir().unwrap();
        let nonce = std::process::id();
        let url = format!(
            "https://github.com/{REPO}/releases/latest/download/no-such-asset-{nonce}.json"
        );
        let with = tmp.path().join("with-fail");
        let without = tmp.path().join("without-fail");
        let (ok_with, code_with, wrote_with) = curl_probe(&url, &with, true);
        let (ok_without, code_without, wrote_without) = curl_probe(&url, &without, false);
        let body = std::fs::read_to_string(&without).unwrap_or_default();

        if code_with.is_empty() || code_with == "000" {
            claims.push(blocked(
                "network.github_reachable",
                format!("curl reached nothing at {url} (offline?)"),
            ));
        } else {
            claims.push(claim(
                "install_sh.curl_fails_closed_on_404",
                !ok_with && code_with == "404" && !wrote_with,
                format!(
                    "with --fail: exit_ok={ok_with} http={code_with} wrote_file={wrote_with} \
                     (want exit_ok=false, 404, no file)"
                ),
            ));
            // The negative control. Without it the claim above could pass for the wrong
            // reason, and this is the exact behaviour that would have written `Not Found`
            // into a release record.
            claims.push(claim(
                "install_sh.curl_without_fail_writes_the_error_body",
                ok_without && code_without == "404" && wrote_without && body.contains("Not Found"),
                format!(
                    "without --fail: exit_ok={ok_without} http={code_without} \
                     wrote_file={wrote_without} body={body:?} (want exit_ok=true and a body)"
                ),
            ));
        }
    }

    // ---- the record lookup: the marker names the channel, and a 404 never parses --------
    {
        let tmp = tempfile::tempdir().unwrap();
        let dir = install_dir(tmp.path(), "proof-channel");
        let out = vox(&dir.join("vox"), tmp.path(), &["update", "--check"], &[]);
        let text = said(&out);
        claims.push(claim(
            "channel.marker_names_the_record",
            text.contains(&format!("proof-channel-{triple}.json")),
            format!("a marker saying `proof-channel` looked up {text:?}"),
        ));
        receipts.insert("channel.marker_names_the_record".into(), text);
    }
    {
        let tmp = tempfile::tempdir().unwrap();
        let dir = install_dir(tmp.path(), "stable");
        let before = snapshot(&dir);
        let out = vox(&dir.join("vox"), tmp.path(), &["update", "--check"], &[]);
        let text = said(&out);

        // Either there is a stable release and vox compared versions, or there is not and vox
        // refused. What it must never do is exit 0 having read an error page as a record.
        let compared = text.contains("is current") || text.contains("is available");
        let refused = !out.status.success() && text.contains(&format!("stable-{triple}.json"));
        claims.push(claim(
            "record.404_never_reads_as_a_release",
            (compared || refused)
                && !text.contains("Not Found")
                && (out.status.success() == compared),
            format!(
                "`vox update --check` on stable said {text:?} (exit_ok={})",
                out.status.success()
            ),
        ));
        claims.push(claim(
            "check.changes_nothing",
            snapshot(&dir) == before,
            format!("the install directory is {:?}", snapshot(&dir)),
        ));
        receipts.insert("record.stable_check".into(), text.clone());
    }

    // What version stable is actually serving, read from the record rather than from vox's
    // prose — a proof that depends on message wording measures the wording.
    let newest: Option<String> = published_version(triple);

    // ---- rollback: the binary you had comes back ----------------------------------------
    {
        let tmp = tempfile::tempdir().unwrap();
        let dir = install_dir(tmp.path(), "stable");
        previous_stub(&dir.join(".vox-previous"), "0.0.1-previous");
        let out = vox(&dir.join("vox"), tmp.path(), &["update", "--rollback"], &[]);
        let text = said(&out);
        let now = Command::new(dir.join("vox"))
            .arg("--version")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default();
        let kept = Command::new(dir.join(".vox-previous"))
            .arg("--version")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default();
        claims.push(claim(
            "rollback.restores_the_previous_binary",
            out.status.success() && now == "vox 0.0.1-previous" && kept.contains(VERSION),
            format!("after --rollback: active reports {now:?}, .vox-previous reports {kept:?}"),
        ));
        receipts.insert("rollback.restores_the_previous_binary".into(), text);
    }
    {
        let tmp = tempfile::tempdir().unwrap();
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
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let dir = install_dir(home, "stable");
        std::fs::copy(VOX, dir.join(".vox-previous")).unwrap();
        std::fs::write(home.join(".zshrc"), "export VOX_PROOF_USER_LINE=kept\n").unwrap();
        let out = vox(&dir.join("vox"), home, &["update", "--rollback"], &[]);
        let rc = std::fs::read_to_string(home.join(".zshrc")).unwrap_or_default();
        claims.push(claim(
            "rollback.refreshes_completions",
            out.status.success()
                && rc.contains(">>> vox >>>")
                && rc.contains("VOX_PROOF_USER_LINE=kept"),
            format!("after --rollback the rc is {rc:?}"),
        ));
        receipts.insert("rollback.refreshes_completions".into(), said(&out));
    }
    {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let dir = install_dir(home, "stable");
        std::fs::copy(VOX, dir.join(".vox-previous")).unwrap();
        std::fs::write(home.join(".zshrc"), "export VOX_PROOF_USER_LINE=kept\n").unwrap();
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
            format!("with VOX_NO_SHELL_SETUP=1 the rc is {rc:?}"),
        ));
    }

    // ---- the journey, and the refusal that needs a release to refuse -------------------
    match newest.as_deref().map(earlier_release) {
        None => {
            let why = "no stable release is published yet, so there is nothing to update from";
            claims.push(blocked("journey.update_replaces_an_older_install", why));
            claims.push(blocked("verify.digest_mismatch_is_refused", why));
        }
        Some(Err(why)) => {
            claims.push(blocked(
                "journey.update_replaces_an_older_install",
                why.clone(),
            ));
            claims.push(blocked("verify.digest_mismatch_is_refused", why));
        }
        Some(Ok(older)) => {
            let newest = newest.clone().unwrap_or_default();
            // The journey: install the older release, run *its* `vox update`, and require that
            // the binary in that directory afterwards is the newer one.
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let dir = home.join("bin");
            std::fs::create_dir_all(&dir).unwrap();
            let url = format!("https://github.com/{REPO}/releases/download/v{older}/vox-{triple}");
            let (ok, code, _) = curl_probe(&url, &dir.join("vox"), true);
            if !ok {
                claims.push(blocked(
                    "journey.update_replaces_an_older_install",
                    format!("v{older}'s binary could not be fetched (http {code})"),
                ));
                claims.push(blocked(
                    "verify.digest_mismatch_is_refused",
                    format!("v{older}'s binary could not be fetched (http {code})"),
                ));
            } else {
                let mut p = std::fs::metadata(dir.join("vox")).unwrap().permissions();
                std::os::unix::fs::PermissionsExt::set_mode(&mut p, 0o755);
                std::fs::set_permissions(dir.join("vox"), p).unwrap();
                std::fs::write(dir.join(".vox-standalone.json"), marker_json("stable")).unwrap();

                let out = vox(&dir.join("vox"), home, &["update"], &[]);
                let text = said(&out);
                let after = Command::new(dir.join("vox"))
                    .arg("--version")
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
                    .unwrap_or_default();
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
                            "v{older} updated itself and now reports {after:?} (want {newest})"
                        ),
                    ));
                }
                receipts.insert("journey.update".into(), text);

                // The same older binary, pointed at the `proof` channel, whose record names
                // the real asset with a deliberately wrong digest. Nothing on `stable` can
                // express this, which is why the channel exists.
                std::fs::write(dir.join(".vox-standalone.json"), marker_json("proof")).unwrap();
                let tampered = home.join("bin2");
                std::fs::create_dir_all(&tampered).unwrap();
                let (ok2, code2, _) = curl_probe(&url, &tampered.join("vox"), true);
                if !ok2 {
                    claims.push(blocked(
                        "verify.digest_mismatch_is_refused",
                        format!("could not stage the older binary again (http {code2})"),
                    ));
                } else {
                    let mut p = std::fs::metadata(tampered.join("vox"))
                        .unwrap()
                        .permissions();
                    std::os::unix::fs::PermissionsExt::set_mode(&mut p, 0o755);
                    std::fs::set_permissions(tampered.join("vox"), p).unwrap();
                    std::fs::write(tampered.join(".vox-standalone.json"), marker_json("proof"))
                        .unwrap();
                    let out = vox(&tampered.join("vox"), home, &["update"], &[]);
                    let text = said(&out);
                    let still = Command::new(tampered.join("vox"))
                        .arg("--version")
                        .output()
                        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
                        .unwrap_or_default();
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

    // ---- disposition: a blocked claim is missing evidence, not a pass -------------------
    println!("\n--- vox update proof ---");
    for c in &claims {
        println!("  [{}] {} — {}", c.status, c.id, c.detail);
    }
    for (k, v) in &receipts {
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

    assert!(
        failed.is_empty(),
        "{} claim(s) failed:\n{}",
        failed.len(),
        failed
            .iter()
            .map(|c| format!("  {} — {}", c.id, c.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        unproven.is_empty(),
        "{} claim(s) unproven — close the gap, or name it in VOX_PROOF_ALLOW_UNPROVEN to \
         accept it deliberately:\n{}",
        unproven.len(),
        unproven
            .iter()
            .map(|c| format!("  {} — {}", c.id, c.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
