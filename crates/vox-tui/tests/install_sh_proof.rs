//! Proof: `install.sh` installs a release it verified, and refuses one it could not.
//!
//! The installer is the first thing anybody runs, and every check in it — record identity,
//! size, SHA-256, "do not overwrite a binary I did not install" — is a refusal that has to
//! actually fire. None of it can be measured against `github.com`, because proving a refusal
//! requires publishing something broken. So this stands up a **loopback release server** with
//! a real release tree on it, points the installer at it with `VOX_RELEASE_BASE` (the hook the
//! script documents for exactly this), and runs the real `install.sh` under `sh`.
//!
//! The binary served as "the release" is the one cargo just built, so a successful install is
//! observable the way a user observes it: `vox --version` runs from the install directory.
//!
//! Owned macOS reruns use the real target updater. Controlled interruption therefore needs
//! `test-knobs` and `VOX_PROOF_NEXT_BINARY`, a genuinely compiled next-version helper (9.4.14
//! for 0.4.14). The existing loopback transport does not establish normal release trust:
//! Developer ID/notarization and native app/profile handoff remain separate optional journeys.
//!
//! On macOS the release is Vox.app carrying that `vox` at `Contents/Helpers/vox` (ADR-014 M-28):
//! the installer puts the app in the folder `VOX_APPLICATIONS_DIR` names (a scratch stand-in for
//! `/Applications`, so the proof never touches the real one) or in `~/Applications` when that
//! folder is not writable, and links `~/.local/bin/vox` into the bundle. An Intel Mac or a Mac
//! before macOS 13 is told so before anything is downloaded; the proof stands in for such a Mac
//! with `uname`, `sysctl` and `sw_vers` shims on `PATH` and counts the release server's requests.
//!
//! This lives in `vox-tui`'s tests because it needs `vox` itself as the release payload.

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

#[path = "support/release_server.rs"]
mod release_server;
use release_server::{serve, Server};

#[path = "support/attach.rs"]
mod unlock_staging;

#[cfg(target_os = "linux")]
#[path = "support/dead_candidate.rs"]
mod dead_candidate;

#[path = "support/optional_proof.rs"]
mod optional_proof;
optional_proof::not_run!(
    the_linux_release_asset_installs_only_where_it_runs,
    the_linux_release_installer_refuses_below_its_floor,
    the_linux_release_installer_names_a_missing_loader,
);

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// **Every red names which it is** (the decider's rule 1). A step of the proof's own staging that
/// fails — a file, a process, the release server — is `APPARATUS (harness error)` at its line;
/// a claim `install.sh` broke is `PRODUCT:` (see [`report`]). Nothing here unwraps bare.
trait Staged<T> {
    /// The value, or `APPARATUS (harness error)` naming this line and what failed.
    fn staged(self) -> T;
}

impl<T, E: std::fmt::Debug> Staged<T> for Result<T, E> {
    #[track_caller]
    fn staged(self) -> T {
        let at = std::panic::Location::caller();
        self.unwrap_or_else(|e| panic!("APPARATUS (harness error) at {at}: {e:?}"))
    }
}

impl<T> Staged<T> for Option<T> {
    #[track_caller]
    fn staged(self) -> T {
        let at = std::panic::Location::caller();
        self.unwrap_or_else(|| panic!("APPARATUS (harness error) at {at}: nothing there"))
    }
}

const VOX: &str = env!("CARGO_BIN_EXE_vox");
/// The version served as "the release": the built `vox`'s own, because on macOS the installer
/// requires the app, its record and `vox --version` to agree (ADR-014 M-28). The loopback server
/// is what keeps it from being mistaken for a real release.
const SERVED: &str = env!("CARGO_PKG_VERSION");

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

fn install_sh() -> PathBuf {
    // <repo>/crates/vox-tui -> <repo>
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("install.sh")
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

/// A record's JSON, every value a scalar, in the field order a `BTreeMap` gives.
fn record_json(f: &BTreeMap<&str, String>) -> String {
    let quoted = |k: &str| !matches!(k, "schema_version" | "size");
    let body = f
        .iter()
        .map(|(k, v)| {
            if quoted(k) {
                format!("\"{k}\":\"{v}\"")
            } else {
                format!("\"{k}\":{v}")
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{body}}}\n")
}

/// On macOS, the release's Vox.app: `Vox-<version>-<triple>.zip` holding a bundle that carries
/// supplied real helper at `Contents/Helpers/vox`, ad-hoc signed (a Developer ID signature exists
/// only as output of the release workflow), and its record at `latest/download/app-<channel>-<triple>.json`.
fn app_release(root: &Path, channel: &str, version: &str, binary: &Path) -> Vec<u8> {
    let triple = target_triple();
    let work = tempfile::tempdir().staged();
    let app = work.path().join("Vox.app");
    let contents = app.join("Contents");
    std::fs::create_dir_all(contents.join("MacOS")).staged();
    std::fs::create_dir_all(contents.join("Helpers")).staged();
    std::fs::copy(binary, contents.join("MacOS/Vox")).staged();
    std::fs::copy(binary, contents.join("Helpers/vox")).staged();
    std::fs::write(
        contents.join("Info.plist"),
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\
             <key>CFBundleIdentifier</key><string>us.vox.app</string>\
             <key>CFBundleExecutable</key><string>Vox</string>\
             <key>CFBundlePackageType</key><string>APPL</string>\
             <key>CFBundleShortVersionString</key><string>{version}</string>\
             <key>LSMinimumSystemVersion</key><string>13.0</string>\
             </dict></plist>\n"
        ),
    )
    .staged();
    let helper = contents.join("Helpers/vox");
    let signed_helper = Command::new("/usr/bin/codesign")
        .args([
            "--force",
            "--sign",
            "-",
            "--identifier",
            "us.vox.proof.helper",
            "--requirements",
            "=designated => identifier \"us.vox.proof.helper\"",
        ])
        .arg(&helper)
        .output()
        .staged();
    assert!(
        signed_helper.status.success(),
        "APPARATUS: ad-hoc signing fixture helper: {}",
        String::from_utf8_lossy(&signed_helper.stderr)
    );
    let signed = Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-"])
        .arg(&app)
        .output()
        .staged();
    assert!(
        signed.status.success(),
        "APPARATUS (harness error): ad-hoc signing the fixture app: {}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let zip_name = format!("Vox-{version}-{triple}.zip");
    let zip = work.path().join(&zip_name);
    let zipped = Command::new("/usr/bin/ditto")
        .args(["-c", "-k", "--keepParent"])
        .arg(&app)
        .arg(&zip)
        .output()
        .staged();
    assert!(
        zipped.status.success(),
        "APPARATUS (harness error): zipping the fixture app: {}",
        String::from_utf8_lossy(&zipped.stderr)
    );
    let bytes = std::fs::read(&zip).staged();
    let asset_dir = root.join("releases/download").join(format!("v{version}"));
    std::fs::create_dir_all(&asset_dir).staged();
    std::fs::write(asset_dir.join(&zip_name), &bytes).staged();

    let mut f: BTreeMap<&str, String> = BTreeMap::new();
    f.insert("kind", "vox.app-release".into());
    f.insert("schema_version", "1".into());
    f.insert("package", "Vox.app".into());
    f.insert("channel", channel.into());
    f.insert("target", triple.into());
    f.insert("version", version.into());
    f.insert("size", bytes.len().to_string());
    f.insert("sha256", sha256_hex(&bytes));
    let rec_dir = root.join("releases/latest/download");
    std::fs::create_dir_all(&rec_dir).staged();
    let record = record_json(&f);
    let name = format!("app-{channel}-{triple}.json");
    std::fs::write(rec_dir.join(&name), &record).staged();
    std::fs::write(asset_dir.join(&name), record).staged();
    std::fs::read(helper).staged()
}

/// A release tree: the record at `latest/download/<channel>-<triple>.json` and the binary at
/// `download/v<version>/vox-<triple>`, and on macOS the app ([`app_release`]). `mangle` gets the
/// last word on the `vox` record's fields.
fn release_tree(root: &Path, channel: &str, mangle: &dyn Fn(&mut BTreeMap<&str, String>)) {
    release_tree_of(root, channel, SERVED, Path::new(VOX), mangle);
}

fn release_tree_of(
    root: &Path,
    channel: &str,
    version: &str,
    binary: &Path,
    mangle: &dyn Fn(&mut BTreeMap<&str, String>),
) {
    let bin = if cfg!(target_os = "macos") {
        app_release(root, channel, version, binary)
    } else {
        std::fs::read(binary).staged()
    };
    let triple = target_triple();
    let asset_dir = root.join("releases/download").join(format!("v{version}"));
    std::fs::create_dir_all(&asset_dir).staged();
    std::fs::write(asset_dir.join(format!("vox-{triple}")), &bin).staged();

    let mut f: BTreeMap<&str, String> = BTreeMap::new();
    f.insert("kind", "vox.standalone-release".into());
    f.insert("schema_version", "1".into());
    f.insert("package", "vox".into());
    f.insert("channel", channel.into());
    f.insert("target", triple.into());
    f.insert("version", version.into());
    f.insert("size", bin.len().to_string());
    f.insert("sha256", sha256_hex(&bin));
    mangle(&mut f);
    let rec_dir = root.join("releases/latest/download");
    std::fs::create_dir_all(&rec_dir).staged();
    let record = record_json(&f);
    let name = format!("{channel}-{triple}.json");
    std::fs::write(rec_dir.join(&name), &record).staged();
    std::fs::write(asset_dir.join(&name), record).staged();
}

const SYSTEM_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// The proof's stand-in for `/Applications`, so no run touches the real one.
fn system_apps(home: &Path) -> PathBuf {
    home.join("SystemApplications")
}

/// Where the install's marker sits: beside the bundle on macOS, beside `vox` elsewhere.
fn marker_path(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        system_apps(home).join(".vox-standalone.json")
    } else {
        home.join("bin/.vox-standalone.json")
    }
}

/// Run the real `install.sh` against `server`, installing into `home/bin`.
fn run_installer(server: &Server, home: &Path, channel: &str) -> (bool, String) {
    run_installer_env(server, home, channel, &[])
}

/// As `run_installer`, with extra environment.
fn run_installer_env(
    server: &Server,
    home: &Path,
    channel: &str,
    extra: &[(&str, &str)],
) -> (bool, String) {
    std::fs::create_dir_all(home).staged();
    std::fs::create_dir_all(system_apps(home)).staged();
    let mut f = std::fs::File::create(home.join(".zshrc")).staged();
    f.write_all(b"export VOX_PROOF_USER_LINE=kept\n").staged();
    // A `PATH` entry in `extra` goes in front of the system's: it is how a shim stands in for
    // another Mac.
    let path = extra
        .iter()
        .find(|(k, _)| *k == "PATH")
        .map_or(SYSTEM_PATH.to_owned(), |(_, v)| {
            format!("{v}:{SYSTEM_PATH}")
        });
    let mut command = Command::new("sh");
    command
        .arg(install_sh())
        .env_clear()
        .env("HOME", home)
        .env("VOX_DATA_DIR", home.join("data"))
        .env("VOX_CONFIG_DIR", home.join("config"))
        .env("VOX_TEST_KEYCHAIN", home.join("data/proof.keychain-db"))
        .env("VOX_APPLICATIONS_DIR", system_apps(home))
        .env("SHELL", "/bin/zsh")
        .env("TERM", "dumb")
        .env("VOX_RELEASE_BASE", &server.base)
        .env("VOX_TEST_RELEASE_BASE", &server.base)
        .env("VOX_INSTALL_DIR", home.join("bin"))
        .env("VOX_CHANNEL", channel)
        .envs(extra.iter().copied().filter(|(k, _)| *k != "PATH"))
        .env("PATH", path);
    #[cfg(target_os = "linux")]
    let out = {
        let (out, timely, leaked) = dead_candidate::bounded(&mut command);
        if !timely || !leaked.is_empty() {
            return (false, format!("PRODUCT: installer did not return within 40 seconds or left sleep children running: timely={timely}, leaked={leaked:?}; {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)));
        }
        out
    };
    #[cfg(not(target_os = "linux"))]
    let out = command.output().staged();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn install_sh_installs_what_it_verified_and_refuses_what_it_could_not() {
    watchdog::arm();
    let mut claims: Vec<Claim> = Vec::new();
    let mut receipts: BTreeMap<String, String> = BTreeMap::new();
    let allowed: Vec<String> = std::env::var("VOX_PROOF_ALLOW_UNPROVEN")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    if cfg!(all(target_os = "linux", not(target_arch = "x86_64"))) {
        claims.push(blocked("install.linux_candidate_arms", "CANNOT MEASURE: ADR-051's Linux arms run as x86_64 in an emulated container; this is aarch64"));
        report(&claims, &receipts, &[]);
        return;
    }

    let tree = tempfile::tempdir().staged();
    release_tree(tree.path(), "stable", &|_| {});
    let server = match serve(tree.path()) {
        Ok(s) => s,
        Err(why) => {
            claims.push(blocked("install.release_server", why));
            report(&claims, &receipts, &allowed);
            return;
        }
    };

    // HK-1/2: the installed binary gives each harness a quiet hook before any node exists.
    // Mutant: skip Codex in install_light_hooks -> PRODUCT at its missing hooks.json below.
    {
        let tmp = tempfile::tempdir().staged();
        let home = tmp.path();
        for dir in [".claude", ".codex", ".config/opencode"] {
            std::fs::create_dir_all(home.join(dir)).staged();
        }
        let (ok, said) = run_installer(&server, home, "stable");
        assert!(
            ok,
            "PRODUCT: install.sh must install the light hooks: {said}"
        );
        let configs = [
            ("claude", ".claude/settings.json"),
            ("codex", ".codex/hooks.json"),
            ("opencode", ".config/opencode/plugin/vox.js"),
        ];
        let bin = home.join("bin/vox");
        let mut before = Vec::new();
        for (harness, rel) in configs {
            let path = home.join(rel);
            let content = std::fs::read_to_string(&path).unwrap_or_default();
            assert!(content.contains(&format!("agent hook --light {harness}"))
                && said.contains(path.to_str().expect("APPARATUS: UTF-8 scratch path")),
                "PRODUCT: install.sh must install {harness}'s light hook and name {path:?}; file={content:?}; output={said}");
            before.push((path, content));
            let out = Command::new(&bin)
                .args(["agent", "hook", "--light", harness, "--format", "text"])
                .env_clear()
                .env("HOME", home)
                .env("PATH", SYSTEM_PATH)
                .env("VOX_DATA_DIR", home.join("data"))
                .env("VOX_CONFIG_DIR", home.join("config"))
                .env("VOX_NODE", "must-not-be-used")
                .output()
                .staged();
            let output = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(out.status.success() && output.lines().count() <= 1,
                "PRODUCT: {harness}'s light hook must exit 0 with at most one line: {:?}, {output:?}", out.status);
        }
        assert!(
            !home.join("data").exists() && !home.join("config").exists(),
            "PRODUCT: node-free hooks must not create a profile or start its daemon"
        );
        assert!(
            data_holders(&home.join("data")).is_empty(),
            "PRODUCT: light hooks must leave no daemon running for the scratch data root"
        );
        let (again, repeated) = run_installer(&server, home, "stable");
        assert!(
            again
                && before
                    .iter()
                    .all(|(p, text)| std::fs::read_to_string(p).ok().as_ref() == Some(text)),
            "PRODUCT: a second installation must preserve existing Vox hooks: {repeated}"
        );
        // A node hook also survives installation byte for byte; no node need be made to wire it.
        let node_hook = r#"{"hooks":{"UserPromptSubmit":[{"hooks":[{"type":"command","command":"vox agent hook --node kept"}]}]},"env":{"VOX_NODE":"kept"}}"#;
        std::fs::write(home.join(".claude/settings.json"), node_hook).staged();
        let (again, said) = run_installer(&server, home, "stable");
        assert!(
            again
                && std::fs::read_to_string(home.join(".claude/settings.json")).staged()
                    == node_hook,
            "PRODUCT: installation must preserve an existing node hook: {said}"
        );
        receipts.insert("install.light_hooks".into(), said);
        claims.push(claim("install.light_hooks", true, "All three hooks installed and named; exit 0, at most one line, no node or daemon; existing light and node hooks preserved."));
    }

    // ---- the happy path, observed the way a user observes it -------------------------
    {
        let tmp = tempfile::tempdir().staged();
        let home = tmp.path();
        // Claude Code is here (its settings folder): the installer gives it the agent skill pack.
        std::fs::create_dir_all(home.join(".claude")).staged();
        let (ok, text) = run_installer(&server, home, "stable");
        let version = if ok {
            run_vox(&home.join("bin/vox"), &uninstall_env(home), &["--version"])
                .1
                .trim()
                .to_owned()
        } else {
            String::new()
        };
        let marker = std::fs::read_to_string(marker_path(home)).unwrap_or_default();
        let rc = std::fs::read_to_string(home.join(".zshrc")).unwrap_or_default();
        claims.push(claim(
            "install.places_a_runnable_binary",
            ok && version.starts_with("vox "),
            format!("installed binary reports {version:?}"),
        ));
        claims.push(claim(
            "install.marker_names_the_channel",
            marker.contains("\"kind\":\"vox.install-channel\"")
                && marker.contains("\"channel\":\"stable\""),
            format!(".vox-standalone.json holds {marker:?}"),
        ));
        claims.push(claim(
            "install.runs_shell_setup",
            rc.contains(">>> vox >>>") && rc.contains("VOX_PROOF_USER_LINE=kept"),
            format!("the rc is {rc:?}"),
        ));
        // **The agent skill pack, installed with Vox** (v0.4.1): where Claude Code reads it, and
        // none for a harness that is not here.
        let pack = home.join(".claude/skills/vox-agent-comms");
        let entry =
            pack.join("SKILL.md").is_file() && pack.join("references/sessions.md").is_file();
        claims.push(claim(
            "install.installs_the_agent_skill_pack",
            ok && entry && !home.join(".codex").exists(),
            format!(
                "{} holds SKILL.md and references/sessions.md: {entry}; .codex made: {}",
                pack.display(),
                home.join(".codex").exists()
            ),
        ));
        receipts.insert("install.happy_path".into(), text);
    }

    // ---- `vox uninstall`: what install.sh, shell-setup and setup put here goes; nodes stay ----
    // A person's whole journey, in a scratch home: install with the real install.sh, make a node
    // and attach it (a daemon runs), wire Claude Code as `vox setup` does (its hook entries merged
    // beside one of the person's own, the agent skill), keep an OpenCode plugin the person edited,
    // then `vox uninstall --dry-run` (nothing changes) and `vox uninstall` with the installed vox.
    // Mutant: uninstall without removing the install (`bundle_files`/`standalone_files` skipped):
    // red at uninstall.removes_the_install.
    {
        let tmp = tempfile::tempdir().staged();
        let home = tmp.path();
        let (installed_ok, install_text) = run_installer(&server, home, "stable");
        let vox = home.join("bin/vox");
        if cfg!(target_os = "macos") {
            unlock_staging::keychain(&home.join("data"));
        }
        let env = uninstall_env(home);
        let pass = home.join("alice.pass");
        std::fs::write(&pass, "alice identity\n").staged();
        let made = run_vox(
            &vox,
            &env,
            &[
                "node",
                "create",
                "alice",
                "--passphrase-file",
                pass.to_str().staged(),
            ],
        );
        let attached = run_vox(
            &vox,
            &env,
            &[
                "node",
                "attach",
                "alice",
                "--passphrase-file",
                pass.to_str().staged(),
            ],
        );
        // Claude Code wired as `vox setup` wires it: Vox's entries and VOX_NODE merged into the
        // person's own settings, which keep their own hook; and the skill.
        let claude = home.join(".claude");
        let plugin = run_vox(
            &vox,
            &env,
            &["agent", "plugin", "claude", "--node", "alice"],
        );
        let mut settings: serde_json::Value = serde_json::from_str(&plugin.1).unwrap_or_default();
        if let Some(stop) = settings["hooks"]["Stop"].as_array_mut() {
            stop.push(serde_json::json!({"hooks": [{"type": "command", "command": "echo the-persons-own-hook"}]}));
        }
        settings["model"] = serde_json::json!("the-persons-setting");
        std::fs::create_dir_all(claude.join("skills/vox-agent-comms")).staged();
        std::fs::write(
            claude.join("settings.json"),
            serde_json::to_string_pretty(&settings).staged(),
        )
        .staged();
        let skill = run_vox(&vox, &env, &["agent", "skill", "claude"]);
        std::fs::write(claude.join("skills/vox-agent-comms/SKILL.md"), &skill.1).staged();
        // OpenCode's plugin, as Vox writes it, then edited by the person: kept, and named.
        let oc = home.join(".config/opencode/plugin");
        std::fs::create_dir_all(&oc).staged();
        let oc_text = run_vox(
            &vox,
            &env,
            &["agent", "plugin", "opencode", "--node", "alice"],
        );
        std::fs::write(
            oc.join("vox.js"),
            format!("{}// the person's own line\n", oc_text.1),
        )
        .staged();
        let daemon_before = data_holders(&home.join("data"));
        let staged_ok = installed_ok
            && made.0
            && attached.0
            && plugin.0
            && skill.0
            && oc_text.0
            && !daemon_before.is_empty();

        let before = home_files(home);
        let dry = run_vox(&vox, &env, &["uninstall", "--dry-run"]);
        let after_dry = home_files(home);
        let out = run_vox(&vox, &env, &["uninstall"]);
        let text = out.1.clone() + &out.2;
        let rc = std::fs::read_to_string(home.join(".zshrc")).unwrap_or_default();
        let settings_after =
            std::fs::read_to_string(claude.join("settings.json")).unwrap_or_default();
        let daemon_after = data_holders(&home.join("data"));
        if !staged_ok {
            claims.push(blocked(
                "uninstall.removes_the_install",
                format!("APPARATUS (staging not achieved): install ok={installed_ok} ({install_text:?}); node create {made:?}; attach {attached:?}; plugin ok={}; skill ok={}; a daemon on the scratch data root: {daemon_before:?}", plugin.0, skill.0),
            ));
        } else {
            claims.push(claim(
                "uninstall.dry_run_changes_nothing",
                dry.0 && before == after_dry && dry.1.contains("would") && dry.1.contains(".zshrc"),
                format!(
                    "--dry-run (exit_ok={}) said {:?}; the home tree changed: {}",
                    dry.0,
                    dry.1,
                    before != after_dry
                ),
            ));
            let install_gone = !vox.exists()
                && std::fs::symlink_metadata(&vox).is_err()
                && !marker_path(home).exists()
                && (!cfg!(target_os = "macos") || !system_apps(home).join("Vox.app").exists());
            claims.push(claim(
                "uninstall.removes_the_install",
                out.0 && install_gone,
                format!("`vox uninstall` (exit_ok={}) said {text:?}; vox left={}, marker left={}, Vox.app left={}",
                    out.0, std::fs::symlink_metadata(&vox).is_ok(), marker_path(home).exists(),
                    system_apps(home).join("Vox.app").exists()),
            ));
            claims.push(claim(
                "uninstall.removes_shell_setup_and_keeps_the_persons_lines",
                !rc.contains(">>> vox >>>")
                    && rc.contains("VOX_PROOF_USER_LINE=kept")
                    && !home.join(".local/share/zsh/site-functions/_vox").exists(),
                format!("the rc is now {rc:?}"),
            ));
            claims.push(claim(
                "uninstall.removes_vox_wiring_and_keeps_the_persons_own",
                !settings_after.contains("vox agent hook") && !settings_after.contains("VOX_NODE")
                    && settings_after.contains("the-persons-own-hook")
                    && settings_after.contains("the-persons-setting")
                    && !claude.join("skills/vox-agent-comms").exists()
                    && oc.join("vox.js").exists() && text.contains("vox.js is kept"),
                format!("Claude's settings are now {settings_after:?}; skill left={}; the edited OpenCode plugin left={}",
                    claude.join("skills/vox-agent-comms").exists(), oc.join("vox.js").exists()),
            ));
            claims.push(claim(
                "uninstall.stops_the_daemon_and_keeps_the_nodes",
                daemon_after.is_empty()
                    && home.join("data/nodes/alice").is_dir()
                    && text.contains("no backup"),
                format!(
                    "processes holding the data root after: {daemon_after:?}; nodes/alice kept={}",
                    home.join("data/nodes/alice").is_dir()
                ),
            ));
            // **Each kept directory is said once, as what it holds** (#632's check): the data
            // root with the nodes, their keys and rooms and the no-backup sentence, a full stop
            // before the `--purge` sentence; the config directory as settings, never as nodes.
            // Mutant: the old line (`<dir> is kept: it holds your nodes, …`) for both.
            let data_dir = home.join("data");
            let config_dir = home.join("config");
            let line_for = |dir: &Path| -> Vec<&str> {
                text.lines()
                    .filter(|l| l.starts_with(&format!("vox uninstall: kept {}", dir.display())))
                    .collect()
            };
            let (data_lines, config_lines) = (line_for(&data_dir), line_for(&config_dir));
            let data_ok = data_lines.len() == 1
                && data_lines[0].starts_with(&format!(
                    "vox uninstall: kept {}: your nodes, their keys and their rooms (alice); there \
                     is no backup of a node",
                    data_dir.display()
                ))
                && data_lines[0].ends_with(". `vox uninstall --purge` removes it.")
                && !data_lines[0].contains(" is kept");
            let config_ok = if config_dir.exists() {
                config_lines
                    == [format!(
                        "vox uninstall: kept {}: the settings Vox reads for your nodes. `vox \
                         uninstall --purge` removes it.",
                        config_dir.display()
                    )
                    .as_str()]
            } else {
                config_lines.is_empty()
            };
            claims.push(claim(
                "uninstall.says_once_what_each_kept_directory_holds",
                data_ok && config_ok,
                format!(
                    "the data root's kept lines: {data_lines:?}; the config directory's (it exists: \
                     {}): {config_lines:?}",
                    config_dir.exists()
                ),
            ));
            // macOS keeps a background item by bundle id, so every Vox shares it: this install
            // registered none, so uninstalling it must touch none, whatever another Vox on this
            // Mac (the person's own, say) has registered.
            claims.push(claim(
                "uninstall.leaves_another_vox_background_items_alone",
                !dry.1.contains("unregister Vox's") && !text.contains("unregistered Vox's"),
                format!(
                    "this install registered no background item; --dry-run said {:?}; uninstall said {text:?}",
                    dry.1
                ),
            ));
        }
        for pid in data_holders(&home.join("data")) {
            let _ = Command::new("/bin/kill").arg(pid).status();
        }
        receipts.insert("uninstall".into(), text);

        // --purge: install again (the nodes are still there), then the installed vox refuses
        // with no terminal, and at a terminal, once the node's name is typed, removes them too.
        // Its preservation was asserted above. Park only this deliberately edited apparatus
        // fixture so the independent purge journey can first install its own valid hooks.
        if oc.join("vox.js").exists() {
            std::fs::rename(oc.join("vox.js"), home.join("edited-plugin.kept")).staged();
        }
        let (again, again_text) = run_installer(&server, home, "stable");
        let refused = run_vox(&vox, &env, &["uninstall", "--purge"]);
        let kept_after_refusal = home.join("data/nodes/alice").is_dir();
        let purged = at_a_terminal(
            &vox.to_string_lossy(),
            &env,
            &["uninstall", "--purge"],
            "alice\n",
        );
        if again {
            claims.push(claim(
                "uninstall.purge_asks_at_a_terminal_and_removes_the_nodes",
                !refused.0 && refused.2.contains("no terminal") && kept_after_refusal
                    && !home.join("data").exists() && !vox.exists(),
                format!("with no terminal it said {:?} (data kept={kept_after_refusal}); at a terminal, typing alice, it said {purged:?}; data left={}, vox left={}",
                    refused.2, home.join("data").exists(), vox.exists()),
            ));
        } else {
            claims.push(blocked(
                "uninstall.purge_asks_at_a_terminal_and_removes_the_nodes",
                format!("APPARATUS (staging not achieved): installing again said {again_text:?}"),
            ));
        }
        for pid in data_holders(&home.join("data")) {
            let _ = Command::new("/bin/kill").arg(pid).status();
        }
    }

    // ---- a record whose digest does not describe the asset ---------------------------
    for (id, channel, mangle) in [
        (
            "install.refuses_a_wrong_digest",
            "badsha",
            &(|f: &mut BTreeMap<&str, String>| {
                f.insert("sha256", "0".repeat(64));
            }) as &dyn Fn(&mut BTreeMap<&str, String>),
        ),
        (
            "install.refuses_a_wrong_size",
            "badsize",
            &|f: &mut BTreeMap<&str, String>| {
                f.insert("size", "1024".into());
            },
        ),
        (
            "install.refuses_a_foreign_target",
            "badtarget",
            &|f: &mut BTreeMap<&str, String>| {
                f.insert("target", "sparc64-unknown-none".into());
            },
        ),
        (
            "install.refuses_a_foreign_kind",
            "badkind",
            &|f: &mut BTreeMap<&str, String>| {
                f.insert("kind", "something.else".into());
            },
        ),
    ] {
        release_tree(tree.path(), channel, mangle);
        let tmp = tempfile::tempdir().staged();
        let home = tmp.path();
        let (ok, text) = run_installer(&server, home, channel);
        let installed = home.join("bin/vox").exists();
        claims.push(claim(
            id,
            !ok && !installed,
            format!("exit_ok={ok}, vox installed={installed}, said {text:?}"),
        ));
    }

    // ---- the Apple gate refuses bytes Apple did not vouch for (macOS) ----------------
    // The fixture app is ad-hoc signed, around a cargo build. Forcing the gate on is the only way
    // to measure it locally: a genuinely notarized app exists only as output of the release
    // workflow. The refusal must name the app itself: its vox is checked too, but a gate that
    // checked only the vox inside would let any bundle around it through.
    if cfg!(target_os = "macos") {
        release_tree(tree.path(), "stable", &|_| {});
        let tmp = tempfile::tempdir().staged();
        let home = tmp.path();
        let (ok, text) =
            run_installer_env(&server, home, "stable", &[("VOX_PROOF_APPLE_VERIFY", "1")]);
        claims.push(claim(
            "install.apple_gate_refuses_an_unsigned_app",
            !ok && !system_apps(home).join("Vox.app").exists()
                && !home.join("bin/vox").exists()
                && text.contains("Vox.app is not signed by team 3T2D2YNTVW"),
            format!("with the Apple gate forced on, the installer said {text:?}"),
        ));
    }
    // Elsewhere there is no Apple gate to prove, so no claim is made: reporting it "blocked" on
    // Linux kept an accepted gap open for ever (ADR-018 §3) for a property Linux does not have.
    // CI's macOS job proves it for real (V210-20, #193).

    // ---- a `vox` this installer did not install is never overwritten -----------------
    {
        release_tree(tree.path(), "stable", &|_| {});
        let tmp = tempfile::tempdir().staged();
        let home = tmp.path();
        let bin = home.join("bin");
        std::fs::create_dir_all(&bin).staged();
        std::fs::write(bin.join("vox"), b"#!/bin/sh\necho mine\n").staged();
        let (ok, text) = run_installer(&server, home, "stable");
        let still = std::fs::read_to_string(bin.join("vox")).unwrap_or_default();
        claims.push(claim(
            "install.refuses_to_overwrite_a_foreign_binary",
            !ok && still.contains("echo mine"),
            format!("exit_ok={ok}, the file is still {still:?}, said {text:?}"),
        ));
    }

    // A real saved room remains readable through an owned same-version rerun.
    {
        let tmp = tempfile::tempdir().staged();
        let home = tmp.path();
        let (first, first_text) = run_installer(&server, home, "stable");
        if !first {
            claims.push(claim(
                "install.owned_rerun_keeps_saved_data",
                false,
                first_text,
            ));
        } else {
            match SavedRoom::stage(home) {
                Ok(saved) => {
                    let (ok, text) = run_installer(&server, home, "stable");
                    let intact = saved.intact(home);
                    let version =
                        run_vox(&home.join("bin/vox"), &uninstall_env(home), &["--version"]);
                    claims.push(claim(
                        "install.owned_rerun_keeps_saved_data",
                        ok && intact && version.0 && version.1.trim() == format!("vox {SERVED}"),
                        format!("rerun exit_ok={ok}, saved room and Ready node intact={intact}, version={version:?}; {text}"),
                    ));
                    saved.cleanup(home);
                }
                Err(why) => claims.push(blocked("install.owned_rerun_keeps_saved_data", why)),
            }
        }
    }

    // A rerun removes both the old fixed partial and a dead per-invocation owner's partial.
    if cfg!(target_os = "linux") {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().staged();
        let home = tmp.path();
        let bin = home.join("bin");
        let (first, said_first) = run_installer(&server, home, "stable");
        if first {
            let mut dead = Command::new("sh").args(["-c", "exit 0"]).spawn().staged();
            let dead_pid = dead.id();
            dead.wait().staged();
            let dead_partial = format!(".vox-candidate.{dead_pid}.dead00");
            for leftover in [
                ".vox-candidate.partial",
                dead_partial.as_str(),
                ".vox-previous",
            ] {
                std::fs::write(bin.join(leftover), b"cut short").staged();
                std::fs::set_permissions(
                    bin.join(leftover),
                    std::fs::Permissions::from_mode(0o555),
                )
                .staged();
            }
            let (ok, text) = run_installer(&server, home, "stable");
            let version = run_vox(&bin.join("vox"), &uninstall_env(home), &["--version"]);
            let previous = std::fs::read(bin.join(".vox-previous")).unwrap_or_default();
            let replaced = previous.len() > 64 && previous != b"cut short";
            let partials: Vec<String> = std::fs::read_dir(&bin)
                .staged()
                .filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with(".vox-candidate."))
                .collect();
            claims.push(claim(
                "install.reruns_after_a_cut_short_run",
                ok && version.0 && version.1.starts_with("vox ") && replaced && partials.is_empty(),
                format!("exit_ok={ok}, version={version:?}, previous replaced={replaced}, partials={partials:?}; {text}"),
            ));
        } else {
            claims.push(claim(
                "install.reruns_after_a_cut_short_run",
                false,
                said_first,
            ));
        }
    }
    #[cfg(target_os = "linux")]
    linux_candidate_claims(&mut claims);

    // ---- macOS: the app lands where the person can open it, and vox is a link into it ----
    if cfg!(target_os = "macos") {
        release_tree(tree.path(), "stable", &|_| {});
        for (id, writable) in [
            ("install.app_goes_to_applications_when_writable", true),
            ("install.app_goes_to_home_applications_otherwise", false),
        ] {
            use std::os::unix::fs::PermissionsExt as _;
            let tmp = tempfile::tempdir().staged();
            let home = tmp.path();
            std::fs::create_dir_all(system_apps(home)).staged();
            if !writable {
                std::fs::set_permissions(system_apps(home), std::fs::Permissions::from_mode(0o555))
                    .staged();
            }
            let (ok, text) = run_installer(&server, home, "stable");
            let apps = if writable {
                system_apps(home)
            } else {
                home.join("Applications")
            };
            let app = apps.join("Vox.app");
            let link = std::fs::read_link(home.join("bin/vox")).unwrap_or_default();
            let version = run_vox(&home.join("bin/vox"), &uninstall_env(home), &["--version"])
                .1
                .trim()
                .to_owned();
            let app_version = Command::new("/usr/libexec/PlistBuddy")
                .args(["-c", "Print :CFBundleShortVersionString"])
                .arg(app.join("Contents/Info.plist"))
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
                .unwrap_or_default();
            let linked_to_app = match (
                std::fs::canonicalize(&link),
                std::fs::canonicalize(app.join("Contents/Helpers/vox")),
            ) {
                (Ok(link), Ok(helper)) => link == helper,
                _ => false,
            };
            claims.push(claim(
                id,
                ok && linked_to_app && app_version == SERVED && version == format!("vox {SERVED}"),
                format!(
                    "exit_ok={ok}, ~/.local/bin/vox -> {}, it reports {version:?}, the app says \
                     {app_version:?}, linked to selected app={linked_to_app}, said {text:?}",
                    link.display()
                ),
            ));
            if !writable {
                std::fs::set_permissions(system_apps(home), std::fs::Permissions::from_mode(0o755))
                    .staged();
            }
        }

        // An Intel Mac, and a Mac before macOS 13, stand in through shims on PATH. "Nothing was
        // downloaded" is read from the server's request log, so the log must be seen counting
        // the installs above first, or a refusal after downloading would read as none.
        let counted = server.requests();
        let shims = tempfile::tempdir().staged();
        for (id, uname_m, os_version) in [
            (
                "install.refuses_an_intel_mac_before_downloading",
                "x86_64",
                "14.6",
            ),
            (
                "install.refuses_macos_12_before_downloading",
                "arm64",
                "12.7.4",
            ),
        ] {
            use std::os::unix::fs::PermissionsExt as _;
            let dir = shims.path().join(id);
            std::fs::create_dir_all(&dir).staged();
            for (name, body) in [
                (
                    "uname",
                    format!(
                        "#!/bin/sh\ncase \"$1\" in -m) echo {uname_m} ;; *) exec /usr/bin/uname \"$@\" ;; esac\n"
                    ),
                ),
                ("sysctl", "#!/bin/sh\necho 0\n".to_owned()),
                ("sw_vers", format!("#!/bin/sh\necho {os_version}\n")),
            ] {
                std::fs::write(dir.join(name), body).staged();
                std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(0o755))
                    .staged();
            }
            if counted == 0 {
                claims.push(blocked(
                    id,
                    "the release server's request log counted none of the installs above, so \
                     whether anything was downloaded cannot be measured",
                ));
                continue;
            }
            let tmp = tempfile::tempdir().staged();
            let home = tmp.path();
            let before = server.requests();
            let dir_text = dir.to_string_lossy().into_owned();
            let (ok, text) = run_installer_env(&server, home, "stable", &[("PATH", &dir_text)]);
            // python logs a request after answering it; give a late line the time to land.
            std::thread::sleep(std::time::Duration::from_millis(300));
            let fetched = server.requests() - before;
            claims.push(claim(
                id,
                !ok && fetched == 0
                    && text.contains("this Mac is not supported: Vox needs a Mac with Apple Silicon and macOS 13 or later")
                    && !home.join("bin/vox").exists(),
                format!("exit_ok={ok}, requests to the release server={fetched}, said {text:?}"),
            ));
        }

        // An invalid install destination must fail without changing the installed app or data.
        {
            let tmp = tempfile::tempdir().staged();
            let home = tmp.path();
            let (first, first_text) = run_installer(&server, home, "stable");
            if !first {
                claims.push(claim(
                    "install.failure_preserves_install_and_data",
                    false,
                    first_text,
                ));
            } else {
                match SavedRoom::stage(home) {
                    Ok(saved) => {
                        let helper = system_apps(home).join("Vox.app/Contents/Helpers/vox");
                        let before = std::fs::read(&helper).staged();
                        let not_a_dir = home.join("not-a-folder");
                        std::fs::write(&not_a_dir, b"a file").staged();
                        let dest = not_a_dir.to_string_lossy().into_owned();
                        let (ok, text) = run_installer_env(
                            &server,
                            home,
                            "stable",
                            &[("VOX_INSTALL_DIR", &dest)],
                        );
                        let intact = saved.intact(home);
                        let unchanged =
                            std::fs::read(&helper).ok().as_deref() == Some(before.as_slice());
                        claims.push(claim(
                            "install.failure_preserves_install_and_data",
                            !ok && unchanged && intact,
                            format!("exit_ok={ok}, installed helper unchanged={unchanged}, saved room and Ready node intact={intact}; {text}"),
                        ));
                        saved.cleanup(home);
                    }
                    Err(why) => {
                        claims.push(blocked("install.failure_preserves_install_and_data", why))
                    }
                }
            }
        }

        // Another installer/update owns the real lock. Wait for its child to signal that
        // lockf has entered the critical section before asserting the competing refusal.
        {
            let tmp = tempfile::tempdir().staged();
            let home = tmp.path();
            let id = "install.refuses_a_concurrent_transition";
            let (first, text) = run_installer(&server, home, "stable");
            if !first {
                claims.push(claim(id, false, format!("first install: {text}")));
            } else {
                let helper = system_apps(home).join("Vox.app/Contents/Helpers/vox");
                let before = std::fs::read(&helper).staged();
                let ready = home.join("lock-held");
                let mut holder = Command::new("/usr/bin/lockf")
                    .arg("-k")
                    .arg(system_apps(home).join(".vox-standalone.lock"))
                    .args([
                        "/bin/sh",
                        "-c",
                        "printf ready > \"$1\"; exec sleep 60",
                        "sh",
                    ])
                    .arg(&ready)
                    .spawn()
                    .staged();
                let start = std::time::Instant::now();
                while !ready.exists()
                    && start.elapsed() < std::time::Duration::from_secs(5)
                    && holder.try_wait().staged().is_none()
                {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                if ready.exists() {
                    let (ok, text) = run_installer(&server, home, "stable");
                    let intact = std::fs::read(&helper).ok().as_deref() == Some(before.as_slice());
                    claims.push(claim(
                        id,
                        !ok && intact,
                        format!("exit_ok={ok}, installed helper unchanged={intact}; {text}"),
                    ));
                } else {
                    claims.push(blocked(
                        id,
                        "APPARATUS: lock holder did not enter its critical section",
                    ));
                }
                let _ = holder.kill();
                let _ = holder.wait();
            }
        }

        // A retained bundle with no valid authority is not shell-owned scratch.
        for existing in [false, true] {
            let tmp = tempfile::tempdir().staged();
            let home = tmp.path();
            let id = if existing {
                "install.refuses_unknown_retained_state_on_owned_install"
            } else {
                "install.refuses_unknown_retained_state_on_first_install"
            };
            if existing {
                let (ok, text) = run_installer(&server, home, "stable");
                if !ok {
                    claims.push(claim(id, false, format!("first install: {text}")));
                    continue;
                }
            } else {
                std::fs::create_dir_all(system_apps(home)).staged();
            }
            let saved = if existing {
                match SavedRoom::stage(home) {
                    Ok(saved) => Some(saved),
                    Err(why) => {
                        claims.push(blocked(id, why));
                        continue;
                    }
                }
            } else {
                None
            };
            let retained = system_apps(home).join(".Vox.app.previous");
            std::fs::create_dir(&retained).staged();
            std::fs::write(retained.join("unknown"), b"not updater authority").staged();
            let helper = system_apps(home).join("Vox.app/Contents/Helpers/vox");
            let before = if existing {
                Some(std::fs::read(&helper).staged())
            } else {
                None
            };
            let (ok, text) = run_installer(&server, home, "stable");
            let kept = std::fs::read(retained.join("unknown")).ok().as_deref()
                == Some(b"not updater authority".as_slice());
            let app_intact = match before {
                Some(bytes) => std::fs::read(&helper).ok().as_deref() == Some(bytes.as_slice()),
                None => !system_apps(home).join("Vox.app").exists(),
            };
            let data_intact = saved.as_ref().is_none_or(|room| room.intact(home));
            claims.push(claim(id, !ok && kept && app_intact && data_intact,
                format!("exit_ok={ok}, unknown bytes kept={kept}, app intact={app_intact}, data intact={data_intact}; {text}")));
            if let Some(saved) = saved {
                saved.cleanup(home);
            }
        }

        // Stage the current journal by actually aborting a target-owned exchange; never fabricate
        // transition JSON or alter a bundle's plist. The installer then recovers it.
        {
            let id = "install.recovers_a_real_interrupted_update";
            let tmp = tempfile::tempdir().staged();
            let home = tmp.path();
            let (first, first_text) = run_installer(&server, home, "stable");
            if !first {
                claims.push(claim(id, false, format!("first install: {first_text}")));
            } else {
                match SavedRoom::stage(home) {
                    Err(why) => claims.push(blocked(id, why)),
                    Ok(saved) => {
                        let next = format!("9{}", &SERVED[1..]);
                        let fixture = std::env::var_os("VOX_PROOF_NEXT_BINARY").map(PathBuf::from);
                        let result = fixture.ok_or_else(|| format!("APPARATUS: set VOX_PROOF_NEXT_BINARY to a genuine {next} test-knobs binary"))
                            .and_then(|path| {
                                let bytes = std::fs::read(&path).map_err(|e| format!("APPARATUS: reading {}: {e}", path.display()))?;
                                for knob in ["VOX_TEST_RELEASE_BASE", "VOX_TEST_ABORT_AFTER_SWAP"] {
                                    if !bytes.windows(knob.len()).any(|w| w == knob.as_bytes()) {
                                        return Err(format!("APPARATUS: next binary lacks {knob}; build with test-knobs"));
                                    }
                                }
                                let version = run_vox(&path, &uninstall_env(home), &["--version"]);
                                if !version.0 || version.1.trim() != format!("vox {next}") {
                                    return Err(format!("APPARATUS: next binary must report vox {next}, got {version:?}"));
                                }
                                Ok(path)
                            });
                        match result {
                            Err(why) => claims.push(blocked(id, why)),
                            Ok(fixture) => {
                                let next_tree = tempfile::tempdir().staged();
                                release_tree_of(
                                    next_tree.path(),
                                    "stable",
                                    &next,
                                    &fixture,
                                    &|_| {},
                                );
                                match serve(next_tree.path()) {
                                    Err(why) => claims.push(blocked(
                                        id,
                                        format!("APPARATUS: next release server: {why}"),
                                    )),
                                    Ok(next_server) => {
                                        let mut env = uninstall_env(home);
                                        env.push((
                                            "VOX_TEST_RELEASE_BASE".into(),
                                            next_server.base.clone(),
                                        ));
                                        env.push(("VOX_TEST_ABORT_AFTER_SWAP".into(), "1".into()));
                                        let cut = run_vox(&home.join("bin/vox"), &env, &["update"]);
                                        let version = run_vox(
                                            &home.join("bin/vox"),
                                            &uninstall_env(home),
                                            &["--version"],
                                        );
                                        let journal = system_apps(home)
                                            .join(".Vox.app.publishing/transition.json");
                                        if cut.0
                                            || version.1.trim() != format!("vox {next}")
                                            || !journal.is_file()
                                        {
                                            claims.push(blocked(id, format!("APPARATUS: real abort after exchange not staged: cut={cut:?}, version={version:?}, journal={}", journal.is_file())));
                                        } else {
                                            let (ok, text) = run_installer(&server, home, "stable");
                                            let restored = run_vox(
                                                &home.join("bin/vox"),
                                                &uninstall_env(home),
                                                &["--version"],
                                            );
                                            let intact = saved.intact(home);
                                            claims.push(claim(id,
                                                ok && restored.0 && restored.1.trim() == format!("vox {SERVED}") && !journal.exists() && intact,
                                                format!("installer exit_ok={ok}, restored={restored:?}, journal remains={}, saved room and Ready node intact={intact}; {text}", journal.exists())));
                                        }
                                    }
                                }
                            }
                        }
                        saved.cleanup(home);
                    }
                }
            }
        }
        {
            let tmp = tempfile::tempdir().staged();
            let home = tmp.path();
            let before = server.requests();
            let (ok, text) = run_installer_env(
                &server,
                home,
                "stable",
                &[("VOX_APPLICATIONS_DIR", "relative/Applications")],
            );
            std::thread::sleep(std::time::Duration::from_millis(300));
            let fetched = server.requests() - before;
            claims.push(claim(
                "install.refuses_a_relative_applications_folder",
                !ok && fetched == 0
                    && text.contains("VOX_APPLICATIONS_DIR must be an absolute path"),
                format!("exit_ok={ok}, requests to the release server={fetched}, said {text:?}"),
            ));
        }
    }

    report(&claims, &receipts, &allowed);
}

#[cfg(target_os = "linux")]
fn linux_candidate_claims(claims: &mut Vec<Claim>) {
    use std::os::unix::fs::PermissionsExt as _;
    let tree = tempfile::tempdir().staged();
    release_tree(tree.path(), "stable", &|_| {});
    let server =
        serve(tree.path()).unwrap_or_else(|why| panic!("APPARATUS: Linux candidate server: {why}"));
    let inputs = tempfile::tempdir().staged();
    let dead = inputs.path().join("dead");
    let need = dead_candidate::stage(Path::new(VOX), &dead);
    let home = tempfile::tempdir().staged();
    let (ok, text) = run_installer(&server, home.path(), "stable");
    assert!(ok, "APPARATUS: existing install for refusal arms: {text}");
    let bin = home.path().join("bin");
    std::fs::write(bin.join(".vox-previous"), "cut short").staged();
    let active = std::fs::read(bin.join("vox")).staged();
    let marker = std::fs::read(marker_path(home.path())).staged();
    let no_partials = |bin: &Path| {
        std::fs::read_dir(bin)
            .staged()
            .filter_map(Result::ok)
            .all(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                !name.ends_with(".partial")
                    && !name.starts_with(".vox-candidate.")
                    && !name.starts_with(".vox-previous.")
            })
    };
    release_tree_of(tree.path(), "stable", SERVED, &dead, &|_| {});
    let (ok, text) = run_installer(&server, home.path(), "stable");
    let preserved = std::fs::read(bin.join("vox")).unwrap_or_default() == active
        && std::fs::read(marker_path(home.path())).unwrap_or_default() == marker
        && std::fs::read(bin.join(".vox-previous")).unwrap_or_default() == b"cut short"
        && no_partials(&bin);
    claims.push(claim(
        "install.keeps_the_previous_when_the_candidate_does_not_run",
        !ok && preserved,
        format!(
            "exit_ok={ok}, active/previous/marker preserved and no partials={preserved}; {text}"
        ),
    ));
    claims.push(claim(
        "install.refuses_a_candidate_that_does_not_run",
        !ok && text.contains(&format!("version `{need}' not found"))
            && text.contains(&format!(
                "needs glibc {}",
                need.trim_start_matches("GLIBC_")
            ))
            && text.contains("defect in Vox, not in this machine")
            && text.contains("nothing was changed:")
            && text.contains(&format!("is still vox {SERVED}.")),
        text,
    ));
    let empty = tempfile::tempdir().staged();
    let (ok, text) = run_installer(&server, empty.path(), "stable");
    claims.push(claim(
        "install.refuses_a_candidate_that_does_not_run_on_first_install",
        !ok && std::fs::read_dir(empty.path().join("bin"))
            .staged()
            .next()
            .is_none()
            && text.trim_end().ends_with("nothing was installed."),
        text,
    ));

    release_tree(tree.path(), "stable", &|_| {});
    let shim = inputs.path().join("shim");
    std::fs::create_dir(&shim).staged();
    std::fs::write(shim.join("getconf"), "#!/bin/sh\nprintf 'glibc 2.27\\n'\n").staged();
    std::fs::set_permissions(shim.join("getconf"), std::fs::Permissions::from_mode(0o755)).staged();
    let empty = tempfile::tempdir().staged();
    std::fs::write(
        empty.path().join(".zshrc"),
        "export VOX_PROOF_USER_LINE=kept\n",
    )
    .staged();
    let before = server.requests();
    let (ok, text) = run_installer_env(
        &server,
        empty.path(),
        "stable",
        &[("PATH", shim.to_str().staged())],
    );
    let expected = "vox install: this Linux is not supported: Vox needs glibc 2.28 or newer (Ubuntu 20.04, Debian 10, RHEL 8 and newer), and this system has glibc 2.27. Nothing was downloaded or installed.\n";
    claims.push(claim(
        "install.refuses_an_old_glibc_before_downloading",
        !ok && text == expected
            && server.requests() == before
            && ["bin", "data", "config"]
                .iter()
                .all(|path| !empty.path().join(path).exists())
            && std::fs::read_to_string(empty.path().join(".zshrc")).staged()
                == "export VOX_PROOF_USER_LINE=kept\n",
        format!("requests={}; {text}", server.requests() - before),
    ));

    for (id, script, wanted) in [
        (
            "install.stops_a_candidate_that_does_not_answer",
            "#!/bin/sh\necho starting >&2\ntrap '' TERM; exec sleep 600\n",
            "did not answer `--version` within 20 seconds and was stopped. Before that it said:",
        ),
        (
            "install.says_what_an_unexplained_candidate_said",
            "#!/bin/sh\necho 'boom: no such table' >&2\nexit 3\n",
            "the cause is not one this installer can name",
        ),
    ] {
        // A baseline may have replaced the first install with the dead candidate.
        release_tree(tree.path(), "stable", &|_| {});
        let (ok, text) = run_installer(&server, home.path(), "stable");
        assert!(ok, "APPARATUS: restore working install before {id}: {text}");
        let fixture = inputs.path().join("script");
        std::fs::write(&fixture, script).staged();
        release_tree_of(tree.path(), "stable", SERVED, &fixture, &|_| {});
        let (ok, text) = run_installer(&server, home.path(), "stable");
        let said = if id.contains("stops") {
            "  starting"
        } else {
            "  boom: no such table"
        };
        claims.push(claim(
            id,
            !ok && text.contains(wanted)
                && text.contains(said)
                && text.contains("nothing was changed:")
                && text.contains(&format!("is still vox {SERVED}."))
                && !text.contains("did not return within 40 seconds")
                && !text.contains("needs glibc 2.28")
                && no_partials(&bin)
                && std::fs::read(bin.join("vox")).unwrap_or_default() == active,
            text,
        ));
    }
    release_tree(tree.path(), "stable", &|_| {});
    let stdin_fixture = inputs.path().join("stdin-candidate");
    std::fs::write(&stdin_fixture, format!(
        "#!/bin/sh\nif read line; then echo 'candidate consumed installer stdin' >&2; exit 1; fi\nprintf 'vox {}\\n'\n", SERVED
    )).staged();
    release_tree_of(tree.path(), "stable", SERVED, &stdin_fixture, &|_| {});
    let mut piped_command = Command::new("sh");
    piped_command
        .arg(install_sh())
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", SYSTEM_PATH)
        .env("VOX_DATA_DIR", home.path().join("data"))
        .env("VOX_CONFIG_DIR", home.path().join("config"))
        .env("VOX_RELEASE_BASE", &server.base)
        .env("VOX_INSTALL_DIR", &bin)
        .env("VOX_NO_SHELL_SETUP", "1")
        .env("VOX_NO_SKILL_INSTALL", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut piped = piped_command
        .spawn()
        .expect("APPARATUS: launch installer with piped stdin");
    writeln!(
        piped.stdin.take().expect("APPARATUS: installer stdin"),
        "installer input"
    )
    .staged();
    let piped = piped
        .wait_with_output()
        .expect("APPARATUS: collect piped installer");
    let piped_text = format!(
        "{}{}",
        String::from_utf8_lossy(&piped.stdout),
        String::from_utf8_lossy(&piped.stderr)
    );
    claims.push(claim(
        "install.candidate_does_not_consume_installer_input",
        piped.status.success() && !piped_text.contains("candidate consumed installer stdin"),
        format!("exit={}; {piped_text}", piped.status),
    ));
    // Two real installers publish different checked bytes to the same directory.
    let first = inputs.path().join("first-candidate");
    let second = inputs.path().join("second-candidate");
    let ready_pipe = inputs.path().join("candidate-ready");
    let release_pipe = inputs.path().join("candidate-release");
    for pipe in [&ready_pipe, &release_pipe] {
        let status = Command::new("mkfifo").arg(pipe).status().staged();
        assert!(status.success(), "APPARATUS: create installer hold pipe");
    }
    let done = inputs.path().join("first-checked");
    let first_script = format!(
        "#!/bin/sh\nif [ ! -e '{}' ]; then printf 'ready\\n' > '{}'; read ignored < '{}'; : > '{}'; fi\nprintf 'vox {}\\n'\n",
        done.display(), ready_pipe.display(), release_pipe.display(), done.display(), SERVED
    );
    let second_script = format!(
        "#!/bin/sh\n# second candidate\nprintf 'vox {}\\n'\n",
        SERVED
    );
    std::fs::write(&first, &first_script).staged();
    std::fs::write(&second, &second_script).staged();
    release_tree_of(tree.path(), "stable", SERVED, &first, &|_| {});
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let ready = ready_pipe.clone();
    std::thread::spawn(move || {
        use std::io::BufRead as _;
        let result = std::fs::File::open(ready).and_then(|file| {
            let mut line = String::new();
            std::io::BufReader::new(file).read_line(&mut line)?;
            Ok(line)
        });
        let _ = ready_tx.send(result);
    });
    let (a, b) = std::thread::scope(|scope| {
        let first_run = scope.spawn(|| run_installer(&server, home.path(), "stable"));
        let ready = ready_rx.recv_timeout(std::time::Duration::from_secs(30));
        assert!(
            matches!(&ready, Ok(Ok(line)) if line == "ready\n"),
            "APPARATUS: first installer did not reach its candidate check: {ready:?}"
        );
        let held: Vec<PathBuf> = std::fs::read_dir(&bin)
            .staged()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".vox-candidate.")
            })
            .map(|entry| entry.path())
            .collect();
        assert_eq!(
            held.len(),
            1,
            "APPARATUS: expected one held installer candidate: {held:?}"
        );
        let mut dead = Command::new("sh").args(["-c", "exit 0"]).spawn().staged();
        let dead_pid = dead.id();
        dead.wait().staged();
        let stale = bin.join(format!(".vox-candidate.{dead_pid}.dead00"));
        let legacy = bin.join(".vox-candidate.partial");
        std::fs::write(&stale, b"cut short").staged();
        std::fs::write(&legacy, b"cut short").staged();
        release_tree_of(tree.path(), "stable", SERVED, &second, &|_| {});
        let second_run = run_installer(&server, home.path(), "stable");
        claims.push(claim(
            "install.rerun_cleans_dead_partials_but_keeps_a_live_install",
            second_run.0 && held[0].exists() && !stale.exists() && !legacy.exists(),
            format!("second={second_run:?}; live partial kept={}; dead partial retained={}; legacy partial retained={}",
                held[0].exists(), stale.exists(), legacy.exists()),
        ));
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut release = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(&release_pipe)
            .expect("APPARATUS: first installer left its check before release");
        writeln!(release, "continue").staged();
        (
            first_run.join().expect("APPARATUS: first installer thread"),
            second_run,
        )
    });
    let installed = std::fs::read(bin.join("vox")).unwrap_or_default();
    claims.push(claim(
        "install.concurrent_checks_publish_their_own_candidate",
        a.0 && b.0 && installed == first_script.as_bytes(),
        format!(
            "first={:?}; second={:?}; installed_first={}",
            a,
            b,
            installed == first_script.as_bytes()
        ),
    ));
    release_tree(tree.path(), "stable", &|_| {});
    // Only the uid is staged. The value is the real kernel readback, never a product hook.
    std::fs::remove_file(shim.join("getconf")).staged();
    std::fs::write(shim.join("id"), "#!/bin/sh\nprintf '1000\\n'\n").staged();
    std::fs::set_permissions(shim.join("id"), std::fs::Permissions::from_mode(0o755)).staged();
    let cap = std::fs::read_to_string("/proc/sys/net/core/rmem_max")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok());
    let (ok, text) = run_installer_env(
        &server,
        home.path(),
        "stable",
        &[("PATH", shim.to_str().staged())],
    );
    let commands = text.contains("sysctl -w net.core.rmem_max=4194304")
        && text.contains("echo 'net.core.rmem_max = 4194304' > /etc/sysctl.d/90-vox.conf");
    let expected = match cap {
        Some(value) if value >= 4_194_304 => !commands,
        Some(value) => commands && text.contains(&format!("at {value} bytes")),
        None => commands && text.contains("an unknown number of bytes"),
    };
    claims.push(claim(
        "install.non_root_reports_the_actual_receive_buffer",
        ok && expected,
        text,
    ));
    if std::env::var_os("VOX_PROOF_ROOT_SYSCTL").as_deref() == Some(std::ffi::OsStr::new("1")) {
        assert!(
            Path::new("/run/.containerenv").exists() || Path::new("/.dockerenv").exists(),
            "APPARATUS: root sysctl scene requires a disposable container"
        );
        let uid = Command::new("/usr/bin/id").arg("-u").output().staged();
        assert_eq!(
            String::from_utf8_lossy(&uid.stdout).trim(),
            "0",
            "APPARATUS: root sysctl scene requires container root"
        );
        let before = std::fs::read_to_string("/proc/sys/net/core/rmem_max")
            .expect("APPARATUS: container kernel receive buffer");
        let value: u64 = before
            .trim()
            .parse()
            .expect("APPARATUS: numeric receive buffer");
        assert!(
            value < 4_194_304,
            "APPARATUS: container receive buffer already meets the target"
        );
        let (ok, text) = run_installer(&server, home.path(), "stable");
        let after = std::fs::read_to_string("/proc/sys/net/core/rmem_max")
            .expect("APPARATUS: container kernel readback");
        let actual: u64 = after.trim().parse().expect("APPARATUS: numeric readback");
        let persisted = std::fs::read_to_string("/etc/sysctl.d/90-vox.conf").unwrap_or_default();
        claims.push(claim(
            "install.root_reports_refused_receive_buffer",
            ok && actual < 4_194_304
                && persisted == "net.core.rmem_max = 4194304\n"
                && !text.contains("net.core.rmem_max: set to 4194304")
                && text.contains(&format!("at {actual} bytes"))
                && text.contains("sysctl -w net.core.rmem_max=4194304"),
            format!("before={value} after={actual} persisted={persisted:?}; {text}"),
        ));
    }
}

/// ADR-051 asset arms (a), (b), (i), driven on the release's own installer and binary.
#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "optional: release assets and disposable x86_64 Linux containers"]
fn the_linux_release_asset_installs_only_where_it_runs() {
    linux_asset_claims(&[0, 1]);
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "optional: release assets and disposable x86_64 Linux containers"]
fn the_linux_release_installer_refuses_below_its_floor() {
    linux_asset_claims(&[2, 3]);
}

#[cfg(feature = "optional-proofs")]
#[test]
#[ignore = "optional: release assets and disposable x86_64 Linux containers"]
fn the_linux_release_installer_names_a_missing_loader() {
    linux_asset_claims(&[4]);
}

#[cfg(feature = "optional-proofs")]
fn linux_asset_claims(selected: &[usize]) {
    use std::process::Stdio;
    // `podman` with the operator's connection list and nothing else of the real HOME.
    fn podman() -> Command {
        let mut cmd = Command::new("podman");
        watchdog::temp_home::real_podman(&mut cmd);
        cmd
    }
    struct Container {
        name: String,
        image: String,
        pulled: bool,
        created: bool,
    }
    impl Drop for Container {
        fn drop(&mut self) {
            if self.created {
                let _ = podman().args(["rm", "-f", &self.name]).status();
            }
            if self.created && self.pulled {
                let _ = podman().args(["rmi", &self.image]).status();
            }
        }
    }
    struct Tunnel(Option<std::process::Child>);
    impl Drop for Tunnel {
        fn drop(&mut self) {
            if let Some(child) = &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    watchdog::arm();
    let dist = std::env::var_os("VOX_PROOF_DIST")
        .map(PathBuf::from)
        .expect("APPARATUS: set VOX_PROOF_DIST to the release asset directory");
    let binary = dist.join("vox-x86_64-unknown-linux-gnu");
    let installer = dist.join("install.sh");
    let bytes = std::fs::read(&binary).staged();
    let record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(dist.join("stable-x86_64-unknown-linux-gnu.json")).staged(),
    )
    .staged();
    let digest = sha256_hex(&bytes);
    let digest_file =
        std::fs::read_to_string(dist.join("vox-x86_64-unknown-linux-gnu.sha256")).staged();
    assert!(
        record["sha256"].as_str() == Some(digest.as_str())
            && digest_file.split_whitespace().next() == Some(digest.as_str())
            && record["size"].as_u64() == Some(bytes.len() as u64),
        "APPARATUS: release asset, sha256 file and record disagree"
    );
    let version = record["version"]
        .as_str()
        .expect("APPARATUS: release version");
    let tree = tempfile::tempdir().staged();
    let assets = tree.path().join(format!("releases/download/v{version}"));
    let records = tree.path().join("releases/latest/download");
    std::fs::create_dir_all(&assets).staged();
    std::fs::create_dir_all(&records).staged();
    std::fs::write(assets.join("vox-x86_64-unknown-linux-gnu"), &bytes).staged();
    std::fs::copy(
        dist.join("stable-x86_64-unknown-linux-gnu.json"),
        records.join("stable-x86_64-unknown-linux-gnu.json"),
    )
    .staged();
    let server =
        serve(tree.path()).unwrap_or_else(|why| panic!("APPARATUS: asset release server: {why}"));
    // Remote Podman runs in a Linux VM, not in this host's loopback namespace. Forward this
    // proof's one server port there; no real profile or home directory enters a container.
    let connections = podman()
        .args(["system", "connection", "list", "--format", "json"])
        .output()
        .staged();
    assert!(
        connections.status.success(),
        "APPARATUS: Podman connection discovery failed"
    );
    let connections: Vec<serde_json::Value> = serde_json::from_slice(&connections.stdout).staged();
    let mut tunnel = Tunnel(None);
    if let Some(connection) = connections
        .iter()
        .find(|connection| connection["Default"] == true)
    {
        if let Some(uri) = connection["URI"]
            .as_str()
            .filter(|uri| uri.starts_with("ssh://"))
        {
            assert!(
                connection["Name"] == "podman-machine-default",
                "APPARATUS: only podman-machine-default is authorized for this proof"
            );
            let uri = reqwest::Url::parse(uri).staged();
            let port = reqwest::Url::parse(&server.base).staged().port().staged();
            let forward = format!("{port}:127.0.0.1:{port}");
            let mut child = Command::new("ssh")
                .args([
                    "-F",
                    "/dev/null",
                    "-N",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "ExitOnForwardFailure=yes",
                    "-i",
                ])
                .arg(connection["Identity"].as_str().staged())
                .args(["-p", &uri.port().staged().to_string(), "-R", &forward])
                .arg(format!("{}@{}", uri.username(), uri.host_str().staged()))
                .stdin(Stdio::null())
                .spawn()
                .staged();
            std::thread::sleep(std::time::Duration::from_millis(500));
            assert!(
                child.try_wait().staged().is_none(),
                "APPARATUS: release-server SSH forward failed"
            );
            tunnel.0 = Some(child);
        }
    }
    let mut claims = Vec::new();
    let receipts = BTreeMap::new();
    for (index, id, image, packages, failing_getconf) in [
        (0, "asset.install_on_floor", "docker.io/library/almalinux@sha256:768bedc30fe0a536adb0a65d2eddb7caad364e514fbddd0ae9e026975f590342",
            "dnf install -y curl shadow-utils util-linux procps-ng; useradd -m -u 1000 user", false),
        (1, "asset.install_above_floor", "docker.io/library/ubuntu@sha256:f64b2ffc2f10ab8f8505aa56b2664bd846cbb9df87c7e2532e30f7667021c0e6",
            "apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y curl passwd util-linux procps; useradd -m -u 1000 user", false),
        (2, "asset.refuses_below_floor_before_downloading", "docker.io/library/ubuntu@sha256:152dc042452c496007f07ca9127571cb9c29697f42acbfad72324b2bb2e43c98",
            "apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y curl passwd util-linux; useradd -m -u 1000 user", false),
        (3, "asset.refuses_below_floor_when_getconf_fails", "docker.io/library/ubuntu@sha256:152dc042452c496007f07ca9127571cb9c29697f42acbfad72324b2bb2e43c98",
            "apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y curl passwd util-linux; useradd -m -u 1000 user", true),
        (4, "asset.names_the_missing_loader", "docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
            "apk add --no-cache curl shadow util-linux; useradd -m -u 1000 user", false),
    ] {
        if !selected.contains(&index) { continue; }
        let pulled = !podman().args(["image", "exists", image]).status().staged().success();
        let mut container = Container { name: format!("vox-rg11-assets-{}-{index}", std::process::id()), image: image.to_owned(), pulled, created: false };
        let work = tempfile::tempdir().staged();
        let entry = work.path().join("entry.sh");
        let shim = if failing_getconf { "mkdir -p \"$HOME/shim\"; printf '#!/bin/sh\\nexit 1\\n' >\"$HOME/shim/getconf\"; chmod 755 \"$HOME/shim/getconf\"; export PATH=\"$HOME/shim:$PATH\"" } else { ":" };
        std::fs::write(&entry, format!(r#"set -eu
{packages}
uname -m; cat /proc/version; getconf GNU_LIBC_VERSION || ldd --version || :
if [ ! -e /lib64/ld-linux-x86-64.so.2 ]; then echo LOADER_ABSENT; fi
cat >/user.sh <<'USER'
export HOME=/home/user VOX_DATA_DIR=/home/user/data VOX_CONFIG_DIR=/home/user/config
export VOX_PROXY=127.0.0.1:0 VOX_LISTEN=127.0.0.1:0
export VOX_RELEASE_BASE='{base}' VOX_NO_SHELL_SETUP=1 VOX_NO_SKILL_INSTALL=1
{shim}
echo INSTALL_BEGIN
sh /install.sh
rc=$?
echo INSTALL_EXIT=$rc
if [ -e "$HOME/.local/bin" ]; then echo BIN_EXISTS; fi
if [ -e "$HOME/.local/bin/vox" ]; then "$HOME/.local/bin/vox" --version; fi
if [ "$rc" = 0 ]; then
  "$HOME/.local/bin/vox" daemon --detach
  pid=$(cat "$VOX_DATA_DIR/.daemon/lock")
  echo "DAEMON_EXE=$(readlink /proc/$pid/exe)"
  if tr '\000' '\n' <"/proc/$pid/cmdline" | grep -Fx "$HOME/.local/bin/vox" >/dev/null; then
    echo "DAEMON_BINARY=$HOME/.local/bin/vox"
  fi
  "$HOME/.local/bin/vox" status
  kill -TERM "$pid"
fi
find "$HOME/.local/bin" -mindepth 1 2>/dev/null | sed 's/^/LEFTOVER /'
exit 0
USER
chmod 755 /user.sh
su -s /bin/sh user -c /user.sh
"#, base=server.base)).staged();
        let created = podman().args(["create", "--platform", "linux/amd64",
            "--cpus", "4", "--memory", "8g", "--network", "host", "--name", &container.name,
            image, "/bin/sh", "/entry.sh"]).output().staged();
        assert!(created.status.success(), "APPARATUS: create {image}: {}", String::from_utf8_lossy(&created.stderr));
        container.created = true;
        for (source, destination) in [(&entry, "/entry.sh"), (&installer, "/install.sh")] {
            let out = podman().arg("cp").arg(source)
                .arg(format!("{}:{destination}", container.name)).output().staged();
            assert!(out.status.success(), "APPARATUS: copy container input: {}", String::from_utf8_lossy(&out.stderr));
        }
        let before = server.requests();
        let started = std::time::Instant::now();
        let out = podman().args(["start", "-a", &container.name]).output().staged();
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success() && text.contains("INSTALL_BEGIN"),
            "APPARATUS: {id} did not reach the installer: {text}");
        assert!(text.contains("\nx86_64\n"), "APPARATUS: {id} did not run as x86_64: {text}");
        if index == 4 {
            assert!(text.contains("LOADER_ABSENT"), "APPARATUS: Alpine's missing loader was not staged: {text}");
        }
        let fetched = server.requests() - before;
        let ok = match index {
            0 | 1 => text.contains("INSTALL_EXIT=0") && text.contains(&format!("vox {version}"))
                && text.contains(&format!("installed: /home/user/.local/bin/vox (vox {version})"))
                && text.contains("DAEMON_BINARY=/home/user/.local/bin/vox"),
            2 => text.contains("INSTALL_EXIT=1") && fetched == 0
                && text.contains("and this system has glibc 2.27. Nothing was downloaded or installed.")
                && !text.contains("BIN_EXISTS") && !text.contains("LEFTOVER "),
            3 => text.contains("INSTALL_EXIT=1") && text.contains("GLIBC_2.28' not found")
                && text.contains("this system is older than that") && text.contains("nothing was installed.")
                && !text.contains("LEFTOVER "),
            _ => text.contains("LOADER_ABSENT") && text.contains("INSTALL_EXIT=1")
                && text.contains("the program loader this build needs, /lib64/ld-linux-x86-64.so.2, is not on this system.")
                && text.contains("nothing was installed.") && !text.contains("LEFTOVER "),
        };
        claims.push(claim(id, ok, format!("image={image}, wall={:?}, requests={fetched}; {text}", started.elapsed())));
    }
    report(&claims, &receipts, &[]);
}

/// The environment `vox uninstall` runs in: the scratch home, and a data root and config directory
/// in it, never the person's.
fn uninstall_env(home: &Path) -> Vec<(String, String)> {
    let h = home.to_string_lossy().into_owned();
    vec![
        ("HOME".into(), h.clone()),
        ("PATH".into(), SYSTEM_PATH.into()),
        ("SHELL".into(), "/bin/zsh".into()),
        ("TERM".into(), "dumb".into()),
        ("VOX_DATA_DIR".into(), format!("{h}/data")),
        ("VOX_CONFIG_DIR".into(), format!("{h}/config")),
        (
            "VOX_TEST_KEYCHAIN".into(),
            format!("{h}/data/proof.keychain-db"),
        ),
        ("VOX_INSTALL_DIR".into(), format!("{h}/bin")),
        ("VOX_LISTEN".into(), "127.0.0.1:0".into()),
        ("VOX_PROXY".into(), "127.0.0.1:0".into()),
    ]
}

/// Run `vox` with only `env`: whether it exited 0, its stdout and its stderr.
fn run_vox(vox: &Path, env: &[(String, String)], args: &[&str]) -> (bool, String, String) {
    let out = match Command::new(vox)
        .args(args)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(std::process::Stdio::null())
        .output()
    {
        Ok(out) => out,
        Err(error) => {
            return (
                false,
                String::new(),
                format!("could not run {}: {error}", vox.display()),
            )
        }
    };
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A real attached node and saved message in this proof's private profile.
struct SavedRoom {
    home: PathBuf,
    room: String,
}

impl SavedRoom {
    fn stage(home: &Path) -> Result<Self, String> {
        if cfg!(target_os = "macos") {
            unlock_staging::keychain(&home.join("data"));
        }
        let mut saved = Self {
            home: home.to_path_buf(),
            room: String::new(),
        };
        let env = uninstall_env(home);
        let vox = home.join("bin/vox");
        let pass = home.join("saved-room-pass");
        std::fs::write(&pass, b"installer proof passphrase\n")
            .map_err(|e| format!("APPARATUS: writing scratch passphrase: {e}"))?;
        let pass = pass
            .to_str()
            .ok_or("APPARATUS: scratch passphrase path is not UTF-8")?;
        for args in [
            &["node", "create", "kept", "--passphrase-file", pass][..],
            &[
                "node",
                "attach",
                "kept",
                "--keep",
                "--passphrase-file",
                pass,
            ],
            &[
                "room",
                "create",
                "--node",
                "kept",
                "--passphrase-file",
                pass,
                "--name",
                "saved",
            ],
        ] {
            let out = run_vox(&vox, &env, args);
            if !out.0 {
                return Err(format!("APPARATUS: staging vox {args:?}: {out:?}"));
            }
        }
        let listing = run_vox(&vox, &env, &["room", "list", "--node", "kept"]);
        if !listing.0 {
            return Err(format!("APPARATUS: listing staged room: {listing:?}"));
        }
        saved.room = listing
            .1
            .split_whitespace()
            .next()
            .ok_or("APPARATUS: staged room list was empty")?
            .to_owned();
        let posted = run_vox(
            &vox,
            &env,
            &[
                "room",
                "post",
                &saved.room,
                "installer proof exact saved message",
                "--node",
                "kept",
            ],
        );
        if !posted.0 || !saved.intact(home) {
            return Err(format!(
                "APPARATUS: staged room is not readable with a Ready node: {posted:?}"
            ));
        }
        Ok(saved)
    }

    fn intact(&self, home: &Path) -> bool {
        let env = uninstall_env(home);
        let vox = home.join("bin/vox");
        let status = run_vox(&vox, &env, &["status", "--node", "kept", "--json"]);
        let read = run_vox(&vox, &env, &["room", "read", &self.room, "--node", "kept"]);
        status.0
            && serde_json::from_str::<serde_json::Value>(&status.1)
                .is_ok_and(|v| v["status"] == "Ready")
            && read.0
            && read
                .1
                .lines()
                .any(|line| line.ends_with("installer proof exact saved message"))
    }

    fn cleanup(self, home: &Path) {
        let _ = run_vox(
            &home.join("bin/vox"),
            &uninstall_env(home),
            &["node", "detach", "kept"],
        );
    }
}

impl Drop for SavedRoom {
    fn drop(&mut self) {
        for pid in data_holders(&self.home.join("data")) {
            let _ = Command::new("/bin/kill").arg(pid).status();
        }
    }
}

/// Run `vox` at a pseudo-terminal (`script`), typing `input`: everything it said.
fn at_a_terminal(vox: &str, env: &[(String, String)], args: &[&str], input: &str) -> String {
    let mut cmd = Command::new("/usr/bin/script");
    if cfg!(target_os = "macos") {
        cmd.args(["-q", "/dev/null", vox]).args(args);
    } else {
        let line = std::iter::once(vox)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        cmd.args(["-qec", &line, "/dev/null"]);
    }
    let mut child = cmd
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .staged();
    // `script` turns the end of its input into ^D at the terminal: the input stays open until the
    // command has ended (or 60 s), so the typed line is read, not an end of file.
    let stdin = child.stdin.take();
    if let Some(mut s) = stdin.as_ref() {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let _ = s.write_all(input.as_bytes());
        let _ = s.flush();
    }
    let t0 = std::time::Instant::now();
    while child.try_wait().ok().flatten().is_none()
        && t0.elapsed() < std::time::Duration::from_secs(60)
    {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    drop(stdin);
    let out = child.wait_with_output().staged();
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Every file and link under `root`, with its size: what a dry run must leave as it was.
fn home_files(root: &Path) -> BTreeMap<PathBuf, u64> {
    let mut seen = BTreeMap::new();
    let mut todo = vec![root.to_path_buf()];
    while let Some(dir) = todo.pop() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let Ok(m) = std::fs::symlink_metadata(e.path()) else {
                continue;
            };
            if m.is_dir() {
                todo.push(e.path());
            } else if !e.path().to_string_lossy().contains("/data/.daemon/") {
                // The daemon's own log and socket change as it runs; everything else must not.
                seen.insert(e.path(), m.len());
            }
        }
    }
    seen
}

/// The processes holding a file under `dir` open: the daemon a proof started for that data root.
fn data_holders(dir: &Path) -> Vec<String> {
    if cfg!(target_os = "linux") {
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
        return pids;
    }
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

fn report(claims: &[Claim], receipts: &BTreeMap<String, String>, allowed: &[String]) {
    println!("\n--- install.sh proof ---");
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
    assert!(
        failed.is_empty(),
        "PRODUCT: {} claim(s) about what install.sh did failed:\n{}",
        failed.len(),
        failed
            .iter()
            .map(|c| format!("  {} — {}", c.id, c.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        unproven.is_empty(),
        "APPARATUS: {} claim(s) unproven because staging failed — close the gap, or name it in \
         VOX_PROOF_ALLOW_UNPROVEN:\n{}",
        unproven.len(),
        unproven
            .iter()
            .map(|c| format!("  {} — {}", c.id, c.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
