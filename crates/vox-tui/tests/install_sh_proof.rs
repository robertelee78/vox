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
//! `vox update` deliberately has **no** equivalent hook. An environment variable that
//! redirects where a binary fetches its own replacement is a vulnerability, not a test seam,
//! so the updater stays pinned to GitHub's origins and its mismatch refusals are recorded as
//! an accepted gap in ADR-018 instead.
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

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

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

/// A python `http.server` over `root`, on a port it chose itself. Killed on drop.
struct Server {
    child: Child,
    base: String,
    /// Everything python said: its request log is on stderr.
    log: std::sync::Arc<std::sync::Mutex<String>>,
}

impl Server {
    /// How many requests the server has answered so far.
    fn requests(&self) -> usize {
        self.log.lock().staged().matches("\"GET ").count()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// How long python may take to start serving.
///
/// `python3` is whatever is on `PATH`, often a version-manager shim that runs several processes
/// before python itself. This used to allow 5s, and on a loaded box (load 81) the proof failed in
/// 9s with "the loopback release server never came up" while nothing was wrong with `install.sh`
/// (#164). A python started 6s late reproduces that failure every time.
const SERVER_START: std::time::Duration = std::time::Duration::from_secs(90);

/// Serve `root` over loopback HTTP.
///
/// **python picks the port and says which.** This used to reserve a port by binding and
/// releasing it, start python on it, and take "the port is bound now" as "python is serving". That
/// was a race: anything that took the port in between made the check pass against the wrong
/// server, and a python that failed to start left only a timeout, because its stderr went to
/// `/dev/null`. Now python binds port 0 and prints the port it got, which is the one fact that
/// means it is serving; and if it exits instead, the failure carries its exit status and stderr.
fn serve(root: &Path) -> Result<Server, String> {
    use std::io::{BufRead as _, BufReader, Read as _};
    let mut child = Command::new("python3")
        .args([
            "-u",
            "-m",
            "http.server",
            "0",
            "--bind",
            "127.0.0.1",
            "--directory",
        ])
        .arg(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("python3 could not be run ({e}); it is what serves the release"))?;
    // Both pipes are drained for the server's whole life: its request log goes to stderr, and an
    // undrained pipe would stop it mid-proof once full.
    let said = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let mut stderr = child.stderr.take().staged();
    let err_log = std::sync::Arc::clone(&said);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stderr.read(&mut buf) {
            if n == 0 {
                break;
            }
            err_log
                .lock()
                .staged()
                .push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    });
    let stdout = child.stdout.take().staged();
    let (port_tx, port_rx) = std::sync::mpsc::channel::<u16>();
    let out_log = std::sync::Arc::clone(&said);
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            // "Serving HTTP on 127.0.0.1 port 61866 (http://127.0.0.1:61866/) ..."
            if let Some(port) = line
                .split_once(" port ")
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .and_then(|p| p.parse().ok())
            {
                let _ = port_tx.send(port);
            }
            out_log.lock().staged().push_str(&format!("{line}\n"));
        }
    });
    let started = std::time::Instant::now();
    loop {
        if let Ok(port) = port_rx.recv_timeout(std::time::Duration::from_millis(100)) {
            let base = format!("http://127.0.0.1:{port}/releases");
            return Ok(Server {
                child,
                base,
                log: said,
            });
        }
        if let Ok(Some(status)) = child.try_wait() {
            // Let the reader threads take what it said before it went.
            std::thread::sleep(std::time::Duration::from_millis(200));
            return Err(format!(
                "python3 exited ({status}) after {:.1}s without serving; it said: {:?}",
                started.elapsed().as_secs_f64(),
                said.lock().staged()
            ));
        }
        if started.elapsed() > SERVER_START {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "python3 did not start serving within {}s; it said: {:?}",
                SERVER_START.as_secs(),
                said.lock().staged()
            ));
        }
    }
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
/// the built `vox` at `Contents/Helpers/vox`, ad-hoc signed (a Developer ID signature exists only
/// as output of the release workflow), and its record at `latest/download/app-<channel>-<triple>.json`.
fn app_release(root: &Path, channel: &str) {
    let triple = target_triple();
    let work = tempfile::tempdir().staged();
    let app = work.path().join("Vox.app");
    let contents = app.join("Contents");
    std::fs::create_dir_all(contents.join("MacOS")).staged();
    std::fs::create_dir_all(contents.join("Helpers")).staged();
    std::fs::copy(VOX, contents.join("MacOS/Vox")).staged();
    std::fs::copy(VOX, contents.join("Helpers/vox")).staged();
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
             <key>CFBundleShortVersionString</key><string>{SERVED}</string>\
             <key>LSMinimumSystemVersion</key><string>13.0</string>\
             </dict></plist>\n"
        ),
    )
    .staged();
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
    let zip_name = format!("Vox-{SERVED}-{triple}.zip");
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
    let asset_dir = root.join("releases/download").join(format!("v{SERVED}"));
    std::fs::create_dir_all(&asset_dir).staged();
    std::fs::write(asset_dir.join(&zip_name), &bytes).staged();

    let mut f: BTreeMap<&str, String> = BTreeMap::new();
    f.insert("kind", "vox.app-release".into());
    f.insert("schema_version", "1".into());
    f.insert("package", "Vox.app".into());
    f.insert("channel", channel.into());
    f.insert("target", triple.into());
    f.insert("version", SERVED.into());
    f.insert("size", bytes.len().to_string());
    f.insert("sha256", sha256_hex(&bytes));
    let rec_dir = root.join("releases/latest/download");
    std::fs::create_dir_all(&rec_dir).staged();
    std::fs::write(
        rec_dir.join(format!("app-{channel}-{triple}.json")),
        record_json(&f),
    )
    .staged();
}

/// A release tree: the record at `latest/download/<channel>-<triple>.json` and the binary at
/// `download/v<version>/vox-<triple>`, and on macOS the app ([`app_release`]). `mangle` gets the
/// last word on the `vox` record's fields.
fn release_tree(root: &Path, channel: &str, mangle: &dyn Fn(&mut BTreeMap<&str, String>)) {
    if cfg!(target_os = "macos") {
        app_release(root, channel);
    }
    let triple = target_triple();
    let bin = std::fs::read(VOX).staged();
    let asset_dir = root.join("releases/download").join(format!("v{SERVED}"));
    std::fs::create_dir_all(&asset_dir).staged();
    std::fs::write(asset_dir.join(format!("vox-{triple}")), &bin).staged();

    let mut f: BTreeMap<&str, String> = BTreeMap::new();
    f.insert("kind", "vox.standalone-release".into());
    f.insert("schema_version", "1".into());
    f.insert("package", "vox".into());
    f.insert("channel", channel.into());
    f.insert("target", triple.into());
    f.insert("version", SERVED.into());
    f.insert("size", bin.len().to_string());
    f.insert("sha256", sha256_hex(&bin));
    mangle(&mut f);
    let rec_dir = root.join("releases/latest/download");
    std::fs::create_dir_all(&rec_dir).staged();
    std::fs::write(
        rec_dir.join(format!("{channel}-{triple}.json")),
        record_json(&f),
    )
    .staged();
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
    let out = Command::new("sh")
        .arg(install_sh())
        .env_clear()
        .env("HOME", home)
        .env("VOX_APPLICATIONS_DIR", system_apps(home))
        .env("SHELL", "/bin/zsh")
        .env("TERM", "dumb")
        .env("VOX_RELEASE_BASE", &server.base)
        .env("VOX_INSTALL_DIR", home.join("bin"))
        .env("VOX_CHANNEL", channel)
        .envs(extra.iter().copied().filter(|(k, _)| *k != "PATH"))
        .env("PATH", path)
        .output()
        .staged();
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

    // ---- the happy path, observed the way a user observes it -------------------------
    {
        let tmp = tempfile::tempdir().staged();
        let home = tmp.path();
        let (ok, text) = run_installer(&server, home, "stable");
        let version = Command::new(home.join("bin/vox"))
            .arg("--version")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default();
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
        receipts.insert("install.happy_path".into(), text);
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

    // ---- a second run over its own install keeps the one it replaced -----------------
    {
        let tmp = tempfile::tempdir().staged();
        let home = tmp.path();
        let (ok1, _) = run_installer(&server, home, "stable");
        let (ok2, text) = run_installer(&server, home, "stable");
        let previous = if cfg!(target_os = "macos") {
            system_apps(home).join(".Vox.app.previous/Contents/Helpers/vox")
        } else {
            home.join("bin/.vox-previous")
        };
        claims.push(claim(
            "install.is_idempotent_and_keeps_the_previous",
            ok1 && ok2 && previous.is_file(),
            format!(
                "second run exit_ok={ok2}, {} present={}, said {text:?}",
                previous.display(),
                previous.is_file()
            ),
        ));
    }

    // ---- a run that was cut short does not stop the next one (V210-117) ---------------
    // What an interrupted run leaves: a read-only `.vox-candidate.partial` (a `vox update` before
    // v0.2.10, cut short, left it 0555) and a `.vox-previous` that cannot be written to. Running
    // the installer again is what a person does next, and it stopped at "Permission denied".
    {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().staged();
        let home = tmp.path();
        let bin = home.join("bin");
        let (first, said_first) = run_installer(&server, home, "stable");
        if first && cfg!(target_os = "macos") {
            // On macOS the leftovers are bundles: a read-only `.Vox.app.partial` and a read-only
            // `.Vox.app.previous`, each with a file inside that only a writable folder can lose.
            let apps = system_apps(home);
            for leftover in [".Vox.app.partial", ".Vox.app.previous"] {
                let dir = apps.join(leftover);
                std::fs::create_dir_all(&dir).staged();
                std::fs::write(dir.join("cut-short"), b"cut short").staged();
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).staged();
            }
            let (ok, text) = run_installer(&server, home, "stable");
            let version = Command::new(bin.join("vox"))
                .arg("--version")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
                .unwrap_or_default();
            let replaced = apps
                .join(".Vox.app.previous/Contents/Helpers/vox")
                .is_file()
                && !apps.join(".Vox.app.previous/cut-short").exists();
            let partials: Vec<String> = std::fs::read_dir(&apps)
                .staged()
                .filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".partial"))
                .collect();
            claims.push(claim(
                "install.reruns_after_a_cut_short_run",
                ok && version == format!("vox {SERVED}") && replaced && partials.is_empty(),
                format!(
                    "over a read-only .Vox.app.partial and .Vox.app.previous: exit_ok={ok}, the \
                     installed vox reports {version:?}, .Vox.app.previous is the replaced \
                     bundle={replaced}, partials left {partials:?}, said {text:?}"
                ),
            ));
        } else if first {
            for leftover in [".vox-candidate.partial", ".vox-previous"] {
                std::fs::write(bin.join(leftover), b"cut short").staged();
                std::fs::set_permissions(
                    bin.join(leftover),
                    std::fs::Permissions::from_mode(0o555),
                )
                .staged();
            }
            let (ok, text) = run_installer(&server, home, "stable");
            let version = Command::new(bin.join("vox"))
                .arg("--version")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
                .unwrap_or_default();
            let previous = std::fs::read(bin.join(".vox-previous")).unwrap_or_default();
            // The binary the re-run replaced, not the leftover it was planted over.
            let replaced = previous.len() > 64 && previous != b"cut short";
            let partials: Vec<String> = std::fs::read_dir(&bin)
                .staged()
                .filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.ends_with(".partial"))
                .collect();
            claims.push(claim(
                "install.reruns_after_a_cut_short_run",
                ok && version.starts_with("vox ") && replaced && partials.is_empty(),
                format!(
                    "over a read-only partial and .vox-previous: exit_ok={ok}, the installed vox \
                     reports {version:?}, .vox-previous is the replaced binary={replaced}, partials left \
                     {partials:?}, said {text:?}"
                ),
            ));
        } else {
            // The first install is install.sh's own work: its failure is the product's.
            claims.push(claim(
                "install.reruns_after_a_cut_short_run",
                false,
                format!("(staging) the first install failed, said {said_first:?}"),
            ));
        }
    }

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
            let version = Command::new(home.join("bin/vox"))
                .arg("--version")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
                .unwrap_or_default();
            let app_version = Command::new("/usr/libexec/PlistBuddy")
                .args(["-c", "Print :CFBundleShortVersionString"])
                .arg(app.join("Contents/Info.plist"))
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
                .unwrap_or_default();
            let said_where = text.contains(&format!("installed: {}", app.display()));
            claims.push(claim(
                id,
                ok && link == app.join("Contents/Helpers/vox")
                    && !app_version.is_empty()
                    && version == format!("vox {app_version}")
                    && said_where,
                format!(
                    "exit_ok={ok}, ~/.local/bin/vox -> {}, it reports {version:?}, the app says \
                     {app_version:?}, said where={said_where}, said {text:?}",
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
    }

    report(&claims, &receipts, &allowed);
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
        "APPARATUS: {} claim(s) unproven, because this proof's own release server did not \
         start — close the gap, or name it in VOX_PROOF_ALLOW_UNPROVEN:\n{}",
        unproven.len(),
        unproven
            .iter()
            .map(|c| format!("  {} — {}", c.id, c.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
