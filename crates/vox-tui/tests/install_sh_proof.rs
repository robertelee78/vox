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
//! This lives in `vox-tui`'s tests because it needs `vox` itself as the release payload.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
/// The synthetic version served as "the release" — clearly not a real one.
const SERVED: &str = "9.9.9";

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
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
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

/// A python `http.server` over `root`, on a port nothing else holds. Killed on drop.
struct Server {
    child: Child,
    base: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn serve(root: &Path) -> Result<Server, String> {
    let port = TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .map_err(|e| format!("no free port: {e}"))?;
    let child = Command::new("python3")
        .args([
            "-m",
            "http.server",
            &port.to_string(),
            "--bind",
            "127.0.0.1",
            "--directory",
        ])
        .arg(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("python3 could not be run ({e}); it is what serves the release"))?;
    let base = format!("http://127.0.0.1:{port}/releases");
    // Wait for it to answer rather than sleeping a guessed interval.
    for _ in 0..100 {
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            // The port is taken, i.e. the server has it.
            return Ok(Server { child, base });
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err("the loopback release server never came up".into())
}

/// A release tree: the record at `latest/download/<channel>-<triple>.json` and the binary at
/// `download/v<version>/vox-<triple>`. `mangle` gets the last word on the record's fields.
fn release_tree(root: &Path, channel: &str, mangle: &dyn Fn(&mut BTreeMap<&str, String>)) {
    let triple = target_triple();
    let bin = std::fs::read(VOX).unwrap();
    let asset_dir = root.join("releases/download").join(format!("v{SERVED}"));
    std::fs::create_dir_all(&asset_dir).unwrap();
    std::fs::write(asset_dir.join(format!("vox-{triple}")), &bin).unwrap();

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
    let rec_dir = root.join("releases/latest/download");
    std::fs::create_dir_all(&rec_dir).unwrap();
    std::fs::write(
        rec_dir.join(format!("{channel}-{triple}.json")),
        format!("{{{body}}}\n"),
    )
    .unwrap();
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
    std::fs::create_dir_all(home).unwrap();
    let mut f = std::fs::File::create(home.join(".zshrc")).unwrap();
    f.write_all(b"export VOX_PROOF_USER_LINE=kept\n").unwrap();
    let out = Command::new("sh")
        .arg(install_sh())
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("SHELL", "/bin/zsh")
        .env("TERM", "dumb")
        .env("VOX_RELEASE_BASE", &server.base)
        .env("VOX_INSTALL_DIR", home.join("bin"))
        .env("VOX_CHANNEL", channel)
        .envs(extra.iter().copied())
        .output()
        .expect("sh ran install.sh");
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
    let mut claims: Vec<Claim> = Vec::new();
    let mut receipts: BTreeMap<String, String> = BTreeMap::new();
    let allowed: Vec<String> = std::env::var("VOX_PROOF_ALLOW_UNPROVEN")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();

    let tree = tempfile::tempdir().unwrap();
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
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let (ok, text) = run_installer(&server, home, "stable");
        let version = Command::new(home.join("bin/vox"))
            .arg("--version")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default();
        let marker =
            std::fs::read_to_string(home.join("bin/.vox-standalone.json")).unwrap_or_default();
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
        let tmp = tempfile::tempdir().unwrap();
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
    // The fixture is a cargo build, so it carries at most an ad-hoc signature. Forcing the gate
    // on is the only way to measure it locally: a genuinely notarized binary exists only as
    // output of the release workflow.
    if cfg!(target_os = "macos") {
        release_tree(tree.path(), "stable", &|_| {});
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let (ok, text) =
            run_installer_env(&server, home, "stable", &[("VOX_PROOF_APPLE_VERIFY", "1")]);
        claims.push(claim(
            "install.apple_gate_refuses_unsigned_bytes",
            !ok && !home.join("bin/vox").exists() && text.contains("3T2D2YNTVW"),
            format!("with the Apple gate forced on, the installer said {text:?}"),
        ));
    } else {
        claims.push(blocked(
            "install.apple_gate_refuses_unsigned_bytes",
            "the Apple gate is macOS-only and this is not macOS",
        ));
    }

    // ---- a `vox` this installer did not install is never overwritten -----------------
    {
        release_tree(tree.path(), "stable", &|_| {});
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let bin = home.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("vox"), b"#!/bin/sh\necho mine\n").unwrap();
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
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let (ok1, _) = run_installer(&server, home, "stable");
        let (ok2, text) = run_installer(&server, home, "stable");
        let previous = home.join("bin/.vox-previous");
        claims.push(claim(
            "install.is_idempotent_and_keeps_the_previous",
            ok1 && ok2 && previous.is_file(),
            format!(
                "second run exit_ok={ok2}, .vox-previous present={}, said {text:?}",
                previous.is_file()
            ),
        ));
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
        "{} claim(s) unproven — close the gap, or name it in VOX_PROOF_ALLOW_UNPROVEN:\n{}",
        unproven.len(),
        unproven
            .iter()
            .map(|c| format!("  {} — {}", c.id, c.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
