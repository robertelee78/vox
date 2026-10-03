//! Proof: after `vox shell-setup`, a **new shell** has `vox` on `PATH` and tab completion
//! works.
//!
//! That sentence is the feature, so it is what gets measured. This spawns a real `zsh` and a
//! real `bash`, lets *them* read the rc file the way they normally would, and then asks the
//! shell itself two questions:
//!
//! - does `vox` resolve on `PATH`, to the directory we installed into?
//! - is a completion actually **registered for the command** — `_comps[vox]` in zsh,
//!   `complete -p vox` in bash?
//!
//! The second question is the one that matters and the one a unit test cannot ask. zsh's
//! `compinit` builds its table once; if the rc already ran it, a later `fpath` change is
//! invisible and completion silently does nothing. Every string-level assertion about the rc
//! block passes in that state. Only the shell can tell you.
//!
//! ## Honest coverage
//! A shell that is not installed is reported as **unproven** and fails the proof rather than
//! passing quietly — an absent prover is missing evidence, not evidence of correctness. Set
//! `VOX_PROOF_ALLOW_UNPROVEN=fish[,bash,...]` to accept a named gap, which makes the gap a
//! deliberate, visible decision instead of a silent one.

#[path = "../../vox-core/tests/support/watchdog.rs"]
mod watchdog;

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const VOX: &str = env!("CARGO_BIN_EXE_vox");
/// Far past what reading an rc file and answering one question takes. A shell still running at
/// this point has hung, and the caller says on which side.
const SHELL_PATIENCE: Duration = Duration::from_secs(30);

/// One question put to a real shell, and what it answered.
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

fn which(bin: &str) -> Option<PathBuf> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let p = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (!p.is_empty()).then(|| PathBuf::from(p))
}

/// Run `cmd` to completion, or kill it once it has run for `SHELL_PATIENCE`: `Err` names how
/// long it ran and what it had said.
fn bounded(mut cmd: Command) -> Result<Output, String> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot spawn {cmd:?}: {e}"));
    // Drained on their own threads, so a full pipe cannot pass for a hang.
    let drain = |mut r: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = r.read_to_end(&mut buf);
            buf
        })
    };
    let out = drain(Box::new(
        child.stdout.take().expect("APPARATUS: piped stdout"),
    ));
    let err = drain(Box::new(
        child.stderr.take().expect("APPARATUS: piped stderr"),
    ));
    let t0 = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if t0.elapsed() < SHELL_PATIENCE => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                child
                    .kill()
                    .unwrap_or_else(|e| panic!("APPARATUS: cannot kill {cmd:?}: {e}"));
                let _ = child.wait();
                let said = String::from_utf8_lossy(&out.join().unwrap_or_default()).into_owned()
                    + &String::from_utf8_lossy(&err.join().unwrap_or_default());
                return Err(format!(
                    "still running after {:?}; it said {said:?}",
                    t0.elapsed()
                ));
            }
            Err(e) => panic!("APPARATUS: cannot wait for {cmd:?}: {e}"),
        }
    };
    Ok(Output {
        status,
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    })
}

/// Run `script` in `shell` as an interactive shell, with `home` as `$HOME`, so the shell
/// reads the rc it would normally read. Returns (stdout, stderr, success); a shell that
/// hangs is killed and answers as a failure whose stderr says so.
fn in_shell(shell: &Path, home: &Path, script: &str) -> (String, String, bool) {
    // `-i` is what makes the shell read the interactive rc — the whole point. A minimal
    // environment keeps the developer's own dotfiles and PATH out of the measurement.
    let mut cmd = Command::new(shell);
    cmd.args(["-i", "-c", script])
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("TERM", "dumb")
        // zsh writes a compdump under $HOME; keep it there.
        .env("ZDOTDIR", home);
    match bounded(cmd) {
        Ok(out) => (
            String::from_utf8_lossy(&out.stdout).trim().to_owned(),
            String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            out.status.success(),
        ),
        Err(hung) => (String::new(), format!("HUNG: {hung}"), false),
    }
}

/// The precondition every shell's claims rest on: the shell answers an interactive `-c` here
/// **before** `vox shell-setup` has touched its rc. If it does not, a failure after setup could
/// be this machine's shell rather than the block vox wrote, so it is CANNOT MEASURE.
fn shell_runs(shell: &Path, home: &Path) -> Result<(), String> {
    match in_shell(shell, home, "print -r -- ready 2>/dev/null || echo ready") {
        (out, _, true) if out.ends_with("ready") => Ok(()),
        (out, err, ok) => Err(format!(
            "APPARATUS, CANNOT MEASURE: {} -i -c did not answer before shell-setup (ok={ok}, out={out:?}, \
             err={err:?})",
            shell.display()
        )),
    }
}

/// Install the binary into `dir` (a copy, so the rc block names a stable path) and run
/// `vox shell-setup` with `home` as `$HOME`.
fn setup(home: &Path, dir: &Path, login_shell: &str) -> (String, PathBuf) {
    std::fs::create_dir_all(dir).expect("APPARATUS: create the install dir");
    let installed = dir.join("vox");
    std::fs::copy(VOX, &installed).expect("APPARATUS: copy vox into the install dir");
    let mut cmd = Command::new(&installed);
    cmd.arg("shell-setup")
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("SHELL", login_shell);
    let out = bounded(cmd).unwrap_or_else(|hung| panic!("PRODUCT: vox shell-setup {hung}"));
    assert!(
        out.status.success(),
        "PRODUCT: vox shell-setup failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (String::from_utf8_lossy(&out.stdout).into_owned(), installed)
}

fn allow_unproven() -> Vec<String> {
    std::env::var("VOX_PROOF_ALLOW_UNPROVEN")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

#[test]
fn shell_setup_gives_a_new_shell_vox_on_path_and_working_completion() {
    watchdog::arm();
    let mut claims: Vec<Claim> = Vec::new();
    let mut receipts: BTreeMap<String, String> = BTreeMap::new();
    let allowed = allow_unproven();

    // ---- zsh: PATH, completion registration, and the compinit-already-ran case ----
    match which("zsh") {
        None => claims.push(blocked(
            "zsh.installed",
            "zsh is not installed on this machine",
        )),
        Some(zsh) => {
            let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
            let home = tmp.path();
            // A pre-existing line proves the block is appended, not substituted for the
            // user's file.
            std::fs::write(home.join(".zshrc"), "export VOX_PROOF_USER_LINE=kept\n")
                .expect("APPARATUS: write .zshrc");
            if let Err(why) = shell_runs(&zsh, home) {
                claims.push(blocked("zsh.runs_interactively", why));
            } else {
                let dir = home.join(".local").join("bin");
                let (out, installed) = setup(home, &dir, "/bin/zsh");
                receipts.insert("zsh.shell_setup.stdout".into(), out);

                let (path, err, ok) = in_shell(&zsh, home, "command -v vox");
                claims.push(claim(
                    "zsh.path",
                    ok && Path::new(&path) == installed,
                    format!("command -v vox -> {path:?} (want {installed:?}) {err}"),
                ));

                // The real question: is a completion registered for the *command*?
                let (comp, err, _) = in_shell(&zsh, home, "print -r -- ${_comps[vox]}");
                claims.push(claim(
                    "zsh.completion_registered",
                    comp == "_vox",
                    format!("_comps[vox] -> {comp:?} (want \"_vox\") {err}"),
                ));

                // And the function behind that binding really loads, and is vox's: `autoload -Uz`
                // alone is lazy and succeeds for a name no file defines, so `+X` loads the body
                // now (failing if `fpath` has no `_vox`), and the body must name a vox verb.
                let (body, err, ok) = in_shell(&zsh, home, "autoload +X _vox && functions _vox");
                claims.push(claim(
                    "zsh.completion_loadable",
                    ok && body.contains("shell-setup"),
                    format!(
                        "autoload +X _vox -> ok={ok}, {} lines, names shell-setup: {} {err}",
                        body.lines().count(),
                        body.contains("shell-setup")
                    ),
                ));

                // The user's own content survived.
                let rc =
                    std::fs::read_to_string(home.join(".zshrc")).expect("APPARATUS: read .zshrc");
                claims.push(claim(
                    "zsh.user_rc_preserved",
                    rc.contains("VOX_PROOF_USER_LINE=kept"),
                    "the user's line is still in .zshrc",
                ));

                // The case that motivated the design: an rc that already ran `compinit`, so a
                // later fpath change is invisible to it. Completion must still be registered.
                let tmp2 = tempfile::tempdir().expect("APPARATUS: tempdir");
                let home2 = tmp2.path();
                let dir2 = home2.join(".local").join("bin");
                std::fs::write(
                    home2.join(".zshrc"),
                    "autoload -Uz compinit && compinit -i\n",
                )
                .expect("APPARATUS: write .zshrc");
                setup(home2, &dir2, "/bin/zsh");
                let (comp2, err2, _) = in_shell(&zsh, home2, "print -r -- ${_comps[vox]}");
                claims.push(claim(
                    "zsh.completion_after_compinit_already_ran",
                    comp2 == "_vox",
                    format!("_comps[vox] -> {comp2:?} with compinit already run {err2}"),
                ));

                // `--remove` leaves the file as it was.
                let before =
                    std::fs::read_to_string(home2.join(".zshrc")).expect("APPARATUS: read .zshrc");
                let mut remove = Command::new(dir2.join("vox"));
                remove
                    .args(["shell-setup", "--remove"])
                    .env_clear()
                    .env("HOME", home2)
                    .env("PATH", "/usr/bin:/bin")
                    .env("SHELL", "/bin/zsh");
                let removed = bounded(remove)
                    .unwrap_or_else(|hung| panic!("PRODUCT: vox shell-setup --remove {hung}"));
                let after =
                    std::fs::read_to_string(home2.join(".zshrc")).expect("APPARATUS: read .zshrc");
                claims.push(claim(
                    "zsh.remove_restores_rc",
                    removed.status.success()
                        && after == "autoload -Uz compinit && compinit -i\n"
                        && before != after,
                    format!(
                        "after --remove the rc is {after:?}; it said {}",
                        String::from_utf8_lossy(&removed.stderr)
                    ),
                ));
            }
        }
    }

    // ---- bash: PATH and a registered completion spec ----
    match which("bash") {
        None => claims.push(blocked("bash.installed", "bash is not installed")),
        Some(bash) => {
            let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
            let home = tmp.path();
            std::fs::write(home.join(".bashrc"), "export VOX_PROOF_USER_LINE=kept\n")
                .expect("APPARATUS: write .bashrc");
            if let Err(why) = shell_runs(&bash, home) {
                claims.push(blocked("bash.runs_interactively", why));
            } else {
                let dir = home.join(".local").join("bin");
                let (out, installed) = setup(home, &dir, "/bin/bash");
                receipts.insert("bash.shell_setup.stdout".into(), out);

                let (path, err, ok) = in_shell(&bash, home, "command -v vox");
                claims.push(claim(
                    "bash.path",
                    ok && Path::new(&path) == installed,
                    format!("command -v vox -> {path:?} (want {installed:?}) {err}"),
                ));

                let (spec, err, _) = in_shell(&bash, home, "complete -p vox 2>/dev/null");
                claims.push(claim(
                    "bash.completion_registered",
                    spec.contains("vox"),
                    format!("complete -p vox -> {spec:?} {err}"),
                ));

                let rc =
                    std::fs::read_to_string(home.join(".bashrc")).expect("APPARATUS: read .bashrc");
                claims.push(claim(
                    "bash.user_rc_preserved",
                    rc.contains("VOX_PROOF_USER_LINE=kept"),
                    "the user's line is still in .bashrc",
                ));
            }
        }
    }

    // ---- fish: proved only if installed ----
    match which("fish") {
        None => claims.push(blocked("fish.installed", "fish is not installed")),
        Some(fish) => {
            let tmp = tempfile::tempdir().expect("APPARATUS: tempdir");
            let home = tmp.path();
            let dir = home.join(".local").join("bin");
            std::fs::create_dir_all(home.join(".config").join("fish"))
                .expect("APPARATUS: create the fish config dir");
            let (_, installed) = setup(home, &dir, "/usr/bin/fish");
            let mut cmd = Command::new(&fish);
            cmd.args(["-c", "command -v vox; complete -C 'vox '"])
                .env_clear()
                .env("HOME", home)
                .env("PATH", "/usr/bin:/bin");
            let text = match bounded(cmd) {
                Ok(out) => String::from_utf8_lossy(&out.stdout).into_owned(),
                Err(hung) => format!("HUNG: {hung}"),
            };
            claims.push(claim(
                "fish.path_and_completion",
                text.contains(&*installed.to_string_lossy()) && text.contains("serve"),
                format!("fish reported {text:?}"),
            ));
        }
    }

    // ---- disposition: a blocked claim is missing evidence, not a pass ----
    println!("\n--- shell-setup proof ---");
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
            let shell = c.id.split('.').next().unwrap_or_default();
            !allowed.contains(&shell.to_owned())
        })
        .collect();

    assert!(
        failed.is_empty(),
        "PRODUCT: {} claim(s) failed — the shell's own answer about what vox shell-setup \
         wrote:\n{}",
        failed.len(),
        failed
            .iter()
            .map(|c| format!("  {} — {}", c.id, c.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        unproven.is_empty(),
        "APPARATUS, CANNOT MEASURE: {} claim(s) unproven — install the shell, or name it in \
         VOX_PROOF_ALLOW_UNPROVEN to accept the gap deliberately:\n{}",
        unproven.len(),
        unproven
            .iter()
            .map(|c| format!("  {} — {}", c.id, c.detail))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
