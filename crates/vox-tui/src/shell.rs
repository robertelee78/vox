//! `vox shell-setup` — PATH and tab completion that work in the next shell.
//!
//! `install.sh` and `vox update` call [`provision`] after placing the binary. It does two
//! things per shell:
//!
//! 1. writes the clap completion script into that shell's **per-user autoload location**,
//!    and
//! 2. maintains **one** idempotent, marker-delimited block at the **end** of the shell's
//!    startup file that puts the install directory first on `PATH` and wires the
//!    completion directory in.
//!
//! Appending at the end is deliberate: a version manager (`fnm`, `nvm`, `pyenv`) prepends
//! its shim directory earlier in the same file, so a block added earlier would lose the
//! `PATH` race with it.
//!
//! ## The zsh case that is easy to get wrong
//! `compinit` builds its command table once. If the rc has already run it — oh-my-zsh
//! does, and so does any other tool's block earlier in the file — then adding a directory
//! to `fpath` afterwards is invisible to it, and completion silently does not work. So the
//! block checks: if `compdef` exists (meaning `compinit` has run) it registers the function
//! directly with `compdef`; otherwise it runs `compinit`, which picks the file up from
//! `fpath` via its `#compdef vox` header. `autoload` alone is not enough — `compdef` is
//! what maps the command to the function.
//!
//! ## Rules that keep this from being a nuisance
//! The block is rewritten in place, never duplicated, and removed exactly by
//! `vox shell-setup --remove`. Only the **login** shell's rc is created if missing; another
//! shell is touched only when its config already exists, so a machine that never uses fish
//! never grows a fish config. Every step is best-effort and reported rather than fatal: a
//! failure here must not fail an install of a binary that is already in place.
//! `VOX_NO_SHELL_SETUP=1` skips all of it.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::CommandFactory;

const BEGIN: &str = "# >>> vox >>>";
const END: &str = "# <<< vox <<<";
const OPT_OUT_VAR: &str = "VOX_NO_SHELL_SETUP";

/// The shells this provisions for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    /// bash
    Bash,
    /// zsh
    Zsh,
    /// fish
    Fish,
}

impl Shell {
    fn name(self) -> &'static str {
        match self {
            Shell::Bash => "bash",
            Shell::Zsh => "zsh",
            Shell::Fish => "fish",
        }
    }

    fn clap(self) -> clap_complete::Shell {
        match self {
            Shell::Bash => clap_complete::Shell::Bash,
            Shell::Zsh => clap_complete::Shell::Zsh,
            Shell::Fish => clap_complete::Shell::Fish,
        }
    }

    /// The user's login shell, when it is one of these.
    fn from_login_shell() -> Option<Self> {
        let s = std::env::var("SHELL").ok()?;
        match Path::new(&s).file_name()?.to_str()? {
            "bash" => Some(Shell::Bash),
            "zsh" => Some(Shell::Zsh),
            "fish" => Some(Shell::Fish),
            _ => None,
        }
    }
}

/// What [`provision`] did, for the caller to print. Errors are collected rather than
/// returned: the binary is installed either way, and a shell that could not be wired is a
/// thing to tell the user about, not a reason to fail.
#[derive(Debug, Default)]
pub struct Report {
    /// One line per thing done.
    pub lines: Vec<String>,
    /// One line per thing that did not work.
    pub errors: Vec<String>,
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from)
}

fn xdg(var: &str, home: &Path, fallback: &[&str]) -> PathBuf {
    std::env::var_os(var).map_or_else(
        || fallback.iter().fold(home.to_path_buf(), |p, s| p.join(s)),
        PathBuf::from,
    )
}

/// Where each shell autoloads a per-user completion for `vox`.
fn completion_path(home: &Path, shell: Shell) -> PathBuf {
    let data = xdg("XDG_DATA_HOME", home, &[".local", "share"]);
    let config = xdg("XDG_CONFIG_HOME", home, &[".config"]);
    match shell {
        Shell::Bash => data.join("bash-completion").join("completions").join("vox"),
        Shell::Zsh => data.join("zsh").join("site-functions").join("_vox"),
        Shell::Fish => config.join("fish").join("completions").join("vox.fish"),
    }
}

/// The startup file(s) that get the managed block.
fn rc_files(home: &Path, shell: Shell) -> Vec<PathBuf> {
    match shell {
        Shell::Zsh => vec![home.join(".zshrc")],
        // macOS login bash reads `.bash_profile` and commonly does not source `.bashrc`;
        // Linux interactive bash reads `.bashrc`. Maintain the block in both when they
        // exist, and create only `.bashrc` when neither does.
        Shell::Bash => vec![home.join(".bashrc"), home.join(".bash_profile")],
        Shell::Fish => vec![xdg("XDG_CONFIG_HOME", home, &[".config"])
            .join("fish")
            .join("conf.d")
            .join("vox.fish")],
    }
}

/// The completion script for `shell`, generated from the same clap model as
/// `vox completions`, so the two can never disagree.
fn completion_script(shell: Shell) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cmd = crate::cli::Cli::command();
    clap_complete::generate(shell.clap(), &mut cmd, "vox", &mut out);
    out
}

fn block_body(shell: Shell, install_dir: &Path, completion_dir: &Path) -> String {
    let dir = install_dir.display();
    let managed =
        "# managed by `vox shell-setup`; edits here are overwritten, remove with `vox shell-setup --remove`";
    match shell {
        Shell::Zsh => format!(
            "{BEGIN}\n{managed}\n\
             export PATH=\"{dir}:$PATH\"\n\
             (( ${{fpath[(Ie){cd}]}} )) || fpath=(\"{cd}\" $fpath)\n\
             if (( $+functions[compdef] )); then autoload -Uz _vox && compdef _vox vox; \
             else autoload -Uz compinit && compinit -i; fi\n\
             {END}\n",
            cd = completion_dir.display(),
        ),
        Shell::Bash => format!(
            "{BEGIN}\n{managed}\n\
             export PATH=\"{dir}:$PATH\"\n\
             [ -f \"{comp}\" ] && . \"{comp}\"\n\
             {END}\n",
            comp = completion_dir.join("vox").display(),
        ),
        // fish reads every file in conf.d at startup, so the block *is* the file; it still
        // carries the markers so `--remove` finds it and a rewrite replaces it.
        Shell::Fish => format!(
            "{BEGIN}\n{managed}\n\
             fish_add_path -g \"{dir}\"\n\
             {END}\n",
        ),
    }
}

/// Write `bytes` to `path` atomically, with `mode`.
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("vox-partial");
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

/// Insert or replace the managed block in `rc`. Returns whether the file changed.
///
/// `create` is false for every rc but the login shell's: wiring a shell the user does not
/// use is litter, and creating its config file is worse than litter.
fn upsert_block(rc: &Path, block: &str, create: bool) -> std::io::Result<bool> {
    let existing = match fs::read_to_string(rc) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !create {
                return Ok(false);
            }
            String::new()
        }
        Err(e) => return Err(e),
    };
    let updated = match (existing.find(BEGIN), existing.find(END)) {
        // Rewrite in place — never append a second block.
        (Some(b), Some(e)) if e > b => {
            let end = e + END.len();
            let tail = if existing[end..].starts_with('\n') {
                end + 1
            } else {
                end
            };
            format!("{}{}{}", &existing[..b], block, &existing[tail..])
        }
        _ => {
            let sep = if existing.is_empty() || existing.ends_with('\n') {
                ""
            } else {
                "\n"
            };
            format!("{existing}{sep}\n{block}")
        }
    };
    if updated == existing {
        return Ok(false);
    }
    if let Some(parent) = rc.parent() {
        fs::create_dir_all(parent)?;
    }
    write_atomic(rc, updated.as_bytes(), 0o644)?;
    Ok(true)
}

/// Remove the managed block from `rc`. Returns whether the file changed.
fn remove_block(rc: &Path) -> std::io::Result<bool> {
    let Ok(existing) = fs::read_to_string(rc) else {
        return Ok(false);
    };
    let (Some(b), Some(e)) = (existing.find(BEGIN), existing.find(END)) else {
        return Ok(false);
    };
    if e < b {
        return Ok(false);
    }
    let end = e + END.len();
    let tail = if existing[end..].starts_with('\n') {
        end + 1
    } else {
        end
    };
    // Also drop the blank line the insert put before the block, so removing and
    // re-adding does not accumulate whitespace.
    let head = existing[..b].trim_end_matches('\n');
    let sep = if head.is_empty() { "" } else { "\n" };
    let updated = format!("{head}{sep}{}", &existing[tail..]);
    if updated == existing {
        return Ok(false);
    }
    write_atomic(rc, updated.as_bytes(), 0o644)?;
    Ok(true)
}

/// Write completions and maintain the rc block for every shell the user actually uses.
pub fn provision(install_dir: &Path) -> Report {
    let mut r = Report::default();
    if std::env::var_os(OPT_OUT_VAR).is_some_and(|v| !v.is_empty()) {
        r.lines
            .push(format!("{OPT_OUT_VAR} set — shell integration skipped"));
        return r;
    }
    let home = home_dir();
    let login = Shell::from_login_shell();
    for shell in [Shell::Zsh, Shell::Bash, Shell::Fish] {
        let is_login = login == Some(shell);
        let rcs = rc_files(&home, shell);
        let configured = match shell {
            Shell::Fish => home.join(".config").join("fish").exists(),
            _ => rcs.iter().any(|p| p.exists()),
        };
        if !is_login && !configured {
            continue; // never litter a shell the user does not use
        }

        let cpath = completion_path(&home, shell);
        let written = cpath
            .parent()
            .ok_or_else(|| std::io::Error::other("completion path has no parent"))
            .and_then(fs::create_dir_all)
            .and_then(|()| write_atomic(&cpath, &completion_script(shell), 0o644));
        match written {
            Ok(()) => r.lines.push(format!(
                "{}: completions -> {}",
                shell.name(),
                cpath.display()
            )),
            Err(e) => r
                .errors
                .push(format!("{}: completions not written ({e})", shell.name())),
        }

        let cdir = cpath.parent().map_or_else(PathBuf::new, Path::to_path_buf);
        let block = block_body(shell, install_dir, &cdir);
        let mut touched = false;
        for (i, rc) in rcs.iter().enumerate() {
            // Create only the login shell's primary rc; everything else is edited only
            // when it already exists.
            let create = is_login && i == 0;
            match upsert_block(rc, &block, create) {
                Ok(true) => {
                    r.lines.push(format!("{}: {}", shell.name(), rc.display()));
                    touched = true;
                }
                Ok(false) => {}
                Err(e) => r.errors.push(format!(
                    "{}: {} not updated ({e})",
                    shell.name(),
                    rc.display()
                )),
            }
        }
        if !touched {
            r.lines
                .push(format!("{}: already up to date", shell.name()));
        }
    }
    r
}

/// Remove everything [`provision`] wrote.
pub fn deprovision() -> Report {
    let mut r = Report::default();
    let home = home_dir();
    for shell in [Shell::Zsh, Shell::Bash, Shell::Fish] {
        for rc in rc_files(&home, shell) {
            match remove_block(&rc) {
                Ok(true) => r.lines.push(format!("{}: {}", shell.name(), rc.display())),
                Ok(false) => {}
                Err(e) => r.errors.push(format!(
                    "{}: {} not updated ({e})",
                    shell.name(),
                    rc.display()
                )),
            }
        }
        let cpath = completion_path(&home, shell);
        if cpath.exists() {
            match fs::remove_file(&cpath) {
                Ok(()) => r
                    .lines
                    .push(format!("{}: removed {}", shell.name(), cpath.display())),
                Err(e) => r.errors.push(format!(
                    "{}: {} not removed ({e})",
                    shell.name(),
                    cpath.display()
                )),
            }
        }
    }
    r
}

/// The directory the running binary is in — what the rc block puts on `PATH`.
///
/// Recorded from the *running* binary rather than guessed, so a binary installed somewhere
/// unusual still gets a correct block. Falls back to `~/.local/bin`, the installer's
/// default, when the executable path cannot be read.
pub fn install_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| home_dir().join(".local").join("bin"))
}

/// `vox shell-setup [--remove]`.
pub fn run(remove: bool) -> std::process::ExitCode {
    let report = if remove {
        deprovision()
    } else {
        provision(&install_dir())
    };
    for line in &report.lines {
        println!("vox shell-setup: {line}");
    }
    for err in &report.errors {
        eprintln!("vox shell-setup: {err}");
    }
    if report.errors.is_empty() {
        if !remove {
            println!("vox shell-setup: open a new shell, or `exec $SHELL`, to pick it up");
        }
        std::process::ExitCode::SUCCESS
    } else {
        // A partial failure is reported but not fatal: the binary is installed.
        std::process::ExitCode::from(1)
    }
}

// There are no unit tests here, deliberately.
//
// The feature is "after install, a new shell has `vox` on PATH and tab completion works".
// A test that asserted this module's string splicing would pass while completion stayed
// broken — which is exactly how the zsh `compinit` case goes wrong, and no amount of
// helper-level assertion would have found it. It is proved instead by
// `tests/shell_setup_proof.rs`, which runs a real zsh and a real bash and asks *them*.
