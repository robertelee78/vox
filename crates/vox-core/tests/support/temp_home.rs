//! Every process a proof starts runs with a throwaway HOME (V210-157, #379).
//!
//! ## Why
//! Proofs start `vox agent hook`, `vox agent plugin`, `vox agent trust`, `vox shell-setup` and
//! daemons, and most of them handed each child the HOME the proof itself was started with: the
//! operator's. A proof that writes hook or settings files, or a defect that makes one write them,
//! would have touched the real `~/.claude`, `~/.codex` or `~/.config`.
//!
//! ## How
//! Before `main` runs, while the process has one thread, this module makes a fresh directory
//! under the system temp dir and points this process's `HOME` and `XDG_*_HOME` there, and
//! unsets `CODEX_HOME`, `CLAUDE_CONFIG_DIR` and `OPENCODE_CONFIG_DIR` (which name an agent's
//! config outside HOME), the variables naming the agent session that runs the proof, and every
//! `VOX_*` but the run's own settings (`VOX_NODE` above all). A
//! child inherits its parent's environment, so every child of every proof gets the temporary
//! HOME by default, through every helper, with no call site to remember. The same constructor
//! gives every child `VOX_PROXY=127.0.0.1:0` unless the run set its own, so no proof's daemon takes
//! port 1080 (see `init`). A proof that passes
//! `HOME` explicitly passes either a directory of its own or `std::env::var("HOME")`, which is
//! now this one.
//!
//! The real HOME is kept only for [`real_home`] (and XDG_DATA_HOME for [`real_xdg_data_home`]):
//! the live-model sandbox reads its OpenCode credentials from there and plants its canary there.
//! Two tools a proof starts need the operator's own setup, and get only that, never HOME:
//! [`real_toolchain`] gives `cargo` the operator's rustup and cargo homes (else the rustup proxy
//! finds no toolchain and downloads one), and [`real_gh`] gives `gh` the operator's gh config
//! directory (else it has no login).
//!
//! [`check`] proves it once per proof process: a child reports its HOME and writes
//! `$HOME/.vox-proof-sentinel`, and the sentinel must land in the temporary HOME and never in
//! the real one. A red there is an APPARATUS red: the proof's harness, not the product.
//!
//! The directory is removed when the process exits normally. A watchdog abort leaves it.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The HOME this process was started with, before it was replaced. `None` when it had none.
static REAL_HOME: OnceLock<Option<PathBuf>> = OnceLock::new();

/// The operator's XDG_DATA_HOME, before it was replaced: where OpenCode keeps credentials.
static REAL_XDG_DATA_HOME: OnceLock<Option<PathBuf>> = OnceLock::new();

/// The operator's XDG_CONFIG_HOME, before it was replaced: where gh keeps its login.
static REAL_XDG_CONFIG_HOME: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Which of [`UNSET`] this process was started with, and their values: kept in memory only, so
/// [`check`] can tell an inherited value that survived from one a proof set on purpose.
static INHERITED: OnceLock<Vec<(&'static str, std::ffi::OsString)>> = OnceLock::new();

/// The temporary HOME every child of this process inherits.
static TEMP_HOME: OnceLock<PathBuf> = OnceLock::new();

/// The variables pointed into the temporary HOME, with where under it.
const XDG: [(&str, &str); 4] = [
    ("XDG_CONFIG_HOME", ".config"),
    ("XDG_DATA_HOME", ".local/share"),
    ("XDG_CACHE_HOME", ".cache"),
    ("XDG_STATE_HOME", ".local/state"),
];

/// Variables that name an agent's config outside HOME: unset, so an agent's config resolves
/// under the temporary HOME. And the variables that name the agent session running the proof, or
/// how to wake it: unset, so a proof's result never depends on who runs it. Inherited, a `vox`
/// child posted as the operator's session (its `from`) and answered that session's wakes. A proof
/// that wants a session sets one on the child.
const UNSET: [&str; 11] = [
    "CODEX_HOME",
    "CLAUDE_CONFIG_DIR",
    "OPENCODE_CONFIG_DIR",
    "VOX_SESSION",
    "CLAUDE_CODE_SESSION_ID",
    "CODEX_THREAD_ID",
    "CLAUDE_CODE_MESSAGING_SOCKET",
    "CLAUDE_CODE_MESSAGING_TOKEN",
    "VOX_HARNESS",
    "VOX_OPENCODE_WAKE_SOCKET",
    "VOX_OPENCODE_WAKE_TOKEN",
];

/// The `VOX_*` a run of proofs may set on purpose, kept: each configures the proof process, never
/// the product (`VOX_PROXY` is set below when the run gives none).
const RUN_SETTINGS: [&str; 7] = [
    "VOX_PROXY",
    "VOX_PROOF_",
    "VOX_MUTANT_",
    "VOX_UPGRADE_FROM",
    "VOX_PREVIOUS_RELEASE_DIR",
    "VOX_PERF_",
    "VOX_TEST_WATCHDOG_SECS",
];

/// Where a `vox` daemon listens for its `.vox` proxy, and the value every proof's child gets unless
/// the run set its own: a free port of the loopback address.
const PROXY: &str = "VOX_PROXY";
const FREE_PROXY: &str = "127.0.0.1:0";

/// The sentinel [`check`] has a child write in its HOME.
const SENTINEL: &str = ".vox-proof-sentinel";

// Run `init` before `main`, the way the C runtime runs constructors: there are no other threads
// yet, so changing the environment races nothing.
#[used]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
static INIT: extern "C" fn() = init;

extern "C" {
    fn atexit(callback: extern "C" fn()) -> std::ffi::c_int;
}

extern "C" fn init() {
    let real = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from);
    let real_data = std::env::var_os("XDG_DATA_HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from);
    let real_config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let home =
        std::env::temp_dir().join(format!("vox-proof-home-{}-{nonce:x}", std::process::id()));
    if let Err(e) = make_private(&home).and_then(|()| make_private(&home.join(".config"))) {
        // No panic: this runs before `main`, where an unwind cannot be caught.
        let _ = std::io::Write::write_all(
            &mut std::io::stderr(),
            format!(
                "APPARATUS: cannot make the proof's temporary HOME {}: {e}\n",
                home.display()
            )
            .as_bytes(),
        );
        std::process::abort();
    }
    std::env::set_var("HOME", &home);
    for (var, sub) in XDG {
        std::env::set_var(var, home.join(sub));
    }
    let _ = INHERITED.set(
        UNSET
            .iter()
            .filter_map(|v| std::env::var_os(v).map(|val| (*v, val)))
            .collect(),
    );
    for var in UNSET {
        std::env::remove_var(var);
    }
    // **Nothing of a terminal or a harness session this proof did not make** (2026-10-07: a
    // proof run from inside the operator's Claude Code session inherited its tmux pane, and a
    // steer line was typed into that session). Every variable whose name starts with `TMUX`,
    // `CLAUDE`, `CODEX` or `OPENCODE` is taken out of this process before `main`, walked from the
    // environment rather than listed, so no child it starts inherits one. A proof that wants one
    // sets its own, on the child.
    let harness: Vec<std::ffi::OsString> = std::env::vars_os()
        .map(|(k, _)| k)
        .filter(|k| {
            let k = k.to_string_lossy();
            ["TMUX", "CLAUDE", "CODEX", "OPENCODE"]
                .iter()
                .any(|p| k.starts_with(p))
        })
        .collect();
    for var in harness {
        std::env::remove_var(var);
    }
    // **No `VOX_*` of the shell that runs the proof** (#666): run from an agent's shell, a proof
    // inherited its `VOX_NODE` (room_verbs went red twice acting as `claude-work-laptop`), and any
    // other would steer the `vox` it runs the same way. Every `VOX_*` is taken out, walked from
    // the environment, except what configures the run itself and is read by the proof process
    // ([`RUN_SETTINGS`]); a proof that wants one on a child sets it there.
    let vox: Vec<std::ffi::OsString> = std::env::vars_os()
        .map(|(k, _)| k)
        .filter(|k| {
            let k = k.to_string_lossy();
            k.starts_with("VOX_") && !RUN_SETTINGS.iter().any(|keep| k.starts_with(keep))
        })
        .collect();
    for var in vox {
        std::env::remove_var(var);
    }
    // A daemon a proof starts binds its `.vox` proxy on a free port, never 127.0.0.1:1080 (ADR-028
    // S-5), so it takes that port from no real daemon and no other proof. `.cargo/config.toml` says
    // so for what `cargo test` runs; a proof binary run on its own (`run-slot.sh`, a checker) gets
    // nothing from cargo, and its daemons took 1080. A run that sets VOX_PROXY keeps its own, and
    // a proof that sets it on a child (the proxy-port proofs) passes its own value there.
    if std::env::var_os(PROXY).is_none() {
        std::env::set_var(PROXY, FREE_PROXY);
    }
    let _ = REAL_HOME.set(real);
    let _ = REAL_XDG_DATA_HOME.set(real_data);
    let _ = REAL_XDG_CONFIG_HOME.set(real_config);
    let _ = TEMP_HOME.set(home);
    // SAFETY: `atexit` is the C library's, which every Rust program on these platforms links;
    // `remove` takes no arguments, never unwinds, and touches only the directory made above.
    unsafe {
        atexit(remove);
    }
}

fn make_private(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new().mode(0o700).create(dir)
}

extern "C" fn remove() {
    if let Some(home) = TEMP_HOME.get() {
        let _ = std::fs::remove_dir_all(home);
    }
}

/// The temporary HOME every child of this process inherits.
#[allow(dead_code)]
pub fn temp_home() -> &'static Path {
    TEMP_HOME
        .get()
        .map(PathBuf::as_path)
        .unwrap_or_else(|| panic!("APPARATUS: the proof's temporary HOME was never made"))
}

/// The HOME this process was started with. Only the live-model sandbox may read it, for the
/// operator's OpenCode credentials and its canary; never hand it to a child.
#[allow(dead_code)]
pub fn real_home() -> Option<&'static Path> {
    REAL_HOME.get().and_then(|h| h.as_deref())
}

/// The operator's XDG_DATA_HOME, as [`real_home`]: only for the live-model sandbox's credentials.
#[allow(dead_code)]
pub fn real_xdg_data_home() -> Option<&'static Path> {
    REAL_XDG_DATA_HOME.get().and_then(|h| h.as_deref())
}

/// Give `cmd` (a `cargo`) the operator's rustup and cargo homes, unless this process already
/// names them (as `cargo test` does). Only those two directories, never HOME: without them the
/// rustup proxy under the temporary HOME finds no toolchain and downloads a whole one.
#[allow(dead_code)]
pub fn real_toolchain(cmd: &mut std::process::Command) -> &mut std::process::Command {
    for (var, sub) in [("RUSTUP_HOME", ".rustup"), ("CARGO_HOME", ".cargo")] {
        if std::env::var_os(var).is_none_or(|v| v.is_empty()) {
            if let Some(real) = real_home() {
                cmd.env(var, real.join(sub));
            }
        }
    }
    cmd
}

/// Give `cmd` (a `gh`) the operator's gh config directory, where its login is. Only that
/// directory, never HOME: without it gh under the temporary HOME has no login.
#[allow(dead_code)]
pub fn real_gh(cmd: &mut std::process::Command) -> &mut std::process::Command {
    if std::env::var_os("GH_CONFIG_DIR").is_none_or(|v| v.is_empty()) {
        let dir = REAL_XDG_CONFIG_HOME
            .get()
            .and_then(|c| c.as_deref())
            .map(|c| c.join("gh"))
            .or_else(|| real_home().map(|h| h.join(".config/gh")));
        if let Some(dir) = dir {
            cmd.env("GH_CONFIG_DIR", dir);
        }
    }
    cmd
}

/// A child reports its HOME and XDG_CONFIG_HOME and writes `$HOME/.vox-proof-sentinel`: both must
/// be the temporary HOME, the sentinel must land there, and never in the real HOME. Panics with
/// an APPARATUS red otherwise.
pub fn check() {
    let temp = temp_home();
    let nonce = format!(
        "{}-{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    );
    let out = std::process::Command::new("/bin/sh")
        .args([
            "-c",
            "printf '%s\\n%s\\n' \"$HOME\" \"$XDG_CONFIG_HOME\"; \
             printf '%s' \"$1\" > \"$HOME/.vox-proof-sentinel\"",
            "sh",
            &nonce,
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("APPARATUS: cannot start a child to report its HOME: {e}"));
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut lines = said.lines();
    let (home, cfg) = (lines.next().unwrap_or(""), lines.next().unwrap_or(""));
    // **What a child would inherit is this process's environment**: any of [`UNSET`] still holding
    // the value this process was started with is the operator's, and a child would carry it. One
    // a proof set itself (an empty CODEX_HOME of its own) is not. Names only; never a value.
    let kept: Vec<&str> = INHERITED
        .get()
        .into_iter()
        .flatten()
        .filter(|(name, val)| std::env::var_os(name).as_ref() == Some(val))
        .map(|(name, _)| *name)
        .collect();
    let in_real = real_home()
        .map(|r| r.join(SENTINEL))
        .filter(|p| std::fs::read_to_string(p).is_ok_and(|t| t == nonce));
    if let Some(p) = &in_real {
        let _ = std::fs::remove_file(p);
    }
    assert!(
        in_real.is_none(),
        "APPARATUS: a proof's child wrote its sentinel in the real HOME, not the temporary one {}",
        temp.display()
    );
    assert!(
        out.status.success() && Path::new(home) == temp,
        "APPARATUS: a proof's child has HOME {home:?}, not the temporary HOME {} ({})",
        temp.display(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    assert!(
        Path::new(cfg) == temp.join(".config"),
        "APPARATUS: a proof's child has XDG_CONFIG_HOME {cfg:?}, not one under the temporary \
         HOME {}",
        temp.display()
    );
    assert!(
        kept.is_empty(),
        "APPARATUS: a proof's children would still inherit {kept:?}, which name an agent's \
         config or the \
         session running the proof"
    );
    let landed = std::fs::read_to_string(temp.join(SENTINEL)).unwrap_or_default();
    assert!(
        landed == nonce,
        "APPARATUS: a proof's child did not write its sentinel in the temporary HOME {}",
        temp.display()
    );
    let _ = std::fs::remove_file(temp.join(SENTINEL));
    let _ = std::io::Write::write_all(
        &mut std::io::stderr(),
        format!(
            "[proof] every child runs with the temporary HOME {}; its sentinel landed there, not in \
             the real HOME\n",
            temp.display()
        )
        .as_bytes(),
    );
}
