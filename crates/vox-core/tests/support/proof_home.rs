//! **No proof's child ever sees the operator's real HOME** (V210-157).
//!
//! A proof starts `vox` daemons, hooks, plugins and pty drivers. Before this, every one of them
//! inherited the HOME of whoever ran the gate, and some proofs copied it into a cleared
//! environment on purpose. A child that writes a hook, a settings file or a config, or one a
//! defect makes write where it shouldn't, would then touch the operator's real `~/.claude`,
//! `~/.codex` or `~/.config`.
//!
//! So the first thing [`isolate`] does, once per test process, is move the process itself onto a
//! fresh temporary HOME: `HOME`, and the XDG config, data, state and cache directories under it.
//! Every child inherits those, whether it is spawned with the inherited environment or with a
//! cleared one that copies `HOME` back in. `CODEX_HOME` and `CLAUDE_CONFIG_DIR` are removed, so
//! those tools fall back to their defaults under the temporary HOME too. The watchdog every proof
//! arms calls it first, so it applies to every proof without each one asking.
//!
//! Two things keep their real locations, and both are tools rather than anything under test:
//! `CARGO_HOME` and `RUSTUP_HOME` are pinned to the real ones when unset, so a toolchain shim on
//! PATH still finds its toolchains. And [`real_home`] answers the two lookups whose whole point is
//! the operator's real HOME, both in live-model proofs only and never in a blocking one: reading
//! the OpenCode credential copied into the sandbox, and the canary that proves the sandbox keeps a
//! model out of it.
//!
//! **It checks itself once.** A child shell reports its HOME and writes a sentinel there; the HOME
//! must be the temporary one, and the sentinel must land there and not in the real HOME. A
//! failure is `APPARATUS`: the harness did not isolate the run, so nothing the run measured can
//! be trusted, and nothing about the product is known.

#![allow(dead_code)] // each includer uses only some of it

use std::path::{Path, PathBuf};
use std::sync::{Once, OnceLock};

/// The operator's HOME, as it was before [`isolate`] replaced it.
static REAL_HOME: OnceLock<Option<PathBuf>> = OnceLock::new();

/// The operator's `XDG_DATA_HOME`, as it was before [`isolate`] replaced it.
static REAL_DATA_HOME: OnceLock<Option<PathBuf>> = OnceLock::new();

/// The temporary HOME every child of this process gets.
static PROOF_HOME: OnceLock<PathBuf> = OnceLock::new();

static ISOLATED: Once = Once::new();

/// The sentinel a child writes to show which HOME it was given.
const SENTINEL: &str = ".vox-proof-sentinel";

/// Move this test process, and so every child it starts, onto a fresh temporary HOME. Idempotent:
/// the first call does it, and every later call returns at once.
pub fn isolate() {
    // `call_once_force`: after an APPARATUS red here, the next test in the process runs the
    // isolation again and gives the same labelled red, not an unlabelled "Once poisoned".
    ISOLATED.call_once_force(|_| {
        let real = std::env::var_os("HOME").map(PathBuf::from);
        let _ = REAL_HOME.set(real.clone());
        let _ = REAL_DATA_HOME.set(std::env::var_os("XDG_DATA_HOME").map(PathBuf::from));
        // Toolchain shims on PATH find their toolchains through HOME unless told; tell them where
        // they really are, so moving HOME breaks no tool. Only when unset: an explicit value stays.
        if let Some(real) = &real {
            for (var, dir) in [("CARGO_HOME", ".cargo"), ("RUSTUP_HOME", ".rustup")] {
                if std::env::var_os(var).is_none() && real.join(dir).is_dir() {
                    std::env::set_var(var, real.join(dir));
                }
            }
        }
        // Under cargo's own per-target scratch directory, one per process, emptied first in case a
        // process with the same id left one behind.
        let home = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("proof-home-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        for sub in [".config", ".local/share", ".local/state", ".cache"] {
            std::fs::create_dir_all(home.join(sub)).unwrap_or_else(|e| {
                panic!(
                    "APPARATUS: could not make the proof's temporary HOME at {}: {e}",
                    home.display()
                )
            });
        }
        std::env::set_var("HOME", &home);
        std::env::set_var("XDG_CONFIG_HOME", home.join(".config"));
        std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));
        std::env::set_var("XDG_STATE_HOME", home.join(".local/state"));
        std::env::set_var("XDG_CACHE_HOME", home.join(".cache"));
        std::env::remove_var("CODEX_HOME");
        std::env::remove_var("CLAUDE_CONFIG_DIR");
        let _ = PROOF_HOME.set(home.clone());
        check(&home, real.as_deref());
    });
}

/// The temporary HOME this process's children get, once [`isolate`] has run.
pub fn proof_home() -> Option<&'static Path> {
    PROOF_HOME.get().map(PathBuf::as_path)
}

/// The operator's real HOME, for the two lookups that exist to reach it, both in
/// `support/oc_sandbox.rs` and both reached only from live-model proofs (feature
/// `live-model-sandbox`): **reading** OpenCode's credential to copy into the sandbox, and planting
/// and probing the canary the sandbox must keep a model away from. **Never from a blocking proof**,
/// and never handed to a child of the proof.
pub fn real_home() -> Option<PathBuf> {
    match REAL_HOME.get() {
        Some(real) => real.clone(),
        // Not isolated yet: the process's HOME is still the real one.
        None => std::env::var_os("HOME").map(PathBuf::from),
    }
}

/// The operator's real data directory (`XDG_DATA_HOME`, else `~/.local/share` under
/// [`real_home`]), only to **read** OpenCode's credential for a live-model proof's sandbox.
pub fn real_data_home() -> Option<PathBuf> {
    let set = match REAL_DATA_HOME.get() {
        Some(d) => d.clone(),
        None => std::env::var_os("XDG_DATA_HOME").map(PathBuf::from),
    };
    set.or_else(|| real_home().map(|h| h.join(".local/share")))
}

/// A child reports its HOME and writes the sentinel there: it must be `home`, and the sentinel
/// must land there and not in `real`.
///
/// The sentinel's name carries this process's id, so a check only ever judges, and only ever
/// removes, a file this process's own child wrote. One that a broken isolation put in the real
/// HOME is removed before the red, so a red run leaves nothing behind there.
fn check(home: &Path, real: Option<&Path>) {
    let sentinel = format!("{SENTINEL}-{}", std::process::id());
    let out = std::process::Command::new("/bin/sh")
        .args([
            "-c",
            &format!("printf %s \"$HOME\"; : > \"$HOME/{sentinel}\""),
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap_or_else(|e| {
            panic!("APPARATUS: could not start /bin/sh to check the proof's HOME: {e}")
        });
    let reported = String::from_utf8_lossy(&out.stdout).into_owned();
    let in_real = real
        .filter(|r| *r != home)
        .map(|r| r.join(&sentinel))
        .filter(|p| p.exists());
    if let Some(p) = &in_real {
        let _ = std::fs::remove_file(p);
    }
    assert!(
        out.status.success() && Path::new(&reported) == home,
        "APPARATUS: a child of this proof was not given the temporary HOME: it reported \
         {reported:?} (exit {:?}), not {}; nothing this run measures can be trusted",
        out.status.code(),
        home.display()
    );
    assert!(
        in_real.is_none(),
        "APPARATUS: a child's sentinel landed in the operator's real HOME ({}); the proof's \
         children are not isolated from it (the file is removed)",
        in_real
            .as_deref()
            .map(Path::display)
            .map(|d| d.to_string())
            .unwrap_or_default()
    );
    assert!(
        home.join(&sentinel).is_file(),
        "APPARATUS: a child's sentinel did not land in the temporary HOME {}",
        home.display()
    );
}
