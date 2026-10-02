//! **The one way a proof starts a live model: confined** (V210-106, the decider 2026-10-02).
//!
//! A model's turn may run a shell. Unconfined, a free model's shell read the operator's files
//! (`~/.claude`, `~/.codex`, `~/.config`, other agents' scratch directories) and sent what it
//! found to its provider. So every OpenCode a proof starts goes through [`OcSandbox`]:
//!
//! - macOS `sandbox-exec` with a whitelist of readable paths (the system, the OpenCode binary's
//!   directory, the run's sandbox root, and what each proof names), writes only to the root and
//!   what the proof names;
//! - a throwaway HOME, and a fixed environment: the system's PATH (plus a proof's own shim
//!   directory), no USER, OpenCode started by its absolute path;
//! - a canary planted in the operator's real HOME: every profile is probed against it before it
//!   is returned, and every turn's output is checked for it; either is APPARATUS;
//! - a copy of OpenCode's own provider credential alone, never the operator's others;
//! - what a run leaves outside itself (the canary, the copy) removed on every exit.
//!
//! And a live model runs **only** in a build with `live-model-sandbox` ([`live_model_allowed`]):
//! live-model proofs are ad hoc, on the decider's request, never in CI, and the general
//! `optional-proofs` switch must not start one.
#![allow(dead_code)] // not every proof that includes this uses every part

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The model every live-model proof runs (the decider, 2026-10-02: opencode/kimi-k3, never a free
/// model). `VOX_PROOF_OPENCODE_MODEL` overrides it.
pub fn model() -> String {
    std::env::var("VOX_PROOF_OPENCODE_MODEL").unwrap_or_else(|_| "opencode/kimi-k3".to_owned())
}

/// Whether this build may start a live model: only with `live-model-sandbox`. Otherwise it says,
/// past the harness's capture, that `what` was not run, and the caller returns: it blocks nothing.
pub fn live_model_allowed(what: &str) -> bool {
    if cfg!(feature = "live-model-sandbox") {
        return true;
    }
    let _ = writeln!(
        std::io::stderr(),
        "OPTIONAL PROOF NOT RUN: {what} starts a live model, which only a build with \
         --features live-model-sandbox does, on the decider's request; it blocks nothing"
    );
    false
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

/// Where OpenCode keeps credentials. Copied into the test's own data dir so the run
/// is isolated from the operator's configuration **and** leaves nothing behind in
/// it — a proof that pollutes the machine it runs on is a bad neighbour.
pub fn auth_json() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".local/share")))?;
    let p = base.join("opencode/auth.json");
    p.is_file().then_some(p)
}

/// **The profile**: every OpenCode a proof starts is confined (macOS `sandbox-exec`): a model's turn may
/// run a shell, and an unconfined one read the operator's files and sent what it found to the
/// model's provider. Reads are a whitelist: the system, the OpenCode binary, the `vox` binary,
/// and `rw` (the run's sandbox root, plus the run's vox profile for the plugin's hook). Writes
/// go only to `rw`. Nothing under `/Users`, `/opt`, `/private/tmp` or another run's temp
/// directory is readable, by any path to it.
pub fn sandbox_profile(rw: &[&Path], r: &[&Path]) -> String {
    let q = |p: &Path| format!("{:?}", real(p).display().to_string());
    let mut s = String::from(
        "(version 1)\n(allow default)\n\
         (deny file-read-data file-write* (subpath \"/\"))\n\
         (allow file-read-metadata)\n\
         (allow file-read-data (literal \"/\") (subpath \"/System\") (subpath \"/usr\") \
         (subpath \"/bin\") (subpath \"/sbin\") (subpath \"/Library/Apple\") \
         (subpath \"/Library/Preferences\") (subpath \"/private/etc\") \
         (subpath \"/private/var/db/timezone\") (subpath \"/private/var/db/dyld\"))\n\
         (deny file-read-data (subpath \"/System/Volumes/Data\"))\n\
         (allow file-read-data file-write* (subpath \"/dev\"))\n",
    );
    for p in r {
        s += &format!("(allow file-read-data (subpath {}))\n", q(p));
    }
    for p in rw {
        s += &format!("(allow file-read-data file-write* (subpath {}))\n", q(p));
    }
    s
}

/// `p` with every symlink resolved: the sandbox matches real paths (`/tmp` is
/// `/private/tmp`).
pub fn real(p: &Path) -> std::path::PathBuf {
    std::fs::canonicalize(p)
        .unwrap_or_else(|e| panic!("APPARATUS: cannot resolve {p:?} for the sandbox: {e}"))
}

/// The OpenCode binary, resolved, and the directory that holds it (all the sandbox lets the
/// model's shell read of the operator's OpenCode install).
pub fn opencode_bin() -> std::path::PathBuf {
    real(&which("opencode").unwrap_or_else(|| panic!("APPARATUS: opencode is not on PATH")))
}

/// **What a run leaves outside itself is removed however it ends**: the canary in the real HOME
/// and the sandbox's credential copy. A panic unwinds into their `Drop`s; an abort (the
/// watchdog's), SIGTERM, SIGINT or SIGHUP runs no destructor, so a handler unlinks them, using
/// only async-signal-safe calls, and re-raises the signal; a SIGKILL is swept at the next run's
/// start (`sweep`).
mod leftovers {
    use std::ffi::{c_char, c_int, CString};
    use std::sync::atomic::{AtomicPtr, Ordering};

    extern "C" {
        fn signal(sig: c_int, handler: usize) -> usize;
        fn raise(sig: c_int) -> c_int;
        fn unlink(path: *const c_char) -> c_int;
        fn kill(pid: c_int, sig: c_int) -> c_int;
    }

    const SIGHUP: c_int = 1;
    const SIGINT: c_int = 2;
    const SIGABRT: c_int = 6;
    const SIGTERM: c_int = 15;
    const SIG_DFL: usize = 0;

    static SLOTS: [AtomicPtr<c_char>; 2] = [
        AtomicPtr::new(std::ptr::null_mut()),
        AtomicPtr::new(std::ptr::null_mut()),
    ];

    extern "C" fn on_fatal(sig: c_int) {
        for slot in &SLOTS {
            let p = slot.swap(std::ptr::null_mut(), Ordering::SeqCst);
            if !p.is_null() {
                // SAFETY: `p` came from `CString::into_raw` and is never freed while in a slot.
                unsafe {
                    unlink(p);
                }
            }
        }
        // SAFETY: restoring the default action and re-raising ends the process as the signal
        // would have, crash report included for an abort.
        unsafe {
            signal(sig, SIG_DFL);
            raise(sig);
        }
    }

    /// Remove `path` on a fatal signal, until [`forget`] (slot 0: the canary, 1: the copy).
    pub fn guard(slot: usize, path: &std::path::Path) {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            for sig in [SIGABRT, SIGTERM, SIGINT, SIGHUP] {
                // SAFETY: `on_fatal` is an `extern "C" fn(c_int)` that never unwinds.
                unsafe {
                    signal(sig, on_fatal as extern "C" fn(c_int) as usize);
                }
            }
        });
        let c = CString::new(path.as_os_str().as_encoded_bytes())
            .unwrap_or_else(|_| panic!("APPARATUS: a path to guard holds a NUL byte"));
        let old = SLOTS[slot].swap(c.into_raw(), Ordering::SeqCst);
        if !old.is_null() {
            // SAFETY: from `into_raw` above, and no longer in a slot.
            drop(unsafe { CString::from_raw(old) });
        }
    }

    /// The file `guard`ed in `slot` is gone by other means; stop guarding it.
    pub fn forget(slot: usize) {
        let old = SLOTS[slot].swap(std::ptr::null_mut(), Ordering::SeqCst);
        if !old.is_null() {
            // SAFETY: from `into_raw` in `guard`, and no longer in a slot.
            drop(unsafe { CString::from_raw(old) });
        }
    }

    /// Whether process `pid` is alive (signal 0 probes without signalling).
    pub fn alive(pid: u32) -> bool {
        // SAFETY: signal 0 delivers nothing.
        c_int::try_from(pid).is_ok_and(|p| unsafe { kill(p, 0) } == 0)
    }

    /// Remove what an earlier run of this proof that was killed (SIGKILL, which no handler
    /// sees) left behind: its canary in the real HOME and its temp directory with the credential
    /// copy, each marked with the pid of a process that no longer runs.
    pub fn sweep(home: &std::path::Path) {
        let dead = |name: &str, prefix: &str| {
            name.strip_prefix(prefix)
                .and_then(|r| r.split('-').next())
                .and_then(|p| p.parse::<u32>().ok())
                .is_some_and(|p| !alive(p))
        };
        for e in std::fs::read_dir(home).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if dead(&name, ".vox-proof-canary-") {
                let _ = std::fs::remove_file(e.path());
            }
        }
        for e in std::fs::read_dir(std::env::temp_dir())
            .into_iter()
            .flatten()
            .flatten()
        {
            let owner = e.path().join("sb/owner");
            let Ok(pid) = std::fs::read_to_string(&owner) else {
                continue;
            };
            if dead(&format!("x{}", pid.trim()), "x") {
                // That run's whole temp directory: its credential copy, its vox profile.
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
}

/// A file in the operator's real HOME that no model may ever see: the proof that the sandbox
/// holds. Removed however the test ends (see `leftovers`).
pub struct Canary {
    pub path: std::path::PathBuf,
    pub text: String,
}

impl Canary {
    pub fn plant() -> Self {
        let home = std::env::var_os("HOME")
            .unwrap_or_else(|| panic!("APPARATUS: HOME is unset, so no canary can be planted"));
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|e| panic!("APPARATUS: the clock is before 1970: {e}"))
            .as_nanos();
        leftovers::sweep(Path::new(&home));
        let path =
            Path::new(&home).join(format!(".vox-proof-canary-{}-{nonce}", std::process::id()));
        let text = format!("VOXCANARY-{nonce:x}");
        leftovers::guard(0, &path);
        std::fs::write(&path, &text)
            .unwrap_or_else(|e| panic!("APPARATUS: cannot plant the canary in the real HOME: {e}"));
        Self { path, text }
    }

    /// Its file name only: no red, and nothing sent to a model, names a real path.
    pub fn name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// Stop if `said`, anything a sandboxed process printed, holds the canary.
    pub fn check(&self, said: &str, what: &str) {
        assert!(
            !said.contains(&self.text),
            "APPARATUS: the sandbox leaked: canary {} was readable by {what}. Stop every \
             live-model run until it is fixed.",
            self.name()
        );
    }
}

/// The sandbox's copy of **only** OpenCode's own provider credential, not the operator's
/// other providers': the least a turn needs, and the most a confined shell could leak, to that
/// same provider. Removed however the test ends.
pub struct Credential(pub std::path::PathBuf);

impl Credential {
    pub fn copy(from: &Path, home: &Path) -> Self {
        let all: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(from)
                .unwrap_or_else(|e| panic!("APPARATUS: cannot read OpenCode's credentials: {e}")),
        )
        .unwrap_or_else(|e| panic!("APPARATUS: OpenCode's credentials are not JSON: {e}"));
        let own = all.get("opencode").unwrap_or_else(|| {
            panic!("CANNOT MEASURE: OpenCode holds no credential of its own provider (`opencode`)")
        });
        let dir = home.join(".local/share/opencode");
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|e| panic!("APPARATUS: cannot make the sandbox's {dir:?}: {e}"));
        let path = dir.join("auth.json");
        leftovers::guard(1, &path);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap_or_else(|e| panic!("APPARATUS: cannot write the sandbox's credential: {e}"));
        f.write_all(
            serde_json::json!({ "opencode": own })
                .to_string()
                .as_bytes(),
        )
        .unwrap_or_else(|e| panic!("APPARATUS: cannot write the sandbox's credential: {e}"));
        Self(path)
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        leftovers::forget(1);
    }
}

impl Drop for Canary {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        leftovers::forget(0);
    }
}

/// The PATH every sandboxed OpenCode runs with: the system's alone, never the operator's.
pub const SANDBOX_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// The line in an `opencode run`'s output where the model provider refused the turn, if any,
/// without the terminal's colour codes. Only opencode's own error lines count (`Error: …`, or
/// the `"name": "…Error"` of an error it prints as JSON): `vox agent hook`'s stderr shares the
/// stream, and a refusal by `vox` must stay the product's.
pub fn provider_failure(said: &str) -> Option<String> {
    const SIGNS: &[&str] = &[
        "upstream request failed",
        "insufficient account funds",
        "insufficient_quota",
        "apicallerror",
        "rate limit",
        "rate_limit",
        "overloaded",
        "unauthorized",
        "invalid api key",
        "providermodelnotfound",
        "unknownerror",
    ];
    let plain = |l: &str| {
        let mut plain = String::new();
        let mut chars = l.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                // An escape sequence runs to its final letter.
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                plain.push(c);
            }
        }
        plain.trim().to_owned()
    };
    let lines: Vec<String> = said.lines().map(plain).collect();
    let opencodes = |l: &str| l.starts_with("Error:") || l.starts_with("\"name\": \"");
    lines
        .iter()
        .position(|l| {
            let low = l.to_ascii_lowercase();
            opencodes(l) && SIGNS.iter().any(|s| low.contains(s))
        })
        .map(|i| {
            if lines[i].starts_with("Error:") {
                return lines[i].clone();
            }
            // A JSON error names its kind on one line and its message on a later one.
            lines[i..]
                .iter()
                .take(4)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
}

/// One run's OpenCode sandbox: its root (the fixture, HOME and TMPDIR a turn may use), the canary
/// planted for it, and the credential copied into it.
pub struct OcSandbox {
    tmp: PathBuf,
    pub root: PathBuf,
    pub home: PathBuf,
    pub canary: Canary,
    _credential: Credential,
}

impl OcSandbox {
    /// Make `<tmp>/sb` and its throwaway HOME, mark whose it is (for a later run's sweep), plant
    /// the canary, and copy in OpenCode's own provider credential alone.
    pub fn new(tmp: &Path) -> Self {
        let root = tmp.join("sb");
        for d in [
            root.join("home/.local/share"),
            root.join("home/.cache"),
            root.join("tmp"),
        ] {
            std::fs::create_dir_all(&d)
                .unwrap_or_else(|e| panic!("APPARATUS: cannot make the sandbox's {d:?}: {e}"));
        }
        // Whose sandbox this is, for the next run's sweep should this one be SIGKILLed.
        std::fs::write(root.join("owner"), std::process::id().to_string())
            .unwrap_or_else(|e| panic!("APPARATUS: cannot mark the sandbox's owner: {e}"));
        let canary = Canary::plant();
        let root = real(&root);
        let home = root.join("home");
        let auth = auth_json().unwrap_or_else(|| {
            panic!(
                "CANNOT MEASURE: no opencode auth.json, so no model can run; authenticate opencode"
            )
        });
        let _credential = Credential::copy(&auth, &home);
        Self {
            tmp: tmp.to_path_buf(),
            root,
            home,
            canary,
            _credential,
        }
    }

    /// A profile that may also read `r` and read and write `rw`, written beside the root, and
    /// **probed before it is returned**: a shell under it must fail to read the canary (by both
    /// of its paths), to find it, and to list it in the real HOME, or the run stops here.
    pub fn profile(&self, name: &str, rw: &[&Path], r: &[&Path]) -> PathBuf {
        let oc_dir = opencode_bin()
            .parent()
            .unwrap_or_else(|| panic!("APPARATUS: opencode's binary has no directory"))
            .to_path_buf();
        let mut all_rw = vec![self.root.as_path()];
        all_rw.extend_from_slice(rw);
        let mut all_r = vec![oc_dir.as_path()];
        all_r.extend_from_slice(r);
        let path = self.tmp.join(format!("{name}.sb"));
        std::fs::write(&path, sandbox_profile(&all_rw, &all_r))
            .unwrap_or_else(|e| panic!("APPARATUS: cannot write the sandbox profile: {e}"));
        let probe = Command::new("/usr/bin/sandbox-exec")
            .arg("-f")
            .arg(&path)
            .args(["/bin/sh", "-c"])
            .arg(format!(
                "cat {p:?} /System/Volumes/Data{p:?}; find / -name {n:?} 2>/dev/null; ls -a {h:?}",
                p = self.canary.path.display().to_string(),
                n = self.canary.name(),
                h = std::env::var("HOME").unwrap_or_default(),
            ))
            .output()
            .unwrap_or_else(|e| panic!("APPARATUS: cannot run the sandbox probe: {e}"));
        let probed = format!(
            "{}{}",
            String::from_utf8_lossy(&probe.stdout),
            String::from_utf8_lossy(&probe.stderr)
        );
        self.canary.check(&probed, "a sandboxed shell");
        // The probe's output holds the real HOME's path and listing, so the red names the canary
        // alone.
        assert!(
            !String::from_utf8_lossy(&probe.stdout).contains(&self.canary.name()),
            "APPARATUS: the sandbox leaked: canary {} was listed or found by a sandboxed shell",
            self.canary.name()
        );
        println!(
            "[proof] sandbox probe ({name}): the canary in the real HOME is unreadable and unfound"
        );
        path
    }

    /// `opencode`, by its absolute path, confined by `profile`, in `cwd`, with a **fixed
    /// environment**: the system's PATH after `path_first` (a proof's own shim directory), the
    /// sandbox's HOME, `XDG_*` and TMPDIR, no USER. The caller adds its own arguments and
    /// variables (each of which must name no path outside the sandbox but the run's own).
    pub fn opencode(&self, profile: &Path, path_first: &[&Path], cwd: &Path) -> Command {
        let mut cmd = Command::new("/usr/bin/sandbox-exec");
        cmd.arg("-f").arg(profile).arg(opencode_bin());
        // A cleared environment: an inherited one (cargo's) silently disables plugin hooks, and
        // the operator's PATH and USER name their home and other agents' scratch directories.
        cmd.env_clear();
        let mut path: Vec<PathBuf> = path_first.iter().map(|p| p.to_path_buf()).collect();
        path.extend(std::env::split_paths(SANDBOX_PATH));
        cmd.env(
            "PATH",
            std::env::join_paths(path)
                .unwrap_or_else(|e| panic!("APPARATUS: a PATH entry holds a separator: {e}")),
        )
        .env("SHELL", "/bin/zsh")
        .env("HOME", &self.home)
        .env("XDG_DATA_HOME", self.home.join(".local/share"))
        .env("XDG_CACHE_HOME", self.home.join(".cache"))
        .env("XDG_STATE_HOME", self.home.join(".local/state"))
        .env("TMPDIR", self.root.join("tmp"));
        if let Some(v) = std::env::var_os("LANG") {
            cmd.env("LANG", v);
        }
        cmd.current_dir(cwd);
        cmd
    }

    /// Stop if `said`, anything a sandboxed process printed, holds the canary.
    pub fn check(&self, said: &str, what: &str) {
        self.canary.check(said, what);
    }
}
