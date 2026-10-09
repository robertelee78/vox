//! `vox uninstall [--dry-run] [--purge]`: undo what `install.sh`, `vox shell-setup` and
//! `vox setup` did on this machine.
//!
//! In order, so nothing removed is still running:
//!
//! 1. on macOS, Vox's background items (the login item and the LAN helper) when launchd runs them
//!    from this install, unregistered by the installed Vox.app itself, the one process macOS lets
//!    do it (`--unregister-background-items`); any other is left and named, with the one step that
//!    removes it. Nothing here asks for an administrator;
//! 2. the account's vox daemon, asked to stop, and any Vox.app running from the install, quit;
//! 3. the Keychain items the daemon stored for kept nodes (named by its attach file, ADR-014 M-6),
//!    and those lines of the attach file;
//! 4. the harness wiring `vox setup` installed: the `vox agent hook` entries in Claude Code's and
//!    Codex's settings (nothing else in those files), OpenCode's plugin and the agent skill, each
//!    only when it is byte for byte what Vox writes; anything else is named and left;
//! 5. the shell completions and the startup-file block `vox shell-setup` added;
//! 6. on macOS, what the app left in the person's Library (its log, preferences, saved state and
//!    the share extension's container);
//! 7. the install itself: Vox.app or the `vox` binary, its marker, lock, previous and leftovers,
//!    and the `vox` link.
//!
//! The data root and config directory (nodes, keys, rooms) are kept, and said where, with what a
//! node without a backup means. `--purge` removes them too, only at a terminal, once every node's
//! name has been typed. `--dry-run` lists all of it and changes nothing.

use std::fs;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use vox_core::node::paths::{Account, NodeName};

use crate::app::AppError;
use crate::update::Channel;

/// The flag the installed Vox.app takes to unregister its background items and exit.
pub const UNREGISTER_FLAG: &str = "--unregister-background-items";

/// How long a stopped daemon or a quit app is given to end.
const END_WITHIN: Duration = Duration::from_secs(30);

/// One thing the uninstall does, said before it is done.
struct Step {
    /// What it removes or stops, as a person reads it.
    what: String,
    /// Doing it: what was done, or why not.
    run: Box<dyn FnOnce() -> Result<String, String>>,
}

/// What the uninstall finds and does, in order.
#[derive(Default)]
struct Plan {
    steps: Vec<Step>,
    /// What it leaves, and why: said in a dry run and a real one alike.
    kept: Vec<String>,
}

impl Plan {
    fn step(&mut self, what: String, run: impl FnOnce() -> Result<String, String> + 'static) {
        self.steps.push(Step {
            what,
            run: Box::new(run),
        });
    }

    /// Remove `path` (a file, a link, or a directory and all in it), when it is there.
    fn remove(&mut self, path: PathBuf) {
        if fs::symlink_metadata(&path).is_err() {
            return;
        }
        let what = format!("remove {}", path.display());
        self.step(what, move || {
            let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            let done = if meta.is_dir() {
                fs::remove_dir_all(&path)
            } else {
                fs::remove_file(&path)
            };
            done.map(|()| format!("removed {}", path.display()))
                .map_err(|e| format!("{} was not removed: {e}", path.display()))
        });
    }
}

/// `vox uninstall`.
///
/// # Errors
/// A binary this tooling did not install (a build from source, a copy by hand), `--purge` with no
/// terminal or with the node names not typed, or a step that failed (each is said; the rest still
/// run).
pub fn run(dry_run: bool, purge: bool) -> Result<(), AppError> {
    let exe = std::env::current_exe()
        .map_err(|e| AppError::Usage(format!("cannot locate the running binary: {e}")))?;
    let installed = crate::update::detect_channel(&exe)?;
    let account = Account::of(None, None).map_err(|e| AppError::Usage(e.to_string()))?;
    if purge && !dry_run && !std::io::stdin().is_terminal() {
        return Err(AppError::Usage(
            "vox uninstall --purge removes every node, and asks you to type each node's name \
             first; there is no terminal to ask at, so nothing was changed"
                .into(),
        ));
    }

    let mut plan = Plan::default();
    match &installed {
        Channel::Bundle { apps_dir, .. } => background_items(&mut plan, &apps_dir.join("Vox.app")),
        Channel::Standalone { .. } => {}
        Channel::Source { exe } | Channel::Unmanaged { exe } => {
            return Err(AppError::Usage(format!(
                "{} was not installed by vox's installer (no .vox-standalone.json beside it), so \
                 vox uninstall will not remove it or anything it may have set up; remove it the \
                 way it was put there",
                exe.display()
            )))
        }
    }
    stop_daemon(&mut plan, &account);
    if let Channel::Bundle { apps_dir, .. } = &installed {
        quit_app(&mut plan, &apps_dir.join("Vox.app"));
    }
    keychain(&mut plan, &account);
    for u in crate::setup::unwire(&account) {
        match u {
            crate::setup::Unwire::Rewrite { what, path, text } => plan.step(what, move || {
                crate::setup::write_whole(&path, &text)
                    .map(|()| format!("updated {}", path.display()))
                    .map_err(|e| format!("{} was not updated: {e}", path.display()))
            }),
            crate::setup::Unwire::Remove(path) => plan.remove(path),
            crate::setup::Unwire::Keep(why) => plan.kept.push(why),
        }
    }
    shell_setup(&mut plan);
    if cfg!(target_os = "macos") {
        app_leftovers(&mut plan);
    }
    match &installed {
        Channel::Bundle { apps_dir, .. } => bundle_files(&mut plan, apps_dir, &exe),
        Channel::Standalone { install_dir, .. } => standalone_files(&mut plan, install_dir),
        _ => {}
    }

    let nodes = account.nodes_on_disk();
    let roots = data_roots(&account);
    if purge {
        for root in &roots {
            plan.remove(root.clone());
        }
    } else {
        for root in &roots {
            plan.kept.push(format!(
                "{} is kept: it holds your nodes, their keys and their rooms ({}). {} \
                 `vox uninstall --purge` removes it.",
                root.display(),
                if nodes.is_empty() {
                    "none yet".to_owned()
                } else {
                    nodes
                        .iter()
                        .map(NodeName::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                crate::ident::NO_BACKUP
            ));
        }
    }

    if dry_run {
        println!("vox uninstall --dry-run: nothing is changed. It would:");
        for s in &plan.steps {
            println!("  {}", s.what);
        }
        for k in &plan.kept {
            println!("  keep: {k}");
        }
        return Ok(());
    }
    if purge && !confirm_purge(&nodes)? {
        return Err(AppError::Usage(
            "the node names were not typed, so nothing was changed".into(),
        ));
    }
    let mut failed = 0;
    for s in plan.steps {
        match (s.run)() {
            Ok(done) => println!("vox uninstall: {done}"),
            Err(why) => {
                failed += 1;
                eprintln!("vox uninstall: {why}");
            }
        }
    }
    for k in &plan.kept {
        println!("vox uninstall: kept: {k}");
    }
    if failed > 0 {
        return Err(AppError::Usage(format!(
            "{failed} step(s) did not complete, each said above"
        )));
    }
    Ok(())
}

/// The data root and the config directory, once each (on macOS they are one folder).
fn data_roots(account: &Account) -> Vec<PathBuf> {
    let mut roots = vec![account.data_root.clone()];
    if account.config_dir != account.data_root {
        roots.push(account.config_dir.clone());
    }
    roots
        .into_iter()
        .filter(|r| fs::symlink_metadata(r).is_ok())
        .collect()
}

/// `--purge`: every node's name typed at the terminal, one per line.
fn confirm_purge(nodes: &[NodeName]) -> Result<bool, AppError> {
    let mut stdin = std::io::stdin().lock();
    let names: Vec<&str> = if nodes.is_empty() {
        vec!["purge"]
    } else {
        nodes.iter().map(NodeName::as_str).collect()
    };
    println!(
        "vox uninstall --purge removes every node on this computer, with its keys and its rooms. \
         {}",
        crate::ident::NO_BACKUP
    );
    for name in names {
        print!("type {name} to remove it: ");
        std::io::stdout().flush().map_err(AppError::Io)?;
        let mut line = String::new();
        stdin.read_line(&mut line).map_err(AppError::Io)?;
        if line.trim() != name {
            return Ok(false);
        }
    }
    Ok(true)
}

/// macOS: the login item and the LAN helper, when they are this install's, unregistered by the
/// installed Vox.app, the process macOS lets do it.
///
/// **Only this install's, told without administrator rights** (#571's lesson; `sfltool`, which
/// lists background items, asks for an administrator here). macOS keeps a background item by
/// bundle identifier, so every copy of us.vox.app shares it: an item counts as this install's only
/// when launchd runs it from inside this bundle (`launchctl print`, then the process's own path).
/// Loaded but not running, or running from another Vox, it is left as it is and named, with the
/// one step that removes it.
fn background_items(plan: &mut Plan, app: &Path) {
    if !cfg!(target_os = "macos") {
        return;
    }
    let bundle = fs::canonicalize(app).unwrap_or_else(|_| app.to_path_buf());
    let uid = rustix::process::getuid().as_raw();
    let mut ours = Vec::new();
    for (target, name) in [
        (format!("gui/{uid}/us.vox.daemon"), "login item"),
        ("system/us.vox.lanhelper".to_owned(), "LAN helper"),
    ] {
        match whose(&target) {
            Whose::None => {}
            Whose::Runs(exe) if exe.starts_with(&bundle) => ours.push(name),
            Whose::Runs(exe) => plan.kept.push(format!(
                "Vox's {name} is another Vox's (launchd runs it from {}), so it is left as it is",
                exe.display()
            )),
            Whose::NotRunning => plan.kept.push(format!(
                "Vox's {name} is registered, and whose it is cannot be told without an \
                 administrator (it is not running, or runs as another user); it is left as it \
                 is. If it is this Vox's, switch Vox off in System Settings, General, Login Items \
                 & Extensions"
            )),
        }
    }
    if ours.is_empty() {
        return;
    }
    let exe = app.join("Contents/MacOS/Vox");
    let named = ours.join(" and ");
    plan.step(
        format!(
            "unregister Vox's {named} (by {} {UNREGISTER_FLAG})",
            exe.display()
        ),
        move || {
            let out = Command::new(&exe)
                .arg(UNREGISTER_FLAG)
                .output()
                .map_err(|e| format!("{} could not be run: {e}", exe.display()))?;
            let said = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            if out.status.success() {
                Ok(format!("unregistered Vox's {named}: {said}"))
            } else {
                Err(format!(
                    "Vox's {named} could not be unregistered ({}): switch Vox off in System \
                     Settings, General, Login Items & Extensions",
                    String::from_utf8_lossy(&out.stderr).trim()
                ))
            }
        },
    );
}

/// Whose a launchd job is, as `launchctl print` and the process's own executable (lsof) tell it,
/// with no privileges.
enum Whose {
    /// launchd has no such job.
    None,
    /// It runs this executable.
    Runs(PathBuf),
    /// launchd has it, and what it runs cannot be read: not running, or another user's process.
    NotRunning,
}

fn whose(target: &str) -> Whose {
    let Ok(o) = Command::new("/bin/launchctl")
        .args(["print", target])
        .output()
    else {
        return Whose::None;
    };
    if !o.status.success() {
        return Whose::None;
    }
    let text = String::from_utf8_lossy(&o.stdout);
    let Some(pid) = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("pid = ").map(str::to_owned))
    else {
        return Whose::NotRunning;
    };
    // The process's executable, its first text mapping as lsof names it: `ps` gives only its
    // name. A process of another user (the LAN helper runs as root) is not readable without an
    // administrator, and is told as not known.
    let exe = Command::new("/usr/sbin/lsof")
        .args(["-a", "-p", &pid, "-d", "txt", "-Fn"])
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .find_map(|l| l.strip_prefix('n').map(PathBuf::from))
        });
    match exe {
        Some(exe) if exe.is_absolute() => Whose::Runs(fs::canonicalize(&exe).unwrap_or(exe)),
        _ => Whose::NotRunning,
    }
}

/// The account's daemon, asked to stop, when one answers.
fn stop_daemon(plan: &mut Plan, account: &Account) {
    let socket = account.socket();
    let Some(pid) = daemon_pid(&socket) else {
        return;
    };
    plan.step(format!("stop the vox daemon (pid {pid})"), move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        rt.block_on(async {
            use vox_core::node::daemonipc::{DaemonClient, DaemonRequest};
            if let Ok(mut d) = DaemonClient::open(&socket).await {
                let _ = d.request(DaemonRequest::Stop).await;
            }
        });
        if gone_within(pid, END_WITHIN) {
            Ok(format!("stopped the vox daemon (pid {pid})"))
        } else {
            Err(format!(
                "the vox daemon (pid {pid}) did not stop within {} s",
                END_WITHIN.as_secs()
            ))
        }
    });
}

/// The pid of the daemon answering at `socket`, if one does.
fn daemon_pid(socket: &Path) -> Option<u32> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    rt.block_on(async {
        vox_core::node::daemonipc::DaemonClient::open(socket)
            .await
            .ok()
            .map(|d| d.pid)
    })
}

/// Whether process `pid` has ended within `bound`.
fn gone_within(pid: u32, bound: Duration) -> bool {
    let t0 = Instant::now();
    loop {
        let alive = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .is_some_and(|p| rustix::process::test_kill_process(p).is_ok());
        if !alive {
            return true;
        }
        if t0.elapsed() >= bound {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Any Vox.app running from the install, quit as a stop signal quits it (ADR-026 S-4).
fn quit_app(plan: &mut Plan, app: &Path) {
    let exe = app.join("Contents/MacOS/Vox");
    let pids: Vec<u32> = Command::new("/usr/bin/pgrep")
        .arg("-f")
        .arg(exe.as_os_str())
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .filter_map(|p| p.parse().ok())
                .filter(|p| *p != std::process::id())
                .collect()
        })
        .unwrap_or_default();
    for pid in pids {
        plan.step(format!("quit Vox.app (pid {pid})"), move || {
            let _ = Command::new("/bin/kill").arg(pid.to_string()).status();
            if gone_within(pid, END_WITHIN) {
                Ok(format!("quit Vox.app (pid {pid})"))
            } else {
                Err(format!(
                    "Vox.app (pid {pid}) did not quit within {} s",
                    END_WITHIN.as_secs()
                ))
            }
        });
    }
}

/// The Keychain items the daemon stored for kept nodes: those its attach file names (an item
/// lives only while the attach file names it, M-6), and those lines of the file.
fn keychain(plan: &mut Plan, account: &Account) {
    let file = account.attach_file();
    let Ok(text) = fs::read_to_string(&file) else {
        return;
    };
    let mut accounts = Vec::new();
    let mut rest = String::new();
    for line in text.lines() {
        match line.split_once('\t') {
            Some((_, source)) if source.starts_with("keychain:") => {
                accounts.push(source.trim_start_matches("keychain:").to_owned());
            }
            _ => {
                rest.push_str(line);
                rest.push('\n');
            }
        }
    }
    if accounts.is_empty() {
        return;
    }
    let names: Vec<String> = text
        .lines()
        .filter(|l| l.contains("\tkeychain:"))
        .filter_map(|l| l.split('\t').next().map(str::to_owned))
        .collect();
    plan.step(
        format!(
            "remove the Keychain item{} Vox stored for node{} {}, and stop keeping {}",
            if accounts.len() == 1 { "" } else { "s" },
            if names.len() == 1 { "" } else { "s" },
            names.join(", "),
            if names.len() == 1 { "it" } else { "them" }
        ),
        move || {
            for a in &accounts {
                crate::keychain::forget(a);
            }
            crate::setup::write_whole(&file, &rest)
                .map_err(|e| format!("{} was not updated: {e}", file.display()))?;
            Ok(format!(
                "removed {} Keychain item(s) and their lines in {}",
                accounts.len(),
                file.display()
            ))
        },
    );
}

/// The completions and the startup-file block `vox shell-setup` added.
fn shell_setup(plan: &mut Plan) {
    let found = crate::shell::provisioned();
    if found.is_empty() {
        return;
    }
    plan.step(
        format!("remove what vox shell-setup added: {}", found.join("; ")),
        || {
            let r = crate::shell::deprovision();
            if r.errors.is_empty() {
                Ok(format!(
                    "removed what vox shell-setup added: {}",
                    r.lines.join("; ")
                ))
            } else {
                Err(r.errors.join("; "))
            }
        },
    );
}

/// What Vox.app left in the person's Library.
fn app_leftovers(plan: &mut Plan) {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return;
    };
    let lib = home.join("Library");
    for p in [
        lib.join("Logs/Vox"),
        lib.join("Preferences/us.vox.app.plist"),
        lib.join("Saved Application State/us.vox.app.savedState"),
        lib.join("Containers/us.vox.app.share"),
    ] {
        plan.remove(p);
    }
}

/// A Vox.app install: the bundle, what `install.sh` and `vox update` keep beside it, and the
/// `vox` link into it.
fn bundle_files(plan: &mut Plan, apps: &Path, exe: &Path) {
    let bundle = apps.join("Vox.app");
    for link in vox_links(&bundle, exe) {
        plan.remove(link);
    }
    if let Ok(entries) = fs::read_dir(apps) {
        let mut ours: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name().is_some_and(|n| {
                    let n = n.to_string_lossy();
                    n.starts_with(".Vox.app.")
                        || n == ".vox-standalone.json"
                        || n == ".vox-standalone.lock"
                })
            })
            .collect();
        ours.sort();
        for p in ours {
            plan.remove(p);
        }
    }
    let lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/\
                      LaunchServices.framework/Support/lsregister";
    let gone = bundle.clone();
    if fs::symlink_metadata(&bundle).is_ok() {
        plan.step(
            format!("unregister {} from Launch Services", bundle.display()),
            move || {
                for ext in fs::read_dir(gone.join("Contents/PlugIns"))
                    .into_iter()
                    .flatten()
                    .flatten()
                {
                    let _ = Command::new("/usr/bin/pluginkit")
                        .arg("-r")
                        .arg(ext.path())
                        .output();
                }
                let _ = Command::new(lsregister).arg("-u").arg(&gone).output();
                Ok(format!(
                    "unregistered {} from Launch Services",
                    gone.display()
                ))
            },
        );
    }
    plan.remove(bundle);
}

/// The `vox` links into `bundle`: the one this ran as, and the installer's default places.
fn vox_links(bundle: &Path, exe: &Path) -> Vec<PathBuf> {
    let bundle = fs::canonicalize(bundle).unwrap_or_else(|_| bundle.to_path_buf());
    let mut candidates = vec![exe.to_path_buf()];
    if let Some(dir) = std::env::var_os("VOX_INSTALL_DIR") {
        candidates.push(PathBuf::from(dir).join("vox"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join(".local/bin/vox"));
    }
    let mut links = Vec::new();
    for c in candidates {
        let is_link = fs::symlink_metadata(&c).is_ok_and(|m| m.file_type().is_symlink());
        let into = fs::canonicalize(&c).is_ok_and(|t| t.starts_with(&bundle));
        if is_link && into && !links.contains(&c) {
            links.push(c);
        }
    }
    links
}

/// A standalone install: `vox`, and what `install.sh` and `vox update` keep beside it.
fn standalone_files(plan: &mut Plan, dir: &Path) {
    for name in [
        ".vox-previous",
        ".vox-candidate.partial",
        ".vox-previous.partial",
        ".vox-rollback.partial",
        ".vox-standalone.lock",
        ".vox-standalone.json",
        "vox",
    ] {
        plan.remove(dir.join(name));
    }
}

// There are no unit tests here, deliberately (ADR-018). `tests/install_sh_proof.rs` installs vox
// with the real install.sh into a scratch home and uninstalls it with the installed `vox`.
