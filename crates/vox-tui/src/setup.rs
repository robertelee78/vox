//! `vox setup`: set up this machine (ADR-029 §7).
//!
//! It looks for the harnesses installed here (Claude Code, Codex, OpenCode: each one's program on
//! `PATH`), and offers each a node of its own, `<harness>-<host>` (ADR-026 N-6) or a name the
//! operator types instead (#665; `skip` makes none), with a passphrase
//! the operator types (ADR-028 K-11), its hook installed in the harness's own settings and the
//! agent skill beside it. On macOS it then offers a node for the person, which may be skipped. It
//! ends by printing every node it made: its fingerprint, grouped, with its art (ADR-028 K-1), and
//! the facts a person needs to recognise it — alias, harness, host, OS and Vox version.
//!
//! Every question says what answering yes changes before anything is changed (ADR-028 E-5). A
//! harness that is not installed is named as not found and offered nothing. Wiring Codex also
//! keeps Codex's app-server running (the decider, 2026-10-06), so a plain `codex` session can be
//! followed and driven from Vox; it runs no model. A node that exists
//! already is left as it is. The harnesses' settings are merged, never replaced: only entries that
//! run `vox agent hook` are taken out, and the new node's put in.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use vox_core::node::paths::NodeName;

use crate::app::AppError;
use crate::client::NodeArgs;

/// A harness `vox setup` knows how to wire.
pub(crate) struct Harness {
    /// How `vox agent plugin` and `vox agent skill` name it.
    pub(crate) key: &'static str,
    /// How a person names it.
    pub(crate) name: &'static str,
    /// Its program, looked for on `PATH`.
    pub(crate) program: &'static str,
}

/// The harnesses `vox setup` and `vox agent connect` wire.
pub(crate) const HARNESSES: [Harness; 3] = [
    Harness {
        key: "claude",
        name: "Claude Code",
        program: "claude",
    },
    Harness {
        key: "codex",
        name: "Codex",
        program: "codex",
    },
    Harness {
        key: "opencode",
        name: "OpenCode",
        program: "opencode",
    },
];

/// A node this run made, with what is printed about it at the end.
struct Made {
    name: NodeName,
    fingerprint: String,
    /// The harness it is for, or "person".
    role: &'static str,
}

/// `vox setup`.
///
/// # Errors
/// No terminal to type passphrases at, a data root that cannot be used, or a node or a file that
/// cannot be written.
pub fn run(args: &NodeArgs) -> Result<(), AppError> {
    // **A passphrase is typed by the operator** (ADR-028 K-11, K-13): never piped in by an agent.
    if !std::io::stdin().is_terminal() {
        return Err(AppError::Usage(
            "vox setup asks for a passphrase for every node it makes, and there is no terminal \
             to ask at; run it in a terminal of your own"
                .into(),
        ));
    }
    let account = args.account()?;
    let host = host_name();
    let os = os_name();
    let mut made: Vec<Made> = Vec::new();
    let mut steps: Vec<String> = Vec::new();

    println!("vox setup: looking for harnesses on this machine (their programs on PATH)");
    let found: Vec<(&Harness, PathBuf)> = HARNESSES
        .iter()
        .filter_map(|h| match on_path(h.program) {
            Some(p) => {
                println!("  {:<12} found: {}", h.name, p.display());
                Some((h, p))
            }
            None => {
                println!("  {:<12} not found", h.name);
                None
            }
        })
        .collect();

    for (h, program) in &found {
        let suggested = NodeName::parse(&format!("{}-{host}", h.key))?;
        let wiring = Wiring::of(h.key)?;
        // **A harness wired already is left as it is** (#666): the node its hook names is the
        // one it is, whatever its name, and a second node would only split it in two.
        if let Some(wired) = connected(&account, &wiring) {
            println!(
                "vox setup: {} is connected to node {wired}; left as it is",
                h.name
            );
            continue;
        }
        if account.nodes_on_disk().contains(&suggested) {
            println!("vox setup: node {suggested} exists already; it is left as it is");
            continue;
        }
        println!();
        println!(
            "{} is to get a node of its own, {suggested} unless you name it, with a passphrase \
             you type.",
            h.name
        );
        for line in wiring.effects(&suggested) {
            println!("  {line}");
        }
        // **The name is the operator's** (#665): Enter keeps the suggestion, a name typed is
        // taken as `vox node create` takes it, and `skip` makes none.
        let Some(name) = node_name(
            &account,
            &format!(
                "a node for {} [{suggested}] (Enter keeps it, or type another name; skip makes \
                 none): ",
                h.name
            ),
            &suggested,
        )?
        else {
            println!("vox setup: no node for {}", h.name);
            continue;
        };
        if name != suggested {
            println!("  as node {name}, not {suggested}");
        }
        let (fingerprint, passphrase) = create(&account, &name)?;
        for line in wiring.install(&name)? {
            println!("  {line}");
        }
        attach(args, &name, passphrase);
        if h.key == "codex" {
            match crate::codex_app_server::ensure(program, &wiring.dir) {
                Ok(_) => println!("  Codex's app-server is running"),
                Err(why) => println!(
                    "  Codex's app-server did not start ({why}): Codex sessions are followed \
                     through their hooks only"
                ),
            }
            steps.push(
                "run `vox agent trust codex`: Codex runs a hook only once it is trusted".into(),
            );
        }
        made.push(Made {
            name,
            fingerprint,
            role: h.name,
        });
    }

    // **The person's node is optional** (ADR-029 ST-2), and on macOS only: iOS has its own app.
    if cfg!(target_os = "macos") {
        println!();
        println!(
            "A node for you, the person, is apart from the agents' nodes: it is the one you read \
             and post as."
        );
        if ask("Create a node for you?", false)? {
            let suggested = node_word(&std::env::var("USER").unwrap_or_default());
            let name = loop {
                let typed = line(&format!("its name [{suggested}]: "))?;
                let typed = if typed.is_empty() {
                    suggested.clone()
                } else {
                    typed
                };
                match NodeName::parse(&typed) {
                    Ok(n) if account.nodes_on_disk().contains(&n) => {
                        println!("  there is a node {n} already; give another name");
                    }
                    Ok(n) => break n,
                    Err(e) => println!("  {e}"),
                }
            };
            let (fingerprint, passphrase) = create(&account, &name)?;
            attach(args, &name, passphrase);
            made.push(Made {
                name,
                fingerprint,
                role: "person",
            });
        } else {
            println!("vox setup: no node for you");
        }
    }

    println!();
    if made.is_empty() {
        println!("vox setup: made no node");
        return Ok(());
    }
    println!(
        "vox setup: made {} node{}; give a fingerprint to whoever is to trust that node",
        made.len(),
        if made.len() == 1 { "" } else { "s" }
    );
    let version = env!("CARGO_PKG_VERSION");
    for m in &made {
        println!();
        for row in vox_text::fingerprint::card(&m.fingerprint) {
            println!("  {row}");
        }
        println!(
            "  alias {} · harness {} · host {host} · {os} · vox {version}",
            m.name, m.role
        );
    }
    println!();
    println!("vox setup: {}", crate::ident::NO_BACKUP);
    for s in steps {
        println!("vox setup: next, {s}");
    }
    Ok(())
}

/// The node `wiring`'s harness is connected to here: the one its Vox hook names, when that node
/// is on this machine (`vox agent status` says the other case).
pub(crate) fn connected(
    account: &vox_core::node::paths::Account,
    wiring: &Wiring,
) -> Option<NodeName> {
    wiring
        .wired_node()
        .and_then(|n| NodeName::parse(&n).ok())
        .filter(|n| account.nodes_on_disk().contains(n))
}

/// Make node `name` with a passphrase typed twice, or none (ADR-028 K-11 as amended): its
/// fingerprint, in base32, and the passphrase, to attach it with.
pub(crate) fn create(
    account: &vox_core::node::paths::Account,
    name: &NodeName,
) -> Result<(String, zeroize::Zeroizing<String>), AppError> {
    let passphrase = ask_new_passphrase(name)?;
    let paths = account.node_paths(name)?;
    let fp = crate::client::create_identity(&paths, &passphrase)?;
    println!("vox setup: created node {name}");
    Ok((vox_core::node::link::b32_encode(&fp), passphrase))
}

/// Attach node `name`, just made, and remember it (#666), so it is usable at once and after every
/// restart with nobody typing. A node made but not attached is said, with the command that
/// attaches it, and setup goes on.
fn attach(args: &NodeArgs, name: &NodeName, passphrase: zeroize::Zeroizing<String>) {
    let attached = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(AppError::Io)
        .and_then(|rt| rt.block_on(crate::client::attach_with(args, name, passphrase, true)));
    if let Err(e) = attached {
        println!(
            "vox setup: node {name} is made, but not attached: {e}\n  attach it: vox node attach \
             {name}"
        );
    }
}

/// A new node's passphrase, typed twice at the terminal. Enter alone, twice, gives none (ADR-005
/// J-2, V030-36), and what that means is said once.
///
/// # Errors
/// The terminal closed.
pub(crate) fn ask_new_passphrase(name: &NodeName) -> Result<zeroize::Zeroizing<String>, AppError> {
    loop {
        let first = zeroize::Zeroizing::new(crate::tunnel_cli::prompt_passphrase(&format!(
            "passphrase for {name} (Enter alone for none)"
        ))?);
        let again = zeroize::Zeroizing::new(crate::tunnel_cli::prompt_passphrase("again")?);
        if *first == *again {
            if first.is_empty() {
                println!("  {}", vox_text::node::NO_PASSPHRASE);
            }
            return Ok(first);
        }
        println!("  the two differ; type it again");
    }
}

/// A node's name, typed after `prompt`: Enter takes `suggested`, `skip` or `n` takes none. A
/// name is refused as `vox node create` refuses it, with its reason, and asked again.
fn node_name(
    account: &vox_core::node::paths::Account,
    prompt: &str,
    suggested: &NodeName,
) -> Result<Option<NodeName>, AppError> {
    loop {
        let typed = line(prompt)?;
        match typed.to_ascii_lowercase().as_str() {
            "" => return Ok(Some(suggested.clone())),
            "skip" | "n" | "no" => return Ok(None),
            _ => {}
        }
        match NodeName::parse(&typed) {
            Ok(n) if account.nodes_on_disk().contains(&n) => {
                println!("  there is a node {n} already; `vox node list` lists them");
            }
            Ok(n) => return Ok(Some(n)),
            Err(e) => println!("  {e}"),
        }
    }
}

/// A yes/no question, answered at the terminal; Enter takes `default`.
fn ask(question: &str, default: bool) -> Result<bool, AppError> {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    loop {
        let a = line(&format!("{question} {hint} "))?.to_ascii_lowercase();
        match a.as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("  answer y or n"),
        }
    }
}

/// One line typed at the terminal, after `prompt`, trimmed.
fn line(prompt: &str) -> Result<String, AppError> {
    print!("{prompt}");
    std::io::stdout().flush().map_err(AppError::Io)?;
    let mut s = String::new();
    if std::io::stdin()
        .lock()
        .read_line(&mut s)
        .map_err(AppError::Io)?
        == 0
    {
        return Err(AppError::Usage(
            "the terminal closed before setup was done".into(),
        ));
    }
    Ok(s.trim().to_owned())
}

/// `program` as an executable file in a directory of `PATH`.
pub(crate) fn on_path(program: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|d| d.join(program))
            .find(|p| {
                std::fs::metadata(p)
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            })
    })
}

/// `s` folded to what a node name may hold: a-z, digits, '-' (ADR-026).
fn node_word(s: &str) -> String {
    let w: String = s
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                c
            } else {
                '-'
            }
        })
        .collect();
    let w = w.trim_matches('-').to_owned();
    if w.is_empty() {
        "me".into()
    } else {
        w
    }
}

/// This machine's short host name, as a node name holds it.
pub(crate) fn host_name() -> String {
    let out = std::process::Command::new("hostname")
        .arg("-s")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    let w = node_word(&out);
    if w == "me" {
        "host".into()
    } else {
        w
    }
}

/// The OS and its version, as a person names them: "macOS 27.2", "Ubuntu 24.04.1 LTS".
fn os_name() -> String {
    if cfg!(target_os = "macos") {
        let v = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default();
        return format!("macOS {v}").trim().to_owned();
    }
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("PRETTY_NAME="))
                .map(|v| v.trim_matches('"').to_owned())
        })
        .unwrap_or_else(|| std::env::consts::OS.to_owned())
}

/// Where a harness reads its settings and skills, and what is written there.
pub(crate) struct Wiring {
    key: &'static str,
    /// The harness's configuration directory.
    pub(crate) dir: PathBuf,
}

impl Wiring {
    pub(crate) fn of(key: &'static str) -> Result<Self, AppError> {
        let home = || {
            std::env::var_os("HOME")
                .filter(|h| !h.is_empty())
                .map(PathBuf::from)
        };
        let var = |v: &str| {
            std::env::var_os(v)
                .filter(|d| !d.is_empty())
                .map(PathBuf::from)
        };
        let dir = match key {
            "claude" => var("CLAUDE_CONFIG_DIR").or_else(|| home().map(|h| h.join(".claude"))),
            "codex" => var("CODEX_HOME").or_else(|| home().map(|h| h.join(".codex"))),
            _ => var("OPENCODE_CONFIG_DIR")
                .or_else(|| var("XDG_CONFIG_HOME").map(|x| x.join("opencode")))
                .or_else(|| home().map(|h| h.join(".config").join("opencode"))),
        };
        dir.map(|dir| Self { key, dir }).ok_or_else(|| {
            AppError::Usage("HOME is not set, so no harness's settings can be found".into())
        })
    }

    /// The node this harness's Vox hook names, as its settings hold it now: `None` when it has
    /// no Vox hook (Claude Code's and Codex's entries that run `vox agent hook --node <name>`,
    /// OpenCode's plugin with its node written in).
    pub(crate) fn wired_node(&self) -> Option<String> {
        let text = std::fs::read_to_string(self.hook_file()).ok()?;
        if self.key == "opencode" {
            return text.lines().find_map(|l| {
                l.trim()
                    .strip_prefix("const VOX_NODE = \"")?
                    .strip_suffix('"')
                    .map(str::to_owned)
            });
        }
        fn walk(v: &serde_json::Value, out: &mut Option<String>) {
            match v {
                serde_json::Value::String(c) if out.is_none() && runs_vox_hook(c) => {
                    let t: Vec<&str> = c.split_whitespace().collect();
                    *out = t
                        .windows(2)
                        .find(|w| w[0] == "--node")
                        .map(|w| w[1].trim_matches(['"', '\'']).to_owned());
                }
                serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
                serde_json::Value::Object(o) => o.values().for_each(|x| walk(x, out)),
                _ => {}
            }
        }
        let v: serde_json::Value = serde_json::from_str(&text).ok()?;
        let mut found = None;
        walk(&v["hooks"], &mut found);
        found
    }

    /// The file the hook goes in.
    pub(crate) fn hook_file(&self) -> PathBuf {
        match self.key {
            "claude" => self.dir.join("settings.json"),
            "codex" => self.dir.join("hooks.json"),
            _ => self.dir.join("plugin").join("vox.js"),
        }
    }

    fn skill_dir(&self) -> PathBuf {
        self.dir.join("skills").join(crate::skill_pack::DIR_NAME)
    }

    /// What installing changes, said before it is done (ADR-028 E-5).
    pub(crate) fn effects(&self, node: &NodeName) -> Vec<String> {
        let hook = match self.key {
            "claude" => format!(
                "its hook, `vox agent hook --node {node}`, is to go in {}, with VOX_NODE={node} \
                 for its sessions; other Vox hook entries there are replaced, nothing else",
                self.hook_file().display()
            ),
            "codex" => format!(
                "its hook, `vox agent hook --node {node}`, is to go in {}; other Vox hook \
                 entries there are replaced, nothing else; and Codex's app-server is to be kept \
                 running (`codex app-server daemon start`), so a plain `codex` session can be \
                 followed and driven from Vox: it runs no model",
                self.hook_file().display()
            ),
            _ => format!(
                "its plugin, acting as {node}, is to be written to {}",
                self.hook_file().display()
            ),
        };
        vec![
            hook,
            format!(
                "the agent skill pack is to be installed in {}; a file there you changed is kept",
                self.skill_dir().display()
            ),
        ]
    }

    /// Install the hook and the skill for `node`: what was written, as a person reads it.
    pub(crate) fn install(&self, node: &NodeName) -> Result<Vec<String>, AppError> {
        let hook = self.hook_file();
        match self.key {
            "claude" => merge_hooks(&hook, &crate::agent_hook::claude_settings(node))?,
            "codex" => merge_hooks(&hook, &crate::agent_hook::codex_hooks(node))?,
            _ => write(&hook, &crate::agent_hook::opencode_plugin(node))?,
        }
        let mut said = vec![format!("installed the hook in {}", hook.display())];
        said.extend(
            crate::skill_pack::install_into(&self.skill_dir())?
                .iter()
                .map(crate::skill_pack::Done::said),
        );
        Ok(said)
    }
}

/// Merge the hook entries of `snippet` (as `vox agent plugin` prints them) into the settings file
/// at `path`: every entry already there that runs `vox agent hook` is taken out, the snippet's
/// put in, and its `env` keys set. Everything else in the file is kept. A file that is not JSON
/// is left alone and named.
fn merge_hooks(path: &Path, snippet: &str) -> Result<(), AppError> {
    let mut settings: serde_json::Value = match std::fs::read_to_string(path) {
        Ok(text) if text.trim().is_empty() => serde_json::json!({}),
        Ok(text) => serde_json::from_str(&text).map_err(|e| {
            AppError::Usage(format!(
                "{} is not JSON ({e}), so nothing was written to it; fix it and run vox setup again",
                path.display()
            ))
        })?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
        Err(e) => return Err(AppError::Io(e)),
    };
    let ours: serde_json::Value = serde_json::from_str(snippet)
        .map_err(|e| AppError::Usage(format!("the hook entries are not JSON: {e}")))?;
    let Some(obj) = settings.as_object_mut() else {
        return Err(AppError::Usage(format!(
            "{} holds no JSON object, so nothing was written to it",
            path.display()
        )));
    };
    let hooks = obj.entry("hooks").or_insert_with(|| serde_json::json!({}));
    if !hooks.is_object() {
        *hooks = serde_json::json!({});
    }
    for (event, groups) in ours["hooks"].as_object().into_iter().flatten() {
        let list = hooks
            .as_object_mut()
            .map(|h| {
                h.entry(event.clone())
                    .or_insert_with(|| serde_json::json!([]))
            })
            .filter(|l| l.is_array());
        let Some(list) = list else { continue };
        // Every Vox hook entry already there goes: a hook for another node would act as it.
        if let Some(existing) = list.as_array_mut() {
            for group in existing.iter_mut() {
                if let Some(entries) = group["hooks"].as_array_mut() {
                    entries.retain(|h| !h["command"].as_str().is_some_and(runs_vox_hook));
                }
            }
            existing.retain(|g| g["hooks"].as_array().is_none_or(|e| !e.is_empty()));
            existing.extend(groups.as_array().cloned().unwrap_or_default());
        }
    }
    if let Some(env) = ours["env"].as_object() {
        let target = obj.entry("env").or_insert_with(|| serde_json::json!({}));
        if let Some(t) = target.as_object_mut() {
            for (k, v) in env {
                t.insert(k.clone(), v.clone());
            }
        }
    }
    let mut text = serde_json::to_string_pretty(&settings)
        .map_err(|e| AppError::Usage(format!("cannot write the settings: {e}")))?;
    text.push('\n');
    write(path, &text)
}

/// Whether `command` runs `vox agent hook` (a program named `vox`, or a path to one).
fn runs_vox_hook(command: &str) -> bool {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    tokens
        .windows(3)
        .any(|w| (w[0] == "vox" || w[0].ends_with("/vox")) && w[1] == "agent" && w[2] == "hook")
}

/// What `vox uninstall` does to the wiring `vox setup` installed.
pub(crate) enum Unwire {
    /// A harness's settings file, rewritten without Vox's entries (everything else kept).
    Rewrite {
        /// What it does, said first.
        what: String,
        path: PathBuf,
        /// The file as it is to be.
        text: String,
    },
    /// A file Vox wrote whole and nobody edited since.
    Remove(PathBuf),
    /// Something left, and why.
    Keep(String),
}

/// Undo [`Wiring::install`] for every harness: in Claude Code's and Codex's settings, the entries
/// that run `vox agent hook` and the `VOX_NODE` Vox set; OpenCode's plugin and the agent skill,
/// only when each is byte for byte what Vox writes (for a node on disk); anything else is named
/// and left. Nothing is changed here: the caller does it, or lists it in a dry run.
pub(crate) fn unwire(account: &vox_core::node::paths::Account) -> Vec<Unwire> {
    let mut out = Vec::new();
    let nodes = account.nodes_on_disk();
    for h in &HARNESSES {
        let Ok(w) = Wiring::of(h.key) else { continue };
        let hook = w.hook_file();
        if h.key == "opencode" {
            if let Ok(text) = std::fs::read_to_string(&hook) {
                if nodes
                    .iter()
                    .any(|n| crate::agent_hook::opencode_plugin(n) == text)
                {
                    out.push(Unwire::Remove(hook.clone()));
                } else if text.contains("vox agent hook") {
                    out.push(Unwire::Keep(format!(
                        "{} is kept: it is not the plugin Vox writes for a node here (edited, or for a node no longer on this machine); remove it yourself if it is Vox's",
                        hook.display()
                    )));
                }
            }
        } else if let Some(text) = without_vox_hooks(&hook) {
            out.push(Unwire::Rewrite {
                what: format!(
                    "take Vox's `vox agent hook` entries out of {} (nothing else in it)",
                    hook.display()
                ),
                path: hook.clone(),
                text,
            });
            if h.key == "codex" {
                out.push(Unwire::Keep(
                    "Codex's app-server, which vox setup started, is Codex's own and is left running; `codex app-server daemon stop` stops it"
                        .into(),
                ));
            }
        }
        // The skill pack, by the rule install keeps (crate::skill_pack): only what Vox wrote
        // and nobody changed goes.
        if let Some(dir) = crate::skill_pack::pack_dir(h.key) {
            let (remove, kept) = crate::skill_pack::uninstall_plan(&dir);
            out.extend(remove.into_iter().map(Unwire::Remove));
            for k in kept {
                out.push(Unwire::Keep(format!(
                    "{} is kept: Vox did not write it, or it was changed after Vox did; remove \
                     it yourself if you do not want it",
                    k.display()
                )));
            }
        }
    }
    out
}

/// The settings file at `path` without Vox's hook entries and `VOX_NODE`, when it has any; `None`
/// when it has none, is missing, or is not a JSON object.
fn without_vox_hooks(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut settings: serde_json::Value = serde_json::from_str(&text).ok()?;
    let obj = settings.as_object_mut()?;
    let mut changed = false;
    if let Some(hooks) = obj
        .get_mut("hooks")
        .and_then(serde_json::Value::as_object_mut)
    {
        for list in hooks.values_mut() {
            let Some(groups) = list.as_array_mut() else {
                continue;
            };
            for group in groups.iter_mut() {
                if let Some(entries) = group["hooks"].as_array_mut() {
                    let before = entries.len();
                    entries.retain(|h| !h["command"].as_str().is_some_and(runs_vox_hook));
                    changed |= entries.len() != before;
                }
            }
            groups.retain(|g| g["hooks"].as_array().is_none_or(|e| !e.is_empty()));
        }
        hooks.retain(|_, list| list.as_array().is_none_or(|l| !l.is_empty()));
        if hooks.is_empty() {
            obj.remove("hooks");
        }
    }
    if let Some(env) = obj
        .get_mut("env")
        .and_then(serde_json::Value::as_object_mut)
    {
        changed |= env.remove("VOX_NODE").is_some();
        if env.is_empty() {
            obj.remove("env");
        }
    }
    if !changed {
        return None;
    }
    let mut out = serde_json::to_string_pretty(&settings).ok()?;
    out.push('\n');
    Some(out)
}

/// [`write`], for `vox uninstall`.
pub(crate) fn write_whole(path: &Path, text: &str) -> Result<(), AppError> {
    write(path, text)
}

/// Write `text` to `path` whole: a temporary file beside it, renamed over it, so a harness never
/// reads half a file. The file keeps the mode it had.
fn write(path: &Path, text: &str) -> Result<(), AppError> {
    use std::os::unix::fs::PermissionsExt;
    let dir = path
        .parent()
        .ok_or_else(|| AppError::Usage(format!("{} has no directory", path.display())))?;
    std::fs::create_dir_all(dir).map_err(AppError::Io)?;
    let mode = std::fs::metadata(path).ok().map(|m| m.permissions().mode());
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(AppError::Io)?;
    tmp.write_all(text.as_bytes()).map_err(AppError::Io)?;
    if let Some(mode) = mode {
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode))
            .map_err(AppError::Io)?;
    }
    tmp.persist(path).map_err(|e| AppError::Io(e.error))?;
    Ok(())
}
