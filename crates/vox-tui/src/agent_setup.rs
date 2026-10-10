//! What a harness session needs before it can work in a Vox room, found and said from the
//! session itself, with no hook yet (#666): `vox agent status` and `vox agent connect`.
//!
//! A session's hook is what brings it Vox's news, and a harness has a hook only once it is wired
//! to a node. So a harness Vox was installed beside, and never set up, has no hook to say so: the
//! agent skill pack is what reaches it, at the start of every session, and it runs
//! `vox agent status --harness <harness>`. That only reads, and says, in fixed words, the first
//! thing missing and the one command the operator runs for it in a terminal of their own (it is
//! where a passphrase is typed):
//!
//! 1. no node wired to this harness here: `vox agent connect <harness> --node <name>`, which makes
//!    the node (its passphrase typed twice), wires the harness's hook to it and the agent skill
//!    beside it, as `vox setup` does for that one harness, and attaches the node; or, for a node
//!    that exists, wires it and attaches it;
//! 2. the node not attached: `vox node attach <node>`;
//! 3. the session's directory not bound to a room: the ask the hook gives (ADR-029 RB-5), with
//!    `vox room join <link> --node <node> --bind <dir>`.
//!
//! Neither command changes trust, and the session never runs them: they take a passphrase.

use std::path::Path;

use vox_core::node::paths::NodeName;

use crate::app::AppError;
use crate::client::NodeArgs;
use crate::setup::{Harness, Wiring, HARNESSES};

/// The harness `key` names (`claude`, `codex`, `opencode`; `claude-code` too).
///
/// # Errors
/// A name that is none of them.
fn harness(key: &str) -> Result<&'static Harness, AppError> {
    let key = match key.to_ascii_lowercase().as_str() {
        "claude-code" => "claude".to_owned(),
        k => k.to_owned(),
    };
    HARNESSES.iter().find(|h| h.key == key).ok_or_else(|| {
        AppError::Usage(format!(
            "no harness {key:?}; known: claude, codex, opencode"
        ))
    })
}

/// `vox agent status --harness <harness>`: what this harness on this machine needs before a
/// session started in `dir` works in a Vox room, the first thing missing with the one command
/// that gives it, in words the session repeats to the operator. It only reads.
///
/// # Errors
/// An unknown harness, or a data root that cannot be used.
pub async fn status(args: &NodeArgs, key: &str, dir: &Path) -> Result<String, AppError> {
    let h = harness(key)?;
    let account = args.account()?;
    let wiring = Wiring::of(h.key)?;
    let suggested = format!("{}-{}", h.key, crate::setup::host_name());
    let hook = wiring.hook_file();
    let wired = wiring.wired_node().and_then(|n| NodeName::parse(&n).ok());
    let connect = |name: &str, what: &str| {
        format!(
            "Vox: {what}, so this session is in no Vox room. Tell the operator, in these words: \
             \"{} has no Vox node on this machine. Choose a name for it and run this in a \
             terminal of your own; it asks there for the new node's passphrase, makes the node, \
             wires {}'s hook to it in {} with the agent skill beside it, and attaches it. Then \
             start a new session.\"\n    vox agent connect {} --node {name}\n\
             Never run it yourself, and never ask for the passphrase here.\n",
            h.name,
            h.name,
            hook.display(),
            h.key
        )
    };
    let Some(node) = wired else {
        return Ok(connect(
            &suggested,
            &format!("{} has no node on this machine", h.name),
        ));
    };
    if !account.nodes_on_disk().contains(&node) {
        return Ok(connect(
            node.as_str(),
            &format!(
                "{}'s hook names node {node}, which is not on this machine",
                h.name
            ),
        ));
    }
    if !crate::client::attached(&account, &node).await {
        return Ok(format!(
            "Vox: {} is node {node} here, and {node} is not attached, so this session is in no \
             Vox room. Tell the operator, in these words: \"Node {node} is not attached. Run \
             this in a terminal of your own; it asks there for the node's passphrase once, and \
             Vox then remembers it and attaches the node by itself after every restart. Then \
             start a new session.\"\n    vox node attach {node}\n\
             Never run it yourself, and never ask for the passphrase here.\n",
            h.name
        ));
    }
    let entries = crate::room_map::read(&account.data_root)?;
    if let Some(e) = crate::room_map::lookup(&entries, dir) {
        return Ok(if e.room == crate::room_map::DECLINED {
            format!(
                "Vox: {} is node {node}, attached; the operator said no to a room for this repo \
                 ({}), so nothing is to be asked.\n",
                h.name,
                dir.display()
            )
        } else {
            format!(
                "Vox: {} is node {node}, attached; this repo ({}) works in room {}.\n",
                h.name,
                dir.display(),
                e.room
            )
        });
    }
    let ask = crate::room_map::note(None, true, None, &account.data_root, dir, node.as_str())
        .unwrap_or_default();
    Ok(format!("Vox: {} is node {node}, attached.\n{ask}", h.name))
}

/// `vox agent connect <harness> --node <name>`: make node `name` if there is none (its
/// passphrase typed twice at this terminal, or read from `passphrase_file`), wire the harness's
/// hook to it with the agent skill beside it, as `vox setup` does, and attach it. What it is to do
/// is said first (ADR-028 E-5).
///
/// # Errors
/// An unknown harness, a name `vox node create` refuses, no terminal to type a passphrase at, or a
/// file or the daemon refusing.
pub async fn connect(
    args: &NodeArgs,
    key: &str,
    name: &str,
    passphrase_file: Option<std::path::PathBuf>,
) -> Result<(), AppError> {
    let h = harness(key)?;
    let name = NodeName::parse(name)?;
    let account = args.account()?;
    let wiring = Wiring::of(h.key)?;
    // **A harness connected already is left as it is** (#666): to another node, nothing changes;
    // to this one, it is attached and remembered below, and nothing else is made.
    if let Some(wired) = crate::setup::connected(&account, &wiring) {
        if wired == name {
            println!(
                "vox: {} is connected to node {name}; left as it is, and node {name} is to be \
                 attached with its passphrase and remembered",
                h.name
            );
            let typed =
                passphrase_file.is_none() && std::env::var_os("VOX_IDENTITY_PASSPHRASE").is_none();
            let passphrase = crate::client::attach_passphrase(None, passphrase_file)?;
            return crate::client::attach_with(args, &name, passphrase, typed).await;
        }
        println!(
            "vox: {} is connected to node {wired}; left as it is. `vox node attach {wired}` \
             attaches it",
            h.name
        );
        return Ok(());
    }
    let exists = account.nodes_on_disk().contains(&name);
    println!(
        "vox: {} is to be wired to {} node {name}{}:",
        h.name,
        if exists { "the existing" } else { "a new" },
        if exists {
            ", attached with its passphrase"
        } else {
            ", made with a passphrase you type twice and attached"
        }
    );
    for line in wiring.effects(&name) {
        println!("  {line}");
    }
    // A new node's passphrase is typed unless it comes from a file; an existing node's, unless
    // from a file or VOX_IDENTITY_PASSPHRASE, as `vox node attach` takes it.
    let typed = passphrase_file.is_none()
        && (!exists || std::env::var_os("VOX_IDENTITY_PASSPHRASE").is_none());
    let passphrase = if exists {
        crate::client::attach_passphrase(None, passphrase_file)?
    } else {
        let passphrase = match passphrase_file {
            Some(f) => zeroize::Zeroizing::new(crate::tunnel_cli::new_identity_passphrase(
                None,
                Some(f),
                "",
            )?),
            None => {
                if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                    return Err(AppError::Usage(
                        "vox agent connect asks for the new node's passphrase, and there is no \
                         terminal to ask at; run it in a terminal of your own"
                            .into(),
                    ));
                }
                crate::setup::ask_new_passphrase(&name)?
            }
        };
        let paths = account.node_paths(&name)?;
        let fp = crate::client::create_identity(&paths, &passphrase)?;
        println!("vox: created node {name}");
        println!("{}", vox_core::node::link::b32_encode(&fp));
        eprintln!("vox: {}", crate::ident::NO_BACKUP);
        passphrase
    };
    for line in wiring.install(&name)? {
        println!("  {line}");
    }
    if h.key == "codex" {
        if let Some(program) = crate::setup::on_path(h.program) {
            match crate::codex_app_server::ensure(&program, &wiring.dir) {
                Ok(_) => println!("  Codex's app-server is running"),
                Err(why) => println!(
                    "  Codex's app-server did not start ({why}): Codex sessions are followed \
                     through their hooks only"
                ),
            }
        }
        println!(
            "vox: next, run `vox agent trust codex`: Codex runs a hook only once it is trusted"
        );
    }
    // Attached already or not, it is attached and remembered (#666): an attach of an attached
    // node checks the passphrase, and keeps it.
    crate::client::attach_with(args, &name, passphrase, typed).await?;
    println!(
        "vox: {} is wired to node {name}; start a new {} session",
        h.name, h.name
    );
    Ok(())
}
