//! What a harness session needs before it can work in a Vox room, found and said from the
//! session itself, with no hook yet (#666): `vox agent status` and `vox agent setup`.
//!
//! A session's hook is what brings it Vox's news, and a harness has a hook only once it is wired
//! to a node. So a harness Vox was installed beside, and never set up, has no hook to say so: the
//! agent skill pack is what reaches it, at the start of every session, and it runs
//! `vox agent status --harness <harness>`. That only reads, and says, in fixed words, the first
//! thing missing and the one command the operator runs for it in a terminal of their own (it is
//! where a passphrase is typed):
//!
//! 1. no node wired to this harness here: `vox agent setup <harness> --node <name>`, which makes
//!    the node (its passphrase typed twice), wires the harness's hook to it and the agent skill
//!    beside it, as `vox setup` does for that one harness, and attaches the node; or, for a node
//!    that exists, wires it and attaches it;
//! 2. the node not attached: `vox node unlock <node>`;
//! 3. the session's directory not bound to a room: the ask the hook gives (ADR-029 RB-5), with
//!    `vox room join <link> --node <node> --bind <dir>`.
//!
//! The terminal setup path takes its passphrase only from the operator and trusts only Vox's
//! own Codex hook; it does not grant any node read or drive trust.

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
    let said = first_missing(args, key, dir).await?;
    let account = args.account()?;
    if crate::setup::connected(&account, &Wiring::of(harness(key)?.key)?).is_none() {
        return Ok(said);
    }
    // **What Vox asks the person, here too** (ADR-029 RB-5): on a machine with no app, this and
    // the TUI are where a person reads that a repo waits for a room.
    let asks = crate::room_ask::fetch(&args.account()?).await?;
    Ok(said + &crate::room_ask::needs_you(&asks, &args.account()?.data_root))
}

/// The first thing missing, for [`status`].
async fn first_missing(args: &NodeArgs, key: &str, dir: &Path) -> Result<String, AppError> {
    let h = harness(key)?;
    let account = args.account()?;
    let wiring = Wiring::of(h.key)?;
    let suggested = crate::setup::suggested_name(h.key, &crate::setup::host_name());
    let hook = wiring.hook_file();
    let wired = wiring.wired_node().and_then(|n| NodeName::parse(&n).ok());
    let setup = |name: &str, what: &str| {
        let command = vox_text::shell::node_command(&["vox", "agent", "setup", h.key], name);
        if crate::agent_onboarding::declined(&account, h.key) {
            return String::new();
        }
        if crate::agent_onboarding::local_app(&account).is_some() {
            return format!(
                "Vox: {} has no Vox node on this machine. Vox offers Set Up in its app; you may start `{command}` to ask there. Never ask for a passphrase in this session.\n",
                h.name
            );
        }
        format!(
            "Vox: {what}, so this session is in no Vox room. Tell the operator, in these words: \
             \"{} has no Vox node on this machine. Choose a name for it and run this in a \
             terminal of your own; it asks there for the new node's passphrase, makes the node, \
             wires {}'s hook to it in {} with the agent skill beside it, and makes it Ready. Then \
             start a new session.\"\n    {command}\n\
             Never run it yourself, and never ask for the passphrase here.\n",
            h.name,
            h.name,
            hook.display()
        )
    };
    let Some(node) = wired else {
        return Ok(setup(
            &suggested,
            &format!("{} has no node on this machine", h.name),
        ));
    };
    if !account.nodes_on_disk().contains(&node) {
        return Ok(setup(
            node.as_str(),
            &format!(
                "{}'s hook names node {node}, which is not on this machine",
                h.name
            ),
        ));
    }
    let status = crate::client::node_status(args, &node).await?;
    if status.is_none() {
        return Ok(format!(
            "Vox is preparing node {node}; start a new session once it is Ready.\n"
        ));
    }
    if status == Some(vox_core::node::daemonipc::NodeStatus::Locked) {
        let unlock = vox_text::shell::command(&["vox", "node", "unlock", "--", node.as_str()]);
        return Ok(format!(
            "Vox: {} is node {node} here, and {node} is Locked, so this session is in no \
             Vox room. Tell the operator, in these words: \"Node {node} is Locked. Run \
             this in a terminal of your own; it asks there for the node's passphrase once, and \
             Vox then remembers it and makes the node Ready by itself after every restart. Then \
             start a new session.\"\n    {unlock}\n\
             Never run it yourself, and never ask for the passphrase here.\n",
            h.name
        ));
    }
    let entries = crate::room_map::read(&account.data_root)?;
    if let Some(e) = crate::room_map::resolve(&entries, dir) {
        return Ok(if e.room == crate::room_map::DECLINED {
            format!(
                "Vox: {} is node {node}, Ready; the operator said no to a room for this repo \
                 ({}), so nothing is to be asked.\n",
                h.name,
                dir.display()
            )
        } else {
            in_bound_room(&account, &node, h.name, dir, &e.room).await
        });
    }
    let ask = crate::room_map::note(
        None,
        true,
        None,
        &account.data_root,
        dir,
        node.as_str(),
        None,
    )
    .unwrap_or_default();
    Ok(format!("Vox: {} is node {node}, Ready.\n{ask}", h.name))
}

/// What status says of a repo the room map binds to the room `link` names: that it works there
/// when `node` is in that room, and otherwise that `node` is not in it yet, so this harness's
/// sessions cannot post there, with how it joins (ADR-029 RB-3, RB-5a). A node whose rooms cannot
/// be read is said as that, never as one in the room.
async fn in_bound_room(
    account: &vox_core::node::paths::Account,
    node: &NodeName,
    harness: &str,
    dir: &Path,
    link: &str,
) -> String {
    let room = vox_core::node::link::InviteLink::parse(link)
        .map(|l| l.channel_id)
        .ok();
    let short: String = room
        .map(|r| vox_core::node::link::b32_encode(&r))
        .unwrap_or_default()
        .chars()
        .take(12)
        .collect();
    let held = match account.node_paths(node) {
        Ok(paths) => match crate::room_cli::attach(&paths).await {
            Ok(mut client) => crate::room_cli::rooms_of(&mut client)
                .await
                .map(|rooms| {
                    rooms
                        .iter()
                        .any(|(id, _, _, over, _)| Some(*id) == room && over.is_empty())
                })
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        },
        Err(e) => Err(e.to_string()),
    };
    match held {
        Ok(true) => format!(
            "Vox: {harness} is node {node}, Ready; this repo ({}) works in room {short}.\n",
            dir.display()
        ),
        Ok(false) => format!(
            "Vox: {harness} is node {node}, Ready; this repo ({}) is bound to room {short}, \
             and {node} is not in it, so this session cannot post there. {node} joins it by \
             itself, with the room map's passphrase, when a session starts here; if that failed, \
             Vox asks the operator (Vox.app dialog), or they run at a terminal: {}\n",
            dir.display(),
            vox_text::shell::command(&["vox", "room", "join", link, "--node", node.as_str()]),
        ),
        Err(why) => format!(
            "Vox: {harness} is node {node}, Ready; this repo ({}) is bound to room {short}, \
             and whether {node} is in it could not be read: {why}\n",
            dir.display()
        ),
    }
}

/// `vox agent setup <harness> [--node <name>]`: the operator's terminal path (also over SSH).
/// Make a node if needed, replace the light hook, trust Codex's hook, and attach the node. The
/// passphrase is typed here, never taken from the agent, a file or an environment variable.
/// Vox.app's request/dialog path is handled separately (ADR-031 NC-2).
///
/// # Errors
/// An unknown harness, an agent-marked process, no terminal for the passphrase, an invalid name,
/// or a file, harness or daemon refusing.
pub async fn setup(args: &NodeArgs, key: &str, name: Option<&str>) -> Result<(), AppError> {
    let h = harness(key)?;
    let account = args.account()?;
    let wiring = Wiring::of(h.key)?;
    let wired = crate::setup::connected(&account, &wiring);
    let suggested = name.is_none() && wired.is_none();
    let name = match name {
        Some(name) => NodeName::parse(name)?,
        None => match &wired {
            Some(name) => name.clone(),
            None => NodeName::parse(&crate::setup::suggested_name(
                h.key,
                &crate::setup::host_name(),
            ))?,
        },
    };
    // A harness already wired to another node stays there; this read-only outcome needs no
    // passphrase. Running setup for its own node below also repairs Codex's hook trust.
    if let Some(wired) = &wired {
        if wired != &name {
            let unlock = vox_text::shell::command(&["vox", "node", "unlock", "--", wired.as_str()]);
            println!(
                "vox: {} is connected to node {wired}; left as it is. `{unlock}` attaches it",
                h.name
            );
            return Ok(());
        }
    }
    if crate::agent_onboarding::request_in_app(args, h.key, &name)? {
        return Ok(());
    }
    let setup = vox_text::shell::node_command(&["vox", "agent", "setup", h.key], name.as_str());
    if crate::coord::agent_marked() {
        return Err(AppError::Usage(format!(
            "run `{setup}` in a terminal of your own outside the agent session; \
             the node's passphrase is asked only there."
        )));
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(AppError::Usage(format!(
            "`{setup}` asks for the node's passphrase only in a terminal of your own; \
             run it there, outside the agent session"
        )));
    }
    // Setup cannot leave Codex's new hook waiting for a separate manual trust command.
    let codex = if h.key == "codex" {
        Some(crate::setup::on_path(h.program).ok_or_else(|| {
            AppError::Usage("Codex is not on PATH; install Codex before setting up its node".into())
        })?)
    } else {
        None
    };
    let exists = account.nodes_on_disk().contains(&name);
    if suggested {
        println!("vox: suggested node name {name}; use --node to choose another");
    }
    println!(
        "vox: {} is to be wired to {} node {name}{}:",
        h.name,
        if exists { "the existing" } else { "a new" },
        if exists {
            ", unlocked with its passphrase"
        } else {
            ", made with a passphrase you type twice and made Ready"
        }
    );
    for line in wiring.effects(&name) {
        println!("  {line}");
    }
    let passphrase = if exists {
        zeroize::Zeroizing::new(crate::tunnel_cli::prompt_passphrase(&format!(
            "passphrase for {name}"
        ))?)
    } else {
        let passphrase = crate::setup::ask_new_passphrase(&name)?;
        let paths = account.node_paths(&name)?;
        let fp = crate::client::create_identity(&paths, &passphrase)?;
        println!("vox: created node {name}");
        println!("{}", vox_core::node::link::b32_encode(&fp));
        eprintln!("vox: {}", crate::ident::NO_BACKUP);
        passphrase
    };
    if wired.is_none() {
        for line in wiring.install(&name)? {
            println!("  {line}");
        }
    }
    if let Some(program) = codex {
        crate::setup::trust_codex_hook(&program)?;
        match crate::codex_app_server::ensure(&program, &wiring.dir) {
            Ok(_) => println!("  Codex's app-server is running"),
            Err(why) => println!(
                "  Codex's app-server did not start ({why}): Codex sessions are followed \
                 through their hooks only"
            ),
        }
    }
    crate::client::attach_with(args, &name, passphrase, true).await?;
    crate::agent_onboarding::completed(&account, h.key, &name)?;
    println!(
        "vox: {} is wired to node {name}; start a new {} session",
        h.name, h.name
    );
    Ok(())
}

/// The app has made and kept the node using its secure fields. Finish only the harness wiring;
/// this secret-free child command cannot make, attach, select or unlock a node.
pub(crate) async fn finish(
    args: &NodeArgs,
    key: &str,
    name: &str,
    check_only: bool,
) -> Result<(), AppError> {
    if crate::coord::agent_marked() {
        return Err(AppError::Usage(
            "only the person in Vox.app or their own terminal can finish node setup".into(),
        ));
    }
    let h = harness(key)?;
    let name = NodeName::parse(name)?;
    let account = args.account()?;
    let wiring = Wiring::of(h.key)?;
    if let Some(wired) = crate::setup::connected(&account, &wiring) {
        if wired != name {
            return Err(AppError::Usage(format!(
                "{} is already set up as node {wired}; left unchanged",
                h.name
            )));
        }
    }
    let codex = if h.key == "codex" {
        Some(crate::setup::on_path(h.program).ok_or_else(|| {
            AppError::Usage("Codex is not on PATH; install Codex before setting up its node".into())
        })?)
    } else {
        None
    };
    // The app checks the edited name before creating anything. Repeat the same guard above
    // when finishing, so another setup cannot silently replace existing wiring.
    if check_only {
        return Ok(());
    }
    if !account.nodes_on_disk().contains(&name) || !crate::client::attached(&account, &name).await?
    {
        return Err(AppError::Usage(format!(
            "node {name} must already be made and Ready before its hook is wired"
        )));
    }
    for line in wiring.install(&name)? {
        println!("vox: {line}");
    }
    if let Some(program) = codex {
        crate::setup::trust_codex_hook(&program)?;
    }
    println!("vox: {} is wired to Ready node {name}", h.name);
    Ok(())
}
