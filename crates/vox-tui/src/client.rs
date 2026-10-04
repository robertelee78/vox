//! Every verb is a client of the account's daemon (ADR-026 §4, §5).
//!
//! No verb hosts a node of its own or opens an endpoint of its own (S-3): each resolves the node it
//! acts as (C-3), reaches the daemon's one socket (C-1), and names that node once per connection
//! with a `Use` (C-2).
//!
//! - A **one-shot verb** (`room`, `status`, `share`, `app`, `service`, `trust`, `tunnel close`)
//!   never attaches: its node must be attached already, and the daemon's refusal says how to
//!   attach it (L-2).
//! - A **verb that holds a session** (`serve`, `connect`, `up`, `forward`, `lan up`) starts the
//!   daemon if none answers (S-2), attaches its node implicitly with the passphrase it resolves
//!   here (C-6), and holds it for as long as its first connection is open (L-3, L-7). When the
//!   daemon goes, that connection closes, and the verb exits non-zero saying so.
//! - **Identity creation** stays in the client (C-5): `vox serve`, `vox connect`, `vox id` and
//!   `vox node create` write a new node's files here, then attach it.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Args;
use vox_core::error::{Error, IpcHandshake};
use vox_core::hash::Digest32;
use vox_core::nat::bootstrap::BootstrapSet;
use vox_core::node::daemonipc::{
    AttachMode, DaemonClient, DaemonFrame, DaemonRequest, KeepSource, NodeInfo, NodeState, UseNode,
};
use vox_core::node::ipc::{Frame, IpcClient, NodeSocket};
use vox_core::node::link::{merge_anchor_spec, merge_anchors_file};
use vox_core::node::paths::{Account, NodeName, Paths, DEFAULT_PROFILE};
use zeroize::Zeroizing;

use crate::app::AppError;

/// The default bind address: every interface, kernel-chosen port. The bound address is not what
/// peers are told to dial (see [`NodeArgs::listen`]), so binding broadly is right.
pub const DEFAULT_LISTEN: &str = "0.0.0.0:0";

/// Which node a verb acts as, and the account it belongs to (ADR-026 C-3).
#[derive(Args, Debug, Clone)]
pub struct NodeArgs {
    /// The node to act as. Without it: the only attached node, else the only node on disk.
    #[arg(long, env = "VOX_NODE")]
    pub node: Option<String>,
    /// Data directory root (holds `nodes/<name>/` and the daemon's `.daemon/`).
    #[arg(long, env = "VOX_DATA_DIR")]
    pub data_dir: Option<PathBuf>,
    /// Config directory.
    #[arg(long, env = "VOX_CONFIG_DIR")]
    pub config_dir: Option<PathBuf>,
    /// Address the daemon binds for peer connections (`ip:port`; port 0 picks one), used only
    /// when this command starts the daemon (ADR-026 D-3). A daemon already running listens where
    /// it does, and is used.
    ///
    /// This is only where the socket binds. What a node *advertises* is worked out separately by
    /// the ADR-012 ladder — its routable address, a gateway-mapped address when one can be had,
    /// and loopback — so the wildcard default is correct and needs no configuration.
    #[arg(long, env = "VOX_LISTEN", default_value = DEFAULT_LISTEN)]
    pub listen: SocketAddr,
    /// Optional. An anchor bridges hosts that cannot otherwise reach each other, typically
    /// both behind NAT; peers that can reach each other directly need none. Given as
    /// `<fingerprint>@<multiaddr>` (repeatable; `VOX_ANCHORS` takes a comma-separated list).
    #[arg(long = "anchor", env = "VOX_ANCHORS", value_delimiter = ',')]
    pub anchors: Vec<String>,
}

impl NodeArgs {
    /// The account these flags name, not created.
    ///
    /// # Errors
    /// If neither a flag, the env vars nor `HOME` names a directory.
    pub fn account(&self) -> vox_core::error::Result<Account> {
        Account::of(self.data_dir.as_deref(), self.config_dir.as_deref())
    }

    /// Resolve the node (C-3) for a verb that does not create an identity, and its paths.
    ///
    /// # Errors
    /// No node can be chosen (the error lists the choices), or its paths cannot be made.
    pub fn paths(&self) -> vox_core::error::Result<Paths> {
        self.paths_for(false)
    }

    /// [`Self::paths`] for a verb that creates an identity when there is none (`serve`,
    /// `connect`, `id`, the TUI): with no node at all on disk it is `default` (C-3, step 4).
    ///
    /// # Errors
    /// As [`Self::paths`].
    pub fn paths_creating(&self) -> vox_core::error::Result<Paths> {
        self.paths_for(true)
    }

    fn paths_for(&self, creates: bool) -> vox_core::error::Result<Paths> {
        let account = self.account()?;
        let name = resolve_node(self.node.as_deref(), &account, creates)?;
        Paths::resolve(
            name.as_str(),
            self.data_dir.as_deref(),
            self.config_dir.as_deref(),
        )
    }

    /// The configured anchors, parsed and merged by identity.
    ///
    /// **An anchors file that names no usable anchor stops nothing** (V210-107). Each skipped
    /// line is said, then that the file names none, and the verb carries on with what is usable
    /// (perhaps nothing): an anchor only bridges hosts that cannot otherwise reach each other
    /// (ADR-012), so a peer this node can reach directly needs none, and a verb that does need
    /// one fails where it needs it, saying what it tried. V210-75 refused such a file for every
    /// verb that starts a node, which stopped `vox connect` to a directly reachable host.
    ///
    /// # Errors
    /// A malformed `--anchor`, or a node path that cannot be resolved.
    pub fn anchor_set(&self) -> vox_core::error::Result<BootstrapSet> {
        let (set, unusable) = self.anchor_set_lenient()?;
        if let Some(e) = unusable {
            eprintln!("vox: {e}; carrying on with no anchor");
        }
        Ok(set)
    }

    /// [`Self::anchor_set`], with the note that the anchors file names no usable anchor returned
    /// rather than said, for `vox node`, which words it as an anchor running with none of its own.
    ///
    /// # Errors
    /// As [`Self::anchor_set`].
    pub fn anchor_set_lenient(
        &self,
    ) -> vox_core::error::Result<(BootstrapSet, Option<vox_core::error::Error>)> {
        let mut set = BootstrapSet::new();
        // The node's anchors file first, then `--anchor` on top (ADR-017 decision 7, M17.4). Both
        // merge into one set rather than one replacing the other: an anchor is additive — more
        // introducers is strictly better reachability — and a person who adds one on the command
        // line almost never means "and forget the one I configured". `vox node` writes its own
        // spec into that file, so a client on the same machine as its anchor needs no flag at
        // all. A line that cannot be used is skipped and said, and the others still count.
        let file = self.paths()?.anchors_file();
        let skipped = merge_anchors_file(&mut set, &file)?;
        for line in &skipped {
            eprintln!("vox: {line}");
        }
        // **A file that names nothing usable is not an empty file** (V210-75): with no
        // `--anchor` either, the verb starts with no anchor at all, and says so.
        let unusable = (set.is_empty()
            && !skipped.is_empty()
            && self.anchors.iter().all(|a| a.trim().is_empty()))
        .then(|| vox_core::error::Error::AnchorsFileUnusable {
            path: file.display().to_string(),
            skipped: skipped.len(),
        });
        for spec in &self.anchors {
            if spec.trim().is_empty() {
                continue;
            }
            merge_anchor_spec(&mut set, spec)?;
        }
        Ok((set, unusable))
    }

    /// `--anchor` as given, for a `Use` that may attach the node (the daemon parses them).
    #[must_use]
    pub fn anchor_specs(&self) -> Vec<String> {
        self.anchors
            .iter()
            .filter(|a| !a.trim().is_empty())
            .cloned()
            .collect()
    }
}

/// The node a verb acts as (ADR-026 C-3), in order: the one it names; else the only attached
/// node; else the only node on disk; else `default`, when the data root has no node at all and
/// the verb creates an identity; else a refusal listing the nodes.
///
/// # Errors
/// A name that is not a node's name, or no node can be chosen.
pub fn resolve_node(
    named: Option<&str>,
    account: &Account,
    creates: bool,
) -> vox_core::error::Result<NodeName> {
    if let Some(name) = named.map(str::trim).filter(|n| !n.is_empty()) {
        return NodeName::parse(name);
    }
    if let [only] = attached_now(account).as_slice() {
        return Ok(only.clone());
    }
    let on_disk = account.nodes_on_disk();
    match on_disk.as_slice() {
        [only] => Ok(only.clone()),
        [] if creates => NodeName::parse(DEFAULT_PROFILE),
        [] => Err(Error::NoNodeChosen(format!(
            "there is no node in {} yet; make one: vox node create <name>",
            account.data_root.display()
        ))),
        many => Err(Error::NoNodeChosen(format!(
            "this data root holds several nodes ({}); name one: --node <name> or VOX_NODE",
            many.iter()
                .map(NodeName::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// The nodes the account's daemon has attached, from its hello; none when no daemon answers.
fn attached_now(account: &Account) -> Vec<NodeName> {
    vox_core::node::daemonipc::attached_nodes(&account.socket(), Duration::from_secs(2))
}

/// The node a node's paths are of: the name of its directory.
///
/// # Errors
/// If the directory's name is not a node's name.
pub fn name_of(paths: &Paths) -> Result<NodeName, AppError> {
    let raw = paths
        .profile_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    NodeName::parse(raw).map_err(AppError::from)
}

/// A one-shot verb's socket for the node at `paths` (L-2: it never attaches).
///
/// # Errors
/// As [`name_of`].
pub fn one_shot(paths: &Paths) -> Result<NodeSocket, AppError> {
    Ok(NodeSocket::one_shot(
        paths.account().socket(),
        name_of(paths)?,
    ))
}

/// A connection to `at` as its node, with each way it can fail said for a person: no daemon, a
/// refusal (the node not attached, no such node), a socket that is not this user's.
///
/// # Errors
/// As above.
pub async fn open(at: &NodeSocket) -> Result<IpcClient, AppError> {
    IpcClient::open_at(at).await.map_err(|e| said(at, e))
}

/// A failure to reach the node `at` names, for a person.
pub fn said(at: &NodeSocket, e: Error) -> AppError {
    let node = &at.using.node;
    let path = at.path.display();
    AppError::Usage(match e {
        Error::Ipc(IpcHandshake::Unreachable { .. }) => format!(
            "no vox daemon is running for this data root, so node {node} is not attached.\n\
             \x20      Start one:  vox daemon      (or `vox node attach {node}`)\n\
             \x20      Socket: {path}"
        ),
        Error::Ipc(IpcHandshake::Refused { reason }) => reason,
        Error::Ipc(h @ IpcHandshake::ClosedBeforeHello) => {
            format!(
                "the daemon's socket at {path} accepted, but {h}: it may be stopping. Try again."
            )
        }
        Error::Ipc(h) => format!("{h}. Socket: {path}"),
        other => format!("the daemon at {path} did not answer ({other})"),
    })
}

/// Make sure the account's daemon is running (ADR-026 S-2), starting it with `listen` and
/// `anchors` when none answers, and waiting for it within its bound.
///
/// **The one place a client starts the daemon** (`vox daemon --detach`'s start, #405).
///
/// # Errors
/// If no daemon answers and none could be started.
pub async fn ensure_daemon(
    account: &Account,
    listen: SocketAddr,
    anchors: &[String],
) -> Result<(), AppError> {
    crate::daemon_client::ensure_daemon(account, listen, anchors)
        .await
        .map(|_| ())
}

/// Warn when `--listen` asked for an address the running daemon does not listen on (ADR-026
/// D-3): the flag sets where a daemon binds only when this command starts it.
async fn warn_if_listening_elsewhere(account: &Account, listen: SocketAddr) {
    if listen.to_string() == DEFAULT_LISTEN {
        return;
    }
    let Ok(mut d) = DaemonClient::open(&account.socket()).await else {
        return;
    };
    if let Ok(DaemonFrame::Status(s)) = d.request(DaemonRequest::Status).await {
        if !s.listen.is_empty() && s.listen != listen.to_string() {
            eprintln!(
                "vox: --listen {listen} is not used: the daemon already running listens on {}",
                s.listen
            );
        }
    }
}

/// Where a held verb's identity passphrase comes from, as the command line gave it.
pub struct Pass {
    /// `--identity-passphrase` (refused when given).
    pub flag: Option<String>,
    /// `--identity-passphrase-file`.
    pub file: Option<PathBuf>,
}

/// A verb's hold on its node (ADR-026 L-7): the connection that holds it, and the socket further
/// connections reach it by, which never attach.
pub struct Held {
    /// The holding connection; requests go over it.
    pub client: IpcClient,
    /// For more connections as the same node (a subscription, a proxy): they attach nothing.
    pub at: NodeSocket,
    /// The node's fingerprint.
    pub me: Option<Digest32>,
}

/// Hold the node at `paths` for a verb that holds a session: start the daemon if none answers,
/// create the node's identity here when the verb makes one and there is none, resolve its
/// passphrase when the node is not attached (C-6), and attach it implicitly with a `Use` that
/// holds it (L-2).
///
/// `waiting` is kept on the step it is in, for a stop to say where it was.
///
/// # Errors
/// No daemon, no identity for a verb that makes none, a passphrase that cannot be had, or the
/// daemon's refusal.
pub async fn hold(
    paths: &Paths,
    args: &NodeArgs,
    pass: Pass,
    creates: bool,
    waiting: Option<&crate::tunnel_cli::Waiting>,
) -> Result<Held, AppError> {
    let account = paths.account();
    let node = name_of(paths)?;
    if let Some(w) = waiting {
        w.on("the vox daemon to answer");
    }
    ensure_daemon(&account, args.listen, &args.anchor_specs()).await?;
    warn_if_listening_elsewhere(&account, args.listen).await;
    let attached = DaemonClient::open(&account.socket())
        .await
        .map(|d| {
            d.attached
                .iter()
                .any(|n| n.name == node && n.state == NodeState::Attached)
        })
        .unwrap_or(false);
    let passphrase = if attached {
        None
    } else {
        if let Some(w) = waiting {
            w.on("this node's identity passphrase");
        }
        Some(identity_for_attach(paths, pass, creates).await?)
    };
    if let Some(w) = waiting {
        w.on("the daemon to attach this node");
    }
    let at = NodeSocket {
        path: account.socket(),
        using: UseNode {
            node: node.clone(),
            attach: AttachMode::Hold,
            passphrase,
            anchors: args.anchor_specs(),
        },
    };
    let client = open(&at).await?;
    let me = client.me();
    Ok(Held {
        client,
        at: at.attached_only(),
        me,
    })
}

/// The identity passphrase a node needs to attach: given, or asked for. For a verb that makes an
/// identity and a node with none, the identity is created here first (C-5), with a passphrase
/// asked twice at a terminal.
async fn identity_for_attach(
    paths: &Paths,
    pass: Pass,
    creates: bool,
) -> Result<Zeroizing<String>, AppError> {
    let paths = paths.clone();
    tokio::task::spawn_blocking(move || {
        let exists = vox_core::node::profile::Profile::exists(&paths);
        if !exists && !creates {
            let node = name_of(&paths)?;
            return Err(AppError::Usage(format!(
                "node {node} has no identity yet; make one: vox node create {node}"
            )));
        }
        if exists {
            return attach_passphrase(pass.flag, pass.file);
        }
        let passphrase = Zeroizing::new(crate::tunnel_cli::identity_passphrase_for(
            &paths, pass.flag, pass.file,
        )?);
        create_identity(&paths, &passphrase)?;
        Ok(passphrase)
    })
    .await
    .map_err(|e| AppError::Usage(format!("asking for a passphrase: {e}")))?
}

/// The passphrase an existing node is attached with: given (`--identity-passphrase-file`,
/// `VOX_IDENTITY_PASSPHRASE`), else asked at a terminal, else none — the empty passphrase a node
/// made without one opens with (V030-36); for any other the daemon's refusal says it was wrong.
///
/// # Errors
/// The refused flag, or a file that cannot be read.
pub fn attach_passphrase(
    flag: Option<String>,
    file: Option<PathBuf>,
) -> Result<Zeroizing<String>, AppError> {
    if let Some(p) = crate::tunnel_cli::identity_passphrase_given(flag, file)? {
        return Ok(Zeroizing::new(p));
    }
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return crate::tunnel_cli::ask_identity_passphrase().map(Zeroizing::new);
    }
    Ok(Zeroizing::new(String::new()))
}

/// Create a node's identity in its directory (C-5): the vault and the store, sealed under
/// `passphrase`. Another vox making it at the same moment is said as that.
///
/// # Errors
/// If the identity exists already, or cannot be written.
pub fn create_identity(paths: &Paths, passphrase: &str) -> Result<Digest32, AppError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    match vox_core::node::profile::Profile::create(paths.clone(), passphrase.as_bytes(), now) {
        Ok(p) => Ok(p.fingerprint()),
        Err(Error::Profile(why)) if why.contains("already exists") => Err(AppError::Usage(
            "another vox created this node's identity at the same time; nothing was created \
             here.\n\x20      Run `vox id` again to see the identity it made."
                .into(),
        )),
        // Said as the node said it when it made identities itself: the identity file, the store,
        // or another vox holding the node, in plain words with what to do — never the raw path
        // error ("profile path write the identity file: …").
        Err(e) => match vox_core::node::actor::fault_of(&e) {
            f @ (vox_core::node::api::Fault::IdentityFileUnwritable
            | vox_core::node::api::Fault::Storage
            | vox_core::node::api::Fault::ProfileBusy) => Err(AppError::Usage(f.to_string())),
            _ => Err(e.into()),
        },
    }
}

/// Wait on a held connection until the daemon closes it or the node detaches, and say which
/// (ADR-026 L-7): a held verb never runs on with nothing behind it.
pub async fn hold_until_closed(client: &mut IpcClient) -> AppError {
    loop {
        match client.next().await {
            Ok(Some(Frame::NodeDetached { node })) => {
                return AppError::Usage(format!(
                    "node {node} was detached from the vox daemon, so this stopped"
                ))
            }
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                return AppError::Usage(
                    "the vox daemon stopped, so this stopped with it".to_owned(),
                )
            }
        }
    }
}

/// A connection's subscription to its node's events, as the node it holds; `None`, having said
/// why, when none could be had.
pub async fn events(at: &NodeSocket) -> Result<IpcClient, AppError> {
    let mut c = open(at).await?;
    c.subscribe()
        .await
        .map_err(|e| AppError::Usage(format!("cannot follow the node's events: {e}")))?;
    Ok(c)
}

// ---- vox node create | attach | detach | list ---------------------------------------------------

/// `vox node create <name>`: write the node's files here (C-5), sending nothing over the socket.
/// Its passphrase comes from `--passphrase-file`, `VOX_IDENTITY_PASSPHRASE`, or the terminal
/// (asked twice); an empty one is allowed (V030-36).
///
/// # Errors
/// A bad name, a node that exists, or a passphrase that cannot be had.
pub fn node_create(
    args: &NodeArgs,
    name: &str,
    passphrase_file: Option<PathBuf>,
) -> Result<(), AppError> {
    let name = NodeName::parse(name)?;
    let account = args.account()?;
    if account.nodes_on_disk().contains(&name) {
        return Err(AppError::Usage(format!(
            "there is a node {name} already; `vox node list` lists them"
        )));
    }
    let paths = Paths::resolve(
        name.as_str(),
        args.data_dir.as_deref(),
        args.config_dir.as_deref(),
    )?;
    let passphrase = Zeroizing::new(crate::tunnel_cli::identity_passphrase_for(
        &paths,
        None,
        passphrase_file,
    )?);
    let fp = create_identity(&paths, &passphrase)?;
    println!("vox: created node {name}");
    println!("{}", vox_core::node::link::b32_encode(&fp));
    Ok(())
}

/// `vox node attach <name> [--keep] [--passphrase-file]`: start the daemon if none answers, and
/// attach the node by hand (L-2), until `vox node detach` or the daemon stops.
///
/// # Errors
/// No daemon, a passphrase that cannot be had, or the daemon's refusal.
pub async fn node_attach(
    args: &NodeArgs,
    name: &str,
    keep: bool,
    passphrase_file: Option<PathBuf>,
) -> Result<(), AppError> {
    let name = NodeName::parse(name)?;
    let account = args.account()?;
    if !account.nodes_on_disk().contains(&name) {
        return Err(AppError::Usage(format!(
            "there is no node {name}; make one: vox node create {name}"
        )));
    }
    let paths = Paths::resolve(
        name.as_str(),
        args.data_dir.as_deref(),
        args.config_dir.as_deref(),
    )?;
    ensure_daemon(&account, args.listen, &args.anchor_specs()).await?;
    let file = passphrase_file.clone();
    let _ = paths;
    let passphrase = tokio::task::spawn_blocking(move || attach_passphrase(None, file))
        .await
        .map_err(|e| AppError::Usage(format!("asking for a passphrase: {e}")))??;
    let keep = keep.then(|| match passphrase_file {
        Some(f) => KeepSource::File(absolute(&f)),
        None => KeepSource::None,
    });
    let mut d = daemon(&account).await?;
    match d
        .request(DaemonRequest::Attach {
            node: name.clone(),
            passphrase: Some(passphrase),
            keep,
            rooms: Vec::new(),
            anchors: args.anchor_specs(),
        })
        .await
    {
        Ok(DaemonFrame::Attached(info)) => {
            println!("vox: node {} attached{}", info.name, kept(&info));
            Ok(())
        }
        Ok(DaemonFrame::Refused(r)) => Err(AppError::Usage(r.to_string())),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(format!("the daemon did not answer: {e}"))),
    }
}

/// `vox node detach <name>`: detach it (L-3); its connections close and its keys are wiped.
///
/// # Errors
/// No daemon, or the daemon's refusal.
pub async fn node_detach(args: &NodeArgs, name: &str) -> Result<(), AppError> {
    let name = NodeName::parse(name)?;
    let account = args.account()?;
    let mut d = daemon(&account).await?;
    match d
        .request(DaemonRequest::Detach { node: name.clone() })
        .await
    {
        Ok(DaemonFrame::Ok) => {
            println!("vox: node {name} detached");
            Ok(())
        }
        Ok(DaemonFrame::Refused(r)) => Err(AppError::Usage(r.to_string())),
        Ok(other) => Err(AppError::Usage(format!("unexpected reply: {other:?}"))),
        Err(e) => Err(AppError::Usage(format!("the daemon did not answer: {e}"))),
    }
}

/// `vox node list`: every node on disk, with what the daemon says of each, if one runs.
///
/// # Errors
/// If the account cannot be resolved.
pub async fn node_list(args: &NodeArgs) -> Result<(), AppError> {
    let account = args.account()?;
    let running: Vec<NodeInfo> = match DaemonClient::open(&account.socket()).await {
        Ok(mut d) => match d.request(DaemonRequest::Nodes).await {
            Ok(DaemonFrame::Nodes(n)) => n,
            _ => d.attached.clone(),
        },
        Err(_) => Vec::new(),
    };
    let mut names: Vec<NodeName> = account.nodes_on_disk();
    for n in &running {
        if !names.contains(&n.name) {
            names.push(n.name.clone());
        }
    }
    names.sort();
    if names.is_empty() {
        println!("vox: no node yet; make one: vox node create <name>");
        return Ok(());
    }
    for name in names {
        let info = running.iter().find(|n| n.name == name);
        let state = match info.map(|i| i.state) {
            Some(NodeState::Attached) => "attached",
            Some(NodeState::Attaching) => "attaching",
            Some(NodeState::Detaching) => "detaching",
            Some(NodeState::Detached) | None => "detached",
        };
        let fp = info
            .and_then(|i| i.fingerprint)
            .map(|f| vox_core::node::link::b32_encode(&f))
            .unwrap_or_default();
        let how = info.map(kept).unwrap_or_default();
        println!("{name:<24} {state:<10} {fp}{how}");
    }
    Ok(())
}

/// The daemon, or why there is none.
async fn daemon(account: &Account) -> Result<DaemonClient, AppError> {
    DaemonClient::open(&account.socket()).await.map_err(|e| {
        AppError::Usage(format!(
            "no vox daemon answers at {} ({e}); start one: vox daemon",
            account.socket().display()
        ))
    })
}

/// How a node stays attached, as `vox node` lists it.
fn kept(info: &NodeInfo) -> String {
    match (info.state, info.keep, info.implicit) {
        (_, true, _) => " (kept)".into(),
        (NodeState::Attached, false, true) => " (held)".into(),
        _ => String::new(),
    }
}

/// `path` made absolute, as the daemon reads a kept node's passphrase file from its own directory.
fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_owned();
    }
    std::env::current_dir().map_or_else(|_| path.to_owned(), |d| d.join(path))
}
