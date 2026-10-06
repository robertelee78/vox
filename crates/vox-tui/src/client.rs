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

/// Which node a verb acts as, and the account it belongs to.
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
    /// when this command starts the daemon. A daemon already running listens where
    /// it does, and is used.
    ///
    /// This is only where the socket binds. What a node *advertises* is worked out separately by
    /// the reachability ladder — its routable address, a gateway-mapped address when one can be had,
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
        let account = Account::of(self.data_dir.as_deref(), self.config_dir.as_deref())?;
        // **A data root not in v0.3.0's layout is refused before any node is resolved** (#423):
        // every client entry point comes through here, and nothing is written before it.
        vox_core::node::layout::refuse_old_layout(&account)?;
        Ok(account)
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
    /// **An anchors file that names no usable anchor stops nothing**. Each skipped
    /// line is said, then that the file names none, and the verb carries on with what is usable
    /// (perhaps nothing): an anchor only bridges hosts that cannot otherwise reach each other,
    /// so a peer this node can reach directly needs none, and a verb that does need
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
        self.anchor_set_lenient_at(&self.paths()?)
    }

    /// [`Self::anchor_set_lenient`] for the node at `paths`, already resolved: `vox node`'s,
    /// which on an empty data root is made, where [`Self::paths`] would refuse to choose one.
    ///
    /// # Errors
    /// As [`Self::anchor_set`].
    pub fn anchor_set_lenient_at(
        &self,
        paths: &Paths,
    ) -> vox_core::error::Result<(BootstrapSet, Option<vox_core::error::Error>)> {
        let mut set = BootstrapSet::new();
        // The node's anchors file first, then `--anchor` on top (ADR-017 decision 7, M17.4). Both
        // merge into one set rather than one replacing the other: an anchor is additive — more
        // introducers is strictly better reachability — and a person who adds one on the command
        // line almost never means "and forget the one I configured". `vox node` writes its own
        // spec into that file, so a client on the same machine as its anchor needs no flag at
        // all. A line that cannot be used is skipped and said, and the others still count.
        let file = paths.anchors_file();
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

/// The node a verb acts as, in order: the one it names; else the only attached
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
    // An anchor's headless node is no person's or agent's: it holds no room and reads nothing, so
    // a verb acting as a node never picks it unnamed (ADR-026 N-5).
    let person = |n: &NodeName| !is_headless(account, n);
    let attached: Vec<NodeName> = attached_now(account).into_iter().filter(person).collect();
    if let [only] = attached.as_slice() {
        return Ok(only.clone());
    }
    let on_disk: Vec<NodeName> = account.nodes_on_disk().into_iter().filter(person).collect();
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

/// Whether `node` is headless: a key file and no vault, an anchor's.
fn is_headless(account: &Account, node: &NodeName) -> bool {
    let dir = account.node_dir(node);
    !dir.join(vox_core::node::paths::VAULT_FILE).is_file()
        && dir.join(vox_core::node::headless::IDENTITY_FILE).is_file()
}

/// The node `vox node` runs as an anchor (ADR-026 N-5, C-3 for an anchor): the one named; else the
/// only headless node on disk, the one an earlier `vox node` made; else the only node on disk
/// (whose anchor key is then `<name>-anchor`, beside a vault); else `default` on an empty data
/// root, made here; else a refusal listing them.
///
/// # Errors
/// As [`resolve_node`], or the node's paths cannot be made.
pub fn anchor_paths_of(args: &NodeArgs) -> vox_core::error::Result<Paths> {
    let account = args.account()?;
    let headless: Vec<NodeName> = account
        .nodes_on_disk()
        .into_iter()
        .filter(|n| is_headless(&account, n))
        .collect();
    let name = match (args.node.as_deref().map(str::trim), headless.as_slice()) {
        (Some(n), _) if !n.is_empty() => NodeName::parse(n)?,
        (_, [only]) => only.clone(),
        _ => resolve_node(None, &account, true)?,
    };
    Paths::resolve(
        name.as_str(),
        args.data_dir.as_deref(),
        args.config_dir.as_deref(),
    )
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
    Ok(NodeSocket {
        waiting: Some(say_daemon_waiting),
        ..NodeSocket::one_shot(paths.account().socket(), name_of(paths)?)
    })
}

/// What a verb says on stderr, once, when the daemon has not greeted it within a second.
pub const DAEMON_WAITING: &str = "vox: waiting: the vox daemon here has not answered yet — it may \
     be busy (moving or attaching a node) or stopped (Ctrl-Z, which goes on once resumed); this \
     waits up to 10 s";

/// Say [`DAEMON_WAITING`]: a verb waiting on the daemon is never silent.
pub fn say_daemon_waiting() {
    eprintln!("{DAEMON_WAITING}");
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
        // The cause stays named (#191): the OS's reason the connect failed, beside the socket.
        Error::Ipc(IpcHandshake::Unreachable { reason }) => format!(
            "no vox daemon is running for this data root, so node {node} is not attached.\n\
             \x20      Start one:  vox daemon      (or `vox node attach {node}`)\n\
             \x20      Socket: {path} ({reason})"
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

/// Make sure the account's daemon is running, starting it with `listen` and
/// `anchors` when none answers, and waiting for it within its bound.
///
/// **The one place a client starts the daemon** (`vox daemon --detach`'s start).
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
#[derive(Clone)]
pub struct Pass {
    /// `--identity-passphrase` (refused when given).
    pub flag: Option<String>,
    /// `--identity-passphrase-file`.
    pub file: Option<PathBuf>,
}

/// A verb's hold on its node: the connection that holds it, and the socket further
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
    // **Held open until the node is attached**: a daemon this started exits once it has no node
    // and no client (L-8), and making an identity or asking for a passphrase takes longer than
    // its linger. This connection is a client.
    let _alive = DaemonClient::open(&account.socket()).await;
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
        waiting: Some(say_daemon_waiting),
    };
    let client = open(&at).await?;
    // What attaching the node said (a skipped anchors line, carrying on with no anchor), in the
    // person's own terminal as well as the daemon's log (R23, R36): the daemon this verb started
    // writes only to `<data root>/.daemon/log`.
    for note in client.attach_notes() {
        eprintln!("vox: {note}");
    }
    let me = client.me();
    Ok(Held {
        client,
        at: at.attached_only(),
        me,
    })
}

/// Attach this verb's node so that it stays attached after the verb ends, if it is not attached
/// already: `vox up`, whose answer is the daemon's proxy, which runs only while a node is
/// attached (ADR-028 S-5). A hold would let the node go when `vox up` exits, and the proxy with it.
///
/// # Errors
/// No daemon, no identity, a passphrase refused, or the daemon's refusal.
pub async fn attach_to_stay(
    paths: &Paths,
    args: &NodeArgs,
    pass: Pass,
    waiting: Option<&crate::tunnel_cli::Waiting>,
) -> Result<(), AppError> {
    let account = paths.account();
    let node = name_of(paths)?;
    if let Some(w) = waiting {
        w.on("the vox daemon to answer");
    }
    ensure_daemon(&account, args.listen, &args.anchor_specs()).await?;
    // Held open while the passphrase is read: a daemon this started exits as idle otherwise (L-8).
    let mut d = daemon(&account).await?;
    if d.attached
        .iter()
        .any(|n| n.name == node && n.state == NodeState::Attached)
    {
        return Ok(());
    }
    if let Some(w) = waiting {
        w.on("this node's identity passphrase");
    }
    let passphrase = identity_for_attach(paths, pass, false).await?;
    if let Some(w) = waiting {
        w.on("the daemon to attach this node");
    }
    match d
        .request(DaemonRequest::Attach {
            node,
            passphrase: Some(passphrase),
            keep: None,
            rooms: Vec::new(),
            anchors: args.anchor_specs(),
        })
        .await
    {
        Ok(DaemonFrame::Attached(_, notes)) => {
            for note in &notes {
                eprintln!("vox: {note}");
            }
            Ok(())
        }
        Ok(DaemonFrame::Refused(r)) => Err(AppError::Usage(r.to_string())),
        Ok(other) => Err(unexpected_daemon(&other)),
        Err(e) => Err(AppError::Usage(format!("the daemon did not answer: {e}"))),
    }
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
/// `VOX_IDENTITY_PASSPHRASE`), else asked at a terminal, else refused, saying how to give one.
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
    // Asked at a terminal; with none, refused at once saying how to give it (V210-165). An
    // identity made with no passphrase is given one as an empty file or an empty variable.
    crate::tunnel_cli::ask_identity_passphrase().map(Zeroizing::new)
}

/// Create a node's identity in its directory (C-5): the vault and the store, sealed under
/// `passphrase`. Another vox making it at the same moment is said as that.
///
/// # Errors
/// If the identity exists already, or cannot be written.
pub fn create_identity(paths: &Paths, passphrase: &str) -> Result<Digest32, AppError> {
    // The node's own clock, a test step included (V210-64): an identity made here is stamped as
    // the node making it would have stamped it.
    let now = (vox_core::time::clock_with_test_skew())();
    // **A wait is said, once, after a second** (V210-100): another vox making this node's identity
    // holds its directory, and one stopped (Ctrl-Z) holds it until resumed; this one waiting with
    // nothing on the screen looked hung.
    match vox_core::node::profile::Profile::create_noting(
        paths.clone(),
        passphrase.as_bytes(),
        now,
        vox_core::atrest::sek::Argon2Profile::default(),
        &crate::tunnel_cli::say_waiting,
    ) {
        // **Its prekey ring is made with it**, as the node making an identity makes it, so the
        // ring's age is the identity's (V210-77): what a node attaching later keeps up, not
        // something it makes afresh.
        Ok(p) => {
            let signer = p.signer()?;
            let dh_secret = *signer.x25519_identity_secret();
            vox_core::node::prekeys::load_or_create(p.store(), signer, &dh_secret, now)?;
            Ok(p.fingerprint())
        }
        // Waited the whole patience and the holder is still not done: say what holds it and how to
        // find it, never to stop a node — the holder may only be slow, or stopped.
        Err(Error::ProfileBusy) => Err(AppError::Usage(format!(
            "another vox is still using this node's directory, and only one at a time may hold \
             it.\n\x20      It is a command that has not finished (a slow one, or one stopped, \
             e.g. with Ctrl-Z, which goes on once resumed), or the vox daemon, which holds an \
             attached node until it detaches.\n\x20      To see which process it is: lsof {}\n\
             \x20      Run this command again once it is done.",
            paths.profile_dir.display()
        ))),
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

/// Wait on a held connection until the daemon closes it or the node detaches, and say which:
/// a held verb never runs on with nothing behind it.
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

/// What a verb says when its node answered a request with a frame it did not ask for, in words
/// (R36): a detach while the request was in flight (L-3) as that, a node's refusal as its reason,
/// and anything else by the frame's name only. Its fields are never printed: a frame's `Debug`
/// is a struct dump a person cannot act on, and some frames carry room content.
#[must_use]
pub fn unexpected(frame: &Frame) -> AppError {
    AppError::Usage(match frame {
        Frame::NodeDetached { node } => {
            format!("node {node} was detached from the vox daemon, so this stopped")
        }
        Frame::Error { reason } => reason.clone(),
        other => mismatch(&format!("{other:?}")),
    })
}

/// [`unexpected`] for a daemon-level answer.
#[must_use]
pub fn unexpected_daemon(frame: &DaemonFrame) -> AppError {
    AppError::Usage(match frame {
        DaemonFrame::Refused(r) => r.to_string(),
        other => mismatch(&format!("{other:?}")),
    })
}

/// A frame no verb expects here, named by its variant alone: this vox and the daemon disagree
/// about the protocol, which a restart of the daemon on this vox settles.
fn mismatch(debug: &str) -> String {
    let name = debug
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .next()
        .unwrap_or_default();
    format!(
        "the vox daemon answered with {name}, which this command does not expect; if vox was \
         updated, restart the daemon so both are the same version"
    )
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

/// `vox node create <name> [--headless]`: write the node's files here (C-5), sending nothing over
/// the socket.
/// Its passphrase comes from `--passphrase-file`, `VOX_IDENTITY_PASSPHRASE`, or the terminal
/// (asked twice); an empty one is allowed.
///
/// # Errors
/// A bad name, a node that exists, or a passphrase that cannot be had.
pub fn node_create(
    args: &NodeArgs,
    name: &str,
    passphrase_file: Option<PathBuf>,
    headless: bool,
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
    // **A headless node is an anchor's** (ADR-026 N-5, ADR-016): a key file and no vault, so it
    // runs with nobody at a keyboard; it holds no room and can read nothing.
    if headless {
        if passphrase_file.is_some() {
            return Err(AppError::Usage(
                "a headless node has no passphrase: its key is a file only you can read".into(),
            ));
        }
        let fp = vox_core::identity::composite::RootSigner::fingerprint(
            &vox_core::node::headless::load_or_create_identity(&paths)?,
        );
        println!(
            "vox: created headless node {name}; `vox node --node {name}` runs it as an anchor"
        );
        println!("{}", vox_core::node::link::b32_encode(&fp));
        eprintln!("vox: {}", crate::ident::NO_BACKUP);
        return Ok(());
    }
    let passphrase = Zeroizing::new(crate::tunnel_cli::identity_passphrase_for(
        &paths,
        None,
        passphrase_file,
    )?);
    let fp = create_identity(&paths, &passphrase)?;
    println!("vox: created node {name}");
    println!("{}", vox_core::node::link::b32_encode(&fp));
    // On stderr, so stdout stays what a script reads: the name, then the fingerprint.
    eprintln!("vox: {}", crate::ident::NO_BACKUP);
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
    // Held open while the passphrase is read: the daemon this started would otherwise exit as
    // idle before the attach reaches it (L-8).
    let mut d = daemon(&account).await?;
    let file = passphrase_file.clone();
    let _ = paths;
    let passphrase = tokio::task::spawn_blocking(move || attach_passphrase(None, file))
        .await
        .map_err(|e| AppError::Usage(format!("asking for a passphrase: {e}")))??;
    let keep = keep.then(|| match passphrase_file {
        Some(f) => KeepSource::File(absolute(&f)),
        None => KeepSource::None,
    });
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
        Ok(DaemonFrame::Attached(info, notes)) => {
            // What attaching it said, in this terminal: the daemon `vox node attach` started
            // writes only to its log (R23, R36).
            for note in &notes {
                eprintln!("vox: {note}");
            }
            println!("vox: node {} attached{}", info.name, kept(&info));
            Ok(())
        }
        Ok(DaemonFrame::Refused(r)) => Err(AppError::Usage(r.to_string())),
        Ok(other) => Err(crate::client::unexpected_daemon(&other)),
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
        Ok(other) => Err(crate::client::unexpected_daemon(&other)),
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
