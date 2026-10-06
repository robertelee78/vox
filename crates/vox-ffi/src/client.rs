//! **The daemon's client, for the macOS app** (ADR-014 M-2–M-5).
//!
//! Vox.app hosts no node: it is a client of the account's daemon, like the TUI and every `vox`
//! verb, and it speaks the daemon's protocol through `vox-core`'s own client
//! ([`DaemonClient`], [`IpcClient`]), never a second implementation of it in Swift. [`VoxClient`]
//! is that client over UniFFI.
//!
//! What crosses into Swift is rendered state only (M-5): text for display, names, fingerprints
//! and room ids as base32, counts. No key, sender key or room secret has a type here. A
//! passphrase goes in as a [`Passphrase`]: an opaque handle on a buffer that is wiped when it is
//! dropped, made from bytes, so Swift never holds one as a `String` (M-3).
//!
//! Every failure is the daemon's own sentence (M-7): a refusal's words, a node's reason, or what
//! went wrong reaching the daemon, said for a person.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::runtime::{Handle, Runtime};
use vox_core::error::{Error, IpcHandshake};
use vox_core::hash::Digest32;
use vox_core::node::api::{MessageRow, NodeEvent};
use vox_core::node::daemonipc::{
    AttachMode, DaemonClient, DaemonFrame, DaemonRequest, KeepSource, NodeName, NodeState, UseNode,
};
use vox_core::node::ipc::{Frame, IpcClient, NodeSocket, Request};
use vox_core::node::link::b32_encode;
use vox_core::node::paths::Account;
use vox_core::node::resolver::ShareState;
use zeroize::Zeroizing;

use crate::{digest, failed, VoxError};

/// A passphrase, held by Rust in a buffer that is wiped when it is dropped or [`Passphrase::wipe`]d.
///
/// Swift makes one from the bytes it has (a secure field's, or the Keychain's `Data`) and passes the
/// handle; it never gets the text back. One handle may be passed more than once, for an attach and
/// then a keyring change within the window.
#[derive(uniffi::Object)]
pub struct Passphrase(Mutex<Zeroizing<String>>);

#[uniffi::export]
impl Passphrase {
    /// A passphrase from its UTF-8 bytes.
    ///
    /// # Errors
    /// Bytes that are not UTF-8.
    #[uniffi::constructor]
    pub fn new(bytes: Vec<u8>) -> Result<Arc<Self>, VoxError> {
        match String::from_utf8(bytes) {
            Ok(text) => Ok(Arc::new(Self(Mutex::new(Zeroizing::new(text))))),
            Err(e) => {
                // Wiped here too: the bytes were most of a passphrase.
                drop(Zeroizing::new(e.into_bytes()));
                Err(failed("a passphrase must be text (UTF-8)"))
            }
        }
    }

    /// Wipe it now; it is the empty passphrase afterwards.
    pub fn wipe(&self) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Zeroizing::new(String::new());
    }
}

impl Passphrase {
    /// A copy for one request, itself wiped when dropped.
    fn copy(&self) -> Zeroizing<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

fn copy_of(p: Option<&Arc<Passphrase>>) -> Zeroizing<String> {
    p.map_or_else(|| Zeroizing::new(String::new()), |p| p.copy())
}

/// A node on this machine, as the daemon lists it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct NodeSummary {
    /// Its name.
    pub name: String,
    /// `detached`, `attaching`, `attached` or `detaching`.
    pub state: String,
    /// Its identity fingerprint, base32; empty until the daemon knows it.
    pub fingerprint: String,
    /// Attached with `--keep`: attached again whenever the daemon starts.
    pub keep: bool,
}

/// A room the acting node holds.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RoomSummary {
    /// The room's id, base32.
    pub id: String,
    /// This device's name for it.
    pub name: String,
    /// Whether its key is unlocked now.
    pub open: bool,
    /// Empty while the room goes on; else, in words, that this node left it or it ended.
    pub over: String,
}

/// One message, rendered.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RoomMessage {
    /// The entry's hash, base32: the read cursor, and what a reply's `re` names.
    pub id: String,
    /// Its author's fingerprint, base32.
    pub author: String,
    /// This node's name for its author, from the keyring; empty when it has none.
    pub author_name: String,
    /// When its author sent it, milliseconds since the Unix epoch.
    pub created_millis: u64,
    /// The message's type: `say` for what a person types.
    pub kind: String,
    /// The text, with every character that would hide or reorder what it says shown as an escape.
    pub text: String,
    /// The members it is addressed to, as whole fingerprints; empty addresses the room.
    pub to: Vec<String>,
    /// The message it answers, or empty.
    pub re: String,
    /// Whether its author marked it urgent.
    pub urgent: bool,
    /// It took its place above messages already shown.
    pub late: bool,
    /// Its body has not been received yet.
    pub owed: bool,
    /// What it is to this node while unread (ADR-028 R-8), by the rule the TUI counts by.
    pub level: UnreadLevel,
    /// The file or folder it shares, when it is a share's announcement (ADR-028 F-1): the message
    /// is its card, its text the note.
    pub file: Option<FileOffer>,
}

/// What a share's announcement offers, as its signed envelope states it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FileOffer {
    /// The name it is offered under.
    pub name: String,
    /// Its size in bytes.
    pub size: u64,
    /// Its SHA-256, hex.
    pub sha256: String,
    /// A folder, served as one archive.
    pub folder: bool,
    /// The sharer's note, or empty.
    pub note: String,
}

/// One member's lane in a room (ADR-028 W-3): its state, derived by the node from what the room
/// carries.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Lane {
    /// The member's fingerprint, base32.
    pub fingerprint: String,
    /// This node's name for it, from the keyring; empty when it has none.
    pub name: String,
    /// `needs you`, `working`, `ready`, `done` or `away`, as `vox room board` says it.
    pub state: String,
}

/// One event of this node's decision record (ADR-028 §7): what it decided, about whom, and why,
/// in its own words; never message text, a file name, a passphrase or a key.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DecisionEvent {
    /// When, milliseconds since the Unix epoch.
    pub at_millis: u64,
    /// What was asked: "to join a room", "a tunnel to a service", …
    pub asked: String,
    /// Who asked, or whom it was about: a fingerprint, base32.
    pub by: String,
    /// This node's name for them when it was decided; empty when it had none.
    pub alias: String,
    /// `refused`, `trusted`, `untrusted`, `cut` or `stopped`.
    pub decided: String,
    /// Why, in this node's words.
    pub why: String,
    /// The room it concerns, by its ID; empty for a decision about no room.
    pub room: String,
}

/// Who has read one of this node's own messages (ADR-028 R-6).
#[derive(Debug, Clone, uniffi::Record)]
pub struct ReadBy {
    /// The message's id.
    pub id: String,
    /// This node's names for the members who read it, sorted; a fingerprint's first 12
    /// characters for one it has no name for.
    pub names: Vec<String>,
}

/// **The three unread levels** (ADR-028 R-8): what one unread message is to this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum UnreadLevel {
    /// Addressed to this node.
    ToYou,
    /// New, to the room.
    New,
    /// Coordination traffic, counted only (ADR-020 6.6).
    Coordination,
}

/// **What a room needs from the person** (ADR-028 W-2): the sidebar's groups, in the order it
/// lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RoomGroup {
    /// A message addressed to this node is unread.
    NeedsYou,
    /// New messages are unread.
    Active,
    /// Nothing is unread.
    Quiet,
}

/// The account's config directory for the data root `data_root` (empty: the default one), as
/// `vox` finds it: what a client keeps its own choices in, readable before any daemon answers.
///
/// # Errors
/// The data root cannot be found.
#[uniffi::export]
pub fn config_dir(data_root: String) -> Result<String, VoxError> {
    let root = (!data_root.is_empty()).then(|| PathBuf::from(&data_root));
    Account::of(root.as_deref(), None)
        .map(|a| a.config_dir.display().to_string())
        .map_err(|e| failed(format!("data root: {e}")))
}

/// The group a room's unread counts, by [`UnreadLevel`], put it in: the TUI's rule
/// (`vox_agentcomms::attention::group`).
#[uniffi::export]
#[must_use]
pub fn room_group(to_you: u32, new: u32, coordination: u32) -> RoomGroup {
    use vox_agentcomms::attention::{group, RoomGroup as G};
    match group(to_you as usize, new as usize, coordination as usize) {
        G::NeedsYou => RoomGroup::NeedsYou,
        G::Active => RoomGroup::Active,
        G::Quiet => RoomGroup::Quiet,
    }
}

/// The group, as the sidebar heads it: the TUI's words.
#[uniffi::export]
#[must_use]
pub fn room_group_words(group: RoomGroup) -> String {
    use vox_agentcomms::attention::RoomGroup as G;
    match group {
        RoomGroup::NeedsYou => G::NeedsYou,
        RoomGroup::Active => G::Active,
        RoomGroup::Quiet => G::Quiet,
    }
    .label()
    .to_owned()
}

/// A member of a room.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Member {
    /// Its fingerprint, base32.
    pub fingerprint: String,
    /// This node's name for it, from the keyring; empty when it has none.
    pub name: String,
}

/// An entry of the trust keyring.
#[derive(Debug, Clone, uniffi::Record)]
pub struct TrustedNode {
    /// Its fingerprint, base32.
    pub fingerprint: String,
    /// The name it was trusted under.
    pub name: String,
}

/// A room link and what it carries.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RoomLink {
    /// The `vox://` address.
    pub url: String,
    /// What it carries, in words; empty when there is nothing to say.
    pub note: String,
}

/// What is shared in a room, and what this node offers there, as `vox service list` says it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RoomServices {
    /// The room's local name.
    pub room: String,
    /// What every member shares there.
    pub shared: Vec<SharedService>,
    /// The services this node offers there.
    pub offered: Vec<OfferedService>,
}

/// A service a member shares in a room.
#[derive(Debug, Clone, uniffi::Record)]
pub struct SharedService {
    /// Its readable address, `<service>.<node>.<room>.vox` in this node's own aliases: for
    /// showing only (ADR-028 S-1a).
    pub address: String,
    /// Its canonical address, every part an identifier (ADR-028 S-1): what a copy or a message
    /// carries, so it reaches the same service on any member's machine.
    pub canonical: String,
    /// Who shares it: this node's name for them, or `you`.
    pub by: String,
    /// Whether it carries datagrams.
    pub udp: bool,
    /// What its sharer's node detected it to be (ADR-028 S-2).
    pub kind: String,
}

/// A service this node offers in a room.
#[derive(Debug, Clone, uniffi::Record)]
pub struct OfferedService {
    /// Its tag.
    pub tag: String,
    /// The local endpoint connections are carried to.
    pub local: String,
}

/// A file or folder this node shares, as `vox share list` shows it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FileShare {
    /// The room-bound service it is served on.
    pub tag: String,
    /// The name it is announced under.
    pub name: String,
    /// Its size in bytes.
    pub size: u64,
    /// Its SHA-256, hex.
    pub sha256: String,
    /// The announcement's message id, or empty if the daemon did not see it land.
    pub entry: String,
    /// Completed fetches since this node started serving it.
    pub fetched: u64,
}

/// A share this node pulled by itself and verified (ADR-028 F-3, F-4).
#[derive(Debug, Clone, uniffi::Record)]
pub struct PulledFile {
    /// The announcement's message id.
    pub entry: String,
    /// Where the verified copy is, under the node's files directory.
    pub path: String,
    /// When it was announced, seconds since the Unix epoch.
    pub created: u64,
}

fn file_share(row: vox_core::node::shares::ShareRow) -> FileShare {
    FileShare {
        tag: row.tag,
        name: shown_name(&row.name),
        size: row.size,
        sha256: row.sha256,
        entry: row.entry,
        fetched: row.fetched,
    }
}

/// Who reads whom in a room: both directions of trust, off the room's log.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RoomConsents {
    /// The members this node consents to reading it, as fingerprints.
    pub outbound: Vec<String>,
    /// The members that consent to this node reading them, as fingerprints.
    pub inbound: Vec<String>,
}

/// The node at a glance, as a client draws it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct NodeView {
    /// Its fingerprint, base32.
    pub me: String,
    /// How many peers it holds a connection to now.
    pub peers: u32,
    /// The keyring window, as the TUI's status bar says it (ADR-028 K-9).
    pub keyring: String,
}

/// What the app hears from the node it acts as.
#[uniffi::export(with_foreign)]
pub trait ClientListener: Send + Sync {
    /// A message became readable in `room`. Each is delivered once; a room's messages that were
    /// readable when [`VoxClient::subscribe`] was called are not delivered (`read` has them).
    fn on_message(&self, room: String, message: RoomMessage);
    /// Anything else the node reports, as a sentence.
    fn on_notice(&self, text: String);
    /// The node was detached, or the daemon stopped: nothing more will come. Said as a sentence.
    fn on_ended(&self, text: String);
}

/// The node this client holds attached, and the connection its requests go over.
struct Held {
    node: NodeName,
    client: IpcClient,
    /// For further connections as the same node; they attach nothing.
    at: NodeSocket,
    /// The forwards this app made, by the address each is bound at: each on a connection of its
    /// own, which carries it until it is stopped or the node is let go of.
    forwards: HashMap<String, IpcClient>,
    /// The family LANs this app runs, by room: each on a connection of its own, which runs it
    /// until it is stopped or the node is let go of.
    lans: HashMap<Digest32, Lan>,
}

/// A family LAN the app runs: dropping `stop` closes its connection, and the daemon takes the LAN
/// down.
struct Lan {
    stop: tokio::sync::oneshot::Sender<()>,
    said: Arc<Mutex<Vec<String>>>,
}

type Slot = Arc<tokio::sync::Mutex<Option<Held>>>;

/// A client of the account's vox daemon.
#[derive(uniffi::Object)]
pub struct VoxClient {
    runtime: Mutex<Option<Runtime>>,
    rt: Handle,
    socket: PathBuf,
    /// The account's data root and config directory: where each node's pulled files and pull
    /// records are.
    data_root: PathBuf,
    config_dir: PathBuf,
    held: Slot,
    /// A connection to the daemon, kept while the client lives: a daemon a client started exits
    /// once no node is attached and no client is connected (ADR-026 L-8), and the app is its
    /// client from the moment it opens, before any node is attached.
    daemon_hold: Mutex<Option<DaemonClient>>,
}

/// A failure to reach the daemon, said for a person.
fn said(socket: &std::path::Path, e: Error) -> VoxError {
    let path = socket.display();
    failed(match e {
        Error::Ipc(IpcHandshake::Unreachable { reason }) => {
            format!("no vox daemon is running for this data root ({path}: {reason})")
        }
        Error::Ipc(IpcHandshake::Refused { reason }) => reason,
        Error::Ipc(h @ IpcHandshake::ClosedBeforeHello) => {
            format!("the vox daemon accepted, but {h}: it may be stopping. Try again.")
        }
        Error::Ipc(h) => format!("{h} ({path})"),
        other => format!("the vox daemon at {path} did not answer ({other})"),
    })
}

/// A node's answer, with its refusal and a detach as errors.
fn answered(frame: Frame) -> Result<Frame, VoxError> {
    match frame {
        Frame::NodeDetached { node } => Err(VoxError::Detached {
            reason: format!("node {node} was detached from the vox daemon"),
        }),
        Frame::Error { reason } => Err(failed(reason)),
        other => Ok(other),
    }
}

/// An answer no request expects here, named by its variant only: frames carry room content.
fn unexpected(frame: &Frame) -> VoxError {
    let debug = format!("{frame:?}");
    let name = debug
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .next()
        .unwrap_or_default()
        .to_owned();
    failed(format!(
        "the vox daemon answered with {name}, which this app does not expect; if vox was updated, \
         restart the daemon so both are the same version"
    ))
}

fn not_attached() -> VoxError {
    failed("no node is attached in this app yet")
}

/// Shown, never laid out: a name another party chose.
fn shown_name(s: &str) -> String {
    vox_agentcomms::envelope::reveal_keeping(s, |_| false)
}

fn rendered(row: &MessageRow, names: &HashMap<Digest32, String>, me: Option<&str>) -> RoomMessage {
    use vox_agentcomms::attention::{unread_level, UnreadLevel as L};
    let reveal = |s: &str| vox_agentcomms::envelope::reveal_keeping(s, |c| c == '\n' || c == '\t');
    let (kind, text, to, re, urgent, file) =
        match vox_agentcomms::envelope::Envelope::parse(&row.text) {
            Ok(env) => (
                shown_name(&env.kind),
                reveal(&env.body),
                env.to.iter().map(|t| shown_name(t)).collect(),
                env.re.as_deref().map(shown_name).unwrap_or_default(),
                env.urgent,
                file_offer(&env),
            ),
            Err(_) => (
                vox_agentcomms::envelope::SAY.to_owned(),
                reveal(&row.text),
                Vec::new(),
                String::new(),
                false,
                None,
            ),
        };
    RoomMessage {
        id: b32_encode(&row.entry_hash),
        author: b32_encode(&row.author),
        author_name: names.get(&row.author).cloned().unwrap_or_default(),
        created_millis: row.created_millis,
        kind,
        text,
        to,
        re,
        urgent,
        late: row.late,
        owed: row.owed,
        level: match unread_level(&row.text, me) {
            L::ToYou => UnreadLevel::ToYou,
            L::New => UnreadLevel::New,
            L::Coordination => UnreadLevel::Coordination,
        },
        file,
    }
}

/// The file a `file` envelope offers, from the fields its sharer's daemon filled in.
fn file_offer(env: &vox_agentcomms::envelope::Envelope) -> Option<FileOffer> {
    if env.kind != vox_core::node::shares::FILE {
        return None;
    }
    let d = &env.data;
    let text = |k: &str| d.get(k).and_then(|v| v.as_str()).map(shown_name);
    Some(FileOffer {
        name: text("name")?,
        size: d.get("size").and_then(|v| v.as_u64())?,
        sha256: text("sha256")?,
        folder: text("kind").as_deref() == Some("folder"),
        note: text("note").unwrap_or_default(),
    })
}

/// The keyring's names, by fingerprint. A read: the node checks no passphrase.
async fn names(client: &mut IpcClient) -> Result<HashMap<Digest32, String>, VoxError> {
    match answered(
        client
            .trusted("")
            .await
            .map_err(|e| failed(e.to_string()))?,
    )? {
        Frame::Trusted { entries } => Ok(entries
            .into_iter()
            .map(|(fp, name)| (fp, shown_name(&name)))
            .collect()),
        other => Err(unexpected(&other)),
    }
}

async fn room_ids(
    client: &mut IpcClient,
) -> Result<Vec<(Digest32, String, bool, String)>, VoxError> {
    match answered(client.rooms().await.map_err(|e| failed(e.to_string()))?)? {
        Frame::Rooms { rooms } => Ok(rooms),
        other => Err(unexpected(&other)),
    }
}

/// Send `req` and read its answer, as a refusal or a detach where it is one.
async fn ask(client: &mut IpcClient, req: &Request) -> Result<Frame, VoxError> {
    answered(
        client
            .request(req)
            .await
            .map_err(|e| failed(format!("the vox daemon stopped answering: {e}")))?,
    )
}

async fn done(client: &mut IpcClient, req: &Request) -> Result<(), VoxError> {
    match ask(client, req).await? {
        Frame::Ok => Ok(()),
        other => Err(unexpected(&other)),
    }
}

/// The texts up the `re` chain from entry `re`, by entry hash, fetched one at a time
/// (`Request::Find`), at most [`vox_agentcomms::envelope::DEFAULT_HOPS`] + 1 of them.
async fn reply_chain(
    client: &mut IpcClient,
    channel_id: Digest32,
    re: &str,
) -> Result<HashMap<Digest32, String>, VoxError> {
    let mut chain = HashMap::new();
    let mut next = vox_core::node::link::b32_decode(re.trim(), "re").ok();
    while let Some(hash) = next.take() {
        if chain.len() > vox_agentcomms::envelope::DEFAULT_HOPS as usize {
            break;
        }
        let req = Request::Find {
            channel_id,
            entries: vec![hash],
        };
        let rows = match ask(client, &req).await? {
            Frame::Rows { rows } => rows,
            other => return Err(unexpected(&other)),
        };
        let Some(row) = rows.into_iter().find(|r| r.entry_hash == hash) else {
            break;
        };
        next = vox_agentcomms::envelope::Envelope::parse(&row.text)
            .ok()
            .and_then(|e| e.re)
            .and_then(|r| vox_core::node::link::b32_decode(r.trim(), "re").ok())
            .filter(|h| !chain.contains_key(h));
        chain.insert(hash, row.text);
    }
    Ok(chain)
}

/// Run `$body` on the client's runtime with `$c` the held node's connection.
macro_rules! on_held {
    ($self:ident, |$c:ident| $body:expr) => {{
        let held = Arc::clone(&$self.held);
        $self
            .on_rt(async move {
                let mut slot = held.lock().await;
                let $c = &mut slot.as_mut().ok_or_else(not_attached)?.client;
                $body
            })
            .await
    }};
}

impl VoxClient {
    /// Run `fut` on the client's runtime and await it from the caller's executor.
    async fn on_rt<T, F>(&self, fut: F) -> Result<T, VoxError>
    where
        T: Send + 'static,
        F: std::future::Future<Output = Result<T, VoxError>> + Send + 'static,
    {
        self.rt
            .spawn(fut)
            .await
            .map_err(|_| failed("the app's connection to vox stopped"))?
    }

    async fn daemon(&self, req: DaemonRequest) -> Result<DaemonFrame, VoxError> {
        let socket = self.socket.clone();
        self.on_rt(async move {
            let mut d = DaemonClient::open(&socket)
                .await
                .map_err(|e| said(&socket, e))?;
            match d.request(req).await {
                Ok(DaemonFrame::Refused(r)) => Err(failed(r.to_string())),
                Ok(f) => Ok(f),
                Err(e) => Err(said(&socket, e)),
            }
        })
        .await
    }

    /// A room created or joined: the one in `after` that was not in `before`.
    async fn new_room(
        &self,
        before: Vec<Digest32>,
        what: &'static str,
    ) -> Result<String, VoxError> {
        let rooms = on_held!(self, |c| room_ids(c).await)?;
        rooms
            .iter()
            .find(|r| !before.contains(&r.0))
            .map(|r| b32_encode(&r.0))
            .ok_or_else(|| failed(format!("{what}, but the room is not listed")))
    }

    async fn room_list(&self) -> Result<Vec<Digest32>, VoxError> {
        Ok(on_held!(self, |c| room_ids(c).await)?
            .into_iter()
            .map(|r| r.0)
            .collect())
    }
}

#[uniffi::export]
impl VoxClient {
    /// A client of the vox daemon for the data root `data_root` (empty: the default one).
    ///
    /// # Errors
    /// No daemon answers there, the socket is not this user's, or the daemon speaks another
    /// protocol version.
    #[uniffi::constructor]
    pub async fn open(data_root: String) -> Result<Arc<Self>, VoxError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("vox-client")
            .enable_all()
            .build()
            .map_err(|e| failed(format!("starting the app's vox runtime: {e}")))?;
        let rt = runtime.handle().clone();
        let root = (!data_root.is_empty()).then(|| PathBuf::from(&data_root));
        let account =
            Account::of(root.as_deref(), None).map_err(|e| failed(format!("data root: {e}")))?;
        let socket = account.socket();
        let probe = socket.clone();
        let hold = rt
            .spawn(async move {
                DaemonClient::open(&probe)
                    .await
                    .map_err(|e| said(&probe, e))
            })
            .await
            .map_err(|_| failed("the app's vox runtime stopped"))??;
        Ok(Arc::new(Self {
            runtime: Mutex::new(Some(runtime)),
            rt,
            socket,
            data_root: account.data_root.clone(),
            config_dir: account.config_dir.clone(),
            held: Arc::new(tokio::sync::Mutex::new(None)),
            daemon_hold: Mutex::new(Some(hold)),
        }))
    }

    /// The account's config directory, where an app keeps its own settings beside vox's
    /// (`VOX_CONFIG_DIR` when set).
    #[must_use]
    pub fn config_dir(&self) -> String {
        self.config_dir.to_string_lossy().into_owned()
    }

    /// The nodes on this machine, as the daemon lists them.
    ///
    /// # Errors
    /// The daemon did not answer.
    pub async fn nodes(&self) -> Result<Vec<NodeSummary>, VoxError> {
        match self.daemon(DaemonRequest::Nodes).await? {
            DaemonFrame::Nodes(infos) => Ok(infos
                .into_iter()
                .map(|n| NodeSummary {
                    name: n.name.to_string(),
                    state: match n.state {
                        NodeState::Detached => "detached",
                        NodeState::Attaching => "attaching",
                        NodeState::Attached => "attached",
                        NodeState::Detaching => "detaching",
                    }
                    .to_owned(),
                    fingerprint: n.fingerprint.map(|f| b32_encode(&f)).unwrap_or_default(),
                    keep: n.keep,
                })
                .collect()),
            _ => Err(failed(
                "the vox daemon did not list its nodes; restart it so it is this vox's version",
            )),
        }
    }

    /// Act as `node`, attaching it if it is not attached (with `passphrase`, its identity's), and
    /// hold it attached until [`VoxClient::release`] or this client goes (ADR-014 M-6): the
    /// daemon then detaches it, unless it was attached with `--keep` or another client holds it.
    /// Acting as another node releases the one held before. Returns the node's fingerprint.
    ///
    /// # Errors
    /// The daemon's refusal: no such node, a wrong passphrase, none given for a node not attached.
    pub async fn attach(
        &self,
        node: String,
        passphrase: Option<Arc<Passphrase>>,
    ) -> Result<String, VoxError> {
        let name = NodeName::parse(&node).map_err(|e| failed(e.to_string()))?;
        let at = NodeSocket {
            path: self.socket.clone(),
            using: UseNode {
                node: name.clone(),
                attach: AttachMode::Hold,
                passphrase: passphrase.as_ref().map(|p| p.copy()),
                anchors: Vec::new(),
            },
            waiting: None,
        };
        let held = Arc::clone(&self.held);
        let socket = self.socket.clone();
        self.on_rt(async move {
            let mut slot = held.lock().await;
            // The node held before is let go first, so a switch never holds two.
            *slot = None;
            let client = IpcClient::open_at(&at)
                .await
                .map_err(|e| said(&socket, e))?;
            let me = client.me().map(|f| b32_encode(&f)).unwrap_or_default();
            *slot = Some(Held {
                node: name,
                client,
                at: at.attached_only(),
                forwards: HashMap::new(),
                lans: HashMap::new(),
            });
            Ok(me)
        })
        .await
    }

    /// Attach `node` so that it stays attached when the app quits, and again whenever the daemon
    /// starts (ADR-014 M-6, ADR-028 K-10): with `passphrase`, the daemon stores it in the login
    /// keychain and reads it from there at its next start; with none, for a node that needs none,
    /// nothing is stored. The node must not be attached already, so a passphrase is stored only
    /// once it has attached the node. Then [`VoxClient::attach`] acts as it.
    ///
    /// # Errors
    /// The daemon's refusal (a wrong passphrase, the node already attached), or the node attached
    /// but not kept, with why.
    pub async fn keep(
        &self,
        node: String,
        passphrase: Option<Arc<Passphrase>>,
    ) -> Result<(), VoxError> {
        let name = NodeName::parse(&node).map_err(|e| failed(e.to_string()))?;
        let keep = if passphrase.is_some() {
            KeepSource::Keychain(String::new())
        } else {
            KeepSource::None
        };
        let req = DaemonRequest::Attach {
            node: name,
            passphrase: passphrase.as_ref().map(|p| p.copy()),
            keep: Some(keep),
            rooms: Vec::new(),
            anchors: Vec::new(),
        };
        match self.daemon(req).await? {
            DaemonFrame::Attached(info, _) if info.keep => Ok(()),
            DaemonFrame::Attached(_, notes) => Err(failed(notes.join("; "))),
            _ => Err(failed(format!(
                "the vox daemon did not say node {node} is kept"
            ))),
        }
    }

    /// Stop holding the node: the daemon detaches it unless it is kept or held by another client.
    pub async fn release(&self) {
        let held = Arc::clone(&self.held);
        let _ = self
            .on_rt(async move {
                *held.lock().await = None;
                Ok(())
            })
            .await;
    }

    /// Detach `node` from the daemon now, whoever holds it.
    ///
    /// # Errors
    /// The daemon's refusal.
    pub async fn detach(&self, node: String) -> Result<(), VoxError> {
        let name = NodeName::parse(&node).map_err(|e| failed(e.to_string()))?;
        let answer = self
            .daemon(DaemonRequest::Detach { node: name.clone() })
            .await?;
        let held = Arc::clone(&self.held);
        let _ = self
            .on_rt(async move {
                let mut slot = held.lock().await;
                if slot.as_ref().is_some_and(|h| h.node == name) {
                    *slot = None;
                }
                Ok(())
            })
            .await;
        match answer {
            DaemonFrame::Ok => Ok(()),
            _ => Err(failed(format!(
                "the vox daemon did not say node {node} detached"
            ))),
        }
    }

    /// Stop: release the node and end the client's work. The object is unusable afterwards.
    pub async fn close(&self) {
        self.release().await;
        let hold = self
            .daemon_hold
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        // Dropped on the runtime its connection belongs to.
        let _ = self
            .on_rt(async move {
                drop(hold);
                Ok(())
            })
            .await;
        if let Some(rt) = self
            .runtime
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            rt.shutdown_background();
        }
    }

    /// Every room the node holds.
    ///
    /// # Errors
    /// No node attached, or the daemon stopped answering.
    pub async fn rooms(&self) -> Result<Vec<RoomSummary>, VoxError> {
        Ok(on_held!(self, |c| room_ids(c).await)?
            .into_iter()
            .map(|(id, name, open, over)| RoomSummary {
                id: b32_encode(&id),
                name: shown_name(&name),
                open,
                over,
            })
            .collect())
    }

    /// The members of a room, with this node's names for them.
    ///
    /// # Errors
    /// A malformed room id, or the node's refusal.
    pub async fn roster(&self, room: String) -> Result<Vec<Member>, VoxError> {
        let channel_id = digest(&room, "room id")?;
        on_held!(self, |c| {
            let names = names(c).await?;
            match ask(c, &Request::Roster { channel_id }).await? {
                Frame::Members { members } => Ok(members
                    .into_iter()
                    .map(|m| Member {
                        fingerprint: b32_encode(&m),
                        name: names.get(&m).cloned().unwrap_or_default(),
                    })
                    .collect()),
                other => Err(unexpected(&other)),
            }
        })
    }

    /// One page of a room, in the room's order: up to `limit` messages (0: all) after the message
    /// `after` (empty: from the first). The next page follows the last message of this one.
    ///
    /// # Errors
    /// A malformed id, or the node's refusal (a closed room, one this node does not hold).
    pub async fn read(
        &self,
        room: String,
        after: String,
        limit: u64,
    ) -> Result<Vec<RoomMessage>, VoxError> {
        let channel_id = digest(&room, "room id")?;
        let after = if after.is_empty() {
            None
        } else {
            Some(digest(&after, "message id")?)
        };
        on_held!(self, |c| {
            let names = names(c).await?;
            let me = c.me().map(|f| b32_encode(&f));
            match ask(
                c,
                &Request::Read {
                    channel_id,
                    since: None,
                    after,
                    limit,
                },
            )
            .await?
            {
                Frame::Rows { rows } => Ok(rows
                    .iter()
                    .map(|r| rendered(r, &names, me.as_deref()))
                    .collect()),
                other => Err(unexpected(&other)),
            }
        })
    }

    /// How many messages a room holds.
    ///
    /// # Errors
    /// A malformed id, or the node's refusal.
    pub async fn count(&self, room: String) -> Result<u64, VoxError> {
        let channel_id = digest(&room, "room id")?;
        on_held!(self, |c| match ask(
            c,
            &Request::Count {
                channel_id,
                since: None
            }
        )
        .await?
        {
            Frame::Count { n, .. } => Ok(n),
            other => Err(unexpected(&other)),
        })
    }

    /// Post `text` to a room, answered once the node has it in the room's log. With `to`
    /// (members' fingerprints), `re` (a message's id) or `urgent`, it is posted as a `say`
    /// carrying them (ADR-020 4.5, 4.6); with none, as the text alone.
    ///
    /// # Errors
    /// An empty message, an addressee that is not a whole fingerprint, or the node's refusal.
    pub async fn post(
        &self,
        room: String,
        text: String,
        to: Vec<String>,
        re: String,
        urgent: bool,
    ) -> Result<(), VoxError> {
        let channel_id = digest(&room, "room id")?;
        if text.trim().is_empty() {
            return Err(failed("refusing to post an empty message"));
        }
        let mut to_fps = Vec::with_capacity(to.len());
        for t in &to {
            to_fps.push(b32_encode(&digest(t, "addressee's fingerprint")?));
        }
        if !re.is_empty() {
            digest(&re, "message id")?;
        }
        let mut env = vox_agentcomms::envelope::Envelope::say(&text);
        env.to = to_fps;
        env.re = (!re.is_empty()).then(|| re.trim().to_owned());
        env.urgent = urgent;
        on_held!(self, |c| {
            // **A reply spends a hop** (ADR-020 §9), by the one rule the CLI follows: its
            // parent's budget less one, read up the `re` chain from the log.
            if let Some(re) = env.re.clone() {
                let chain = reply_chain(c, channel_id, &re).await?;
                env.hops = vox_agentcomms::envelope::reply_hops_by(&re, |h| {
                    let hash = vox_core::node::link::b32_decode(h.trim(), "re").ok()?;
                    chain.get(&hash).cloned()
                });
            }
            let text = env.to_text();
            // A link card, fetched by this node (ADR-028 F-10).
            done(
                c,
                &Request::Post {
                    channel_id,
                    text,
                    card: true,
                },
            )
            .await
        })
    }

    /// Create a room named `name`, its one shared name (ADR-028 R-1), under `passphrase`; returns
    /// its id.
    ///
    /// # Errors
    /// The node's refusal.
    pub async fn create_room(
        &self,
        name: String,
        passphrase: Arc<Passphrase>,
    ) -> Result<String, VoxError> {
        let before = self.room_list().await?;
        let req = Request::Create {
            name,
            passphrase: passphrase.copy(),
        };
        on_held!(self, |c| done(c, &req).await)?;
        self.new_room(before, "the room was created").await
    }

    /// Join a room from its `vox://` link with its passphrase; returns its id. The room keeps the
    /// name its members gave it (ADR-028 R-1).
    ///
    /// # Errors
    /// The node's refusal, with where the join stopped.
    pub async fn join_room(
        &self,
        link: String,
        passphrase: Arc<Passphrase>,
    ) -> Result<String, VoxError> {
        let before = self.room_list().await?;
        let req = Request::Join {
            link,
            passphrase: passphrase.copy(),
        };
        on_held!(self, |c| done(c, &req).await)?;
        self.new_room(before, "joined").await
    }

    /// Open a closed room with its passphrase.
    ///
    /// # Errors
    /// A wrong passphrase, or the node's refusal.
    pub async fn open_room(
        &self,
        room: String,
        passphrase: Arc<Passphrase>,
    ) -> Result<(), VoxError> {
        let req = Request::OpenRoom {
            channel_id: digest(&room, "room id")?,
            passphrase: passphrase.copy(),
        };
        on_held!(self, |c| done(c, &req).await)
    }

    /// A room link, for someone else to join with.
    ///
    /// # Errors
    /// The node's refusal (a closed room, or no address to put in it).
    pub async fn link(&self, room: String) -> Result<RoomLink, VoxError> {
        let channel_id = digest(&room, "room id")?;
        on_held!(
            self,
            |c| match ask(c, &Request::Invite { channel_id }).await? {
                Frame::Link { url, note } => Ok(RoomLink { url, note }),
                other => Err(unexpected(&other)),
            }
        )
    }

    /// Leave a room: answered once another member has that and the room is deleted here.
    ///
    /// # Errors
    /// The node's refusal.
    pub async fn leave(&self, room: String) -> Result<(), VoxError> {
        let channel_id = digest(&room, "room id")?;
        on_held!(self, |c| done(c, &Request::Leave { channel_id }).await)
    }

    /// End a room for everyone; its creator only.
    ///
    /// # Errors
    /// The node's refusal.
    pub async fn end(&self, room: String) -> Result<(), VoxError> {
        let channel_id = digest(&room, "room id")?;
        on_held!(self, |c| done(c, &Request::End { channel_id }).await)
    }

    /// Keep `room`'s message bodies for `ttl_secs` seconds (0: forever), as
    /// `vox room retention` does (ADR-023 decision 2); its creator or an admin only. Shortening
    /// it deletes stored history, so the identity passphrase is always asked for.
    ///
    /// # Errors
    /// A malformed id, a wrong passphrase, or the node's refusal (not the creator or an admin).
    pub async fn set_retention(
        &self,
        room: String,
        ttl_secs: u64,
        identity_passphrase: Arc<Passphrase>,
    ) -> Result<(), VoxError> {
        let req = Request::SetRetention {
            channel_id: digest(&room, "room id")?,
            ttl: ttl_secs,
            identity_passphrase: identity_passphrase.copy(),
        };
        on_held!(self, |c| done(c, &req).await)
    }

    /// `room`'s admins, its creator first, as fingerprints.
    ///
    /// # Errors
    /// A malformed id, or the node's refusal (the room not open).
    pub async fn admins(&self, room: String) -> Result<Vec<String>, VoxError> {
        let channel_id = digest(&room, "room id")?;
        on_held!(
            self,
            |c| match ask(c, &Request::Admins { channel_id }).await? {
                Frame::Members { members } => Ok(members.iter().map(b32_encode).collect()),
                other => Err(unexpected(&other)),
            }
        )
    }

    /// Make `member` an admin of `room`, or (`admin` false) take it back; its creator only.
    ///
    /// # Errors
    /// A malformed id, or the node's refusal.
    pub async fn set_admin(
        &self,
        room: String,
        member: String,
        admin: bool,
    ) -> Result<(), VoxError> {
        let req = Request::SetAdmin {
            channel_id: digest(&room, "room id")?,
            member: digest(&member, "member's fingerprint")?,
            admin,
        };
        on_held!(self, |c| done(c, &req).await)
    }

    /// Trust `fingerprint` under `name`. The identity passphrase is needed once the keyring
    /// window has passed; within it, pass none.
    ///
    /// # Errors
    /// A malformed fingerprint, the passphrase needed or wrong, or the node's refusal.
    pub async fn trust_add(
        &self,
        fingerprint: String,
        name: String,
        identity_passphrase: Option<Arc<Passphrase>>,
    ) -> Result<(), VoxError> {
        let req = Request::Trust {
            target: digest(&fingerprint, "fingerprint")?,
            petname: name,
            identity_passphrase: copy_of(identity_passphrase.as_ref()),
            full_history: false,
        };
        on_held!(self, |c| done(c, &req).await)
    }

    /// The trust keyring.
    ///
    /// # Errors
    /// The node's refusal.
    pub async fn trust_list(&self) -> Result<Vec<TrustedNode>, VoxError> {
        let mut list: Vec<TrustedNode> = on_held!(self, |c| names(c).await)?
            .into_iter()
            .map(|(fp, name)| TrustedNode {
                fingerprint: b32_encode(&fp),
                name,
            })
            .collect();
        list.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        Ok(list)
    }

    /// Rename a trusted node, keeping what its trust releases.
    ///
    /// # Errors
    /// As [`VoxClient::trust_add`].
    pub async fn trust_rename(
        &self,
        fingerprint: String,
        name: String,
        identity_passphrase: Option<Arc<Passphrase>>,
    ) -> Result<(), VoxError> {
        let req = Request::Rename {
            target: digest(&fingerprint, "fingerprint")?,
            petname: name,
            identity_passphrase: copy_of(identity_passphrase.as_ref()),
        };
        on_held!(self, |c| done(c, &req).await)
    }

    /// Stop trusting a node.
    ///
    /// # Errors
    /// As [`VoxClient::trust_add`].
    pub async fn trust_remove(
        &self,
        fingerprint: String,
        identity_passphrase: Option<Arc<Passphrase>>,
    ) -> Result<(), VoxError> {
        let req = Request::Untrust {
            target: digest(&fingerprint, "fingerprint")?,
            identity_passphrase: copy_of(identity_passphrase.as_ref()),
        };
        on_held!(self, |c| done(c, &req).await)
    }

    /// What is shared in `room` and what this node offers there (`vox service list`).
    ///
    /// # Errors
    /// A malformed id, or the node's refusal.
    pub async fn services(&self, room: String) -> Result<RoomServices, VoxError> {
        let channel_id = digest(&room, "room id")?;
        on_held!(
            self,
            |c| match ask(c, &Request::Services { channel_id }).await? {
                Frame::Services {
                    room,
                    services,
                    shared,
                } => Ok(RoomServices {
                    room: shown_name(&room),
                    shared: shared
                        .into_iter()
                        .map(|s| SharedService {
                            address: shown_name(&s.address),
                            canonical: s.canonical,
                            by: shown_name(&s.by),
                            udp: s.udp,
                            kind: shown_name(&s.kind),
                        })
                        .collect(),
                    offered: services
                        .into_iter()
                        .map(|(tag, local)| OfferedService { tag, local })
                        .collect(),
                }),
                other => Err(unexpected(&other)),
            }
        )
    }

    /// Offer the local endpoint `local` (`ip:port`) in `room` as the service `tag`, kept across
    /// this node's restarts until removed (`vox service add`).
    ///
    /// # Errors
    /// A malformed id or endpoint, or the node's refusal.
    pub async fn service_add(
        &self,
        room: String,
        tag: String,
        local: String,
    ) -> Result<(), VoxError> {
        let channel_id = digest(&room, "room id")?;
        let local: std::net::SocketAddr = local.trim().parse().map_err(|_| {
            failed(format!(
                "{local:?} is not a local endpoint: give it as ip:port, like 127.0.0.1:22"
            ))
        })?;
        let req = Request::AddService {
            channel_id,
            service_tag: tag,
            local: local.to_string(),
            persist: true,
        };
        on_held!(self, |c| done(c, &req).await)
    }

    /// Stop offering the service `tag` in `room`; its live sessions are cut
    /// (`vox service remove`).
    ///
    /// # Errors
    /// A malformed id, or the node's refusal (no such service).
    pub async fn service_remove(&self, room: String, tag: String) -> Result<(), VoxError> {
        let channel_id = digest(&room, "room id")?;
        let req = Request::RemoveService {
            channel_id,
            service_tag: tag,
        };
        on_held!(self, |c| done(c, &req).await)
    }

    /// Forward `local` (`ip:port`; port 0 lets the system choose, empty is `127.0.0.1:0`) to the
    /// service at `address`, `<service>.<node>.<room>.vox`, as `vox forward` does: in a room not
    /// yet synced it waits for the room's log to say what is shared there, and a share the log
    /// does not carry is refused at once. Carried until [`Self::stop_forward`] or the node is let
    /// go of. Answers the address bound.
    ///
    /// # Errors
    /// The name leading nowhere, the share absent, or the node's refusal to bind.
    pub async fn forward(&self, address: String, local: String) -> Result<String, VoxError> {
        let held = Arc::clone(&self.held);
        self.on_rt(async move {
            let at = held
                .lock()
                .await
                .as_ref()
                .map(|h| h.at.clone())
                .ok_or_else(not_attached)?;
            let resolve = || async {
                vox_core::node::nameipc::resolve(&at, &address)
                    .await
                    .map_err(|e| failed(format!("{address}: {e}")))
            };
            let mut room = resolve().await?;
            let deadline = tokio::time::Instant::now() + vox_core::node::up::HOST_PATIENCE;
            while room.share == ShareState::NotYetKnown && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                room = resolve().await?;
            }
            match room.share {
                ShareState::Stated => {}
                ShareState::Absent => {
                    return Err(failed(format!(
                        "{address}: {} shares no service called `{}` in that room",
                        b32_encode(&room.host),
                        vox_core::node::channel::service_name(&room.service)
                    )))
                }
                ShareState::NotYetKnown => {
                    return Err(failed(format!(
                        "{address}: that room has not synced with its members since this node \
                         joined it, so what is shared there is not known here yet; try again once \
                         a member is reachable"
                    )))
                }
            }
            let local = match local.trim() {
                "" => "127.0.0.1:0".to_owned(),
                l => l.to_owned(),
            };
            let mut carrier = IpcClient::open_at(&at)
                .await
                .map_err(|e| failed(format!("the vox daemon stopped answering: {e}")))?;
            let req = Request::Forward {
                channel_id: room.channel_id,
                host: room.host,
                service_tag: room.service,
                local,
            };
            let bound = match ask(&mut carrier, &req).await? {
                Frame::Bound { local } => local,
                other => return Err(unexpected(&other)),
            };
            match held.lock().await.as_mut() {
                Some(h) => {
                    h.forwards.insert(bound.clone(), carrier);
                    Ok(bound)
                }
                // Let go of while the forward was being made: its connection ends it.
                None => Err(not_attached()),
            }
        })
        .await
    }

    /// Stop the forward bound at `local`, as [`Self::forward`] answered it.
    ///
    /// # Errors
    /// No forward of this app's is bound there, or the node's refusal.
    pub async fn stop_forward(&self, local: String) -> Result<(), VoxError> {
        let held = Arc::clone(&self.held);
        self.on_rt(async move {
            let carrier = held
                .lock()
                .await
                .as_mut()
                .ok_or_else(not_attached)?
                .forwards
                .remove(&local);
            let Some(mut carrier) = carrier else {
                return Err(failed(format!("this app has no forward bound at {local}")));
            };
            done(&mut carrier, &Request::StopForward { local }).await
        })
        .await
    }

    /// Share the file or folder at `path` in `room`, addressed like a message (`vox share`):
    /// `to` members' fingerprints (empty: the room), a `note`, `re` the message it answers, and
    /// `urgent`. The daemon hashes and serves it and posts its announcement; it serves it until
    /// the message expires, it is stopped, this node leaves the room or the room ends, or after
    /// `count` fetches or `for_secs` seconds when either is not 0.
    ///
    /// # Errors
    /// A path that cannot be read, a malformed id, or the node's refusal.
    #[allow(clippy::too_many_arguments)]
    pub async fn share(
        &self,
        room: String,
        path: String,
        to: Vec<String>,
        note: String,
        re: String,
        urgent: bool,
        count: u64,
        for_secs: u64,
    ) -> Result<FileShare, VoxError> {
        let channel_id = digest(&room, "room id")?;
        // The daemon reads the path: made whole here.
        let path = std::fs::canonicalize(&path).map_err(|e| failed(format!("{path}: {e}")))?;
        let mut to_fps = Vec::with_capacity(to.len());
        for t in &to {
            to_fps.push(b32_encode(&digest(t, "addressee's fingerprint")?));
        }
        if !re.is_empty() {
            digest(&re, "message id")?;
        }
        // The note is the message's body; with none, the daemon says what is shared.
        let note = note.trim().to_owned();
        let mut env = vox_agentcomms::envelope::Envelope::new(vox_core::node::shares::FILE, &note);
        env.to = to_fps;
        env.urgent = urgent;
        env.re = (!re.is_empty()).then(|| re.trim().to_owned());
        if !note.is_empty() {
            env.data = serde_json::json!({ "note": note });
        }
        on_held!(self, |c| {
            // **A share is a post, and follows a post's hop rule** (ADR-020 §9), as `vox share`.
            if let Some(re) = env.re.clone() {
                let chain = reply_chain(c, channel_id, &re).await?;
                env.hops = vox_agentcomms::envelope::reply_hops_by(&re, |h| {
                    let hash = vox_core::node::link::b32_decode(h.trim(), "re").ok()?;
                    chain.get(&hash).cloned()
                });
            }
            let req = Request::Share {
                channel_id,
                path: path.to_string_lossy().into_owned(),
                envelope: env.to_text(),
                count,
                for_secs,
            };
            match ask(c, &req).await? {
                Frame::Shares { shares } => shares
                    .into_iter()
                    .next()
                    .map(file_share)
                    .ok_or_else(|| failed("the vox daemon did not say what it shares")),
                other => Err(unexpected(&other)),
            }
        })
    }

    /// This node's shares in `room` (`vox share list`).
    ///
    /// # Errors
    /// A malformed id, or the node's refusal.
    pub async fn shares(&self, room: String) -> Result<Vec<FileShare>, VoxError> {
        let channel_id = digest(&room, "room id")?;
        on_held!(
            self,
            |c| match ask(c, &Request::ShareList { channel_id }).await? {
                Frame::Shares { shares } => Ok(shares.into_iter().map(file_share).collect()),
                other => Err(unexpected(&other)),
            }
        )
    }

    /// Stop this node's shares in `room` that `selector` names: a name, a tag, or a prefix of a
    /// SHA-256 or of the announcement's id (`vox share stop`). Answers those stopped.
    ///
    /// # Errors
    /// A malformed id, or the node's refusal (no share matches).
    pub async fn share_stop(
        &self,
        room: String,
        selector: String,
    ) -> Result<Vec<FileShare>, VoxError> {
        let channel_id = digest(&room, "room id")?;
        let req = Request::ShareStop {
            channel_id,
            selector,
        };
        on_held!(self, |c| match ask(c, &req).await? {
            Frame::Shares { shares } => Ok(shares.into_iter().map(file_share).collect()),
            other => Err(unexpected(&other)),
        })
    }

    /// This node's decision record, newest first (ADR-028 §7, D-1, D-2): every day's file it
    /// keeps (14 days), read from `nodes/<node>/decisions/`, as the TUI's Decisions screen reads
    /// it. A line that does not parse is left out.
    ///
    /// # Errors
    /// No node attached, or the data root cannot be found.
    pub async fn decisions(&self) -> Result<Vec<DecisionEvent>, VoxError> {
        let held = Arc::clone(&self.held);
        let (data_root, config_dir) = (self.data_root.clone(), self.config_dir.clone());
        self.on_rt(async move {
            let node = held
                .lock()
                .await
                .as_ref()
                .map(|h| h.node.clone())
                .ok_or_else(not_attached)?;
            let account = Account::of(Some(&data_root), Some(&config_dir))
                .map_err(|e| failed(format!("data root: {e}")))?;
            let dir = account
                .node_dir(&node)
                .join(vox_core::node::decisions::DECISIONS_DIR);
            let Ok(days) = std::fs::read_dir(&dir) else {
                return Ok(Vec::new());
            };
            let text = |v: &serde_json::Value, k: &str| {
                v.get(k)
                    .and_then(serde_json::Value::as_str)
                    .map(shown_name)
                    .unwrap_or_default()
            };
            let mut events: Vec<DecisionEvent> = days
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
                .filter_map(|p| std::fs::read_to_string(p).ok())
                .flat_map(|day| {
                    day.lines()
                        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                        .collect::<Vec<_>>()
                })
                .filter_map(|v| {
                    Some(DecisionEvent {
                        at_millis: v.get("at_ms")?.as_u64()?,
                        asked: text(&v, "asked"),
                        by: text(&v, "by"),
                        alias: text(&v, "alias"),
                        decided: text(&v, "decided"),
                        why: text(&v, "why"),
                        room: text(&v, "room"),
                    })
                })
                .collect();
            events.sort_by(|a, b| b.at_millis.cmp(&a.at_millis));
            Ok(events)
        })
        .await
    }

    /// What this node pulled by itself in `room` and verified, oldest first, each where `vox room
    /// get` puts it: `<data root>/nodes/<node>/files/<room>/`.
    ///
    /// # Errors
    /// No node attached, or a malformed id.
    pub async fn pulled(&self, room: String) -> Result<Vec<PulledFile>, VoxError> {
        let channel_id = digest(&room, "room id")?;
        let held = Arc::clone(&self.held);
        let (data_root, config_dir) = (self.data_root.clone(), self.config_dir.clone());
        self.on_rt(async move {
            let node = held
                .lock()
                .await
                .as_ref()
                .map(|h| h.node.clone())
                .ok_or_else(not_attached)?;
            let account = Account::of(Some(&data_root), Some(&config_dir))
                .map_err(|e| failed(format!("data root: {e}")))?;
            let paths = account
                .node_paths(&node)
                .map_err(|e| failed(format!("node {node}: {e}")))?;
            let mut pulled: Vec<PulledFile> = vox_core::node::pulls::recorded(&paths)
                .into_iter()
                .filter(|p| p.room == channel_id)
                .map(|p| PulledFile {
                    entry: b32_encode(&p.entry),
                    path: p.path.to_string_lossy().into_owned(),
                    created: p.created,
                })
                .collect();
            pulled.sort_by_key(|p| p.created);
            Ok(pulled)
        })
        .await
    }

    /// The node's report, as `vox status --json` prints it: JSON, the report's contract.
    ///
    /// # Errors
    /// No node attached, or the node did not answer.
    pub async fn status(&self) -> Result<String, VoxError> {
        let held = Arc::clone(&self.held);
        self.on_rt(async move {
            let at = held
                .lock()
                .await
                .as_ref()
                .map(|h| h.at.clone())
                .ok_or_else(not_attached)?;
            vox_core::node::status::request(&at)
                .await
                .map_err(|e| failed(format!("the node did not report: {e}")))
        })
        .await
    }

    /// The node at a glance: who it is and how many peers it is connected to.
    ///
    /// # Errors
    /// No node attached, or the daemon's refusal.
    pub async fn view(&self) -> Result<NodeView, VoxError> {
        let body = vox_core::node::snapshot::request_body();
        let reply = on_held!(self, |c| c
            .exchange(&body)
            .await
            .map_err(|e| failed(format!("the vox daemon stopped answering: {e}"))))?;
        match vox_core::node::snapshot::NodeSnapshot::from_bytes(&reply) {
            Ok(Some(s)) => Ok(NodeView {
                me: s.me.map(|m| b32_encode(&m)).unwrap_or_default(),
                peers: u32::try_from(s.connected_peers.len()).unwrap_or(u32::MAX),
                keyring: vox_core::node::snapshot::keyring_label(s.keyring_open_secs),
            }),
            Ok(None) => match Frame::from_bytes(&reply) {
                Ok(frame) => Err(answered(frame).err().unwrap_or_else(|| {
                    failed("the vox daemon did not answer with the node's state")
                })),
                Err(e) => Err(failed(format!("the vox daemon's answer did not read: {e}"))),
            },
            Err(e) => Err(failed(format!("the vox daemon's answer did not read: {e}"))),
        }
    }

    /// Who reads whom in a room (ADR-028 L-4: a member in the keyring that consents back is
    /// shown ⇄).
    ///
    /// # Errors
    /// A malformed id, or the node's refusal.
    pub async fn consents(&self, room: String) -> Result<RoomConsents, VoxError> {
        let channel_id = digest(&room, "room id")?;
        on_held!(
            self,
            |c| match ask(c, &Request::Consents { channel_id }).await? {
                Frame::Consents { outbound, inbound } => Ok(RoomConsents {
                    outbound: outbound.iter().map(b32_encode).collect(),
                    inbound: inbound.iter().map(b32_encode).collect(),
                }),
                other => Err(unexpected(&other)),
            }
        )
    }

    /// Bring this Mac onto `room`'s family LAN (ADR-013), as `vox lan up` does: the daemon asks the
    /// root helper for the interface and runs the LAN until [`Self::lan_down`] or the node is let
    /// go of. `allow` are the local ports members may reach over it; none by default. The root
    /// helper is asked on `helper_socket` (empty: where Vox.app's helper listens). Answers the
    /// daemon's first line, once the LAN is up: the interface and this node's LAN addresses.
    ///
    /// # Errors
    /// A malformed id, the room not open, the helper not running or refusing, or the LAN not
    /// started, with why.
    pub async fn lan_up(
        &self,
        room: String,
        allow: Vec<u16>,
        helper_socket: String,
    ) -> Result<String, VoxError> {
        use vox_core::node::lan_request::{LanRequest, LanSaid, DEFAULT_HELPER_SOCKET};
        let channel_id = digest(&room, "room id")?;
        let held = Arc::clone(&self.held);
        self.on_rt(async move {
            let at = held
                .lock()
                .await
                .as_ref()
                .map(|h| h.at.clone())
                .ok_or_else(not_attached)?;
            let (mut stream, _) = vox_core::node::ipc::open_as(&at)
                .await
                .map_err(|e| failed(format!("the vox daemon stopped answering: {e}")))?;
            let req = LanRequest {
                channel_id,
                helper: PathBuf::from(if helper_socket.is_empty() {
                    DEFAULT_HELPER_SOCKET
                } else {
                    &helper_socket
                }),
                stats_file: None,
                allow: allow.into_iter().collect(),
            };
            vox_core::node::ipc::write_frame(&mut stream, &req.to_bytes())
                .await
                .map_err(|e| failed(format!("the vox daemon stopped answering: {e}")))?;
            let first = match vox_core::node::ipc::read_frame(&mut stream).await {
                Ok(Some(body)) => match LanSaid::parse(&body) {
                    Some(LanSaid::Said(line)) => line,
                    Some(LanSaid::Failed(why)) => return Err(failed(why)),
                    None => match Frame::from_bytes(&body) {
                        Ok(Frame::Error { reason }) => return Err(failed(reason)),
                        _ => {
                            return Err(failed(
                                "the vox daemon answered the LAN with something else",
                            ))
                        }
                    },
                },
                _ => return Err(failed("the vox daemon closed the LAN before it was up")),
            };
            let said = Arc::new(Mutex::new(vec![first.clone()]));
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            // The LAN's lines, kept for `lan_said`, until it is stopped or the daemon ends it.
            let lines = Arc::clone(&said);
            tokio::spawn(async move {
                tokio::pin!(stopped);
                loop {
                    tokio::select! {
                        _ = &mut stopped => break,
                        frame = vox_core::node::ipc::read_frame(&mut stream) => {
                            let line = match frame {
                                Ok(Some(body)) => match LanSaid::parse(&body) {
                                    Some(LanSaid::Said(l)) => l,
                                    Some(LanSaid::Failed(why)) => format!("the LAN stopped: {why}"),
                                    None => continue,
                                },
                                _ => "the LAN stopped: the vox daemon closed it".to_owned(),
                            };
                            let end = line.starts_with("the LAN stopped");
                            lines.lock().unwrap_or_else(PoisonError::into_inner).push(line);
                            if end {
                                break;
                            }
                        }
                    }
                }
                // Closing the connection takes the LAN down.
                drop(stream);
            });
            match held.lock().await.as_mut() {
                Some(h) => {
                    h.lans.insert(channel_id, Lan { stop, said });
                    Ok(first)
                }
                None => Err(not_attached()),
            }
        })
        .await
    }

    /// Take `room`'s family LAN down: its interface goes with it.
    ///
    /// # Errors
    /// A malformed id, or no LAN of this app's runs for that room.
    pub async fn lan_down(&self, room: String) -> Result<(), VoxError> {
        let channel_id = digest(&room, "room id")?;
        let held = Arc::clone(&self.held);
        self.on_rt(async move {
            let lan = held
                .lock()
                .await
                .as_mut()
                .ok_or_else(not_attached)?
                .lans
                .remove(&channel_id);
            match lan {
                Some(lan) => {
                    let _ = lan.stop.send(());
                    Ok(())
                }
                None => Err(failed("this app runs no LAN for that room")),
            }
        })
        .await
    }

    /// What `room`'s family LAN has said, oldest first, as `vox lan up` prints it; empty when
    /// this app runs none there.
    ///
    /// # Errors
    /// A malformed id.
    pub async fn lan_said(&self, room: String) -> Result<Vec<String>, VoxError> {
        let channel_id = digest(&room, "room id")?;
        let held = Arc::clone(&self.held);
        self.on_rt(async move {
            Ok(held
                .lock()
                .await
                .as_ref()
                .and_then(|h| h.lans.get(&channel_id))
                .map(|l| {
                    l.said
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .clone()
                })
                .unwrap_or_default())
        })
        .await
    }

    /// Who has read this node's own recent messages in `room` (ADR-028 R-6), from the read
    /// records the node can open, as `vox room read --json` says it: a member whose records it
    /// cannot open is in none.
    ///
    /// # Errors
    /// A malformed id, or the daemon's refusal.
    pub async fn read_by(&self, room: String) -> Result<Vec<ReadBy>, VoxError> {
        let channel_id = digest(&room, "room id")?;
        let body = vox_core::node::snapshot::request_body();
        let (reply, names) = on_held!(self, |c| {
            let names = names(c).await?;
            let reply = c
                .exchange(&body)
                .await
                .map_err(|e| failed(format!("the vox daemon stopped answering: {e}")))?;
            Ok((reply, names))
        })?;
        let Ok(Some(snap)) = vox_core::node::snapshot::NodeSnapshot::from_bytes(&reply) else {
            return Err(failed(
                "the vox daemon did not answer with the node's state",
            ));
        };
        let name = |fp: &Digest32| {
            names
                .get(fp)
                .cloned()
                .unwrap_or_else(|| b32_encode(fp).chars().take(12).collect())
        };
        Ok(snap
            .open
            .into_iter()
            .find(|o| o.channel_id == channel_id)
            .map(|o| o.read_by)
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, who)| !who.is_empty())
            .map(|(entry, who)| {
                let mut names: Vec<String> = who.iter().map(name).collect();
                names.sort();
                ReadBy {
                    id: b32_encode(&entry),
                    names,
                }
            })
            .collect())
    }

    /// Each other member's lane in `room`, in the room's member order (ADR-028 W-3), as
    /// `vox room board` shows it.
    ///
    /// # Errors
    /// A malformed id, or the node's refusal.
    pub async fn lanes(&self, room: String) -> Result<Vec<Lane>, VoxError> {
        let channel_id = digest(&room, "room id")?;
        on_held!(self, |c| {
            let names = names(c).await?;
            match ask(c, &Request::Lanes { channel_id }).await? {
                Frame::Lanes { lanes } => Ok(lanes
                    .into_iter()
                    .map(|(member, state)| Lane {
                        fingerprint: b32_encode(&member),
                        name: names.get(&member).cloned().unwrap_or_default(),
                        state: shown_name(&state),
                    })
                    .collect()),
                other => Err(unexpected(&other)),
            }
        })
    }

    /// The messages `ids` in `room` were shown to the person: the node records them read, and
    /// its read records tell the room's members (ADR-028 R-6), as the TUI does for what it draws.
    ///
    /// # Errors
    /// A malformed id, or the node's refusal (a room left or ended).
    pub async fn mark_read(&self, room: String, ids: Vec<String>) -> Result<(), VoxError> {
        let channel_id = digest(&room, "room id")?;
        let mut entries = Vec::with_capacity(ids.len());
        for id in &ids {
            entries.push(digest(id, "message id")?);
        }
        if entries.is_empty() {
            return Ok(());
        }
        let req = Request::MarkRead {
            channel_id,
            entries,
        };
        on_held!(self, |c| done(c, &req).await)
    }

    /// Deliver the held node's events to `listener` until it is detached or the daemon stops.
    ///
    /// When the node says a room has new readable messages (its own post, a sync that rendered
    /// rows, a sender key that made held rows readable), the room is read from its cursor, the
    /// newest message delivered, so every message that becomes readable is delivered once,
    /// including one that arrives late by sync and one whose body was owed. Messages already
    /// readable now are not delivered.
    ///
    /// # Errors
    /// No node attached, or the daemon would not stream its events.
    pub async fn subscribe(&self, listener: Arc<dyn ClientListener>) -> Result<(), VoxError> {
        let held = Arc::clone(&self.held);
        let socket = self.socket.clone();
        // The cursors and the stream are set up before this returns, so nothing posted after it
        // is missed.
        let (stream, cursors) = self
            .on_rt({
                let held = Arc::clone(&held);
                async move {
                    let mut slot = held.lock().await;
                    let h = slot.as_mut().ok_or_else(not_attached)?;
                    let mut stream = IpcClient::open_at(&h.at)
                        .await
                        .map_err(|e| said(&socket, e))?;
                    stream
                        .subscribe()
                        .await
                        .map_err(|e| failed(format!("cannot follow the node's events: {e}")))?;
                    let mut cursors = HashMap::new();
                    for (id, _, open, _) in room_ids(&mut h.client).await? {
                        if !open {
                            continue;
                        }
                        let req = Request::Count {
                            channel_id: id,
                            since: None,
                        };
                        if let Frame::Count { last, .. } = ask(&mut h.client, &req).await? {
                            cursors.insert(id, last);
                        }
                    }
                    Ok((stream, cursors))
                }
            })
            .await?;
        self.rt.spawn(follow(stream, cursors, held, listener));
        Ok(())
    }
}

/// The event loop behind [`VoxClient::subscribe`].
async fn follow(
    mut stream: IpcClient,
    mut cursors: HashMap<Digest32, Option<Digest32>>,
    held: Slot,
    listener: Arc<dyn ClientListener>,
) {
    let mut delivered: HashSet<Digest32> = HashSet::new();
    loop {
        let rooms: Vec<Digest32> = match stream.next().await {
            // This node's own post.
            Ok(Some(Frame::Event(NodeEvent::NewEntry { channel_id, .. }))) => vec![channel_id],
            // Others' messages: a sync that rendered rows, or a sender key that made rows already
            // held readable. Said as a notice too, as the TUI says them.
            Ok(Some(Frame::Event(
                ev @ (NodeEvent::Synced { .. } | NodeEvent::SenderKeyReceived { .. }),
            ))) => {
                let room = match &ev {
                    NodeEvent::Synced {
                        channel_id,
                        rendered,
                        ..
                    } => (*rendered > 0).then_some(*channel_id),
                    NodeEvent::SenderKeyReceived { channel_id, .. } => Some(*channel_id),
                    _ => None,
                };
                listener.on_notice(ev.words());
                room.into_iter().collect()
            }
            Ok(Some(Frame::Event(ev))) => {
                listener.on_notice(ev.words());
                continue;
            }
            // Events were dropped for this client: every room it follows is read from its cursor.
            Ok(Some(Frame::Lagged { .. })) => cursors.keys().copied().collect(),
            Ok(Some(Frame::NodeDetached { node })) => {
                listener.on_ended(format!("node {node} was detached from the vox daemon"));
                return;
            }
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => {
                listener.on_ended("the vox daemon stopped".to_owned());
                return;
            }
        };
        for room in rooms {
            let since = cursors.get(&room).copied().flatten();
            let rows = {
                let mut slot = held.lock().await;
                let Some(h) = slot.as_mut() else {
                    listener.on_ended("the app released its node".to_owned());
                    return;
                };
                let rows = match h.client.read_rows(room, since).await {
                    Ok(Frame::Rows { rows }) => rows,
                    Ok(Frame::NodeDetached { node }) => {
                        listener.on_ended(format!("node {node} was detached from the vox daemon"));
                        return;
                    }
                    // The cursor's row has gone (it expired): start again from the newest.
                    Ok(_) => {
                        let req = Request::Count {
                            channel_id: room,
                            since: None,
                        };
                        if let Ok(Frame::Count { last, .. }) = h.client.request(&req).await {
                            cursors.insert(room, last);
                        }
                        listener.on_notice(
                            "some messages could not be followed; read the room again".to_owned(),
                        );
                        continue;
                    }
                    Err(e) => {
                        listener.on_ended(format!("the vox daemon stopped answering: {e}"));
                        return;
                    }
                };
                let names = names(&mut h.client).await.unwrap_or_default();
                let me = h.client.me().map(|f| b32_encode(&f));
                rows.iter()
                    .map(|r| (r.clone(), rendered(r, &names, me.as_deref())))
                    .collect::<Vec<_>>()
            };
            if let Some(newest) = rows
                .iter()
                .filter(|(r, _)| !r.owed)
                .max_by_key(|(r, _)| r.arrival)
            {
                cursors.insert(room, Some(newest.0.entry_hash));
            } else {
                cursors.entry(room).or_insert(None);
            }
            for (row, message) in rows {
                if !row.owed && delivered.insert(row.entry_hash) {
                    listener.on_message(b32_encode(&room), message);
                }
            }
        }
    }
}
