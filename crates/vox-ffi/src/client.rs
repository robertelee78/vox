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
use vox_core::error::Error;
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
/// then a keyring change.
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
    /// The image a file share announces (ADR-028 F-9), or none: not a share, or not an image.
    pub image: Option<ImagePreview>,
    /// The link card its sender's node fetched for its first link (ADR-028 F-10), or none.
    pub card: Option<LinkCard>,
    /// The platform its author's node says it runs on, when it is a `hello` that says so (ADR-020
    /// §4.9b): that node's claim, not checked.
    pub platform: Option<NodePlatform>,
    /// What it relates to, as its sender tagged it (#636): `task:#636`, `project:vox`, each on
    /// one line and cut, sorted. Shown only to those who can read the message.
    pub tags: Vec<String>,
}

/// The OS, OS version and CPU architecture a node says it runs on, from its `hello` (ADR-020
/// §4.9b). Its own claim: shown as what the node says, never as fact.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NodePlatform {
    /// The OS's name, as the node gave it.
    pub os: String,
    /// The OS's version, as the node gave it; empty when it gave none.
    pub os_version: String,
    /// The CPU architecture, as the node gave it; empty when it gave none.
    pub arch: String,
}

/// What a file share's announcement carries of an image (ADR-028 F-9), so it can be shown while
/// the sharer is offline.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ImagePreview {
    /// The image's width, in pixels.
    pub width: u32,
    /// Its height, in pixels.
    pub height: u32,
    /// A JPEG thumbnail of at most 16 KB.
    pub thumb: Vec<u8>,
    /// Its BlurHash, for the moment before the thumbnail is drawn.
    pub blurhash: String,
}

/// A link card (ADR-028 F-10): what the sender's node found at the message's first link, carried
/// in the message, so no reader fetches anything.
#[derive(Debug, Clone, uniffi::Record)]
pub struct LinkCard {
    /// The link.
    pub url: String,
    /// The page's title, or empty.
    pub title: String,
    /// Its description, or empty.
    pub description: String,
    /// Its image's bytes, as the page served them, when it was small enough to travel.
    pub image: Option<Vec<u8>>,
}

fn unbase64(s: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// `data.image` of a file share, or `None` when any part is missing or malformed.
fn image_of(env: &vox_agentcomms::envelope::Envelope) -> Option<ImagePreview> {
    if env.kind != vox_core::node::shares::FILE {
        return None;
    }
    let image = env.data.get("image")?;
    Some(ImagePreview {
        width: u32::try_from(image.get("width")?.as_u64()?).ok()?,
        height: u32::try_from(image.get("height")?.as_u64()?).ok()?,
        thumb: unbase64(image.get("thumb")?.as_str()?)?,
        blurhash: image.get("blurhash")?.as_str()?.to_owned(),
    })
}

/// `data.card`, or `None` when it has no link or says nothing. Its words are the page's, another
/// party's choice: shown, never laid out.
fn card_of(env: &vox_agentcomms::envelope::Envelope) -> Option<LinkCard> {
    let card = env.data.get("card")?;
    let text = |k: &str| card.get(k).and_then(|v| v.as_str()).map(shown_name);
    let (title, description) = (text("title"), text("description"));
    if title.is_none() && description.is_none() {
        return None;
    }
    Some(LinkCard {
        url: shown_name(card.get("url")?.as_str()?),
        title: title.unwrap_or_default(),
        description: description.unwrap_or_default(),
        image: card
            .get("image")
            .and_then(|v| v.as_str())
            .and_then(unbase64),
    })
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
    /// Whom it is addressed to, as whole fingerprints (a session of one as
    /// `<fingerprint>/<session id>`); empty for the whole room. A card addressed to others names
    /// them, and the sharer (ADR-028 F-3; D5).
    pub to: Vec<String>,
    /// Whether the sharer is in this node's keyring. This node pulls a share by itself only from
    /// one it trusts; another's it pulls only when asked (`get`).
    pub sharer_trusted: bool,
}

/// Where the pull of one file offer stands on this node (ADR-028 F-3; D5). One pulled is in
/// [`VoxClient::pulled`].
#[derive(Debug, Clone, uniffi::Enum)]
pub enum PullState {
    /// Being pulled: `bytes` of `of` have come (a folder's are not counted).
    Pulling {
        /// What has come.
        bytes: u64,
        /// What was announced.
        of: u64,
    },
    /// The last try failed, and it is tried again by itself: the sharer may be offline.
    Waiting {
        /// Why the last try failed, in the node's words.
        why: String,
    },
    /// Asked for with `get`, and failed.
    Failed {
        /// Why, in the node's words.
        why: String,
    },
}

/// One offer's pull, by its announcement's id.
#[derive(Debug, Clone, uniffi::Record)]
pub struct OfferPull {
    /// The announcement's message id.
    pub entry: String,
    /// Where it stands.
    pub state: PullState,
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

/// Where one of this node's own messages is (ADR-028 R-6): said while no member is known to have
/// read it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Whereabouts {
    /// The message's id.
    pub id: String,
    /// "only on this machine", or "on N of M members' nodes", as the TUI says it.
    pub words: String,
}

/// Who has pulled one of this node's own shares whole and verified it (ADR-028 F-7).
#[derive(Debug, Clone, uniffi::Record)]
pub struct PulledBy {
    /// The share's announcement: its message id.
    pub id: String,
    /// This node's names for the members who pulled it, sorted; a fingerprint's first 12
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

/// A node directory of an earlier release, moved aside (#576): where it was, and where it is now.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MovedAside {
    /// The directory it was.
    pub from: String,
    /// The directory it is now, under the data root's `moved-aside/`.
    pub to: String,
}

/// The node directories of an earlier release that make the data root `data_root` (empty: the
/// default one) one this version does not read, as full paths: what the daemon refuses it for.
/// Read only.
///
/// # Errors
/// The data root cannot be found.
#[uniffi::export]
pub fn old_layout(data_root: String) -> Result<Vec<String>, VoxError> {
    let root = (!data_root.is_empty()).then(|| PathBuf::from(&data_root));
    let account =
        Account::of(root.as_deref(), None).map_err(|e| failed(format!("data root: {e}")))?;
    Ok(vox_core::node::layout::old_layout_dirs(&account)
        .into_iter()
        .map(|name| account.data_root.join(name).display().to_string())
        .collect())
}

/// Move the data root's earlier-release node directories aside, as the person asked (#576): each
/// renamed, whole and unread, into `<data root>/moved-aside/<name>-<date>`, `date` being the
/// person's day (`YYYY-MM-DD`). Nothing is deleted. Each move, from and to.
///
/// # Errors
/// A `date` that is not `YYYY-MM-DD`, or a move that fails (the ones before it stand).
#[uniffi::export]
pub fn move_old_layout_aside(data_root: String, date: String) -> Result<Vec<MovedAside>, VoxError> {
    if date.len() != 10 || !date.chars().all(|c| c.is_ascii_digit() || c == '-') {
        return Err(failed(format!("{date:?} is not a date (YYYY-MM-DD)")));
    }
    let root = (!data_root.is_empty()).then(|| PathBuf::from(&data_root));
    let account =
        Account::of(root.as_deref(), None).map_err(|e| failed(format!("data root: {e}")))?;
    vox_core::node::layout::move_old_layout_aside(&account, &date)
        .map(|moved| {
            moved
                .into_iter()
                .map(|(from, to)| MovedAside {
                    from: from.display().to_string(),
                    to: to.display().to_string(),
                })
                .collect()
        })
        .map_err(|e| failed(e.to_string()))
}

/// What a person is told wherever a node is made, as `vox node create` says it (ADR-028 K-8): a
/// node has no backup.
#[uniffi::export]
#[must_use]
pub fn no_backup_notice() -> String {
    vox_text::node::NO_BACKUP.to_owned()
}

/// What a person is told when a node is made with no identity passphrase, as `vox node create`
/// says it (ADR-005 J-2, V030-36): the key is kept unencrypted.
#[uniffi::export]
#[must_use]
pub fn no_passphrase_notice() -> String {
    vox_text::node::NO_PASSPHRASE.to_owned()
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
    /// What its entry grants: read, and (`true`) drive as well (ADR-028 K-14).
    pub drive: bool,
}

/// Why a node is offered to the keyring (ADR-028 K-15, K-17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum OfferWhy {
    /// It joined a room after this node did.
    Joined,
    /// It trusts this node.
    TrustsYou,
}

/// A room an offer comes from.
#[derive(Debug, Clone, uniffi::Record)]
pub struct OfferRoom {
    /// The room's id, base32.
    pub id: String,
    /// Its name as this node shows it.
    pub name: String,
}

/// A node offered to the keyring (ADR-028 K-15 – K-18): accepted with
/// [`VoxClient::trust_add`], dismissed with [`VoxClient::dismiss_offer`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct OfferInfo {
    /// Its fingerprint, base32; the app groups it and draws its art.
    pub fingerprint: String,
    /// The rooms it is offered from.
    pub rooms: Vec<OfferRoom>,
    /// Why: joined, trusts you, or both.
    pub why: Vec<OfferWhy>,
    /// The fingerprints (base32) of the keyring's nodes that trust it (K-7).
    pub trusted_by: Vec<String>,
    /// What is said of it, word for word as the TUI says it (ADR-028 CL-1).
    pub said: String,
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
    /// The ready-to-copy commands for its kind, each with the canonical address (ADR-028 S-3).
    pub commands: Vec<ServiceCommand>,
    /// What reaching it from here needs, and whether each holds (S-3).
    pub needs: Vec<ServiceNeed>,
}

/// One ready-to-copy command for a shared service (ADR-028 S-3), as `vox service list` gives it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ServiceCommand {
    /// What it is: `ssh`, `forward`, `then` (what to run after the forward), `open`.
    pub what: String,
    /// The command, carrying the canonical address: it works pasted on any member's machine.
    pub command: String,
}

/// One thing reaching a shared service needs (ADR-028 S-3), as `vox service list` says it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ServiceNeed {
    /// The condition, in words.
    pub need: String,
    /// Whether it holds now.
    pub holds: bool,
    /// What to do when it does not; empty when it holds.
    pub otherwise: String,
}

/// A service this node offers in a room.
#[derive(Debug, Clone, uniffi::Record)]
pub struct OfferedService {
    /// Its tag.
    pub tag: String,
    /// The local endpoint connections are carried to.
    pub local: String,
}

/// A service listening on this machine, as one-step sharing lists it (ADR-028 S-4): what `vox
/// serve` with no name lists.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ListeningService {
    /// Its port.
    pub port: u16,
    /// Whether it takes datagrams (UDP) rather than connections (TCP).
    pub udp: bool,
    /// The listening program's command name, where this user may read it; `None` for one this
    /// user cannot see (usually another user's, root's among them).
    pub program: Option<String>,
    /// Every address it listens on, as `ip:port`; `0.0.0.0` or `[::]` for every interface.
    pub addresses: Vec<String>,
    /// Whether it listens on every interface, which this machine's networks reach without Vox.
    pub every_interface: bool,
    /// The line `vox serve` lists it as: program, addresses, protocol, `(every interface)`.
    pub line: String,
}

/// What listens on this machine, and the sentence said under the list (ADR-028 S-4).
#[derive(Debug, Clone, uniffi::Record)]
pub struct ListeningServices {
    /// The services, as `vox serve` lists them.
    pub services: Vec<ListeningService>,
    /// Said under the list, always: another user's listeners may be missing from it or listed
    /// without their program (#491).
    pub may_be_missing: String,
}

/// What sharing one listening service would do, said before it is done (ADR-028 S-4), as `vox
/// serve` with no name says it: the name and tag it is offered under, the endpoint members are
/// carried to, and each warning.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ServicePreview {
    /// The suggested name: its detected kind (`ssh`, `http`, …), else its program's name, else
    /// `service`. A person may give another; `service_add` takes any valid one.
    pub name: String,
    /// The tag it is offered under: the name, `udp/` before it for datagrams.
    pub tag: String,
    /// The endpoint members are carried to, as `ip:port`: what `service_add` takes.
    pub local: String,
    /// Each warning, one sentence: it listens on every interface, or sits on a sensitive port.
    pub warnings: Vec<String>,
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

/// One Session of a room (ADR-029): a harness session working in it, as its node says.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSession {
    /// The fingerprint of the node whose session it is, base32.
    pub node_fingerprint: String,
    /// This node's name for that node (ADR-028 K-3); empty for none.
    pub node_alias: String,
    /// The harness's own session id, as its node claims it.
    pub session_id: String,
    /// The first 8 characters of the id.
    pub short_id: String,
    /// The session's current name, as its node last gave it.
    pub name: Option<String>,
    /// How every client labels it (SE-3): `codex@device-2 · gso-cap · 3f0c25bf`.
    pub label: String,
    /// Open, or ended (SE-5).
    pub open: bool,
    /// When it opened, milliseconds since the Unix epoch.
    pub opened_at_ms: u64,
    /// When it ended, if it has.
    pub ended_at_ms: Option<u64>,
    /// Whether this node may drive it (ADR-029 §3).
    pub can_drive: bool,
    /// How many approvals and questions are open in it that this node may answer from Vox; 0
    /// without drive (ADR-029 CL-2).
    pub pending: u32,
}

/// One Session read as a member with drive reads it (ADR-029 SC-1, #554), word for word as
/// `vox room session` prints it (CL-1).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSessionRead {
    /// Its entries, oldest first; none when this node may not see inside it.
    pub entries: Vec<FfiSessionEntry>,
    /// What to say besides: "opening not received yet", or whose trust this node lacks to see
    /// inside; `None` when there is nothing to say.
    pub note: Option<String>,
}

/// One activity in a Session.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSessionEntry {
    /// Its id, stable: a split entry joined is one entry, with its first part's id.
    pub id: String,
    /// When its node sent it, milliseconds since the Unix epoch.
    pub at_ms: u64,
    /// The one line, exactly as `vox room session` prints it.
    pub line: String,
    /// Its full input and output, for Details, as `vox room session --details` prints them under
    /// the line; empty when the line is all there is.
    pub details: String,
    /// A file to or from the session.
    pub file: Option<FfiSessionFile>,
    /// An approval or a question the session asked.
    pub request: Option<FfiRequest>,
}

/// A file to or from a session.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSessionFile {
    /// Its name.
    pub name: String,
    /// Its size in bytes.
    pub size: u64,
    /// Its SHA-256, hex; empty when the entry does not give it.
    pub sha256: String,
    /// The session sent it, rather than received it.
    pub from_session: bool,
    /// Its entry's id: what pulling it names (#546).
    pub entry: String,
    /// Where this node's verified copy is, once it has one.
    pub pulled_path: Option<String>,
}

/// An approval or a question a session asked (ADR-029 DR-4).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiRequest {
    /// What [`VoxClient::drive`]'s approve, reject or answer takes.
    pub reference: String,
    /// A question, rather than an approval.
    pub is_question: bool,
    /// A question's parts; none for an approval.
    pub questions: Vec<FfiQuestion>,
    /// `None` while it is open and may be answered from Vox; otherwise what became of it, in the
    /// line's words: "approved here", "answered in Vox by ann: blue", "not answerable from Vox: …".
    pub state: Option<String>,
}

/// One part of a question.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiQuestion {
    /// What it asks.
    pub text: String,
    /// Its options' labels, in order.
    pub options: Vec<String>,
}

/// How the app names nodes in a Session's words, as the CLI does: its alias for a node, `you` for
/// itself, or the fingerprint cut short for a node it has no name for.
struct Known {
    names: HashMap<Digest32, String>,
    me: Option<Digest32>,
}

impl Known {
    async fn of(c: &mut IpcClient) -> Result<Self, VoxError> {
        Ok(Self {
            names: names(c).await?,
            me: c.me(),
        })
    }

    /// How a Session is labelled (SE-3), as `vox room sessions` labels it.
    fn label(&self, s: &vox_core::node::sessions::SessionRow) -> String {
        use vox_core::node::session_view::Names as _;
        vox_agentcomms::envelope::session_label(&self.alias(&s.node), s.name.as_deref(), &s.id)
    }
}

impl vox_core::node::session_view::Names for Known {
    fn alias(&self, fp: &Digest32) -> String {
        if self.me.as_ref() == Some(fp) {
            return "you".to_owned();
        }
        match self.names.get(fp) {
            Some(n) if !n.is_empty() => n.clone(),
            _ => b32_encode(fp).chars().take(12).collect(),
        }
    }
    fn is_me(&self, by: &str) -> bool {
        vox_core::node::link::b32_decode(by, "fingerprint").is_ok_and(|fp| self.me == Some(fp))
    }
    fn alias_b32(&self, by: &str) -> String {
        match vox_core::node::link::b32_decode(by, "fingerprint") {
            Ok(fp) => self.alias(&fp),
            Err(_) => by.chars().take(12).collect(),
        }
    }
}

/// The envelope's `to`, and the sessions it addresses by node.
type Addressed = (Vec<String>, Vec<(Digest32, String)>);

/// `to` as an envelope carries it: each a member's fingerprint, or one session of it as
/// `<fingerprint>/<session id>` (ADR-029 TA-1); and the sessions so addressed.
fn addressed(to: &[String]) -> Result<Addressed, VoxError> {
    let mut to_fps = Vec::with_capacity(to.len());
    let mut sessions = Vec::new();
    for t in to {
        let (node, session) = vox_agentcomms::envelope::addressee(t.trim());
        let fp = digest(node, "addressee's fingerprint")?;
        match session {
            Some(id) => {
                sessions.push((fp, id.to_owned()));
                to_fps.push(format!("{}/{id}", b32_encode(&fp)));
            }
            None => to_fps.push(b32_encode(&fp)),
        }
    }
    Ok((to_fps, sessions))
}

/// Each session addressed is one of its node's open Sessions in the room, or nothing is posted
/// (TA-5), refused in the words `vox room post` says.
async fn sessions_addressable(
    c: &mut IpcClient,
    channel_id: Digest32,
    addressed: &[(Digest32, String)],
) -> Result<(), VoxError> {
    if addressed.is_empty() {
        return Ok(());
    }
    let (sessions, _, known) = session_parts(c, channel_id).await?;
    for (fp, id) in addressed {
        match vox_core::node::sessions::addressable(&sessions, fp, id, |s| known.label(s)) {
            Ok(found) if found == *id => {}
            Ok(_) => {
                return Err(failed(format!(
                    "refusing to post it: no Session in this room is named {}",
                    shown_name(id)
                )))
            }
            Err(e) => return Err(failed(format!("refusing to post it: {e}"))),
        }
    }
    Ok(())
}

/// The parts of a room's Sessions as this node holds them.
type SessionParts = (
    Vec<vox_core::node::sessions::SessionRow>,
    Vec<vox_core::node::drive::SessionRow>,
    Known,
);

/// A room's Sessions, the Session entries this node holds there, and how it names nodes.
async fn session_parts(c: &mut IpcClient, channel_id: Digest32) -> Result<SessionParts, VoxError> {
    let sessions = match ask(c, &Request::Sessions { channel_id }).await? {
        Frame::Sessions { sessions } => sessions,
        other => return Err(unexpected(&other)),
    };
    let rows = match ask(c, &Request::SessionEntries { channel_id }).await? {
        Frame::SessionEntries { rows } => rows,
        other => return Err(unexpected(&other)),
    };
    Ok((sessions, rows, Known::of(c).await?))
}

/// The open requests in the Session `s` that this node may answer: none without drive.
fn pending_in(
    s: &vox_core::node::sessions::SessionRow,
    sessions: &[vox_core::node::sessions::SessionRow],
    rows: &[vox_core::node::drive::SessionRow],
    known: &Known,
) -> u32 {
    if !s.can_drive || !s.open {
        return 0;
    }
    vox_core::node::session_view::read(
        sessions,
        rows.to_vec(),
        &s.id,
        Some(&s.node),
        &|r| known.label(r),
        known,
    )
    .map_or(0, |r| vox_core::node::session_view::pending(&r))
}

/// What a member with drive sends a session (ADR-029 DR-1), as `vox room session --say …` does.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum DriveAction {
    /// Typed as the operator's input, and submitted.
    Text {
        /// What is typed.
        text: String,
    },
    /// Esc: interrupt the turn it is running.
    Interrupt,
    /// Ctrl-C.
    Stop,
    /// A slash command, as typed: `/compact`, `/clear`, `/rename NAME`.
    Slash {
        /// The command and its arguments.
        command: String,
    },
    /// Approve the tool call waiting under `reference` (the request entry's `ref`).
    Approve {
        /// The request's `ref`.
        reference: String,
    },
    /// Reject it, with the reason the model is given.
    Reject {
        /// The request's `ref`.
        reference: String,
        /// Why.
        why: Option<String>,
    },
    /// Answer the question waiting under `reference`: question (its id or its text) → answer.
    Answer {
        /// The request's `ref`.
        reference: String,
        /// Each question's answer; several choices joined with ", ".
        answers: HashMap<String, String>,
    },
    /// Send the session a file (DR-1.7, #546): this node serves it to the session's node alone,
    /// which pulls it, verifies it and tells the session where it landed. The answer says it was
    /// accepted; where it landed, or why not, follows in the Session.
    File {
        /// The file, as this app can read it.
        path: String,
        /// A note the session is told with it.
        note: Option<String>,
    },
}

/// Whether a drive reached its session's node, and what that node said (DR-6).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum DriveDelivery {
    /// The session's node answered: [`DriveAnswer::ok`] says whether the input was delivered.
    Answered,
    /// The session's node could not be reached, or would not take drive input from this node.
    /// Nothing was sent.
    Unreachable,
    /// The request went out and no answer came: whether it was delivered is not known.
    NoAnswer,
}

/// The outcome of a drive.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DriveAnswer {
    /// Whether the input reached the session.
    pub ok: bool,
    /// What happened, or why not, in words to show as they are.
    pub said: String,
    /// Whether the session's node answered at all.
    pub delivery: DriveDelivery,
}

/// Something done to a room, said among its messages (ADR-028 R-1, R-7): its retention set, its
/// name changed. The client names who: "you", the alias, or the fingerprint marked not in keyring.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RoomNoticeRow {
    /// Its log entry's id.
    pub id: String,
    /// Who did it, base32.
    pub author: String,
    /// Their name in this node's keyring; empty when they are not in it.
    pub author_name: String,
    /// When, as its author's entry claims, milliseconds since the Unix epoch.
    pub created_millis: u64,
    /// What they did, without who, as the TUI says it: `set messages here to be kept for 1 week`.
    pub what: String,
    /// The id of the message it follows in the room's order, where it is drawn; empty before
    /// every message.
    pub after: String,
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
    /// A Session in `room` opened, ended or was renamed, or what in it waits on this node changed
    /// (ADR-029 CL-2): [`VoxClient::sessions`] has it now.
    fn on_sessions(&self, room: String);
    /// The Session `session_id` of the node `node` (its fingerprint) in `room` has a new entry, or
    /// a request in it was resolved: [`VoxClient::session_read`] has it now.
    fn on_session_entry(&self, room: String, node: String, session_id: String);
}

/// What the app last heard of a room's Sessions: each Session as [`VoxClient::sessions`] gives
/// it, and the entries of each session this node holds.
#[derive(Default)]
struct SessionsSeen {
    /// Each Session: its node, id, whether it is open, its name, whether this node may drive it,
    /// and what in it waits on this node.
    sessions: Vec<(Digest32, String, bool, Option<String>, bool, u32)>,
    /// Session id → its node, and the entries held for it.
    entries: HashMap<String, (Digest32, HashSet<Digest32>)>,
}

/// A room's Sessions as the app hears of them; `None` when the node will not say.
async fn sessions_seen(c: &mut IpcClient, room: Digest32) -> Option<SessionsSeen> {
    let (sessions, rows, known) = session_parts(c, room).await.ok()?;
    let mut seen = SessionsSeen {
        sessions: sessions
            .iter()
            .map(|s| {
                (
                    s.node,
                    s.id.clone(),
                    s.open,
                    s.name.clone(),
                    s.can_drive,
                    pending_in(s, &sessions, &rows, &known),
                )
            })
            .collect(),
        entries: HashMap::new(),
    };
    for r in &rows {
        // A driver's entry names the session; the Session is its node's.
        let node = sessions
            .iter()
            .find(|s| s.id == r.session_id)
            .map_or(r.author, |s| s.node);
        seen.entries
            .entry(r.session_id.clone())
            .or_insert_with(|| (node, HashSet::new()))
            .1
            .insert(r.entry_hash);
    }
    Some(seen)
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
/// The sentence vox-core writes for it, which the CLI shows too (ADR-028 E-7).
fn said(socket: &std::path::Path, e: Error) -> VoxError {
    failed(vox_core::node::daemonipc::unreached(socket, None, e))
}

/// An attach's failure, typed where a client acts on it (P4): a wrong passphrase is asked for
/// again; another process holding the node is no passphrase's to fix. Told apart by the daemon's
/// own refusal sentence for this node, word for word; anything else as [`said`] says it.
fn attach_said(socket: &std::path::Path, node: &NodeName, e: Error) -> VoxError {
    use vox_core::error::IpcHandshake;
    use vox_core::node::daemonipc::Refusal;
    if let Error::Ipc(IpcHandshake::Refused { reason }) = &e {
        if *reason == (Refusal::WrongPassphrase { node: node.clone() }).to_string() {
            return VoxError::WrongPassphrase {
                reason: reason.clone(),
            };
        }
        if *reason == (Refusal::NodeInUse { node: node.clone() }).to_string() {
            return VoxError::Busy {
                reason: reason.clone(),
            };
        }
    }
    said(socket, e)
}

/// A node's answer, with its refusal and a detach as errors.
fn answered(frame: Frame) -> Result<Frame, VoxError> {
    match frame {
        Frame::NodeDetached { node } => Err(VoxError::Detached {
            reason: format!("node {node} was detached from the vox daemon"),
        }),
        // The node says why as a sentence; the passphrase gate's is its own fault's, word for
        // word, so it is told apart here, once, and typed for the client (D1).
        Frame::Error { reason }
            if reason == vox_core::node::api::Fault::PassphraseNeeded.explain() =>
        {
            Err(VoxError::PassphraseNeeded { reason })
        }
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

/// Serve `path` to `node` alone, for a file driven into its Session (ADR-029 DR-1.7, #546), and
/// the drive action that says so; or why it cannot be served.
async fn start_file_for(
    client: &mut IpcClient,
    channel_id: Digest32,
    node: Digest32,
    path: &str,
    note: Option<String>,
) -> Result<vox_agentcomms::drive::Action, String> {
    let path = std::fs::canonicalize(path).map_err(|e| format!("{path}: {e}"))?;
    let note = note.map(|n| n.trim().to_owned()).filter(|n| !n.is_empty());
    let mut env = vox_agentcomms::envelope::Envelope::new(
        vox_core::node::shares::FILE,
        note.as_deref().unwrap_or(""),
    );
    if let Some(n) = &note {
        env.data = serde_json::json!({ "note": n });
    }
    let req = Request::SessionShare {
        channel_id,
        path: path.to_string_lossy().into_owned(),
        envelope: env.to_text(),
        to: vox_core::node::ipc::SessionTo::Node(node),
    };
    match ask(client, &req).await {
        Ok(Frame::Shares { shares }) => {
            let row = shares
                .into_iter()
                .next()
                .ok_or_else(|| "the vox daemon did not serve it".to_owned())?;
            Ok(vox_agentcomms::drive::Action::File {
                name: row.name,
                size: row.size,
                sha256: row.sha256,
                tag: row.tag,
                note,
            })
        }
        Ok(Frame::Error { reason }) => Err(reason),
        Ok(other) => Err(unexpected(&other).to_string()),
        Err(e) => Err(e.to_string()),
    }
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
    let (kind, text, to, re, urgent, file, image, card, platform) =
        match vox_agentcomms::envelope::Envelope::parse(&row.text) {
            Ok(env) => (
                shown_name(&env.kind),
                // What it says as every reader says it (#406): a Session's opening or end as
                // "<name · short id> opened", any other envelope with no text as "(<kind>
                // message, no text)", never a blank row. A share says its file in its card.
                match vox_agentcomms::envelope::session_line(&env) {
                    Some(line) => reveal(&line),
                    None if env.body.trim().is_empty()
                        && env.kind != vox_core::node::shares::FILE =>
                    {
                        vox_agentcomms::envelope::no_text(&shown_name(&env.kind))
                    }
                    None => reveal(&env.body),
                },
                env.to.iter().map(|t| shown_name(t)).collect(),
                env.re.as_deref().map(shown_name).unwrap_or_default(),
                env.urgent,
                file_offer(&env, names.contains_key(&row.author)),
                image_of(&env),
                card_of(&env),
                platform_of(&env),
            ),
            Err(_) => (
                vox_agentcomms::envelope::SAY.to_owned(),
                reveal(&row.text),
                Vec::new(),
                String::new(),
                false,
                None,
                None,
                None,
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
        image,
        card,
        platform,
        tags: vox_core::node::api::message_tags(&row.text)
            .iter()
            .map(|t| {
                vox_agentcomms::envelope::shown(
                    t,
                    vox_agentcomms::envelope::MAX_TAG + "milestone:".len(),
                )
            })
            .collect(),
    }
}

/// The most of each platform field shown, in bytes, as the CLI and the TUI show it: a node's claim,
/// so its length is the node's choice too.
const PLATFORM_FIELD: usize = 48;

/// The platform a `hello` says its node runs on (ADR-020 §4.9b), when it names at least the OS:
/// `os` (`macOS`, `Linux`, …), `os_version` (`26.2`, `Ubuntu 24.04.1 LTS`) and `arch`, filled by
/// that node's Vox. An older node's `hello` has none.
fn platform_of(env: &vox_agentcomms::envelope::Envelope) -> Option<NodePlatform> {
    if env.kind != vox_agentcomms::envelope::HELLO {
        return None;
    }
    let text = |k: &str| {
        env.data
            .get(k)
            .and_then(|v| v.as_str())
            .map(|v| vox_text::shown(v.trim(), PLATFORM_FIELD))
            .unwrap_or_default()
    };
    let os = text("os");
    (!os.is_empty()).then(|| NodePlatform {
        os,
        os_version: text("os_version"),
        arch: text("arch"),
    })
}

/// The file a `file` envelope offers, from the fields its sharer's daemon filled in.
fn file_offer(env: &vox_agentcomms::envelope::Envelope, sharer_trusted: bool) -> Option<FileOffer> {
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
        to: env.to.iter().map(|t| shown_name(t)).collect(),
        sharer_trusted,
    })
}

/// The keyring's names, by fingerprint. A read: the node checks no passphrase.
/// The keyring's names as a person reads them in messages, members, To: and the decision
/// record: two aliases that differ only in case each carry their fingerprint's first characters
/// (ADR-028 K-4, [`vox_text::alias::alias_of`]). The keyring's own rows keep the bare alias.
async fn names(client: &mut IpcClient) -> Result<HashMap<Digest32, String>, VoxError> {
    let entries: Vec<(Digest32, String)> = keyring(client)
        .await?
        .into_iter()
        .map(|(fp, name, _)| (fp, name))
        .collect();
    Ok(entries
        .iter()
        .map(|(fp, name)| {
            let shown =
                vox_text::alias::alias_of(&entries, fp, b32_encode).unwrap_or_else(|| name.clone());
            (*fp, shown)
        })
        .collect())
}

/// The keyring's entries: fingerprint, name as shown, and whether the entry grants drive.
async fn keyring(client: &mut IpcClient) -> Result<Vec<(Digest32, String, bool)>, VoxError> {
    match answered(
        client
            .trusted("")
            .await
            .map_err(|e| failed(e.to_string()))?,
    )? {
        Frame::Trusted { entries } => Ok(entries
            .into_iter()
            .map(|(fp, name, capability)| (fp, shown_name(&name), capability.drive()))
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

/// Send `req` and read its answer, as a refusal or a detach where it is one. A daemon that stops
/// answering once it was asked leaves it not known whether it was done.
async fn ask(client: &mut IpcClient, req: &Request) -> Result<Frame, VoxError> {
    answered(client.request(req).await.map_err(|e| VoxError::Unknown {
        reason: format!(
            "the vox daemon stopped answering before it said whether this was done: {e}"
        ),
    })?)
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

    /// `room` as the node's snapshot holds it, and the names it knows: `None` when the room is
    /// not open.
    async fn open_snap(
        &self,
        room: &str,
    ) -> Result<
        (
            Option<vox_core::node::snapshot::OpenRoomSnap>,
            HashMap<Digest32, String>,
        ),
        VoxError,
    > {
        let (open, names, _) = self.open_snap_me(room).await?;
        Ok((open, names))
    }

    /// [`Self::open_snap`], and this node's own fingerprint as the snapshot names it.
    async fn open_snap_me(
        &self,
        room: &str,
    ) -> Result<
        (
            Option<vox_core::node::snapshot::OpenRoomSnap>,
            HashMap<Digest32, String>,
            Option<Digest32>,
        ),
        VoxError,
    > {
        let channel_id = digest(room, "room id")?;
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
        Ok((
            snap.open.into_iter().find(|o| o.channel_id == channel_id),
            names,
            snap.me,
        ))
    }

    /// One of the node's marks on its own entries in `room`, from one snapshot: each entry's id
    /// and the sorted names of the members `pick` lists for it, entries with none left out.
    async fn own_marks(
        &self,
        room: String,
        pick: fn(vox_core::node::snapshot::OpenRoomSnap) -> Vec<(Digest32, Vec<Digest32>)>,
    ) -> Result<Vec<(String, Vec<String>)>, VoxError> {
        let (open, names) = self.open_snap(&room).await?;
        let name = |fp: &Digest32| {
            names
                .get(fp)
                .cloned()
                .unwrap_or_else(|| b32_encode(fp).chars().take(12).collect())
        };
        Ok(open
            .map(pick)
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, who)| !who.is_empty())
            .map(|(entry, who)| {
                let mut names: Vec<String> = who.iter().map(name).collect();
                names.sort();
                (b32_encode(&entry), names)
            })
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

    /// Make node `node` on this machine, as `vox node create` does: its identity sealed under
    /// `passphrase` (an empty one gives none, ADR-005 J-2, V030-36), with its prekey
    /// ring, in this client's data root; nothing goes over the socket. Returns its fingerprint,
    /// base32. Attach it next with [`VoxClient::attach`].
    ///
    /// # Errors
    /// A name a node cannot have, a node by that name already, another vox
    /// holding the node's directory, or one that cannot be written.
    pub async fn create_node(
        &self,
        node: String,
        passphrase: Arc<Passphrase>,
    ) -> Result<String, VoxError> {
        let name = NodeName::parse(&node).map_err(|e| failed(e.to_string()))?;
        let account = Account::of(Some(&self.data_root), Some(&self.config_dir))
            .map_err(|e| failed(format!("data root: {e}")))?;
        if account.nodes_on_disk().contains(&name) {
            return Err(failed(format!("there is a node {name} already")));
        }
        let paths = vox_core::node::paths::Paths::resolve(
            name.as_str(),
            Some(&self.data_root),
            Some(&self.config_dir),
        )
        .map_err(|e| failed(e.to_string()))?;
        let secret = passphrase.copy();
        // The node's own clock, a test step included (V210-64), as `vox node create` stamps it.
        let now_ms = (vox_core::time::clock_with_test_skew())();
        self.on_rt(async move {
            // Argon2id and the files: off the runtime's workers.
            tokio::task::spawn_blocking(move || {
                vox_core::node::profile::Profile::create_node(
                    paths,
                    secret.as_bytes(),
                    now_ms,
                    &|| {},
                )
                .map(|fp| b32_encode(&fp))
                .map_err(|e| match vox_core::node::actor::fault_of(&e) {
                    f @ (vox_core::node::api::Fault::IdentityFileUnwritable
                    | vox_core::node::api::Fault::Storage
                    | vox_core::node::api::Fault::ProfileBusy) => failed(f.to_string()),
                    _ => failed(e.to_string()),
                })
            })
            .await
            .map_err(|_| failed("making the node stopped"))?
        })
        .await
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
                .map_err(|e| attach_said(&socket, &name, e))?;
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
        let passphrase = passphrase.as_ref().map(|p| p.copy());
        // An empty passphrase is a node made with none (ADR-005 J-2): nothing is stored for it.
        let keep = match &passphrase {
            Some(p) if !p.is_empty() => KeepSource::Keychain(String::new()),
            _ => KeepSource::None,
        };
        let req = DaemonRequest::Attach {
            node: name,
            passphrase,
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

    /// Stop keeping `node` (ADR-014 M-6): it is no longer attached again when the daemon starts,
    /// and its Keychain item goes. Held by this client, it stays attached until released, then
    /// detaches as a node never kept does.
    ///
    /// # Errors
    /// The daemon's refusal.
    pub async fn unkeep(&self, node: String) -> Result<(), VoxError> {
        let name = NodeName::parse(&node).map_err(|e| failed(e.to_string()))?;
        match self.daemon(DaemonRequest::Unkeep { node: name }).await? {
            DaemonFrame::Ok => Ok(()),
            other => Err(failed(format!(
                "the vox daemon did not say node {node} is no longer kept ({other:?})"
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

    /// A room's messages tagged `tag` (#636), in the order they arrived: a thread of one task,
    /// project or milestone, found through the node's index of the tags of what it can read.
    ///
    /// # Errors
    /// A malformed id or tag, or the node's refusal (a closed room, or a node from before tags).
    pub async fn read_tagged(
        &self,
        room: String,
        tag: String,
    ) -> Result<Vec<RoomMessage>, VoxError> {
        let channel_id = digest(&room, "room id")?;
        if !vox_agentcomms::envelope::is_valid_tag(&tag) {
            return Err(failed(
                "not a tag: use task:, project: or milestone: and a value",
            ));
        }
        on_held!(self, |c| {
            let names = names(c).await?;
            let me = c.me().map(|f| b32_encode(&f));
            let frame = c
                .read_tagged(channel_id, std::slice::from_ref(&tag), None)
                .await
                .map_err(|e| VoxError::Unknown {
                    reason: format!(
                        "the vox daemon stopped answering before it said whether this was done: {e}"
                    ),
                })?;
            match answered(frame)? {
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
        let (to_fps, one_session) = addressed(&to)?;
        if !re.is_empty() {
            digest(&re, "message id")?;
        }
        let mut env = vox_agentcomms::envelope::Envelope::say(&text);
        env.to = to_fps;
        env.re = (!re.is_empty()).then(|| re.trim().to_owned());
        env.urgent = urgent;
        on_held!(self, |c| {
            sessions_addressable(c, channel_id, &one_session).await?;
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

    /// Give a room a new name, for every member (ADR-028 R-1), as `vox room rename`: only its
    /// creator or an admin may. No passphrase is asked for (ADR-028 K-11).
    ///
    /// # Errors
    /// A malformed id, or the node's refusal in its own words (this node may not rename the
    /// room; the name is not one DNS label).
    pub async fn rename_room(&self, room: String, name: String) -> Result<(), VoxError> {
        let req = Request::RenameRoom {
            channel_id: digest(&room, "room id")?,
            name,
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
    /// `vox room retention` does (ADR-023 decision 2); its creator or an admin only. No
    /// passphrase (ADR-028 K-11): the room's governance says who may.
    ///
    /// # Errors
    /// A malformed id, or the node's refusal (not the creator or an admin).
    pub async fn set_retention(&self, room: String, ttl_secs: u64) -> Result<(), VoxError> {
        let req = Request::SetRetention {
            channel_id: digest(&room, "room id")?,
            ttl: ttl_secs,
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

    /// Trust `fingerprint` under `name`, granting read, and drive as well when `drive` (ADR-028
    /// K-14, K-16). The identity passphrase is needed unless one was given for a keyring change
    /// within the keyring window; attaching opens no window (ADR-028 K-12).
    ///
    /// # Errors
    /// A malformed fingerprint, the passphrase needed or wrong, or the node's refusal.
    pub async fn trust_add(
        &self,
        fingerprint: String,
        name: String,
        drive: bool,
        identity_passphrase: Option<Arc<Passphrase>>,
    ) -> Result<(), VoxError> {
        let req = Request::Trust {
            target: digest(&fingerprint, "fingerprint")?,
            petname: name,
            identity_passphrase: copy_of(identity_passphrase.as_ref()),
            full_history: false,
            drive,
        };
        on_held!(self, |c| done(c, &req).await)
    }

    /// The trust keyring.
    ///
    /// # Errors
    /// The node's refusal.
    pub async fn trust_list(&self) -> Result<Vec<TrustedNode>, VoxError> {
        let mut list: Vec<TrustedNode> = on_held!(self, |c| keyring(c).await)?
            .into_iter()
            .map(|(fp, name, drive)| TrustedNode {
                fingerprint: b32_encode(&fp),
                name,
                drive,
            })
            .collect();
        list.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        Ok(list)
    }

    /// The nodes offered to the keyring (ADR-028 K-15 – K-18), in fingerprint order: as the node
    /// keeps them, so the TUI and the app always agree, dismissals included.
    ///
    /// # Errors
    /// The node's refusal.
    pub async fn pending_offers(&self) -> Result<Vec<OfferInfo>, VoxError> {
        on_held!(self, |c| match ask(c, &Request::Offers).await? {
            Frame::Offers { offers } => Ok(offers
                .into_iter()
                .map(|o| OfferInfo {
                    fingerprint: b32_encode(&o.member),
                    rooms: o
                        .rooms
                        .into_iter()
                        .map(|r| OfferRoom {
                            id: b32_encode(&r.id),
                            name: r.name,
                        })
                        .collect(),
                    why: o
                        .why
                        .into_iter()
                        .map(|w| match w {
                            vox_core::node::api::OfferWhy::Joined => OfferWhy::Joined,
                            vox_core::node::api::OfferWhy::TrustsYou => OfferWhy::TrustsYou,
                        })
                        .collect(),
                    trusted_by: o.trusted_by.iter().map(b32_encode).collect(),
                    said: o.said,
                })
                .collect()),
            other => Err(unexpected(&other)),
        })
    }

    /// Dismiss the offer of the node `fingerprint` (ADR-028 K-18): kept by the node, on this node
    /// alone; the node offered is not told and stays out of the keyring. Asks no passphrase.
    ///
    /// # Errors
    /// A malformed fingerprint, or the node's refusal.
    pub async fn dismiss_offer(&self, fingerprint: String) -> Result<(), VoxError> {
        let req = Request::DismissOffer {
            member: digest(&fingerprint, "fingerprint")?,
        };
        on_held!(self, |c| done(c, &req).await)
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

    /// Change what a trusted node's entry grants: read, and drive as well when `drive` (ADR-028
    /// K-14), as `vox trust drive|read`. A keyring change, behind the passphrase gate.
    ///
    /// # Errors
    /// As [`VoxClient::trust_add`].
    pub async fn set_capability(
        &self,
        fingerprint: String,
        drive: bool,
        identity_passphrase: Option<Arc<Passphrase>>,
    ) -> Result<(), VoxError> {
        let req = Request::SetCapability {
            target: digest(&fingerprint, "fingerprint")?,
            drive,
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

    /// What listens on this machine, for one-step sharing (ADR-028 S-4), as `vox serve` with no
    /// name lists it, and the sentence said under the list.
    ///
    /// **Read here, in the app's process, not by the daemon**, as `vox serve` and the TUI read it:
    /// unprivileged, `lsof` and `ss` see what the user running them may see, and the person
    /// sharing is the app's user. It needs no node attached.
    pub async fn listening(&self) -> ListeningServices {
        let found = self
            .rt
            .spawn_blocking(vox_core::node::probe::listening)
            .await
            .unwrap_or_default();
        ListeningServices {
            services: found
                .iter()
                .map(|l| ListeningService {
                    port: l.port,
                    udp: l.udp,
                    program: l.command.clone(),
                    addresses: l
                        .addrs
                        .iter()
                        .map(|a| std::net::SocketAddr::new(*a, l.port).to_string())
                        .collect(),
                    every_interface: l.on_every_interface(),
                    line: vox_core::node::probe::listing_line(l).trim_end().to_owned(),
                })
                .collect(),
            may_be_missing: vox_core::node::probe::MAY_BE_MISSING.to_owned(),
        }
    }

    /// What sharing the service listening on `port` would do (ADR-028 S-4), said before it is
    /// done, as `vox serve` with no name says it; `udp` picks one of two on the same port, `None`
    /// the first. Share it with `service_add(room, tag, local)`.
    ///
    /// # Errors
    /// Nothing this user can see listens on that port.
    pub async fn service_preview(
        &self,
        port: u16,
        udp: Option<bool>,
    ) -> Result<ServicePreview, VoxError> {
        self.on_rt(async move {
            let found = tokio::task::spawn_blocking(vox_core::node::probe::listening)
                .await
                .unwrap_or_default();
            let chosen = found
                .into_iter()
                .find(|l| l.port == port && udp.is_none_or(|u| l.udp == u))
                .ok_or_else(|| {
                    failed(format!(
                        "nothing listening on port {port} can be seen from here; {}",
                        vox_core::node::probe::MAY_BE_MISSING
                    ))
                })?;
            let local = chosen.endpoint();
            let name = vox_core::node::probe::suggested_name(&chosen).await;
            let tag = vox_core::node::probe::tag_of(name.clone(), chosen.udp);
            let warnings = vox_core::node::probe::exposure_warnings(
                &[(chosen.port, tag.clone())],
                Some(local),
            )
            .await;
            Ok(ServicePreview {
                name,
                tag,
                local: local.to_string(),
                warnings,
            })
        })
        .await
    }

    /// What is shared in `room` and what this node offers there (`vox service list`).
    ///
    /// # Errors
    /// A malformed id, or the node's refusal.
    pub async fn services(&self, room: String) -> Result<RoomServices, VoxError> {
        let channel_id = digest(&room, "room id")?;
        // Whether the `.vox` proxy runs, for the needs of ssh by address and of a URL, asked as
        // `vox service list` asks it.
        let held = Arc::clone(&self.held);
        let proxy = self
            .on_rt(async move {
                let at = held
                    .lock()
                    .await
                    .as_ref()
                    .map(|h| h.at.clone())
                    .ok_or_else(not_attached)?;
                Ok(vox_core::node::nameipc::proxy(&at)
                    .await
                    .map_err(|e| match e {
                        Error::AppRefused(reason) => reason,
                        other => other.to_string(),
                    }))
            })
            .await?;
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
                        .map(|s| {
                            use vox_core::node::service_reach::{commands, needs};
                            SharedService {
                                commands: commands(&s)
                                    .into_iter()
                                    .map(|(what, command)| ServiceCommand {
                                        what: what.to_owned(),
                                        command,
                                    })
                                    .collect(),
                                needs: needs(&s, Some(&proxy))
                                    .into_iter()
                                    .map(|(need, holds, otherwise)| ServiceNeed {
                                        need: shown_name(&need),
                                        holds,
                                        otherwise: shown_name(&otherwise),
                                    })
                                    .collect(),
                                address: shown_name(&s.address),
                                canonical: s.canonical,
                                by: shown_name(&s.by),
                                udp: s.udp,
                                kind: shown_name(&s.kind),
                            }
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
                    .map_err(|e| failed(e.to_string()))
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
        let (to_fps, one_session) = addressed(&to)?;
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
            sessions_addressable(c, channel_id, &one_session).await?;
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

    /// The Sessions of `room`, oldest opening first (ADR-029; `vox room sessions`).
    ///
    /// # Errors
    /// A malformed id, or the node's refusal (a room not open).
    pub async fn sessions(&self, room: String) -> Result<Vec<FfiSession>, VoxError> {
        let channel_id = digest(&room, "room id")?;
        on_held!(self, |c| {
            let (sessions, rows, known) = session_parts(c, channel_id).await?;
            Ok(sessions
                .iter()
                .map(|s| FfiSession {
                    node_fingerprint: b32_encode(&s.node),
                    node_alias: known.names.get(&s.node).cloned().unwrap_or_default(),
                    short_id: s.id.chars().take(8).collect(),
                    label: known.label(s),
                    session_id: s.id.clone(),
                    name: s.name.clone(),
                    open: s.open,
                    opened_at_ms: s.opened_millis,
                    ended_at_ms: s.ended_millis,
                    can_drive: s.can_drive,
                    pending: pending_in(s, &sessions, &rows, &known),
                })
                .collect())
        })
    }

    /// One Session of `room`, the session `session_id` of the node `node` (its fingerprint), read
    /// as `vox room session` reads it (ADR-029 SC-1, CL-1): its entries in order, each line word
    /// for word. An ended Session stays readable (SE-5); one whose opening has not reached this
    /// node is read from its entries, with a note saying so. Without drive, no entries and a note
    /// saying whose trust this node lacks (SC-3).
    ///
    /// # Errors
    /// A malformed id, the node's refusal, or no such Session, said as `vox room session` says it.
    pub async fn session_read(
        &self,
        room: String,
        node: String,
        session_id: String,
    ) -> Result<FfiSessionRead, VoxError> {
        use vox_core::node::session_view::{details_text, read, OPENING_NOT_RECEIVED};
        let channel_id = digest(&room, "room id")?;
        let node = digest(&node, "node's fingerprint")?;
        // Where each file this node pulled landed, by its entry (ADR-028 F-6).
        let pulled: HashMap<String, String> = self
            .pulled(room)
            .await?
            .into_iter()
            .map(|p| (p.entry, p.path))
            .collect();
        on_held!(self, |c| {
            let (sessions, rows, known) = session_parts(c, channel_id).await?;
            let r = read(
                &sessions,
                rows,
                &session_id,
                Some(&node),
                &|s| known.label(s),
                &known,
            )
            .map_err(failed)?;
            let note = r.hidden.clone().or_else(|| {
                (r.state == OPENING_NOT_RECEIVED).then(|| OPENING_NOT_RECEIVED.to_owned())
            });
            Ok(FfiSessionRead {
                entries: r
                    .lines
                    .iter()
                    .map(|l| FfiSessionEntry {
                        id: b32_encode(&l.id),
                        at_ms: l.at_millis,
                        line: l.text.clone(),
                        details: details_text(l),
                        file: l.file.as_ref().map(|f| FfiSessionFile {
                            name: shown_name(&f.name),
                            size: f.size,
                            sha256: f.sha256.clone(),
                            from_session: f.from_session,
                            entry: b32_encode(&l.id),
                            pulled_path: pulled.get(&b32_encode(&l.id)).cloned(),
                        }),
                        request: l.request.as_ref().map(|q| FfiRequest {
                            reference: q.reference.clone(),
                            is_question: q.is_question,
                            questions: q
                                .questions
                                .iter()
                                .map(|(text, options)| FfiQuestion {
                                    text: text.clone(),
                                    options: options.clone(),
                                })
                                .collect(),
                            state: q.state.clone(),
                        }),
                    })
                    .collect(),
                note,
            })
        })
    }

    /// Drive the open Session `session` (its whole id) of `room` (ADR-029 §3, #544): the input
    /// reaches that session alone, or the session's node says why not. A refusal is an answer
    /// (`ok` false, the reason in `said`), not an error.
    ///
    /// # Errors
    /// A malformed room id, no open Session with that id, or the node's refusal to list them.
    pub async fn drive(
        &self,
        room: String,
        session: String,
        action: DriveAction,
    ) -> Result<DriveAnswer, VoxError> {
        use vox_agentcomms::drive::{Action, Request as Drive};
        let channel_id = digest(&room, "room id")?;
        // A file is served before it is said: its share is started once the Session's node is
        // known, below.
        let mut file = None;
        let action = match action {
            DriveAction::File { path, note } => {
                file = Some((path, note));
                Action::Interrupt
            }
            DriveAction::Text { text } => Action::Text { text },
            DriveAction::Interrupt => Action::Interrupt,
            DriveAction::Stop => Action::Stop,
            DriveAction::Slash { command } => Action::Slash { text: command },
            DriveAction::Approve { reference } => Action::Approve { r#ref: reference },
            DriveAction::Reject { reference, why } => Action::Reject {
                r#ref: reference,
                why,
            },
            DriveAction::Answer { reference, answers } => Action::Answer {
                r#ref: reference,
                answers: answers.into_iter().collect(),
            },
        };
        let held = Arc::clone(&self.held);
        self.on_rt(async move {
            let (at, node, trusted, action, shown) = {
                let mut slot = held.lock().await;
                let h = slot.as_mut().ok_or_else(not_attached)?;
                let names = names(&mut h.client).await?;
                let sessions = match ask(&mut h.client, &Request::Sessions { channel_id }).await? {
                    Frame::Sessions { sessions } => sessions,
                    other => return Err(unexpected(&other)),
                };
                let row = sessions
                    .into_iter()
                    .find(|s| s.id == session && s.open)
                    .ok_or_else(|| failed("no open Session in this room has that id"))?;
                // This node's own Sessions it drives as their operator (SC-2), over its own socket.
                let trusted = names.contains_key(&row.node) || h.client.me() == Some(row.node);
                // The session's node as this node knows it: its alias, or its short fingerprint.
                let shown = names
                    .get(&row.node)
                    .filter(|a| !a.is_empty())
                    .cloned()
                    .unwrap_or_else(|| b32_encode(&row.node).chars().take(12).collect());
                let action = match file {
                    Some((path, note)) if trusted => {
                        match start_file_for(&mut h.client, channel_id, row.node, &path, note).await
                        {
                            Ok(a) => a,
                            Err(said) => {
                                return Ok(DriveAnswer {
                                    ok: false,
                                    said: format!("not sent: {said}"),
                                    delivery: DriveDelivery::Unreachable,
                                })
                            }
                        }
                    }
                    _ => action,
                };
                (h.at.clone(), row.node, trusted, action, shown)
            };
            // The app gate opens a stream only between nodes that trust each other; a member
            // with drive trusts the session's node already, since it reads the Session only
            // through that node's drive key (#543).
            if !trusted {
                return Ok(DriveAnswer {
                    ok: false,
                    said: format!(
                        "you do not trust {shown}, so you cannot drive or read its Sessions"
                    ),
                    delivery: DriveDelivery::Unreachable,
                });
            }
            let request = Drive {
                v: 1,
                session,
                action,
            };
            let file_tag = match &request.action {
                Action::File { tag, .. } => Some(tag.clone()),
                _ => None,
            };
            let answer =
                match vox_core::node::drive_input::send(&at, channel_id, node, &request).await {
                    Ok(a) => DriveAnswer {
                        ok: a.ok,
                        said: a.said_to(&shown),
                        delivery: DriveDelivery::Answered,
                    },
                    Err(vox_core::node::drive_input::Unsent::Unreachable(said)) => DriveAnswer {
                        ok: false,
                        said,
                        delivery: DriveDelivery::Unreachable,
                    },
                    Err(vox_core::node::drive_input::Unsent::NoAnswer(said)) => DriveAnswer {
                        ok: false,
                        said,
                        delivery: DriveDelivery::NoAnswer,
                    },
                };
            // A file not taken is served to no one, so not served at all.
            if let (Some(tag), false) = (file_tag, answer.ok) {
                if let Some(h) = held.lock().await.as_mut() {
                    let _ = ask(
                        &mut h.client,
                        &Request::ShareStop {
                            channel_id,
                            selector: tag,
                        },
                    )
                    .await;
                }
            }
            Ok(answer)
        })
        .await
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

    /// This node's decision record, newest first (ADR-028 §7, D-1, D-2): every event it keeps
    /// (14 days), as the TUI's Decisions screen shows it. Read by the node, which alone opens
    /// the record: it is sealed at rest under the identity (#563).
    ///
    /// # Errors
    /// No node attached, or the node did not answer.
    pub async fn decisions(&self) -> Result<Vec<DecisionEvent>, VoxError> {
        let held = Arc::clone(&self.held);
        self.on_rt(async move {
            // Read by the node, which alone opens the sealed record (#563).
            let found = {
                let mut slot = held.lock().await;
                let h = slot.as_mut().ok_or_else(not_attached)?;
                match ask(&mut h.client, &Request::Decisions { limit: u64::MAX }).await? {
                    Frame::Decisions { events } => events,
                    other => return Err(unexpected(&other)),
                }
            };
            let mut events: Vec<DecisionEvent> = found
                .into_iter()
                .map(|e| DecisionEvent {
                    at_millis: e.at_ms,
                    asked: shown_name(&e.asked),
                    by: shown_name(&e.by),
                    alias: e.alias.as_deref().map(shown_name).unwrap_or_default(),
                    decided: shown_name(&e.decided),
                    why: shown_name(&e.why),
                    room: e.room.as_deref().map(shown_name).unwrap_or_default(),
                })
                .collect();
            events.sort_by(|a, b| b.at_millis.cmp(&a.at_millis));
            Ok(events)
        })
        .await
    }

    /// **Pull the file the message `entry` of `room` offers, now** (ADR-028 F-3; D5), as `vox
    /// room get` does: whoever it is addressed to, and from a sharer not in the keyring too, since
    /// a person asked. Its SHA-256 is checked before it is kept, so nothing unverified is ever
    /// where the app looks. Returns where the verified copy is; one already pulled is not pulled
    /// again. [`Self::pull_states`] says how it is going meanwhile.
    ///
    /// # Errors
    /// No node attached, a malformed id, or why it could not be pulled, in the node's words.
    pub async fn get(&self, room: String, entry: String) -> Result<String, VoxError> {
        let channel_id = digest(&room, "room id")?;
        let entry = digest(&entry, "message id")?;
        // On a connection of its own: a pull can take as long as the file does, and the app's
        // other requests do not wait behind it.
        let held = Arc::clone(&self.held);
        let socket = self.socket.clone();
        self.on_rt(async move {
            let at = {
                let slot = held.lock().await;
                slot.as_ref().ok_or_else(not_attached)?.at.clone()
            };
            let mut c = IpcClient::open_at(&at)
                .await
                .map_err(|e| said(&socket, e))?;
            match ask(&mut c, &Request::Pull { channel_id, entry }).await? {
                Frame::Pulled { path } => Ok(path),
                other => Err(unexpected(&other)),
            }
        })
        .await
    }

    /// Where the pulls of `room`'s file offers stand that are not done (D5): being pulled, with
    /// how much has come; waiting to be tried again; or asked for and failed. One pulled is in
    /// [`Self::pulled`].
    ///
    /// # Errors
    /// No node attached, a malformed id, or the node's refusal.
    pub async fn pull_states(&self, room: String) -> Result<Vec<OfferPull>, VoxError> {
        use vox_core::node::pulls::PullState as P;
        let channel_id = digest(&room, "room id")?;
        on_held!(self, |c| {
            match ask(c, &Request::PullStates { channel_id }).await? {
                Frame::PullStates { states } => Ok(states
                    .into_iter()
                    .map(|(entry, state)| OfferPull {
                        entry: b32_encode(&entry),
                        state: match state {
                            P::Pulling { bytes, of } => PullState::Pulling { bytes, of },
                            P::Waiting { why } => PullState::Waiting { why },
                            P::Failed { why } => PullState::Failed { why },
                        },
                    })
                    .collect()),
                other => Err(unexpected(&other)),
            }
        })
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
                    created: p.created_ms / 1_000,
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
        Ok(self
            .own_marks(room, |o| o.read_by)
            .await?
            .into_iter()
            .map(|(id, names)| ReadBy { id, names })
            .collect())
    }

    /// What a member's client says when `member` joins `room` (ADR-028 K-7), word for word as the
    /// TUI says it: its name (alias, else its fingerprint marked "(not in keyring)"), "joined.",
    /// and which nodes in this node's keyring trust it, from the consent grants on the room's log.
    /// It adds nothing to any keyring.
    ///
    /// # Errors
    /// A malformed id, the room not open here, or the daemon's refusal.
    pub async fn join_said(&self, room: String, member: String) -> Result<String, VoxError> {
        let who = digest(&member, "member fingerprint")?;
        let (open, names) = self.open_snap(&room).await?;
        let Some(open) = open else {
            return Err(failed("the room is not open on this node"));
        };
        let mut trusters: Vec<String> = open
            .trusted_by
            .iter()
            .find(|(m, _)| *m == who)
            .map(|(_, by)| by.iter().filter_map(|fp| names.get(fp).cloned()).collect())
            .unwrap_or_default();
        trusters.sort();
        let name = vox_text::offer::name(names.get(&who).map(String::as_str), &b32_encode(&who));
        Ok(format!(
            "{name} joined. {}",
            vox_text::offer::trusted_by(&trusters)
        ))
    }

    /// Where each of this node's own recent messages in `room` is (ADR-028 R-6), from how many of
    /// the other members' nodes said they hold it, in the TUI's words: what a message no member
    /// has read says.
    ///
    /// # Errors
    /// A malformed id, or the daemon's refusal.
    pub async fn whereabouts(&self, room: String) -> Result<Vec<Whereabouts>, VoxError> {
        let (open, _, me) = self.open_snap_me(&room).await?;
        let Some(open) = open else {
            return Ok(Vec::new());
        };
        let others = open.members.iter().filter(|m| me != Some(**m)).count() as u64;
        Ok(open
            .held
            .iter()
            .map(|(entry, held)| Whereabouts {
                id: b32_encode(entry),
                words: vox_text::read::whereabouts(*held, others),
            })
            .collect())
    }

    /// What was done to `room`, in the room's order, as the TUI says it among the messages
    /// (ADR-028 R-1, R-7): who set its retention, who renamed it, and the message each follows.
    ///
    /// # Errors
    /// A malformed id, the room not open, or the daemon's refusal.
    pub async fn notices(&self, room: String) -> Result<Vec<RoomNoticeRow>, VoxError> {
        let (open, names) = self.open_snap(&room).await?;
        let Some(open) = open else {
            return Err(failed("the room is not open on this node"));
        };
        Ok(open
            .notices
            .into_iter()
            .map(|n| RoomNoticeRow {
                id: b32_encode(&n.entry_hash),
                author: b32_encode(&n.author),
                author_name: names.get(&n.author).cloned().unwrap_or_default(),
                created_millis: n.created_millis,
                what: n.what,
                after: n.after.map(|a| b32_encode(&a)).unwrap_or_default(),
            })
            .collect())
    }

    /// How long `room` keeps messages here, as a person reads it ("1 week", "forever"), as the
    /// TUI's timeline title says it (ADR-028 R-7).
    ///
    /// # Errors
    /// A malformed id, the room not open, or the daemon's refusal.
    pub async fn retention(&self, room: String) -> Result<String, VoxError> {
        match self.open_snap(&room).await?.0 {
            Some(open) => Ok(vox_core::node::retention::describe(open.retention)),
            None => Err(failed("the room is not open on this node")),
        }
    }

    /// How long `room` keeps messages here, in seconds; 0 for forever (ADR-028 R-7, F-5): what a
    /// retention change starts from, so it never opens at a value the room does not keep.
    ///
    /// # Errors
    /// A malformed id, the room not open, or the daemon's refusal.
    pub async fn retention_secs(&self, room: String) -> Result<u64, VoxError> {
        match self.open_snap(&room).await?.0 {
            Some(open) => Ok(open.retention),
            None => Err(failed("the room is not open on this node")),
        }
    }

    /// Who has pulled this node's own shares in `room` whole and verified them (ADR-028 F-7), from
    /// the daemon's record of completed fetches, as `vox room read` says "pulled by": a fetch cut
    /// short is in none.
    ///
    /// # Errors
    /// A malformed id, or the daemon's refusal.
    pub async fn pulled_by(&self, room: String) -> Result<Vec<PulledBy>, VoxError> {
        Ok(self
            .own_marks(room, |o| o.pulled_by)
            .await?
            .into_iter()
            .map(|(id, names)| PulledBy { id, names })
            .collect())
    }

    /// What this node's person has not read in `room`, oldest first (ADR-028 R-8): the messages
    /// after the newest one the node recorded as read, by someone else. A client counts its unread
    /// from these when it starts, then from the node's events.
    ///
    /// # Errors
    /// A malformed id, or the node's refusal (the room not open).
    pub async fn unread(&self, room: String) -> Result<Vec<RoomMessage>, VoxError> {
        let channel_id = digest(&room, "room id")?;
        on_held!(self, |c| {
            let names = names(c).await?;
            let me = c.me().map(|f| b32_encode(&f));
            match ask(c, &Request::Unread { channel_id }).await? {
                Frame::Rows { rows } => Ok(rows
                    .iter()
                    .map(|r| rendered(r, &names, me.as_deref()))
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
        let (stream, cursors, seen) = self
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
                    let mut seen = HashMap::new();
                    for (id, _, open, _) in room_ids(&mut h.client).await? {
                        if !open {
                            continue;
                        }
                        if let Some(s) = sessions_seen(&mut h.client, id).await {
                            seen.insert(id, s);
                        }
                        let req = Request::Count {
                            channel_id: id,
                            since: None,
                        };
                        if let Frame::Count { last, .. } = ask(&mut h.client, &req).await? {
                            cursors.insert(id, last);
                        }
                    }
                    Ok((stream, cursors, seen))
                }
            })
            .await?;
        self.rt.spawn(follow(stream, cursors, seen, held, listener));
        Ok(())
    }
}

/// The event loop behind [`VoxClient::subscribe`].
async fn follow(
    mut stream: IpcClient,
    mut cursors: HashMap<Digest32, Option<Digest32>>,
    mut seen: HashMap<Digest32, SessionsSeen>,
    held: Slot,
    listener: Arc<dyn ClientListener>,
) {
    let mut delivered: HashSet<Digest32> = HashSet::new();
    loop {
        // The rooms whose Sessions this event may have changed, besides those it brought messages
        // to: a Session's opening and end are room messages; its entries are not.
        let mut sessions_in: Vec<Digest32> = Vec::new();
        let rooms: Vec<Digest32> = match stream.next().await {
            // A new entry, with its row: delivered as it came, as `vox room tail` delivers it. Read
            // back instead, it could come from the room's view before the node published the row in
            // it, find nothing, and be lost for good with no later event to read it again (the
            // walkthrough's WHERE-15, posted with every peer offline). The cursor stays where reads
            // left it: a row rendered late still sits after it, and `delivered` keeps this one from
            // being told twice when a later read returns it.
            Ok(Some(Frame::Event(NodeEvent::NewEntry { channel_id, row }))) => {
                if cursors.contains_key(&channel_id)
                    && !row.owed
                    && delivered.insert(row.entry_hash)
                {
                    let message = {
                        let mut slot = held.lock().await;
                        let Some(h) = slot.as_mut() else {
                            listener.on_ended("the app released its node".to_owned());
                            return;
                        };
                        let names = names(&mut h.client).await.unwrap_or_default();
                        let me = h.client.me().map(|f| b32_encode(&f));
                        rendered(&row, &names, me.as_deref())
                    };
                    listener.on_message(b32_encode(&channel_id), message);
                }
                sessions_in.push(channel_id);
                Vec::new()
            }
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
            // A Session's news (ADR-029 CL-2): told below, with the room's Sessions read again.
            Ok(Some(Frame::Event(NodeEvent::SessionEntry { channel_id, .. }))) => {
                sessions_in.push(channel_id);
                Vec::new()
            }
            // Anything else the node says. Who has drive changed: what every room's Sessions let
            // this node see and answer.
            Ok(Some(Frame::Event(ev))) => {
                if matches!(ev, NodeEvent::CapabilityChanged { .. }) {
                    sessions_in.extend(cursors.keys().copied());
                }
                listener.on_notice(ev.words());
                Vec::new()
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
        sessions_in.extend(rooms.iter().copied());
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
        sessions_in.sort_unstable();
        sessions_in.dedup();
        sessions_in.retain(|r| cursors.contains_key(r));
        if !sessions_told(&sessions_in, &mut seen, &held, listener.as_ref()).await {
            return;
        }
    }
}

/// Read the Sessions of `rooms` again and tell the listener what changed: a Session opened,
/// ended, renamed or waiting differently ([`ClientListener::on_sessions`]), and a session with
/// entries it had not held ([`ClientListener::on_session_entry`]). `false` once the node is let go
/// of: nothing more will come.
async fn sessions_told(
    rooms: &[Digest32],
    seen: &mut HashMap<Digest32, SessionsSeen>,
    held: &Slot,
    listener: &dyn ClientListener,
) -> bool {
    for &room in rooms {
        let now = {
            let mut slot = held.lock().await;
            let Some(h) = slot.as_mut() else {
                listener.on_ended("the app released its node".to_owned());
                return false;
            };
            match sessions_seen(&mut h.client, room).await {
                Some(now) => now,
                None => continue,
            }
        };
        let before = seen.remove(&room).unwrap_or_default();
        if now.sessions != before.sessions {
            listener.on_sessions(b32_encode(&room));
        }
        for (id, (node, entries)) in &now.entries {
            let old = before.entries.get(id).map(|(_, e)| e);
            if old.is_none_or(|old| entries.iter().any(|e| !old.contains(e))) {
                listener.on_session_entry(b32_encode(&room), b32_encode(node), id.clone());
            }
        }
        seen.insert(room, now);
    }
    true
}
