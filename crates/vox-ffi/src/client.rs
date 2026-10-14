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

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use tokio::runtime::{Handle, Runtime};
use vox_core::error::Error;
use vox_core::hash::Digest32;
use vox_core::node::api::{HistoryCursor, MessageRow, NodeEvent};
use vox_core::node::daemonipc::{
    AttachMode, DaemonClient, DaemonFrame, DaemonRequest, KeepSource, NodeName, NodeState, UseNode,
};
use vox_core::node::ipc::{Frame, IpcClient, NodeSocket, Request, SessionSummary};
use vox_core::node::link::b32_encode;
use vox_core::node::paths::Account;
use vox_core::node::resolver::ShareState;
use zeroize::Zeroizing;

use crate::{digest, failed, input_fingerprint, VoxError};

/// One bounded footer page for an exact displayed message. Continuations mean more people;
/// clients replace a viewed recipient page instead of accumulating every historical recipient.
#[derive(Clone, Debug, uniffi::Record)]
pub struct MessageFooter {
    /// Selected message identity.
    pub id: String,
    /// False when this is no longer a readable own message.
    pub present: bool,
    /// Names in this reader page.
    pub read_by: Vec<String>,
    /// Continue readers after this opaque fingerprint.
    pub read_after: Option<String>,
    /// Current delivery wording for the exact message.
    pub whereabouts: String,
    /// Names in this completed-fetch page.
    pub pulled_by: Vec<String>,
    /// Continue completed-fetch disk records at this stable offset.
    pub pulled_after: Option<u64>,
}
/// Exact footer response on the caller's saved room.
#[derive(Clone, Debug, uniffi::Record)]
pub struct MessageFooters {
    /// The validated saved-room identity.
    pub instance: Vec<u8>,
    /// One row per requested id, including explicit absence.
    pub rows: Vec<MessageFooter>,
}

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
    /// `Ready` or `Locked`; absent while the daemon is starting or stopping this node.
    pub status: Option<String>,
    /// Its identity fingerprint, base32; empty until the daemon knows it.
    pub fingerprint: String,
    /// Attached with `--keep`: attached again whenever the daemon starts.
    pub keep: bool,
}

/// One source in the daemon's shared machine anchor inventory.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AnchorSourceSummary {
    /// added-by-hand or room.
    pub kind: String,
    /// Full room identity for a room source.
    pub room: Option<String>,
    /// Last observed shared room name.
    pub name: Option<String>,
    /// The source includes a closed or locked observation.
    pub stale: bool,
}

/// Real authenticated-dial observations; absent means no observation by a running node.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AnchorReachSummary {
    /// An observing node currently holds an authenticated connection.
    pub connected: bool,
    /// Most recent authenticated anchor dial, Unix milliseconds.
    pub last_reached_ms: Option<u64>,
    /// No observing node has a connection since this Unix time.
    pub unreached_since_ms: Option<u64>,
}

/// The shared machine record, also used by a room's members panel by matching source.room.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AnchorSummary {
    /// Full anchor fingerprint, base32.
    pub fingerprint: String,
    /// Configured addresses, deduplicated.
    pub addresses: Vec<String>,
    /// Independent manual and saved-room provenance.
    pub sources: Vec<AnchorSourceSummary>,
    /// Absent until a running node has a dial observation.
    pub reach: Option<AnchorReachSummary>,
    /// Daemon-derived reach words for display.
    pub reach_text: String,
}

impl From<vox_core::node::daemonipc::AnchorInfo> for AnchorSummary {
    fn from(anchor: vox_core::node::daemonipc::AnchorInfo) -> Self {
        let reach_text = anchor.reach_words(vox_core::transport::quic::unix_now_ms());
        Self {
            fingerprint: b32_encode(&anchor.fingerprint),
            addresses: anchor.addresses,
            sources: anchor
                .sources
                .into_iter()
                .map(|source| match source {
                    vox_core::node::daemonipc::AnchorSource::AddedByHand => AnchorSourceSummary {
                        kind: "added-by-hand".into(),
                        room: None,
                        name: None,
                        stale: false,
                    },
                    vox_core::node::daemonipc::AnchorSource::Room { room, name, stale } => {
                        AnchorSourceSummary {
                            kind: "room".into(),
                            room: Some(b32_encode(&room)),
                            name: Some(name),
                            stale,
                        }
                    }
                })
                .collect(),
            reach: anchor.reach.map(|r| AnchorReachSummary {
                connected: r.connected,
                last_reached_ms: r.last_reached_ms,
                unreached_since_ms: r.unreached_since_ms,
            }),
            reach_text,
        }
    }
}

/// The selected node's current room-anchor editing capability, not a cached UI decision.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RoomAnchorAuthority {
    /// Full room identity that was queried.
    pub room: String,
    /// Full identity of the held actor that the daemon answered for.
    pub node: String,
    /// The room creator and currently delegated admins only.
    pub can_manage: bool,
}

/// An anchor and the addresses named by this room's own signed configuration.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RoomAnchorEndpoint {
    /// Full anchor identity.
    pub fingerprint: String,
    /// Only the addresses recorded for this anchor in the selected room.
    pub addresses: Vec<String>,
}

/// Exactly what a newly created room's link would carry on this node now.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RoomLinkPreview {
    /// Full fingerprint of the node whose addresses were read.
    pub node: String,
    /// Room anchors inside the link cap, in the link's order.
    pub anchors: Vec<RoomAnchorEndpoint>,
    /// This node's own direct route, separate from the room's anchors.
    pub direct: Option<RoomAnchorEndpoint>,
    /// Selected room anchors kept in the configuration but omitted from the link.
    pub omitted: u32,
}

/// The held node's current observation of one room's signed anchor configuration.
/// Identity-level reach observations are separate and do not prove these addresses were dialed.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RoomAnchorConfiguration {
    /// Full room identity that was queried.
    pub room: String,
    /// Full identity of the held actor that answered.
    pub node: String,
    /// The room's anchors only; machine and other-room sources are excluded.
    pub anchors: Vec<RoomAnchorEndpoint>,
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

/// Independent Session-step retention (ADR-031 SA-9); zero seconds means forever.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiStepRetention {
    /// The room's configured step lifetime, before message retention clamps it.
    pub room_seconds: u64,
    /// The room's step lifetime clamped by its configured message lifetime.
    pub room_cap_seconds: u64,
    /// What this node actually retains, including its shorter message/step choices.
    pub effective_seconds: u64,
    /// This node's explicit shorter step choice, if any.
    pub local_seconds: Option<u64>,
}

/// The message domain of one native room window. All adds Session lifecycle notices
/// separately; its message domain is the same General roots, not every thread reply.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum RoomView {
    /// General messages and readable owed placeholders.
    General,
    /// General messages, with separate Session lifecycle notices supplied by the caller.
    All,
    /// Messages carrying one exact raw tag, including replies.
    Tag {
        /// The raw key from FfiMessageTag; never its escaped display label.
        key: String,
    },
}
impl RoomView {
    fn core(&self) -> Result<vox_core::node::api::RoomView, VoxError> {
        use vox_core::node::api::RoomView as Core;
        Ok(match self {
            Self::General => Core::General,
            Self::All => Core::All,
            Self::Tag { key } => {
                if !vox_agentcomms::envelope::is_valid_tag(key) {
                    return Err(failed("The selected room tag is invalid."));
                }
                Core::Tag(key.clone())
            }
        })
    }
}

/// A tag's exact selection identity and separately escaped, bounded display label.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiMessageTag {
    /// Raw validated tag for RoomView::Tag; never decode a label to recover this value.
    pub key: String,
    /// Safe label for visible text and accessibility.
    pub label: String,
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
    /// The canonical General message whose thread contains this reply, or empty for General.
    /// This comes from `thread`, independently of the immediate reply target `re`.
    pub thread: String,
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
    /// Exact raw selectors paired with the same safe labels as tags, in the same order.
    pub tag_selectors: Vec<FfiMessageTag>,
    /// Source data.work, safely displayed as opaque plain text; never a tracker link.
    pub work: String,
}

/// One daemon-folded current claim or outstanding addressed relationship (ADR-033 WD).
#[derive(Debug, Clone, uniffi::Record)]
pub struct MemberWork {
    /// Responsible member's complete fingerprint.
    pub member: String,
    /// Exact Session, empty for a node-wide address.
    pub session: String,
    /// Claim, handoff, ask, assign, or blocked.
    pub kind: String,
    /// Source room message, for identity only.
    pub entry: String,
    /// Authenticated source author.
    pub author: String,
    /// Source author's claimed Session.
    pub from: String,
    /// Resource, displayed as plain text.
    pub resource: String,
    /// Safe source tags, displayed as plain text.
    pub tags: Vec<String>,
    /// Opaque safe work reference, displayed as plain text.
    pub work: String,
    /// Safe source description or blocked reason.
    pub text: String,
}
/// One bounded page; clients replace this page rather than accumulating history.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MemberWorkPage {
    /// Reading node identity.
    pub node: String,
    /// Saved room incarnation.
    pub instance: Vec<u8>,
    /// Current display token; a changed token invalidates this page.
    pub revision: String,
    /// Earliest expiry or refresh deadline, milliseconds since Unix epoch.
    pub refresh_at: u64,
    /// Current claims and outstanding relationships, at most 64 and 96 KiB before safe display.
    pub rows: Vec<MemberWork>,
    /// Explicit next-page cursor. Absent means complete, including an empty complete board.
    pub next: Option<String>,
    /// A version mismatch refuses coordination; it does not hide what the room said.
    pub coordination_refused: bool,
}

/// One author in a thread summary, named by this node's keyring.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ThreadAuthor {
    /// The complete author fingerprint.
    pub fingerprint: String,
    /// This node's local name, empty when unnamed.
    pub name: String,
}

/// A thread summary from all replies this node retains and can read, not a UI timeline page.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ThreadSummary {
    /// The General message starting the thread.
    pub root: String,
    /// Exact retained readable reply count, excluding the root.
    pub reply_count: u64,
    /// Latest reply send time in milliseconds, zero when there are no retained replies.
    pub last_reply_millis: u64,
    /// One bounded page of distinct repliers in fingerprint order.
    pub authors: Vec<ThreadAuthor>,
    /// Pass this as `after_author` for the remaining authors; absent means complete.
    pub next_author: Option<String>,
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

/// Counts and the first boundary in the node's existing bounded unread range.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RoomUnread {
    /// Messages addressed to this node.
    pub addressed: u64,
    /// Urgent messages among addressed messages.
    pub urgent: u64,
    /// Room conversation messages.
    pub new: u64,
    /// Coordination messages.
    pub coordination: u64,
    /// Oldest unread message in the examined range, if any.
    pub first: Option<String>,
    /// Older rows exist outside the node's unread examination range.
    pub scan_limited: bool,
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

/// `words` as one command line a person pastes into a shell, each word quoted as the CLI quotes it
/// (`vox_text::shell`, v0.4.3): the app's Copy buttons give what the CLI prints.
#[uniffi::export]
#[must_use]
pub fn shell_command(words: Vec<String>) -> String {
    vox_text::shell::command(&words)
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
    /// Authenticated remote self-name, independent of the local keyring alias.
    pub presented_name: String,
    /// Its fingerprint, base32.
    pub fingerprint: String,
    /// This node's name for it, from the keyring; empty when it has none.
    pub name: String,
    /// What is said of it about this node's key in the room, after its name, if anything (ADR-030
    /// D-5, W-4): that the key waits, and why, or that it runs an older Vox. As `vox room roster`
    /// says it.
    pub key_waits: Option<String>,
}

/// Current daemon-derived eligibility for individual Trust controls. Refresh when policy
/// changes; the daemon separately rechecks authorization when the person performs the action.
#[derive(Debug, Clone, uniffi::Record)]
pub struct IndividualTrustEligibility {
    /// False for managed group grants, quarantine, or policy still applying locally.
    pub can_manage_individual_trust: bool,
    /// User-facing reason when false; empty when eligible.
    pub reason: String,
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
    /// Authenticated remote self-name; empty for older or unreachable peers.
    pub presented_name: String,
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

/// A directory harness sessions started in with no room bound to it (ADR-029 RB-5): what Vox asks
/// the person, under needs you.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RoomAskInfo {
    /// The directory, absolute: what the answer names.
    pub dir: String,
    /// What it says: "Claude Code in /opt/vox has no room".
    pub sentence: String,
    /// The room the room map binds it to already, its id in base32, which the sessions' nodes
    /// are not in (RB-5a); empty when no room is bound to it. Answered by
    /// [`VoxClient::bind_room`] with an empty link.
    pub room: String,
    /// The nodes of the sessions waiting, each once, in the order they asked.
    pub nodes: Vec<String>,
    /// How many sessions wait on the answer.
    pub sessions: u32,
}

/// What binding or declining an ask did: whether it was done, and its lines, said for a person.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RoomAnswerInfo {
    /// It was done.
    pub done: bool,
    /// What was done, or why not.
    pub said: Vec<String>,
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
    /// Continue after this inspected slot; empty pages can still continue.
    pub next: Option<ServiceCursor>,
    /// Carry this revision into the continuation.
    pub revision: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ServiceCursor {
    pub host: String,
    pub name_hash: String,
}
#[derive(Debug, Clone, uniffi::Record)]
pub struct NoticeCursor {
    pub clock: u64,
    pub entry: String,
}
#[derive(Debug, Clone, uniffi::Record)]
pub struct RoomAdmins {
    pub creator: String,
    pub members: Vec<String>,
    pub next: Option<String>,
    pub revision: u64,
}
#[derive(Debug, Clone, uniffi::Record)]
pub struct RoomNotices {
    pub rows: Vec<RoomNoticeRow>,
    pub before: Option<NoticeCursor>,
    pub revision: u64,
}
#[derive(Debug, Clone, uniffi::Record)]
pub struct RoomConsentPage {
    pub author: String,
    pub targets: Vec<String>,
    pub next: Option<String>,
    pub revision: u64,
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

fn ffi_session(
    s: &vox_core::node::sessions::SessionRow,
    t: &SessionSummary,
    known: &Known,
) -> FfiSession {
    FfiSession {
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
        pending: t.waiting,
    }
}

/// One displayed page of Session metadata. Replace the page when following `next`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSessionsPage {
    /// Complete rows, including complete member-written names.
    pub sessions: Vec<FfiSession>,
    /// The exclusive opening cursor for the next page, or none at the end.
    pub next: Option<String>,
}

/// An indexed, currently answerable request; fetch its details only when selected.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiPendingTarget {
    /// Authenticated Session owner's fingerprint.
    pub node: String,
    /// Complete harness Session ID.
    pub session_id: String,
    /// Current Session opening entry.
    pub opening: String,
    /// The exact pending request origin for a selected activity lookup.
    pub entry: String,
}

/// One bounded page of live pending targets. An empty page may still have a continuation.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiPendingPage {
    /// Current targets from this bounded scan.
    pub targets: Vec<FfiPendingTarget>,
    /// Opaque continuation, including when this page has no eligible target.
    pub next: Option<String>,
}

/// One Session read as a member with drive reads it (ADR-029 SC-1, #554), word for word as
/// `vox room session` prints it (CL-1).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSessionRead {
    /// Opaque 16-byte saved-room identity for revalidating this held window.
    pub instance: Vec<u8>,
    /// Its entries, oldest first; none when this node may not see inside it.
    pub entries: Vec<FfiSessionEntry>,
    /// What to say besides: "opening not received yet", or whose trust this node lacks to see
    /// inside; `None` when there is nothing to say.
    pub note: Option<String>,
    /// How many older entries the Session has before these (ADR-034 FR-4).
    pub older: u64,
    /// Where the older ones end, for [`VoxClient::session_read_older`]; `None` when there are none.
    pub before: Option<String>,
}

/// One bounded room-history page, with how to fetch the preceding page on scroll (FR-4).
#[derive(Clone, Debug, uniffi::Record)]
pub struct FfiRoomRead {
    /// Opaque 16-byte saved-room identity for refreshing or marking this held window.
    pub instance: Vec<u8>,
    /// Messages in room order, oldest first.
    pub messages: Vec<RoomMessage>,
    /// How many older messages precede this page.
    pub older: u64,
    /// Entry before which the next older page ends, or none once the first page is reached.
    pub before: Option<String>,
}

/// One bounded thread window. Earlier/later navigation replaces the held window.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiThreadRead {
    /// Readable replies, oldest arrival first within this window.
    pub messages: Vec<RoomMessage>,
    /// Saved room identity for subsequent navigation and exact refresh.
    pub instance: Vec<u8>,
    /// Exclusive earlier-page boundary, absent when no earlier replies remain.
    pub before: Option<String>,
    /// Exclusive later-page boundary, absent when no later replies remain.
    pub after: Option<String>,
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

fn session_entry(
    l: &vox_core::node::session_view::Line,
    pulled: &HashMap<String, String>,
) -> FfiSessionEntry {
    use vox_core::node::session_view::details_text;
    FfiSessionEntry {
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
    }
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
        let fp = input_fingerprint(node)?;
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
    let known = Known::of(c).await?;
    for (fp, id) in addressed {
        let (sessions, _) = exact_session(c, channel_id, *fp, id).await?;
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

/// One logical metadata page. A member-written field is returned whole (ADR-034 FR-7/8),
/// so the one-large-row exception is distinct from accumulating a room's history.
async fn room_sessions_page(
    c: &mut IpcClient,
    channel_id: Digest32,
    after: Option<Digest32>,
) -> Result<
    (
        Vec<vox_core::node::sessions::SessionRow>,
        Vec<SessionSummary>,
        Option<Digest32>,
    ),
    VoxError,
> {
    match c.sessions_page(channel_id, after).await {
        Ok(Frame::SessionsPage {
            sessions,
            summaries,
            more,
        }) => {
            if sessions.len() != summaries.len() {
                return Err(failed("the Session page has mismatched summaries"));
            }
            let next = more.then(|| sessions.last().map(|s| s.opening)).flatten();
            if more && (next.is_none() || next == after) {
                return Err(failed("the Session page made no progress"));
            }
            Ok((sessions, summaries, next))
        }
        Ok(other) => Err(unexpected(&answered(other)?)),
        Err(e) => Err(listing_failed("a room's Sessions", e)),
    }
}

/// Resolve the complete selected identity, without listing other Sessions.
async fn exact_session(
    c: &mut IpcClient,
    room: Digest32,
    node: Digest32,
    id: &str,
) -> Result<
    (
        Vec<vox_core::node::sessions::SessionRow>,
        Vec<SessionSummary>,
    ),
    VoxError,
> {
    match c.session_lookup(room, node, id.to_owned()).await {
        Ok(Frame::SessionsPage {
            sessions,
            summaries,
            more: false,
        }) if sessions.len() <= 1
            && sessions.len() == summaries.len()
            && sessions.iter().all(|s| s.node == node && s.id == id) =>
        {
            Ok((sessions, summaries))
        }
        Ok(other) => Err(unexpected(&answered(other)?)),
        Err(e) => Err(listing_failed("the selected Session", e)),
    }
}

/// A paged listing whose answer did not come, or could not be read: not known to be whole, so
/// not shown.
fn listing_failed(what: &str, e: Error) -> VoxError {
    VoxError::Unknown {
        reason: format!("the vox daemon's answer listing {what} could not be read: {e}"),
    }
}

/// One page of the Session `session_id`'s entries (ADR-034 FR-4): the newest before `before`, or
/// the newest when `None`; and how many are older. Limit origins before rendering, so
/// companions can join or suppress lines without inventing a pagination cursor.
async fn session_page(
    c: &mut IpcClient,
    channel_id: Digest32,
    session_id: &str,
    before: Option<Digest32>,
) -> Result<(Vec<vox_core::node::drive::SessionRow>, u64, [u8; 16]), VoxError> {
    let which = vox_core::node::drive::SessionFilter::Session(session_id.to_owned());
    match c
        .session_page_limited(channel_id, which, before, SESSION_WINDOW_ROWS as u64)
        .await
    {
        Ok(Frame::SessionPage {
            rows,
            older,
            instance,
        }) => Ok((rows, older, instance)),
        Ok(other) => Err(unexpected(&answered(other)?)),
        Err(e) => Err(listing_failed("a Session's entries", e)),
    }
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
#[async_trait::async_trait]
pub trait ClientListener: Send + Sync {
    /// A message became readable in `room`, in the saved room `instance`. Each is delivered
    /// once; messages readable when [`VoxClient::subscribe`] was called are not delivered.
    /// Await actual consumption, without starting an unowned task. Return false when this
    /// listener's captured actor/observation generation or room instance is no longer current.
    async fn on_message(&self, room: String, instance: Vec<u8>, message: RoomMessage) -> bool;
    /// Anything else the node reports. Await consumption; false retires an obsolete listener.
    async fn on_notice(&self, text: String) -> bool;
    /// The node was detached, or the daemon stopped: nothing more will come. Check the captured
    /// actor/observation generation and cancellation before applying this terminal notification.
    async fn on_ended(&self, text: String);
    /// A Session's metadata, activity or drive authority in `room` changed. Await the bounded
    /// refresh, preserving room/node/selection fences; false retires an obsolete listener.
    async fn on_sessions(&self, room: String) -> bool;
}

/// One opaque projection token per open room; no Session records are retained for comparison.
async fn session_revisions(c: &mut IpcClient) -> Result<HashMap<Digest32, Digest32>, VoxError> {
    let reply = c
        .exchange(&vox_core::node::snapshot::request_body())
        .await
        .map_err(|e| listing_failed("Session changes", e))?;
    match vox_core::node::snapshot::NodeSnapshot::from_bytes(&reply) {
        Ok(Some(snapshot)) => Ok(snapshot
            .open
            .into_iter()
            .map(|room| (room.channel_id, room.session_revision))
            .collect()),
        Ok(None) => match Frame::from_bytes(&reply) {
            Ok(frame) => Err(unexpected(&answered(frame)?)),
            Err(error) => Err(listing_failed("Session changes", error)),
        },
        Err(error) => Err(listing_failed("Session changes", error)),
    }
}

/// The node this client holds attached, and the connection its requests go over.
struct Held {
    /// A release followed by reattaching the same name/fingerprint is still a new attachment.
    attachment: Arc<()>,
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

impl Held {
    /// Replace the connection if an exchange on it failed (ADR-034 WT-2, FR-3): its next reply
    /// might be an earlier request's. The new one holds the node as the old one did, opened while
    /// the old one still holds it, so the node stays attached between them and no passphrase is
    /// needed again.
    ///
    /// # Errors
    /// The new connection could not be opened, in the daemon's words; the old one is kept, broken,
    /// and the next call tries again.
    async fn mend(&mut self) -> Result<(), VoxError> {
        if !self.client.is_broken() {
            return Ok(());
        }
        let mut again = self.at.clone();
        again.using.attach = AttachMode::Hold;
        self.client = IpcClient::open_at(&again)
            .await
            .map_err(|e| {
                let contextual = |reason| {
                    format!(
                    "the app's connection to node {} broke, and a new one could not be opened: {}",
                    self.node, reason
                )
                };
                match said(&self.at.path, e) {
                    VoxError::Unreachable { reason } => VoxError::Unreachable {
                        reason: contextual(reason),
                    },
                    VoxError::ReadInterrupted { reason } => VoxError::ReadInterrupted {
                        reason: contextual(reason),
                    },
                    VoxError::Unknown { reason } => VoxError::Unknown {
                        reason: contextual(reason),
                    },
                    VoxError::Failed { reason } => VoxError::Failed {
                        reason: contextual(reason),
                    },
                    other => other,
                }
            })?
            .with_answer_bound(REQUEST_WITHIN);
        Ok(())
    }
}

const REQUEST_WITHIN: std::time::Duration = std::time::Duration::from_secs(60);

type Slot = Arc<tokio::sync::Mutex<Option<Held>>>;
type FollowSlot = Arc<Mutex<Option<Subscription>>>;

/// Owned by VoxClient, never by its task. The task keeps only a weak reference to this slot,
/// so dropping the client cancels an awaited foreign callback without a task/client cycle.
struct Subscription {
    identity: Arc<()>,
    task: tokio::task::AbortHandle,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn stop_follow(following: &FollowSlot) {
    drop(
        following
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take(),
    );
}

/// One captured pause selection. Its roster is bounded by the room's existing member limit;
/// release/replacement of the app's attachment invalidates it even if the fingerprint is reused.
#[derive(uniffi::Object)]
pub struct RoomPauseSelection {
    selected: vox_core::node::room_pause::Selection,
    attachment: Arc<()>,
}

#[uniffi::export]
impl RoomPauseSelection {
    /// The exact room selected by the person.
    pub fn room(&self) -> String {
        b32_encode(&self.selected.room)
    }
    /// The acting node, not a target of another window.
    pub fn node(&self) -> String {
        b32_encode(&self.selected.actor)
    }
    /// All members captured for this action, including the acting node.
    pub fn members(&self) -> Vec<String> {
        self.selected.members.iter().map(b32_encode).collect()
    }
}

/// An interruption continuation belongs to one target and one captured room/attachment.
#[derive(uniffi::Object)]
pub struct RoomPauseContinuation {
    capture: Arc<RoomPauseSelection>,
    peer: Digest32,
    after: String,
    expected: vox_agentcomms::drive::PauseSelection,
}

/// A confirmed durable receiver state. `at_millis == 0` means no change has ever been recorded.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RoomPauseState {
    pub paused: bool,
    pub by: String,
    pub at_millis: u64,
}
impl From<vox_agentcomms::drive::PauseState> for RoomPauseState {
    fn from(state: vox_agentcomms::drive::PauseState) -> Self {
        Self {
            paused: state.paused,
            by: if state.at_millis == 0 {
                String::new()
            } else {
                b32_encode(&state.by)
            },
            at_millis: state.at_millis,
        }
    }
}

/// Admission and interruption are separate: Confirmed does not promise every Esc was delivered.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum RoomPauseDelivery {
    Confirmed,
    Refused,
    NotSent,
    Unknown,
}

/// One bounded interruption page, summarized before crossing the FFI. Consumers drain `next`
/// and retain counts/one diagnostic per target, never a lifetime list of Session results.
#[derive(uniffi::Record)]
pub struct RoomPausePage {
    pub delivery: RoomPauseDelivery,
    pub state: Option<RoomPauseState>,
    pub interrupted: u32,
    pub unconfirmed: u32,
    pub interruption_error: Option<String>,
    pub said: String,
    pub next: Option<Arc<RoomPauseContinuation>>,
}

async fn pause_socket(held: &Slot, capture: &RoomPauseSelection) -> Result<NodeSocket, VoxError> {
    let mut slot = held.lock().await;
    let h = slot.as_mut().ok_or_else(not_attached)?;
    h.mend().await?;
    if !Arc::ptr_eq(&h.attachment, &capture.attachment)
        || h.client.me() != Some(capture.selected.actor)
    {
        return Err(failed(
            "The acting node attachment changed; select pause targets again.",
        ));
    }
    match ask(
        &mut h.client,
        &Request::ArrivalHead {
            channel_id: capture.selected.room,
        },
    )
    .await?
    {
        Frame::ArrivalHead { head } if head.instance == capture.selected.instance => {
            Ok(h.at.clone())
        }
        Frame::ArrivalHead { .. } => Err(failed(
            "The saved room changed; select pause targets again.",
        )),
        other => Err(unexpected(&other)),
    }
}

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
    /// At most one observer; release, detach and replacement cancel it, including UI waits.
    following: FollowSlot,
    /// A connection to the daemon, kept while the client lives: a daemon a client started exits
    /// once no node is attached and no client is connected (ADR-026 L-8), and the app is its
    /// client from the moment it opens, before any node is attached.
    daemon_hold: Mutex<Option<DaemonClient>>,
}

/// A failure to reach the daemon, said for a person.
/// The sentence vox-core writes for it, which the CLI shows too (ADR-028 E-7).
fn said(socket: &std::path::Path, e: Error) -> VoxError {
    use vox_core::error::IpcHandshake;
    let unreachable = matches!(&e, Error::Ipc(IpcHandshake::Unreachable { .. }));
    let interrupted = matches!(&e, Error::Ipc(IpcHandshake::HungUp { .. }));
    let uncertain = matches!(&e, Error::Ipc(IpcHandshake::RequestTimedOut { .. }));
    let reason = vox_core::node::daemonipc::unreached(socket, None, e);
    if unreachable {
        VoxError::Unreachable { reason }
    } else if interrupted || uncertain {
        VoxError::Unknown { reason }
    } else {
        VoxError::Failed { reason }
    }
}

/// A transport failure of an authoritative read, replaceable by a later healthy read.
/// Mutation exchanges and malformed or refused replies never use this boundary.
fn read_interrupted(e: Error, words: impl FnOnce(Error) -> String) -> VoxError {
    use vox_core::error::IpcHandshake;
    let interrupted = matches!(
        &e,
        Error::Ipc(
            IpcHandshake::Unreachable { .. }
                | IpcHandshake::HungUp { .. }
                | IpcHandshake::Cut
                | IpcHandshake::RequestTimedOut { .. }
        )
    );
    let reason = words(e);
    if interrupted {
        VoxError::ReadInterrupted { reason }
    } else {
        VoxError::Failed { reason }
    }
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
            reason: format!("the connection to node {node} ended"),
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
    failed("choose a Ready node in this app first")
}

/// Shown, never laid out: a name another party chose.
fn shown_name(s: &str) -> String {
    vox_agentcomms::envelope::reveal_keeping(s, |_| false)
}

fn rendered(row: &MessageRow, names: &HashMap<Digest32, String>, me: Option<&str>) -> RoomMessage {
    use vox_agentcomms::attention::{unread_level, UnreadLevel as L};
    let reveal = |s: &str| vox_agentcomms::envelope::reveal_keeping(s, |c| c == '\n' || c == '\t');
    let (kind, text, to, re, thread, urgent, file, image, card, platform) =
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
                vox_core::node::api::message_thread(&row.text)
                    .map(|root| b32_encode(&root))
                    .unwrap_or_default(),
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
        thread,
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
        tag_selectors: vox_core::node::api::message_tags(&row.text)
            .into_iter()
            .map(|key| {
                let label = vox_agentcomms::envelope::shown(
                    &key,
                    vox_agentcomms::envelope::MAX_TAG + "milestone:".len(),
                );
                FfiMessageTag { key, label }
            })
            .collect(),
        work: vox_agentcomms::envelope::Envelope::parse(&row.text)
            .ok()
            .and_then(|env| {
                env.data
                    .get(vox_agentcomms::envelope::WORK_KEY)
                    .and_then(|v| v.as_str())
                    .map(shown_name)
            })
            .unwrap_or_default(),
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

fn anchor_endpoints(anchors: &vox_core::nat::bootstrap::BootstrapSet) -> Vec<RoomAnchorEndpoint> {
    anchors
        .nodes()
        .iter()
        .map(|a| RoomAnchorEndpoint {
            fingerprint: b32_encode(&a.id),
            addresses: a
                .endpoints
                .addrs()
                .iter()
                .map(ToString::to_string)
                .collect(),
        })
        .collect()
}

fn pinned_anchor_set(
    anchors: Vec<RoomAnchorEndpoint>,
) -> Result<vox_core::nat::bootstrap::BootstrapSet, VoxError> {
    use vox_core::nat::bootstrap::{BootstrapSet, MAX_BOOTSTRAP_NODES};
    use vox_core::nat::multiaddr::{Multiaddr, MAX_ENDPOINTS};
    if anchors.len() > MAX_BOOTSTRAP_NODES {
        return Err(failed("at most 64 room anchors can be kept"));
    }
    let mut set = BootstrapSet::new();
    for anchor in anchors {
        if anchor.addresses.len() > MAX_ENDPOINTS {
            return Err(failed("an anchor has more than 8 endpoints"));
        }
        let id = input_fingerprint(&anchor.fingerprint)?;
        let mut endpoints = Vec::new();
        for text in anchor.addresses {
            let address = Multiaddr::parse(&text)
                .map_err(|e| failed(format!("invalid resolved anchor address: {e}")))?;
            if address
                .socket_addr()
                .is_none_or(|s| s.port() == 0 || s.ip().is_unspecified() || s.ip().is_multicast())
            {
                return Err(failed("an anchor must name a concrete served address"));
            }
            if !endpoints.contains(&address) {
                endpoints.push(address);
            }
        }
        if endpoints.is_empty() {
            return Err(failed("an anchor has no endpoint"));
        }
        // Repeated chips for one identity combine their explicitly kept addresses.
        for endpoint in endpoints {
            let spec = format!("{}@{endpoint}", b32_encode(&id));
            vox_core::node::link::merge_anchor_spec(&mut set, &spec)
                .map_err(|e| failed(e.to_string()))?;
        }
    }
    Ok(set)
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
        let Some(row) = rows.into_iter().find(|r| r.entry_hash == hash && !r.owed) else {
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
                let h = slot.as_mut().ok_or_else(not_attached)?;
                h.mend().await?;
                let $c = &mut h.client;
                $body
            })
            .await
    }};
}

/// A native window holds at most 128 selected messages and 128 KiB of raw row data.
/// One legal row may stand alone above the byte budget, as in the daemon's pages.
const ROOM_WINDOW_ROWS: usize = 128;
const ROOM_WINDOW_BYTES: usize = vox_core::node::ipc::ROWS_BUDGET;

/// Newest/older pages and exact held refresh share this logical-origin ceiling.
/// Multipart pieces and outcomes do not add rendered rows. The daemon's existing
/// byte budget still applies, including one complete legal oversized activity.
const SESSION_WINDOW_ROWS: usize = 128;

async fn room_read_fence(
    client: &mut IpcClient,
    channel_id: Digest32,
) -> Result<([u8; 16], Digest32), VoxError> {
    let instance = match ask(client, &Request::ArrivalHead { channel_id }).await? {
        Frame::ArrivalHead { head } => head.instance,
        other => return Err(unexpected(&other)),
    };
    let revision = match ask(client, &Request::RoomDisplayRevision { channel_id }).await? {
        Frame::RoomDisplayRevision { revision } => revision,
        other => return Err(unexpected(&other)),
    };
    Ok((instance, revision))
}

fn room_window_bytes(rows: &[MessageRow]) -> Result<(), VoxError> {
    let bytes = rows.iter().fold(0usize, |total, row| {
        total.saturating_add(row.text.len() + vox_core::node::ipc::ROW_OVERHEAD)
    });
    if rows.len() > ROOM_WINDOW_ROWS || (rows.len() > 1 && bytes > ROOM_WINDOW_BYTES) {
        return Err(failed(
            "The held room selection exceeds one window's count or byte budget. Refresh fewer messages.",
        ));
    }
    Ok(())
}

impl VoxClient {
    async fn post_selected(
        &self,
        room: String,
        text: String,
        to: Vec<String>,
        re: String,
        urgent: bool,
        selected: Option<(Digest32, [u8; 16])>,
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
            if selected.is_some_and(|(actor, _)| c.me() != Some(actor)) {
                return Err(failed(
                    "The acting node changed before sending. This message was not posted.",
                ));
            }
            sessions_addressable(c, channel_id, &one_session).await?;
            // **A reply spends a hop** (ADR-020 §9), by the one rule the CLI follows: its
            // parent's budget less one, read up the `re` chain from the log.
            if let Some(re) = env.re.clone() {
                let chain = reply_chain(c, channel_id, &re).await?;
                let parent = |h: &str| {
                    let hash = vox_core::node::link::b32_decode(h.trim(), "re").ok()?;
                    chain.get(&hash).cloned()
                };
                env.hops = vox_agentcomms::envelope::reply_hops_by(&re, parent);
                env.thread = Some(
                    vox_agentcomms::envelope::reply_thread_by(&re, parent).ok_or_else(|| {
                        failed(format!(
                            "cannot reply to {re}: this node cannot read that message; nothing was posted"
                        ))
                    })?,
                );
                if let Some(root) = env.thread.as_deref().and_then(|h| digest(h, "thread").ok()) {
                    match ask(
                        c,
                        &Request::Find {
                            channel_id,
                            entries: vec![root],
                        },
                    )
                    .await?
                    {
                        Frame::Rows { rows } => {
                            if let Some(starting) =
                                rows.iter().find(|r| r.entry_hash == root && !r.owed)
                            {
                                env.tags = vox_agentcomms::envelope::inherit_thread_tags(
                                    &env.tags,
                                    &starting.text,
                                )
                                .map_err(failed)?;
                            }
                        }
                        other => return Err(unexpected(&other)),
                    }
                }
            }
            let text = env.to_text();
            // A link card, fetched by this node (ADR-028 F-10).
            let request = match selected {
                Some((_, instance)) => Request::PostAt {
                    channel_id,
                    instance,
                    text,
                    card: true,
                },
                None => Request::Post {
                    channel_id,
                    text,
                    card: true,
                },
            };
            done(c, &request).await
        })
    }

    async fn room_page_read(
        &self,
        room: String,
        before: Option<Digest32>,
        view: Option<RoomView>,
        instance: Option<[u8; 16]>,
    ) -> Result<FfiRoomRead, VoxError> {
        let channel_id = digest(&room, "room id")?;
        let view = view.map(|view| view.core()).transpose()?;
        on_held!(self, |c| {
            let actor = c.me().ok_or_else(not_attached)?;
            let fence = room_read_fence(c, channel_id).await?;
            if instance.is_some_and(|expected| expected != fence.0) {
                return Err(failed(
                    "The saved room changed. Open its current page again.",
                ));
            }
            let names = names(c).await?;
            let request = match view {
                Some(view) => Request::RoomViewPage {
                    channel_id,
                    view,
                    instance: Some(fence.0),
                    before,
                    limit: ROOM_WINDOW_ROWS as u64,
                },
                None => Request::RoomPage {
                    channel_id,
                    before,
                    limit: ROOM_WINDOW_ROWS as u64,
                },
            };
            let (rows, older) = match ask(c, &request).await? {
                Frame::RoomPage { rows, older } => (rows, older),
                other => return Err(unexpected(&other)),
            };
            room_window_bytes(&rows)?;
            if room_read_fence(c, channel_id).await? != fence || c.me() != Some(actor) {
                return Err(failed(
                    "The room changed while reading. Refresh and try again.",
                ));
            }
            let me = b32_encode(&actor);
            Ok(FfiRoomRead {
                instance: fence.0.to_vec(),
                before: rows
                    .first()
                    .filter(|_| older > 0)
                    .map(|r| b32_encode(&r.entry_hash)),
                messages: rows
                    .iter()
                    .map(|r| rendered(r, &names, Some(&me)))
                    .collect(),
                older,
            })
        })
    }
    async fn room_selection_read(
        &self,
        room: String,
        node: String,
        instance: Vec<u8>,
        loaded: Vec<String>,
        view: Option<RoomView>,
    ) -> Result<FfiRoomRead, VoxError> {
        if loaded.len() > ROOM_WINDOW_ROWS {
            return Err(failed("A held room window may name at most 128 messages."));
        }
        let channel_id = digest(&room, "room id")?;
        let view = view.map(|view| view.core()).transpose()?;
        let actor = input_fingerprint(&node)?;
        let instance: [u8; 16] = instance
            .try_into()
            .map_err(|_| failed("The saved room identity must contain exactly 16 bytes."))?;
        let entries = loaded
            .iter()
            .map(|id| digest(id, "entry"))
            .collect::<Result<Vec<_>, _>>()?;
        on_held!(self, |c| {
            if c.me() != Some(actor) {
                return Err(failed(
                    "The acting node changed before refreshing this room.",
                ));
            }
            let fence = room_read_fence(c, channel_id).await?;
            if fence.0 != instance {
                return Err(failed(
                    "The saved room changed. Open its current page again.",
                ));
            }
            let names = names(c).await?;
            let mut found = HashMap::new();
            let mut bytes = 0usize;
            for chunk in entries.chunks(vox_core::node::ipc::MAX_FIND) {
                // Find itself streams one coherent selection. At most 64 bounded raw rows
                // exist in this temporary reply, independent of the room's history size.
                let request = match &view {
                    Some(view) => Request::RoomViewFind {
                        channel_id,
                        view: view.clone(),
                        instance,
                        entries: chunk.to_vec(),
                    },
                    None => Request::Find {
                        channel_id,
                        entries: chunk.to_vec(),
                    },
                };
                let rows = match ask(c, &request).await? {
                    Frame::Rows { rows } => rows,
                    other => return Err(unexpected(&other)),
                };
                for row in rows {
                    if !chunk.contains(&row.entry_hash) {
                        return Err(failed(
                            "The room returned a message outside the held selection.",
                        ));
                    }
                    if found.contains_key(&row.entry_hash) {
                        continue;
                    }
                    bytes =
                        bytes.saturating_add(row.text.len() + vox_core::node::ipc::ROW_OVERHEAD);
                    if !found.is_empty() && bytes > ROOM_WINDOW_BYTES {
                        return Err(failed(
                            "The held room selection exceeds one window's byte budget. Refresh fewer messages.",
                        ));
                    }
                    found.insert(row.entry_hash, row);
                }
            }
            if room_read_fence(c, channel_id).await? != fence || c.me() != Some(actor) {
                return Err(failed(
                    "The room changed while refreshing its held messages. Try again.",
                ));
            }
            let me = b32_encode(&actor);
            Ok(FfiRoomRead {
                instance: instance.to_vec(),
                messages: entries
                    .iter()
                    .filter_map(|id| found.remove(id))
                    .map(|row| rendered(&row, &names, Some(&me)))
                    .collect(),
                older: 0,
                before: None,
            })
        })
    }

    /// A page of a Session, newest first: see [`VoxClient::session_read`].
    async fn session_page_read(
        &self,
        room: String,
        node: String,
        session_id: String,
        before: Option<Digest32>,
    ) -> Result<FfiSessionRead, VoxError> {
        use vox_core::node::session_view::{read, OPENING_NOT_RECEIVED};
        let channel_id = digest(&room, "room id")?;
        let node = input_fingerprint(&node)?;
        let (mut page, actor) = on_held!(self, |c| {
            let actor = c.me().ok_or_else(not_attached)?;
            let (sessions, _) = exact_session(c, channel_id, node, &session_id).await?;
            let known = Known::of(c).await?;
            let (rows, older, instance) = session_page(c, channel_id, &session_id, before).await?;
            let first_hash = rows.first().map(|r| r.entry_hash);
            if older > 0 && (first_hash.is_none() || first_hash == before) {
                return Err(failed("the Session activity page made no progress"));
            }
            let first = first_hash.map(|hash| b32_encode(&hash));
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
            Ok((
                FfiSessionRead {
                    instance: instance.to_vec(),
                    entries: r
                        .lines
                        .iter()
                        .map(|l| session_entry(l, &HashMap::new()))
                        .collect(),
                    note,
                    older,
                    before: first.filter(|_| older > 0),
                },
                actor,
            ))
        })?;
        self.enrich_session_files(room, actor, &mut page).await?;
        Ok(page)
    }

    async fn enrich_session_files(
        &self,
        room: String,
        actor: Digest32,
        page: &mut FfiSessionRead,
    ) -> Result<(), VoxError> {
        let files: Vec<String> = page
            .entries
            .iter()
            .filter_map(|entry| entry.file.as_ref())
            .map(|file| file.entry.clone())
            .collect();
        for chunk in files.chunks(64) {
            let pulled = self
                .pulled_for_actor(room.clone(), chunk.to_vec(), Some(actor))
                .await?;
            for entry in &mut page.entries {
                if let Some(file) = entry
                    .file
                    .as_mut()
                    .filter(|file| chunk.contains(&file.entry))
                {
                    file.pulled_path = pulled
                        .iter()
                        .find(|p| p.entry == file.entry)
                        .map(|p| p.path.clone());
                }
            }
        }
        Ok(())
    }

    async fn pulled_for_actor(
        &self,
        room: String,
        entries: Vec<String>,
        actor: Option<Digest32>,
    ) -> Result<Vec<PulledFile>, VoxError> {
        if entries.len() > 64 {
            return Err(failed("read at most 64 saved copies at a time"));
        }
        let channel_id = digest(&room, "room id")?;
        let entries = entries
            .iter()
            .map(|s| digest(s, "offer entry"))
            .collect::<Result<Vec<_>, _>>()?;
        let held = Arc::clone(&self.held);
        let (data_root, config_dir) = (self.data_root.clone(), self.config_dir.clone());
        self.on_rt(async move {
            let node = {
                let slot = held.lock().await;
                let held = slot.as_ref().ok_or_else(not_attached)?;
                if actor.is_some_and(|actor| held.client.me() != Some(actor)) {
                    return Err(failed(
                        "The acting node changed before reading this Session's saved copies.",
                    ));
                }
                held.node.clone()
            };
            let account = Account::of(Some(&data_root), Some(&config_dir))
                .map_err(|e| failed(format!("data root: {e}")))?;
            let paths = account
                .node_paths(&node)
                .map_err(|e| failed(format!("node {node}: {e}")))?;
            let mut pulled: Vec<PulledFile> = entries
                .iter()
                .filter_map(|entry| vox_core::node::pulls::recorded_entry(&paths, entry))
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

    async fn computer_request(
        &self,
        request: DaemonRequest,
    ) -> Result<crate::ComputerStatus, VoxError> {
        match self.daemon(request).await? {
            DaemonFrame::ComputerStatus(json) => {
                serde_json::from_str::<vox_core::node::computer::ComputerStatus>(&json)
                    .map(Into::into)
                    .map_err(|_| failed("the daemon's computer status could not be read"))
            }
            DaemonFrame::ComputerFailed(why) => Err(failed(why)),
            _ => Err(failed("the daemon did not answer computer management")),
        }
    }

    /// Run `fut` on the client's runtime and await it from the caller's executor.
    async fn on_rt<T, F>(&self, fut: F) -> Result<T, VoxError>
    where
        T: Send + 'static,
        F: std::future::Future<Output = Result<T, VoxError>> + Send + 'static,
    {
        // This includes waiting for the held-connection mutex: another stalled call must not
        // leave every control in the app waiting behind it (ADR-034 WT-1). The deadline
        // cancels its exchange; IpcClient marks an exchange broken before its first write, so
        // the next call opens a fresh connection while retaining the node's hold (WT-2, WT-5).
        self.rt
            .spawn(async move {
                tokio::time::timeout(REQUEST_WITHIN, fut)
                    .await
                    .unwrap_or_else(|_| Err(VoxError::Unknown {
                        reason: "vox did not finish this request within 60 seconds; its outcome is unknown. Try again to reconnect.".into(),
                    }))
            })
            .await
            .map_err(|_| failed("the app's connection to vox stopped"))?
    }

    async fn anchor_request(&self, req: DaemonRequest) -> Result<Vec<AnchorSummary>, VoxError> {
        match self.daemon(req).await? {
            DaemonFrame::Anchors(anchors) => Ok(anchors.into_iter().map(Into::into).collect()),
            DaemonFrame::AnchorFailed(why) => Err(failed(why)),
            _ => Err(failed("the daemon did not return its anchor list")),
        }
    }

    async fn daemon(&self, req: DaemonRequest) -> Result<DaemonFrame, VoxError> {
        // Only Nodes is classified here as an authoritative read; other requests may mutate.
        let read_only = matches!(&req, DaemonRequest::Nodes);
        let socket = self.socket.clone();
        self.on_rt(async move {
            let mut d = DaemonClient::open(&socket)
                .await
                .map_err(|e| said(&socket, e))?;
            match d.request(req).await {
                Ok(DaemonFrame::Refused(r)) => Err(failed(r.to_string())),
                Ok(f) => Ok(f),
                Err(e) if read_only => Err(read_interrupted(e, |e| {
                    vox_core::node::daemonipc::unreached(&socket, None, e)
                })),
                Err(e) => Err(said(&socket, e)),
            }
        })
        .await
    }

    /// A bind or a no for an ask, and what the daemon said of it.
    async fn room_answer(&self, req: DaemonRequest) -> Result<RoomAnswerInfo, VoxError> {
        match self.daemon(req).await? {
            DaemonFrame::RoomAnswer { done, said } => Ok(RoomAnswerInfo { done, said }),
            _ => Err(failed(
                "the vox daemon did not answer for the room map; restart it so it is this vox's \
                 version",
            )),
        }
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
            let reply = c.exchange(&body).await.map_err(|e| {
                read_interrupted(e, |e| format!("the vox daemon stopped answering: {e}"))
            })?;
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

    async fn footers_read(
        &self,
        room: String,
        node: String,
        instance: Vec<u8>,
        entries: Vec<vox_core::node::api::FooterSelection>,
        limit: usize,
    ) -> Result<MessageFooters, VoxError> {
        if entries.len() > 128 {
            return Err(failed(
                "A footer selection may contain at most 128 messages.",
            ));
        }
        let channel_id = digest(&room, "room id")?;
        let actor = input_fingerprint(&node)?;
        let instance: [u8; 16] = instance
            .try_into()
            .map_err(|_| failed("The saved room identity must contain exactly 16 bytes."))?;
        on_held!(self, |c| {
            if c.me() != Some(actor) {
                return Err(failed(
                    "The acting node changed before reading message footers.",
                ));
            }
            let names = names(c).await?;
            let rows = match ask(
                c,
                &Request::Footers {
                    channel_id,
                    instance,
                    entries: entries.clone(),
                    limit,
                },
            )
            .await?
            {
                Frame::Footers {
                    instance: actual,
                    rows,
                } if actual == instance => rows,
                other => return Err(unexpected(&other)),
            };
            if rows.len() != entries.len()
                || rows
                    .iter()
                    .zip(&entries)
                    .any(|(row, selection)| row.entry != selection.entry)
            {
                return Err(failed("The footer response changed the selected messages."));
            }
            let mut bytes = rows.len() * 192;
            let mut named = |members: Vec<Digest32>| -> Result<Vec<String>, VoxError> {
                let mut out = Vec::with_capacity(members.len());
                for member in members {
                    let name = names
                        .get(&member)
                        .cloned()
                        .unwrap_or_else(|| b32_encode(&member));
                    if name.len() > 1024 {
                        return Err(failed("A member name exceeds the message-footer limit."));
                    }
                    bytes = bytes.saturating_add(name.len());
                    if bytes > 128 * 1024 {
                        return Err(failed(
                            "Message footer names exceed 128 KiB. Select fewer messages.",
                        ));
                    }
                    out.push(name);
                }
                out.sort();
                Ok(out)
            };
            let mut rendered = Vec::with_capacity(rows.len());
            for row in rows {
                rendered.push(MessageFooter {
                    id: b32_encode(&row.entry),
                    present: row.present,
                    read_by: named(row.read_by)?,
                    read_after: row.read_after.as_ref().map(b32_encode),
                    whereabouts: if row.present {
                        vox_text::read::whereabouts(row.held, row.others)
                    } else {
                        String::new()
                    },
                    pulled_by: named(row.pulled_by)?,
                    pulled_after: row.pulled_after,
                });
            }
            if c.me() != Some(actor) {
                return Err(failed(
                    "The acting node changed while reading message footers.",
                ));
            }
            Ok(MessageFooters {
                instance: instance.to_vec(),
                rows: rendered,
            })
        })
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
            following: Arc::new(Mutex::new(None)),
            daemon_hold: Mutex::new(Some(hold)),
        }))
    }

    /// The account's config directory, where an app keeps its own settings beside vox's
    /// (`VOX_CONFIG_DIR` when set).
    #[must_use]
    pub fn config_dir(&self) -> String {
        self.config_dir.to_string_lossy().into_owned()
    }

    /// Read daemon-wide computer trust without selecting or unlocking a chat node.
    pub async fn computer_status(&self) -> Result<crate::ComputerStatus, VoxError> {
        self.computer_request(DaemonRequest::ComputerStatus).await
    }
    /// Explicit operator release, destination transfer approval, or recovery after removal/fault.
    pub async fn change_computer_binding(
        &self,
        action: String,
        node: String,
        destination: String,
        frontier: String,
    ) -> Result<crate::ComputerStatus, VoxError> {
        vox_core::node::computer::operator_only().map_err(|e| failed(e.to_string()))?;
        self.computer_request(DaemonRequest::ComputerBinding {
            action,
            node,
            destination,
            frontier,
        })
        .await
    }
    /// Save the personal selection using a Ready node's authenticated local identity.
    pub async fn select_personal_node(
        &self,
        node: String,
    ) -> Result<crate::ComputerStatus, VoxError> {
        vox_core::node::computer::operator_only().map_err(|e| failed(e.to_string()))?;
        self.computer_request(DaemonRequest::ComputerPersonal { node })
            .await
    }
    /// Remove the exact displayed computer and policy frontier after operator confirmation.
    pub async fn remove_computer(
        &self,
        computer: String,
        frontier: String,
    ) -> Result<crate::ComputerStatus, VoxError> {
        vox_core::node::computer::operator_only().map_err(|e| failed(e.to_string()))?;
        self.computer_request(DaemonRequest::ComputerRemove { computer, frontier })
            .await
    }
    /// Produce one expiring invitation for an operator.
    pub async fn begin_computer_pairing(&self) -> Result<crate::ComputerStatus, VoxError> {
        vox_core::node::computer::operator_only().map_err(|e| failed(e.to_string()))?;
        self.computer_request(DaemonRequest::ComputerBegin).await
    }
    /// Authenticate a peer before the app displays its approval choice.
    pub async fn preview_computer_pairing(
        &self,
        link: String,
    ) -> Result<crate::ComputerStatus, VoxError> {
        vox_core::node::computer::operator_only().map_err(|e| failed(e.to_string()))?;
        self.computer_request(DaemonRequest::ComputerPreview {
            link: zeroize::Zeroizing::new(link),
        })
        .await
    }
    /// Approve exactly the authenticated preview the person saw.
    pub async fn approve_computer_pairing(
        &self,
        operation_id: String,
    ) -> Result<crate::ComputerStatus, VoxError> {
        vox_core::node::computer::operator_only().map_err(|e| failed(e.to_string()))?;
        self.computer_request(DaemonRequest::ComputerApprove {
            operation: operation_id,
        })
        .await
    }
    /// Cancel an uncommitted invitation or preview.
    pub async fn cancel_computer_pairing(
        &self,
        operation_id: String,
    ) -> Result<crate::ComputerStatus, VoxError> {
        vox_core::node::computer::operator_only().map_err(|e| failed(e.to_string()))?;
        self.computer_request(DaemonRequest::ComputerCancel {
            operation: operation_id,
        })
        .await
    }

    /// The machine's manual and saved-room anchor sources and actual dial observations.
    pub async fn anchors(&self) -> Result<Vec<AnchorSummary>, VoxError> {
        self.anchor_request(DaemonRequest::Anchors).await
    }

    /// Resolve an optional room anchor field without saving it anywhere.
    /// A bare host:port proves the responding anchor's fingerprint. An explicit
    /// fingerprint@address is checked as input and authenticated when the room dials it.
    /// Callers must still discard a stale result after the field, room or node changes.
    pub async fn resolve_anchor(&self, input: String) -> Result<String, VoxError> {
        match self.daemon(DaemonRequest::AnchorResolve { input }).await? {
            DaemonFrame::AnchorResolved(spec) => Ok(spec),
            DaemonFrame::AnchorFailed(why) => Err(failed(why)),
            _ => Err(failed("the daemon did not return the resolved anchor")),
        }
    }

    /// Search only when explicitly chosen. This uses a separate daemon connection, names no
    /// room, persists nothing, and holds no selected-node lock. Callers discard results after
    /// their sheet/search generation changes; cancellation can never change a room.
    pub async fn search_anchors(&self) -> Result<Vec<RoomAnchorEndpoint>, VoxError> {
        match self.daemon(DaemonRequest::AnchorSearch).await? {
            DaemonFrame::AnchorsFound(anchors) => Ok(anchor_endpoints(&anchors)),
            DaemonFrame::AnchorFailed(why) => Err(failed(why)),
            _ => Err(failed("the daemon did not answer the anchor search")),
        }
    }

    /// Resolve a manually entered chip before creation, producing numeric pinned endpoints.
    /// Hostname lookup happens here, never in create_room_with_anchors.
    pub async fn resolve_anchor_endpoint(
        &self,
        input: String,
    ) -> Result<RoomAnchorEndpoint, VoxError> {
        let spec = self.resolve_anchor(input).await?;
        self.on_rt(async move {
            tokio::task::spawn_blocking(move || {
                let mut set = vox_core::nat::bootstrap::BootstrapSet::new();
                vox_core::node::link::merge_anchor_spec(&mut set, &spec)
                    .map_err(|e| failed(e.to_string()))?;
                anchor_endpoints(&set)
                    .into_iter()
                    .next()
                    .ok_or_else(|| failed("the anchor has no endpoint"))
            })
            .await
            .map_err(|e| failed(e.to_string()))?
        })
        .await
    }

    /// Add fingerprint@address or host:port; host lookup proves the returned fingerprint.
    pub async fn add_anchor(&self, input: String) -> Result<Vec<AnchorSummary>, VoxError> {
        self.anchor_request(DaemonRequest::AnchorAdd { input })
            .await
    }

    /// Remove only the manual source; a room's independent source remains visible.
    pub async fn remove_anchor(&self, fingerprint: String) -> Result<Vec<AnchorSummary>, VoxError> {
        self.anchor_request(DaemonRequest::AnchorRemove {
            fingerprint: input_fingerprint(&fingerprint)?,
        })
        .await
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
                    status: n.status.map(|s| s.as_str().to_owned()),
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
        let unprotected = secret.is_empty();
        // The node's own clock, a test step included (V210-64), as `vox node create` stamps it.
        let now_ms = (vox_core::time::clock_with_test_skew())();
        let fingerprint = self
            .on_rt(async move {
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
            .await?;
        if unprotected {
            self.keep(node, None).await?;
        }
        Ok(fingerprint)
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
        let following = Arc::clone(&self.following);
        let socket = self.socket.clone();
        self.on_rt(async move {
            let mut slot = held.lock().await;
            stop_follow(&following);
            // The node held before is let go first, so a switch never holds two.
            *slot = None;
            let client = IpcClient::open_at(&at)
                .await
                .map_err(|e| attach_said(&socket, &name, e))?
                .with_answer_bound(REQUEST_WITHIN);
            let me = client.me().map(|f| b32_encode(&f)).unwrap_or_default();
            *slot = Some(Held {
                attachment: Arc::new(()),
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
                "the vox daemon did not confirm that node {node} is remembered"
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
                "the vox daemon did not confirm that node {node} is forgotten ({other:?})"
            ))),
        }
    }

    /// Stop holding the node: the daemon detaches it unless it is kept or held by another client.
    pub async fn release(&self) {
        let held = Arc::clone(&self.held);
        let following = Arc::clone(&self.following);
        let _ = self
            .on_rt(async move {
                let mut slot = held.lock().await;
                stop_follow(&following);
                *slot = None;
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
        let following = Arc::clone(&self.following);
        let _ = self
            .on_rt(async move {
                let mut slot = held.lock().await;
                if slot.as_ref().is_some_and(|h| h.node == name) {
                    stop_follow(&following);
                    *slot = None;
                }
                Ok(())
            })
            .await;
        match answer {
            DaemonFrame::Ok => Ok(()),
            _ => Err(failed(format!(
                "the vox daemon did not confirm the lock of node {node}"
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
            let presented: HashMap<_, _> = c
                .presented_names()
                .await
                .unwrap_or_default()
                .into_iter()
                .collect();
            let members = match ask(c, &Request::Roster { channel_id }).await? {
                Frame::Members { members } => members,
                other => return Err(unexpected(&other)),
            };
            let waits: std::collections::HashMap<Digest32, String> =
                match ask(c, &Request::KeyWaits { channel_id }).await {
                    Ok(Frame::KeyWaits { waits }) => waits.into_iter().collect(),
                    _ => std::collections::HashMap::new(),
                };
            Ok(members
                .into_iter()
                .map(|m| Member {
                    presented_name: presented.get(&m).cloned().unwrap_or_default(),
                    fingerprint: b32_encode(&m),
                    name: names.get(&m).cloned().unwrap_or_default(),
                    key_waits: waits.get(&m).cloned(),
                })
                .collect())
        })
    }

    /// Open a room at its newest bounded history page (ADR-034 FR-4).
    ///
    /// # Errors
    /// The room id is malformed or the node refuses the read.
    pub async fn room_read(&self, room: String) -> Result<FfiRoomRead, VoxError> {
        self.room_page_read(room, None, None, None).await
    }

    /// Newest bounded page in the selected view domain; filtering precedes the page limit.
    /// All uses General's message domain; lifecycle notices remain a separate bounded read.
    ///
    /// # Errors
    /// A malformed selection, incomplete derived index, or the node's current read refusal.
    pub async fn room_view_read(
        &self,
        room: String,
        view: RoomView,
    ) -> Result<FfiRoomRead, VoxError> {
        self.room_page_read(room, None, Some(view), None).await
    }

    /// Older selected-domain page in this saved room, using current canonical order.
    /// A cursor outside the selected domain or a replaced room is refused.
    ///
    /// # Errors
    /// Invalid view, room identity or cursor; a changed room or the node's refusal.
    pub async fn room_view_read_older(
        &self,
        room: String,
        view: RoomView,
        instance: Vec<u8>,
        before: String,
    ) -> Result<FfiRoomRead, VoxError> {
        let instance = instance
            .try_into()
            .map_err(|_| failed("The saved room identity must contain exactly 16 bytes."))?;
        self.room_page_read(
            room,
            Some(digest(&before, "entry")?),
            Some(view),
            Some(instance),
        )
        .await
    }

    /// Revalidate only held ids in their selected domain and original saved room, within
    /// the existing 128-row/128-KiB window. No gap is walked and no new rows are added.
    /// Paging metadata is unchanged by this lookup: the result has older=0 and before=None.
    ///
    /// # Errors
    /// A malformed or oversized selection, changed actor/room/view, or read refusal.
    pub async fn room_view_read_retaining(
        &self,
        room: String,
        view: RoomView,
        node: String,
        instance: Vec<u8>,
        loaded: Vec<String>,
    ) -> Result<FfiRoomRead, VoxError> {
        self.room_selection_read(room, node, instance, loaded, Some(view))
            .await
    }

    /// Revalidate exactly the held message ids, in their requested order, on the same node
    /// and saved room. Missing ids are omitted only after every authoritative lookup succeeds.
    /// This does not add newer messages or walk the gap to the newest page. The caller keeps
    /// its paging metadata: this exact selection returns `older = 0` and `before = None`.
    /// At most 128 ids and 128 KiB of raw row data are accepted (one legal large row alone).
    pub async fn room_read_retaining(
        &self,
        room: String,
        node: String,
        instance: Vec<u8>,
        loaded: Vec<String>,
    ) -> Result<FfiRoomRead, VoxError> {
        self.room_selection_read(room, node, instance, loaded, None)
            .await
    }

    /// Load the room-history page before `before`, when the person scrolls up (ADR-034 FR-4).
    ///
    /// # Errors
    /// The room or cursor is malformed, or the cursor is no longer in the room.
    pub async fn room_read_older(
        &self,
        room: String,
        before: String,
    ) -> Result<FfiRoomRead, VoxError> {
        self.room_page_read(room, Some(digest(&before, "entry")?), None, None)
            .await
    }

    /// One page of a room, in the room's order: up to `limit` messages (0: the page's bound) after the message
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

    /// Fetch the one readable root of an open thread without paging through General history.
    /// A missing, expired or unreadable root is `None`; the caller must discard its cached root.
    ///
    /// # Errors
    /// A malformed id, a closed room, or the selected node's refusal.
    pub async fn thread_root(
        &self,
        room: String,
        root: String,
    ) -> Result<Option<RoomMessage>, VoxError> {
        let channel_id = digest(&room, "room id")?;
        let root = digest(&root, "thread root")?;
        on_held!(self, |c| {
            let names = names(c).await?;
            let me = c.me().map(|f| b32_encode(&f));
            match ask(
                c,
                &Request::Find {
                    channel_id,
                    entries: vec![root],
                },
            )
            .await?
            {
                Frame::Rows { rows } => Ok(rows
                    .iter()
                    .find(|r| r.entry_hash == root && !r.owed)
                    .map(|r| rendered(r, &names, me.as_deref()))),
                other => Err(unexpected(&other)),
            }
        })
    }

    /// One bounded page of readable thread replies in arrival order, matching `thread_summary`.
    /// Opaque owed rows have no readable thread metadata and are not included. Empty `since`
    /// starts the thread; the next request follows the last returned id. An empty page finishes
    /// the read. A cursor removed by retention is an explicit error; reload from the beginning.
    /// This does not drain later pages or read another room.
    ///
    /// # Errors
    /// A malformed id, an invalid cursor, or the node's refusal.
    pub async fn read_thread_page(
        &self,
        room: String,
        root: String,
        since: String,
    ) -> Result<Vec<RoomMessage>, VoxError> {
        let channel_id = digest(&room, "room id")?;
        let root = digest(&root, "thread root")?;
        let since = if since.is_empty() {
            None
        } else {
            Some(digest(&since, "message id")?)
        };
        on_held!(self, |c| {
            let names = names(c).await?;
            let me = c.me().map(|f| b32_encode(&f));
            match ask(
                c,
                &Request::Thread {
                    channel_id,
                    root,
                    since,
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

    /// Read one bounded thread window: neither cursor starts at the first replies, `before`
    /// moves earlier, and `after` moves later. Pass the held room instance on continuations.
    /// Retention of a cursor is an explicit refusal; it never silently jumps to another page.
    pub async fn thread_page(
        &self,
        room: String,
        root: String,
        instance: Option<Vec<u8>>,
        before: Option<String>,
        after: Option<String>,
    ) -> Result<FfiThreadRead, VoxError> {
        if before.is_some() && after.is_some() {
            return Err(failed("Choose either earlier or later thread replies."));
        }
        let channel_id = digest(&room, "room id")?;
        let root = digest(&root, "thread root")?;
        let expected: Option<[u8; 16]> = instance
            .map(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| failed("invalid saved room instance"))
            })
            .transpose()?;
        let before = before
            .as_deref()
            .map(|id| digest(id, "thread reply"))
            .transpose()?;
        let after = after
            .as_deref()
            .map(|id| digest(id, "thread reply"))
            .transpose()?;
        on_held!(self, |c| {
            let actor = c.me().ok_or_else(not_attached)?;
            let fence = room_read_fence(c, channel_id).await?;
            if expected.is_some_and(|instance| instance != fence.0) {
                return Err(failed(
                    "The saved room changed. Open its current thread again.",
                ));
            }
            let names = names(c).await?;
            let (rows, before, after) = match ask(
                c,
                &Request::ThreadPage {
                    channel_id,
                    root,
                    before,
                    after,
                },
            )
            .await?
            {
                Frame::ThreadPage {
                    rows,
                    before,
                    after,
                } => (rows, before, after),
                other => return Err(unexpected(&other)),
            };
            room_window_bytes(&rows)?;
            if room_read_fence(c, channel_id).await? != fence || c.me() != Some(actor) {
                return Err(failed(
                    "The thread changed while reading its page. Try again.",
                ));
            }
            let me = b32_encode(&actor);
            Ok(FfiThreadRead {
                messages: rows
                    .iter()
                    .map(|row| rendered(row, &names, Some(&me)))
                    .collect(),
                instance: fence.0.to_vec(),
                before: before.as_ref().map(b32_encode),
                after: after.as_ref().map(b32_encode),
            })
        })
    }

    /// Refresh only the at-most-128 reply IDs held in this thread window. No latest page is
    /// added. The caller retains its earlier/later cursors and separate exact thread summary.
    pub async fn thread_entries(
        &self,
        room: String,
        root: String,
        node: String,
        instance: Vec<u8>,
        ids: Vec<String>,
    ) -> Result<FfiRoomRead, VoxError> {
        let root = b32_encode(&digest(&root, "thread root")?);
        let read = self.room_read_retaining(room, node, instance, ids).await?;
        if read
            .messages
            .iter()
            .any(|row| row.owed || row.thread != root)
        {
            return Err(failed("A held reply does not belong to this thread."));
        }
        Ok(read)
    }

    /// Opaque equality token for the selected room's current sealed display. It changes when the
    /// readable timeline changes (including late fills and expiry), on room reopen, or when
    /// display names change. Actor restart changes the token even when this client repairs its
    /// connection internally. The daemon reads it under the same readiness and room-lock
    /// boundary as exact message lookup, without collecting historical message bodies.
    /// Compare only within this held client's lifetime; discard cached tokens on a new client,
    /// node change, detach or refusal. A newly loaded root still needs its initial summary.
    ///
    /// # Errors
    /// A malformed room id, a closed room, or the node's refusal.
    pub async fn room_display_revision(&self, room: String) -> Result<String, VoxError> {
        let channel_id = digest(&room, "room id")?;
        on_held!(self, |c| {
            match ask(c, &Request::RoomDisplayRevision { channel_id }).await? {
                Frame::RoomDisplayRevision { revision } => Ok(b32_encode(&revision)),
                other => Err(unexpected(&other)),
            }
        })
    }

    /// The complete readable reply count and latest time, with a bounded author page.
    /// Pass `next_author` back as `after_author` only when more author names are needed.
    ///
    /// # Errors
    /// A malformed id or author cursor, or the node's refusal.
    pub async fn thread_summary(
        &self,
        room: String,
        root: String,
        after_author: Option<String>,
    ) -> Result<ThreadSummary, VoxError> {
        let channel_id = digest(&room, "room id")?;
        let root = digest(&root, "thread root")?;
        let after_author = after_author
            .as_deref()
            .map(|fp| digest(fp, "author cursor"))
            .transpose()?;
        on_held!(self, |c| {
            let names = names(c).await?;
            match ask(
                c,
                &Request::ThreadSummary {
                    channel_id,
                    root,
                    after_author,
                },
            )
            .await?
            {
                Frame::ThreadSummary {
                    reply_count,
                    last_reply_millis,
                    authors,
                    next_author,
                } => Ok(ThreadSummary {
                    root: b32_encode(&root),
                    reply_count,
                    last_reply_millis,
                    authors: authors
                        .into_iter()
                        .map(|fp| ThreadAuthor {
                            fingerprint: b32_encode(&fp),
                            name: names.get(&fp).cloned().unwrap_or_default(),
                        })
                        .collect(),
                    next_author: next_author.map(|fp| b32_encode(&fp)),
                }),
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
        self.post_selected(room, text, to, re, urgent, None).await
    }

    /// Send only as the captured acting node and to the captured saved room incarnation.
    /// The actor is checked while holding the client; the daemon checks the instance under
    /// its append lock. A lost response remains Unknown, never a claim that nothing posted.
    ///
    /// # Errors
    /// Invalid input, a changed actor/room, or the ordinary post refusal/unknown outcome.
    #[allow(clippy::too_many_arguments)] // The existing post fields plus its exact UI selection.
    pub async fn post_at(
        &self,
        room: String,
        node: String,
        instance: Vec<u8>,
        text: String,
        to: Vec<String>,
        re: String,
        urgent: bool,
    ) -> Result<(), VoxError> {
        let actor = input_fingerprint(&node)?;
        let instance: [u8; 16] = instance
            .try_into()
            .map_err(|_| failed("The saved room identity must contain exactly 16 bytes."))?;
        self.post_selected(room, text, to, re, urgent, Some((actor, instance)))
            .await
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
            anchors: vox_core::nat::bootstrap::BootstrapSet::new(),
        };
        on_held!(self, |c| done(c, &req).await)?;
        self.new_room(before, "the room was created").await
    }

    /// Preview exactly the link routes for the resolved anchors the person kept, without
    /// creating a room, searching or dialing. Fence the full selected-node fingerprint.
    pub async fn preview_room_link(
        &self,
        anchors: Vec<RoomAnchorEndpoint>,
        node: String,
    ) -> Result<RoomLinkPreview, VoxError> {
        let expected = input_fingerprint(&node)?;
        let anchors = pinned_anchor_set(anchors)?;
        on_held!(self, |c| {
            if c.me() != Some(expected) {
                return Err(failed(
                    "the selected node changed; review the room before creating it",
                ));
            }
            match ask(c, &Request::LinkPreview { anchors }).await? {
                Frame::LinkPreview {
                    node,
                    routes,
                    omitted,
                } if node == expected => {
                    let mut anchors = Vec::new();
                    let mut direct = None;
                    for route in routes {
                        let endpoint = RoomAnchorEndpoint {
                            fingerprint: b32_encode(&route.id),
                            addresses: route
                                .endpoints
                                .addrs()
                                .iter()
                                .map(ToString::to_string)
                                .collect(),
                        };
                        if route.id == node {
                            direct = Some(endpoint);
                        } else {
                            anchors.push(endpoint);
                        }
                    }
                    Ok(RoomLinkPreview {
                        node: b32_encode(&node),
                        anchors,
                        direct,
                        omitted: omitted as u32,
                    })
                }
                Frame::LinkPreview { .. } => Err(failed(
                    "the selected node changed; review the room before creating it",
                )),
                other => Err(unexpected(&other)),
            }
        })
    }

    /// Create using only the already resolved anchors the person kept. Check the full expected
    /// node fingerprint before mutation and keep its connection locked through the result read.
    /// Pending searches do not hold this lock. An empty set creates a room without an anchor.
    pub async fn create_room_with_anchors(
        &self,
        name: String,
        passphrase: Arc<Passphrase>,
        anchors: Vec<RoomAnchorEndpoint>,
        node: String,
    ) -> Result<String, VoxError> {
        let expected = input_fingerprint(&node)?;
        let anchors = pinned_anchor_set(anchors)?;
        on_held!(self, |c| {
            if c.me() != Some(expected) {
                return Err(failed(
                    "the selected node changed; review the room before creating it",
                ));
            }
            let before = room_ids(c).await?;
            done(
                c,
                &Request::Create {
                    name: name.clone(),
                    passphrase: passphrase.copy(),
                    anchors,
                },
            )
            .await?;
            room_ids(c)
                .await?
                .into_iter()
                .find(|(id, held, _, _)| held == &name && !before.iter().any(|(old, ..)| old == id))
                .map(|(id, ..)| b32_encode(&id))
                .ok_or_else(|| {
                    failed("the room was created, but it is not listed on the creating node")
                })
        })
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
        on_held!(self, |c| match ask(c, &req).await? {
            Frame::Ok | Frame::OwnRetention { .. } => Ok(()),
            other => Err(unexpected(&other)),
        })
    }

    /// Set the room's Session-step lifetime, or this member's shorter local lifetime.
    /// No identity passphrase is needed; the daemon enforces who can change the room rule.
    ///
    /// # Errors
    /// A malformed room, a choice above the room cap by a member, or the daemon's refusal.
    pub async fn set_step_retention(&self, room: String, seconds: u64) -> Result<(), VoxError> {
        let req = Request::SetStepRetention {
            channel_id: digest(&room, "room id")?,
            seconds,
        };
        on_held!(self, |c| match ask(c, &req).await? {
            Frame::Ok | Frame::OwnRetention { .. } => Ok(()),
            other => Err(unexpected(&other)),
        })
    }

    /// `room`'s admins, its creator first, as fingerprints.
    ///
    /// # Errors
    /// A malformed id, or the node's refusal (the room not open).
    pub async fn is_admin(&self, room: String, member: String) -> Result<bool, VoxError> {
        use vox_core::node::api::{GovernancePage, GovernanceQuery};
        let channel_id = digest(&room, "room id")?;
        let target = input_fingerprint(&member)?;
        on_held!(self, |c| match ask(
            c,
            &Request::GovernancePage {
                channel_id,
                query: GovernanceQuery::Admin { target }
            }
        )
        .await?
        {
            Frame::GovernancePage {
                page: GovernancePage::Admin { admin, .. },
            } => Ok(admin),
            other => Err(unexpected(&other)),
        })
    }

    /// One bounded page of the daemon's canonical work board. No app fold or tracker lookup.
    /// The held node, saved room and display revision are checked around the read.
    ///
    /// # Errors
    /// A changed room, stale cursor, capacity refusal, or the daemon's read failure.
    pub async fn member_work_page(
        &self,
        room: String,
        after: Option<String>,
    ) -> Result<MemberWorkPage, VoxError> {
        use vox_core::node::work_board::{Cursor, Page, Query, Row, Section};
        let channel_id = digest(&room, "room id")?;
        let after = after
            .map(|s| {
                serde_json::from_str::<Cursor>(&s).map_err(|_| failed("Invalid work-board cursor."))
            })
            .transpose()?;
        let query = serde_json::to_string(&Query {
            section: Section::Work,
            member: None,
            after,
        })
        .map_err(|e| failed(e.to_string()))?;
        on_held!(self, |c| {
            let actor = c.me().ok_or_else(not_attached)?;
            let fence = room_read_fence(c, channel_id).await?;
            let page: Page = match ask(c, &Request::WorkBoard { channel_id, query }).await? {
                Frame::WorkBoard { page } => serde_json::from_str(&page)
                    .map_err(|_| failed("Invalid daemon work-board page."))?,
                other => return Err(unexpected(&other)),
            };
            if room_read_fence(c, channel_id).await? != fence || c.me() != Some(actor) {
                return Err(failed(
                    "The room changed while reading its work board. Refresh and retry.",
                ));
            }
            let mut rows = Vec::with_capacity(page.rows.len());
            for row in page.rows {
                let Row::Work(row) = row else {
                    return Err(failed("Unexpected work-board row."));
                };
                rows.push(MemberWork {
                    member: b32_encode(&row.member),
                    session: shown_name(&row.session),
                    kind: row.kind,
                    entry: b32_encode(&row.entry),
                    author: b32_encode(&row.author),
                    from: shown_name(&row.from),
                    resource: shown_name(&row.resource),
                    tags: row.tags.iter().map(|s| shown_name(s)).collect(),
                    work: shown_name(&row.work),
                    text: vox_agentcomms::envelope::reveal_keeping(&row.body, |c| {
                        c == '\n' || c == '\t'
                    }),
                });
            }
            Ok(MemberWorkPage {
                node: b32_encode(&actor),
                instance: fence.0.to_vec(),
                revision: b32_encode(&fence.1),
                refresh_at: page.cursor.valid_until,
                rows,
                next: page
                    .next
                    .map(|c| serde_json::to_string(&c).map_err(|e| failed(e.to_string())))
                    .transpose()?,
                coordination_refused: page.refused,
            })
        })
    }

    pub async fn admins_page(
        &self,
        room: String,
        after: Option<String>,
        revision: Option<u64>,
    ) -> Result<RoomAdmins, VoxError> {
        use vox_core::node::api::{GovernancePage, GovernanceQuery};
        let channel_id = digest(&room, "room id")?;
        let after = after.map(|v| digest(&v, "admin cursor")).transpose()?;
        on_held!(self, |c| match ask(
            c,
            &Request::GovernancePage {
                channel_id,
                query: GovernanceQuery::Admins { after, revision }
            }
        )
        .await?
        {
            Frame::GovernancePage {
                page:
                    GovernancePage::Admins {
                        creator,
                        members,
                        next,
                        revision,
                    },
            } => Ok(RoomAdmins {
                creator: b32_encode(&creator),
                members: members.iter().map(b32_encode).collect(),
                next: next.as_ref().map(b32_encode),
                revision
            }),
            other => Err(unexpected(&other)),
        })
    }

    /// Read creator/admin authority for the currently held node and exact room.
    /// A caller must fence room/node changes before publishing this snapshot. Mutations below
    /// independently enforce current authority in the daemon; this snapshot grants nothing.
    ///
    /// # Errors
    /// A malformed room, no selected actor, a closed room, or the daemon's refusal.
    pub async fn room_anchor_authority(
        &self,
        room: String,
    ) -> Result<RoomAnchorAuthority, VoxError> {
        use vox_core::node::api::{GovernancePage, GovernanceQuery};
        let channel_id = digest(&room, "room id")?;
        on_held!(self, |c| {
            let me = c.me().ok_or_else(not_attached)?;
            match ask(
                c,
                &Request::GovernancePage {
                    channel_id,
                    query: GovernanceQuery::Admin { target: me },
                },
            )
            .await?
            {
                Frame::GovernancePage {
                    page: GovernancePage::Admin { target, admin, .. },
                } if target == me => Ok(RoomAnchorAuthority {
                    room: b32_encode(&channel_id),
                    node: b32_encode(&me),
                    can_manage: admin,
                }),
                other => Err(unexpected(&other)),
            }
        })
    }

    /// Read only this room's signed anchor configuration, preserving each address's scope.
    /// A caller must fence room/node changes before publishing this snapshot, just as it does
    /// for room_anchor_authority. The daemon refuses stale or unavailable observations.
    ///
    /// # Errors
    /// A malformed room, no held actor, a closed room, or unavailable room provenance.
    pub async fn room_anchor_configuration(
        &self,
        room: String,
    ) -> Result<RoomAnchorConfiguration, VoxError> {
        let channel_id = digest(&room, "room id")?;
        on_held!(self, |c| {
            let me = c.me().ok_or_else(not_attached)?;
            match ask(c, &Request::RoomAnchors { channel_id }).await? {
                Frame::RoomAnchors { anchors } => Ok(RoomAnchorConfiguration {
                    room: b32_encode(&channel_id),
                    node: b32_encode(&me),
                    anchors: anchors
                        .nodes()
                        .iter()
                        .map(|anchor| RoomAnchorEndpoint {
                            fingerprint: b32_encode(&anchor.id),
                            addresses: anchor
                                .endpoints
                                .addrs()
                                .iter()
                                .map(ToString::to_string)
                                .collect(),
                        })
                        .collect(),
                }),
                other => Err(unexpected(&other)),
            }
        })
    }

    /// Add a full pinned fingerprint@address to this room's signed governance statement.
    /// This consumes an already authenticated/resolved spec, or a fingerprint the
    /// person explicitly pinned. It does not perform bare host:port identity discovery/search,
    /// and never changes the machine's manual-anchor list. DNS parsing is off the async workers;
    /// the room's ordinary anchor transport still authenticates the pinned identity on dial.
    ///
    /// # Errors
    /// Malformed pinned input, a closed room, or the daemon's fresh NotAdmin refusal.
    pub async fn add_room_anchor_pinned(&self, room: String, spec: String) -> Result<(), VoxError> {
        let channel_id = digest(&room, "room id")?;
        on_held!(self, |c| {
            // Hold the selected actor across DNS parsing and mutation: switching this client
            // during the await must never submit the old intent as the newly selected node.
            let add = tokio::task::spawn_blocking(move || {
                let mut add = vox_core::nat::bootstrap::BootstrapSet::new();
                vox_core::node::link::merge_anchor_spec(&mut add, &spec)
                    .map_err(|error| failed(error.to_string()))?;
                Ok::<_, VoxError>(add)
            })
            .await
            .map_err(|error| {
                failed(format!(
                    "the pinned room anchor could not be parsed: {error}"
                ))
            })??;
            done(
                c,
                &Request::ChangeRoomAnchors {
                    channel_id,
                    add,
                    remove: None,
                },
            )
            .await
        })
    }

    /// Remove the exact full anchor fingerprint from this room's signed governance statement.
    /// The machine's independent manual source and other rooms are unchanged.
    ///
    /// # Errors
    /// A malformed room/fingerprint, a closed room, or the daemon's fresh NotAdmin refusal.
    pub async fn remove_room_anchor(
        &self,
        room: String,
        fingerprint: String,
    ) -> Result<(), VoxError> {
        let channel_id = digest(&room, "room id")?;
        let remove = Some(input_fingerprint(&fingerprint)?);
        on_held!(self, |c| done(
            c,
            &Request::ChangeRoomAnchors {
                channel_id,
                add: vox_core::nat::bootstrap::BootstrapSet::new(),
                remove,
            }
        )
        .await)
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
            member: input_fingerprint(&member)?,
            admin,
        };
        on_held!(self, |c| done(c, &req).await)
    }

    /// A remote name authenticated by this node's current connection, or missing-name fallback.
    pub async fn presented_name(&self, fingerprint: String) -> Result<Option<String>, VoxError> {
        let target = input_fingerprint(&fingerprint)?;
        on_held!(
            self,
            |c| match ask(c, &Request::Presentation { target }).await? {
                Frame::Presented { entries } => Ok(entries
                    .into_iter()
                    .find(|(fp, _)| *fp == target)
                    .map(|(_, name)| name)),
                _ => Ok(None),
            }
        )
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
        let (target, hint) = vox_core::node::link::copied_identity(&fingerprint)
            .map_err(|e| failed(e.to_string()))?;
        let name = if name.trim().is_empty() {
            match hint {
                Some(name) => name,
                None => self
                    .presented_name(b32_encode(&target))
                    .await?
                    .unwrap_or_default(),
            }
        } else {
            name
        };
        let req = Request::Trust {
            target,
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

    /// Whether current daemon policy permits individual Trust controls for this fingerprint.
    /// This is a current observation; mutations check policy again when performed.
    ///
    /// # Errors
    /// Invalid fingerprint, unavailable node, or daemon refusal.
    pub async fn individual_trust_eligibility(
        &self,
        fingerprint: String,
    ) -> Result<IndividualTrustEligibility, VoxError> {
        let member = input_fingerprint(&fingerprint)?;
        on_held!(self, |c| {
            match ask(c, &Request::IndividualTrustEligibility { member }).await? {
                Frame::IndividualTrustEligibility { can_manage, reason } => {
                    Ok(IndividualTrustEligibility {
                        can_manage_individual_trust: can_manage,
                        reason,
                    })
                }
                _ => Err(failed(
                    "the node did not report individual trust eligibility",
                )),
            }
        })
    }

    /// The current keyring offers in fingerprint order, including local dismissals.
    /// Presence alone is not individual-trust eligibility.
    ///
    /// # Errors
    /// The node's refusal.
    pub async fn pending_offers(&self) -> Result<Vec<OfferInfo>, VoxError> {
        on_held!(self, |c| {
            let presented: HashMap<_, _> = c
                .presented_names()
                .await
                .unwrap_or_default()
                .into_iter()
                .collect();
            match ask(c, &Request::Offers).await? {
                Frame::Offers { offers } => Ok(offers
                    .into_iter()
                    .map(|o| OfferInfo {
                        presented_name: presented.get(&o.member).cloned().unwrap_or_default(),
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
            }
        })
    }

    /// The directories harness sessions started in with no room bound to them, which the person
    /// has not said no for (ADR-029 RB-5): one per directory, as the daemon works them out.
    ///
    /// # Errors
    /// The daemon did not answer.
    pub async fn room_asks(&self) -> Result<Vec<RoomAskInfo>, VoxError> {
        match self.daemon(DaemonRequest::RoomAsks).await? {
            DaemonFrame::RoomAsks(asks) => Ok(asks
                .into_iter()
                .map(|a| {
                    let mut nodes: Vec<String> = Vec::new();
                    for s in &a.sessions {
                        if !nodes.iter().any(|n| n == s.node.as_str()) {
                            nodes.push(s.node.to_string());
                        }
                    }
                    RoomAskInfo {
                        sentence: a.sentence(),
                        sessions: u32::try_from(a.sessions.len()).unwrap_or(u32::MAX),
                        nodes,
                        dir: a.dir,
                        room: a.room,
                    }
                })
                .collect()),
            _ => Err(failed(
                "the vox daemon did not list what waits for a room; restart it so it is this \
                 vox's version",
            )),
        }
    }

    /// Bind the directory `dir` to the room `link` names (ADR-029 RB-6), the person's answer to
    /// its ask: what `vox room join <link> --node <node> --bind <dir>` does. The room's
    /// `passphrase` is the person's, typed in the app, and never an agent's; empty when it has
    /// none. Every session waiting there is put in the room. With `link` empty, the nodes join
    /// the room the room map binds `dir` to already, with the map's own link and passphrase
    /// (RB-5a), and `passphrase` is not used.
    ///
    /// # Errors
    /// The daemon did not answer.
    pub async fn bind_room(
        &self,
        dir: String,
        link: String,
        passphrase: Arc<Passphrase>,
    ) -> Result<RoomAnswerInfo, VoxError> {
        let request = DaemonRequest::RoomBind {
            dir,
            link: link.trim().to_owned(),
            passphrase: passphrase.copy(),
        };
        self.room_answer(request).await
    }

    /// Say no for the directory `dir` (ADR-029 RB-7): it stays tied to no room, and no session
    /// started there is asked again.
    ///
    /// # Errors
    /// The daemon did not answer.
    pub async fn decline_room(&self, dir: String) -> Result<RoomAnswerInfo, VoxError> {
        self.room_answer(DaemonRequest::RoomDecline { dir }).await
    }

    /// Dismiss the offer of the node `fingerprint` (ADR-028 K-18): kept by the node, on this node
    /// alone; the node offered is not told and stays out of the keyring. Asks no passphrase.
    ///
    /// # Errors
    /// A malformed fingerprint, or the node's refusal.
    pub async fn dismiss_offer(&self, fingerprint: String) -> Result<(), VoxError> {
        let req = Request::DismissOffer {
            member: input_fingerprint(&fingerprint)?,
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
            target: input_fingerprint(&fingerprint)?,
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
            target: input_fingerprint(&fingerprint)?,
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
            target: input_fingerprint(&fingerprint)?,
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
    /// # Errors
    /// The local service lookup failed or did not finish within the app's request bound.
    pub async fn listening(&self) -> Result<ListeningServices, VoxError> {
        let found = self
            .on_rt(async {
                tokio::task::spawn_blocking(vox_core::node::probe::listening)
                    .await
                    .map_err(|_| failed("the local service lookup stopped before it answered"))
            })
            .await?;
        Ok(ListeningServices {
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
        })
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
    pub async fn services_page(
        &self,
        room: String,
        after: Option<ServiceCursor>,
        revision: Option<u64>,
    ) -> Result<RoomServices, VoxError> {
        let channel_id = digest(&room, "room id")?;
        let after = after
            .map(|v| {
                Ok::<_, VoxError>((
                    digest(&v.host, "service cursor host")?,
                    digest(&v.name_hash, "service cursor name")?,
                ))
            })
            .transpose()?;
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
        on_held!(self, |c| match ask(
            c,
            &Request::Services {
                channel_id,
                after,
                revision
            }
        )
        .await?
        {
            Frame::Services {
                room,
                services,
                shared,
                next,
                revision,
            } => Ok(RoomServices {
                next: next.map(|(host, name_hash)| ServiceCursor {
                    host: b32_encode(&host),
                    name_hash: b32_encode(&name_hash)
                }),
                revision,
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
        })
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
                let parent = |h: &str| {
                    let hash = vox_core::node::link::b32_decode(h.trim(), "re").ok()?;
                    chain.get(&hash).cloned()
                };
                env.hops = vox_agentcomms::envelope::reply_hops_by(&re, parent);
                env.thread = Some(
                    vox_agentcomms::envelope::reply_thread_by(&re, parent).ok_or_else(|| {
                        failed(format!(
                            "cannot reply to {re}: this node cannot read that message; nothing was shared"
                        ))
                    })?,
                );
                if let Some(root) = env.thread.as_deref().and_then(|h| digest(h, "thread").ok()) {
                    match ask(
                        c,
                        &Request::Find {
                            channel_id,
                            entries: vec![root],
                        },
                    )
                    .await?
                    {
                        Frame::Rows { rows } => {
                            if let Some(starting) =
                                rows.iter().find(|r| r.entry_hash == root && !r.owed)
                            {
                                env.tags = vox_agentcomms::envelope::inherit_thread_tags(
                                    &env.tags,
                                    &starting.text,
                                )
                                .map_err(failed)?;
                            }
                        }
                        other => return Err(unexpected(&other)),
                    }
                }
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
    pub async fn sessions_page(
        &self,
        room: String,
        after: Option<String>,
    ) -> Result<FfiSessionsPage, VoxError> {
        let channel_id = digest(&room, "room id")?;
        let after = after
            .as_deref()
            .map(|id| digest(id, "Session opening"))
            .transpose()?;
        on_held!(self, |c| {
            let (sessions, summaries, next) = room_sessions_page(c, channel_id, after).await?;
            let known = Known::of(c).await?;
            Ok(FfiSessionsPage {
                sessions: sessions
                    .iter()
                    .zip(&summaries)
                    .map(|(s, t)| ffi_session(s, t, &known))
                    .collect(),
                next: next.map(|id| b32_encode(&id)),
            })
        })
    }

    /// One indexed page of all currently drivable open Sessions. Continue through `next`
    /// to discover every live tab; ended Session history is not scanned or accumulated.
    pub async fn sessions_open_page(
        &self,
        room: String,
        after: Option<String>,
    ) -> Result<FfiSessionsPage, VoxError> {
        let channel_id = digest(&room, "room id")?;
        let after = after
            .as_deref()
            .map(|id| digest(id, "Session opening"))
            .transpose()?;
        on_held!(self, |c| {
            let (sessions, summaries, more) =
                match ask(c, &Request::SessionsOpenPage { channel_id, after }).await? {
                    Frame::SessionsPage {
                        sessions,
                        summaries,
                        more,
                    } if sessions.len() == summaries.len() => (sessions, summaries, more),
                    other => return Err(unexpected(&other)),
                };
            if sessions
                .iter()
                .any(|session| !session.open || !session.can_drive)
            {
                return Err(failed(
                    "The node returned a Session outside the live drive selection.",
                ));
            }
            let next = more
                .then(|| sessions.last().map(|session| session.opening))
                .flatten();
            if more && (next.is_none() || next == after) {
                return Err(failed("The open Session page made no progress."));
            }
            let known = Known::of(c).await?;
            Ok(FfiSessionsPage {
                sessions: sessions
                    .iter()
                    .zip(&summaries)
                    .map(|(session, summary)| ffi_session(session, summary, &known))
                    .collect(),
                next: next.as_ref().map(b32_encode),
            })
        })
    }

    /// Exact answerable request count across every current open Session, independent of
    /// which metadata/activity page is displayed. Refusal is never a fabricated zero.
    pub async fn sessions_waiting(&self, room: String) -> Result<u64, VoxError> {
        let channel_id = digest(&room, "room id")?;
        on_held!(
            self,
            |c| match ask(c, &Request::SessionsWaiting { channel_id }).await? {
                Frame::SessionsWaiting { waiting } => Ok(waiting),
                other => Err(unexpected(&other)),
            }
        )
    }

    /// At most 64 current pending targets after an opaque revision-bound scan cursor.
    /// Continue when `next` is present, even if this page has no eligible target.
    pub async fn sessions_pending_page(
        &self,
        room: String,
        after: Option<String>,
    ) -> Result<FfiPendingPage, VoxError> {
        let channel_id = digest(&room, "room id")?;
        let after = after
            .as_deref()
            .map(|value| {
                let (revision, after) = value
                    .split_once(':')
                    .ok_or_else(|| failed("invalid pending request cursor"))?;
                let after = after
                    .parse::<u64>()
                    .ok()
                    .filter(|after| *after != 0)
                    .ok_or_else(|| failed("invalid pending request position"))?;
                Ok::<_, VoxError>(vox_core::node::sessions::PendingCursor {
                    revision: digest(revision, "pending revision")?,
                    after,
                })
            })
            .transpose()?;
        on_held!(
            self,
            |c| match ask(c, &Request::SessionsPending { channel_id, after }).await? {
                Frame::SessionsPendingPage { targets, next } => Ok(FfiPendingPage {
                    targets: targets
                        .into_iter()
                        .map(|target| FfiPendingTarget {
                            node: b32_encode(&target.node),
                            session_id: target.id,
                            opening: b32_encode(&target.opening),
                            entry: b32_encode(&target.entry),
                        })
                        .collect(),
                    next: next.map(|cursor| format!(
                        "{}:{}",
                        b32_encode(&cursor.revision),
                        cursor.after
                    )),
                }),
                other => Err(unexpected(&other)),
            }
        )
    }

    /// Exact metadata for the selected node and Session ID; none if its opening is absent.
    ///
    /// # Errors
    /// A malformed identity or the daemon's refusal.
    pub async fn session(
        &self,
        room: String,
        node: String,
        session_id: String,
    ) -> Result<Option<FfiSession>, VoxError> {
        let room = digest(&room, "room id")?;
        let node = input_fingerprint(&node)?;
        on_held!(self, |c| {
            let (sessions, summaries) = exact_session(c, room, node, &session_id).await?;
            let known = Known::of(c).await?;
            Ok(sessions
                .first()
                .zip(summaries.first())
                .map(|(s, t)| ffi_session(s, t, &known)))
        })
    }

    /// One Session of `room`, the session `session_id` of the node `node` (its fingerprint), read
    /// as `vox room session` reads it (ADR-029 SC-1, CL-1): its **newest page** of entries, oldest
    /// first, each line word for word, and how many older entries there are (ADR-034 FR-4): the
    /// app loads those with [`VoxClient::session_read_older`] only when the person scrolls to
    /// them. An ended Session stays readable (SE-5); one whose opening has not reached this node is
    /// read from its entries, with a note saying so. Without drive, no entries and a note saying
    /// whose trust this node lacks (SC-3).
    /// The daemon selects at most 128 logical origins before rendering. Its byte budget may
    /// select fewer; one legal oversized activity stays complete and readable on its own.
    ///
    /// # Errors
    /// A malformed id, the node's refusal, or no such Session, said as `vox room session` says it.
    pub async fn session_read(
        &self,
        room: String,
        node: String,
        session_id: String,
    ) -> Result<FfiSessionRead, VoxError> {
        self.session_page_read(room, node, session_id, None).await
    }

    /// The page of the Session's entries before `before` (an [`FfiSessionRead::before`]), read as
    /// [`VoxClient::session_read`] reads the newest (ADR-034 FR-4): for the app to load when the
    /// person scrolls up to it.
    ///
    /// # Errors
    /// As [`VoxClient::session_read`], or `before` not among the Session's entries.
    pub async fn session_read_older(
        &self,
        room: String,
        node: String,
        session_id: String,
        before: String,
    ) -> Result<FfiSessionRead, VoxError> {
        let before = digest(&before, "entry")?;
        self.session_page_read(room, node, session_id, Some(before))
            .await
    }

    /// Re-read at most 128 logical activities already held in this Session window, including
    /// selected multipart Details. `instance` must be the token of their original page.
    /// Success contains only current requested entries; missing/expired entries are omitted.
    /// The caller preserves its pagination cursors separately (`older` is zero here).
    ///
    /// # Errors
    /// Identity/drive/lifetime change, projection/storage failure, more than 128 IDs, or a
    /// multi-entry selection exceeding one page's byte budget. One legal oversized logical
    /// activity is streamed whole, just as in an ordinary Session page.
    pub async fn session_entries(
        &self,
        room: String,
        node: String,
        session_id: String,
        instance: Vec<u8>,
        ids: Vec<String>,
    ) -> Result<FfiSessionRead, VoxError> {
        use vox_core::node::{drive::SessionFilter, session_view::read};
        if ids.len() > SESSION_WINDOW_ROWS {
            return Err(failed(
                "at most 128 held Session IDs can be refreshed together",
            ));
        }
        let channel_id = digest(&room, "room id")?;
        let node = input_fingerprint(&node)?;
        let expected: [u8; 16] = instance
            .try_into()
            .map_err(|_| failed("invalid saved room instance"))?;
        let entries: Vec<Digest32> = ids
            .iter()
            .map(|id| digest(id, "Session entry id"))
            .collect::<Result<_, _>>()?;
        let (mut page, actor) = on_held!(self, |c| {
            let actor = c.me().ok_or_else(not_attached)?;
            let (sessions, _) = exact_session(c, channel_id, node, &session_id).await?;
            let known = Known::of(c).await?;
            let which = SessionFilter::Entries {
                node,
                session_id: session_id.clone(),
                entries: entries.clone(),
                instance: expected,
            };
            let (rows, instance) = match c
                .session_page(channel_id, which, None)
                .await
                .map_err(|e| listing_failed("held Session entries", e))?
            {
                Frame::SessionPage {
                    rows,
                    instance,
                    older: 0,
                } if instance == expected => (rows, instance),
                other => return Err(unexpected(&answered(other)?)),
            };
            // Authority, readiness and the room instance were checked by the successful
            // exact selection. An opening-not-received Session may have no descriptor once
            // its final held activity expires; that is a valid empty revalidation.
            if rows.is_empty() {
                return Ok((
                    FfiSessionRead {
                        instance: instance.to_vec(),
                        entries: Vec::new(),
                        note: None,
                        older: 0,
                        before: None,
                    },
                    actor,
                ));
            }
            let r = read(
                &sessions,
                rows,
                &session_id,
                Some(&node),
                &|s| known.label(s),
                &known,
            )
            .map_err(failed)?;
            Ok((
                FfiSessionRead {
                    instance: instance.to_vec(),
                    entries: r
                        .lines
                        .iter()
                        .filter(|line| entries.contains(&line.id))
                        .map(|line| session_entry(line, &HashMap::new()))
                        .collect(),
                    note: r.hidden,
                    older: 0,
                    before: None,
                },
                actor,
            ))
        })?;
        self.enrich_session_files(room, actor, &mut page).await?;
        Ok(page)
    }

    /// One page of pending requests, or of the explicitly named request's resolution history.
    /// `before` continues that same selection; no other requests are silently included or omitted.
    ///
    /// # Errors
    /// As [`VoxClient::session_read`], or an invalid continuation.
    pub async fn session_requests_page(
        &self,
        room: String,
        node: String,
        session_id: String,
        reference: Option<String>,
        before: Option<String>,
    ) -> Result<FfiSessionRead, VoxError> {
        use vox_core::node::{drive::SessionFilter, session_view::read};
        let channel_id = digest(&room, "room id")?;
        let node = input_fingerprint(&node)?;
        let before = before
            .as_deref()
            .map(|id| digest(id, "entry"))
            .transpose()?;
        on_held!(self, |c| {
            let (sessions, _) = exact_session(c, channel_id, node, &session_id).await?;
            let known = Known::of(c).await?;
            let which = match reference {
                Some(reference) => SessionFilter::Request {
                    session_id: session_id.clone(),
                    reference,
                },
                None => SessionFilter::Pending(session_id.clone()),
            };
            let (rows, older, instance) = match c
                .session_page(channel_id, which, before)
                .await
                .map_err(|e| listing_failed("a Session's requests", e))?
            {
                Frame::SessionPage {
                    rows,
                    older,
                    instance,
                } => (rows, older, instance),
                other => return Err(unexpected(&answered(other)?)),
            };
            let next = rows.first().map(|r| r.entry_hash);
            if older > 0 && (next.is_none() || next == before) {
                return Err(failed("the request page made no progress"));
            }
            let r = read(
                &sessions,
                rows,
                &session_id,
                Some(&node),
                &|s| known.label(s),
                &known,
            )
            .map_err(failed)?;
            Ok(FfiSessionRead {
                instance: instance.to_vec(),
                entries: r
                    .lines
                    .iter()
                    .filter(|l| l.request.is_some())
                    .map(|l| session_entry(l, &HashMap::new()))
                    .collect(),
                note: r.hidden,
                older,
                before: next.filter(|_| older > 0).map(|id| b32_encode(&id)),
            })
        })
    }

    /// Capture the current room roster without collecting Session history.
    ///
    /// # Errors
    /// The actor, attachment or saved room is unavailable or changes during capture.
    pub async fn room_pause_capture(
        &self,
        room: String,
        node: String,
    ) -> Result<Arc<RoomPauseSelection>, VoxError> {
        let room = digest(&room, "room id")?;
        let actor = input_fingerprint(&node)?;
        let held = Arc::clone(&self.held);
        self.on_rt(async move {
            let (at, attachment) = {
                let mut slot = held.lock().await;
                let h = slot.as_mut().ok_or_else(not_attached)?;
                h.mend().await?;
                if h.client.me() != Some(actor) {
                    return Err(failed(
                        "The acting node changed before selecting pause targets.",
                    ));
                }
                (h.at.clone(), Arc::clone(&h.attachment))
            };
            let selected = vox_core::node::room_pause::capture(&at, room)
                .await
                .map_err(failed)?;
            if selected.actor != actor {
                return Err(failed(
                    "The acting node changed while selecting pause targets.",
                ));
            }
            let capture = Arc::new(RoomPauseSelection {
                selected,
                attachment,
            });
            pause_socket(&held, &capture).await?;
            Ok(capture)
        })
        .await
    }

    /// Read current state without reapplying a mutation after reconnect. A failure is not Resume.
    ///
    /// # Errors
    /// The captured attachment/room changed, or the receiver could not be read.
    pub async fn room_pause_status(
        &self,
        capture: Arc<RoomPauseSelection>,
        member: String,
    ) -> Result<RoomPauseState, VoxError> {
        let peer = input_fingerprint(&member)?;
        if !capture.selected.members.contains(&peer) {
            return Err(failed("The node was not in the captured room roster."));
        }
        let held = Arc::clone(&self.held);
        self.on_rt(async move {
            let at = pause_socket(&held, &capture).await?;
            let state = vox_core::node::room_pause::status(&at, capture.selected.room, peer)
                .await
                .map_err(|e| failed(e.to_string()))?;
            pause_socket(&held, &capture).await?;
            Ok(state.into())
        })
        .await
    }

    /// Change one exact selected member and return one interruption page. The app must drain
    /// each continuation in the same action, retaining previous admission if a later page fails.
    ///
    /// # Errors
    /// A malformed target, invalid continuation, or changed local attachment/room. A timeout may
    /// follow a committed change; the caller must say outcome unknown and never replay it.
    pub async fn room_pause_change(
        &self,
        capture: Arc<RoomPauseSelection>,
        member: String,
        paused: bool,
        next: Option<Arc<RoomPauseContinuation>>,
    ) -> Result<RoomPausePage, VoxError> {
        use vox_core::node::room_pause::{self, Failure};
        let peer = input_fingerprint(&member)?;
        let continuation = match next {
            Some(next) if Arc::ptr_eq(&capture, &next.capture) && peer == next.peer && paused => {
                Some((next.after.clone(), next.expected))
            }
            Some(_) => {
                return Err(failed(
                    "This interruption continuation belongs to another pause selection.",
                ))
            }
            None => None,
        };
        let held = Arc::clone(&self.held);
        self.on_rt(async move {
            let at = pause_socket(&held, &capture).await?;
            let answer =
                room_pause::change(&at, &capture.selected, peer, paused, continuation).await;
            pause_socket(&held, &capture).await?;
            match answer {
                Ok(report) => {
                    let interrupted =
                        report.interrupts.iter().filter(|i| i.delivered).count() as u32;
                    let unconfirmed = report.interrupts.len() as u32 - interrupted;
                    let said = report
                        .interrupts
                        .iter()
                        .find(|i| !i.delivered)
                        .map(|i| format!("Session {}: {}", i.session, i.said))
                        .unwrap_or_default();
                    Ok(RoomPausePage {
                        delivery: RoomPauseDelivery::Confirmed,
                        state: Some(report.selection.state.into()),
                        interrupted,
                        unconfirmed,
                        interruption_error: report.interrupt_error,
                        said,
                        next: report.next.map(|after| {
                            Arc::new(RoomPauseContinuation {
                                capture,
                                peer,
                                after,
                                expected: report.selection,
                            })
                        }),
                    })
                }
                Err(error) => {
                    let delivery = match error {
                        Failure::Refused(_) => RoomPauseDelivery::Refused,
                        Failure::NotSent(_) => RoomPauseDelivery::NotSent,
                        Failure::Unknown(_) => RoomPauseDelivery::Unknown,
                    };
                    Ok(RoomPausePage {
                        delivery,
                        state: None,
                        interrupted: 0,
                        unconfirmed: 0,
                        interruption_error: None,
                        said: error.to_string(),
                        next: None,
                    })
                }
            }
        })
        .await
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
        node: String,
        session: String,
        action: DriveAction,
    ) -> Result<DriveAnswer, VoxError> {
        use vox_agentcomms::drive::{Action, Request as Drive};
        let channel_id = digest(&room, "room id")?;
        let node = input_fingerprint(&node)?;
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
                h.mend().await?;
                let names = names(&mut h.client).await?;
                let (sessions, _) =
                    exact_session(&mut h.client, channel_id, node, &session).await?;
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
                h.mend().await?;
                match ask(&mut h.client, &Request::Decisions { limit: 0 }).await? {
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

    /// Where the displayed offers stand, without reading older transfers. Read at most 64
    /// announcement hashes per call; every requested state is returned whole or the call refuses.
    ///
    /// # Errors
    /// No node attached, malformed ids, too many entries, or the node's refusal.
    pub async fn pull_states_for(
        &self,
        room: String,
        entries: Vec<String>,
    ) -> Result<Vec<OfferPull>, VoxError> {
        use vox_core::node::pulls::PullState as P;
        if entries.len() > 64 {
            return Err(failed("read at most 64 pull states at a time"));
        }
        let channel_id = digest(&room, "room id")?;
        let entries = entries
            .iter()
            .map(|s| digest(s, "offer entry"))
            .collect::<Result<Vec<_>, _>>()?;
        on_held!(self, |c| {
            match ask(
                c,
                &Request::PullStatesFor {
                    channel_id,
                    entries,
                },
            )
            .await?
            {
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
    /// No node attached, a malformed id, or more receipts than one reply holds; use
    /// [`Self::pulled_for`] for the displayed entries in that case.
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
                .filter(|p| p.room == channel_id)
                .take(65)
                .map(|p| PulledFile {
                    entry: b32_encode(&p.entry),
                    path: p.path.to_string_lossy().into_owned(),
                    created: p.created_ms / 1_000,
                })
                .collect();
            if pulled.len() > 64 {
                return Err(failed("this room has more saved copies than one reply holds; read the copies of the displayed entries"));
            }
            pulled.sort_by_key(|p| p.created);
            Ok(pulled)
        })
        .await
    }

    /// The verified local copies of at most 64 displayed announcements. Folder manifests
    /// remain on disk; only the entry, destination and date cross into the app.
    ///
    /// # Errors
    /// No node attached, malformed ids, or too many entries.
    pub async fn pulled_for(
        &self,
        room: String,
        entries: Vec<String>,
    ) -> Result<Vec<PulledFile>, VoxError> {
        self.pulled_for_actor(room, entries, None).await
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
        let reply = on_held!(self, |c| c.exchange(&body).await.map_err(|e| {
            read_interrupted(e, |e| format!("the vox daemon stopped answering: {e}"))
        }))?;
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
    pub async fn member_consents(&self, room: String) -> Result<RoomConsents, VoxError> {
        let channel_id = digest(&room, "room id")?;
        on_held!(
            self,
            |c| match ask(c, &Request::MemberConsents { channel_id }).await? {
                Frame::MemberConsents { outbound, inbound } => Ok(RoomConsents {
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

    /// Read bounded first recipient pages for exactly the displayed ids. At most 128 ids,
    /// eight readers and eight completed-fetch records per card, and 128 KiB of names.
    pub async fn message_footers(
        &self,
        room: String,
        node: String,
        instance: Vec<u8>,
        entries: Vec<String>,
    ) -> Result<MessageFooters, VoxError> {
        if entries.len() > 128 {
            return Err(failed(
                "A footer selection may contain at most 128 messages.",
            ));
        }
        let selections = entries
            .iter()
            .map(|entry| {
                Ok(vox_core::node::api::FooterSelection {
                    entry: digest(entry, "message id")?,
                    read_after: None,
                    pulled_after: None,
                })
            })
            .collect::<Result<Vec<_>, VoxError>>()?;
        self.footers_read(room, node, instance, selections, 8).await
    }

    /// Read the next bounded recipient page for one displayed card. The caller keeps only
    /// the viewed page and indicates More whenever either continuation is present.
    pub async fn message_footer_page(
        &self,
        room: String,
        node: String,
        instance: Vec<u8>,
        entry: String,
        read_after: Option<String>,
        pulled_after: Option<u64>,
    ) -> Result<MessageFooters, VoxError> {
        let selection = vox_core::node::api::FooterSelection {
            entry: digest(&entry, "message id")?,
            read_after: read_after
                .as_ref()
                .map(|id| digest(id, "reader cursor"))
                .transpose()?,
            pulled_after,
        };
        self.footers_read(room, node, instance, vec![selection], 64)
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
    /// It adds nothing to any keyring. A current drive-readable opening can enrich that same
    /// line with its registered directory; no Session history or new notice is produced.
    ///
    /// # Errors
    /// A malformed id, the room not open here, changed authority or oversized join metadata.
    /// A caller must remove any prior private caption on failure.
    pub async fn join_said(&self, room: String, member: String) -> Result<String, VoxError> {
        let who = input_fingerprint(&member)?;
        let channel_id = digest(&room, "room id")?;
        // Only the daemon's inventory proves that an author is on this Mac. A harness,
        // claimed hostname or a reader's alias cannot establish that fact.
        let local = self
            .nodes()
            .await?
            .into_iter()
            .find(|n| n.fingerprint == b32_encode(&who));
        on_held!(self, |c| {
            let before = match ask(c, &Request::ArrivalHead { channel_id }).await? {
                Frame::ArrivalHead { head } => head.instance,
                other => return Err(unexpected(&other)),
            };
            let names = names(c).await?;
            let bytes = c
                .exchange(&vox_core::node::snapshot::request_body())
                .await
                .map_err(|e| {
                    read_interrupted(e, |e| format!("the vox daemon stopped answering: {e}"))
                })?;
            let snap = vox_core::node::snapshot::NodeSnapshot::from_bytes(&bytes)
                .map_err(|e| failed(e.to_string()))?
                .ok_or_else(|| failed("the vox daemon did not answer with the node's state"))?;
            let open = snap
                .open
                .into_iter()
                .find(|o| o.channel_id == channel_id)
                .ok_or_else(|| failed("the room is not open on this node"))?;
            if !open.members.contains(&who) {
                return Err(failed("the node is no longer a member of this room"));
            }
            let mut trusters: Vec<String> = open
                .trusted_by
                .iter()
                .find(|(m, _)| *m == who)
                .map(|(_, by)| by.iter().filter_map(|fp| names.get(fp).cloned()).collect())
                .unwrap_or_default();
            trusters.sort();
            let name =
                vox_text::offer::name(names.get(&who).map(String::as_str), &b32_encode(&who));
            let ordinary = format!("{name} joined. {}", vox_text::offer::trusted_by(&trusters));
            let session = match ask(
                c,
                &Request::SessionJoin {
                    channel_id,
                    node: who,
                },
            )
            .await?
            {
                Frame::SessionsPage {
                    mut sessions,
                    summaries,
                    more: false,
                } if sessions.len() <= 1
                    && sessions.len() == summaries.len()
                    && sessions
                        .iter()
                        .all(|s| s.node == who && s.open && s.can_drive) =>
                {
                    sessions.pop()
                }
                other => return Err(unexpected(&other)),
            };
            let after = match ask(c, &Request::ArrivalHead { channel_id }).await? {
                Frame::ArrivalHead { head } => head.instance,
                other => return Err(unexpected(&other)),
            };
            if before != after {
                return Err(failed("the saved room changed; refresh its join line"));
            }
            let Some(cwd) = session.and_then(|s| s.cwd).filter(|cwd| !cwd.is_empty()) else {
                return Ok(ordinary);
            };
            let label = names
                .get(&who)
                .cloned()
                .or_else(|| local.as_ref().map(|n| shown_name(&n.name)))
                .unwrap_or(name);
            let location = if local.is_some() {
                " (on this Mac)"
            } else {
                ""
            };
            let room = open
                .name
                .map(|name| shown_name(&name))
                .unwrap_or_else(|| b32_encode(&channel_id));
            Ok(format!(
                "{label}{location} joined {room} and is working in {}. {}",
                shown_name(&cwd),
                vox_text::offer::trusted_by(&trusters)
            ))
        })
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
    pub async fn notices_page(
        &self,
        room: String,
        before: Option<NoticeCursor>,
        revision: Option<u64>,
    ) -> Result<RoomNotices, VoxError> {
        use vox_core::node::api::{GovernancePage, GovernanceQuery};
        let channel_id = digest(&room, "room id")?;
        let before = before
            .map(|v| Ok::<_, VoxError>((v.clock, digest(&v.entry, "notice cursor")?)))
            .transpose()?;
        let (_, names) = self.open_snap(&room).await?;
        on_held!(self, |c| match ask(
            c,
            &Request::GovernancePage {
                channel_id,
                query: GovernanceQuery::Notices { before, revision }
            }
        )
        .await?
        {
            Frame::GovernancePage {
                page:
                    GovernancePage::Notices {
                        rows,
                        before,
                        revision,
                    },
            } => Ok(RoomNotices {
                rows: rows
                    .into_iter()
                    .map(|n| RoomNoticeRow {
                        id: b32_encode(&n.entry_hash),
                        author: b32_encode(&n.author),
                        author_name: names.get(&n.author).cloned().unwrap_or_default(),
                        created_millis: n.created_millis,
                        what: n.what,
                        after: n.after.as_ref().map(b32_encode).unwrap_or_default()
                    })
                    .collect(),
                before: before.map(|(clock, entry)| NoticeCursor {
                    clock,
                    entry: b32_encode(&entry)
                }),
                revision,
            }),
            other => Err(unexpected(&other)),
        })
    }

    /// Complete consent history through bounded pages, including targets outside the roster.
    pub async fn consents_page(
        &self,
        room: String,
        author: Option<String>,
        after: Option<String>,
        revision: Option<u64>,
    ) -> Result<RoomConsentPage, VoxError> {
        use vox_core::node::api::{GovernancePage, GovernanceQuery};
        let channel_id = digest(&room, "room id")?;
        let author = author.map(|v| digest(&v, "consent author")).transpose()?;
        let after = after.map(|v| digest(&v, "consent cursor")).transpose()?;
        on_held!(self, |c| match ask(
            c,
            &Request::GovernancePage {
                channel_id,
                query: GovernanceQuery::Consent {
                    author,
                    after,
                    revision
                }
            }
        )
        .await?
        {
            Frame::GovernancePage {
                page:
                    GovernancePage::Consent {
                        author,
                        targets,
                        next,
                        revision,
                    },
            } => Ok(RoomConsentPage {
                author: b32_encode(&author),
                targets: targets.iter().map(b32_encode).collect(),
                next: next.as_ref().map(b32_encode),
                revision
            }),
            other => Err(unexpected(&other)),
        })
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

    /// The configured, capped and effective Session-step lifetime of this open room.
    ///
    /// # Errors
    /// A malformed room, a room that is not open, or the daemon's refusal.
    pub async fn step_retention(&self, room: String) -> Result<FfiStepRetention, VoxError> {
        match self.open_snap(&room).await?.0 {
            Some(open) => Ok(FfiStepRetention {
                room_seconds: open.room_step_retention,
                room_cap_seconds: vox_core::node::retention::shortest(
                    open.room_step_retention,
                    open.room_retention,
                ),
                effective_seconds: open.step_retention,
                local_seconds: open.local_step_retention,
            }),
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
        let (open, _, me) = self.open_snap_me(&room).await?;
        let Some(open) = open else {
            return Ok(Vec::new());
        };
        let actor = me.ok_or_else(not_attached)?;
        let channel_id = digest(&room, "room id")?;
        let instance = on_held!(self, |c| {
            match ask(c, &Request::ArrivalHead { channel_id }).await? {
                Frame::ArrivalHead { head } => Ok(head.instance),
                other => Err(unexpected(&other)),
            }
        })?;
        let result = self
            .message_footers(
                room,
                b32_encode(&actor),
                instance.to_vec(),
                open.held.iter().map(|(id, _)| b32_encode(id)).collect(),
            )
            .await?;
        result
            .rows
            .into_iter()
            .map(|row| {
                if row.pulled_after.is_some() {
                    return Err(failed(
                        "More completed recipients are available through message_footer_page.",
                    ));
                }
                Ok(PulledBy {
                    id: row.id,
                    names: row.pulled_by,
                })
            })
            .collect()
    }

    /// What this node's person has not read in `room`, oldest first (ADR-028 R-8): the messages
    /// after the newest one the node recorded as read, by someone else. A client counts its unread
    /// from these when it starts, then from the node's events.
    ///
    /// # Errors
    /// A malformed id, or the node's refusal (the room not open).
    pub async fn unread_summary(&self, room: String) -> Result<RoomUnread, VoxError> {
        let channel_id = digest(&room, "room id")?;
        on_held!(self, |c| {
            match ask(c, &Request::UnreadSummary { channel_id }).await? {
                Frame::UnreadSummary { summary } => Ok(RoomUnread {
                    addressed: summary.addressed,
                    urgent: summary.urgent,
                    new: summary.new,
                    coordination: summary.coordination,
                    first: summary.first.as_ref().map(b32_encode),
                    scan_limited: summary.scan_limited,
                }),
                other => Err(unexpected(&other)),
            }
        })
    }

    /// The bounded unread rows, for callers that need their bodies.
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

    /// Mark the messages actually shown from this exact held room window. Even an empty
    /// selection checks the actor and atomically validates the room instance in the daemon.
    /// Success means the selected marks were admitted to durable local state.
    pub async fn mark_read_at(
        &self,
        room: String,
        node: String,
        instance: Vec<u8>,
        ids: Vec<String>,
    ) -> Result<(), VoxError> {
        if ids.len() > ROOM_WINDOW_ROWS {
            return Err(failed("A held room window may mark at most 128 messages."));
        }
        let channel_id = digest(&room, "room id")?;
        let actor = input_fingerprint(&node)?;
        let instance: [u8; 16] = instance
            .try_into()
            .map_err(|_| failed("The saved room identity must contain exactly 16 bytes."))?;
        let entries = ids
            .iter()
            .map(|id| digest(id, "message id"))
            .collect::<Result<Vec<_>, _>>()?;
        on_held!(self, |c| {
            if c.me() != Some(actor) {
                return Err(failed(
                    "The acting node changed before marking this room read.",
                ));
            }
            done(
                c,
                &Request::MarkReadAt {
                    channel_id,
                    instance,
                    entries,
                },
            )
            .await
        })
    }

    /// Mark received messages from other members through one captured arrival head.
    /// One held actor, one room instance, and one bounded page are retained throughout.
    /// Cursor, authority and durable-mark failures abort without claiming whole-room success.
    pub async fn mark_room_read(&self, room: String, node: String) -> Result<u64, VoxError> {
        let channel_id = digest(&room, "room id")?;
        let actor = input_fingerprint(&node)?;
        on_held!(self, |c| {
            if c.me() != Some(actor) {
                return Err(failed(
                    "The acting node changed before marking this room read.",
                ));
            }
            let head = match ask(c, &Request::ArrivalHead { channel_id }).await? {
                Frame::ArrivalHead { head } => head,
                other => return Err(unexpected(&other)),
            };
            let mut cursor = HistoryCursor {
                instance: head.instance,
                arrival: 0,
            };
            let mut marked = 0u64;
            while cursor.arrival < head.arrival {
                let (rows, instance, next) = match ask(
                    c,
                    &Request::ArrivalPage {
                        channel_id,
                        after: cursor,
                    },
                )
                .await?
                {
                    Frame::ArrivalPage {
                        rows,
                        instance,
                        next,
                    } => (rows, instance, next),
                    other => return Err(unexpected(&other)),
                };
                if instance != head.instance {
                    return Err(failed(
                        "The saved room changed while marking it read. Try again.",
                    ));
                }
                let mut last = cursor.arrival;
                for row in &rows {
                    if row.arrival <= last || row.owed {
                        return Err(failed(
                            "The room's arrival page did not advance consistently.",
                        ));
                    }
                    last = row.arrival;
                }
                if next.is_some_and(|n| {
                    n.instance != head.instance || n.arrival <= cursor.arrival || n.arrival < last
                }) {
                    return Err(failed(
                        "The room's arrival continuation did not advance consistently.",
                    ));
                }
                let mut entries: Vec<_> = rows
                    .iter()
                    .filter(|row| row.arrival <= head.arrival && row.author != actor)
                    .map(|row| row.entry_hash)
                    .collect();
                entries.sort_unstable();
                entries.dedup();
                for page in entries.chunks(vox_core::node::content::MAX_READ_HASHES) {
                    done(
                        c,
                        &Request::MarkReadAt {
                            channel_id,
                            instance: head.instance,
                            entries: page.to_vec(),
                        },
                    )
                    .await?;
                    marked = marked
                        .checked_add(page.len() as u64)
                        .ok_or_else(|| failed("The room's read count is too large."))?;
                }
                if last >= head.arrival {
                    break;
                }
                let Some(next) = next else { break };
                cursor = next;
            }
            // Validate completion even when the captured room was empty, all rows were
            // ours, or the final page contained no markable rows.
            done(
                c,
                &Request::MarkReadAt {
                    channel_id,
                    instance: head.instance,
                    entries: Vec::new(),
                },
            )
            .await?;
            Ok(marked)
        })
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
        let following = Arc::clone(&self.following);
        let socket = self.socket.clone();
        // Setup and installation share the attachment lock: release/reattach cannot install an
        // obsolete observer after replacing this node. Nothing posted after return is missed.
        self.on_rt(async move {
            let mut slot = held.lock().await;
            let h = slot.as_mut().ok_or_else(not_attached)?;
            stop_follow(&following);
            h.mend().await?;
            let mut cursors = HashMap::new();
            let seen = session_revisions(&mut h.client).await?;
            for (id, _, open, _) in room_ids(&mut h.client).await? {
                if !open {
                    continue;
                }
                match ask(&mut h.client, &Request::ArrivalHead { channel_id: id }).await? {
                    Frame::ArrivalHead { head } => {
                        cursors.insert(id, head);
                    }
                    other => return Err(unexpected(&other)),
                }
            }
            let identity = Arc::new(());
            let owner = FollowOwner {
                node: h.node.clone(),
                fingerprint: h.client.me(),
                attachment: Arc::clone(&h.attachment),
                identity: Arc::clone(&identity),
                following: Arc::downgrade(&following),
            };
            // Capture heads before registering: follow immediately reads the gap, then queued
            // events only wake reads after those same saved cursors.
            let mut stream = IpcClient::open_at(&h.at)
                .await
                .map_err(|e| said(&socket, e))?;
            if h.at.using.node != owner.node || stream.me() != owner.fingerprint {
                return Err(failed("the app's node identity changed"));
            }
            stream
                .subscribe()
                .await
                .map_err(|e| failed(format!("cannot follow the node's events: {e}")))?;
            // A room opened before registration has no queued Opened event. Reanchor instead
            // of silently baselining that room after messages have already arrived.
            let reanchor = room_ids(&mut h.client)
                .await?
                .into_iter()
                .any(|(id, _, open, _)| open && !cursors.contains_key(&id));
            let task_held = Arc::clone(&held);
            // The start signal is only an installation barrier, never a delivery queue. It
            // keeps even the immediate terminal callback outside the setup's Slot guard.
            let (start, ready) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                if ready.await.is_err() {
                    return;
                }
                if let Err(why) = follow(
                    stream,
                    cursors,
                    seen,
                    task_held,
                    &owner,
                    reanchor,
                    listener.as_ref(),
                )
                .await
                {
                    if owner.current() {
                        listener.on_ended(why).await;
                    }
                }
            });
            *following.lock().unwrap_or_else(PoisonError::into_inner) = Some(Subscription {
                identity,
                task: task.abort_handle(),
            });
            drop(slot);
            let _ = start.send(());
            Ok(())
        })
        .await
    }
}

/// Name and fingerprint bind the actor; the attachment token also rejects release/reattach of
/// that same actor. Only a weak subscription slot is held, never the owner of this task.
struct FollowOwner {
    node: NodeName,
    fingerprint: Option<Digest32>,
    attachment: Arc<()>,
    identity: Arc<()>,
    following: Weak<Mutex<Option<Subscription>>>,
}
impl FollowOwner {
    fn holds(&self, held: &Held) -> bool {
        Arc::ptr_eq(&held.attachment, &self.attachment)
            && held.node == self.node
            && held.client.me() == self.fingerprint
    }

    fn current(&self) -> bool {
        let Some(following) = self.following.upgrade() else {
            return false;
        };
        let registered = following.lock().unwrap_or_else(PoisonError::into_inner);
        registered
            .as_ref()
            .is_some_and(|s| Arc::ptr_eq(&s.identity, &self.identity))
    }

    /// Serialize only this scalar commit with replacement/release. No foreign call or IPC
    /// wait occurs under the registration lock; an obsolete observer cannot advance afterward.
    fn advance(&self, cursor: &mut HistoryCursor, arrival: u64) -> bool {
        let Some(following) = self.following.upgrade() else {
            return false;
        };
        let registered = following.lock().unwrap_or_else(PoisonError::into_inner);
        if !registered
            .as_ref()
            .is_some_and(|s| Arc::ptr_eq(&s.identity, &self.identity))
        {
            return false;
        }
        cursor.arrival = arrival;
        true
    }

    async fn notice(&self, listener: &dyn ClientListener, text: String) -> bool {
        self.current() && listener.on_notice(text).await && self.current()
    }

    async fn sessions(&self, listener: &dyn ClientListener, room: Digest32) -> bool {
        self.current() && listener.on_sessions(b32_encode(&room)).await && self.current()
    }
}

async fn follow_head(
    held: &Slot,
    owner: &FollowOwner,
    room: Digest32,
) -> Result<HistoryCursor, String> {
    let mut slot = held.lock().await;
    let h = slot
        .as_mut()
        .filter(|h| owner.holds(h))
        .ok_or_else(|| "the app released or changed its node".to_owned())?;
    h.mend().await.map_err(|e| e.to_string())?;
    if !owner.holds(h) {
        return Err("the app's node identity changed".into());
    }
    match ask(&mut h.client, &Request::ArrivalHead { channel_id: room })
        .await
        .map_err(|e| e.to_string())?
    {
        Frame::ArrivalHead { head } => Ok(head),
        other => Err(unexpected(&other).to_string()),
    }
}

enum FollowPage {
    More,
    CaughtUp,
    Obsolete,
}

/// Hold one sealed arrival page, release Slot, then await each consumer acknowledgement. No
/// foreign callback holds an IPC mutex or synchronously waits on the native executor. The
/// scalar cursor advances only after consumption; the instance travels with every delivery.
async fn follow_page(
    held: &Slot,
    owner: &FollowOwner,
    room: Digest32,
    cursor: &mut HistoryCursor,
    listener: &dyn ClientListener,
) -> Result<FollowPage, String> {
    if !owner.current() {
        return Ok(FollowPage::Obsolete);
    }
    let (messages, instance, next, last) = {
        let mut slot = held.lock().await;
        let h = slot
            .as_mut()
            .filter(|h| owner.holds(h))
            .ok_or_else(|| "the app released or changed its node".to_owned())?;
        h.mend().await.map_err(|e| e.to_string())?;
        if !owner.holds(h) {
            return Err("the app's node identity changed".into());
        }
        let (rows, instance, next) = match ask(
            &mut h.client,
            &Request::ArrivalPage {
                channel_id: room,
                after: *cursor,
            },
        )
        .await
        .map_err(|e| e.to_string())?
        {
            Frame::ArrivalPage {
                rows,
                instance,
                next,
            } => (rows, instance, next),
            other => return Err(unexpected(&other).to_string()),
        };
        if instance != cursor.instance {
            return Err(
                "the saved room changed; refreshing its history and restarting observation".into(),
            );
        }
        let mut last = cursor.arrival;
        for row in &rows {
            if row.arrival <= last || row.owed {
                return Err("the room's arrival page did not advance consistently".into());
            }
            last = row.arrival;
        }
        if next.is_some_and(|n| {
            n.instance != instance || n.arrival <= cursor.arrival || n.arrival < last
        }) {
            return Err("the room's arrival continuation did not advance consistently".into());
        }
        let names = names(&mut h.client).await.map_err(|e| e.to_string())?;
        // Names are a separate exchange. A close/rejoin between the page and that exchange
        // must not publish the old page under the new saved room's metadata.
        let head = match ask(&mut h.client, &Request::ArrivalHead { channel_id: room })
            .await
            .map_err(|e| e.to_string())?
        {
            Frame::ArrivalHead { head } => head,
            other => return Err(unexpected(&other).to_string()),
        };
        if head.instance != instance {
            return Err(
                "the saved room changed; refreshing its history and restarting observation".into(),
            );
        }
        let me = h.client.me().map(|f| b32_encode(&f));
        let messages: Vec<_> = rows
            .into_iter()
            .map(|row| rendered(&row, &names, me.as_deref()))
            .collect();
        (messages, instance, next, last)
    };
    for message in messages {
        if !owner.current()
            || !listener
                .on_message(b32_encode(&room), instance.to_vec(), message)
                .await
            || !owner.current()
        {
            return Ok(FollowPage::Obsolete);
        }
    }
    // UI consumption may await its own client calls. Fence the saved room again, without
    // retaining Slot over the callback or rereading any bodies, before committing this page.
    if !owner.current() {
        return Ok(FollowPage::Obsolete);
    }
    let head = follow_head(held, owner, room).await?;
    if !owner.current() {
        return Ok(FollowPage::Obsolete);
    }
    if head.instance != instance {
        return Err(
            "the saved room changed; refreshing its history and restarting observation".into(),
        );
    }
    if !owner.advance(cursor, next.map_or(last, |n| n.arrival)) {
        return Ok(FollowPage::Obsolete);
    }
    Ok(if next.is_some() {
        FollowPage::More
    } else {
        FollowPage::CaughtUp
    })
}

/// Events only wake durable arrival reads. Native consumption backpressures this one task;
/// a slow listener does not create a body queue, task per message or lifetime dedup set.
async fn follow(
    mut stream: IpcClient,
    mut cursors: HashMap<Digest32, HistoryCursor>,
    mut seen: HashMap<Digest32, Digest32>,
    held: Slot,
    owner: &FollowOwner,
    reanchor: bool,
    listener: &dyn ClientListener,
) -> Result<(), String> {
    if !owner.current() {
        return Ok(());
    }
    if reanchor {
        return Err("a room opened while observation started; refreshing its history and restarting observation".into());
    }
    // Close the head-to-subscribe race once; queued events subsequently use these same cursors.
    let initial_rooms: Vec<_> = cursors.keys().copied().collect();
    for (&room, cursor) in &mut cursors {
        loop {
            match follow_page(&held, owner, room, cursor, listener).await? {
                FollowPage::More => tokio::task::yield_now().await,
                FollowPage::CaughtUp => break,
                FollowPage::Obsolete => return Ok(()),
            }
        }
    }
    if !sessions_told(&initial_rooms, &mut seen, &held, owner, listener).await? {
        return Ok(());
    }
    loop {
        let event = stream.next().await;
        if !owner.current() {
            return Ok(());
        }
        {
            let slot = held.lock().await;
            if !slot.as_ref().is_some_and(|h| owner.holds(h)) {
                return Err("the app released or changed its node".into());
            }
        }
        let mut sessions_in = Vec::new();
        let rooms: Vec<Digest32> = match event {
            Ok(Some(Frame::Event(NodeEvent::NewEntry { channel_id, .. }))) => {
                sessions_in.push(channel_id);
                cursors
                    .contains_key(&channel_id)
                    .then_some(channel_id)
                    .into_iter()
                    .collect()
            }
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
                if !owner.notice(listener, ev.words()).await {
                    return Ok(());
                }
                room.filter(|r| cursors.contains_key(r))
                    .into_iter()
                    .collect()
            }
            Ok(Some(Frame::Event(ev @ NodeEvent::ChannelOpened { channel_id }))) => {
                let Some(previous) = cursors.get(&channel_id) else {
                    return Err(
                        "a room opened; refreshing its history and restarting observation".into(),
                    );
                };
                let head = follow_head(&held, owner, channel_id).await?;
                if previous.instance != head.instance {
                    return Err(
                        "the saved room changed; refreshing its history and restarting observation"
                            .into(),
                    );
                }
                if !owner.notice(listener, ev.words()).await {
                    return Ok(());
                }
                sessions_in.push(channel_id);
                vec![channel_id]
            }
            Ok(Some(Frame::Event(
                ev @ (NodeEvent::ChannelClosed { channel_id }
                | NodeEvent::RoomRemoved { channel_id }),
            ))) => {
                cursors.remove(&channel_id);
                seen.remove(&channel_id);
                if !owner.notice(listener, ev.words()).await
                    || !owner.sessions(listener, channel_id).await
                {
                    return Ok(());
                }
                Vec::new()
            }
            Ok(Some(Frame::Event(NodeEvent::SessionEntry { channel_id, .. }))) => {
                sessions_in.push(channel_id);
                Vec::new()
            }
            Ok(Some(Frame::Event(ev))) => {
                if matches!(ev, NodeEvent::CapabilityChanged { .. }) {
                    sessions_in.extend(cursors.keys().copied());
                }
                if !owner.notice(listener, ev.words()).await {
                    return Ok(());
                }
                Vec::new()
            }
            Ok(Some(Frame::Lagged { .. })) => {
                // A lost open/close event must not silently attach an old cursor to a new log.
                let open = {
                    let mut slot = held.lock().await;
                    let h = slot
                        .as_mut()
                        .filter(|h| owner.holds(h))
                        .ok_or_else(|| "the app released or changed its node".to_owned())?;
                    h.mend().await.map_err(|e| e.to_string())?;
                    if !owner.holds(h) {
                        return Err("the app's node identity changed".into());
                    }
                    room_ids(&mut h.client)
                        .await
                        .map_err(|e| e.to_string())?
                        .into_iter()
                        .filter(|r| r.2)
                        .map(|r| r.0)
                        .collect::<Vec<_>>()
                };
                cursors.retain(|room, _| open.contains(room));
                seen.retain(|room, _| open.contains(room));
                if open.iter().any(|room| !cursors.contains_key(room)) {
                    return Err("a room opened while events were missed; refreshing its history and restarting observation".into());
                }
                if !owner.notice(listener,
                    "room observation caught up after missed events; refreshing the visible rooms".into()
                ).await { return Ok(()); }
                open
            }
            Ok(Some(Frame::NodeDetached { node })) => {
                return Err(format!("the connection to node {node} ended"));
            }
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => return Err("the vox daemon stopped".into()),
        };
        sessions_in.extend(rooms.iter().copied());
        for room in rooms {
            let Some(cursor) = cursors.get_mut(&room) else {
                continue;
            };
            loop {
                match follow_page(&held, owner, room, cursor, listener).await? {
                    FollowPage::More => tokio::task::yield_now().await,
                    FollowPage::CaughtUp => break,
                    FollowPage::Obsolete => return Ok(()),
                }
            }
        }
        sessions_in.sort_unstable();
        sessions_in.dedup();
        sessions_in.retain(|r| cursors.contains_key(r));
        if !sessions_told(&sessions_in, &mut seen, &held, owner, listener).await? {
            return Ok(());
        }
    }
}

/// Compare one projection token per room. No IPC guard crosses a foreign callback, including
/// error notices; an obsolete consumer ends observation without notifying its replacement.
async fn sessions_told(
    rooms: &[Digest32],
    seen: &mut HashMap<Digest32, Digest32>,
    held: &Slot,
    owner: &FollowOwner,
    listener: &dyn ClientListener,
) -> Result<bool, String> {
    if rooms.is_empty() {
        return Ok(owner.current());
    }
    let now = {
        let mut slot = held.lock().await;
        let h = slot
            .as_mut()
            .filter(|h| owner.holds(h))
            .ok_or_else(|| "the app released its node".to_owned())?;
        match h.mend().await {
            Err(error) => Err(error.to_string()),
            Ok(()) => {
                if !owner.holds(h) {
                    return Err("the app's node identity changed".into());
                }
                session_revisions(&mut h.client)
                    .await
                    .map_err(|e| e.to_string())
            }
        }
    };
    let now = match now {
        Ok(now) => now,
        Err(why) => return Ok(owner.notice(listener, why).await),
    };
    for &room in rooms {
        if seen.get(&room) != now.get(&room) && !owner.sessions(listener, room).await {
            return Ok(false);
        }
        // Only advance tokens whose invalidation has actually been consumed.
        match now.get(&room) {
            Some(revision) => {
                seen.insert(room, *revision);
            }
            None => {
                seen.remove(&room);
            }
        }
    }
    Ok(owner.current())
}
