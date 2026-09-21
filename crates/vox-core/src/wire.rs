//! Wire contracts shared series-wide (ADR-008): the struct-type tag registry,
//! struct framing, the per-struct domain-separation labels, the sync frame IDs,
//! and the application error-code table.
//!
//! ## Struct framing
//! Every signed/authenticated struct is transmitted/stored as
//! `tag(2, big-endian) ‖ version(1) ‖ canonical_cbor_body` (see [`frame`]).
//!
//! ## Signing input
//! The authenticator over a struct is computed over `domain_sep ‖ canonical_bytes`
//! (ADR-008), where `domain_sep` is the ASCII label from
//! [`StructTag::domain_sep`] and `canonical_bytes` is the CBOR body. The tag and
//! version are *not* re-hashed: the domain label already pins both the struct
//! type and its `/v1` version, so a verifier that uses the wrong label simply
//! fails the check (see [`signing_input`]).

use crate::error::{Error, Result};

/// Current format version emitted for every struct in this build.
pub const FORMAT_VERSION: u8 = 1;

/// The ADR-008 struct-type tag registry. The 2-byte tag identifies the
/// structure so identical canonical bytes are never cross-interpreted (the
/// serialization analogue of ADR-003's algorithm prefixes).
///
/// This tag space is **disjoint from** the ADR-003 ciphersuite-ID space; the two
/// never co-occur on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
#[non_exhaustive]
pub enum StructTag {
    /// `0x0001` — per-author hash-linked log entry (ADR-008).
    LogEntry = 0x0001,
    /// `0x0002` — Sender-Key distribution message (ADR-006).
    Skdm = 0x0002,
    /// `0x0003` — admin / governance certificate (ADR-007).
    AdminCert = 0x0003,
    /// `0x0004` — per-sender consent grant (ADR-007).
    ConsentGrant = 0x0004,
    /// `0x0005` — consent revocation (ADR-007).
    ConsentRevocation = 0x0005,
    /// `0x0006` — policy / passphrase-rotation update (ADR-007).
    PolicyRotation = 0x0006,
    /// `0x0007` — rendezvous record (ADR-012).
    RendezvousRecord = 0x0007,
    /// `0x0008` — pre-join record (ADR-012).
    PreJoinRecord = 0x0008,
    /// `0x0009` — TLS identity extension (ADR-011).
    TlsIdentityExtension = 0x0009,
    /// `0x000A` — file chunk manifest (ADR-014).
    ChunkManifest = 0x000A,
    /// `0x000B` — DGKA setup entry (ADR-009).
    DgkaSetup = 0x000B,
    /// `0x000C` — personal self-channel entry (ADR-008).
    SelfChannelEntry = 0x000C,
    /// `0x000D` — channel genesis record (ADR-007).
    GenesisRecord = 0x000D,
    /// `0x000E` — admin-delegation revocation (ADR-007).
    AdminDelegationRevocation = 0x000E,
    /// `0x000F` — tunnel service advertisement (ADR-013).
    ServiceAdvertisement = 0x000F,
    /// `0x0010` — epoch-end ephemeral-signing-key publication (ADR-009).
    EskPublication = 0x0010,
    /// `0x0011` — transport session-establishment record (ADR-011).
    SessionEstablishment = 0x0011,
    /// `0x0012` — member prekey-bundle rendezvous record (ADR-016 M14): a
    /// member's root-signed prekey bundle on the rendezvous board.
    MemberBundleRecord = 0x0012,
    /// `0x0013` — service-grant exclusion (ADR-007/ADR-017): withdraws the genesis
    /// service grant from one member, which is the only way to take back a
    /// capability nobody was ever issued a certificate for.
    ServiceGrantExclusion = 0x0013,
    /// `0x0014` — join witness (ADR-016 M17.6): the member that actually verified a
    /// joiner's ADR-005 passphrase proof signs that it did so. A key becomes an author
    /// only on such evidence, which is what makes "no member can add another member"
    /// enforceable rather than merely intended.
    JoinWitness = 0x0014,
}

impl StructTag {
    /// All registered tags, in ascending order.
    pub const ALL: [StructTag; 20] = [
        StructTag::LogEntry,
        StructTag::Skdm,
        StructTag::AdminCert,
        StructTag::ConsentGrant,
        StructTag::ConsentRevocation,
        StructTag::PolicyRotation,
        StructTag::RendezvousRecord,
        StructTag::PreJoinRecord,
        StructTag::TlsIdentityExtension,
        StructTag::ChunkManifest,
        StructTag::DgkaSetup,
        StructTag::SelfChannelEntry,
        StructTag::GenesisRecord,
        StructTag::AdminDelegationRevocation,
        StructTag::ServiceAdvertisement,
        StructTag::EskPublication,
        StructTag::SessionEstablishment,
        StructTag::MemberBundleRecord,
        StructTag::ServiceGrantExclusion,
        StructTag::JoinWitness,
    ];

    /// The 2-byte tag value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Resolve a tag from its 2-byte value, or [`Error::UnknownStructTag`].
    pub fn from_u16(v: u16) -> Result<Self> {
        // Linear scan over a 20-element table: trivial and avoids an
        // unsafe transmute or a brittle hand-maintained match-on-int.
        Self::ALL
            .into_iter()
            .find(|t| t.as_u16() == v)
            .ok_or(Error::UnknownStructTag(v))
    }

    /// The ASCII domain-separation label `vox/<struct>/v1` used as the prefix of
    /// this struct's signing input. This is the single source of truth for the
    /// labels referenced by the individual ADRs.
    #[must_use]
    pub const fn domain_sep(self) -> &'static str {
        match self {
            StructTag::LogEntry => "vox/log-entry/v1",
            StructTag::Skdm => "vox/skdm/v1",
            StructTag::AdminCert => "vox/admin-cert/v1",
            StructTag::ConsentGrant => "vox/consent-grant/v1",
            StructTag::ConsentRevocation => "vox/consent-revocation/v1",
            StructTag::ServiceGrantExclusion => "vox/service-grant-exclusion/v1",
            StructTag::PolicyRotation => "vox/policy-rotation/v1",
            StructTag::RendezvousRecord => "vox/rendezvous-record/v1",
            StructTag::PreJoinRecord => "vox/pre-join-record/v1",
            StructTag::TlsIdentityExtension => "vox/tls-identity-extension/v1",
            StructTag::ChunkManifest => "vox/chunk-manifest/v1",
            StructTag::DgkaSetup => "vox/dgka-setup/v1",
            StructTag::SelfChannelEntry => "vox/self-channel-entry/v1",
            StructTag::GenesisRecord => "vox/genesis/v1",
            StructTag::AdminDelegationRevocation => "vox/admin-delegation-revocation/v1",
            StructTag::ServiceAdvertisement => "vox/service-advertisement/v1",
            StructTag::EskPublication => "vox/esk-publication/v1",
            StructTag::SessionEstablishment => "vox/session-establishment/v1",
            StructTag::MemberBundleRecord => "vox/member-bundle-record/v1",
            StructTag::JoinWitness => "vox/join-witness/v1",
        }
    }
}

/// Frame a canonical CBOR body for the wire: `tag(2 BE) ‖ version(1) ‖ body`.
#[must_use]
pub fn frame(tag: StructTag, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len().saturating_add(3));
    out.extend_from_slice(&tag.as_u16().to_be_bytes());
    out.push(FORMAT_VERSION);
    out.extend_from_slice(body);
    out
}

/// A parsed wire frame: its struct tag, format version, and CBOR body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// The struct-type tag.
    pub tag: StructTag,
    /// The format version byte.
    pub version: u8,
    /// The canonical CBOR body (still to be decoded by the struct's codec).
    pub body: &'a [u8],
}

/// Parse a wire frame, resolving the tag and requiring a version this build
/// implements. Rejects unknown tags ([`Error::UnknownStructTag`]) and
/// unsupported versions ([`Error::UnsupportedVersion`]).
pub fn parse_frame(bytes: &[u8]) -> Result<Frame<'_>> {
    let tag_bytes = bytes.get(0..2).ok_or(Error::UnknownStructTag(0))?;
    let tag_val = u16::from_be_bytes([tag_bytes[0], tag_bytes[1]]);
    let tag = StructTag::from_u16(tag_val)?;
    let version = *bytes.get(2).ok_or(Error::UnsupportedVersion {
        tag: tag_val,
        version: 0,
    })?;
    if version != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion {
            tag: tag_val,
            version,
        });
    }
    Ok(Frame {
        tag,
        version,
        body: &bytes[3..],
    })
}

/// Build the signing/authentication input for a struct: `domain_sep ‖ body`
/// (ADR-008). `body` is the canonical CBOR encoding of the struct's fields.
#[must_use]
pub fn signing_input(tag: StructTag, body: &[u8]) -> Vec<u8> {
    let dom = tag.domain_sep().as_bytes();
    let mut out = Vec::with_capacity(dom.len().saturating_add(body.len()));
    out.extend_from_slice(dom);
    out.extend_from_slice(body);
    out
}

/// Anti-entropy sync frame IDs (ADR-008). Each frame is a 1-byte ID followed by
/// a canonical-CBOR body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum FrameId {
    /// `0x01` — opening frame carrying the mode bitmap.
    Hello = 0x01,
    /// `0x02` — feeds a peer holds: `[(author_id, max_seq, head_hash)]`.
    Have = 0x02,
    /// `0x03` — requested ranges: `[(author_id, from_seq, to_seq)]`.
    Want = 0x03,
    /// `0x04` — a log entry (skeleton + optional payload).
    Entry = 0x04,
    /// `0x05` — Negentropy range-reconciliation payload.
    Neg = 0x05,
}

impl FrameId {
    /// The 1-byte frame ID.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Resolve a frame ID from its byte, or [`Error::UnknownStructTag`] reused as
    /// a generic "unknown wire token" — callers at the sync layer translate this
    /// into a [`WireError::SyncModeUnsupported`] stream close where appropriate.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(FrameId::Hello),
            0x02 => Some(FrameId::Have),
            0x03 => Some(FrameId::Want),
            0x04 => Some(FrameId::Entry),
            0x05 => Some(FrameId::Neg),
            _ => None,
        }
    }
}

/// `HELLO` mode bitmap bit: frontier sync (default, required of every peer).
pub const SYNC_MODE_FRONTIER: u8 = 0b0000_0001;
/// `HELLO` mode bitmap bit: Negentropy range-reconciliation (required at scale).
pub const SYNC_MODE_RANGE_RECONCILIATION: u8 = 0b0000_0010;

/// The single wire application-error contract (ADR-008). A hard fail closes the
/// QUIC stream/connection with one of these codes — never a silent downgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[repr(u8)]
#[non_exhaustive]
pub enum WireError {
    /// `0x01` — protocol version unsupported.
    #[error("protocol version unsupported")]
    ProtocolVersionUnsupported = 0x01,
    /// `0x02` — offered suite below the channel policy floor (ADR-003).
    #[error("suite below floor")]
    SuiteBelowFloor = 0x02,
    /// `0x03` — unknown struct tag.
    #[error("unknown struct tag")]
    UnknownStructTag = 0x03,
    /// `0x04` — unknown algorithm id.
    #[error("unknown algo id")]
    UnknownAlgoId = 0x04,
    /// `0x05` — authenticator (signature/MAC) invalid.
    #[error("authenticator invalid")]
    AuthenticatorInvalid = 0x05,
    /// `0x06` — per-author quota exceeded (ADR-008).
    #[error("quota exceeded")]
    QuotaExceeded = 0x06,
    /// `0x07` — sync mode unsupported / mismatched.
    #[error("sync mode unsupported")]
    SyncModeUnsupported = 0x07,
    /// `0x08` — `(channelID, epoch)` mismatch.
    #[error("epoch mismatch")]
    EpochMismatch = 0x08,
    /// `0x09` — the **transport** failed mid-session: the peer went away, the stream
    /// reset, a frame could not be written or read. Nothing about the protocol or the
    /// peer's frames was wrong, which is exactly why it has its own code: before this
    /// existed every such failure was reported as `0x01`
    /// (protocol-version-unsupported), so a peer that simply closed its laptop was
    /// diagnosed as speaking the wrong version (ADR-008, ADR-016 M15.2c).
    #[error("transport failed")]
    TransportFailed = 0x09,
}

impl WireError {
    /// The 1-byte application error code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Resolve a wire error from its code byte.
    pub fn from_code(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(WireError::ProtocolVersionUnsupported),
            0x02 => Some(WireError::SuiteBelowFloor),
            0x03 => Some(WireError::UnknownStructTag),
            0x04 => Some(WireError::UnknownAlgoId),
            0x05 => Some(WireError::AuthenticatorInvalid),
            0x06 => Some(WireError::QuotaExceeded),
            0x07 => Some(WireError::SyncModeUnsupported),
            0x08 => Some(WireError::EpochMismatch),
            0x09 => Some(WireError::TransportFailed),
            _ => None,
        }
    }
}
