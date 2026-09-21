//! ADR-020 §3 — the node-wide **trust keyring**: which identities this node has
//! decided to trust, and the petname it calls each of them.
//!
//! ## Why this exists
//!
//! ADR-007 makes reading a member a deliberate act, taken **per sender**. That is
//! right for people and fatal for agents: five agent identities is twenty manual
//! approvals, with nobody at the keyboard to give them.
//!
//! A genesis "open room" flag was designed for this and **rejected**. The keyring
//! is the decider's answer and it is better on three counts: no wire change, no
//! immutable genesis decision, and it is reversible. Consent is still *delivered*
//! per room — an SKDM is a sender key for one room's log, and there is no way
//! around that — but the **decision** is per identity. Trusting an agent once
//! therefore covers every room shared with it, now and in future.
//!
//! ## The escalation it closes
//!
//! A room cannot be joined without the passphrase
//! ([`ChannelState::join_channel_with_profile`](crate::node::channel::ChannelState::join_channel_with_profile)
//! derives the channel secret through Argon2id). But **admission is not joining**:
//! [`admit_author`](crate::node::channel::ChannelState::admit_author) is a *log*
//! fact, and `nat::service` admits a member-bundle record for an author this node
//! does not know when a peer it *does* know publishes it — deliberate vouching, so
//! members learn of each other without meeting.
//!
//! Vouching is harmless under per-sender consent. It becomes an escalation only if
//! auto-consent keys on "admitted author", which the rejected genesis flag would
//! have done: one compromised member could vouch a stranger onto the board and
//! hand it the room. Keyed on the keyring instead, a vouched stranger is not in the
//! keyring and reads **nothing**, however it came to be admitted.
//!
//! ## Petnames
//!
//! The name is local, chosen by this operator, and binds to a fingerprint — a
//! petname. Nothing is looked up, nothing is registered, and two nodes may call the
//! same identity different things without disagreeing about *who* it is, because
//! the fingerprint is the identity and the name is only how this node says it.
//!
//! ## At rest
//!
//! Sealed under a key derived from this node's own identity
//! ([`TRUST_SEK_INFO`]), mirroring how an anchor seals its log. Two consequences,
//! both intended: a stolen disk yields no trust graph without the identity, and
//! **trust operations require an unlocked identity** — which is correct, since
//! deciding whom to trust is an identity-level act. The sealed blob is then kept in
//! the store's public metadata table, which stays honest: ciphertext is a public
//! fact.

use std::collections::{BTreeMap, BTreeSet};

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::atrest::sek::{Sek, NONCE_LEN, SEK_LEN};
use crate::atrest::store::{open_segment, seal_segment, SealedSegment, SegmentKind};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::{sha256, Digest32};
use crate::identity::composite::RootSigner;
use crate::node::store::Store;

/// HKDF label for the keyring's sealing key.
pub const TRUST_SEK_INFO: &[u8] = b"vox/trust-keyring-sek/v1";

/// Domain-separated context the identity factor is taken over. A fixed value
/// because the keyring is node-wide: it belongs to no channel.
pub const TRUST_CONTEXT_LABEL: &[u8] = b"vox/trust-keyring-context/v1";

/// The metadata key the sealed keyring is stored under.
pub const TRUST_META_KEY: &str = "trust";

/// Only slot; the keyring is a single blob.
const TRUST_SEGMENT_ID: u64 = 0;

/// Encoding version of the keyring body.
const KEYRING_VERSION: u64 = 1;

/// Most identities one node will ever trust. A bound, not a target: it keeps a
/// corrupt or hostile blob from forcing an unbounded allocation on load.
pub const MAX_TRUSTED: usize = 1024;

/// Longest petname. Long enough for `codex@some-long-hostname`, short enough that
/// a name cannot be used to smuggle a payload into a operator's terminal.
pub const MAX_PETNAME: usize = 64;

/// The sealing key for this identity's keyring.
pub fn trust_sek(signer: &dyn RootSigner) -> Result<Sek> {
    use crate::atrest::idfactor::{IdentityFactor, SignatureIdentityFactor};
    let context = sha256(TRUST_CONTEXT_LABEL);
    let factor = SignatureIdentityFactor::new(signer);
    let factor_id = factor.factor_id(&context)?;
    let hk = Hkdf::<Sha256>::new(None, factor_id.as_ref());
    let mut key = Zeroizing::new([0u8; SEK_LEN]);
    hk.expand(TRUST_SEK_INFO, key.as_mut())
        .map_err(|_| Error::AtRestUnlockFailed)?;
    Ok(Sek::from_bytes(key))
}

/// This node's trusted identities, each with the petname this node calls it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Keyring {
    entries: BTreeMap<Digest32, String>,
}

impl Keyring {
    /// An empty keyring — trusting nobody, which is the correct default.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust `fingerprint`, calling it `petname`. Re-trusting an identity renames
    /// it rather than adding a second entry: a fingerprint is the identity, so it
    /// can only be in the keyring once.
    ///
    /// The petname must be non-empty, at most [`MAX_PETNAME`] bytes, and free of
    /// control characters — it is displayed in a terminal and used to address
    /// members by name.
    pub fn trust(&mut self, fingerprint: Digest32, petname: &str) -> Result<()> {
        let name = petname.trim();
        if name.is_empty() || name.len() > MAX_PETNAME {
            return Err(Error::SizeLimitExceeded("petname length"));
        }
        if name.chars().any(char::is_control) {
            return Err(Error::MalformedGovernance("petname control character"));
        }
        if !self.entries.contains_key(&fingerprint) && self.entries.len() >= MAX_TRUSTED {
            return Err(Error::SizeLimitExceeded("trusted identities"));
        }
        self.entries.insert(fingerprint, name.to_owned());
        Ok(())
    }

    /// Stop trusting `fingerprint`. Returns whether it was trusted.
    ///
    /// Forward-looking only, and deliberately so: this stops *future* rooms from
    /// auto-consenting, and does not recall consent already granted. Recalling
    /// that is [`ChannelState::revoke_consent`](crate::node::channel::ChannelState::revoke_consent),
    /// a per-room governance act — ADR-007's "enforcement honesty" applies, and
    /// nothing here can say otherwise.
    pub fn untrust(&mut self, fingerprint: &Digest32) -> bool {
        self.entries.remove(fingerprint).is_some()
    }

    /// Whether `fingerprint` is trusted.
    #[must_use]
    pub fn is_trusted(&self, fingerprint: &Digest32) -> bool {
        self.entries.contains_key(fingerprint)
    }

    /// This node's petname for `fingerprint`, if it is trusted.
    #[must_use]
    pub fn petname(&self, fingerprint: &Digest32) -> Option<&str> {
        self.entries.get(fingerprint).map(String::as_str)
    }

    /// Every trusted fingerprint.
    #[must_use]
    pub fn trusted(&self) -> BTreeSet<Digest32> {
        self.entries.keys().copied().collect()
    }

    /// Every entry, in fingerprint order.
    pub fn iter(&self) -> impl Iterator<Item = (&Digest32, &str)> {
        self.entries.iter().map(|(f, n)| (f, n.as_str()))
    }

    /// How many identities are trusted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nobody is trusted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Canonical CBOR body: `[version, [[fingerprint, petname], ..]]`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(2).uint(KEYRING_VERSION).array(self.entries.len());
        for (fp, name) in &self.entries {
            e.array(2).bytes(fp).text(name);
        }
        e.finish()
    }

    /// Parse a keyring body.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(b);
        let outer = d.array().map_err(|_| Error::MalformedAtRest("keyring"))?;
        if outer != 2 {
            return Err(Error::MalformedAtRest("keyring arity"));
        }
        let version = d
            .uint()
            .map_err(|_| Error::MalformedAtRest("keyring version"))?;
        if version != KEYRING_VERSION {
            return Err(Error::MalformedAtRest("keyring version"));
        }
        let n = d
            .array()
            .map_err(|_| Error::MalformedAtRest("keyring len"))?;
        if n > MAX_TRUSTED {
            return Err(Error::SizeLimitExceeded("trusted identities"));
        }
        let mut entries = BTreeMap::new();
        for _ in 0..n {
            let pair = d
                .array()
                .map_err(|_| Error::MalformedAtRest("keyring row"))?;
            if pair != 2 {
                return Err(Error::MalformedAtRest("keyring row arity"));
            }
            let fp = Digest32::try_from(
                d.bytes()
                    .map_err(|_| Error::MalformedAtRest("keyring fingerprint"))?,
            )
            .map_err(|_| Error::MalformedAtRest("keyring fingerprint length"))?;
            let name = d
                .text()
                .map_err(|_| Error::MalformedAtRest("keyring petname"))?
                .to_owned();
            if name.is_empty() || name.len() > MAX_PETNAME {
                return Err(Error::MalformedAtRest("keyring petname length"));
            }
            entries.insert(fp, name);
        }
        d.finish()
            .map_err(|_| Error::MalformedAtRest("keyring trailing"))?;
        Ok(Self { entries })
    }

    /// Seal and write the keyring. Requires an unlocked identity.
    pub fn save(&self, store: &Store, signer: &dyn RootSigner) -> Result<()> {
        let sek = trust_sek(signer)?;
        let sealed = seal_segment(&sek, SegmentKind::Trust, TRUST_SEGMENT_ID, &self.to_bytes())?;
        let mut blob = Vec::with_capacity(NONCE_LEN + sealed.ciphertext.len());
        blob.extend_from_slice(&sealed.nonce);
        blob.extend_from_slice(&sealed.ciphertext);
        store.put_meta(TRUST_META_KEY, &blob)
    }

    /// Read and open the keyring, or an empty one if this node has never trusted
    /// anybody. Requires an unlocked identity.
    pub fn load(store: &Store, signer: &dyn RootSigner) -> Result<Self> {
        let Some(blob) = store.get_meta(TRUST_META_KEY)? else {
            return Ok(Self::new());
        };
        if blob.len() < NONCE_LEN {
            return Err(Error::MalformedAtRest("keyring blob too short"));
        }
        let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
        let nonce = <[u8; NONCE_LEN]>::try_from(nonce_bytes)
            .map_err(|_| Error::MalformedAtRest("keyring nonce"))?;
        let sealed = SealedSegment {
            nonce,
            ciphertext: ciphertext.to_vec(),
        };
        let sek = trust_sek(signer)?;
        let plain = open_segment(&sek, SegmentKind::Trust, TRUST_SEGMENT_ID, &sealed)?;
        Self::from_bytes(&plain)
    }
}
