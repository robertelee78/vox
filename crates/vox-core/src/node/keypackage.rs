//! ADR-023 decision 4 / M23.3 — **key delivery through members**: a sender-key message sealed
//! to one member and posted to the room's log as a `key-package` entry.
//!
//! A sender key used to travel only on a direct pairwise stream (`release_key_to`, the
//! re-key path). Two members who were never online at the same time therefore converged on
//! each other's ciphertext and could never read it: the key had no way to wait for its
//! recipient. The log already is a store-and-forward medium — every member replicates every
//! entry — so the key goes there. An always-on member (the NAS) holds it like any entry and
//! hands it over when the recipient next syncs. No service is added and the anchor stores
//! nothing (PRD-001 R34): delivery is through member nodes only.
//!
//! The direct pairwise stream stays the fast path. A key-package is posted when that path
//! cannot reach the recipient now.
//!
//! ## The seal: a one-shot PQXDH, always
//!
//! ADR-023 says the package is sealed with the pairwise session's keys if a session exists,
//! and otherwise with a one-shot PQXDH to the recipient's published prekey (ADR-004). This
//! **always** uses the one-shot, and the reason is measured rather than preferred: pairwise
//! sessions live only in the node's memory (`Node::sessions` is never persisted). A package
//! sealed into a session is unopenable by a recipient that has restarted since — and a
//! recipient that is never online with its sender restarts between the two by definition.
//! A one-shot seal needs nothing but the recipient's prekey ring, which *is* persisted, so a
//! package opens whenever it arrives.
//!
//! The seal is the same PQXDH opening message and first ratchet message a pairwise `Hello`
//! plus `Skdm` carries — nothing new cryptographically — kept whole in one entry.
//!
//! ## What a non-recipient learns
//!
//! The recipient's fingerprint and that a key was sent, which the consent entries already
//! reveal to every member (ADR-023 decision 4). The SKDM itself is sealed to the recipient's
//! prekeys: another member's store holds the entry and cannot open it.
//!
//! ## Not built here
//!
//! Pruning a package once its recipient has acknowledged it needs ADR-023's `seen` (M23.2),
//! which this tree does not have. Packages are prunable by retention like any content entry,
//! and a recipient ignores one it has already installed (`ChannelState::accept_skdm` keeps the
//! live chain).

use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::group::skdm::Skdm;
use crate::hash::Digest32;
use crate::identity::keyagreement::X25519IdentityKey;
use crate::identity::PrekeyBundlePublic;
use crate::join::session::JoinContext;
use crate::pairwise::init_message::InitialMessage;
use crate::pairwise::message::Message;
use crate::pairwise::session::Session;
use crate::wire::{frame, parse_frame, StructTag};

/// The body version of a key-package.
const KEY_PACKAGE_VERSION: u64 = 1;

/// The largest key-package this node will parse: an SKDM and a PQXDH opening message, with
/// room to spare. A bound, because the bytes come from another member's log entry.
const MAX_KEY_PACKAGE: usize = 64 * 1024;

/// One sealed sender-key message for one member, as it sits in the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPackage {
    /// Who it is for.
    pub recipient: Digest32,
    /// The PQXDH opening message (`InitialMessage::to_wire`) against the recipient's
    /// published prekey bundle.
    pub initial: Vec<u8>,
    /// The first ratchet message of that one-shot session (`Message::to_wire`), whose
    /// plaintext is the SKDM.
    pub sealed: Vec<u8>,
}

impl KeyPackage {
    /// Seal `skdm` to the member whose published bundle is `bundle`.
    ///
    /// # Errors
    /// If the PQXDH handshake or the seal fails.
    pub fn seal(
        identity_dh: &X25519IdentityKey,
        bundle: &PrekeyBundlePublic,
        ctx: &JoinContext,
        recipient: Digest32,
        skdm: &Skdm,
    ) -> Result<Self> {
        let (initial, mut session) = Session::initiate(
            identity_dh,
            bundle,
            &ctx.channel_id,
            ctx.epoch,
            ctx.suite_id,
            ctx.floor,
        )?;
        let sealed = skdm.seal_into(&mut session)?.to_wire();
        Ok(Self {
            recipient,
            initial: initial.to_wire(),
            sealed,
        })
    }

    /// The opening message, parsed.
    ///
    /// # Errors
    /// If it does not parse.
    pub fn initial_message(&self) -> Result<InitialMessage> {
        InitialMessage::from_wire(&self.initial)
    }

    /// Open the sealed SKDM with the one-shot `session` the recipient built from
    /// [`Self::initial_message`] and its own prekeys. Still unverified: the channel verifies
    /// it against its author's admitted key.
    ///
    /// # Errors
    /// If the message does not parse or does not decrypt under `session`.
    pub fn open(&self, session: &mut Session, now_secs: u64) -> Result<Skdm> {
        let message = Message::from_wire(&self.sealed)?;
        Skdm::open_from(session, &message, now_secs)
    }

    /// Try to open this package with `ring`, **persisting nothing** — the question "could this
    /// identity open it", asked of a store at rest (a diagnostic, and what a proof uses to show
    /// that a member carrying a package for someone else cannot read it). The node installs
    /// packages through its own path, which persists the one-time-prekey consume.
    ///
    /// # Errors
    /// If the ring holds no prekey the package was sealed to, or the seal does not open.
    pub fn open_with_ring(
        &self,
        ring: &mut crate::node::prekeys::PrekeyRing,
        ctx: &JoinContext,
        now_secs: u64,
    ) -> Result<Skdm> {
        let init = self.initial_message()?;
        let mut reuse = crate::pairwise::OtpReuseTracker::new();
        if let Some(id) = init.one_time_prekey_id {
            match ring.use_one_time(id, now_secs) {
                crate::node::prekeys::OneTimeUse::Fresh => {}
                crate::node::prekeys::OneTimeUse::Reused => {
                    reuse.observe(id);
                }
                crate::node::prekeys::OneTimeUse::Unknown => {
                    return Err(Error::MalformedBundle(
                        "key-package names a one-time prekey this ring never held",
                    ))
                }
            }
        }
        let signed_prekey =
            ring.signed_prekey_for(init.signed_prekey_id)
                .ok_or(Error::MalformedBundle(
                    "key-package names a signed prekey this ring does not hold",
                ))?;
        let one_time_prekey = init
            .one_time_prekey_id
            .and_then(|id| ring.consumed_one_time(id));
        let prekeys = crate::pairwise::ResponderPrekeys {
            identity_dh_key: ring.identity_dh(),
            signed_prekey,
            one_time_prekey,
        };
        let mut session = Session::accept(
            &init,
            &prekeys,
            &ctx.channel_id,
            ctx.epoch,
            &mut reuse,
            ctx.floor,
        )?;
        self.open(&mut session, now_secs)
    }

    /// The framed entry payload.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array(4)
            .uint(KEY_PACKAGE_VERSION)
            .bytes(&self.recipient)
            .bytes(&self.initial)
            .bytes(&self.sealed);
        frame(StructTag::KeyPackage, &e.finish())
    }

    /// Parse a framed key-package.
    ///
    /// # Errors
    /// If the bytes are not a key-package, are too large, or are malformed.
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_KEY_PACKAGE {
            return Err(Error::SizeLimitExceeded("key-package"));
        }
        let parsed = parse_frame(bytes)?;
        if parsed.tag != StructTag::KeyPackage {
            return Err(Error::MalformedBundle("not a key-package"));
        }
        let mut d = Decoder::new(parsed.body);
        if d.array()? != 4 {
            return Err(Error::MalformedBundle("key-package arity"));
        }
        if d.uint()? != KEY_PACKAGE_VERSION {
            return Err(Error::MalformedBundle("key-package version"));
        }
        let recipient: Digest32 = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedBundle("key-package recipient"))?;
        let initial = d.bytes()?.to_vec();
        let sealed = d.bytes()?.to_vec();
        d.finish()?;
        Ok(Self {
            recipient,
            initial,
            sealed,
        })
    }

    /// Whether a log entry's payload is a key-package, by its struct tag alone.
    #[must_use]
    pub fn is_key_package(payload: &[u8]) -> bool {
        parse_frame(payload).is_ok_and(|f| f.tag == StructTag::KeyPackage)
    }
}
