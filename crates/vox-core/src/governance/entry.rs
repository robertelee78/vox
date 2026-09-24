//! The typed governance log entry and its causal position (ADR-007/ADR-008).
//!
//! Governance facts ride the causal log ([`crate::log`]) as `EntryKind::Governance`
//! entries whose payload is one of the framed governance structs (genesis, admin
//! cert, admin-delegation revocation, consent grant/revocation, policy-update,
//! passphrase-rotation). This module is the **decoded, evaluator-ready** view of
//! such an entry: its parsed body, its 32-byte entry hash (the tie-break key and
//! the target of a revocation reference, ADR-008), and the **causal coordinates**
//! the deterministic evaluator needs.
//!
//! ## Causal coordinates (reusing the M5 model)
//! M5's DAG is per-author `seq` chains merged as concurrent feeds, with **no
//! cross-author happens-before edge** ([`crate::log::dag`]). The evaluator needs a
//! partial causal order over governance entries to apply revocation-wins and the
//! ascending-entry-hash tie-break. We model that order explicitly and minimally:
//!
//! - `author_id` + `seq`: within one author, lower `seq` causally precedes higher
//!   `seq` (the per-author total order M5 guarantees).
//! - `causal_predecessors`: the set of governance entry hashes this entry
//!   *happens-after* across authors. M5 has no cross-author schema edge, so this
//!   is supplied by the application from whatever causal references it tracks
//!   (e.g. the heads an author had seen when it authored — ADR-008 sync). Two
//!   governance entries are **concurrent** iff neither is in the other's
//!   transitive predecessor set. The evaluator treats an empty set as "concurrent
//!   with everything not in its own author-chain", which is the conservative,
//!   fail-safe reading (a revocation that *might* be concurrent with a delegation
//!   wins, ADR-007 §"Removal beats addition").
//!
//! Making causality an explicit input (rather than wall-clock or receipt order) is
//! exactly what makes [`crate::governance::evaluator::Evaluator`] a **total
//! function of log state**: the same entry set with the same causal edges yields
//! the identical verdict on every client, the precondition for the golden-vector
//! equality gate.

use std::collections::BTreeSet;

use crate::error::{Error, Result};
use crate::governance::cert::{AdminCert, AdminRevocation};
use crate::governance::consent::{ConsentGrant, ConsentRevocation};
use crate::governance::genesis::Genesis;
use crate::governance::policy::PolicyUpdate;
use crate::governance::rotation::PassphraseRotation;
use crate::governance::servicegrant::ServiceGrantExclusion;
use crate::hash::Digest32;
use crate::identity::composite::CompositePublicKey;
use crate::log::entry::Entry;
use crate::wire::{parse_frame, StructTag};

/// A decoded governance body — exactly the closed set of governance struct types
/// that may appear on the log (ADR-007). Any other struct tag is not a governance
/// fact and is rejected by [`GovBody::parse_framed`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum GovBody {
    /// The channel genesis record (tag `0x000D`) — the trust anchor / root admin.
    Genesis(Box<Genesis>),
    /// An admin-delegation cert (tag `0x0003`).
    AdminCert(Box<AdminCert>),
    /// An admin-delegation revocation (tag `0x000E`).
    AdminRevocation(Box<AdminRevocation>),
    /// A per-sender consent grant (tag `0x0004`).
    ConsentGrant(Box<ConsentGrant>),
    /// A per-sender consent revocation (tag `0x0005`).
    ConsentRevocation(Box<ConsentRevocation>),
    /// A service-grant exclusion (tag `0x0013`) — withdraws the genesis service
    /// grant from one member (ADR-017).
    ServiceGrantExclusion(Box<ServiceGrantExclusion>),
    /// A policy-update (tag `0x0006`, body kind = policy-update).
    PolicyUpdate(Box<PolicyUpdate>),
    /// A passphrase-rotation / epoch bump (tag `0x0006`, body kind = rotation).
    PassphraseRotation(Box<PassphraseRotation>),
}

impl GovBody {
    /// Parse a framed governance struct from its wire bytes, dispatching on the
    /// ADR-008 struct tag. The `0x0006` tag is disambiguated by attempting a
    /// policy-update first and falling back to a passphrase-rotation (the two carry
    /// distinct body-kind discriminants, so exactly one parse succeeds).
    ///
    /// A frame whose tag is not a governance struct is rejected with
    /// [`Error::MalformedGovernance`] — the governance plane's domain is closed.
    pub fn parse_framed(bytes: &[u8]) -> Result<Self> {
        let frame = parse_frame(bytes)?;
        match frame.tag {
            StructTag::GenesisRecord => Ok(GovBody::Genesis(Box::new(Genesis::from_wire(bytes)?))),
            StructTag::AdminCert => Ok(GovBody::AdminCert(Box::new(AdminCert::from_wire(bytes)?))),
            StructTag::AdminDelegationRevocation => Ok(GovBody::AdminRevocation(Box::new(
                AdminRevocation::from_wire(bytes)?,
            ))),
            StructTag::ConsentGrant => Ok(GovBody::ConsentGrant(Box::new(
                ConsentGrant::from_wire(bytes)?,
            ))),
            StructTag::ConsentRevocation => Ok(GovBody::ConsentRevocation(Box::new(
                ConsentRevocation::from_wire(bytes)?,
            ))),
            StructTag::ServiceGrantExclusion => Ok(GovBody::ServiceGrantExclusion(Box::new(
                ServiceGrantExclusion::from_wire(bytes)?,
            ))),
            StructTag::PolicyRotation => {
                // 0x0006 is shared: try policy-update, then passphrase-rotation.
                if let Ok(pu) = PolicyUpdate::from_wire(bytes) {
                    Ok(GovBody::PolicyUpdate(Box::new(pu)))
                } else {
                    Ok(GovBody::PassphraseRotation(Box::new(
                        PassphraseRotation::from_wire(bytes)?,
                    )))
                }
            }
            _ => Err(Error::MalformedGovernance("not a governance struct tag")),
        }
    }

    /// The `(channelID, epoch)` this body is bound to (genesis has epoch 0 by
    /// definition — it predates any epoch bump).
    #[must_use]
    pub fn channel_and_epoch(&self) -> (Digest32, u64) {
        match self {
            GovBody::Genesis(g) => (g.channel_id(), 0),
            GovBody::AdminCert(c) => (c.body.channel_id, c.body.epoch),
            GovBody::AdminRevocation(r) => (r.body.channel_id, r.body.epoch),
            GovBody::ConsentGrant(g) => (g.body.channel_id, g.body.epoch),
            GovBody::ConsentRevocation(r) => (r.body.channel_id, r.body.epoch),
            GovBody::ServiceGrantExclusion(x) => (x.body.channel_id, x.body.epoch),
            GovBody::PolicyUpdate(p) => (p.body.channel_id, p.body.epoch),
            GovBody::PassphraseRotation(r) => (r.body.channel_id, r.body.old_epoch),
        }
    }

    /// The identity that authored/issued this body (the signer whose authority the
    /// evaluator checks). For genesis this is the creator (root admin).
    #[must_use]
    pub fn issuer_id(&self) -> Digest32 {
        match self {
            GovBody::Genesis(g) => g.creator_pubkey().fingerprint(),
            GovBody::AdminCert(c) => c.body.issuer_id,
            GovBody::AdminRevocation(r) => r.body.issuer_id,
            GovBody::ConsentGrant(g) => g.body.author_id,
            GovBody::ConsentRevocation(r) => r.body.author_id,
            GovBody::ServiceGrantExclusion(x) => x.body.issuer_id,
            GovBody::PolicyUpdate(p) => p.body.issuer_id,
            GovBody::PassphraseRotation(r) => r.body.issuer_id,
        }
    }
}

/// A governance entry positioned in the causal log: its decoded body, its 32-byte
/// log entry hash, the author + per-author sequence, and the cross-author causal
/// predecessor set the evaluator uses for happens-before.
#[derive(Debug, Clone)]
pub struct GovEntry {
    /// The decoded governance body.
    pub body: GovBody,
    /// The SHA-256 of the canonical log entry (ADR-008) — the tie-break key and
    /// the target a revocation references.
    pub entry_hash: Digest32,
    /// The authoring identity's fingerprint (== the body's issuer/author).
    pub author_id: Digest32,
    /// The per-author sequence number (within-author causal order).
    pub seq: u64,
    /// The cross-author governance entry hashes this entry causally happens-after
    /// (see module docs). Empty for an entry concurrent with all other authors'.
    pub causal_predecessors: BTreeSet<Digest32>,
}

impl GovEntry {
    /// Build a positioned governance entry from a **verified** M5 log entry — the
    /// only production-trusted construction path (closes the forged-coordinate
    /// vector).
    ///
    /// `author_root` is the claimed author's composite root public key (trusted via
    /// the identity layer). This:
    /// 1. **verifies** the M5 entry — composite signature over the skeleton +
    ///    payload-hash binding ([`Entry::verify`]) — and that the signer's
    ///    fingerprint equals `entry.skeleton.author_id`;
    /// 2. requires a **retained payload** (the framed governance struct lives in
    ///    the payload; a pruned entry cannot be decoded into a governance fact);
    /// 3. confirms the entry binds to `expected_channel` (and parses the payload as
    ///    a governance struct also bound to that channel — the bridge rejects a
    ///    governance body whose own `channelID` disagrees with the log entry's);
    /// 4. **recomputes** all coordinates from the verified entry: `entry_hash =
    ///    entry.entry_hash()`, `author_id`/`seq` from the signed skeleton.
    ///
    /// `causal_predecessors` is the set of governance entry hashes this entry
    /// happens-after, supplied from ADR-008 sync heads (the application's causal
    /// references); each is a 32-byte content address that the evaluator only ever
    /// *follows* (never trusts for authority), so passing it here is safe — a bogus
    /// edge to a non-existent hash is simply ignored by the evaluator's causal
    /// relation.
    pub fn from_verified_log_entry(
        entry: &Entry,
        author_root: &CompositePublicKey,
        expected_channel: &Digest32,
        causal_predecessors: BTreeSet<Digest32>,
    ) -> Result<Self> {
        // 1. The M5 entry must verify (signature + payload binding + author match).
        entry.verify(author_root)?;
        // 2. The framed governance struct lives in the retained payload.
        let payload = entry.payload.as_deref().ok_or(Error::MalformedGovernance(
            "governance entry payload pruned",
        ))?;
        // 3a. Bind to the expected channel at the log layer.
        if &entry.skeleton.channel_id != expected_channel {
            return Err(Error::MalformedGovernance(
                "governance entry channelID mismatch",
            ));
        }
        // 3b. Decode the payload as a governance body and bind BOTH its channelID
        //     AND its epoch to the signed log skeleton — the (channelID, epoch)
        //     binding must cover both axes, so a body's self-asserted epoch cannot
        //     disagree with the epoch the author actually signed (genesis carries
        //     epoch 0, matching a genesis log entry's skeleton epoch).
        let body = GovBody::parse_framed(payload)?;
        let (body_channel, body_epoch) = body.channel_and_epoch();
        if body_channel != entry.skeleton.channel_id {
            return Err(Error::MalformedGovernance(
                "governance body channelID disagrees with log entry",
            ));
        }
        if body_epoch != entry.skeleton.epoch {
            return Err(Error::MalformedGovernance(
                "governance body epoch disagrees with log entry",
            ));
        }
        // 4. Recompute coordinates from the verified, signed skeleton.
        Ok(Self {
            body,
            entry_hash: entry.entry_hash(),
            author_id: entry.skeleton.author_id,
            seq: entry.skeleton.seq,
            causal_predecessors,
        })
    }
}
