//! Emergent membership and per-sender visibility (ADR-007 §"Join and per-sender
//! consent flow", §"Conflict resolution").
//!
//! **Membership is emergent, not a roster** (ADR-007): you are *in the swarm* by
//! holding the passphrase (ADR-005/M3), and you are *readable* by whoever has
//! consent-granted to you. There is no admin-issued membership certificate and no
//! admin-maintained member list to forge — the Signalgate / Megolm
//! membership-injection class is structurally absent.
//!
//! This module derives the "who can read whom" view **from the log** (via the
//! deterministic [`crate::governance::evaluator::Evaluator`]) and exposes the
//! per-sender, monotonic visibility ADR-007 promises:
//! - a reader `N`'s readable set fills in **monotonically, per sender**: each
//!   member `A` independently decides whether to consent, and until `A` does, `A`'s
//!   messages are undecryptable to `N` — forever if `A` never consents.
//!
//! It also provides the consent issuing seam: building the consent-grant entry
//! that carries `skdm_ref` (the SHA-256 of the SKDM delivered over M4's pairwise
//! session), and the consent-revocation entry that records `A`'s `chain_id`
//! rotation excluding the revoked target. The SKDM and the actual sender-key
//! rotation are M4's job; M6 authors the signed log facts.

use std::collections::BTreeSet;

use crate::error::Result;
use crate::governance::consent::{ConsentGrant, ConsentRevocation};
use crate::governance::evaluator::Evaluator;
use crate::governance::genesis::HistoryMode;
use crate::group::Skdm;
use crate::hash::{sha256, Digest32};
use crate::identity::composite::RootSigner;

/// The emergent membership / readability view over a channel, derived from the
/// governance log via the [`Evaluator`].
///
/// Borrows the evaluator: the view is exactly the consent edges the evaluator
/// resolved (single-writer, latest-causal), with no separate roster.
#[derive(Debug)]
pub struct MembershipView<'a> {
    evaluator: &'a Evaluator,
}

impl<'a> MembershipView<'a> {
    /// View the emergent membership/readability over the given evaluator.
    #[must_use]
    pub fn new(evaluator: &'a Evaluator) -> Self {
        Self { evaluator }
    }

    /// Whether `reader` may currently read `author`'s messages on the **outbound**
    /// (consent) axis. This is the authoritative log-derived readability.
    #[must_use]
    pub fn can_read(&self, reader: &Digest32, author: &Digest32) -> bool {
        self.evaluator.can_read(reader, author)
    }

    /// The set of authors `reader` may currently read, derived by asking the
    /// evaluator which authors consent to `reader`. This is `reader`'s monotonic
    /// per-sender readable set (ADR-007): it grows as more members consent and
    /// shrinks only when a member revokes (forward-only).
    #[must_use]
    pub fn readable_authors(
        &self,
        reader: &Digest32,
        all_authors: &[Digest32],
    ) -> BTreeSet<Digest32> {
        all_authors
            .iter()
            .copied()
            .filter(|a| self.evaluator.can_read(reader, a))
            .collect()
    }

    /// The set of identities `author` currently consents to (who may read
    /// `author`), in deterministic order.
    #[must_use]
    pub fn readers_of(&self, author: &Digest32) -> BTreeSet<Digest32> {
        self.evaluator.readers_of(author)
    }
}

/// Compute the `skdm_ref` a consent-grant entry carries: the SHA-256 of the framed
/// SKDM `A` delivered to the target over the M4 pairwise session (ADR-007 — the
/// entry carries only this hash; the SKDM itself travels out-of-band).
#[must_use]
pub fn skdm_ref(skdm: &Skdm) -> Digest32 {
    sha256(&skdm.to_wire())
}

/// Issue a consent grant: `A` releasing `A`'s sender key to `target`.
///
/// This authors the signed consent-grant log entry ([`ConsentGrant`]) carrying the
/// `skdm_ref` of the SKDM `A` delivered to `target` over M4's pairwise session, and
/// the history mode in force at grant time (which decided whether `A` released its
/// origin or current chain key, ADR-006/M4). The SKDM delivery itself is M4's job;
/// this is the M6 log fact that records the consent.
pub fn issue_consent_grant(
    author_root: &dyn RootSigner,
    channel_id: &Digest32,
    epoch: u64,
    target: Digest32,
    delivered_skdm: &Skdm,
    history_mode_at_grant: HistoryMode,
) -> Result<ConsentGrant> {
    ConsentGrant::build(
        author_root,
        channel_id,
        epoch,
        target,
        skdm_ref(delivered_skdm),
        history_mode_at_grant,
    )
}

/// Issue a consent revocation: `A` withdrawing `target`'s access to `A`'s **future**
/// messages by rotating `A`'s own `chain_id` to `new_chain_id` (excluding
/// `target`). This authors the signed consent-revocation log entry; the actual
/// sender-key rotation + SKDM redistribution to the remaining consenters is M4's
/// job. Only the forward guarantee is cryptographic — `target` keeps the old
/// (now-uncallable) keys and cannot read `A`'s future, but already-held traffic is
/// not recalled (ADR-007 §"Enforcement honesty").
pub fn issue_consent_revocation(
    author_root: &dyn RootSigner,
    channel_id: &Digest32,
    epoch: u64,
    target: Digest32,
    new_chain_id: u64,
) -> Result<ConsentRevocation> {
    ConsentRevocation::build(author_root, channel_id, epoch, target, new_chain_id)
}

/// The signed, room-bound removal of one exact node identity.
#[derive(Debug, Clone)]
pub struct MemberRemoval {
    /// Channel in which the fact applies.
    pub channel_id: Digest32,
    /// Channel epoch.
    pub epoch: u64,
    /// Fingerprint of the signer.
    pub issuer_id: Digest32,
    /// Fingerprint of the removed node.
    pub target_id: Digest32,
    /// Composite signature over the canonical unsigned body.
    pub signature: crate::identity::composite::CompositeSignature,
}

impl MemberRemoval {
    /// Sign a removal. Authorization is checked against the causal governance log.
    pub fn build(
        issuer_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        target_id: &Digest32,
    ) -> Result<Self> {
        let issuer_id = issuer_root.fingerprint();
        let body = member_body(channel_id, epoch, &issuer_id, target_id, None);
        let signature = issuer_root.sign(&crate::wire::signing_input(
            crate::wire::StructTag::MemberRemoval,
            &body,
        ))?;
        Ok(Self {
            channel_id: *channel_id,
            epoch,
            issuer_id,
            target_id: *target_id,
            signature,
        })
    }

    /// Canonical unsigned body covered by the signature.
    pub fn canonical_body(&self) -> Vec<u8> {
        member_body(
            &self.channel_id,
            self.epoch,
            &self.issuer_id,
            &self.target_id,
            None,
        )
    }

    /// Canonical framed fact, including the composite signature.
    pub fn to_wire(&self) -> Vec<u8> {
        member_wire(
            crate::wire::StructTag::MemberRemoval,
            &self.channel_id,
            self.epoch,
            &self.issuer_id,
            &self.target_id,
            None,
            &self.signature,
        )
    }

    /// Decode a framed fact without granting authority.
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let (channel_id, epoch, issuer_id, target_id, _, signature) =
            parse_member(bytes, crate::wire::StructTag::MemberRemoval)?;
        Ok(Self {
            channel_id,
            epoch,
            issuer_id,
            target_id,
            signature,
        })
    }

    /// Verify the signer binding and signature.
    pub fn verify(&self, key: &crate::identity::composite::CompositePublicKey) -> Result<()> {
        verify_member(
            key,
            &self.issuer_id,
            crate::wire::StructTag::MemberRemoval,
            &member_body(
                &self.channel_id,
                self.epoch,
                &self.issuer_id,
                &self.target_id,
                None,
            ),
            &self.signature,
        )
    }
}

/// Creator-signed readmission referencing the removal log entry hashes it supersedes.
#[derive(Debug, Clone)]
pub struct MemberReadmission {
    /// Channel in which the fact applies.
    pub channel_id: Digest32,
    /// Channel epoch.
    pub epoch: u64,
    /// Fingerprint of the signer.
    pub issuer_id: Digest32,
    /// Fingerprint of the readmitted node.
    pub target_id: Digest32,
    /// Nonempty, strictly sorted removal entry hashes.
    pub removal_entry_hashes: Vec<Digest32>,
    /// Composite signature over the canonical unsigned body.
    pub signature: crate::identity::composite::CompositeSignature,
}

impl MemberReadmission {
    /// Sign a readmission. References must already be nonempty, sorted and unique.
    pub fn build(
        issuer_root: &dyn RootSigner,
        channel_id: &Digest32,
        epoch: u64,
        target_id: &Digest32,
        removal_entry_hashes: Vec<Digest32>,
    ) -> Result<Self> {
        check_removals(&removal_entry_hashes)?;
        let issuer_id = issuer_root.fingerprint();
        let body = member_body(
            channel_id,
            epoch,
            &issuer_id,
            target_id,
            Some(&removal_entry_hashes),
        );
        let signature = issuer_root.sign(&crate::wire::signing_input(
            crate::wire::StructTag::MemberReadmission,
            &body,
        ))?;
        Ok(Self {
            channel_id: *channel_id,
            epoch,
            issuer_id,
            target_id: *target_id,
            removal_entry_hashes,
            signature,
        })
    }

    /// Canonical unsigned body covered by the signature.
    pub fn canonical_body(&self) -> Vec<u8> {
        member_body(
            &self.channel_id,
            self.epoch,
            &self.issuer_id,
            &self.target_id,
            Some(&self.removal_entry_hashes),
        )
    }

    /// Canonical framed fact, including the composite signature.
    pub fn to_wire(&self) -> Vec<u8> {
        member_wire(
            crate::wire::StructTag::MemberReadmission,
            &self.channel_id,
            self.epoch,
            &self.issuer_id,
            &self.target_id,
            Some(&self.removal_entry_hashes),
            &self.signature,
        )
    }

    /// Decode a framed fact without granting authority.
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let (channel_id, epoch, issuer_id, target_id, hashes, signature) =
            parse_member(bytes, crate::wire::StructTag::MemberReadmission)?;
        Ok(Self {
            channel_id,
            epoch,
            issuer_id,
            target_id,
            removal_entry_hashes: hashes,
            signature,
        })
    }

    /// Verify the signer binding and signature.
    pub fn verify(&self, key: &crate::identity::composite::CompositePublicKey) -> Result<()> {
        check_removals(&self.removal_entry_hashes)?;
        verify_member(
            key,
            &self.issuer_id,
            crate::wire::StructTag::MemberReadmission,
            &member_body(
                &self.channel_id,
                self.epoch,
                &self.issuer_id,
                &self.target_id,
                Some(&self.removal_entry_hashes),
            ),
            &self.signature,
        )
    }
}

fn check_removals(hashes: &[Digest32]) -> Result<()> {
    if hashes.is_empty() || hashes.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(crate::error::Error::MalformedGovernance(
            "readmission removal hashes",
        ));
    }
    Ok(())
}

fn member_fields(
    e: &mut crate::cbor::Encoder,
    channel: &Digest32,
    epoch: u64,
    issuer: &Digest32,
    target: &Digest32,
    hashes: Option<&[Digest32]>,
) {
    e.bytes(channel).uint(epoch).bytes(issuer).bytes(target);
    if let Some(hashes) = hashes {
        e.array(hashes.len());
        for hash in hashes {
            e.bytes(hash);
        }
    }
}

fn member_body(
    channel: &Digest32,
    epoch: u64,
    issuer: &Digest32,
    target: &Digest32,
    hashes: Option<&[Digest32]>,
) -> Vec<u8> {
    let mut e = crate::cbor::Encoder::new();
    e.array(if hashes.is_some() { 5 } else { 4 });
    member_fields(&mut e, channel, epoch, issuer, target, hashes);
    e.finish()
}

fn member_wire(
    tag: crate::wire::StructTag,
    channel: &Digest32,
    epoch: u64,
    issuer: &Digest32,
    target: &Digest32,
    hashes: Option<&[Digest32]>,
    signature: &crate::identity::composite::CompositeSignature,
) -> Vec<u8> {
    let mut e = crate::cbor::Encoder::new();
    e.array(if hashes.is_some() { 6 } else { 5 });
    member_fields(&mut e, channel, epoch, issuer, target, hashes);
    e.bytes(&signature.to_bytes());
    crate::wire::frame(tag, &e.finish())
}

fn parse_member(
    bytes: &[u8],
    tag: crate::wire::StructTag,
) -> Result<(
    Digest32,
    u64,
    Digest32,
    Digest32,
    Vec<Digest32>,
    crate::identity::composite::CompositeSignature,
)> {
    let frame = crate::wire::parse_frame(bytes)?;
    if frame.tag != tag {
        return Err(crate::error::Error::MalformedGovernance("member fact tag"));
    }
    let mut d = crate::cbor::Decoder::new(frame.body);
    let readmission = tag == crate::wire::StructTag::MemberReadmission;
    if d.array()? != if readmission { 6 } else { 5 } {
        return Err(crate::error::Error::MalformedGovernance(
            "member fact arity",
        ));
    }
    fn digest(d: &mut crate::cbor::Decoder<'_>) -> Result<Digest32> {
        d.bytes()?
            .try_into()
            .map_err(|_| crate::error::Error::MalformedGovernance("member fact digest length"))
    }
    let channel = digest(&mut d)?;
    let epoch = d.uint()?;
    let issuer = digest(&mut d)?;
    let target = digest(&mut d)?;
    let mut hashes = Vec::new();
    if readmission {
        let count = d.array()?;
        for _ in 0..count {
            hashes.push(digest(&mut d)?);
        }
        check_removals(&hashes)?;
    }
    let signature: [u8; crate::hash::COMPOSITE_SIG_LEN] = d
        .bytes()?
        .try_into()
        .map_err(|_| crate::error::Error::MalformedGovernance("member fact signature length"))?;
    d.finish()?;
    Ok((
        channel,
        epoch,
        issuer,
        target,
        hashes,
        crate::identity::composite::CompositeSignature::from_bytes(&signature)?,
    ))
}

fn verify_member(
    key: &crate::identity::composite::CompositePublicKey,
    issuer: &Digest32,
    tag: crate::wire::StructTag,
    body: &[u8],
    signature: &crate::identity::composite::CompositeSignature,
) -> Result<()> {
    if key.fingerprint() != *issuer {
        return Err(crate::error::Error::MalformedGovernance(
            "member fact issuer",
        ));
    }
    key.verify(&crate::wire::signing_input(tag, body), signature)
}
