//! Work coordination as **claims**, resolved by the log with no coordinator
//! (ADR-020 §5, as corrected by ADR-021 §4–§6).
//!
//! Borrowed from ruflo's agentbbs, which reached the same shape: "assignment of
//! work" is literally a claim on a resource, and a converging authenticated log
//! already has everything needed to settle one — a total order and a
//! deterministic tie-break key.
//!
//! ## The property that matters
//!
//! Every node on one Vox version **must** reach the same state, having possibly
//! received the operations in a different order. That is achieved the only way it
//! reliably can be: the operations are sorted into a canonical order before they are
//! folded, so the answer is a function of the *set* of operations, not of arrival
//! order.
//!
//! The sort key is `(created_millis, entry_hash)` — the author's recorded time, and
//! then the entry hash as the tie-break. Never wall-clock-at-receipt and never
//! arrival order, because those differ per node and would make two agents disagree
//! about who owns a task while both believe they converged.
//!
//! A dishonest `created_millis` can win a race it should have lost. That is
//! accepted, and it is the same trade the ADR-007 evaluator makes for concurrent
//! governance: the alternative is a clock nobody has. The claim system schedules
//! cooperating agents; it is not a defence against one that lies.
//!
//! ## A claim is a message, not a lock
//!
//! Nothing here reserves anything. Posting a claim is posting a message; **the
//! state is whatever [`fold`] computes from the room's log**, and an agent that has
//! not caught up computes it from a smaller set. Two agents can be **behind**; they
//! cannot permanently **disagree** — provided they run the same version, which is
//! why an operation stamped with any other version changes nothing here (ADR-021
//! §5) rather than being folded under rules its author did not use.
//!
//! ## The protocol (ADR-021 §4)
//!
//! - The owner is `(author fingerprint, session)`, never the harness key alone:
//!   two sessions on one harness are two owners.
//! - A resource is [`State::Held`], [`State::Pending`] a handoff, or absent (free).
//! - `handoff` reserves the resource for a recipient **fingerprint**, and optionally
//!   one exact session, until a deadline of the handoff's own. An eligible recipient
//!   completes it by claiming; an eligible `decline` frees it; the deadline frees it.
//! - `renew` names the acquisition it extends, so a late renewal can neither revive
//!   an expired claim nor extend a later, unrelated one.
//!
//! ## What this deliberately does not promise
//!
//! **Causality between authors.** Two agents' entries have no causal edge in the log
//! (ADR-008 gives no cross-author parent). Millisecond timestamps make ties rare, but
//! a tie is still decided by entry hash, and an author's clock is only its claim
//! about when it acted. So a `release` guarantees that **the releaser no longer
//! holds the resource**, not that the resource is unowned.

use std::collections::BTreeMap;

use crate::envelope::{work, Envelope};
use crate::ops::{self, OpIndex, Verdict};
use crate::version::{self, Stamp};

/// Take ownership of a resource, or complete a pending handoff.
pub const CLAIM: &str = "claim";
/// Give it up.
pub const RELEASE: &str = "release";
/// Relinquish it and reserve it for a named recipient.
pub const HANDOFF: &str = "handoff";
/// Extend the holder's current acquisition.
pub const RENEW: &str = "renew";

/// A pending handoff's deadline when the sender names none, stamped explicitly by the
/// CLI so the fold never has to assume one. One hour: long enough to wake a session,
/// short enough that an abandoned handoff does not strand the work for a day.
pub const DEFAULT_HANDOFF_TTL_SECS: u64 = 3600;

/// A message as the log holds it: the envelope plus the three facts the log
/// supplies and the envelope therefore does not carry.
#[derive(Debug, Clone, PartialEq)]
pub struct Posted {
    /// The entry hash — the message id, and the tie-break.
    pub entry_hash: [u8; 32],
    /// The signed author's fingerprint.
    pub author: [u8; 32],
    /// The author's recorded send time, **milliseconds** since the Unix epoch.
    ///
    /// Milliseconds because this is half the sort key, and whole seconds put two agents
    /// racing for one resource in the same bucket — where the entry-hash tie-break
    /// decided the winner instead of who asked first.
    pub created_millis: u64,
    /// The message.
    pub envelope: Envelope,
}

impl Posted {
    /// The send time in whole seconds, for display.
    #[must_use]
    pub const fn created_secs(&self) -> u64 {
        self.created_millis / 1_000
    }
}

/// Who holds something: a harness key and one session under it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Owner {
    /// The harness identity's fingerprint — proven by the log's signature.
    pub author: [u8; 32],
    /// The session under it — claimed, per ADR-020 §2.
    pub session: String,
}

/// A claim-protocol operation, read out of a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOp {
    /// Take `resource`, or complete a handoff pending for the claimant.
    Claim {
        /// What is being claimed.
        resource: String,
        /// Seconds after which the holding lapses on its own, if any.
        ttl_secs: Option<u64>,
    },
    /// Give up `resource`.
    Release {
        /// What is being released.
        resource: String,
    },
    /// Relinquish `resource` and reserve it for `to_fp`.
    Handoff {
        /// What is being handed off.
        resource: String,
        /// The recipient harness's fingerprint.
        to_fp: [u8; 32],
        /// One exact session of it, if the sender named one.
        to_session: Option<String>,
        /// Seconds until the pending handoff lapses. Required.
        ttl_secs: u64,
    },
    /// Refuse a handoff pending for the decliner, which frees the resource.
    Decline {
        /// The resource whose handoff is declined.
        resource: String,
    },
    /// Extend one acquisition.
    Renew {
        /// What is being renewed.
        resource: String,
        /// The entry hash of the claim that created the holding being extended.
        acquisition: [u8; 32],
    },
}

impl ClaimOp {
    /// The resource this operates on.
    #[must_use]
    pub fn resource(&self) -> &str {
        match self {
            ClaimOp::Claim { resource, .. }
            | ClaimOp::Release { resource }
            | ClaimOp::Handoff { resource, .. }
            | ClaimOp::Decline { resource }
            | ClaimOp::Renew { resource, .. } => resource,
        }
    }
}

/// Whether a message belongs to the claim protocol at all.
///
/// `decline` is two things in the vocabulary: with `data.resource` it refuses a
/// pending handoff (ownership); without it, it refuses an `assign` (a request), which
/// is conversation and not this protocol's business.
#[must_use]
pub fn is_claim_protocol(env: &Envelope) -> bool {
    match env.kind.as_str() {
        CLAIM | RELEASE | HANDOFF | RENEW => true,
        k if k == work::DECLINE => env.data.get("resource").is_some(),
        _ => false,
    }
}

/// Read a claim-protocol message, or say exactly why it is not a valid operation.
///
/// Every operation MUST carry a resource, a session (`from`), an operation id and a
/// version stamp (ADR-021 §4). The stamp is checked here only for presence; whether
/// it *matches* is the fold's question, answered against the folding worker's own
/// version.
///
/// # Errors
///
/// A reason, for a person, naming the missing or unusable field.
pub fn parse_op(env: &Envelope) -> Result<ClaimOp, String> {
    let resource = env
        .data
        .get("resource")
        .and_then(serde_json::Value::as_str)
        .filter(|r| !r.is_empty())
        .ok_or("no data.resource")?
        .to_owned();
    if env.from.is_empty() {
        return Err("no session (`from` is empty)".into());
    }
    match ops::op_of(env) {
        Some(op) if ops::is_valid_op(op) => {}
        Some(_) => return Err("data.op is not [A-Za-z0-9._-]{8,64}".into()),
        None => return Err("no data.op".into()),
    }
    let ttl = |key: &str| env.data.get(key).and_then(serde_json::Value::as_u64);
    match env.kind.as_str() {
        CLAIM => Ok(ClaimOp::Claim {
            resource,
            ttl_secs: ttl("ttl_secs"),
        }),
        RELEASE => Ok(ClaimOp::Release { resource }),
        HANDOFF => {
            let to_fp = env
                .data
                .get("to_fp")
                .and_then(serde_json::Value::as_str)
                .and_then(from_b32)
                .ok_or("a handoff needs data.to_fp, a full base32 fingerprint")?;
            let to_session = env
                .data
                .get("to_session")
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            let ttl_secs = ttl("ttl_secs")
                .filter(|t| *t > 0)
                .ok_or("a handoff needs data.ttl_secs, so it has a finite deadline")?;
            Ok(ClaimOp::Handoff {
                resource,
                to_fp,
                to_session,
                ttl_secs,
            })
        }
        k if k == work::DECLINE => Ok(ClaimOp::Decline { resource }),
        RENEW => {
            let acquisition = env
                .data
                .get("acquisition")
                .and_then(serde_json::Value::as_str)
                .and_then(from_b32)
                .ok_or("a renew needs data.acquisition, the entry hash of the claim it extends")?;
            Ok(ClaimOp::Renew {
                resource,
                acquisition,
            })
        }
        _ => Err("not a claim-protocol type".into()),
    }
}

/// The state of one resource that is not free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Owned by one session.
    Held {
        /// Who holds it.
        owner: Owner,
        /// The entry hash of the claim that created this holding. A renewal must name
        /// it.
        acquisition: [u8; 32],
        /// When the holding began.
        since_millis: u64,
        /// The acquiring claim's TTL, which every renewal reuses.
        ttl_secs: Option<u64>,
        /// When it lapses on its own, if it does.
        expires_millis: Option<u64>,
    },
    /// Relinquished by `from` and reserved for a recipient until `deadline_millis`.
    Pending {
        /// Who handed it off. It no longer holds anything.
        from: Owner,
        /// The recipient harness.
        to_fp: [u8; 32],
        /// One exact session of it, or any session of it when `None`.
        to_session: Option<String>,
        /// The petname the sender used, for display only.
        to_name: Option<String>,
        /// The handoff's entry hash.
        handoff: [u8; 32],
        /// When the handoff was made.
        since_millis: u64,
        /// When the reservation lapses and the resource is free.
        deadline_millis: u64,
    },
}

impl State {
    /// Whether `who` may complete or decline this handoff.
    #[must_use]
    pub fn is_eligible(&self, who: &Owner) -> bool {
        match self {
            State::Pending {
                to_fp, to_session, ..
            } => *to_fp == who.author && to_session.as_ref().is_none_or(|s| *s == who.session),
            State::Held { .. } => false,
        }
    }

    /// When this state lapses on its own, if it does.
    #[must_use]
    pub fn lapses_at(&self) -> Option<u64> {
        match self {
            State::Held { expires_millis, .. } => *expires_millis,
            State::Pending {
                deadline_millis, ..
            } => Some(*deadline_millis),
        }
    }
}

/// What one claim-protocol message did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// It changed the state as asked.
    Applied,
    /// A claim that found the resource held, or reserved for someone else.
    Lost,
    /// Well-formed and of this version, but it had no effect — for the reason given.
    NoEffect(&'static str),
    /// Not a valid operation: a field is missing or unusable.
    Invalid(String),
    /// Stamped with another version, or with none: ignored by this fold (ADR-021 §5).
    OtherVersion(Stamp),
    /// A repeat of an operation already applied, with the same content.
    Duplicate {
        /// The entry that is the operation.
        of: [u8; 32],
    },
    /// Part of an operation id whose entries disagree. No entry in the group has any
    /// effect.
    Conflict {
        /// Every entry in the group, in canonical order.
        group: Vec<[u8; 32]>,
    },
}

/// Every resource's state, and what every claim-protocol message did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fold {
    /// Resources that are held or pending. A free resource is absent.
    pub resources: BTreeMap<String, State>,
    /// What each claim-protocol entry did, by entry hash.
    pub outcomes: BTreeMap<[u8; 32], Outcome>,
}

/// Fold a room's claim-protocol messages into one state per resource, as of
/// `now_millis`, under the rules of version `mine`.
///
/// Deterministic in the set of messages: the same set in any order yields the same
/// [`Fold`]. Non-claim messages are ignored.
#[must_use]
pub fn fold(messages: &[Posted], mine: &str, now_millis: u64) -> Fold {
    let mut out = Fold::default();

    let mut ours: Vec<&Posted> = Vec::new();
    let mut index = OpIndex::new();
    for m in messages.iter().filter(|m| is_claim_protocol(&m.envelope)) {
        match version::stamp_of(&m.envelope, mine) {
            Stamp::Match => {
                index.insert(m.entry_hash, m.author, m.created_millis, &m.envelope);
                ours.push(m);
            }
            other => {
                out.outcomes
                    .insert(m.entry_hash, Outcome::OtherVersion(other));
            }
        }
    }
    ours.sort_by(|a, b| {
        a.created_millis
            .cmp(&b.created_millis)
            .then_with(|| a.entry_hash.cmp(&b.entry_hash))
    });

    for posted in ours {
        let op = match parse_op(&posted.envelope) {
            Ok(op) => op,
            Err(why) => {
                out.outcomes
                    .insert(posted.entry_hash, Outcome::Invalid(why));
                continue;
            }
        };
        match index.verdict(posted.author, &posted.envelope, posted.entry_hash) {
            Some(Verdict::Effective) | None => {}
            Some(Verdict::Duplicate { of }) => {
                out.outcomes
                    .insert(posted.entry_hash, Outcome::Duplicate { of });
                continue;
            }
            Some(Verdict::Conflict { group }) => {
                out.outcomes
                    .insert(posted.entry_hash, Outcome::Conflict { group });
                continue;
            }
        }
        lapse(&mut out.resources, op.resource(), posted.created_millis);
        let outcome = apply(&mut out.resources, posted, op);
        out.outcomes.insert(posted.entry_hash, outcome);
    }

    let keys: Vec<String> = out.resources.keys().cloned().collect();
    for k in keys {
        lapse(&mut out.resources, &k, now_millis);
    }
    out
}

/// Free `resource` if its holding or reservation has lapsed by `at_millis`.
fn lapse(resources: &mut BTreeMap<String, State>, resource: &str, at_millis: u64) {
    if resources
        .get(resource)
        .and_then(State::lapses_at)
        .is_some_and(|t| t <= at_millis)
    {
        resources.remove(resource);
    }
}

fn apply(resources: &mut BTreeMap<String, State>, posted: &Posted, op: ClaimOp) -> Outcome {
    let who = Owner {
        author: posted.author,
        session: posted.envelope.from.clone(),
    };
    let at = posted.created_millis;
    let held_by_who =
        |s: Option<&State>| matches!(s, Some(State::Held { owner, .. }) if *owner == who);
    match op {
        ClaimOp::Claim { resource, ttl_secs } => {
            let take = match resources.get(&resource) {
                None => true,
                Some(s @ State::Pending { .. }) => s.is_eligible(&who),
                Some(State::Held { .. }) => false,
            };
            if !take {
                return Outcome::Lost;
            }
            resources.insert(
                resource,
                State::Held {
                    owner: who,
                    acquisition: posted.entry_hash,
                    since_millis: at,
                    ttl_secs,
                    expires_millis: ttl_secs.map(|t| at.saturating_add(t.saturating_mul(1_000))),
                },
            );
            Outcome::Applied
        }
        ClaimOp::Release { resource } => {
            if !held_by_who(resources.get(&resource)) {
                return Outcome::NoEffect("the releaser does not hold it");
            }
            resources.remove(&resource);
            Outcome::Applied
        }
        ClaimOp::Handoff {
            resource,
            to_fp,
            to_session,
            ttl_secs,
        } => {
            if !held_by_who(resources.get(&resource)) {
                return Outcome::NoEffect("only the exact holder may hand off");
            }
            let to_name = posted
                .envelope
                .data
                .get("to")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned);
            resources.insert(
                resource,
                State::Pending {
                    from: who,
                    to_fp,
                    to_session,
                    to_name,
                    handoff: posted.entry_hash,
                    since_millis: at,
                    // Replaced, not inherited: a nearly lapsed holding would give the
                    // recipient no time, and one with no TTL would give it none to inherit.
                    deadline_millis: at.saturating_add(ttl_secs.saturating_mul(1_000)),
                },
            );
            Outcome::Applied
        }
        ClaimOp::Decline { resource } => {
            match resources.get(&resource) {
                Some(s @ State::Pending { .. }) if s.is_eligible(&who) => {}
                Some(State::Pending { .. }) => {
                    return Outcome::NoEffect("the decliner is not an eligible recipient")
                }
                _ => return Outcome::NoEffect("no handoff is pending"),
            }
            // Freed — **not** returned to the sender, who may claim it again like anyone.
            resources.remove(&resource);
            Outcome::Applied
        }
        ClaimOp::Renew {
            resource,
            acquisition,
        } => renew(resources, &resource, &who, acquisition, at),
    }
}

/// Rule 5: extend exactly one acquisition, for exactly its session, if it has a TTL.
fn renew(
    resources: &mut BTreeMap<String, State>,
    resource: &str,
    who: &Owner,
    acquisition: [u8; 32],
    at: u64,
) -> Outcome {
    match resources.get_mut(resource) {
        Some(State::Held {
            owner,
            acquisition: current,
            ttl_secs: Some(ttl),
            expires_millis,
            ..
        }) if owner == who && *current == acquisition => {
            *expires_millis = Some(at.saturating_add(ttl.saturating_mul(1_000)));
            Outcome::Applied
        }
        Some(State::Held {
            owner,
            acquisition: current,
            ttl_secs: None,
            ..
        }) if owner == who && *current == acquisition => {
            Outcome::NoEffect("the holding has no TTL to extend")
        }
        _ => Outcome::NoEffect("stale renewal: not the current acquisition of this session"),
    }
}

/// The base32 alphabet Vox renders every id in (RFC 4648, lowercased, unpadded).
const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Render a 32-byte id as Vox renders fingerprints and entry hashes: 52 lowercase
/// base32 characters.
///
/// Duplicated from `vox-core`'s `link::b32_encode` on purpose: this crate does not
/// depend on the core (ADR-020 §1), and an id on the wire is text anyway.
#[must_use]
pub fn b32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(52);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32[((acc >> bits) & 0x1F) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(B32[((acc << (5 - bits)) & 0x1F) as usize]));
    }
    out
}

/// Parse a full 52-character base32 id, case-insensitively. `None` for anything else,
/// including a prefix: an id in a message is copied, never abbreviated.
#[must_use]
pub fn from_b32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 52 {
        return None;
    }
    let mut out = [0u8; 32];
    let (mut acc, mut bits, mut n) = (0u32, 0u32, 0usize);
    for c in text.bytes() {
        let lower = c.to_ascii_lowercase();
        let val = u32::try_from(B32.iter().position(|a| *a == lower)?).ok()?;
        acc = (acc << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if n == 32 {
                return None;
            }
            out[n] = u8::try_from((acc >> bits) & 0xFF).ok()?;
            n += 1;
        }
    }
    // Canonical encoding only: the trailing bits must be zero, so one id has one
    // spelling and two nodes cannot disagree about whether they name the same member.
    if n != 32 || (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}
