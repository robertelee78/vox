//! Work assignment as **claims**, resolved by the log with no coordinator
//! (ADR-020 §5).
//!
//! Borrowed from ruflo's agentbbs, which reached the same shape: "assignment of
//! work" is literally a claim on a resource, and a converging authenticated log
//! already has everything needed to settle one — a total order and a
//! deterministic tie-break key.
//!
//! ## The property that matters
//!
//! Every node **must** reach the same owner, having possibly received the claims
//! in a different order. That is achieved the only way it reliably can be: the
//! ops are sorted into a canonical order before they are folded, so the answer is
//! a function of the *set* of ops, not of arrival order.
//!
//! The sort key is `(created_secs, entry_hash)` — the author's recorded time, and
//! then the entry hash as the tie-break. Never wall-clock-at-receipt and never
//! arrival order, because those differ per node and would make two agents
//! disagree about who owns a task while both believe they converged.
//!
//! A dishonest `created_secs` can win a race it should have lost. That is
//! accepted, and it is the same trade the ADR-007 evaluator makes for concurrent
//! governance: the alternative is a clock nobody has. The claim system schedules
//! cooperating agents; it is not a defence against one that lies.
//!
//! ## A claim is a message, not a lock
//!
//! Nothing here reserves anything. There is no lock table, no lease server and
//! nothing to hold. Posting a claim is posting a message; **ownership is whatever
//! [`resolve`] computes from the room's log**, and an agent that has not caught up
//! computes it from a smaller set.
//!
//! That is what makes a stale view harmless rather than dangerous. An agent behind
//! on the log can post a claim that loses — and because `resolve` is a pure
//! function of the set of ops, it *will* lose on every node once the sets converge,
//! including its own. Two agents can be **behind**; they cannot permanently
//! **disagree**.
//!
//! So the guarantee this offers is not "everyone has the latest message", which no
//! peer-to-peer system can promise. It is:
//!
//! - **convergence** — same set of ops, same owner, on every node, in any order;
//! - **detectability** — a claimant can read the board back and see whether it won,
//!   which is why `vox room claim` re-reads after posting and exits non-zero when
//!   somebody else holds the resource. An agent is *told* it lost rather than
//!   quietly starting work someone else is already doing;
//! - **self-healing** — a claim with `ttl_secs` lapses on its own, so an agent that
//!   is partitioned, wedged or dead stops holding work with nobody intervening and
//!   nobody noticing it went. That is the answer to "what if a participant never
//!   comes back", and it is the only honest one.
//!
//! ## What this deliberately does not promise
//!
//! **Causality within one second.** `created_secs` has one-second resolution, so a
//! losing claim and the release that follows it can carry the same timestamp, and
//! the entry-hash tie-break then decides their order. Every node computes the same
//! answer — that is exactly what the tie-break is for — but the answer need not
//! match the order things happened in. The observable consequence: an agent
//! correctly told "you did not get it" may hold the resource once the current owner
//! releases it. Neither statement was false. A `release` therefore guarantees that
//! **the releaser no longer holds the resource**, not that the resource is unowned.
//!
//! **A global "latest".** There is no global clock and no coordinator, so "the most
//! recent message" is not a thing any node can know it has. Nothing here depends on
//! one.

use std::collections::BTreeMap;

use crate::envelope::Envelope;

/// Reserved type: take ownership of a resource.
pub const CLAIM: &str = "claim";
/// Reserved type: give it up.
pub const RELEASE: &str = "release";
/// Reserved type: pass it to someone else.
pub const HANDOFF: &str = "handoff";

/// A message as the log holds it: the envelope plus the three facts the log
/// supplies and the envelope therefore does not carry.
#[derive(Debug, Clone, PartialEq)]
pub struct Posted {
    /// ADR-008 entry hash — the message id, and the tie-break key.
    pub entry_hash: [u8; 32],
    /// The signed author's fingerprint.
    pub author: [u8; 32],
    /// The author's recorded send time.
    pub created_secs: u64,
    /// The message.
    pub envelope: Envelope,
}

/// A claim operation, read out of a [`Posted`] message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOp {
    /// Take `resource`, optionally for a bounded time.
    Claim {
        /// What is being claimed.
        resource: String,
        /// Seconds after which the claim lapses on its own, if any.
        ttl_secs: Option<u64>,
    },
    /// Give up `resource`.
    Release {
        /// What is being released.
        resource: String,
    },
    /// Pass `resource` to the identity named by `to`.
    Handoff {
        /// What is being handed off.
        resource: String,
        /// The petname of the recipient, as the sender knows it.
        to: String,
    },
}

impl ClaimOp {
    /// The resource this operates on.
    #[must_use]
    pub fn resource(&self) -> &str {
        match self {
            ClaimOp::Claim { resource, .. }
            | ClaimOp::Release { resource }
            | ClaimOp::Handoff { resource, .. } => resource,
        }
    }

    /// Read a claim operation out of a message, or `None` if it is not one.
    #[must_use]
    pub fn from_envelope(env: &Envelope) -> Option<Self> {
        let resource = env.data.get("resource")?.as_str()?.to_owned();
        if resource.is_empty() {
            return None;
        }
        match env.kind.as_str() {
            CLAIM => Some(ClaimOp::Claim {
                resource,
                ttl_secs: env.data.get("ttl_secs").and_then(serde_json::Value::as_u64),
            }),
            RELEASE => Some(ClaimOp::Release { resource }),
            HANDOFF => {
                let to = env.data.get("to")?.as_str()?.to_owned();
                if to.is_empty() {
                    return None;
                }
                Some(ClaimOp::Handoff { resource, to })
            }
            _ => None,
        }
    }
}

/// Who holds a resource, and since when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ownership {
    /// The owning identity's fingerprint.
    pub owner: [u8; 32],
    /// When the owning claim was made.
    pub since_secs: u64,
    /// When it lapses on its own, if it does.
    pub expires_secs: Option<u64>,
    /// The petname the *claimant* used for the owner, when ownership arrived by
    /// handoff. Advisory: the fingerprint is the identity.
    pub named: Option<String>,
}

/// Resolve ownership of every claimed resource, as of `now_secs`.
///
/// Deterministic in the set of messages: the same set in any order yields the
/// same map. Rules, applied in the canonical order described in the module docs:
///
/// 1. one owner per resource;
/// 2. the first valid `claim` wins — a claim on a resource that is already owned
///    and unexpired is ignored, so an owner cannot be displaced by a latecomer;
/// 3. a `release` frees it, and only from the current owner;
/// 4. an expired `ttl_secs` frees it without anybody saying so;
/// 5. a `handoff` is valid **only** from the current owner.
///
/// A handoff names its recipient by petname, which is local to the sender. The
/// fingerprint cannot be derived here, so the transfer is recorded with the
/// sender's name for it and `resolve_with` is the form that takes a resolver.
#[must_use]
pub fn resolve(messages: &[Posted], now_secs: u64) -> BTreeMap<String, Ownership> {
    resolve_with(messages, now_secs, |_| None)
}

/// [`resolve`], with a resolver from petname to fingerprint so `handoff` can
/// transfer ownership rather than merely record an intent.
#[must_use]
pub fn resolve_with(
    messages: &[Posted],
    now_secs: u64,
    name_to_fingerprint: impl Fn(&str) -> Option<[u8; 32]>,
) -> BTreeMap<String, Ownership> {
    // Canonical order first — this is what makes the result independent of the
    // order these messages happened to arrive in.
    let mut ops: Vec<(&Posted, ClaimOp)> = messages
        .iter()
        .filter_map(|m| ClaimOp::from_envelope(&m.envelope).map(|op| (m, op)))
        .collect();
    ops.sort_by(|(a, _), (b, _)| {
        a.created_secs
            .cmp(&b.created_secs)
            .then_with(|| a.entry_hash.cmp(&b.entry_hash))
    });

    let mut owned: BTreeMap<String, Ownership> = BTreeMap::new();
    for (posted, op) in ops {
        // An expired claim frees the resource before this op is considered, so a
        // later claim succeeds exactly as if a release had been posted.
        if let Some(cur) = owned.get(op.resource()) {
            if cur.expires_secs.is_some_and(|e| e <= posted.created_secs) {
                owned.remove(op.resource());
            }
        }
        match op {
            ClaimOp::Claim { resource, ttl_secs } => {
                if owned.contains_key(&resource) {
                    continue; // first valid claim wins
                }
                owned.insert(
                    resource,
                    Ownership {
                        owner: posted.author,
                        since_secs: posted.created_secs,
                        expires_secs: ttl_secs.map(|t| posted.created_secs.saturating_add(t)),
                        named: None,
                    },
                );
            }
            ClaimOp::Release { resource } => {
                if owned
                    .get(&resource)
                    .is_some_and(|o| o.owner == posted.author)
                {
                    owned.remove(&resource);
                }
            }
            ClaimOp::Handoff { resource, to } => {
                let Some(cur) = owned.get(&resource) else {
                    continue; // nobody owns it; a handoff is not a claim
                };
                if cur.owner != posted.author {
                    continue; // only the current owner may hand off
                }
                // When the recipient's name cannot be resolved here, ownership is
                // left exactly as it was: recording the sender as owner would be a
                // lie, and dropping the resource would let an unresolvable name
                // silently free it.
                if let Some(new_owner) = name_to_fingerprint(&to) {
                    owned.insert(
                        resource,
                        Ownership {
                            owner: new_owner,
                            since_secs: posted.created_secs,
                            expires_secs: None,
                            named: Some(to),
                        },
                    );
                }
            }
        }
    }

    // Finally drop anything that has lapsed by `now_secs` — a resource whose
    // holder went away without releasing it.
    owned.retain(|_, o| o.expires_secs.is_none_or(|e| e > now_secs));
    owned
}
