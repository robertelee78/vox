//! Inbound visibility opt-out — the receiver-side "whom do I read?" control
//! (ADR-007 §"Revocation and epochs", §"Visibility opt-out").
//!
//! This is **purely local to one member `A`** and answers a *different* question
//! from outbound consent ([`crate::governance::consent`]):
//!
//! | control                          | question            | log entry? | affects others? | reversible? |
//! |----------------------------------|---------------------|------------|-----------------|-------------|
//! | outbound consent (grant/revoke)  | "who may read **me**?" | **yes** (signed) | yes | rotation-bounded |
//! | inbound visibility opt-out (here)| "whom do **I** read?"  | **no**     | **no**          | **yes**, freely |
//!
//! `A` chooses to stop *seeing* a sender `B` by dropping `B`'s sender key from
//! `A`'s active set and not rendering `B`. It needs no cooperation from `B`,
//! creates **no governance entry** (it affects only `A`'s own view), and is
//! reversible while `B` still consents to `A`. The two functions are orthogonal
//! and set independently per member.
//!
//! Because it is not a log fact, this is modeled as **local mutable state**, not a
//! signed struct: a [`VisibilitySet`] is the set of senders `A` has muted. It is
//! the render-side counterpart to the M5 render-gate ([`crate::log::dag::Dag::render`]):
//! even if `A` *holds* `B`'s key, a muted `B` is not rendered.

use std::collections::BTreeSet;

use crate::hash::Digest32;

/// The set of senders one member has chosen **not to see** (inbound opt-out).
///
/// Local, in-memory, reversible state — never serialized to the log. Deterministic
/// iteration (a [`BTreeSet`]) so any UI/diagnostic over it is stable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VisibilitySet {
    muted: BTreeSet<Digest32>,
}

impl VisibilitySet {
    /// An empty opt-out set — every consented sender is visible.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stop seeing `sender` (idempotent). Returns whether this newly muted them.
    /// Creates **no** log entry and affects no other member.
    pub fn mute(&mut self, sender: Digest32) -> bool {
        self.muted.insert(sender)
    }

    /// Resume seeing `sender` (idempotent). Returns whether they were muted.
    /// Reversible at will, with no log entry, while the sender still consents.
    pub fn unmute(&mut self, sender: &Digest32) -> bool {
        self.muted.remove(sender)
    }

    /// Whether `A` is currently *not* rendering `sender`.
    #[must_use]
    pub fn is_muted(&self, sender: &Digest32) -> bool {
        self.muted.contains(sender)
    }

    /// Whether `A` would *render* `sender` on the inbound axis. This composes with
    /// outbound consent at the render site: a sender is shown only if they have
    /// consent-granted to `A` (outbound, the log) **and** `A` has not muted them
    /// (inbound, here).
    #[must_use]
    pub fn is_visible(&self, sender: &Digest32) -> bool {
        !self.is_muted(sender)
    }

    /// The muted senders, in deterministic order.
    pub fn muted(&self) -> impl Iterator<Item = &Digest32> {
        self.muted.iter()
    }

    /// How many senders are muted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.muted.len()
    }

    /// Whether nothing is muted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.muted.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: Digest32 = [0xBB; 32];
    const C: Digest32 = [0xCC; 32];

    #[test]
    fn mute_unmute_is_local_and_reversible() {
        let mut v = VisibilitySet::new();
        assert!(v.is_visible(&B));
        assert!(v.mute(B));
        assert!(!v.mute(B)); // idempotent
        assert!(v.is_muted(&B));
        assert!(!v.is_visible(&B));
        // Reversible at will.
        assert!(v.unmute(&B));
        assert!(!v.unmute(&B));
        assert!(v.is_visible(&B));
    }

    #[test]
    fn muting_one_does_not_affect_another() {
        let mut v = VisibilitySet::new();
        v.mute(B);
        assert!(v.is_muted(&B));
        assert!(v.is_visible(&C)); // C unaffected
        assert_eq!(v.len(), 1);
    }
}
