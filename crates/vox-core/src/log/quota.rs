//! Per-author abuse-resistance quotas (ADR-008 §"Abuse resistance (quantified)").
//!
//! Replication is bounded by **per-author quotas each peer enforces locally**.
//! The channel-policy-tunable defaults are **≤ 1000 entries/hour** and **≤ 50 MB
//! per epoch** per author. Over-quota entries from an author are **dropped (not
//! relayed)** and the event is surfaced as an abuse signal. This bounds the
//! render-gating amplification vector: because every ciphertext replicates to all
//! members, the per-author byte cap is what makes a joined author's storage cost
//! finite.
//!
//! The rate limit is a sliding-window count over the last hour; the byte limit is
//! a running total per `(author, epoch)` that resets when the epoch advances
//! (passphrase rotation, ADR-007). Time is supplied by the caller (monotonic
//! seconds) so the quota logic is deterministic and testable — there is no
//! ambient clock.

use std::collections::{HashMap, VecDeque};

use crate::hash::Digest32;

/// Default per-author entry-rate cap: 1000 entries per rolling hour (ADR-008).
pub const DEFAULT_MAX_ENTRIES_PER_HOUR: u32 = 1000;
/// Default per-author byte cap per epoch: 50 MiB (ADR-008).
pub const DEFAULT_MAX_BYTES_PER_EPOCH: u64 = 50 * 1024 * 1024;
/// The rolling-window span for the entry-rate cap, in seconds (one hour).
pub const RATE_WINDOW_SECS: u64 = 3600;

/// The channel-policy-tunable quota limits (ADR-008). Defaults via
/// [`QuotaPolicy::default`]; a channel policy (ADR-007) may raise/lower them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaPolicy {
    /// Maximum entries accepted from one author per rolling hour.
    pub max_entries_per_hour: u32,
    /// Maximum payload bytes accepted from one author per epoch.
    pub max_bytes_per_epoch: u64,
}

impl Default for QuotaPolicy {
    fn default() -> Self {
        Self {
            max_entries_per_hour: DEFAULT_MAX_ENTRIES_PER_HOUR,
            max_bytes_per_epoch: DEFAULT_MAX_BYTES_PER_EPOCH,
        }
    }
}

/// The reason an entry was rejected by the quota gate (surfaced as an abuse
/// signal, ADR-008 — like revocation churn).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum QuotaReject {
    /// The author exceeded the rolling-hour entry-rate cap.
    RateExceeded,
    /// The author exceeded the per-epoch byte cap.
    BytesExceeded,
}

/// Per-author quota accounting for one channel. A peer keeps one of these per
/// channel and consults it before accepting/relaying an entry.
#[derive(Debug, Default)]
pub struct QuotaTracker {
    policy: QuotaPolicy,
    /// author -> recent acceptance timestamps (seconds), oldest at the front.
    rate: HashMap<Digest32, VecDeque<u64>>,
    /// (author, epoch) -> bytes accepted so far this epoch.
    bytes: HashMap<(Digest32, u64), u64>,
}

impl QuotaTracker {
    /// A tracker with the given policy.
    #[must_use]
    pub fn new(policy: QuotaPolicy) -> Self {
        Self {
            policy,
            rate: HashMap::new(),
            bytes: HashMap::new(),
        }
    }

    /// A tracker with the ADR-008 default policy.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(QuotaPolicy::default())
    }

    /// The policy in force.
    #[must_use]
    pub fn policy(&self) -> QuotaPolicy {
        self.policy
    }

    /// Try to admit one entry of `payload_len` bytes authored by `author` in
    /// `epoch` at time `now_secs`. On success the entry is **counted** (rate +
    /// bytes) and `Ok(())` is returned; on failure nothing is counted and the
    /// [`QuotaReject`] reason is returned so the caller drops (does not relay) the
    /// entry and surfaces the abuse signal.
    ///
    /// Both limits are checked before either is mutated, so a rejected entry never
    /// partially consumes quota.
    pub fn admit(
        &mut self,
        author: &Digest32,
        epoch: u64,
        payload_len: u64,
        now_secs: u64,
    ) -> Result<(), QuotaReject> {
        // Rate: prune the window, then check headroom. An earlier timestamp
        // `front` is still in-window iff `now − front < RATE_WINDOW_SECS`; we test
        // that directly (rather than a saturating cutoff) so an entry at time 0
        // is not spuriously evicted when `now < RATE_WINDOW_SECS`.
        let window = self.rate.entry(*author).or_default();
        while let Some(&front) = window.front() {
            if now_secs.saturating_sub(front) >= RATE_WINDOW_SECS {
                window.pop_front();
            } else {
                break;
            }
        }
        if window.len() as u64 >= u64::from(self.policy.max_entries_per_hour) {
            return Err(QuotaReject::RateExceeded);
        }

        // Bytes: check the running per-epoch total has headroom for this entry.
        let used = *self.bytes.get(&(*author, epoch)).unwrap_or(&0);
        let proposed = used.saturating_add(payload_len);
        if proposed > self.policy.max_bytes_per_epoch {
            return Err(QuotaReject::BytesExceeded);
        }

        // Both checks passed: commit the counts.
        window.push_back(now_secs);
        self.bytes.insert((*author, epoch), proposed);
        Ok(())
    }

    /// The bytes counted so far for `(author, epoch)`.
    #[must_use]
    pub fn bytes_used(&self, author: &Digest32, epoch: u64) -> u64 {
        *self.bytes.get(&(*author, epoch)).unwrap_or(&0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn author(b: u8) -> Digest32 {
        [b; 32]
    }

    #[test]
    fn admits_within_limits() {
        let mut q = QuotaTracker::with_defaults();
        let a = author(1);
        for i in 0..10u64 {
            assert!(q.admit(&a, 0, 1000, 100 + i).is_ok());
        }
        assert_eq!(q.bytes_used(&a, 0), 10_000);
    }

    #[test]
    fn rate_cap_drops_over_quota_and_does_not_count() {
        let policy = QuotaPolicy {
            max_entries_per_hour: 3,
            max_bytes_per_epoch: u64::MAX,
        };
        let mut q = QuotaTracker::new(policy);
        let a = author(2);
        // 3 admitted within the same second window.
        assert!(q.admit(&a, 0, 1, 1000).is_ok());
        assert!(q.admit(&a, 0, 1, 1000).is_ok());
        assert!(q.admit(&a, 0, 1, 1000).is_ok());
        // 4th in-window is rejected (rate) and not counted.
        assert_eq!(q.admit(&a, 0, 1, 1000), Err(QuotaReject::RateExceeded));
        assert_eq!(q.bytes_used(&a, 0), 3); // the rejected one did not add bytes
    }

    #[test]
    fn rate_window_slides() {
        let policy = QuotaPolicy {
            max_entries_per_hour: 2,
            max_bytes_per_epoch: u64::MAX,
        };
        let mut q = QuotaTracker::new(policy);
        let a = author(3);
        assert!(q.admit(&a, 0, 1, 0).is_ok());
        assert!(q.admit(&a, 0, 1, 10).is_ok());
        assert_eq!(q.admit(&a, 0, 1, 20), Err(QuotaReject::RateExceeded));
        // After more than an hour passes, the early entries fall out of the window.
        assert!(q.admit(&a, 0, 1, 3700).is_ok());
    }

    #[test]
    fn byte_cap_drops_over_quota() {
        let policy = QuotaPolicy {
            max_entries_per_hour: u32::MAX,
            max_bytes_per_epoch: 100,
        };
        let mut q = QuotaTracker::new(policy);
        let a = author(4);
        assert!(q.admit(&a, 0, 60, 0).is_ok());
        // Next 60 would bring the total to 120 > 100: rejected, not counted.
        assert_eq!(q.admit(&a, 0, 60, 1), Err(QuotaReject::BytesExceeded));
        assert_eq!(q.bytes_used(&a, 0), 60);
        // A smaller entry that fits is admitted.
        assert!(q.admit(&a, 0, 40, 2).is_ok());
        assert_eq!(q.bytes_used(&a, 0), 100);
    }

    #[test]
    fn byte_cap_is_per_epoch() {
        let policy = QuotaPolicy {
            max_entries_per_hour: u32::MAX,
            max_bytes_per_epoch: 100,
        };
        let mut q = QuotaTracker::new(policy);
        let a = author(5);
        assert!(q.admit(&a, 0, 100, 0).is_ok());
        assert_eq!(q.admit(&a, 0, 1, 1), Err(QuotaReject::BytesExceeded));
        // A new epoch resets the byte budget.
        assert!(q.admit(&a, 1, 100, 2).is_ok());
    }

    #[test]
    fn quotas_are_per_author() {
        let policy = QuotaPolicy {
            max_entries_per_hour: 1,
            max_bytes_per_epoch: u64::MAX,
        };
        let mut q = QuotaTracker::new(policy);
        let a = author(6);
        let b = author(7);
        assert!(q.admit(&a, 0, 1, 0).is_ok());
        assert_eq!(q.admit(&a, 0, 1, 0), Err(QuotaReject::RateExceeded));
        // A different author has its own budget.
        assert!(q.admit(&b, 0, 1, 0).is_ok());
    }
}
