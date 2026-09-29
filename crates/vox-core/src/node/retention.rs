//! Retention: how long a room's message bodies are kept (ADR-023 decision 2, PRD-001 R6–R10).
//!
//! Two policies meet here, and **the shorter wins**:
//!
//! - **The room's**, which is the ADR-007 policy-update `ttl` — `0` is forever, anything else is
//!   "disappearing after that many seconds" — set by whoever holds the `policy` capability;
//! - **the node's**, local configuration in the node's config directory ([`RetentionConfig`]),
//!   per room or as a default. A node may keep *less* than its room, never more.
//!
//! Pruning drops a content entry's payload body and its plaintext cache row and keeps the signed
//! skeleton, so the feed's hash chain, sync and fork detection keep working (ADR-008/ADR-010). It
//! is **not** a security property: a modified node can keep everything.
//!
//! An entry's age runs from the author's claimed time, **clamped to no later than when this node
//! first saw it**, so a back-dated message can expire early but a future-dated one cannot outlive
//! the policy. An entry this node cannot read has no claimed time it can see, and ages from when it
//! was first seen.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use crate::hash::Digest32;

/// One hour, one week and one month, in seconds — the durations the product offers by name.
pub const HOUR: u64 = 3_600;
/// One week in seconds.
pub const WEEK: u64 = 7 * 24 * HOUR;
/// One month (thirty days) in seconds.
pub const MONTH: u64 = 30 * 24 * HOUR;

/// Parse a retention as a person types it: `forever` (`0`), `1h`, `1w`, `1m` (a month), or a
/// number of seconds. `None` for anything else, so a typo is refused rather than guessed at.
///
/// `1m` is a **month**, as PRD-001 R7 names the choices (1 hour, 1 week, 1 month); a minute is
/// written as `60`.
#[must_use]
pub fn parse_duration(text: &str) -> Option<u64> {
    let t = text.trim();
    match t {
        "forever" | "never" | "0" => return Some(0),
        _ => {}
    }
    let (digits, unit) = match t.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => t.split_at(i),
        None => (t, ""),
    };
    let n: u64 = digits.parse().ok()?;
    let scale = match unit {
        "" | "s" => 1,
        "h" => HOUR,
        "w" => WEEK,
        "m" => MONTH,
        _ => return None,
    };
    n.checked_mul(scale)
}

/// A retention as a person reads it: the named durations by name, anything else in seconds.
#[must_use]
pub fn describe(secs: u64) -> String {
    match secs {
        0 => "forever".into(),
        HOUR => "1 hour".into(),
        WEEK => "1 week".into(),
        MONTH => "1 month".into(),
        s => format!("{s} seconds"),
    }
}

/// The shorter of two retentions, where `0` means forever and so never wins.
#[must_use]
pub fn shortest(a: u64, b: u64) -> u64 {
    match (a, b) {
        (0, x) | (x, 0) => x,
        (x, y) => x.min(y),
    }
}

/// The node's own retention (ADR-023 decision 2): the `retention` file in the node's config
/// directory. One setting per line, `#` starts a comment:
///
/// ```text
/// default 1w
/// 4yxukqst 60        # a room, by the prefix of its id as `vox` prints it
/// ```
///
/// A missing file is "no node policy" — the room's governs alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetentionConfig {
    /// For every room without a line of its own.
    pub default: u64,
    /// `(room id prefix, retention)`, in file order.
    pub rooms: Vec<(String, u64)>,
}

impl RetentionConfig {
    /// Read the file at `path`. A missing file is the empty policy; a line that does not parse
    /// is an error naming it, because silently keeping *more* than the operator asked for is the
    /// one failure this file must not have.
    pub fn load(path: &Path) -> crate::error::Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(_) => return Err(crate::error::Error::Profile("retention file unreadable")),
        };
        Self::parse(&text)
    }

    /// Parse the file's text (see [`RetentionConfig`]).
    pub fn parse(text: &str) -> crate::error::Result<Self> {
        let mut out = Self::default();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut words = line.split_whitespace();
            let (Some(key), Some(value), None) = (words.next(), words.next(), words.next()) else {
                return Err(crate::error::Error::Profile(
                    "retention file: each line is `<default|room> <duration>`",
                ));
            };
            let secs = parse_duration(value).ok_or(crate::error::Error::Profile(
                "retention file: a duration is forever, 1h, 1w, 1m or seconds",
            ))?;
            if key == "default" {
                out.default = secs;
            } else {
                out.rooms.push((key.to_ascii_lowercase(), secs));
            }
        }
        Ok(out)
    }

    /// This node's retention for `channel_id`: the first room line whose prefix matches its id as
    /// `vox` prints it, else the default. `0` is "no node limit".
    #[must_use]
    pub fn for_room(&self, channel_id: &Digest32) -> u64 {
        let id = crate::node::link::b32_encode(channel_id);
        self.rooms
            .iter()
            .find(|(prefix, _)| id.starts_with(prefix.as_str()))
            .map_or(self.default, |(_, secs)| *secs)
    }
}

/// Where one retained body lives and how old it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tracked {
    /// The entry's `LogDb` segment id.
    pub log_id: u64,
    /// When this node first saw it, seconds.
    pub first_seen: u64,
    /// The author's claimed time in seconds, once this node has read it.
    pub claimed: Option<u64>,
    /// Its plaintext cache row, once rendered.
    pub cache_id: Option<u64>,
}

impl Tracked {
    /// The instant its age runs from: the claim, clamped to no later than first sight.
    pub fn base(&self) -> u64 {
        self.claimed
            .map_or(self.first_seen, |c| c.min(self.first_seen))
    }
}

/// Every content entry of a room that still holds its body, ordered by age, so a sweep costs what
/// it prunes rather than what the room holds.
#[derive(Debug, Default)]
pub(crate) struct RetentionIndex {
    live: HashMap<Digest32, Tracked>,
    by_age: BTreeSet<(u64, Digest32)>,
}

impl RetentionIndex {
    /// Start tracking a stored body.
    pub fn track(&mut self, hash: Digest32, tracked: Tracked) {
        self.forget(&hash);
        self.by_age.insert((tracked.base(), hash));
        self.live.insert(hash, tracked);
    }

    /// Record that the body was read: its claimed time and its cache row.
    pub fn rendered(&mut self, hash: &Digest32, claimed: u64, cache_id: u64) {
        if let Some(mut t) = self.live.get(hash).copied() {
            t.claimed = Some(claimed);
            t.cache_id = Some(cache_id);
            self.track(*hash, t);
        }
    }

    /// What is known about `hash`, if its body is still held.
    pub fn get(&self, hash: &Digest32) -> Option<Tracked> {
        self.live.get(hash).copied()
    }

    /// Stop tracking `hash`, returning what was known.
    pub fn forget(&mut self, hash: &Digest32) -> Option<Tracked> {
        let t = self.live.remove(hash)?;
        self.by_age.remove(&(t.base(), *hash));
        Some(t)
    }

    /// Remove and return every entry whose age base is at or before `cutoff`.
    pub fn take_due(&mut self, cutoff: u64) -> Vec<(Digest32, Tracked)> {
        let due: Vec<Digest32> = self
            .by_age
            .iter()
            .take_while(|(base, _)| *base <= cutoff)
            .map(|(_, h)| *h)
            .collect();
        due.into_iter()
            .filter_map(|h| self.forget(&h).map(|t| (h, t)))
            .collect()
    }
}
