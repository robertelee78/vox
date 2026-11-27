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
        "d" => 24 * HOUR,
        "w" => WEEK,
        "m" => MONTH,
        _ => return None,
    };
    n.checked_mul(scale)
}

/// A retention as a person reads it: a whole count of the largest unit that divides it evenly,
/// `2 weeks` for `2w` (it said `1209600 seconds`: only one of each unit had a name).
#[must_use]
pub fn describe(secs: u64) -> String {
    if secs == 0 {
        return "forever".into();
    }
    let units = [
        (MONTH, "month"),
        (WEEK, "week"),
        (24 * HOUR, "day"),
        (HOUR, "hour"),
        (60, "minute"),
        (1, "second"),
    ];
    let (size, name) = units
        .into_iter()
        .find(|(size, _)| secs.is_multiple_of(*size))
        .unwrap_or((1, "second"));
    let n = secs / size;
    format!("{n} {name}{}", if n == 1 { "" } else { "s" })
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
///
/// **A node may keep less than its room, never more** (V030-32): a value above the room's is
/// ignored (the shorter wins) and the node says so once. A member writes a room's line with
/// `vox room retention <room> <duration>` ([`RetentionConfig::write_room`]), which refuses a value
/// above the room's.
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

    /// Set this node's own retention for `channel_id` in the file at `path` (V030-32): a member's
    /// `vox room retention` below the room's value lands here as `Some(secs)`, and one equal to the
    /// room's as `None`, which clears the line so the node follows the room again. Every room line
    /// whose prefix matches the room is removed, and `Some` adds one naming the room's whole id;
    /// every other line, and every comment, is kept as it was. Written to a temporary file and
    /// renamed, so a reader never sees half a file.
    ///
    /// # Errors
    /// The file cannot be read (other than missing) or written.
    pub fn write_room(
        path: &Path,
        channel_id: &Digest32,
        secs: Option<u64>,
    ) -> crate::error::Result<()> {
        let id = crate::node::link::b32_encode(channel_id);
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(_) => return Err(crate::error::Error::Profile("retention file unreadable")),
        };
        let mut out = String::new();
        for line in text.lines() {
            let key = line
                .split('#')
                .next()
                .unwrap_or("")
                .split_whitespace()
                .next();
            let this_room = key
                .is_some_and(|k| k != "default" && id.starts_with(k.to_ascii_lowercase().as_str()));
            if !this_room {
                out.push_str(line);
                out.push('\n');
            }
        }
        if let Some(secs) = secs {
            let value = if secs == 0 {
                "forever".to_owned()
            } else {
                secs.to_string()
            };
            out.push_str(&format!("{id} {value}\n"));
        }
        let tmp = path.with_extension("tmp");
        let written = (|| {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&tmp, out.as_bytes())?;
            std::fs::rename(&tmp, path)
        })();
        written.map_err(|_| crate::error::Error::Profile("retention file unwritable"))
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
    /// When this node first saw it, milliseconds since the Unix epoch.
    pub first_seen_ms: u64,
    /// The author's claimed time in milliseconds, once this node has read it.
    pub claimed_ms: Option<u64>,
    /// Its plaintext cache row, once rendered.
    pub cache_id: Option<u64>,
    /// Encrypted Session activity, including a body this node cannot decrypt.
    pub steps: bool,
    /// The message came back after a removal took it away (ADR-053 MP-11) and arrived again: its
    /// plaintext row has a newer arrival than the one a reader of it was given before. A
    /// continuation that names it by hash is refused, since its place in arrival moved.
    pub returned: bool,
}

impl Tracked {
    /// The instant its age runs from, milliseconds: the claim, clamped to no later than first
    /// sight.
    pub fn base(&self) -> u64 {
        self.claimed_ms
            .map_or(self.first_seen_ms, |c| c.min(self.first_seen_ms))
    }
}

/// What one lengthening keeps expired at this node, for one kind (messages or Session steps).
///
/// When a longer lifetime replaces a shorter one, what the shorter one had made due here stays
/// due: a row aged from at or before `floor` (the instant the shorter lifetime last reached) that
/// this node had first seen by `seen_by` (the instant the shorter lifetime stopped being in force
/// here). A row that first reaches this node later was never hidden here, and the longer lifetime
/// keeps it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Pair {
    pub floor: u64,
    pub seen_by: u64,
}

impl Pair {
    fn covers(self, base: u64, first_seen: u64) -> bool {
        base <= self.floor && (first_seen <= self.seen_by || edge_mutant(EdgeMutant::Seen))
    }
    /// Whether this pair keeps expired everything `other` does.
    fn dominates(self, other: Self) -> bool {
        self.floor >= other.floor && self.seen_by >= other.seen_by
    }
}

/// How many lengthenings one kind's fence holds apart; past it, the two oldest are merged.
pub(crate) const FENCE_PAIRS: usize = 8;

/// What all lengthenings here keep expired, for one kind: a row stays expired if any of its pairs
/// covers it. Pairs no other pair dominates, oldest (`seen_by`) first; none: nothing fenced.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Fence {
    pairs: [Pair; FENCE_PAIRS],
    len: u8,
}

impl Fence {
    pub fn pairs(&self) -> &[Pair] {
        &self.pairs[..usize::from(self.len)]
    }
    /// A saved fence, refused unless it is what [`Self::add`] keeps: at most [`FENCE_PAIRS`]
    /// pairs, each reaching some age, oldest first, none dominating another.
    pub fn from_pairs(pairs: &[Pair]) -> Option<Self> {
        let kept = pairs.len() <= FENCE_PAIRS
            && pairs.iter().all(|pair| pair.floor != 0)
            && pairs
                .windows(2)
                .all(|w| w[0].seen_by < w[1].seen_by && w[0].floor > w[1].floor);
        let mut fence = Self::default();
        fence.pairs[..pairs.len().min(FENCE_PAIRS)]
            .copy_from_slice(&pairs[..pairs.len().min(FENCE_PAIRS)]);
        fence.len = pairs.len().min(FENCE_PAIRS) as u8;
        kept.then_some(fence)
    }
    /// Whether a row aged from `base` and first seen here at `first_seen` stays expired.
    pub fn covers(&self, base: u64, first_seen: u64) -> bool {
        self.covering(base, first_seen).is_some()
    }
    /// The floor of a pair that keeps the row expired.
    pub fn covering(&self, base: u64, first_seen: u64) -> Option<u64> {
        self.pairs()
            .iter()
            .find(|pair| pair.covers(base, first_seen))
            .map(|pair| pair.floor)
    }
    /// The newest age any pair reaches.
    pub fn reach(&self) -> Option<u64> {
        self.pairs().iter().map(|pair| pair.floor).max()
    }
    /// Keep `new` expired too. A pair another dominates is dropped; past [`FENCE_PAIRS`], the two
    /// oldest become one that covers both (and may cover a late arrival neither did).
    pub fn add(&mut self, new: Pair) {
        if new.floor == 0 {
            return;
        }
        let mut pairs: Vec<Pair> = self.pairs().to_vec();
        if edge_mutant(EdgeMutant::Merged) {
            pairs = vec![pairs.iter().fold(new, |a, b| Pair {
                floor: a.floor.max(b.floor),
                seen_by: a.seen_by.max(b.seen_by),
            })];
        } else if !pairs.iter().any(|pair| pair.dominates(new)) {
            pairs.retain(|pair| !new.dominates(*pair));
            pairs.push(new);
            pairs.sort_by_key(|pair| (pair.seen_by, pair.floor));
            while pairs.len() > FENCE_PAIRS {
                let merged = Pair {
                    floor: pairs[0].floor.max(pairs[1].floor),
                    seen_by: pairs[0].seen_by.max(pairs[1].seen_by),
                };
                pairs.drain(..2);
                pairs.retain(|pair| !merged.dominates(*pair));
                pairs.insert(0, merged);
                pairs.sort_by_key(|pair| (pair.seen_by, pair.floor));
            }
        }
        *self = Self::default();
        for (slot, pair) in self.pairs.iter_mut().zip(&pairs) {
            *slot = *pair;
        }
        self.len = pairs.len() as u8;
    }
}

/// The fences in force, `[messages, Session steps]`, when the lifetimes last projected here were
/// `projected` (with the fences `fence` they kept) and the lifetimes now in force are `current`.
/// The shorter lifetime was in force here until `until`: the switch's instant, or, for a node
/// that stopped under it, the instant it stopped. A kind whose lifetime grew (or became
/// unlimited) gets the pair `floor = until − shorter`, `seen_by = until`.
pub(crate) fn lengthened(
    fence: [Fence; 2],
    projected: Option<[u64; 3]>,
    current: [u64; 2],
    until: u64,
) -> [Fence; 2] {
    let Some(old) = projected else {
        return fence;
    };
    let mut fence = fence;
    for ((fence, was), now) in fence.iter_mut().zip(old).zip(current) {
        if longer(was, now) {
            fence.add(Pair {
                floor: until.saturating_sub(was.saturating_mul(1_000)),
                seen_by: until,
            });
        }
    }
    fence
}

/// Whether the lifetime `now` keeps longer than `was` (`0` is forever).
pub(crate) fn longer(was: u64, now: u64) -> bool {
    was != 0 && (now == 0 || now > was)
}

/// The lifetimes in force and what lengthenings keep expired, `[messages, Session steps]`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Expiry {
    pub ttl: [u64; 2],
    pub fence: [Fence; 2],
}

impl Expiry {
    /// Whether something of `kind` (0 messages and Session records, 1 Session steps), aged from
    /// `base` and first seen here at `first_seen`, has expired by `now`.
    pub fn expired(&self, kind: usize, base: u64, first_seen: u64, now: u64) -> bool {
        let ttl = self.ttl[kind];
        (ttl != 0 && base <= now.saturating_sub(ttl.saturating_mul(1_000)))
            || (self.fence[kind].covers(base, first_seen)
                && !edge_mutant(EdgeMutant::PrivateUnfenced))
    }
}

/// `test-knobs` mutants of the retention fence, one per edge it closes, chosen by
/// `VOX_TEST_RETENTION_EDGE_MUTANT`. Never selectable in a build without the feature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum EdgeMutant {
    /// A longer lifetime applies to reads and cleanup before its switch saves and publishes it,
    /// with only the saved fences.
    Read,
    /// The fence covers late arrivals too: first sight is ignored.
    Seen,
    /// A node that stopped under the shorter lifetime fences from its restart, not its stop.
    Stopped,
    /// Private Session expiry ignores the fences.
    PrivateUnfenced,
    /// Every lengthening folds into one pair per kind (the largest floor and `seen_by`).
    Merged,
}

pub(crate) fn edge_mutant(which: EdgeMutant) -> bool {
    #[cfg(feature = "test-knobs")]
    {
        let name = match which {
            EdgeMutant::Read => "read",
            EdgeMutant::Seen => "seen",
            EdgeMutant::Stopped => "stopped",
            EdgeMutant::PrivateUnfenced => "private",
            EdgeMutant::Merged => "merged",
        };
        if std::env::var("VOX_TEST_RETENTION_EDGE_MUTANT").is_ok_and(|v| v == name) {
            static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            if !SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
                eprintln!("test-knobs: retention edge mutant engaged: {name}");
            }
            return true;
        }
    }
    #[cfg(not(feature = "test-knobs"))]
    let _ = which;
    false
}
