//! The node's **decision record** (ADR-028 §7): what this node decided, one JSON line per
//! decision, in `nodes/<name>/decisions/<YYYY-MM-DD>.jsonl` (mode `0600`, the directory `0700`),
//! kept 14 days and never sent anywhere (D-1, D-2).
//!
//! Every refusal and every change of access is a decision: a refused join or tunnel, a trust added
//! or removed, a session cut. An event holds when, what was asked, by whom (fingerprint and this
//! node's alias for them, if it has one), what was decided and why — **never** message text, a
//! file name or content, a passphrase, a key or a token. So an event is built only from what this
//! module is handed as named fields, each a value the node made itself, and nothing a peer wrote
//! is copied in beyond a fingerprint.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::hash::Digest32;

/// The directory under a node's own directory that holds its decision record.
pub const DECISIONS_DIR: &str = "decisions";

/// How many days of the record are kept: today's file and the 13 before it (D-2).
pub const KEEP_DAYS: i64 = 14;

/// How long a repeating decision is folded before it is written again
/// ([`DecisionLog::record_folded`]): an hour.
pub const FOLD_MS: u64 = 3_600_000;

/// What was decided (D-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decided {
    /// Asked for, and refused.
    Refused,
    /// Added to this node's trust keyring.
    Trusted,
    /// Removed from this node's trust keyring.
    Untrusted,
    /// A session that was running, cut.
    Cut,
    /// Something this node offered, offered no more: a share stopped.
    Stopped,
}

impl Decided {
    /// How the record words it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Decided::Refused => "refused",
            Decided::Trusted => "trusted",
            Decided::Untrusted => "untrusted",
            Decided::Cut => "cut",
            Decided::Stopped => "stopped",
        }
    }
}

/// One decision (D-1). `asked` and `why` are this node's own words.
#[derive(Debug, Clone)]
pub struct Decision {
    /// What was asked: "to join a room", "a tunnel to a service", "trust", …
    pub asked: &'static str,
    /// Who asked, or whom it was about.
    pub by: Digest32,
    /// This node's name for them, if it has one.
    pub alias: Option<String>,
    /// What was decided.
    pub decided: Decided,
    /// Why, in this node's words.
    pub why: String,
    /// The room it concerns, by its ID — never its name or anything in it (D-2) — when the
    /// decision is about one: a join, a share stopped. `None` for one about no room (a trust, a
    /// stream or relay circuit asked of the connection).
    pub room: Option<Digest32>,
}

/// A node's decision record: where it is, and which day it was last pruned on. Cheap to clone;
/// every clone appends to the same files.
#[derive(Debug, Clone)]
pub struct DecisionLog {
    dir: PathBuf,
    pruned: std::sync::Arc<std::sync::Mutex<Option<i64>>>,
    /// This node's names for the members it trusts, as last published: what an event names
    /// someone as when the decision was taken where the keyring is not at hand.
    aliases: std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<Digest32, String>>>,
    /// Each decision that repeats ([`DecisionLog::record_folded`]), by what makes it the same.
    folded: std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, Folded>>>,
}

/// A decision being folded ([`DecisionLog::record_folded`]).
#[derive(Debug, Clone)]
struct Folded {
    /// When it was written, ms since the Unix epoch: its hour runs from here.
    since: u64,
    /// How many times it was decided again since, not written.
    repeats: u64,
    /// The decision, as written.
    decision: Decision,
}

impl DecisionLog {
    /// The record under `node_dir` (`nodes/<name>/`).
    #[must_use]
    pub fn new(node_dir: &Path) -> Self {
        Self {
            dir: node_dir.join(DECISIONS_DIR),
            pruned: std::sync::Arc::new(std::sync::Mutex::new(None)),
            aliases: std::sync::Arc::default(),
            folded: std::sync::Arc::default(),
        }
    }

    /// [`Self::record`] for a decision that can repeat many times a minute (a stream refused
    /// until a joiner's membership reaches this node): written at once, then not again for
    /// [`FOLD_MS`] for the same `same` (who, what, why). The repeats in that hour are counted and
    /// written as one event when it is over ([`Self::flush_folded`]), so a reader sees that they
    /// were folded and how many there were.
    pub fn record_folded(&self, now_ms: u64, same: &str, d: &Decision) {
        self.flush_folded(now_ms);
        {
            let mut seen = self
                .folded
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(f) = seen.get_mut(same) {
                f.repeats += 1;
                return;
            }
            seen.insert(
                same.to_owned(),
                Folded {
                    since: now_ms,
                    repeats: 0,
                    decision: d.clone(),
                },
            );
        }
        let mut d = d.clone();
        d.why = format!(
            "{} (repeats in the next hour are counted, and recorded as one event)",
            d.why
        );
        self.record(now_ms, &d);
    }

    /// Write each folded decision whose hour is over: one event saying how many times it was
    /// decided again in that hour, when it was at all. Called by every folded record and by the
    /// node's tick, so a count is written even when nothing repeats after it.
    pub fn flush_folded(&self, now_ms: u64) {
        let due: Vec<Folded> = {
            let mut seen = self
                .folded
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let over: Vec<String> = seen
                .iter()
                .filter(|(_, f)| now_ms >= f.since.saturating_add(FOLD_MS))
                .map(|(k, _)| k.clone())
                .collect();
            over.into_iter().filter_map(|k| seen.remove(&k)).collect()
        };
        for f in due.into_iter().filter(|f| f.repeats > 0) {
            let mut d = f.decision;
            d.why = format!(
                "{} — {} more times in the hour from {} UTC, folded into this one event",
                d.why,
                f.repeats,
                time_of(f.since)
            );
            self.record(now_ms, &d);
        }
    }

    /// This node's names for the members it trusts, from now on.
    pub fn set_aliases(&self, rows: &[(Digest32, String)]) {
        *self
            .aliases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = rows.iter().cloned().collect();
    }

    /// Where the record's files are.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Append `d`, decided at `now_ms` (ms since the Unix epoch), to that day's file, and drop
    /// the files past [`KEEP_DAYS`] once a day. Best effort: a record that cannot be written
    /// changes nothing the node does, and is said on stderr.
    pub fn record(&self, now_ms: u64, d: &Decision) {
        let day = days_from_epoch(now_ms);
        let mut event = serde_json::json!({
            "at_ms": now_ms,
            "asked": d.asked,
            "by": crate::node::link::b32_encode(&d.by),
            "alias": d.alias.clone().or_else(|| {
                self.aliases
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&d.by)
                    .cloned()
            }),
            "decided": d.decided.as_str(),
            "why": d.why,
        });
        // Only on an event about a room: its ID, nothing else of it (D-2).
        if let (Some(room), Some(fields)) = (d.room, event.as_object_mut()) {
            fields.insert("room".into(), crate::node::link::b32_encode(&room).into());
        }
        let line = event.to_string();
        if let Err(e) = self.append(day, &line) {
            eprintln!(
                "vox: could not write the decision record in {}: {e}",
                self.dir.display()
            );
        }
        let mut pruned = self
            .pruned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *pruned != Some(day) {
            *pruned = Some(day);
            self.prune(day);
        }
    }

    fn append(&self, day: i64, line: &str) -> std::io::Result<()> {
        crate::node::paths::create_private_dir(&self.dir)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let mut open = std::fs::OpenOptions::new();
        open.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            open.mode(0o600);
        }
        let mut f = open.open(self.dir.join(format!("{}.jsonl", date_of(day))))?;
        f.write_all(format!("{line}\n").as_bytes())
    }

    /// Remove every day's file older than [`KEEP_DAYS`] before `today`. A file whose name is not a
    /// date this module writes is left alone.
    pub fn prune(&self, today: i64) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for e in entries.flatten() {
            let name = e.file_name();
            let Some(day) = name
                .to_str()
                .and_then(|n| n.strip_suffix(".jsonl"))
                .and_then(day_of)
            else {
                continue;
            };
            if day <= today - KEEP_DAYS {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// Days since 1970-01-01 (UTC) of `ms`.
#[must_use]
pub fn days_from_epoch(ms: u64) -> i64 {
    i64::try_from(ms / 86_400_000).unwrap_or(i64::MAX)
}

/// `YYYY-MM-DD` of a day counted from 1970-01-01 (proleptic Gregorian, UTC).
#[must_use]
pub fn date_of(days: i64) -> String {
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DD HH:MM` (UTC) of `ms` since the Unix epoch.
#[must_use]
pub fn time_of(ms: u64) -> String {
    let mins = ms / 60_000;
    format!(
        "{} {:02}:{:02}",
        date_of(days_from_epoch(ms)),
        (mins / 60) % 24,
        mins % 60
    )
}

/// The day counted from 1970-01-01 that `YYYY-MM-DD` names, if it is one.
#[must_use]
pub fn day_of(date: &str) -> Option<i64> {
    let mut parts = date.splitn(3, '-');
    let (y, m, d) = (parts.next()?, parts.next()?, parts.next()?);
    if y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return None;
    }
    let (y, m, d): (i64, i64, i64) = (y.parse().ok()?, m.parse().ok()?, d.parse().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Howard Hinnant's days_from_civil.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}
