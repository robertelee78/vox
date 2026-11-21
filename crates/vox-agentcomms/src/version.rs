//! Claims use a claim-rules number, not the Vox package version (ADR-052 RG-10).
//!
//! Change [`CLAIM_RULES`] only when the fold or participation rules change. Operations
//! under other rules are ignored, and a participating worker under other rules blocks
//! coordination. The v0.4.30 package stamp names these same rules and remains readable.

use std::collections::BTreeSet;

use crate::claim::{self, Posted, State};
use crate::envelope::{Envelope, BYE, HELLO};

/// Decimal claim-rules number. Independent of the client/daemon control protocol.
pub const CLAIM_RULES: &str = "1";
/// The `data` key carrying the decimal claim-rules number.
pub const CLAIMS_KEY: &str = "claims";

/// The `data` key that carries the informational Vox package version.
pub const VOX_KEY: &str = "vox";

/// How long after its last message a worker still counts as participating.
pub const PARTICIPATION_HORIZON_MILLIS: u64 = 24 * 3600 * 1_000;

/// What a message's claim-rules stamp says relative to the reading worker's rules.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Stamp {
    /// Exactly the reader's claim rules.
    Match,
    /// A valid claim-rules number that is not the reader's.
    Other(String),
    /// No stamp at all — what every binary predating ADR-021 writes.
    Missing,
    /// A stamp that is not a decimal claim-rules number.
    Unknown(String),
}

impl Stamp {
    /// The stamp as a person reads it in a refusal.
    #[must_use]
    pub fn describe(&self, mine: &str) -> String {
        match self {
            Stamp::Match => mine.to_owned(),
            Stamp::Other(v) => crate::envelope::shown(v, crate::envelope::SHOWN_NAME),
            Stamp::Missing => "no claim-rules number".to_owned(),
            // Quoted and cut: the stamp is the author's text, printed into every
            // coordinating session's context (V210-123).
            Stamp::Unknown(v) => format!(
                "{}, which is not a claim-rules number",
                crate::envelope::shown(&format!("{v:?}"), crate::envelope::SHOWN_NAME)
            ),
        }
    }

    /// A short machine token: `match`, `mismatched`, `missing` or `unknown`.
    #[must_use]
    pub fn token(&self) -> &'static str {
        match self {
            Stamp::Match => "match",
            Stamp::Other(_) => "mismatched",
            Stamp::Missing => "missing",
            Stamp::Unknown(_) => "unknown",
        }
    }

    /// The version string carried, if there was one.
    #[must_use]
    pub fn carried(&self, mine: &str) -> Option<String> {
        match self {
            Stamp::Match => Some(mine.to_owned()),
            Stamp::Other(v) | Stamp::Unknown(v) => Some(v.clone()),
            Stamp::Missing => None,
        }
    }
}

/// What `env`'s claim-rules stamp says relative to `mine`.
/// Only v0.4.30's package-only stamp is recognized as the original rules.
#[must_use]
pub fn stamp_of(env: &Envelope, mine: &str) -> Stamp {
    if env.data.get(CLAIMS_KEY).is_none()
        && env.data.get(VOX_KEY).and_then(serde_json::Value::as_str) == Some("0.4.30")
    {
        return if mine == "1" {
            Stamp::Match
        } else {
            Stamp::Other("1".into())
        };
    }
    match env.data.get(CLAIMS_KEY) {
        None | Some(serde_json::Value::Null) => Stamp::Missing,
        Some(serde_json::Value::String(v)) if v == mine => Stamp::Match,
        Some(serde_json::Value::String(v)) if !v.starts_with('0') && v.parse::<u32>().is_ok() => {
            Stamp::Other(v.clone())
        }
        Some(serde_json::Value::String(v)) => Stamp::Unknown(v.clone()),
        Some(other) => Stamp::Unknown(other.to_string()),
    }
}

/// Whether a message counts toward a worker's version: a claim-protocol operation,
/// a *work* `hello` (one carrying a stamp), or a `bye`.
fn counts(env: &Envelope) -> bool {
    claim::is_claim_protocol(env)
        || (env.kind == HELLO
            && (env.data.get(CLAIMS_KEY).is_some() || env.data.get(VOX_KEY).is_some()))
        || env.kind == BYE
}

/// One participating worker and what its latest message says.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Participant {
    /// The worker's harness fingerprint.
    pub author: [u8; 32],
    /// The session that posted its latest counted message.
    pub session: String,
    /// That message's stamp.
    pub stamp: Stamp,
    /// That message's entry hash.
    pub entry_hash: [u8; 32],
    /// That message's time.
    pub last_millis: u64,
}

/// Every participant other than the reading worker, and whether coordination is
/// refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionTable {
    /// The reading worker's version.
    pub mine: String,
    /// Every other participating worker.
    pub participants: Vec<Participant>,
}

impl VersionTable {
    /// Every participant whose stamp does not match.
    #[must_use]
    pub fn mismatched(&self) -> Vec<&Participant> {
        self.participants
            .iter()
            .filter(|p| p.stamp != Stamp::Match)
            .collect()
    }

    /// Whether this worker must refuse to coordinate.
    #[must_use]
    pub fn refused(&self) -> bool {
        !self.mismatched().is_empty()
    }
}

/// Build the table for worker `me`, using claim rules `mine`, as of `now_millis`.
///
/// `roster` is the room's current membership: a worker removed from the room stops
/// participating. `me` is excluded, because this worker's version is by definition
/// the one it runs — its own earlier messages may carry the version it ran *before*
/// an upgrade, and they must not make it refuse itself.
#[must_use]
pub fn version_table(
    messages: &[Posted],
    me: [u8; 32],
    roster: &[[u8; 32]],
    mine: &str,
    now_millis: u64,
    board: &claim::Fold,
) -> VersionTable {
    let roster: BTreeSet<[u8; 32]> = roster.iter().copied().collect();
    let mut involved: BTreeSet<[u8; 32]> = BTreeSet::new();
    for s in board.resources.values() {
        match s {
            State::Held { owner, .. } => {
                involved.insert(owner.author);
            }
            State::Pending { to_fp, .. } => {
                involved.insert(*to_fp);
            }
        }
    }

    let mut latest: std::collections::BTreeMap<[u8; 32], &Posted> =
        std::collections::BTreeMap::new();
    for m in messages.iter().filter(|m| counts(&m.envelope)) {
        let newer = latest.get(&m.author).is_none_or(|cur| {
            (m.created_millis, m.entry_hash) > (cur.created_millis, cur.entry_hash)
        });
        if newer {
            latest.insert(m.author, m);
        }
    }

    let mut participants: Vec<Participant> = latest
        .into_iter()
        .filter(|(author, m)| {
            *author != me
                && roster.contains(author)
                && m.envelope.kind != BYE
                && (now_millis.saturating_sub(m.created_millis) <= PARTICIPATION_HORIZON_MILLIS
                    || involved.contains(author))
        })
        .map(|(author, m)| Participant {
            author,
            session: m.envelope.from.clone(),
            stamp: stamp_of(&m.envelope, mine),
            entry_hash: m.entry_hash,
            last_millis: m.created_millis,
        })
        .collect();
    participants.sort_by(|a, b| a.author.cmp(&b.author));
    VersionTable {
        mine: mine.to_owned(),
        participants,
    }
}
