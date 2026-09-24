//! Workers must run the same Vox version, enforced (ADR-021 §5).
//!
//! Mixed-version work coordination is **not supported**. The deployment this serves
//! is one operator who controls every worker and upgrades them together, so
//! correctness is bought by *refusing to coordinate across versions* rather than by
//! engineering compatibility between them.
//!
//! Two mechanisms, and both are needed:
//!
//! 1. **The fold applies only operations stamped with the folding worker's own
//!    version** ([`crate::claim::fold`]). Workers on one version therefore fold
//!    identically, and an operation from any other version — or with no stamp,
//!    which is what every binary before ADR-021 produces — changes nothing.
//! 2. **A worker refuses to participate while any participant does not match**
//!    ([`VersionTable::refused`]). Without this, an upgraded worker would claim work
//!    that an old worker, folding under old rules, believes it still holds.
//!
//! ## Who participates
//!
//! A worker (an author fingerprint) participates if it is in the room's roster, its
//! latest claim-protocol operation or work `hello` is not superseded by a `bye`, and
//! either that message is within the **participation horizon** or it holds, or is
//! the target of, a resource under this worker's fold. Its version is the stamp on
//! that latest message.
//!
//! The horizon is what lets the check work in both directions: a newly upgraded
//! worker sees an older worker that is still active before its own first operation,
//! and a worker retired without being upgraded stops blocking the room one horizon
//! after its last message, with nobody acting.

use std::collections::BTreeSet;

use crate::claim::{self, Posted, State};
use crate::envelope::{Envelope, BYE, HELLO};

/// The `data` key that carries a worker's Vox version.
pub const VOX_KEY: &str = "vox";

/// How long after its last message a worker still counts as participating.
pub const PARTICIPATION_HORIZON_MILLIS: u64 = 24 * 3600 * 1_000;

/// What a message's version stamp says, relative to the reading worker's version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stamp {
    /// Exactly the reader's version.
    Match,
    /// A valid version that is not the reader's.
    Other(String),
    /// No stamp at all — what every binary predating ADR-021 writes.
    Missing,
    /// A stamp that is not a semantic version.
    Unknown(String),
}

impl Stamp {
    /// The stamp as a person reads it in a refusal.
    #[must_use]
    pub fn describe(&self, mine: &str) -> String {
        match self {
            Stamp::Match => mine.to_owned(),
            Stamp::Other(v) => v.clone(),
            Stamp::Missing => "no version (a vox that predates ADR-021)".to_owned(),
            Stamp::Unknown(v) => format!("{v:?}, which is not a version"),
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

/// Whether `s` is a semantic version: `MAJOR.MINOR.PATCH`, each a number without a
/// leading zero, optionally followed by `-prerelease` and/or `+build`.
#[must_use]
pub fn is_semver(s: &str) -> bool {
    let core = s.split(['-', '+']).next().unwrap_or("");
    if core.len() != s.len() {
        let rest = &s[core.len()..];
        let ok = rest.len() > 1
            && rest
                .chars()
                .skip(1)
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '+');
        if !ok {
            return false;
        }
    }
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        })
}

/// What `env`'s stamp says relative to `mine`. **Exact string equality** is the
/// rule; development builds between two tags share a version, and that is accepted
/// because the operator upgrades together.
#[must_use]
pub fn stamp_of(env: &Envelope, mine: &str) -> Stamp {
    match env.data.get(VOX_KEY) {
        None | Some(serde_json::Value::Null) => Stamp::Missing,
        Some(serde_json::Value::String(v)) if v == mine => Stamp::Match,
        Some(serde_json::Value::String(v)) if is_semver(v) => Stamp::Other(v.clone()),
        Some(serde_json::Value::String(v)) => Stamp::Unknown(v.clone()),
        Some(other) => Stamp::Unknown(other.to_string()),
    }
}

/// Whether a message counts toward a worker's version: a claim-protocol operation,
/// a *work* `hello` (one carrying a stamp), or a `bye`.
fn counts(env: &Envelope) -> bool {
    claim::is_claim_protocol(env)
        || (env.kind == HELLO && env.data.get(VOX_KEY).is_some())
        || env.kind == BYE
}

/// One participating worker and what its latest message says.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Build the version table for the worker `me`, running `mine`, as of `now_millis`.
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
