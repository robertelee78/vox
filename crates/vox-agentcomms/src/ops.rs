//! Operation ids: real retries, explicit conflicts (ADR-021 §6).
//!
//! A worker that posts, loses the response, and posts again has made **one**
//! operation, not two. It says so by carrying the same `data.op` both times. The
//! log cannot tell on its own: a retry is a new entry with a new timestamp and a new
//! entry hash, so de-duplicating identical entries never catches it.
//!
//! ## Identity and content
//!
//! An operation is identified by `(author fingerprint, op)`. Two entries with that
//! identity are the **same operation** when their *semantic content* agrees — see
//! [`semantic`] — and a **conflict** when it does not.
//!
//! ## Why a conflict voids, rather than "first wins"
//!
//! Under "first in canonical order wins", an entry that arrives *late* but *sorts
//! early* silently changes the answer — after a tracker may already have acted on the
//! entry it displaced. Voiding instead makes the change **explicit**: every entry in
//! a conflicted group has no effect, on every node, whatever order they arrived in,
//! and every one of them is reported. Conflict is monotone: an operation can go from
//! ok to conflicted, and never back.

use std::collections::BTreeMap;

use crate::envelope::Envelope;

/// The `data` key that carries the operation id.
pub const OP_KEY: &str = "op";

/// Longest accepted operation id.
pub const MAX_OP: usize = 64;
/// Shortest accepted operation id — long enough that two callers do not collide by
/// accident.
pub const MIN_OP: usize = 8;

/// Whether `op` is a well-formed operation id: `[A-Za-z0-9._-]{8,64}`.
#[must_use]
pub fn is_valid_op(op: &str) -> bool {
    (MIN_OP..=MAX_OP).contains(&op.len())
        && op
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// The operation id an envelope carries, if any.
#[must_use]
pub fn op_of(env: &Envelope) -> Option<&str> {
    env.data.get(OP_KEY).and_then(serde_json::Value::as_str)
}

/// The **semantic content** of an envelope, as canonical JSON (sorted keys at every
/// depth).
///
/// Included: `type`, sorted `to`, `urgent`, `re`, `thread`, `from`, and `data` with
/// the `op` key removed. Excluded: `body`, which is human prose a retrying model may
/// reword; `at`, which is volatile context; and `hops` and `v`, which are transport.
/// A reworded retry is therefore still a retry, and a retry that changes what it
/// *does* is a conflict.
#[must_use]
pub fn semantic(env: &Envelope) -> String {
    let mut to = env.to.clone();
    to.sort();
    let mut data = env.data.clone();
    if let serde_json::Value::Object(m) = &mut data {
        m.remove(OP_KEY);
    }
    let v = serde_json::json!({
        "type": env.kind,
        "to": to,
        "urgent": env.urgent,
        "re": env.re,
        "thread": env.thread,
        "from": env.from,
        "data": data,
    });
    canonical(&v)
}

/// Serialise a JSON value with object keys sorted at every depth.
///
/// Done explicitly rather than relying on `serde_json`'s default map ordering, which
/// a `preserve_order` feature anywhere in the build graph would silently change.
#[must_use]
pub fn canonical(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let mut out = String::from("{");
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::Value::String((*k).clone()).to_string());
                out.push(':');
                out.push_str(&canonical(&m[*k]));
            }
            out.push('}');
            out
        }
        serde_json::Value::Array(a) => {
            let mut out = String::from("[");
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&canonical(x));
            }
            out.push(']');
            out
        }
        other => other.to_string(),
    }
}

/// What the log says about one operation id, in canonical order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The entry is the operation — the canonical first of its group, and the group
    /// agrees.
    Effective,
    /// The entry repeats an operation with the same content. It has no effect.
    Duplicate {
        /// The entry that is the operation.
        of: [u8; 32],
    },
    /// The group disagrees about what the operation is. **No** entry in it has any
    /// effect.
    Conflict {
        /// Every entry in the group, in canonical order.
        group: Vec<[u8; 32]>,
    },
}

/// One entry, as the operation index needs it.
#[derive(Debug, Clone)]
struct Member {
    entry_hash: [u8; 32],
    created_millis: u64,
    semantic: String,
}

/// Every operation id seen, grouped by `(author, op)`.
///
/// Built incrementally, so a stream can ask after each arrival whether that arrival
/// turned an earlier, already-delivered entry into a conflict.
#[derive(Debug, Clone, Default)]
pub struct OpIndex {
    groups: BTreeMap<([u8; 32], String), Vec<Member>>,
}

impl OpIndex {
    /// An empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an entry. Returns `true` if this arrival **newly** made its group a
    /// conflict — the moment a consumer must be told that entries it already has
    /// are void.
    ///
    /// An entry without an operation id is not recorded.
    pub fn insert(
        &mut self,
        entry_hash: [u8; 32],
        author: [u8; 32],
        created_millis: u64,
        env: &Envelope,
    ) -> bool {
        let Some(op) = op_of(env) else {
            return false;
        };
        let group = self.groups.entry((author, op.to_owned())).or_default();
        if group.iter().any(|m| m.entry_hash == entry_hash) {
            return false;
        }
        let was_conflict = is_conflict(group);
        group.push(Member {
            entry_hash,
            created_millis,
            semantic: semantic(env),
        });
        group.sort_by(|a, b| {
            a.created_millis
                .cmp(&b.created_millis)
                .then_with(|| a.entry_hash.cmp(&b.entry_hash))
        });
        !was_conflict && is_conflict(group)
    }

    /// The canonical verdict on one entry, or `None` if it carries no operation id or
    /// was never inserted.
    #[must_use]
    pub fn verdict(&self, author: [u8; 32], env: &Envelope, entry_hash: [u8; 32]) -> Option<Verdict> {
        let op = op_of(env)?;
        let group = self.groups.get(&(author, op.to_owned()))?;
        if !group.iter().any(|m| m.entry_hash == entry_hash) {
            return None;
        }
        if is_conflict(group) {
            return Some(Verdict::Conflict {
                group: group.iter().map(|m| m.entry_hash).collect(),
            });
        }
        let first = group[0].entry_hash;
        Some(if first == entry_hash {
            Verdict::Effective
        } else {
            Verdict::Duplicate { of: first }
        })
    }

    /// Every entry in the group `entry_hash` belongs to, in canonical order.
    #[must_use]
    pub fn group_of(&self, author: [u8; 32], env: &Envelope) -> Vec<[u8; 32]> {
        op_of(env)
            .and_then(|op| self.groups.get(&(author, op.to_owned())))
            .map(|g| g.iter().map(|m| m.entry_hash).collect())
            .unwrap_or_default()
    }
}

fn is_conflict(group: &[Member]) -> bool {
    group
        .first()
        .is_some_and(|f| group.iter().any(|m| m.semantic != f.semantic))
}
