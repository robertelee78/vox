//! Output-specific authority queries over sealed facts. No complete causal scope
//! or recursive authority map is materialized, including while deciding revokes.

use super::facts::{Table, Write, hash_key, position};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::governance::capability::{Capability, CapabilitySet};
use crate::governance::entry::{GovBody, GovEntry};
use crate::hash::Digest32;
use crate::log::entry::Entry;

fn invalid(why: &'static str) -> Error {
    Error::MalformedAtRest(why)
}

/// `None` is the head; `Some(entry)` is its strict causal past.
#[derive(Clone, Copy, Default)]
pub(super) struct Scope(pub Option<Digest32>);

impl Scope {
    pub(super) fn contains(self, writer: &Write<'_>, entry: &Entry) -> Result<bool> {
        match self.0 {
            None => Ok(true),
            Some(scope) => Ok(scope != entry.entry_hash()
                && entry.skeleton.seq <= writer.reached(&scope, &entry.skeleton.author_id)?),
        }
    }
}

/// Presence is distinct from an empty granted set, as in the existing evaluator.
#[derive(Clone, Copy, Default)]
pub(super) struct Grant {
    pub present: bool,
    pub admin: bool,
    pub policy: bool,
    pub expiry: u64,
}

impl Grant {
    pub(super) fn root() -> Self {
        Self {
            present: true,
            admin: true,
            policy: false,
            expiry: 0,
        }
    }
    pub(super) fn capabilities(self) -> CapabilitySet {
        let mut set = CapabilitySet::new();
        if self.admin {
            set.insert(Capability::Admin);
        }
        if self.policy {
            set.insert(Capability::Policy);
        }
        set
    }
    pub(super) fn grants_policy(self) -> bool {
        self.admin || self.policy
    }
    pub(super) fn write(self, e: &mut Encoder) {
        e.array(2)
            .uint(
                u64::from(self.present)
                    | (u64::from(self.admin) << 1)
                    | (u64::from(self.policy) << 2),
            )
            .uint(self.expiry);
    }
    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 2 {
            return Err(invalid("governance grant arity"));
        }
        let bits = d.uint()?;
        let expiry = d.uint()?;
        if bits > 7 || (bits & 1 == 0 && (bits != 0 || expiry != 0)) {
            return Err(invalid("governance grant bounds"));
        }
        Ok(Self {
            present: bits & 1 != 0,
            admin: bits & 2 != 0,
            policy: bits & 4 != 0,
            expiry,
        })
    }
}

fn option(e: &mut Encoder, value: Option<Digest32>) {
    match value {
        Some(value) => {
            e.array(1).bytes(&value);
        }
        None => {
            e.array(0);
        }
    }
}
fn read_option(d: &mut Decoder<'_>) -> Result<Option<Digest32>> {
    match d.array()? {
        0 => Ok(None),
        1 => Ok(Some(
            d.bytes()?
                .try_into()
                .map_err(|_| invalid("authority query hash"))?,
        )),
        _ => Err(invalid("authority query hash arity")),
    }
}

/// At most one candidate certificate and one revocation are opened by a step.
/// This record is saved with its caller's evaluation cursor between turns.
#[derive(Clone)]
pub(super) struct Query {
    scope: Scope,
    target: Digest32,
    before: Option<u64>,
    candidate: Option<u64>,
    after_revoke: Option<Digest32>,
}

impl Query {
    pub(super) fn new(scope: Scope, target: Digest32) -> Self {
        Self {
            scope,
            target,
            before: None,
            candidate: None,
            after_revoke: None,
        }
    }

    pub(super) fn write(&self, e: &mut Encoder) {
        e.array(5);
        option(e, self.scope.0);
        e.bytes(&self.target);
        match self.before {
            Some(value) => {
                e.array(1).uint(value);
            }
            None => {
                e.array(0);
            }
        }
        match self.candidate {
            Some(value) => {
                e.array(1).uint(value);
            }
            None => {
                e.array(0);
            }
        }
        option(e, self.after_revoke);
    }

    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 5 {
            return Err(invalid("authority query arity"));
        }
        let scope = Scope(read_option(d)?);
        let target = d
            .bytes()?
            .try_into()
            .map_err(|_| invalid("authority query target"))?;
        let mut number = || match d.array()? {
            0 => Ok(None),
            1 => Ok(Some(d.uint()?)),
            _ => Err(invalid("authority query number arity")),
        };
        let before = number()?;
        let candidate = number()?;
        let after_revoke = read_option(d)?;
        if candidate == Some(0) || (candidate.is_none() && after_revoke.is_some()) {
            return Err(invalid("authority query bounds"));
        }
        Ok(Self {
            scope,
            target,
            before,
            candidate,
            after_revoke,
        })
    }

    /// Only creator-issued certs can confer authority (#319). Their same-author
    /// order is total. The latest in-scope, unexpired creator certificate is the
    /// only possible governing candidate: if a revoke kills it, that revoke also
    /// kills every earlier candidate. Noncreator certs still participate in the
    /// separate stable-denial classification; they are not silently made valid.
    pub(super) fn advance(
        &mut self,
        writer: &Write<'_>,
        root: &Digest32,
        now_ms: u64,
        generation: u64,
    ) -> Result<Option<Grant>> {
        if self.target == *root {
            return Ok(Some(Grant::root()));
        }
        if self.candidate.is_none() {
            let before = match self.before {
                Some(seq) => position(&self.target, seq),
                None => {
                    let mut key = hash_key(&self.target);
                    key[32..].fill(u8::MAX);
                    key
                }
            };
            let Some((key, log)) = writer
                .last(Table::CreatorCerts, Some(before))?
                .filter(|(key, _)| key[..32] == self.target[..])
            else {
                return Ok(Some(Grant::default()));
            };
            if key[40..].iter().any(|b| *b != 0) {
                return Err(invalid("authority certificate position"));
            }
            let entry = writer.entry(log)?;
            self.before = Some(entry.skeleton.seq);
            let GovBody::AdminCert(cert) = GovEntry::body_bound_to(&entry)? else {
                return Err(invalid("authority certificate locator kind"));
            };
            if cert.body.issuer_id != *root
                || cert.body.delegate_id() != self.target
                || entry.skeleton.author_id != *root
            {
                return Err(invalid("authority certificate locator binding"));
            }
            if cert.body.epoch != 0
                || (cert.body.expiry_ms != 0 && cert.body.expiry_ms <= now_ms)
                || !self.scope.contains(writer, &entry)?
            {
                return Ok(None);
            }
            self.candidate = Some(log);
            self.after_revoke = None;
            return Ok(None);
        }
        let log = self
            .candidate
            .ok_or(invalid("authority candidate missing"))?;
        let candidate = writer.entry(log)?;
        let GovBody::AdminCert(cert) = GovEntry::body_bound_to(&candidate)? else {
            return Err(invalid("authority candidate kind"));
        };
        match next_revocation(writer, &self.target, self.after_revoke)? {
            None => Ok(Some(Grant {
                present: true,
                admin: cert
                    .body
                    .capability_set
                    .iter()
                    .any(|c| *c == Capability::Admin),
                policy: cert
                    .body
                    .capability_set
                    .iter()
                    .any(|c| *c == Capability::Policy),
                expiry: cert.body.expiry_ms,
            })),
            Some((hash, revoke_log)) => {
                self.after_revoke = Some(hash);
                let revoke = writer.entry(revoke_log)?;
                if !self.scope.contains(writer, &revoke)? {
                    return Ok(None);
                }
                let GovBody::AdminRevocation(body) = GovEntry::body_bound_to(&revoke)? else {
                    return Err(invalid("authority revoke locator kind"));
                };
                let Some(named) =
                    writer.get(Table::Hashes, &hash_key(&body.body.revoked_delegation_hash))?
                else {
                    return Err(invalid("authority revoke target missing"));
                };
                let named = writer.entry(named)?;
                if !self.scope.contains(writer, &named)? {
                    return Ok(None);
                }
                if authorized_revoke(writer, &hash, generation)?
                    && !Scope(Some(candidate.entry_hash())).contains(writer, &revoke)?
                {
                    return Ok(Some(Grant::default()));
                }
                Ok(None)
            }
        }
    }
}

pub(super) fn next_revocation(
    writer: &Write<'_>,
    target: &Digest32,
    after: Option<Digest32>,
) -> Result<Option<(Digest32, u64)>> {
    let mut key = hash_key(target);
    let row = match after {
        Some(after) => {
            key[32..].copy_from_slice(&after);
            writer.first(Table::Revocations, Some(key))?
        }
        None => writer.at_or_after(Table::Revocations, key)?,
    };
    row.filter(|(key, _)| key[..32] == target[..])
        .map(|(key, log)| {
            Ok((
                key[32..]
                    .try_into()
                    .map_err(|_| invalid("authority revoke cursor"))?,
                log,
            ))
        })
        .transpose()
}

pub(super) fn authorized_revoke(
    writer: &Write<'_>,
    hash: &Digest32,
    generation: u64,
) -> Result<bool> {
    let record = writer
        .get(Table::RevocationDecisions, &hash_key(hash))?
        .ok_or(invalid("governance revocation decision not ready"))?;
    let bytes = writer.record(record)?;
    let mut d = Decoder::new(&bytes);
    if d.array()? != 3 || d.uint()? != 1 || d.uint()? != generation {
        return Err(invalid("governance revocation decision stale"));
    }
    let authorized = match d.uint()? {
        0 => false,
        1 => true,
        _ => return Err(invalid("governance revocation decision boolean")),
    };
    d.finish()?;
    Ok(authorized)
}

pub(super) fn save_revocation(
    writer: &mut Write<'_>,
    hash: &Digest32,
    generation: u64,
    authorized: bool,
) -> Result<()> {
    let key = hash_key(hash);
    let old = writer.get(Table::RevocationDecisions, &key)?;
    let mut e = Encoder::new();
    e.array(3)
        .uint(1)
        .uint(generation)
        .uint(u64::from(authorized));
    let record = writer.save_record(old, &e.finish())?;
    writer.put(Table::RevocationDecisions, key, Some(record))
}
