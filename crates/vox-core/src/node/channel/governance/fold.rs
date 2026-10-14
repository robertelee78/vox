//! Checked authority and display effects. Historical inputs and intermediate
//! decisions stay in sealed records; a turn opens only its current entry/query.

use super::authority::{self, Grant, Scope};
use super::canonical::{rank_from, rank_key};
use super::context::CachedQuery;
use super::facts::{Cursor, Table, Write, hash_key};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::governance::entry::{GovBody, GovEntry};
use crate::governance::lifecycle::LifecycleKind;
use crate::hash::Digest32;
use crate::log::entry::{Entry, EntryRead};

const AUTHORITY: u64 = 0;
const CLEAR: u64 = 1;
const ACTIONS: u64 = 2;
const HEAD: u64 = 3;
const DONE: u64 = 4;

pub(super) const NAME: u64 = 1;
pub(super) const MESSAGES: u64 = 2;
pub(super) const STEPS: u64 = 3;
pub(super) const END: u64 = 4;
pub(super) const IDLE: u64 = 5;
pub(super) const ANCHORS: u64 = 6;

fn invalid(why: &'static str) -> Error {
    Error::MalformedAtRest(why)
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
                .map_err(|_| invalid("governance fold hash"))?,
        )),
        _ => Err(invalid("governance fold hash arity")),
    }
}

pub(super) fn kind_key(kind: u64, rank: u64) -> [u8; 64] {
    let mut key = [0; 64];
    key[..8].copy_from_slice(&kind.to_be_bytes());
    key[8..16].copy_from_slice(&rank.to_be_bytes());
    key
}
fn notice_key(clock: u64, hash: &Digest32) -> [u8; 64] {
    let mut key = rank_key(clock);
    key[8..40].copy_from_slice(hash);
    key
}
fn pair(left: &Digest32, right: &Digest32) -> [u8; 64] {
    let mut key = hash_key(left);
    key[32..].copy_from_slice(right);
    key
}

struct State {
    phase: u64,
    ordered: u64,
    generation: u64,
    now: u64,
    deadline: u64,
    from: u64,
    after_rank: u64,
    log: u64,
    query: Option<CachedQuery>,
    grant: Option<Grant>,
    after_revoke: Option<Digest32>,
    target: Option<Digest32>,
    after_cert: Option<Digest32>,
    deny: u64,
    head_grant: Option<Grant>,
}
impl State {
    fn new(writer: &Write<'_>, now: u64) -> Self {
        let auth = writer.authority_generation() != writer.authority_folded();
        Self {
            phase: if auth { AUTHORITY } else { CLEAR },
            ordered: writer.ordered(),
            generation: writer.authority_generation(),
            now,
            deadline: 0,
            from: if auth {
                1
            } else {
                writer.ordered_from().max(1)
            },
            after_rank: 0,
            log: 0,
            query: None,
            grant: None,
            after_revoke: None,
            target: None,
            after_cert: None,
            deny: 1,
            head_grant: None,
        }
    }
    fn load(writer: &Write<'_>) -> Result<Option<Self>> {
        let Some(bytes) = writer.cursor(Cursor::Evaluation)? else {
            return Ok(None);
        };
        let mut d = Decoder::new(&bytes);
        if d.array()? != 16 || d.uint()? != 1 {
            return Err(invalid("governance fold cursor format"));
        }
        let phase = d.uint()?;
        let ordered = d.uint()?;
        let generation = d.uint()?;
        let now = d.uint()?;
        let deadline = d.uint()?;
        let from = d.uint()?;
        let after_rank = d.uint()?;
        let log = d.uint()?;
        let query = match d.array()? {
            0 => None,
            1 => Some(CachedQuery::read(&mut d)?),
            _ => return Err(invalid("governance fold query arity")),
        };
        let grant = read_grant(&mut d)?;
        let after_revoke = read_option(&mut d)?;
        let target = read_option(&mut d)?;
        let after_cert = read_option(&mut d)?;
        let deny = d.uint()?;
        let head_grant = read_grant(&mut d)?;
        d.finish()?;
        if phase > DONE || from == 0 || generation == 0 || !(1..=5).contains(&deny) {
            return Err(invalid("governance fold cursor bounds"));
        }
        Ok(Some(Self {
            phase,
            ordered,
            generation,
            now,
            deadline,
            from,
            after_rank,
            log,
            query,
            grant,
            after_revoke,
            target,
            after_cert,
            deny,
            head_grant,
        }))
    }
    fn save(&self, writer: &mut Write<'_>) -> Result<()> {
        let mut e = Encoder::new();
        e.array(16)
            .uint(1)
            .uint(self.phase)
            .uint(self.ordered)
            .uint(self.generation)
            .uint(self.now)
            .uint(self.deadline)
            .uint(self.from)
            .uint(self.after_rank)
            .uint(self.log);
        match &self.query {
            Some(query) => {
                e.array(1);
                query.write(&mut e);
            }
            None => {
                e.array(0);
            }
        }
        write_grant(&mut e, self.grant);
        option(&mut e, self.after_revoke);
        option(&mut e, self.target);
        option(&mut e, self.after_cert);
        e.uint(self.deny);
        write_grant(&mut e, self.head_grant);
        writer.save_cursor(Cursor::Evaluation, &e.finish())
    }
    fn clear_query(&mut self) {
        self.log = 0;
        self.query = None;
        self.grant = None;
        self.after_revoke = None;
    }
    fn query(
        &mut self,
        writer: &mut Write<'_>,
        root: &Digest32,
        scope: Scope,
        target: Digest32,
    ) -> Result<Option<Grant>> {
        if let Some(grant) = self.grant {
            return Ok(Some(grant));
        }
        let query = self
            .query
            .get_or_insert_with(|| CachedQuery::new(scope, target));
        let grant = query.advance(writer, root, self.now, self.generation)?;
        if grant.is_some() {
            self.grant = grant;
            self.query = None;
        }
        Ok(grant)
    }
}
fn write_grant(e: &mut Encoder, grant: Option<Grant>) {
    match grant {
        Some(grant) => {
            e.array(1);
            grant.write(e);
        }
        None => {
            e.array(0);
        }
    }
}
fn read_grant(d: &mut Decoder<'_>) -> Result<Option<Grant>> {
    match d.array()? {
        0 => Ok(None),
        1 => Ok(Some(Grant::read(d)?)),
        _ => Err(invalid("governance optional grant arity")),
    }
}

pub(super) fn advance(
    writer: &mut Write<'_>,
    input: &super::super::entry_store::Read<'_>,
    root: &Digest32,
    now: u64,
) -> Result<bool> {
    if !writer.causal_settled() || !writer.order_ready() {
        return Ok(false);
    }
    writer.expire_authority(now)?;
    let mut state = match State::load(writer)? {
        Some(state)
            if state.generation == writer.authority_generation()
                && state.ordered == writer.ordered() =>
        {
            state
        }
        _ => State::new(writer, now),
    };
    // Expiry changes historical authorization too. No decision at an old wall
    // time may be published after a relevant deadline passed during paged work.
    if state.deadline != 0 && now >= state.deadline {
        writer.authority_changed()?;
        state = State::new(writer, now);
    }
    match state.phase {
        AUTHORITY => authority_step(writer, root, &mut state)?,
        CLEAR => clear_step(writer, &mut state)?,
        ACTIONS => action_step(writer, input, root, &mut state)?,
        HEAD => head_step(writer, root, &mut state)?,
        DONE => return Ok(true),
        _ => return Err(invalid("governance fold phase")),
    }
    state.save(writer)?;
    Ok(state.phase == DONE)
}

fn authority_step(writer: &mut Write<'_>, root: &Digest32, state: &mut State) -> Result<()> {
    if state.log == 0 {
        let Some((key, log)) =
            writer.first(Table::AuthorityOrder, Some(rank_key(state.after_rank)))?
        else {
            // Head projections are rebuilt in the same generation before public
            // authority reads become ready; actions can already use these facts.
            writer.authority_published(state.generation, state.deadline)?;
            state.phase = CLEAR;
            state.after_rank = 0;
            return Ok(());
        };
        state.after_rank = rank_from(&key)?;
        state.log = log;
    }
    let entry = writer.entry(state.log)?;
    let hash = entry.entry_hash();
    let body = GovEntry::body_bound_to(&entry)?;
    match body {
        GovBody::AdminCert(cert) => {
            if cert.body.expiry_ms > state.now {
                state.deadline = if state.deadline == 0 {
                    cert.body.expiry_ms
                } else {
                    state.deadline.min(cert.body.expiry_ms)
                };
            }
            let Some(grant) = state.query(writer, root, Scope(Some(hash)), cert.body.issuer_id)?
            else {
                return Ok(());
            };
            let key = hash_key(&hash);
            let old = writer.get(Table::IssuerRoles, &key)?;
            let mut e = Encoder::new();
            e.array(3).uint(1).uint(state.generation);
            grant.write(&mut e);
            let record = writer.save_record(old, &e.finish())?;
            writer.put(Table::IssuerRoles, key, Some(record))?;
        }
        GovBody::AdminRevocation(rev) => {
            let authorized = if rev.body.epoch == 0 {
                let Some(grant) =
                    state.query(writer, root, Scope(Some(hash)), rev.body.issuer_id)?
                else {
                    return Ok(());
                };
                grant.admin
            } else {
                false
            };
            if let Some(named_log) =
                writer.get(Table::Hashes, &hash_key(&rev.body.revoked_delegation_hash))?
            {
                let named = writer.entry(named_log)?;
                if let GovBody::AdminCert(cert) = GovEntry::body_bound_to(&named)? {
                    writer.put(
                        Table::Revocations,
                        pair(&cert.body.delegate_id(), &hash),
                        Some(state.log),
                    )?;
                }
            }
            authority::save_revocation(writer, &hash, state.generation, authorized)?;
        }
        _ => return Err(invalid("governance authority order kind")),
    }
    state.clear_query();
    Ok(())
}

fn effect_kind(body: &GovBody) -> Option<u64> {
    match body {
        GovBody::RoomName(_) => Some(NAME),
        GovBody::PolicyUpdate(p) if p.body.ttl_ms.is_some() => Some(MESSAGES),
        GovBody::StepPolicyUpdate(_) => Some(STEPS),
        GovBody::RoomAnchors(_) => Some(ANCHORS),
        GovBody::Lifecycle(l) => Some(match l.body.kind {
            LifecycleKind::End => END,
            LifecycleKind::IdleEnd(_) => IDLE,
        }),
        _ => None,
    }
}

fn clear_step(writer: &mut Write<'_>, state: &mut State) -> Result<()> {
    let Some((key, log)) = writer.at_or_after(Table::Effects, rank_key(state.from))? else {
        state.phase = ACTIONS;
        state.after_rank = state.from - 1;
        return Ok(());
    };
    let entry = writer.entry(log)?;
    let hash = entry.entry_hash();
    let kind =
        effect_kind(&GovEntry::body_bound_to(&entry)?).ok_or(invalid("governance effect kind"))?;
    writer.put(Table::EffectKinds, kind_key(kind, rank_from(&key)?), None)?;
    writer.put(Table::Effects, key, None)?;
    if let Some(record) = writer.get(Table::NoticeByHash, &hash_key(&hash))? {
        let bytes = writer.record(record)?;
        let mut d = Decoder::new(&bytes);
        if d.array()? != 2 || d.uint()? != 1 {
            return Err(invalid("governance notice locator format"));
        }
        let clock = d.uint()?;
        d.finish()?;
        writer.put(Table::Notices, notice_key(clock, &hash), None)?;
        writer.put(Table::NoticeByHash, hash_key(&hash), None)?;
        writer.delete_record(record)?;
    }
    Ok(())
}

fn action_step(
    writer: &mut Write<'_>,
    input: &super::super::entry_store::Read<'_>,
    root: &Digest32,
    state: &mut State,
) -> Result<()> {
    if state.log == 0 {
        let Some((key, log)) =
            writer.first(Table::ActionOrder, Some(rank_key(state.after_rank)))?
        else {
            if writer.head_ready() {
                writer.evaluation_published(state.ordered)?;
                state.phase = DONE;
            } else {
                state.phase = HEAD;
            }
            state.after_rank = 0;
            return Ok(());
        };
        state.after_rank = rank_from(&key)?;
        state.log = log;
    }
    let entry = writer.entry(state.log)?;
    let hash = entry.entry_hash();
    let body = GovEntry::body_bound_to(&entry)?;
    let Some(kind) = effect_kind(&body) else {
        state.clear_query();
        return Ok(());
    };
    let authorized = match kind {
        IDLE => entry.skeleton.author_id == *root,
        END if entry.skeleton.author_id == *root => true,
        _ => {
            if kind != END && body.channel_and_epoch().1 != 0 {
                state.clear_query();
                return Ok(());
            }
            let Some(grant) =
                state.query(writer, root, Scope(Some(hash)), entry.skeleton.author_id)?
            else {
                return Ok(());
            };
            if !grant.grants_policy() {
                state.clear_query();
                return Ok(());
            }
            match next_concurrent_revoke(writer, &entry, state.after_revoke, state.generation)? {
                Concurrent::Pending(hash) => {
                    state.after_revoke = Some(hash);
                    return Ok(());
                }
                Concurrent::Revoked => {
                    state.clear_query();
                    return Ok(());
                }
                Concurrent::Clear => true,
            }
        }
    };
    if authorized {
        writer.put(Table::Effects, rank_key(state.after_rank), Some(state.log))?;
        writer.put(
            Table::EffectKinds,
            kind_key(kind, state.after_rank),
            Some(state.log),
        )?;
        if kind == NAME || kind == MESSAGES {
            let clock = input
                .clock(&hash)?
                .ok_or(invalid("governance notice order missing"))?;
            writer.put(Table::Notices, notice_key(clock, &hash), Some(state.log))?;
            let old = writer.get(Table::NoticeByHash, &hash_key(&hash))?;
            let mut e = Encoder::new();
            e.array(2).uint(1).uint(clock);
            let record = writer.save_record(old, &e.finish())?;
            writer.put(Table::NoticeByHash, hash_key(&hash), Some(record))?;
        }
    }
    state.clear_query();
    Ok(())
}

enum Concurrent {
    Pending(Digest32),
    Clear,
    Revoked,
}
fn next_concurrent_revoke(
    writer: &Write<'_>,
    entry: &Entry,
    after: Option<Digest32>,
    generation: u64,
) -> Result<Concurrent> {
    let Some((hash, log)) = authority::next_revocation(writer, &entry.skeleton.author_id, after)?
    else {
        return Ok(Concurrent::Clear);
    };
    let rev = writer.entry(log)?;
    if !Scope(Some(entry.entry_hash())).contains(writer, &rev)?
        && !Scope(Some(hash)).contains(writer, entry)?
        && authority::authorized_revoke(writer, &hash, generation)?
    {
        return Ok(Concurrent::Revoked);
    }
    Ok(Concurrent::Pending(hash))
}

fn head_step(writer: &mut Write<'_>, root: &Digest32, state: &mut State) -> Result<()> {
    if state.target.is_none() {
        let Some((key, _)) = writer.first(Table::AllCerts, None)? else {
            writer.head_published(state.generation)?;
            writer.evaluation_published(state.ordered)?;
            state.phase = DONE;
            return Ok(());
        };
        state.target = Some(
            key[..32]
                .try_into()
                .map_err(|_| invalid("governance delegate"))?,
        );
    }
    let target = state.target.ok_or(invalid("governance head target"))?;
    if state.head_grant.is_none() {
        let Some(grant) = state.query(writer, root, Scope(None), target)? else {
            return Ok(());
        };
        state.head_grant = Some(grant);
        state.clear_query();
    }
    let grant = state.head_grant.ok_or(invalid("governance head grant"))?;
    if !grant.present && !classify_denial(writer, state, &target)? {
        return Ok(());
    }
    let key = hash_key(&target);
    let old = writer.get(Table::CurrentAuthority, &key)?;
    let mut e = Encoder::new();
    e.array(4).uint(1).uint(state.generation);
    grant.write(&mut e);
    e.uint(state.deny);
    let record = writer.save_record(old, &e.finish())?;
    writer.put(Table::CurrentAuthority, key, Some(record))?;
    let mut after = hash_key(&target);
    after[32..].fill(u8::MAX);
    match writer.first(Table::AllCerts, Some(after))? {
        Some((key, _)) => {
            state.target = Some(
                key[..32]
                    .try_into()
                    .map_err(|_| invalid("governance delegate cursor"))?,
            )
        }
        None => {
            writer.head_published(state.generation)?;
            writer.evaluation_published(state.ordered)?;
            state.phase = DONE;
        }
    }
    state.head_grant = None;
    state.after_cert = None;
    state.deny = 1;
    state.clear_query();
    Ok(())
}

fn classify_denial(writer: &Write<'_>, state: &mut State, target: &Digest32) -> Result<bool> {
    if state.log == 0 {
        let row = match state.after_cert {
            Some(hash) => writer.first(Table::AllCerts, Some(pair(target, &hash)))?,
            None => writer.at_or_after(Table::AllCerts, hash_key(target))?,
        }
        .filter(|(key, _)| key[..32] == target[..]);
        let Some((key, log)) = row else {
            return Ok(true);
        };
        state.after_cert = Some(
            key[32..]
                .try_into()
                .map_err(|_| invalid("governance denial cursor"))?,
        );
        state.log = log;
    }
    let entry = writer.entry(state.log)?;
    let GovBody::AdminCert(cert) = GovEntry::body_bound_to(&entry)? else {
        return Err(invalid("governance denial kind"));
    };
    if let Some((hash, log)) = authority::next_revocation(writer, target, state.after_revoke)? {
        state.after_revoke = Some(hash);
        let rev = writer.entry(log)?;
        if !Scope(Some(entry.entry_hash())).contains(writer, &rev)?
            && authority::authorized_revoke(writer, &hash, state.generation)?
        {
            state.deny = 5;
            state.clear_query();
            return Ok(true);
        }
        return Ok(false);
    }
    if cert.body.expiry_ms != 0 && cert.body.expiry_ms <= state.now {
        state.deny = state.deny.max(4);
    } else if cert.body.epoch == 0 {
        let record = writer
            .get(Table::IssuerRoles, &hash_key(&entry.entry_hash()))?
            .ok_or(invalid("governance issuer decision missing"))?;
        let bytes = writer.record(record)?;
        let mut d = Decoder::new(&bytes);
        if d.array()? != 3 || d.uint()? != 1 || d.uint()? != state.generation {
            return Err(invalid("governance issuer decision stale"));
        }
        let issuer = Grant::read(&mut d)?;
        d.finish()?;
        if issuer.present && !cert.body.capability_set.is_within(&issuer.capabilities()) {
            state.deny = state.deny.max(3);
        }
    }
    state.clear_query();
    Ok(false)
}
