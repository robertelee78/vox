//! Bounded validation of signed room-member governance inputs.

use super::authority::Scope;
use super::facts::{hash_key, Table, Write};
use super::view::{read_recipient_cut, write_recipient_cut, RecipientCutState};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::governance::entry::{GovBody, GovEntry};
use crate::hash::Digest32;

/// Validates one creator readmission against already validated removal decisions.
/// The caller persists this cursor alongside its fold state between bounded turns.
pub(super) struct ReadmissionValidation {
    hash: Digest32,
    next: u64,
}

impl ReadmissionValidation {
    pub(super) fn new(hash: Digest32) -> Self {
        Self { hash, next: 0 }
    }

    pub(super) fn write(&self, e: &mut Encoder) {
        e.array(2).bytes(&self.hash).uint(self.next);
    }

    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 2 {
            return Err(Error::MalformedAtRest(
                "readmission validation cursor arity",
            ));
        }
        let hash = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("readmission validation cursor hash"))?;
        Ok(Self {
            hash,
            next: d.uint()?,
        })
    }

    /// `None` means another bounded turn is needed. An unavailable or invalid
    /// referenced fact is inert; a later causal/index generation reevaluates it.
    pub(super) fn advance(
        &mut self,
        writer: &Write<'_, '_>,
        root: &Digest32,
        generation: u64,
    ) -> Result<Option<bool>> {
        let Some(log) = writer.get(Table::Hashes, &hash_key(&self.hash))? else {
            return Ok(Some(false));
        };
        if writer
            .get(Table::Complete, &hash_key(&self.hash))?
            .is_none()
            || writer
                .get(Table::Incomplete, &hash_key(&self.hash))?
                .is_some()
        {
            return Ok(Some(false));
        }
        let entry = writer.entry(log)?;
        let GovBody::MemberReadmission(body) = GovEntry::body_bound_to(&entry)? else {
            return Err(Error::MalformedAtRest(
                "readmission validation locator kind",
            ));
        };
        if entry.entry_hash() != self.hash
            || !writer.fork_safe(&entry)?
            || entry.skeleton.author_id != *root
            || body.issuer_id != *root
            || body.target_id == *root
            || body.epoch != 0
            || body.removal_entry_hashes.is_empty()
        {
            return Ok(Some(false));
        }
        let index = usize::try_from(self.next)
            .map_err(|_| Error::MalformedAtRest("readmission validation cursor overflow"))?;
        let Some(hash) = body.removal_entry_hashes.get(index) else {
            return Ok(Some(index == body.removal_entry_hashes.len()));
        };
        let Some(removal_log) = writer.evidence_locator(hash)? else {
            return Ok(Some(false));
        };
        if writer.get(Table::MemberDecisions, &hash_key(hash))? != Some(generation)
            || writer.get(Table::Complete, &hash_key(hash))?.is_none()
            || writer.get(Table::Incomplete, &hash_key(hash))?.is_some()
        {
            return Ok(Some(false));
        }
        let removal = writer.entry(removal_log)?;
        let GovBody::MemberRemoval(removal_body) = GovEntry::body_bound_to(&removal)? else {
            return Ok(Some(false));
        };
        if removal.entry_hash() != *hash
            || removal_body.target_id != body.target_id
            || removal_body.channel_id != body.channel_id
            || removal_body.epoch != body.epoch
            || !Scope(Some(self.hash)).contains(writer, &removal)?
        {
            return Ok(Some(false));
        }
        self.next = self.next.checked_add(1).ok_or(Error::MalformedAtRest(
            "readmission validation cursor overflow",
        ))?;
        Ok(None)
    }
}

fn option_hash(e: &mut Encoder, hash: Option<Digest32>) {
    match hash {
        Some(hash) => {
            e.array(1).bytes(&hash);
        }
        None => {
            e.array(0);
        }
    }
}

fn read_option_hash(d: &mut Decoder<'_>) -> Result<Option<Digest32>> {
    match d.array()? {
        0 => Ok(None),
        1 => Ok(Some(d.bytes()?.try_into().map_err(|_| {
            Error::MalformedAtRest("membership cursor hash")
        })?)),
        _ => Err(Error::MalformedAtRest("membership cursor option")),
    }
}

fn option_cut(e: &mut Encoder, cut: Option<(u64, Digest32)>) {
    match cut {
        Some((seq, hash)) => {
            e.array(2).uint(seq).bytes(&hash);
        }
        None => {
            e.array(0);
        }
    }
}

fn read_option_cut(d: &mut Decoder<'_>) -> Result<Option<(u64, Digest32)>> {
    match d.array()? {
        0 => Ok(None),
        2 => {
            let seq = d.uint()?;
            let hash = d
                .bytes()?
                .try_into()
                .map_err(|_| Error::MalformedAtRest("membership cut hash"))?;
            Ok(Some((seq, hash)))
        }
        _ => Err(Error::MalformedAtRest("membership cut option")),
    }
}

fn target_row(
    writer: &Write<'_, '_>,
    table: Table,
    target: &Digest32,
    after: Option<Digest32>,
) -> Result<Option<(Digest32, u64)>> {
    let mut key = hash_key(target);
    let row = match after {
        Some(hash) => {
            key[32..].copy_from_slice(&hash);
            writer.first(table, Some(key))?
        }
        None => writer.at_or_after(table, key)?,
    };
    row.filter(|(key, _)| key[..32] == target[..])
        .map(|(key, log)| {
            Ok((
                key[32..]
                    .try_into()
                    .map_err(|_| Error::MalformedAtRest("membership source hash"))?,
                log,
            ))
        })
        .transpose()
}

/// Resolve removal/readmission status in an action's strict causal past.
/// One step inspects at most one signed removal or readmission.
pub(super) struct PastMembership {
    action: Digest32,
    target: Digest32,
    content: bool,
    bound: Option<Digest32>,
    after_removal: Option<Digest32>,
    removal: Option<Digest32>,
    after_readmission: Option<Digest32>,
}

impl PastMembership {
    pub(super) fn new(action: Digest32, target: Digest32) -> Self {
        Self {
            action,
            target,
            content: false,
            bound: None,
            after_removal: None,
            removal: None,
            after_readmission: None,
        }
    }

    pub(super) fn for_content(entry: Digest32, target: Digest32) -> Self {
        let mut state = Self::new(entry, target);
        state.content = true;
        state
    }

    pub(super) fn content_in_past(entry: Digest32, target: Digest32, bound: Digest32) -> Self {
        let mut state = Self::for_content(entry, target);
        state.bound = Some(bound);
        state
    }

    pub(super) fn write(&self, e: &mut Encoder) {
        e.array(7)
            .bytes(&self.action)
            .bytes(&self.target)
            .uint(u64::from(self.content));
        option_hash(e, self.bound);
        option_hash(e, self.after_removal);
        option_hash(e, self.removal);
        option_hash(e, self.after_readmission);
    }

    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 7 {
            return Err(Error::MalformedAtRest("past membership cursor arity"));
        }
        let action = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("past membership action"))?;
        let target = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("past membership target"))?;
        let content = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(Error::MalformedAtRest("membership cursor mode")),
        };
        let bound = read_option_hash(d)?;
        let after_removal = read_option_hash(d)?;
        let removal = read_option_hash(d)?;
        let after_readmission = read_option_hash(d)?;
        if removal.is_none() && after_readmission.is_some() {
            return Err(Error::MalformedAtRest("past membership cursor bounds"));
        }
        Ok(Self {
            action,
            target,
            content,
            bound,
            after_removal,
            removal,
            after_readmission,
        })
    }

    pub(super) fn advance(
        &mut self,
        writer: &Write<'_, '_>,
        generation: u64,
    ) -> Result<Option<bool>> {
        if writer
            .get(Table::Complete, &hash_key(&self.action))?
            .is_none()
            || writer
                .get(Table::Incomplete, &hash_key(&self.action))?
                .is_some()
        {
            return Ok(Some(false));
        }
        if let Some(removal) = self.removal {
            let Some((hash, log)) = target_row(
                writer,
                Table::MemberReadmissions,
                &self.target,
                self.after_readmission,
            )?
            else {
                return Ok(Some(false));
            };
            self.after_readmission = Some(hash);
            if writer.get(Table::MemberDecisions, &hash_key(&hash))? != Some(generation) {
                return Ok(None);
            }
            let entry = writer.entry(log)?;
            let GovBody::MemberReadmission(body) = GovEntry::body_bound_to(&entry)? else {
                return Err(Error::MalformedAtRest("past membership readmission kind"));
            };
            if body.target_id == self.target
                && body.removal_entry_hashes.binary_search(&removal).is_ok()
                && Scope(Some(self.action)).contains(writer, &entry)?
            {
                self.removal = None;
                self.after_readmission = None;
            }
            return Ok(None);
        }
        let Some((hash, log)) = target_row(
            writer,
            Table::MemberRemovals,
            &self.target,
            self.after_removal,
        )?
        else {
            return Ok(Some(true));
        };
        self.after_removal = Some(hash);
        if writer.get(Table::MemberDecisions, &hash_key(&hash))? != Some(generation) {
            return Ok(None);
        }
        let entry = writer.entry(log)?;
        if let Some(bound) = self.bound {
            if writer.get(Table::Complete, &hash_key(&bound))?.is_none()
                || !Scope(Some(bound)).contains(writer, &entry)?
            {
                return Ok(None);
            }
        }
        let applies = if self.content {
            let Some(action_log) = writer.evidence_locator(&self.action)? else {
                return Ok(Some(false));
            };
            let action = writer.entry(action_log)?;
            !Scope(Some(hash)).contains(writer, &action)?
        } else {
            Scope(Some(self.action)).contains(writer, &entry)?
        };
        if applies {
            self.removal = Some(hash);
            self.after_readmission = None;
        }
        Ok(None)
    }
}

/// Incremental strict-past membership and own signed leave/return check for a
/// delegated governance act. A receiver's current roster is not authority.
pub(super) struct DelegatedMembership {
    action: Digest32,
    author: Digest32,
    stage: u64,
    past: Option<PastMembership>,
    before: Option<u64>,
    candidate: u64,
}

impl DelegatedMembership {
    pub(super) fn new(action: Digest32, author: Digest32) -> Self {
        Self {
            action,
            author,
            stage: 0,
            past: None,
            before: None,
            candidate: 0,
        }
    }

    pub(super) fn write(&self, e: &mut Encoder) {
        e.array(6)
            .bytes(&self.action)
            .bytes(&self.author)
            .uint(self.stage);
        match &self.past {
            Some(v) => {
                e.array(1);
                v.write(e);
            }
            None => {
                e.array(0);
            }
        }
        match self.before {
            Some(v) => {
                e.array(1).uint(v);
            }
            None => {
                e.array(0);
            }
        }
        e.uint(self.candidate);
    }

    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        if d.array()? != 6 {
            return Err(Error::MalformedAtRest("delegated membership cursor"));
        }
        let action = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("membership action"))?;
        let author = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("membership author"))?;
        let stage = d.uint()?;
        let past = match d.array()? {
            0 => None,
            1 => Some(PastMembership::read(d)?),
            _ => return Err(Error::MalformedAtRest("membership past cursor")),
        };
        let before = match d.array()? {
            0 => None,
            1 => Some(d.uint()?),
            _ => return Err(Error::MalformedAtRest("membership presence cursor")),
        };
        let candidate = d.uint()?;
        if stage > 2 || (stage == 2 && candidate == 0) {
            return Err(Error::MalformedAtRest("delegated membership bounds"));
        }
        Ok(Self {
            action,
            author,
            stage,
            past,
            before,
            candidate,
        })
    }

    pub(super) fn advance(
        &mut self,
        writer: &Write<'_, '_>,
        generation: u64,
    ) -> Result<Option<bool>> {
        if self.stage == 0 {
            let past = self
                .past
                .get_or_insert_with(|| PastMembership::new(self.action, self.author));
            if let Some(valid) = past.advance(writer, generation)? {
                if !valid {
                    return Ok(Some(false));
                }
                self.past = None;
                self.stage = 1;
            }
            return Ok(None);
        }
        if self.stage == 2 {
            let entry = writer.entry(self.candidate)?;
            let past = self.past.get_or_insert_with(|| {
                PastMembership::content_in_past(entry.entry_hash(), self.author, self.action)
            });
            if let Some(eligible) = past.advance(writer, generation)? {
                self.past = None;
                self.candidate = 0;
                self.stage = 1;
                if eligible {
                    let GovBody::Presence(body) = GovEntry::body_bound_to(&entry)? else {
                        return Err(Error::MalformedAtRest("delegated presence kind"));
                    };
                    return Ok(Some(body.body.here));
                }
            }
            return Ok(None);
        }
        let action_log = writer
            .evidence_locator(&self.action)?
            .ok_or(Error::MalformedAtRest("delegated action missing"))?;
        let action = writer.entry(action_log)?;
        if !writer.fork_prefix_available(&action)? {
            return Ok(Some(false));
        }
        let before = self.before.unwrap_or(action.skeleton.seq);
        let row = writer.last(
            Table::Positions,
            Some(super::facts::position(&self.author, before)),
        )?;
        let Some((_, log)) = row.filter(|(key, _)| key[..32] == self.author[..]) else {
            return Ok(Some(true));
        };
        let entry = writer.entry(log)?;
        self.before = Some(entry.skeleton.seq);
        if writer.fork_safe(&entry)?
            && Scope(Some(self.action)).contains(writer, &entry)?
            && matches!(GovEntry::body_bound_to(&entry)?, GovBody::Presence(_))
        {
            if writer
                .get(Table::Incomplete, &hash_key(&entry.entry_hash()))?
                .is_some()
            {
                return Ok(Some(false));
            }
            self.candidate = log;
            self.stage = 2;
        }
        Ok(None)
    }
}

// The membership cursor is persisted separately from the display fold. One
// advance inspects at most one indexed fact or one authority-query step.
struct MembershipFold {
    generation: u64,
    ordered: u64,
    phase: u64,
    rank: u64,
    after: Option<[u8; 64]>,
    log: u64,
    stage: u64,
    query: Option<super::authority::Query>,
    cutoff: Option<super::authority::RootCutoff>,
    past: Option<PastMembership>,
    readmission: Option<ReadmissionValidation>,
    presence_before: Option<u64>,
    presence_log: u64,
    deadline: u64,
    target: Option<Digest32>,
    removal: Option<Digest32>,
    after_readmission: Option<Digest32>,
    removed: bool,
    /// Earliest covering creator readmission of the current validated removal (#1171).
    removal_cut: Option<(u64, Digest32)>,
    /// Latest of those earliest cuts across the current target's validated removals.
    target_cut: Option<(u64, Digest32)>,
    /// Latest readmitted target cut so far in this pass, for the one bounded room row.
    room_cut: Option<(u64, Digest32)>,
    changed: bool,
    pass_changed: bool,
}

impl MembershipFold {
    fn new(writer: &Write<'_, '_>) -> Self {
        Self {
            generation: writer.authority_generation(),
            ordered: writer.ordered(),
            phase: 0,
            rank: 0,
            after: None,
            log: 0,
            stage: 0,
            query: None,
            cutoff: None,
            past: None,
            readmission: None,
            presence_before: None,
            presence_log: 0,
            deadline: 0,
            target: None,
            removal: None,
            after_readmission: None,
            removed: false,
            removal_cut: None,
            target_cut: None,
            room_cut: None,
            changed: false,
            pass_changed: false,
        }
    }

    fn load(writer: &Write<'_, '_>) -> Result<Self> {
        let Some(bytes) = writer.cursor(super::facts::Cursor::Membership)? else {
            return Ok(Self::new(writer));
        };
        let mut d = Decoder::new(&bytes);
        let (arity, version) = (d.array()?, d.uint()?);
        if !matches!((arity, version), (20, 1) | (21, 2 | 3) | (24, 4)) {
            return Err(Error::MalformedAtRest("membership fold cursor format"));
        }
        let generation = d.uint()?;
        let ordered = d.uint()?;
        let phase = d.uint()?;
        let rank = d.uint()?;
        let after = match d.array()? {
            0 => None,
            1 => Some(
                d.bytes()?
                    .try_into()
                    .map_err(|_| Error::MalformedAtRest("membership cursor key"))?,
            ),
            _ => return Err(Error::MalformedAtRest("membership cursor key option")),
        };
        let log = d.uint()?;
        let stage = d.uint()?;
        let query = match d.array()? {
            0 => None,
            1 if version >= 3 => Some(super::authority::Query::read(&mut d)?),
            1 => {
                super::context::CachedQuery::read(&mut d)?;
                None
            }
            _ => return Err(Error::MalformedAtRest("membership query option")),
        };
        let cutoff = match d.array()? {
            0 => None,
            1 => Some(super::authority::RootCutoff::read(&mut d)?),
            _ => return Err(Error::MalformedAtRest("membership cutoff option")),
        };
        let past = match d.array()? {
            0 => None,
            1 => Some(PastMembership::read(&mut d)?),
            _ => return Err(Error::MalformedAtRest("membership past option")),
        };
        let readmission = match d.array()? {
            0 => None,
            1 => Some(ReadmissionValidation::read(&mut d)?),
            _ => return Err(Error::MalformedAtRest("membership readmission option")),
        };
        let presence_before = match d.array()? {
            0 => None,
            1 => Some(d.uint()?),
            _ => return Err(Error::MalformedAtRest("membership presence cursor")),
        };
        let presence_log = d.uint()?;
        let deadline = d.uint()?;
        let target = read_option_hash(&mut d)?;
        let removal = read_option_hash(&mut d)?;
        let after_readmission = read_option_hash(&mut d)?;
        let removed = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(Error::MalformedAtRest("membership removed flag")),
        };
        let changed = match d.uint()? {
            0 => false,
            1 => true,
            _ => return Err(Error::MalformedAtRest("membership changed flag")),
        };
        let pass_changed = if version >= 2 {
            match d.uint()? {
                0 => false,
                1 => true,
                _ => return Err(Error::MalformedAtRest("membership pass flag")),
            }
        } else {
            false
        };
        let (removal_cut, target_cut, room_cut) = if version >= 4 {
            (
                read_option_cut(&mut d)?,
                read_option_cut(&mut d)?,
                read_option_cut(&mut d)?,
            )
        } else {
            (None, None, None)
        };
        d.finish()?;
        if phase > 4 || stage > 4 || generation == 0 {
            return Err(Error::MalformedAtRest("membership fold cursor bounds"));
        }
        // Format 3 predates the recipient-cut projection: its rows must be refolded.
        if version < 4 || generation != writer.authority_generation() || ordered != writer.ordered()
        {
            let mut fresh = Self::new(writer);
            // Earlier turns may already have written membership rows. A finished legacy
            // cursor can retain its old flag, but has no unfinished rotation obligation.
            fresh.changed = changed && phase != 3;
            return Ok(fresh);
        }
        Ok(Self {
            generation,
            ordered,
            phase,
            rank,
            after,
            log,
            stage,
            query,
            cutoff,
            past,
            readmission,
            presence_before,
            presence_log,
            deadline,
            target,
            removal,
            after_readmission,
            removed,
            removal_cut,
            target_cut,
            room_cut,
            changed,
            pass_changed,
        })
    }

    fn save(&self, writer: &mut Write<'_, '_>) -> Result<()> {
        let mut e = Encoder::new();
        e.array(24)
            .uint(4)
            .uint(self.generation)
            .uint(self.ordered)
            .uint(self.phase)
            .uint(self.rank);
        match self.after {
            Some(key) => {
                e.array(1).bytes(&key);
            }
            None => {
                e.array(0);
            }
        }
        e.uint(self.log).uint(self.stage);
        match &self.query {
            Some(v) => {
                e.array(1);
                v.write(&mut e);
            }
            None => {
                e.array(0);
            }
        }
        match &self.cutoff {
            Some(v) => {
                e.array(1);
                v.write(&mut e);
            }
            None => {
                e.array(0);
            }
        }
        match &self.past {
            Some(v) => {
                e.array(1);
                v.write(&mut e);
            }
            None => {
                e.array(0);
            }
        }
        match &self.readmission {
            Some(v) => {
                e.array(1);
                v.write(&mut e);
            }
            None => {
                e.array(0);
            }
        }
        match self.presence_before {
            Some(v) => {
                e.array(1).uint(v);
            }
            None => {
                e.array(0);
            }
        }
        e.uint(self.presence_log).uint(self.deadline);
        option_hash(&mut e, self.target);
        option_hash(&mut e, self.removal);
        option_hash(&mut e, self.after_readmission);
        e.uint(u64::from(self.removed))
            .uint(u64::from(self.changed))
            .uint(u64::from(self.pass_changed));
        option_cut(&mut e, self.removal_cut);
        option_cut(&mut e, self.target_cut);
        option_cut(&mut e, self.room_cut);
        writer.save_cursor(super::facts::Cursor::Membership, &e.finish())
    }

    fn clear_action(&mut self) {
        self.log = 0;
        self.stage = 0;
        self.query = None;
        self.cutoff = None;
        self.past = None;
        self.readmission = None;
        self.presence_before = None;
        self.presence_log = 0;
    }

    fn decide(&mut self, writer: &mut Write<'_, '_>, hash: &Digest32, valid: bool) -> Result<()> {
        let current = writer.get(Table::MemberDecisions, &hash_key(hash))? == Some(self.generation);
        self.pass_changed |= current != valid;
        let was_valid = writer
            .get(Table::MemberDecisions, &hash_key(hash))?
            .is_some();
        self.changed |= was_valid != valid;
        if valid {
            let entry = writer.entry(self.log)?;
            if let GovBody::MemberRemoval(body) = GovEntry::body_bound_to(&entry)? {
                writer.record_sender_cut(hash, &body.target_id)?;
            }
        }
        writer.put(
            Table::MemberDecisions,
            hash_key(hash),
            valid.then_some(self.generation),
        )?;
        self.clear_action();
        Ok(())
    }
}

/// Advance one durable membership decision or publication step.
/// Returns completion with no expiry deadline for non-expiring removal authority.
pub(super) fn advance(writer: &mut Write<'_, '_>, root: &Digest32) -> Result<Option<u64>> {
    use super::canonical::{rank_from, rank_key};
    use super::facts::position;
    let mut state = MembershipFold::load(writer)?;
    match state.phase {
        // Root removals are independent of delegated authority. Index all of them
        // first so a concurrent root cutoff cannot depend on presentation order.
        0 => {
            if let Some((key, log)) = writer.first(Table::MemberRemovals, state.after)? {
                state.after = Some(key);
                let entry = writer.entry(log)?;
                let GovBody::MemberRemoval(body) = GovEntry::body_bound_to(&entry)? else {
                    return Err(Error::MalformedAtRest("membership removal locator"));
                };
                if entry.skeleton.author_id == *root {
                    let valid = body.issuer_id == *root
                        && body.target_id != *root
                        && body.epoch == 0
                        && writer
                            .get(Table::Complete, &hash_key(&entry.entry_hash()))?
                            .is_some()
                        && writer
                            .get(Table::Incomplete, &hash_key(&entry.entry_hash()))?
                            .is_none();
                    let fact_key = hash_key(&entry.entry_hash());
                    if valid {
                        writer.record_sender_cut(&entry.entry_hash(), &body.target_id)?;
                    }
                    state.changed |=
                        writer.get(Table::MemberDecisions, &fact_key)?.is_some() != valid;
                    writer.put(
                        Table::MemberDecisions,
                        fact_key,
                        valid.then_some(state.generation),
                    )?;
                }
            } else {
                state.phase = 1;
                state.after = None;
            }
        }
        1 | 4 => {
            if state.log == 0 {
                let log = if state.phase == 1 {
                    let Some((key, log)) =
                        writer.first(Table::Order, Some(rank_key(state.rank)))?
                    else {
                        state.phase = 4;
                        state.after = None;
                        state.save(writer)?;
                        return Ok(None);
                    };
                    state.rank = rank_from(&key)?;
                    log
                } else {
                    let Some((key, _)) = writer.first(Table::ForkExclusions, state.after)? else {
                        if state.pass_changed {
                            state.pass_changed = false;
                            state.phase = 1;
                            state.rank = 0;
                        } else {
                            state.phase = 2;
                        }
                        state.after = None;
                        state.save(writer)?;
                        return Ok(None);
                    };
                    state.after = Some(key);
                    let hash: Digest32 = key[..32]
                        .try_into()
                        .map_err(|_| Error::MalformedAtRest("fork membership hash"))?;
                    let Some(log) = writer.evidence_locator(&hash)? else {
                        state.save(writer)?;
                        return Ok(None);
                    };
                    log
                };
                let entry = writer.entry(log)?;
                if !matches!(
                    GovEntry::body_bound_to(&entry)?,
                    GovBody::MemberRemoval(_) | GovBody::MemberReadmission(_)
                ) {
                    state.save(writer)?;
                    return Ok(None);
                }
                state.log = log;
            }
            let entry = writer.entry(state.log)?;
            let hash = entry.entry_hash();
            let body = GovEntry::body_bound_to(&entry)?;
            match body {
                GovBody::MemberReadmission(_) => {
                    let validation = state
                        .readmission
                        .get_or_insert_with(|| ReadmissionValidation::new(hash));
                    if let Some(valid) = validation.advance(writer, root, state.generation)? {
                        state.decide(writer, &hash, valid)?;
                    }
                }
                GovBody::MemberRemoval(body) => {
                    if entry.skeleton.author_id == *root {
                        state.clear_action();
                    } else if body.epoch != 0
                        || body.target_id == *root
                        || writer.get(Table::Complete, &hash_key(&hash))?.is_none()
                        || writer.get(Table::Incomplete, &hash_key(&hash))?.is_some()
                        || !writer.fork_prefix_available(&entry)?
                    {
                        state.decide(writer, &hash, false)?;
                    } else if state.stage == 0 {
                        let query = state.query.get_or_insert_with(|| {
                            super::authority::Query::new(Scope(Some(hash)), body.issuer_id)
                        });
                        // Non-expiring removal authority is a signed causal fact, not a
                        // wall-clock query. Keep it outside the shared timed grant cache.
                        if let Some(grant) = query.advance(writer, root, 0, state.generation)? {
                            let grants_policy = grant.grants_policy();
                            #[cfg(feature = "test-knobs")]
                            let grants_policy = grants_policy
                                || std::env::var("VOX_TEST_FX62_MUTANT").as_deref()
                                    == Ok("nonadmin-remove");
                            if !grants_policy || grant.expiry != 0 {
                                state.decide(writer, &hash, false)?;
                            } else {
                                state.query = None;
                                state.stage = 1;
                            }
                        }
                    } else if state.stage == 1 {
                        let cutoff = state.cutoff.get_or_insert_with(|| {
                            super::authority::RootCutoff::new(hash, body.issuer_id)
                        });
                        if let Some(valid) = cutoff.advance(writer, root, state.generation)? {
                            if valid {
                                state.cutoff = None;
                                state.stage = 2;
                            } else {
                                state.decide(writer, &hash, false)?;
                            }
                        }
                    } else if state.stage == 2 {
                        let past = state
                            .past
                            .get_or_insert_with(|| PastMembership::new(hash, body.issuer_id));
                        if let Some(valid) = past.advance(writer, state.generation)? {
                            if valid {
                                state.past = None;
                                state.stage = 3;
                            } else {
                                state.decide(writer, &hash, false)?;
                            }
                        }
                    } else if state.presence_log != 0 {
                        let presence = writer.entry(state.presence_log)?;
                        let past = state.past.get_or_insert_with(|| {
                            PastMembership::content_in_past(
                                presence.entry_hash(),
                                body.issuer_id,
                                hash,
                            )
                        });
                        if let Some(eligible) = past.advance(writer, state.generation)? {
                            state.past = None;
                            state.presence_log = 0;
                            if eligible {
                                let GovBody::Presence(presence) =
                                    GovEntry::body_bound_to(&presence)?
                                else {
                                    return Err(Error::MalformedAtRest(
                                        "membership presence locator",
                                    ));
                                };
                                state.decide(writer, &hash, presence.body.here)?;
                            }
                        }
                    } else {
                        let before = state.presence_before.unwrap_or(entry.skeleton.seq);
                        let row = writer
                            .last(Table::Positions, Some(position(&body.issuer_id, before)))?;
                        if let Some((_key, log)) =
                            row.filter(|(key, _)| key[..32] == body.issuer_id[..])
                        {
                            let candidate = writer.entry(log)?;
                            state.presence_before = Some(candidate.skeleton.seq);
                            if writer.fork_safe(&candidate)?
                                && Scope(Some(hash)).contains(writer, &candidate)?
                                && matches!(
                                    GovEntry::body_bound_to(&candidate)?,
                                    GovBody::Presence(_)
                                )
                            {
                                if writer
                                    .get(Table::Incomplete, &hash_key(&candidate.entry_hash()))?
                                    .is_some()
                                {
                                    state.decide(writer, &hash, false)?;
                                    state.save(writer)?;
                                    return Ok(None);
                                }
                                state.presence_log = log;
                            }
                        } else {
                            // No signed leave in the issuer's own past.
                            state.decide(writer, &hash, true)?;
                        }
                    }
                }
                _ => return Err(Error::MalformedAtRest("membership fold action")),
            }
        }
        2 => current_step(writer, &mut state)?,
        3 => return Ok(Some(state.deadline)),
        _ => return Err(Error::MalformedAtRest("membership fold phase")),
    }
    state.save(writer)?;
    Ok((state.phase == 3).then_some(state.deadline))
}

fn current_step(writer: &mut Write<'_, '_>, state: &mut MembershipFold) -> Result<()> {
    if let (Some(target), Some(removal)) = (state.target, state.removal) {
        if let Some((hash, log)) = target_row(
            writer,
            Table::MemberReadmissions,
            &target,
            state.after_readmission,
        )? {
            state.after_readmission = Some(hash);
            if writer.get(Table::MemberDecisions, &hash_key(&hash))? == Some(state.generation) {
                let entry = writer.entry(log)?;
                let GovBody::MemberReadmission(body) = GovEntry::body_bound_to(&entry)? else {
                    return Err(Error::MalformedAtRest("current membership readmission"));
                };
                // Every covering readmission is inspected: the earliest creator position is
                // this removal's cut, so a later duplicate cannot hide already-eligible bodies.
                let candidate = (entry.skeleton.seq, hash);
                if body.removal_entry_hashes.binary_search(&removal).is_ok()
                    && state
                        .removal_cut
                        .is_none_or(|earliest| candidate < earliest)
                {
                    state.removal_cut = Some(candidate);
                }
            }
            return Ok(());
        }
        state.removal = None;
        state.after_readmission = None;
        if let Some(cut) = state.removal_cut.take() {
            state.target_cut = state.target_cut.max(Some(cut));
        } else {
            state.removed = true;
            let mut last = hash_key(&target);
            last[32..].fill(u8::MAX);
            state.after = Some(last);
        }
    }
    let next = writer.first(Table::MemberRemovals, state.after)?;
    let next_target: Option<Digest32> = next
        .as_ref()
        .map(|(key, _)| {
            key[..32]
                .try_into()
                .map_err(|_| Error::MalformedAtRest("current membership target"))
        })
        .transpose()?;
    if let Some(target) = state.target {
        if next_target != Some(target) {
            let key = hash_key(&target);
            let old = writer.get(Table::CurrentRemoved, &key)?.is_some();
            state.changed |= old != state.removed;
            writer.put(
                Table::CurrentRemoved,
                key,
                state.removed.then_some(state.generation),
            )?;
            let cut = if state.removed {
                RecipientCutState::Removed
            } else if let Some((_, hash)) = state.target_cut {
                RecipientCutState::After(hash)
            } else {
                RecipientCutState::NotRemoved
            };
            let old = writer.get(Table::RecipientCuts, &key)?;
            let previous = old
                .map(|record| read_recipient_cut(&writer.record(record)?))
                .transpose()?;
            // A first projection write is migration, not a membership change: removal,
            // readmission and CurrentRemoved transitions already mark a real one.
            state.changed |= previous.is_some_and(|(_, previous)| previous != cut);
            let record = writer.save_record(old, &write_recipient_cut(state.generation, &cut))?;
            writer.put(Table::RecipientCuts, key, Some(record))?;
            if !state.removed {
                state.room_cut = state.room_cut.max(state.target_cut);
            }
            state.target = None;
            state.removed = false;
            state.target_cut = None;
            return Ok(());
        }
    }
    let Some((key, _)) = next else {
        // One bounded room row: the latest cut on the creator's single chain. Containing it
        // contains every target's cut, so local authoring names one required ancestor.
        let key = super::view::ROOM_CUT_KEY;
        let cut = match state.room_cut {
            Some((_, hash)) => RecipientCutState::After(hash),
            None => RecipientCutState::NotRemoved,
        };
        let old = writer.get(Table::RecipientCuts, &key)?;
        let record = writer.save_record(old, &write_recipient_cut(state.generation, &cut))?;
        writer.put(Table::RecipientCuts, key, Some(record))?;
        state.room_cut = None;
        if state.changed {
            writer.advance_removal_generation()?;
            writer.display_changed()?;
            state.changed = false;
        }
        writer.start_eligibility_replay()?;
        state.phase = 3;
        return Ok(());
    };
    let target = next_target.ok_or(Error::MalformedAtRest("current membership target missing"))?;
    state.target = Some(target);
    state.after = Some(key);
    let hash: Digest32 = key[32..]
        .try_into()
        .map_err(|_| Error::MalformedAtRest("current membership removal hash"))?;
    if writer.get(Table::MemberDecisions, &hash_key(&hash))? == Some(state.generation) {
        state.removal = Some(hash);
        state.after_readmission = None;
    }
    Ok(())
}

/// Advance at most one causal eligibility decision step. Source replay has a
/// fixed receipt tail; later appends are independently queued at frontier completion.
pub(super) fn advance_eligibility(writer: &mut Write<'_, '_>) -> Result<bool> {
    use super::facts::Cursor;
    if writer.eligibility_replaying() {
        return Ok(false);
    }
    let generation = writer.authority_generation();
    let saved = writer.cursor(Cursor::Eligibility)?;
    let (log, serial, hash, mut stage, mut past) = if let Some(bytes) = saved {
        let mut d = Decoder::new(&bytes);
        let arity = d.array()?;
        let version = d.uint()?;
        if !matches!((version, arity), (1, 6) | (2, 7)) {
            return Err(Error::MalformedAtRest("eligibility cursor format"));
        }
        let old_generation = d.uint()?;
        let log = d.uint()?;
        let serial = d.uint()?;
        let hash: Digest32 = d
            .bytes()?
            .try_into()
            .map_err(|_| Error::MalformedAtRest("eligibility cursor hash"))?;
        let stage = if version == 2 { d.uint()? } else { 0 };
        if stage > 1 {
            return Err(Error::MalformedAtRest("eligibility cursor stage"));
        }
        let past = PastMembership::read(&mut d)?;
        d.finish()?;
        if old_generation != generation {
            writer.clear_cursor(Cursor::Eligibility)?;
            return Ok(true);
        }
        (log, serial, hash, stage, past)
    } else {
        let Some((key, log)) = writer.first(Table::EligibilityOrder, None)? else {
            return Ok(false);
        };
        let hash: Digest32 = key[8..40]
            .try_into()
            .map_err(|_| Error::MalformedAtRest("eligibility queue hash"))?;
        if writer.get(Table::EligibilityPending, &hash_key(&hash))? != Some(log) {
            return Err(Error::MalformedAtRest("eligibility queue binding"));
        }
        let Some(serial) = writer.get(Table::Complete, &hash_key(&hash))? else {
            writer.finish_eligibility(&hash, log)?;
            return Ok(true);
        };
        let entry = writer.entry(log)?;
        if entry.entry_hash() != hash {
            return Err(Error::MalformedAtRest("eligibility source binding"));
        }
        (
            log,
            serial,
            hash,
            0,
            PastMembership::for_content(hash, entry.skeleton.author_id),
        )
    };
    if writer.get(Table::Pending, &hash_key(&hash))?.is_some()
        || writer.get(Table::Incomplete, &hash_key(&hash))?.is_some()
    {
        writer.finish_eligibility(&hash, log)?;
        writer.clear_cursor(Cursor::Eligibility)?;
        return Ok(true);
    }
    if writer.get(Table::Complete, &hash_key(&hash))? != Some(serial) {
        // A newer completed frontier already requeued the same source. Keep
        // that obligation and restart against its new serial next turn.
        writer.clear_cursor(Cursor::Eligibility)?;
        return Ok(true);
    }
    if let Some(eligible) = past.advance(writer, generation)? {
        let key = hash_key(&hash);
        let table = if stage == 0 {
            Table::EligibilityDecisions
        } else {
            Table::FloorRecipientDecisions
        };
        let old = writer.get(table, &key)?;
        let mut e = Encoder::new();
        e.array(3)
            .uint(1)
            .uint(generation)
            .uint(u64::from(eligible));
        let record = writer.save_record(old, &e.finish())?;
        writer.put(table, key, Some(record))?;
        if stage == 0 {
            let entry = writer.entry(log)?;
            if let Some(floor) = entry
                .payload
                .as_deref()
                .and_then(super::super::session_floor::Floor::read)
                .filter(|floor| {
                    floor.room == entry.skeleton.channel_id
                        && floor.author == entry.skeleton.author_id
                        && floor.epoch == entry.skeleton.epoch
                })
            {
                stage = 1;
                past = PastMembership::for_content(hash, floor.recipient);
            } else {
                writer.finish_eligibility(&hash, log)?;
                writer.clear_cursor(Cursor::Eligibility)?;
                return Ok(true);
            }
        } else {
            writer.finish_eligibility(&hash, log)?;
            writer.clear_cursor(Cursor::Eligibility)?;
            return Ok(true);
        }
    }
    let mut e = Encoder::new();
    e.array(7)
        .uint(2)
        .uint(generation)
        .uint(log)
        .uint(serial)
        .bytes(&hash)
        .uint(stage);
    past.write(&mut e);
    writer.save_cursor(Cursor::Eligibility, &e.finish())?;
    Ok(true)
}
