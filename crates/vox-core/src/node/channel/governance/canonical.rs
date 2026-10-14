//! The governance Kahn order, advanced a bounded part at a time.
//!
//! There is one candidate per admitted author. A candidate waits on one exact
//! predecessor; emitting that predecessor wakes it to check the next coordinate.
//! Old canonical prefixes remain usable for the calculation, but no authority
//! reader may use a partially rewritten suffix.

use super::facts::{Cursor, Table, Write, hash_key, position};
use crate::cbor::{Decoder, Encoder};
use crate::error::{Error, Result};
use crate::hash::Digest32;
use zeroize::Zeroizing;

const WORK: usize = 64;
const IDLE: u64 = 0;
const PLAN: u64 = 1;
const CLEAR: u64 = 2;
const INIT: u64 = 3;
const CHECK: u64 = 4;
const WAKE: u64 = 5;
const TRIM: u64 = 6;

fn invalid(why: &'static str) -> Error {
    Error::MalformedAtRest(why)
}

pub(super) fn rank_key(rank: u64) -> [u8; 64] {
    let mut key = [0; 64];
    key[..8].copy_from_slice(&rank.to_be_bytes());
    key
}

pub(super) fn rank_from(key: &[u8; 64]) -> Result<u64> {
    if key[8..].iter().any(|b| *b != 0) {
        return Err(invalid("governance rank padding"));
    }
    let rank = u64::from_be_bytes(
        key[..8]
            .try_into()
            .map_err(|_| invalid("governance rank"))?,
    );
    if rank == 0 {
        return Err(invalid("governance rank is zero"));
    }
    Ok(rank)
}

fn joined(left: &Digest32, right: &Digest32) -> [u8; 64] {
    let mut key = [0; 64];
    key[..32].copy_from_slice(left);
    key[32..].copy_from_slice(right);
    key
}

fn hash_from(key: &[u8; 64]) -> Result<Digest32> {
    if key[32..].iter().any(|b| *b != 0) {
        return Err(invalid("governance hash padding"));
    }
    key[..32].try_into().map_err(|_| invalid("governance hash"))
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
                .map_err(|_| invalid("governance order cursor hash"))?,
        )),
        _ => Err(invalid("governance order cursor hash arity")),
    }
}

#[derive(Default)]
struct State {
    phase: u64,
    /// First rank whose old prefix cannot be reused; zero means not chosen yet.
    cut: u64,
    next: u64,
    author: Option<Digest32>,
    item: Option<Digest32>,
    after: Option<Digest32>,
    maximum: u64,
    /// Exact causal-input version for a partly inspected frontier.
    revision: u64,
}

impl State {
    fn load(writer: &Write<'_>) -> Result<Self> {
        let Some(bytes) = writer.cursor(Cursor::Canonical)? else {
            return Ok(Self::default());
        };
        let mut d = Decoder::new(&bytes);
        if d.array()? != 9 || d.uint()? != 1 {
            return Err(invalid("governance order cursor format"));
        }
        let state = Self {
            phase: d.uint()?,
            cut: d.uint()?,
            next: d.uint()?,
            author: read_option(&mut d)?,
            item: read_option(&mut d)?,
            after: read_option(&mut d)?,
            maximum: d.uint()?,
            revision: d.uint()?,
        };
        d.finish()?;
        if state.phase > TRIM || (state.phase >= INIT && (state.cut == 0 || state.next < state.cut))
        {
            return Err(invalid("governance order cursor bounds"));
        }
        Ok(state)
    }

    fn save(&self, writer: &mut Write<'_>) -> Result<()> {
        let mut e = Encoder::new();
        e.array(9)
            .uint(1)
            .uint(self.phase)
            .uint(self.cut)
            .uint(self.next);
        option(&mut e, self.author);
        option(&mut e, self.item);
        option(&mut e, self.after);
        e.uint(self.maximum).uint(self.revision);
        writer.save_cursor(Cursor::Canonical, &Zeroizing::new(e.finish()))
    }

    fn clear_item(&mut self) {
        self.item = None;
        self.after = None;
        self.maximum = 0;
    }
    fn lower_cut(&mut self, cut: u64) {
        self.cut = if self.cut == 0 {
            cut
        } else {
            self.cut.min(cut)
        };
    }
}

/// A locator belongs to the retained prefix only when both directions agree.
/// A suffix overwrite can leave an old hash rank until bounded trimming reaches
/// it; that old mapping must never look like an emitted predecessor.
fn held_rank(writer: &Write<'_>, hash: &Digest32, log: u64) -> Result<Option<u64>> {
    let Some(rank) = writer.get(Table::Ranks, &hash_key(hash))? else {
        return Ok(None);
    };
    Ok((writer.get(Table::Order, &rank_key(rank))? == Some(log)).then_some(rank))
}

/// Greatest governance sequence in a frontier. The entry's own position is
/// excluded, even though its inclusive causal vector contains that position.
fn predecessor(writer: &Write<'_>, author: &Digest32, seq: u64, own: bool) -> Result<Option<u64>> {
    let mut before = position(author, seq);
    if !own {
        before[40] = 1;
    } // immediately beyond this exact sequence's zero padding
    let row = writer.last(Table::Positions, Some(before))?;
    Ok(row
        .filter(|(key, _)| key[..32] == author[..])
        .map(|(_, log)| log))
}

fn next_author_entry(writer: &Write<'_>, author: &Digest32, seq: u64) -> Result<Option<u64>> {
    Ok(writer
        .first(Table::Positions, Some(position(author, seq)))?
        .filter(|(key, _)| key[..32] == author[..])
        .map(|(_, log)| log))
}

fn queue_check(writer: &mut Write<'_>, log: u64) -> Result<()> {
    let entry = writer.entry(log)?;
    writer.put(Table::Checks, hash_key(&entry.entry_hash()), Some(log))
}

/// One bounded continuation. `true` means the complete current Kahn order is
/// published; the evaluator must still finish its separate checked fold.
pub(super) fn advance(writer: &mut Write<'_>) -> Result<bool> {
    if !writer.causal_settled() {
        return Ok(false);
    }
    let mut state = State::load(writer)?;
    let dirty = writer.first(Table::Dirty, None)?.is_some();
    if dirty && state.phase == IDLE {
        state = State {
            phase: PLAN,
            revision: writer.revision(),
            ..State::default()
        };
    } else if dirty && state.phase > PLAN {
        // A new governance input during suffix work invalidates that unpublished
        // calculation. Keep no stale authority, and resume from a safe prefix.
        state = State {
            phase: PLAN,
            cut: 1,
            revision: writer.revision(),
            ..State::default()
        };
    } else if state.phase == PLAN && state.revision != writer.revision() {
        // A late parent can extend a frontier behind our saved author cursor.
        state.clear_item();
        state.revision = writer.revision();
    }
    match state.phase {
        IDLE => return Ok(true),
        PLAN => plan(writer, &mut state)?,
        CLEAR => clear(writer, &mut state)?,
        INIT => initialize(writer, &mut state)?,
        CHECK => check(writer, &mut state)?,
        WAKE => wake(writer, &mut state)?,
        TRIM => trim(writer, &mut state)?,
        _ => return Err(invalid("governance order phase")),
    }
    state.save(writer)?;
    Ok(state.phase == IDLE)
}

fn plan(writer: &mut Write<'_>, state: &mut State) -> Result<()> {
    if state.item.is_none() {
        let Some((key, log)) = writer.first(Table::Dirty, None)? else {
            if state.cut == 0 {
                state.phase = IDLE;
                return Ok(());
            }
            state.phase = CLEAR;
            state.next = state.cut;
            state.author = None;
            return Ok(());
        };
        let hash = hash_from(&key)?;
        if let Some(rank) = held_rank(writer, &hash, log)? {
            state.lower_cut(rank);
            writer.put(Table::Dirty, key, None)?;
            return Ok(());
        }
        state.item = Some(hash);
        state.after = None;
        state.maximum = 0;
    }
    let hash = state.item.ok_or(invalid("governance planning entry"))?;
    let log = writer
        .get(Table::Hashes, &hash_key(&hash))?
        .ok_or(invalid("governance planning locator"))?;
    let entry = writer.entry(log)?;
    for _ in 0..WORK {
        let Some((author, seq)) = writer.frontier_after(&hash, state.after)? else {
            state.lower_cut(
                state
                    .maximum
                    .checked_add(1)
                    .ok_or(invalid("governance rank exhausted"))?,
            );
            writer.put(Table::Dirty, hash_key(&hash), None)?;
            state.clear_item();
            return Ok(());
        };
        state.after = Some(author);
        if let Some(parent_log) =
            predecessor(writer, &author, seq, author == entry.skeleton.author_id)?
        {
            let parent = writer.entry(parent_log)?;
            match held_rank(writer, &parent.entry_hash(), parent_log)? {
                Some(rank) => state.maximum = state.maximum.max(rank),
                None => state.lower_cut(1),
            }
        }
    }
    Ok(())
}

fn clear(writer: &mut Write<'_>, state: &mut State) -> Result<()> {
    // At most one candidate per author, plus one blocker per candidate. Clearing
    // is paged too; a reset never collects their keys into an unbounded vector.
    for table in [Table::Checks, Table::Ready, Table::Blocked] {
        if let Some((key, _)) = writer.first(table, None)? {
            writer.put(table, key, None)?;
            return Ok(());
        }
    }
    state.phase = INIT;
    state.author = None;
    state.clear_item();
    Ok(())
}

fn initialize(writer: &mut Write<'_>, state: &mut State) -> Result<()> {
    let after = state.author.map(|author| {
        let mut key = hash_key(&author);
        key[32..].fill(u8::MAX);
        key
    });
    let Some((key, _)) = writer.first(Table::Positions, after)? else {
        state.phase = CHECK;
        state.author = None;
        return Ok(());
    };
    let author: Digest32 = key[..32]
        .try_into()
        .map_err(|_| invalid("governance author cursor"))?;
    let emitted = writer
        .last(Table::AuthorOrder, Some(position(&author, state.cut)))?
        .filter(|(key, _)| key[..32] == author[..])
        .map(|(_, seq)| seq)
        .unwrap_or(0);
    if let Some(log) = next_author_entry(writer, &author, emitted)? {
        queue_check(writer, log)?;
    }
    state.author = Some(author);
    Ok(())
}

fn check(writer: &mut Write<'_>, state: &mut State) -> Result<()> {
    if state.item.is_none() {
        match writer.first(Table::Checks, None)? {
            Some((key, _)) => state.item = Some(hash_from(&key)?),
            None => return emit(writer, state),
        }
    }
    let hash = state.item.ok_or(invalid("governance candidate missing"))?;
    let log = writer
        .get(Table::Checks, &hash_key(&hash))?
        .ok_or(invalid("governance candidate locator"))?;
    let entry = writer.entry(log)?;
    for _ in 0..WORK {
        let Some((author, seq)) = writer.frontier_after(&hash, state.after)? else {
            writer.put(Table::Ready, hash_key(&hash), Some(log))?;
            writer.put(Table::Checks, hash_key(&hash), None)?;
            state.clear_item();
            return Ok(());
        };
        state.after = Some(author);
        let Some(parent_log) =
            predecessor(writer, &author, seq, author == entry.skeleton.author_id)?
        else {
            continue;
        };
        let parent = writer.entry(parent_log)?;
        let parent_hash = parent.entry_hash();
        if held_rank(writer, &parent_hash, parent_log)?.is_some_and(|rank| rank < state.next) {
            continue;
        }
        writer.put(Table::Blocked, joined(&parent_hash, &hash), Some(log))?;
        writer.put(Table::Checks, hash_key(&hash), None)?;
        state.clear_item();
        return Ok(());
    }
    Ok(())
}

fn remove_old_rank(writer: &mut Write<'_>, rank: u64) -> Result<()> {
    let Some(log) = writer.get(Table::Order, &rank_key(rank))? else {
        return Ok(());
    };
    let old = writer.entry(log)?;
    let hash = old.entry_hash();
    if writer.get(Table::Ranks, &hash_key(&hash))? == Some(rank) {
        writer.put(Table::Ranks, hash_key(&hash), None)?;
    }
    writer.put(
        Table::AuthorOrder,
        position(&old.skeleton.author_id, rank),
        None,
    )?;
    writer.put(Table::AuthorityOrder, rank_key(rank), None)?;
    writer.put(Table::ActionOrder, rank_key(rank), None)?;
    writer.put(Table::Order, rank_key(rank), None)
}

fn emit(writer: &mut Write<'_>, state: &mut State) -> Result<()> {
    let Some((key, log)) = writer.first(Table::Ready, None)? else {
        if writer.first(Table::Blocked, None)?.is_some() {
            return Err(Error::GovernanceCycle);
        }
        state.phase = TRIM;
        return Ok(());
    };
    let hash = hash_from(&key)?;
    let entry = writer.entry(log)?;
    remove_old_rank(writer, state.next)?;
    writer.put(Table::Order, rank_key(state.next), Some(log))?;
    writer.put(Table::Ranks, key, Some(state.next))?;
    writer.put(
        Table::AuthorOrder,
        position(&entry.skeleton.author_id, state.next),
        Some(entry.skeleton.seq),
    )?;
    use crate::governance::entry::{GovBody, GovEntry};
    match GovEntry::body_bound_to(&entry)? {
        GovBody::AdminCert(_) | GovBody::AdminRevocation(_) => {
            writer.put(Table::AuthorityOrder, rank_key(state.next), Some(log))?;
        }
        GovBody::PolicyUpdate(_)
        | GovBody::StepPolicyUpdate(_)
        | GovBody::Lifecycle(_)
        | GovBody::RoomName(_)
        | GovBody::RoomAnchors(_) => {
            writer.put(Table::ActionOrder, rank_key(state.next), Some(log))?;
        }
        _ => {}
    }
    writer.put(Table::Ready, key, None)?;
    if let Some(next) = next_author_entry(writer, &entry.skeleton.author_id, entry.skeleton.seq)? {
        queue_check(writer, next)?;
    }
    state.next = state
        .next
        .checked_add(1)
        .ok_or(invalid("governance rank exhausted"))?;
    state.phase = WAKE;
    state.item = Some(hash);
    state.after = None;
    Ok(())
}

fn wake(writer: &mut Write<'_>, state: &mut State) -> Result<()> {
    let hash = state.item.ok_or(invalid("governance wake entry"))?;
    let row = writer
        .at_or_after(Table::Blocked, hash_key(&hash))?
        .filter(|(key, _)| key[..32] == hash[..]);
    match row {
        Some((key, log)) => {
            queue_check(writer, log)?;
            writer.put(Table::Blocked, key, None)?;
        }
        None => {
            state.phase = CHECK;
            state.clear_item();
        }
    }
    Ok(())
}

fn trim(writer: &mut Write<'_>, state: &mut State) -> Result<()> {
    match writer.at_or_after(Table::Order, rank_key(state.next))? {
        Some((key, _)) => remove_old_rank(writer, rank_from(&key)?)?,
        None => {
            writer.order_published(state.cut)?;
            *state = State::default();
        }
    }
    Ok(())
}
