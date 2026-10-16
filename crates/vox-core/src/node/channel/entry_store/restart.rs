//! Bounded accepted-prefix state, sealed in the same directory as its published roots.
//! This is not a copy of history. Each author occupies one fixed-size feed/presence row.

use super::{flag, invalid, Decoder, Digest32, Encoder, Entry, Result};
use crate::log::dag::PublishedFeed;
use crate::node::channel::governance::Presence;
use crate::node::channel::AUTHORS_HARD_LIMIT;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub(crate) struct RestartState {
    pub room: Digest32,
    pub epoch: u64,
    pub feeds: BTreeMap<Digest32, PublishedFeed>,
    pub presence: BTreeMap<Digest32, Presence>,
    pub projection: Option<Vec<u8>>,
    pub retained_step_body: Option<Digest32>,
    pub set_aside: crate::node::channel::SetAside,
    /// Source positions may be sparse; `feeds` still records only actually contiguous data.
    pub sparse: bool,
}

impl RestartState {
    pub(super) fn empty(room: Digest32, epoch: u64) -> Self {
        Self {
            room,
            epoch,
            feeds: BTreeMap::new(),
            presence: BTreeMap::new(),
            projection: None,
            retained_step_body: None,
            set_aside: crate::node::channel::SetAside::default(),
            sparse: false,
        }
    }
    pub(super) fn write(&self, e: &mut Encoder) {
        e.array(8)
            .bytes(&self.room)
            .uint(self.epoch)
            .array(self.feeds.len());
        for (author, state) in &self.feeds {
            e.array(2).bytes(author);
            write_feed(state, e);
        }
        e.array(self.presence.len());
        for (author, state) in &self.presence {
            e.array(4)
                .bytes(author)
                .uint(state.last.0)
                .uint(u64::from(state.last.1));
            match state.back {
                Some((seq, ms)) => {
                    e.array(2).uint(seq).uint(ms);
                }
                None => {
                    e.array(0);
                }
            }
        }
        match self.retained_step_body {
            Some(hash) => {
                e.array(1).bytes(&hash);
            }
            None => {
                e.array(0);
            }
        }
        e.array(2).array(self.set_aside.entries().len());
        for entry in self.set_aside.entries() {
            e.text(entry);
        }
        e.uint(self.set_aside.omitted());
        match &self.projection {
            Some(bytes) => {
                e.array(1).bytes(bytes);
            }
            None => {
                e.array(0);
            }
        }
        e.uint(u64::from(self.sparse));
    }
    pub(super) fn read(d: &mut Decoder<'_>) -> Result<Self> {
        let arity = d.array()?;
        if !matches!(arity, 7 | 8) {
            return Err(invalid("restart state arity"));
        }
        let room = digest(d)?;
        let epoch = d.uint()?;
        let n = d.array()?;
        if n > AUTHORS_HARD_LIMIT {
            return Err(invalid("restart author bound"));
        }
        let mut feeds = BTreeMap::new();
        for _ in 0..n {
            if d.array()? != 2 {
                return Err(invalid("restart author row"));
            }
            let author = digest(d)?;
            let state = read_feed(d)?;
            if state.seq == 0 || feeds.insert(author, state).is_some() {
                return Err(invalid("restart author duplicate or empty"));
            }
        }
        let n = d.array()?;
        if n > AUTHORS_HARD_LIMIT {
            return Err(invalid("restart presence bound"));
        }
        let mut presence = BTreeMap::new();
        for _ in 0..n {
            if d.array()? != 4 {
                return Err(invalid("restart presence row"));
            }
            let author = digest(d)?;
            let last = (d.uint()?, flag(d)?);
            let back = match d.array()? {
                0 => None,
                2 => Some((d.uint()?, d.uint()?)),
                _ => return Err(invalid("restart presence back")),
            };
            if last.0 == 0
                || back.is_some_and(|(seq, _)| seq == 0 || seq > last.0)
                || presence.insert(author, Presence { last, back }).is_some()
            {
                return Err(invalid("restart presence binding"));
            }
        }
        let retained_step_body = match d.array()? {
            0 => None,
            1 => Some(digest(d)?),
            _ => return Err(invalid("restart retained step marker")),
        };
        if d.array()? != 2 {
            return Err(invalid("restart diagnostics arity"));
        }
        let n = d.array()?;
        if n > 64 {
            return Err(invalid("restart diagnostic count"));
        }
        let mut messages = Vec::new();
        for _ in 0..n {
            let message = d.text()?;
            if message.len() > 1024 {
                return Err(invalid("restart diagnostic size"));
            }
            messages.push(message.to_owned());
        }
        let set_aside = crate::node::channel::SetAside::restored(messages, d.uint()?)?;
        let projection = match d.array()? {
            0 => None,
            1 => {
                let b = d.bytes()?;
                if b.len() > 256 {
                    return Err(invalid("restart projection bound"));
                }
                Some(b.to_vec())
            }
            _ => return Err(invalid("restart projection arity")),
        };
        let sparse = arity >= 8 && flag(d)?;
        if !sparse
            && presence
                .iter()
                .any(|(author, state)| feeds.get(author).is_none_or(|feed| state.last.0 > feed.seq))
        {
            return Err(invalid("legacy restart presence beyond feed"));
        }
        Ok(Self {
            room,
            epoch,
            feeds,
            presence,
            projection,
            retained_step_body,
            set_aside,
            sparse,
        })
    }
}

pub(super) fn write_feed(state: &PublishedFeed, e: &mut Encoder) {
    e.array(6)
        .uint(state.seq)
        .bytes(&state.hash)
        .uint(state.first_claimed_ms)
        .uint(u64::from(state.ended));
    match state.checkpoint {
        Some((seq, hash)) => {
            e.array(2).uint(seq).bytes(&hash);
        }
        None => {
            e.array(0);
        }
    }
    e.uint(state.swept_to);
}
pub(super) fn read_feed(d: &mut Decoder<'_>) -> Result<PublishedFeed> {
    if d.array()? != 6 {
        return Err(invalid("restart feed arity"));
    }
    let seq = d.uint()?;
    let hash = digest(d)?;
    let first_claimed_ms = d.uint()?;
    let ended = flag(d)?;
    let checkpoint = match d.array()? {
        0 => None,
        2 => Some((d.uint()?, digest(d)?)),
        _ => return Err(invalid("restart checkpoint arity")),
    };
    let swept_to = d.uint()?;
    if checkpoint.is_some_and(|(at, _)| at == 0 || at >= seq)
        || swept_to > checkpoint.map_or(0, |c| c.0)
    {
        return Err(invalid("restart checkpoint bound"));
    }
    Ok(PublishedFeed {
        seq,
        hash,
        first_claimed_ms,
        ended,
        checkpoint,
        swept_to,
    })
}
fn digest(d: &mut Decoder<'_>) -> Result<Digest32> {
    d.bytes()?.try_into().map_err(|_| invalid("restart digest"))
}

/// Advance only through this promotion's already authenticated entries. The candidate
/// remains unpublished until the signed witness and active root switch commit together.
pub(super) fn advance(state: &mut PublishedFeed, entry: &Entry) -> Result<()> {
    if state.seq.checked_add(1) != Some(entry.skeleton.seq)
        || state.hash != entry.skeleton.prev_hash
        || state.ended
    {
        return Err(invalid("restart promotion continuity"));
    }
    if state.seq == 0 {
        state.first_claimed_ms = entry.skeleton.claimed_ms;
    }
    state.seq = entry.skeleton.seq;
    state.hash = entry.entry_hash();
    state.ended = entry.skeleton.end_of_feed;
    if let Some(payload) = entry
        .payload
        .as_deref()
        .filter(|_| entry.skeleton.v2.is_none())
    {
        if let Some(cp) = crate::log::checkpoint::Checkpoint::from_payload(payload)? {
            if cp.seq >= state.seq {
                return Err(invalid("restart checkpoint position"));
            }
            if state.checkpoint.is_none_or(|held| cp.seq > held.0) {
                state.checkpoint = Some((cp.seq, cp.entry_hash));
            }
        }
    }
    Ok(())
}

impl super::Write<'_, '_> {
    /// A valid checkpoint body can arrive after its signed skeleton was accepted. Its
    /// durable control state must accompany that body, without advancing the accepted head.
    pub(super) fn note_checkpoint_refill(&mut self, entry: &Entry) -> Result<()> {
        if entry.skeleton.v2.is_some() {
            return Ok(());
        }
        let Some(payload) = entry.payload.as_deref().filter(|_| entry.is_signed()) else {
            return Ok(());
        };
        let Some(checkpoint) = crate::log::checkpoint::Checkpoint::from_payload(payload)
            .ok()
            .flatten()
        else {
            return Ok(());
        };
        entry.verify_payload_binding()?;
        let author = entry.skeleton.author_id;
        let restart = self
            .directory
            .restart
            .as_ref()
            .ok_or(invalid("checkpoint refill without restart state"))?;
        let feed = restart
            .feeds
            .get(&author)
            .ok_or(invalid("checkpoint refill author is not published"))?;
        if entry.skeleton.channel_id != restart.room
            || entry.skeleton.epoch != restart.epoch
            || entry.skeleton.seq > feed.seq
        {
            return Err(invalid("checkpoint refill outside published feed"));
        }
        // Match Dag::fill_body: a malformed checkpoint claim does not become authority
        // merely because its body matches an already accepted signed skeleton.
        if checkpoint.seq >= entry.skeleton.seq
            || feed.checkpoint.is_some_and(|old| old.0 >= checkpoint.seq)
        {
            return Ok(());
        }
        let source = super::Source::Batch(self.batch);
        let Some(at) = source.find(
            self.sek,
            self.channel,
            self.directory.active.sequence,
            &super::position(&author, checkpoint.seq),
        )?
        else {
            return Ok(());
        };
        let named = super::indexed_entry(
            &source,
            self.sek,
            self.channel,
            crate::atrest::store::SegmentKind::LogDb,
            at,
        )?;
        if named.entry_hash() != checkpoint.entry_hash {
            return Ok(());
        }
        self.directory
            .restart
            .as_mut()
            .and_then(|state| state.feeds.get_mut(&author))
            .ok_or(invalid("checkpoint refill state disappeared"))?
            .checkpoint = Some((checkpoint.seq, checkpoint.entry_hash));
        Ok(())
    }
}
