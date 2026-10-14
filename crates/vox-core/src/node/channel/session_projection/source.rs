//! Short, authenticated source reads. A bundle reader retains one ordinary record's body,
//! independent of the number of parts or the total metadata length.

use crate::atrest::sek::{Sek, TAG_LEN};
use crate::atrest::store::{open_segment, SegmentKind};
use crate::cbor::Decoder;
use crate::error::{Error, Result};
use crate::hash::Digest32;
use crate::node::store::Snapshot;

use super::record::{EnvelopeRef, Part, Source};
use super::storage::{Read, Tree};
use super::text::Input;

fn invalid(why: &'static str) -> Error {
    Error::MalformedAtRest(why)
}

/// A source descriptor is an authenticated locator, not authority. Current room/drive
/// eligibility is checked by the actor for each query/chunk before this reader is created.
pub(super) fn body(
    snapshot: &Snapshot,
    sek: &Sek,
    room: &Digest32,
    source: Source,
) -> Result<String> {
    let kind = if source.position.private {
        SegmentKind::PrivateSession
    } else {
        SegmentKind::PlaintextCache
    };
    let sealed = snapshot
        .get_segment(room, kind, source.id)?
        .ok_or_else(|| invalid("Session metadata source missing"))?;
    // These are existing record limits, not new limits on assembled metadata fields.
    let max = if source.position.private {
        2 * crate::node::sessionstream::MAX_RECORD
    } else {
        crate::node::content::MAX_TEXT_LEN + 1024
    };
    if sealed.ciphertext.len() > max.saturating_add(TAG_LEN) {
        return Err(invalid("Session metadata source exceeds record format"));
    }
    let bytes = open_segment(sek, kind, source.id, &sealed)?;
    let (hash, author, created, text) = if source.position.private {
        let saved = super::super::private_session::Stored::read(&bytes)?;
        let row = saved
            .row
            .ok_or_else(|| invalid("Session metadata source is not readable"))?;
        (row.entry_hash, row.author, row.created_millis, row.body)
    } else {
        let super::super::CacheRow::Text(row) = super::super::parse_cache(&bytes)? else {
            return Err(invalid("Session metadata source cache kind"));
        };
        (row.entry_hash, row.author, row.created_millis, row.text)
    };
    if hash != source.position.hash || author != source.author || created != source.position.created
    {
        return Err(invalid("Session metadata source binding"));
    }
    Ok(text)
}

pub(super) struct EnvelopeInput<'a> {
    read: &'a Read<'a>,
    envelope: EnvelopeRef,
    loaded: Option<(u64, String)>,
}

impl<'a> EnvelopeInput<'a> {
    pub fn new(read: &'a Read<'a>, envelope: EnvelopeRef) -> Self {
        Self {
            read,
            envelope,
            loaded: None,
        }
    }

    fn load(&mut self, offset: u64) -> Result<()> {
        if self
            .loaded
            .as_ref()
            .is_some_and(|(start, text)| offset >= *start && offset - *start < text.len() as u64)
        {
            return Ok(());
        }
        if self.envelope.bundle.is_none() {
            let text = self.read.source(self.envelope.first)?;
            if text.len() as u64 != self.envelope.bytes {
                return Err(invalid("Session metadata source length changed"));
            }
            self.loaded = Some((0, text));
            return Ok(());
        }
        let first = self.envelope.first.position.hash;
        let mut bound = Part::key(&first, offset);
        // last_before is exclusive. The unused final byte includes the exact offset key.
        bound[63] = 1;
        let (key, id) = self
            .read
            .previous(Tree::Parts, Some(bound))?
            .ok_or_else(|| invalid("Session metadata part missing"))?;
        if key[..32] != first {
            return Err(invalid("Session metadata part bundle differs"));
        }
        let bytes = self.read.descriptor(id)?;
        let mut d = Decoder::new(&bytes);
        let part = Part::read(&mut d)?;
        d.finish()?;
        if key != Part::key(&first, part.offset)
            || part.source.author != self.envelope.first.author
            || part.number > self.envelope.parts
            || offset < part.offset
            || offset - part.offset >= part.bytes
        {
            return Err(invalid("Session metadata part range"));
        }
        let text = self.read.source(part.source)?;
        let envelope = vox_agentcomms::envelope::Envelope::parse(&text)
            .map_err(|_| invalid("Session metadata part envelope changed"))?;
        if envelope.body.len() as u64 != part.bytes {
            return Err(invalid("Session metadata part body changed"));
        }
        self.loaded = Some((part.offset, envelope.body));
        Ok(())
    }
}

impl Input for EnvelopeInput<'_> {
    fn len(&self) -> u64 {
        self.envelope.bytes
    }

    fn read_at(&mut self, offset: u64, out: &mut [u8]) -> Result<usize> {
        if offset > self.envelope.bytes {
            return Err(invalid("Session metadata source offset"));
        }
        if offset == self.envelope.bytes || out.is_empty() {
            return Ok(0);
        }
        self.load(offset)?;
        let (start, text) = self
            .loaded
            .as_ref()
            .ok_or_else(|| invalid("Session source not loaded"))?;
        let at =
            usize::try_from(offset - *start).map_err(|_| invalid("Session source offset width"))?;
        let remaining = &text.as_bytes()[at..];
        let n = out.len().min(remaining.len());
        out[..n].copy_from_slice(&remaining[..n]);
        Ok(n)
    }
}
